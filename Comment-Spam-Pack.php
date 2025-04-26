<?php
/**
 * Plugin Name: Comment Spam Pack MU
 * Description: A comprehensive must-use plugin to protect WordPress sites from comment spam
 * Version: 1.0.0
 * Author: Sunil Kumar
 * Author URI: https://stackspectra.com/
 * License: GPL v2 or later
 */

// If this file is called directly, abort.
if (!defined('WPINC')) {
    die;
}

class Comment_Spam_Pack_MU {
    
    /**
     * Initialize the plugin
     */
    public function __construct() {
        // Core filters for spam prevention
        add_filter('pre_comment_approved', array($this, 'check_comment_spam'), 99, 2);
        add_filter('comment_form_defaults', array($this, 'add_honeypot_field'));
        add_action('wp_head', array($this, 'add_honeypot_css'));
        
        // Add settings page in admin
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add AJAX handling for blacklist
        add_action('wp_ajax_cspm_blacklist_ip', array($this, 'blacklist_ip'));
        
        // Initialize default options
        $this->init_options();
        
        // Schedule cleanup of temporary blacklist
        if (!wp_next_scheduled('cspm_cleanup_temp_blacklist')) {
            wp_schedule_event(time(), 'daily', 'cspm_cleanup_temp_blacklist');
        }
        add_action('cspm_cleanup_temp_blacklist', array($this, 'cleanup_temp_blacklist'));
    }

    /**
     * Initialize default options
     */
    public function init_options() {
        $default_options = array(
            'enable_honeypot' => 'yes',
            'check_comment_time' => 'yes',
            'min_comment_time' => 5,
            'enable_keyword_filter' => 'yes',
            'spam_keywords' => "viagra\ncasino\npayday loan\ncheap seo\nsex\nporn\nxxx",
            'enable_ip_blacklist' => 'yes',
            'ip_blacklist' => '',
            'temp_ip_blacklist' => array(),
            'enable_link_limits' => 'yes',
            'max_links' => 2,
            'enable_akismet_integration' => 'yes'
        );
        
        foreach ($default_options as $key => $value) {
            if (get_option('cspm_' . $key) === false) {
                update_option('cspm_' . $key, $value);
            }
        }
    }

    /**
     * Main function to check comments for spam
     */
    public function check_comment_spam($approved, $comment_data) {
        // Skip checks for logged-in users if option is enabled
        if (is_user_logged_in() && get_option('cspm_trusted_users') === 'yes') {
            return $approved;
        }
        
        // Get the comment author IP
        $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
        
        // Check against IP blacklist
        if (get_option('cspm_enable_ip_blacklist') === 'yes') {
            if ($this->is_ip_blacklisted($ip)) {
                return 'spam';
            }
        }
        
        // Check honeypot
        if (get_option('cspm_enable_honeypot') === 'yes') {
            if (!empty($_POST['website_url'])) {
                $this->maybe_blacklist_ip($ip);
                return 'spam';
            }
        }
        
        // Check comment time
        if (get_option('cspm_check_comment_time') === 'yes') {
            $min_time = get_option('cspm_min_comment_time', 5);
            $comment_time = isset($_POST['comment_time']) ? intval($_POST['comment_time']) : 0;
            $current_time = time();
            
            if (($current_time - $comment_time) < $min_time) {
                $this->maybe_blacklist_ip($ip);
                return 'spam';
            }
        }
        
        // Check for spam keywords
        if (get_option('cspm_enable_keyword_filter') === 'yes') {
            $keywords = explode("\n", get_option('cspm_spam_keywords'));
            $comment_text = strtolower($comment_data['comment_content']);
            
            foreach ($keywords as $keyword) {
                $keyword = trim(strtolower($keyword));
                if (!empty($keyword) && strpos($comment_text, $keyword) !== false) {
                    $this->maybe_blacklist_ip($ip);
                    return 'spam';
                }
            }
        }
        
        // Check link limits
        if (get_option('cspm_enable_link_limits') === 'yes') {
            $max_links = get_option('cspm_max_links', 2);
            $link_count = substr_count($comment_data['comment_content'], 'http');
            
            if ($link_count > $max_links) {
                $this->maybe_blacklist_ip($ip);
                return 'spam';
            }
        }
        
        // Check Akismet if enabled and available
        if (get_option('cspm_enable_akismet_integration') === 'yes' && function_exists('akismet_init')) {
            if ($this->check_akismet($comment_data)) {
                $this->maybe_blacklist_ip($ip);
                return 'spam';
            }
        }
        
        return $approved;
    }

    /**
     * Check if an IP is blacklisted
     */
    public function is_ip_blacklisted($ip) {
        // Check permanent blacklist
        $blacklist = explode("\n", get_option('cspm_ip_blacklist', ''));
        if (in_array($ip, array_map('trim', $blacklist))) {
            return true;
        }
        
        // Check temporary blacklist
        $temp_blacklist = get_option('cspm_temp_ip_blacklist', array());
        if (isset($temp_blacklist[$ip]) && $temp_blacklist[$ip] > time()) {
            return true;
        }
        
        return false;
    }

    /**
     * Maybe blacklist an IP after spam detection
     */
    public function maybe_blacklist_ip($ip) {
        $temp_blacklist = get_option('cspm_temp_ip_blacklist', array());
        
        // Count spam attempts
        if (!isset($temp_blacklist[$ip])) {
            $temp_blacklist[$ip] = time() + (24 * 60 * 60); // 24 hours
            $spam_count = 1;
        } else {
            $spam_count = isset($temp_blacklist[$ip . '_count']) ? $temp_blacklist[$ip . '_count'] + 1 : 1;
        }
        
        $temp_blacklist[$ip . '_count'] = $spam_count;
        update_option('cspm_temp_ip_blacklist', $temp_blacklist);
        
        // If multiple spam attempts, add to permanent blacklist
        if ($spam_count >= 3) {
            $blacklist = get_option('cspm_ip_blacklist', '');
            $blacklist_array = explode("\n", $blacklist);
            if (!in_array($ip, array_map('trim', $blacklist_array))) {
                $blacklist .= "\n" . $ip;
                update_option('cspm_ip_blacklist', trim($blacklist));
            }
        }
    }

    /**
     * Clean up temporary blacklist
     */
    public function cleanup_temp_blacklist() {
        $temp_blacklist = get_option('cspm_temp_ip_blacklist', array());
        $current_time = time();
        
        foreach ($temp_blacklist as $ip => $expiry) {
            // Skip the count entries
            if (strpos($ip, '_count') !== false) {
                continue;
            }
            
            if ($expiry < $current_time) {
                unset($temp_blacklist[$ip]);
                unset($temp_blacklist[$ip . '_count']);
            }
        }
        
        update_option('cspm_temp_ip_blacklist', $temp_blacklist);
    }

    /**
     * Check comment against Akismet
     */
    public function check_akismet($comment_data) {
        if (!function_exists('akismet_init')) {
            return false;
        }
        
        global $akismet_api_host, $akismet_api_port;
        
        $akismet_api_key = get_option('wordpress_api_key');
        if (empty($akismet_api_key)) {
            return false;
        }
        
        $comment = array(
            'comment_author' => $comment_data['comment_author'],
            'comment_author_email' => $comment_data['comment_author_email'],
            'comment_author_url' => $comment_data['comment_author_url'],
            'comment_content' => $comment_data['comment_content'],
            'user_ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'referrer' => $_SERVER['HTTP_REFERER'],
            'blog' => get_option('home')
        );
        
        $query_string = '';
        foreach ($comment as $key => $data) {
            if (!empty($data)) {
                $query_string .= $key . '=' . urlencode(stripslashes($data)) . '&';
            }
        }
        
        $response = akismet_http_post($query_string, $akismet_api_host, '/1.1/comment-check', $akismet_api_port);
        return $response[1] == 'true';
    }

    /**
     * Add honeypot field to comment form
     */
    public function add_honeypot_field($fields) {
        if (get_option('cspm_enable_honeypot') === 'yes') {
            $fields['fields']['website_url'] = '<input type="text" name="website_url" id="website_url" class="website_url" />';
            
            // Add timestamp field for minimum comment time check
            if (get_option('cspm_check_comment_time') === 'yes') {
                $fields['fields']['comment_time'] = '<input type="hidden" name="comment_time" value="' . time() . '" />';
            }
        }
        
        return $fields;
    }

    /**
     * Add CSS to hide honeypot field
     */
    public function add_honeypot_css() {
        if (get_option('cspm_enable_honeypot') === 'yes') {
            echo '<style>.website_url { display:none !important; }</style>';
        }
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_options_page(
            'Comment Spam Pack Settings',
            'Comment Spam Pack',
            'manage_options',
            'comment-spam-pack',
            array($this, 'settings_page')
        );
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('cspm_settings', 'cspm_enable_honeypot');
        register_setting('cspm_settings', 'cspm_check_comment_time');
        register_setting('cspm_settings', 'cspm_min_comment_time');
        register_setting('cspm_settings', 'cspm_enable_keyword_filter');
        register_setting('cspm_settings', 'cspm_spam_keywords');
        register_setting('cspm_settings', 'cspm_enable_ip_blacklist');
        register_setting('cspm_settings', 'cspm_ip_blacklist');
        register_setting('cspm_settings', 'cspm_enable_link_limits');
        register_setting('cspm_settings', 'cspm_max_links');
        register_setting('cspm_settings', 'cspm_enable_akismet_integration');
        register_setting('cspm_settings', 'cspm_trusted_users');
    }

    /**
     * Settings page HTML
     */
    public function settings_page() {
        ?>
        <div class="wrap">
            <h1>Comment Spam Pack Settings</h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('cspm_settings'); ?>
                <?php do_settings_sections('cspm_settings'); ?>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Trust Logged-in Users</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_trusted_users" value="yes" <?php checked(get_option('cspm_trusted_users'), 'yes'); ?> />
                                Skip spam checks for logged-in users
                            </label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Honeypot Protection</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_enable_honeypot" value="yes" <?php checked(get_option('cspm_enable_honeypot'), 'yes'); ?> />
                                Enable honeypot field to catch bots
                            </label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Minimum Comment Time</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_check_comment_time" value="yes" <?php checked(get_option('cspm_check_comment_time'), 'yes'); ?> />
                                Check for minimum time spent on comment form
                            </label>
                            <br />
                            <input type="number" name="cspm_min_comment_time" value="<?php echo esc_attr(get_option('cspm_min_comment_time', 5)); ?>" min="1" max="60" />
                            seconds minimum
                            <p class="description">Comments submitted faster than this time will be marked as spam</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Keyword Filtering</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_enable_keyword_filter" value="yes" <?php checked(get_option('cspm_enable_keyword_filter'), 'yes'); ?> />
                                Enable spam keyword filtering
                            </label>
                            <br />
                            <textarea name="cspm_spam_keywords" rows="5" cols="50"><?php echo esc_textarea(get_option('cspm_spam_keywords')); ?></textarea>
                            <p class="description">Enter one keyword or phrase per line</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">IP Blacklist</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_enable_ip_blacklist" value="yes" <?php checked(get_option('cspm_enable_ip_blacklist'), 'yes'); ?> />
                                Enable IP blacklisting
                            </label>
                            <br />
                            <textarea name="cspm_ip_blacklist" rows="5" cols="50"><?php echo esc_textarea(get_option('cspm_ip_blacklist')); ?></textarea>
                            <p class="description">Enter one IP address per line</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th scope="row">Link Limits</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_enable_link_limits" value="yes" <?php checked(get_option('cspm_enable_link_limits'), 'yes'); ?> />
                                Limit number of links in comments
                            </label>
                            <br />
                            <input type="number" name="cspm_max_links" value="<?php echo esc_attr(get_option('cspm_max_links', 2)); ?>" min="0" max="20" />
                            maximum links allowed
                        </td>
                    </tr>
                    
                    <?php if (function_exists('akismet_init')): ?>
                    <tr>
                        <th scope="row">Akismet Integration</th>
                        <td>
                            <label>
                                <input type="checkbox" name="cspm_enable_akismet_integration" value="yes" <?php checked(get_option('cspm_enable_akismet_integration'), 'yes'); ?> />
                                Check comments with Akismet if available
                            </label>
                        </td>
                    </tr>
                    <?php endif; ?>
                </table>
                
                <?php submit_button(); ?>
            </form>
            
            <div class="cspm-stats">
                <h2>Spam Statistics</h2>
                <?php
                $stats = array(
                    'total_caught' => get_option('cspm_stats_total_caught', 0),
                    'honeypot_caught' => get_option('cspm_stats_honeypot_caught', 0),
                    'keyword_caught' => get_option('cspm_stats_keyword_caught', 0),
                    'ip_blocked' => get_option('cspm_stats_ip_blocked', 0),
                    'time_check_caught' => get_option('cspm_stats_time_check_caught', 0),
                    'link_limit_caught' => get_option('cspm_stats_link_limit_caught', 0),
                    'akismet_caught' => get_option('cspm_stats_akismet_caught', 0)
                );
                ?>
                <table class="widefat">
                    <thead>
                        <tr>
                            <th>Metric</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Total Spam Caught</td>
                            <td><?php echo esc_html($stats['total_caught']); ?></td>
                        </tr>
                        <tr>
                            <td>Caught by Honeypot</td>
                            <td><?php echo esc_html($stats['honeypot_caught']); ?></td>
                        </tr>
                        <tr>
                            <td>Caught by Keyword Filter</td>
                            <td><?php echo esc_html($stats['keyword_caught']); ?></td>
                        </tr>
                        <tr>
                            <td>Blocked by IP</td>
                            <td><?php echo esc_html($stats['ip_blocked']); ?></td>
                        </tr>
                        <tr>
                            <td>Caught by Time Check</td>
                            <td><?php echo esc_html($stats['time_check_caught']); ?></td>
                        </tr>
                        <tr>
                            <td>Caught by Link Limit</td>
                            <td><?php echo esc_html($stats['link_limit_caught']); ?></td>
                        </tr>
                        <tr>
                            <td>Caught by Akismet</td>
                            <td><?php echo esc_html($stats['akismet_caught']); ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
        <?php
    }

    /**
     * AJAX handler for blacklisting an IP
     */
    public function blacklist_ip() {
        // Security check
        check_ajax_referer('cspm_blacklist_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die();
        }
        
        $ip = isset($_POST['ip']) ? sanitize_text_field($_POST['ip']) : '';
        
        if (!empty($ip)) {
            $blacklist = get_option('cspm_ip_blacklist', '');
            $blacklist_array = explode("\n", $blacklist);
            
            if (!in_array($ip, array_map('trim', $blacklist_array))) {
                $blacklist .= "\n" . $ip;
                update_option('cspm_ip_blacklist', trim($blacklist));
                wp_send_json_success(array('message' => 'IP added to blacklist'));
            } else {
                wp_send_json_error(array('message' => 'IP already in blacklist'));
            }
        } else {
            wp_send_json_error(array('message' => 'Invalid IP address'));
        }
        
        wp_die();
    }
}

// Initialize the plugin
new Comment_Spam_Pack_MU();

/**
 * Installation function for the plugin
 * This will only run when manually activated, not as an mu-plugin
 */
function comment_spam_pack_mu_activate() {
    // Create the mu-plugins directory if it doesn't exist
    $mu_plugins_dir = ABSPATH . 'wp-content/mu-plugins';
    
    if (!file_exists($mu_plugins_dir)) {
        wp_mkdir_p($mu_plugins_dir);
    }
    
    // Copy the plugin file to the mu-plugins directory
    $source_file = plugin_dir_path(__FILE__) . basename(__FILE__);
    $target_file = $mu_plugins_dir . '/' . basename(__FILE__);
    
    if (!file_exists($target_file)) {
        copy($source_file, $target_file);
    }
}
register_activation_hook(__FILE__, 'comment_spam_pack_mu_activate');
