<?php
/**
 * Plugin Name: XTEC Login
 * Plugin URI: https://github.com/projectestac/wordpress-xtec-ldap-login
 * Description: Overrides the core WordPress authentication method to allow the user authentication and registration
 *              through LDAP or OAuth. It also adds an API function for a web service authentication
 * Version: 3.0
 * Author: Francesc Bassas & Toni Ginard
 */

const XTEC_DOMAIN = '@xtec.cat';

register_activation_hook(__FILE__, 'xtec_ldap_login_activate');
add_action('init', 'xtec_ldap_login_init');
add_filter('send_password_change_email', '__return_false');

function xtec_ldap_login_activate()
{
    // Add the rewrite rule on activation
    add_rewrite_rule('^oauth-callback/?$', 'index.php?oauth_callback=1', 'top');

    // Flush rewrite rules to make sure our custom endpoint is registered
    flush_rewrite_rules();
}

/**
 * Plugin initialization
 */
function xtec_ldap_login_init()
{
    // Localization
    load_plugin_textdomain('xtec-ldap-login', false, basename(__DIR__) . '/languages/');

    // Check for WordPress multisite and add option to Dashboard
    if (is_multisite()) {
        add_action('network_admin_menu', 'xtec_ldap_login_network_admin_menu');
    } else {
        add_action('admin_menu', 'xtec_ldap_login_admin_menu');
    }

    add_filter('authenticate', 'xtec_ldap_authenticate', 10, 3); // Executed before standard filter.
    add_action('login_form', 'xtec_oauth_add_login_button');

    // Use 'template_redirect' to handle the callback on the frontend
    add_action('template_redirect', 'xtec_oauth_handle_callback');

    add_rewrite_rule('^oauth-callback/?$', 'index.php?oauth_callback=1', 'top');
    add_filter('query_vars', function ($vars) {
        $vars[] = 'oauth_callback';
        return $vars;
    });
}

/**
 * Add plugin to settings in network admin menu (multisite configuration)
 */
function xtec_ldap_login_network_admin_menu()
{
    add_submenu_page(
            'settings.php',
            __('XTEC Login', 'xtec-ldap-login'),
            __('XTEC Login', 'xtec-ldap-login'),
            'manage_network_options',
            'ms-ldap-login',
            'xtec_ldap_login_options'
    );
}

/**
 * Add plugin to tools in admin menu (single site configuration)
 */
function xtec_ldap_login_admin_menu()
{
    add_submenu_page(
            'tools.php',
            __('XTEC Login', 'xtec-ldap-login'),
            __('XTEC Login', 'xtec-ldap-login'),
            'manage_options',
            'ldap-login',
            'xtec_ldap_login_options'
    );
}

/**
 * Create options form and save data
 */
function xtec_ldap_login_options()
{
    // Save data.
    if (isset($_GET['action']) && $_GET['action'] === 'siteoptions') {
        if (isset($_POST['xtec_ldap_host'])) {
            $xtec_ldap_host = sanitize_text_field($_POST['xtec_ldap_host']);
            update_site_option('xtec_ldap_host', $xtec_ldap_host);
        }
        if (isset($_POST['xtec_ldap_port'])) {
            $xtec_ldap_port = sanitize_text_field($_POST['xtec_ldap_port']);
            update_site_option('xtec_ldap_port', $xtec_ldap_port);
        }
        if (isset($_POST['xtec_ldap_version'])) {
            $xtec_ldap_version = sanitize_text_field($_POST['xtec_ldap_version']);
            update_site_option('xtec_ldap_version', $xtec_ldap_version);
        }
        if (isset($_POST['xtec_ldap_base_dn'])) {
            $xtec_ldap_base_dn = sanitize_text_field($_POST['xtec_ldap_base_dn']);
            update_site_option('xtec_ldap_base_dn', $xtec_ldap_base_dn);
        }
        if (isset($_POST['xtec_ldap_login_type'])) {
            $xtec_ldap_login_type = sanitize_text_field($_POST['xtec_ldap_login_type']);
            update_site_option('xtec_ldap_login_type', $xtec_ldap_login_type);
        }
        if (isset($_POST['xtec_oauth_client_id'])) {
            $xtec_oauth_client_id = sanitize_text_field($_POST['xtec_oauth_client_id']);
            update_site_option('xtec_oauth_client_id', $xtec_oauth_client_id);
        }
        if (isset($_POST['xtec_oauth_client_secret'])) {
            $xtec_oauth_client_secret = sanitize_text_field($_POST['xtec_oauth_client_secret']);
            update_site_option('xtec_oauth_client_secret', $xtec_oauth_client_secret);
        }
        if (isset($_POST['xtec_oauth_client_token_url'])) {
            $xtec_oauth_client_token_url = sanitize_text_field($_POST['xtec_oauth_client_token_url']);
            update_site_option('xtec_oauth_client_token_url', $xtec_oauth_client_token_url);
        }
        if (isset($_POST['xtec_oauth_client_user_info_url'])) {
            $xtec_oauth_client_user_info_url = sanitize_text_field($_POST['xtec_oauth_client_user_info_url']);
            update_site_option('xtec_oauth_client_user_info_url', $xtec_oauth_client_user_info_url);
        }
        if (isset($_POST['xtec_oauth_client_scope'])) {
            $xtec_oauth_client_scope = sanitize_text_field($_POST['xtec_oauth_client_scope']);
            update_site_option('xtec_oauth_client_scope', $xtec_oauth_client_scope);
        }
        if (isset($_POST['xtec_oauth_client_auth_url'])) {
            $xtec_oauth_client_auth_url = sanitize_text_field($_POST['xtec_oauth_client_auth_url']);
            update_site_option('xtec_oauth_client_auth_url', $xtec_oauth_client_auth_url);
        }
        ?>
        <div id="message" class="updated notice is-dismissible">
            <p><?php _e('Options saved.', 'xtec-ldap-login') ?></p>
        </div>
        <?php
    }
    ?>

    <div class="wrap">
        <?php
        $page = (is_multisite()) ? 'ms-ldap-login' : 'ldap-login'; ?>
        <form method="post" action="?page=<?php echo $page; ?>&action=siteoptions">
            <h2><?php _e('XTEC Login', 'xtec-ldap-login') ?></h2>
            <table class="form-table">
                <tbody>
                <?php
                if (is_xtec_super_admin()) { ?>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_ldap_host">
                                <?php _e('LDAP Host', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_ldap_host" name="xtec_ldap_host"
                                   value="<?php echo get_site_option('xtec_ldap_host'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_ldap_port">
                                <?php _e('LDAP Port', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_ldap_port" name="xtec_ldap_port"
                                   value="<?php echo get_site_option('xtec_ldap_port'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_ldap_version">
                                <?php _e('LDAP Version', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_ldap_version" name="xtec_ldap_version"
                                   value="<?php echo get_site_option('xtec_ldap_version'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_ldap_base_dn">
                                <?php _e('Base DN', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_ldap_base_dn" name="xtec_ldap_base_dn"
                                   value="<?php echo get_site_option('xtec_ldap_base_dn'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_id">
                                <?php _e('OAuth Client ID', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_id" name="xtec_oauth_client_id"
                                   value="<?php echo get_site_option('xtec_oauth_client_id'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_secret">
                                <?php _e('OAuth Client Secret', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_secret" name="xtec_oauth_client_secret"
                                   value="<?php echo get_site_option('xtec_oauth_client_secret'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_token_url">
                                <?php _e('OAuth Client Token URL', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_token_url" name="xtec_oauth_client_token_url"
                                   value="<?php echo get_site_option('xtec_oauth_client_token_url'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_user_info_url">
                                <?php _e('OAuth Client User Info URL', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_user_info_url" name="xtec_oauth_client_user_info_url"
                                   value="<?php echo get_site_option('xtec_oauth_client_user_info_url'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_scope">
                                <?php _e('OAuth Client Scope', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_scope" name="xtec_oauth_client_scope"
                                   value="<?php echo get_site_option('xtec_oauth_client_scope'); ?>"/>
                        </td>
                    </tr>
                    <tr valign="top">
                        <th scope="row">
                            <label for="xtec_oauth_client_auth_url">
                                <?php _e('OAuth Client Auth URL', 'xtec-ldap-login') ?>
                            </label>
                        </th>
                        <td>
                            <input type="text" size="50" id="xtec_oauth_client_auth_url" name="xtec_oauth_client_auth_url"
                                   value="<?php echo get_site_option('xtec_oauth_client_auth_url'); ?>"/>
                        </td>
                    </tr>
                <?php
                } ?>
                <tr valign="top">
                    <th scope="row">
                        <label for="xtec_ldap_login_type">
                            <?php _e('Validation Type', 'xtec-ldap-login') ?>
                        </label>
                    </th>
                    <?php
                    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type', 'LDAP');
                    ?>
                    <td>
                        <p>
                            <label>
                                <input type="radio" name="xtec_ldap_login_type" value="LDAP"
                                    <?php
                                    if ($xtec_ldap_login_type === 'LDAP') {
                                        echo 'checked="checked"';
                                    }
                                    ?>
                                />
                                <?php _e('LDAP', 'xtec-ldap-login'); ?>
                            </label>
                        </p>
                        <p class="description">
                            <?php
                            _e(
                                'The user is validated through the LDAP server. If the user enters for the first time and validates, the application registers it. First attempt to validate as user of LDAP server and then if fails attempt to validate as user of the application. <strong>IMPORTANT: When LDAP is on, any XTEC user can log in.</strong>',
                                'xtec-ldap-login'
                            );
                            ?>
                        </p>
                        <br/>
                        <p>
                            <label>
                                <input type="radio" name="xtec_ldap_login_type" value="OAuth"
                                    <?php
                                    if ($xtec_ldap_login_type === 'OAuth') {
                                        echo 'checked="checked"';
                                    } ?>
                                />
                                <?php _e('OAuth', 'xtec-ldap-login'); ?>
                            </label>
                        </p>
                        <p class="description">
                            <?php _e('The user is validated through the OAuth server.', 'xtec-ldap-login'); ?>
                        </p>
                        <br/>
                        <p>
                            <label>
                                <input type="radio" name="xtec_ldap_login_type" value="Application Data Base"
                                    <?php
                                    if ($xtec_ldap_login_type === 'Application Data Base') {
                                        echo 'checked="checked"';
                                    }
                                    ?>
                                />
                            </label>
                            <?php _e('Application Data Base', 'xtec-ldap-login'); ?>
                        </p>
                        <p class="description">
                            <?php _e('The user is validated through Application Data Base', 'xtec-ldap-login'); ?>
                        </p>
                    </td>
                </tr>
                </tbody>
            </table>
            <p class="submit">
                <input type="submit" name="submit" id="submit" class="button-large button-primary"
                       value="<?php _e('Save'); ?>"/>
            </p>
        </form>
    </div>
    <?php
}

/**
 * Checks a user's login information, and it tries to log them in through LDAP
 * server or locally depending on plugin configuration. Usernames longer than
 * 8 chars or having edu365 domain or called 'admin', always log in locally.
 * Any existing user whose e-mail is XTEC, will always log in through LDAP if
 * it is activated. Users that validate successfully via LDAP who doesn't exist
 * locally, are created using WordPress API.
 *
 * @param WP_User $user
 * @param string $username User's username
 * @param string $password User's password
 * @return WP_Error|WP_User WP_User object if login successful, otherwise WP_Error object.
 */
function xtec_ldap_authenticate($user, string $username, string $password)
{
    if ($user instanceof \WP_User) {
        return $user;
    }

    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type');

    if ($xtec_ldap_login_type === 'OAuth') {
        // With OAuth, the authentication is handled by the callback.
        return $user;
    }

    // Remove standard authentication only in XTECBlocs.
    if (is_xtecblocs()) {
        remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
    }

    if (empty($username) || empty($password)) {
        $error = new WP_Error();

        if (empty($username)) {
            $error->add('empty_username', __('The username is empty.', 'xtec-ldap-login'));
        }
        if (empty($password)) {
            $error->add('empty_password', __('The password is empty.', 'xtec-ldap-login'));
        }

        return $error;
    }

    // Filter username to remove trailing '@xtec.cat' in case it exists.
    if (strpos($username, XTEC_DOMAIN)) {
        $username = substr($username, 0, -strlen(XTEC_DOMAIN));
    }

    // Check if user exists in wp_users.
    $user_info = get_user_by('login', $username);

    // If cannot find user_login in wp_users, look for any user with @xtec.cat e-mail
    if ($user_info === false) {
        $user_info = get_user_by('email', $username . XTEC_DOMAIN);
    }

    // In some cases always do local login (admin and @edu365.cat)
    if ($user_info &&
        ((strlen($username) > 8) ||
            ($username === 'admin') ||
            (is_xtecblocs() && preg_match("/^.+@edu365\.cat$/", $user_info->user_email)))
    ) {
        if (!wp_check_password($password, $user_info->user_pass, $user_info->ID)) {
            do_action('wp_login_failed', $username);
            return new WP_Error('incorrect_password', __('The password is not correct', 'xtec-ldap-login'));
        }

        return new WP_User($user_info->ID);
    }

    $xtec_ldap_host = get_site_option('xtec_ldap_host');
    $xtec_ldap_port = get_site_option('xtec_ldap_port');
    $xtec_ldap_version = get_site_option('xtec_ldap_version');
    $xtec_ldap_base_dn = get_site_option('xtec_ldap_base_dn');

    if ($xtec_ldap_login_type === 'LDAP') {
        // Verify credentials through LDAP.
        $ldap_conn = ldap_connect($xtec_ldap_host, $xtec_ldap_port);
        if ($ldap_conn === false) {
            return new WP_Error('ldap_connection', __('Could not connect to LDAP server', 'xtec-ldap-login'));
        }

        ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $xtec_ldap_version);

        $ldap_bind = @ldap_bind($ldap_conn, 'cn=' . $username . ',' . $xtec_ldap_base_dn, $password);

        if ($ldap_bind === false) {
            // If LDAP fails, in Nodes, this do_action activates the local login. In XTECBlocs,
            // it was previously removed, so this do_action has no effect
            do_action('wp_login_failed', $username);
            return new WP_Error('incorrect_password', __('Could not bind to the LDAP directory. The username, the password or both are not correct', 'xtec-ldap-login'));
        }

        $result = ldap_search($ldap_conn, $xtec_ldap_base_dn, '(cn=' . $username . ')', array('cn', 'sn', 'givenname', 'mail'));
        $ldap_user = ldap_get_entries($ldap_conn, $result);

        // If user does not exist in wp_users and the credentials are valid in LDAP, create the local user
        if (!$user_info && ($ldap_user['count'] === 1)) {
            // Create user using wp standard API
            $user_data = array(
                'user_pass' => $password,
                'user_login' => $username,
                'user_nicename' => $ldap_user[0]['givenname'][0] . ' ' . $ldap_user[0]['sn'][0],
                'user_email' => $ldap_user[0]['mail'][0],
                'display_name' => $ldap_user[0]['givenname'][0] . ' ' . $ldap_user[0]['sn'][0],
                'first_name' => $ldap_user[0]['givenname'][0],
                'last_name' => $ldap_user[0]['sn'][0],
            );

            // In Àgora will use the default role of WordPress
            if (is_xtecblocs()) {
                $user_data['role'] = strtolower('subscriber');
            }

            // Insert the user into the database (creates it)
            $user_id = wp_insert_user($user_data);

            // Set user metadata required for XTECBlocs
            $domain = strstr($ldap_user[0]['mail'][0], '@');
            if ($domain === XTEC_DOMAIN) {
                update_user_meta($user_id, 'xtec_user_creator', 'LDAP_XTEC');
            }

            if (is_wp_error($user_id)) {
                return new WP_Error($user_id->get_error_code(), $user_id->get_error_message());
            }

            // Do the actual validation
            return new WP_User($user_id);
        }

        if (is_multisite()) {
            // Is user marked as spam?
            if (1 === (int)$user_info->spam) {
                return new WP_Error('invalid_username', __('Your account has been marked as a spammer', 'xtec-ldap-login'));
            }
            // Is a user's blog marked as spam?
            if (!is_super_admin($user_info->ID) && isset($user_info->primary_blog)) {
                $details = get_blog_details($user_info->primary_blog);
                if (is_object($details) && (int)$details->spam === 1) {
                    return new WP_Error('blog_suspended', __('Site Suspended', 'xtec-ldap-login'));
                }
            }
        }

        $user_info = apply_filters('wp_authenticate_user', $user_info, $password);

        if (is_wp_error($user_info)) {
            return new WP_Error($user_info->get_error_code(), $user_info->get_error_message());
        }

        // Update the password if it has changed
        if (!wp_check_password($password, $user_info->user_pass, $user_info->ID)) {
            wp_update_user(['ID' => $user_info->ID, 'user_pass' => $password]);
        }

        if ($ldap_user['count'] === 1) {
            $domain = strstr($ldap_user[0]['mail'][0], '@');
            if ($domain === XTEC_DOMAIN) {
                // Ensure the user metadata is set, as it is required to create blogs in XTECBlocs
                update_user_meta($user_info->ID, 'xtec_user_creator', 'LDAP_XTEC');
            }
        }

        // Do the actual validation
    } else if (!wp_check_password($password, $user_info->user_pass, $user_info->ID)) { // get_site_option('xtec_ldap_login_type') == "Application Data Base")
        return new WP_Error('incorrect_password', sprintf(__('The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s" title="Password Lost and Found">Lost your password</a>?', 'xtec-ldap-login'), $username, site_url('wp-login.php?action=lostpassword', 'login')));
    }

    return new WP_User($user_info->ID);
}

function xtec_oauth_add_login_button()
{
    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type');
    if ($xtec_ldap_login_type === 'OAuth') {
        $client_id = get_site_option('xtec_oauth_client_id');
        $redirect_uri = site_url('/oauth-callback');
        $scope = get_site_option('xtec_oauth_client_scope');
        $auth_url = get_site_option('xtec_oauth_client_auth_url');
        $auth_url .= '&client_id=' . $client_id . '&redirect_uri=' . $redirect_uri . '&scope=' . urlencode($scope);

        echo '<a href="' . $auth_url . '" class="button button-primary button-large">' . __('XTEC Login', 'xtec-ldap-login') . '</a><br><br>';
    }
}

function xtec_oauth_handle_callback()
{
    if (get_query_var('oauth_callback')) {
        xtec_oauth_callback();
    }
}

function xtec_oauth_callback()
{
    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type');
    if ($xtec_ldap_login_type !== 'OAuth') {
        return;
    }

    if (isset($_GET['code'])) {
        $code = $_GET['code'];
        $token_url = get_site_option('xtec_oauth_client_token_url');
        $client_id = get_site_option('xtec_oauth_client_id');
        $client_secret = get_site_option('xtec_oauth_client_secret');
        $redirect_uri = site_url('/oauth-callback');

        $response = wp_remote_post($token_url, [
            'body' => [
                'grant_type' => 'authorization_code',
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'redirect_uri' => $redirect_uri,
                'code' => $code,
            ],
        ]);

        if (is_wp_error($response)) {
            wp_die(__('Error getting access token.', 'xtec-ldap-login'));
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $access_token = $body['access_token'];
        $user_info_url = get_site_option('xtec_oauth_client_user_info_url');

        $response = wp_remote_get($user_info_url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
            ],
        ]);

        if (is_wp_error($response)) {
            wp_die(__('Error getting user info.', 'xtec-ldap-login'));
        }

        $user_info = json_decode(wp_remote_retrieve_body($response), true);

        $email = $user_info['email'];
        $user = get_user_by('email', $email);

        if (!$user) {
            // User does not exist, create them.
            $username = substr($email, 0, strpos($email, '@'));

            if (empty($username)) {
                wp_die(__('Could not create user: username derived from email is empty.', 'xtec-ldap-login'));
            }

            $given_name = $user_info['given_name'] ?? '';
            $family_name = $user_info['family_name'] ?? '';

            // Create nicename as nom_cognom1_cognom2
            $nicename = $given_name . '_' . str_replace(' ', '_', $family_name);
            $nicename = sanitize_title($nicename);

            $user_data = [
                'user_login' => $username,
                'user_pass' => wp_generate_password(),
                'user_email' => $email,
                'first_name' => $given_name,
                'last_name' => $family_name,
                'display_name' => $user_info['name'] ?? '',
                'user_nicename' => $nicename,
            ];

            $user_id = wp_insert_user($user_data);

            if (is_wp_error($user_id)) {
                wp_die(__('Could not create user:', 'xtec-ldap-login') . ' ' . $user_id->get_error_message());
            }

            $user = get_user_by('id', $user_id);
        }

        if ($user instanceof \WP_User) {
            wp_set_current_user($user->ID, $user->user_login);
            wp_set_auth_cookie($user->ID);
            do_action('wp_login', $user->user_login, $user);

            wp_redirect(admin_url());
            exit;
        }

        wp_die(__('Could not log in. User could not be found or created.', 'xtec-ldap-login'));
    }
}
