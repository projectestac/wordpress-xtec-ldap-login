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

// Cookie with the random value that is sent to the OAuth provider and must come back in the callback
const XTEC_OAUTH_STATE_COOKIE = 'xtec_oauth_state';

add_action('init', 'xtec_ldap_login_init');
add_filter('send_password_change_email', '__return_false');

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
    add_action('login_init', 'xtec_oauth_set_state');
    add_action('login_form', 'xtec_oauth_add_login_button');

    // The callback is detected by its path, before WordPress looks for the content of the request, so that it doesn't
    // depend on the rewrite rules, which may not have been regenerated in the server
    add_action('parse_request', 'xtec_oauth_handle_callback');
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
                if (is_super_admin()) { ?>
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

    // Remove standard authentication.
    remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

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
            preg_match("/^.+@edu365\.cat$/", $user_info->user_email))
    ) {
        return xtec_ldap_local_authenticate($user_info, $username, $password);
    }

    $xtec_ldap_host = get_site_option('xtec_ldap_host');
    $xtec_ldap_port = get_site_option('xtec_ldap_port');
    $xtec_ldap_version = get_site_option('xtec_ldap_version');
    $xtec_ldap_base_dn = get_site_option('xtec_ldap_base_dn');

    if ($xtec_ldap_login_type === 'LDAP') {
        // Local users, which aren't XTEC users, can always log in with the password of the application when
        // the validation through LDAP fails.
        $is_local_user = $user_info && !xtec_ldap_is_xtec_user($user_info);

        // Without the LDAP extension of PHP, the credentials can't be verified.
        $ldap_conn = function_exists('ldap_connect') ? ldap_connect($xtec_ldap_host, $xtec_ldap_port) : false;
        if ($ldap_conn === false) {
            if ($is_local_user) {
                return xtec_ldap_local_authenticate($user_info, $username, $password);
            }
            return new WP_Error('ldap_connection', __('Could not connect to LDAP server', 'xtec-ldap-login'));
        }

        ldap_set_option($ldap_conn, LDAP_OPT_PROTOCOL_VERSION, $xtec_ldap_version);

        $ldap_bind = @ldap_bind($ldap_conn, 'cn=' . $username . ',' . $xtec_ldap_base_dn, $password);

        if ($ldap_bind === false) {
            if ($is_local_user) {
                return xtec_ldap_local_authenticate($user_info, $username, $password);
            }
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

            $user_data['role'] = 'subscriber';

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

        // The credentials are valid in LDAP, but the user doesn't exist locally and couldn't be created
        if (!$user_info) {
            return new WP_Error('invalid_username', __('Could not log in. User could not be found or created.', 'xtec-ldap-login'));
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
    } else if (!$user_info) {
        do_action('wp_login_failed', $username);
        return new WP_Error(
            'invalid_username',
            sprintf(
                __('<strong>Error:</strong> The username <strong>%s</strong> is not registered on this site. If you are unsure of your username, try your email address instead.'),
                esc_html($username)
            )
        );
    } else if (!wp_check_password($password, $user_info->user_pass, $user_info->ID)) {
        return new WP_Error(
            'incorrect_password',
            sprintf(
                __('The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s" title="Password Lost and Found">Lost your password</a>?', 'xtec-ldap-login'),
                $username,
                site_url('wp-login.php?action=lostpassword', 'login')
            )
        );
    }

    return new WP_User($user_info->ID);
}

/**
 * Validates a user with the password stored in the application.
 *
 * @param WP_User $user_info The user.
 * @param string $username User's username, as entered in the login form.
 * @param string $password User's password.
 * @return WP_Error|WP_User WP_User object if login successful, otherwise WP_Error object.
 */
function xtec_ldap_local_authenticate(WP_User $user_info, string $username, string $password)
{
    if (!wp_check_password($password, $user_info->user_pass, $user_info->ID)) {
        do_action('wp_login_failed', $username);
        return new WP_Error('incorrect_password', __('The password is not correct', 'xtec-ldap-login'));
    }

    return new WP_User($user_info->ID);
}

/**
 * Checks if a user is a XTEC user, that is, if it was registered through LDAP or OAuth or if it has a XTEC e-mail.
 *
 * @param WP_User $user_info The user.
 * @return bool True if it is a XTEC user.
 */
function xtec_ldap_is_xtec_user(WP_User $user_info): bool
{
    $creator = get_user_meta($user_info->ID, 'xtec_user_creator', true);

    return in_array($creator, ['LDAP_XTEC', 'OAUTH_XTEC'], true)
        || str_ends_with(strtolower($user_info->user_email), XTEC_DOMAIN);
}

/**
 * Adds the OAuth login button to the WordPress login form.
 *
 * This function checks if OAuth is the selected login method and, if so,
 * constructs the authorization URL and displays a login button.
 */
function xtec_oauth_add_login_button()
{
    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type');
    if ($xtec_ldap_login_type === 'OAuth') {
        $client_id = get_site_option('xtec_oauth_client_id');
        $scope = get_site_option('xtec_oauth_client_scope');
        $auth_url = get_site_option('xtec_oauth_client_auth_url');
        $auth_url .= '&client_id=' . urlencode($client_id) . '&redirect_uri=' . urlencode(xtec_oauth_redirect_uri())
            . '&scope=' . urlencode($scope) . '&state=' . urlencode(xtec_oauth_state());

        ?>
        <style>
            #xtec-buttons {
                width: fit-content;
            }

            .xtec-form-container {
                display: none;
            }

            .xtec-button-container {
                text-align: center;
                width: 230px;
                margin: 10px 0;
            }

            .xtec-button-container a {
                display: inline-flex;
                align-items: center;
                padding: 10px 20px;
                border: 1px solid #ccc;
                background-color: #fff;
                color: #555;
                text-decoration: none;
                font-size: 14px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                width: 100%;
                justify-content: center;
            }

            .xtec-button-container img {
                margin-right: 10px;
                width: 24px;
                height: 24px;
            }
        </style>

        <div id="xtec-buttons">
            <div class="xtec-button-container">
                <a href="<?php echo $auth_url; ?>">
                    <img src="<?php echo esc_url(plugins_url('images/google.png', __FILE__)); ?>" alt="Google logo"/>
                    <?php _e('Login with Google XTEC', 'xtec-ldap-login'); ?>
                </a>
            </div>
            <div class="xtec-button-container">
                <a href="#" id="password-login-link">
                    <img src="<?php echo esc_url(plugins_url('images/wordpress.png', __FILE__)); ?>" alt="WordPress logo"/>
                    <?php _e('Login with username and password', 'xtec-ldap-login'); ?>
                </a>
            </div>
        </div>

        <script>
            document.addEventListener('DOMContentLoaded', function () {
                // Move the standard form elements to a hidden container. They are moved, not copied, so that the
                // fields keep working (WordPress enables and handles them with JavaScript) and aren't duplicated.
                const loginForm = document.getElementById('loginform');
                const formContainer = document.createElement('div');
                formContainer.className = 'xtec-form-container';

                const formElements = loginForm.querySelectorAll('p, .user-pass-wrap, .forgetmenot, .submit');
                formElements.forEach(function (el) {
                    formContainer.appendChild(el);
                });
                loginForm.appendChild(formContainer);

                // Show the form when the password link is clicked
                document.getElementById('password-login-link').addEventListener('click', function (e) {
                    e.preventDefault();
                    formContainer.style.display = 'block';
                    // WordPress disables the password field while it is hidden, to prevent autofill
                    document.getElementById('user_pass').disabled = false;
                    document.getElementById('user_login').focus();
                });
            });
        </script>
        <?php
    }
}

/**
 * Returns the random value of the login with OAuth of the browser.
 *
 * @return string The value, or empty if the browser doesn't have it.
 */
function xtec_oauth_state(): string
{
    $state = $_COOKIE[XTEC_OAUTH_STATE_COOKIE] ?? '';

    return is_string($state) && preg_match('/^[a-f0-9]{32}$/', $state) ? $state : '';
}

/**
 * Keeps a random value in a cookie of the browser, before the login page is shown. The value is sent to the OAuth
 * provider, which sends it back in the callback, where it must be the same as the one of the cookie. So a callback
 * that hasn't been started in this browser, for example by another web, is rejected.
 */
function xtec_oauth_set_state(): void
{
    if (get_site_option('xtec_ldap_login_type') !== 'OAuth' || xtec_oauth_state() !== '') {
        return;
    }

    $state = bin2hex(random_bytes(16));
    // The cookie is sent when the provider redirects the browser to the callback, which is in the main site
    setcookie(XTEC_OAUTH_STATE_COOKIE, $state, [
        'expires' => time() + HOUR_IN_SECONDS,
        'path' => '/',
        'domain' => COOKIE_DOMAIN ?: '',
        'secure' => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE[XTEC_OAUTH_STATE_COOKIE] = $state;
}

/**
 * Returns the address where the OAuth provider sends the user back, which must be the same when the user is sent to
 * the provider and when the code is exchanged for the token. It must also be registered in the provider.
 *
 * @return string The address, in the main site of the network.
 */
function xtec_oauth_redirect_uri(): string
{
    return network_home_url('/oauth-callback');
}

/**
 * Handles the OAuth callback request, when the path of the request is the one of the callback, with or without a
 * slash at the end.
 */
function xtec_oauth_handle_callback(): void
{
    $path = (string)parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    $callback = (string)parse_url(xtec_oauth_redirect_uri(), PHP_URL_PATH);

    if (untrailingslashit($path) === untrailingslashit($callback)) {
        xtec_oauth_callback();
    }
}

/**
 * Processes the OAuth callback from the provider.
 *
 * This function handles the authorization code returned by the OAuth provider,
 * exchanges it for an access token, retrieves user information, and then
 * creates or logs in the user in WordPress.
 */
function xtec_oauth_callback()
{
    $xtec_ldap_login_type = get_site_option('xtec_ldap_login_type');
    if ($xtec_ldap_login_type !== 'OAuth') {
        return;
    }

    if (isset($_GET['code']) && is_string($_GET['code'])) {
        $code = $_GET['code'];

        // The callback must have been started in this browser, and the value is only used once
        $state = isset($_GET['state']) && is_string($_GET['state']) ? $_GET['state'] : '';
        $expected = xtec_oauth_state();
        setcookie(XTEC_OAUTH_STATE_COOKIE, '', ['expires' => 1, 'path' => '/', 'domain' => COOKIE_DOMAIN ?: '']);
        if ($expected === '' || !hash_equals($expected, $state)) {
            wp_die(
                esc_html__('The login could not be verified. Please try again.', 'xtec-ldap-login'),
                '',
                ['response' => 403, 'link_url' => wp_login_url(), 'link_text' => esc_html__('Log In')]
            );
        }

        $token_url = get_site_option('xtec_oauth_client_token_url');
        $client_id = get_site_option('xtec_oauth_client_id');
        $client_secret = get_site_option('xtec_oauth_client_secret');
        $redirect_uri = xtec_oauth_redirect_uri();

        $response = wp_remote_post($token_url, [
            'body' => [
                'grant_type' => 'authorization_code',
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'redirect_uri' => $redirect_uri,
                'code' => $code,
            ],
        ]);

        // The provider answers with an error if the code isn't valid, for example if it has already been used
        $body = is_wp_error($response) ? null : json_decode(wp_remote_retrieve_body($response), true);
        $access_token = is_array($body) ? ($body['access_token'] ?? '') : '';
        if (!is_string($access_token) || $access_token === '') {
            wp_die(__('Error getting access token.', 'xtec-ldap-login'));
        }

        $user_info_url = get_site_option('xtec_oauth_client_user_info_url');

        $response = wp_remote_get($user_info_url, [
            'headers' => [
                'Authorization' => 'Bearer ' . $access_token,
            ],
        ]);

        $user_info = is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200
            ? null : json_decode(wp_remote_retrieve_body($response), true);
        $email = is_array($user_info) ? ($user_info['email'] ?? '') : '';
        if (!is_string($email) || $email === '') {
            wp_die(__('Error getting user info.', 'xtec-ldap-login'));
        }

        // Restrict access to the users of the domain of XTEC, whose address has been verified by the provider. The
        // version 2 of the user info of Google says it in verified_email, and the version 3 in email_verified. Google
        // also gives the domain of the account (hd).
        $verified = $user_info['verified_email'] ?? $user_info['email_verified'] ?? false;
        $domain = ltrim(XTEC_DOMAIN, '@');
        if (
            !str_ends_with(strtolower($email), XTEC_DOMAIN)
            || ($verified !== true && $verified !== 'true')
            || (isset($user_info['hd']) && $user_info['hd'] !== $domain)
        ) {
            wp_die(__('Access is restricted to XTEC users.', 'xtec-ldap-login'));
        }

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
            // Ensure the user metadata is set, as it is required to create blogs in XTECBlocs
            update_user_meta($user->ID, 'xtec_user_creator', 'OAUTH_XTEC');

            wp_set_current_user($user->ID, $user->user_login);
            wp_set_auth_cookie($user->ID);
            do_action('wp_login', $user->user_login, $user);

            wp_redirect(admin_url('my-sites.php'));
            exit;
        }

        wp_die(__('Could not log in. User could not be found or created.', 'xtec-ldap-login'));
    }
}