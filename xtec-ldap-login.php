<?php
/**
 * Plugin Name: XTEC LDAP Login
 * Plugin URI: https://github.com/projectestac/wordpress-xtec-ldap-login
 * Description: Overrides the core WordPress authentication method to allow the user authentication and registration through LDAP Server. It also changes the login screen logo and it adds an API function for a web service authentication
 * Version: 2.0
 * Author: Francesc Bassas i Toni Ginard
 * Author URI:
 */

function xtec_ldap_login_init() {
    // Localization
    load_plugin_textdomain('xtec-ldap-login', false, basename(dirname(__FILE__)) . '/languages/');

    // Check for WordPress multisite and add option to Dashboard
    if (is_multisite()) {
        add_action('network_admin_menu', 'xtec_ldap_login_network_admin_menu');
    } else {
        add_action('admin_menu', 'xtec_ldap_login_admin_menu');
    }
}

add_action('init', 'xtec_ldap_login_init');
add_filter('authenticate', 'xtec_ldap_authenticate', 10, 3); // Executed before standard filter

/**
 * Adds plugin to settings in network admin menu
 */
function xtec_ldap_login_network_admin_menu() {
    add_submenu_page('settings.php', __('LDAP Login', 'xtec-ldap-login'), __('LDAP Login', 'xtec-ldap-login'), 'manage_network_options', 'ms-ldap-login', 'xtec_ldap_login_options');
}

/**
 * Adds plugin to settings in admin menu
 */
function xtec_ldap_login_admin_menu() {
    if (is_xtecadmin()) {
        add_submenu_page('tools.php', __('LDAP Login', 'xtec-ldap-login'), __('LDAP Login', 'xtec-ldap-login'), 'manage_options', 'ldap-login', 'xtec_ldap_login_options');
    }
}

/**
 * Add plugin options form to network administration options form.
 */
function xtec_ldap_login_options() {
	if ($_GET['action'] == 'siteoptions') {
        if ($_POST['xtec_ldap_host']) {
            $xtec_ldap_host = $_POST['xtec_ldap_host'];
            update_site_option('xtec_ldap_host', $xtec_ldap_host);
        }
        if ($_POST['xtec_ldap_port']) {
            $xtec_ldap_port = $_POST['xtec_ldap_port'];
            update_site_option('xtec_ldap_port', $xtec_ldap_port);
        }
        if ($_POST['xtec_ldap_version']) {
            $xtec_ldap_version = $_POST['xtec_ldap_version'];
            update_site_option('xtec_ldap_version', $xtec_ldap_version);
        }
        if ($_POST['xtec_ldap_base_dn']) {
            $xtec_ldap_base_dn = $_POST['xtec_ldap_base_dn'];
            update_site_option('xtec_ldap_base_dn', $xtec_ldap_base_dn);
        }
        if ($_POST['xtec_ldap_login_type']) {
            $xtec_ldap_login_type = $_POST['xtec_ldap_login_type'];
            update_site_option('xtec_ldap_login_type', $xtec_ldap_login_type);
        }
        ?>
        <div id="message" class="updated"><p><?php _e('Options saved.', 'xtec-ldap-login') ?></p></div>
        <?php
    }
    ?>
    <div class="wrap">
        <?php $page = (is_multisite()) ? 'ms-ldap-login' : 'ldap-login'; ?>
        <form method="post" action="?page=<?php echo $page; ?>&action=siteoptions">
            <h2><?php _e('XTEC LDAP Login', 'xtec-ldap-login') ?></h2>
            <table class="form-table">
                <tbody>
                    <tr valign="top">
                        <th scope="row"><?php _e('LDAP Host', 'xtec-ldap-login') ?></th>
                        <td><input type="text" size="50" name="xtec_ldap_host" value="<?php echo get_site_option('xtec_ldap_host'); ?>" /></td>
                    </tr>         
                    <tr valign="top">
                        <th scope="row"><?php _e('LDAP Port', 'xtec-ldap-login') ?></th>
                        <td><input type="text" size="50" name="xtec_ldap_port" value="<?php echo get_site_option('xtec_ldap_port'); ?>" /></td>
                    </tr>        
                    <tr valign="top">
                        <th scope="row"><?php _e('LDAP Version', 'xtec-ldap-login') ?></th>
                        <td><input type="text" size="50" name="xtec_ldap_version" value="<?php echo get_site_option('xtec_ldap_version'); ?>" /></td>
                    </tr>        
                    <tr valign="top">
                        <th scope="row"><?php _e('Base DN', 'xtec-ldap-login') ?></th>
                        <td><input type="text" size="50" name="xtec_ldap_base_dn" value="<?php echo get_site_option('xtec_ldap_base_dn'); ?>" /></td>
                    </tr>        
                    <tr valign="top">
                        <th scope="row"><?php _e('Validation Type', 'xtec-ldap-login') ?></th>
                        <?php
                        if (!get_site_option('xtec_ldap_login_type')) {
                            update_site_option('xtec_ldap_login_type', 'LDAP');
                        }
                        ?>
                        <td><input type="radio" name="xtec_ldap_login_type" value="LDAP" 
                                <?php if (get_site_option('xtec_ldap_login_type') == "LDAP") { echo 'checked="checked"'; } ?>
                            /> 
                            <?php _e('LDAP', 'xtec-ldap-login'); ?>
                            <br />
                            <?php _e('The user is validated through the LDAP server. If the user enters for the first time and validates, the application registers it. First attempt to validate as user of LDAP server and then if fails attempt to validate as user of the application.', 'xtec-ldap-login'); ?>
                            <br />
                            <br><input type="radio" name="xtec_ldap_login_type" value="Application Data Base"
                                <?php if (get_site_option('xtec_ldap_login_type') == "Application Data Base") { echo 'checked="checked"'; } ?>
                            />
                            <?php _e('Application Data Base', 'xtec-ldap-login'); ?>
                            <br />
                            <?php _e('The user is validated through Application Data Base', 'xtec-ldap-login'); ?>
                            <br />
                        </td>
                    </tr>        
                </tbody>
            </table>
            <p class="submit"><input type="submit" name="submit" id="submit" class="button-primary" value="<?php _e('Save', 'xtec-ldap-login'); ?>"></p>
        </form>
    </div>
    <?php
}

/**
 * Checks a user's login information and it tries to logs them in through LDAP Server or through application database depending on plugin configuration.
 *
 * @param WP_User $user
 * @param string $username User's username
 * @param string $password User's password
 * @return WP_Error|WP_User WP_User object if login successful, otherwise WP_Error object.
 */
function xtec_ldap_authenticate($user, $username, $password) {

    if (is_a($user, 'WP_User')) {
        return $user;
    }

    // Remove standard authenticate
    remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);

    if (empty($username) || empty($password)) {
        $error = new WP_Error();

        if (empty($username))
            $error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.', 'xtec-ldap-login'));

        if (empty($password))
            $error->add('empty_password', __('<strong>ERROR</strong>: The password field is empty.', 'xtec-ldap-login'));

        return $error;
    }

    // Filter username to remove trailing '@xtec.cat' in case it exists
    if (strpos($username, '@xtec.cat')) {
        $username = substr($username, 0, -strlen('@xtec.cat'));
    }

    $userdata = get_user_by('login', $username);

    if (!$userdata || (strtolower($userdata->user_login) != strtolower($username))) {
        // No user, we attempt to create one
        $ldap = ldap_connect(get_site_option('xtec_ldap_host'), get_site_option('xtec_ldap_port'))
                or die ("Can't connect to LDAP server.");

        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, get_site_option('xtec_ldap_version'));

        $ldapbind = @ldap_bind($ldap, 'cn=' . $username . ',' . get_site_option('xtec_ldap_base_dn'), $password);

        if ($ldapbind == true) {
            $result = ldap_search($ldap, get_site_option('xtec_ldap_base_dn'), '(cn=' . $username . ')', array(LOGIN, 'sn', 'givenname', 'mail'));
            $ldapuser = ldap_get_entries($ldap, $result);

            if ($ldapuser['count'] == 1) {
                // Create user using wp standard include
                $userData = array(
                    'user_pass' => $password,
                    'user_login' => $username,
                    'user_nicename' => $ldapuser[0]['givenname'][0] . ' ' . $ldapuser[0]['sn'][0],
                    'user_email' => $ldapuser[0]['mail'][0],
                    'display_name' => $ldapuser[0]['givenname'][0] . ' ' . $ldapuser[0]['sn'][0],
                    'first_name' => $ldapuser[0]['givenname'][0],
                    'last_name' => $ldapuser[0]['sn'][0],
                    // May be necessary for blocs!
                    //'role' => strtolower('subscriber')
                );

                // Insert the user into the database (creates it)
                $user_id = wp_insert_user($userData);

                if (!is_wp_error($user_id)) {
                    // On success, get data again after user creation
                    $userdata = get_user_by('login', $username);
                } else {
                    return new WP_Error($user_id->get_error_code(), $user_id->get_error_message());
                }
            }
        } else {
            do_action('wp_login_failed', $username);
            return new WP_Error('invalid_username', '<strong>ERROR</strong>: Aquest nom d\'usuari i contrasenya no corresponen a cap usuari XTEC.');
        }
    }

    if (is_multisite()) {
        // Is user marked as spam?
        if (1 == $userdata->spam)
            return new WP_Error('invalid_username', __('<strong>ERROR</strong>: Your account has been marked as a spammer.'));

        // Is a user's blog marked as spam?
        if (!is_super_admin($userdata->ID) && isset($userdata->primary_blog)) {
            $details = get_blog_details($userdata->primary_blog);
            if (is_object($details) && $details->spam == 1) {
                return new WP_Error('blog_suspended', __('Site Suspended.'));
            }
        }
    }

    $userdata = apply_filters('wp_authenticate_user', $userdata, $password);

    if (is_wp_error($userdata)) {
        return new WP_Error($userdata->get_error_code(), $userdata->get_error_message());
    }

    if (get_site_option('xtec_ldap_login_type') == 'LDAP') {
        // Attempt to validate through LDAP
        $ldap = ldap_connect(get_site_option('xtec_ldap_host'), get_site_option('xtec_ldap_port'))
                or die("Can't connect to LDAP server.");

        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, get_site_option('xtec_ldap_version'));
        $ldapbind = @ldap_bind($ldap, 'cn=' . $username . ',' . get_site_option('xtec_ldap_base_dn'), $password);

        if ($ldapbind == false) {
            // If LDAP validation fails, check if it is a user of the application
            if (!wp_check_password($password, $userdata->user_pass, $userdata->ID)) {
                do_action('wp_login_failed', $username);
                return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.'));
            }

            // XTEC users (<=8 chars) can only log in through LDAP (exceptions: 'admin' and @edu365.cat)
            $user_info = get_user_by('login', $username);

            if ((strlen($username) > 8) || ($username == 'admin') || preg_match("/^.+@edu365\.cat$/", $user_info->user_email)) {
                return new WP_User($userdata->ID);
            } else {
                return new WP_Error('incorrect_password', __('<strong>ERROR</strong>: Incorrect password.'));
            }
        } else { // $ldapbind == true
            // Update the password if it has changed
            if (!wp_check_password($password, $userdata->user_pass, $userdata->ID)) {
                wp_update_user(array("ID" => $userdata->ID, "user_pass" => $password));
            }

            $result = ldap_search($ldap, get_site_option('xtec_ldap_base_dn'), '(cn=' . $username . ')', array('mail'));
            $ldapuser = ldap_get_entries($ldap, $result);

            if ($ldapuser['count'] == 1) {
                $domain = strstr($ldapuser[0]['mail'][0], '@');
                if ($domain == '@xtec.cat') {
                    // It's an XTEC user
                    update_user_meta($userdata->ID, 'xtec_user_creator', 'LDAP_XTEC');
                }
            }

            // Do the actual validation
            return new WP_User($userdata->ID);
        }
    } else { // get_site_option('xtec_ldap_login_type') == "Application Data Base")
        if (!wp_check_password($password, $userdata->user_pass, $userdata->ID)) {
            return new WP_Error('incorrect_password', sprintf(__('<strong>ERROR</strong>: The password you entered for the username <strong>%1$s</strong> is incorrect. <a href="%2$s" title="Password Lost and Found">Lost your password</a>?'), $username, site_url('wp-login.php?action=lostpassword', 'login')));
        }

        // Do the actual validation
        return new WP_User($userdata->ID);
    }
}

/**
 * This function is only used by xtec-external-authentication.php in XTECBlocs. 
 * Checks a user login information and tries to authenticate them in through the
 * LDAP Server or through the application database if it fails.
 *
 * @param string $username User's username
 * @param string $password User's password
 * @return '1$$usermail' if user is a XTEC user, 
 *         '2$$usermail' if user is not a XTEC user, 
 *         '101' if username's empty, 
 *         '102' if password's empty, 
 *         '103' if username's incorrect,
 *         '104' if password's incorrect.
 */
function xtec_authenticate($username, $password) {

    if ('' == $username) {
        return 101;
    }

    if ('' == $password) {
        return 102;
    }

    $user = get_userdatabylogin($username);

    if (!$user || (strtolower($user->user_login) != strtolower($username) )) {
        return 103;
    }

    if (!wp_check_password($password, $user->user_pass, $user->ID)) {
        return 104;
    } else {
        if (get_user_meta($user->ID, 'xtec_user_creator', true) == 'LDAP_XTEC') {
            return 1 . '$$' . $user->user_email;
        } else {
            return 2 . '$$' . $user->user_email;
        }
    }
}
