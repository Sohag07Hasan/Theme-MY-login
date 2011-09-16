<?php
/*
Plugin Name: Themed Profiles
Description: Enabling this module will initialize and enable themed profiles. There are no other settings for this module.
*/

if ( !class_exists( 'Theme_My_Login_Themed_Profiles' ) ) :
/**
 * Theme My Login Themed Profiles module class
 *
 * Allows users to edit profile on the front-end.
 *
 * @since 6.0
 */
class Theme_My_Login_Themed_Profiles extends Theme_My_Login_Module {
	/**
	 * Redirects "profile.php" to themed profile page
	 *
	 * Callback for "init" hook
	 *
	 * @since 6.0
	 * @access public
	 */
	function init() {
		global $pagenow;
		if ( 'profile.php' == $pagenow && !isset( $_REQUEST['page'] ) ) {
			$redirect_to = add_query_arg( 'action', 'profile', $GLOBALS['theme_my_login']->get_login_page_link() );
			$redirect_to = add_query_arg( $_GET, $redirect_to );
			wp_redirect( $redirect_to );
			exit();
		}
	}

	/**
	 * Redirects login page to profile if user is logged in
	 *
	 * Callback for "template_redirect" hook
	 *
	 * @since 6.0
	 * @access public
	 */
	function template_redirect() {
		if ( $GLOBALS['theme_my_login']->is_login_page() ) {
			if ( 'profile' == $GLOBALS['theme_my_login']->request_action ) {
				if ( !is_user_logged_in() ) {
					// Redirect to login page if not logged in
					$redirect_to = add_query_arg( 'reauth', 1, $GLOBALS['theme_my_login']->get_login_page_link() );
					wp_redirect( $redirect_to );
					exit();
				} elseif ( $GLOBALS['theme_my_login']->request_instance ) {
					// Remove instance if instance requested
					$redirect_to = remove_query_arg( array( 'instance' ) );
					wp_redirect( $redirect_to );
					exit();
				}
			} elseif ( is_user_logged_in() && 'logout' != $GLOBALS['theme_my_login']->request_action ) {
				// Redirect to profile if trying to access login page while logged in
				$redirect_to = add_query_arg( 'action', 'profile', $GLOBALS['theme_my_login']->get_login_page_link() );
				wp_redirect( $redirect_to );
				exit();
			}
		}
	}

	/**
	 * Handles profile action
	 *
	 * Callback for "tml_request_profile" in method Theme_My_Login::the_request()
	 *
	 * @see Theme_My_Login::the_request()
	 * @since 6.0
	 * @access public
	 */
	function profile_action() {

		require_once( ABSPATH . 'wp-admin/includes/user.php' );
		require_once( ABSPATH . 'wp-admin/includes/misc.php' );
		if ( version_compare( $GLOBALS['wp_version'], '3.1', '<' ) )
			require_once( ABSPATH . WPINC . '/registration.php' );

		define( 'IS_PROFILE_PAGE', true );

		register_admin_color_schemes();

		wp_enqueue_style( 'password-strength', plugins_url( 'theme-my-login/modules/themed-profiles/themed-profiles.css' ) );

		$suffix = defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ? '.dev' : '';

		wp_enqueue_script( 'user-profile', admin_url( "js/user-profile$suffix.js" ), array( 'jquery' ), '', true );
		wp_enqueue_script( 'password-strength-meter', admin_url( "js/password-strength-meter$suffix.js" ), array( 'jquery' ), '', true );
		wp_localize_script( 'password-strength-meter', 'pwsL10n', array(
			'empty' => __( 'Strength indicator', 'theme-my-login' ),
			'short' => __( 'Very weak', 'theme-my-login' ),
			'bad' => __( 'Weak', 'theme-my-login' ),
			/* translators: password strength */
			'good' => _x( 'Medium', 'password strength', 'theme-my-login' ),
			'strong' => __( 'Strong', 'theme-my-login' ),
			'l10n_print_after' => 'try{convertEntities(pwsL10n);}catch(e){};'
		) );

		$current_user = wp_get_current_user();

		if ( 'POST' == $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'update-user_' . $current_user->ID );

			if ( !current_user_can( 'edit_user', $current_user->ID ) )
				wp_die( __( 'You do not have permission to edit this user.', 'theme-my-login' ) );

			do_action( 'personal_options_update', $current_user->ID );

			$errors = edit_user( $current_user->ID );

			if ( !is_wp_error( $errors ) ) {
				$redirect = add_query_arg( array( 'updated' => 'true' ) );
				wp_redirect( $redirect );
				exit();
			}

			$GLOBALS['theme_my_login']->errors = $errors;
		}

		if ( isset( $_GET['updated'] ) && 'true' == $_GET['updated'] )
			$GLOBALS['theme_my_login']->errors->add( 'profile_updated', __( 'Profile updated.', 'theme-my-login' ), 'message' );
	}

	/**
	 * Outputs profile form HTML
	 *
	 * Callback for "tml_template_profile" hook in method Theme_My_login_Template::display()
	 *
	 * @see Theme_My_Login_Template::display()
	 * @since 6.0
	 * @access public
	 *
	 * @param object $template Reference to $theme_my_login_template object
	 */
	function get_profile_form( &$template ) {
		$_template = array();
		// Allow template override via shortcode or template tag args
		if ( !empty( $template->options['profile_template'] ) )
			$_template[] = $template->options['profile_template'];
		// Default template
		$_template[] = 'profile-form.php';
		// Load template
		$template->get_template( $_template );
	}

	/**
	 * Changes links from "profile.php" to themed profile page
	 *
	 * Callback for "site_url" hook
	 *
	 * @see site_url()
	 * @since 6.0
	 * @access public
	 *
	 * @param string $url The generated link
	 * @param string $path The specified path
	 * @param string $orig_scheme The original connection scheme
	 * @return string The filtered link
	 */
	function site_url( $url, $path, $orig_scheme = '' ) {
		if ( strpos( $url, 'profile.php' ) !== false ) {
			$parsed_url = parse_url( $url );
			$url = add_query_arg( 'action', 'profile', $GLOBALS['theme_my_login']->get_login_page_link() );
			if ( isset( $parsed_url['query'] ) ) {
				wp_parse_str( $parsed_url['query'], $r );
				foreach ( $r as $k => $v ) {
					if ( strpos( $v, ' ' ) !== false )
						$r[$k] = rawurlencode( $v );
				}
				$url = add_query_arg( $r, $url );
			}
		}
		return $url;
	}

	/**
	 * Changes the page title for themed profile page
	 *
	 * Callback for "tml_title" hook in method Theme_My_Login_Template::get_page_title()
	 *
	 * @see Theme_My_Login_Template::get_page_title()
	 * @since 6.0
	 * @access public
	 *
	 * @param string $title The current title
	 * @param string $action The requested action
	 * @return string The filtered title
	 */
	function tml_title( $title, $action ) {
		if ( 'profile' == $action && is_user_logged_in() && '' == $GLOBALS['theme_my_login']->request_instance )
			$title = __( 'Your Profile', 'theme-my-login' );
		return $title;
	}

	/**
	 * Adds filters to site_url() and admin_url()
	 *
	 * Callback for "tml_modules_loaded" in file "theme-my-login.php"
	 *
	 * @since 6.0
	 * @access public
	 */
	function modules_loaded() {
		add_filter( 'site_url', array( &$this, 'site_url' ), 10, 3 );
		add_filter( 'admin_url', array( &$this, 'site_url' ), 10, 2 );
	}

	/**
	 * Loads the module
	 *
	 * @since 6.0
	 * @access public
	 */
	function load() {
		// Load
		add_action( 'tml_modules_loaded', array( &$this, 'modules_loaded' ) );
		add_filter( 'tml_title', array( &$this, 'tml_title' ), 10, 2 );

		add_action( 'init', array( &$this, 'init' ) );
		add_action( 'template_redirect', array( &$this, 'template_redirect' ) );

		add_action( 'tml_request_profile', array( &$this, 'profile_action' ) );
		add_action( 'tml_display_profile', array( &$this, 'get_profile_form' ) );
	}
}

/**
 * Holds the reference to Theme_My_Login_Themed_Profiles object
 * @global object $theme_my_login_themed_profiles
 * @since 6.0
 */
$theme_my_login_themed_profiles = new Theme_My_Login_Themed_Profiles();

endif; // Class exists

?>
