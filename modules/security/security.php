<?php
/*
Plugin Name: Security
Description: Enabling this module will initialize security. You will then have to configure the settings via the "Security" tab.
*/

if ( !class_exists( 'Theme_My_Login_Security' ) ) :
/**
 * Theme My Login Custom User Links module class
 *
 * Adds options to help protect your site.
 *
 * @since 6.0
 */
class Theme_My_Login_Security extends Theme_My_Login_Module {
	/**
	 * Blocks locked users from logging in
	 *
	 * Callback for "authenticate" hook in function wp_authenticate()
	 *
	 * @see wp_authenticate()
	 * @since 6.0
	 * @access public
	 *
	 * @param WP_User $user WP_User object
	 * @param string $username Username posted
	 * @param string $password Password posted
	 * @return WP_User|WP_Error WP_User if the user can login, WP_Error otherwise
	 */
	function authenticate( $user, $username, $password ) {

		if ( !$userdata = get_user_by( 'login', $username ) )
			return;

		// Current time
		$time = time();

		if ( $this->is_user_locked( $userdata->ID ) ) {
			if ( $expiration = $this->get_user_lock_expiration( $userdata->ID ) ) {
				if ( $time > $expiration )
					$this->unlock_user( $userdata->ID );
				else
					return new WP_Error( 'locked_account', sprintf( __( '<strong>ERROR</strong>: This account has been locked because of too many failed login attempts. You may try again in %s.', 'theme-my-login' ), human_time_diff( $time, $expiration ) ) );
			} else {
				return new WP_Error( 'locked_account', __( '<strong>ERROR</strong>: This account has been locked.', 'theme-my-login' ) );
			}
		} elseif ( is_wp_error( $user ) && 'incorrect_password' == $user->get_error_code() ) {
			// Get the options
			$options = $GLOBALS['theme_my_login']->options->get_option( array( 'security', 'failed_login' ), array() );

			// Get the attempts
			$attempts = $this->get_failed_login_attempts( $userdata->ID );

			// Get the first valid attempt
			$first_attempt = reset( $attempts );

			// Get the relative duration
			$duration = $first_attempt['time'] + $this->get_seconds_from_unit( $options['threshold_duration'], $options['threshold_duration_unit'] );

			// If current time is less than relative duration time, we're still within the defensive zone
			if ( $time < $duration ) {
				// Log this attempt
				$this->add_failed_login_attempt( $userdata->ID, $time );
				// If failed attempts reach treshold, lock the account
				if ( $this->get_failed_login_attempt_count( $userdata->ID ) >= $options['threshold'] ) {
					// Create new expiration
					$expiration = $time + $this->get_seconds_from_unit( $options['lockout_duration'], $options['lockout_duration_unit'] );
					$this->lock_user( $userdata->ID, $expiration );
					return new WP_Error( 'locked_account', sprintf( __( '<strong>ERROR</strong>: This account has been locked because of too many failed login attempts. You may try again in %s.', 'theme-my-login' ), human_time_diff( $time, $expiration ) ) );
				}
			} else {
				// Clear the attempts
				$this->reset_failed_login_attempts( $userdata->ID );
				// Log this attempt
				$this->add_failed_login_attempt( $userdata->ID, $time );
			}
		}
		return $user;
	}

	/**
	 * Blocks locked users from resetting their password, if locked by admin
	 *
	 * Callback for "allow_password_reset" in method Theme_My_Login::retrieve_password()
	 *
	 * @see Theme_My_Login::retrieve_password()
	 * @since 6.0
	 * @access public
	 *
	 * @param bool $allow Default setting
	 * @param int $user_id User ID
	 * @return bool Whether to allow password reset or not
	 */
	function allow_password_reset( $allow, $user_id ) {
		if ( $this->is_user_locked( $user_id ) && !$this->get_user_lock_expiration( $user_id ) )
			$allow = false;
		return $allow;
	}

	/**
	 * Locks a user
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int|WP_User $user User ID ir WP_User object
	 * @param int $expires When the lock expires, in seconds from current time
	 */
	function lock_user( $user, $expires = 0 ) {
		if ( is_object( $user ) )
			$user = $user->ID;

		$user = (int) $user;

		do_action( 'tml_lock_user', $user );

		$security = $this->get_security_meta( $user );

		$security['is_locked'] = true;
		if ( $expires )
			$security['lock_expiration'] = absint( $expires );

		return update_user_meta( $user, 'theme_my_login_security', $security );
	}

	/**
	 * Unlocks a user
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int|WP_User $user User ID or WP_User object
	 */
	function unlock_user( $user ) {
		if ( is_object( $user ) )
			$user = $user->ID;

		$user = (int) $user;

		do_action( 'tml_unlock_user', $user );

		$security = $this->get_security_meta( $user );

		$security['is_locked'] = false;
		if ( isset( $security['lock_expiration'] ) )
			unset( $security['lock_expiration'] );
		$security['failed_login_attempts'] = array();

		return update_user_meta( $user, 'theme_my_login_security', $security );
	}

	/**
	 * Determine if a user is locked or not
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int|WP_User $user User ID or WP_User object
	 * @return bool True if user is locked, false if not
	 */
	function is_user_locked( $user ) {
		if ( is_object( $user ) )
			$user = $user->ID;

		$user = (int) $user;

		$security = $this->get_security_meta( $user );

		// If "is_locked" is not set, there is no lock
		if ( !$security['is_locked'] )
			return false;

		// If "lock_expires" is not set, there is a lock but no expiry
		if ( !$expires = $this->get_user_lock_expiration( $user ) )
			return true;

		// We have a lock with an expiry
		$time = time();
		if ( $time > $expires ) {
			$this->unlock_user( $user );
			return false;
		}

		return true;
	}

	/**
	 * Get a user's security meta
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 * @return array User's security meta
	 */
	function get_security_meta( $user_id ) {
		$defaults = array(
			'is_locked' => false,
			'failed_login_attempts' => array()
			);
		$meta = get_user_meta( $user_id, 'theme_my_login_security', true );
		if ( !is_array( $meta ) )
			$meta = array();

		return array_merge( $defaults, $meta );
	}

	/**
	 * Get a user's failed login attempts
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 * @return array User's failed login attempts
	 */
	function get_failed_login_attempts( $user_id ) {
		$security_meta = $this->get_security_meta( $user_id );
		if ( !is_array( $security_meta['failed_login_attempts'] ) )
			$security_meta['failed_login_attempts'] = array();
		return $security_meta['failed_login_attempts'];
	}

	/**
	 * Reset a user's failed login attempts
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 */
	function reset_failed_login_attempts( $user_id ) {
		$security_meta = $this->get_security_meta( $user_id );
		$security_meta['failed_login_attempts'] = array();
		return update_user_meta( $user_id, 'theme_my_login_security', $security_meta );
	}

	/**
	 * Get a user's failed login attempt count
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 * @return int Number of user's failed login attempts
	 */
	function get_failed_login_attempt_count( $user_id ) {
		return count( $this->get_failed_login_attempts( $user_id ) );
	}

	/**
	 * Add a failed login attempt to a user
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 * @param int $time Time of attempt, in seconds
	 * @param string $ip IP address of attempt
	 */
	function add_failed_login_attempt( $user_id, $time = '', $ip = '' ) {
		$security_meta = $this->get_security_meta( $user_id );
		if ( !is_array( $security_meta['failed_login_attempts'] ) )
			$security_meta['failed_login_attempts'] = array();

		$time = absint( $time );

		if ( empty( $time ) )
			$time = time();

		if ( empty( $ip ) )
			$ip = $_SERVER['REMOTE_ADDR'];

		$security_meta['failed_login_attempts'][] = array( 'time' => $time, 'ip' => $ip );

		return update_user_meta( $user_id, 'theme_my_login_security', $security_meta );
	}

	/**
	 * Get user's lock expiration time
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $user_id User ID
	 * @return int User's lock expiration time
	 */
	function get_user_lock_expiration( $user_id ) {
		$expiration = false;
		$security_meta = $this->get_security_meta( $user_id );
		if ( isset( $security_meta['lock_expiration'] ) )
			$expiration = absint( $security_meta['lock_expiration'] );
		return apply_filters( 'tml_user_lock_expiration', $expiration, $user_id );
	}

	/**
	 * Get number of secongs from days, hours and minutes
	 *
	 * @since 6.0
	 * @access public
	 *
	 * @param int $value Number of $unit
	 * @param string $unit Can be either "day", "hour" or "minute"
	 * @return int Number of seconds
	 */
	function get_seconds_from_unit( $value, $unit = 'minute' ) {
		switch ( $unit ) {
			case 'day' :
				$value = $value * 24 * 60 * 60;
				break;
			case 'hour' :
				$value = $value * 60 * 60;
				break;
			case 'minute' :
				$value = $value * 60;
				break;
		}
		return $value;
	}

	/**
	 * Initializes options for this module
	 *
	 * Callback for "tml_init_options" hook in method Theme_My_Login_Base::init_options()
	 *
	 * @see Theme_My_Login_Base::init_options()
	 * @since 6.0
	 * @access public
	 *
	 * @param array $options Options passed in from filter
	 * @return array Original $options array with module options appended
	 */
	function init_options( $options = array() ) {
		// Make sure it's an array
		$options = (array) $options;
		// Assign our options
		$options['security'] = array(
			'failed_login' => array(
				'threshold' => 5,
				'threshold_duration' => 1,
				'threshold_duration_unit' => 'hour',
				'lockout_duration' => 24,
				'lockout_duration_unit' => 'hour'
				)
			);
		return $options;
	}

	/**
	 * Loads the module
	 *
	 * @since 6.0
	 * @access public
	 */
	function load() {
		// Initialize
		add_filter( 'tml_init_options', array( &$this, 'init_options' ) );

		// Block locked users from logging in
		add_action( 'authenticate', array( &$this, 'authenticate' ), 100, 3 );
		// Block locked users from password reset
		add_filter( 'allow_password_reset', array( &$this, 'allow_password_reset' ), 10, 2 );
	}
}

/**
 * Holds the reference to Theme_My_Login_Security object
 * @global object $theme_my_login_security
 * @since 6.0
 */
$theme_my_login_security = new Theme_My_Login_Security();

if ( is_admin() )
	include_once( TML_ABSPATH . '/modules/security/admin/security-admin.php' );
	
endif; // Class exists

?>
