<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class STUH_Gripp {
	private const CONNECTION = 'stuh_gripp_connection';
	private const CACHE = 'stuh_gripp_projects';
	private const CACHE_RESOURCE = 'umbrellaproject-budget-v1';
	private const PAGE_SIZE = 250;
	private const UNIT_OPTION = 'stuh_fmp_unit';

	public static function init(): void {
		add_action( 'admin_menu', [ self::class, 'register_menu' ], 20 );
		add_action( 'admin_post_stuh_gripp_action', [ self::class, 'handle_action' ] );
		add_filter( 'set_screen_option_' . self::UNIT_OPTION, [ self::class, 'save_display_unit' ], 10, 3 );
	}

	public static function register_menu(): void {
		$hook = add_submenu_page( 'stuh', __( 'FMP', 'stuh' ), __( 'FMP', 'stuh' ), 'manage_options', 'stuh-fmp', [ self::class, 'render_dashboard' ] );
		add_action( 'load-' . $hook, [ self::class, 'register_screen_options' ] );
	}

	public static function register_screen_options(): void {
		$screen = get_current_screen();
		if ( $screen ) {
			add_filter( 'manage_' . $screen->id . '_columns', [ self::class, 'columns' ] );
			add_filter( 'screen_settings', [ self::class, 'render_screen_settings' ] );
		}
	}

	public static function render_screen_settings( string $settings ): string {
		$unit = self::display_unit( $_GET );
		$settings .= '<fieldset id="stuh-fmp-unit"><legend>' . esc_html__( 'Display budgets in', 'stuh' ) . '</legend>';
		$settings .= '<input type="hidden" name="wp_screen_options[option]" value="' . esc_attr( self::UNIT_OPTION ) . '">';
		foreach ( [ 'eur' => __( 'Euros', 'stuh' ), 'hours' => __( 'Hours', 'stuh' ) ] as $value => $label ) {
			$settings .= '<label><input type="radio" name="wp_screen_options[value]" value="' . esc_attr( $value ) . '"' . ( $unit === $value ? ' checked' : '' ) . '> ' . esc_html( $label ) . '</label> ';
		}
		$settings .= '<p>' . esc_html__( '1 hour = EUR 90. Hours are budget equivalents, not logged time; displayed amounts are rounded to two decimals.', 'stuh' ) . '</p>';
		return $settings . '<p><button type="submit" name="screen-options-apply" class="button button-primary">' . esc_html__( 'Apply', 'stuh' ) . '</button></p></fieldset>';
	}

	public static function save_display_unit( $status, string $option, $value ): string {
		self::require_admin();
		if ( ! is_string( $value ) || ! in_array( $value, [ 'eur', 'hours' ], true ) ) {
			wp_die( esc_html__( 'Invalid budget display unit.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		return $value;
	}

	public static function columns(): array {
		return [
			'number' => __( 'Number', 'stuh' ),
			'project' => __( 'Project', 'stuh' ),
			'startdate' => __( 'Start date', 'stuh' ),
			'deadline' => __( 'Deadline', 'stuh' ),
			'archived' => __( 'Archived', 'stuh' ),
			'budget' => __( 'Budget', 'stuh' ),
			'monthly' => __( 'Monthly allowance', 'stuh' ),
			'used' => __( 'Budget used', 'stuh' ),
			'remaining' => __( 'Budget left', 'stuh' ),
			'planned' => __( 'Allowance to date', 'stuh' ),
			'left_to_date' => __( 'Budget left to date', 'stuh' ),
			'schedule' => __( 'Budget schedule', 'stuh' ),
		];
	}

	private static function require_admin(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ), '', [ 'response' => 403 ] );
		}
	}

	private static function input( array $source, string $key ): string {
		return isset( $source[ $key ] ) && is_string( $source[ $key ] ) ? trim( wp_unslash( $source[ $key ] ) ) : '';
	}

	private static function settings_url(): string {
		return admin_url( 'admin.php?page=stuh-settings#stuh-gripp-settings' );
	}

	private static function dashboard_url( int $offset = 0, string $unit = 'eur' ): string {
		return add_query_arg( [ 'page' => 'stuh-fmp', 'offset' => $offset, 'unit' => $unit ], admin_url( 'admin.php' ) );
	}

	private static function display_unit( array $source ): string {
		$saved = get_user_option( self::UNIT_OPTION );
		if ( false !== $saved && '' !== $saved ) {
			if ( ! is_string( $saved ) || ! in_array( $saved, [ 'eur', 'hours' ], true ) ) {
				wp_die( esc_html__( 'Invalid saved budget display unit. Choose Euros or Hours in Screen Options.', 'stuh' ), '', [ 'response' => 400 ] );
			}
			return $saved;
		}
		$unit = self::input( $source, 'unit' );
		if ( '' === $unit && ! isset( $source['unit'] ) ) {
			return 'eur';
		}
		if ( ! in_array( $unit, [ 'eur', 'hours' ], true ) ) {
			wp_die( esc_html__( 'Invalid budget display unit.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		return $unit;
	}

	private static function offset( array $source ): int {
		$value = self::input( $source, 'offset' );
		$offset = '' === $value ? 0 : filter_var( $value, FILTER_VALIDATE_INT, [ 'options' => [ 'min_range' => 0, 'max_range' => PHP_INT_MAX - self::PAGE_SIZE ] ] );
		if ( false === $offset || $offset % self::PAGE_SIZE !== 0 ) {
			wp_die( esc_html__( 'Invalid project page.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		return $offset;
	}

	private static function configuration_error(): ?WP_Error {
		if ( ! function_exists( 'openssl_encrypt' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return new WP_Error( 'gripp_encryption', __( 'Enable PHP OpenSSL to store the Gripp API token securely.', 'stuh' ) );
		}
		return null;
	}

	private static function connection() {
		$stored = get_option( self::CONNECTION, '' );
		if ( '' === $stored ) {
			return new WP_Error( 'gripp_disconnected', __( 'Connect Gripp in Updater Host > Settings > Gripp.', 'stuh' ) );
		}
		$error = self::configuration_error();
		if ( $error ) {
			return $error;
		}
		$raw = is_string( $stored ) ? base64_decode( $stored, true ) : false;
		if ( false === $raw || strlen( $raw ) <= 28 ) {
			return new WP_Error( 'gripp_credentials', __( 'Stored Gripp credentials are invalid. Reconnect Gripp.', 'stuh' ) );
		}
		$token = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', hash( 'sha256', wp_salt( 'auth' ), true ), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ), self::CONNECTION );
		if ( false === $token || '' === $token ) {
			return new WP_Error( 'gripp_credentials', __( 'Cannot decrypt the Gripp API token. Restore the original WordPress authentication salts or reconnect Gripp.', 'stuh' ) );
		}
		return $token;
	}

	private static function save_connection( string $token ) {
		$error = self::configuration_error();
		if ( $error ) {
			return $error;
		}
		$iv = random_bytes( 12 );
		$tag = '';
		$encrypted = openssl_encrypt( $token, 'aes-256-gcm', hash( 'sha256', wp_salt( 'auth' ), true ), OPENSSL_RAW_DATA, $iv, $tag, self::CONNECTION );
		if ( false === $encrypted ) {
			return new WP_Error( 'gripp_encrypt', __( 'Could not encrypt the Gripp API token.', 'stuh' ) );
		}
		if ( ! update_option( self::CONNECTION, base64_encode( $iv . $tag . $encrypted ), false ) ) {
			return new WP_Error( 'gripp_storage', __( 'Could not save the Gripp connection.', 'stuh' ) );
		}
		delete_transient( self::CACHE );
		return true;
	}

	private static function project_date( $value, string $field ) {
		if ( null === $value || '' === $value ) {
			return '';
		}
		if ( is_array( $value ) ) {
			$value = $value['date'] ?? null;
		}
		// Gripp serializes some unset dates as PHP's normalized MySQL zero date.
		if ( is_string( $value ) && preg_match( '/^-0001-11-30 00:00:00(?:\.0{1,6})?$/D', $value ) ) {
			return '';
		}
		if ( ! is_string( $value ) || ! preg_match( '/^(\d{4})-(\d{2})-(\d{2})(?: \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)?$/D', $value, $parts ) || ! checkdate( (int) $parts[2], (int) $parts[3], (int) $parts[1] ) ) {
			return new WP_Error( 'gripp_response', sprintf( __( 'Gripp returned an invalid project date (%s).', 'stuh' ), $field ) );
		}
		return substr( $value, 0, 10 );
	}

	private static function fetch_page( string $token, string $entity, int $offset, array $filters = [] ) {
		$response = wp_remote_post( 'https://api.gripp.com/public/api3.php', [
			'timeout' => 20,
			'redirection' => 0,
			'headers' => [ 'Authorization' => 'Bearer ' . $token, 'Content-Type' => 'application/json' ],
			'body' => wp_json_encode( [ [
				'method' => $entity . '.get',
				'params' => [ $filters, [
					'paging' => [ 'firstresult' => $offset, 'maxresults' => self::PAGE_SIZE ],
					'orderings' => [ [ 'field' => $entity . '.id', 'direction' => 'asc' ] ],
				] ],
				'id' => 1,
			] ] ),
		] );
		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'gripp_network', __( 'Unable to reach Gripp. Check server connectivity and retry.', 'stuh' ) );
		}
		$status = wp_remote_retrieve_response_code( $response );
		if ( $status < 200 || $status >= 300 ) {
			return new WP_Error( 'gripp_http', sprintf( __( 'Gripp returned HTTP %d. Check the API token, permissions and rate limits, then retry.', 'stuh' ), $status ) );
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) || ! array_is_list( $data ) || 1 !== count( $data ) || ! is_array( $data[0] ) || 1 !== ( $data[0]['id'] ?? null ) ) {
			return new WP_Error( 'gripp_response', __( 'Gripp returned an invalid project response.', 'stuh' ) );
		}
		if ( ! empty( $data[0]['error'] ) ) {
			return new WP_Error( 'gripp_api', __( 'Gripp rejected the request. Check that the API role has read access to umbrella projects (Projecten / Retainers) and linked orders (Opdrachten), and that its rate limit has not been reached.', 'stuh' ) );
		}
		$result = $data[0]['result'] ?? null;
		if ( ! is_array( $result ) || ! isset( $result['rows'], $result['more_items_in_collection'] ) || ! is_array( $result['rows'] ) || ! array_is_list( $result['rows'] ) || ! is_bool( $result['more_items_in_collection'] ) || count( $result['rows'] ) > self::PAGE_SIZE ) {
			return new WP_Error( 'gripp_response', __( 'Gripp returned invalid project rows or pagination.', 'stuh' ) );
		}
		$more = $result['more_items_in_collection'];
		if ( $more && ( self::PAGE_SIZE !== count( $result['rows'] ) || ( $result['next_start'] ?? null ) !== $offset + self::PAGE_SIZE ) ) {
			return new WP_Error( 'gripp_pagination', __( 'Gripp returned inconsistent project pagination. Retry before continuing.', 'stuh' ) );
		}
		return $result;
	}

	private static function money_amount( $value, string $field ) {
		if ( ! ( is_int( $value ) || is_float( $value ) || is_string( $value ) ) || ! is_numeric( $value ) || ! is_finite( (float) $value ) || abs( (float) $value ) >= PHP_INT_MAX / 100 ) {
			return new WP_Error( 'gripp_amount', sprintf( __( 'Gripp returned an invalid amount (%s).', 'stuh' ), $field ) );
		}
		return (int) round( (float) $value * 100 );
	}

	private static function order_totals( string $token, array $ids ) {
		$totals = array_fill_keys( $ids, 0 );
		if ( ! $ids ) {
			return $totals;
		}
		$offset = 0;
		do {
			$page = self::fetch_page( $token, 'project', $offset, [ [ 'field' => 'project.umbrellaproject', 'operator' => 'in', 'value' => $ids ] ] );
			if ( is_wp_error( $page ) ) {
				return $page;
			}
			foreach ( $page['rows'] as $row ) {
				$parent = is_array( $row ) ? ( $row['umbrellaproject'] ?? null ) : null;
				$id = is_array( $parent ) ? ( $parent['id'] ?? null ) : $parent;
				if ( ! ( is_int( $id ) || is_string( $id ) ) || ! array_key_exists( $id, $totals ) ) {
					return new WP_Error( 'gripp_order', __( 'Gripp returned an order with an invalid umbrella project reference.', 'stuh' ) );
				}
				$amount = self::money_amount( $row['totalexclvat'] ?? null, 'totalexclvat' );
				if ( is_wp_error( $amount ) ) {
					return $amount;
				}
				$total = $totals[ $id ] + $amount;
				if ( ! is_int( $total ) ) {
					return new WP_Error( 'gripp_amount', __( 'The linked order total is too large to calculate safely.', 'stuh' ) );
				}
				$totals[ $id ] = $total;
			}
			$offset += self::PAGE_SIZE;
		} while ( $page['more_items_in_collection'] );
		return $totals;
	}

	private static function fetch_projects( string $token, int $offset ) {
		$result = self::fetch_page( $token, 'umbrellaproject', $offset );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$rows = [];
		foreach ( $result['rows'] as $row ) {
			if ( ! is_array( $row ) || ! isset( $row['id'], $row['name'] ) || ! is_scalar( $row['id'] ) || ! ctype_digit( (string) $row['id'] ) || ! is_string( $row['name'] ) ) {
				return new WP_Error( 'gripp_response', __( 'Gripp returned an invalid project record.', 'stuh' ) );
			}
			$project = [ 'id' => $row['id'], 'name' => $row['name'] ];
			if ( isset( $row['number'] ) && ! is_string( $row['number'] ) && ! is_int( $row['number'] ) ) {
				return new WP_Error( 'gripp_response', __( 'Gripp returned an invalid project number.', 'stuh' ) );
			}
			$project['number'] = $row['number'] ?? '';
			foreach ( [ 'startdate', 'deadline', 'archivedon' ] as $field ) {
				$date = self::project_date( $row[ $field ] ?? null, $field );
				if ( is_wp_error( $date ) ) {
					return $date;
				}
				$project[ $field ] = $date;
			}
			if ( isset( $row['archived'] ) && ! is_bool( $row['archived'] ) ) {
				return new WP_Error( 'gripp_response', __( 'Gripp returned an invalid project archive status.', 'stuh' ) );
			}
			$project['archived'] = $row['archived'] ?? ( '' !== $project['archivedon'] );
			$project['budget'] = null;
			if ( isset( $row['budget'] ) && '' !== $row['budget'] ) {
				$budget = self::money_amount( $row['budget'], 'budget' );
				if ( is_wp_error( $budget ) ) {
					return $budget;
				}
				if ( $budget < 0 ) {
					return new WP_Error( 'gripp_amount', __( 'Gripp returned a negative project budget.', 'stuh' ) );
				}
				$project['budget'] = $budget;
			}
			$rows[] = $project;
		}
		$totals = self::order_totals( $token, array_column( $rows, 'id' ) );
		if ( is_wp_error( $totals ) ) {
			return $totals;
		}
		foreach ( $rows as &$project ) {
			$project['used'] = $totals[ $project['id'] ];
		}
		unset( $project );
		return [ 'rows' => $rows, 'more' => $result['more_items_in_collection'], 'updated_at' => time() ];
	}

	private static function projects( string $token, int $offset ) {
		$fingerprint = hash( 'sha256', (string) get_option( self::CONNECTION, '' ) );
		$cache = get_transient( self::CACHE );
		if ( is_array( $cache ) && ( $cache['resource'] ?? '' ) === self::CACHE_RESOURCE && ( $cache['connection'] ?? '' ) === $fingerprint && ( $cache['offset'] ?? null ) === $offset ) {
			return $cache['data'];
		}
		$data = self::fetch_projects( $token, $offset );
		if ( ! is_wp_error( $data ) && hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
			set_transient( self::CACHE, [ 'resource' => self::CACHE_RESOURCE, 'connection' => $fingerprint, 'offset' => $offset, 'data' => $data ], 5 * MINUTE_IN_SECONDS );
		}
		return $data;
	}

	private static function finish( string $message, bool $error = false, ?int $offset = null, string $unit = 'eur' ): void {
		set_transient( 'stuh_gripp_notice_' . get_current_user_id(), [ 'message' => $message, 'error' => $error ], 5 * MINUTE_IN_SECONDS );
		wp_safe_redirect( null === $offset ? self::settings_url() : self::dashboard_url( $offset, $unit ) );
		exit;
	}

	private static function notice(): void {
		$key = 'stuh_gripp_notice_' . get_current_user_id();
		$notice = get_transient( $key );
		if ( is_array( $notice ) ) {
			delete_transient( $key );
			echo '<div class="notice ' . ( $notice['error'] ? 'notice-error' : 'notice-success' ) . '"><p>' . esc_html( $notice['message'] ) . '</p></div>';
		}
	}

	public static function handle_action(): void {
		self::require_admin();
		check_admin_referer( 'stuh_gripp' );
		switch ( self::input( $_POST, 'operation' ) ) {
			case 'connect':
				$token = self::input( $_POST, 'api_token' );
				if ( '' === $token || preg_match( '/[\x00-\x20\x7f]/', $token ) ) {
					self::finish( __( 'Enter a valid Gripp API token.', 'stuh' ), true );
				}
				$error = self::configuration_error();
				if ( $error ) {
					self::finish( $error->get_error_message(), true );
				}
				$result = self::fetch_projects( $token, 0 );
				if ( is_wp_error( $result ) ) {
					self::finish( $result->get_error_message(), true );
				}
				$saved = self::save_connection( $token );
				if ( is_wp_error( $saved ) ) {
					self::finish( $saved->get_error_message(), true );
				}
				set_transient( self::CACHE, [ 'resource' => self::CACHE_RESOURCE, 'connection' => hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ), 'offset' => 0, 'data' => $result ], 5 * MINUTE_IN_SECONDS );
				self::finish( __( 'Gripp connected. Projects are available in FMP.', 'stuh' ) );
				break;
			case 'disconnect':
				if ( '' !== get_option( self::CONNECTION, '' ) && ! delete_option( self::CONNECTION ) ) {
					self::finish( __( 'Could not remove the Gripp connection. Retry.', 'stuh' ), true );
				}
				delete_transient( self::CACHE );
				self::finish( __( 'Gripp disconnected and cached projects removed.', 'stuh' ) );
				break;
			case 'refresh':
				$offset = self::offset( $_POST );
				$unit = self::display_unit( $_POST );
				$token = self::connection();
				if ( is_wp_error( $token ) ) {
					self::finish( $token->get_error_message(), true, $offset, $unit );
				}
				delete_transient( self::CACHE );
				$result = self::projects( $token, $offset );
				self::finish( is_wp_error( $result ) ? $result->get_error_message() : __( 'Projects refreshed from Gripp.', 'stuh' ), is_wp_error( $result ), $offset, $unit );
				break;
			default:
				wp_die( esc_html__( 'Unknown Gripp action.', 'stuh' ), '', [ 'response' => 400 ] );
		}
	}

	private static function form_start( string $operation ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'stuh_gripp' );
		echo '<input type="hidden" name="action" value="stuh_gripp_action"><input type="hidden" name="operation" value="' . esc_attr( $operation ) . '">';
	}

	public static function render_settings(): void {
		self::require_admin();
		echo '<section id="stuh-gripp-settings"><h2>' . esc_html__( 'Gripp', 'stuh' ) . '</h2>';
		self::notice();
		echo '<p>' . esc_html__( 'Connect a Gripp API token with read access to umbrella projects (Projecten / Retainers) and linked orders (Opdrachten). The token stays encrypted on this host and is never sent to client sites. FMP is read-only.', 'stuh' ) . '</p>';
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			echo '<p>' . esc_html( $connection->get_error_message() ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'Gripp is connected.', 'stuh' ) . '</p>';
		}
		$error = self::configuration_error();
		if ( $error ) {
			echo '<p role="alert">' . esc_html( $error->get_error_message() ) . '</p>';
		} else {
			self::form_start( 'connect' );
			echo '<p><label for="stuh-gripp-token">' . esc_html__( 'Gripp API token', 'stuh' ) . '</label><br><input type="password" class="regular-text" id="stuh-gripp-token" name="api_token" value="" autocomplete="new-password" required></p>';
			submit_button( is_wp_error( $connection ) ? __( 'Connect Gripp', 'stuh' ) : __( 'Replace Gripp connection', 'stuh' ) );
			echo '</form>';
		}
		if ( '' !== get_option( self::CONNECTION, '' ) ) {
			self::form_start( 'disconnect' );
			submit_button( __( 'Disconnect Gripp and remove cached projects', 'stuh' ), 'secondary' );
			echo '</form>';
		}
		echo '<p><a href="' . esc_url( self::dashboard_url() ) . '">' . esc_html__( 'Open FMP', 'stuh' ) . '</a></p></section>';
	}

	private static function month_units( DateTimeImmutable $start, DateTimeImmutable $end ): float {
		if ( $end < $start ) {
			return 0.0;
		}
		$months = ( (int) $end->format( 'Y' ) - (int) $start->format( 'Y' ) ) * 12 + (int) $end->format( 'n' ) - (int) $start->format( 'n' );
		if ( 0 === $months ) {
			return ( (int) $end->format( 'j' ) - (int) $start->format( 'j' ) + 1 ) / (int) $start->format( 't' );
		}
		return $months - 1
			+ ( (int) $start->format( 't' ) - (int) $start->format( 'j' ) + 1 ) / (int) $start->format( 't' )
			+ (int) $end->format( 'j' ) / (int) $end->format( 't' );
	}

	private static function budget_schedule( array $project, DateTimeImmutable $today ) {
		if ( null === $project['budget'] ) {
			return new WP_Error( 'gripp_budget_missing', __( 'Set a budget in Gripp to calculate the budget schedule.', 'stuh' ) );
		}
		if ( '' === $project['startdate'] || '' === $project['deadline'] ) {
			return new WP_Error( 'gripp_dates_missing', __( 'Set both the start date and deadline in Gripp to calculate the monthly allowance.', 'stuh' ) );
		}
		$start = new DateTimeImmutable( $project['startdate'], $today->getTimezone() );
		$end = new DateTimeImmutable( $project['deadline'], $today->getTimezone() );
		$today = $today->setTime( 0, 0 );
		if ( $end < $start ) {
			return new WP_Error( 'gripp_dates_invalid', __( 'The deadline is before the start date. Correct the dates in Gripp.', 'stuh' ) );
		}
		$months = self::month_units( $start, $end );
		$elapsed = self::month_units( $start, $today < $end ? $today : $end );
		$planned = (int) round( $project['budget'] * min( 1, $elapsed / $months ) );
		if ( $project['used'] > $project['budget'] ) {
			$status = __( 'Over budget', 'stuh' );
		} elseif ( $today < $start ) {
			$status = $project['used'] > 0 ? __( 'Budget used before start', 'stuh' ) : __( 'Not started', 'stuh' );
		} elseif ( $today > $end ) {
			$status = __( 'Past deadline', 'stuh' );
		} elseif ( $project['used'] > $planned ) {
			$status = __( 'Ahead of budget schedule', 'stuh' );
		} elseif ( $project['used'] < $planned ) {
			$status = __( 'Behind budget schedule', 'stuh' );
		} else {
			$status = __( 'On budget schedule', 'stuh' );
		}
		return [
			'months' => $months,
			'monthly' => (int) round( $project['budget'] / $months ),
			'planned' => $planned,
			'status' => $status,
		];
	}

	private static function display_amount( int $cents, string $unit ): string {
		return 'hours' === $unit
			? sprintf( __( '%s h', 'stuh' ), number_format_i18n( $cents / 9000, 2 ) )
			: "\u{20AC}" . number_format_i18n( $cents / 100, 2 );
	}

	public static function render_dashboard(): void {
		self::require_admin();
		$offset = self::offset( $_GET );
		$unit = self::display_unit( $_GET );
		echo '<div class="wrap"><h1>' . esc_html__( 'FMP', 'stuh' ) . '</h1>';
		self::notice();
		echo '<p>' . esc_html__( 'Projecten / Retainers from Gripp, including archived umbrella projects. Individual orders (Opdrachten) are not shown.', 'stuh' ) . ' <a href="' . esc_url( self::settings_url() ) . '">' . esc_html__( 'Gripp settings', 'stuh' ) . '</a></p>';
		$token = self::connection();
		if ( is_wp_error( $token ) ) {
			echo '<p role="alert">' . esc_html( $token->get_error_message() ) . '</p></div>';
			return;
		}
		self::form_start( 'refresh' );
		echo '<input type="hidden" name="offset" value="' . esc_attr( (string) $offset ) . '"><input type="hidden" name="unit" value="' . esc_attr( $unit ) . '">';
		submit_button( __( 'Refresh projects', 'stuh' ), 'secondary' );
		echo '</form>';
		$data = self::projects( $token, $offset );
		if ( is_wp_error( $data ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $data->get_error_message() ) . '</p></div></div>';
			return;
		}
		echo '<p>' . esc_html( sprintf( __( 'Last loaded: %s. Each page is cached for up to five minutes.', 'stuh' ), wp_date( 'Y-m-d H:i', $data['updated_at'] ) ) ) . '</p>';
		echo '<p>' . esc_html__( 'Budget used is the total value of all linked orders excluding VAT, including archived orders; it is committed value, not hours or invoices. Monthly allowances use calendar months, prorating partial months by days. Allowance to date includes today in the WordPress timezone. Schedule compares budget usage, not work completed.', 'stuh' ) . '</p>';
		$today = new DateTimeImmutable( 'today', wp_timezone() );
		$current = [];
		$past = [];
		foreach ( $data['rows'] as $row ) {
			if ( '' !== $row['deadline'] && $row['deadline'] < $today->format( 'Y-m-d' ) ) {
				$past[] = $row;
			} else {
				$current[] = $row;
			}
		}
		echo '<h2 id="stuh-fmp-current-heading">' . esc_html__( 'Current projects', 'stuh' ) . '</h2>';
		self::render_projects_table( $current, $today, 'stuh-fmp-current', $unit );
		echo '<h2 id="stuh-fmp-past-heading">' . esc_html__( 'Past deadline projects', 'stuh' ) . '</h2>';
		echo '<p>' . esc_html__( 'These projects are assumed finished because their deadline has passed. Their status in Gripp is not changed.', 'stuh' ) . '</p>';
		self::render_projects_table( $past, $today, 'stuh-fmp-past', $unit );
		echo '<nav aria-label="' . esc_attr__( 'Project pages', 'stuh' ) . '"><p>';
		if ( $offset > 0 ) {
			echo '<a class="button" href="' . esc_url( self::dashboard_url( $offset - self::PAGE_SIZE, $unit ) ) . '">' . esc_html__( 'Previous projects', 'stuh' ) . '</a> ';
		}
		if ( $data['more'] ) {
			echo '<a class="button" href="' . esc_url( self::dashboard_url( $offset + self::PAGE_SIZE, $unit ) ) . '">' . esc_html__( 'Next projects', 'stuh' ) . '</a>';
		}
		echo '</p></nav></div>';
	}

	private static function project_url( int $id ): string {
		// Gripp's umbrella-project screen uses a base64-encoded navigation state.
		$state = [
			'action' => 'viewSubpage',
			'actionparams' => [
				'sn_' => [
					'n67114n' => [ 'selectedtab' => 'n67232n' ],
					'n67047n' => [ 'recordid' => $id, 'o_' => 'view', 'pinned' => [], 'showpinnedonly' => [] ],
				],
				're_' => 'n67051n',
			],
		];
		return 'https://switch.gripp.com/public/index.php?u=98237#' . base64_encode( wp_json_encode( $state ) );
	}

	private static function render_projects_table( array $rows, DateTimeImmutable $today, string $id, string $unit ): void {
		$columns = self::columns();
		$screen = get_current_screen();
		$hidden = $screen ? get_hidden_columns( $screen ) : [];
		echo '<table id="' . esc_attr( $id ) . '" aria-labelledby="' . esc_attr( $id . '-heading' ) . '" class="widefat striped"><thead><tr>';
		foreach ( $columns as $column => $heading ) {
			$header_id = 'stuh-fmp-current' === $id ? ' id="' . esc_attr( $column ) . '"' : '';
			echo '<th scope="col"' . $header_id . ' class="manage-column column-' . esc_attr( $column ) . ( in_array( $column, $hidden, true ) ? ' hidden' : '' ) . '">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$schedule = self::budget_schedule( $row, $today );
			$left_to_date = is_wp_error( $schedule ) ? null : $schedule['planned'] - $row['used'];
			$monthly = is_wp_error( $schedule ) ? __( 'Unavailable', 'stuh' ) : sprintf( __( '%1$s / month (%2$s months)', 'stuh' ), self::display_amount( $schedule['monthly'], $unit ), number_format_i18n( $schedule['months'], 2 ) );
			echo '<tr>';
			foreach ( [
				'number' => $row['number'],
				'project' => $row['name'],
				'startdate' => $row['startdate'],
				'deadline' => $row['deadline'],
				'archived' => $row['archived'] ? __( 'Yes', 'stuh' ) : __( 'No', 'stuh' ),
				'budget' => null === $row['budget'] ? __( 'Not set', 'stuh' ) : self::display_amount( $row['budget'], $unit ),
				'monthly' => $monthly,
				'used' => self::display_amount( $row['used'], $unit ),
				'remaining' => null === $row['budget'] ? __( 'Unavailable', 'stuh' ) : self::display_amount( $row['budget'] - $row['used'], $unit ),
				'planned' => is_wp_error( $schedule ) ? __( 'Unavailable', 'stuh' ) : self::display_amount( $schedule['planned'], $unit ),
				'left_to_date' => null === $left_to_date ? __( 'Unavailable', 'stuh' ) : self::display_amount( $left_to_date, $unit ),
				'schedule' => is_wp_error( $schedule ) ? $schedule->get_error_message() : $schedule['status'],
			] as $column => $value ) {
				$classes = 'column-' . $column . ( in_array( $column, $hidden, true ) ? ' hidden' : '' );
				if ( 'left_to_date' === $column ) {
					$classes .= ' stuh-budget-left-to-date';
				}
				$attributes = ' class="' . esc_attr( $classes ) . '"';
				if ( 'left_to_date' === $column && null !== $left_to_date && 0 !== $left_to_date ) {
					$attributes .= ' style="color:' . ( $left_to_date > 0 ? '#008a20' : '#b32d2e' ) . ';font-weight:600"';
				}
				$content = esc_html( '' === $value ? '-' : $value );
				if ( 'number' === $column && '' !== $value ) {
					$url = self::project_url( (int) $row['id'] );
					$content = '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">' . $content . '</a>';
				}
				echo '<td' . $attributes . '>' . $content . '</td>';
			}
			echo '</tr>';
		}
		if ( ! $rows ) {
			$visible = max( 1, count( array_diff( array_keys( $columns ), $hidden ) ) );
			echo '<tr><td class="colspanchange" colspan="' . esc_attr( (string) $visible ) . '">' . esc_html__( 'No projects found on this page.', 'stuh' ) . '</td></tr>';
		}
		echo '</tbody></table>';
	}
}
