<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class STUH_Gripp {
	private const CONNECTION = 'stuh_gripp_connection';
	private const CACHE = 'stuh_gripp_projects';
	private const USAGE_CACHE = 'stuh_gripp_usage';
	private const ACTIVE_ORDERS_CACHE = 'stuh_gripp_active_orders';
	private const CACHE_RESOURCE = 'umbrellaproject-budget-hours-active-v3';
	private const PAGE_SIZE = 250;
	private const UNIT_OPTION = 'stuh_fmp_unit';

	public static function init(): void {
		add_action( 'admin_menu', [ self::class, 'register_menu' ], 20 );
		add_action( 'admin_post_stuh_gripp_action', [ self::class, 'handle_action' ] );
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue_assets' ] );
		add_filter( 'set_screen_option_' . self::UNIT_OPTION, [ self::class, 'save_display_unit' ], 10, 3 );
	}

	public static function enqueue_assets( string $hook ): void {
		if ( get_plugin_page_hookname( 'stuh-fmp', 'stuh' ) !== $hook || ! isset( $_GET['project_id'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$plugin = dirname( __DIR__ ) . '/switch-theme-updater-host.php';
		wp_enqueue_style( 'stuh-uplot', plugins_url( 'assets/vendor/uplot/uPlot.min.css', $plugin ), [], '1.6.32' );
		wp_enqueue_script( 'stuh-uplot', plugins_url( 'assets/vendor/uplot/uPlot.iife.min.js', $plugin ), [], '1.6.32', true );
		wp_enqueue_script( 'stuh-fmp-chart', plugins_url( 'assets/js/fmp-chart.js', $plugin ), [ 'stuh-uplot' ], (string) filemtime( dirname( __DIR__ ) . '/assets/js/fmp-chart.js' ), true );
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
		$settings .= '<p>' . esc_html__( '1 hour = EUR 90. Budget and invoice hours are equivalents; the details chart also shows actual logged time. Displayed amounts are rounded to two decimals.', 'stuh' ) . '</p>';
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
			'active_projects' => __( 'Active projects', 'stuh' ),
			'startdate' => __( 'Start date', 'stuh' ),
			'deadline' => __( 'Deadline', 'stuh' ),
			'archived' => __( 'Archived', 'stuh' ),
			'budget' => __( 'Budget', 'stuh' ),
			'monthly' => __( 'Monthly allowance', 'stuh' ),
			'used' => __( 'Budget used', 'stuh' ),
			'remaining' => __( 'Budget left', 'stuh' ),
			'planned' => __( 'Allowance to date', 'stuh' ),
			'left_to_date' => __( 'Budget left to date', 'stuh' ),
			'real_left_to_date' => __( 'Real budget left to date', 'stuh' ),
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

	private static function details_url( int $id, int $offset, string $unit ): string {
		return add_query_arg( [ 'page' => 'stuh-fmp', 'project_id' => $id, 'offset' => $offset, 'unit' => $unit ], admin_url( 'admin.php' ) );
	}

	private static function selected_project( array $source ): ?int {
		if ( ! isset( $source['project_id'] ) ) {
			return null;
		}
		$id = filter_var( self::input( $source, 'project_id' ), FILTER_VALIDATE_INT, [ 'options' => [ 'min_range' => 1 ] ] );
		if ( false === $id ) {
			wp_die( esc_html__( 'Invalid Gripp project ID.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		return $id;
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
		delete_transient( self::USAGE_CACHE );
		delete_transient( self::ACTIVE_ORDERS_CACHE );
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
			return new WP_Error( 'gripp_api', __( 'Gripp rejected the request. Check API read permissions for umbrella projects, orders, hours, invoice lines and invoices, and check the rate limit.', 'stuh' ) );
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

	private static function numeric_amount( $value, string $field ) {
		if ( ! ( is_int( $value ) || is_float( $value ) || is_string( $value ) ) || ! is_numeric( $value ) || ! is_finite( (float) $value ) || abs( (float) $value ) >= PHP_INT_MAX / 100 ) {
			return new WP_Error( 'gripp_amount', sprintf( __( 'Gripp returned an invalid amount (%s).', 'stuh' ), $field ) );
		}
		return (float) $value;
	}

	private static function money_amount( $value, string $field ) {
		$amount = self::numeric_amount( $value, $field );
		return is_wp_error( $amount ) ? $amount : (int) round( $amount * 100 );
	}

	private static function reference_id( $value ): ?int {
		$value = is_array( $value ) ? ( $value['id'] ?? null ) : $value;
		if ( ! is_int( $value ) && ! is_string( $value ) ) {
			return null;
		}
		$id = filter_var( $value, FILTER_VALIDATE_INT, [ 'options' => [ 'min_range' => 1 ] ] );
		return false === $id ? null : $id;
	}

	private static function fetch_all( string $token, string $entity, array $filters ) {
		$rows = [];
		$offset = 0;
		do {
			$page = self::fetch_page( $token, $entity, $offset, $filters );
			if ( is_wp_error( $page ) ) {
				return $page;
			}
			foreach ( $page['rows'] as $row ) {
				$id = is_array( $row ) ? self::reference_id( $row['id'] ?? null ) : null;
				if ( null === $id || isset( $rows[ $id ] ) ) {
					return new WP_Error( 'gripp_response', __( 'Gripp returned an invalid or repeated record ID.', 'stuh' ) );
				}
				$rows[ $id ] = $row;
			}
			$offset += self::PAGE_SIZE;
		} while ( $page['more_items_in_collection'] );
		return $rows;
	}

	private static function recorded_hour( array $hour, array $ids ) {
		$id = self::reference_id( $hour['offerprojectbase'] ?? null );
		if ( ! in_array( $id, $ids, true ) ) {
			return new WP_Error( 'gripp_hour', __( 'Gripp returned time for an unrelated order.', 'stuh' ) );
		}
		$amount = self::numeric_amount( $hour['amount'] ?? null, 'hour.amount' );
		$date = self::project_date( $hour['date'] ?? null, 'hour.date' );
		if ( is_wp_error( $amount ) || is_wp_error( $date ) ) {
			return is_wp_error( $amount ) ? $amount : $date;
		}
		if ( '' === $date ) {
			return new WP_Error( 'gripp_hour', __( 'Gripp returned time without a recording date.', 'stuh' ) );
		}
		return [ 'order' => $id, 'amount' => $amount, 'date' => $date ];
	}

	private static function fetch_usage( string $token, int $id ) {
		$orders = self::fetch_all( $token, 'project', [ [ 'field' => 'project.umbrellaproject', 'operator' => 'equals', 'value' => $id ] ] );
		if ( is_wp_error( $orders ) ) {
			return $orders;
		}
		foreach ( $orders as $order ) {
			if ( self::reference_id( $order['umbrellaproject'] ?? null ) !== $id ) {
				return new WP_Error( 'gripp_order', __( 'Gripp returned an unrelated order in the usage history.', 'stuh' ) );
			}
		}
		$events = [];
		$lines = self::fetch_all( $token, 'invoiceline', [
			[ 'field' => 'invoiceline.umbrellaproject', 'operator' => 'equals', 'value' => $id ],
			[ 'field' => 'invoiceline.rowtype', 'operator' => 'equals', 'value' => 'NORMAL' ],
		] );
		if ( is_wp_error( $lines ) ) {
			return $lines;
		}
		foreach ( array_chunk( array_keys( $orders ), self::PAGE_SIZE ) as $ids ) {
			$hours = self::fetch_all( $token, 'hour', [ [ 'field' => 'hour.offerprojectbase', 'operator' => 'in', 'value' => $ids ] ] );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			foreach ( $hours as $hour ) {
				$record = self::recorded_hour( $hour, $ids );
				if ( is_wp_error( $record ) ) {
					return $record;
				}
				$cents = self::money_amount( $record['amount'] * 90, 'hour.amount at EUR 90' );
				if ( is_wp_error( $cents ) ) {
					return $cents;
				}
				$events[] = [ 'date' => $record['date'], 'actual' => $cents, 'invoiced' => 0 ];
			}
			$page_lines = self::fetch_all( $token, 'invoiceline', [
				[ 'field' => 'invoiceline.project', 'operator' => 'in', 'value' => $ids ],
				[ 'field' => 'invoiceline.rowtype', 'operator' => 'equals', 'value' => 'NORMAL' ],
			] );
			if ( is_wp_error( $page_lines ) ) {
				return $page_lines;
			}
			$lines += $page_lines;
		}
		$invoice_ids = [];
		foreach ( $lines as $line ) {
			if ( self::reference_id( $line['umbrellaproject'] ?? null ) !== $id && ! isset( $orders[ self::reference_id( $line['project'] ?? null ) ] ) ) {
				return new WP_Error( 'gripp_invoice', __( 'Gripp returned an unrelated invoice line.', 'stuh' ) );
			}
			$invoice_id = self::reference_id( $line['invoice'] ?? null );
			if ( null === $invoice_id ) {
				return new WP_Error( 'gripp_invoice', __( 'Gripp returned an invoice line without a valid invoice reference.', 'stuh' ) );
			}
			$invoice_ids[ $invoice_id ] = $invoice_id;
		}
		$invoices = [];
		foreach ( array_chunk( array_values( $invoice_ids ), self::PAGE_SIZE ) as $ids ) {
			$sent = self::fetch_all( $token, 'invoice', [
				[ 'field' => 'invoice.id', 'operator' => 'in', 'value' => $ids ],
				[ 'field' => 'invoice.status', 'operator' => 'equals', 'value' => 'SENT' ],
			] );
			if ( is_wp_error( $sent ) ) {
				return $sent;
			}
			foreach ( $sent as $invoice_id => $invoice ) {
				if ( ! in_array( $invoice_id, $ids, true ) ) {
					return new WP_Error( 'gripp_invoice', __( 'Gripp returned an unrelated invoice.', 'stuh' ) );
				}
			}
			$invoices += $sent;
		}
		foreach ( $lines as $line ) {
			$invoice = $invoices[ self::reference_id( $line['invoice'] ) ] ?? null;
			if ( null === $invoice ) {
				continue;
			}
			$values = [];
			foreach ( [ 'amount', 'sellingprice', 'discount' ] as $field ) {
				$values[ $field ] = self::numeric_amount( $line[ $field ] ?? null, 'invoiceline.' . $field );
				if ( is_wp_error( $values[ $field ] ) ) {
					return $values[ $field ];
				}
			}
			$cents = self::money_amount( $values['amount'] * $values['sellingprice'] * ( 1 - $values['discount'] / 100 ), 'invoiceline.total' );
			$date = self::project_date( $invoice['date'] ?? null, 'invoice.date' );
			if ( is_wp_error( $cents ) || is_wp_error( $date ) ) {
				return is_wp_error( $cents ) ? $cents : $date;
			}
			if ( '' === $date ) {
				return new WP_Error( 'gripp_invoice', __( 'Gripp returned a sent invoice without an invoice date.', 'stuh' ) );
			}
			$events[] = [ 'date' => $date, 'actual' => 0, 'invoiced' => $cents ];
		}
		usort( $events, static fn( array $a, array $b ): int => strcmp( $a['date'], $b['date'] ) );
		return $events;
	}

	private static function usage( string $token, int $id ) {
		$fingerprint = hash( 'sha256', (string) get_option( self::CONNECTION, '' ) );
		$cache = get_transient( self::USAGE_CACHE );
		if ( is_array( $cache ) && ( $cache['connection'] ?? '' ) === $fingerprint && ( $cache['id'] ?? null ) === $id ) {
			return $cache['events'];
		}
		$events = self::fetch_usage( $token, $id );
		if ( ! is_wp_error( $events ) && hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
			set_transient( self::USAGE_CACHE, [ 'connection' => $fingerprint, 'id' => $id, 'events' => $events ], 5 * MINUTE_IN_SECONDS );
		}
		return $events;
	}

	private static function order_totals( string $token, array $ids, ?array &$recorded = null, ?array &$active = null ) {
		$totals = array_fill_keys( $ids, 0 );
		if ( null !== $active ) {
			$active = array_fill_keys( $ids, 0 );
		}
		$parents = [];
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
				if ( null !== $active ) {
					if ( ! isset( $row['archived'] ) || ! is_bool( $row['archived'] ) ) {
						return new WP_Error( 'gripp_order', __( 'Gripp returned an invalid linked project archive status.', 'stuh' ) );
					}
					if ( ! $row['archived'] ) {
						$active[ $id ]++;
					}
				}
				if ( null !== $recorded ) {
					$order_id = self::reference_id( $row['id'] ?? null );
					if ( null === $order_id || isset( $parents[ $order_id ] ) ) {
						return new WP_Error( 'gripp_order', __( 'Gripp returned an invalid or repeated linked order ID.', 'stuh' ) );
					}
					$parents[ $order_id ] = $id;
				}
			}
			$offset += self::PAGE_SIZE;
		} while ( $page['more_items_in_collection'] );
		if ( null !== $recorded ) {
			$hours = self::order_hours( $token, array_keys( $parents ) );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			$recorded = array_fill_keys( $ids, 0.0 );
			$compensation = array_fill_keys( $ids, 0.0 );
			foreach ( $hours as $order_id => $amount ) {
				$parent = $parents[ $order_id ];
				$adjusted = $amount - $compensation[ $parent ];
				$total = $recorded[ $parent ] + $adjusted;
				$compensation[ $parent ] = ( $total - $recorded[ $parent ] ) - $adjusted;
				$recorded[ $parent ] = $total;
			}
			foreach ( $recorded as &$amount ) {
				$amount = self::money_amount( $amount * 90, 'logged hours at EUR 90' );
				if ( is_wp_error( $amount ) ) {
					return $amount;
				}
			}
			unset( $amount );
		}
		return $totals;
	}

	private static function active_orders( string $token, int $id ) {
		$fingerprint = hash( 'sha256', (string) get_option( self::CONNECTION, '' ) );
		$cache = get_transient( self::ACTIVE_ORDERS_CACHE );
		if ( is_array( $cache ) && ( $cache['version'] ?? null ) === 2 && ( $cache['connection'] ?? '' ) === $fingerprint && ( $cache['id'] ?? null ) === $id ) {
			return $cache['rows'];
		}
		$orders = self::fetch_all( $token, 'project', [
			[ 'field' => 'project.umbrellaproject', 'operator' => 'equals', 'value' => $id ],
			[ 'field' => 'project.archived', 'operator' => 'equals', 'value' => false ],
		] );
		if ( is_wp_error( $orders ) ) {
			return $orders;
		}
		$rows = [];
		foreach ( $orders as $order_id => $order ) {
			if ( self::reference_id( $order['umbrellaproject'] ?? null ) !== $id || false !== ( $order['archived'] ?? null ) || ! isset( $order['name'] ) || ! is_string( $order['name'] ) || ( isset( $order['number'] ) && ! is_string( $order['number'] ) && ! is_int( $order['number'] ) ) ) {
				return new WP_Error( 'gripp_order', __( 'Gripp returned an invalid active project or umbrella project reference.', 'stuh' ) );
			}
			$row = [ 'id' => $order_id, 'number' => $order['number'] ?? '', 'name' => $order['name'] ];
			$row['value'] = self::money_amount( $order['totalexclvat'] ?? null, 'project.totalexclvat' );
			if ( is_wp_error( $row['value'] ) ) {
				return $row['value'];
			}
			$rows[] = $row;
		}
		$hours = self::order_hours( $token, array_keys( $orders ) );
		if ( is_wp_error( $hours ) ) {
			return $hours;
		}
		foreach ( $rows as &$row ) {
			$row['hours'] = $hours[ $row['id'] ];
		}
		unset( $row );
		if ( hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
			set_transient( self::ACTIVE_ORDERS_CACHE, [ 'version' => 2, 'connection' => $fingerprint, 'id' => $id, 'rows' => $rows ], 5 * MINUTE_IN_SECONDS );
		}
		return $rows;
	}

	private static function order_hours( string $token, array $ids ) {
		$totals = array_fill_keys( $ids, 0.0 );
		$compensation = array_fill_keys( $ids, 0.0 );
		$today = ( new DateTimeImmutable( 'today', wp_timezone() ) )->format( 'Y-m-d' );
		foreach ( array_chunk( $ids, self::PAGE_SIZE ) as $chunk ) {
			$hours = self::fetch_all( $token, 'hour', [ [ 'field' => 'hour.offerprojectbase', 'operator' => 'in', 'value' => $chunk ] ] );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			foreach ( $hours as $hour ) {
				$record = self::recorded_hour( $hour, $chunk );
				if ( is_wp_error( $record ) ) {
					return $record;
				}
				if ( $record['date'] > $today ) {
					continue;
				}
				$id = $record['order'];
				// Compensate floating-point error before rounding fractional hours for display.
				$adjusted = $record['amount'] - $compensation[ $id ];
				$total = $totals[ $id ] + $adjusted;
				if ( ! is_finite( $total ) ) {
					return new WP_Error( 'gripp_amount', __( 'The recorded hours total is too large to calculate safely.', 'stuh' ) );
				}
				$compensation[ $id ] = ( $total - $totals[ $id ] ) - $adjusted;
				$totals[ $id ] = $total;
			}
		}
		return $totals;
	}

	private static function fetch_projects( string $token, int $offset, array $filters = [] ) {
		$result = self::fetch_page( $token, 'umbrellaproject', $offset, $filters );
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
		$recorded = [];
		$active = [];
		$totals = self::order_totals( $token, array_column( $rows, 'id' ), $recorded, $active );
		if ( is_wp_error( $totals ) ) {
			return $totals;
		}
		foreach ( $rows as &$project ) {
			$project['used'] = $totals[ $project['id'] ];
			$project['recorded'] = $recorded[ $project['id'] ];
			$project['active_projects'] = $active[ $project['id'] ];
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
				delete_transient( self::USAGE_CACHE );
				delete_transient( self::ACTIVE_ORDERS_CACHE );
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
				delete_transient( self::USAGE_CACHE );
				delete_transient( self::ACTIVE_ORDERS_CACHE );
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
		echo '<p>' . esc_html__( 'Connect a Gripp API token with read access to umbrella projects (Projecten / Retainers), linked orders (Opdrachten), hours, invoice lines and invoices. The token stays encrypted on this host and is never sent to client sites. FMP is read-only.', 'stuh' ) . '</p>';
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

	private static function budget_chart_data( array $project ) {
		$timezone = wp_timezone();
		$schedule = self::budget_schedule( $project, new DateTimeImmutable( 'today', $timezone ) );
		if ( is_wp_error( $schedule ) ) {
			return $schedule;
		}
		$start = new DateTimeImmutable( $project['startdate'], $timezone );
		$end = new DateTimeImmutable( $project['deadline'], $timezone );
		$points = [ [ 'date' => $project['startdate'], 'months' => 0.0, 'allocated' => 0, 'cumulative' => 0 ] ];
		$cursor = $start;
		$previous = 0;
		while ( $cursor <= $end ) {
			$month_end = $cursor->modify( 'last day of this month' );
			if ( $month_end > $end ) {
				$month_end = $end;
			}
			$months = self::month_units( $start, $month_end );
			$cumulative = (int) round( $project['budget'] * $months / $schedule['months'] );
			$points[] = [
				'date' => $month_end->format( 'Y-m-d' ),
				'months' => $months,
				'allocated' => $cumulative - $previous,
				'cumulative' => $cumulative,
			];
			$previous = $cumulative;
			$cursor = $month_end->modify( '+1 day' );
		}
		return [ 'schedule' => $schedule, 'points' => $points ];
	}

	private static function usage_chart_data( array $project, array $chart, array $events, DateTimeImmutable $today ) {
		$timezone = $today->getTimezone();
		$today = $today->setTime( 0, 0 );
		$events = array_values( array_filter( $events, static fn( array $event ): bool => $event['date'] <= $today->format( 'Y-m-d' ) ) );
		$start = new DateTimeImmutable( $project['startdate'], $timezone );
		$end = new DateTimeImmutable( $project['deadline'], $timezone );
		if ( $events ) {
			$start = min( $start, new DateTimeImmutable( $events[0]['date'], $timezone ) );
			$end = max( $end, new DateTimeImmutable( $events[ count( $events ) - 1 ]['date'], $timezone ) );
		}
		$chart['months'] = self::month_units( $start, $end );
		foreach ( $chart['points'] as $index => &$point ) {
			$date = new DateTimeImmutable( $point['date'], $timezone );
			$point['months'] = self::month_units( $start, 0 === $index ? $date->modify( '-1 day' ) : $date );
		}
		unset( $point );
		$chart['axis'] = [];
		$cursor = $start;
		while ( $cursor <= $end ) {
			$date = min( $cursor->modify( 'last day of this month' ), $end );
			$chart['axis'][] = [ 'date' => $date->format( 'Y-m-d' ), 'months' => self::month_units( $start, $date ) ];
			$cursor = $date->modify( '+1 day' );
		}
		$cutoff = min( $today, $end );
		$chart['usage'] = [];
		$chart['actual'] = 0;
		$chart['invoiced'] = 0;
		if ( $cutoff < $start ) {
			return $chart;
		}
		$chart['usage'][] = [ 'date' => $start->format( 'Y-m-d' ), 'months' => 0.0, 'actual' => 0, 'invoiced' => 0 ];
		$dates = array_column( array_filter( $chart['axis'], static fn( array $point ): bool => $point['date'] < $cutoff->format( 'Y-m-d' ) ), 'date' );
		$dates[] = $cutoff->format( 'Y-m-d' );
		$index = 0;
		foreach ( $dates as $date ) {
			while ( isset( $events[ $index ] ) && $events[ $index ]['date'] <= $date ) {
				foreach ( [ 'actual', 'invoiced' ] as $field ) {
					$total = $chart[ $field ] + $events[ $index ][ $field ];
					if ( ! is_int( $total ) ) {
						return new WP_Error( 'gripp_amount', __( 'The usage history total is too large to calculate safely.', 'stuh' ) );
					}
					$chart[ $field ] = $total;
				}
				$index++;
			}
			$chart['usage'][] = [
				'date' => $date,
				'months' => self::month_units( $start, new DateTimeImmutable( $date, $timezone ) ),
				'actual' => $chart['actual'],
				'invoiced' => $chart['invoiced'],
			];
		}
		return $chart;
	}

	private static function render_project_details( int $id, int $offset, string $unit ): void {
		$token = self::connection();
		$data = is_wp_error( $token ) ? $token : self::projects( $token, $offset );
		$project = null;
		if ( ! is_wp_error( $data ) ) {
			foreach ( $data['rows'] as $row ) {
				if ( (int) $row['id'] === $id ) {
					$project = $row;
					break;
				}
			}
			if ( null === $project ) {
				$data = self::fetch_projects( $token, 0, [ [ 'field' => 'umbrellaproject.id', 'operator' => 'equals', 'value' => $id ] ] );
				if ( ! is_wp_error( $data ) ) {
					foreach ( $data['rows'] as $row ) {
						if ( (int) $row['id'] === $id ) {
							$project = $row;
							break;
						}
					}
					if ( null === $project ) {
						wp_die( esc_html__( 'Gripp project not found or no longer accessible.', 'stuh' ), '', [ 'response' => 404 ] );
					}
				}
			}
		}
		echo '<div class="wrap"><p><a class="button" href="' . esc_url( self::dashboard_url( $offset, $unit ) ) . '">' . esc_html__( 'Back to FMP', 'stuh' ) . '</a></p>';
		if ( is_wp_error( $data ) ) {
			echo '<h1>' . esc_html__( 'FMP project details', 'stuh' ) . '</h1><div class="notice notice-error inline"><p>' . esc_html( $data->get_error_message() ) . '</p></div></div>';
			return;
		}
		echo '<h1>' . esc_html( $project['name'] ) . '</h1>';
		echo '<p><a href="' . esc_url( self::project_url( $id ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Open in Gripp', 'stuh' ) . ' ' . esc_html( $project['number'] ) . '</a></p>';
		self::notice();
		$chart = self::budget_chart_data( $project );
		$usage = is_wp_error( $chart ) ? null : self::usage( $token, $id );
		if ( is_array( $usage ) ) {
			$chart = self::usage_chart_data( $project, $chart, $usage, new DateTimeImmutable( 'today', wp_timezone() ) );
		}
		echo '<dl class="stuh-fmp-summary">';
		foreach ( [
			__( 'Budget', 'stuh' ) => null === $project['budget'] ? __( 'Not set', 'stuh' ) : self::display_amount( $project['budget'], $unit ),
			__( 'Monthly allowance', 'stuh' ) => is_wp_error( $chart ) ? __( 'Unavailable', 'stuh' ) : self::display_amount( $chart['schedule']['monthly'], $unit ),
			__( 'Committed order value', 'stuh' ) => self::display_amount( $project['used'], $unit ),
			__( 'Budget left', 'stuh' ) => null === $project['budget'] ? __( 'Unavailable', 'stuh' ) : self::display_amount( $project['budget'] - $project['used'], $unit ),
			__( 'Actual recorded time', 'stuh' ) => is_wp_error( $chart ) || ! isset( $chart['actual'] ) ? __( 'Unavailable', 'stuh' ) : self::display_amount( $chart['actual'], $unit ),
			__( 'Invoiced value', 'stuh' ) => is_wp_error( $chart ) || ! isset( $chart['invoiced'] ) ? __( 'Unavailable', 'stuh' ) : self::display_amount( $chart['invoiced'], $unit ),
		] as $label => $value ) {
			echo '<div><dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( $value ) . '</dd></div>';
		}
		echo '</dl><p>' . esc_html( sprintf( __( 'Project period: %1$s to %2$s (inclusive).', 'stuh' ), $project['startdate'] ?: '-', $project['deadline'] ?: '-' ) ) . '</p>';
		if ( is_wp_error( $chart ) ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( $chart->get_error_message() ) . '</p></div>';
		} else {
			if ( is_wp_error( $usage ) ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html( $usage->get_error_message() ) . '</p></div>';
			}
			self::render_budget_chart( $project, $chart, $unit );
		}
		self::render_active_orders( $token, $id, $unit );
		echo '</div>';
	}

	private static function render_active_orders( string $token, int $id, string $unit ): void {
		echo '<h2 id="stuh-fmp-active-heading">' . esc_html__( 'Active projects', 'stuh' ) . '</h2>';
		echo '<p>' . esc_html__( 'Non-archived projects (Opdrachten) linked to this umbrella project. Actual hours include all recorded time through today, including Concept entries and zero-value work, and always display as hours.', 'stuh' ) . '</p>';
		$rows = self::active_orders( $token, $id );
		if ( is_wp_error( $rows ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $rows->get_error_message() ) . '</p></div>';
			return;
		}
		echo '<div class="stuh-analytics-line-scroll" role="region" tabindex="0" aria-labelledby="stuh-fmp-active-heading"><table id="stuh-fmp-active-projects" class="widefat striped" aria-labelledby="stuh-fmp-active-heading"><thead><tr>';
		foreach ( [ __( 'Number', 'stuh' ), __( 'Project', 'stuh' ), __( 'Actual hours', 'stuh' ), __( 'Order value (excl. VAT)', 'stuh' ) ] as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$number = '' === $row['number'] ? '-' : '<a href="' . esc_url( self::order_url( $row['id'] ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $row['number'] ) . '</a>';
			echo '<tr><td>' . $number . '</td>';
			foreach ( [ $row['name'], sprintf( __( '%s h', 'stuh' ), number_format_i18n( $row['hours'], 2 ) ), self::display_amount( $row['value'], $unit ) ] as $value ) {
				echo '<td>' . esc_html( $value ) . '</td>';
			}
			echo '</tr>';
		}
		if ( ! $rows ) {
			echo '<tr><td colspan="4">' . esc_html__( 'No active projects linked to this umbrella project.', 'stuh' ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	private static function render_budget_chart( array $project, array $chart, string $unit ): void {
		$title = __( 'Budget over time', 'stuh' );
		$axis = $chart['axis'] ?? array_slice( $chart['points'], 1 );
		$months = $chart['months'] ?? $chart['schedule']['months'];
		$width = max( 960, ( count( $axis ) + 1 ) * 70 + 150 );
		$left = 110;
		$right = $width - 40;
		$values = array_merge( [ 0, $project['budget'] ], array_column( $chart['usage'] ?? [], 'actual' ), array_column( $chart['usage'] ?? [], 'invoiced' ) );
		$minimum = min( $values );
		$maximum = max( 'hours' === $unit ? 9000 : 100, max( $values ) );
		$x_position = static fn( float $value ): string => number_format( $left + $value / $months * ( $right - $left ), 2, '.', '' );
		$y_position = static fn( int $value ): string => number_format( 300 - ( $value - $minimum ) / ( $maximum - $minimum ) * 240, 2, '.', '' );
		$budget_y = $y_position( $project['budget'] );
		$zero_y = $y_position( 0 );
		$timestamp = static fn( string $date, bool $end ): int => ( new DateTimeImmutable( $date, new DateTimeZone( 'UTC' ) ) )->setTime( $end ? 23 : 0, $end ? 59 : 0, $end ? 59 : 0 )->getTimestamp();
		$coordinates = static function( array $points, string $field ) use ( $timestamp ): array {
			$values = [];
			foreach ( $points as $index => $point ) {
				$values[] = [ $timestamp( $point['date'], 0 !== $index ), $point[ $field ] ];
			}
			return $values;
		};
		$start_date = $chart['usage'][0]['date'] ?? $project['startdate'];
		$end_date = $axis[ count( $axis ) - 1 ]['date'];
		$interactive = [
			'unit' => $unit,
			'xLabel' => __( 'Months', 'stuh' ),
			'yLabel' => 'hours' === $unit ? __( 'Budget (hours)', 'stuh' ) : __( 'Budget (EUR)', 'stuh' ),
			'dateLabel' => __( 'Through date', 'stuh' ),
			'series' => [
				[ 'label' => __( 'Total project budget', 'stuh' ), 'stroke' => '#646970', 'dash' => [ 6, 4 ], 'points' => [ [ $timestamp( $start_date, false ), $project['budget'] ], [ $timestamp( $end_date, true ), $project['budget'] ] ] ],
				[ 'label' => __( 'Accumulated monthly allowance', 'stuh' ), 'stroke' => '#2271b1', 'dash' => [], 'points' => $coordinates( $chart['points'], 'cumulative' ) ],
			],
		];
		if ( isset( $chart['usage'] ) ) {
			$interactive['series'][] = [ 'label' => __( 'Actual recorded time', 'stuh' ), 'stroke' => '#d63638', 'dash' => [], 'points' => $coordinates( $chart['usage'], 'actual' ) ];
			$interactive['series'][] = [ 'label' => __( 'Invoiced value', 'stuh' ), 'stroke' => '#008a20', 'dash' => [ 8, 4 ], 'points' => $coordinates( $chart['usage'], 'invoiced' ) ];
		}
		echo '<figure class="stuh-analytics-chart stuh-analytics-history stuh-fmp-budget-chart" data-stuh-fmp-chart="' . esc_attr( wp_json_encode( $interactive ) ) . '"><figcaption><h2>' . esc_html( $title ) . '</h2></figcaption>';
		echo '<ul class="stuh-analytics-legend"><li class="stuh-analytics-legend--previous">' . esc_html__( 'Total project budget', 'stuh' ) . '</li><li>' . esc_html__( 'Accumulated monthly allowance', 'stuh' ) . '</li>';
		if ( isset( $chart['usage'] ) ) {
			echo '<li class="stuh-fmp-legend-actual">' . esc_html__( 'Actual recorded time', 'stuh' ) . '</li><li class="stuh-fmp-legend-invoiced">' . esc_html__( 'Invoiced value', 'stuh' ) . '</li>';
		}
		echo '</ul><p>' . esc_html__( 'The horizontal line is the total budget. Blue accumulates the monthly allowance, prorating partial months by days.', 'stuh' ) . '</p>';
		if ( isset( $chart['usage'] ) ) {
			echo '<p>' . esc_html__( 'Red shows all recorded time, including Concept entries and time on zero-value orders, valued at EUR 90 per hour. Dashed green shows sent invoice lines excluding VAT, after discounts and credits, on their invoice dates. Invoice hours are value divided by EUR 90, not recorded or billable hours. Usage lines show monthly cumulative totals through today, without forecasting; dates outside the project period extend the chart. Dashboard budget-left figures still use committed order value.', 'stuh' ) . '</p>';
		} else {
			echo '<p>' . esc_html__( 'Recorded time and invoiced usage are unavailable; only planned budget lines are shown.', 'stuh' ) . '</p>';
		}
		echo '<p class="notice notice-warning inline" data-stuh-fmp-chart-error hidden>' . esc_html__( 'The interactive chart could not load. The static chart and data tables remain available.', 'stuh' ) . '</p>';
		echo '<div data-stuh-fmp-interactive hidden><p id="stuh-fmp-zoom-help">' . esc_html__( 'Drag horizontally across a period to zoom in. Use Reset zoom to restore the full period.', 'stuh' ) . '</p>';
		echo '<p><button type="button" class="button" data-stuh-fmp-reset disabled>' . esc_html__( 'Reset zoom', 'stuh' ) . '</button> <span data-stuh-fmp-range role="status" aria-live="polite"></span></p>';
		echo '<div class="stuh-fmp-interactive-plot" data-stuh-fmp-plot role="region" tabindex="0" aria-label="' . esc_attr( $title ) . '" aria-describedby="stuh-fmp-zoom-help"></div></div>';
		echo '<div class="stuh-analytics-line-scroll" data-stuh-fmp-static tabindex="0" role="region" aria-label="' . esc_attr( $title ) . '"><svg class="stuh-analytics-line-chart stuh-fmp-budget-svg" viewBox="0 0 ' . esc_attr( (string) $width ) . ' 380" style="min-width:' . esc_attr( (string) $width ) . 'px" role="img" aria-labelledby="stuh-fmp-chart-title stuh-fmp-chart-desc">';
		echo '<title id="stuh-fmp-chart-title">' . esc_html( $title ) . '</title><desc id="stuh-fmp-chart-desc">' . esc_html__( 'Dashed grey: total budget. Blue: accumulated monthly allowance. When available, red: recorded time; dashed green: invoiced value. Exact figures are available in the tables below.', 'stuh' ) . '</desc>';
		for ( $tick = 0; $tick <= 4; $tick++ ) {
			$y = 300 - $tick * 60;
			echo '<line class="stuh-analytics-gridline" x1="' . $left . '" y1="' . $y . '" x2="' . esc_attr( (string) $right ) . '" y2="' . $y . '"/><text x="100" y="' . ( $y + 4 ) . '" text-anchor="end">' . esc_html( self::display_amount( (int) round( $minimum + ( $maximum - $minimum ) * $tick / 4 ), $unit ) ) . '</text>';
		}
		echo '<text transform="translate(22 180) rotate(-90)" text-anchor="middle">' . esc_html( 'hours' === $unit ? __( 'Budget (hours)', 'stuh' ) : __( 'Budget (EUR)', 'stuh' ) ) . '</text>';
		echo '<text x="' . esc_attr( (string) ( ( $left + $right ) / 2 ) ) . '" y="365" text-anchor="middle">' . esc_html__( 'Months', 'stuh' ) . '</text>';
		$points = [];
		$dots = '';
		foreach ( $axis as $point ) {
			$date = new DateTimeImmutable( $point['date'], wp_timezone() );
			echo '<text x="' . esc_attr( $x_position( $point['months'] ) ) . '" y="327" text-anchor="middle">' . esc_html( wp_date( 'M Y', $date->getTimestamp(), wp_timezone() ) ) . '</text>';
		}
		foreach ( $chart['points'] as $point ) {
			$x = $x_position( $point['months'] );
			$y = $y_position( $point['cumulative'] );
			$points[] = $x . ',' . $y;
			$dots .= '<circle cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="4"><title>' . esc_html( $point['date'] . ': ' . self::display_amount( $point['cumulative'], $unit ) ) . '</title></circle>';
		}
		echo '<polygon class="stuh-fmp-budget-area" points="' . esc_attr( $x_position( $chart['points'][0]['months'] ) . ',' . $zero_y . ' ' . implode( ' ', $points ) . ' ' . $x_position( $chart['points'][ count( $chart['points'] ) - 1 ]['months'] ) . ',' . $zero_y ) . '"/>';
		echo '<line class="stuh-fmp-budget-limit" x1="' . $left . '" y1="' . esc_attr( $budget_y ) . '" x2="' . esc_attr( (string) $right ) . '" y2="' . esc_attr( $budget_y ) . '"/>';
		echo '<g class="stuh-analytics-series"><polyline class="stuh-fmp-budget-cumulative" points="' . esc_attr( implode( ' ', $points ) ) . '"/>' . $dots . '</g>';
		foreach ( [ 'actual' => __( 'Actual recorded time', 'stuh' ), 'invoiced' => __( 'Invoiced value', 'stuh' ) ] as $field => $label ) {
			$points = [];
			$dots = '';
			foreach ( $chart['usage'] ?? [] as $point ) {
				$x = $x_position( $point['months'] );
				$y = $y_position( $point[ $field ] );
				$points[] = $x . ',' . $y;
				$dots .= '<circle cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="4"><title>' . esc_html( $point['date'] . ' - ' . $label . ': ' . self::display_amount( $point[ $field ], $unit ) ) . '</title></circle>';
			}
			if ( $points ) {
				echo '<g class="stuh-analytics-series stuh-fmp-series-' . esc_attr( $field ) . '"><polyline points="' . esc_attr( implode( ' ', $points ) ) . '"/>' . $dots . '</g>';
			}
		}
		echo '</svg></div>';
		echo '<details class="stuh-analytics-monthly-data"><summary>' . esc_html__( 'View monthly values', 'stuh' ) . '</summary><table class="widefat striped"><thead><tr>';
		foreach ( [ __( 'Through date', 'stuh' ), __( 'Monthly allowance', 'stuh' ), __( 'Accumulated allowance', 'stuh' ) ] as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $chart['points'] as $index => $point ) {
			echo '<tr><th scope="row">' . esc_html( $point['date'] . ( 0 === $index ? ' (' . __( 'Start', 'stuh' ) . ')' : '' ) ) . '</th><td>' . esc_html( self::display_amount( $point['allocated'], $unit ) ) . '</td><td>' . esc_html( self::display_amount( $point['cumulative'], $unit ) ) . '</td></tr>';
		}
		echo '</tbody></table>';
		if ( isset( $chart['usage'] ) ) {
			echo '<h3>' . esc_html__( 'Recorded and invoiced usage', 'stuh' ) . '</h3><table class="widefat striped"><thead><tr>';
			foreach ( [ __( 'Through date', 'stuh' ), __( 'Actual recorded time', 'stuh' ), __( 'Invoiced value', 'stuh' ) ] as $heading ) {
				echo '<th scope="col">' . esc_html( $heading ) . '</th>';
			}
			echo '</tr></thead><tbody>';
			foreach ( $chart['usage'] as $index => $point ) {
				echo '<tr><th scope="row">' . esc_html( $point['date'] . ( 0 === $index ? ' (' . __( 'Start; before usage', 'stuh' ) . ')' : '' ) ) . '</th><td>' . esc_html( self::display_amount( $point['actual'], $unit ) ) . '</td><td>' . esc_html( self::display_amount( $point['invoiced'], $unit ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</details></figure>';
	}

	public static function render_dashboard(): void {
		self::require_admin();
		$offset = self::offset( $_GET );
		$unit = self::display_unit( $_GET );
		$project_id = self::selected_project( $_GET );
		if ( null !== $project_id ) {
			self::render_project_details( $project_id, $offset, $unit );
			return;
		}
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
		echo '<p>' . esc_html__( 'Budget used is the total value of all linked orders excluding VAT, including archived orders; it is committed value, not hours or invoices. Real budget left to date is allowance to date minus all logged hours through today at EUR 90 per hour, including Concept entries, archived orders and zero-value work. Monthly allowances use calendar months, prorating partial months by days. Allowance to date includes today in the WordPress timezone. Schedule compares committed budget usage, not work completed.', 'stuh' ) . '</p>';
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

	private static function order_url( int $id ): string {
		$state = [
			'action' => 'viewSubpage',
			'actionparams' => [
				'sn_' => [
					'n6409n' => [ 'selectedtab' => 'n15338n' ],
					'n9098n' => [ 'recordid' => $id, 'o_' => 'view', 'pinned' => [], 'showpinnedonly' => [] ],
				],
				're_' => 'n9102n',
			],
		];
		return 'https://switch.gripp.com/public/index.php?u=98237#' . base64_encode( wp_json_encode( $state ) );
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
			$real_left_to_date = is_wp_error( $schedule ) ? null : $schedule['planned'] - $row['recorded'];
			$monthly = is_wp_error( $schedule ) ? __( 'Unavailable', 'stuh' ) : sprintf( __( '%1$s / month (%2$s months)', 'stuh' ), self::display_amount( $schedule['monthly'], $unit ), number_format_i18n( $schedule['months'], 2 ) );
			echo '<tr>';
			foreach ( [
				'number' => $row['number'],
				'project' => $row['name'],
				'active_projects' => number_format_i18n( $row['active_projects'] ),
				'startdate' => $row['startdate'],
				'deadline' => $row['deadline'],
				'archived' => $row['archived'] ? __( 'Yes', 'stuh' ) : __( 'No', 'stuh' ),
				'budget' => null === $row['budget'] ? __( 'Not set', 'stuh' ) : self::display_amount( $row['budget'], $unit ),
				'monthly' => $monthly,
				'used' => self::display_amount( $row['used'], $unit ),
				'remaining' => null === $row['budget'] ? __( 'Unavailable', 'stuh' ) : self::display_amount( $row['budget'] - $row['used'], $unit ),
				'planned' => is_wp_error( $schedule ) ? __( 'Unavailable', 'stuh' ) : self::display_amount( $schedule['planned'], $unit ),
				'left_to_date' => null === $left_to_date ? __( 'Unavailable', 'stuh' ) : self::display_amount( $left_to_date, $unit ),
				'real_left_to_date' => null === $real_left_to_date ? __( 'Unavailable', 'stuh' ) : self::display_amount( $real_left_to_date, $unit ),
				'schedule' => is_wp_error( $schedule ) ? $schedule->get_error_message() : $schedule['status'],
			] as $column => $value ) {
				$classes = 'column-' . $column . ( in_array( $column, $hidden, true ) ? ' hidden' : '' );
				if ( 'left_to_date' === $column ) {
					$classes .= ' stuh-budget-left-to-date';
				}
				$attributes = ' class="' . esc_attr( $classes ) . '"';
				$balance = 'real_left_to_date' === $column ? $real_left_to_date : $left_to_date;
				if ( in_array( $column, [ 'left_to_date', 'real_left_to_date' ], true ) && null !== $balance && 0 !== $balance ) {
					$attributes .= ' style="color:' . ( $balance > 0 ? '#008a20' : '#b32d2e' ) . ';font-weight:600"';
				}
				$content = esc_html( '' === $value ? '-' : $value );
				if ( 'number' === $column && '' !== $value ) {
					$url = self::project_url( (int) $row['id'] );
					$content = '<a href="' . esc_url( $url ) . '" target="_blank" rel="noopener noreferrer">' . $content . '</a>';
				} elseif ( 'project' === $column ) {
					$url = self::details_url( (int) $row['id'], self::offset( $_GET ), $unit );
					$content = '<a href="' . esc_url( $url ) . '">' . $content . '</a>';
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
