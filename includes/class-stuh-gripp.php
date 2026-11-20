<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class STUH_Gripp {
	private const CONNECTION = 'stuh_gripp_connection';
	private const CACHE = 'stuh_gripp_projects';
	private const USAGE_CACHE = 'stuh_gripp_usage';
	private const ACTIVE_ORDERS_CACHE = 'stuh_gripp_active_orders';
	private const BALANCE_CACHE = 'stuh_gripp_balance';
	private const CACHE_RESOURCE = 'umbrellaproject-budget-hours-active-v4';
	private const PAGE_SIZE = 250;
	private const UNIT_OPTION = 'stuh_fmp_unit';
	private const PROJECT_SITES_PREFIX = 'stuh_fmp_project_sites_';
	private const HIDDEN_FORMS_PREFIX = 'stuh_fmp_hidden_forms_';

	public static function init(): void {
		add_action( 'admin_menu', [ self::class, 'register_menu' ], 20 );
		add_action( 'admin_post_stuh_gripp_action', [ self::class, 'handle_action' ] );
		add_action( 'admin_enqueue_scripts', [ self::class, 'enqueue_assets' ] );
		add_filter( 'set_screen_option_' . self::UNIT_OPTION, [ self::class, 'save_display_unit' ], 10, 3 );
	}

	public static function enqueue_assets( string $hook ): void {
		if ( ! in_array( $hook, [ get_plugin_page_hookname( 'stuh-fmp', 'stuh' ), 'toplevel_page_stuh-fmp' ], true ) || ! isset( $_GET['project_id'] ) || ! self::can_view() ) {
			return;
		}
		$plugin = dirname( __DIR__ ) . '/switch-theme-updater-host.php';
		$tab = self::project_tab( $_GET );
		if ( 'reports' === $tab ) {
			wp_enqueue_script( 'stuh-fmp-export', plugins_url( 'assets/js/fmp-export.js', $plugin ), [], (string) filemtime( dirname( __DIR__ ) . '/assets/js/fmp-export.js' ), true );
			return;
		}
		if ( 'overview' !== $tab ) {
			return;
		}
		wp_enqueue_style( 'stuh-uplot', plugins_url( 'assets/vendor/uplot/uPlot.min.css', $plugin ), [], '1.6.32' );
		wp_enqueue_script( 'stuh-uplot', plugins_url( 'assets/vendor/uplot/uPlot.iife.min.js', $plugin ), [], '1.6.32', true );
		wp_enqueue_script( 'stuh-fmp-chart', plugins_url( 'assets/js/fmp-chart.js', $plugin ), [ 'stuh-uplot' ], (string) filemtime( dirname( __DIR__ ) . '/assets/js/fmp-chart.js' ), true );
	}

	public static function register_menu(): void {
		if ( current_user_can( 'manage_options' ) ) {
			$hook = add_submenu_page( 'stuh', __( 'FMP', 'stuh' ), __( 'FMP', 'stuh' ), 'manage_options', 'stuh-fmp', [ self::class, 'render_dashboard' ] );
		} else {
			$hook = add_menu_page( __( 'FMP', 'stuh' ), __( 'FMP', 'stuh' ), 'edit_others_posts', 'stuh-fmp', [ self::class, 'render_dashboard' ], 'dashicons-chart-line' );
		}
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
		self::require_viewer();
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

	private static function can_view(): bool {
		return current_user_can( 'manage_options' ) || current_user_can( 'edit_others_posts' );
	}

	private static function require_viewer(): void {
		if ( ! self::can_view() ) {
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

	private static function details_url( int $id, int $offset, string $unit, string $tab = 'overview' ): string {
		$args = [ 'page' => 'stuh-fmp', 'project_id' => $id, 'offset' => $offset, 'unit' => $unit ];
		if ( 'overview' !== $tab ) {
			$args['project_tab'] = $tab;
		}
		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	private static function project_tab( array $source ): string {
		$tab = isset( $source['project_tab'] ) ? self::input( $source, 'project_tab' ) : 'overview';
		if ( ! in_array( $tab, [ 'overview', 'reports', 'settings' ], true ) ) {
			wp_die( esc_html__( 'Invalid FMP project tab.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		if ( 'settings' === $tab ) {
			self::require_admin();
		}
		return $tab;
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

	private static function selected_hours_month( array $source ): string {
		$month = self::input( $source, 'hours_month' );
		if ( isset( $source['hours_month'] ) && ( ! is_string( $source['hours_month'] ) || ( '' !== $month && ! preg_match( '/\A(?!0000)[0-9]{4}-(0[1-9]|1[0-2])\z/', $month ) ) ) ) {
			wp_die( esc_html__( 'Invalid recorded-hours month. Choose a calendar month or All months.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		return $month;
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
		delete_transient( self::BALANCE_CACHE );
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
			return new WP_Error( 'gripp_api', __( 'Gripp rejected the request. Check API read permissions for umbrella projects, orders, order lines, hours, invoice lines and invoices, and check the rate limit.', 'stuh' ) );
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

	private static function recorded_hours( string $token, array $ids ) {
		$hours = self::fetch_all( $token, 'hour', [ [ 'field' => 'hour.offerprojectbase', 'operator' => 'in', 'value' => $ids ] ] );
		if ( is_wp_error( $hours ) ) {
			return $hours;
		}
		$records = [];
		$line_orders = [];
		$today = ( new DateTimeImmutable( 'today', wp_timezone() ) )->format( 'Y-m-d' );
		foreach ( $hours as $hour ) {
			$record = self::recorded_hour( $hour, $ids );
			if ( is_wp_error( $record ) ) {
				return $record;
			}
			if ( $record['date'] > $today ) {
				continue;
			}
			$reference = $hour['offerprojectline'] ?? null;
			$line_id = null === $reference || '' === $reference ? 0 : self::reference_id( $reference );
			if ( null === $line_id || ( isset( $line_orders[ $line_id ] ) && $line_orders[ $line_id ] !== $record['order'] ) ) {
				return new WP_Error( 'gripp_hour', __( 'Gripp returned an invalid or conflicting order line reference for recorded time.', 'stuh' ) );
			}
			if ( $line_id > 0 ) {
				$line_orders[ $line_id ] = $record['order'];
			}
			$records[] = $record + [ 'line' => $line_id ];
		}
		$products = [ 0 => [ 'id' => 0, 'name' => __( 'No product', 'stuh' ) ] ];
		foreach ( array_chunk( array_keys( $line_orders ), self::PAGE_SIZE ) as $line_ids ) {
			$lines = self::fetch_all( $token, 'offerprojectline', [ [ 'field' => 'offerprojectline.id', 'operator' => 'in', 'value' => $line_ids ] ] );
			if ( is_wp_error( $lines ) ) {
				return $lines;
			}
			foreach ( $lines as $line_id => $line ) {
				if ( ! in_array( $line_id, $line_ids, true ) || self::reference_id( $line['offerprojectbase'] ?? null ) !== $line_orders[ $line_id ] ) {
					return new WP_Error( 'gripp_hour', __( 'Gripp returned an invalid order line for recorded time.', 'stuh' ) );
				}
				$product = $line['product'] ?? null;
				if ( null === $product || '' === $product ) {
					$products[ $line_id ] = $products[0];
					continue;
				}
				$product_id = self::reference_id( $product );
				if ( null === $product_id || ! is_array( $product ) || ! isset( $product['searchname'] ) || ! is_string( $product['searchname'] ) || '' === trim( $product['searchname'] ) ) {
					return new WP_Error( 'gripp_hour', __( 'Gripp returned an invalid product or product label for recorded time.', 'stuh' ) );
				}
				$products[ $line_id ] = [ 'id' => $product_id, 'name' => $product['searchname'] ];
			}
			if ( count( $lines ) !== count( $line_ids ) ) {
				return new WP_Error( 'gripp_hour', __( 'Some recorded-time order lines are missing or inaccessible in Gripp. Check order-line read permissions.', 'stuh' ) );
			}
		}
		$included = [];
		foreach ( $records as $record ) {
			$product = $products[ $record['line'] ];
			if ( preg_match( '/\(\s*ND\s*\/\s*intern\s*\)/i', $product['name'] ) ) {
				continue;
			}
			$included[] = $record + [ 'product' => $product ];
		}
		return $included;
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
			$hours = self::recorded_hours( $token, $ids );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			foreach ( $hours as $record ) {
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
		if ( is_array( $cache ) && ( $cache['resource'] ?? '' ) === self::CACHE_RESOURCE && ( $cache['connection'] ?? '' ) === $fingerprint && ( $cache['id'] ?? null ) === $id ) {
			return $cache['events'];
		}
		$events = self::fetch_usage( $token, $id );
		if ( ! is_wp_error( $events ) && hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
			set_transient( self::USAGE_CACHE, [ 'resource' => self::CACHE_RESOURCE, 'connection' => $fingerprint, 'id' => $id, 'events' => $events ], 5 * MINUTE_IN_SECONDS );
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
		if ( is_array( $cache ) && ( $cache['version'] ?? null ) === 6 && ( $cache['connection'] ?? '' ) === $fingerprint && ( $cache['id'] ?? null ) === $id ) {
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
		$breakdown = [];
		$monthly = [];
		$hours = self::order_hours( $token, array_keys( $orders ), $breakdown, $monthly );
		if ( is_wp_error( $hours ) ) {
			return $hours;
		}
		foreach ( $rows as &$row ) {
			$row['hours'] = $hours[ $row['id'] ];
			$row['products'] = $breakdown[ $row['id'] ];
			$row['months'] = $monthly[ $row['id'] ];
		}
		unset( $row );
		if ( hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
			set_transient( self::ACTIVE_ORDERS_CACHE, [ 'version' => 6, 'connection' => $fingerprint, 'id' => $id, 'rows' => $rows ], 5 * MINUTE_IN_SECONDS );
		}
		return $rows;
	}

	private static function add_hours( float &$total, float &$compensation, float $amount ): ?WP_Error {
		// Compensate floating-point error before rounding fractional hours for display.
		$adjusted = $amount - $compensation;
		$sum = $total + $adjusted;
		if ( ! is_finite( $sum ) ) {
			return new WP_Error( 'gripp_amount', __( 'The recorded hours total is too large to calculate safely.', 'stuh' ) );
		}
		$compensation = ( $sum - $total ) - $adjusted;
		$total = $sum;
		return null;
	}

	private static function order_hours( string $token, array $ids, ?array &$breakdown = null, ?array &$monthly = null, ?array &$history = null ) {
		$totals = array_fill_keys( $ids, 0.0 );
		$compensation = array_fill_keys( $ids, 0.0 );
		$groups = array_fill_keys( $ids, [] );
		$line_products = [];
		$history_compensation = [];
		if ( null !== $history ) {
			$history = [];
		}
		foreach ( array_chunk( $ids, self::PAGE_SIZE ) as $chunk ) {
			$hours = self::recorded_hours( $token, $chunk );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			foreach ( $hours as $record ) {
				$id = $record['order'];
				$error = self::add_hours( $totals[ $id ], $compensation[ $id ], $record['amount'] );
				if ( $error ) {
					return $error;
				}
				if ( null !== $history ) {
					$date = $record['date'];
					$history[ $date ] ??= 0.0;
					$history_compensation[ $date ] ??= 0.0;
					$error = self::add_hours( $history[ $date ], $history_compensation[ $date ], $record['amount'] );
					if ( $error ) {
						return $error;
					}
				}
				if ( null !== $breakdown ) {
					$line_id = $record['line'];
					$line_products[ $line_id ] = $record['product'];
					$periods = null === $monthly ? [ '' ] : [ '', substr( $record['date'], 0, 7 ) ];
					foreach ( $periods as $period ) {
						if ( ! isset( $groups[ $id ][ $period ][ $line_id ] ) ) {
							$groups[ $id ][ $period ][ $line_id ] = [ 'hours' => 0.0, 'compensation' => 0.0 ];
						}
						$group = &$groups[ $id ][ $period ][ $line_id ];
						$error = self::add_hours( $group['hours'], $group['compensation'], $record['amount'] );
						unset( $group );
						if ( $error ) {
							return $error;
						}
					}
				}
			}
		}
		if ( null !== $breakdown ) {
			$breakdown = array_fill_keys( $ids, [] );
			if ( null !== $monthly ) {
				$monthly = array_fill_keys( $ids, [] );
			}
			foreach ( $groups as $order_id => $order_periods ) {
				foreach ( $order_periods as $period => $order_groups ) {
					$products = [];
					$total = 0.0;
					$total_compensation = 0.0;
					foreach ( $order_groups as $line_id => $group ) {
						$product = $line_products[ $line_id ];
						$product_id = $product['id'];
						if ( ! isset( $products[ $product_id ] ) ) {
							$products[ $product_id ] = $product + [ 'hours' => 0.0, 'compensation' => 0.0 ];
						}
						$error = self::add_hours( $products[ $product_id ]['hours'], $products[ $product_id ]['compensation'], $group['hours'] );
						if ( $error ) {
							return $error;
						}
						$error = self::add_hours( $total, $total_compensation, $group['hours'] );
						if ( $error ) {
							return $error;
						}
					}
					foreach ( $products as &$product ) {
						unset( $product['compensation'] );
					}
					unset( $product );
					if ( '' === $period ) {
						$breakdown[ $order_id ] = array_values( $products );
					} else {
						$monthly[ $order_id ][ $period ] = [ 'hours' => $total, 'products' => array_values( $products ) ];
					}
				}
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
		$operation = self::input( $_POST, 'operation' );
		if ( 'refresh' === $operation ) {
			self::require_viewer();
		} else {
			self::require_admin();
		}
		check_admin_referer( 'stuh_gripp' );
		switch ( $operation ) {
			case 'save_project_sites':
				self::save_project_sites( $_POST );
				break;
			case 'save_hidden_forms':
				self::save_hidden_forms( $_POST );
				break;
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
				delete_transient( self::BALANCE_CACHE );
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
				delete_transient( self::BALANCE_CACHE );
				$result = self::projects( $token, $offset );
				self::finish( is_wp_error( $result ) ? $result->get_error_message() : __( 'Projects refreshed from Gripp.', 'stuh' ), is_wp_error( $result ), $offset, $unit );
				break;
			default:
				wp_die( esc_html__( 'Unknown Gripp action.', 'stuh' ), '', [ 'response' => 400 ] );
		}
	}

	private static function project_site_ids( int $id ): array {
		$ids = get_option( self::PROJECT_SITES_PREFIX . $id, [] );
		if ( ! is_array( $ids ) || array_filter( $ids, static fn( $value ): bool => ! is_string( $value ) || '' === $value ) ) {
			wp_die( esc_html__( 'Stored FMP client-site links are invalid.', 'stuh' ), '', [ 'response' => 500 ] );
		}
		return array_values( $ids );
	}

	private static function save_project_sites( array $source ): void {
		$id = self::selected_project( $source );
		if ( null === $id ) {
			wp_die( esc_html__( 'Select a Gripp umbrella project to configure.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		$offset = self::offset( $source );
		$unit = self::display_unit( $source );
		$submitted = $source['client_ids'] ?? [];
		if ( ! is_array( $submitted ) ) {
			wp_die( esc_html__( 'Invalid client-site selection.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		$available = array_column( STUH_Plugin::get_clients(), 'id' );
		$ids = [];
		foreach ( $submitted as $value ) {
			if ( ! is_string( $value ) || ! in_array( wp_unslash( $value ), $available, true ) ) {
				wp_die( esc_html__( 'A selected client site no longer exists. Reload the settings and try again.', 'stuh' ), '', [ 'response' => 400 ] );
			}
			$ids[] = wp_unslash( $value );
		}
		$ids = array_values( array_unique( $ids ) );
		$token = self::connection();
		$projects = is_wp_error( $token ) ? $token : self::fetch_all( $token, 'umbrellaproject', [ [ 'field' => 'umbrellaproject.id', 'operator' => 'equals', 'value' => $id ] ] );
		if ( is_wp_error( $projects ) ) {
			wp_die( esc_html( $projects->get_error_message() ), '', [ 'response' => 502 ] );
		}
		if ( 1 !== count( $projects ) || ! isset( $projects[ $id ] ) ) {
			wp_die( esc_html__( 'Gripp project not found or no longer accessible.', 'stuh' ), '', [ 'response' => 404 ] );
		}
		$key = self::PROJECT_SITES_PREFIX . $id;
		if ( get_option( $key, [] ) !== $ids && ! update_option( $key, $ids, false ) ) {
			wp_die( esc_html__( 'Could not save the FMP client-site links. Retry.', 'stuh' ), '', [ 'response' => 500 ] );
		}
		set_transient( 'stuh_gripp_notice_' . get_current_user_id(), [ 'message' => __( 'Linked client sites saved.', 'stuh' ), 'error' => false ], 5 * MINUTE_IN_SECONDS );
		wp_safe_redirect( self::details_url( $id, $offset, $unit, 'settings' ) );
		exit;
	}

	private static function hidden_forms( int $id ): array {
		$hidden = get_option( self::HIDDEN_FORMS_PREFIX . $id, [] );
		if ( ! is_array( $hidden ) ) {
			wp_die( esc_html__( 'Stored FMP hidden-form settings are invalid.', 'stuh' ), '', [ 'response' => 500 ] );
		}
		foreach ( $hidden as $client_id => $form_ids ) {
			if ( ( ! is_string( $client_id ) && ! is_int( $client_id ) ) || ! is_array( $form_ids ) ) {
				wp_die( esc_html__( 'Stored FMP hidden-form settings are invalid.', 'stuh' ), '', [ 'response' => 500 ] );
			}
			foreach ( $form_ids as $form_id ) {
				if ( ! is_int( $form_id ) || $form_id < 1 ) {
					wp_die( esc_html__( 'Stored FMP hidden-form settings are invalid.', 'stuh' ), '', [ 'response' => 500 ] );
				}
			}
		}
		return $hidden;
	}

	private static function save_hidden_forms( array $source ): void {
		$id = self::selected_project( $source );
		if ( null === $id ) {
			wp_die( esc_html__( 'Select a Gripp umbrella project to configure.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		$offset = self::offset( $source );
		$unit = self::display_unit( $source );
		$month = self::selected_hours_month( $source );
		$submitted = $source['hidden_forms'] ?? [];
		if ( ! is_array( $submitted ) ) {
			wp_die( esc_html__( 'Invalid hidden Gravity Forms selection.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		$available = [];
		foreach ( self::linked_gravity_forms( $id ) as $site ) {
			if ( ! $site['exists'] || null === $site['report'] ) {
				continue;
			}
			$available[ $site['id'] ] = array_column( $site['report']['forms'], 'form_id' );
		}
		$hidden = [];
		foreach ( $submitted as $client_id => $form_ids ) {
			$client_id = wp_unslash( (string) $client_id );
			if ( ! isset( $available[ $client_id ] ) || ! is_array( $form_ids ) ) {
				wp_die( esc_html__( 'A selected Gravity Forms report is no longer available. Reload the page and try again.', 'stuh' ), '', [ 'response' => 400 ] );
			}
			foreach ( $form_ids as $form_id ) {
				if ( ! is_string( $form_id ) || ! ctype_digit( $form_id ) || (int) $form_id < 1 || ! in_array( (int) $form_id, $available[ $client_id ], true ) ) {
					wp_die( esc_html__( 'A selected Gravity Form is no longer available. Reload the page and try again.', 'stuh' ), '', [ 'response' => 400 ] );
				}
				$hidden[ $client_id ][] = (int) $form_id;
			}
			$hidden[ $client_id ] = array_values( array_unique( $hidden[ $client_id ] ?? [] ) );
		}
		$key = self::HIDDEN_FORMS_PREFIX . $id;
		if ( get_option( $key, [] ) !== $hidden && ! update_option( $key, $hidden, false ) ) {
			wp_die( esc_html__( 'Could not save hidden Gravity Forms settings. Retry.', 'stuh' ), '', [ 'response' => 500 ] );
		}
		set_transient( 'stuh_gripp_notice_' . get_current_user_id(), [ 'message' => __( 'Word export form visibility saved.', 'stuh' ), 'error' => false ], 5 * MINUTE_IN_SECONDS );
		$url = self::details_url( $id, $offset, $unit, 'reports' );
		wp_safe_redirect( '' === $month ? $url : add_query_arg( [ 'hours_month' => $month ], $url ) );
		exit;
	}

	private static function render_project_settings( int $id, int $offset, string $unit ): void {
		self::require_admin();
		$selected = self::project_site_ids( $id );
		$clients = STUH_Plugin::get_clients();
		usort( $clients, static fn( array $a, array $b ): int => strcasecmp( $a['site_url'] ?? $a['id'], $b['site_url'] ?? $b['id'] ) );
		echo '<h2>' . esc_html__( 'Linked client sites', 'stuh' ) . '</h2><p>' . esc_html__( 'Select the client sites belonging to this FMP project or retainer. Their reported Gravity Forms counts appear in Monthly reports; linking does not start additional data collection.', 'stuh' ) . '</p>';
		$missing = array_diff( $selected, array_column( $clients, 'id' ) );
		if ( $missing ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Some linked client sites have been removed from the host. Saving will remove those unavailable links.', 'stuh' ) . '</p></div>';
		}
		self::form_start( 'save_project_sites' );
		foreach ( [ 'project_id' => $id, 'offset' => $offset, 'unit' => $unit ] as $key => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '">';
		}
		echo '<fieldset><legend class="screen-reader-text">' . esc_html__( 'Client sites', 'stuh' ) . '</legend>';
		foreach ( $clients as $client ) {
			echo '<p><label><input type="checkbox" name="client_ids[]" value="' . esc_attr( $client['id'] ) . '"' . ( in_array( $client['id'], $selected, true ) ? ' checked' : '' ) . '> ' . esc_html( $client['site_url'] ?? $client['id'] ) . '</label></p>';
		}
		if ( ! $clients ) {
			echo '<p>' . esc_html__( 'No client sites are registered on this host yet.', 'stuh' ) . '</p>';
		}
		echo '</fieldset>';
		submit_button( __( 'Save linked sites', 'stuh' ) );
		echo '</form>';
	}

	private static function monthly_balance( string $token, int $id, string $month ) {
		$fingerprint = hash( 'sha256', (string) get_option( self::CONNECTION, '' ) );
		$data = get_transient( self::BALANCE_CACHE );
		if ( ! is_array( $data ) || ( $data['resource'] ?? '' ) !== self::CACHE_RESOURCE || ( $data['connection'] ?? '' ) !== $fingerprint || ( $data['id'] ?? null ) !== $id ) {
			$projects = self::fetch_all( $token, 'umbrellaproject', [ [ 'field' => 'umbrellaproject.id', 'operator' => 'equals', 'value' => $id ] ] );
			if ( is_wp_error( $projects ) ) {
				return $projects;
			}
			if ( 1 !== count( $projects ) || ! isset( $projects[ $id ] ) ) {
				return new WP_Error( 'gripp_project', __( 'Gripp project not found or no longer accessible.', 'stuh' ) );
			}
			$raw = $projects[ $id ];
			$project = [ 'budget' => null === ( $raw['budget'] ?? null ) || '' === $raw['budget'] ? null : self::money_amount( $raw['budget'], 'umbrellaproject.budget' ), 'used' => 0 ];
			foreach ( [ 'startdate', 'deadline' ] as $field ) {
				$project[ $field ] = self::project_date( $raw[ $field ] ?? null, $field );
			}
			foreach ( $project as $value ) {
				if ( is_wp_error( $value ) ) {
					return $value;
				}
			}
			$schedule = self::budget_schedule( $project, new DateTimeImmutable( 'today', wp_timezone() ) );
			if ( is_wp_error( $schedule ) ) {
				return $schedule;
			}
			$orders = self::fetch_all( $token, 'project', [ [ 'field' => 'project.umbrellaproject', 'operator' => 'equals', 'value' => $id ] ] );
			if ( is_wp_error( $orders ) ) {
				return $orders;
			}
			foreach ( $orders as $order ) {
				if ( self::reference_id( $order['umbrellaproject'] ?? null ) !== $id ) {
					return new WP_Error( 'gripp_order', __( 'Gripp returned an unrelated order in the hours balance.', 'stuh' ) );
				}
			}
			$breakdown = null;
			$monthly = null;
			$history = [];
			$hours = self::order_hours( $token, array_keys( $orders ), $breakdown, $monthly, $history );
			if ( is_wp_error( $hours ) ) {
				return $hours;
			}
			$data = [ 'resource' => self::CACHE_RESOURCE, 'connection' => $fingerprint, 'id' => $id, 'project' => $project, 'history' => $history ];
			if ( hash_equals( $fingerprint, hash( 'sha256', (string) get_option( self::CONNECTION, '' ) ) ) ) {
				set_transient( self::BALANCE_CACHE, $data, 5 * MINUTE_IN_SECONDS );
			}
		}
		return self::calculate_monthly_balance( $data['project'], $data['history'], $month, new DateTimeImmutable( 'today', wp_timezone() ) );
	}

	private static function calculate_monthly_balance( array $project, array $history, string $month, DateTimeImmutable $today ) {
		$start = '' === $month ? null : new DateTimeImmutable( $month . '-01', $today->getTimezone() );
		$end = null === $start ? $today : $start->modify( 'last day of this month' );
		$closing = self::budget_schedule( $project, $end );
		$opening = null === $start ? null : self::budget_schedule( $project, $start->modify( '-1 day' ) );
		if ( is_wp_error( $closing ) || is_wp_error( $opening ) ) {
			return is_wp_error( $closing ) ? $closing : $opening;
		}
		$before = 0.0;
		$worked = 0.0;
		$before_compensation = 0.0;
		$worked_compensation = 0.0;
		foreach ( $history as $date => $hours ) {
			if ( $date > $today->format( 'Y-m-d' ) || $date > $end->format( 'Y-m-d' ) ) {
				continue;
			}
			if ( null !== $start && $date < $start->format( 'Y-m-d' ) ) {
				$error = self::add_hours( $before, $before_compensation, $hours );
			} else {
				$error = self::add_hours( $worked, $worked_compensation, $hours );
			}
			if ( $error ) {
				return $error;
			}
		}
		$opening_allowance = null === $opening ? 0 : $opening['planned'];
		$balance = [
			'opening' => $opening_allowance / 9000.0 - $before,
			'allowance' => ( $closing['planned'] - $opening_allowance ) / 9000.0,
			'worked' => $worked,
		];
		$balance['closing'] = $balance['opening'] + $balance['allowance'] - $worked;
		return $balance;
	}

	private static function format_monthly_export( array $rows, array $sites, int $id, string $month, array $balance ): array {
		$rows = self::filter_active_orders( $rows, $month );
		$period = '' === $month ? __( 'All months', 'stuh' ) : wp_date( 'F Y', ( new DateTimeImmutable( $month . '-01', wp_timezone() ) )->getTimestamp(), wp_timezone() ) . ' (' . $month . ')';
		$lines = [
			__( 'FMP - Monthly reports', 'stuh' ),
			sprintf( __( 'Umbrella project ID: %d', 'stuh' ), $id ),
			sprintf( __( 'Calendar month: %s', 'stuh' ), $period ),
			__( 'Uren per product voor de geselecteerde periode.', 'stuh' ),
			'',
			__( 'Active projects', 'stuh' ),
		];
		$plain = static fn( string $value ): string => str_replace( [ "\r", "\n", "\t" ], ' ', $value );
		$font = 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;';
		$blank_line = '<p style="' . $font . 'margin:0;line-height:1.4;"><br></p>';
		$heading = static fn( string $value ): string => '<p style="' . $font . 'margin:20px 0 8px;color:#ff0054;"><strong>' . esc_html( $value ) . '</strong></p>';
		$table_start = '<table style="' . $font . 'width:100%;border-collapse:collapse;border:0;" cellpadding="0" cellspacing="0"><tbody>';
		$table_end = '</tbody></table>';
		$html_row = static function( string $label, string $value, bool $bold = false, bool $highlight = false ) use ( $font ): string {
			$style = $font . 'padding:4px 0;border:0;color:' . ( $highlight ? '#ff0054' : '#111111' ) . ';';
			$label = esc_html( $label );
			$value = esc_html( $value );
			return '<tr><td style="' . $style . '">' . ( $bold ? '<strong>' . $label . '</strong>' : $label ) . '</td><td style="' . $style . 'text-align:right;white-space:nowrap;" align="right">' . ( $bold ? '<strong>' . $value . '</strong>' : $value ) . '</td></tr>';
		};
		$html = '<div style="' . $font . 'line-height:1.4;color:#111111;background:#ffffff;">';
		$html .= '<p style="' . $font . '"><strong>' . esc_html( $lines[0] ) . '</strong><br>' . esc_html( $lines[1] ) . '<br>' . esc_html( $lines[2] ) . '</p>';
		$html .= '<p style="' . $font . '">' . esc_html__( 'Onderstaan een overzicht van de verrichte werkzaamheden.', 'stuh' ) . '</p>';
		foreach ( $rows as $row ) {
			$title = sprintf( __( 'Opdracht %1$s %2$s', 'stuh' ), $plain( '' === $row['number'] ? '-' : (string) $row['number'] ), $plain( $row['name'] ) );
			$lines[] = $title;
			$html .= $blank_line . $heading( $title ) . $table_start;
			foreach ( $row['products'] as $product ) {
				$label = $plain( self::product_label( $product['name'] ) );
				$value = number_format( $product['hours'], 2, ',', '.' );
				$lines[] = $label . "\t" . $value;
				$html .= $html_row( $label, $value );
			}
			$html .= $table_end;
			$lines[] = '';
		}
		if ( ! $rows ) {
			$lines[] = '' === $month ? __( 'No active projects linked to this umbrella project.', 'stuh' ) : __( 'No active projects have recorded time in this month.', 'stuh' );
			$html .= '<p style="' . $font . '">' . esc_html( end( $lines ) ) . '</p>';
		}
		$lines[] = '';
		$html .= $blank_line . '<div style="margin-top:24px;">' . $table_start;
		foreach ( [
			'opening' => '' === $month ? __( 'Uren begin van de periode', 'stuh' ) : __( 'Uren begin van de maand', 'stuh' ),
			'allowance' => __( 'Beschikbare uren in de periode', 'stuh' ),
			'worked' => __( 'Totaal gewerkt', 'stuh' ),
			'closing' => '' === $month ? __( 'Uren eind van de periode', 'stuh' ) : __( 'Uren eind van de maand', 'stuh' ),
		] as $key => $label ) {
			$value = number_format( $balance[ $key ], 2, ',', '.' );
			$lines[] = $label . "\t" . $value;
			$html .= $html_row( $label, $value, true, 'closing' === $key );
		}
		$html .= $table_end . '</div>';
		if ( $sites ) {
			$hidden_forms = self::hidden_forms( $id );
			$export_sites = [];
			foreach ( $sites as $site ) {
				if ( null === self::gravity_forms_status( $site ) ) {
					$site['report']['forms'] = array_values( array_filter(
						$site['report']['forms'],
						static fn( array $form ): bool => ! in_array( $form['form_id'], $hidden_forms[ $site['id'] ] ?? [], true )
					) );
					if ( ! $site['report']['forms'] ) {
						continue;
					}
				}
				$export_sites[] = $site;
			}
			if ( $export_sites ) {
				$lines[] = '';
				$lines[] = __( 'Gravity Forms', 'stuh' );
				$html .= $heading( __( 'Gravity Forms', 'stuh' ) );
				foreach ( $export_sites as $site ) {
					$lines[] = '';
					$lines[] = $plain( $site['name'] );
					$html .= '<p style="' . $font . 'margin:16px 0 8px;"><strong>' . esc_html( $plain( $site['name'] ) ) . '</strong></p>';
					$status = self::gravity_forms_status( $site );
					if ( null !== $status ) {
						$lines[] = "\t" . $status;
						$html .= '<p style="' . $font . '">' . esc_html( $status ) . '</p>';
						continue;
					}
					$lines[] = "\t" . __( 'Form', 'stuh' ) . "\t" . __( 'Entries', 'stuh' );
					$html .= self::gravity_forms_word_matrix( $site['report']['forms'], $month, $font );
					foreach ( $site['report']['forms'] as $form ) {
						$label = $plain( $form['form_title'] );
						$value = self::gravity_form_entries( $form, $month );
						$lines[] = "\t" . $label . "\t" . $value;
					}
				}
			}
		}
		return [
			'text' => implode( "\n", $lines ) . "\n",
			'html' => $html . '</div>',
		];
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
		echo '<p>' . esc_html__( 'Connect a Gripp API token with read access to umbrella projects (Projecten / Retainers), linked orders (Opdrachten), order lines, hours, invoice lines and invoices. The token stays encrypted on this host and is never sent to client sites. FMP is read-only.', 'stuh' ) . '</p>';
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
		$chart['monthly_usage'] = [];
		$chart['current_month'] = $today->format( 'Y-m' );
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
			$monthly_actual = 0;
			while ( isset( $events[ $index ] ) && $events[ $index ]['date'] <= $date ) {
				$monthly_actual += $events[ $index ]['actual'];
				if ( ! is_int( $monthly_actual ) ) {
					return new WP_Error( 'gripp_amount', __( 'The monthly usage total is too large to calculate safely.', 'stuh' ) );
				}
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
			$period_start = max( $start, ( new DateTimeImmutable( $date, $timezone ) )->modify( 'first day of this month' ) );
			$chart['monthly_usage'][] = [
				'startdate' => $period_start->format( 'Y-m-d' ),
				'date' => $date,
				'start_months' => self::month_units( $start, $period_start->modify( '-1 day' ) ),
				'months' => self::month_units( $start, new DateTimeImmutable( $date, $timezone ) ),
				'actual' => $monthly_actual,
			];
		}
		return $chart;
	}

	private static function render_project_details( int $id, int $offset, string $unit ): void {
		$tab = self::project_tab( $_GET );
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
		$tabs = [ 'overview' => __( 'Overview', 'stuh' ), 'reports' => __( 'Monthly reports', 'stuh' ) ];
		if ( current_user_can( 'manage_options' ) ) {
			$tabs['settings'] = __( 'Settings', 'stuh' );
		}
		echo '<nav class="nav-tab-wrapper" aria-label="' . esc_attr__( 'FMP project sections', 'stuh' ) . '">';
		foreach ( $tabs as $key => $label ) {
			echo '<a class="nav-tab' . ( $key === $tab ? ' nav-tab-active' : '' ) . '" href="' . esc_url( self::details_url( $id, $offset, $unit, $key ) ) . '"' . ( $key === $tab ? ' aria-current="page"' : '' ) . '>' . esc_html( $label ) . '</a>';
		}
		echo '</nav>';
		if ( 'settings' === $tab ) {
			self::render_project_settings( $id, $offset, $unit );
			echo '</div>';
			return;
		}
		if ( 'reports' === $tab ) {
			self::render_project_reports( $token, $id, $unit );
			echo '</div>';
			return;
		}
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
			self::render_budget_chart( $project, $chart, $unit, self::chart_overlay( $id ), isset( $chart['usage'] ) ? self::chart_releases( $id ) : [] );
		}
		echo '</div>';
	}

	private static function filter_active_orders( array $rows, string $month ): array {
		if ( '' === $month ) {
			return $rows;
		}
		$filtered = [];
		foreach ( $rows as $row ) {
			if ( isset( $row['months'][ $month ] ) ) {
				$row['hours'] = $row['months'][ $month ]['hours'];
				$row['products'] = $row['months'][ $month ]['products'];
				$filtered[] = $row;
			}
		}
		return $filtered;
	}

	private static function linked_gravity_forms( int $id ): array {
		$ids = self::project_site_ids( $id );
		if ( ! $ids ) {
			return [];
		}
		$clients = array_column( STUH_Plugin::get_clients(), null, 'id' );
		$sites = [];
		foreach ( array_unique( $ids ) as $client_id ) {
			$client = $clients[ $client_id ] ?? null;
			$sites[] = [
				'id' => $client_id,
				'name' => null === $client ? __( 'Removed client site', 'stuh' ) : ( $client['site_url'] ?? $client_id ),
				'exists' => null !== $client,
				'report' => null === $client ? null : STUH_Plugin::get_gravity_forms_report( $client_id ),
			];
		}
		return $sites;
	}

	private static function render_project_reports( string $token, int $id, string $unit ): void {
		$month = self::selected_hours_month( $_GET );
		$rows = self::active_orders( $token, $id );
		$sites = self::linked_gravity_forms( $id );
		$months = [ ( new DateTimeImmutable( 'today', wp_timezone() ) )->format( 'Y-m' ) => true ];
		if ( ! is_wp_error( $rows ) ) {
			foreach ( $rows as $row ) {
				foreach ( array_keys( $row['months'] ) as $recorded_month ) {
					$months[ $recorded_month ] = true;
				}
			}
		}
		foreach ( $sites as $site ) {
			foreach ( $site['report']['forms'] ?? [] as $form ) {
				foreach ( array_keys( $form['months'] ) as $recorded_month ) {
					$months[ $recorded_month ] = true;
				}
			}
		}
		if ( '' !== $month ) {
			$months[ $month ] = true;
		}
		krsort( $months );
		echo '<h2 id="stuh-fmp-reports-heading">' . esc_html__( 'Monthly reports', 'stuh' ) . '</h2>';
		echo '<form method="get" action="' . esc_url( admin_url( 'admin.php#stuh-fmp-reports-heading' ) ) . '"><p>';
		foreach ( [ 'page' => 'stuh-fmp', 'project_id' => $id, 'project_tab' => 'reports', 'offset' => self::offset( $_GET ), 'unit' => $unit ] as $key => $value ) {
			echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '">';
		}
		echo '<label for="stuh-fmp-hours-month">' . esc_html__( 'Calendar month', 'stuh' ) . '</label> <select id="stuh-fmp-hours-month" name="hours_month"><option value=""' . ( '' === $month ? ' selected' : '' ) . '>' . esc_html__( 'All months', 'stuh' ) . '</option>';
		foreach ( array_keys( $months ) as $option ) {
			$date = new DateTimeImmutable( $option . '-01', wp_timezone() );
			echo '<option value="' . esc_attr( $option ) . '"' . ( $option === $month ? ' selected' : '' ) . '>' . esc_html( wp_date( 'F Y', $date->getTimestamp(), wp_timezone() ) ) . '</option>';
		}
		echo '</select> <button class="button" type="submit">' . esc_html__( 'Filter', 'stuh' ) . '</button></p></form>';
		echo '<p>' . esc_html__( 'The calendar month filters active-project hours and Gravity Forms entries together. Projects without time entries in the selected month are hidden; order values and the budget chart remain unchanged.', 'stuh' ) . '</p>';
		echo '<h2 id="stuh-fmp-active-heading">' . esc_html__( 'Active projects', 'stuh' ) . '</h2>';
		echo '<p>' . esc_html__( 'Non-archived projects (Opdrachten) linked to this umbrella project. Actual hours include all recorded time through today, including Concept entries and zero-value work, excluding products marked (ND / intern), and always display as hours. Sub-rows summarize hours per Gripp product, combining all order lines for the same product. Time without a product is listed separately.', 'stuh' ) . '</p>';
		if ( is_wp_error( $rows ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $rows->get_error_message() ) . '</p></div>';
		} else {
			self::render_active_orders( $rows, $unit, $month );
		}
		if ( $sites ) {
			self::render_gravity_forms( $sites, $month, $id );
		}
		if ( ! is_wp_error( $rows ) ) {
			$balance = self::monthly_balance( $token, $id, $month );
			if ( is_wp_error( $balance ) ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html( $balance->get_error_message() ) . '</p></div>';
				return;
			}
			$export = self::format_monthly_export( $rows, $sites, $id, $month, $balance );
			echo '<h2>' . esc_html__( 'Word preview', 'stuh' ) . '</h2>';
			echo '<p>' . esc_html__( 'Copy the formatted report into Word and choose Keep Source Formatting when pasting. If needed, select and copy the formatted preview manually.', 'stuh' ) . '</p>';
			echo '<div class="stuh-fmp-word-preview" data-stuh-fmp-word-preview data-stuh-fmp-copy-text="' . esc_attr( $export['text'] ) . '" tabindex="0" role="region" aria-label="' . esc_attr__( 'Formatted report for Word', 'stuh' ) . '">' . $export['html'] . '</div>';
			echo '<p><button class="button button-primary" type="button" data-stuh-fmp-copy-word hidden>' . esc_html__( 'Copy for Word', 'stuh' ) . '</button> <span role="status" aria-live="polite" data-stuh-fmp-copy-status data-success="' . esc_attr__( 'Copied with formatting. Paste into Word using Keep Source Formatting.', 'stuh' ) . '" data-failure="' . esc_attr__( 'Automatic copying failed. The formatted report is selected; press Ctrl+C or Command+C, then paste into Word using Keep Source Formatting.', 'stuh' ) . '"></span></p>';
		}
	}

	private static function product_label( string $name ): string {
		return preg_replace( '/\s*\([0-9]+\)\s*\z/', '', $name );
	}

	private static function render_active_orders( array $rows, string $unit, string $month ): void {
		$rows = self::filter_active_orders( $rows, $month );
		echo '<div class="stuh-analytics-line-scroll" role="region" tabindex="0" aria-labelledby="stuh-fmp-active-heading"><table id="stuh-fmp-active-projects" class="widefat striped" aria-labelledby="stuh-fmp-active-heading"><thead><tr>';
		foreach ( [ __( 'Number', 'stuh' ), __( 'Project', 'stuh' ), __( 'Actual hours', 'stuh' ), __( 'Order value (excl. VAT)', 'stuh' ) ] as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		foreach ( $rows as $row ) {
			$number = '' === $row['number'] ? '-' : '<a href="' . esc_url( self::order_url( $row['id'] ) ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $row['number'] ) . '</a>';
			echo '<tr class="stuh-fmp-order-total"><td>' . $number . '</td><th scope="row" id="stuh-fmp-order-' . esc_attr( (string) $row['id'] ) . '">' . esc_html( $row['name'] ) . '</th>';
			foreach ( [ sprintf( __( '%s h', 'stuh' ), number_format_i18n( $row['hours'], 2 ) ), self::display_amount( $row['value'], $unit ) ] as $value ) {
				echo '<td>' . esc_html( $value ) . '</td>';
			}
			echo '</tr>';
			foreach ( $row['products'] as $product ) {
				echo '<tr class="stuh-fmp-order-line"><td></td><th scope="row" headers="stuh-fmp-order-' . esc_attr( (string) $row['id'] ) . '">' . esc_html( self::product_label( $product['name'] ) ) . '</th><td>' . esc_html( sprintf( __( '%s h', 'stuh' ), number_format_i18n( $product['hours'], 2 ) ) ) . '</td><td></td></tr>';
			}
		}
		if ( ! $rows ) {
			echo '<tr><td colspan="4">' . esc_html( '' === $month ? __( 'No active projects linked to this umbrella project.', 'stuh' ) : __( 'No active projects have recorded time in this month.', 'stuh' ) ) . '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	private static function gravity_forms_status( array $site ): ?string {
		if ( ! $site['exists'] ) {
			return __( 'Client site no longer exists.', 'stuh' );
		}
		if ( null === $site['report'] ) {
			return __( 'No Gravity Forms report received yet.', 'stuh' );
		}
		return ! $site['report']['forms'] ? __( 'No forms reported.', 'stuh' ) : null;
	}

	private static function gravity_form_entries( array $form, string $month ): string {
		$count = '' === $month ? 0 : ( $form['months'][ $month ] ?? null );
		if ( '' === $month ) {
			foreach ( $form['months'] as $amount ) {
				if ( ! is_int( $count + $amount ) ) {
					return __( 'Count is too large to display.', 'stuh' );
				}
				$count += $amount;
			}
		}
		return null === $count ? __( 'Not reported', 'stuh' ) : number_format_i18n( $count );
	}

	private static function gravity_forms_word_matrix( array $forms, string $month, string $font ): string {
		$first = null;
		$last = '' === $month ? null : $month;
		foreach ( $forms as $form ) {
			foreach ( $form['months'] as $period => $count ) {
				if ( '' === $month || $period <= $month ) {
					$first = null === $first ? $period : min( $first, $period );
					$last = null === $last ? $period : max( $last, $period );
				}
			}
		}
		if ( null === $last ) {
			return '<p style="' . $font . '">' . esc_html__( 'No form entries reported for months up to this period.', 'stuh' ) . '</p>';
		}
		$years = [];
		$cursor = new DateTimeImmutable( ( $first ?? $last ) . '-01', wp_timezone() );
		while ( $cursor->format( 'Y-m' ) <= $last ) {
			$years[ $cursor->format( 'Y' ) ][ $cursor->format( 'Y-m' ) ] = true;
			$cursor = $cursor->modify( '+1 month' );
		}
		krsort( $years, SORT_STRING );
		$cell = $font . 'padding:6px 8px;border:0;border-left:1px solid #b7b7b7;text-align:center;';
		$html = '<p style="' . $font . '">' . esc_html__( 'Maanden tot en met de geselecteerde periode. Jaarregels en totalen tellen alleen gerapporteerde aantallen op; - betekent niet gerapporteerd.', 'stuh' ) . '</p>';
		$html .= '<table style="' . $font . 'width:100%;border-collapse:collapse;table-layout:fixed;" cellpadding="0" cellspacing="0"><thead><tr>';
		$html .= '<th scope="col" style="' . $font . 'padding:6px 8px;text-align:left;border-bottom:1px solid #b7b7b7;">' . esc_html__( 'Maand', 'stuh' ) . '</th>';
		foreach ( array_merge( array_column( $forms, 'form_title' ), [ __( 'Totaal', 'stuh' ) ] ) as $title ) {
			$html .= '<th scope="col" style="' . $cell . 'border-bottom:1px solid #b7b7b7;color:#13969c;word-wrap:break-word;"><strong>' . esc_html( $title ) . '</strong></th>';
		}
		$html .= '</tr></thead><tbody>';
		$count_label = static fn( array $counts ): string => $counts ? self::gravity_form_entries( [ 'months' => $counts ], '' ) : '-';
		$row_index = 0;
		$render_row = static function( string $label, array $counts_by_form, bool $annual, bool $selected = false ) use ( $font, $cell, $count_label, &$row_index ): string {
			$background = 0 === $row_index++ % 2 ? '#f2f2f2' : '#ffffff';
			$style = 'background-color:' . $background . ';color:' . ( $annual ? '#ff0054' : '#111111' ) . ';';
			$wrap = static fn( string $value ): string => $annual || $selected ? '<strong>' . esc_html( $value ) . '</strong>' : esc_html( $value );
			$html = '<tr style="page-break-inside:avoid;"><th scope="row" style="' . $font . $style . 'padding:6px 8px;text-align:left;font-weight:normal;border:0;">' . $wrap( $label ) . '</th>';
			$total = [];
			foreach ( $counts_by_form as $counts ) {
				$html .= '<td align="center" style="' . $cell . $style . '">' . $wrap( $count_label( $counts ) ) . '</td>';
				foreach ( $counts as $count ) {
					$total[] = $count;
				}
			}
			$html .= '<td align="center" style="' . $cell . $style . '">' . $wrap( $count_label( $total ) ) . '</td></tr>';
			return $html;
		};
		$month_labels = [ 'JAN', 'FEB', 'MRT', 'APR', 'MEI', 'JUNI', 'JULI', 'AUG', 'SEP', 'OKT', 'NOV', 'DEC' ];
		foreach ( $years as $year => $periods ) {
			krsort( $periods, SORT_STRING );
			$annual_counts = [];
			foreach ( $forms as $form ) {
				$annual_counts[] = array_intersect_key( $form['months'], $periods );
			}
			$html .= $render_row( (string) $year, $annual_counts, true );
			foreach ( $periods as $period => $reported ) {
				$counts = [];
				foreach ( $forms as $form ) {
					$counts[] = isset( $form['months'][ $period ] ) ? [ $form['months'][ $period ] ] : [];
				}
				$html .= $render_row( $month_labels[ (int) substr( $period, 5, 2 ) - 1 ], $counts, false, $period === $month );
			}
		}
		return $html . '</tbody></table>';
	}

	private static function render_gravity_forms( array $sites, string $month, int $id ): void {
		echo '<h2 id="stuh-fmp-forms-heading">' . esc_html__( 'Gravity Forms', 'stuh' ) . '</h2>';
		$can_edit = current_user_can( 'manage_options' );
		echo '<p>' . esc_html__( 'Entry counts reported by linked client sites. All months sums each form\'s reported months. Missing months are shown as Not reported, not zero. Forms on different sites remain separate.', 'stuh' );
		if ( $can_edit ) {
			echo ' ' . esc_html__( 'Use Hide from Word to omit a form from the formatted export without hiding it from this table.', 'stuh' );
		}
		echo '</p>';
		if ( $can_edit ) {
			self::form_start( 'save_hidden_forms' );
			foreach ( [ 'project_id' => $id, 'offset' => self::offset( $_GET ), 'unit' => self::display_unit( $_GET ), 'hours_month' => $month ] as $key => $value ) {
				echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '">';
			}
		}
		echo '<div class="stuh-analytics-line-scroll" role="region" tabindex="0" aria-labelledby="stuh-fmp-forms-heading"><table id="stuh-fmp-gravity-forms" class="widefat striped" aria-labelledby="stuh-fmp-forms-heading"><thead><tr>';
		$headings = [ __( 'Client site', 'stuh' ), __( 'Form', 'stuh' ), __( 'Entries', 'stuh' ) ];
		if ( $can_edit ) {
			$headings[] = __( 'Hide from Word', 'stuh' );
		}
		foreach ( $headings as $heading ) {
			echo '<th scope="col">' . esc_html( $heading ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		$hidden_forms = $can_edit ? self::hidden_forms( $id ) : [];
		foreach ( $sites as $site ) {
			$status = self::gravity_forms_status( $site );
			if ( null !== $status ) {
				echo '<tr><th scope="row">' . esc_html( $site['name'] ) . '</th><td colspan="' . ( $can_edit ? '3' : '2' ) . '">' . esc_html( $status ) . '</td></tr>';
				continue;
			}
			foreach ( $site['report']['forms'] as $form ) {
				$value = self::gravity_form_entries( $form, $month );
				echo '<tr><td>' . esc_html( $site['name'] ) . '</td><th scope="row">' . esc_html( $form['form_title'] ) . '</th><td>' . esc_html( $value ) . '</td>';
				if ( $can_edit ) {
					$checked = in_array( $form['form_id'], $hidden_forms[ $site['id'] ] ?? [], true ) ? ' checked' : '';
					echo '<td><label><input type="checkbox" name="hidden_forms[' . esc_attr( $site['id'] ) . '][]" value="' . esc_attr( (string) $form['form_id'] ) . '"' . $checked . '> ' . esc_html__( 'Hide from Word', 'stuh' ) . '</label></td>';
				}
				echo '</tr>';
			}
		}
		echo '</tbody></table></div>';
		if ( $can_edit ) {
			echo '<p><button class="button" type="submit">' . esc_html__( 'Save Word export visibility', 'stuh' ) . '</button></p></form>';
		}
	}

	private static function budget_variance_regions( array $allowance, array $actual ): array {
		if ( count( $allowance ) < 2 || count( $actual ) < 2 ) {
			return [];
		}
		$start = max( $allowance[0][0], $actual[0][0] );
		$end = min( $allowance[ count( $allowance ) - 1 ][0], $actual[ count( $actual ) - 1 ][0] );
		$times = array_values( array_unique( array_merge( array_column( $allowance, 0 ), array_column( $actual, 0 ) ) ) );
		sort( $times, SORT_NUMERIC );
		$times = array_values( array_filter( $times, static fn( int $time ): bool => $time >= $start && $time <= $end ) );
		$interpolate = static function( array $points, int $time, int &$index ): float {
			while ( $index + 1 < count( $points ) - 1 && $points[ $index + 1 ][0] < $time ) {
				$index++;
			}
			$a = $points[ $index ];
			$b = $points[ $index + 1 ];
			return $a[1] + ( $b[1] - $a[1] ) * ( $time - $a[0] ) / ( $b[0] - $a[0] );
		};
		$regions = [];
		$allowance_index = 0;
		$actual_index = 0;
		$previous = null;
		foreach ( $times as $time ) {
			$current = [ $time, $interpolate( $allowance, $time, $allowance_index ), $interpolate( $actual, $time, $actual_index ) ];
			if ( null !== $previous ) {
				$before = $previous[2] - $previous[1];
				$after = $current[2] - $current[1];
				$segments = [ [ $previous, $current ] ];
				if ( ( $before < 0 && $after > 0 ) || ( $before > 0 && $after < 0 ) ) {
					$fraction = $before / ( $before - $after );
					$cross_time = $previous[0] + ( $time - $previous[0] ) * $fraction;
					$cross_value = $previous[1] + ( $current[1] - $previous[1] ) * $fraction;
					$cross = [ $cross_time, $cross_value, $cross_value ];
					$segments = [ [ $previous, $cross ], [ $cross, $current ] ];
				}
				foreach ( $segments as [ $a, $b ] ) {
					$difference = ( $a[2] - $a[1] ) + ( $b[2] - $b[1] );
					if ( 0.0 === (float) $difference ) {
						continue;
					}
					$regions[] = [
						'over' => $difference > 0,
						'points' => [ [ $a[0], $a[1] ], [ $b[0], $b[1] ], [ $b[0], $b[2] ], [ $a[0], $a[2] ] ],
					];
				}
			}
			$previous = $current;
		}
		return $regions;
	}

	private static function chart_overlay( int $id ): array {
		$sites = self::linked_gravity_forms( $id );
		$options = [ '' => __( 'None', 'stuh' ) ];
		$forms = [];
		if ( $sites ) {
			$options['forms'] = __( 'All forms', 'stuh' );
		}
		foreach ( $sites as $site ) {
			foreach ( $site['report']['forms'] ?? [] as $form ) {
				$key = 'form:' . rawurlencode( $site['id'] ) . ':' . $form['form_id'];
				$options[ $key ] = $site['name'] . ' - ' . $form['form_title'] . ' (#' . $form['form_id'] . ')';
				$forms[ $key ] = $form['months'];
			}
		}
		if ( $sites ) {
			$options['analytics'] = __( 'All websites', 'stuh' );
			foreach ( $sites as $site ) {
				$options[ 'analytics:' . rawurlencode( $site['id'] ) ] = $site['name'];
			}
		}
		$selected = self::input( $_GET, 'chart_overlay' );
		if ( ( isset( $_GET['chart_overlay'] ) && ! is_string( $_GET['chart_overlay'] ) ) || ! array_key_exists( $selected, $options ) ) {
			wp_die( esc_html__( 'Invalid chart overlay. Choose a dataset from the list.', 'stuh' ), '', [ 'response' => 400 ] );
		}
		$result = [ 'options' => $options, 'selected' => $selected, 'label' => $options[ $selected ], 'months' => [], 'datasets' => [], 'warnings' => [] ];
		if ( '' === $selected ) {
			return $result;
		}
		$sources = [];
		$unavailable = false;
		if ( isset( $forms[ $selected ] ) ) {
			$sources[] = $forms[ $selected ];
		} elseif ( 'forms' === $selected ) {
			$sources = array_values( $forms );
			foreach ( $forms as $key => $months ) {
				if ( $months ) {
					$result['datasets'][] = [ 'label' => $options[ $key ], 'months' => $months ];
				}
			}
			foreach ( $sites as $site ) {
				if ( ! $site['exists'] || null === $site['report'] ) {
					$result['warnings'][] = $site['name'] . ': ' . self::gravity_forms_status( $site );
				}
			}
		} else {
			foreach ( $sites as $site ) {
				if ( 'analytics' !== $selected && 'analytics:' . rawurlencode( $site['id'] ) !== $selected ) {
					continue;
				}
				$history = ! $site['exists']
					? new WP_Error( 'missing_site', __( 'Client site no longer exists.', 'stuh' ) )
					: STUH_Analytics::monthly_active_users( $site['id'] );
				if ( is_wp_error( $history ) ) {
					$result['warnings'][] = $site['name'] . ': ' . $history->get_error_message();
					$unavailable = true;
					continue;
				}
				$sources[] = $history['months'];
				if ( 'analytics' === $selected ) {
					$result['datasets'][] = [ 'label' => $site['name'], 'months' => $history['months'] ];
				}
				foreach ( $history['warnings'] as $warning ) {
					$result['warnings'][] = $site['name'] . ': ' . $warning;
				}
			}
		}
		if ( ! $unavailable && $sources ) {
			$months = array_unique( array_merge( ...array_map( 'array_keys', $sources ) ) );
			foreach ( $months as $month ) {
				$total = 0;
				foreach ( $sources as $source ) {
					$value = $source[ $month ] ?? null;
					if ( null === $value ) {
						if ( 'forms' === $selected ) {
							continue;
						}
						$total = null;
						break;
					}
					$total += $value;
					if ( ! is_finite( (float) $total ) || $total > 9007199254740991 ) {
						$result['warnings'][] = __( 'An overlay total is too large to display safely.', 'stuh' );
						$total = null;
						break;
					}
				}
				$result['months'][ $month ] = $total;
			}
		}
		return $result;
	}

	private static function chart_releases( int $id ): array {
		$clients = array_column( STUH_Plugin::get_clients(), null, 'id' );
		$telemetry = STUH_Plugin::get_telemetry();
		$repos = [];
		foreach ( self::project_site_ids( $id ) as $client_id ) {
			$repo = $telemetry[ $client_id ]['data']['active_theme']['github_repo'] ?? '';
			if ( isset( $clients[ $client_id ] ) && is_string( $repo ) && '' !== trim( $repo ) ) {
				$repos[ strtolower( trim( $repo ) ) ] = true;
			}
		}
		$result = [ 'releases' => [], 'warnings' => [] ];
		foreach ( array_keys( $repos ) as $repo ) {
			$history = STUH_Plugin::theme_release_history( $repo );
			if ( is_wp_error( $history ) ) {
				$result['warnings'][] = $repo . ': ' . $history->get_error_message();
			} else {
				$result['releases'] = array_merge( $result['releases'], $history );
			}
		}
		return $result;
	}

	private static function render_budget_chart( array $project, array $chart, string $unit, ?array $overlay = null, array $release_history = [] ): void {
		$title = __( 'Budget over time', 'stuh' );
		$axis = $chart['axis'] ?? array_slice( $chart['points'], 1 );
		$current_month = $chart['current_month'] ?? wp_date( 'Y-m', time() );
		$secondary = null;
		$secondary_series = [];
		$secondary_values = [];
		$overlay_selection = $overlay['selected'] ?? '';
		$secondary_label = 'analytics' === $overlay_selection || str_starts_with( $overlay_selection, 'analytics:' ) ? __( 'Active users', 'stuh' ) : __( 'Form entries', 'stuh' );
		if ( null !== $overlay && '' !== $overlay['selected'] ) {
			$cursor = new DateTimeImmutable( substr( $chart['usage'][0]['date'] ?? $project['startdate'], 0, 7 ) . '-01', new DateTimeZone( 'UTC' ) );
			$last = min( substr( $axis[ count( $axis ) - 1 ]['date'], 0, 7 ), wp_date( 'Y-m', time() ) );
			$secondary = [ 'label' => $secondary_label, 'scale' => 'secondary', 'stroke' => '#8c45a8', 'dash' => [], 'points' => [] ];
			while ( $cursor->format( 'Y-m' ) <= $last ) {
				$value = $overlay['months'][ $cursor->format( 'Y-m' ) ] ?? null;
				$secondary['points'][] = [ $cursor->getTimestamp(), $value ];
				$secondary_values[ $cursor->format( 'Y-m' ) ] = $value;
				$cursor = $cursor->modify( '+1 month' );
			}
			if ( $last === $current_month && null !== ( $secondary_values[ $current_month ] ?? null ) ) {
				$secondary['provisional'] = true;
			}
			if ( ! array_filter( $secondary_values, static fn( $value ): bool => null !== $value ) ) {
				$overlay['warnings'][] = __( 'No overlay data available in this chart period. Missing reports are not zero.', 'stuh' );
				$secondary = null;
			}
			if ( null !== $secondary ) {
				foreach ( $overlay['datasets'] ?? [] as $index => $dataset ) {
					$item = $secondary;
					$hue = ( 275 + $index * 137 ) % 360;
					$item['label'] = $dataset['label'];
					$item['stroke'] = 'hsl(' . $hue . ',55%,42%)';
					$item['fill'] = 'hsla(' . $hue . ',55%,42%,0.28)';
					$item['stacked'] = true;
					$item['points'] = array_map( static fn( array $point ): array => [ $point[0], $dataset['months'][ gmdate( 'Y-m', $point[0] ) ] ?? null ], $secondary['points'] );
					$secondary_series[] = $item;
				}
				if ( ! $secondary_series ) {
					$secondary_series[] = $secondary;
				}
			}
		}
		$month_number = static function( string $date ): int {
			return (int) substr( $date, 0, 4 ) * 12 + (int) substr( $date, 5, 2 ) - 1;
		};
		$first_month = $month_number( $chart['usage'][0]['date'] ?? $project['startdate'] ) - 1;
		$months = $month_number( $axis[ count( $axis ) - 1 ]['date'] ) - $first_month + 1;
		$width = max( 960, ( count( $axis ) + 1 ) * 70 + 150 );
		$left = 110;
		$right = $width - ( null === $secondary ? 40 : 140 );
		$values = array_merge( [ 0, $project['budget'] ], array_column( $chart['usage'] ?? [], 'actual' ), array_column( $chart['usage'] ?? [], 'invoiced' ), array_column( $chart['monthly_usage'] ?? [], 'actual' ) );
		$minimum = min( $values );
		$maximum = max( 'hours' === $unit ? 9000 : 100, max( $values ) );
		$x_position = static fn( float $value ): string => number_format( $left + $value / $months * ( $right - $left ), 2, '.', '' );
		$month_x = static fn( string $date, bool $baseline = false ): string => $x_position( $month_number( $date ) - $first_month + 0.5 - ( $baseline ? 1 : 0 ) );
		$y_position = static fn( int $value ): string => number_format( 300 - ( $value - $minimum ) / ( $maximum - $minimum ) * 240, 2, '.', '' );
		$budget_y = $y_position( $project['budget'] );
		$zero_y = $y_position( 0 );
		$timestamp = static function( string $date, bool $end ): int {
			$month = new DateTimeImmutable( substr( $date, 0, 7 ) . '-01', new DateTimeZone( 'UTC' ) );
			return ( $end ? $month : $month->modify( '-1 month' ) )->getTimestamp();
		};
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
			'dateLabel' => __( 'Month', 'stuh' ),
			'series' => [
				[ 'label' => __( 'Total budget', 'stuh' ), 'show' => false, 'stroke' => '#646970', 'dash' => [ 6, 4 ], 'points' => [ [ $timestamp( $start_date, false ), $project['budget'] ], [ $timestamp( $end_date, true ), $project['budget'] ] ] ],
				[ 'label' => __( 'Allowance', 'stuh' ), 'stroke' => '#2271b1', 'dash' => [], 'points' => $coordinates( $chart['points'], 'cumulative' ) ],
			],
		];
		if ( isset( $chart['usage'] ) ) {
			$interactive['series'][] = [ 'label' => __( 'Recorded time', 'stuh' ), 'stroke' => '#d63638', 'dash' => [], 'points' => $coordinates( $chart['usage'], 'actual' ) ];
			$last_usage = $chart['usage'] ? $chart['usage'][ count( $chart['usage'] ) - 1 ] : null;
			$provisional = null !== $last_usage && substr( $last_usage['date'], 0, 7 ) === $chart['current_month'] && count( $chart['usage'] ) > 1;
			if ( $provisional ) {
				$interactive['series'][2]['provisional'] = true;
			}
			$interactive['series'][] = [ 'label' => __( 'Invoiced', 'stuh' ), 'show' => false, 'stroke' => '#008a20', 'dash' => [ 8, 4 ], 'points' => $coordinates( $chart['usage'], 'invoiced' ) ];
			if ( $provisional ) {
				$interactive['series'][3]['provisional'] = true;
			}
			$bars = [ 'label' => __( 'Monthly hours', 'stuh' ), 'type' => 'bars', 'stroke' => '#b38600', 'fill' => 'rgba(219,166,23,0.35)', 'points' => [], 'periods' => [] ];
			foreach ( $chart['monthly_usage'] as $point ) {
				$center = $timestamp( $point['date'], true );
				$period = [ $center - 12 * 86400, $center + 12 * 86400 ];
				$bars['points'][] = [ $center, $point['actual'] ];
				$bars['periods'][] = $period;
			}
			if ( $chart['monthly_usage'] && substr( $chart['monthly_usage'][ count( $chart['monthly_usage'] ) - 1 ]['date'], 0, 7 ) === $current_month ) {
				$bars['provisional'] = true;
			}
			$interactive['series'][] = $bars;
			$interactive['variance'] = self::budget_variance_regions( $interactive['series'][1]['points'], $interactive['series'][2]['points'] );
			$interactive['series'][2]['releases'] = [];
			foreach ( $release_history['releases'] ?? [] as $release ) {
				$points = $interactive['series'][2]['points'];
				for ( $index = 1; $index < count( $points ); $index++ ) {
					[ $start, $from ] = $points[ $index - 1 ];
					[ $end, $to ] = $points[ $index ];
					if ( $release['timestamp'] >= $start && $release['timestamp'] <= $end && $end > $start ) {
						$release['value'] = $from + ( $to - $from ) * ( $release['timestamp'] - $start ) / ( $end - $start );
						$interactive['series'][2]['releases'][] = $release;
						break;
					}
				}
			}
		}
		if ( null !== $secondary ) {
			$interactive['secondaryLabel'] = $secondary_label;
			if ( ! empty( $secondary_series[0]['stacked'] ) ) {
				$interactive['stackTotals'] = $secondary['points'];
			}
			$interactive['series'] = array_merge( $interactive['series'], $secondary_series );
		}
		$releases = $interactive['series'][2]['releases'] ?? [];
		if ( $releases ) {
			$interactive['releaseLabel'] = __( 'Theme releases', 'stuh' );
		}
		echo '<figure class="stuh-analytics-chart stuh-analytics-history stuh-fmp-budget-chart" data-stuh-fmp-chart="' . esc_attr( wp_json_encode( $interactive ) ) . '"><figcaption><h2>' . esc_html( $title ) . '</h2></figcaption>';
		echo '<ul class="stuh-analytics-legend" data-stuh-fmp-static-legend><li class="stuh-analytics-legend--previous">' . esc_html__( 'Total project budget', 'stuh' ) . '</li><li>' . esc_html__( 'Accumulated monthly allowance', 'stuh' ) . '</li>';
		if ( isset( $chart['usage'] ) ) {
			echo '<li class="stuh-fmp-legend-actual">' . esc_html__( 'Actual recorded time', 'stuh' ) . '</li><li class="stuh-fmp-legend-invoiced">' . esc_html__( 'Invoiced value', 'stuh' ) . '</li><li class="stuh-fmp-legend-monthly">' . esc_html__( 'Actual hours this month', 'stuh' ) . '</li>';
		}
		foreach ( $secondary_series as $item ) {
			echo '<li class="stuh-fmp-legend-secondary" style="--stuh-fmp-series-color:' . esc_attr( $item['stroke'] ) . '">' . esc_html( $item['label'] ) . '</li>';
		}
		if ( $releases ) {
			echo '<li class="stuh-fmp-legend-releases">' . esc_html( $interactive['releaseLabel'] ) . '</li>';
		}
		echo '</ul>';
		if ( ! isset( $chart['usage'] ) ) {
			echo '<p>' . esc_html__( 'Recorded time and invoiced usage are unavailable; only planned budget lines are shown.', 'stuh' ) . '</p>';
		}
		echo '<p class="notice notice-warning inline" data-stuh-fmp-chart-error hidden>' . esc_html__( 'The interactive chart could not load. The static chart remains available.', 'stuh' ) . '</p>';
		echo '<div data-stuh-fmp-interactive hidden><div class="stuh-fmp-chart-toolbar"><span data-stuh-fmp-range role="status" aria-live="polite"></span>';
		echo '<button type="button" class="button-link" data-stuh-fmp-reset disabled hidden>' . esc_html__( 'Reset zoom', 'stuh' ) . '</button><span id="stuh-fmp-zoom-help" class="stuh-fmp-zoom-hint">' . esc_html__( 'Drag to zoom', 'stuh' ) . '</span></div>';
		echo '<div class="stuh-fmp-interactive-plot" data-stuh-fmp-plot role="region" tabindex="0" aria-label="' . esc_attr( $title ) . '" aria-describedby="stuh-fmp-zoom-help"></div></div>';
		echo '<div class="stuh-analytics-line-scroll" data-stuh-fmp-static tabindex="0" role="region" aria-label="' . esc_attr( $title ) . '"><svg class="stuh-analytics-line-chart stuh-fmp-budget-svg" viewBox="0 0 ' . esc_attr( (string) $width ) . ' 380" style="min-width:' . esc_attr( (string) $width ) . 'px" role="img" aria-labelledby="stuh-fmp-chart-title stuh-fmp-chart-desc">';
		echo '<title id="stuh-fmp-chart-title">' . esc_html( $title ) . '</title><desc id="stuh-fmp-chart-desc">' . esc_html__( 'Dashed grey: total budget. Blue: accumulated monthly allowance. When available, red: recorded time; dashed green: invoiced value; gold bars: actual hours per month.', 'stuh' ) . '</desc>';
		for ( $tick = 0; $tick <= 4; $tick++ ) {
			$y = 300 - $tick * 60;
			echo '<line class="stuh-analytics-gridline" x1="' . $left . '" y1="' . $y . '" x2="' . esc_attr( (string) $right ) . '" y2="' . $y . '"/><text x="100" y="' . ( $y + 4 ) . '" text-anchor="end">' . esc_html( self::display_amount( (int) round( $minimum + ( $maximum - $minimum ) * $tick / 4 ), $unit ) ) . '</text>';
		}
		echo '<text transform="translate(22 180) rotate(-90)" text-anchor="middle">' . esc_html( 'hours' === $unit ? __( 'Budget (hours)', 'stuh' ) : __( 'Budget (EUR)', 'stuh' ) ) . '</text>';
		if ( null !== $secondary ) {
			$secondary_max = max( 1, max( $secondary_values ) );
			$secondary_ticks = min( 4, (int) $secondary_max );
			$secondary_max = ceil( $secondary_max / $secondary_ticks ) * $secondary_ticks;
			$secondary_y = static fn( $value ): string => number_format( 300 - $value / $secondary_max * 240, 2, '.', '' );
			for ( $tick = 0; $tick <= $secondary_ticks; $tick++ ) {
				echo '<text x="' . esc_attr( (string) ( $right + 10 ) ) . '" y="' . esc_attr( (string) ( 304 - $tick / $secondary_ticks * 240 ) ) . '" fill="#8c45a8">' . esc_html( number_format_i18n( $secondary_max * $tick / $secondary_ticks ) ) . '</text>';
			}
			echo '<text transform="translate(' . esc_attr( (string) ( $width - 20 ) ) . ' 180) rotate(90)" text-anchor="middle">' . esc_html( $secondary_label ) . '</text>';
			$bases = array_fill_keys( array_keys( $secondary_values ), 0 );
			foreach ( $secondary_series as $item ) {
				$previous = null;
				foreach ( $item['points'] as [ $time, $raw ] ) {
					$month = gmdate( 'Y-m', $time );
					$stacked = ! empty( $item['stacked'] );
					$value = $stacked ? ( null === $secondary_values[ $month ] ? null : $bases[ $month ] + ( $raw ?? 0 ) ) : $raw;
					if ( null === $value ) {
						$previous = null;
						continue;
					}
					$x = $month_x( $month . '-01' );
					$y = $secondary_y( $value );
					$bottom = $secondary_y( $bases[ $month ] );
					if ( null !== $previous ) {
						if ( $stacked ) {
							echo '<polygon class="stuh-fmp-stack-area" fill="' . esc_attr( $item['fill'] ) . '" points="' . esc_attr( $previous[0] . ',' . $previous[1] . ' ' . $x . ',' . $y . ' ' . $x . ',' . $bottom . ' ' . $previous[0] . ',' . $previous[2] ) . '"/>';
						}
						echo '<polyline fill="none" stroke="' . esc_attr( $item['stroke'] ) . '" stroke-width="2"' . ( $month === $current_month && ! empty( $item['provisional'] ) ? ' stroke-dasharray="2 4"' : '' ) . ' points="' . esc_attr( $previous[0] . ',' . $previous[1] . ' ' . $x . ',' . $y ) . '"/>';
					}
					echo '<circle fill="' . esc_attr( $item['stroke'] ) . '" cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="3"><title>' . esc_html( $month . ' - ' . $item['label'] . ': ' . ( null === $raw ? __( 'Not reported', 'stuh' ) : number_format_i18n( $raw ) ) ) . '</title></circle>';
					$previous = [ $x, $y, $bottom ];
					$bases[ $month ] = $value;
				}
			}
		}
		echo '<text x="' . esc_attr( (string) ( ( $left + $right ) / 2 ) ) . '" y="365" text-anchor="middle">' . esc_html__( 'Months', 'stuh' ) . '</text>';
		$points = [];
		$dots = '';
		foreach ( $axis as $point ) {
			$date = new DateTimeImmutable( $point['date'], wp_timezone() );
			echo '<text x="' . esc_attr( $month_x( $point['date'] ) ) . '" y="327" text-anchor="middle">' . esc_html( wp_date( 'M Y', $date->getTimestamp(), wp_timezone() ) ) . '</text>';
		}
		foreach ( $chart['points'] as $index => $point ) {
			$x = $month_x( $point['date'], 0 === $index );
			$y = $y_position( $point['cumulative'] );
			$points[] = $x . ',' . $y;
			$dots .= '<circle cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="4"><title>' . esc_html( substr( $point['date'], 0, 7 ) . ': ' . self::display_amount( $point['cumulative'], $unit ) ) . '</title></circle>';
		}
		$band_y = static fn( float $value ): string => number_format( 300 - ( $value - $minimum ) / ( $maximum - $minimum ) * 240, 2, '.', '' );
		$time_x = static function( int|float $time ) use ( $x_position, $month_number, $first_month ): string {
			$date = new DateTimeImmutable( '@' . (int) floor( $time ) );
			$month_start = $date->modify( 'first day of this month' )->setTime( 0, 0 );
			$next_month = $month_start->modify( '+1 month' );
			$fraction = ( $time - $month_start->getTimestamp() ) / ( $next_month->getTimestamp() - $month_start->getTimestamp() );
			return $x_position( $month_number( $date->format( 'Y-m-d' ) ) - $first_month + 0.5 + $fraction );
		};
		foreach ( $interactive['variance'] ?? [] as $region ) {
			$polygon = [];
			foreach ( $region['points'] as [ $time, $value ] ) {
				$polygon[] = $time_x( $time ) . ',' . $band_y( $value );
			}
			echo '<polygon class="stuh-fmp-variance-' . ( $region['over'] ? 'over' : 'under' ) . '" points="' . esc_attr( implode( ' ', $polygon ) ) . '"/>';
		}
		foreach ( $chart['monthly_usage'] ?? [] as $point ) {
			$center_x = (float) $month_x( $point['date'] );
			$start_x = $center_x - ( $right - $left ) / $months / 2;
			$end_x = $center_x + ( $right - $left ) / $months / 2;
			$y = (float) $y_position( $point['actual'] );
			$bar_title = substr( $point['date'], 0, 7 ) . ' - ' . __( 'Actual hours this month', 'stuh' ) . ': ' . self::display_amount( $point['actual'], 'hours' );
			if ( 'hours' !== $unit ) {
				$bar_title .= ' (' . self::display_amount( $point['actual'], $unit ) . ')';
			}
			echo '<rect class="stuh-fmp-monthly-bar"' . ( substr( $point['date'], 0, 7 ) === $current_month ? ' stroke-dasharray="2 4"' : '' ) . ' x="' . esc_attr( (string) ( $start_x + ( $end_x - $start_x ) * 0.175 ) ) . '" y="' . esc_attr( (string) min( (float) $zero_y, $y ) ) . '" width="' . esc_attr( (string) ( ( $end_x - $start_x ) * 0.65 ) ) . '" height="' . esc_attr( (string) abs( (float) $zero_y - $y ) ) . '"><title>' . esc_html( $bar_title ) . '</title></rect>';
		}
		echo '<line class="stuh-fmp-budget-limit" x1="' . $left . '" y1="' . esc_attr( $budget_y ) . '" x2="' . esc_attr( (string) $right ) . '" y2="' . esc_attr( $budget_y ) . '"/>';
		echo '<g class="stuh-analytics-series"><polyline class="stuh-fmp-budget-cumulative" points="' . esc_attr( implode( ' ', $points ) ) . '"/>' . $dots . '</g>';
		foreach ( [ 'actual' => __( 'Actual recorded time', 'stuh' ), 'invoiced' => __( 'Invoiced value', 'stuh' ) ] as $field => $label ) {
			$points = [];
			$dots = '';
			foreach ( $chart['usage'] ?? [] as $index => $point ) {
				$x = $month_x( $point['date'], 0 === $index );
				$y = $y_position( $point[ $field ] );
				$points[] = $x . ',' . $y;
				$dots .= '<circle cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="4"><title>' . esc_html( substr( $point['date'], 0, 7 ) . ' - ' . $label . ': ' . self::display_amount( $point[ $field ], $unit ) ) . '</title></circle>';
			}
			if ( $points ) {
				$dotted = '';
				if ( $provisional ) {
					$last = array_pop( $points );
					$dotted = '<polyline stroke-dasharray="2 4" style="stroke-dasharray:2 4" points="' . esc_attr( end( $points ) . ' ' . $last ) . '"/>';
				}
				echo '<g class="stuh-analytics-series stuh-fmp-series-' . esc_attr( $field ) . '"><polyline points="' . esc_attr( implode( ' ', $points ) ) . '"/>' . $dotted . $dots . '</g>';
			}
		}
		foreach ( $releases as $release ) {
			echo '<a href="' . esc_url( $release['url'] ) . '" target="_blank" rel="noopener noreferrer"><rect x="' . esc_attr( (string) ( (float) $time_x( $release['timestamp'] ) - 4 ) ) . '" y="' . esc_attr( (string) ( (float) $band_y( $release['value'] ) - 4 ) ) . '" width="8" height="8" fill="#d63638" stroke="#fff"><title>' . esc_html( $release['label'] ) . '</title></rect></a>';
		}
		echo '</svg></div>';
		foreach ( $release_history['warnings'] ?? [] as $warning ) {
			echo '<p role="alert">' . esc_html( __( 'Theme releases', 'stuh' ) . ' - ' . $warning ) . '</p>';
		}
		if ( null !== $overlay ) {
			echo '<form class="stuh-fmp-chart-overlay" method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '"><p>';
			foreach ( [ 'page' => 'stuh-fmp', 'project_id' => $project['id'], 'offset' => self::offset( $_GET ), 'unit' => $unit ] as $key => $value ) {
				echo '<input type="hidden" name="' . esc_attr( $key ) . '" value="' . esc_attr( (string) $value ) . '">';
			}
			echo '<label for="stuh-fmp-overlay">' . esc_html__( 'Secondary dataset', 'stuh' ) . '</label> <select id="stuh-fmp-overlay" name="chart_overlay">';
			if ( isset( $overlay['options'][''] ) ) {
				echo '<option value=""' . ( '' === $overlay['selected'] ? ' selected' : '' ) . '>' . esc_html( $overlay['options'][''] ) . '</option>';
			}
			foreach ( [ 'forms' => __( 'Forms', 'stuh' ), 'analytics' => __( 'Analytics', 'stuh' ) ] as $group => $group_label ) {
				$prefix = 'forms' === $group ? 'form:' : 'analytics:';
				$options = array_filter( $overlay['options'], static fn( string $value ): bool => $value === $group || str_starts_with( $value, $prefix ), ARRAY_FILTER_USE_KEY );
				if ( ! $options ) {
					continue;
				}
				echo '<optgroup label="' . esc_attr( $group_label ) . '">';
				foreach ( $options as $value => $label ) {
					echo '<option value="' . esc_attr( $value ) . '"' . ( $overlay['selected'] === $value ? ' selected' : '' ) . '>' . esc_html( $label ) . '</option>';
				}
				echo '</optgroup>';
			}
			echo '</select> <button type="submit" class="button">' . esc_html__( 'Apply overlay', 'stuh' ) . '</button></p></form>';
			foreach ( array_unique( $overlay['warnings'] ) as $warning ) {
				echo '<p role="alert">' . esc_html( $warning ) . '</p>';
			}
		}
		echo '</figure>';
	}

	public static function render_dashboard(): void {
		self::require_viewer();
		$offset = self::offset( $_GET );
		$unit = self::display_unit( $_GET );
		$project_id = self::selected_project( $_GET );
		if ( null !== $project_id ) {
			self::render_project_details( $project_id, $offset, $unit );
			return;
		}
		echo '<div class="wrap"><h1>' . esc_html__( 'FMP', 'stuh' ) . '</h1>';
		self::notice();
		echo '<p>' . esc_html__( 'Projecten / Retainers from Gripp, including archived umbrella projects. Individual orders (Opdrachten) are not shown.', 'stuh' );
		if ( current_user_can( 'manage_options' ) ) {
			echo ' <a href="' . esc_url( self::settings_url() ) . '">' . esc_html__( 'Gripp settings', 'stuh' ) . '</a>';
		}
		echo '</p>';
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
		echo '<p>' . esc_html__( 'Budget used is the total value of all linked orders excluding VAT, including archived orders; it is committed value, not hours or invoices. Real budget left to date is allowance to date minus all logged hours through today at EUR 90 per hour, including Concept entries, archived orders and zero-value work, excluding products marked (ND / intern). Monthly allowances use calendar months, prorating partial months by days. Allowance to date includes today in the WordPress timezone. Schedule compares committed budget usage, not work completed.', 'stuh' ) . '</p>';
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
