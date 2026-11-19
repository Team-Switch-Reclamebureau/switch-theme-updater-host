<?php
/**
 * Standalone client-view regression checks: php tests/client-details.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );

class ViewRedirect extends RuntimeException {}
class WP_Error {
	public function __construct( private string $code, private string $message, private $data = null ) {}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}
function __( $text, $domain = '' ) { return $text; }
function _n( $single, $plural, $count, $domain = '' ) { return 1 === $count ? $single : $plural; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function number_format_i18n( $value, $decimals = 0 ) { return number_format( $value, $decimals ); }
function esc_textarea( $value ) { return esc_html( $value ); }
function esc_js( $value ) { return addslashes( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function esc_url_raw( $value ) { return trim( $value ); }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_attr__( $text, $domain = '' ) { return esc_attr( $text ); }
function esc_html_e( $text, $domain = '' ) { echo esc_html( $text ); }
function esc_attr_e( $text, $domain = '' ) { echo esc_attr( $text ); }
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function plugin_dir_path( $file ) { return dirname( $file ) . '/'; }
function current_user_can( $capability ) { return $GLOBALS['authorized'] ?? true; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function wp_die( $message ) { throw new RuntimeException( $message ); }
function wp_unslash( $value ) { return $value; }
function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( $value ) ); }
function sanitize_html_class( $value ) { return preg_replace( '/[^A-Za-z0-9_-]/', '', $value ); }
function is_email( $value ) { return false !== filter_var( $value, FILTER_VALIDATE_EMAIL ); }
function get_option( $key, $default = false ) { return $GLOBALS['options'][ $key ] ?? $default; }
function update_option( $key, $value ) {
	if ( $GLOBALS['storage_fail'] ?? false ) { return false; }
	if ( get_option( $key ) === $value ) { return false; }
	$GLOBALS['options'][ $key ] = $value;
	return true;
}
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['transients'][ $key ] = $value; return true; }
function delete_transient( $key ) { unset( $GLOBALS['transients'][ $key ] ); }
function get_current_user_id() { return 1; }
function wp_next_scheduled( ...$args ) { return true; }
function wp_clear_scheduled_hook( ...$args ) {}
function get_current_screen() { return (object) [ 'id' => 'toplevel_page_stuh' ]; }
function get_column_headers( $screen ) { return ( new STUH_Plugin() )->client_columns(); }
function get_hidden_columns( $screen ) { return [ 'diagnostics', 'ssl' ]; }
function admin_url( $path ) { return 'https://host.example/wp-admin/' . $path; }
function add_query_arg( $key, $value, $url = null ) {
	$args = is_array( $key ) ? $key : [ $key => $value ];
	$url = is_array( $key ) ? $value : $url;
	$parts = explode( '?', $url, 2 );
	parse_str( $parts[1] ?? '', $query );
	return $parts[0] . '?' . http_build_query( array_merge( $query, $args ) );
}
function remove_query_arg( $key, $url ) {
	$parts = explode( '?', $url, 2 );
	parse_str( $parts[1] ?? '', $query );
	unset( $query[ $key ] );
	return $parts[0] . '?' . http_build_query( $query );
}
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function wp_parse_args( $args, $defaults ) { return array_merge( $defaults, $args ); }
function wp_json_encode( $value, $flags = 0 ) { return json_encode( $value, $flags ); }
function wp_nonce_field( $action ) { echo '<input type="hidden" name="_wpnonce" value="test-nonce">'; }
function check_admin_referer( $action ) {
	if ( 'test-nonce' !== ( $_POST['_wpnonce'] ?? '' ) ) {
		wp_die( 'Invalid nonce' );
	}
}
function wp_safe_redirect( $url ) { throw new ViewRedirect( $url ); }
function date_i18n( $format, $time ) { return gmdate( $format, $time ); }
function wp_date( $format, $time, $zone = null ) { return gmdate( $format, $time ); }
function wp_timezone() { return new DateTimeZone( 'UTC' ); }
function human_time_diff( $from, $to ) { return '1 hour'; }
function selected( $selected, $value ) { if ( $selected === $value ) { echo 'selected'; } }
function checked( $value ) { if ( $value ) { echo 'checked'; } }
function get_plugin_data( $file ) { return [ 'Version' => 'test' ]; }
function submit_button( $label ) { echo '<button type="submit">' . esc_html( $label ) . '</button>'; }

require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

set_error_handler( static function( $severity, $message, $file, $line ) {
	throw new ErrorException( $message, 0, $severity, $file, $line );
} );
function expect_view( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}
function render_view(): string {
	ob_start();
	try {
		( new STUH_Plugin() )->render_clients_page();
		return ob_get_contents();
	} finally {
		ob_end_clean();
	}
}
function view_xpath( string $html ): DOMXPath {
	$document = new DOMDocument();
	$previous = libxml_use_internal_errors( true );
	$document->loadHTML( '<!doctype html><html><body>' . $html . '</body></html>' );
	libxml_clear_errors();
	libxml_use_internal_errors( $previous );
	return new DOMXPath( $document );
}
function post_view_action( string $action, array $fields = [] ): string {
	$_POST = array_merge( [ 'stuh_action' => $action, 'client_id' => 'site-1', '_wpnonce' => 'test-nonce' ], $fields );
	try {
		( new STUH_Plugin() )->handle_admin_actions();
	} catch ( ViewRedirect $redirect ) {
		$_POST = [];
		return $redirect->getMessage();
	}
	throw new RuntimeException( 'Expected action redirect' );
}

$client = [
	'id' => 'site-1', 'site_url' => 'https://first.example',
	'site_urls' => [ 'https://first.example', 'https://second.example' ],
	'enabled' => true, 'created_at' => time(), 'last_seen' => time(),
	'last_seen_ip' => '', 'api_key' => 'test-key', 'tags' => [ 'webshop' ],
];
$GLOBALS['options'] = [
	STUH_OPTION_CLIENTS => [ $client, array_merge( $client, [
		'id' => 'site-2', 'site_url' => 'https://other.example', 'site_urls' => [ 'https://other.example' ], 'enabled' => false,
	] ) ],
	STUH_OPTION_EXTERNAL_PARTIES => [ [ 'id' => 'party-1', 'name' => 'Example owner', 'email' => 'owner@example.com' ] ],
	STUH_OPTION_TELEMETRY => [ 'site-1' => [
		'received_at' => time(), 'request_type' => 'versions',
		'data' => [
			'site' => [ 'title' => 'Example <script>alert(1)</script>', 'description' => 'A test website', 'login_url' => 'https://first.example/wp-login.php', 'search_engine_visibility' => false ],
			'runtime' => [ 'wordpress' => '6.9', 'php' => '8.4.1' ],
			'pending_updates' => 2,
			'packages' => [
				'plugins' => [ [ 'name' => 'Test Plugin', 'file' => 'test/test.php', 'version' => '1.2', 'active' => true ] ],
				'themes' => [ [ 'name' => 'Test Theme', 'stylesheet' => 'test-theme', 'version' => '2.0', 'active' => false ] ],
			],
			'smtp' => [ 'configured' => true, 'delivery' => false ],
			'debug' => [ 'wp_debug' => true, 'debug_display' => true ],
			'wp_config' => [ 'post_revisions' => true, 'core_upgrade_skip_new_bundled' => false ],
		],
	] ],
];
$GLOBALS['transients'] = [
	'stuh_wp_safety_' . md5( '6.9|8.4.1' ) => [ 'status' => 'outdated', 'latest' => '6.9.1', 'update' => '6.9.1' ],
	'stuh_php_lifecycle_v2' => [ 'releases' => [], 'error' => 'Test catalogue unavailable' ],
];
$_GET = [ 'page' => 'stuh', 'stuh_search' => 'webshop', 'stuh_status' => 'enabled' ];
$_POST = [];
$list = render_view();
$xpath = view_xpath( $list );
expect_view( 2 === $xpath->query( '//tr[contains(@class,"stuh-client-row") and @data-client-id]' )->length, 'List still shows all clients' );
expect_view( 2 === $xpath->query( '//td[contains(@class,"column-site_url")]/a[contains(@href,"client_id=site-1")]' )->length, 'Domains open website details' );
expect_view( 1 === $xpath->query( '//strong[contains(@class,"stuh-client-site-title")]/a[contains(@href,"client_id=site-1")]' )->length, 'Site title opens details' );
expect_view( 1 === $xpath->query( '//td[@class="column-site"]/a[contains(@href,"client_id=site-2")]' )->length, 'Sites without telemetry have a details link' );
expect_view( strpos( $list, 'class="open-site"' ) < strpos( $list, 'class="login"' ), 'Open site precedes Login' );
expect_view( 1 === $xpath->query( '//span[@class="open-site"]/a[@href="https://first.example" and @target="_blank"]' )->length, 'Open the first URL in a new tab' );
expect_view( 2 === $xpath->query( '//td[@class="column-ssl hidden"]' )->length, 'List honors hidden columns' );
expect_view( str_contains( $list, 'value="add_client"' ), 'List retains registration form' );
expect_view( 2 === $xpath->query( '//td[contains(@class,"column-telemetry_analytics")]/a[contains(@href,"#stuh-analytics") and text()="Not connected"]' )->length, 'Analytics column shows property connection state and links to the report panel' );

// Exercise the real heading sort with numeric counts, zero users and missing reports.
$original_clients = $GLOBALS['options'][ STUH_OPTION_CLIENTS ];
putenv( 'ANALYTICS_CLIENT_ID=view-client' );
putenv( 'ANALYTICS_CLIENT_SECRET=view-secret' );
putenv( 'STUH_GOOGLE_TOKEN_KEY=0123456789abcdef0123456789abcdef' );
$connection = [ 'id' => 'view-connection', 'client_id' => 'view-client', 'access_token' => 'view-access', 'refresh_token' => 'view-refresh', 'expires_at' => time() + 3600 ];
( new ReflectionMethod( STUH_Analytics::class, 'save_connection' ) )->invoke( null, $connection );
$mappings = [];
foreach ( [ 'site-1' => 20.0, 'site-2' => 100.0, 'site-zero' => 0.0, 'site-pending' => null ] as $id => $count ) {
	if ( ! in_array( $id, [ 'site-1', 'site-2' ], true ) ) {
		$GLOBALS['options'][ STUH_OPTION_CLIENTS ][] = array_merge( $client, [ 'id' => $id ] );
	}
	$mapping = [ 'connection_id' => 'view-connection', 'property_id' => '123', 'name' => 'View property', 'hostname' => 'first.example', 'timezone' => 'UTC' ];
	$mappings[ $id ] = $mapping;
	$record = [ 'fingerprint' => hash( 'sha256', json_encode( $mapping ) ) ];
	if ( null !== $count ) {
		$record += [
			'fetched_at' => time(),
			'data' => [
				'current' => [ 'activeUsers' => $count ], 'previous' => [ 'activeUsers' => 10.0 ],
				'period' => [ 'startDate' => '2026-10-01', 'endDate' => '2026-10-28' ],
				'previous_period' => [ 'startDate' => '2026-09-03', 'endDate' => '2026-09-30' ],
			],
		];
	}
	$GLOBALS['options'][ 'stuh_google_report_' . hash( 'sha256', $id ) ] = $record;
}
$GLOBALS['options'][ STUH_OPTION_CLIENTS ][] = array_merge( $client, [ 'id' => 'site-unmapped' ] );
$GLOBALS['options']['stuh_google_mappings'] = $mappings;
$_GET['orderby'] = 'telemetry_analytics';
foreach ( [
	'asc' => [ 'site-zero', 'site-1', 'site-2', 'site-pending', 'site-unmapped' ],
	'desc' => [ 'site-2', 'site-1', 'site-zero', 'site-pending', 'site-unmapped' ],
] as $order => $expected_ids ) {
	$_GET['order'] = $order;
	$sorted = view_xpath( render_view() );
	$actual_ids = [];
	foreach ( $sorted->query( '//tr[contains(@class,"stuh-client-row") and @data-client-id]' ) as $row ) {
		$actual_ids[] = $row->getAttribute( 'data-client-id' );
	}
	expect_view( $expected_ids === $actual_ids, 'Analytics heading sorts numerically with missing counts last: ' . $order );
	expect_view( 1 === $sorted->query( '//th[contains(@class,"column-telemetry_analytics")]/a[contains(@href,"orderby=telemetry_analytics") and contains(@href,"order=' . ( 'asc' === $order ? 'desc' : 'asc' ) . '")]' )->length, 'Analytics heading toggles sort direction' );
}
foreach ( array_keys( $mappings ) as $id ) {
	unset( $GLOBALS['options'][ 'stuh_google_report_' . hash( 'sha256', $id ) ] );
}
unset( $GLOBALS['options']['stuh_google_connection'], $GLOBALS['options']['stuh_google_mappings'], $_GET['orderby'], $_GET['order'] );
$GLOBALS['options'][ STUH_OPTION_CLIENTS ] = $original_clients;

ob_start();
( new STUH_Plugin() )->render_settings_page();
$settings = ob_get_clean();
$settings_xpath = view_xpath( $settings );
expect_view( 1 === $settings_xpath->query( '//h1' )->length && 1 === $settings_xpath->query( '//section[@id="stuh-google-settings"]/h2[text()="Google Analytics"]' )->length, 'Google controls are embedded in the existing Settings page below its single page heading' );
expect_view( 1 === $settings_xpath->query( '//section[@id="stuh-google-settings"]//form/input[@name="operation" and @value="connect"]' )->length, 'Settings page includes the Google connection form' );
expect_view( 0 === $settings_xpath->query( '//form//form' )->length, 'Embedded Google settings forms are not nested in the existing settings form' );
expect_view( 1 === $settings_xpath->query( '//form/input[@name="stuh_action" and @value="save_settings"]' )->length, 'Existing host settings form remains available' );
expect_view( 1 === $settings_xpath->query( '//section[@id="stuh-gripp-settings"]/h2[text()="Gripp"]' )->length, 'Gripp connection controls are embedded in Settings' );
expect_view( 1 === $settings_xpath->query( '//section[@id="stuh-gripp-settings"]//form/input[@name="operation" and @value="connect"]' )->length, 'Settings includes the separate Gripp connection form' );

$_GET['client_id'] = 'site-1';
if ( '--render' === ( $argv[1] ?? '' ) ) {
	$_GET['client_tab'] = $argv[2] ?? 'overview';
}
$GLOBALS['transients']['stuh_pending_updates_1'] = [ 'type' => 'success', 'message' => 'Updates installed' ];
$detail = render_view();
if ( '--render' === ( $argv[1] ?? '' ) ) {
	echo '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
	echo '<title>Website details preview</title><style>body{margin:24px;background:#f0f0f1;color:#1d2327;font:13px/1.5 sans-serif}a{color:#2271b1}h1{font-size:24px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px}button,input,textarea,select{font:inherit}.widefat{background:white}.row-actions{font-size:13px}';
	echo file_get_contents( dirname( __DIR__ ) . '/assets/css/client-sites.css' );
	echo '</style>' . $detail . '</html>';
	exit;
}
$details = [ 'overview' => $detail ];
foreach ( [ 'packages', 'forms', 'analytics', 'diagnostics' ] as $tab ) {
	$_GET['client_tab'] = $tab;
	$details[ $tab ] = render_view();
}
$tab_labels = [ 'Overview', 'Plugins & Themes', 'Forms', 'Analytics', 'Diagnostics' ];
foreach ( $details as $tab => $html ) {
	$tab_xpath = view_xpath( $html );
	$labels = [];
	foreach ( $tab_xpath->query( '//nav[@aria-label="Client site sections"]/a' ) as $link ) {
		$labels[] = $link->textContent;
		expect_view( str_contains( $link->getAttribute( 'href' ), 'client_id=site-1' ) && str_contains( $link->getAttribute( 'href' ), 'stuh_search=webshop' ) && str_contains( $link->getAttribute( 'href' ), 'stuh_status=enabled' ), 'Tab links preserve the selected client and list filters' );
	}
	expect_view( $tab_labels === $labels && 1 === $tab_xpath->query( '//nav/a[@aria-current="page" and contains(@class,"nav-tab-active") and contains(@href,"client_tab=' . $tab . '")]' )->length, 'Tabs retain the requested order and mark only the active section: ' . $tab );
	expect_view( ( 'overview' === $tab ? 4 : ( 'forms' === $tab ? 0 : 1 ) ) === $tab_xpath->query( '//section[contains(@class,"stuh-client-detail-group")]' )->length, 'Only the selected tab renders its information groups: ' . $tab );
	expect_view( ( 'forms' === $tab ? 1 : 0 ) === $tab_xpath->query( '//section[@class="stuh-gravity-forms-import"]' )->length && ( 'analytics' === $tab ? 1 : 0 ) === $tab_xpath->query( '//section[@id="stuh-analytics"]' )->length, 'Forms uploads and Analytics panels appear only in their respective tabs' );
	expect_view( ( 'forms' === $tab ? 1 : 0 ) === $tab_xpath->query( '//section[@class="stuh-client-gravity-forms"]' )->length, 'Combined form history is available only on the Forms tab' );
	expect_view( ( 'packages' === $tab ? 2 : 0 ) === $tab_xpath->query( '//table[contains(@class,"stuh-package-table")]' )->length && ( 'diagnostics' === $tab ? 1 : 0 ) === $tab_xpath->query( '//details[not(@open)]' )->length, 'Package inventories and raw diagnostics appear only in their respective tabs' );
	expect_view( ( 'overview' === $tab ? 1 : 0 ) === $tab_xpath->query( '//table[contains(@class,"stuh-client-detail-editors")]' )->length, 'Inline editors stay with their Overview controls' );
	$tab_back = $tab_xpath->query( '//a[contains(text(),"Back to Client Sites")]' )->item( 0 )->getAttribute( 'href' );
	expect_view( ! str_contains( $tab_back, 'client_id=' ) && ! str_contains( $tab_back, 'client_tab=' ), 'Back link clears detail selection and tab: ' . $tab );
}
foreach ( [ 'missing-tab', [ 'forms' ] ] as $invalid_tab ) {
	$_GET['client_tab'] = $invalid_tab;
	$fallback_xpath = view_xpath( render_view() );
	expect_view( 1 === $fallback_xpath->query( '//nav/a[@aria-current="page" and contains(@href,"client_tab=overview")]' )->length && 4 === $fallback_xpath->query( '//section[contains(@class,"stuh-client-detail-group")]' )->length, 'Unknown or malformed tab requests fall back to Overview without exposing other sections' );
}
unset( $_GET['client_tab'] );
$xpath = view_xpath( implode( '', $details ) );
$columns = ( new STUH_Plugin() )->client_columns();
expect_view( count( $columns ) === $xpath->query( '//div[contains(@class,"stuh-client-detail-field--")]' )->length, 'Every existing field appears on exactly one tab, independent of Screen Options' );
foreach ( array_keys( $columns ) as $column ) {
	expect_view( 1 === $xpath->query( '//section/div[@class="stuh-client-detail-field stuh-client-detail-field--' . $column . '"]/h3' )->length, 'Grouped field has label: ' . $column );
}
expect_view( 0 === $xpath->query( '//table//section' )->length, 'Detail cards are not nested in the list table' );
expect_view( 0 === $xpath->query( '//form//form' )->length, 'Action forms are not nested' );
expect_view( ! str_contains( $detail, 'other.example' ), 'Only the selected website is shown' );
expect_view( ! str_contains( $detail, 'id="stuh-client-search"' ) && ! str_contains( $detail, 'value="add_client"' ), 'Hide list-only controls on details' );
expect_view( str_contains( $detail, 'Updates installed' ), 'Action notices appear on the details page' );
expect_view( ! str_contains( $detail, '<script>alert(1)</script>' ), 'Reported titles are escaped' );
expect_view( 2 === $xpath->query( '//section[contains(@class,"--packages")]//table' )->length, 'Themes and plugins have separate tables' );
expect_view( 1 === $xpath->query( '//table[contains(@class,"--themes")]//tr[td/strong[text()="Test Theme"]]/td[text()="2.0"]' )->length, 'Theme table shows version' );
expect_view( 1 === $xpath->query( '//table[contains(@class,"--themes")]//tr[td/strong[text()="Test Theme"]]/td[text()="No"]' )->length, 'Theme table shows inactive status' );
expect_view( 1 === $xpath->query( '//table[contains(@class,"--plugins")]//tr[td/strong[text()="Test Plugin"]]/td[text()="Yes"]' )->length, 'Plugin table shows active status' );
expect_view( strpos( $details['packages'], 'stuh-package-table--themes' ) < strpos( $details['packages'], 'stuh-package-table--plugins' ), 'Themes appear before plugins' );
expect_view( 0 === $xpath->query( '//section[contains(@class,"--packages")]//details' )->length, 'Package tables are never collapsed' );
expect_view( 1 === $xpath->query( '//details[not(@open)]' )->length, 'Only raw diagnostics are collapsed initially' );
foreach ( [ 'toggle_client', 'delete_client', 'refresh_client_diagnostics', 'check_client_ssl', 'bulk_update_clients', 'install_wordpress_update', 'install_pending_updates', 'retry_failed_smtp_emails', 'disable_debugging', 'toggle_search_engine_visibility', 'set_post_revisions', 'skip_new_bundled_themes', 'edit_client_urls', 'edit_client_tags', 'assign_external_party' ] as $action ) {
	expect_view( $xpath->query( '//form/input[@name="stuh_action" and @value="' . $action . '"]' )->length > 0, 'Action available: ' . $action );
}
expect_view( 0 === $xpath->query( '//form[not(input[@name="_wpnonce"])]' )->length, 'Every action form has a nonce' );
$back = $xpath->query( '//a[contains(text(),"Back to Client Sites")]' )->item( 0 )->getAttribute( 'href' );
expect_view( ! str_contains( $back, 'client_id' ) && str_contains( $back, 'stuh_search=webshop' ) && str_contains( $back, 'stuh_status=enabled' ), 'Back link preserves list filters, not detail selection' );
expect_view( 1 === $xpath->query( '//form[@enctype="multipart/form-data" and input[@name="stuh_action" and @value="import_gravity_forms"] and input[@name="client_id" and @value="site-1"] and input[@name="_wpnonce"]]//input[@type="file" and @name="gravity_forms_file" and @accept=".json,application/json"]' )->length, 'Client details offer a nonce-protected JSON upload tied to the selected client' );
expect_view( ! str_contains( $list, 'value="import_gravity_forms"' ), 'History upload is not repeated on the client list' );
expect_view( str_contains( $details['forms'], 'No Gravity Forms report received yet.' ) && ! str_contains( $details['forms'], '<table id="stuh-client-gravity-forms"' ), 'The Forms tab distinguishes missing history from zero entries' );
$import_forms = static fn( string $id, string $json ) => ( new ReflectionMethod( STUH_Plugin::class, 'import_gravity_forms_json' ) )->invoke( null, $id, $json );
$GLOBALS['options'][ STUH_OPTION_TELEMETRY ]['site-1']['gravity_forms'] = [
	'received_at' => 100,
	'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Contact live', 'months' => [ '2026-10' => 8, '2026-11' => 7 ] ],
		[ 'form_id' => 3, 'form_title' => 'Reported only', 'months' => [ '2025-01' => 4 ] ],
	],
];
$before_import = STUH_Plugin::get_telemetry()['site-1'];
expect_view( true === $import_forms( 'site-1', '[{"form_id":1,"form_title":"Contact","months":{"2024-12":12,"2026-10":8},"entries":[{"email":"must-not-be-saved"}]}]' ), 'Import historical form counts using the client-reported array format' );
expect_view( array_diff_key( STUH_Plugin::get_telemetry()['site-1'], [ 'gravity_forms_import' => true ] ) === $before_import && ! str_contains( json_encode( STUH_Plugin::get_telemetry() ), 'must-not-be-saved' ), 'Imports preserve client-reported history, diagnostics and real last-received metadata and discard submission fields' );
$_GET['client_tab'] = 'forms';
$forms_xpath = view_xpath( render_view() );
expect_view( '8' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="October 2026"]/td[1]' )->item( 0 )->textContent && 0 === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="October 2026"]/td[1]/em' )->length && '12' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="December 2024"]/td[1]/em' )->item( 0 )->textContent, 'Equal counts use normal reported styling while imported-only counts are italicized' );
unset( $_GET['client_tab'] );
expect_view( true === $import_forms( 'site-2', '{"gravity_forms":[{"form_id":1,"form_title":"Other site","months":{"2024-12":99}}]}' ) && ! isset( STUH_Plugin::get_telemetry()['site-2']['received_at'] ), 'Accept a gravity_forms envelope for a site without prior telemetry without inventing a live report receipt' );
expect_view( true === $import_forms( 'site-1', '{"gravity_forms":[{"form_id":1,"form_title":"Contact renamed","months":{"2024-12":3,"2026-10":10,"2025-01":0}},{"form_id":2,"form_title":"Appointment","months":{"2025-01":5}}]}' ), 'Replace the previous uploaded snapshot, accepting lower historical counts in a new import' );
$imported_forms = STUH_Plugin::get_telemetry()['site-1']['gravity_forms_import']['forms'];
expect_view( [
	[ 'form_id' => 1, 'form_title' => 'Contact renamed', 'months' => [ '2024-12' => 3, '2026-10' => 10, '2025-01' => 0 ] ],
	[ 'form_id' => 2, 'form_title' => 'Appointment', 'months' => [ '2025-01' => 5 ] ],
] === $imported_forms && 99 === STUH_Plugin::get_telemetry()['site-2']['gravity_forms_import']['forms'][0]['months']['2024-12'] && $before_import['gravity_forms'] === STUH_Plugin::get_telemetry()['site-1']['gravity_forms'], 'Store imports separately, replace old uploaded counts, and leave all reported history and other clients untouched' );
$combined = STUH_Plugin::get_gravity_forms_report( 'site-1' );
expect_view( [
	[ 'form_id' => 1, 'form_title' => 'Contact live', 'months' => [ '2024-12' => 3, '2026-10' => 10, '2025-01' => 0, '2026-11' => 7 ] ],
	[ 'form_id' => 2, 'form_title' => 'Appointment', 'months' => [ '2025-01' => 5 ] ],
	[ 'form_id' => 3, 'form_title' => 'Reported only', 'months' => [ '2025-01' => 4 ] ],
] === $combined['forms'] && STUH_Plugin::get_telemetry()['site-1']['gravity_forms_import']['received_at'] === $combined['received_at'], 'Combine source maxima per form and month, union forms and months, prefer live titles and keep actual source timestamps' );
$before_render = STUH_Plugin::get_telemetry();
$_GET['client_tab'] = 'forms';
$forms_xpath = view_xpath( render_view() );
expect_view( '10' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="October 2026"]/td[1]/em' )->item( 0 )->textContent && '7' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="November 2026"]/td[1]' )->item( 0 )->textContent && 0 === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="November 2026"]/td[1]/em' )->length, 'The client Forms table italicizes imported maxima and keeps higher or exclusively live-reported values normal' );
expect_view( '0' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="January 2025"]/td[1]/em' )->item( 0 )->textContent && '5' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="January 2025"]/td[2]/em' )->item( 0 )->textContent && '4' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="January 2025"]/td[3]' )->item( 0 )->textContent, 'Imported zeros remain explicit italic zeros and forms unique to each source are separate columns' );
expect_view( 24 === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]/tbody/tr' )->length && 3 === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="February 2025"]/td[text()="-"]' )->length && 0 === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="February 2025"]//em' )->length && 'November 2026' === $forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]/tbody/tr[1]/th' )->item( 0 )->textContent, 'The monthly table includes missing months as non-italic dashes and sorts newest first' );
expect_view( $before_render === STUH_Plugin::get_telemetry(), 'Rendering combined history never changes either source' );
$_GET['client_id'] = 'site-2';
$other_forms_xpath = view_xpath( render_view() );
expect_view( '99' === $other_forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="December 2024"]/td/em' )->item( 0 )->textContent && 1 === $other_forms_xpath->query( '//table[@id="stuh-client-gravity-forms"]/tbody/tr' )->length, 'Imported-only clients display their own history entirely in italics without leaking another site\'s counts' );
$_GET['client_id'] = 'site-1';
unset( $_GET['client_tab'] );
$GLOBALS['options']['stuh_fmp_project_sites_99'] = [ 'site-1', 'site-2' ];
$fmp_sites = ( new ReflectionMethod( STUH_Gripp::class, 'linked_gravity_forms' ) )->invoke( null, 99 );
expect_view( $combined === $fmp_sites[0]['report'] && STUH_Plugin::get_telemetry()['site-2']['gravity_forms_import'] === $fmp_sites[1]['report'], 'FMP receives combined source data for each linked site, including imported-only sites' );
$combined_matrix = ( new ReflectionMethod( STUH_Gripp::class, 'gravity_forms_word_matrix' ) )->invoke( null, $combined['forms'], '2026-10', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
$combined_xpath = view_xpath( $combined_matrix );
expect_view( '10' === $combined_xpath->query( '//tr[th/strong="OKT"]/td[last()]' )->item( 0 )->textContent && '9' === $combined_xpath->query( '//tr[th="JAN" and td="5"]/td[last()]' )->item( 0 )->textContent, 'Word matrix totals use the maximum overlapping count and combine distinct forms from both sources without double counting' );
unset( $GLOBALS['options']['stuh_fmp_project_sites_99'] );
$replacement = '[{"form_id":1,"form_title":"Contact renamed","months":{"2026-10":2}}]';
$import_forms( 'site-1', $replacement );
expect_view( [ [ 'form_id' => 1, 'form_title' => 'Contact renamed', 'months' => [ '2026-10' => 2 ] ] ] === STUH_Plugin::get_telemetry()['site-1']['gravity_forms_import']['forms'] && 8 === STUH_Plugin::get_gravity_forms_report( 'site-1' )['forms'][0]['months']['2026-10'] && ! isset( STUH_Plugin::get_gravity_forms_report( 'site-1' )['forms'][0]['months']['2024-12'] ) && 2 === count( STUH_Plugin::get_gravity_forms_report( 'site-1' )['forms'] ), 'A replacement removes omitted imported-only months and forms, and falls back to the untouched reported count when the new upload is lower' );
$_GET['client_tab'] = 'forms';
$replaced_forms = view_xpath( render_view() );
expect_view( '8' === $replaced_forms->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="October 2026"]/td[1]' )->item( 0 )->textContent && 0 === $replaced_forms->query( '//table[@id="stuh-client-gravity-forms"]//em' )->length && 0 === $replaced_forms->query( '//table[@id="stuh-client-gravity-forms"]//tr[th="December 2024"]' )->length && 3 === $replaced_forms->query( '//table[@id="stuh-client-gravity-forms"]/thead/tr/th' )->length, 'Re-uploading lower counts immediately restores normal reported numbers and removes obsolete imported-only months and forms from the table' );
unset( $_GET['client_tab'] );
$import_forms( 'site-1', '[]' );
expect_view( [] === STUH_Plugin::get_telemetry()['site-1']['gravity_forms_import']['forms'] && $before_import['gravity_forms']['forms'] === STUH_Plugin::get_gravity_forms_report( 'site-1' )['forms'], 'An empty upload clears only the imported snapshot, retaining all client-reported history' );
expect_view( true === $import_forms( 'site-1', '[]' . str_repeat( ' ', 1048574 ) ), 'Accept a valid JSON file exactly at the 1 MB size limit' );
$import_forms( 'site-1', $replacement );
$import_forms( 'site-1', $replacement );
expect_view( 2 === STUH_Plugin::get_telemetry()['site-1']['gravity_forms_import']['forms'][0]['months']['2026-10'] && $before_import['gravity_forms'] === STUH_Plugin::get_telemetry()['site-1']['gravity_forms'], 'Repeated uploads do not add counts or mutate reported history' );
foreach ( [ '{', 'null', '{}', '{"gravity_forms":{}}', '[{"form_id":1,"form_title":"Bad","months":[]}]', '[{"form_id":1,"form_title":"Bad","months":{"2025-13":1}}]', '[{"form_id":1,"form_title":"Bad","months":{"2025-01":-1}}]', str_repeat( ' ', 1048577 ) ] as $invalid_json ) {
	$before = STUH_Plugin::get_telemetry();
	expect_view( is_wp_error( $import_forms( 'site-1', $invalid_json ) ) && $before === STUH_Plugin::get_telemetry(), 'Reject malformed, invalid or oversized imports atomically' );
}
expect_view( is_wp_error( $import_forms( 'unknown', '[]' ) ), 'Do not import into removed or unknown client sites' );
$before = STUH_Plugin::get_telemetry();
$GLOBALS['storage_fail'] = true;
$failed_import = $import_forms( 'site-1', '[{"form_id":3,"form_title":"Not saved","months":{"2025-01":1}}]' );
unset( $GLOBALS['storage_fail'] );
expect_view( is_wp_error( $failed_import ) && 'Could not save Gravity Forms history. Please try again.' === $failed_import->get_error_message() && $before === STUH_Plugin::get_telemetry(), 'Storage failures are explicit and preserve all previous telemetry' );
foreach ( [
	[ [], [], 'The JSON upload failed.' ],
	[ [], [ 'gravity_forms_file' => [ 'error' => UPLOAD_ERR_INI_SIZE ] ], 'The JSON upload failed.' ],
	[ [], [ 'gravity_forms_file' => [ 'error' => UPLOAD_ERR_OK, 'name' => 'data.php', 'tmp_name' => __FILE__ ] ], 'Please upload a valid .json file.' ],
	[ [], [ 'gravity_forms_file' => [ 'error' => UPLOAD_ERR_OK, 'name' => 'data.json', 'tmp_name' => __FILE__ ] ], 'Please upload a valid .json file.' ],
	[ [ '_wpnonce' => 'wrong' ], [], 'Invalid nonce' ],
	[ [ 'client_id' => 'unknown' ], [], 'The selected client site could not be found.' ],
] as [ $fields, $files, $message ] ) {
	$_FILES = $files;
	try {
		post_view_action( 'import_gravity_forms', $fields );
		throw new LogicException( 'Invalid file import was accepted' );
	} catch ( RuntimeException $error ) {
		expect_view( str_starts_with( $error->getMessage(), $message ) && $before === STUH_Plugin::get_telemetry(), 'Validate upload errors, real upload provenance, nonce and client before changing history' );
	} finally {
		$_POST = [];
		$_FILES = [];
	}
}
$GLOBALS['authorized'] = false;
try {
	post_view_action( 'import_gravity_forms' );
	throw new LogicException( 'Unauthorized import was accepted' );
} catch ( RuntimeException $error ) {
	expect_view( 'Insufficient permissions' === $error->getMessage() && $before === STUH_Plugin::get_telemetry(), 'Non-administrators cannot import historical client data' );
} finally {
	$_POST = [];
	unset( $GLOBALS['authorized'] );
}

$_GET['client_id'] = 'site-2';
$without_report = render_view();
expect_view( str_contains( $without_report, '<h1>other.example</h1>' ), 'Clients without telemetry still have a details page' );
expect_view( ! str_contains( $without_report, 'class="login"' ), 'Do not invent a login URL' );
$_GET['client_tab'] = 'packages';
expect_view( 2 === substr_count( render_view(), 'None reported.' ), 'The inventory tab retains both explicit empty states for clients without telemetry' );
$_GET['client_tab'] = 'diagnostics';
expect_view( str_contains( render_view(), 'None received' ), 'The Diagnostics tab has an explicit empty state for clients without telemetry' );
$redirect = post_view_action( 'toggle_client', [ 'client_id' => 'site-2' ] );
expect_view( str_contains( $redirect, 'client_id=site-2' ) && str_contains( $redirect, 'client_tab=diagnostics' ), 'Client actions preserve the selected details tab on redirect' );
post_view_action( 'toggle_client', [ 'client_id' => 'site-2' ] );
unset( $_GET['client_tab'] );
$_GET['client_id'] = 'site-1';
$redirect = post_view_action( 'edit_client_tags', [ 'client_tags' => 'updated, maintenance' ] );
expect_view( str_contains( $redirect, 'client_id=site-1' ), 'Editing returns to website details' );
expect_view( [ 'updated', 'maintenance' ] === STUH_Plugin::get_clients()[0]['tags'], 'Tag edit persists' );
$redirect = post_view_action( 'edit_client_urls', [ 'site_urls_raw' => "https://changed.example\nhttps://second.example" ] );
expect_view( str_contains( $redirect, 'client_id=site-1' ) && 'https://changed.example' === STUH_Plugin::get_clients()[0]['site_url'], 'URL editing persists and stays on details' );
post_view_action( 'assign_external_party', [ 'connection_type' => 'domain', 'external_party_id' => 'party-1' ] );
expect_view( 'party-1' === STUH_Plugin::get_clients()[0]['domain_external_party_id'], 'Ownership editing persists' );
post_view_action( 'toggle_client' );
$disabled = render_view();
expect_view( str_contains( $disabled, '>Enable</button>' ) && ! str_contains( $disabled, 'value="refresh_client_diagnostics"' ), 'Disabled client retains access controls and existing action gating' );
expect_view( str_contains( $disabled, 'Example owner' ), 'Updated owner appears on details' );
$redirect = post_view_action( 'delete_client' );
expect_view( ! str_contains( $redirect, 'client_id=' ) && 1 === count( STUH_Plugin::get_clients() ), 'Deletion persists and returns to list' );
expect_view( ! isset( STUH_Plugin::get_telemetry()['site-1'] ), 'Deleting a client removes both its reported and imported form history' );
try {
	render_view();
	throw new LogicException( 'Missing client was not rejected' );
} catch ( RuntimeException $error ) {
	expect_view( 'The selected client site could not be found.' === $error->getMessage(), 'Unknown client produces an explicit error' );
}
$GLOBALS['authorized'] = false;
try {
	render_view();
	throw new LogicException( 'Unauthorized details access was not rejected' );
} catch ( RuntimeException $error ) {
	expect_view( 'Insufficient permissions' === $error->getMessage(), 'Details require administrator access' );
}
echo "Client details regression checks passed.\n";
