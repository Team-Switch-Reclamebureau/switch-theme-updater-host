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
function __( $text, $domain = '' ) { return $text; }
function _n( $single, $plural, $count, $domain = '' ) { return 1 === $count ? $single : $plural; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_textarea( $value ) { return esc_html( $value ); }
function esc_js( $value ) { return addslashes( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function esc_url_raw( $value ) { return trim( $value ); }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_html_e( $text, $domain = '' ) { echo esc_html( $text ); }
function esc_attr_e( $text, $domain = '' ) { echo esc_attr( $text ); }
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function plugin_dir_path( $file ) { return dirname( $file ) . '/'; }
function current_user_can( $capability ) { return $GLOBALS['authorized'] ?? true; }
function wp_die( $message ) { throw new RuntimeException( $message ); }
function wp_unslash( $value ) { return $value; }
function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( $value ) ); }
function sanitize_html_class( $value ) { return preg_replace( '/[^A-Za-z0-9_-]/', '', $value ); }
function is_email( $value ) { return false !== filter_var( $value, FILTER_VALIDATE_EMAIL ); }
function get_option( $key, $default = false ) { return $GLOBALS['options'][ $key ] ?? $default; }
function update_option( $key, $value ) { $GLOBALS['options'][ $key ] = $value; }
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
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
function wp_parse_url( $url ) { return parse_url( $url ); }
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

$_GET['client_id'] = 'site-1';
$GLOBALS['transients']['stuh_pending_updates_1'] = [ 'type' => 'success', 'message' => 'Updates installed' ];
$detail = render_view();
if ( '--render' === ( $argv[1] ?? '' ) ) {
	echo '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">';
	echo '<title>Website details preview</title><style>body{margin:24px;background:#f0f0f1;color:#1d2327;font:13px/1.5 sans-serif}a{color:#2271b1}h1{font-size:24px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px}button,input,textarea,select{font:inherit}.widefat{background:white}.row-actions{font-size:13px}';
	echo file_get_contents( dirname( __DIR__ ) . '/assets/css/client-sites.css' );
	echo '</style>' . $detail . '</html>';
	exit;
}
$xpath = view_xpath( $detail );
$columns = ( new STUH_Plugin() )->client_columns();
expect_view( 6 === $xpath->query( '//section[contains(@class,"stuh-client-detail-group")]' )->length, 'Details use six compact information groups' );
expect_view( count( $columns ) === $xpath->query( '//div[contains(@class,"stuh-client-detail-field--")]' )->length, 'Every field appears once, independent of Screen Options' );
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
expect_view( strpos( $detail, 'stuh-package-table--themes' ) < strpos( $detail, 'stuh-package-table--plugins' ), 'Themes appear before plugins' );
expect_view( 0 === $xpath->query( '//section[contains(@class,"--packages")]//details' )->length, 'Package tables are never collapsed' );
expect_view( 1 === $xpath->query( '//details[not(@open)]' )->length, 'Only raw diagnostics are collapsed initially' );
foreach ( [ 'toggle_client', 'delete_client', 'refresh_client_diagnostics', 'check_client_ssl', 'bulk_update_clients', 'install_wordpress_update', 'install_pending_updates', 'retry_failed_smtp_emails', 'disable_debugging', 'toggle_search_engine_visibility', 'set_post_revisions', 'skip_new_bundled_themes', 'edit_client_urls', 'edit_client_tags', 'assign_external_party' ] as $action ) {
	expect_view( $xpath->query( '//form/input[@name="stuh_action" and @value="' . $action . '"]' )->length > 0, 'Action available: ' . $action );
}
expect_view( 0 === $xpath->query( '//form[not(input[@name="_wpnonce"])]' )->length, 'Every action form has a nonce' );
$back = $xpath->query( '//a[contains(text(),"Back to Client Sites")]' )->item( 0 )->getAttribute( 'href' );
expect_view( ! str_contains( $back, 'client_id' ) && str_contains( $back, 'stuh_search=webshop' ) && str_contains( $back, 'stuh_status=enabled' ), 'Back link preserves list filters, not detail selection' );

$_GET['client_id'] = 'site-2';
$without_report = render_view();
expect_view( str_contains( $without_report, '<h1>other.example</h1>' ) && str_contains( $without_report, 'None received' ), 'Clients without telemetry still have a details page' );
expect_view( ! str_contains( $without_report, 'class="login"' ), 'Do not invent a login URL' );
expect_view( 2 === substr_count( $without_report, 'None reported.' ), 'Empty inventories retain separate tables with explicit empty states' );
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
