<?php
/**
 * Standalone regression checks: php tests/batch-versions.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );
define( 'MINUTE_IN_SECONDS', 60 );

class WP_Error {
	private $code;
	private $message;
	private $data;
	public function __construct( $code, $message, $data = [] ) {
		$this->code = $code;
		$this->message = $message;
		$this->data = $data;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
	public function get_error_data() { return $this->data; }
}
class WP_REST_Request {
	private $params = [];
	private $headers = [];
	public function __construct( $method = 'GET' ) {}
	public function get_param( $name ) { return $this->params[ $name ] ?? null; }
	public function set_param( $name, $value ) { $this->params[ $name ] = $value; }
	public function get_header( $name ) { return $this->headers[ strtolower( $name ) ] ?? ''; }
	public function set_header( $name, $value ) { $this->headers[ strtolower( $name ) ] = $value; }
	public function get_route() { return '/stu-host/v1/versions'; }
}
class WP_REST_Response {
	private $data;
	public function __construct( $data ) { $this->data = $data; }
	public function get_data() { return $this->data; }
}
class WP_REST_Server {
	const READABLE = 'GET';
	const CREATABLE = 'POST';
}
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function rest_ensure_response( $value ) { return new WP_REST_Response( $value ); }
function wp_json_encode( $value ) { return json_encode( $value ); }
function sanitize_text_field( $value ) { return trim( strip_tags( $value ) ); }
function register_rest_route( $namespace, $path, $args ) { $GLOBALS['routes'][ $path ] = $args; }
function get_option( $name, $default = [] ) { return $GLOBALS['options'][ $name ] ?? $default; }
function update_option( $name, $value, $autoload = null ) {
	if ( $GLOBALS['storage_fail'] ?? false ) { return false; }
	$GLOBALS['options'][ $name ] = $value;
	$GLOBALS['autoload'][ $name ] = $autoload;
	return true;
}
function sanitize_key( $value ) { return preg_replace( '/[^a-z0-9_-]/', '', strtolower( $value ) ); }
function esc_url_raw( $value ) { return $value; }
function wp_parse_url( $url ) { return parse_url( $url ); }
function home_url() { return 'https://host.example'; }
function wp_check_password( $key, $hash ) { return $hash === 'hashed-' . $key; }
function get_transient( $key ) { return str_starts_with( $key, 'stuh_homepage_check_' ) ? 1 : false; }
function wp_parse_args( $value, $defaults ) { return array_merge( $defaults, $value ); }
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return json_encode( $response['body'] ); }
function wp_remote_request( $url, $args ) {
	$GLOBALS['requests'][] = $url;
	if ( strpos( $url, '/missing/' ) !== false ) {
		return [ 'status' => 404, 'body' => [ 'message' => 'Not found' ] ];
	}
	if ( strpos( $url, '/commits?' ) !== false ) {
		return [ 'status' => 200, 'body' => [ [ 'sha' => 'abc123' ] ] ];
	}
	if ( strpos( $url, '/contents/' ) !== false ) {
		return [ 'status' => 200, 'body' => [ 'content' => base64_encode( "Version: 3.0\n" ) ] ];
	}
	return [ 'status' => 200, 'body' => [ 'tag_name' => strpos( $url, '/tags/' ) !== false ? 'v0.9' : 'v2.0' ] ];
}

require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

function expect_batch( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}
$host = new STUH_Plugin();
$host->register_rest_routes();
expect_batch( $GLOBALS['routes']['/version']['methods'] === 'GET', 'Legacy endpoint is retained' );
expect_batch( $GLOBALS['routes']['/versions']['methods'] === 'POST', 'Batch endpoint accepts POST' );
expect_batch( $GLOBALS['routes']['/versions']['permission_callback'] === [ $host, 'rest_permission' ], 'Batch endpoint uses existing authentication and telemetry' );
$schema = $GLOBALS['routes']['/versions']['args']['packages'];
expect_batch( $schema['required'] && $schema['minItems'] === 1 && $schema['maxItems'] === 100, 'REST validation bounds batch size' );
expect_batch( $schema['items']['required'] === [ 'repo' ] && $schema['items']['properties']['repo']['type'] === 'string', 'Repository is a required string' );
expect_batch( $schema['items']['properties']['mode']['enum'] === [ 'releases', 'commits', 'tag' ], 'Invalid modes are rejected by REST validation' );

$request = new WP_REST_Request( 'POST' );
$request->set_param( 'packages', [
	[ 'repo' => 'team/plugin' ],
	[ 'repo' => 'team/plugin' ],
	[ 'repo' => 'team/theme', 'mode' => 'commits', 'branch' => 'feature/test', 'path' => '/subdir' ],
	[ 'repo' => 'team/theme', 'mode' => 'tag', 'ref' => 'v0.9' ],
	[ 'repo' => 'invalid' ],
	[ 'repo' => 'team/missing' ],
] );
$GLOBALS['requests'] = [];
$results = $host->rest_versions( $request )->get_data()['results'];
expect_batch( count( $results ) === 6, 'One ordered result per input' );
expect_batch( $results[0] === [ 'version' => '2.0', 'ref' => 'v2.0' ] && $results[1] === $results[0], 'Release results preserve legacy shape and duplicates' );
expect_batch( $results[2] === [ 'version' => '3.0', 'ref' => 'abc123' ], 'Commit result uses style version and commit ref' );
expect_batch( strpos( $GLOBALS['requests'][1], 'sha=feature%2Ftest' ) !== false, 'Commit branch is forwarded' );
expect_batch( strpos( $GLOBALS['requests'][2], '/contents/subdir/style.css' ) !== false, 'Theme subdirectory is forwarded' );
expect_batch( $results[3] === [ 'version' => '0.9', 'ref' => 'v0.9' ], 'Pinned tag supports downgrades' );
expect_batch( $results[4]['error']['code'] === 'invalid_repo' && $results[4]['error']['status'] === 400, 'Invalid repositories return item errors' );
expect_batch( $results[5]['error']['code'] === 'no_version' && $results[5]['error']['status'] === 404, 'Missing versions return item errors' );
expect_batch( count( $GLOBALS['requests'] ) === 5, 'Duplicate and invalid repositories do not make extra GitHub requests' );

$legacy = new WP_REST_Request();
foreach ( [ 'repo' => 'team/plugin', 'mode' => 'releases', 'branch' => 'main', 'ref' => '', 'path' => '/' ] as $key => $value ) {
	$legacy->set_param( $key, $value );
}
expect_batch( $host->rest_version( $legacy )->get_data() === $results[0], 'Older clients still receive the same single-version response' );

$GLOBALS['options'][ STUH_OPTION_CLIENTS ] = [
	[ 'id' => 'site-one', 'site_url' => 'https://one.example', 'enabled' => true, 'api_key_hash' => 'hashed-key-one', 'last_seen' => time() ],
	[ 'id' => 'site-two', 'site_url' => 'https://two.example', 'enabled' => true, 'api_key_hash' => 'hashed-key-two', 'last_seen' => time() ],
];
$send_report = static function( string $site, string $key, array $metadata ) use ( $host ) {
	$_SERVER['HTTP_USER_AGENT'] = 'WordPress/6.7; https://' . $site . '.example';
	$request = new WP_REST_Request( 'POST' );
	$request->set_header( 'X-STU-Key', $key );
	$request->set_header( 'X-STU-Metadata-Version', '1' );
	$request->set_header( 'X-STU-Request-Type', 'batch' );
	$request->set_header( 'X-STU-Metadata', rtrim( strtr( base64_encode( gzencode( json_encode( $metadata ) ) ), '+/', '-_' ), '=' ) );
	return $host->rest_permission( $request );
};
$form_report = [
	[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-10' => 12, '2026-11' => 8 ], 'entries' => [ 'must-not-be-persisted' ] ],
	[ 'form_id' => 2, 'form_title' => 'Information', 'months' => (object) [ '2026-11' => 0 ] ],
];
expect_batch( true === $send_report( 'one', 'key-one', [ 'gravity_forms' => $form_report, 'wp_version' => '6.7' ] ), 'Receive form reports through the existing authenticated version-check metadata path' );
$reports = STUH_Plugin::get_telemetry();
$first_snapshot = $reports['site-one']['gravity_forms'];
expect_batch( $first_snapshot['forms'] === [
	[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [ '2026-10' => 12, '2026-11' => 8 ] ],
	[ 'form_id' => 2, 'form_title' => 'Information', 'months' => [ '2026-11' => 0 ] ],
] && is_int( $first_snapshot['received_at'] ) && ! isset( $reports['site-one']['data']['gravity_forms'] ) && '6.7' === $reports['site-one']['data']['wp_version'] && false === $GLOBALS['autoload'][ STUH_OPTION_TELEMETRY ], 'Persist validated aggregate fields and a receipt timestamp per site without duplicate raw reports, submission fields or autoloading' );
expect_batch( true === $send_report( 'two', 'key-two', [ 'client_id' => 'site-one', 'gravity_forms' => [ [ 'form_id' => 1, 'form_title' => 'Other contact', 'months' => (object) [ '2026-11' => 99 ] ] ] ] ), 'Accept reports from a second authenticated site with the same local form ID' );
expect_batch( $first_snapshot === STUH_Plugin::get_telemetry()['site-one']['gravity_forms'] && 99 === STUH_Plugin::get_telemetry()['site-two']['gravity_forms']['forms'][0]['months']['2026-11'], 'Authenticate ownership from the matched client, not a reported client ID or shared form ID' );
$send_report( 'one', 'key-one', [ 'gravity_forms' => [ [ 'form_id' => 1, 'form_title' => 'Renamed contact', 'months' => (object) [ '2026-11' => 3 ] ] ] ] );
$retained_report = STUH_Plugin::get_telemetry()['site-one']['gravity_forms'];
expect_batch( [
	[ 'form_id' => 1, 'form_title' => 'Renamed contact', 'months' => [ '2026-10' => 12, '2026-11' => 8 ] ],
	[ 'form_id' => 2, 'form_title' => 'Information', 'months' => [ '2026-11' => 0 ] ],
] === $retained_report['forms'], 'Retain higher counts, omitted months and omitted forms when entries have been deleted, while accepting the latest form title' );
$increased_report = [
	[ 'form_id' => 1, 'form_title' => 'Renamed contact', 'months' => (object) [ '2026-10' => 0, '2026-11' => 15, '2026-12' => 4 ] ],
	[ 'form_id' => 3, 'form_title' => 'New signup', 'months' => (object) [ '2026-12' => 0 ] ],
];
$send_report( 'one', 'key-one', [ 'gravity_forms' => $increased_report ] );
$retained_report = STUH_Plugin::get_telemetry()['site-one']['gravity_forms'];
expect_batch( [
	[ 'form_id' => 1, 'form_title' => 'Renamed contact', 'months' => [ '2026-10' => 12, '2026-11' => 15, '2026-12' => 4 ] ],
	[ 'form_id' => 2, 'form_title' => 'Information', 'months' => [ '2026-11' => 0 ] ],
	[ 'form_id' => 3, 'form_title' => 'New signup', 'months' => [ '2026-12' => 0 ] ],
] === $retained_report['forms'] && 99 === STUH_Plugin::get_telemetry()['site-two']['gravity_forms']['forms'][0]['months']['2026-11'], 'Increase counts without adding them, preserve historical maxima against explicit zero, append new months/forms including zero, and keep client histories isolated' );
$send_report( 'one', 'key-one', [ 'gravity_forms' => $increased_report ] );
expect_batch( $retained_report['forms'] === STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'], 'Repeated reports do not double count or duplicate forms' );
$reported_before_import = STUH_Plugin::get_telemetry()['site-one']['gravity_forms'];
$import_result = ( new ReflectionMethod( STUH_Plugin::class, 'import_gravity_forms_json' ) )->invoke( null, 'site-one', '[{"form_id":1,"form_title":"Historical contact","months":{"2026-11":100,"2020-01":10}},{"form_id":8,"form_title":"Imported only","months":{"2020-01":0}}]' );
expect_batch( true === $import_result && $reported_before_import === STUH_Plugin::get_telemetry()['site-one']['gravity_forms'], 'Historical uploads are persisted separately without changing live-reported counts or timestamps' );
$import_snapshot = STUH_Plugin::get_telemetry()['site-one']['gravity_forms_import'];
$send_report( 'one', 'key-one', [ 'gravity_forms' => [ [ 'form_id' => 1, 'form_title' => 'Renamed contact', 'months' => (object) [ '2026-11' => 3 ] ] ] ] );
$combined_report = STUH_Plugin::get_gravity_forms_report( 'site-one' );
expect_batch( $import_snapshot === STUH_Plugin::get_telemetry()['site-one']['gravity_forms_import'] && 15 === STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'][0]['months']['2026-11'] && ! isset( STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'][0]['months']['2020-01'] ) && 100 === $combined_report['forms'][0]['months']['2026-11'] && 10 === $combined_report['forms'][0]['months']['2020-01'], 'Live reports retain their own historical maxima without absorbing imported values or modifying the imported snapshot, while combined reads show source maxima' );
$retained_report = STUH_Plugin::get_telemetry()['site-one']['gravity_forms'];
$send_report( 'one', 'key-one', [ 'php_version' => '8.4' ] );
expect_batch( $retained_report === STUH_Plugin::get_telemetry()['site-one']['gravity_forms'] && $import_snapshot === STUH_Plugin::get_telemetry()['site-one']['gravity_forms_import'] && [ 'php_version' => '8.4' ] === STUH_Plugin::get_telemetry()['site-one']['data'], 'Diagnostics without form reports preserve both independent sources and their timestamps' );

$log_path = tempnam( sys_get_temp_dir(), 'stuh-gravity-test-' );
$previous_log = ini_set( 'error_log', $log_path );
try {
	foreach ( [
		null,
		(object) [],
		[ (object) [] ],
		[ [ 'form_id' => '1', 'form_title' => 'Contact', 'months' => (object) [] ] ],
		[ [ 'form_id' => 0, 'form_title' => 'Contact', 'months' => (object) [] ] ],
		[ [ 'form_id' => 1, 'form_title' => [], 'months' => (object) [] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-13' => 1 ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-1' => 1 ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '0000-01' => 1 ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-11' => -1 ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-11' => '8' ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-11' => 1.5 ] ] ],
		[ [ 'form_id' => 1, 'form_title' => 'Contact', 'months' => (object) [ '2026-11' => true ] ] ],
		[ $form_report[0], $form_report[0] ],
		[ $form_report[0], [ 'form_id' => 3, 'form_title' => 'Invalid', 'months' => (object) [ 'bad-month' => 1 ] ] ],
	] as $invalid_forms ) {
		expect_batch( true === $send_report( 'one', 'key-one', [ 'gravity_forms' => $invalid_forms, 'diagnostics' => 'still accepted' ] ), 'Malformed form reports must not block client update checks' );
		expect_batch( $retained_report === STUH_Plugin::get_telemetry()['site-one']['gravity_forms'] && [ 'diagnostics' => 'still accepted' ] === STUH_Plugin::get_telemetry()['site-one']['data'], 'Reject malformed reports atomically without overwriting prior counts or persisting raw invalid data' );
	}
	expect_batch( substr_count( file_get_contents( $log_path ), 'Invalid gravity_forms report for client site-one' ) === 16 && ! str_contains( file_get_contents( $log_path ), 'must-not-be-persisted' ) && $import_snapshot === STUH_Plugin::get_telemetry()['site-one']['gravity_forms_import'], 'Log malformed live reports without logging submitted data or changing the imported snapshot' );
	$GLOBALS['storage_fail'] = true;
	$send_report( 'one', 'key-one', [ 'gravity_forms' => [] ] );
	expect_batch( $retained_report === STUH_Plugin::get_telemetry()['site-one']['gravity_forms'] && str_contains( file_get_contents( $log_path ), 'Could not save telemetry for client site-one' ), 'Storage failures preserve the previous report and are logged instead of silently appearing saved' );
} finally {
	unset( $GLOBALS['storage_fail'] );
	ini_set( 'error_log', $previous_log );
	unlink( $log_path );
}
$send_report( 'one', 'key-one', [ 'gravity_forms' => [ [ 'form_id' => 5, 'form_title' => 'New form', 'months' => (object) [] ] ] ] );
expect_batch( [ 'form_id' => 5, 'form_title' => 'New form', 'months' => [] ] === STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'][3] && $retained_report['forms'] === array_slice( STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'], 0, 3 ), 'Accept a new form with no months without removing previously saved forms or counts' );
$before_empty_report = STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'];
$send_report( 'one', 'key-one', [ 'gravity_forms' => [] ] );
expect_batch( $before_empty_report === STUH_Plugin::get_telemetry()['site-one']['gravity_forms']['forms'] && 99 === STUH_Plugin::get_telemetry()['site-two']['gravity_forms']['forms'][0]['months']['2026-11'], 'An empty report never clears saved history or changes another client site' );
$before_unauthorized = STUH_Plugin::get_telemetry();
expect_batch( is_wp_error( $send_report( 'two', 'key-one', [ 'gravity_forms' => [] ] ) ) && $before_unauthorized === STUH_Plugin::get_telemetry(), 'A valid key for a different site cannot overwrite the registered site report' );
$GLOBALS['options'][ STUH_OPTION_CLIENTS ][1]['enabled'] = false;
expect_batch( is_wp_error( $send_report( 'two', 'key-two', [ 'gravity_forms' => [] ] ) ) && $before_unauthorized === STUH_Plugin::get_telemetry(), 'Disabled clients cannot overwrite saved form reports' );
echo "Batch host regression checks passed.\n";
