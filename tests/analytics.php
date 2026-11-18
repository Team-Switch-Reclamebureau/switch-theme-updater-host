<?php
/**
 * Standalone Analytics regression checks: php tests/analytics.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );

class WP_Error {
	public function __construct( private string $code, private string $message, private $data = null ) {}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}
class AnalyticsRedirect extends RuntimeException {}
class STUH_Plugin {
	public static function get_clients(): array { return [ [ 'id' => 'site-1', 'site_url' => 'https://client.example' ] ]; }
}
function __( $text, $domain = '' ) { return $text; }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function add_action( ...$args ) {}
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function current_user_can( $capability ) { return $GLOBALS['authorized'] ?? true; }
function get_current_user_id() { return $GLOBALS['user'] ?? 1; }
function wp_die( $message, ...$args ) { throw new RuntimeException( $message ); }
function wp_unslash( $value ) { return $value; }
function wp_json_encode( $value ) { return json_encode( $value ); }
function admin_url( $path ) { return 'https://host.example/wp-admin/' . $path; }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function add_query_arg( array $args, string $url ) { return $url . '?' . http_build_query( $args ); }
function get_option( $key, $default = false ) { return $GLOBALS['options'][ $key ] ?? $default; }
function update_option( $key, $value, $autoload = null ) {
	if ( get_option( $key ) === $value ) { return false; }
	$GLOBALS['options'][ $key ] = $value;
	return true;
}
function delete_option( $key ) { unset( $GLOBALS['options'][ $key ] ); return true; }
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['transients'][ $key ] = $value; return true; }
function delete_transient( $key ) { unset( $GLOBALS['transients'][ $key ] ); }
function wp_safe_redirect( $url ) { throw new AnalyticsRedirect( $url ); }
function wp_redirect( $url ) { throw new AnalyticsRedirect( $url ); }
function check_admin_referer( $action ) {
	if ( 'valid' !== ( $_POST['_wpnonce'] ?? '' ) ) { wp_die( 'Invalid nonce' ); }
}
function wp_nonce_field( $action ) { echo '<input name="_wpnonce" value="valid">'; }
function submit_button( $label, ...$args ) { echo '<button>' . esc_html( $label ) . '</button>'; }
function wp_date( $format, $time ) { return gmdate( $format, $time ); }
function number_format_i18n( $value, $decimals = 0 ) { return number_format( $value, $decimals ); }
function wp_next_scheduled( $hook, $args ) { return $GLOBALS['scheduled'][ $args[0] ] ?? false; }
function wp_schedule_single_event( $time, $hook, $args, $wp_error ) {
	if ( $GLOBALS['schedule_fail'] ?? false ) { return new WP_Error( 'cron_failed', 'Cron failed' ); }
	$GLOBALS['scheduled'][ $args[0] ] = $time;
	return true;
}
function wp_clear_scheduled_hook( $hook, $args ) { unset( $GLOBALS['scheduled'][ $args[0] ] ); }
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return $response['body']; }
function wp_remote_post( $url, $args ) { return wp_remote_request( $url, $args ); }
function wp_remote_request( $url, $args ) {
	$GLOBALS['requests'][] = [ $url, $args ];
	if ( ! $GLOBALS['responses'] ) { throw new RuntimeException( 'Unexpected Google request: ' . $url ); }
	$response = array_shift( $GLOBALS['responses'] );
	return is_callable( $response ) ? $response( $url, $args ) : $response;
}

require dirname( __DIR__ ) . '/includes/class-stuh-analytics.php';
set_error_handler( static function( $severity, $message, $file, $line ) {
	throw new ErrorException( $message, 0, $severity, $file, $line );
} );
putenv( 'ANALYTICS_CLIENT_ID=test-client' );
putenv( 'ANALYTICS_CLIENT_SECRET=test-secret' );
putenv( 'STUH_GOOGLE_TOKEN_KEY=0123456789abcdef0123456789abcdef' );
$GLOBALS['responses'] = [];
$GLOBALS['requests'] = [];

function expect_analytics( bool $condition, string $message ): void {
	if ( ! $condition ) { throw new RuntimeException( $message ); }
}
function invoke_analytics( string $method, ...$args ) {
	return ( new ReflectionMethod( STUH_Analytics::class, $method ) )->invoke( null, ...$args );
}
function google_response( array $data, int $status = 200 ): array {
	return [ 'status' => $status, 'body' => json_encode( $data ) ];
}
function analytics_action( string $operation, array $fields = [] ): array {
	$_POST = array_merge( [ '_wpnonce' => 'valid', 'operation' => $operation, 'client_id' => 'site-1' ], $fields );
	try {
		STUH_Analytics::handle_action();
	} catch ( AnalyticsRedirect $redirect ) {
		return [ $redirect->getMessage(), get_transient( 'stuh_google_notice_' . get_current_user_id() ) ];
	} finally {
		$_POST = [];
	}
	throw new RuntimeException( 'Expected Analytics redirect' );
}
function report_fixture( array $metrics, array $values, array $dimensions = [], array $labels = [] ): array {
	return [
		'metricHeaders' => array_map( static fn( $name ) => [ 'name' => $name ], $metrics ),
		'dimensionHeaders' => array_map( static fn( $name ) => [ 'name' => $name ], $dimensions ),
		'rows' => [ [
			'metricValues' => array_map( static fn( $value ) => [ 'value' => (string) $value ], $values ),
			'dimensionValues' => array_map( static fn( $value ) => [ 'value' => $value ], $labels ),
		] ],
		'rowCount' => 1,
	];
}
function render_analytics(): string {
	ob_start();
	try {
		STUH_Analytics::render_client_panel( STUH_Plugin::get_clients()[0] );
		return ob_get_contents();
	} finally {
		ob_end_clean();
	}
}

// Authorization is administrator-only, nonce-protected, user-bound and single-use.
$GLOBALS['authorized'] = false;
try {
	analytics_action( 'connect' );
	throw new RuntimeException( 'Unauthorized action succeeded' );
} catch ( RuntimeException $error ) {
	expect_analytics( 'Insufficient permissions' === $error->getMessage(), 'Admin capability must be enforced' );
}
$GLOBALS['authorized'] = true;
try {
	analytics_action( 'connect', [ '_wpnonce' => 'bad' ] );
	throw new RuntimeException( 'Invalid nonce succeeded' );
} catch ( RuntimeException $error ) {
	expect_analytics( 'Invalid nonce' === $error->getMessage(), 'Nonce must be enforced' );
}
[ $url ] = analytics_action( 'connect' );
parse_str( parse_url( $url, PHP_URL_QUERY ), $query );
expect_analytics( 'accounts.google.com' === parse_url( $url, PHP_URL_HOST ), 'Authorization must use Google' );
expect_analytics( 'https://www.googleapis.com/auth/analytics.readonly' === $query['scope'] && 'offline' === $query['access_type'], 'Request read-only offline access' );
expect_analytics( 'https://host.example/wp-admin/admin-post.php?action=stuh_google_oauth_callback' === $query['redirect_uri'], 'Use the registered callback' );
$pending = get_transient( 'stuh_google_state_1' );
expect_analytics( $query['code_challenge'] === rtrim( strtr( base64_encode( hash( 'sha256', $pending['verifier'], true ) ), '+/', '-_' ), '=' ), 'PKCE challenge must match verifier' );
$GLOBALS['user'] = 2;
$_GET = [ 'state' => $query['state'], 'code' => 'authorization-code' ];
try {
	STUH_Analytics::callback();
	throw new RuntimeException( 'Other user accepted authorization state' );
} catch ( RuntimeException $error ) {
	expect_analytics( str_contains( $error->getMessage(), 'Invalid or expired' ), 'State must be bound to the initiating user' );
}
$GLOBALS['user'] = 1;
$GLOBALS['responses'][] = google_response( [ 'access_token' => 'access-one', 'refresh_token' => 'refresh-one', 'expires_in' => 3600, 'scope' => $query['scope'] ] );
try {
	STUH_Analytics::callback();
} catch ( AnalyticsRedirect $redirect ) {}
expect_analytics( false === get_transient( 'stuh_google_state_1' ), 'Consume state before exchanging the code' );
$connection = invoke_analytics( 'connection' );
expect_analytics( 'refresh-one' === $connection['refresh_token'], 'Authorization must persist the refresh token' );
$stored = get_option( 'stuh_google_connection' );
expect_analytics( ! str_contains( $stored, 'refresh-one' ) && ! str_contains( $stored, 'access-one' ), 'Tokens must be encrypted at rest' );
try {
	STUH_Analytics::callback();
	throw new RuntimeException( 'Authorization state was replayed' );
} catch ( RuntimeException $error ) {
	expect_analytics( str_contains( $error->getMessage(), 'Invalid or expired' ), 'Reject state replay' );
}
$_GET = [];
putenv( 'STUH_GOOGLE_TOKEN_KEY=fedcba9876543210fedcba9876543210' );
expect_analytics( is_wp_error( invoke_analytics( 'connection' ) ), 'Wrong encryption key must fail explicitly' );
putenv( 'STUH_GOOGLE_TOKEN_KEY=0123456789abcdef0123456789abcdef' );
$raw = base64_decode( $stored );
$raw[30] = chr( ord( $raw[30] ) ^ 1 );
$GLOBALS['options']['stuh_google_connection'] = base64_encode( $raw );
expect_analytics( is_wp_error( invoke_analytics( 'connection' ) ), 'Reject tampered ciphertext' );
$GLOBALS['options']['stuh_google_connection'] = $stored;

// Background access refresh preserves the refresh token; failures keep credentials.
$connection['expires_at'] = time() - 10;
invoke_analytics( 'save_connection', $connection );
$GLOBALS['responses'][] = google_response( [ 'access_token' => 'access-two', 'expires_in' => 3600 ] );
expect_analytics( 'access-two' === invoke_analytics( 'access_token' ), 'Expired token should refresh' );
expect_analytics( 'refresh-one' === invoke_analytics( 'connection' )['refresh_token'], 'Missing replacement refresh token must preserve original' );
$connection = invoke_analytics( 'connection' );
$connection['expires_at'] = time() - 10;
invoke_analytics( 'save_connection', $connection );
$stored = get_option( 'stuh_google_connection' );
$GLOBALS['responses'][] = google_response( [ 'error' => 'invalid_grant' ], 400 );
expect_analytics( is_wp_error( invoke_analytics( 'access_token' ) ), 'Revoked refresh token must not appear successful' );
expect_analytics( $stored === get_option( 'stuh_google_connection' ), 'Failed refresh must not overwrite credentials' );
$connection['expires_at'] = time() + 3600;
invoke_analytics( 'save_connection', $connection );

// Discover all property pages and validate mappings against Google's property API.
$GLOBALS['responses'][] = google_response( [ 'accountSummaries' => [ [ 'propertySummaries' => [ [ 'property' => 'properties/123', 'displayName' => 'Client property' ] ] ] ], 'nextPageToken' => 'next-page' ] );
$GLOBALS['responses'][] = google_response( [ 'accountSummaries' => [ [ 'propertySummaries' => [ [ 'property' => 'properties/456', 'displayName' => 'Other property' ] ] ] ] ] );
[ , $notice ] = analytics_action( 'properties' );
expect_analytics( ! $notice['error'] && str_contains( $notice['message'], '2' ), 'Load properties across all pages' );
expect_analytics( str_contains( end( $GLOBALS['requests'] )[0], 'pageToken=next-page' ), 'Follow pagination tokens' );
$before = count( $GLOBALS['requests'] );
[ , $notice ] = analytics_action( 'map', [ 'property_id' => 'G-ABC', 'hostname' => 'client.example' ] );
expect_analytics( $notice['error'] && count( $GLOBALS['requests'] ) === $before, 'Reject measurement IDs without contacting Google' );
[ , $notice ] = analytics_action( 'map', [ 'property_id' => '123', 'hostname' => 'https://client.example/path' ] );
expect_analytics( $notice['error'], 'Reject URLs in the hostname filter' );
$GLOBALS['responses'][] = google_response( [ 'name' => 'properties/123', 'displayName' => '<Client>', 'timeZone' => 'Europe/Amsterdam' ] );
[ , $notice ] = analytics_action( 'map', [ 'property_id' => '123', 'hostname' => 'CLIENT.example' ] );
$mapping = get_option( 'stuh_google_mappings' )['site-1'];
expect_analytics( ! $notice['error'] && 'client.example' === $mapping['hostname'] && $mapping['connection_id'] === $connection['id'], 'Save confirmed property, hostname and connection' );
expect_analytics( isset( $GLOBALS['scheduled']['site-1'] ), 'Mapping must queue a background refresh' );

// Verify the actual report payload, date boundaries and response shape.
$metrics = [ 'activeUsers', 'sessions', 'screenPageViews', 'engagementRate', 'keyEvents' ];
$reports = [
	report_fixture( $metrics, [ 10, 20, 30, 0.75, 2.5 ] ),
	report_fixture( $metrics, [ 5, 10, 15, 0.5, 1 ] ),
	report_fixture( [ 'screenPageViews' ], [ 12 ], [ 'pagePath' ], [ '/<script>' ] ),
	report_fixture( [ 'sessions' ], [ 14 ], [ 'sessionDefaultChannelGroup' ], [ 'Organic Search' ] ),
];
$reports[0]['metadata'] = [ 'subjectToThresholding' => true ];
$GLOBALS['responses'][] = google_response( [ 'reports' => $reports ] );
unset( $GLOBALS['scheduled']['site-1'] );
STUH_Analytics::refresh_report( 'site-1' );
[ $url, $args ] = end( $GLOBALS['requests'] );
expect_analytics( 'https://analyticsdata.googleapis.com/v1beta/properties/123:batchRunReports' === $url, 'Call GA4 reporting for the mapped property' );
$body = json_decode( $args['body'], true );
expect_analytics( 4 === count( $body['requests'] ), 'Fetch both periods, top pages and channels' );
$today = new DateTimeImmutable( 'today', new DateTimeZone( 'Europe/Amsterdam' ) );
foreach ( $body['requests'] as $request ) {
	expect_analytics( [ 'matchType' => 'EXACT', 'value' => 'client.example', 'caseSensitive' => false ] === $request['dimensionFilter']['filter']['stringFilter'], 'Every report must be hostname-scoped' );
	expect_analytics( 'hostName' === $request['dimensionFilter']['filter']['fieldName'], 'Filter on the hostname dimension' );
}
expect_analytics( $today->modify( '-28 days' )->format( 'Y-m-d' ) === $body['requests'][0]['dateRanges'][0]['startDate'] && $today->modify( '-1 day' )->format( 'Y-m-d' ) === $body['requests'][0]['dateRanges'][0]['endDate'], 'Use the last 28 complete property-local days' );
expect_analytics( $today->modify( '-56 days' )->format( 'Y-m-d' ) === $body['requests'][1]['dateRanges'][0]['startDate'] && $today->modify( '-29 days' )->format( 'Y-m-d' ) === $body['requests'][1]['dateRanges'][0]['endDate'], 'Comparison must be the adjacent previous 28 days' );
$key = invoke_analytics( 'report_key', 'site-1' );
$good = get_option( $key );
expect_analytics( 0.75 === $good['data']['current']['engagementRate'] && $good['data']['limited'], 'Keep rates and Google reporting limitations' );
$before = count( $GLOBALS['requests'] );
$html = render_analytics();
expect_analytics( str_contains( $html, '75.0%' ) && str_contains( $html, '2.50' ) && str_contains( $html, '&lt;script&gt;' ) && ! str_contains( $html, '/<script>' ), 'Render rates, fractional key events and escaped dimensions' );
expect_analytics( count( $GLOBALS['requests'] ) === $before, 'Page rendering must not contact Google' );

// Failures retain the last successful data instead of reporting fake zero traffic.
$GLOBALS['responses'][] = google_response( [ 'error' => [ 'status' => 'PERMISSION_DENIED' ] ], 403 );
STUH_Analytics::refresh_report( 'site-1' );
$failed = get_option( $key );
expect_analytics( $failed['data'] === $good['data'] && $failed['fetched_at'] === $good['fetched_at'] && str_contains( $failed['error'], '403' ), 'Retain successful data on authorization failure' );
expect_analytics( str_contains( render_analytics(), 'Stale report' ), 'Mark retained reports stale after failure' );
$invalid = $reports;
$invalid[0]['rows'][0]['metricValues'][0]['value'] = 'not-a-number';
$GLOBALS['responses'][] = google_response( [ 'reports' => $invalid ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( '' !== get_option( $key )['error'] && $good['data'] === get_option( $key )['data'], 'Malformed metric data must not replace a good report' );
$GLOBALS['responses'][] = google_response( [ 'reports' => [] ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( '' !== get_option( $key )['error'], 'Reject incomplete report batches' );
$empty = $reports;
foreach ( $empty as &$report ) {
	unset( $report['rows'], $report['rowCount'] );
}
unset( $report );
$GLOBALS['responses'][] = google_response( [ 'reports' => $empty ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( 0.0 === get_option( $key )['data']['current']['activeUsers'] && '' === get_option( $key )['error'], 'A valid empty response may represent zero traffic' );

// Cache scheduling, changed mappings, and disconnect must not leak old reports.
$record = get_option( $key );
$record['fetched_at'] = time() - 5 * HOUR_IN_SECONDS;
$record['attempted_at'] = time() - 20 * MINUTE_IN_SECONDS;
update_option( $key, $record );
$GLOBALS['schedule_fail'] = true;
expect_analytics( str_contains( render_analytics(), 'Cron failed' ), 'Expose scheduler failures' );
$GLOBALS['schedule_fail'] = false;
render_analytics();
expect_analytics( isset( $GLOBALS['scheduled']['site-1'] ), 'Stale reports must schedule a refresh' );
$GLOBALS['responses'][] = static function() use ( $reports ) {
	$mappings = get_option( 'stuh_google_mappings' );
	$mappings['site-1']['hostname'] = 'changed.example';
	update_option( 'stuh_google_mappings', $mappings );
	return google_response( [ 'reports' => $reports ] );
};
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( get_option( $key ) === $record, 'Do not publish reports for a mapping changed mid-request' );
$connection['id'] = 'new-connection';
invoke_analytics( 'save_connection', $connection );
$html = render_analytics();
expect_analytics( str_contains( $html, 'Save this mapping again' ) && ! str_contains( $html, 'Last successful report' ), 'Reconnect must require mapping confirmation and hide old reports' );
$GLOBALS['responses'][] = [ 'status' => 200, 'body' => '' ];
[ , $notice ] = analytics_action( 'disconnect' );
expect_analytics( ! $notice['error'] && false === get_option( 'stuh_google_connection' ) && false === get_option( $key ) && false === get_option( 'stuh_google_mappings' ), 'Disconnect must revoke and delete local tokens, mappings and reports' );
update_option( 'stuh_google_mappings', [ 'site-1' => $mapping ] );
update_option( $key, $good );
$GLOBALS['scheduled']['site-1'] = time();
expect_analytics( true === STUH_Analytics::forget_client( 'site-1' ), 'Client deletion cleanup must succeed' );
expect_analytics( [] === get_option( 'stuh_google_mappings' ) && false === get_option( $key ) && ! isset( $GLOBALS['scheduled']['site-1'] ), 'Client deletion must remove its mapping, cached report and queued refresh' );
expect_analytics( ! $GLOBALS['responses'], 'All expected requests must be consumed' );
echo "Analytics regression checks passed.\n";
