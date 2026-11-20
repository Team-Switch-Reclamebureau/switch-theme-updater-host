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
	public static function get_clients(): array { return $GLOBALS['clients'] ?? [ [ 'id' => 'site-1', 'site_url' => 'https://client.example' ] ]; }
	public static function get_telemetry(): array { return $GLOBALS['telemetry'] ?? []; }
}
function __( $text, $domain = '' ) { return $text; }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_attr__( $text, $domain = '' ) { return esc_attr( $text ); }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function add_action( ...$args ) {}
function add_submenu_page( ...$args ) { $GLOBALS['submenus'][] = $args; }
function add_menu_page( ...$args ) { $GLOBALS['top_menus'][] = $args; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function current_user_can( $capability ) { return isset( $GLOBALS['capabilities'] ) ? in_array( $capability, $GLOBALS['capabilities'], true ) : ( $GLOBALS['authorized'] ?? true ); }
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
function wp_next_scheduled( $hook, $args ) {
	$key = 'stuh_google_discover' === $hook ? 'discovery_scheduled' : 'scheduled';
	return $GLOBALS[ $key ][ $args[0] ] ?? false;
}
function wp_schedule_single_event( $time, $hook, $args, $wp_error ) {
	if ( $GLOBALS['schedule_fail'] ?? false ) { return new WP_Error( 'cron_failed', 'Cron failed' ); }
	$key = 'stuh_google_discover' === $hook ? 'discovery_scheduled' : 'scheduled';
	$GLOBALS[ $key ][ $args[0] ] = $time;
	return true;
}
function wp_clear_scheduled_hook( $hook, $args ) {
	$key = 'stuh_google_discover' === $hook ? 'discovery_scheduled' : 'scheduled';
	unset( $GLOBALS[ $key ][ $args[0] ] );
}
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

function render_analytics_column(): string {
	ob_start();
	try {
		STUH_Analytics::render_client_column( 'site-1' );
		return ob_get_contents();
	} finally {
		ob_end_clean();
	}
}

function render_analytics_page( string $method ): string {
	ob_start();
	try {
		STUH_Analytics::$method();
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
expect_analytics( 'https://www.googleapis.com/auth/analytics.readonly https://www.googleapis.com/auth/tagmanager.readonly' === $query['scope'] && 'offline' === $query['access_type'], 'Request read-only Analytics and GTM offline access' );
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
$history_start = new DateTimeImmutable( 'first day of this month 00:00:00', new DateTimeZone( 'Europe/Amsterdam' ) );
$today = new DateTimeImmutable( 'today', new DateTimeZone( 'Europe/Amsterdam' ) );
$has_mtd = (int) $today->format( 'j' ) > 1;
$monthly_report = report_fixture( [ 'activeUsers' ], [ 0 ], $has_mtd ? [ 'yearMonth', 'dateRange' ] : [ 'yearMonth' ], [] );
$monthly_report['rows'] = [];
for ( $offset = 24; $offset >= 1; $offset-- ) {
	if ( 6 === $offset ) {
		continue;
	}
	$monthly_report['rows'][] = [
		'metricValues' => [ [ 'value' => (string) ( 5 === $offset ? 0 : ( 25 - $offset ) * 10 ) ] ],
		'dimensionValues' => array_merge( [ [ 'value' => $history_start->modify( '-' . $offset . ' months' )->format( 'Ym' ) ] ], $has_mtd ? [ [ 'value' => 'complete' ] ] : [] ),
	];
}
if ( $has_mtd ) {
	foreach ( [ 'current_mtd' => [ $history_start, '125' ], 'previous_mtd' => [ $history_start->modify( '-12 months' ), '75' ] ] as $range => [ $date, $value ] ) {
		$monthly_report['rows'][] = [ 'metricValues' => [ [ 'value' => $value ] ], 'dimensionValues' => [ [ 'value' => $date->format( 'Ym' ) ], [ 'value' => $range ] ] ];
	}
}
$monthly_report['rowCount'] = count( $monthly_report['rows'] );
$reports[] = $monthly_report;
$reports[0]['metadata'] = [ 'subjectToThresholding' => true ];
$GLOBALS['responses'][] = google_response( [ 'reports' => $reports ] );
unset( $GLOBALS['scheduled']['site-1'] );
STUH_Analytics::refresh_report( 'site-1' );
[ $url, $args ] = end( $GLOBALS['requests'] );
expect_analytics( 'https://analyticsdata.googleapis.com/v1beta/properties/123:batchRunReports' === $url, 'Call GA4 reporting for the mapped property' );
$body = json_decode( $args['body'], true );
expect_analytics( 5 === count( $body['requests'] ), 'Fetch both 28-day periods, top pages, channels and monthly history within one five-request batch' );
$today = new DateTimeImmutable( 'today', new DateTimeZone( 'Europe/Amsterdam' ) );
foreach ( $body['requests'] as $request ) {
	expect_analytics( [ 'matchType' => 'EXACT', 'value' => 'client.example', 'caseSensitive' => false ] === $request['dimensionFilter']['filter']['stringFilter'], 'Every report must be hostname-scoped' );
	expect_analytics( 'hostName' === $request['dimensionFilter']['filter']['fieldName'], 'Filter on the hostname dimension' );
}
expect_analytics( $today->modify( '-28 days' )->format( 'Y-m-d' ) === $body['requests'][0]['dateRanges'][0]['startDate'] && $today->modify( '-1 day' )->format( 'Y-m-d' ) === $body['requests'][0]['dateRanges'][0]['endDate'], 'Use the last 28 complete property-local days' );
expect_analytics( $today->modify( '-56 days' )->format( 'Y-m-d' ) === $body['requests'][1]['dateRanges'][0]['startDate'] && $today->modify( '-29 days' )->format( 'Y-m-d' ) === $body['requests'][1]['dateRanges'][0]['endDate'], 'Comparison must be the adjacent previous 28 days' );
expect_analytics( [ [ 'name' => 'yearMonth' ] ] === $body['requests'][4]['dimensions'] && [ [ 'name' => 'activeUsers' ] ] === $body['requests'][4]['metrics'], 'Request true monthly active users, not sums of daily or 28-day users' );
expect_analytics( [ 'startDate' => $history_start->modify( '-24 months' )->format( 'Y-m-d' ), 'endDate' => $history_start->modify( '-1 day' )->format( 'Y-m-d' ), 'name' => 'complete' ] === $body['requests'][4]['dateRanges'][0], 'Complete-month range remains distinct from month-to-date queries' );
if ( $has_mtd ) {
	expect_analytics( 3 === count( $body['requests'][4]['dateRanges'] ) && [ 'startDate' => $history_start->format( 'Y-m-d' ), 'endDate' => $today->modify( '-1 day' )->format( 'Y-m-d' ), 'name' => 'current_mtd' ] === $body['requests'][4]['dateRanges'][1], 'Request the ongoing month through yesterday as a separate named range' );
	$prior_start = $history_start->modify( '-12 months' );
	expect_analytics( $prior_start->modify( '+' . ( min( (int) $today->format( 'j' ) - 1, (int) $prior_start->format( 't' ) ) - 1 ) . ' days' )->format( 'Y-m-d' ) === $body['requests'][4]['dateRanges'][2]['endDate'], 'Prior-year month-to-date uses matching elapsed calendar days' );
}
expect_analytics( 26 === $body['requests'][4]['limit'] && true === $body['requests'][4]['keepEmptyRows'], 'Allow 24 complete-month rows plus two month-to-date values and preserve reported zero counts' );
$key = invoke_analytics( 'report_key', 'site-1' );
$good = get_option( $key );
expect_analytics( 0.75 === $good['data']['current']['engagementRate'] && $good['data']['limited'], 'Keep rates and Google reporting limitations' );
expect_analytics( 13 === count( $good['data']['history']['months'] ) && 130.0 === $good['data']['history']['months'][0]['current'] && 10.0 === $good['data']['history']['months'][0]['previous'], 'Preserve twelve complete year-over-year pairs and append the ongoing month' );
expect_analytics( true === $good['data']['history']['months'][12]['in_progress'] && ( $has_mtd ? 125.0 : null ) === $good['data']['history']['months'][12]['current'] && ( $has_mtd ? 75.0 : null ) === $good['data']['history']['months'][12]['previous'], 'The thirteenth pair is explicitly partial and uses independent current/prior month-to-date values' );
expect_analytics( null === $good['data']['history']['months'][6]['current'] && 0.0 === $good['data']['history']['months'][7]['current'], 'Unreported months remain null while explicit zero months remain zero' );
$history_request_count = count( $GLOBALS['requests'] );
$cached_history = STUH_Analytics::monthly_active_users( 'site-1' );
expect_analytics( 130.0 === $cached_history['months'][ $good['data']['history']['months'][0]['month'] ] && null === $cached_history['months'][ $good['data']['history']['months'][6]['month'] ] && 0.0 === $cached_history['months'][ $good['data']['history']['months'][7]['month'] ], 'Chart history exposes calendar-month counts, preserves unknowns and zeros, and does not replace complete months with prior-year partial comparisons' );
expect_analytics( 25 === count( $cached_history['months'] ) && $cached_history['warnings'] && count( $GLOBALS['requests'] ) === $history_request_count, 'Chart history includes complete prior months plus current month, surfaces report limitations, and never requests Google data' );
$leap_history = invoke_analytics( 'monthly_history', new DateTimeImmutable( '2025-03-01', new DateTimeZone( 'Europe/Amsterdam' ) ), [
	[ 'dimensions' => [ '202402' ], 'metrics' => [ 'activeUsers' => 42.0 ] ],
	[ 'dimensions' => [ '202502' ], 'metrics' => [ 'activeUsers' => 84.0 ] ],
] );
expect_analytics( '2024-03-01' === $leap_history['period']['startDate'] && '2025-02-28' === $leap_history['period']['endDate'] && '2024-02-29' === $leap_history['previous_period']['endDate'], 'Annual ranges handle leap-year February correctly without month overflow' );
expect_analytics( 84.0 === $leap_history['months'][11]['current'] && 42.0 === $leap_history['months'][11]['previous'], 'Compare February against February across a leap year' );
$first_day_ranges = invoke_analytics( 'history_ranges', new DateTimeImmutable( '2026-01-01', new DateTimeZone( 'Europe/Amsterdam' ) ) );
expect_analytics( 1 === count( $first_day_ranges ) && '2025-12-31' === $first_day_ranges[0]['endDate'], 'First-of-month queries omit invalid empty month-to-date ranges' );
expect_analytics( null === $leap_history['months'][12]['current'] && null === $leap_history['months'][12]['previous'], 'The first day of a month shows missing partial data rather than copying last year totals' );
$leap_ranges = invoke_analytics( 'history_ranges', new DateTimeImmutable( '2024-02-29', new DateTimeZone( 'Europe/Amsterdam' ) ) );
expect_analytics( '2024-02-28' === $leap_ranges[1]['endDate'] && '2023-02-28' === $leap_ranges[2]['endDate'], 'Leap-day elapsed ranges compare valid same-day cutoffs' );
$march_ranges = invoke_analytics( 'history_ranges', new DateTimeImmutable( '2026-03-31', new DateTimeZone( 'Europe/Amsterdam' ) ) );
expect_analytics( '2025-03-30' === $march_ranges[2]['endDate'], 'End-of-month prior-year ranges do not overflow into another month' );
$partial_rows = [
	[ 'dimensions' => [ '202411', 'complete' ], 'metrics' => [ 'activeUsers' => 130.0 ] ],
	[ 'dimensions' => [ '202511', 'current_mtd' ], 'metrics' => [ 'activeUsers' => 0.0 ] ],
	[ 'dimensions' => [ '202411', 'previous_mtd' ], 'metrics' => [ 'activeUsers' => 75.0 ] ],
];
$partial_history = invoke_analytics( 'monthly_history', new DateTimeImmutable( '2025-11-18', new DateTimeZone( 'Europe/Amsterdam' ) ), $partial_rows );
expect_analytics( 130.0 === $partial_history['months'][0]['current'] && 0.0 === $partial_history['months'][12]['current'] && 75.0 === $partial_history['months'][12]['previous'], 'A full month and the same prior-year partial month remain distinct, including confirmed zero partial traffic' );
expect_analytics( '2025-11-17' === $partial_history['months'][12]['current_end'] && '2024-11-17' === $partial_history['months'][12]['previous_end'], 'Store exact month-to-date cutoffs for hover labels' );
$partial_rows[] = $partial_rows[1];
expect_analytics( is_wp_error( invoke_analytics( 'monthly_history', new DateTimeImmutable( '2025-11-18' ), $partial_rows ) ), 'Reject duplicate partial-month rows, even when the first value was zero' );
$before = count( $GLOBALS['requests'] );
$html = render_analytics();
expect_analytics( str_contains( $html, '75.0%' ) && str_contains( $html, '2.50' ) && str_contains( $html, '&lt;script&gt;' ) && ! str_contains( $html, '/<script>' ), 'Render rates, fractional key events and escaped dimensions' );
expect_analytics( count( $GLOBALS['requests'] ) === $before, 'Page rendering must not contact Google' );

// Global settings and report pages are separate, and the same cached report serves both views.
$before = count( $GLOBALS['requests'] );
$settings_html = render_analytics_page( 'render_settings' );
expect_analytics( str_contains( $settings_html, '<section id="stuh-google-settings"><h2>' ) && ! str_contains( $settings_html, '<h1>' ), 'Google settings render as a section inside the existing Settings page' );
expect_analytics( str_contains( $settings_html, 'value="connect"' ) && str_contains( $settings_html, 'value="properties"' ) && str_contains( $settings_html, 'value="discover_all"' ), 'Settings retain Google connection and discovery controls' );
$_GET = [ 'page' => 'stuh-analytics', 'client_id' => 'site-1' ];
$reports_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $reports_html, 'GA4 property' ) && str_contains( $reports_html, 'client.example' ) && str_contains( $reports_html, '75.0%' ) && str_contains( $reports_html, 'Organic Search' ), 'Analytics page shows the overview and selected site report' );
expect_analytics( str_contains( $reports_html, '<select id="stuh-analytics-client" name="client_id">' ) && str_contains( $reports_html, '<option value="site-1" selected>' ), 'Report page uses the selected client dropdown instead of a client table' );
$document = new DOMDocument();
$previous_errors = libxml_use_internal_errors( true );
$document->loadHTML( '<!doctype html><html><body>' . $reports_html . '</body></html>' );
libxml_clear_errors();
libxml_use_internal_errors( $previous_errors );
$chart_xpath = new DOMXPath( $document );
expect_analytics( 0 === $chart_xpath->query( '//table[not(ancestor::details)]' )->length, 'Tables appear only in the optional exact monthly values disclosure' );
expect_analytics( 7 === $chart_xpath->query( '//figure[@class="stuh-analytics-chart"]' )->length, 'Render five period comparisons and two ranking charts' );
expect_analytics( '100.000' === $chart_xpath->query( '(//figure[@class="stuh-analytics-chart"])[1]//li[1]//*[local-name()="rect"][2]' )->item( 0 )->getAttribute( 'width' ) && '50.000' === $chart_xpath->query( '(//figure[@class="stuh-analytics-chart"])[1]//li[2]//*[local-name()="rect"][2]' )->item( 0 )->getAttribute( 'width' ), 'Current and previous bars share the same scale within each comparison chart' );
expect_analytics( '75.000' === $chart_xpath->query( '(//figure[@class="stuh-analytics-chart"])[4]//li[1]//*[local-name()="rect"][2]' )->item( 0 )->getAttribute( 'width' ) && '50.000' === $chart_xpath->query( '(//figure[@class="stuh-analytics-chart"])[4]//li[2]//*[local-name()="rect"][2]' )->item( 0 )->getAttribute( 'width' ), 'Engagement charts use a fixed zero-to-100-percent scale' );
expect_analytics( 1 === $chart_xpath->query( '(//figure)[1][contains(@class,"stuh-analytics-history")]' )->length, 'Year-over-year line chart appears above all existing charts' );
expect_analytics( 2 === $chart_xpath->query( '//*[local-name()="g" and contains(@class,"stuh-analytics-series--current")]/*[local-name()="polyline" and not(@class)]' )->length && 1 === $chart_xpath->query( '//*[local-name()="g" and contains(@class,"stuh-analytics-series--previous")]/*[local-name()="polyline" and not(@class)]' )->length, 'Complete lines still break at missing months without including the partial point' );
expect_analytics( ( $has_mtd ? 25 : 23 ) === $chart_xpath->query( '//*[local-name()="circle"]' )->length && 1 === $chart_xpath->query( '//*[local-name()="svg" and @role="img" and @aria-label="Active users - year over year"]' )->length, 'Render only reported data points and label the line chart accessibly' );
expect_analytics( ( $has_mtd ? 2 : 0 ) === $chart_xpath->query( '//*[local-name()="circle" and @class="stuh-analytics-in-progress"]' )->length && ( $has_mtd ? 2 : 0 ) === $chart_xpath->query( '//*[local-name()="polyline" and @class="stuh-analytics-in-progress"]' )->length, 'Only the current month points and their connecting segments use the lighter in-progress style' );
expect_analytics( 13 === $chart_xpath->query( '//*[local-name()="g" and @class="stuh-analytics-month-hover" and @tabindex="0"]' )->length && 13 === $chart_xpath->query( '//*[local-name()="g" and @class="stuh-analytics-month-tooltip"]' )->length, 'Each month provides a broad hover and keyboard-focus target with both year values' );
expect_analytics( str_contains( $reports_html, 'Month to date - in progress' ) && ( ! $has_mtd || str_contains( $reports_html, ': 125; ' ) ), 'Partial-month hover label contains its status and both numeric series' );
expect_analytics( 13 === $chart_xpath->query( '//details[@class="stuh-analytics-monthly-data"]//tbody/tr' )->length && str_contains( $reports_html, 'No data reported' ), 'Expose all thirteen monthly pairs in the accessible disclosure' );
expect_analytics( str_contains( $reports_html, '2.50' ) && str_contains( $reports_html, '/&lt;script&gt;' ) && ! str_contains( $reports_html, '/<script>' ), 'Charts preserve fractional key events and escape page-path labels' );
expect_analytics( 12 === $chart_xpath->query( '//*[local-name()="svg" and @aria-hidden="true" and @focusable="false"]' )->length && 12 === $chart_xpath->query( '//div[@class="stuh-analytics-bar-label"]/strong' )->length, 'Every decorative bar has a visible label and exact value without requiring color or SVG accessibility' );
if ( in_array( $argv[1] ?? '', [ '--render', '--render-demo' ], true ) ) {
	if ( '--render-demo' === $argv[1] ) {
		$GLOBALS['clients'] = [];
		unset( $_GET['client_id'] );
		$reports_html = render_analytics_page( 'render_reports' );
	}
	echo '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Analytics charts preview</title><style>body{margin:24px;background:#f0f0f1;color:#1d2327;font:13px/1.5 sans-serif}a{color:#2271b1}button,select{font:inherit}';
	echo file_get_contents( dirname( __DIR__ ) . '/assets/css/client-sites.css' );
	echo '</style>' . $reports_html . '</html>';
	exit;
}
expect_analytics( ! str_contains( $reports_html, 'value="connect"' ) && ! str_contains( $reports_html, 'value="map"' ) && ! str_contains( $reports_html, 'value="properties"' ), 'Analytics report page does not contain connection or mapping settings' );
expect_analytics( str_contains( $reports_html, 'page=stuh-settings#stuh-google-settings' ) && str_contains( $reports_html, 'name="return_page" value="analytics"' ), 'Report page links to Settings and keeps refresh actions on reports' );
STUH_Analytics::register_menu();
expect_analytics( 'stuh' === $GLOBALS['submenus'][0][0] && 'manage_options' === $GLOBALS['submenus'][0][3], 'Administrators retain Analytics under the existing Updater Host menu' );
$GLOBALS['capabilities'] = [ 'read', 'edit_posts', 'edit_others_posts' ];
STUH_Analytics::register_menu();
expect_analytics( 'edit_others_posts' === $GLOBALS['top_menus'][0][2] && 'stuh-analytics' === $GLOBALS['top_menus'][0][3], 'Editors get a standalone Google Analytics menu without exposing administrator-only host pages' );
$editor_request_count = count( $GLOBALS['requests'] );
$editor_reports = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $editor_reports, 'Top pages - page views' ) && str_contains( $editor_reports, 'Refresh Analytics' ) && ! str_contains( $editor_reports, 'Google Analytics settings</a>' ) && ! str_contains( $editor_reports, 'Manage this site mapping' ) && count( $GLOBALS['requests'] ) === $editor_request_count, 'Editors can read cached reports and request refreshes without Google API calls or links to restricted settings/mappings' );
$editor_connection = get_option( 'stuh_google_connection' );
$editor_mappings = get_option( 'stuh_google_mappings' );
foreach ( [ 'connect', 'disconnect', 'properties', 'discover_all', 'discover', 'map', 'unmap' ] as $operation ) {
	try {
		analytics_action( $operation );
		throw new RuntimeException( 'Editor management action succeeded' );
	} catch ( RuntimeException $error ) {
		expect_analytics( 'Insufficient permissions' === $error->getMessage(), 'Editors cannot change Google credentials, properties, discovery or site mappings' );
	}
}
foreach ( [ 'render_settings', 'callback' ] as $method ) {
	try {
		render_analytics_page( $method );
		throw new RuntimeException( 'Editor opened restricted Google settings or callback' );
	} catch ( RuntimeException $error ) {
		expect_analytics( 'Insufficient permissions' === $error->getMessage(), 'Connection settings and OAuth callbacks remain administrator-only' );
	}
}
expect_analytics( $editor_connection === get_option( 'stuh_google_connection' ) && $editor_mappings === get_option( 'stuh_google_mappings' ), 'Denied editor actions preserve credentials and mappings' );
try {
	analytics_action( 'refresh', [ '_wpnonce' => 'bad' ] );
	throw new RuntimeException( 'Editor refreshed without a nonce' );
} catch ( RuntimeException $error ) {
	expect_analytics( 'Invalid nonce' === $error->getMessage(), 'Editor refresh remains nonce-protected' );
}
unset( $GLOBALS['scheduled']['site-1'] );
[ $editor_refresh_url, $editor_refresh_notice ] = analytics_action( 'refresh' );
expect_analytics( ! $editor_refresh_notice['error'] && isset( $GLOBALS['scheduled']['site-1'] ) && str_contains( $editor_refresh_url, 'page=stuh-analytics' ) && str_contains( $editor_refresh_url, 'client_id=site-1' ), 'Editors can queue a mapped report refresh and return to Analytics even without an explicit return-page field' );
foreach ( [ [ 'read' ], [ 'read', 'edit_posts', 'publish_posts' ] ] as $capabilities ) {
	$GLOBALS['capabilities'] = $capabilities;
	foreach ( [ 'reports', 'refresh' ] as $operation ) {
		try {
			if ( 'reports' === $operation ) {
				render_analytics_page( 'render_reports' );
			} else {
				analytics_action( 'refresh' );
			}
			throw new RuntimeException( 'Lower-privilege Analytics access succeeded' );
		} catch ( RuntimeException $error ) {
			expect_analytics( 'Insufficient permissions' === $error->getMessage(), 'Authors and subscribers cannot view or refresh Analytics reports' );
		}
	}
}
unset( $GLOBALS['capabilities'], $GLOBALS['scheduled']['site-1'] );
[ $refresh_url ] = analytics_action( 'refresh', [ 'return_page' => 'analytics' ] );
expect_analytics( str_contains( $refresh_url, 'page=stuh-analytics' ) && str_contains( $refresh_url, 'client_id=site-1' ), 'Report refresh returns to the selected Analytics report' );
unset( $GLOBALS['scheduled']['site-1'] );
$_GET = [ 'page' => 'stuh-analytics' ];
$reports_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $reports_html, 'Top pages - page views' ) && str_contains( $reports_html, '<option value="site-1" selected>' ), 'Opening reports defaults to a mapped client and displays its charts' );
$GLOBALS['clients'] = [ [ 'id' => 'unmapped', 'site_url' => 'https://unmapped.example' ], STUH_Plugin::get_clients()[0] ];
$reports_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $reports_html, '<option value="site-1" selected>' ) && ! str_contains( $reports_html, '<option value="unmapped" selected>' ), 'Default selection prefers a mapped site over an unmapped first client' );
$_GET['client_id'] = 'unmapped';
$reports_html = render_analytics_page( 'render_reports' );
expect_analytics( ! str_contains( $reports_html, '<option value="unmapped"' ) && str_contains( $reports_html, 'No Analytics property is connected' ) && ! str_contains( $reports_html, '<svg' ), 'Unmapped sites are excluded from the dropdown and direct links do not display a different client report' );
unset( $_GET['client_id'] );
$original_mappings = get_option( 'stuh_google_mappings' );
$dropdown_mappings = $original_mappings;
$GLOBALS['clients'] = [
	[ 'id' => 'zulu', 'site_url' => 'http://Zulu.example' ],
	[ 'id' => 'pending', 'site_url' => 'https://pending.example' ],
	[ 'id' => 'alpha', 'site_url' => 'https://alpha.example' ],
	[ 'id' => 'obsolete', 'site_url' => 'https://obsolete.example' ],
	[ 'id' => 'old-account', 'site_url' => 'https://old.example' ],
	[ 'id' => 'unmapped', 'site_url' => 'https://unmapped.example' ],
	STUH_Plugin::get_clients()[1],
];
foreach ( [ 'zulu', 'alpha', 'pending', 'obsolete', 'old-account' ] as $id ) {
	$dropdown_mappings[ $id ] = $mapping;
	$dropdown_record = $good;
	if ( 'alpha' === $id ) {
		$dropdown_record['data']['current']['activeUsers'] = 0.0;
	}
	if ( 'zulu' === $id ) {
		$dropdown_record['error'] = 'Refresh failed';
	}
	if ( 'pending' === $id ) {
		unset( $dropdown_record['data'] );
	}
	if ( 'obsolete' === $id ) {
		$dropdown_record['fingerprint'] = 'obsolete';
	}
	if ( 'old-account' === $id ) {
		$dropdown_mappings[ $id ]['connection_id'] = 'another-connection';
	}
	update_option( invoke_analytics( 'report_key', $id ), $dropdown_record );
}
update_option( 'stuh_google_mappings', $dropdown_mappings );
$dropdown_html = render_analytics_page( 'render_reports' );
preg_match_all( '#<option value="([^"]+)"[^>]*>([^<]+)</option>#', $dropdown_html, $dropdown_options, PREG_SET_ORDER );
expect_analytics( [ 'alpha', 'site-1', 'zulu' ] === array_column( $dropdown_options, 1 ), 'Dropdown sorts available reports alphabetically regardless of URL scheme and excludes pending, obsolete, unmapped and old-connection sites' );
expect_analytics( [ 'alpha.example', 'client.example', 'Zulu.example' ] === array_column( $dropdown_options, 2 ), 'Dropdown labels omit HTTP and HTTPS schemes' );
expect_analytics( str_contains( $dropdown_html, '<option value="alpha" selected>' ), 'Default selection is the first alphabetical report and includes confirmed zero traffic' );
foreach ( [ 'zulu', 'alpha', 'pending', 'obsolete', 'old-account' ] as $id ) {
	delete_option( invoke_analytics( 'report_key', $id ) );
}
update_option( 'stuh_google_mappings', [] );
$demo_options = $GLOBALS['options'];
$demo_scheduled = $GLOBALS['scheduled'] ?? [];
$demo_requests = count( $GLOBALS['requests'] );
$demo_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $demo_html, 'Demo data - no client Analytics reports available.' ) && str_contains( $demo_html, 'demo.example (Demo)' ) && str_contains( $demo_html, '<select id="stuh-analytics-client" disabled>' ), 'Sites without available reports show an explicitly labeled dummy site' );
expect_analytics( str_contains( $demo_html, 'stuh-analytics-line-chart' ) && 7 === substr_count( $demo_html, '<figure class="stuh-analytics-chart">' ) && str_contains( $demo_html, 'Month to date - in progress' ), 'Demo includes the year-over-year chart, hover values, metric comparisons and rankings' );
expect_analytics( ! str_contains( $demo_html, '<form' ) && ! str_contains( $demo_html, 'Refresh Analytics</button>' ) && ! str_contains( $demo_html, 'Manage this site mapping' ), 'Dummy reports have no actionable fake client or mapping controls' );
expect_analytics( $demo_options === $GLOBALS['options'] && $demo_scheduled === ( $GLOBALS['scheduled'] ?? [] ) && $demo_requests === count( $GLOBALS['requests'] ), 'Rendering a demo never persists fake clients, reports or mappings, queues work, or calls Google' );
update_option( 'stuh_google_mappings', $original_mappings );
$GLOBALS['clients'] = [];
expect_analytics( str_contains( render_analytics_page( 'render_reports' ), 'demo.example (Demo)' ), 'An installation without registered clients still shows demo charts' );
$saved_connection = get_option( 'stuh_google_connection' );
delete_option( 'stuh_google_connection' );
$offline_demo = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $offline_demo, 'demo.example (Demo)' ) && str_contains( $offline_demo, 'Connect Google in Updater Host' ), 'Unconnected installations show demo data without concealing the connection status' );
update_option( 'stuh_google_connection', $saved_connection );
unset( $GLOBALS['clients'] );
$_GET['client_id'] = 'missing-site';
try {
	render_analytics_page( 'render_reports' );
	throw new RuntimeException( 'Unknown report site was accepted' );
} catch ( RuntimeException $error ) {
	expect_analytics( 'The selected client site could not be found.' === $error->getMessage(), 'Report pages reject unknown client IDs' );
}
$GLOBALS['authorized'] = false;
foreach ( [ 'render_reports', 'render_settings' ] as $method ) {
	try {
		render_analytics_page( $method );
		throw new RuntimeException( 'Unauthorized page access' );
	} catch ( RuntimeException $error ) {
		expect_analytics( 'Insufficient permissions' === $error->getMessage(), 'Both Analytics page entry points enforce administrator access' );
	}
}
$GLOBALS['authorized'] = true;
$_GET = [];
expect_analytics( count( $GLOBALS['requests'] ) === $before, 'Neither settings nor reports pages make synchronous Google requests' );

$chart_record = $good;
$chart_record['data']['current'] = array_fill_keys( $metrics, 0.0 );
$chart_record['data']['previous'] = array_fill_keys( $metrics, 0.0 );
$chart_record['data']['pages'] = [];
$chart_record['data']['channels'] = [];
update_option( $key, $chart_record );
$_GET = [ 'page' => 'stuh-analytics', 'client_id' => 'site-1' ];
$zero_html = render_analytics_page( 'render_reports' );
expect_analytics( 10 === substr_count( $zero_html, 'width="0.000"' ) && 2 === substr_count( $zero_html, 'No data returned for this hostname and period.' ), 'Zero totals produce empty bars without division errors and rankings have explicit empty states' );
expect_analytics( ! str_contains( $zero_html, 'demo.example' ), 'Real zero-traffic reports must not be replaced by demo data' );
$legacy_record = $good;
$legacy_record['data']['history']['months'] = array_slice( $legacy_record['data']['history']['months'], 0, 12 );
unset( $legacy_record['data']['history']['includes_current'] );
update_option( $key, $legacy_record );
$legacy_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $legacy_html, 'Refresh Analytics to include the ongoing month.' ) && 12 === substr_count( $legacy_html, 'class="stuh-analytics-month-hover"' ), 'Older twelve-point caches remain usable and prompt for the new partial-month data' );
unset( $legacy_record['data']['history'] );
update_option( $key, $legacy_record );
expect_analytics( str_contains( render_analytics_page( 'render_reports' ), 'Refresh Analytics to load yearly data.' ), 'Pre-upgrade cached reports explain how to load history instead of fabricating annual data' );
update_option( $key, [ 'fingerprint' => invoke_analytics( 'fingerprint', $mapping ) ] );
$pending_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $pending_html, 'Demo data - no client Analytics reports available.' ) && str_contains( $pending_html, 'demo.example' ), 'If all real reports are pending, show explicitly marked demo data rather than fictitious client counts' );
unset( $GLOBALS['scheduled']['site-1'] );
update_option( $key, $good );
$_GET = [];

// The reused Analytics column reports the connected property, users and signed change.
$html = render_analytics_column();
expect_analytics( str_contains( $html, '>10</a>' ) && str_contains( $html, 'stuh-analytics-change--up">+100.0%' ), 'Column shows 28-day active users and a positive change class' );
expect_analytics( str_contains( $html, 'page=stuh-analytics' ) && str_contains( $html, 'client_id=site-1' ) && ! str_contains( $html, '#stuh-analytics' ) && str_contains( $html, 'Active users (28 days)' ), 'Available counts link to the Analytics page with this client selected and label the reporting window' );
expect_analytics( str_contains( $html, 'class="stuh-analytics-users"' ), 'User count has its own black-link style' );
expect_analytics( [ 'site-1' => 10.0, 'unmapped' => null ] === STUH_Analytics::column_sort_values( [ [ 'id' => 'site-1' ], [ 'id' => 'unmapped' ] ] ), 'Sort values use numeric active users and null for unmapped clients' );
$column_record = $good;
$column_record['data']['current']['activeUsers'] = 2.0;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'stuh-analytics-change--down">-60.0%' ), 'Column shows a negative change with the decline class' );
$column_record['data']['current']['activeUsers'] = 5.0;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'stuh-analytics-change--neutral">0.0%' ), 'Unchanged traffic is neutral' );
$column_record['data']['current']['activeUsers'] = 0.0;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'stuh-analytics-change--down">-100.0%' ), 'A drop to zero is a full decline, not unavailable data' );
$column_record['data']['previous']['activeUsers'] = 0.0;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'stuh-analytics-change--neutral">0.0%' ), 'Two valid empty periods show zero change' );
expect_analytics( str_contains( render_analytics_column(), 'page=stuh-analytics' ), 'Zero-traffic reports still link to the Analytics dashboard' );
expect_analytics( [ 'site-1' => 0.0 ] === STUH_Analytics::column_sort_values( [ [ 'id' => 'site-1' ] ] ), 'Zero active users remains a sortable count rather than missing data' );
$column_record['data']['current']['activeUsers'] = 5.0;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), '>N/A</span>' ) && ! str_contains( render_analytics_column(), 'stuh-analytics-change--up' ), 'A zero baseline must not fabricate a percentage increase' );
$column_record['error'] = 'Google failed <script>';
update_option( $key, $column_record );
$html = render_analytics_column();
expect_analytics( str_contains( $html, 'Stale data' ) && str_contains( $html, '&lt;script&gt;' ) && ! str_contains( $html, '<script>' ), 'Stale reports remain labeled and errors are escaped in tooltips' );
$column_record['error'] = '';
$column_record['fetched_at'] = time() - 5 * HOUR_IN_SECONDS;
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'Stale data' ), 'Old cached reports are explicitly stale even without a failed refresh' );
update_option( $key, [ 'fingerprint' => invoke_analytics( 'fingerprint', $mapping ) ] );
expect_analytics( str_contains( render_analytics_column(), 'Connected - report pending' ), 'A connected property without data is pending, not zero' );
expect_analytics( is_wp_error( STUH_Analytics::monthly_active_users( 'site-1' ) ), 'Chart history explicitly rejects a missing saved report rather than returning zeros' );
expect_analytics( str_contains( render_analytics_column(), 'client_tab=analytics' ) && str_contains( render_analytics_column(), '#stuh-analytics' ), 'Pending reports open the client details Analytics tab' );
update_option( $key, [ 'fingerprint' => invoke_analytics( 'fingerprint', $mapping ), 'error' => 'Quota exceeded' ] );
expect_analytics( str_contains( render_analytics_column(), 'Connected - report failed' ), 'A failed first report must not appear merely pending' );
$column_record['fingerprint'] = 'obsolete-mapping';
update_option( $key, $column_record );
expect_analytics( str_contains( render_analytics_column(), 'Connected - report pending' ), 'Do not show user counts from a different mapping' );
expect_analytics( [ 'site-1' => null ] === STUH_Analytics::column_sort_values( [ [ 'id' => 'site-1' ] ] ), 'Obsolete report mappings cannot contribute sort values' );
expect_analytics( is_wp_error( STUH_Analytics::monthly_active_users( 'site-1' ) ), 'Chart overlays cannot reuse history from an obsolete mapping' );
$original_mappings = get_option( 'stuh_google_mappings' );
$changed_mappings = $original_mappings;
$changed_mappings['site-1']['connection_id'] = 'old-connection';
update_option( 'stuh_google_mappings', $changed_mappings );
expect_analytics( str_contains( render_analytics_column(), 'Reconnect required' ), 'Reconnected accounts must not display counts from the previous connection' );
expect_analytics( [ 'site-1' => null ] === STUH_Analytics::column_sort_values( [ [ 'id' => 'site-1' ] ] ), 'Reports from another connection cannot contribute sort values' );
expect_analytics( is_wp_error( STUH_Analytics::monthly_active_users( 'site-1' ) ), 'Chart overlays reject a report from another Google connection' );
update_option( 'stuh_google_mappings', [] );
expect_analytics( str_contains( render_analytics_column(), 'Not connected' ), 'Unmapped sites explicitly show not connected' );
expect_analytics( str_contains( render_analytics_column(), 'class="stuh-analytics-disconnected"' ), 'Disconnected link has its own light-grey style' );
expect_analytics( str_contains( render_analytics_column(), 'client_tab=analytics' ) && str_contains( render_analytics_column(), '#stuh-analytics' ) && ! str_contains( render_analytics_column(), 'page=stuh-analytics' ), 'Unconnected sites open their client details Analytics tab rather than the report dashboard' );
update_option( 'stuh_google_mappings', $original_mappings );
update_option( $key, $good );
expect_analytics( count( $GLOBALS['requests'] ) === $before, 'Column rendering must never call Google' );

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
$invalid_history = $reports;
$invalid_history[4]['rows'][] = $invalid_history[4]['rows'][0];
$invalid_history[4]['rowCount']++;
$GLOBALS['responses'][] = google_response( [ 'reports' => $invalid_history ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( str_contains( get_option( $key )['error'], 'duplicate monthly' ) && $good['data'] === get_option( $key )['data'], 'Duplicate months must fail explicitly and preserve the complete last successful report' );
$invalid_history = $reports;
$invalid_history[4]['rows'][0]['dimensionValues'][0]['value'] = $history_start->format( 'Ym' );
$GLOBALS['responses'][] = google_response( [ 'reports' => $invalid_history ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( '' !== get_option( $key )['error'] && $good['data'] === get_option( $key )['data'], 'Reject a partial current month or an out-of-range history month' );
$empty = $reports;
foreach ( $empty as &$report ) {
	unset( $report['rows'], $report['rowCount'] );
}
unset( $report );
$GLOBALS['responses'][] = google_response( [ 'reports' => $empty ] );
STUH_Analytics::refresh_report( 'site-1' );
expect_analytics( 0.0 === get_option( $key )['data']['current']['activeUsers'] && '' === get_option( $key )['error'], 'A valid empty response may represent zero traffic' );
$_GET = [ 'page' => 'stuh-analytics', 'client_id' => 'site-1' ];
$empty_history_html = render_analytics_page( 'render_reports' );
expect_analytics( str_contains( $empty_history_html, 'No monthly data available.' ) && ! str_contains( $empty_history_html, 'class="stuh-analytics-line-chart"' ), 'A wholly missing monthly report must not render a false zero-valued annual line' );
$_GET = [];

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
[ $disconnect_url, $notice ] = analytics_action( 'disconnect' );
expect_analytics( str_contains( $disconnect_url, 'page=stuh-settings#stuh-google-settings' ), 'Global Google actions now return to the Settings section' );
expect_analytics( ! $notice['error'] && false === get_option( 'stuh_google_connection' ) && false === get_option( $key ) && false === get_option( 'stuh_google_mappings' ), 'Disconnect must revoke and delete local tokens, mappings and reports' );
update_option( 'stuh_google_mappings', [ 'site-1' => $mapping ] );
update_option( $key, $good );
$GLOBALS['scheduled']['site-1'] = time();
expect_analytics( true === STUH_Analytics::forget_client( 'site-1' ), 'Client deletion cleanup must succeed' );
expect_analytics( [] === get_option( 'stuh_google_mappings' ) && false === get_option( $key ) && ! isset( $GLOBALS['scheduled']['site-1'] ), 'Client deletion must remove its mapping, cached report and queued refresh' );

// GTM diagnostics are optional, but malformed or dynamic destinations must not be guessed.
expect_analytics( [] === invoke_analytics( 'container_ids', [ 'gtm_container_ids' => null ] ), 'Null GTM diagnostics must mean no detected containers' );
expect_analytics( is_wp_error( invoke_analytics( 'container_ids', [ 'gtm_container_ids' => 'GTM-ABC1234' ] ) ), 'Reject a string instead of the agreed array format' );
expect_analytics( is_wp_error( invoke_analytics( 'container_ids', [ 'gtm_container_ids' => [ 'GTM-ABC1234', null ] ] ) ), 'Reject partial invalid ID lists instead of discarding ambiguous input' );
$version = [
	'tag' => [ [ 'type' => 'googtag', 'parameter' => [ [ 'key' => 'tagId', 'value' => '{{Analytics ID}}' ] ] ] ],
	'variable' => [ [ 'name' => 'Analytics ID', 'type' => 'c', 'parameter' => [ [ 'key' => 'value', 'value' => 'G-ONE123' ] ] ] ],
];
expect_analytics( [ 'G-ONE123' ] === invoke_analytics( 'published_measurements', $version ), 'Resolve a constant variable in a published Google tag' );
$dynamic = $version;
$dynamic['variable'][0]['type'] = 'jsm';
expect_analytics( is_wp_error( invoke_analytics( 'published_measurements', $dynamic ) ), 'Never execute or guess dynamic GTM variables' );
$legacy = [ 'tag' => [
	[ 'type' => 'gaawc', 'parameter' => [ [ 'key' => 'measurementId', 'value' => 'G-ONE123' ] ] ],
	[ 'type' => 'gaawe', 'parameter' => [ [ 'key' => 'measurementIdOverride', 'value' => 'G-TWO456' ] ] ],
	[ 'type' => 'googtag', 'paused' => true, 'parameter' => [ [ 'key' => 'tagId', 'value' => 'G-PAUSED' ] ] ],
] ];
expect_analytics( [ 'G-ONE123', 'G-TWO456' ] === invoke_analytics( 'published_measurements', $legacy ), 'Include explicit GA4 event destinations but ignore paused tags' );
$alias = [ 'tag' => [ [ 'type' => 'googtag', 'parameter' => [ [ 'key' => 'tagId', 'value' => 'GT-ALIAS' ] ] ] ] ];
expect_analytics( is_wp_error( invoke_analytics( 'published_measurements', $alias ) ), 'Unsupported Google tag aliases must remain manual rather than be mistaken for property IDs' );

// Discover the real numeric property through GTM and paginated GA4 stream metadata.
$connection['id'] = 'discovery-connection';
$connection['scopes'] = [ 'https://www.googleapis.com/auth/analytics.readonly', 'https://www.googleapis.com/auth/tagmanager.readonly' ];
invoke_analytics( 'save_connection', $connection );
$client = STUH_Plugin::get_clients()[0];
$GLOBALS['telemetry'] = [ 'site-1' => [ 'data' => [ 'analytics' => 'disabled', 'gtm_container_ids' => null ] ] ];
$before = count( $GLOBALS['requests'] );
expect_analytics( false === STUH_Analytics::queue_discovery( $client ), 'Null detection must not schedule an API lookup' );
$GLOBALS['telemetry']['site-1']['data']['gtm_container_ids'] = [ 'GTM-ABC1234', 'GTM-ABC1234' ];
expect_analytics( true === STUH_Analytics::queue_discovery( $client ), 'New GTM IDs must immediately queue discovery even when Analytics diagnostics say disabled' );
expect_analytics( count( $GLOBALS['requests'] ) === $before && isset( $GLOBALS['discovery_scheduled']['site-1'] ), 'Telemetry processing must only queue discovery, never call Google' );
$GLOBALS['responses'][] = google_response( [ 'publicId' => 'GTM-ABC1234', 'path' => 'accounts/10/containers/20' ] );
$GLOBALS['responses'][] = google_response( $version );
$GLOBALS['responses'][] = google_response( [ 'accountSummaries' => [ [ 'propertySummaries' => [ [ 'property' => 'properties/123', 'displayName' => 'Client property' ], [ 'property' => 'properties/456', 'displayName' => 'Other property' ] ] ] ] ] );
$GLOBALS['responses'][] = google_response( [ 'dataStreams' => [], 'nextPageToken' => 'streams-page-two' ] );
$GLOBALS['responses'][] = google_response( [ 'dataStreams' => [ [ 'type' => 'WEB_DATA_STREAM', 'webStreamData' => [ 'measurementId' => 'G-ONE123', 'defaultUri' => 'https://client.example/' ] ] ] ] );
$GLOBALS['responses'][] = google_response( [ 'dataStreams' => [] ] );
$GLOBALS['responses'][] = google_response( [ 'name' => 'properties/123', 'displayName' => 'Automatically found', 'timeZone' => 'Europe/Amsterdam' ] );
unset( $GLOBALS['discovery_scheduled']['site-1'] );
STUH_Analytics::discover_client( 'site-1' );
$automatic = get_option( 'stuh_google_mappings' )['site-1'];
expect_analytics( '123' === $automatic['property_id'] && 'gtm' === $automatic['source'] && [ 'GTM-ABC1234' ] === $automatic['gtm_container_ids'], 'Persist only the unique GTM-to-stream property match with provenance' );
expect_analytics( 'client.example' === $automatic['hostname'] && isset( $GLOBALS['scheduled']['site-1'] ), 'Automatic mapping must preserve hostname isolation and queue the report' );
$discovery_requests = array_slice( $GLOBALS['requests'], $before );
expect_analytics( str_contains( $discovery_requests[0][0], 'containers:lookup?tagId=GTM-ABC1234' ) && str_ends_with( $discovery_requests[1][0], '/versions:live' ), 'Resolve the detected container and published version, not workspace drafts' );
expect_analytics( str_contains( $discovery_requests[4][0], 'pageToken=streams-page-two' ), 'Search all stream pages before deciding a destination is missing' );
$before = count( $GLOBALS['requests'] );
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( count( $GLOBALS['requests'] ) === $before && get_option( 'stuh_google_mappings' )['site-1'] === $automatic, 'Existing mappings must never be automatically overwritten' );

// An explicit removal pauses discovery; resuming remains an administrator action.
analytics_action( 'unmap' );
expect_analytics( false === STUH_Analytics::queue_discovery( $client, true ) && ! isset( $GLOBALS['discovery_scheduled']['site-1'] ), 'Removing a mapping must not immediately recreate it' );
analytics_action( 'discover' );
expect_analytics( isset( $GLOBALS['discovery_scheduled']['site-1'] ), 'An administrator can explicitly resume discovery' );
$discovery_key = invoke_analytics( 'discovery_key', 'site-1' );
$status = get_option( $discovery_key );
unset( $GLOBALS['discovery_scheduled']['site-1'] );
expect_analytics( false === STUH_Analytics::queue_discovery( $client ), 'Automatic retries must respect the discovery cache interval' );
$status['checked_at'] = time() - HOUR_IN_SECONDS;
update_option( $discovery_key, $status );
expect_analytics( true === STUH_Analytics::queue_discovery( $client ), 'Retry discovery once the one-hour interval expires' );

// Ambiguous properties and hostname mismatches must not result in partial mappings.
$gtm_key = 'stuh_google_gtm_' . hash( 'sha256', $connection['id'] . 'GTM-ABC1234' );
set_transient( $gtm_key, [ 'G-ONE123', 'G-TWO456' ], HOUR_IN_SECONDS );
$stream_key = 'stuh_google_streams_' . $connection['id'];
set_transient( $stream_key, [
	'G-ONE123' => [ [ 'property_id' => '123', 'hostname' => 'client.example' ] ],
	'G-TWO456' => [ [ 'property_id' => '456', 'hostname' => 'client.example' ] ],
], HOUR_IN_SECONDS );
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( ! isset( get_option( 'stuh_google_mappings' )['site-1'] ) && str_contains( get_option( $discovery_key )['message'], 'multiple GA4 properties' ), 'Multiple destinations in different properties must require manual review' );
set_transient( $gtm_key, [ 'G-ONE123' ], HOUR_IN_SECONDS );
set_transient( $stream_key, [ 'G-ONE123' => [ [ 'property_id' => '123', 'hostname' => 'www.client.example' ] ] ], HOUR_IN_SECONDS );
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( ! isset( get_option( 'stuh_google_mappings' )['site-1'] ) && get_option( $discovery_key )['error'], 'Do not silently conflate www and bare hostnames' );
delete_transient( $gtm_key );
$GLOBALS['responses'][] = google_response( [ 'error' => [ 'status' => 'PERMISSION_DENIED' ] ], 403 );
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( str_contains( get_option( $discovery_key )['message'], '403' ) && ! isset( get_option( 'stuh_google_mappings' )['site-1'] ), 'GTM API failures must be visible and must not fall back to guessed properties' );

// In-flight discovery must preserve new manual choices and changed diagnostics.
set_transient( $gtm_key, [ 'G-ONE123' ], HOUR_IN_SECONDS );
set_transient( $stream_key, [ 'G-ONE123' => [ [ 'property_id' => '123', 'hostname' => 'client.example' ] ] ], HOUR_IN_SECONDS );
$GLOBALS['responses'][] = static function() use ( $mapping ) {
	update_option( 'stuh_google_mappings', [ 'site-1' => $mapping ] );
	return google_response( [ 'name' => 'properties/123', 'displayName' => 'Automatic', 'timeZone' => 'Europe/Amsterdam' ] );
};
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( $mapping === get_option( 'stuh_google_mappings' )['site-1'], 'Do not overwrite a manual mapping saved during discovery' );
update_option( 'stuh_google_mappings', [] );
$GLOBALS['responses'][] = static function() {
	$GLOBALS['telemetry']['site-1']['data']['gtm_container_ids'] = [ 'GTM-CHANGED' ];
	return google_response( [ 'name' => 'properties/123', 'displayName' => 'Automatic', 'timeZone' => 'Europe/Amsterdam' ] );
};
STUH_Analytics::discover_client( 'site-1' );
expect_analytics( ! isset( get_option( 'stuh_google_mappings' )['site-1'] ), 'Do not map an obsolete diagnostics snapshot' );
$connection['scopes'] = [ 'https://www.googleapis.com/auth/analytics.readonly' ];
invoke_analytics( 'save_connection', $connection );
$result = STUH_Analytics::queue_discovery( $client, true );
expect_analytics( is_wp_error( $result ) && str_contains( $result->get_error_message(), 'reconnect' ), 'Old Analytics-only connections need explicit GTM reauthorization' );
$before = count( $GLOBALS['requests'] );
$html = render_analytics();
expect_analytics( count( $GLOBALS['requests'] ) === $before && str_contains( $html, 'GTM-CHANGED' ), 'Discovery UI must show reported IDs without making synchronous Google calls' );
STUH_Analytics::forget_client( 'site-1' );
expect_analytics( false === get_option( $discovery_key ) && ! isset( $GLOBALS['discovery_scheduled']['site-1'] ), 'Client cleanup must remove discovery-only status and pending jobs' );
expect_analytics( ! $GLOBALS['responses'], 'All expected requests must be consumed' );
echo "Analytics regression checks passed.\n";
