<?php
/**
 * Standalone SSL regression checks: php tests/ssl-column.php
 */
if ( '--serve' === ( $argv[1] ?? '' ) ) {
	$context = stream_context_create( [ 'ssl' => [
		'local_cert' => $argv[2],
		'allow_self_signed' => true,
		'verify_peer' => false,
	] ] );
	$server = stream_socket_server( 'tls://127.0.0.1:0', $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context );
	if ( false === $server ) {
		fwrite( STDERR, $error );
		exit( 1 );
	}
	echo stream_socket_get_name( $server, false ) . "\n";
	flush();
	$connection = stream_socket_accept( $server, 15 );
	if ( false !== $connection ) {
		fclose( $connection );
	}
	fclose( $server );
	exit( false === $connection ? 1 : 0 );
}

define( 'ABSPATH', __DIR__ . '/' );
define( 'DAY_IN_SECONDS', 86400 );
define( 'HOUR_IN_SECONDS', 3600 );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );

class WP_Error {
	private $message;
	public function __construct( $code, $message ) { $this->message = $message; }
	public function get_error_message() { return $this->message; }
}
function __( $text, $domain = '' ) { return $text; }
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function wp_parse_url( $url ) { return parse_url( $url ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_option( $key, $default = false ) { return $GLOBALS['options'][ $key ] ?? $default; }
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['transients'][ $key ] = $value;
	$GLOBALS['ttls'][ $key ] = $ttl;
	return true;
}
function wp_next_scheduled( $hook, $args ) { return $GLOBALS['events'][ $args[0] ] ?? false; }
function wp_schedule_single_event( $time, $hook, $args, $wp_error ) {
	if ( ! empty( $GLOBALS['schedule_error'] ) ) {
		return new WP_Error( 'schedule_failed', 'Scheduling failed' );
	}
	$GLOBALS['events'][ $args[0] ] = $time;
	return true;
}

require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

function invoke_ssl( string $method, ...$args ) {
	return ( new ReflectionMethod( STUH_Plugin::class, $method ) )->invoke( null, ...$args );
}
function expect_ssl( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

$client = [ 'id' => 'site-1', 'site_url' => 'https://legacy.example', 'site_urls' => [ 'https://first.example', 'https://second.example' ] ];
expect_ssl( 'https://first.example' === invoke_ssl( 'client_ssl_url', $client ), 'Use the first registered URL' );
expect_ssl( 'https://legacy.example' === invoke_ssl( 'client_ssl_url', [ 'site_url' => 'https://legacy.example' ] ), 'Support legacy single URLs' );
expect_ssl( '' === invoke_ssl( 'client_ssl_url', [ 'site_urls' => [] ] ), 'Empty URL lists have no SSL target' );
expect_ssl( isset( ( new STUH_Plugin() )->client_columns()['ssl'] ), 'Register the SSL column with Screen Options' );

$now = time();
$generic = invoke_ssl( 'ssl_certificate_details', [ 'issuer' => [ 'O' => 'Example CA' ], 'validTo_time_t' => $now + 10 * DAY_IN_SECONDS + 3600 ] );
$lets_encrypt = invoke_ssl( 'ssl_certificate_details', [ 'issuer' => [ 'O' => "Let's Encrypt", 'CN' => 'R13' ], 'validTo_time_t' => $now + DAY_IN_SECONDS ] );
expect_ssl( 10 === invoke_ssl( 'ssl_expiry_days', $generic ), 'Display complete days remaining' );
expect_ssl( null === invoke_ssl( 'ssl_expiry_days', $lets_encrypt ), "Let's Encrypt has no displayed day count" );
expect_ssl( true === $lets_encrypt['is_lets_encrypt'], 'Recognize issuer organization independently of intermediate name' );
$spoofed = invoke_ssl( 'ssl_certificate_details', [ 'issuer' => [ 'O' => "Not Let's Encrypt", 'CN' => "Let's Encrypt" ], 'validTo_time_t' => $now + DAY_IN_SECONDS ] );
expect_ssl( false === $spoofed['is_lets_encrypt'], 'Do not match issuer substrings or common names' );
expect_ssl( is_wp_error( invoke_ssl( 'ssl_certificate_details', [] ) ), 'Missing expiry is an explicit error' );
expect_ssl( -2 === invoke_ssl( 'ssl_expiry_days', [ 'expires_at' => $now - DAY_IN_SECONDS - 3600 ] ), 'Expired certificates have negative days' );
expect_ssl( null === invoke_ssl( 'ssl_expiry_days', [ 'error' => 'Failed', 'expires_at' => $now + DAY_IN_SECONDS ] ), 'Failed checks have no sortable day count' );
expect_ssl( is_wp_error( invoke_ssl( 'inspect_ssl_certificate', 'file:///tmp/site' ) ), 'Reject non-HTTP site URLs' );

$statuses = [
	[ 'id' => 'hundred', 'expires_at' => $now + 100 * DAY_IN_SECONDS + 3600 ],
	[ 'id' => 'ten', 'expires_at' => $now + 10 * DAY_IN_SECONDS + 3600 ],
	[ 'id' => 'expired', 'expires_at' => $now - DAY_IN_SECONDS - 3600 ],
	[ 'id' => 'two', 'expires_at' => $now + 2 * DAY_IN_SECONDS + 3600 ],
	array_merge( [ 'id' => 'le' ], $lets_encrypt ),
	[ 'id' => 'error', 'error' => 'Failed' ],
	[ 'id' => 'pending' ],
];
foreach ( [ 'asc' => [ 'expired', 'two', 'ten', 'hundred' ], 'desc' => [ 'hundred', 'ten', 'two', 'expired' ] ] as $order => $expected ) {
	$sorted = $statuses;
	usort( $sorted, fn( $a, $b ) => invoke_ssl( 'compare_ssl_status', $a, $b, $order ) );
	expect_ssl( $expected === array_column( array_slice( $sorted, 0, 4 ), 'id' ), "Numeric expiry sorting: $order" );
	expect_ssl( [ 'le', 'error', 'pending' ] === array_column( array_slice( $sorted, 4 ), 'id' ), "Non-day results remain last: $order" );
}

$GLOBALS['transients'] = [];
$GLOBALS['events'] = [];
expect_ssl( [] === invoke_ssl( 'client_ssl_status', $client ), 'Initial check is pending' );
expect_ssl( isset( $GLOBALS['events']['site-1'] ), 'Queue an initial background check' );
$GLOBALS['transients']['stuh_ssl_' . md5( 'https://first.example' )] = array_merge( $generic, [ 'checked_at' => $now ] );
$GLOBALS['events'] = [];
invoke_ssl( 'client_ssl_status', $client );
expect_ssl( [] === $GLOBALS['events'], 'Fresh results do not trigger another check' );
$GLOBALS['transients']['stuh_ssl_' . md5( 'https://first.example' )]['checked_at'] = $now - DAY_IN_SECONDS - 1;
$stale = invoke_ssl( 'client_ssl_status', $client );
expect_ssl( isset( $GLOBALS['events']['site-1'] ) && $stale['expires_at'] === $generic['expires_at'], 'Retain stale results while refreshing' );
$GLOBALS['events'] = [];
$GLOBALS['transients']['stuh_ssl_' . md5( 'https://first.example' )] = [ 'error' => 'Failed', 'checked_at' => $now - HOUR_IN_SECONDS - 1 ];
invoke_ssl( 'client_ssl_status', $client );
expect_ssl( isset( $GLOBALS['events']['site-1'] ), 'Retry failures after an hour' );
$client['site_urls'][0] = 'https://changed.example';
expect_ssl( [] === invoke_ssl( 'client_ssl_status', $client ), 'Changed first URLs never use the previous certificate' );
$GLOBALS['events'] = [];
$GLOBALS['schedule_error'] = true;
expect_ssl( 'Scheduling failed' === invoke_ssl( 'client_ssl_status', $client )['error'], 'Scheduling failures are visible' );
$GLOBALS['schedule_error'] = false;

// Exercise the real TLS capture with a local self-signed certificate.
$key = openssl_pkey_new( [ 'private_key_bits' => 2048 ] );
$csr = openssl_csr_new( [ 'commonName' => 'localhost', 'organizationName' => 'Example CA' ], $key );
$cert = openssl_csr_sign( $csr, null, $key, 30 );
expect_ssl( false !== $cert, 'Generate local test certificate' );
openssl_x509_export( $cert, $cert_pem );
openssl_pkey_export( $key, $key_pem );
$pem_file = tempnam( sys_get_temp_dir(), 'stuh-ssl-test-' );
$process = null;
$pipes = [];
try {
	file_put_contents( $pem_file, $cert_pem . $key_pem );
	$process = proc_open( [ PHP_BINARY, __FILE__, '--serve', $pem_file ], [ 0 => [ 'pipe', 'r' ], 1 => [ 'pipe', 'w' ], 2 => [ 'pipe', 'w' ] ], $pipes );
	expect_ssl( is_resource( $process ), 'Start local TLS fixture' );
	stream_set_timeout( $pipes[1], 10 );
	$address = trim( (string) fgets( $pipes[1] ) );
	expect_ssl( 1 === preg_match( '/^127\.0\.0\.1:[0-9]+$/', $address ), 'Local TLS fixture is responsive' );
	$url = 'https://' . $address . '/wordpress';
	$GLOBALS['options'][ STUH_OPTION_CLIENTS ] = [ [ 'id' => 'tls-test', 'site_urls' => [ $url, 'https://unused.invalid' ] ] ];
	( new STUH_Plugin() )->run_scheduled_ssl_check( 'tls-test' );
	$result = get_transient( 'stuh_ssl_' . md5( $url ) );
	expect_ssl( empty( $result['error'] ), 'Capture a self-signed certificate without requiring trusted HTTPS' );
	expect_ssl( 'Example CA' === $result['issuer'], 'Capture the leaf certificate issuer' );
	expect_ssl( 29 === invoke_ssl( 'ssl_expiry_days', $result ) || 30 === invoke_ssl( 'ssl_expiry_days', $result ), 'Capture actual certificate expiry' );
	expect_ssl( $url === $result['url'] && $result['checked_at'] >= $now, 'Persist the checked URL and timestamp' );
	expect_ssl( 7 * DAY_IN_SECONDS === $GLOBALS['ttls']['stuh_ssl_' . md5( $url )], 'Retain the cached result for seven days' );
	foreach ( $pipes as $pipe ) {
		fclose( $pipe );
	}
	$pipes = [];
	expect_ssl( 0 === proc_close( $process ), 'TLS fixture exits cleanly' );
	$process = null;
	( new STUH_Plugin() )->run_scheduled_ssl_check( 'tls-test' );
	$failed = get_transient( 'stuh_ssl_' . md5( $url ) );
	expect_ssl( ! empty( $failed['error'] ), 'Persist a visible error when the TLS endpoint is unavailable' );
	expect_ssl( ! isset( $failed['expires_at'] ), 'A failed check must not retain a success-shaped expiry result' );
} finally {
	foreach ( $pipes as $pipe ) {
		fclose( $pipe );
	}
	if ( is_resource( $process ) ) {
		proc_terminate( $process );
		proc_close( $process );
	}
	unlink( $pem_file );
}

echo "SSL column regression checks passed.\n";
