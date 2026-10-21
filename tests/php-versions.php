<?php
/**
 * Standalone PHP support regression checks: php tests/php-versions.php
 */
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
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) {
	$GLOBALS['transients'][ $key ] = $value;
	$GLOBALS['ttls'][ $key ] = $ttl;
	return true;
}
function wp_remote_get( $url, $args ) {
	if ( 'https://endoflife.date/api/php.json' !== $url || 5 !== $args['timeout'] ) {
		throw new RuntimeException( 'Unexpected lifecycle request' );
	}
	++$GLOBALS['requests'];
	return $GLOBALS['response'];
}
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return $response['body']; }

require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

function invoke_php( string $method, ...$args ) {
	return ( new ReflectionMethod( STUH_Plugin::class, $method ) )->invoke( null, ...$args );
}
function expect_php( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}
function respond_php( $response ): void {
	$GLOBALS['transients'] = [];
	$GLOBALS['ttls'] = [];
	$GLOBALS['requests'] = 0;
	$GLOBALS['response'] = $response;
}
function release_php( string $cycle, string $support, string $eol ): array {
	return [ 'cycle' => $cycle, 'releaseDate' => '2000-01-01', 'support' => $support, 'eol' => $eol, 'latest' => $cycle . '.1' ];
}

$compatibility = [
	'7.1' => [ '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5' ],
	'7.0' => [ '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5' ],
	'6.9' => [ '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5' ],
	'6.8' => [ '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4' ],
	'6.7' => [ '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4' ],
	'6.6' => [ '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3' ],
	'6.5' => [ '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3' ],
	'6.4' => [ '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3' ],
];
foreach ( $compatibility as $wordpress => $supported ) {
	foreach ( [ '5.6', '7.0', '7.1', '7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5', '8.6', '9.0' ] as $php ) {
		expect_php(
			in_array( $php, $supported, true ) === invoke_php( 'is_php_version_supported_by_wordpress', $php . '.1', $wordpress . '.1' ),
			"Official compatibility matrix: WordPress $wordpress / PHP $php"
		);
	}
}
expect_php( null === invoke_php( 'is_php_version_supported_by_wordpress', '8.2.1', '6.3' ), 'Unlisted WordPress branches remain unknown' );
expect_php( null === invoke_php( 'is_php_version_supported_by_wordpress', 'invalid', '7.1' ), 'Invalid PHP compatibility input is unknown' );
expect_php( null === invoke_php( 'is_php_version_supported_by_wordpress', '8.5.1', 'invalid' ), 'Invalid WordPress compatibility input is unknown' );

$today = gmdate( 'Y-m-d' );
$yesterday = gmdate( 'Y-m-d', time() - DAY_IN_SECONDS );
$tomorrow = gmdate( 'Y-m-d', time() + DAY_IN_SECONDS );
$releases = [
	release_php( '8.5', $tomorrow, $tomorrow ),
	release_php( '8.4', $today, $tomorrow ),
	release_php( '8.3', $yesterday, $today ),
	release_php( '8.2', $yesterday, $yesterday ),
	release_php( '8.1', $yesterday, $yesterday ),
];
$valid_response = [ 'status' => 200, 'body' => json_encode( $releases ) ];
respond_php( $valid_response );
$GLOBALS['transients']['stuh_php_lifecycle_v1'] = [ 'releases' => [], 'error' => 'Old 24-hour cache' ];

$active = invoke_php( 'php_version_safety', '8.5.1', '7.0' );
expect_php( 'current' === $active['status'], 'Actively supported and compatible PHP is normal' );
expect_php( false !== strpos( $active['title'], $tomorrow ), 'Active tooltip includes support dates' );
expect_php( false !== strpos( $active['title'], 'locally configured' ), 'Tooltip identifies the local compatibility check' );
expect_php( false !== strpos( $active['title'], 'table checked 2026-10-21' ), 'Tooltip identifies when the local table was verified' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.1', '7.1' )['status'], 'WordPress 7.1 supports current PHP 8.5' );
expect_php( 'outdated' === invoke_php( 'php_version_safety', '8.1.1', '7.1' )['status'], 'Compatible but end-of-life PHP stays red under the live lifecycle check' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.4.1', '7.0' )['status'], 'Active support lasts through its final UTC date' );
$security = invoke_php( 'php_version_safety', '8.3.1', '6.8' );
expect_php( 'warning' === $security['status'], 'Security-only PHP is orange, including its final support date' );
expect_php( false !== strpos( $security['title'], 'security fixes only' ), 'Orange tooltip explains security-only support' );
expect_php( 'outdated' === invoke_php( 'php_version_safety', '8.2.0', '7.0' )['status'], 'EOL PHP is red even within the local compatibility range' );
$incompatible = invoke_php( 'php_version_safety', '8.5.1', '6.8' );
expect_php( 'outdated' === $incompatible['status'], 'Local incompatibility takes priority over active support' );
expect_php( false !== strpos( $incompatible['title'], 'outside' ), 'Red tooltip explains the local compatibility problem' );
$unknown_wp = invoke_php( 'php_version_safety', '8.1.0', '99.0' );
expect_php( 'outdated' === $unknown_wp['status'], 'EOL PHP is red even for an unknown WordPress version' );
expect_php( false !== strpos( $unknown_wp['title'], 'could not be verified' ), 'Unknown WordPress compatibility is explicit' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.1-ubuntu', '7.0' )['status'], 'Accept distribution version suffixes' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.1+vendor', '7.0' )['status'], 'Ignore vendor build suffixes for patch comparisons' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.2', '7.0' )['status'], 'Do not flag versions ahead of the catalogue' );
$behind = invoke_php( 'php_version_safety', '8.5.0-ubuntu', '7.0' );
expect_php( 'warning' === $behind['status'], 'An old patch on an active branch is orange' );
expect_php( false !== strpos( $behind['title'], 'installed 8.5.0-ubuntu; latest in this branch is 8.5.1' ), 'Patch tooltip includes installed and latest versions' );
expect_php( 'warning' === invoke_php( 'php_version_safety', '8.3.0', '6.8' )['status'], 'Patch lag on a security-only branch stays orange' );
$eol_behind = invoke_php( 'php_version_safety', '8.2.0', '7.0' );
expect_php( 'outdated' === $eol_behind['status'] && false !== strpos( $eol_behind['title'], 'patch update available' ), 'EOL red takes priority while retaining the patch explanation' );
expect_php( 'outdated' === invoke_php( 'php_version_safety', '8.5.0', '6.8' )['status'], 'WordPress range red takes priority over patch warnings' );
$branch_only = invoke_php( 'php_version_safety', '8.5', '7.0' );
expect_php( 'current' === $branch_only['status'] && false !== strpos( $branch_only['title'], 'no patch version was reported' ), 'Branch-only reports do not invent a patch version' );
expect_php( 'unknown' === invoke_php( 'php_version_safety', '99.0.0', '99.0' )['status'], 'Unknown PHP branches are not assumed supported' );
expect_php( 'unknown' === invoke_php( 'php_version_safety', '', '7.0' )['status'], 'Missing PHP versions are unknown' );
expect_php( 'unknown' === invoke_php( 'php_version_safety', 'invalid', '7.0' )['status'], 'Malformed PHP versions are unknown' );
expect_php( 1 === $GLOBALS['requests'], 'One catalogue request serves all PHP and WordPress versions' );
expect_php( HOUR_IN_SECONDS === $GLOBALS['ttls']['stuh_php_lifecycle_v2'], 'Successful catalogues are cached for exactly one hour' );

$new_releases = $releases;
$new_releases[0]['latest'] = '8.5.10';
$GLOBALS['response']['body'] = json_encode( $new_releases );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.9', '7.0' )['status'], 'Reuse cached data before expiration' );
unset( $GLOBALS['transients']['stuh_php_lifecycle_v2'] );
expect_php( 'warning' === invoke_php( 'php_version_safety', '8.5.9', '7.0' )['status'], 'Refetch after expiration and compare multi-digit patch versions numerically' );
expect_php( 'current' === invoke_php( 'php_version_safety', '8.5.10', '7.0' )['status'], 'Latest patch in the branch is not flagged' );
expect_php( 2 === $GLOBALS['requests'], 'Only refetch when the shared cache expires' );

$future = release_php( '8.5', $tomorrow, $tomorrow );
$future['releaseDate'] = $tomorrow;
respond_php( [ 'status' => 200, 'body' => json_encode( [ $future ] ) ] );
expect_php( 'unknown' === invoke_php( 'php_version_safety', '8.5.0', '7.0' )['status'], 'Future releases are not assumed supported' );

$invalid_date = release_php( '8.5', '2026-02-30', $tomorrow );
$null_byte_date = release_php( '8.5', "2026-12-31\0", $tomorrow );
$inconsistent = release_php( '8.5', $tomorrow, $yesterday );
$invalid_latest = [];
foreach ( [ null, '', '8.5', '8.5.2RC1', '8.4.99', 80502 ] as $latest ) {
	$invalid_release = release_php( '8.5', $today, $tomorrow );
	$invalid_release['latest'] = $latest;
	$invalid_latest[] = [ 'status' => 200, 'body' => json_encode( [ $invalid_release ] ) ];
}
foreach ( [
	new WP_Error( 'timeout', 'Connection timed out' ),
	[ 'status' => 503, 'body' => '' ],
	[ 'status' => 200, 'body' => 'not JSON' ],
	[ 'status' => 200, 'body' => '[]' ],
	[ 'status' => 200, 'body' => '{"error":"unavailable"}' ],
	[ 'status' => 200, 'body' => json_encode( [ $invalid_date ] ) ],
	[ 'status' => 200, 'body' => json_encode( [ $null_byte_date ] ) ],
	[ 'status' => 200, 'body' => json_encode( [ $inconsistent ] ) ],
	[ 'status' => 200, 'body' => json_encode( [ release_php( '8.5', $today, $tomorrow ), [ 'cycle' => '8.4' ] ] ) ],
	...$invalid_latest,
] as $response ) {
	respond_php( $response );
	$failed = invoke_php( 'php_version_safety', '8.5.1', '7.0' );
	expect_php( 'unknown' === $failed['status'], 'Failed checks never claim active support' );
	expect_php( false !== strpos( $failed['title'], 'Could not verify PHP lifecycle status:' ), 'Failures appear in the tooltip' );
	expect_php( [] === invoke_php( 'php_lifecycle_data' )['releases'], 'Invalid catalogues never provide partial success' );
	expect_php( 'outdated' === invoke_php( 'php_version_safety', '8.5.1', '6.8' )['status'], 'Local compatibility errors stay red during service failures' );
	expect_php( 1 === $GLOBALS['requests'], 'Failures are shared and cached across sites' );
	expect_php( 15 * MINUTE_IN_SECONDS === $GLOBALS['ttls']['stuh_php_lifecycle_v2'], 'Failures retry after 15 minutes' );
}

respond_php( $valid_response );
invoke_php( 'php_version_safety', 'invalid', '7.0' );
expect_php( 0 === $GLOBALS['requests'], 'Invalid versions do not trigger HTTP requests' );

echo "All PHP support checks passed.\n";
