<?php
/** Standalone release history checks: php tests/theme-releases.php */
define( 'ABSPATH', __DIR__ . '/' );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'HOUR_IN_SECONDS', 3600 );

class WP_Error {
	public function __construct( private string $code, private string $message ) {}
	public function get_error_message() { return $this->message; }
}
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function __( $text, $domain = '' ) { return $text; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function current_user_can( $capability ) { return in_array( $capability, $GLOBALS['capabilities'] ?? [ 'manage_options' ], true ); }
function get_option( $key, $default = false ) { return $default; }
function wp_parse_args( $args, $defaults = [] ) { return array_merge( $defaults, $args ); }
function get_transient( $key ) { return $GLOBALS['cache'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['cache'][ $key ] = $value; $GLOBALS['ttl'] = $ttl; }
function wp_remote_retrieve_response_code( $response ) { return 200; }
function wp_remote_retrieve_body( $response ) { return json_encode( $response ); }
function wp_remote_request( $url, $args ) {
	$GLOBALS['requests'][] = $url;
	if ( ! $GLOBALS['responses'] ) { throw new RuntimeException( 'Unexpected GitHub request' ); }
	return array_shift( $GLOBALS['responses'] );
}
require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

function expect_releases( bool $condition, string $message ): void {
	if ( ! $condition ) { throw new RuntimeException( $message ); }
}
$release = [ 'tag_name' => 'v1/test', 'published_at' => '2026-01-15T12:00:00Z', 'draft' => false ];
$GLOBALS['responses'] = [
	array_fill( 0, 100, $release ),
	[ array_merge( $release, [ 'draft' => true ] ), array_merge( $release, [ 'prerelease' => true ] ) ],
];
$history = STUH_Plugin::theme_release_history( 'owner/theme' );
expect_releases( 101 === count( $history ) && str_ends_with( $GLOBALS['requests'][1], 'page=2' ), 'Load later pages, skip drafts and include published prereleases' );
expect_releases( strtotime( $release['published_at'] ) === $history[0]['timestamp'] && str_ends_with( $history[0]['url'], 'v1%2Ftest' ), 'Use publication timestamps and encode tag links' );
expect_releases( $history === STUH_Plugin::theme_release_history( 'OWNER/THEME' ) && 2 === count( $GLOBALS['requests'] ) && 3600 === $GLOBALS['ttl'], 'Reuse repository history case-insensitively for an hour' );
$GLOBALS['responses'] = [ new WP_Error( 'http', 'Timed out' ) ];
$error = STUH_Plugin::theme_release_history( 'owner/offline' );
expect_releases( is_wp_error( $error ) && 'Timed out' === $error->get_error_message() && 300 === $GLOBALS['ttl'], 'Preserve API failures with a short cache' );
expect_releases( $error === STUH_Plugin::theme_release_history( 'owner/offline' ) && 3 === count( $GLOBALS['requests'] ), 'Do not repeatedly request a failing repository' );
$client = new STUH_GitHubClient( '', 'https://api.github.com' );
$GLOBALS['responses'] = [ array_fill( 0, 100, $release ), new WP_Error( 'http', 'Page two failed' ) ];
expect_releases( is_wp_error( $client->get_published_releases( 'owner/theme' ) ), 'Do not return partial history when later pages fail' );
foreach ( [ null, [ 'unexpected' => 'object' ], [ 'invalid release' ], [ array_merge( $release, [ 'published_at' => null ] ) ], [ array_merge( $release, [ 'published_at' => '2026-02-30T00:00:00Z' ] ) ] ] as $invalid ) {
	$GLOBALS['responses'] = [ $invalid ];
	expect_releases( is_wp_error( $client->get_published_releases( 'owner/theme' ) ), 'Malformed responses must not look like no releases' );
}
$GLOBALS['responses'] = [ [] ];
expect_releases( [] === $client->get_published_releases( 'owner/empty' ), 'An empty release history is valid' );
$request_count = count( $GLOBALS['requests'] );
expect_releases( is_wp_error( STUH_Plugin::theme_release_history( 'owner/theme/invalid' ) ), 'Reject invalid repositories before requesting GitHub' );
$GLOBALS['capabilities'] = [];
expect_releases( is_wp_error( STUH_Plugin::theme_release_history( 'owner/theme' ) ) && $request_count === count( $GLOBALS['requests'] ), 'Check permissions even for cached histories' );
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
expect_releases( $history === STUH_Plugin::theme_release_history( 'owner/theme' ), 'FMP editors can view cached releases' );
echo "Theme release checks passed.\n";
