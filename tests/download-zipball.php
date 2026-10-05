<?php
/**
 * Standalone download regression checks: php tests/download-zipball.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );

class WP_Error {
	private $code;
	private $message;
	public function __construct( $code, $message ) {
		$this->code = $code;
		$this->message = $message;
	}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}
class WP_REST_Request {
	private $params;
	public function __construct( array $params ) { $this->params = $params; }
	public function get_param( $key ) { return $this->params[ $key ] ?? null; }
}
class Download_Response extends RuntimeException {
	public $data;
	public $status;
	public function __construct( $data, $status ) {
		parent::__construct( 'Download error response' );
		$this->data = $data;
		$this->status = $status;
	}
}
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function register_activation_hook( ...$args ) {}
function plugin_basename( $file ) { return basename( $file ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_option( $key, $default = false ) { return $default; }
function wp_parse_args( $args, $defaults = [] ) { return array_merge( $defaults, $args ); }
function get_temp_dir() { return $GLOBALS['download_root'] . '/'; }
function wp_mkdir_p( $path ) {
	return empty( $GLOBALS['mkdir_fail'] ) && ( is_dir( $path ) || mkdir( $path, 0755, true ) );
}
function wp_remote_get( $url, $args ) {
	$GLOBALS['download_url'] = $url;
	$response = $GLOBALS['download_response'];
	if ( ! is_wp_error( $response ) ) {
		file_put_contents( $args['filename'], $GLOBALS['download_body'] );
	}
	return $response;
}
function wp_remote_retrieve_response_code( $response ) { return $response['response']['code']; }
function wp_send_json_error( $data, $status ) { throw new Download_Response( $data, $status ); }

require dirname( __DIR__ ) . '/switch-theme-updater-host.php';

function expect_download( bool $condition, string $message ): void {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}
function expect_download_error( $result, string $code ): void {
	expect_download( is_wp_error( $result ) && $code === $result->get_error_code(), 'Return WP_Error: ' . $code );
	expect_download( [] === glob( get_temp_dir() . 'stuh-*' ), 'Clean up failed download workspace' );
}
function zip_fixture( array $files ): string {
	$file = get_temp_dir() . 'fixture.zip';
	$zip = new ZipArchive();
	expect_download( true === $zip->open( $file, ZipArchive::CREATE | ZipArchive::OVERWRITE ), 'Create ZIP fixture' );
	foreach ( $files as $path => $content ) {
		expect_download( $zip->addFromString( $path, $content ), 'Add ZIP fixture entry' );
	}
	expect_download( $zip->close(), 'Save ZIP fixture' );
	$body = file_get_contents( $file );
	unlink( $file );
	return $body;
}

expect_download( class_exists( 'ZipArchive' ), 'Download tests require ZipArchive' );
$GLOBALS['download_root'] = sys_get_temp_dir() . '/stuh-download-test-' . uniqid();
expect_download( mkdir( $GLOBALS['download_root'], 0755 ), 'Create isolated test directory' );
$client = new STUH_GitHubClient( '', 'https://api.github.com' );

try {
	$GLOBALS['mkdir_fail'] = true;
	expect_download_error( $client->download_zipball( 'owner/theme', 'v1' ), 'temp_dir' );
	$GLOBALS['mkdir_fail'] = false;

	$network_error = new WP_Error( 'http_request_failed', 'Connection timed out' );
	$GLOBALS['download_response'] = $network_error;
	$result = $client->download_zipball( 'owner/theme', 'v1' );
	expect_download( $network_error === $result, 'Preserve the original transport error' );
	expect_download_error( $result, 'http_request_failed' );

	$GLOBALS['download_response'] = [ 'response' => [ 'code' => 403 ] ];
	$GLOBALS['download_body'] = 'Forbidden';
	$result = $client->download_zipball( 'owner/theme', 'v1' );
	expect_download_error( $result, 'download_failed' );
	expect_download( 'GitHub returned HTTP 403' === $result->get_error_message(), 'Preserve HTTP failure details' );

	$GLOBALS['download_response']['response']['code'] = 200;
	$GLOBALS['download_body'] = '';
	expect_download_error( $client->download_zipball( 'owner/theme', 'v1' ), 'empty_zip' );
	$GLOBALS['download_body'] = 'Not a ZIP archive';
	expect_download_error( $client->download_zipball( 'owner/theme', 'v1' ), 'zip_open' );

	// A file blocking a nested directory makes real ZipArchive extraction fail.
	$GLOBALS['download_body'] = zip_fixture( [
		'github-root/blocked' => 'file',
		'github-root/blocked/style.css' => 'Version: 1.0',
	] );
	set_error_handler( function ( $severity, $message ) {
		if ( E_WARNING === $severity && str_contains( $message, 'ZipArchive::extractTo(' ) ) {
			return true;
		}
		return false;
	} );
	try {
		expect_download_error( $client->download_zipball( 'owner/theme', 'v1' ), 'zip_extract' );
		$plugin = new STUH_Plugin();
		try {
			$plugin->rest_download( new WP_REST_Request( [
				'repo' => 'owner/theme', 'ref' => 'v1', 'path' => '/', 'pack' => 'theme',
			] ) );
			throw new RuntimeException( 'Expected a REST error response' );
		} catch ( Download_Response $response ) {
			expect_download( 502 === $response->status, 'REST extraction failure returns HTTP 502' );
			expect_download( [ 'message' => 'Failed to extract zip' ] === $response->data, 'REST exposes the original extraction error' );
			expect_download( [] === glob( get_temp_dir() . 'stuh-*' ), 'REST failure cleans up its workspace' );
		}
	} finally {
		restore_error_handler();
	}

	$GLOBALS['download_body'] = zip_fixture( [ 'style.css' => 'Version: 1.0' ] );
	expect_download_error( $client->download_zipball( 'owner/theme', 'v1' ), 'no_folder' );
	$GLOBALS['download_body'] = zip_fixture( [ 'github-root/theme/style.css' => 'Version: 1.0' ] );
	expect_download_error( $client->download_zipball( 'owner/theme', 'v1', '/missing' ), 'path_not_found' );

	foreach ( [ '/' => 'theme/theme/style.css', '/theme' => 'theme/style.css' ] as $path => $entry ) {
		$result = $client->download_zipball( 'owner/theme', 'release/1', $path );
		expect_download( is_string( $result ) && is_file( $result ), 'Success returns a local ZIP path' );
		expect_download( 'https://api.github.com/repos/owner/theme/zipball/release%2F1' === $GLOBALS['download_url'], 'Encode the requested ref' );
		$zip = new ZipArchive();
		expect_download( true === $zip->open( $result ), 'Open repackaged ZIP' );
		expect_download( 'Version: 1.0' === $zip->getFromName( $entry ), 'Preserve content and package folder' );
		$zip->close();
		unlink( $result );
		rmdir( dirname( $result ) );
	}
	echo "Download regression checks passed.\n";
} finally {
	( new ReflectionMethod( STUH_GitHubClient::class, 'rrmdir' ) )->invoke( $client, $GLOBALS['download_root'] );
}
