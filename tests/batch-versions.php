<?php
/**
 * Standalone regression checks: php tests/batch-versions.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'STUH_CLONE_ARTIFACT_DIR', sys_get_temp_dir() );

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
	public function __construct( $method = 'GET' ) {}
	public function get_param( $name ) { return $this->params[ $name ] ?? null; }
	public function set_param( $name, $value ) { $this->params[ $name ] = $value; }
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
function get_option( $name, $default = [] ) { return $default; }
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
echo "Batch host regression checks passed.\n";
