<?php
/**
 * Standalone Gripp regression checks: php tests/gripp.php
 */
define( 'ABSPATH', __DIR__ . '/' );
define( 'MINUTE_IN_SECONDS', 60 );

class WP_Error {
	public function __construct( private string $code, private string $message ) {}
	public function get_error_code() { return $this->code; }
	public function get_error_message() { return $this->message; }
}
class GrippRedirect extends RuntimeException {}
class STUH_Plugin {
	public static function theme_release_history( string $repo ): array|WP_Error {
		$GLOBALS['release_requests'][] = $repo;
		return $GLOBALS['release_history'][ $repo ] ?? [];
	}
	public static function get_clients(): array { return $GLOBALS['clients'] ?? []; }
	public static function get_telemetry(): array { return $GLOBALS['telemetry'] ?? []; }
	public static function get_gravity_forms_report( string $client_id ): ?array { return self::get_telemetry()[ $client_id ]['gravity_forms'] ?? null; }
}
class STUH_Analytics {
	public static function monthly_active_users( string $client_id ) { return $GLOBALS['analytics_history'][ $client_id ] ?? new WP_Error( 'missing', 'No Analytics report.' ); }
}
function __( $text, $domain = '' ) { return $text; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_textarea( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_attr__( $text, $domain = '' ) { return esc_attr( $text ); }
function add_action( ...$args ) { $GLOBALS['hooks'][] = $args; }
function add_filter( ...$args ) { $GLOBALS['filters'][] = $args; }
function add_submenu_page( ...$args ) { $GLOBALS['menus'][] = $args; return 'updater-host_page_stuh-fmp'; }
function add_menu_page( ...$args ) { $GLOBALS['top_menus'][] = $args; return 'toplevel_page_stuh-fmp'; }
function get_current_screen() { return (object) [ 'id' => 'updater-host_page_stuh-fmp' ]; }
function get_hidden_columns( $screen ) { return $GLOBALS['hidden_columns'][ get_current_user_id() ] ?? []; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function current_user_can( $capability ) { return isset( $GLOBALS['capabilities'] ) ? in_array( $capability, $GLOBALS['capabilities'], true ) : ( $GLOBALS['authorized'] ?? true ); }
function get_current_user_id() { return $GLOBALS['user'] ?? 1; }
function get_user_option( $key ) { return $GLOBALS['user_options'][ get_current_user_id() ][ $key ] ?? false; }
function wp_die( $message, ...$args ) { throw new RuntimeException( $message ); }
function wp_unslash( $value ) { return $value; }
function wp_salt( $scheme ) { return $GLOBALS['salt'] ?? 'test-only-stable-authentication-salt'; }
function wp_json_encode( $value ) { return json_encode( $value ); }
function admin_url( $path ) { return 'https://host.example/wp-admin/' . $path; }
function get_plugin_page_hookname( $page, $parent ) { return 'updater-host_page_' . $page; }
function plugins_url( $path, $plugin ) { return 'https://host.example/wp-content/plugins/switch-theme-updater-host/' . $path; }
function wp_enqueue_style( ...$args ) { $GLOBALS['enqueued_styles'][] = $args; }
function wp_enqueue_script( ...$args ) { $GLOBALS['enqueued_scripts'][] = $args; }
function add_query_arg( array $args, string $url ) { return $url . '?' . http_build_query( $args ); }
function get_option( $key, $default = false ) { return $GLOBALS['options'][ $key ] ?? $default; }
function update_option( $key, $value, $autoload = null ) {
	if ( $GLOBALS['storage_fail'] ?? false ) { return false; }
	$GLOBALS['options'][ $key ] = $value;
	$GLOBALS['autoload'][ $key ] = $autoload;
	return true;
}
function delete_option( $key ) {
	if ( $GLOBALS['storage_fail'] ?? false ) { return false; }
	unset( $GLOBALS['options'][ $key ] );
	return true;
}
function get_transient( $key ) { return $GLOBALS['transients'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['transients'][ $key ] = $value; return true; }
function delete_transient( $key ) { unset( $GLOBALS['transients'][ $key ] ); return true; }
function wp_safe_redirect( $url ) { throw new GrippRedirect( $url ); }
function check_admin_referer( $action ) {
	if ( 'stuh_gripp' !== $action || 'valid' !== ( $_POST['_wpnonce'] ?? '' ) ) { wp_die( 'Invalid nonce' ); }
}
function wp_nonce_field( $action ) { echo '<input type="hidden" name="_wpnonce" value="valid">'; }
function submit_button( $label, ...$args ) { echo '<button>' . esc_html( $label ) . '</button>'; }
function wp_date( $format, $time, $timezone = null ) { return ( new DateTimeImmutable( '@' . $time ) )->setTimezone( $timezone ?? wp_timezone() )->format( $format ); }
function wp_timezone() { return new DateTimeZone( 'Europe/Amsterdam' ); }
function number_format_i18n( $value, $decimals = 0 ) { return number_format( $value, $decimals ); }
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return $response['body']; }
function wp_remote_post( $url, $args ) {
	$GLOBALS['requests'][] = [ $url, $args ];
	$method = json_decode( $args['body'], true )[0]['method'];
	if ( isset( $GLOBALS['entity_responses'][ $method ] ) ) {
		if ( ! $GLOBALS['entity_responses'][ $method ] ) { throw new RuntimeException( 'Unexpected ' . $method . ' request' ); }
		return array_shift( $GLOBALS['entity_responses'][ $method ] );
	}
	if ( 'project.get' === $method ) {
		return $GLOBALS['order_responses'] ? array_shift( $GLOBALS['order_responses'] ) : project_response( [] );
	}
	if ( in_array( $method, [ 'invoiceline.get', 'hour.get' ], true ) ) { return project_response( [] ); }
	if ( ! $GLOBALS['responses'] ) { throw new RuntimeException( 'Unexpected Gripp request' ); }
	return array_shift( $GLOBALS['responses'] );
}

require dirname( __DIR__ ) . '/includes/class-stuh-gripp.php';
set_error_handler( static function( $severity, $message, $file, $line ) {
	throw new ErrorException( $message, 0, $severity, $file, $line );
} );
$GLOBALS['requests'] = [];
$GLOBALS['responses'] = [];
$GLOBALS['order_responses'] = [];

function expect_gripp( bool $condition, string $message ): void {
	if ( ! $condition ) { throw new RuntimeException( $message ); }
}
function invoke_gripp( string $method, ...$args ) {
	return ( new ReflectionMethod( STUH_Gripp::class, $method ) )->invoke( null, ...$args );
}
function gripp_response( $data, int $status = 200 ): array {
	return [ 'status' => $status, 'body' => json_encode( $data ) ];
}
function project_response( array $rows, bool $more = false, ?int $next = null ): array {
	return gripp_response( [ [ 'id' => 1, 'error' => null, 'result' => [ 'rows' => $rows, 'more_items_in_collection' => $more, 'next_start' => $next ] ] ] );
}
function project_rows( int $start, int $count ): array {
	$rows = [];
	for ( $id = $start; $id < $start + $count; $id++ ) {
		$rows[] = [ 'id' => $id, 'number' => 1000 + $id, 'name' => 'Project ' . $id, 'startdate' => null, 'deadline' => '2026-12-01', 'archivedon' => 0 === $id % 2 ? '2026-11-01' : null, 'budget' => '6480.00' ];
	}
	return $rows;
}
function gripp_balance_cache( int $id = 1 ): array {
	return [
		'resource' => 'umbrellaproject-budget-hours-active-v4',
		'connection' => hash( 'sha256', get_option( 'stuh_gripp_connection', '' ) ),
		'id' => $id,
		'project' => [ 'budget' => 648000, 'startdate' => '2000-01-01', 'deadline' => '2000-12-31', 'used' => 0 ],
		'history' => [],
	];
}
function gripp_action( string $operation, array $fields = [] ): array {
	$_POST = array_merge( [ '_wpnonce' => 'valid', 'operation' => $operation ], $fields );
	try {
		STUH_Gripp::handle_action();
	} catch ( GrippRedirect $redirect ) {
		return [ $redirect->getMessage(), get_transient( 'stuh_gripp_notice_' . get_current_user_id() ) ];
	} finally {
		$_POST = [];
	}
	throw new RuntimeException( 'Expected Gripp redirect' );
}
function gripp_render( string $method, int $offset = 0, string $unit = 'eur', ?int $project_id = null, ?string $tab = null ): string {
	$_GET = [ 'offset' => (string) $offset, 'unit' => $unit ];
	if ( null !== $project_id ) {
		$_GET['project_id'] = (string) $project_id;
	}
	if ( null !== $tab ) {
		$_GET['project_tab'] = $tab;
	}
	ob_start();
	try {
		STUH_Gripp::$method();
		return ob_get_contents();
	} finally {
		ob_end_clean();
		$_GET = [];
	}
}

STUH_Gripp::init();
STUH_Gripp::register_menu();
STUH_Gripp::register_screen_options();
$_GET = [ 'project_id' => '1' ];
STUH_Gripp::enqueue_assets( 'updater-host_page_stuh-settings' );
$_GET = [];
STUH_Gripp::enqueue_assets( 'updater-host_page_stuh-fmp' );
expect_gripp( empty( $GLOBALS['enqueued_scripts'] ) && empty( $GLOBALS['enqueued_styles'] ), 'Do not load interactive chart assets on Settings or the FMP list' );
$_GET = [ 'project_id' => '1' ];
STUH_Gripp::enqueue_assets( 'updater-host_page_stuh-fmp' );
expect_gripp( 2 === count( $GLOBALS['enqueued_scripts'] ) && [ 'stuh-uplot' ] === $GLOBALS['enqueued_scripts'][1][2] && true === $GLOBALS['enqueued_scripts'][1][4] && str_contains( $GLOBALS['enqueued_scripts'][0][1], 'https://host.example/wp-content/plugins/' ) && 1 === count( $GLOBALS['enqueued_styles'] ), 'Load the locally hosted chart scripts only on the Overview tab' );
$_GET = [];
expect_gripp( in_array( [ 'load-updater-host_page_stuh-fmp', [ STUH_Gripp::class, 'register_screen_options' ] ], $GLOBALS['hooks'], true ) && in_array( [ 'manage_updater-host_page_stuh-fmp_columns', [ STUH_Gripp::class, 'columns' ] ], $GLOBALS['filters'], true ), 'Register native Screen Options columns only on the FMP screen load hook' );
expect_gripp( 'stuh-fmp' === $GLOBALS['menus'][0][4] && 'manage_options' === $GLOBALS['menus'][0][3], 'Register administrator-only FMP under Updater Host' );
expect_gripp( str_contains( gripp_render( 'render_dashboard' ), 'Connect Gripp' ) && ! $GLOBALS['requests'], 'Disconnected dashboard explains setup without API calls or dummy data' );

$GLOBALS['authorized'] = false;
foreach ( [ 'render_settings', 'render_dashboard', 'handle_action' ] as $method ) {
	try {
		STUH_Gripp::$method();
		throw new RuntimeException( 'Unauthorized access succeeded' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Gripp pages and actions require administrator access' );
	}
}
$GLOBALS['authorized'] = true;
try {
	gripp_action( 'connect', [ '_wpnonce' => 'invalid' ] );
	throw new RuntimeException( 'Invalid nonce accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Invalid nonce' === $error->getMessage(), 'Connection actions require a nonce' );
}
foreach ( [ '', "bad\r\ntoken" ] as $token ) {
	[ , $notice ] = gripp_action( 'connect', [ 'api_token' => $token ] );
	expect_gripp( $notice['error'] && ! $GLOBALS['requests'], 'Reject missing or unsafe tokens without sending a request' );
}

$first = project_rows( 1, 250 );
$first[0]['name'] = '<script>alert("project")</script>';
$first[0]['startdate'] = [ 'date' => '2026-11-18 00:00:00.000000', 'timezone_type' => 3, 'timezone' => 'Europe/Amsterdam' ];
$first[0]['deadline'] = [ 'date' => '2026-12-01 00:00:00.000000', 'timezone_type' => 3, 'timezone' => 'Europe/Amsterdam' ];
$first[0]['archivedon'] = [ 'date' => '2026-11-19 00:00:00.000000', 'timezone_type' => 3, 'timezone' => 'Europe/Amsterdam' ];
$first[0]['archived'] = false;
$first[1]['archivedon'] = $first[0]['archivedon'];
unset( $first[1]['archived'] );
$first[2]['startdate'] = [ 'date' => '-0001-11-30 00:00:00.000000', 'timezone_type' => 3, 'timezone' => 'Europe/Amsterdam' ];
$first[2]['archivedon'] = $first[2]['startdate'];
unset( $first[2]['archived'] );
$GLOBALS['responses'][] = project_response( $first, true, 250 );
$GLOBALS['order_responses'][] = project_response( [
	[ 'id' => 9001, 'umbrellaproject' => [ 'id' => 1, 'searchname' => 'Retainer' ], 'totalexclvat' => '120.00', 'archived' => false ],
	[ 'id' => 9002, 'umbrellaproject' => [ 'id' => 1, 'searchname' => 'Retainer' ], 'totalexclvat' => '30.50', 'archived' => true ],
] );
[ $url, $notice ] = gripp_action( 'connect', [ 'api_token' => 'test-gripp-token' ] );
expect_gripp( ! $notice['error'] && str_contains( $url, 'page=stuh-settings#stuh-gripp-settings' ), 'Successful connection returns to Settings' );
$stored = get_option( 'stuh_gripp_connection' );
expect_gripp( ! str_contains( $stored, 'test-gripp-token' ) && 'test-gripp-token' === invoke_gripp( 'connection' ), 'Token is encrypted and decrypts correctly' );
expect_gripp( false === $GLOBALS['autoload']['stuh_gripp_connection'], 'Credentials must not autoload' );
[ $endpoint, $args ] = $GLOBALS['requests'][0];
$rpc = json_decode( $args['body'], true )[0];
expect_gripp( 'https://api.gripp.com/public/api3.php' === $endpoint && 0 === $args['redirection'] && 'Bearer test-gripp-token' === $args['headers']['Authorization'], 'Send credentials only to the fixed HTTPS endpoint without redirects' );
expect_gripp( 'umbrellaproject.get' === $rpc['method'] && [] === $rpc['params'][0] && [ 'firstresult' => 0, 'maxresults' => 250 ] === $rpc['params'][1]['paging'], 'Request Projecten / Retainers rather than ordinary orders, without archive filters' );
expect_gripp( [ [ 'field' => 'umbrellaproject.id', 'direction' => 'asc' ] ] === $rpc['params'][1]['orderings'], 'Use stable umbrella project ID ordering across pages' );
$html = gripp_render( 'render_dashboard' );
expect_gripp( 3 === count( $GLOBALS['requests'] ) && str_contains( $html, 'offset=250' ) && ! str_contains( $html, 'Previous projects' ), 'First dashboard page uses the connection, order and recorded-time cache and offers next-page navigation' );
expect_gripp( str_contains( $html, '&lt;script&gt;' ) && ! str_contains( $html, '<script>' ) && ! str_contains( $html, 'test-gripp-token' ), 'Escape project content and never render the token' );
expect_gripp( str_contains( $html, '<td class="column-startdate">2026-11-18</td><td class="column-deadline">2026-12-01</td>' ) && ! str_contains( $html, '00:00:00' ), 'Render Gripp date objects as calendar dates without shifting their timezone' );
$cached_rows = get_transient( 'stuh_gripp_projects' )['data']['rows'];
expect_gripp( '2026-11-19' === $cached_rows[0]['archivedon'] && false === $cached_rows[0]['archived'] && true === $cached_rows[1]['archived'], 'Normalize archived dates while respecting explicit archive status and supporting its date fallback' );
expect_gripp( '' === $cached_rows[2]['startdate'] && '' === $cached_rows[2]['archivedon'] && false === $cached_rows[2]['archived'], 'Gripp zero-date objects represent unset dates and do not imply an archived project' );
expect_gripp( 648000 === $cached_rows[0]['budget'] && 15050 === $cached_rows[0]['used'] && 0 === $cached_rows[1]['used'], 'Preserve budget and aggregate all linked order values excluding VAT in cents, including archived orders' );
expect_gripp( str_contains( $html, '6,329.50' ) && str_contains( $html, 'Set both the start date and deadline' ), 'Render remaining budget and explicitly identify dates missing for monthly calculations' );
$original_cache = get_transient( 'stuh_gripp_projects' );
$today = new DateTimeImmutable( 'today', wp_timezone() );
$planned = (int) round( 31000 * (int) $today->format( 'j' ) / (int) $today->format( 't' ) );
$color_rows = [];
foreach ( [ 100, -100, 0, null ] as $balance ) {
	$color_rows[] = array_merge( $cached_rows[0], [
		'budget' => 31000,
		'used' => $planned - ( $balance ?? 0 ),
		'startdate' => $today->format( 'Y-m-01' ),
		'deadline' => null === $balance ? '' : $today->format( 'Y-m-t' ),
	] );
}
$color_cache = $original_cache;
$color_cache['data']['rows'] = $color_rows;
$GLOBALS['transients']['stuh_gripp_projects'] = $color_cache;
$color_html = gripp_render( 'render_dashboard' );
preg_match_all( '/<td class="[^"]*\bstuh-budget-left-to-date\b[^"]*"([^>]*)>([^<]*)<\/td>/', $color_html, $balance_cells, PREG_SET_ORDER );
expect_gripp( 4 === count( $balance_cells ) && str_contains( $balance_cells[0][1], 'color:#008a20' ) && "\u{20AC}1.00" === $balance_cells[0][2], 'Positive allowance minus used budget is displayed in green' );
expect_gripp( str_contains( $balance_cells[1][1], 'color:#b32d2e' ) && "\u{20AC}-1.00" === $balance_cells[1][2], 'Negative allowance minus used budget is displayed in red, even when total project budget remains positive' );
expect_gripp( '' === $balance_cells[2][1] && "\u{20AC}0.00" === $balance_cells[2][2] && '' === $balance_cells[3][1] && 'Unavailable' === $balance_cells[3][2], 'Zero and unavailable balances remain neutral' );
$group_rows = [];
foreach ( [
	[ 'name' => 'Current due today', 'deadline' => $today->format( 'Y-m-d' ) ],
	[ 'name' => 'Current future deadline', 'deadline' => $today->modify( '+1 day' )->format( 'Y-m-d' ) ],
	[ 'name' => 'Current missing deadline', 'deadline' => '' ],
	[ 'name' => 'Finished over budget', 'deadline' => $today->modify( '-1 day' )->format( 'Y-m-d' ), 'used' => 999999 ],
	[ 'name' => 'Finished missing budget', 'deadline' => $today->modify( '-1 day' )->format( 'Y-m-d' ), 'budget' => null, 'startdate' => '', 'number' => '' ],
] as $fields ) {
	$group_rows[] = array_merge( $color_rows[0], $fields );
}
$group_cache = $original_cache;
$group_cache['data']['rows'] = $group_rows;
$GLOBALS['transients']['stuh_gripp_projects'] = $group_cache;
$group_html = gripp_render( 'render_dashboard' );
preg_match( '/<table id="stuh-fmp-current".*?<\/table>/s', $group_html, $current_table );
preg_match( '/<table id="stuh-fmp-past".*?<\/table>/s', $group_html, $past_table );
expect_gripp( isset( $current_table[0], $past_table[0] ), 'Render separate current and past-deadline tables' );
foreach ( [ [ $current_table[0], 1001, 1 ], [ $past_table[0], 1001, 1 ], [ $html, 1002, 2 ] ] as [ $table, $number, $record_id ] ) {
	expect_gripp( 1 === preg_match( '/<a href="([^"]+)" target="_blank" rel="noopener noreferrer">' . $number . '<\/a>/', $table, $link ), 'Project numbers link to Gripp in a safe new tab in both tables' );
	$url = html_entity_decode( $link[1], ENT_QUOTES, 'UTF-8' );
	$state = json_decode( base64_decode( parse_url( $url, PHP_URL_FRAGMENT ), true ), true );
	expect_gripp( 'switch.gripp.com' === parse_url( $url, PHP_URL_HOST ) && '/public/index.php' === parse_url( $url, PHP_URL_PATH ) && 'u=98237' === parse_url( $url, PHP_URL_QUERY ), 'Use the actual Gripp application entry point from the supplied working URL' );
	expect_gripp( 'viewSubpage' === $state['action'] && 'n67051n' === $state['actionparams']['re_'] && $record_id === $state['actionparams']['sn_']['n67047n']['recordid'] && 'view' === $state['actionparams']['sn_']['n67047n']['o_'], 'Encoded navigation targets the umbrella record ID, including record 2 for project 1002' );
}
expect_gripp( str_contains( $past_table[0], '<td class="column-number">-</td>' ), 'Projects without a display number keep an unlinked placeholder' );
foreach ( [ $current_table[0], $past_table[0] ] as $table ) {
	expect_gripp( 1 === preg_match( '/class="column-project"><a href="([^"]+)">/', $table, $title_link ), 'Project titles open an internal FMP details screen in both tables' );
	parse_str( parse_url( html_entity_decode( $title_link[1], ENT_QUOTES, 'UTF-8' ), PHP_URL_QUERY ), $query );
	expect_gripp( 'stuh-fmp' === $query['page'] && '1' === $query['project_id'] && '0' === $query['offset'] && 'eur' === $query['unit'], 'Project detail links retain the internal ID, list page and selected unit' );
}
foreach ( $group_rows as $index => $project ) {
	$expected_table = $index < 3 ? $current_table[0] : $past_table[0];
	$other_table = $index < 3 ? $past_table[0] : $current_table[0];
	expect_gripp( str_contains( $expected_table, $project['name'] ) && ! str_contains( $other_table, $project['name'] ), 'Partition each project exactly once by its deadline, independently of budget status or missing schedule inputs' );
}
expect_gripp( str_contains( $past_table[0], 'Over budget' ) && str_contains( $past_table[0], 'stuh-budget-left-to-date' ), 'Past-deadline projects retain their financial status and budget balance display' );
$unit_cache = $original_cache;
$unit_rows = [];
foreach ( [ $today, $today->modify( '-1 year' ) ] as $year_date ) {
	$unit_rows[] = array_merge( $cached_rows[0], [
		'budget' => 648000,
		'used' => 9000,
		'startdate' => $year_date->format( 'Y-01-01' ),
		'deadline' => $year_date->format( 'Y-12-31' ),
	] );
}
$unit_cache['data']['rows'] = $unit_rows;
$GLOBALS['transients']['stuh_gripp_projects'] = $unit_cache;
$requests_before_toggle = count( $GLOBALS['requests'] );
$hours_html = gripp_render( 'render_dashboard', 0, 'hours' );
preg_match_all( '/<table id="stuh-fmp-(?:current|past)".*?<\/table>/s', $hours_html, $hours_tables );
foreach ( $hours_tables[0] as $table ) {
	expect_gripp( str_contains( $table, 'class="column-budget">72.00 h</td>' ) && str_contains( $table, '6.00 h / month (12.00 months)' ) && str_contains( $table, 'class="column-used">1.00 h</td>' ) && str_contains( $table, 'class="column-remaining">71.00 h</td>' ), 'Convert total, monthly, used and remaining budgets at EUR 90 per hour in both tables' );
	expect_gripp( ! str_contains( $table, "\u{20AC}" ) && preg_match( '/class="column-planned">-?[\d,.]+ h<\/td>/', $table ) && preg_match( '/class="column-left_to_date stuh-budget-left-to-date"[^>]*>-?[\d,.]+ h<\/td>/', $table ), 'Allowance and balance to date also use hours, without altering the balance color hook' );
}
expect_gripp( ! str_contains( $hours_html, 'Display budgets in' ) && str_contains( $hours_html, 'name="unit" value="hours">' ) && str_contains( $hours_html, 'offset=250&amp;unit=hours' ), 'Unit controls are removed from the dashboard body, while refresh and next-page links retain the unit' );
$_GET = [ 'unit' => 'hours' ];
$screen_settings = STUH_Gripp::render_screen_settings( '<p>Existing screen settings</p>' );
$_GET = [];
expect_gripp( str_contains( $screen_settings, '<p>Existing screen settings</p>' ) && str_contains( $screen_settings, 'name="wp_screen_options[option]" value="stuh_fmp_unit"' ) && str_contains( $screen_settings, 'name="wp_screen_options[value]" value="hours" checked' ) && str_contains( $screen_settings, 'screen-options-apply' ) && ! str_contains( $screen_settings, '<form' ), 'Render the selected unit and Apply button inside the existing native Screen Options form without nesting another form' );
expect_gripp( in_array( [ 'screen_settings', [ STUH_Gripp::class, 'render_screen_settings' ] ], $GLOBALS['filters'], true ) && in_array( [ 'set_screen_option_stuh_fmp_unit', [ STUH_Gripp::class, 'save_display_unit' ], 10, 3 ], $GLOBALS['filters'], true ), 'Register native screen rendering and the early per-user persistence filter' );
$GLOBALS['user_options'][1]['stuh_fmp_unit'] = STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', 'hours' );
$saved_hours_html = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $saved_hours_html, 'class="column-budget">72.00 h</td>' ), 'Saved screen preference applies on later visits and overrides stale euro URLs' );
$GLOBALS['user'] = 2;
expect_gripp( str_contains( gripp_render( 'render_dashboard' ), 'class="column-budget">' . "\u{20AC}6,480.00</td>" ), 'A different administrator keeps their own default unit' );
$GLOBALS['user'] = 1;
$GLOBALS['user_options'][1]['stuh_fmp_unit'] = STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', 'eur' );
expect_gripp( str_contains( gripp_render( 'render_dashboard', 0, 'hours' ), 'class="column-budget">' . "\u{20AC}6,480.00</td>" ), 'Saving Euros takes precedence over an older hours URL' );
unset( $GLOBALS['user_options'] );
foreach ( [ 'unsupported-unit', [ 'hours' ] ] as $invalid_unit ) {
	try {
		STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', $invalid_unit );
		throw new RuntimeException( 'Invalid display unit saved' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Invalid budget display unit.' === $error->getMessage(), 'Invalid screen option values are explicitly rejected' );
	}
}
$GLOBALS['authorized'] = false;
try {
	STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', 'hours' );
	throw new RuntimeException( 'Unauthorized preference save succeeded' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Saving the display unit requires administrator access' );
}
$GLOBALS['authorized'] = true;
$euros_html = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $euros_html, 'class="column-budget">' . "\u{20AC}6,480.00</td>" ) && count( $GLOBALS['requests'] ) === $requests_before_toggle && $unit_cache === get_transient( 'stuh_gripp_projects' ), 'Switching back to euros restores original figures without extra API calls or converted cache values' );
$negative_hours = array_merge( $unit_rows[0], [ 'used' => 657000 ] );
$unit_cache['data']['rows'] = [ $negative_hours, array_merge( $unit_rows[1], [ 'budget' => null ] ) ];
$GLOBALS['transients']['stuh_gripp_projects'] = $unit_cache;
$negative_hours_html = gripp_render( 'render_dashboard', 0, 'hours' );
expect_gripp( str_contains( $negative_hours_html, 'class="column-remaining">-1.00 h</td>' ) && str_contains( $negative_hours_html, 'color:#b32d2e' ) && str_contains( $negative_hours_html, 'Over budget' ) && str_contains( $negative_hours_html, 'Not set' ), 'Hours preserve negative balances, over-budget warnings and missing-budget states' );
$GLOBALS['transients']['stuh_gripp_projects'] = $group_cache;
$GLOBALS['hidden_columns'][1] = [ 'budget', 'left_to_date' ];
$hidden_html = gripp_render( 'render_dashboard' );
preg_match_all( '/<table id="stuh-fmp-(?:current|past)".*?<\/table>/s', $hidden_html, $hidden_tables );
foreach ( $hidden_tables[0] as $table ) {
	expect_gripp( str_contains( $table, 'class="manage-column column-budget hidden"' ) && str_contains( $table, 'class="column-budget hidden"' ) && str_contains( $table, 'class="column-left_to_date hidden stuh-budget-left-to-date"' ), 'Apply saved hidden preferences to headers and cells in both tables without removing values or budget colors' );
	expect_gripp( str_contains( $table, 'class="manage-column column-project"' ) && str_contains( $table, 'class="column-project"' ), 'Columns not hidden remain visible' );
}
expect_gripp( 1 === substr_count( $hidden_html, ' id="budget"' ), 'Only the current table supplies native preference column IDs, preventing duplicate IDs and saved keys' );
$GLOBALS['user'] = 2;
$other_user_html = gripp_render( 'render_dashboard' );
expect_gripp( ! str_contains( $other_user_html, 'column-budget hidden' ), 'Column preferences are read for the current administrator, not shared across users' );
$GLOBALS['user'] = 1;
$group_cache['data']['rows'] = [];
$GLOBALS['transients']['stuh_gripp_projects'] = $group_cache;
$empty_group_html = gripp_render( 'render_dashboard' );
expect_gripp( 2 === substr_count( $empty_group_html, 'No projects found on this page.' ), 'Both project tables have an explicit empty state' );
expect_gripp( 2 === substr_count( $empty_group_html, 'class="colspanchange" colspan="12"' ), 'Empty rows span the visible columns in both tables and support native live colspan updates' );
unset( $GLOBALS['hidden_columns'] );
$GLOBALS['transients']['stuh_gripp_projects'] = $original_cache;
$settings = gripp_render( 'render_settings' );
expect_gripp( ! str_contains( $settings, 'test-gripp-token' ) && str_contains( $settings, 'value=""' ) && str_contains( $settings, 'Disconnect Gripp' ), 'Connected settings never prefill credentials and offer disconnect' );

$GLOBALS['responses'][] = project_response( project_rows( 251, 250 ), true, 500 );
$html = gripp_render( 'render_dashboard', 250 );
expect_gripp( str_contains( $html, 'Project 500' ) && str_contains( $html, 'Previous projects' ) && str_contains( $html, 'offset=500' ), 'Second page exposes later projects and both navigation directions' );
$umbrella_requests = array_values( array_filter( $GLOBALS['requests'], static fn( $request ) => 'umbrellaproject.get' === json_decode( $request[1]['body'], true )[0]['method'] ) );
expect_gripp( 250 === json_decode( $umbrella_requests[1][1]['body'], true )[0]['params'][1]['paging']['firstresult'], 'Fetch the requested API offset' );
$GLOBALS['responses'][] = project_response( project_rows( 501, 1 ) );
$html = gripp_render( 'render_dashboard', 500 );
expect_gripp( str_contains( $html, 'Project 501' ) && ! str_contains( $html, 'Next projects' ), 'Last page remains accessible beyond 500 projects and stops at the documented end' );
$GLOBALS['responses'][] = project_response( [] );
[ $url, $notice ] = gripp_action( 'refresh', [ 'offset' => '500', 'unit' => 'hours' ] );
expect_gripp( ! $notice['error'] && str_contains( $url, 'offset=500' ) && str_contains( $url, 'unit=hours' ) && str_contains( gripp_render( 'render_dashboard', 500 ), 'No projects found' ), 'Refresh retains the same page and selected unit, and valid empty responses have an explicit empty state' );
$GLOBALS['responses'][] = gripp_response( [], 503 );
[ $url, $notice ] = gripp_action( 'refresh', [ 'offset' => '500', 'unit' => 'hours' ] );
expect_gripp( $notice['error'] && str_contains( $url, 'offset=500' ) && str_contains( $url, 'unit=hours' ), 'Failed refreshes also retain the selected unit and page' );
try {
	gripp_render( 'render_dashboard', 0, 'unsupported-unit' );
	throw new RuntimeException( 'Invalid display unit accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Invalid budget display unit.' === $error->getMessage(), 'Reject unsupported display units explicitly' );
}

$GLOBALS['salt'] = 'changed-authentication-salt';
expect_gripp( is_wp_error( invoke_gripp( 'connection' ) ), 'Salt rotation fails explicitly instead of using an invalid credential' );
unset( $GLOBALS['salt'] );
$raw = base64_decode( $stored );
$raw[28] = chr( ord( $raw[28] ) ^ 1 );
$GLOBALS['options']['stuh_gripp_connection'] = base64_encode( $raw );
expect_gripp( is_wp_error( invoke_gripp( 'connection' ) ), 'Authenticated encryption rejects tampered tokens' );
$GLOBALS['options']['stuh_gripp_connection'] = $stored;

foreach ( [
	new WP_Error( 'network', 'Network unavailable' ),
	gripp_response( [], 401 ),
	gripp_response( [], 429 ),
	gripp_response( [ [ 'id' => 1, 'error' => 'Token rejected: do-not-echo-this' ] ] ),
	[ 'status' => 200, 'body' => '<html>not JSON</html>' ],
	gripp_response( [ [ 'id' => 1, 'result' => [] ] ] ),
	project_response( [ [ 'id' => 1, 'name' => [ 'invalid' ] ] ] ),
	project_response( [ [ 'id' => 1, 'name' => 'Invalid date', 'deadline' => [ 'date' => [ 'invalid' ] ] ] ] ),
	project_response( [ [ 'id' => 1, 'name' => 'Invalid date', 'startdate' => '2026-02-30' ] ] ),
	project_response( [ [ 'id' => 1, 'name' => 'Invalid budget', 'budget' => 'not-an-amount' ] ] ),
	project_response( [ [ 'id' => 1, 'name' => 'Invalid budget', 'budget' => '-1.00' ] ] ),
	project_response( project_rows( 1, 1 ), true, 0 ),
] as $failure ) {
	$GLOBALS['responses'][] = $failure;
	[ , $notice ] = gripp_action( 'connect', [ 'api_token' => 'replacement-token' ] );
	expect_gripp( $notice['error'] && $stored === get_option( 'stuh_gripp_connection' ), 'Connection failures preserve the working connection' );
	expect_gripp( ! str_contains( $notice['message'], 'do-not-echo-this' ), 'Do not expose raw API errors that could contain credentials' );
}
$GLOBALS['responses'][] = project_response( [ [ 'id' => 1, 'name' => 'Invalid date', 'deadline' => [ 'unexpected' => 'private-field-value' ] ] ] );
[ , $notice ] = gripp_action( 'connect', [ 'api_token' => 'replacement-token' ] );
expect_gripp( $notice['error'] && str_contains( $notice['message'], 'deadline' ) && ! str_contains( $notice['message'], 'private-field-value' ), 'Malformed date errors identify the field without exposing project data' );
$GLOBALS['responses'][] = gripp_response( [], 403 );
delete_transient( 'stuh_gripp_projects' );
$html = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $html, 'HTTP 403' ) && ! str_contains( $html, 'No projects found' ), 'API failures are not presented as empty or successful results' );
$GLOBALS['transients']['stuh_gripp_projects'] = [
	'connection' => hash( 'sha256', $stored ),
	'offset' => 0,
	'data' => [ 'rows' => [ [ 'name' => 'Obsolete ordinary order' ] ], 'more' => false, 'updated_at' => time() ],
];
$umbrella_rows = project_rows( 1, 2 );
$umbrella_rows[0]['name'] = 'Retainer example';
$umbrella_rows[0]['startdate'] = '2026-01-01';
$umbrella_rows[0]['deadline'] = '2026-12-31';
$umbrella_rows[1]['budget'] = null;
$GLOBALS['responses'][] = project_response( $umbrella_rows );
$GLOBALS['order_responses'][] = project_response( [ [ 'id' => 9001, 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => '7000.00', 'archived' => false ] ] );
$html = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $html, 'Retainer example' ) && ! str_contains( $html, 'Obsolete ordinary order' ), 'Existing ordinary-project cache is discarded without reconnecting' );
expect_gripp( str_contains( $html, 'Projecten / Retainers' ) && ! str_contains( $html, 'Retainers are not included yet' ), 'Dashboard identifies the correct Gripp list' );
expect_gripp( str_contains( $html, '540.00 / month (12.00 months)' ) && str_contains( $html, '-520.00' ) && str_contains( $html, 'Over budget' ), 'Render the required monthly amount and retain negative remaining budgets with an over-budget warning' );
expect_gripp( str_contains( $html, 'Set a budget in Gripp' ) && str_contains( $html, 'Not set' ), 'Missing budgets are visibly unavailable, never replaced with zero' );
foreach ( [ '-250', '1', 'invalid', '99999999999999999999999' ] as $offset ) {
	try {
		invoke_gripp( 'offset', [ 'offset' => $offset ] );
		throw new RuntimeException( 'Invalid pagination accepted' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Invalid project page.' === $error->getMessage(), 'Reject invalid or overflowing page offsets' );
	}
}

$GLOBALS['responses'][] = project_response( [] );
$GLOBALS['storage_fail'] = true;
[ , $notice ] = gripp_action( 'connect', [ 'api_token' => 'replacement-token' ] );
expect_gripp( $notice['error'] && $stored === get_option( 'stuh_gripp_connection' ), 'Connection storage failures are explicit and preserve previous credentials' );
[ , $notice ] = gripp_action( 'disconnect' );
expect_gripp( $notice['error'], 'Failed credential deletion cannot report a successful disconnect' );
$GLOBALS['storage_fail'] = false;
$GLOBALS['responses'][] = project_response( [] );
[ , $notice ] = gripp_action( 'connect', [ 'api_token' => 'replacement-token' ] );
expect_gripp( ! $notice['error'] && 'replacement-token' === invoke_gripp( 'connection' ), 'A verified replacement token can be saved' );
expect_gripp( str_contains( gripp_render( 'render_dashboard' ), 'No projects found' ), 'Empty accounts are valid connections without fabricated data' );
[ , $notice ] = gripp_action( 'disconnect' );
expect_gripp( ! $notice['error'] && false === get_option( 'stuh_gripp_connection' ) && false === get_transient( 'stuh_gripp_projects' ), 'Disconnect removes local credentials and cached projects' );
foreach ( $GLOBALS['requests'] as [ , $request ] ) {
	$rpc = json_decode( $request['body'], true )[0];
	if ( 'project.get' === $rpc['method'] ) {
		expect_gripp( 'project.umbrellaproject' === $rpc['params'][0][0]['field'] && 'in' === $rpc['params'][0][0]['operator'] && [] !== $rpc['params'][0][0]['value'], 'Only fetch ordinary orders linked to the displayed umbrella projects' );
	} elseif ( 'hour.get' === $rpc['method'] ) {
		expect_gripp( 'hour.offerprojectbase' === $rpc['params'][0][0]['field'] && [] !== $rpc['params'][0][0]['value'], 'Dashboard logged time is restricted to linked orders' );
	} else {
		expect_gripp( 'umbrellaproject.get' === $rpc['method'], 'Dashboard rows must come from umbrella projects only' );
	}
}

$order_page = array_map( static fn( $id ) => [ 'id' => $id, 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => '1.01' ], range( 1, 250 ) );
$GLOBALS['order_responses'] = [
	project_response( $order_page, true, 250 ),
	project_response( [
		[ 'id' => 251, 'umbrellaproject' => 1, 'totalexclvat' => '-2.50' ],
		[ 'id' => 252, 'umbrellaproject' => [ 'id' => 2 ], 'totalexclvat' => '10.05' ],
	] ),
];
expect_gripp( [ 1 => 25000, 2 => 1005 ] === invoke_gripp( 'order_totals', 'test-token', [ 1, 2 ] ), 'Follow every linked-order page, aggregate by parent and preserve decimal precision and credits' );
expect_gripp( 250 === json_decode( end( $GLOBALS['requests'] )[1]['body'], true )[0]['params'][1]['paging']['firstresult'], 'Linked orders use their own pagination offsets' );
foreach ( [
	project_response( [ [ 'umbrellaproject' => [ 'id' => 99 ], 'totalexclvat' => '1.00' ] ] ),
	project_response( [ [ 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => null ] ] ),
	gripp_response( [], 403 ),
] as $failure ) {
	$GLOBALS['order_responses'] = [ project_response( $order_page, true, 250 ), $failure ];
	expect_gripp( is_wp_error( invoke_gripp( 'order_totals', 'test-token', [ 1, 2 ] ) ), 'Invalid or failed later order pages cannot return a misleading partial or zero total' );
}

$year = [ 'budget' => 648000, 'used' => 324000, 'startdate' => '2026-01-01', 'deadline' => '2026-12-31' ];
$schedule = invoke_gripp( 'budget_schedule', $year, new DateTimeImmutable( '2026-06-30', wp_timezone() ) );
expect_gripp( 12.0 === $schedule['months'] && 54000 === $schedule['monthly'] && 324000 === $schedule['planned'] && 'On budget schedule' === $schedule['status'], 'EUR 6480 over twelve complete calendar months gives EUR 540 per month and EUR 3240 through June' );
foreach ( [ 324001 => 'Ahead of budget schedule', 323999 => 'Behind budget schedule', 648001 => 'Over budget' ] as $used => $status ) {
	$schedule = invoke_gripp( 'budget_schedule', array_merge( $year, [ 'used' => $used ] ), new DateTimeImmutable( '2026-06-30', wp_timezone() ) );
	expect_gripp( $status === $schedule['status'], 'Compare actual committed value with allowance in cents, retaining over-budget amounts' );
}
$partial = [ 'budget' => 45000, 'used' => 0, 'startdate' => '2026-04-16', 'deadline' => '2026-05-15' ];
$schedule = invoke_gripp( 'budget_schedule', $partial, new DateTimeImmutable( '2026-04-30', wp_timezone() ) );
$units = 15 / 30 + 15 / 31;
expect_gripp( abs( $schedule['months'] - $units ) < 0.000001 && (int) round( 45000 / $units ) === $schedule['monthly'] && (int) round( 45000 * ( 15 / 30 ) / $units ) === $schedule['planned'], 'Prorate first and last partial calendar months by their actual day counts' );
$leap = [ 'budget' => 29000, 'used' => 0, 'startdate' => '2028-02-01', 'deadline' => '2028-02-29' ];
$schedule = invoke_gripp( 'budget_schedule', $leap, new DateTimeImmutable( '2028-02-15', wp_timezone() ) );
expect_gripp( 1.0 === $schedule['months'] && 15000 === $schedule['planned'], 'Leap-year daily proration includes today and uses 29 days in February' );
foreach ( [ '2025-12-31' => 'Not started', '2027-01-01' => 'Past deadline' ] as $date => $status ) {
	$schedule = invoke_gripp( 'budget_schedule', array_merge( $year, [ 'used' => 0 ] ), new DateTimeImmutable( $date, wp_timezone() ) );
	expect_gripp( $status === $schedule['status'] && ( 'Not started' === $status ? 0 : 648000 ) === $schedule['planned'], 'Clamp allowance before the start and after the inclusive deadline' );
}
$schedule = invoke_gripp( 'budget_schedule', array_merge( $year, [ 'used' => 1 ] ), new DateTimeImmutable( '2025-12-31', wp_timezone() ) );
expect_gripp( 'Budget used before start' === $schedule['status'], 'Do not label pre-start commitments as an untouched future project' );
$single_day = [ 'budget' => 10000, 'used' => 10000, 'startdate' => '2026-04-15', 'deadline' => '2026-04-15' ];
$schedule = invoke_gripp( 'budget_schedule', $single_day, new DateTimeImmutable( '2026-04-15', wp_timezone() ) );
expect_gripp( 10000 === $schedule['planned'] && 'On budget schedule' === $schedule['status'], 'A same-day project includes its full allowance without division by zero' );
$schedule = invoke_gripp( 'budget_schedule', array_merge( $year, [ 'budget' => 0, 'used' => 0 ] ), new DateTimeImmutable( '2026-06-30', wp_timezone() ) );
expect_gripp( 0 === $schedule['monthly'] && 0 === $schedule['planned'], 'An explicitly zero budget is valid and distinct from a missing budget' );
foreach ( [ [ 'budget' => null ], [ 'startdate' => '' ], [ 'deadline' => '' ], [ 'deadline' => '2025-12-31' ] ] as $fields ) {
	expect_gripp( is_wp_error( invoke_gripp( 'budget_schedule', array_merge( $year, $fields ), new DateTimeImmutable( '2026-06-30', wp_timezone() ) ) ), 'Missing budgets and missing or reversed dates have explicit unavailable states' );
}

$annual_chart = invoke_gripp( 'budget_chart_data', $year );
expect_gripp( 13 === count( $annual_chart['points'] ) && 0 === $annual_chart['points'][0]['cumulative'] && 54000 === $annual_chart['points'][1]['cumulative'] && 648000 === $annual_chart['points'][12]['cumulative'], 'A twelve-month chart starts at zero, allocates EUR 540 after January, and ends at EUR 6480' );
expect_gripp( 648000 === array_sum( array_column( $annual_chart['points'], 'allocated' ) ) && [ '2026-01-31', '2026-02-28', '2026-03-31' ] === array_column( array_slice( $annual_chart['points'], 1, 3 ), 'date' ), 'Chart month endpoints and allocated amounts cover the complete budget without rounding drift' );
$partial_chart = invoke_gripp( 'budget_chart_data', $partial );
expect_gripp( 3 === count( $partial_chart['points'] ) && '2026-04-30' === $partial_chart['points'][1]['date'] && '2026-05-15' === $partial_chart['points'][2]['date'] && (int) round( 45000 * ( 15 / 30 ) / $units ) === $partial_chart['points'][1]['cumulative'] && 45000 === $partial_chart['points'][2]['cumulative'], 'Chart partial months use the same daily proration as the dashboard and finish at the exact deadline' );
$leap_chart = invoke_gripp( 'budget_chart_data', $leap );
expect_gripp( '2028-02-29' === $leap_chart['points'][1]['date'] && 29000 === $leap_chart['points'][1]['cumulative'], 'Leap-month chart endpoints retain February 29' );
$single_chart = invoke_gripp( 'budget_chart_data', $single_day );
expect_gripp( 2 === count( $single_chart['points'] ) && 10000 === $single_chart['points'][1]['cumulative'], 'Same-day projects still have a zero-to-full-budget chart' );

$GLOBALS['options']['stuh_gripp_connection'] = $stored;
$detail_project = array_merge( $cached_rows[0], $year, [ 'name' => 'Chart <retainer>' ] );
$detail_cache = $original_cache;
$detail_cache['offset'] = 250;
$detail_cache['data']['rows'] = [ $detail_project ];
$GLOBALS['transients']['stuh_gripp_projects'] = $detail_cache;
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache();
$detail_request_count = count( $GLOBALS['requests'] );
$detail_html = gripp_render( 'render_dashboard', 250, 'eur', 1 );
expect_gripp( str_contains( $detail_html, '<h1>Chart &lt;retainer&gt;</h1>' ) && ! str_contains( $detail_html, 'id="stuh-fmp-current"' ) && ! str_contains( $detail_html, 'id="stuh-fmp-active-projects"' ) && ! str_contains( $detail_html, 'id="stuh-fmp-export-preview"' ) && str_contains( $detail_html, 'offset=250&amp;unit=eur' ) && count( $GLOBALS['requests'] ) === $detail_request_count + 2, 'Overview reuses the cached project, loads only chart usage, escapes the title, and leaves monthly report data to its own tab' );
$xml_errors = libxml_use_internal_errors( true );
$chart_document = new DOMDocument();
$chart_document->loadHTML( $detail_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$chart_xpath = new DOMXPath( $chart_document );
$interactive_data = json_decode( $chart_xpath->query( '//figure[@data-stuh-fmp-chart]' )->item( 0 )->getAttribute( 'data-stuh-fmp-chart' ), true, 512, JSON_THROW_ON_ERROR );
expect_gripp( 5 === count( $interactive_data['series'] ) && 'bars' === $interactive_data['series'][4]['type'] && 13 === count( $interactive_data['series'][1]['points'] ) && [ 0, 54000, 648000 ] === [ $interactive_data['series'][1]['points'][0][1], $interactive_data['series'][1]['points'][1][1], $interactive_data['series'][1]['points'][12][1] ], 'Interactive series preserve exact accumulated allowances and all four existing lines alongside the monthly bars' );
expect_gripp( [ false, true, true, false, true ] === array_map( static fn( array $series ): bool => $series['show'] ?? true, $interactive_data['series'] ), 'Default interactive view shows allowance, actual time and monthly hours while retaining budget and invoice series as optional' );
expect_gripp( 1 === $chart_xpath->query( '//div[contains(@class,"stuh-fmp-chart-toolbar")]//button[@data-stuh-fmp-reset and @hidden]' )->length && 1 === $chart_xpath->query( '//ul[@data-stuh-fmp-static-legend and not(@hidden)]' )->length && ! str_contains( $detail_html, 'Drag horizontally across a period to zoom in.' ), 'Use compact zoom controls while preserving the visible static legend until JavaScript loads' );
expect_gripp( '2025-12-01 00:00:00' === gmdate( 'Y-m-d H:i:s', $interactive_data['series'][1]['points'][0][0] ) && '2026-12-01 00:00:00' === gmdate( 'Y-m-d H:i:s', $interactive_data['series'][1]['points'][12][0] ) && str_contains( $detail_html, 'data-stuh-fmp-reset disabled' ) && str_contains( $detail_html, 'data-stuh-fmp-static' ), 'Monthly points use canonical UTC months with a separate preceding baseline, offer reset, and retain the static fallback' );
$budget_line = $chart_xpath->query( '//line[@class="stuh-fmp-budget-limit"]' )->item( 0 );
$allowance_line = $chart_xpath->query( '//polyline[@class="stuh-fmp-budget-cumulative"]' )->item( 0 );
expect_gripp( null !== $budget_line && null !== $allowance_line && $budget_line->getAttribute( 'y1' ) === $budget_line->getAttribute( 'y2' ), 'Details contain a truly horizontal total budget line and a separate cumulative allowance polyline' );
$coordinates = array_map( static fn( $point ) => array_map( 'floatval', explode( ',', $point ) ), explode( ' ', $allowance_line->getAttribute( 'points' ) ) );
expect_gripp( 13 === count( $coordinates ) && 300.0 === $coordinates[0][1] && (float) $budget_line->getAttribute( 'y1' ) === $coordinates[12][1] && $coordinates[12][0] > $coordinates[0][0], 'The accumulated line starts at zero and rises across all months to meet the budget line' );
expect_gripp( str_contains( $detail_html, 'Jan 2026' ) && str_contains( $detail_html, 'Dec 2026' ) && str_contains( $detail_html, 'Budget (EUR)' ) && str_contains( $detail_html, 'Months' ) && str_contains( $detail_html, 'View monthly values' ) && str_contains( $detail_html, 'aria-labelledby="stuh-fmp-chart-title stuh-fmp-chart-desc"' ), 'Chart has month/year labels, budget and month axes, accessible descriptions and an exact monthly values table' );
$GLOBALS['user_options'][1]['stuh_fmp_unit'] = 'hours';
$detail_hours = gripp_render( 'render_dashboard', 250, 'eur', 1 );
expect_gripp( str_contains( $detail_hours, 'Budget (hours)' ) && str_contains( $detail_hours, '72.00 h' ) && str_contains( $detail_hours, '6.00 h' ) && str_contains( $detail_hours, 'offset=250&amp;unit=hours' ), 'Details summary, chart, monthly data and return navigation all respect the saved hours preference' );
unset( $GLOBALS['user_options'] );
foreach ( [ [ 'budget' => null ], [ 'startdate' => '' ], [ 'deadline' => '2025-12-31' ] ] as $fields ) {
	$detail_cache['data']['rows'] = [ array_merge( $detail_project, $fields ) ];
	$GLOBALS['transients']['stuh_gripp_projects'] = $detail_cache;
	$unavailable_detail = gripp_render( 'render_dashboard', 250, 'eur', 1 );
	expect_gripp( ! str_contains( $unavailable_detail, '<svg' ) && str_contains( $unavailable_detail, 'notice-warning' ), 'Missing or invalid chart inputs show an explicit notice without drawing fabricated data' );
}
$detail_cache['data']['rows'] = [ array_merge( $detail_project, [ 'budget' => 0, 'used' => 0 ] ) ];
$GLOBALS['transients']['stuh_gripp_projects'] = $detail_cache;
$zero_chart_html = gripp_render( 'render_dashboard', 250, 'eur', 1 );
expect_gripp( str_contains( $zero_chart_html, '<svg' ) && str_contains( $zero_chart_html, 'stuh-fmp-budget-cumulative' ) && ! str_contains( $zero_chart_html, 'NAN' ) && ! str_contains( $zero_chart_html, 'INF' ), 'A valid zero budget renders finite chart coordinates rather than failing or inventing a positive budget' );
$GLOBALS['authorized'] = false;
try {
	gripp_render( 'render_dashboard', 250, 'eur', 1 );
	throw new RuntimeException( 'Unauthorized detail access succeeded' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Project details require administrator access' );
}
$GLOBALS['authorized'] = true;
foreach ( [ '', '0', '-1', 'invalid', [ '1' ], '99999999999999999999999999' ] as $id ) {
	try {
		invoke_gripp( 'selected_project', [ 'project_id' => $id ] );
		throw new RuntimeException( 'Invalid detail ID accepted' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Invalid Gripp project ID.' === $error->getMessage(), 'Reject malformed and overflowing project IDs explicitly' );
	}
}
$fallback_project = array_merge( project_rows( 501, 1 )[0], [ 'name' => 'Project outside original page', 'startdate' => '2026-01-01' ] );
$GLOBALS['responses'][] = project_response( [ $fallback_project ] );
$requests_before_lookup = count( $GLOBALS['requests'] );
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache( 501 );
$fallback_html = gripp_render( 'render_dashboard', 250, 'eur', 501 );
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache();
$lookup = json_decode( $GLOBALS['requests'][ $requests_before_lookup ][1]['body'], true )[0];
expect_gripp( [ [ 'field' => 'umbrellaproject.id', 'operator' => 'equals', 'value' => 501 ] ] === $lookup['params'][0] && str_contains( $fallback_html, '<h1>Project outside original page</h1>' ), 'Bookmarked details find their exact project by ID even after it moves off the original list page' );
$GLOBALS['responses'][] = project_response( [] );
try {
	gripp_render( 'render_dashboard', 250, 'eur', 502 );
	throw new RuntimeException( 'Missing detail project accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Gripp project not found or no longer accessible.' === $error->getMessage(), 'Deleted or inaccessible projects have an explicit not-found response' );
}
$GLOBALS['responses'][] = gripp_response( [], 403 );
$failed_details = gripp_render( 'render_dashboard', 250, 'eur', 503 );
expect_gripp( str_contains( $failed_details, 'HTTP 403' ) && ! str_contains( $failed_details, '<svg' ), 'API access failures show an explicit error instead of a misleading project chart' );

$usage_orders = [
	[ 'id' => 41, 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => '0.00' ],
	[ 'id' => 42, 'umbrellaproject' => 1, 'totalexclvat' => '900.00' ],
];
$usage_hours = [
	[ 'id' => 51, 'offerprojectbase' => [ 'id' => 41 ], 'amount' => 2.125, 'date' => [ 'date' => '1999-12-20 00:00:00.000000' ], 'status' => [ 'id' => 1, 'searchname' => 'Concept' ] ],
	[ 'id' => 52, 'offerprojectbase' => 42, 'amount' => '1.5', 'date' => '2000-02-15' ],
	[ 'id' => 53, 'offerprojectbase' => 42, 'amount' => 100, 'date' => '3000-01-01' ],
	[ 'id' => 54, 'offerprojectbase' => 41, 'offerprojectline' => 81, 'amount' => 100, 'date' => '1999-12-20' ],
	[ 'id' => 55, 'offerprojectbase' => 42, 'offerprojectline' => 82, 'amount' => -5, 'date' => '2000-02-15' ],
];
$sent_line = [ 'id' => 61, 'umbrellaproject' => [ 'id' => 1 ], 'project' => [ 'id' => 42 ], 'invoice' => [ 'id' => 71 ], 'amount' => 2, 'sellingprice' => '90.00', 'discount' => '10' ];
$zero_line = array_merge( $sent_line, [ 'id' => 62, 'amount' => 0, 'umbrellaproject' => null ] );
$draft_line = array_merge( $sent_line, [ 'id' => 63, 'invoice' => 72, 'amount' => 100 ] );
$credit_line = array_merge( $sent_line, [ 'id' => 64, 'invoice' => 73, 'amount' => -1, 'discount' => 0 ] );
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( $usage_orders ) ],
	'hour.get' => [ project_response( $usage_hours ) ],
	'offerprojectline.get' => [ project_response( [
		[ 'id' => 81, 'offerprojectbase' => 41, 'product' => [ 'id' => 91, 'searchname' => 'Webdevelopment (ND / intern) (8026)' ] ],
		[ 'id' => 82, 'offerprojectbase' => 42, 'product' => [ 'id' => 92, 'searchname' => 'Marketing ( nd/intern )' ] ],
	] ) ],
	'invoiceline.get' => [ project_response( [ $sent_line ] ), project_response( [ $sent_line, $zero_line, $draft_line, $credit_line ] ) ],
	'invoice.get' => [ project_response( [
		[ 'id' => 71, 'date' => '2000-02-20', 'totalincldiscountexclvat' => '999999.00' ],
		[ 'id' => 73, 'date' => [ 'date' => '2001-01-15 00:00:00.000000' ] ],
	] ) ],
];
$usage_request_count = count( $GLOBALS['requests'] );
$GLOBALS['transients']['stuh_gripp_usage'] = [ 'resource' => 'umbrellaproject-budget-hours-active-v3', 'connection' => hash( 'sha256', $stored ), 'id' => 1, 'events' => [ [ 'actual' => 999999 ] ] ];
$events = invoke_gripp( 'usage', 'test-token', 1 );
expect_gripp( is_array( $events ) && 5 === count( $events ) && 7200 === array_sum( array_column( $events, 'invoiced' ) ), 'Usage counts each invoice line once, excludes future time, draft invoices and unrelated invoice totals, and retains discounts, zero amounts and negative credits' );
expect_gripp( 19125 === $events[0]['actual'] && '1999-12-20' === $events[0]['date'], 'Actual time includes Concept entries on zero-value orders and preserves fractional hours before conversion at EUR 90' );
expect_gripp( 32625 === array_sum( array_column( $events, 'actual' ) ), 'Invalidate old usage caches and exclude ND / intern hours and corrections from the chart, matching case-insensitively with optional spacing and trailing product IDs' );
$usage_calls = array_map( static fn( $request ) => json_decode( $request[1]['body'], true )[0], array_slice( $GLOBALS['requests'], $usage_request_count ) );
expect_gripp( [ [ 'field' => 'hour.offerprojectbase', 'operator' => 'in', 'value' => [ 41, 42 ] ] ] === $usage_calls[2]['params'][0], 'Load all recorded time for linked orders without filtering out Concept entries or zero-value work' );
expect_gripp( [ [ 'field' => 'invoice.id', 'operator' => 'in', 'value' => [ 71, 72, 73 ] ], [ 'field' => 'invoice.status', 'operator' => 'equals', 'value' => 'SENT' ] ] === $usage_calls[5]['params'][0], 'Use the API sent-invoice status filter, not localized status labels or time-entry authorization' );
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all explicitly queued usage responses' );
unset( $GLOBALS['entity_responses'] );

$usage_project = array_merge( $year, [ 'startdate' => '2000-01-01', 'deadline' => '2000-12-31', 'budget' => 10000 ] );
$usage_plan = invoke_gripp( 'budget_chart_data', $usage_project );
$current_usage = invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, $events, new DateTimeImmutable( '2000-06-15', wp_timezone() ) );
expect_gripp( 32625 === $current_usage['actual'] && 16200 === $current_usage['invoiced'] && '2000-06-15' === end( $current_usage['usage'] )['date'], 'Cumulative usage stops at today, retains all recorded time, and excludes future invoices and future time rather than forecasting them' );
expect_gripp( [ 19125, 0, 13500, 0, 0, 0, 0 ] === array_column( $current_usage['monthly_usage'], 'actual' ) && '2000-06-15' === end( $current_usage['monthly_usage'] )['date'], 'Monthly bars reset each calendar month, include zero months and pre-start work, exclude internal/future time, and stop at today without changing cumulative lines' );
expect_gripp( '1999-12-31' === $current_usage['axis'][0]['date'] && '2000-12-31' === end( $current_usage['axis'] )['date'] && $current_usage['points'][0]['months'] > 0, 'Pre-start work extends the monthly axis and shifts the planned line without changing the project allowance period' );
$finished_usage = invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, $events, new DateTimeImmutable( '2001-02-01', wp_timezone() ) );
expect_gripp( 7200 === $finished_usage['invoiced'] && '2001-01-15' === end( $finished_usage['usage'] )['date'] && '2001-01-15' === end( $finished_usage['axis'] )['date'], 'Post-deadline credits extend the timeline on their invoice date without flattening actual usage out to an unrelated future date' );
$before_start_usage = invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, [], new DateTimeImmutable( '1999-01-01', wp_timezone() ) );
expect_gripp( [] === $before_start_usage['usage'] && 0 === $before_start_usage['actual'], 'Future projects do not acquire a usage curve projected from a future start date' );
$overflow_events = [
	[ 'date' => '2000-01-01', 'actual' => PHP_INT_MAX, 'invoiced' => 0 ],
	[ 'date' => '2000-01-02', 'actual' => 1, 'invoiced' => 0 ],
];
expect_gripp( is_wp_error( invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, $overflow_events, new DateTimeImmutable( '2000-06-15', wp_timezone() ) ) ), 'Unsafe cumulative totals fail explicitly instead of wrapping or losing precision' );

ob_start();
invoke_gripp( 'render_budget_chart', $usage_project, $current_usage, 'hours' );
$usage_html = ob_get_clean();
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $usage_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$chart_xpath = new DOMXPath( $chart_document );
$actual_line = $chart_xpath->query( '//g[contains(@class,"stuh-fmp-series-actual")]/polyline' )->item( 0 );
$invoice_line = $chart_xpath->query( '//g[contains(@class,"stuh-fmp-series-invoiced")]/polyline' )->item( 0 );
$actual_coordinates = array_map( static fn( $point ) => array_map( 'floatval', explode( ',', $point ) ), explode( ' ', $actual_line->getAttribute( 'points' ) ) );
expect_gripp( null !== $invoice_line && 60.0 === end( $actual_coordinates )[1] && end( $actual_coordinates )[0] < 960, 'Both real usage curves render, overruns expand the Y scale, and actual usage stops before the future end of the planned line' );
expect_gripp( str_contains( $usage_html, '3.63 h' ) && str_contains( $usage_html, '1.80 h' ) && str_contains( $usage_html, 'Recorded and invoiced usage' ) && ! str_contains( $usage_html, 'The horizontal line is' ) && ! str_contains( $usage_html, 'The shaded gap between' ) && ! str_contains( $usage_html, 'Gold bars show' ) && ! str_contains( $usage_html, 'Red shows all' ), 'Keep exact accessible values and legends without the explanatory wall of text above the chart' );
$negative_usage = invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, [ [ 'date' => '2000-02-01', 'actual' => 0, 'invoiced' => -9000 ] ], new DateTimeImmutable( '2000-03-01', wp_timezone() ) );
ob_start();
invoke_gripp( 'render_budget_chart', $usage_project, $negative_usage, 'eur' );
$negative_html = ob_get_clean();
expect_gripp( str_contains( $negative_html, '€-90.00' ) && ! str_contains( $negative_html, 'NAN' ) && ! str_contains( $negative_html, 'INF' ), 'Credit-only histories retain negative invoice values and finite chart coordinates' );
$monthly_correction = invoke_gripp( 'usage_chart_data', $usage_project, $usage_plan, [
	[ 'date' => '2000-01-31', 'actual' => 18000, 'invoiced' => 0 ],
	[ 'date' => '2000-02-01', 'actual' => -27000, 'invoiced' => 0 ],
	[ 'date' => '2000-02-29', 'actual' => 9000, 'invoiced' => 0 ],
	[ 'date' => '2000-03-05', 'actual' => 4500, 'invoiced' => 0 ],
	[ 'date' => '2000-03-11', 'actual' => 9000, 'invoiced' => 0 ],
], new DateTimeImmutable( '2000-03-10', wp_timezone() ) );
expect_gripp( [ 18000, -18000, 4500 ] === array_column( $monthly_correction['monthly_usage'], 'actual' ) && 4500 === $monthly_correction['actual'], 'Leap-month boundaries, negative monthly corrections and current-month partial hours aggregate independently, excluding future entries' );
ob_start();
invoke_gripp( 'render_budget_chart', $usage_project, $monthly_correction, 'eur' );
$monthly_bar_html = ob_get_clean();
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $monthly_bar_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$monthly_xpath = new DOMXPath( $chart_document );
$monthly_payload = json_decode( $monthly_xpath->query( '//figure[@data-stuh-fmp-chart]' )->item( 0 )->getAttribute( 'data-stuh-fmp-chart' ), true, 512, JSON_THROW_ON_ERROR );
expect_gripp( [ 18000, -18000, 4500 ] === array_column( $monthly_payload['series'][4]['points'], 1 ) && 3 === $monthly_xpath->query( '//rect[@class="stuh-fmp-monthly-bar" and number(@height)>0 and number(@width)>0]' )->length && str_contains( $monthly_bar_html, '2.00 h (€180.00)' ) && str_contains( $monthly_bar_html, '-2.00 h (€-180.00)' ) && str_contains( $monthly_bar_html, '<td>-2.00 h</td>' ), 'Interactive bars, accessible monthly-hour values and SVG bars share exact non-cumulative totals, with hour tooltips even in Euros mode' );
expect_gripp( true === $monthly_payload['series'][2]['provisional'] && 1 === $monthly_xpath->query( '//g[contains(@class,"stuh-fmp-series-actual")]/polyline[@stroke-dasharray="2 4"]' )->length && array_column( $monthly_payload['series'][4]['points'], 0 ) === array_slice( array_column( $monthly_payload['series'][2]['points'], 0 ), 1 ), 'Align bars and cumulative actual points to the exact same month and dot only the provisional current-month segment in both chart renderers' );
$svg_bar = $monthly_xpath->query( '//rect[@class="stuh-fmp-monthly-bar"]' )->item( 2 );
$svg_actual = $monthly_xpath->query( '//g[contains(@class,"stuh-fmp-series-actual")]/circle' )->item( 3 );
expect_gripp( abs( (float) $svg_actual->getAttribute( 'cx' ) - ( (float) $svg_bar->getAttribute( 'x' ) + (float) $svg_bar->getAttribute( 'width' ) / 2 ) ) < 0.01, 'Center partial-month SVG bars under the matching line point' );
ob_start();
invoke_gripp( 'render_budget_chart', $usage_project, $finished_usage, 'hours' );
$historical_chart_html = ob_get_clean();
expect_gripp( ! str_contains( $historical_chart_html, '&quot;provisional&quot;' ) && ! str_contains( $historical_chart_html, 'stroke-dasharray="2 4"' ), 'Entirely historical actual lines remain solid' );
$variance_regions = invoke_gripp( 'budget_variance_regions', [ [ 0, 0 ], [ 100, 100 ] ], [ [ 0, 20 ], [ 100, 80 ], [ 200, 200 ] ] );
expect_gripp( 2 === count( $variance_regions ) && true === $variance_regions[0]['over'] && false === $variance_regions[1]['over'] && [ 50.0, 50.0 ] === $variance_regions[0]['points'][1] && $variance_regions[0]['points'][1] === $variance_regions[1]['points'][0] && 100 === $variance_regions[1]['points'][1][0], 'Split budget variance exactly at the interpolated line crossing, red above and green below, without shading beyond the shared period' );
expect_gripp( [] === invoke_gripp( 'budget_variance_regions', [ [ 0, 0 ], [ 100, 100 ] ], [ [ 0, 0 ], [ 100, 100 ] ] ) && [] === invoke_gripp( 'budget_variance_regions', [ [ 0, 0 ], [ 100, 100 ] ], [] ), 'Equal lines or unavailable recorded time do not create misleading colored areas' );
$variance_regions = invoke_gripp( 'budget_variance_regions', [ [ 0, 0 ], [ 100, 0 ] ], [ [ 0, -20 ], [ 25, -10 ], [ 50, 0 ], [ 100, 20 ] ] );
expect_gripp( [ false, false, true ] === array_column( $variance_regions, 'over' ), 'Negative corrections, extra actual samples and crossings exactly on a point preserve correct variance colors' );
expect_gripp( $monthly_xpath->query( '//polygon[@class="stuh-fmp-variance-over"]' )->length > 0 && $monthly_xpath->query( '//polygon[@class="stuh-fmp-variance-under"]' )->length > 0 && count( $monthly_payload['variance'] ) === $monthly_xpath->query( '//polygon[starts-with(@class,"stuh-fmp-variance-")]' )->length, 'Static SVG and interactive shading use the same red/green regions, including the provisional current-month segment' );

$hour_page = [];
for ( $id = 1; $id <= 250; $id++ ) {
	$hour_page[] = [ 'id' => $id ];
}
$GLOBALS['entity_responses']['hour.get'] = [ project_response( $hour_page, true, 250 ), project_response( [ [ 'id' => 251 ] ] ) ];
expect_gripp( 251 === count( invoke_gripp( 'fetch_all', 'test-token', 'hour', [] ) ), 'Usage reads every page of time, invoice-line or invoice responses through the shared pagination helper' );
$GLOBALS['entity_responses']['hour.get'] = [ project_response( $hour_page, true, 250 ), gripp_response( [], 403 ) ];
expect_gripp( is_wp_error( invoke_gripp( 'fetch_all', 'test-token', 'hour', [] ) ), 'A failed later usage page cannot become a successful partial history' );
$GLOBALS['entity_responses']['hour.get'] = [ project_response( $hour_page, true, 250 ), project_response( [ [ 'id' => 250 ] ] ) ];
expect_gripp( is_wp_error( invoke_gripp( 'fetch_all', 'test-token', 'hour', [] ) ), 'Repeated usage IDs across pages are rejected rather than double counted' );
unset( $GLOBALS['entity_responses'] );
foreach ( [
	[ 'amount' => 'not-hours' ],
	[ 'date' => null ],
	[ 'offerprojectbase' => 999 ],
] as $invalid_hour ) {
	$GLOBALS['entity_responses'] = [
		'project.get' => [ project_response( $usage_orders ) ],
		'invoiceline.get' => [ project_response( [] ) ],
		'hour.get' => [ project_response( [ array_merge( $usage_hours[0], $invalid_hour ) ] ) ],
	];
	expect_gripp( is_wp_error( invoke_gripp( 'fetch_usage', 'test-token', 1 ) ), 'Malformed amounts, missing dates and unrelated time entries fail explicitly' );
}
unset( $GLOBALS['entity_responses'] );
$detail_cache['data']['rows'] = [ array_merge( $detail_project, $usage_project ) ];
$GLOBALS['transients']['stuh_gripp_projects'] = $detail_cache;
$GLOBALS['transients']['stuh_gripp_usage'] = [ 'resource' => 'umbrellaproject-budget-hours-active-v4', 'connection' => hash( 'sha256', $stored ), 'id' => 1, 'events' => $events ];
$before_usage_cache = count( $GLOBALS['requests'] );
$recorded_details = gripp_render( 'render_dashboard', 250, 'hours', 1 );
expect_gripp( count( $GLOBALS['requests'] ) === $before_usage_cache && str_contains( $recorded_details, '3.63 h' ) && str_contains( $recorded_details, '0.80 h' ) && str_contains( $recorded_details, 'Committed order value' ), 'Overview reuses the usage cache without loading active projects and separates recorded hours, invoiced equivalents and committed value' );
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $recorded_details );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$chart_xpath = new DOMXPath( $chart_document );
$interactive_usage = json_decode( $chart_xpath->query( '//figure[@data-stuh-fmp-chart]' )->item( 0 )->getAttribute( 'data-stuh-fmp-chart' ), true, 512, JSON_THROW_ON_ERROR );
expect_gripp( 'hours' === $interactive_usage['unit'] && 32625 === end( $interactive_usage['series'][2]['points'] )[1] && 7200 === end( $interactive_usage['series'][3]['points'] )[1] && '2001-01-01' === gmdate( 'Y-m-d', end( $interactive_usage['series'][3]['points'] )[0] ), 'Zoomable payloads retain overruns, selected units and invoice credits while aligning usage to its month' );
$GLOBALS['transients']['stuh_gripp_usage']['connection'] = 'another-connection';
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [] ) ],
	'invoiceline.get' => [ gripp_response( [], 403 ) ],
];
$usage_error_details = gripp_render( 'render_dashboard', 250, 'eur', 1 );
expect_gripp( str_contains( $usage_error_details, 'HTTP 403' ) && str_contains( $usage_error_details, 'only planned budget lines' ) && ! str_contains( $usage_error_details, '<g class="stuh-analytics-series stuh-fmp-series-actual"' ), 'A different connection cannot reuse usage, and an API error shows planned-only data without a fabricated zero-usage curve' );
expect_gripp( 'another-connection' === $GLOBALS['transients']['stuh_gripp_usage']['connection'], 'Failed histories are not cached as successful empty data' );
unset( $GLOBALS['entity_responses'] );
$active_order = [
	'id' => 1001, 'umbrellaproject' => [ 'id' => 1 ], 'archived' => false,
	'number' => '2026001', 'name' => '<img src=x onerror=alert(1)>',
	'startdate' => [ 'date' => '2026-01-15 00:00:00.000000' ],
	'deliverydate' => '2000-01-01', 'totalexclvat' => '900.00',
];
$active_page = [];
for ( $id = 1001; $id <= 1250; $id++ ) {
	$active_page[] = array_merge( $active_order, [ 'id' => $id, 'name' => 1001 === $id ? $active_order['name'] : 'Active order ' . $id ] );
}
$active_page[1]['startdate'] = [ 'date' => '-0001-11-30 00:00:00.000000' ];
$active_page[1]['deliverydate'] = 'unused date';
$active_page[1]['totalexclvat'] = '0.00';
$last_active = array_merge( $active_order, [ 'id' => 1251, 'name' => 'Last active order', 'totalexclvat' => '-90.00' ] );
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses']['project.get'] = [ project_response( $active_page, true, 250 ), project_response( [ $last_active ] ) ];
$active_hour_page = [];
for ( $id = 2001; $id <= 2250; $id++ ) {
	$active_hour_page[] = [ 'id' => $id, 'offerprojectbase' => [ 'id' => 1001 ], 'offerprojectline' => [ 'id' => 6001 ], 'amount' => 0.01, 'date' => '2000-01-01', 'status' => [ 'id' => 1, 'searchname' => 'Concept' ] ];
}
$GLOBALS['entity_responses']['hour.get'] = [
	project_response( $active_hour_page, true, 250 ),
	project_response( [
		[ 'id' => 2251, 'offerprojectbase' => 1001, 'offerprojectline' => 6002, 'amount' => 0.125, 'date' => '2000-01-01' ],
		[ 'id' => 2252, 'offerprojectbase' => 1002, 'offerprojectline' => 6003, 'amount' => 4.25, 'date' => '2000-01-01' ],
		[ 'id' => 2253, 'offerprojectbase' => 1001, 'amount' => 100, 'date' => '3000-01-01' ],
		[ 'id' => 2255, 'offerprojectbase' => 1001, 'offerprojectline' => 6004, 'amount' => 10, 'date' => '2000-01-01' ],
		[ 'id' => 2256, 'offerprojectbase' => 1001, 'offerprojectline' => 6004, 'amount' => -1, 'date' => '1999-12-01' ],
		[ 'id' => 2257, 'offerprojectbase' => 1003, 'offerprojectline' => 6005, 'amount' => 5, 'date' => '1999-12-01' ],
	] ),
	project_response( [ [ 'id' => 2254, 'offerprojectbase' => 1251, 'amount' => 1.5, 'date' => '2000-01-01' ] ] ),
];
$GLOBALS['entity_responses']['offerprojectline.get'] = [ project_response( [
	[ 'id' => 6001, 'offerprojectbase' => [ 'id' => 1001 ], 'product' => [ 'id' => 101, 'searchname' => 'Webdevelopment' ] ],
	[ 'id' => 6002, 'offerprojectbase' => 1001, 'product' => [ 'id' => 102, 'searchname' => 'Project Management' ] ],
	[ 'id' => 6003, 'offerprojectbase' => 1002, 'product' => [ 'id' => 101, 'searchname' => 'Webdevelopment' ] ],
	[ 'id' => 6004, 'offerprojectbase' => 1001, 'product' => [ 'id' => 103, 'searchname' => 'Webdevelopment (ND / intern)' ] ],
	[ 'id' => 6005, 'offerprojectbase' => 1003, 'product' => [ 'id' => 103, 'searchname' => 'Webdevelopment (ND / intern)' ] ],
] ) ];
$active_request_count = count( $GLOBALS['requests'] );
$active_orders = invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( 251 === count( $active_orders ) && 90000 === $active_orders[0]['value'] && abs( 2.625 - $active_orders[0]['hours'] ) < 0.000001 && 4.25 === $active_orders[1]['hours'] && 0 === $active_orders[1]['value'] && -9000 === $active_orders[250]['value'] && 1.5 === $active_orders[250]['hours'], 'Load every active order and hour page, retain fractional Concept time and zero-value work, exclude future time, and batch all order IDs' );
$active_query = json_decode( $GLOBALS['requests'][ $active_request_count ][1]['body'], true )[0];
$active_next = json_decode( $GLOBALS['requests'][ $active_request_count + 1 ][1]['body'], true )[0];
expect_gripp( [ [ 'field' => 'project.umbrellaproject', 'operator' => 'equals', 'value' => 1 ], [ 'field' => 'project.archived', 'operator' => 'equals', 'value' => false ] ] === $active_query['params'][0] && 250 === $active_next['params'][1]['paging']['firstresult'], 'Select only non-archived orders belonging to the exact umbrella project, without excluding past delivery dates' );
$active_hour_requests = array_values( array_filter( array_slice( $GLOBALS['requests'], $active_request_count ), static fn( $request ): bool => 'hour.get' === json_decode( $request[1]['body'], true )[0]['method'] ) );
$last_hour_query = json_decode( end( $active_hour_requests )[1]['body'], true )[0];
expect_gripp( [ [ 'field' => 'hour.offerprojectbase', 'operator' => 'in', 'value' => [ 1251 ] ] ] === $last_hour_query['params'][0], 'Load actual hours for the second batch of active order IDs, rather than only the first 250 projects' );
expect_gripp( [ 'Webdevelopment', 'Project Management' ] === array_column( $active_orders[0]['products'], 'name' ) && 2.5 === $active_orders[0]['products'][0]['hours'] && 0.125 === $active_orders[0]['products'][1]['hours'] && 4.25 === $active_orders[1]['products'][0]['hours'] && 101 === $active_orders[1]['products'][0]['id'] && 'No product' === $active_orders[250]['products'][0]['name'] && [] === $active_orders[2]['products'], 'Summarize paginated Concept time by product within each project, without merging the same product across projects or fabricating rows for projects without time' );
expect_gripp( abs( array_sum( array_column( $active_orders[0]['products'], 'hours' ) ) - $active_orders[0]['hours'] ) < 0.000001 && ! $GLOBALS['entity_responses']['offerprojectline.get'], 'Product-hour subtotals reconcile to the project total before display rounding and use the batched line metadata' );
expect_gripp( 0.0 === $active_orders[2]['hours'] && [] === $active_orders[2]['months'] && [] === invoke_gripp( 'filter_active_orders', $active_orders, '1999-12' ) && ! str_contains( json_encode( $active_orders ), 'ND / intern' ), 'Exclude internal products from active totals and breakdowns, and hide projects and months with only internal time' );
$active_cached_count = count( $GLOBALS['requests'] );
invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( count( $GLOBALS['requests'] ) === $active_cached_count, 'Repeated detail views reuse the matching active-project cache' );
$detail_cache['data']['rows'] = [ array_merge( $detail_project, [ 'budget' => null ] ) ];
$GLOBALS['transients']['stuh_gripp_projects'] = $detail_cache;
$active_detail_html = gripp_render( 'render_dashboard', 250, 'eur', 1, 'reports' );
expect_gripp( str_contains( $active_detail_html, 'id="stuh-fmp-active-projects"' ) && str_contains( $active_detail_html, 'Last active order' ) && str_contains( $active_detail_html, '&lt;img src=x onerror=alert(1)&gt;' ) && ! str_contains( $active_detail_html, '<img' ) && ! str_contains( $active_detail_html, '2000-01-01' ) && ! str_contains( $active_detail_html, '<svg' ) && str_contains( $active_detail_html, '2.63 h' ) && str_contains( $active_detail_html, '4.25 h' ) && ! str_contains( $active_detail_html, '>Delivery date<' ), 'Details replace unused dates with actual logged hours, including zero-value work, while escaping project content and working without a chart' );
expect_gripp( str_contains( $active_detail_html, '€0.00' ) && str_contains( $active_detail_html, '€-90.00' ) && str_contains( gripp_render( 'render_dashboard', 250, 'hours', 1, 'reports' ), '10.00 h' ), 'The active-project table respects the Euros/Hours choice without dropping zero or negative order values' );
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $active_detail_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$chart_xpath = new DOMXPath( $chart_document );
expect_gripp( 4 === $chart_xpath->query( '//table[@id="stuh-fmp-active-projects"]//tr[@class="stuh-fmp-order-line"]' )->length && 'Webdevelopment' === $chart_xpath->query( '//tr[@class="stuh-fmp-order-line"][1]/th' )->item( 0 )->textContent && 'stuh-fmp-order-1001' === $chart_xpath->query( '//tr[@class="stuh-fmp-order-line"][1]/th' )->item( 0 )->getAttribute( 'headers' ), 'Render indented sub-rows directly below their parent projects with accessible parent-header associations' );
$order_link = $chart_xpath->query( '//table[@id="stuh-fmp-active-projects"]/tbody/tr[1]/td[1]/a' )->item( 0 );
$order_state = json_decode( base64_decode( parse_url( $order_link->getAttribute( 'href' ), PHP_URL_FRAGMENT ), true ), true, 512, JSON_THROW_ON_ERROR );
expect_gripp( '2026001' === $order_link->textContent && 1001 === $order_state['actionparams']['sn_']['n9098n']['recordid'] && 'n15338n' === $order_state['actionparams']['sn_']['n6409n']['selectedtab'] && 'n9102n' === $order_state['actionparams']['re_'] && '_blank' === $order_link->getAttribute( 'target' ) && 'noopener noreferrer' === $order_link->getAttribute( 'rel' ), 'Project numbers link to the supplied Gripp order-view route using the internal ID, not the displayed number or umbrella navigation' );
$GLOBALS['transients']['stuh_gripp_active_orders']['connection'] = 'another-connection';
$GLOBALS['entity_responses']['project.get'] = [ project_response( [ $last_active ] ) ];
$GLOBALS['entity_responses']['hour.get'] = [ project_response( [] ) ];
expect_gripp( 1 === count( invoke_gripp( 'active_orders', 'test-token', 1 ) ), 'Changing the connection cannot reuse another connection active-project cache' );
$GLOBALS['entity_responses']['project.get'] = [ project_response( [ array_merge( $active_order, [ 'umbrellaproject' => 2 ] ) ] ) ];
$GLOBALS['entity_responses']['hour.get'] = [ project_response( [] ) ];
expect_gripp( 1 === count( invoke_gripp( 'active_orders', 'test-token', 2 ) ), 'Changing umbrella project cannot reuse the previous active-project list' );
foreach ( [ [ 'archived' => true ], [ 'archived' => null ], [ 'umbrellaproject' => 2 ], [ 'name' => [] ], [ 'totalexclvat' => 'invalid' ] ] as $invalid_order ) {
	delete_transient( 'stuh_gripp_active_orders' );
	$GLOBALS['entity_responses']['project.get'] = [ project_response( [ array_merge( $active_order, $invalid_order ) ] ) ];
	expect_gripp( is_wp_error( invoke_gripp( 'active_orders', 'test-token', 1 ) ) && false === get_transient( 'stuh_gripp_active_orders' ), 'Invalid, archived or unrelated active-order responses are explicit errors and never cached as a successful list' );
}
$GLOBALS['entity_responses']['project.get'] = [ project_response( $active_page, true, 250 ), gripp_response( [], 403 ) ];
$failed_active = gripp_render( 'render_dashboard', 250, 'eur', 1, 'reports' );
expect_gripp( str_contains( $failed_active, 'HTTP 403' ) && ! str_contains( $failed_active, 'No active projects linked' ) && ! str_contains( $failed_active, 'id="stuh-fmp-active-projects"' ) && false === get_transient( 'stuh_gripp_active_orders' ), 'A failed later active-project page displays an error, never a partial table or misleading empty state' );
$GLOBALS['entity_responses']['project.get'] = [ project_response( [] ) ];
$empty_active = gripp_render( 'render_dashboard', 250, 'eur', 1, 'reports' );
expect_gripp( str_contains( $empty_active, '<td colspan="4">No active projects linked to this umbrella project.</td>' ), 'An actually empty active-project list has an explicit table empty state matching the new columns' );
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses']['project.get'] = [ project_response( [ $active_order ] ) ];
$GLOBALS['entity_responses']['hour.get'] = [ project_response( $active_hour_page, true, 250 ), gripp_response( [], 403 ) ];
$failed_hours = gripp_render( 'render_dashboard', 250, 'eur', 1, 'reports' );
expect_gripp( str_contains( $failed_hours, 'HTTP 403' ) && ! str_contains( $failed_hours, 'id="stuh-fmp-active-projects"' ) && false === get_transient( 'stuh_gripp_active_orders' ), 'A failed later hour page cannot cache or display a misleading partial or zero-hours total' );
$GLOBALS['transients']['stuh_gripp_active_orders'] = [ 'connection' => hash( 'sha256', $stored ), 'id' => 1, 'rows' => [ [ 'name' => 'Old date-only cache' ] ] ];
$GLOBALS['entity_responses']['project.get'] = [ project_response( [ $active_order ] ) ];
$GLOBALS['entity_responses']['hour.get'] = [ project_response( [] ) ];
$without_hours = invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( 0.0 === $without_hours[0]['hours'] && 1001 === $without_hours[0]['id'], 'Invalidate date-only caches and show zero hours only after a successful empty time response' );
foreach ( [ [ 'offerprojectbase' => 999 ], [ 'amount' => 'invalid' ], [ 'date' => null ] ] as $invalid_hour ) {
	$GLOBALS['entity_responses']['hour.get'] = [ project_response( [ array_merge( $active_hour_page[0], $invalid_hour ) ] ) ];
	expect_gripp( is_wp_error( invoke_gripp( 'order_hours', 'test-token', [ 1001 ] ) ), 'Unrelated, malformed or undated time entries cannot become an actual-hours total' );
}
$GLOBALS['entity_responses']['hour.get'] = [ project_response( [
	[ 'id' => 5001, 'offerprojectbase' => 1001, 'amount' => 2.125, 'date' => '2000-01-01' ],
	[ 'id' => 5002, 'offerprojectbase' => 1001, 'amount' => -0.5, 'date' => '2000-01-01' ],
] ) ];
expect_gripp( 1.625 === invoke_gripp( 'order_hours', 'test-token', [ 1001 ] )[1001], 'Actual hours retain fractional time corrections rather than clipping negative entries' );
expect_gripp( ! $GLOBALS['entity_responses']['hour.get'], 'Consume every expected recorded-time response' );
expect_gripp( ! $GLOBALS['entity_responses']['project.get'], 'Consume every expected active-order response' );
unset( $GLOBALS['entity_responses'] );
$GLOBALS['responses'][] = project_response( [] );
gripp_action( 'refresh' );
expect_gripp( false === get_transient( 'stuh_gripp_active_orders' ), 'Refreshing projects invalidates the active-project details cache' );
$GLOBALS['options']['stuh_gripp_connection'] = $stored;
$real_projects = project_rows( 1, 3 );
foreach ( $real_projects as &$real_project ) {
	$real_project['startdate'] = $today->format( 'Y-m-01' );
	$real_project['deadline'] = $today->format( 'Y-m-t' );
}
unset( $real_project );
$GLOBALS['transients']['stuh_gripp_projects'] = [
	'resource' => 'umbrellaproject-budget-v1', 'connection' => hash( 'sha256', $stored ),
	'offset' => 0, 'data' => [ 'rows' => [ [ 'name' => 'Old cache without logged time' ] ] ],
];
$GLOBALS['responses'][] = project_response( $real_projects );
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [
		[ 'id' => 7001, 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => '900.00', 'archived' => true ],
		[ 'id' => 7002, 'umbrellaproject' => 1, 'totalexclvat' => '0.00', 'archived' => false ],
		[ 'id' => 7003, 'umbrellaproject' => 2, 'totalexclvat' => '1800.00', 'archived' => false ],
	] ) ],
	'hour.get' => [ project_response( [
		[ 'id' => 8001, 'offerprojectbase' => 7001, 'amount' => 1.125, 'date' => $today->format( 'Y-m-d' ), 'status' => [ 'id' => 1 ] ],
		[ 'id' => 8002, 'offerprojectbase' => 7002, 'amount' => 0.5, 'date' => '2000-01-01' ],
		[ 'id' => 8003, 'offerprojectbase' => 7002, 'amount' => -0.125, 'date' => '2000-01-01' ],
		[ 'id' => 8004, 'offerprojectbase' => 7003, 'amount' => 2, 'date' => '2000-01-01' ],
		[ 'id' => 8005, 'offerprojectbase' => 7001, 'amount' => 100, 'date' => $today->modify( '+1 day' )->format( 'Y-m-d' ) ],
	] ) ],
];
$real_data = invoke_gripp( 'projects', 'test-token', 0 );
expect_gripp( [ 13500, 18000, 0 ] === array_column( $real_data['rows'], 'recorded' ) && [ 90000, 180000, 0 ] === array_column( $real_data['rows'], 'used' ), 'Real budget usage sums linked archived and zero-value order hours, includes Concept time and corrections through today, excludes future time, and leaves commitments unchanged' );
expect_gripp( [ 1, 1, 0 ] === array_column( $real_data['rows'], 'active_projects' ), 'Active project counts exclude archived orders, include zero-value projects, and return zero when no orders are linked' );
$real_request_count = count( $GLOBALS['requests'] );
invoke_gripp( 'projects', 'test-token', 0 );
expect_gripp( count( $GLOBALS['requests'] ) === $real_request_count && ! str_contains( json_encode( $real_data ), 'Old cache' ), 'Invalidate old commitment-only caches and cache real logged usage with the matching dashboard page' );
$real_rows = [];
foreach ( [ 9000, -9000, 0, null ] as $balance ) {
	$real_rows[] = array_merge( $real_data['rows'][0], [
		'budget' => 31000, 'used' => 999999, 'recorded' => $planned - ( $balance ?? 0 ),
		'deadline' => null === $balance ? '' : $today->format( 'Y-m-t' ),
	] );
}
$real_cache = get_transient( 'stuh_gripp_projects' );
$real_cache['data']['rows'] = $real_rows;
$GLOBALS['transients']['stuh_gripp_projects'] = $real_cache;
$real_html = gripp_render( 'render_dashboard' );
preg_match_all( '/<td class="column-real_left_to_date"([^>]*)>([^<]*)<\/td>/', $real_html, $real_cells, PREG_SET_ORDER );
expect_gripp( 4 === count( $real_cells ) && str_contains( $real_cells[0][1], '#008a20' ) && '€90.00' === $real_cells[0][2] && str_contains( $real_cells[1][1], '#b32d2e' ) && '€-90.00' === $real_cells[1][2], 'Real allowance minus logged usage is green when positive and red when negative regardless of committed order value' );
expect_gripp( '' === $real_cells[2][1] && '€0.00' === $real_cells[2][2] && '' === $real_cells[3][1] && 'Unavailable' === $real_cells[3][2], 'Zero real budget balances and unavailable schedules are neutral, not fabricated positive or negative values' );
$real_hours_html = gripp_render( 'render_dashboard', 0, 'hours' );
expect_gripp( str_contains( $real_hours_html, 'class="column-real_left_to_date" style="color:#008a20;font-weight:600">1.00 h</td>' ) && str_contains( $real_hours_html, '>Real budget left to date</th>' ), 'Real budget column follows the Euros/Hours setting at EUR 90 per hour' );
$GLOBALS['hidden_columns'][1] = [ 'real_left_to_date', 'active_projects' ];
$real_cache['data']['rows'][0]['deadline'] = $today->modify( '-1 day' )->format( 'Y-m-d' );
$GLOBALS['transients']['stuh_gripp_projects'] = $real_cache;
$hidden_real_html = gripp_render( 'render_dashboard' );
expect_gripp( 2 === substr_count( $hidden_real_html, 'class="manage-column column-real_left_to_date hidden"' ) && str_contains( $hidden_real_html, 'class="column-real_left_to_date hidden"' ), 'Native Screen Options hides the real budget column in both current and past-deadline tables' );
expect_gripp( 2 === substr_count( $hidden_real_html, 'class="manage-column column-active_projects hidden"' ) && str_contains( $hidden_real_html, 'class="column-active_projects hidden">1</td>' ), 'Active project counts render in both FMP tables and respect native column visibility preferences' );
unset( $GLOBALS['hidden_columns'] );
delete_transient( 'stuh_gripp_projects' );
$GLOBALS['responses'][] = project_response( [ $real_projects[0] ] );
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [ [ 'id' => 7001, 'umbrellaproject' => 1, 'totalexclvat' => '0.00', 'archived' => false ] ] ) ],
	'hour.get' => [ gripp_response( [], 403 ) ],
];
$real_failure = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $real_failure, 'HTTP 403' ) && ! str_contains( $real_failure, 'id="stuh-fmp-current"' ) && false === get_transient( 'stuh_gripp_projects' ), 'Logged-time API failures remain explicit and cannot produce or cache a misleading real budget balance' );
unset( $GLOBALS['entity_responses'] );
$count_page = [];
for ( $id = 1; $id <= 250; $id++ ) {
	$count_page[] = [ 'id' => $id, 'umbrellaproject' => 1, 'totalexclvat' => '0.00', 'archived' => false ];
}
$GLOBALS['responses'][] = project_response( $real_projects );
$GLOBALS['entity_responses'] = [
	'project.get' => [
		project_response( $count_page, true, 250 ),
		project_response( [
			[ 'id' => 251, 'umbrellaproject' => 1, 'totalexclvat' => '0.00', 'archived' => false ],
			[ 'id' => 252, 'umbrellaproject' => 2, 'totalexclvat' => '90.00', 'archived' => true ],
		] ),
	],
	'hour.get' => [ project_response( [] ), project_response( [] ) ],
];
$count_data = invoke_gripp( 'fetch_projects', 'test-token', 0 );
expect_gripp( [ 251, 0, 0 ] === array_column( $count_data['rows'], 'active_projects' ), 'Count active projects across all order pages while keeping archived-only and empty umbrella projects at zero' );
foreach ( [ null, 'false' ] as $archive_status ) {
	$GLOBALS['responses'][] = project_response( [ $real_projects[0] ] );
	$GLOBALS['entity_responses']['project.get'] = [ project_response( [
		[ 'id' => 1, 'umbrellaproject' => 1, 'totalexclvat' => '0.00', 'archived' => $archive_status ],
	] ) ];
	expect_gripp( is_wp_error( invoke_gripp( 'fetch_projects', 'test-token', 0 ) ), 'Missing or invalid archive states cannot silently produce a misleading active-project count' );
}
unset( $GLOBALS['entity_responses'] );
$GLOBALS['capabilities'] = [ 'read', 'edit_posts', 'edit_others_posts' ];
$GLOBALS['transients']['stuh_gripp_projects'] = $original_cache;
STUH_Gripp::register_menu();
expect_gripp( 'edit_others_posts' === $GLOBALS['top_menus'][0][2] && 'stuh-fmp' === $GLOBALS['top_menus'][0][3] && in_array( [ 'load-toplevel_page_stuh-fmp', [ STUH_Gripp::class, 'register_screen_options' ] ], $GLOBALS['hooks'], true ), 'Editors get a standalone FMP menu and native Screen Options without access to the administrator-only Updater Host parent' );
$editor_dashboard = gripp_render( 'render_dashboard' );
expect_gripp( str_contains( $editor_dashboard, 'id="stuh-fmp-current"' ) && str_contains( $editor_dashboard, 'Refresh projects' ) && ! str_contains( $editor_dashboard, '>Gripp settings</a>' ), 'Editors can view FMP and refresh data but do not see a link to restricted connection settings' );
expect_gripp( 'hours' === STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', 'hours' ), 'Editors can save their own budget unit through native Screen Options' );
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache();
$editor_detail = gripp_render( 'render_dashboard', 0, 'eur', 1, 'reports' );
expect_gripp( str_contains( $editor_detail, '<h1>' ) && str_contains( $editor_detail, 'id="stuh-fmp-active-projects"' ), 'Editors can open umbrella project details and their active-project table' );
$_GET = [ 'project_id' => '1' ];
$editor_script_count = count( $GLOBALS['enqueued_scripts'] );
STUH_Gripp::enqueue_assets( 'toplevel_page_stuh-fmp' );
$_GET = [];
expect_gripp( count( $GLOBALS['enqueued_scripts'] ) === $editor_script_count + 2, 'Editor Overview loads the chart scripts on their standalone FMP screen' );
$_GET = [ 'project_id' => '1', 'project_tab' => 'reports' ];
$report_script_count = count( $GLOBALS['enqueued_scripts'] );
$report_style_count = count( $GLOBALS['enqueued_styles'] );
STUH_Gripp::enqueue_assets( 'toplevel_page_stuh-fmp' );
$_GET = [];
expect_gripp( count( $GLOBALS['enqueued_scripts'] ) === $report_script_count + 1 && 'stuh-fmp-export' === $GLOBALS['enqueued_scripts'][ $report_script_count ][0] && count( $GLOBALS['enqueued_styles'] ) === $report_style_count, 'Editors get only the rich-copy script on Monthly reports, without loading chart scripts or styles' );
foreach ( [ 'connect', 'disconnect' ] as $admin_operation ) {
	try {
		gripp_action( $admin_operation, [ 'api_token' => 'must-not-be-saved' ] );
		throw new RuntimeException( 'Editor credential mutation succeeded' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Insufficient permissions' === $error->getMessage() && $stored === get_option( 'stuh_gripp_connection' ), 'Editors cannot replace or disconnect the stored Gripp credentials' );
	}
}
try {
	gripp_render( 'render_settings' );
	throw new RuntimeException( 'Editor opened connection settings' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Gripp connection settings remain administrator-only' );
}
try {
	gripp_action( 'refresh', [ '_wpnonce' => 'invalid' ] );
	throw new RuntimeException( 'Editor refreshed without nonce' );
} catch ( RuntimeException $error ) {
	expect_gripp( 'Invalid nonce' === $error->getMessage(), 'Editor refresh still requires a valid nonce' );
}
$GLOBALS['responses'][] = project_response( [] );
[ $editor_refresh_url, $editor_refresh_notice ] = gripp_action( 'refresh' );
expect_gripp( ! $editor_refresh_notice['error'] && str_contains( $editor_refresh_url, 'page=stuh-fmp' ), 'Editors can explicitly refresh FMP data and return to the dashboard' );
foreach ( [ [ 'read' ], [ 'read', 'edit_posts', 'publish_posts' ] ] as $lower_capabilities ) {
	$GLOBALS['capabilities'] = $lower_capabilities;
	foreach ( [ 'render_dashboard', 'save_display_unit', 'refresh' ] as $restricted_action ) {
		try {
			if ( 'refresh' === $restricted_action ) {
				gripp_action( 'refresh' );
			} elseif ( 'save_display_unit' === $restricted_action ) {
				STUH_Gripp::save_display_unit( false, 'stuh_fmp_unit', 'hours' );
			} else {
				gripp_render( 'render_dashboard' );
			}
			throw new RuntimeException( 'Lower-privilege FMP access succeeded' );
		} catch ( RuntimeException $error ) {
			expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Authors and subscribers cannot view, refresh or change FMP preferences' );
		}
	}
}
unset( $GLOBALS['capabilities'] );
$breakdown_hours = [
	[ 'id' => 1, 'offerprojectbase' => 1001, 'offerprojectline' => [ 'id' => 11 ], 'amount' => 2.125, 'date' => '2000-01-01' ],
	[ 'id' => 2, 'offerprojectbase' => 1001, 'offerprojectline' => 11, 'amount' => -0.5, 'date' => '2000-01-02' ],
	[ 'id' => 3, 'offerprojectbase' => 1001, 'offerprojectline' => 12, 'amount' => 3, 'date' => '2000-01-02' ],
	[ 'id' => 4, 'offerprojectbase' => 1001, 'offerprojectline' => null, 'amount' => 0.25, 'date' => '2000-01-02' ],
	[ 'id' => 5, 'offerprojectbase' => 1001, 'offerprojectline' => 999, 'amount' => 100, 'date' => '3000-01-01' ],
	[ 'id' => 6, 'offerprojectbase' => 1001, 'offerprojectline' => 13, 'amount' => 1, 'date' => '2000-01-02' ],
	[ 'id' => 7, 'offerprojectbase' => 1001, 'offerprojectline' => 14, 'amount' => 0.5, 'date' => '2000-01-02' ],
];
$breakdown_lines = [
	[ 'id' => 11, 'offerprojectbase' => 1001, 'searchname' => 'Custom line A', 'product' => [ 'id' => 21, 'searchname' => '<Webdevelopment>' ] ],
	[ 'id' => 12, 'offerprojectbase' => 1001, 'searchname' => 'Custom line B', 'product' => [ 'id' => 21, 'searchname' => '<Webdevelopment>' ] ],
	[ 'id' => 13, 'offerprojectbase' => 1001, 'product' => [ 'id' => 22, 'searchname' => '<Webdevelopment>' ] ],
	[ 'id' => 14, 'offerprojectbase' => 1001, 'product' => null ],
];
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [ $active_order ] ) ],
	'hour.get' => [ project_response( $breakdown_hours ) ],
	'offerprojectline.get' => [ project_response( $breakdown_lines ) ],
];
$GLOBALS['transients']['stuh_gripp_active_orders'] = [ 'version' => 4, 'connection' => hash( 'sha256', $stored ), 'id' => 1, 'rows' => [ [ 'name' => 'Old cache without monthly hours' ] ] ];
$line_rows = invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( 6.375 === $line_rows[0]['hours'] && [ 4.625, 0.75, 1.0 ] === array_column( $line_rows[0]['products'], 'hours' ) && [ 21, 0, 22 ] === array_column( $line_rows[0]['products'], 'id' ), 'Invalidate caches without monthly hours and combine different lines sharing a product, including corrections; keep distinct same-label products separate and combine missing-line/product time without counting future time' );
ob_start();
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache();
invoke_gripp( 'render_project_reports', 'test-token', 1, 'eur' );
$line_html = ob_get_clean();
preg_match( '/<table id="stuh-fmp-active-projects".*?<\/table>/s', $line_html, $line_table );
expect_gripp( 2 === substr_count( $line_table[0], '&lt;Webdevelopment&gt;' ) && ! str_contains( $line_html, '<Webdevelopment>' ) && ! str_contains( $line_html, 'Custom line' ) && str_contains( $line_html, 'No product' ) && str_contains( $line_html, '4.63 h' ) && str_contains( $line_html, '1.00 h' ), 'Render one escaped product label per product ID, not custom order-line names, and keep summarized time in hours even when order values display as euros' );
foreach ( [
	project_response( [] ),
	project_response( [ array_merge( $breakdown_lines[0], [ 'offerprojectbase' => 999 ] ) ] ),
	project_response( [ array_merge( $breakdown_lines[0], [ 'product' => [ 'id' => 21, 'searchname' => null ] ] ) ] ),
	project_response( [ array_merge( $breakdown_lines[0], [ 'product' => [ 'id' => 'invalid', 'searchname' => 'Webdevelopment' ] ] ) ] ),
	project_response( [ array_merge( $breakdown_lines[0], [ 'product' => 21 ] ) ] ),
	gripp_response( [], 403 ),
] as $line_failure ) {
	delete_transient( 'stuh_gripp_active_orders' );
	$GLOBALS['entity_responses'] = [
		'project.get' => [ project_response( [ $active_order ] ) ],
		'hour.get' => [ project_response( [ $breakdown_hours[0] ] ) ],
		'offerprojectline.get' => [ $line_failure ],
	];
	expect_gripp( is_wp_error( invoke_gripp( 'active_orders', 'test-token', 1 ) ) && false === get_transient( 'stuh_gripp_active_orders' ), 'Missing, unrelated, malformed or inaccessible line/product metadata must fail explicitly and never cache a partial breakdown' );
}
foreach ( [ [ 'unexpected' => 'reference' ], false ] as $invalid_line_reference ) {
	$GLOBALS['entity_responses'] = [
		'project.get' => [ project_response( [ $active_order ] ) ],
		'hour.get' => [ project_response( [ array_merge( $breakdown_hours[0], [ 'offerprojectline' => $invalid_line_reference ] ) ] ) ],
	];
	expect_gripp( is_wp_error( invoke_gripp( 'active_orders', 'test-token', 1 ) ), 'Malformed nonempty line references cannot be silently grouped as unassigned time' );
}
$many_line_hours = [];
$many_lines = [];
for ( $id = 1; $id <= 251; $id++ ) {
	$many_line_hours[] = [ 'id' => $id, 'offerprojectbase' => 1001, 'offerprojectline' => $id, 'amount' => 0.5, 'date' => '2000-01-01' ];
	$many_lines[] = [ 'id' => $id, 'offerprojectbase' => 1001, 'product' => [ 'id' => $id % 2 + 1, 'searchname' => 'Product ' . ( $id % 2 + 1 ) ] ];
}
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [ $active_order ] ) ],
	'hour.get' => [ project_response( array_slice( $many_line_hours, 0, 250 ), true, 250 ), project_response( array_slice( $many_line_hours, 250 ) ) ],
	'offerprojectline.get' => [ project_response( array_slice( $many_lines, 0, 250 ) ), project_response( array_slice( $many_lines, 250 ) ) ],
];
$many_line_rows = invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( 125.5 === $many_line_rows[0]['hours'] && [ 'Product 2', 'Product 1' ] === array_column( $many_line_rows[0]['products'], 'name' ) && [ 63.0, 62.5 ] === array_column( $many_line_rows[0]['products'], 'hours' ), 'Combine products across metadata batches of more than 250 order lines while retaining every paginated time entry and subtotal' );
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [ $active_order ] ) ],
	'hour.get' => [ project_response( array_slice( $many_line_hours, 0, 250 ), true, 250 ), project_response( array_slice( $many_line_hours, 250 ) ) ],
	'offerprojectline.get' => [ project_response( array_slice( $many_lines, 0, 250 ) ), gripp_response( [], 403 ) ],
];
expect_gripp( is_wp_error( invoke_gripp( 'active_orders', 'test-token', 1 ) ) && false === get_transient( 'stuh_gripp_active_orders' ), 'A failed later line-metadata batch cannot return a successful partial breakdown' );
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected breakdown responses' );
unset( $GLOBALS['entity_responses'] );
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [
		array_merge( $active_order, [ 'name' => 'Multi-month project' ] ),
		array_merge( $active_order, [ 'id' => 1002, 'name' => 'February only' ] ),
		array_merge( $active_order, [ 'id' => 1003, 'name' => 'Corrected project' ] ),
		array_merge( $active_order, [ 'id' => 1004, 'name' => 'No recorded time' ] ),
	] ) ],
	'hour.get' => [ project_response( [
		[ 'id' => 1, 'offerprojectbase' => 1001, 'offerprojectline' => 11, 'amount' => 2.125, 'date' => [ 'date' => '2000-01-31 23:59:59.000000' ] ],
		[ 'id' => 2, 'offerprojectbase' => 1001, 'offerprojectline' => 12, 'amount' => -0.5, 'date' => '2000-01-31' ],
		[ 'id' => 3, 'offerprojectbase' => 1001, 'offerprojectline' => 12, 'amount' => 3, 'date' => '2000-02-01' ],
		[ 'id' => 4, 'offerprojectbase' => 1001, 'offerprojectline' => 13, 'amount' => 2, 'date' => '2000-02-29' ],
		[ 'id' => 5, 'offerprojectbase' => 1001, 'offerprojectline' => 11, 'amount' => 7, 'date' => '2001-01-01' ],
		[ 'id' => 6, 'offerprojectbase' => 1001, 'amount' => 0.25, 'date' => '2000-01-01' ],
		[ 'id' => 7, 'offerprojectbase' => 1002, 'offerprojectline' => 14, 'amount' => 9, 'date' => '2000-02-01' ],
		[ 'id' => 8, 'offerprojectbase' => 1003, 'offerprojectline' => 15, 'amount' => 1, 'date' => '2000-01-01' ],
		[ 'id' => 9, 'offerprojectbase' => 1003, 'offerprojectline' => 15, 'amount' => -1, 'date' => '2000-01-02' ],
		[ 'id' => 10, 'offerprojectbase' => 1001, 'offerprojectline' => 999, 'amount' => 100, 'date' => '3000-01-01' ],
	] ) ],
	'offerprojectline.get' => [ project_response( [
		[ 'id' => 11, 'offerprojectbase' => 1001, 'product' => [ 'id' => 21, 'searchname' => 'Webdevelopment' ] ],
		[ 'id' => 12, 'offerprojectbase' => 1001, 'product' => [ 'id' => 21, 'searchname' => 'Webdevelopment' ] ],
		[ 'id' => 13, 'offerprojectbase' => 1001, 'product' => [ 'id' => 22, 'searchname' => 'Project Management' ] ],
		[ 'id' => 14, 'offerprojectbase' => 1002, 'product' => [ 'id' => 21, 'searchname' => 'Webdevelopment' ] ],
		[ 'id' => 15, 'offerprojectbase' => 1003, 'product' => [ 'id' => 21, 'searchname' => 'Webdevelopment' ] ],
	] ) ],
];
$monthly_rows = invoke_gripp( 'active_orders', 'test-token', 1 );
expect_gripp( 13.875 === $monthly_rows[0]['hours'] && [ '2000-01' => 1.875, '2000-02' => 5.0, '2001-01' => 7.0 ] === array_map( static fn( array $period ): float => $period['hours'], $monthly_rows[0]['months'] ), 'Partition recorded time by full calendar month and year, including leap-day and month-end entries, without changing the all-time total or counting future entries' );
expect_gripp( [ 1.625, 0.25 ] === array_column( $monthly_rows[0]['months']['2000-01']['products'], 'hours' ) && [ 'Webdevelopment', 'No product' ] === array_column( $monthly_rows[0]['months']['2000-01']['products'], 'name' ) && 0.0 === $monthly_rows[2]['months']['2000-01']['hours'] && [] === $monthly_rows[3]['months'], 'Monthly product subtotals combine lines and corrections, retain unassigned time and distinguish cancelled time from no entries' );
$render_monthly = static function( $month, string $unit = 'eur' ): string {
	$_GET = [ 'hours_month' => $month, 'offset' => '250' ];
	ob_start();
	try {
		invoke_gripp( 'render_project_reports', 'test-token', 1, $unit );
		return ob_get_contents();
	} finally {
		ob_end_clean();
		$_GET = [];
	}
};
$monthly_request_count = count( $GLOBALS['requests'] );
$january_html = $render_monthly( '2000-01' );
expect_gripp( str_contains( $january_html, 'Multi-month project' ) && str_contains( $january_html, 'Corrected project' ) && ! str_contains( $january_html, 'February only' ) && ! str_contains( $january_html, 'No recorded time' ) && ! str_contains( $january_html, 'Project Management' ) && str_contains( $january_html, '1.88 h' ) && str_contains( $january_html, '1.63 h' ) && str_contains( $january_html, '€900.00' ), 'A selected month filters both parent and product hours, hides projects/products without entries, retains corrections cancelling to zero and leaves full order values unchanged' );
expect_gripp( str_contains( $january_html, '<option value="2000-01" selected>January 2000</option>' ) && str_contains( $january_html, '>January 2001</option>' ) && ! str_contains( $january_html, '3000-01' ) && str_contains( $january_html, 'name="project_id" value="1"' ) && str_contains( $january_html, 'name="offset" value="250"' ) && str_contains( $january_html, 'name="unit" value="eur"' ), 'The labelled calendar-month selector distinguishes years, excludes future entries and preserves project navigation and units on submit' );
$february_html = $render_monthly( '2000-02' );
expect_gripp( str_contains( $february_html, 'February only' ) && str_contains( $february_html, 'Project Management' ) && str_contains( $february_html, '5.00 h' ) && ! str_contains( $february_html, 'Corrected project' ), 'Switching month changes visibility and totals without leaking another month of the same product' );
$empty_month_html = $render_monthly( '2000-03' );
expect_gripp( str_contains( $empty_month_html, 'No active projects have recorded time in this month.' ) && ! str_contains( $empty_month_html, 'stuh-fmp-order-total' ), 'A month without entries shows an explicit empty table instead of all-time totals' );
$all_months_html = $render_monthly( '' );
expect_gripp( str_contains( $all_months_html, '13.88 h' ) && str_contains( $all_months_html, 'February only' ) && str_contains( $all_months_html, 'No recorded time' ) && $monthly_request_count === count( $GLOBALS['requests'] ), 'All months restores the unfiltered table, and every month selection reuses the same cache without additional API calls' );
foreach ( [ '2000-13', '2000-1', '0000-01', '2000-01-01', [ '2000-01' ] ] as $invalid_month ) {
	try {
		$render_monthly( $invalid_month );
		throw new RuntimeException( 'Invalid month was accepted' );
	} catch ( RuntimeException $error ) {
		expect_gripp( str_contains( $error->getMessage(), 'Invalid recorded-hours month' ), 'Reject invalid calendar-month input explicitly' );
	}
}
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected monthly responses' );
unset( $GLOBALS['entity_responses'] );
$export_document = static function( array $fields = [] ): array {
	$_GET = array_merge( [ 'project_id' => '1', 'project_tab' => 'reports', 'hours_month' => '2000-01', 'unit' => 'eur' ], $fields );
	ob_start();
	try {
		invoke_gripp( 'require_viewer' );
		$id = invoke_gripp( 'selected_project', $_GET );
		$unit = invoke_gripp( 'display_unit', $_GET );
		invoke_gripp( 'render_project_reports', 'test-token', $id, $unit );
		$html = ob_get_contents();
	} finally {
		ob_end_clean();
		$_GET = [];
	}
	$document = new DOMDocument();
	$previous = libxml_use_internal_errors( true );
	$document->loadHTML( '<?xml encoding="UTF-8">' . $html );
	libxml_clear_errors();
	libxml_use_internal_errors( $previous );
	$xpath = new DOMXPath( $document );
	$preview = $xpath->query( '//*[@data-stuh-fmp-word-preview]' )->item( 0 );
	if ( null === $preview ) {
		throw new RuntimeException( $xpath->query( '//*[contains(@class,"notice-error")]' )->item( 0 )?->textContent ?? 'Word preview unavailable' );
	}
	$formatted = '';
	foreach ( $preview->childNodes as $child ) {
		$formatted .= $document->saveHTML( $child );
	}
	return [ 'text' => $preview->getAttribute( 'data-stuh-fmp-copy-text' ), 'html' => $formatted ];
};
$GLOBALS['capabilities'] = [ 'read', 'edit_posts', 'edit_others_posts' ];
$january_export = $export_document();
// Compare the decoded clipboard alternative, not its HTML-escaped attribute.
$preview_value = static function( string $html ): string {
	$document = new DOMDocument();
	$previous = libxml_use_internal_errors( true );
	$document->loadHTML( '<?xml encoding="UTF-8">' . $html );
	libxml_clear_errors();
	libxml_use_internal_errors( $previous );
	$xpath = new DOMXPath( $document );
	$preview = $xpath->query( '//*[@data-stuh-fmp-word-preview and @data-stuh-fmp-copy-text]' );
	expect_gripp( 1 === $preview->length, 'Show one formatted preview with its plain-text clipboard alternative' );
	return $preview->item( 0 )->getAttribute( 'data-stuh-fmp-copy-text' );
};
expect_gripp( $january_export['text'] === $preview_value( $january_html ) && strpos( $january_html, 'id="stuh-fmp-active-projects"' ) < strpos( $january_html, 'data-stuh-fmp-word-preview' ), 'The formatted report and its clipboard alternative follow the monthly reports table' );
expect_gripp( str_contains( $january_export['text'], 'January 2000 (2000-01)' ) && str_contains( $january_export['text'], "Opdracht 2026001 Multi-month project\nWebdevelopment\t1,63\nNo product\t0,25\n" ) && str_contains( $january_export['text'], "Opdracht 2026001 Corrected project\nWebdevelopment\t0,00" ) && ! str_contains( $january_export['text'], 'February only' ) && ! str_contains( $january_export['text'], 'Project Management' ) && ! str_contains( $january_export['text'], 'No recorded time' ) && ! str_contains( $january_export['text'], '€' ), 'Editors copy order headings and decimal-comma product hours without order values or duplicate project totals' );
expect_gripp( ! str_contains( $january_html, 'stuh_gripp_export' ) && ! str_contains( $january_html, 'stuh-fmp-export-preview' ) && ! str_contains( $january_html, 'Export TXT' ) && str_contains( $january_html, 'data-stuh-fmp-copy-word' ) && ! in_array( [ 'admin_post_stuh_gripp_export', [ STUH_Gripp::class, 'handle_export' ] ], $GLOBALS['hooks'], true ), 'Remove the TXT preview, download form and endpoint while preserving Copy for Word' );
$GLOBALS['capabilities'] = [ 'manage_options' ];
$all_export = $export_document( [ 'hours_month' => '', 'unit' => 'hours' ] );
expect_gripp( $all_export['text'] === $preview_value( $render_monthly( '', 'hours' ) ), 'All-month previews use exactly the same unit formatting and content as the download' );
expect_gripp( str_contains( $all_export['text'], 'All months' ) && str_contains( $all_export['text'], "Opdracht 2026001 Multi-month project\nWebdevelopment\t11,63\nProject Management\t2,00\nNo product\t0,25" ) && str_contains( $all_export['text'], 'February only' ) && str_contains( $all_export['text'], 'No recorded time' ) && $monthly_request_count === count( $GLOBALS['requests'] ), 'Administrators copy All months as actual hours regardless of budget-unit preference without extra requests' );
$empty_export = $export_document( [ 'hours_month' => '2000-03' ] );
expect_gripp( $empty_export['text'] === $preview_value( $empty_month_html ), 'Empty-period previews match the exported empty-state message' );
expect_gripp( str_contains( $empty_export['text'], 'No active projects have recorded time in this month.' ) && ! str_contains( $empty_export['text'], 'Multi-month project' ), 'Export an explicit empty-period message instead of falling back to unfiltered data' );
$export_cache = $GLOBALS['transients']['stuh_gripp_active_orders'];
$GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['name'] = "Caf\u{00E9}\tproject\r\nname";
$GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['months']['2000-01']['products'][0]['name'] = "Web\tdevelopment\n& design";
$plain_export = $export_document();
expect_gripp( $plain_export['text'] === $preview_value( $render_monthly( '2000-01' ) ), 'Preview and download preserve the same UTF-8 characters, whitespace normalization and unescaped plain-text labels' );
expect_gripp( str_contains( $plain_export['text'], "Opdracht 2026001 Caf\u{00E9} project  name\n" ) && str_contains( $plain_export['text'], "Web development & design\t1,63" ) && ! str_contains( $plain_export['text'], '&amp;' ), 'Preserve UTF-8 labels as plain text while normalizing tabs and line breaks in names so they cannot create fake export rows' );
$GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['name'] = '</textarea><script>alert(1)</script>';
$unsafe_preview_html = $render_monthly( '2000-01' );
expect_gripp( ! str_contains( $unsafe_preview_html, '<script>' ) && $export_document()['text'] === $preview_value( $unsafe_preview_html ), 'Escape closing-textarea markup and scripts in report labels without altering the previewed plain-text content' );
$GLOBALS['transients']['stuh_gripp_active_orders'] = $export_cache;
$GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['months']['2000-01']['products'][0]['name'] = 'Webdevelopment (8026)';
$GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['months']['2000-01']['products'][1]['name'] = 'Marketing (SEO) (99)';
$clean_labels_html = $render_monthly( '2000-01' );
$clean_labels_export = $export_document();
expect_gripp( str_contains( $clean_labels_html, '>Webdevelopment</th>' ) && str_contains( $clean_labels_html, '>Marketing (SEO)</th>' ) && ! str_contains( $clean_labels_html, '(8026)' ) && ! str_contains( $clean_labels_html, '(99)' ) && str_contains( $clean_labels_export['text'], "Webdevelopment\t1,63\nMarketing (SEO)\t0,25\n" ) && $clean_labels_export['text'] === $preview_value( $clean_labels_html ), 'Remove numeric product suffixes consistently from cached table labels, preview and download, retaining descriptive parentheses and original hours' );
expect_gripp( 'Webdevelopment (8026)' === $GLOBALS['transients']['stuh_gripp_active_orders']['rows'][0]['months']['2000-01']['products'][0]['name'], 'Label cleanup is presentation-only and does not change cached Gripp product identities or grouping' );
$GLOBALS['transients']['stuh_gripp_active_orders'] = $export_cache;
foreach ( [ [ 'read' ], [ 'read', 'edit_posts' ] ] as $capabilities ) {
	$GLOBALS['capabilities'] = $capabilities;
	try {
		$export_document();
		throw new RuntimeException( 'Export permissions were bypassed' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Authors and subscribers cannot download FMP data' );
	}
}
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
foreach ( [
	[ [ 'project_id' => '-1' ], 'Invalid Gripp project ID' ],
	[ [ 'hours_month' => '2000-13' ], 'Invalid recorded-hours month' ],
	[ [ 'unit' => 'invalid' ], 'Invalid budget display unit' ],
] as [ $fields, $expected_error ] ) {
	try {
		$export_document( $fields );
		throw new RuntimeException( 'Invalid export request was accepted' );
	} catch ( RuntimeException $error ) {
		expect_gripp( str_contains( $error->getMessage(), $expected_error ), 'Reject invalid export nonces, project IDs, months and units before generating a download' );
	}
}
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses'] = [ 'project.get' => [ gripp_response( [], 403 ) ] ];
try {
	$export_document();
	throw new RuntimeException( 'Failed API export was accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( str_contains( $error->getMessage(), 'HTTP 403' ) && false === get_transient( 'stuh_gripp_active_orders' ), 'Surface API failures explicitly rather than downloading a successful-looking empty or partial document' );
}
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected export responses' );
unset( $GLOBALS['entity_responses'], $GLOBALS['capabilities'] );
$GLOBALS['transients']['stuh_gripp_active_orders'] = $export_cache;
$GLOBALS['clients'] = [
	[ 'id' => 'site-one', 'site_url' => 'https://one.example/?x=<script>', 'api_key' => 'never-render-client-credential' ],
	[ 'id' => 'site-two', 'site_url' => 'https://two.example', 'enabled' => false ],
];
$site_key = 'stuh_fmp_project_sites_1';
$site_fields = [ 'project_id' => '1', 'offset' => '250', 'unit' => 'eur', 'client_ids' => [ 'site-two', 'site-one', 'site-two' ] ];
$GLOBALS['capabilities'] = [ 'manage_options' ];
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [ [ 'id' => 1 ] ] ) ];
[ $site_redirect, $site_notice ] = gripp_action( 'save_project_sites', $site_fields );
expect_gripp( [ 'site-two', 'site-one' ] === get_option( $site_key ) && false === $GLOBALS['autoload'][ $site_key ] && ! $site_notice['error'] && str_contains( $site_redirect, 'project_id=1' ) && str_contains( $site_redirect, 'project_tab=settings' ) && str_contains( $site_redirect, 'offset=250' ), 'Administrators can persist multiple registered sites per umbrella project, deduplicate selections without autoloading, and return to that project settings tab' );
expect_gripp( $export_cache === get_transient( 'stuh_gripp_active_orders' ) && false === get_option( 'stuh_fmp_project_sites_2' ), 'Site associations are isolated per umbrella project without changing hours or report caches' );
$GLOBALS['transients']['stuh_gripp_projects'] = $original_cache;
$settings_request_count = count( $GLOBALS['requests'] );
$project_settings_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'settings' );
expect_gripp( str_contains( $project_settings_html, 'nav-tab nav-tab-active' ) && str_contains( $project_settings_html, '>Settings</a>' ) && str_contains( $project_settings_html, 'value="site-one" checked' ) && str_contains( $project_settings_html, 'value="site-two" checked' ) && str_contains( $project_settings_html, '&lt;script&gt;' ) && ! str_contains( $project_settings_html, '<script>' ) && ! str_contains( $project_settings_html, 'never-render-client-credential' ) && str_contains( $project_settings_html, 'name="operation" value="save_project_sites"' ) && str_contains( $project_settings_html, 'name="_wpnonce" value="valid"' ), 'The admin-only Settings tab offers checked registered-site choices, including disabled sites, without exposing credentials or unescaped labels' );
expect_gripp( ! str_contains( $project_settings_html, 'id="stuh-fmp-active-projects"' ) && ! str_contains( $project_settings_html, 'data-stuh-fmp-chart' ) && count( $GLOBALS['requests'] ) === $settings_request_count, 'Settings replace the overview without loading hour or chart data when the project is cached' );
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [ [ 'id' => 1 ] ] ) ];
gripp_action( 'save_project_sites', $site_fields );
expect_gripp( [ 'site-two', 'site-one' ] === get_option( $site_key ), 'Saving an unchanged site selection succeeds without treating WordPress unchanged-option results as storage errors' );
$GLOBALS['clients'] = [ $GLOBALS['clients'][0] ];
$removed_site_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'settings' );
expect_gripp( str_contains( $removed_site_html, 'Some linked client sites have been removed' ) && ! str_contains( $removed_site_html, 'value="site-two"' ), 'Removed sites are flagged rather than silently presented as valid selections' );
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [ [ 'id' => 1 ] ] ) ];
gripp_action( 'save_project_sites', array_diff_key( $site_fields, [ 'client_ids' => true ] ) );
expect_gripp( [] === get_option( $site_key ), 'Submitting no checked sites clears associations, including links to removed clients' );
foreach ( [
	[ [ 'client_ids' => [ 'missing-site' ] ], 'no longer exists' ],
	[ [ 'client_ids' => 'site-one' ], 'Invalid client-site selection' ],
	[ [ 'client_ids' => [ [ 'site-one' ] ] ], 'no longer exists' ],
	[ [ 'project_id' => null ], 'Select a Gripp umbrella project' ],
	[ [ 'project_id' => '0' ], 'Invalid Gripp project ID' ],
	[ [ '_wpnonce' => 'invalid' ], 'Invalid nonce' ],
] as [ $invalid_fields, $expected_error ] ) {
	try {
		gripp_action( 'save_project_sites', array_merge( $site_fields, $invalid_fields ) );
		throw new RuntimeException( 'Invalid site-link request succeeded' );
	} catch ( RuntimeException $error ) {
		expect_gripp( str_contains( $error->getMessage(), $expected_error ) && [] === get_option( $site_key ), 'Reject invalid site IDs, project IDs, arrays and nonces without changing associations' );
	}
}
$valid_site_fields = array_merge( $site_fields, [ 'client_ids' => [ 'site-one' ] ] );
foreach ( [
	[ project_response( [] ), 'not found' ],
	[ project_response( [ [ 'id' => 2 ] ] ), 'not found' ],
	[ gripp_response( [], 403 ), 'HTTP 403' ],
] as [ $project_response, $expected_error ] ) {
	$GLOBALS['entity_responses']['umbrellaproject.get'] = [ $project_response ];
	try {
		gripp_action( 'save_project_sites', $valid_site_fields );
		throw new RuntimeException( 'Site links saved for an inaccessible project' );
	} catch ( RuntimeException $error ) {
		expect_gripp( str_contains( $error->getMessage(), $expected_error ) && [] === get_option( $site_key ), 'Validate project existence and access against Gripp before persisting associations, surfacing API failures' );
	}
}
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [ [ 'id' => 1 ] ] ) ];
$GLOBALS['storage_fail'] = true;
try {
	gripp_action( 'save_project_sites', $valid_site_fields );
	throw new RuntimeException( 'Failed link storage was accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( str_contains( $error->getMessage(), 'Could not save' ) && [] === get_option( $site_key ), 'A failed association save must not report success' );
} finally {
	unset( $GLOBALS['storage_fail'] );
}
foreach ( [ [ 'edit_others_posts' ], [ 'read', 'edit_posts' ], [ 'read' ] ] as $capabilities ) {
	$GLOBALS['capabilities'] = $capabilities;
	foreach ( [ 'view', 'save' ] as $attempt ) {
		try {
			if ( 'view' === $attempt ) {
				gripp_render( 'render_dashboard', 0, 'eur', 1, 'settings' );
			} else {
				gripp_action( 'save_project_sites', $valid_site_fields );
			}
			throw new RuntimeException( 'Non-admin accessed project settings' );
		} catch ( RuntimeException $error ) {
			expect_gripp( 'Insufficient permissions' === $error->getMessage() && [] === get_option( $site_key ), 'Non-admins cannot open project settings through a direct URL or submit site associations' );
		}
	}
}
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
$editor_project_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'reports' );
expect_gripp( str_contains( $editor_project_html, 'id="stuh-fmp-active-projects"' ) && str_contains( $editor_project_html, '>Monthly reports</a>' ) && ! str_contains( $editor_project_html, 'project_tab=settings' ) && ! str_contains( $editor_project_html, 'client_ids[]' ) && ! str_contains( $editor_project_html, 'data-stuh-fmp-chart=' ), 'Editors can open Monthly reports without seeing Settings, site-link controls or the Overview chart' );
$GLOBALS['capabilities'] = [ 'manage_options' ];
$admin_project_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'reports' );
expect_gripp( str_contains( $admin_project_html, 'project_tab=settings' ) && str_contains( $admin_project_html, 'id="stuh-fmp-active-projects"' ), 'Administrators can navigate from the existing overview to project-specific Settings' );
$tab_document = new DOMDocument();
$xml_errors = libxml_use_internal_errors( true );
$tab_document->loadHTML( $admin_project_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$tab_xpath = new DOMXPath( $tab_document );
$tab_labels = [];
foreach ( $tab_xpath->query( '//nav/a' ) as $tab_link ) {
	$tab_labels[] = $tab_link->textContent;
}
expect_gripp( [ 'Overview', 'Monthly reports', 'Settings' ] === $tab_labels && 'Monthly reports' === $tab_xpath->query( '//nav/a[@aria-current="page"]' )->item( 0 )->textContent && 1 === $tab_xpath->query( '//form[@method="get"]//input[@name="project_tab" and @value="reports"]' )->length, 'Order administrator tabs as Overview, Monthly reports, Settings, mark the selected tab, and keep calendar-month submissions on Reports' );
expect_gripp( ! str_contains( $admin_project_html, 'class="stuh-fmp-summary"' ) && ! str_contains( $admin_project_html, 'data-stuh-fmp-chart=' ) && str_contains( $admin_project_html, 'data-stuh-fmp-word-preview' ), 'Monthly reports contains its Word preview and filters, not duplicate Overview budget cards or charts' );
$_GET = [ 'project_id' => '1', 'project_tab' => 'settings' ];
$settings_script_count = count( $GLOBALS['enqueued_scripts'] );
STUH_Gripp::enqueue_assets( 'updater-host_page_stuh-fmp' );
$_GET = [];
expect_gripp( $settings_script_count === count( $GLOBALS['enqueued_scripts'] ), 'Project Settings does not enqueue chart or rich-copy scripts' );
foreach ( [ [ 'read' ], [ 'read', 'edit_posts' ] ] as $capabilities ) {
	$GLOBALS['capabilities'] = $capabilities;
	try {
		gripp_render( 'render_dashboard', 0, 'eur', 1, 'reports' );
		throw new RuntimeException( 'Lower-privilege monthly report access succeeded' );
	} catch ( RuntimeException $error ) {
		expect_gripp( 'Insufficient permissions' === $error->getMessage(), 'Authors and subscribers cannot directly open Monthly reports' );
	}
}
$GLOBALS['capabilities'] = [ 'manage_options' ];
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected project-settings responses' );
unset( $GLOBALS['capabilities'], $GLOBALS['entity_responses'], $GLOBALS['clients'] );
$GLOBALS['clients'] = [
	[ 'id' => 'site-one', 'site_url' => 'https://one.example/?x=<script>' ],
	[ 'id' => 'site-two', 'site_url' => 'https://two.example' ],
	[ 'id' => 'site-three', 'site_url' => 'https://waiting.example' ],
	[ 'id' => 'site-four', 'site_url' => 'https://empty.example' ],
	[ 'id' => 'unlinked', 'site_url' => 'https://unlinked.example' ],
];
$GLOBALS['options'][ $site_key ] = [ 'site-one', 'site-two', 'site-three', 'site-four', 'removed' ];
$GLOBALS['telemetry'] = [
	'site-one' => [ 'gravity_forms' => [ 'received_at' => time(), 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Contact <script>', 'months' => [ '1999-12' => 2, '2000-01' => 12, '2000-02' => 8 ] ],
		[ 'form_id' => 2, 'form_title' => 'Zero entries', 'months' => [ '2000-01' => 0 ] ],
		[ 'form_id' => 3, 'form_title' => 'New form', 'months' => [] ],
	] ] ],
	'site-two' => [ 'gravity_forms' => [ 'received_at' => time(), 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Contact <script>', 'months' => [ '2000-01' => 3, '2000-02' => 4 ] ],
	] ] ],
	'site-four' => [ 'gravity_forms' => [ 'received_at' => time(), 'forms' => [] ] ],
	'unlinked' => [ 'gravity_forms' => [ 'received_at' => time(), 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Unlinked private form', 'months' => [ '1998-06' => 999 ] ],
	] ] ],
	'removed' => [ 'gravity_forms' => [ 'received_at' => time(), 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Removed private form', 'months' => [ '1997-01' => 999 ] ],
	] ] ],
];
$forms_request_count = count( $GLOBALS['requests'] );
$forms_january_html = $render_monthly( '2000-01' );
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $forms_january_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$forms_xpath = new DOMXPath( $chart_document );
expect_gripp( 1 === $forms_xpath->query( '//table[@id="stuh-fmp-gravity-forms"]/following::div[@data-stuh-fmp-word-preview]' )->length && 1 === $forms_xpath->query( '//div[@data-stuh-fmp-word-preview]/following::button[@data-stuh-fmp-copy-word]' )->length, 'Keep the formatted preview and Copy for Word button below the Gravity Forms table' );
expect_gripp( 1 === $forms_xpath->query( '//select[@name="hours_month"]' )->length && 1 === $forms_xpath->query( '//select[@name="hours_month"]/option[@value="1999-12"]' )->length && 0 === $forms_xpath->query( '//select[@name="hours_month"]/option[@value="1998-06" or @value="1997-01"]' )->length && str_contains( $forms_january_html, '>Calendar month</label>' ), 'One shared calendar-month filter includes months reported only by linked forms, excluding unlinked and removed-site months' );
expect_gripp( '12' === $forms_xpath->query( '//table[@id="stuh-fmp-gravity-forms"]/tbody/tr[1]/td[2]' )->item( 0 )->textContent && '0' === $forms_xpath->query( '//table[@id="stuh-fmp-gravity-forms"]/tbody/tr[2]/td[2]' )->item( 0 )->textContent && 'Not reported' === $forms_xpath->query( '//table[@id="stuh-fmp-gravity-forms"]/tbody/tr[3]/td[2]' )->item( 0 )->textContent && '3' === $forms_xpath->query( '//table[@id="stuh-fmp-gravity-forms"]/tbody/tr[4]/td[2]' )->item( 0 )->textContent, 'Monthly form counts distinguish explicit zero from missing data and keep identical form titles/IDs separate per client site' );
expect_gripp( str_contains( $forms_january_html, '&lt;script&gt;' ) && ! str_contains( $forms_january_html, '<script>' ) && ! str_contains( $forms_january_html, 'Unlinked private form' ) && ! str_contains( $forms_january_html, 'Removed private form' ) && str_contains( $forms_january_html, 'No Gravity Forms report received yet.' ) && str_contains( $forms_january_html, 'No forms reported.' ) && str_contains( $forms_january_html, 'Client site no longer exists.' ), 'Escape site names and form titles, isolate linked-site reports, and explicitly distinguish waiting, empty and removed sites' );
expect_gripp( str_contains( $forms_january_html, 'Multi-month project' ) && str_contains( $forms_january_html, '1.88 h' ) && ! str_contains( $forms_january_html, 'February only' ), 'The same month selection filters active-project rows and totals alongside form counts' );
$forms_february_html = $render_monthly( '2000-02' );
expect_gripp( str_contains( $forms_february_html, '</th><td>8</td>' ) && str_contains( $forms_february_html, '</th><td>4</td>' ) && str_contains( $forms_february_html, 'February only' ) && str_contains( $forms_february_html, '5.00 h' ), 'Changing the shared month changes both form-entry counts and project-hour data' );
$forms_only_html = $render_monthly( '1999-12' );
expect_gripp( str_contains( $forms_only_html, '</th><td>2</td>' ) && str_contains( $forms_only_html, 'No active projects have recorded time in this month.' ) && str_contains( $forms_only_html, 'Not reported' ), 'A form-only month remains selectable and renders entries even with no recorded project hours' );
$forms_all_html = $render_monthly( '' );
expect_gripp( str_contains( $forms_all_html, '</th><td>22</td>' ) && str_contains( $forms_all_html, '</th><td>7</td>' ) && str_contains( $forms_all_html, '13.88 h' ) && $forms_request_count === count( $GLOBALS['requests'] ), 'All months restores hours and sums each form history independently, without additional Gripp or client-site requests' );
$grouped_forms_export = $export_document();
expect_gripp( str_contains( $forms_january_html, 'data-stuh-fmp-copy-word hidden' ) && str_contains( $forms_january_html, 'aria-label="Formatted report for Word"' ) && str_contains( $forms_january_html, 'data-stuh-fmp-copy-status' ) && str_contains( $grouped_forms_export['html'], 'https://one.example/?x=&lt;script&gt;' ) && ! str_contains( $grouped_forms_export['html'], '<script>' ) && 1 === substr_count( $grouped_forms_export['html'], 'https://one.example/' ) && str_contains( $grouped_forms_export['html'], 'Contact &lt;script&gt;' ), 'Provide accessible rich-copy controls and an escaped, site-grouped formatted report alongside the plain-text preview' );
expect_gripp( strpos( $grouped_forms_export['text'], 'Active projects' ) < strpos( $grouped_forms_export['text'], 'Uren begin van de maand' ) && strpos( $grouped_forms_export['text'], 'Uren eind van de maand' ) < strpos( $grouped_forms_export['text'], "\nGravity Forms\n" ) && 1 === substr_count( $grouped_forms_export['text'], 'Uren begin van de maand' ) && ! str_contains( $grouped_forms_export['text'], 'Urenoverzicht' ) && ! str_contains( $grouped_forms_export['html'], 'Urenoverzicht' ), 'Keep the four summary rows once between active projects and Gravity Forms, without the removed heading in plain or formatted exports' );
expect_gripp( $grouped_forms_export['text'] === $preview_value( $forms_january_html ) && str_contains( $grouped_forms_export['text'], "\nGravity Forms\n\nhttps://one.example/?x=<script>\n\tForm\tEntries\n\tContact <script>\t12\n\tZero entries\t0\n\tNew form\tNot reported\n" ) && str_contains( $grouped_forms_export['text'], "\nhttps://two.example\n\tForm\tEntries\n\tContact <script>\t3\n" ), 'The preview and download include month-filtered form counts grouped by site, keeping same-title forms separate and distinguishing zeros from unreported months' );
expect_gripp( 1 === substr_count( $grouped_forms_export['text'], 'https://one.example/' ) && 1 === substr_count( $grouped_forms_export['text'], 'https://two.example' ) && ! str_contains( $grouped_forms_export['text'], 'Unlinked private form' ) && ! str_contains( $grouped_forms_export['text'], 'Removed private form' ) && ! str_contains( $grouped_forms_export['text'], 'https://unlinked.example' ), 'Export each linked site URL once as a heading, not on every form row, without including unlinked or removed-site data' );
expect_gripp( str_contains( $grouped_forms_export['text'], "https://waiting.example\n\tNo Gravity Forms report received yet." ) && str_contains( $grouped_forms_export['text'], "https://empty.example\n\tNo forms reported." ) && str_contains( $grouped_forms_export['text'], "Removed client site\n\tClient site no longer exists." ), 'Grouped exports retain explicit waiting, empty and removed-site statuses instead of fabricating entry counts' );
$hide_forms_source = [ 'project_id' => '1', 'offset' => '250', 'unit' => 'eur', 'hours_month' => '2000-01', 'hidden_forms' => [ 'site-one' => [ '2' ] ] ];
try {
	invoke_gripp( 'save_hidden_forms', $hide_forms_source );
	throw new RuntimeException( 'Saving hidden Gravity Forms did not redirect' );
} catch ( GrippRedirect $redirect ) {
	expect_gripp( str_contains( $redirect->getMessage(), 'project_tab=reports' ) && str_contains( $redirect->getMessage(), 'hours_month=2000-01' ), 'Saving hidden forms returns to the current project and month' );
}
$hidden_forms_html = $render_monthly( '2000-01' );
$hidden_forms_export = $export_document();
expect_gripp( str_contains( $hidden_forms_html, 'name="hidden_forms[site-one][]" value="2" checked' ) && str_contains( $hidden_forms_html, 'Zero entries' ) && ! str_contains( $hidden_forms_export['text'], 'Zero entries' ) && ! str_contains( $hidden_forms_export['html'], 'Zero entries' ) && str_contains( $hidden_forms_export['text'], "\tContact <script>\t12\n" ), 'Saved per-site form visibility hides a selected form only from both Word formats, not the counts table' );
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
$editor_hidden_html = $render_monthly( '2000-01' );
$editor_hidden_export = $export_document();
$editor_save_error = null;
$_POST = [ '_wpnonce' => 'valid', 'operation' => 'save_hidden_forms', 'project_id' => '1' ];
try {
	STUH_Gripp::handle_action();
} catch ( RuntimeException $error ) {
	$editor_save_error = $error->getMessage();
} finally {
	$_POST = [];
}
$GLOBALS['capabilities'] = [ 'manage_options' ];
expect_gripp( ! str_contains( $editor_hidden_html, 'name="hidden_forms[' ) && ! str_contains( $editor_hidden_export['text'], 'Zero entries' ) && 'Insufficient permissions' === $editor_save_error, 'Editors receive filtered Word output but cannot change administrator-managed visibility' );
$hide_forms_source['hidden_forms'] = [ 'site-one' => [ '1', '2', '3' ] ];
try {
	invoke_gripp( 'save_hidden_forms', $hide_forms_source );
	throw new RuntimeException( 'Saving hidden Gravity Forms did not redirect' );
} catch ( GrippRedirect $redirect ) {
	$all_site_one_hidden = $export_document();
	expect_gripp( ! str_contains( $all_site_one_hidden['text'], 'https://one.example/' ) && str_contains( $all_site_one_hidden['text'], "\nhttps://two.example\n\tForm\tEntries\n\tContact <script>\t3\n" ), 'Hiding every form omits that site from Word while the same form ID on another site remains visible' );
}
try {
	invoke_gripp( 'save_hidden_forms', array_merge( $hide_forms_source, [ 'hidden_forms' => [ 'site-one' => [ '999' ] ] ] ) );
	throw new RuntimeException( 'An unavailable form was accepted' );
} catch ( RuntimeException $error ) {
	expect_gripp( str_contains( $error->getMessage(), 'Gravity Form is no longer available' ), 'Reject attempts to hide forms outside the linked reports' );
}
try {
	invoke_gripp( 'save_hidden_forms', array_merge( $hide_forms_source, [ 'hidden_forms' => [] ] ) );
	throw new RuntimeException( 'Saving hidden Gravity Forms did not redirect' );
} catch ( GrippRedirect $redirect ) {
	expect_gripp( [] === get_option( 'stuh_fmp_hidden_forms_1', [] ), 'Saving with all forms visible clears the project hide settings' );
}
$grouped_forms_february = $export_document( [ 'hours_month' => '2000-02' ] );
expect_gripp( $grouped_forms_february['text'] === $preview_value( $forms_february_html ) && str_contains( $grouped_forms_february['text'], "\tContact <script>\t8\n" ) && str_contains( $grouped_forms_february['text'], "\tContact <script>\t4\n" ) && str_contains( $grouped_forms_february['text'], "Opdracht 2026001 Multi-month project\nWebdevelopment\t3,00\nProject Management\t2,00" ), 'Changing the shared month filters both exported hours and grouped form counts exactly as previewed' );
$matrix_document = new DOMDocument();
$xml_errors = libxml_use_internal_errors( true );
$matrix_document->loadHTML( $grouped_forms_february['html'] );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$matrix_xpath = new DOMXPath( $matrix_document );
$matrix_table = $matrix_xpath->query( '//table[thead/tr/th="Contact <script>"]' )->item( 0 );
$matrix_headers = [];
foreach ( $matrix_xpath->query( 'thead/tr/th', $matrix_table ) as $cell ) {
	$matrix_headers[] = $cell->textContent;
}
$matrix_rows = [];
foreach ( $matrix_xpath->query( 'tbody/tr', $matrix_table ) as $row ) {
	$cells = [];
	foreach ( $matrix_xpath->query( 'th|td', $row ) as $cell ) {
		$cells[] = $cell->textContent;
	}
	$matrix_rows[] = $cells;
}
expect_gripp( [ 'Maand', 'Contact <script>', 'Zero entries', 'New form', 'Totaal' ] === $matrix_headers && [
	[ '2000', '20', '0', '-', '20' ],
	[ 'FEB', '8', '-', '-', '8' ],
	[ 'JAN', '12', '0', '-', '12' ],
	[ '1999', '2', '-', '-', '2' ],
	[ 'DEC', '2', '-', '-', '2' ],
] === $matrix_rows, 'Word form matrices have one column per form, descending historical months, yearly subtotals and row totals, distinguishing missing data from explicit zero' );
expect_gripp( 5 === $matrix_xpath->query( 'tbody/tr[th/strong="FEB"]/*/strong', $matrix_table )->length && 0 === $matrix_xpath->query( 'tbody/tr[th="JAN"]/*/strong', $matrix_table )->length, 'Bold the selected report month label, all form counts including missing values, and total without bolding other months' );
$all_months_matrix = invoke_gripp( 'gravity_forms_word_matrix', [
	[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [ '2000-01' => 0, '2000-02' => 8, '1999-02' => 2 ] ],
], '', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
expect_gripp( ! str_contains( $all_months_matrix, '<strong>FEB</strong>' ) && ! str_contains( $all_months_matrix, '<strong>JAN</strong>' ), 'All months has no highlighted month, while annual subtotals keep their existing bold styling' );
expect_gripp( 2 === $matrix_xpath->query( '//table[thead/tr/th="Contact <script>"]' )->length && 2 === $matrix_xpath->query( 'tbody/tr/th[contains(@style,"color:#ff0054")]/strong', $matrix_table )->length && 3 === $matrix_xpath->query( 'tbody/tr/th[contains(@style,"background-color:#f2f2f2")]', $matrix_table )->length && 0 === $matrix_xpath->query( '//table[thead]//*[self::td or self::th][not(contains(@style,"font-family:Montserrat,Arial,sans-serif;")) or not(contains(@style,"font-size:10pt;"))]' )->length, 'Keep matrices separate by site with pink annual subtotals, alternating shading and Montserrat 10 pt on every Word table cell' );
$january_matrix_html = $grouped_forms_export['html'];
expect_gripp( ! str_contains( $january_matrix_html, '>FEB<' ) && str_contains( $january_matrix_html, '>DEC<' ) && ! str_contains( $january_matrix_html, 'Unlinked private form' ), 'Selected-month Word history excludes later months but retains previous years and does not include unlinked sites' );
$empty_matrix_html = invoke_gripp( 'gravity_forms_word_matrix', [ [ 'form_id' => 1, 'form_title' => 'Future only', 'months' => [ '2001-01' => 5 ] ] ], '2000-12', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
expect_gripp( str_contains( $empty_matrix_html, '<strong>DEC</strong>' ) && ! str_contains( $empty_matrix_html, '>5<' ) && 4 === substr_count( $empty_matrix_html, '<strong>-</strong>' ), 'Show the selected month even without earlier reports, using missing counts rather than future data or invented zeros' );
$gap_matrix_html = invoke_gripp( 'gravity_forms_word_matrix', [
	[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [ '2025-11' => 2, '2026-02' => 0, '2026-03' => 3, '2026-06' => 9 ] ],
], '2026-05', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
$gap_document = new DOMDocument();
$gap_document->loadHTML( $gap_matrix_html );
$gap_xpath = new DOMXPath( $gap_document );
$gap_rows = [];
foreach ( $gap_xpath->query( '//tbody/tr' ) as $row ) {
	$cells = [];
	foreach ( $gap_xpath->query( 'th|td', $row ) as $cell ) {
		$cells[] = $cell->textContent;
	}
	$gap_rows[] = $cells;
}
expect_gripp( [
	[ '2026', '3', '3' ], [ 'MEI', '-', '-' ], [ 'APR', '-', '-' ],
	[ 'MRT', '3', '3' ], [ 'FEB', '0', '0' ], [ 'JAN', '-', '-' ],
	[ '2025', '2', '2' ], [ 'DEC', '-', '-' ], [ 'NOV', '2', '2' ],
] === $gap_rows && 3 === $gap_xpath->query( '//tr[th/strong="MEI"]/*/strong' )->length, 'Fill every missing month across year boundaries through the selected month, preserve reported zero and annual totals, and bold the empty selected month' );
$all_gaps_html = invoke_gripp( 'gravity_forms_word_matrix', [
	[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [ '2026-01' => 1, '2026-03' => 2 ] ],
], '', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
expect_gripp( str_contains( $all_gaps_html, '>FEB<' ) && ! str_contains( $all_gaps_html, '>APR<' ), 'All months fills gaps between earliest and latest reported months without extending beyond the reported history' );
$overflow_matrix_html = invoke_gripp( 'gravity_forms_word_matrix', [
	[ 'form_id' => 1, 'form_title' => 'Same title', 'months' => [ '2000-01' => PHP_INT_MAX, '2000-02' => 1 ] ],
	[ 'form_id' => 2, 'form_title' => 'Same title', 'months' => [ '2000-01' => 1 ] ],
], '', 'font-family:Montserrat,Arial,sans-serif;font-size:10pt;' );
expect_gripp( 2 === substr_count( $overflow_matrix_html, '<strong>Same title</strong>' ) && 3 === substr_count( $overflow_matrix_html, 'Count is too large to display.' ), 'Same-title forms stay separate columns and monthly and annual overflow remain explicit rather than rounding or wrapping' );
$grouped_forms_all = $export_document( [ 'hours_month' => '' ] );
expect_gripp( $grouped_forms_all['text'] === $preview_value( $forms_all_html ) && str_contains( $grouped_forms_all['text'], "\tContact <script>\t22\n" ) && str_contains( $grouped_forms_all['text'], "\tContact <script>\t7\n" ), 'All months exports each form full reported total under its own site heading' );
$grouped_forms_only = $export_document( [ 'hours_month' => '1999-12' ] );
expect_gripp( $grouped_forms_only['text'] === $preview_value( $forms_only_html ) && str_contains( $grouped_forms_only['text'], "\tContact <script>\t2\n" ) && str_contains( $grouped_forms_only['text'], 'No active projects have recorded time in this month.' ) && $forms_request_count === count( $GLOBALS['requests'] ), 'Form-only months export correctly even when no active projects have time, without additional API requests' );
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
$editor_grouped_export = $export_document();
expect_gripp( $editor_grouped_export === $grouped_forms_export, 'Editors receive the same filtered site-grouped export as administrators' );
$editor_forms_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'reports' );
expect_gripp( str_contains( $editor_forms_html, 'id="stuh-fmp-gravity-forms"' ) && ! str_contains( $editor_forms_html, 'project_tab=settings' ), 'Linked Gravity Forms reports appear on the editor overview while site-link settings remain admin-only' );
$GLOBALS['capabilities'] = [ 'manage_options' ];
$forms_settings_html = gripp_render( 'render_dashboard', 0, 'eur', 1, 'settings' );
expect_gripp( ! str_contains( $forms_settings_html, 'id="stuh-fmp-gravity-forms"' ) && ! str_contains( $forms_settings_html, 'name="hours_month"' ), 'Settings do not render overview reports or a second calendar-month filter' );
$GLOBALS['options'][ $site_key ] = [];
expect_gripp( ! str_contains( $render_monthly( '' ), 'id="stuh-fmp-gravity-forms"' ), 'No linked sites means no Gravity Forms section even if other sites have saved reports' );
$GLOBALS['options'][ $site_key ] = [ 'site-one' ];
delete_transient( 'stuh_gripp_active_orders' );
$GLOBALS['entity_responses'] = [ 'project.get' => [ gripp_response( [], 403 ) ] ];
$forms_with_hours_error = $render_monthly( '2000-01' );
expect_gripp( str_contains( $forms_with_hours_error, 'HTTP 403' ) && ! str_contains( $forms_with_hours_error, 'id="stuh-fmp-active-projects"' ) && ! str_contains( $forms_with_hours_error, 'id="stuh-fmp-export-preview"' ) && ! str_contains( $forms_with_hours_error, '>Export TXT</button>' ) && str_contains( $forms_with_hours_error, 'id="stuh-fmp-gravity-forms"' ) && str_contains( $forms_with_hours_error, '</th><td>12</td>' ) && str_contains( $forms_with_hours_error, 'value="1999-12"' ), 'Gripp failures remain explicit without offering a misleading successful preview/download or suppressing independent saved form reports' );
$GLOBALS['transients']['stuh_gripp_active_orders'] = $export_cache;
$GLOBALS['telemetry']['site-one']['gravity_forms']['forms'] = [
	[ 'form_id' => 1, 'form_title' => 'Large totals', 'months' => [ '2000-01' => PHP_INT_MAX, '2000-02' => 1 ] ],
];
expect_gripp( str_contains( $render_monthly( '' ), 'Count is too large to display.' ), 'Overflowing entry totals are explicitly unavailable rather than displaying a rounded or invalid count' );
expect_gripp( str_contains( $export_document( [ 'hours_month' => '' ] )['text'], "\tLarge totals\tCount is too large to display." ), 'Export count overflow uses the same explicit status as the table and preview' );
$GLOBALS['clients'][0]['site_url'] = "https://one.example/\tpath\nname";
$GLOBALS['telemetry']['site-one']['gravity_forms']['forms'] = [
	[ 'form_id' => 1, 'form_title' => "Contact\tteam\n</textarea><script>alert(1)</script>", 'months' => [ '2000-01' => 5 ] ],
];
$grouped_unsafe_html = $render_monthly( '2000-01' );
$grouped_unsafe_export = $export_document();
expect_gripp( $grouped_unsafe_export['text'] === $preview_value( $grouped_unsafe_html ) && str_contains( $grouped_unsafe_export['text'], "\nhttps://one.example/ path name\n" ) && str_contains( $grouped_unsafe_export['text'], "\tContact team </textarea><script>alert(1)</script>\t5\n" ) && ! str_contains( $grouped_unsafe_html, '<script>' ), 'Normalize line breaks/tabs in site and form labels, and escape dangerous markup in the matching textarea preview' );
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected shared-report responses' );
unset( $GLOBALS['capabilities'], $GLOBALS['entity_responses'], $GLOBALS['clients'], $GLOBALS['telemetry'] );
$GLOBALS['options'][ $site_key ] = [];
$balance_project = [ 'budget' => 1728000, 'startdate' => '2026-01-01', 'deadline' => '2026-12-31', 'used' => 0 ];
$balance_history = [ '2025-12-31' => 122.26, '2026-09-01' => 1.0, '2026-09-02' => 0.5, '2026-09-03' => 1.0, '2026-09-04' => 4.25, '2026-09-05' => 1.08, '2027-01-01' => 100.0 ];
$balance_today = new DateTimeImmutable( '2026-11-19', wp_timezone() );
$september_balance = invoke_gripp( 'calculate_monthly_balance', $balance_project, $balance_history, '2026-09', $balance_today );
expect_gripp( abs( $september_balance['opening'] - 5.74 ) < 0.000001 && 16.0 === $september_balance['allowance'] && abs( $september_balance['worked'] - 7.83 ) < 0.000001 && abs( $september_balance['closing'] - 13.91 ) < 0.000001, 'Calculate the example opening, allowance, worked and closing values from the actual budget and full history, including pre-start hours and excluding future time' );
foreach ( [ 100.0, 125.0 ] as $earlier_hours ) {
	$carry_history = [ '2026-07-31' => $earlier_hours, '2026-08-31' => 20.0, '2026-09-05' => 7.83 ];
	$carry_today = new DateTimeImmutable( '2026-09-10', wp_timezone() );
	$previous_balance = invoke_gripp( 'calculate_monthly_balance', $balance_project, $carry_history, '2026-08', $carry_today );
	$current_balance = invoke_gripp( 'calculate_monthly_balance', $balance_project, $carry_history, '2026-09', $carry_today );
	$previous_schedule = invoke_gripp( 'budget_schedule', $balance_project, new DateTimeImmutable( '2026-08-31', wp_timezone() ) );
	$previous_real_left = $previous_schedule['planned'] / 9000.0 - $earlier_hours - 20.0;
	expect_gripp( abs( $current_balance['opening'] - $previous_real_left ) < 0.000001 && abs( $current_balance['opening'] - $previous_balance['closing'] ) < 0.000001 && 16.0 === $current_balance['allowance'] && abs( $current_balance['worked'] - 7.83 ) < 0.000001 && abs( $current_balance['closing'] - ( $previous_real_left + 16.0 - 7.83 ) ) < 0.000001, 'Carry positive or negative previous-month Real budget left to date into opening hours, then add the full regular monthly allowance and subtract this month actual hours even mid-month' );
}
$GLOBALS['entity_responses'] = [
	'project.get' => [ project_response( [
		[ 'id' => 1001, 'umbrellaproject' => 1, 'totalexclvat' => '900.00' ],
	] ) ],
	'hour.get' => [ project_response( [
		[ 'id' => 1, 'offerprojectbase' => 1001, 'offerprojectline' => 11, 'amount' => 2.5, 'date' => '2000-01-01' ],
		[ 'id' => 2, 'offerprojectbase' => 1001, 'offerprojectline' => 12, 'amount' => 10, 'date' => '2000-01-01' ],
		[ 'id' => 3, 'offerprojectbase' => 1001, 'amount' => 0.5, 'date' => '2000-01-01' ],
	] ) ],
	'offerprojectline.get' => [ project_response( [
		[ 'id' => 11, 'offerprojectbase' => 1001, 'product' => [ 'id' => 21, 'searchname' => 'Webdevelopment (intern)' ] ],
		[ 'id' => 12, 'offerprojectbase' => 1001, 'product' => [ 'id' => 22, 'searchname' => 'Webdevelopment (ND / intern)' ] ],
	] ) ],
];
$dashboard_recorded = [];
$dashboard_totals = ( new ReflectionMethod( STUH_Gripp::class, 'order_totals' ) )->invokeArgs( null, [ 'test-token', [ 1 ], &$dashboard_recorded ] );
expect_gripp( [ 1 => 90000 ] === $dashboard_totals && [ 1 => 27000 ] === $dashboard_recorded, 'Dashboard spent hours exclude only the ND / intern marker, keep other labels and no-product time, and leave committed order values unchanged' );
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Dashboard product-aware hours consume all expected responses' );
unset( $GLOBALS['entity_responses'] );
$layout_orders = [
	[ 'number' => '16780', 'name' => "FMP '26 - September", 'products' => [ [ 'name' => 'Webdevelopment', 'hours' => 1.0 ] ] ],
	[ 'number' => '16780', 'name' => "FMP '26 - Oktober", 'products' => [ [ 'name' => 'Projectmanagement', 'hours' => 0.5 ], [ 'name' => 'Online marketing', 'hours' => 1.0 ], [ 'name' => 'Webdevelopment', 'hours' => 4.25 ] ] ],
	[ 'number' => '16715', 'name' => 'Online marketing - Google Ads', 'products' => [ [ 'name' => 'Online marketing', 'hours' => 1.08 ] ] ],
];
foreach ( $layout_orders as &$layout_order ) {
	$layout_order['months'] = [ '2026-09' => [ 'hours' => array_sum( array_column( $layout_order['products'], 'hours' ) ), 'products' => $layout_order['products'] ] ];
}
unset( $layout_order );
$layout_export = invoke_gripp( 'format_monthly_export', $layout_orders, [], 1, '2026-09', $september_balance );
$rich_document = new DOMDocument();
$rich_document->loadHTML( $layout_export['html'] );
$rich_xpath = new DOMXPath( $rich_document );
expect_gripp( 1 === $rich_xpath->query( '//p[text()="Onderstaan een overzicht van de verrichte werkzaamheden."]/following-sibling::p[starts-with(strong,"Opdracht ")][1]' )->length && ! str_contains( $layout_export['text'], 'Onderstaan een overzicht' ), 'Include the requested introduction above the project list in Word content only' );
expect_gripp( 0 === $rich_xpath->query( '//p[not(contains(@style,"font-family:Montserrat,Arial,sans-serif;")) or not(contains(@style,"font-size:10pt;"))] | //td[not(contains(@style,"font-family:Montserrat,Arial,sans-serif;")) or not(contains(@style,"font-size:10pt;"))]' )->length && 3 === $rich_xpath->query( '//p[starts-with(strong,"Opdracht ")]/preceding-sibling::*[1][self::p and br]' )->length && 1 === $rich_xpath->query( '//div[@style="margin-top:24px;"]/preceding-sibling::*[1][self::p and br]' )->length, 'Use Montserrat 10 pt on all Word paragraphs/cells and explicit blank paragraphs before every order and the summary' );
expect_gripp( 3 === $rich_xpath->query( '//p[contains(@style,"color:#ff0054")]/strong' )->length && 1 === $rich_xpath->query( '//td[contains(@style,"color:#ff0054")]/strong[text()="Uren eind van de maand"]' )->length && 1 === $rich_xpath->query( '//td[@align="right" and contains(@style,"color:#ff0054")]/strong[text()="13,91"]' )->length && 1 === $rich_xpath->query( '//td[@align="right"]/strong[text()="7,83"]' )->length && 1 === $rich_xpath->query( '//td[@align="right" and text()="4,25"]' )->length, 'Render pink bold order headings, a bold hours summary, a pink closing balance and aligned unchanged numeric values using Word-friendly inline styles' );
expect_gripp( str_contains( $layout_export['text'], "Opdracht 16780 FMP '26 - September\nWebdevelopment\t1,00\n\nOpdracht 16780 FMP '26 - Oktober\nProjectmanagement\t0,50\nOnline marketing\t1,00\nWebdevelopment\t4,25\n\nOpdracht 16715 Online marketing - Google Ads\nOnline marketing\t1,08\n" ) && str_ends_with( $layout_export['text'], "Uren begin van de maand\t5,74\nBeschikbare uren in de periode\t16,00\nTotaal gewerkt\t7,83\nUren eind van de maand\t13,91\n" ), 'Match the screenshot order/product layout and four accurately calculated summary lines, using decimal commas and putting the summary at the very bottom' );
$partial_balance = invoke_gripp( 'calculate_monthly_balance', array_merge( $balance_project, [ 'budget' => 90000, 'startdate' => '2026-01-16', 'deadline' => '2026-02-15' ] ), [ '2026-01-31' => 2.625, '2026-02-01' => 50.0 ], '2026-01', $balance_today );
$partial_allowance = round( 90000 * ( 16 / 31 ) / ( 16 / 31 + 15 / 28 ) ) / 9000;
expect_gripp( 0.0 === $partial_balance['opening'] && abs( $partial_balance['allowance'] - $partial_allowance ) < 0.000001 && 2.625 === $partial_balance['worked'] && abs( $partial_balance['closing'] - ( $partial_allowance - 2.625 ) ) < 0.000001, 'Prorate a partial starting month by the existing budget schedule and keep fractional hours unrounded across calendar boundaries' );
$all_balance = invoke_gripp( 'calculate_monthly_balance', $balance_project, $balance_history, '', new DateTimeImmutable( '2026-09-10', wp_timezone() ) );
expect_gripp( 0.0 === $all_balance['opening'] && abs( $all_balance['worked'] - 130.09 ) < 0.000001 && abs( $all_balance['allowance'] - round( 1728000 * ( 8 + 10 / 30 ) / 12 ) / 9000 ) < 0.000001 && abs( $all_balance['closing'] - ( $all_balance['allowance'] - 130.09 ) ) < 0.000001, 'All months uses allowance accrued through today and all actual hours, not the full future annual budget or future time entries' );
$credit_balance = invoke_gripp( 'calculate_monthly_balance', array_merge( $balance_project, [ 'budget' => 0 ] ), [ '2026-08-31' => 2.0, '2026-09-01' => -0.5 ], '2026-09', $balance_today );
expect_gripp( -2.0 === $credit_balance['opening'] && 0.0 === $credit_balance['allowance'] && -0.5 === $credit_balance['worked'] && -1.5 === $credit_balance['closing'], 'Zero budgets and negative time corrections retain their real balances without silent clamping' );
$after_deadline = invoke_gripp( 'calculate_monthly_balance', $balance_project, [ '2027-01-01' => 2.0 ], '2027-01', new DateTimeImmutable( '2027-02-01', wp_timezone() ) );
expect_gripp( 192.0 === $after_deadline['opening'] && 0.0 === $after_deadline['allowance'] && 2.0 === $after_deadline['worked'] && 190.0 === $after_deadline['closing'], 'Stop allocating budget at the deadline while still deducting hours logged afterwards' );
foreach ( [ [ 'budget' => null ], [ 'startdate' => '' ], [ 'deadline' => '2025-01-01' ] ] as $invalid_balance_project ) {
	expect_gripp( is_wp_error( invoke_gripp( 'calculate_monthly_balance', array_merge( $balance_project, $invalid_balance_project ), [], '2026-09', $balance_today ) ), 'Missing budgets, missing dates and invalid date ranges cannot generate invented balances' );
}
$GLOBALS['transients']['stuh_gripp_balance'] = array_merge( gripp_balance_cache(), [ 'resource' => 'umbrellaproject-budget-hours-active-v3' ] );
$GLOBALS['entity_responses'] = [
	'umbrellaproject.get' => [ project_response( [ [ 'id' => 1, 'budget' => '17280.00', 'startdate' => [ 'date' => '2026-01-01 00:00:00.000000' ], 'deadline' => '2026-12-31' ] ] ) ],
	'project.get' => [ project_response( [
		[ 'id' => 1001, 'umbrellaproject' => 1, 'archived' => false, 'totalexclvat' => '900.00' ],
		[ 'id' => 1002, 'umbrellaproject' => [ 'id' => 1 ], 'archived' => true, 'totalexclvat' => '0.00' ],
	] ) ],
	'hour.get' => [ project_response( [
		[ 'id' => 1, 'offerprojectbase' => 1002, 'amount' => 122.26, 'date' => '2025-12-31' ],
		[ 'id' => 2, 'offerprojectbase' => 1001, 'amount' => 6.75, 'date' => '2026-09-01', 'status' => [ 'searchname' => 'Concept' ] ],
		[ 'id' => 3, 'offerprojectbase' => 1002, 'amount' => 1.58, 'date' => '2026-09-02' ],
		[ 'id' => 4, 'offerprojectbase' => 1002, 'amount' => -0.5, 'date' => '2026-09-03' ],
		[ 'id' => 5, 'offerprojectbase' => 1002, 'amount' => 100, 'date' => '3000-01-01' ],
		[ 'id' => 6, 'offerprojectbase' => 1002, 'offerprojectline' => 901, 'amount' => 10, 'date' => '2025-12-30' ],
		[ 'id' => 7, 'offerprojectbase' => 1002, 'offerprojectline' => 901, 'amount' => 20, 'date' => '2026-09-02' ],
		[ 'id' => 8, 'offerprojectbase' => 1002, 'offerprojectline' => 901, 'amount' => -1, 'date' => '2026-09-03' ],
	] ) ],
	'offerprojectline.get' => [ project_response( [
		[ 'id' => 901, 'offerprojectbase' => 1002, 'product' => [ 'id' => 902, 'searchname' => 'Webdevelopment (ND / intern)' ] ],
	] ) ],
];
$balance_request_start = count( $GLOBALS['requests'] );
$loaded_balance = invoke_gripp( 'monthly_balance', 'test-token', 1, '2026-09' );
expect_gripp( abs( $loaded_balance['opening'] - 5.74 ) < 0.000001 && abs( $loaded_balance['worked'] - 7.83 ) < 0.000001 && abs( $loaded_balance['closing'] - 13.91 ) < 0.000001, 'Invalidate old balance caches and exclude internal hours and corrections from both historical carry-over and this month, including archived orders' );
$balance_order_query = json_decode( $GLOBALS['requests'][ $balance_request_start + 1 ][1]['body'], true )[0];
expect_gripp( [ [ 'field' => 'project.umbrellaproject', 'operator' => 'equals', 'value' => 1 ] ] === $balance_order_query['params'][0] && 4 === count( $GLOBALS['requests'] ) - $balance_request_start, 'Balance reads include archived orders and resolve products to exclude internal time, without requiring invoice permissions' );
$balance_cached_count = count( $GLOBALS['requests'] );
invoke_gripp( 'monthly_balance', 'test-token', 1, '2026-10' );
expect_gripp( $balance_cached_count === count( $GLOBALS['requests'] ), 'Changing the selected month reuses the full balance history cache' );
$GLOBALS['capabilities'] = [ 'edit_others_posts' ];
$september_export = $export_document( [ 'hours_month' => '2026-09' ] );
expect_gripp( str_ends_with( $september_export['text'], "Uren begin van de maand\t5,74\nBeschikbare uren in de periode\t16,00\nTotaal gewerkt\t7,83\nUren eind van de maand\t13,91\n" ) && $september_export['text'] === $preview_value( $render_monthly( '2026-09' ) ), 'The authenticated download and read-only preview share the accurately loaded full-retainer summary even when the active-only table has no time in that month' );
$GLOBALS['transients']['stuh_gripp_balance']['connection'] = 'another-connection';
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ gripp_response( [], 403 ) ];
expect_gripp( is_wp_error( invoke_gripp( 'monthly_balance', 'test-token', 1, '2026-09' ) ), 'Another connection cannot reuse a cached budget or historical hours balance' );
delete_transient( 'stuh_gripp_balance' );
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [ [ 'id' => 1, 'budget' => '17280.00', 'startdate' => '2026-01-01', 'deadline' => '2026-12-31' ] ] ) ];
$GLOBALS['entity_responses']['project.get'] = [ project_response( [ [ 'id' => 1001, 'umbrellaproject' => 1 ] ] ) ];
$GLOBALS['entity_responses']['hour.get'] = [ gripp_response( [], 403 ) ];
try {
	$export_document( [ 'hours_month' => '2026-09' ] );
	throw new RuntimeException( 'Export accepted a failed balance request' );
} catch ( RuntimeException $error ) {
	expect_gripp( str_contains( $error->getMessage(), 'HTTP 403' ) && false === get_transient( 'stuh_gripp_balance' ), 'Summary API failures block misleading downloads and do not cache partial history' );
}
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ gripp_response( [], 403 ) ];
$failed_summary_html = $render_monthly( '2026-09' );
expect_gripp( str_contains( $failed_summary_html, 'HTTP 403' ) && ! str_contains( $failed_summary_html, 'id="stuh-fmp-export-preview"' ) && ! str_contains( $failed_summary_html, '>Export TXT</button>' ), 'Preview failures are explicit and cannot expose a fabricated zero balance' );
$GLOBALS['transients']['stuh_gripp_balance'] = gripp_balance_cache();
$GLOBALS['entity_responses']['umbrellaproject.get'] = [ project_response( [] ) ];
gripp_action( 'refresh' );
expect_gripp( false === get_transient( 'stuh_gripp_balance' ), 'Refresh projects invalidates the historical balance cache alongside the other Gripp caches' );
expect_gripp( ! array_filter( $GLOBALS['entity_responses'] ), 'Consume all expected balance responses' );
unset( $GLOBALS['entity_responses'], $GLOBALS['capabilities'] );
expect_gripp( ! $GLOBALS['responses'] && ! $GLOBALS['order_responses'], 'All expected API responses were consumed' );
$GLOBALS['clients'] = [
	[ 'id' => 'overlay-one', 'site_url' => 'https://one.example' ],
	[ 'id' => 'overlay-two', 'site_url' => 'https://two.example' ],
];
$GLOBALS['options']['stuh_fmp_project_sites_99'] = [ 'overlay-one', 'overlay-two' ];
$GLOBALS['options']['stuh_fmp_hidden_forms_99'] = [ 'overlay-one' => [ 1 ] ];
$GLOBALS['telemetry'] = [
	'overlay-one' => [ 'gravity_forms' => [ 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Contact <script>', 'months' => [ '2000-01' => 2, '2000-03' => 4 ] ],
		[ 'form_id' => 2, 'form_title' => 'Other form', 'months' => [ '2000-01' => 0, '2000-02' => 1, '2000-03' => 1, '2000-04' => 0 ] ],
		[ 'form_id' => 3, 'form_title' => 'Unreported form', 'months' => [] ],
	] ] ],
	'overlay-two' => [ 'gravity_forms' => [ 'forms' => [
		[ 'form_id' => 1, 'form_title' => 'Contact', 'months' => [ '2000-01' => 3, '2000-03' => 2 ] ],
	] ] ],
];
$overlay_requests = count( $GLOBALS['requests'] );
$overlay_project = [ 'id' => 99, 'budget' => 900000, 'used' => 0, 'startdate' => '2000-01-01', 'deadline' => '2000-05-31' ];
$overlay_plan = invoke_gripp( 'budget_chart_data', $overlay_project );
$_GET = [ 'chart_overlay' => 'forms' ];
$all_forms_overlay = invoke_gripp( 'chart_overlay', 99 );
expect_gripp( [ '2000-01' => 5, '2000-03' => 7, '2000-02' => 1, '2000-04' => 0 ] === $all_forms_overlay['months'], 'All forms sum available counts across differing histories, including Word-hidden forms, without requiring overlapping months or reports from empty forms' );
ob_start();
invoke_gripp( 'render_budget_chart', $overlay_project, $overlay_plan, 'hours', $all_forms_overlay );
$overlay_html = ob_get_clean();
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $overlay_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$overlay_xpath = new DOMXPath( $chart_document );
$overlay_payload = json_decode( $overlay_xpath->query( '//figure[@data-stuh-fmp-chart]' )->item( 0 )->getAttribute( 'data-stuh-fmp-chart' ), true, 512, JSON_THROW_ON_ERROR );
expect_gripp( 'secondary' === $overlay_payload['series'][2]['scale'] && [ 5, 1, 7, 0, null ] === array_column( $overlay_payload['series'][2]['points'], 1 ) && '2000-01-01' === gmdate( 'Y-m-d', $overlay_payload['series'][2]['points'][0][0] ), 'All-forms chart includes non-overlapping reports and explicit zero while keeping months without any report as gaps' );
expect_gripp( str_contains( $overlay_html, 'rotate(90)' ) && str_contains( $overlay_html, 'Form entries' ) && str_contains( $overlay_html, 'Not reported' ) && str_contains( $overlay_html, 'Contact &lt;script&gt;' ) && ! str_contains( $overlay_html, '<script>' ), 'Static fallback includes a right count axis, accessible monthly values, and escaped selector labels' );
expect_gripp( 1 === $overlay_xpath->query( '//select[@name="chart_overlay"]/option[@value="forms" and @selected]' )->length && 1 === $overlay_xpath->query( '//input[@name="project_id" and @value="99"]' )->length, 'Overlay form retains the current selection and project when applying another dataset' );
expect_gripp( 1 === $overlay_xpath->query( '//div[@data-stuh-fmp-static]/following-sibling::form//select[@name="chart_overlay"]' )->length && 1 === $overlay_xpath->query( '//div[@data-stuh-fmp-interactive]/following-sibling::form//select[@name="chart_overlay"]' )->length, 'Place the secondary dataset selector below both chart renderers' );
$saved_overlay_site = $GLOBALS['telemetry']['overlay-two'];
unset( $GLOBALS['telemetry']['overlay-two'] );
$available_forms_overlay = invoke_gripp( 'chart_overlay', 99 );
expect_gripp( 2 === $available_forms_overlay['months']['2000-01'] && 1 === $available_forms_overlay['months']['2000-02'] && $available_forms_overlay['warnings'], 'Unavailable sites do not suppress available form counts and remain explicitly flagged' );
$GLOBALS['telemetry']['overlay-two'] = $saved_overlay_site;
$_GET['chart_overlay'] = 'form:overlay-one:2';
$one_form_overlay = invoke_gripp( 'chart_overlay', 99 );
expect_gripp( [ '2000-01' => 0, '2000-02' => 1, '2000-03' => 1, '2000-04' => 0 ] === $one_form_overlay['months'], 'Selecting a single form retains zero and does not include other forms or sites' );
$GLOBALS['analytics_history'] = [
	'overlay-one' => [ 'months' => [ '2000-01' => 10.0, '2000-02' => null, '2000-03' => 0.0 ], 'warnings' => [ 'Stale report <script>' ] ],
	'overlay-two' => [ 'months' => [ '2000-01' => 20.0, '2000-02' => 5.0, '2000-03' => 0.0 ], 'warnings' => [] ],
];
$_GET['chart_overlay'] = 'analytics';
$analytics_overlay = invoke_gripp( 'chart_overlay', 99 );
expect_gripp( [ '2000-01' => 30.0, '2000-02' => null, '2000-03' => 0.0 ] === $analytics_overlay['months'] && str_contains( $analytics_overlay['warnings'][0], 'Stale report' ), 'Analytics sums linked-site monthly users, not 28-day totals, while retaining missing months, zero and source warnings' );
$GLOBALS['analytics_history']['overlay-two'] = new WP_Error( 'failed', 'Analytics mapping changed.' );
expect_gripp( [] === invoke_gripp( 'chart_overlay', 99 )['months'], 'An unavailable Analytics site cannot produce a misleading partial linked-site total' );
foreach ( [ 'form:unlinked:1', [ 'forms' ] ] as $invalid_overlay ) {
	$_GET['chart_overlay'] = $invalid_overlay;
	try {
		invoke_gripp( 'chart_overlay', 99 );
		throw new RuntimeException( 'Invalid chart overlay accepted' );
	} catch ( RuntimeException $error ) {
		expect_gripp( str_contains( $error->getMessage(), 'Invalid chart overlay' ), 'Reject invalid or unlinked dataset selections' );
	}
}
$_GET = [];
expect_gripp( count( $GLOBALS['requests'] ) === $overlay_requests, 'Overlay selection never makes Gripp or client-site requests' );
$GLOBALS['telemetry']['overlay-one']['data']['active_theme'] = [ 'github_repo' => 'Owner/Theme', 'parent_theme' => [ 'github_repo' => 'owner/parent' ] ];
$GLOBALS['telemetry']['overlay-two']['data']['active_theme'] = [ 'github_repo' => 'owner/theme' ];
$release_time = strtotime( '2000-01-16T12:00:00Z' );
$GLOBALS['release_history']['owner/theme'] = [
	[ 'timestamp' => $release_time, 'label' => 'Theme v1 <script>', 'url' => 'https://github.com/owner/theme/releases/tag/v1' ],
	[ 'timestamp' => strtotime( '1990-01-01' ), 'label' => 'Old', 'url' => 'https://github.com/owner/theme/releases/tag/old' ],
	[ 'timestamp' => strtotime( '2099-01-01' ), 'label' => 'Future', 'url' => 'https://github.com/owner/theme/releases/tag/future' ],
];
$history = invoke_gripp( 'chart_releases', 99 );
expect_gripp( [ 'owner/theme' ] === $GLOBALS['release_requests'] && 3 === count( $history['releases'] ), 'Deduplicate active repositories across linked sites without including parent themes' );
ob_start();
invoke_gripp( 'render_budget_chart', $usage_project, $current_usage, 'hours', null, $history );
$release_html = ob_get_clean();
$xml_errors = libxml_use_internal_errors( true );
$chart_document->loadHTML( $release_html );
libxml_clear_errors();
libxml_use_internal_errors( $xml_errors );
$release_xpath = new DOMXPath( $chart_document );
$payload = json_decode( $release_xpath->query( '//figure[@data-stuh-fmp-chart]' )->item( 0 )->getAttribute( 'data-stuh-fmp-chart' ), true );
$markers = $payload['series'][2]['releases'];
expect_gripp( 1 === count( $markers ) && $release_time === $markers[0]['timestamp'], 'Only place releases within recorded-time bounds, never extrapolate' );
$actual_points = $payload['series'][2]['points'];
$january = array_values( array_filter( $actual_points, static fn( array $point ): bool => $point[0] === strtotime( '2000-01-01T00:00:00Z' ) ) )[0];
$february = array_values( array_filter( $actual_points, static fn( array $point ): bool => $point[0] === strtotime( '2000-02-01T00:00:00Z' ) ) )[0];
$expected_value = $january[1] + ( $february[1] - $january[1] ) / 2;
expect_gripp( abs( $markers[0]['value'] - $expected_value ) < 0.001, 'Release squares interpolate the recorded line at the exact UTC publication time' );
expect_gripp( 1 === $release_xpath->query( '//svg//a/rect[@width="8" and @height="8"]' )->length && str_contains( $release_html, 'Theme v1 &lt;script&gt;' ) && ! str_contains( $release_html, '<script>' ), 'Static squares and accessible release links escape release labels' );
expect_gripp( 'Theme releases' === $payload['releaseLabel'] && 1 === $release_xpath->query( '//ul[@data-stuh-fmp-static-legend]/li[@class="stuh-fmp-legend-releases"]' )->length && 0 === $release_xpath->query( '//details[summary="Theme releases"]' )->length, 'Identify release squares in both legends without a raw release list toggle' );
$GLOBALS['release_history']['owner/theme'] = new WP_Error( 'failed', 'GitHub unavailable' );
$history = invoke_gripp( 'chart_releases', 99 );
expect_gripp( [] === $history['releases'] && str_contains( $history['warnings'][0], 'GitHub unavailable' ), 'Report release failures rather than silently presenting empty history' );
echo "Gripp regression checks passed.\n";
