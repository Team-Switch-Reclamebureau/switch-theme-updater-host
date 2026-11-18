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
function __( $text, $domain = '' ) { return $text; }
function esc_html( $value ) { return htmlspecialchars( (string) $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function esc_html__( $text, $domain = '' ) { return esc_html( $text ); }
function esc_attr__( $text, $domain = '' ) { return esc_attr( $text ); }
function add_action( ...$args ) { $GLOBALS['hooks'][] = $args; }
function add_filter( ...$args ) { $GLOBALS['filters'][] = $args; }
function add_submenu_page( ...$args ) { $GLOBALS['menus'][] = $args; return 'updater-host_page_stuh-fmp'; }
function get_current_screen() { return (object) [ 'id' => 'updater-host_page_stuh-fmp' ]; }
function get_hidden_columns( $screen ) { return $GLOBALS['hidden_columns'][ get_current_user_id() ] ?? []; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function current_user_can( $capability ) { return $GLOBALS['authorized'] ?? true; }
function get_current_user_id() { return $GLOBALS['user'] ?? 1; }
function get_user_option( $key ) { return $GLOBALS['user_options'][ get_current_user_id() ][ $key ] ?? false; }
function wp_die( $message, ...$args ) { throw new RuntimeException( $message ); }
function wp_unslash( $value ) { return $value; }
function wp_salt( $scheme ) { return $GLOBALS['salt'] ?? 'test-only-stable-authentication-salt'; }
function wp_json_encode( $value ) { return json_encode( $value ); }
function admin_url( $path ) { return 'https://host.example/wp-admin/' . $path; }
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
function wp_date( $format, $time ) { return gmdate( $format, $time ); }
function wp_timezone() { return new DateTimeZone( 'Europe/Amsterdam' ); }
function number_format_i18n( $value, $decimals = 0 ) { return number_format( $value, $decimals ); }
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return $response['body']; }
function wp_remote_post( $url, $args ) {
	$GLOBALS['requests'][] = [ $url, $args ];
	if ( 'project.get' === json_decode( $args['body'], true )[0]['method'] ) {
		return $GLOBALS['order_responses'] ? array_shift( $GLOBALS['order_responses'] ) : project_response( [] );
	}
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
function gripp_render( string $method, int $offset = 0, string $unit = 'eur' ): string {
	$_GET = [ 'offset' => (string) $offset, 'unit' => $unit ];
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
	[ 'id' => 9001, 'umbrellaproject' => [ 'id' => 1, 'searchname' => 'Retainer' ], 'totalexclvat' => '120.00' ],
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
expect_gripp( 2 === count( $GLOBALS['requests'] ) && str_contains( $html, 'offset=250' ) && ! str_contains( $html, 'Previous projects' ), 'First dashboard page uses the connection and order cache and offers next-page navigation' );
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
expect_gripp( 2 === substr_count( $empty_group_html, 'class="colspanchange" colspan="10"' ), 'Empty rows span the visible columns in both tables and support native live colspan updates' );
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
$GLOBALS['order_responses'][] = project_response( [ [ 'id' => 9001, 'umbrellaproject' => [ 'id' => 1 ], 'totalexclvat' => '7000.00' ] ] );
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
expect_gripp( ! $GLOBALS['responses'] && ! $GLOBALS['order_responses'], 'All expected API responses were consumed' );
echo "Gripp regression checks passed.\n";
