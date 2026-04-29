<?php
/**
 * Plugin Name: Team Switch - Theme Updater Host
 * Plugin URI: https://github.com/Team-Switch-Reclamebureau/switch-theme-updater-host
 * Description: Central update proxy that authenticates client sites and relays GitHub releases without sharing the GitHub token. Manage all client sites from one place and remotely revoke access.
 * Version: 0.0.2
 * Author: Team Switch
 * Author URI: https://teamswitch.nl
 * GitHub Repo: Team-Switch-Reclamebureau/switch-theme-updater-host
 * GitHub Branch: main
 * GitHub Path: /
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'STUH_OPTION_CLIENTS',    'stuh_clients' );
define( 'STUH_OPTION_SETTINGS',   'stuh_settings' );
define( 'STUH_OPTION_UNVERIFIED', 'stuh_unverified' );
define( 'STUH_REST_NS',           'stu-host/v1' );

// ============================================================
// Main plugin class
// ============================================================
class STUH_Plugin {

	public function __construct() {
		add_action( 'admin_menu',    [ $this, 'register_admin_menu' ] );
		add_action( 'admin_init',    [ $this, 'handle_admin_actions' ] );
		add_action( 'rest_api_init', [ $this, 'register_rest_routes' ] );
		add_action( 'admin_notices', [ $this, 'maybe_notice_no_token' ] );
	}

	public function maybe_notice_no_token(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$s     = self::get_settings();
		$token = defined( 'STUH_TOKEN' ) ? STUH_TOKEN : ( $s['token'] ?? '' );
		if ( $token ) {
			return;
		}
		$url = admin_url( 'admin.php?page=stuh-settings' );
		echo '<div class="notice notice-error"><p>';
		echo '<strong>Switch Updater Host:</strong> No GitHub token is configured. ';
		echo 'Client sites will not be able to fetch updates until a token is added. ';
		echo '<a href="' . esc_url( $url ) . '">Configure now &rarr;</a>';
		echo '</p></div>';
	}

	// --------------------------------------------------------
	// Data helpers
	// --------------------------------------------------------

	public static function get_settings(): array {
		$opt = get_option( STUH_OPTION_SETTINGS, [] );
		return wp_parse_args( $opt, [ 'token' => '' ] );
	}

	public static function get_clients(): array {
		return (array) get_option( STUH_OPTION_CLIENTS, [] );
	}

	private static function save_clients( array $clients ): void {
		update_option( STUH_OPTION_CLIENTS, array_values( $clients ) );
	}

	public static function get_unverified(): array {
		return (array) get_option( STUH_OPTION_UNVERIFIED, [] );
	}

	private static function save_unverified( array $records ): void {
		update_option( STUH_OPTION_UNVERIFIED, array_values( $records ) );
	}

	/**
	 * Record an unauthenticated or invalid-key request.
	 * Deduplicates by IP; throttles DB writes to once per 5 minutes per IP.
	 *
	 * @param WP_REST_Request $req  The failed request.
	 * @param string          $reason  'missing_key' or 'invalid_key'.
	 */
	public static function record_unverified( WP_REST_Request $req, string $reason ): void {
		$ip       = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );
		$endpoint = sanitize_text_field( $req->get_route() );

		// Try to parse the WordPress site URL from the User-Agent.
		// WordPress sets UA like: "WordPress/6.5; https://example.com"
		$ua       = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' );
		$site_url = '';
		if ( preg_match( '#WordPress/[\d.]+;\s*(https?://[^\s]+)#i', $ua, $m ) ) {
			$site_url = esc_url_raw( rtrim( $m[1], '/' ) );
		}

		if ( ! $ip ) {
			return;
		}

		$records = self::get_unverified();
		$now     = time();
		$found   = false;

		foreach ( $records as &$r ) {
			if ( $r['ip'] !== $ip ) {
				continue;
			}
			$found = true;
			$r['attempts']++;
			$r['last_reason'] = $reason;
			$r['last_endpoint'] = $endpoint;
			if ( $site_url ) {
				$r['site_url'] = $site_url;
			}
			// Throttle write: only update last_seen once per 5 minutes.
			if ( ( $now - ( $r['last_seen'] ?? 0 ) ) > 300 ) {
				$r['last_seen'] = $now;
				self::save_unverified( $records );
			}
			break;
		}
		unset( $r );

		if ( ! $found ) {
			$records[] = [
				'id'            => uniqid( 'stuh_uv_', true ),
				'ip'            => $ip,
				'site_url'      => $site_url,
				'first_seen'    => $now,
				'last_seen'     => $now,
				'attempts'      => 1,
				'last_reason'   => $reason,
				'last_endpoint' => $endpoint,
			];
			self::save_unverified( $records );
		}
	}

	// --------------------------------------------------------
	// Authentication
	// --------------------------------------------------------

	/**
	 * Validate a raw API key against stored (hashed) client records.
	 * Updates last_seen at most once per 5 minutes to reduce DB writes.
	 *
	 * @param string $raw_key  The plaintext key sent by the client.
	 * @return array|false     The matching client record, or false on failure.
	 */
	public static function authenticate_client( string $raw_key ) {
		if ( empty( $raw_key ) ) {
			return false;
		}

		$clients = self::get_clients();
		$matched = false;
		$idx     = null;

		foreach ( $clients as $i => $client ) {
			if ( ! ( $client['enabled'] ?? true ) ) {
				continue;
			}
			if ( wp_check_password( $raw_key, $client['api_key_hash'] ) ) {
				$matched = $client;
				$idx     = $i;
				break;
			}
		}

		if ( false === $matched ) {
			return false;
		}

		// Throttle last_seen writes to once per 5 minutes.
		$last = $matched['last_seen'] ?? 0;
		if ( ( time() - $last ) > 300 ) {
			$clients[ $idx ]['last_seen']    = time();
			$clients[ $idx ]['last_seen_ip'] = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );
			self::save_clients( $clients );
		}

		return $matched;
	}

	// --------------------------------------------------------
	// REST API registration
	// --------------------------------------------------------

	public function register_rest_routes(): void {
		$auth = [ $this, 'rest_permission' ];

		register_rest_route( STUH_REST_NS, '/version', [
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => [ $this, 'rest_version' ],
			'permission_callback' => $auth,
			'args'                => [
				'repo'   => [ 'required' => true,  'sanitize_callback' => 'sanitize_text_field' ],
				'mode'   => [ 'default'  => 'releases', 'sanitize_callback' => 'sanitize_text_field' ],
				'branch' => [ 'default'  => 'main', 'sanitize_callback' => 'sanitize_text_field' ],
				'ref'    => [ 'default'  => '',    'sanitize_callback' => 'sanitize_text_field' ],
				'path'   => [ 'default'  => '/',   'sanitize_callback' => 'sanitize_text_field' ],
			],
		] );

		register_rest_route( STUH_REST_NS, '/releases', [
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => [ $this, 'rest_releases' ],
			'permission_callback' => $auth,
			'args'                => [
				'repo' => [ 'required' => true, 'sanitize_callback' => 'sanitize_text_field' ],
			],
		] );

		register_rest_route( STUH_REST_NS, '/download', [
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => [ $this, 'rest_download' ],
			'permission_callback' => $auth,
			'args'                => [
				'repo' => [ 'required' => true,  'sanitize_callback' => 'sanitize_text_field' ],
				'ref'  => [ 'required' => true,  'sanitize_callback' => 'sanitize_text_field' ],
				'path' => [ 'default'  => '/',   'sanitize_callback' => 'sanitize_text_field' ],
				'pack' => [ 'default'  => '',    'sanitize_callback' => 'sanitize_text_field' ],
			],
		] );
	}

	// --------------------------------------------------------
	// REST permission callback (shared by all endpoints)
	// --------------------------------------------------------

	public function rest_permission( WP_REST_Request $req ) {
		$key = $req->get_header( 'X-STU-Key' );
		if ( empty( $key ) ) {
			self::record_unverified( $req, 'missing_key' );
			return new WP_Error( 'missing_key', 'API key required', [ 'status' => 401 ] );
		}
		if ( ! self::authenticate_client( $key ) ) {
			self::record_unverified( $req, 'invalid_key' );
			return new WP_Error( 'invalid_key', 'Invalid or disabled API key', [ 'status' => 403 ] );
		}
		return true;
	}

	// --------------------------------------------------------
	// REST endpoint: latest version
	// --------------------------------------------------------

	public function rest_version( WP_REST_Request $req ) {
		$repo   = $req->get_param( 'repo' );
		$mode   = $req->get_param( 'mode' );
		$branch = $req->get_param( 'branch' );
		$ref    = $req->get_param( 'ref' );
		$path   = $req->get_param( 'path' );

		if ( ! $this->valid_repo( $repo ) ) {
			return new WP_Error( 'invalid_repo', 'Invalid repository format (expected owner/repo)', [ 'status' => 400 ] );
		}

		$gh = $this->github();

		if ( 'tag' === $mode && $ref ) {
			$result = $gh->get_version_from_tag( $repo, $ref, $path );
		} elseif ( 'commits' === $mode ) {
			$result = $gh->get_latest_version( $repo, $branch, $path, 'commits' );
		} else {
			$result = $gh->get_latest_version( $repo, null, $path, 'releases' );
		}

		if ( ! $result ) {
			return new WP_Error( 'no_version', 'No version found for this repository', [ 'status' => 404 ] );
		}

		return rest_ensure_response( $result );
	}

	// --------------------------------------------------------
	// REST endpoint: list releases
	// --------------------------------------------------------

	public function rest_releases( WP_REST_Request $req ) {
		$repo = $req->get_param( 'repo' );

		if ( ! $this->valid_repo( $repo ) ) {
			return new WP_Error( 'invalid_repo', 'Invalid repository format', [ 'status' => 400 ] );
		}

		$releases = $this->github()->get_releases( $repo );
		return rest_ensure_response( [ 'releases' => $releases ] );
	}

	// --------------------------------------------------------
	// REST endpoint: download zip (binary stream – exits early)
	// --------------------------------------------------------

	public function rest_download( WP_REST_Request $req ): void {
		$repo = $req->get_param( 'repo' );
		$ref  = $req->get_param( 'ref' );
		$path = $req->get_param( 'path' );
		$pack = $req->get_param( 'pack' ) ?: basename( $repo );

		if ( ! $this->valid_repo( $repo ) ) {
			wp_send_json_error( [ 'message' => 'Invalid repository format' ], 400 );
		}

		$zip = $this->github()->download_zipball( $repo, $ref, $path, $pack );

		if ( is_wp_error( $zip ) ) {
			wp_send_json_error( [ 'message' => $zip->get_error_message() ], 502 );
		}

		// Stream binary zip to the client site.
		header( 'Content-Type: application/zip' );
		header( 'Content-Disposition: attachment; filename="' . sanitize_file_name( $pack ) . '.zip"' );
		header( 'Content-Length: ' . filesize( $zip ) );
		header( 'Cache-Control: no-store' );
		readfile( $zip ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_readfile
		@unlink( $zip );  // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		exit;
	}

	// --------------------------------------------------------
	// Internal helpers
	// --------------------------------------------------------

	private function valid_repo( string $repo ): bool {
		return (bool) preg_match( '/^[a-zA-Z0-9_.\-]+\/[a-zA-Z0-9_.\-]+$/', $repo );
	}

	private function github(): STUH_GitHubClient {
		static $gh = null;
		if ( $gh ) {
			return $gh;
		}
		$s     = self::get_settings();
		$token = defined( 'STUH_TOKEN' ) ? STUH_TOKEN : ( $s['token'] ?? '' );
		$gh    = new STUH_GitHubClient( $token, 'https://api.github.com' );
		return $gh;
	}

	// --------------------------------------------------------
	// Admin menus
	// --------------------------------------------------------

	public function register_admin_menu(): void {
		add_menu_page(
			__( 'Switch Updater Host', 'stuh' ),
			__( 'Updater Host', 'stuh' ),
			'manage_options',
			'stuh',
			[ $this, 'render_clients_page' ],
			'dashicons-cloud',
			59
		);
		add_submenu_page(
			'stuh',
			__( 'Client Sites', 'stuh' ),
			__( 'Client Sites', 'stuh' ),
			'manage_options',
			'stuh',
			[ $this, 'render_clients_page' ]
		);
		add_submenu_page(
			'stuh',
			__( 'Settings', 'stuh' ),
			__( 'Settings', 'stuh' ),
			'manage_options',
			'stuh-settings',
			[ $this, 'render_settings_page' ]
		);
	}

	// --------------------------------------------------------
	// Admin action handler (POST handler for all admin forms)
	// --------------------------------------------------------

	public function handle_admin_actions(): void {
		if ( empty( $_POST['stuh_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'stuh_admin' );

		$action  = sanitize_key( $_POST['stuh_action'] );
		$clients = self::get_clients();

		switch ( $action ) {

			case 'add_client':
				$name = sanitize_text_field( $_POST['site_name'] ?? '' );
				$url  = esc_url_raw( trim( $_POST['site_url'] ?? '' ) );
				if ( $name && $url ) {
					$raw_key   = bin2hex( random_bytes( 24 ) ); // 48 hex chars, 192 bits
					$clients[] = [
						'id'           => uniqid( 'stuh_', true ),
						'site_name'    => $name,
						'site_url'     => $url,
						'api_key_hash' => wp_hash_password( $raw_key ),
						'enabled'      => true,
						'created_at'   => time(),
						'last_seen'    => null,
						'last_seen_ip' => null,
					];
					self::save_clients( $clients );
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $name ],
						120 // shown for 2 minutes max
					);
				}
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'toggle_client':
				$id = sanitize_text_field( $_POST['client_id'] ?? '' );
				foreach ( $clients as &$c ) {
					if ( $c['id'] === $id ) {
						$c['enabled'] = ! ( $c['enabled'] ?? true );
						break;
					}
				}
				unset( $c );
				self::save_clients( $clients );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'delete_client':
				$id      = sanitize_text_field( $_POST['client_id'] ?? '' );
				$clients = array_values( array_filter( $clients, fn( $c ) => $c['id'] !== $id ) );
				self::save_clients( $clients );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'regenerate_key':
				$id        = sanitize_text_field( $_POST['client_id'] ?? '' );
				$site_name = '';
				foreach ( $clients as &$c ) {
					if ( $c['id'] === $id ) {
						$raw_key          = bin2hex( random_bytes( 24 ) );
						$c['api_key_hash'] = wp_hash_password( $raw_key );
						$site_name         = $c['site_name'];
						break;
					}
				}
				unset( $c );
				self::save_clients( $clients );
				if ( $site_name ) {
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $site_name ],
						120
					);
				}
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'save_settings':
				$token = sanitize_text_field( $_POST['token'] ?? '' );
				update_option( STUH_OPTION_SETTINGS, [ 'token' => $token ] );
				wp_safe_redirect( add_query_arg( 'stuh_saved', '1', admin_url( 'admin.php?page=stuh-settings' ) ) );
				exit;

			case 'delete_unverified':
				$id      = sanitize_text_field( $_POST['unverified_id'] ?? '' );
				$records = array_values( array_filter( self::get_unverified(), fn( $r ) => $r['id'] !== $id ) );
				self::save_unverified( $records );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'clear_unverified':
				delete_option( STUH_OPTION_UNVERIFIED );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'promote_unverified':
				$id      = sanitize_text_field( $_POST['unverified_id'] ?? '' );
				$records = self::get_unverified();
				$entry   = null;
				foreach ( $records as $r ) {
					if ( $r['id'] === $id ) { $entry = $r; break; }
				}
				if ( $entry ) {
					$raw_key   = bin2hex( random_bytes( 24 ) );
					$site_name = $entry['site_url'] ?: $entry['ip'];
					$clients   = self::get_clients();
					$clients[] = [
						'id'           => uniqid( 'stuh_', true ),
						'site_name'    => $site_name,
						'site_url'     => $entry['site_url'] ?: '',
						'api_key_hash' => wp_hash_password( $raw_key ),
						'enabled'      => true,
						'created_at'   => time(),
						'last_seen'    => null,
						'last_seen_ip' => null,
					];
					self::save_clients( $clients );
					// Remove from unverified.
					$records = array_values( array_filter( $records, fn( $r ) => $r['id'] !== $id ) );
					self::save_unverified( $records );
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $site_name ],
						120
					);
				}
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;
		}
	}

	// --------------------------------------------------------
	// Admin page: client site list
	// --------------------------------------------------------

	public function render_clients_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ) );
		}

		$clients = self::get_clients();
		$uid     = get_current_user_id();
		$new_key = get_transient( 'stuh_new_key_' . $uid );
		if ( $new_key ) {
			delete_transient( 'stuh_new_key_' . $uid );
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Switch Updater Host — Client Sites', 'stuh' ); ?></h1>

			<?php if ( $new_key ) : ?>
			<div class="notice notice-success" style="padding: 16px 16px 8px;">
				<h3 style="margin-top: 0;">&#128274; API Key for <em><?php echo esc_html( $new_key['site'] ); ?></em></h3>
				<p><strong>This key is shown only once. Copy it before leaving this page.</strong></p>
				<code id="stuh-api-key" style="display:block;font-size:14px;background:#f0f0f1;padding:10px 14px;border-radius:4px;word-break:break-all;user-select:all;margin-bottom:12px;"><?php echo esc_html( $new_key['key'] ); ?></code>
				<p>Add the following constants to the client site's <code>wp-config.php</code>:</p>
				<pre style="background:#f0f0f1;padding:12px;border-radius:4px;overflow:auto;font-size:13px;">define( 'GHTU_HOST_URL',   '<?php echo esc_html( rtrim( get_site_url(), '/' ) ); ?>' );
define( 'GHTU_CLIENT_KEY', '<?php echo esc_html( $new_key['key'] ); ?>' );</pre>
				<p style="margin-top:8px;"><em>Once these constants are set the client site will route all update checks and downloads through this host — the GitHub token never leaves this server.</em></p>
			</div>
			<?php endif; ?>

			<table class="wp-list-table widefat fixed striped" style="margin-top: 20px;">
				<thead>
					<tr>
						<th scope="col" style="width: 18%;">Name</th>
						<th scope="col" style="width: 28%;">URL</th>
						<th scope="col" style="width: 10%;">Status</th>
						<th scope="col" style="width: 12%;">Created</th>
						<th scope="col" style="width: 16%;">Last Seen</th>
						<th scope="col">Actions</th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $clients ) ) : ?>
					<tr>
						<td colspan="6" style="padding: 16px;">
							<em><?php esc_html_e( 'No client sites registered yet. Add one below.', 'stuh' ); ?></em>
						</td>
					</tr>
					<?php else : ?>
					<?php foreach ( $clients as $c ) :
						$enabled = (bool) ( $c['enabled'] ?? true );
					?>
					<tr>
						<td><strong><?php echo esc_html( $c['site_name'] ); ?></strong></td>
						<td>
							<a href="<?php echo esc_url( $c['site_url'] ); ?>" target="_blank" rel="noopener">
								<?php echo esc_html( $c['site_url'] ); ?>
							</a>
						</td>
						<td>
							<?php if ( $enabled ) : ?>
								<span style="color:#46b450;font-weight:600;">&#10003; Active</span>
							<?php else : ?>
								<span style="color:#d63638;font-weight:600;">&#10005; Disabled</span>
							<?php endif; ?>
						</td>
						<td>
							<?php echo esc_html( $c['created_at'] ? date_i18n( 'Y-m-d', $c['created_at'] ) : '—' ); ?>
						</td>
						<td>
							<?php if ( $c['last_seen'] ) : ?>
								<?php echo esc_html( date_i18n( 'Y-m-d H:i', $c['last_seen'] ) ); ?><br>
								<small><?php echo esc_html( $c['last_seen_ip'] ?? '' ); ?></small>
							<?php else : ?>
								<em>Never</em>
							<?php endif; ?>
						</td>
						<td style="white-space: nowrap;">
							<!-- Enable / Disable -->
							<form method="post" style="display:inline-block;margin-right:4px;">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="toggle_client">
								<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
								<button type="submit" class="button button-secondary">
									<?php echo $enabled ? esc_html__( 'Disable', 'stuh' ) : esc_html__( 'Enable', 'stuh' ); ?>
								</button>
							</form>
							<!-- Regenerate key -->
							<form method="post" style="display:inline-block;margin-right:4px;"
								  onsubmit="return confirm('Regenerate API key? The old key will stop working immediately.');">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="regenerate_key">
								<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
								<button type="submit" class="button">
									<?php esc_html_e( 'New Key', 'stuh' ); ?>
								</button>
							</form>
							<!-- Delete -->
							<form method="post" style="display:inline-block;"
								  onsubmit="return confirm('Permanently delete this client site?');">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="delete_client">
								<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
								<button type="submit" class="button"
										style="color:#d63638;border-color:#d63638;">
									<?php esc_html_e( 'Delete', 'stuh' ); ?>
								</button>
							</form>
						</td>
					</tr>
					<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

		<?php
		$unverified = self::get_unverified();
		if ( ! empty( $unverified ) ) :
		?>
		<hr>
		<h2 style="color:#d63638;">&#9888; Unverified Access Attempts</h2>
		<p>These sites contacted the update host without a valid API key. You can grant them access by clicking <strong>Register &amp; Generate Key</strong>, or dismiss them.</p>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width:20%;">Detected Site URL</th>
					<th style="width:14%;">IP Address</th>
					<th style="width:10%;">Attempts</th>
					<th style="width:12%;">First Seen</th>
					<th style="width:12%;">Last Seen</th>
					<th style="width:14%;">Reason</th>
					<th>Actions</th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $unverified as $uv ) : ?>
				<tr>
					<td>
						<?php if ( $uv['site_url'] ) : ?>
							<a href="<?php echo esc_url( $uv['site_url'] ); ?>" target="_blank" rel="noopener">
								<?php echo esc_html( $uv['site_url'] ); ?>
							</a>
						<?php else : ?>
							<em>Unknown</em>
						<?php endif; ?>
					</td>
					<td><code><?php echo esc_html( $uv['ip'] ); ?></code></td>
					<td><?php echo (int) $uv['attempts']; ?></td>
					<td><?php echo esc_html( date_i18n( 'Y-m-d H:i', $uv['first_seen'] ) ); ?></td>
					<td><?php echo esc_html( date_i18n( 'Y-m-d H:i', $uv['last_seen'] ) ); ?></td>
					<td>
						<?php
						$reason_label = 'missing_key' === $uv['last_reason']
							? '<span title="No key was sent">No key</span>'
							: '<span title="A key was sent but did not match any registered site">Invalid key</span>';
						echo wp_kses( $reason_label, [ 'span' => [ 'title' => [] ] ] );
						?>
						<br><small><code><?php echo esc_html( $uv['last_endpoint'] ?? '' ); ?></code></small>
					</td>
					<td style="white-space:nowrap;">
						<!-- Promote to registered client -->
						<form method="post" style="display:inline-block;margin-right:4px;"
							  onsubmit="return confirm('Register this site and generate an API key?');">
							<?php wp_nonce_field( 'stuh_admin' ); ?>
							<input type="hidden" name="stuh_action" value="promote_unverified">
							<input type="hidden" name="unverified_id" value="<?php echo esc_attr( $uv['id'] ); ?>">
							<button type="submit" class="button button-primary">
								<?php esc_html_e( 'Register &amp; Generate Key', 'stuh' ); ?>
							</button>
						</form>
						<!-- Dismiss -->
						<form method="post" style="display:inline-block;">
							<?php wp_nonce_field( 'stuh_admin' ); ?>
							<input type="hidden" name="stuh_action" value="delete_unverified">
							<input type="hidden" name="unverified_id" value="<?php echo esc_attr( $uv['id'] ); ?>">
							<button type="submit" class="button" style="color:#d63638;border-color:#d63638;">
								<?php esc_html_e( 'Dismiss', 'stuh' ); ?>
							</button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<form method="post" style="margin-top:8px;"
			  onsubmit="return confirm('Clear all unverified records?');">
			<?php wp_nonce_field( 'stuh_admin' ); ?>
			<input type="hidden" name="stuh_action" value="clear_unverified">
			<button type="submit" class="button"><?php esc_html_e( 'Clear All Unverified', 'stuh' ); ?></button>
		</form>
		<?php endif; ?>

		<hr>
		<h2><?php esc_html_e( 'Add Client Site', 'stuh' ); ?></h2>
		<form method="post">
			<?php wp_nonce_field( 'stuh_admin' ); ?>
			<input type="hidden" name="stuh_action" value="add_client">
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">
						<label for="site_name"><?php esc_html_e( 'Site Name', 'stuh' ); ?></label>
					</th>
					<td>
						<input type="text" id="site_name" name="site_name"
							   class="regular-text" placeholder="e.g. Client Website" required>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="site_url"><?php esc_html_e( 'Site URL', 'stuh' ); ?></label>
					</th>
					<td>
						<input type="url" id="site_url" name="site_url"
							   class="regular-text" placeholder="https://example.com" required>
						<p class="description">
							<?php esc_html_e( 'Used for display only; it does not affect authentication.', 'stuh' ); ?>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Add Site &amp; Generate Key', 'stuh' ) ); ?>
		</form>
	</div>
	<?php
	}

	// --------------------------------------------------------
	// Admin page: settings
	// --------------------------------------------------------

	public function render_settings_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ) );
		}
		$s = self::get_settings();
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Switch Updater Host — Settings', 'stuh' ); ?></h1>

			<?php if ( isset( $_GET['stuh_saved'] ) ) : ?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Settings saved.', 'stuh' ); ?></p>
			</div>
			<?php endif; ?>

			<form method="post">
				<?php wp_nonce_field( 'stuh_admin' ); ?>
				<input type="hidden" name="stuh_action" value="save_settings">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="token"><?php esc_html_e( 'GitHub Personal Access Token', 'stuh' ); ?></label>
						</th>
						<td>
							<input type="password" id="token" name="token"
								   class="regular-text" value="<?php echo esc_attr( $s['token'] ?? '' ); ?>"
								   autocomplete="new-password">
							<p class="description">
								<?php esc_html_e( 'Token requires repo scope. Never stored in client sites.', 'stuh' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Settings', 'stuh' ) ); ?>
			</form>

			<hr>
			<h2><?php esc_html_e( 'REST API Endpoint', 'stuh' ); ?></h2>
			<p><?php esc_html_e( 'Client sites connect to this base URL:', 'stuh' ); ?></p>
			<code><?php echo esc_html( get_rest_url( null, STUH_REST_NS ) ); ?></code>

			<h3><?php esc_html_e( 'Available Endpoints', 'stuh' ); ?></h3>
			<table class="wp-list-table widefat fixed" style="max-width:800px;">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Method', 'stuh' ); ?></th>
						<th><?php esc_html_e( 'Path', 'stuh' ); ?></th>
						<th><?php esc_html_e( 'Description', 'stuh' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><code>GET</code></td>
						<td><code>/version</code></td>
						<td><?php esc_html_e( 'Latest version for a repo (?repo=owner/repo&mode=releases|commits|tag&ref=)', 'stuh' ); ?></td>
					</tr>
					<tr>
						<td><code>GET</code></td>
						<td><code>/releases</code></td>
						<td><?php esc_html_e( 'All releases for a repo (?repo=owner/repo)', 'stuh' ); ?></td>
					</tr>
					<tr>
						<td><code>GET</code></td>
						<td><code>/download</code></td>
						<td><?php esc_html_e( 'Download zip (?repo=owner/repo&ref=v1.0&path=/&pack=slug)', 'stuh' ); ?></td>
					</tr>
				</tbody>
			</table>
			<p class="description">
				<?php esc_html_e( 'All endpoints require the header:', 'stuh' ); ?>
				<code>X-STU-Key: &lt;api_key&gt;</code>
			</p>
		</div>
		<?php
	}
}

// ============================================================
// GitHub client (adapted from switch-theme-updater)
// ============================================================
class STUH_GitHubClient {

	private string $token;
	private string $api;

	public function __construct( string $token, string $api ) {
		$this->token = $token;
		$this->api   = rtrim( $api, '/' );
	}

	private function headers(): array {
		$h = [
			'Accept'     => 'application/vnd.github+json',
			'User-Agent' => 'stuh-host/1.0',
		];
		if ( $this->token ) {
			$h['Authorization'] = 'Bearer ' . $this->token;
		}
		return $h;
	}

	private function request( string $method, string $url, $body = null ) {
		$args = [
			'method'  => $method,
			'headers' => $this->headers(),
			'timeout' => 30,
		];
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}
		$res = wp_remote_request( $url, $args );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		$code = wp_remote_retrieve_response_code( $res );
		$data = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( $code >= 200 && $code < 300 ) {
			return $data;
		}
		return new WP_Error(
			'github_error',
			'GitHub API ' . $code . ': ' . ( $data['message'] ?? 'unknown' )
		);
	}

	public function get_latest_version( string $repo, ?string $branch, string $path = '/', string $mode = 'releases' ): ?array {
		if ( 'commits' === $mode && $branch ) {
			$commits = $this->request(
				'GET',
				$this->api . '/repos/' . $repo . '/commits?sha=' . rawurlencode( $branch ) . '&per_page=1'
			);
			if ( ! is_wp_error( $commits ) && isset( $commits[0] ) ) {
				$sha        = $commits[0]['sha'];
				$style_path = ltrim( rtrim( $path, '/' ) . '/style.css', '/' );
				$file       = $this->request(
					'GET',
					$this->api . '/repos/' . $repo . '/contents/' . $style_path . '?ref=' . rawurlencode( $branch )
				);
				if ( ! is_wp_error( $file ) && isset( $file['content'] ) ) {
					$content = base64_decode( $file['content'] );
					if ( preg_match( '/Version:\s*(.+?)$/m', $content, $m ) ) {
						return [ 'version' => trim( $m[1] ), 'ref' => $sha ];
					}
				}
				return null;
			}
		}

		$rel = $this->request( 'GET', $this->api . '/repos/' . $repo . '/releases/latest' );
		if ( ! is_wp_error( $rel ) && isset( $rel['tag_name'] ) ) {
			return [ 'version' => ltrim( $rel['tag_name'], 'v' ), 'ref' => $rel['tag_name'] ];
		}
		return null;
	}

	public function get_version_from_tag( string $repo, string $tag, string $path = '/' ): ?array {
		$rel = $this->request( 'GET', $this->api . '/repos/' . $repo . '/releases/tags/' . rawurlencode( $tag ) );
		if ( is_wp_error( $rel ) || ! isset( $rel['tag_name'] ) ) {
			return null;
		}
		return [ 'version' => ltrim( $rel['tag_name'], 'v' ), 'ref' => $rel['tag_name'] ];
	}

	public function get_releases( string $repo ): array {
		$data = $this->request( 'GET', $this->api . '/repos/' . $repo . '/releases?per_page=100' );
		if ( is_wp_error( $data ) || ! is_array( $data ) ) {
			return [];
		}
		$out = [];
		foreach ( $data as $r ) {
			if ( isset( $r['tag_name'] ) ) {
				$out[] = [
					'tag'          => $r['tag_name'],
					'version'      => ltrim( $r['tag_name'], 'v' ),
					'name'         => $r['name'] ?: $r['tag_name'],
					'published_at' => $r['published_at'] ?? $r['created_at'] ?? '',
				];
			}
		}
		return $out;
	}

	/**
	 * Download a GitHub zipball, repackage it with the correct folder name,
	 * and return the path to the final zip file.
	 */
	public function download_zipball( string $repo, string $ref, string $path = '/', string $pack = '' ): string {
		if ( ! $pack ) {
			$pack = basename( $repo );
		}

		$temp_dir = get_temp_dir() . 'stuh-' . uniqid() . '-' . time();
		if ( ! wp_mkdir_p( $temp_dir ) ) {
			return new WP_Error( 'temp_dir', 'Failed to create temp directory' );
		}
		@chmod( $temp_dir, 0755 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$zipball_url = $this->api . '/repos/' . $repo . '/zipball/' . rawurlencode( $ref );
		$response    = wp_remote_get( $zipball_url, [
			'timeout'    => 300,
			'headers'    => $this->headers(),
			'stream'     => false,
			'decompress' => false,
		] );

		if ( is_wp_error( $response ) ) {
			$this->rrmdir( $temp_dir );
			return $response;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'download_failed', 'GitHub returned HTTP ' . $code );
		}

		$zip_data = wp_remote_retrieve_body( $response );
		if ( empty( $zip_data ) ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'empty_zip', 'Empty response from GitHub' );
		}

		$temp_zip = $temp_dir . '/download.zip';
		if ( false === file_put_contents( $temp_zip, $zip_data, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'write_failed', 'Failed to write zip' );
		}
		@chmod( $temp_zip, 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$extract_dir = $temp_dir . '/extract';
		if ( ! wp_mkdir_p( $extract_dir ) ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'extract_dir', 'Failed to create extract directory' );
		}

		if ( ! class_exists( 'ZipArchive' ) ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'no_zip', 'ZipArchive class not available' );
		}

		$zip    = new ZipArchive();
		$opened = $zip->open( $temp_zip );
		if ( true !== $opened ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'zip_open', 'Failed to open zip (error ' . $opened . ')' );
		}

		$extracted = $zip->extractTo( $extract_dir );
		$zip->close();
		if ( ! $extracted ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'zip_extract', 'Failed to extract zip' );
		}
		@unlink( $temp_zip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$folders = glob( $extract_dir . '/*', GLOB_ONLYDIR );
		if ( empty( $folders ) ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'no_folder', 'No folder found after extraction' );
		}

		$source = $folders[0];
		if ( $path && '/' !== $path ) {
			$sub = $source . '/' . ltrim( $path, '/' );
			if ( ! is_dir( $sub ) ) {
				$this->rrmdir( $temp_dir );
				return new WP_Error( 'path_not_found', 'Sub-path not found: ' . $path );
			}
			$source = $sub;
		}

		$final_zip = $temp_dir . '/' . $pack . '.zip';
		$new_zip   = new ZipArchive();
		if ( true !== $new_zip->open( $final_zip, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'final_zip', 'Failed to create final zip' );
		}
		$this->add_dir_to_zip( $new_zip, $source, $pack );
		$new_zip->close();
		@chmod( $final_zip, 0644 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$this->rrmdir( $extract_dir );
		return $final_zip;
	}

	private function add_dir_to_zip( ZipArchive $zip, string $source_dir, string $prefix ): void {
		$source_dir = rtrim( $source_dir, '/\\' );
		$iter       = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $source_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ( $iter as $file ) {
			$rel      = substr( $file->getRealPath(), strlen( realpath( $source_dir ) ) + 1 );
			$zip_path = $prefix . '/' . $rel;
			$file->isDir() ? $zip->addEmptyDir( $zip_path ) : $zip->addFile( $file->getRealPath(), $zip_path );
		}
	}

	private function rrmdir( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$iter = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $iter as $f ) {
			$f->isDir() ? rmdir( $f->getRealPath() ) : unlink( $f->getRealPath() );
		}
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	}
}

// Bootstrap.
new STUH_Plugin();

// Settings link in plugins list.
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function ( $links ) {
	array_unshift(
		$links,
		'<a href="' . esc_url( admin_url( 'admin.php?page=stuh' ) ) . '">' . esc_html__( 'Clients', 'stuh' ) . '</a>',
		'<a href="' . esc_url( admin_url( 'admin.php?page=stuh-settings' ) ) . '">' . esc_html__( 'Settings', 'stuh' ) . '</a>'
	);
	return $links;
} );
