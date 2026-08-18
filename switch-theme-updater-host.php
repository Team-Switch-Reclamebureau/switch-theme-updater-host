<?php
/**
 * Plugin Name: Team Switch - Theme Updater Host
 * Plugin URI: https://github.com/Team-Switch-Reclamebureau/switch-theme-updater-host
 * Description: Central update proxy that authenticates client sites and relays GitHub releases without sharing the GitHub token. Manage all client sites from one place and remotely revoke access.
 * Version: 0.2.17
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
define( 'STUH_OPTION_WHITELIST',  'stuh_whitelist' );
define( 'STUH_OPTION_TELEMETRY',  'stuh_telemetry' );
define( 'STUH_REST_NS',           'stu-host/v1' );

// ============================================================
// Main plugin class
// ============================================================
class STUH_Plugin {
	private $clients_page_hook = '';

	/**
	 * Legacy mu-plugin this plugin used to write. It never worked: it hooked a
	 * non-existent `wp_maintenance` filter (the real one is `enable_maintenance_mode`),
	 * and mu-plugins load at wp-settings.php:505 while wp_maintenance() runs at
	 * wp-settings.php:79 — far too late to have any effect. Kept only so existing
	 * installs can have the orphaned file cleaned up.
	 */
	const LEGACY_MU_PLUGIN_FILE = 'stuh-maintenance-bypass.php';

	public function __construct() {
		add_action( 'admin_menu',    [ $this, 'register_admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_clients_styles' ] );
		add_action( 'admin_init',    [ $this, 'handle_admin_actions' ] );
		add_action( 'rest_api_init', [ $this, 'register_rest_routes' ] );
		add_action( 'admin_notices', [ $this, 'maybe_notice_no_token' ] );
		add_action( 'admin_init',    [ $this, 'cleanup_legacy_mu_plugin' ] );

		// Intercept our own plugin update before WordPress tries to HTTP-download
		// from our REST API — which would hit maintenance mode on this same server.
		add_filter( 'upgrader_pre_download', [ $this, 'intercept_self_upgrade' ], 5, 4 );

		// Safety net: switch-theme-updater <= 2.3.0 hooks upgrader_pre_download at
		// priority 10 and ignores the incoming $reply, so it overwrites our result
		// with its own failed loopback download. Re-assert ours last.
		add_filter( 'upgrader_pre_download', [ $this, 'reassert_intercepted_package' ], PHP_INT_MAX, 2 );

		// Self-update: check GitHub for new releases and inject into WP update system.
		add_filter( 'pre_set_site_transient_update_plugins', [ $this, 'self_update_check' ] );
		add_filter( 'plugins_api', [ $this, 'self_plugins_api' ], 10, 3 );
	}

	// --------------------------------------------------------
	// Legacy cleanup
	// --------------------------------------------------------

	/**
	 * Deletes the orphaned maintenance-bypass mu-plugin left behind by <= 0.1.6.
	 *
	 * Maintenance mode cannot be bypassed from an mu-plugin, so the file was
	 * always inert. Self-upgrades are handled in-process by
	 * intercept_self_upgrade() instead, which never touches the local REST API.
	 */
	public function cleanup_legacy_mu_plugin(): void {
		if ( get_option( 'stuh_mu_plugin_cleaned' ) ) {
			return;
		}

		$mu_dir  = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
		$mu_file = $mu_dir . DIRECTORY_SEPARATOR . self::LEGACY_MU_PLUGIN_FILE;

		if ( file_exists( $mu_file ) ) {
			unlink( $mu_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}

		update_option( 'stuh_mu_plugin_cleaned', 1, false );
	}

	// --------------------------------------------------------
	// Self-upgrade: bypass maintenance mode by downloading
	// directly from GitHub instead of via our own REST API
	// --------------------------------------------------------

	/**
	 * Intercepts the WordPress upgrader before it makes an HTTP request for a
	 * package that points back at this same site.
	 *
	 * WP_Upgrader writes the .maintenance file before downloading (see
	 * Plugin_Upgrader::bulk_upgrade(), which the "Update now" button reaches via
	 * wp_ajax_update_plugin()). Any loopback HTTP request made from that point on
	 * is answered by wp_maintenance() with a 503, so an update whose package URL
	 * is hosted on this site can never download itself over HTTP.
	 *
	 * We therefore intercept on the invariant that actually matters — "does this
	 * package URL resolve to this site?" — rather than on which plugin is being
	 * upgraded. Matching on a plugin basename is fragile: it breaks whenever the
	 * plugin is installed under a non-canonical directory name, and it misses
	 * theme updates entirely.
	 *
	 * Priority 5 (lower than the client plugin's filter at 10) ensures we run
	 * first. If another filter already handled the download we pass through.
	 *
	 * @param false|string|\WP_Error $reply      The current reply (false = not yet handled).
	 * @param string                 $package    The package URL from the update transient.
	 * @param \WP_Upgrader           $upgrader   The upgrader instance.
	 * @param array                  $hook_extra Extra args ('plugin' or 'theme' key).
	 * @return false|string|\WP_Error  Local temp-file path on success; false to pass through.
	 */
	public function intercept_self_upgrade( $reply, $package, $upgrader, $hook_extra ) {
		// Already handled by another filter — pass through.
		if ( false !== $reply ) {
			return $reply;
		}

		if ( ! is_string( $package ) || '' === $package ) {
			return false;
		}

		// Only these two URL shapes carry the GitHub coordinates we need to
		// reproduce the download locally.
		$is_host_download    = str_contains( $package, '/wp-json/' . STUH_REST_NS . '/download' );
		$is_updater_download = str_contains( $package, 'action=ghtu_download' );
		if ( ! $is_host_download && ! $is_updater_download ) {
			return false;
		}

		// If the package lives on another server there is no maintenance-mode
		// deadlock — let WordPress fetch it normally. We also intercept whenever
		// maintenance mode is already active, because in that state *any* loopback
		// HTTP request 503s, and the configured host URL may not textually match
		// home_url() (http vs https, localhost:8080 vs site.test, and so on).
		if ( ! $this->is_local_url( $package ) && ! $this->in_maintenance_mode() ) {
			return false;
		}

		$parsed = wp_parse_url( $package );
		if ( empty( $parsed['query'] ) ) {
			return false; // Unexpected format — let WordPress handle it normally.
		}

		wp_parse_str( $parsed['query'], $params );
		$repo = sanitize_text_field( $params['repo'] ?? '' );
		$ref  = sanitize_text_field( $params['ref']  ?? '' );
		$path = sanitize_text_field( $params['path'] ?? '/' );

		// Plugins send 'pack', themes send 'stylesheet'.
		$pack = sanitize_file_name( $params['pack'] ?? $params['stylesheet'] ?? '' );
		if ( '' === $pack ) {
			$pack = basename( $repo );
		}

		if ( ! $repo || ! $ref ) {
			return false;
		}

		// Download straight from GitHub — no HTTP request to this server.
		$zip = $this->github()->download_zipball( $repo, $ref, $path, $pack );

		if ( is_wp_error( $zip ) ) {
			// Deliberately return the error rather than passing through. The HTTP
			// fallback is guaranteed to fail with a misleading 503, so surfacing the
			// real cause (bad token, missing release, etc.) is far more useful.
			error_log( '[STUH] Local package download failed for ' . $repo . '@' . $ref . ': ' . $zip->get_error_message() );
			return $zip;
		}

		// Remember it so reassert_intercepted_package() can restore it if a later
		// filter discards our result, and stop the client plugin from running at all.
		$this->intercepted[ $package ] = $zip;
		$this->disable_client_download_filter();

		return $zip;
	}

	/** Packages we downloaded locally, keyed by the original package URL. */
	private $intercepted = [];

	/**
	 * Removes switch-theme-updater's own upgrader_pre_download handler.
	 *
	 * That handler returns early only when the package URL does *not* match
	 * 'action=ghtu_download'. For URLs that do match it ignores the $reply it was
	 * given and performs its own HTTP download, so a result we already produced at
	 * priority 5 gets thrown away and replaced with a 503 from maintenance mode.
	 *
	 * Removing a later-priority callback from inside a running filter is supported
	 * by WP_Hook, which tracks its own iteration state.
	 */
	private function disable_client_download_filter(): void {
		global $wp_filter;

		if ( empty( $wp_filter['upgrader_pre_download'] ) || ! is_object( $wp_filter['upgrader_pre_download'] ) ) {
			return;
		}

		foreach ( $wp_filter['upgrader_pre_download']->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $callback ) {
				$fn = $callback['function'] ?? null;

				if ( ! is_array( $fn ) || ! is_object( $fn[0] ?? null ) ) {
					continue;
				}
				if ( 'handle_upgrader_download' !== ( $fn[1] ?? '' ) ) {
					continue;
				}

				remove_filter( 'upgrader_pre_download', $fn, $priority );
			}
		}
	}

	/**
	 * Restores a package we downloaded locally if a later filter discarded it.
	 *
	 * Runs at PHP_INT_MAX so it sees whatever the last word was.
	 *
	 * @param false|string|\WP_Error $reply   The current reply.
	 * @param string                 $package The package URL.
	 * @return false|string|\WP_Error
	 */
	public function reassert_intercepted_package( $reply, $package ) {
		if ( ! is_string( $package ) || ! isset( $this->intercepted[ $package ] ) ) {
			return $reply;
		}

		$zip = $this->intercepted[ $package ];

		// Already the value we produced — nothing to do.
		if ( $reply === $zip ) {
			return $reply;
		}

		if ( ! file_exists( $zip ) ) {
			unset( $this->intercepted[ $package ] );
			return $reply;
		}

		error_log( '[STUH] Restoring locally downloaded package that another upgrader_pre_download filter discarded: ' . $package );

		return $zip;
	}

	/**
	 * Whether a URL points back at this same WordPress site.
	 */
	private function is_local_url( string $url ): bool {
		$target = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( '' === $target ) {
			return false;
		}

		foreach ( [ home_url(), site_url() ] as $self_url ) {
			$self = strtolower( (string) wp_parse_url( $self_url, PHP_URL_HOST ) );
			if ( '' !== $self && $target === $self ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether WordPress has this site in maintenance mode right now.
	 *
	 * WP_Upgrader writes ABSPATH/.maintenance before downloading, so this is true
	 * for the whole download+install phase of an upgrade.
	 */
	private function in_maintenance_mode(): bool {
		$file = ABSPATH . '.maintenance';
		if ( ! file_exists( $file ) ) {
			return false;
		}

		$upgrading = null;
		include $file; // Sets $upgrading to a timestamp.

		if ( ! is_int( $upgrading ) ) {
			return false;
		}

		// Core treats a stamp older than 10 minutes as a stale leftover.
		return ( time() - $upgrading ) < 10 * MINUTE_IN_SECONDS;
	}

	// --------------------------------------------------------
	// Self-update: version check + download directly from GitHub
	// --------------------------------------------------------

	/** Slug used in WordPress's update transient. */
	private function self_plugin_basename(): string {
		// Use the WP_PLUGIN_DIR-relative path WordPress registered this plugin under.
		// plugin_basename() resolves symlinks, so we derive it from the registered slug
		// via the plugin headers instead.
		return plugin_basename( __FILE__ );
	}

	/** The GitHub repo this plugin lives in (from plugin header). */
	private function self_github_repo(): string {
		return 'Team-Switch-Reclamebureau/switch-theme-updater-host';
	}

	/**
	 * Checks GitHub for a newer release and, if found, injects an update record
	 * into the WordPress update transient so the Dashboard shows the update.
	 */
	public function self_update_check( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$slug     = $this->self_plugin_basename();
		$current  = $transient->checked[ $slug ] ?? '0.0.0';
		$repo     = $this->self_github_repo();
		$gh       = $this->github();
		$result   = $gh->get_latest_version( $repo, null, '/', 'releases' );

		if ( ! $result || empty( $result['version'] ) || empty( $result['ref'] ) ) {
			return $transient;
		}

		if ( version_compare( $result['version'], $current, '<=' ) ) {
			return $transient;
		}

		// Build a download URL that points to our own REST endpoint —
		// intercept_self_upgrade will catch it and download from GitHub directly.
		$pack        = 'switch-theme-updater-host';
		$download    = add_query_arg(
			[
				'repo' => $repo,
				'ref'  => $result['ref'],
				'path' => '/',
				'pack' => $pack,
			],
			get_rest_url( null, STUH_REST_NS . '/download' )
		);

		$transient->response[ $slug ] = (object) [
			'slug'        => dirname( $slug ),
			'plugin'      => $slug,
			'new_version' => $result['version'],
			'package'     => $download,
			'url'         => 'https://github.com/' . $repo,
		];

		return $transient;
	}

	/**
	 * Supplies plugin information for the "View details" modal in wp-admin.
	 */
	public function self_plugins_api( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}
		if ( ( $args->slug ?? '' ) !== dirname( $this->self_plugin_basename() ) ) {
			return $result;
		}

		$repo   = $this->self_github_repo();
		$latest = $this->github()->get_latest_version( $repo, null, '/', 'releases' );

		return (object) [
			'name'          => 'Team Switch - Theme Updater Host',
			'slug'          => dirname( $this->self_plugin_basename() ),
			'version'       => $latest['version'] ?? '',
			'author'        => 'Team Switch',
			'homepage'      => 'https://github.com/' . $repo,
			'download_link' => add_query_arg(
				[
					'repo' => $repo,
					'ref'  => $latest['ref'] ?? '',
					'path' => '/',
					'pack' => 'switch-theme-updater-host',
				],
				get_rest_url( null, STUH_REST_NS . '/download' )
			),
			'sections'      => [
				'description' => 'Central update proxy. Authenticates client sites and relays GitHub releases without exposing the GitHub token.',
			],
		];
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

	/**
	 * Load IP-to-label map from ip-labels.json. Keys may be exact IPs or
	 * wildcard prefixes ending in *, such as "192.0.2.*" or "2001:db8:*".
	 *
	 * @return array<string, string>
	 */
	public static function get_ip_labels(): array {
		$file = plugin_dir_path( __FILE__ ) . 'ip-labels.json';
		if ( ! file_exists( $file ) ) {
			return [];
		}
		$json = file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$data = json_decode( $json, true );
		return is_array( $data ) ? $data : [];
	}

	/**
	 * Return the human-readable label for an IP, or an empty string if none is defined.
	 * Exact IP entries take precedence over wildcard prefixes; the longest matching
	 * wildcard prefix wins.
	 */
	public static function ip_label( string $ip ): string {
		$labels = self::get_ip_labels();
		if ( isset( $labels[ $ip ] ) && is_string( $labels[ $ip ] ) ) {
			return $labels[ $ip ];
		}

		$label         = '';
		$matched_length = 0;
		foreach ( $labels as $pattern => $candidate_label ) {
			if ( ! is_string( $pattern ) || ! is_string( $candidate_label ) || ! str_ends_with( $pattern, '*' ) ) {
				continue;
			}

			$prefix = substr( $pattern, 0, -1 );
			if ( '' !== $prefix && str_starts_with( $ip, $prefix ) && strlen( $prefix ) > $matched_length ) {
				$label          = $candidate_label;
				$matched_length = strlen( $prefix );
			}
		}

		return $label;
	}

	public static function get_settings(): array {
		$opt = get_option( STUH_OPTION_SETTINGS, [] );
		return wp_parse_args( $opt, [ 'token' => '', 'allow_unverified' => false ] );
	}

	public static function get_clients(): array {
		return (array) get_option( STUH_OPTION_CLIENTS, [] );
	}

	private static function save_clients( array $clients ): void {
		update_option( STUH_OPTION_CLIENTS, array_values( $clients ) );
	}

	/**
	 * @return array<int, string>
	 */
	private static function sanitize_client_tags( string $raw_tags ): array {
		$tags = preg_split( '/[\r\n,]+/', $raw_tags );
		$tags = is_array( $tags ) ? $tags : [];
		$tags = array_map( static fn( string $tag ): string => sanitize_text_field( trim( $tag ) ), $tags );
		$tags = array_filter( $tags, static fn( string $tag ): bool => '' !== $tag );

		return array_values( array_unique( $tags, SORT_STRING ) );
	}

	/**
	 * Build text for the client-list search without exposing private client fields.
	 *
	 * @param array<string, mixed> $client
	 * @param array<string, mixed> $telemetry
	 */
	private static function client_search_text( array $client, array $telemetry ): string {
		$values = [
			...array_map( 'strval', (array) ( $client['site_urls'] ?? [] ) ),
			(string) ( $client['site_url'] ?? '' ),
			...array_map( 'strval', (array) ( $client['tags'] ?? [] ) ),
			(string) ( $client['last_seen_ip'] ?? '' ),
			self::ip_label( (string) ( $client['last_seen_ip'] ?? '' ) ),
		];
		$data = is_array( $telemetry['data'] ?? null ) ? $telemetry['data'] : [];
		$collect_values = static function( array $items ) use ( &$collect_values ): array {
			$collected = [];
			foreach ( $items as $key => $value ) {
				$collected[] = (string) $key;
				if ( is_array( $value ) ) {
					$collected = [ ...$collected, ...$collect_values( $value ) ];
				} elseif ( is_scalar( $value ) ) {
					$collected[] = (string) $value;
				}
			}
			return $collected;
		};

		return implode( ' ', [ ...$values, ...$collect_values( $data ) ] );
	}

	public static function get_unverified(): array {
		return (array) get_option( STUH_OPTION_UNVERIFIED, [] );
	}

	private static function save_unverified( array $records ): void {
		update_option( STUH_OPTION_UNVERIFIED, array_values( $records ) );
	}

	public static function get_whitelist(): array {
		return (array) get_option( STUH_OPTION_WHITELIST, [] );
	}

	private static function save_whitelist( array $entries ): void {
		update_option( STUH_OPTION_WHITELIST, array_values( $entries ) );
	}

	/**
	 * Return the most recent telemetry report for each client, keyed by client ID.
	 *
	 * Telemetry is intentionally stored separately from the client list so
	 * diagnostics do not add to the autoloaded client option.
	 */
	public static function get_telemetry(): array {
		return (array) get_option( STUH_OPTION_TELEMETRY, [] );
	}

	private static function save_telemetry( array $telemetry ): void {
		update_option( STUH_OPTION_TELEMETRY, $telemetry, false );
	}

	/**
	 * Returns true if the given IP is in the whitelist.
	 */
	public static function ip_is_whitelisted( string $ip ): bool {
		foreach ( self::get_whitelist() as $entry ) {
			if ( ( $entry['ip'] ?? '' ) === $ip ) {
				return true;
			}
		}
		return false;
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
			$site_url = self::strip_language_prefix( esc_url_raw( rtrim( $m[1], '/' ) ) );
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

			// Notify on first sighting of this IP.
			$display    = $site_url ?: $ip;
			$admin_url  = admin_url( 'admin.php?page=stuh' );
			wp_mail(
				'online@teamswitch.nl',
				sprintf( '[teamswitch.dev] New unverified access attempt from %s', $display ),
				sprintf(
					"A new unverified access attempt was recorded.\n\n" .
					"IP address : %s\n" .
					"Site URL   : %s\n" .
					"Endpoint   : %s\n" .
					"Reason     : %s\n\n" .
					"Review and allow or dismiss in wp-admin:\n%s",
					$ip,
					$site_url ?: '(unknown)',
					$endpoint,
					$reason,
					$admin_url
				)
			);
		}
	}

	// --------------------------------------------------------
	// Authentication
	// --------------------------------------------------------

	/**
	 * Strip a WPML-style language-code path segment from a site URL so that
	 * https://example.com/en and https://example.com are treated as the same site.
	 * Only a single path segment that is 2-3 ASCII alpha characters is removed;
	 * subdirectory installs (e.g. https://example.com/blog) are left untouched.
	 */
	private static function strip_language_prefix( string $url ): string {
		$parsed = wp_parse_url( $url );
		if ( empty( $parsed['host'] ) ) {
			return $url;
		}
		$path = trim( $parsed['path'] ?? '', '/' );
		// Strip only when the whole path looks like a 2- or 3-letter ISO language code.
		if ( $path !== '' && preg_match( '#^[a-z]{2,3}$#i', $path ) ) {
			$clean = ( $parsed['scheme'] ?? 'https' ) . '://' . $parsed['host'];
			if ( ! empty( $parsed['port'] ) ) {
				$clean .= ':' . $parsed['port'];
			}
			return $clean;
		}
		return $url;
	}

	/**
	 * Find an enabled client that is registered for a site URL.
	 *
	 * @return array|false
	 */
	private static function find_client_by_site_url( string $site_url ) {
		$norm_url = strtolower( rtrim( $site_url, '/' ) );
		if ( '' === $norm_url ) {
			return false;
		}

		foreach ( self::get_clients() as $client ) {
			if ( ! ( $client['enabled'] ?? true ) ) {
				continue;
			}

			$stored_raw  = $client['site_urls'] ?? ( ( $client['site_url'] ?? '' ) !== '' ? [ $client['site_url'] ] : [] );
			$stored_norm = array_map( fn( $url ) => strtolower( rtrim( $url, '/' ) ), $stored_raw );
			if ( in_array( $norm_url, $stored_norm, true ) ) {
				return $client;
			}
		}

		return false;
	}

	/**
	 * Record client activity at most once per five minutes to reduce DB writes.
	 */
	private static function record_client_activity( string $client_id ): void {
		$clients = self::get_clients();

		foreach ( $clients as $index => $client ) {
			if ( $client_id !== ( $client['id'] ?? '' ) ) {
				continue;
			}
			if ( ( time() - ( $client['last_seen'] ?? 0 ) ) > 300 ) {
				$clients[ $index ]['last_seen']    = time();
				$clients[ $index ]['last_seen_ip'] = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );
				self::save_clients( $clients );
			}
			return;
		}
	}

	/**
	 * Validate a raw API key against stored (hashed) client records.
	 * Updates last_seen at most once per 5 minutes to reduce DB writes.
	 *
	 * @param string $raw_key  The plaintext key sent by the client.
	 * @return array|false     The matching client record, or false on failure.
	 */
	public static function authenticate_client( string $raw_key, string $site_url = '' ) {
		if ( empty( $raw_key ) ) {
			return false;
		}

		$clients = self::get_clients();
		$matched = false;

		// Normalise the incoming URL for comparison (lowercase, no trailing slash).
		$norm_url = strtolower( rtrim( $site_url, '/' ) );

		foreach ( $clients as $client ) {
			if ( ! ( $client['enabled'] ?? true ) ) {
				continue;
			}
			if ( ! wp_check_password( $raw_key, $client['api_key_hash'] ) ) {
				continue;
			}
			// Key matches — now verify the site URL against all stored URLs.
			// Support both legacy single site_url and the newer site_urls array.
			$stored_raw  = $client['site_urls'] ?? ( ( $client['site_url'] ?? '' ) !== '' ? [ $client['site_url'] ] : [] );
			$stored_norm = array_map( fn( $u ) => strtolower( rtrim( $u, '/' ) ), $stored_raw );
			if ( ! empty( $stored_norm ) && ! in_array( $norm_url, $stored_norm, true ) ) {
				// Key is valid but no stored URL matches — reject.
				return false;
			}

			$matched = $client;
			break;
		}

		if ( false === $matched ) {
			return false;
		}

		self::record_client_activity( (string) $matched['id'] );

		return $matched;
	}

	/**
	 * Decode and store versioned diagnostics sent by an authenticated client.
	 *
	 * Malformed diagnostics must not prevent a client from checking for updates,
	 * but are logged so a client/host version mismatch remains diagnosable.
	 *
	 * @param array<string, mixed> $client Authenticated client record.
	 */
	private static function record_client_telemetry( array $client, WP_REST_Request $req ): void {
		$metadata = $req->get_header( 'X-STU-Metadata' );
		if ( '' === $metadata ) {
			return;
		}

		$version = $req->get_header( 'X-STU-Metadata-Version' );
		if ( '1' !== $version ) {
			error_log( sprintf( '[STUH telemetry] Unsupported metadata version "%s" for client %s', $version, $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		if ( strlen( $metadata ) > 131072 || ! preg_match( '/^[A-Za-z0-9_-]+$/', $metadata ) ) {
			error_log( sprintf( '[STUH telemetry] Invalid metadata encoding for client %s', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$encoded = strtr( $metadata, '-_', '+/' );
		$encoded .= str_repeat( '=', ( 4 - strlen( $encoded ) % 4 ) % 4 );
		$gzip = base64_decode( $encoded, true );
		if ( false === $gzip ) {
			error_log( sprintf( '[STUH telemetry] Metadata base64 decoding failed for client %s', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$json = gzdecode( $gzip, 1048576 );
		if ( false === $json ) {
			error_log( sprintf( '[STUH telemetry] Metadata gzip decoding failed for client %s', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$data = json_decode( $json, true );
		if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) || array_is_list( $data ) ) {
			error_log( sprintf( '[STUH telemetry] Metadata JSON is not a valid object for client %s', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$client_id = $client['id'] ?? '';
		if ( ! is_string( $client_id ) || '' === $client_id ) {
			error_log( '[STUH telemetry] Authenticated client record has no ID' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$telemetry               = self::get_telemetry();
		$telemetry[ $client_id ] = [
			'version'      => 1,
			'request_type' => sanitize_key( $req->get_header( 'X-STU-Request-Type' ) ),
			'received_at'  => time(),
			'data'         => $data,
		];
		self::save_telemetry( $telemetry );
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

		register_rest_route( STUH_REST_NS, '/validate', [
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => [ $this, 'rest_validate' ],
			'permission_callback' => '__return_true',
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
		$s    = self::get_settings();
		$key  = $req->get_header( 'X-STU-Key' );
		$ip   = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );

		// Extract the site URL from the WordPress User-Agent header.
		// WP sends: "WordPress/6.5; https://example.com"
		$ua       = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' );
		$site_url = '';
		if ( preg_match( '#WordPress/[\d.]+;\s*(https?://[^\s]+)#i', $ua, $m ) ) {
			$site_url = self::strip_language_prefix( esc_url_raw( rtrim( $m[1], '/' ) ) );
		}

		// Whitelisted IPs always pass through, no key required. Associate
		// diagnostics with the registered site identified by its User-Agent.
		if ( $ip && self::ip_is_whitelisted( $ip ) ) {
			$client = self::find_client_by_site_url( $site_url );
			if ( $client ) {
				self::record_client_activity( (string) $client['id'] );
				self::record_client_telemetry( $client, $req );
			}
			return true;
		}

		// Detect requests originating from this site itself (e.g. self-update).
		// Loopback IPs or a User-Agent site URL matching home_url() both count.
		$home      = rtrim( home_url(), '/' );
		$is_self   = in_array( $ip, [ '127.0.0.1', '::1' ], true )
		             || ( $site_url && $site_url === $home );

		if ( empty( $key ) ) {
			if ( ! $is_self ) {
				self::record_unverified( $req, 'missing_key' );
			}
			if ( ! empty( $s['allow_unverified'] ) ) {
				return true;
			}
			return new WP_Error( 'missing_key', 'API key required', [ 'status' => 401 ] );
		}

		$client = self::authenticate_client( $key, $site_url );
		if ( ! $client ) {
			if ( ! $is_self ) {
				self::record_unverified( $req, 'invalid_key' );
			}
			if ( ! empty( $s['allow_unverified'] ) ) {
				return true;
			}
			return new WP_Error( 'invalid_key', 'Invalid or disabled API key', [ 'status' => 403 ] );
		}
		self::record_client_telemetry( $client, $req );
		return true;
	}

	// --------------------------------------------------------
	// REST endpoint: validate licence / API key
	// --------------------------------------------------------

	public function rest_validate( WP_REST_Request $req ) {
		$ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' );

		$key      = $req->get_header( 'X-STU-Key' );
		$ua       = sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' );
		$site_url = '';
		if ( preg_match( '#WordPress/[\d.]+;\s*(https?://[^\s]+)#i', $ua, $m ) ) {
			$site_url = self::strip_language_prefix( esc_url_raw( rtrim( $m[1], '/' ) ) );
		}

		// Whitelisted IPs are always valid, no key required. Associate
		// diagnostics with the registered site identified by its User-Agent.
		if ( $ip && self::ip_is_whitelisted( $ip ) ) {
			$client = self::find_client_by_site_url( $site_url );
			if ( $client ) {
				self::record_client_activity( (string) $client['id'] );
				self::record_client_telemetry( $client, $req );
			}
			return rest_ensure_response( [
				'valid'  => true,
				'method' => 'ip_whitelist',
			] );
		}

		$client = $key ? self::authenticate_client( $key, $site_url ) : false;

		if ( $client ) {
			self::record_client_telemetry( $client, $req );
			error_log( sprintf( '[STUH validate] PASS api_key | ip=%s site=%s', $ip, $client['site_url'] ?? $site_url ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return rest_ensure_response( [
				'valid'    => true,
				'method'   => 'api_key',
				'site_url' => $client['site_url'] ?? '',
			] );
		}

		// Determine whether this is a self-request (same logic as rest_permission).
		$home    = rtrim( home_url(), '/' );
		$is_self = ( $site_url && $site_url === $home );

		$reason = $key ? 'invalid_key' : 'missing_key';
		error_log( sprintf( '[STUH validate] FAIL %s | ip=%s site=%s self=%s', $reason, $ip, $site_url ?: '(unknown)', $is_self ? 'yes' : 'no' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log

		if ( ! $is_self ) {
			self::record_unverified( $req, $reason );
		}

		// allow_unverified let this request through, but the licence is not valid.
		return rest_ensure_response( [ 'valid' => false ] );
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
		$this->clients_page_hook = add_menu_page(
			__( 'Switch Updater Host', 'stuh' ),
			__( 'Updater Host', 'stuh' ),
			'manage_options',
			'stuh',
			[ $this, 'render_clients_page' ],
			'dashicons-cloud',
			59
		);
		add_action( 'load-' . $this->clients_page_hook, [ $this, 'register_clients_screen_options' ] );
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

	/**
	 * Load Client Sites styles only on the Client Sites admin screen.
	 */
	public function enqueue_clients_styles( string $hook ): void {
		if ( $hook !== $this->clients_page_hook ) {
			return;
		}

		$stylesheet = 'assets/css/client-sites.css';
		$path       = plugin_dir_path( __FILE__ ) . $stylesheet;

		wp_enqueue_style(
			'stuh-client-sites',
			plugins_url( $stylesheet, __FILE__ ),
			[],
			(string) filemtime( $path )
		);
	}

	/**
	 * Register Client Sites columns with the native Screen Options panel.
	 */
	public function register_clients_screen_options(): void {
		$screen = get_current_screen();
		if ( ! $screen ) {
			return;
		}

		add_filter( 'manage_' . $screen->id . '_columns', [ $this, 'client_columns' ] );
		add_thickbox();
	}

	/**
	 * @return array<string, string>
	 */
	public function client_columns(): array {
		return [
			'site_url'        => __( 'URL', 'stuh' ),
			'tags'            => __( 'Tags', 'stuh' ),
			'created_at'      => __( 'Created', 'stuh' ),
			'last_seen'       => __( 'Last Seen', 'stuh' ),
			'last_seen_ip'    => __( 'Server / IP', 'stuh' ),
			'telemetry_site'  => __( 'Reported Site URL', 'stuh' ),
			'telemetry_home'  => __( 'Home URL', 'stuh' ),
			'telemetry_admin_email' => __( 'Admin Email', 'stuh' ),
			'telemetry_locale'=> __( 'Locale', 'stuh' ),
			'telemetry_wp'    => __( 'WordPress', 'stuh' ),
			'telemetry_php'   => __( 'PHP', 'stuh' ),
			'telemetry_updater' => __( 'Updater', 'stuh' ),
			'telemetry_pending_updates' => __( 'Pending Updates', 'stuh' ),
			'telemetry_multisite' => __( 'Multisite', 'stuh' ),
			'telemetry_multilanguage' => __( 'Multilanguage', 'stuh' ),
			'telemetry_packages'  => __( 'Packages', 'stuh' ),
			'telemetry_database'  => __( 'Database', 'stuh' ),
			'telemetry_analytics' => __( 'Analytics', 'stuh' ),
			'telemetry_smtp'      => __( 'SMTP', 'stuh' ),
			'telemetry_debug'     => __( 'Debug', 'stuh' ),
			'telemetry_post_revisions' => __( 'Post Revisions', 'stuh' ),
			'telemetry_core_upgrade_skip_new_bundled' => __( 'Skip New Bundled Themes', 'stuh' ),
			'diagnostics'     => __( 'Diagnostics', 'stuh' ),
		];
	}

	/**
	 * Render client actions beneath the primary URL, following WordPress list-table conventions.
	 *
	 * @param array<string, mixed> $client
	 */
	private static function render_client_row_actions( array $client, bool $enabled ): void {
		?>
		<div class="row-actions stuh-client-row-actions">
			<span class="toggle">
				<form method="post">
					<?php wp_nonce_field( 'stuh_admin' ); ?>
					<input type="hidden" name="stuh_action" value="toggle_client">
					<input type="hidden" name="client_id" value="<?php echo esc_attr( $client['id'] ); ?>">
					<button type="submit"><?php echo $enabled ? esc_html__( 'Disable', 'stuh' ) : esc_html__( 'Enable', 'stuh' ); ?></button>
				</form> |
			</span>
			<?php if ( ! empty( $client['api_key'] ) ) : ?>
			<span class="copy-key">
				<button type="button" data-key="<?php echo esc_attr( $client['api_key'] ); ?>" onclick="(function(btn){ navigator.clipboard.writeText(btn.dataset.key).then(function(){ btn.textContent='Copied!'; setTimeout(function(){ btn.textContent='Copy Key'; }, 2000); }); })(this)"><?php esc_html_e( 'Copy Key', 'stuh' ); ?></button> |
			</span>
			<?php endif; ?>
			<span class="edit-urls">
				<button type="button" onclick="(function(btn){ var row = document.getElementById('stuh-edit-urls-<?php echo esc_js( $client['id'] ); ?>'); var hidden = row.style.display === 'none' || row.style.display === ''; row.style.display = hidden ? 'table-row' : 'none'; btn.textContent = hidden ? 'Cancel' : 'Edit URLs'; })(this)"><?php esc_html_e( 'Edit URLs', 'stuh' ); ?></button> |
			</span>
			<span class="edit-tags">
				<button type="button" onclick="(function(btn){ var row = document.getElementById('stuh-edit-tags-<?php echo esc_js( $client['id'] ); ?>'); var hidden = row.style.display === 'none' || row.style.display === ''; row.style.display = hidden ? 'table-row' : 'none'; btn.textContent = hidden ? 'Cancel' : 'Edit Tags'; })(this)"><?php esc_html_e( 'Edit Tags', 'stuh' ); ?></button> |
			</span>
			<span class="delete">
				<form method="post" onsubmit="return confirm('Permanently delete this client site?');">
					<?php wp_nonce_field( 'stuh_admin' ); ?>
					<input type="hidden" name="stuh_action" value="delete_client">
					<input type="hidden" name="client_id" value="<?php echo esc_attr( $client['id'] ); ?>">
					<button type="submit"><?php esc_html_e( 'Delete', 'stuh' ); ?></button>
				</form>
			</span>
		</div>
		<?php
	}

	/**
	 * Return a concise, human-readable value for a telemetry table column.
	 *
	 * @param array<string, mixed> $data
	 */
	private static function telemetry_column_value( string $column, array $data ): string {
		$site     = (array) ( $data['site'] ?? [] );
		$runtime  = (array) ( $data['runtime'] ?? [] );
		$packages = (array) ( $data['packages'] ?? [] );
		$database = (array) ( $data['database'] ?? [] );
		$smtp     = (array) ( $data['smtp'] ?? [] );
		$debug    = (array) ( $data['debug'] ?? [] );
		$wp_config = (array) ( $data['wp_config'] ?? [] );

		switch ( $column ) {
			case 'telemetry_site':
				return (string) ( $site['site_url'] ?? '' );
			case 'telemetry_home':
				return (string) ( $site['home_url'] ?? '' );
			case 'telemetry_admin_email':
				return (string) ( $site['admin_email'] ?? '' );
			case 'telemetry_locale':
				return (string) ( $site['locale'] ?? '' );
			case 'telemetry_wp':
				return (string) ( $runtime['wordpress'] ?? '' );
			case 'telemetry_php':
				return (string) ( $runtime['php'] ?? '' );
			case 'telemetry_updater':
				return (string) ( $runtime['updater'] ?? '' );
			case 'telemetry_pending_updates':
				$pending_updates = $data['pending_updates'] ?? null;
				return is_int( $pending_updates ) && $pending_updates >= 0 ? (string) $pending_updates : '';
			case 'telemetry_multisite':
				if ( ! array_key_exists( 'multisite', $site ) ) {
					return '';
				}
				return ! empty( $site['multisite'] ) ? __( 'Yes', 'stuh' ) : __( 'No', 'stuh' );
			case 'telemetry_multilanguage':
				$multilanguage = $site['multilanguage'] ?? $data['multilanguage'] ?? null;
				if ( null === $multilanguage ) {
					return '';
				}
				return ! empty( $multilanguage ) ? __( 'Yes', 'stuh' ) : __( 'No', 'stuh' );
			case 'telemetry_packages':
				if ( ! array_key_exists( 'plugins', $packages ) && ! array_key_exists( 'themes', $packages ) ) {
					return '';
				}
				$plugins = is_array( $packages['plugins'] ?? null ) ? count( $packages['plugins'] ) : 0;
				$themes  = is_array( $packages['themes'] ?? null ) ? count( $packages['themes'] ) : 0;
				return sprintf( __( '%1$d plugins, %2$d themes', 'stuh' ), $plugins, $themes );
			case 'telemetry_database':
				$size = $database['size_bytes'] ?? null;
				return is_numeric( $size ) ? size_format( (int) $size, 1 ) : '';
			case 'telemetry_analytics':
				return (string) ( $data['analytics'] ?? '' );
			case 'telemetry_smtp':
				if ( ! array_key_exists( 'configured', $smtp ) ) {
					return '';
				}
				$smtp_status = self::smtp_diagnostic_status( $smtp );
				if ( 'healthy' === $smtp_status ) {
					return __( 'FluentSMTP', 'stuh' );
				}
				if ( 'warning' === $smtp_status ) {
					return __( 'FluentSMTP (no alert)', 'stuh' );
				}
				if ( 'unverified' === $smtp_status ) {
					return __( 'Unverified configuration', 'stuh' );
				}
				if ( 'not_configured' === $smtp_status ) {
					return __( 'Not configured', 'stuh' );
				}
				if ( 'error' === $smtp_status ) {
					return __( 'Delivery failed', 'stuh' );
				}
				return ! empty( $smtp['configured'] )
					? __( 'Configured', 'stuh' )
					: __( 'Not configured', 'stuh' );
			case 'telemetry_debug':
				if ( ! array_key_exists( 'wp_debug', $debug ) ) {
					return '';
				}
				return ! empty( $debug['wp_debug'] )
					? sprintf(
						__( 'Enabled (display: %1$s, log: %2$s)', 'stuh' ),
						! empty( $debug['debug_display'] ) ? __( 'yes', 'stuh' ) : __( 'no', 'stuh' ),
						! empty( $debug['debug_log'] ) ? __( 'yes', 'stuh' ) : __( 'no', 'stuh' )
					)
					: __( 'Disabled', 'stuh' );
			case 'telemetry_post_revisions':
				if ( ! array_key_exists( 'post_revisions', $wp_config ) ) {
					return '';
				}
				$post_revisions = $wp_config['post_revisions'];
				if ( true === $post_revisions || 'true' === $post_revisions ) {
					return __( 'Unlimited', 'stuh' );
				}
				if ( false === $post_revisions || 'false' === $post_revisions || 0 === $post_revisions || '0' === $post_revisions ) {
					return __( 'Disabled', 'stuh' );
				}
				return is_scalar( $post_revisions ) ? (string) $post_revisions : '';
			case 'telemetry_core_upgrade_skip_new_bundled':
				if ( ! array_key_exists( 'core_upgrade_skip_new_bundled', $wp_config ) ) {
					return '';
				}
				return ! empty( $wp_config['core_upgrade_skip_new_bundled'] )
					? __( 'Yes', 'stuh' )
					: __( 'No', 'stuh' );
		}

		return '';
	}

	/**
	 * Return an SMTP health status when the complete diagnostic is available.
	 */
	private static function smtp_diagnostic_status( array $smtp ): ?string {
		if ( ! array_key_exists( 'configured', $smtp ) ) {
			return null;
		}
		if ( true !== $smtp['configured'] ) {
			return 'not_configured';
		}
		if ( 'unverified' === ( $smtp['delivery'] ?? null ) ) {
			return 'unverified';
		}
		if ( array_key_exists( 'delivery', $smtp ) && true !== $smtp['delivery'] ) {
			return 'error';
		}
		if ( ! array_key_exists( 'delivery', $smtp ) || ! array_key_exists( 'alert', $smtp ) ) {
			return null;
		}

		return true === $smtp['alert'] ? 'healthy' : 'warning';
	}

	/**
	 * Check whether WordPress offers a maintenance release for a reported version.
	 *
	 * @return array{status: 'current'|'outdated'|'unknown', latest: string, update: string}
	 */
	private static function wordpress_version_safety( string $wordpress_version, string $php_version ): array {
		$unknown = [ 'status' => 'unknown', 'latest' => '', 'update' => '' ];
		if ( ! preg_match( '/^\d+\.\d+(?:\.\d+)?$/', $wordpress_version ) ) {
			return $unknown;
		}

		$cache_key = 'stuh_wp_safety_' . md5( $wordpress_version . '|' . $php_version );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return wp_parse_args( $cached, $unknown );
		}

		$response = wp_remote_get( add_query_arg( [
			'version' => $wordpress_version,
			'php'     => $php_version ?: PHP_VERSION,
			'locale'  => 'en_US',
		], 'https://api.wordpress.org/core/version-check/1.7/' ), [ 'timeout' => 10 ] );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return $unknown;
		}

		$payload = json_decode( wp_remote_retrieve_body( $response ), true );
		$offers  = is_array( $payload['offers'] ?? null ) ? $payload['offers'] : [];
		if ( [] === $offers ) {
			return $unknown;
		}

		$result = [ 'status' => 'current', 'latest' => '', 'update' => '' ];
		foreach ( $offers as $offer ) {
			if ( ! is_array( $offer ) ) {
				continue;
			}
			$offered_version = (string) ( $offer['version'] ?? '' );
			if ( '' === $result['latest'] && preg_match( '/^\d+\.\d+(?:\.\d+)?$/', $offered_version ) ) {
				$result['latest'] = $offered_version;
			}
			if ( $wordpress_version === (string) ( $offer['partial_version'] ?? '' ) ) {
				$result['status'] = 'outdated';
				$result['update'] = $offered_version;
				break;
			}
		}

		set_transient( $cache_key, $result, 12 * HOUR_IN_SECONDS );
		return $result;
	}

	/**
	 * Whether a reported PHP version is supported by the reported WordPress version.
	 *
	 * This reflects the WordPress/PHP compatibility table as of WordPress 7.0.
	 */
	private static function is_php_version_supported_by_wordpress( string $php_version, string $wordpress_version ): ?bool {
		if ( ! preg_match( '/^(\d+\.\d+)/', $wordpress_version, $wordpress_matches ) || ! preg_match( '/^(\d+\.\d+)/', $php_version, $php_matches ) ) {
			return null;
		}

		// this table below is a combination of wordpress php compatibility and php supported versions, as of 2026-08-12
		// https://www.php.net/supported-versions.php
		// https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/

		$supported_php_ranges = [
			'7.0' => [ '8.2', '8.5' ],
			'6.9' => [ '8.2', '8.5' ],
			'6.8' => [ '8.2', '8.4' ],
			'6.7' => [ '8.2', '8.4' ],
			'6.6' => [ '8.2', '8.3' ],
			'6.5' => [ '8.2', '8.3' ],
			'6.4' => [ '8.2', '8.3' ],
		];
		$wordpress_minor = $wordpress_matches[1];
		$php_minor       = $php_matches[1];

		if ( ! isset( $supported_php_ranges[ $wordpress_minor ] ) ) {
			return null;
		}

		[ $minimum_php, $maximum_php ] = $supported_php_ranges[ $wordpress_minor ];

		return version_compare( $php_minor, $minimum_php, '>=' ) && version_compare( $php_minor, $maximum_php, '<=' );
	}

	/**
	 * Whether a PHP version receives regular, non-security-only support from PHP.
	 *
	 * This reflects https://www.php.net/supported-versions.php as of 2026-08-12.
	 */
	private static function is_php_version_regularly_supported( string $php_version ): ?bool {
		if ( ! preg_match( '/^(\d+\.\d+)/', $php_version, $matches ) ) {
			return null;
		}

		[ $minimum_php, $maximum_php ] = [ '8.4', '8.5' ];
		return version_compare( $matches[1], $minimum_php, '>=' ) && version_compare( $matches[1], $maximum_php, '<=' );
	}

	/**
	 * Render the latest reported plugin and theme inventory in a ThickBox dialog.
	 *
	 * @param array<string, mixed> $packages
	 */
	private static function render_packages_dialog( string $dialog_id, array $packages ): void {
		$plugins = is_array( $packages['plugins'] ?? null ) ? $packages['plugins'] : [];
		$themes  = is_array( $packages['themes'] ?? null ) ? $packages['themes'] : [];
		?>
		<div id="<?php echo esc_attr( $dialog_id ); ?>" style="display:none;">
			<div style="padding:16px;">
				<h2 style="margin-top:0;"><?php esc_html_e( 'Reported Packages', 'stuh' ); ?></h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Package', 'stuh' ); ?></th>
							<th><?php esc_html_e( 'Type', 'stuh' ); ?></th>
							<th><?php esc_html_e( 'Version', 'stuh' ); ?></th>
							<th><?php esc_html_e( 'Active', 'stuh' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $plugins as $plugin ) : ?>
						<?php if ( ! is_array( $plugin ) ) { continue; } ?>
						<tr>
							<td>
								<strong><?php echo esc_html( $plugin['name'] ?? $plugin['file'] ?? '' ); ?></strong><br>
								<code><?php echo esc_html( $plugin['file'] ?? '' ); ?></code>
							</td>
							<td><?php esc_html_e( 'Plugin', 'stuh' ); ?></td>
							<td><?php echo esc_html( $plugin['version'] ?? '' ); ?></td>
							<td><?php echo ! empty( $plugin['active'] ) ? esc_html__( 'Yes', 'stuh' ) : esc_html__( 'No', 'stuh' ); ?></td>
						</tr>
					<?php endforeach; ?>
					<?php foreach ( $themes as $theme ) : ?>
						<?php if ( ! is_array( $theme ) ) { continue; } ?>
						<tr>
							<td>
								<strong><?php echo esc_html( $theme['name'] ?? $theme['stylesheet'] ?? '' ); ?></strong><br>
								<code><?php echo esc_html( $theme['stylesheet'] ?? '' ); ?></code>
							</td>
							<td><?php esc_html_e( 'Theme', 'stuh' ); ?></td>
							<td><?php echo esc_html( $theme['version'] ?? '' ); ?></td>
							<td><?php echo ! empty( $theme['active'] ) ? esc_html__( 'Yes', 'stuh' ) : esc_html__( 'No', 'stuh' ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		</div>
		<?php
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
				// Parse one URL per line from the textarea; sanitize and filter empties.
				$lines = explode( "\n", $_POST['site_url'] ?? '' );
				$urls  = array_values( array_filter(
					array_map( fn( $l ) => esc_url_raw( trim( $l ) ), $lines )
				) );
				if ( ! empty( $urls ) ) {
					$raw_key   = bin2hex( random_bytes( 24 ) ); // 48 hex chars, 192 bits
					$clients[] = [
						'id'           => uniqid( 'stuh_', true ),
						'site_url'     => $urls[0], // primary URL (used for display/sorting)
						'site_urls'    => $urls,
						'api_key'      => $raw_key,
						'api_key_hash' => wp_hash_password( $raw_key ),
						'tags'         => [],
						'enabled'      => true,
						'created_at'   => time(),
						'last_seen'    => null,
						'last_seen_ip' => null,
					];
					self::save_clients( $clients );
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $urls[0] ],
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
				$telemetry = self::get_telemetry();
				unset( $telemetry[ $id ] );
				self::save_telemetry( $telemetry );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'edit_client_urls':
				$id    = sanitize_text_field( $_POST['client_id'] ?? '' );
				$lines = explode( "\n", $_POST['site_urls_raw'] ?? '' );
				$urls  = array_values( array_filter(
					array_map( fn( $l ) => esc_url_raw( trim( $l ) ), $lines )
				) );
				foreach ( $clients as &$c ) {
					if ( $c['id'] !== $id ) {
						continue;
					}
					$c['site_urls'] = $urls;
					$c['site_url']  = $urls[0] ?? '';
					break;
				}
				unset( $c );
				self::save_clients( $clients );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'edit_client_tags':
				$id   = sanitize_text_field( $_POST['client_id'] ?? '' );
				$tags = self::sanitize_client_tags( (string) wp_unslash( $_POST['client_tags'] ?? '' ) );
				foreach ( $clients as &$c ) {
					if ( $c['id'] !== $id ) {
						continue;
					}
					$c['tags'] = $tags;
					break;
				}
				unset( $c );
				self::save_clients( $clients );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'regenerate_key':
				$id       = sanitize_text_field( $_POST['client_id'] ?? '' );
				$site_url = '';
				foreach ( $clients as &$c ) {
					if ( $c['id'] === $id ) {
						$raw_key          = bin2hex( random_bytes( 24 ) );
						$c['api_key_hash'] = wp_hash_password( $raw_key );
						$site_url          = $c['site_url'];
						break;
					}
				}
				unset( $c );
				self::save_clients( $clients );
				if ( $site_url ) {
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $site_url ],
						120
					);
				}
				wp_safe_redirect( admin_url( 'admin.php?page=stuh' ) );
				exit;

			case 'save_settings':
				$token            = sanitize_text_field( $_POST['token'] ?? '' );
				$allow_unverified = ! empty( $_POST['allow_unverified'] );
				update_option( STUH_OPTION_SETTINGS, [ 'token' => $token, 'allow_unverified' => $allow_unverified ] );
				wp_safe_redirect( add_query_arg( 'stuh_saved', '1', admin_url( 'admin.php?page=stuh-settings' ) ) );
				exit;

			case 'check_for_updates':
				// Bust GitHub API cache so a fresh version check is performed.
				global $wpdb;
				$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_stuh_gh_%' OR option_name LIKE '_transient_timeout_stuh_gh_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				// Delete the cached transient so WordPress re-checks immediately.
				delete_site_transient( 'update_plugins' );
				// Trigger the check synchronously so the result is ready when we redirect.
				wp_update_plugins();
				$slug    = plugin_basename( __FILE__ );
				$updates = get_site_transient( 'update_plugins' );
				if ( isset( $updates->response[ $slug ] ) ) {
					$status = 'update_available';
				} else {
					$status = 'up_to_date';
				}
				wp_safe_redirect( add_query_arg( 'stuh_update_check', $status, admin_url( 'admin.php?page=stuh-settings' ) ) );
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

			case 'add_whitelist':
				$wl_ip   = sanitize_text_field( trim( $_POST['wl_ip']   ?? '' ) );
				$wl_name = sanitize_text_field( trim( $_POST['wl_name'] ?? '' ) );
				if ( $wl_ip && $wl_name ) {
					// Basic IP validation (IPv4 and IPv6).
					if ( filter_var( $wl_ip, FILTER_VALIDATE_IP ) ) {
						$whitelist   = self::get_whitelist();
						$whitelist[] = [
							'id'         => uniqid( 'stuh_wl_', true ),
							'ip'         => $wl_ip,
							'label'      => $wl_name,
							'created_at' => time(),
						];
						self::save_whitelist( $whitelist );
					}
				}
				wp_safe_redirect( admin_url( 'admin.php?page=stuh-settings' ) );
				exit;

			case 'delete_whitelist':
				$wl_id     = sanitize_text_field( $_POST['wl_id'] ?? '' );
				$whitelist = array_values( array_filter( self::get_whitelist(), fn( $e ) => $e['id'] !== $wl_id ) );
				self::save_whitelist( $whitelist );
				wp_safe_redirect( admin_url( 'admin.php?page=stuh-settings' ) );
				exit;

			case 'promote_unverified':
				$id      = sanitize_text_field( $_POST['unverified_id'] ?? '' );
				$records = self::get_unverified();
				$entry   = null;
				foreach ( $records as $r ) {
					if ( $r['id'] === $id ) { $entry = $r; break; }
				}
				if ( $entry ) {
					$raw_key = bin2hex( random_bytes( 24 ) );
					$clients = self::get_clients();
					$site    = $entry['site_url'] ?: '';
					$clients[] = [
						'id'           => uniqid( 'stuh_', true ),
						'site_url'     => $site,
						'site_urls'    => $site ? [ $site ] : [],
						'api_key'      => $raw_key,
						'api_key_hash' => wp_hash_password( $raw_key ),
						'tags'         => [],
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
						[ 'key' => $raw_key, 'site' => $entry['site_url'] ?: $entry['ip'] ],
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
		$telemetry = self::get_telemetry();
		$client_tags = [];
		foreach ( $clients as $client ) {
			foreach ( (array) ( $client['tags'] ?? [] ) as $tag ) {
				$client_tags[ $tag ] = $tag;
			}
		}
		natcasesort( $client_tags );
		$screen = get_current_screen();
		$columns = $screen ? get_column_headers( $screen ) : $this->client_columns();
		$hidden_columns = $screen ? get_hidden_columns( $screen ) : [];
		$visible_column_count = count( array_diff_key( $columns, array_flip( $hidden_columns ) ) );
		$uid     = get_current_user_id();
		$new_key = get_transient( 'stuh_new_key_' . $uid );
		if ( $new_key ) {
			delete_transient( 'stuh_new_key_' . $uid );
		}
		?>
		<div class="wrap stuh-client-sites">
			<h1><?php esc_html_e( 'Switch Updater Host — Client Sites', 'stuh' ); ?></h1>

			<?php if ( $new_key ) : ?>
			<div class="notice notice-success" style="padding: 16px 16px 8px;">
				<h3 style="margin-top: 0;">&#128274; New API Key</h3>
				<p><strong>This key is shown only once. Copy it before leaving this page.</strong></p>
				<code id="stuh-api-key" style="display:block;font-size:14px;background:#f0f0f1;padding:10px 14px;border-radius:4px;word-break:break-all;user-select:all;margin-bottom:12px;"><?php echo esc_html( $new_key['key'] ); ?></code>
			</div>
			<?php endif; ?>

			<?php
			// Sorting.
			$allowed_cols = array_diff( array_keys( $columns ), [ 'diagnostics' ] );
			$orderby      = in_array( $_GET['orderby'] ?? '', $allowed_cols, true ) ? $_GET['orderby'] : 'site_url';
			$order        = strtolower( $_GET['order'] ?? 'asc' ) === 'desc' ? 'desc' : 'asc';
			$opposite     = $order === 'asc' ? 'desc' : 'asc';
			$search_query = sanitize_text_field( wp_unslash( $_GET['stuh_search'] ?? '' ) );

			usort( $clients, function( $a, $b ) use ( $orderby, $order, $telemetry ) {
				$va = $a[ $orderby ] ?? '';
				$vb = $b[ $orderby ] ?? '';
				if ( 'tags' === $orderby ) {
					$va = implode( ', ', (array) $va );
					$vb = implode( ', ', (array) $vb );
				}
				if ( str_starts_with( $orderby, 'telemetry_' ) ) {
					$data_a = is_array( $telemetry[ $a['id'] ]['data'] ?? null ) ? $telemetry[ $a['id'] ]['data'] : [];
					$data_b = is_array( $telemetry[ $b['id'] ]['data'] ?? null ) ? $telemetry[ $b['id'] ]['data'] : [];
					if ( 'telemetry_database' === $orderby ) {
						$database_a = is_array( $data_a['database'] ?? null ) ? $data_a['database'] : [];
						$database_b = is_array( $data_b['database'] ?? null ) ? $data_b['database'] : [];
						$va         = $database_a['size_bytes'] ?? null;
						$vb         = $database_b['size_bytes'] ?? null;
					} elseif ( 'telemetry_smtp' === $orderby ) {
						$smtp_a = is_array( $data_a['smtp'] ?? null ) ? $data_a['smtp'] : [];
						$smtp_b = is_array( $data_b['smtp'] ?? null ) ? $data_b['smtp'] : [];
						$ranks  = [ 'error' => 1, 'unverified' => 2, 'warning' => 3, 'not_configured' => 4, 'healthy' => 6 ];
						$status_a = self::smtp_diagnostic_status( $smtp_a );
						$status_b = self::smtp_diagnostic_status( $smtp_b );
						$va       = array_key_exists( 'configured', $smtp_a ) ? ( $ranks[ $status_a ] ?? 3 ) : null;
						$vb       = array_key_exists( 'configured', $smtp_b ) ? ( $ranks[ $status_b ] ?? 3 ) : null;
					} else {
						$va = self::telemetry_column_value( $orderby, $data_a );
						$vb = self::telemetry_column_value( $orderby, $data_b );
					}
				}
				// Nulls last.
				if ( $va === null || $va === '' ) return $order === 'asc' ? 1 : -1;
				if ( $vb === null || $vb === '' ) return $order === 'asc' ? -1 : 1;
				if ( 'last_seen_ip' === $orderby ) {
					$ip_a    = (string) $va;
					$ip_b    = (string) $vb;
					$label_a = self::ip_label( $ip_a );
					$label_b = self::ip_label( $ip_b );
					$cmp     = strcasecmp( $label_a ?: $ip_a, $label_b ?: $ip_b );
					if ( 0 === $cmp ) {
						$cmp = strcasecmp( $ip_a, $ip_b );
					}
					return $order === 'asc' ? $cmp : -$cmp;
				}
				$cmp = in_array( $orderby, [ 'telemetry_wp', 'telemetry_php' ], true )
					? version_compare( (string) $va, (string) $vb )
					: ( is_numeric( $va ) ? ( $va <=> $vb ) : strcasecmp( (string) $va, (string) $vb ) );
				return $order === 'asc' ? $cmp : -$cmp;
			} );

			$sort_url = function( string $col ) use ( $orderby, $order, $opposite, $search_query ): string {
				$args = [
					'page'    => 'stuh',
					'orderby' => $col,
					'order'   => $orderby === $col ? $opposite : 'asc',
				];
				if ( '' !== $search_query ) {
					$args['stuh_search'] = $search_query;
				}

				return esc_url( add_query_arg( $args, admin_url( 'admin.php' ) ) );
			};
			$sort_indicator = function( string $col ) use ( $orderby, $order ): string {
				if ( $orderby !== $col ) return '';
				return ' <span class="dashicons dashicons-arrow-' . ( $order === 'asc' ? 'up' : 'down' ) . '" style="vertical-align:middle;font-size:14px;"></span>';
			};
			?>
			<p class="search-box" style="float:none;margin:20px 0 10px;">
				<label class="screen-reader-text" for="stuh-client-search"><?php esc_html_e( 'Search client sites', 'stuh' ); ?></label>
				<input type="search" id="stuh-client-search" value="<?php echo esc_attr( $search_query ); ?>" placeholder="<?php esc_attr_e( 'Search tags, URLs, plugins, themes, and more... Use -term to exclude.', 'stuh' ); ?>">
				<span id="stuh-client-search-count" aria-live="polite"></span>
			</p>
			<?php if ( $client_tags ) : ?>
			<div class="stuh-client-tag-filters" aria-label="<?php esc_attr_e( 'Filter client sites by tag', 'stuh' ); ?>">
				<strong><?php esc_html_e( 'Filter by tag:', 'stuh' ); ?></strong>
				<?php foreach ( $client_tags as $tag ) : ?>
				<button type="button" class="stuh-client-tag stuh-client-tag--<?php echo esc_attr( sanitize_html_class( strtolower( $tag ) ) ); ?>" data-tag="<?php echo esc_attr( $tag ); ?>"><?php echo esc_html( $tag ); ?></button>
				<?php endforeach; ?>
			</div>
			<?php endif; ?>

			<table class="wp-list-table widefat" style="margin-top: 20px;">
				<thead>
					<tr>
						<?php foreach ( $columns as $column_id => $column_label ) : ?>
						<th scope="col" id="<?php echo esc_attr( $column_id ); ?>" class="manage-column column-<?php echo esc_attr( $column_id ); ?><?php echo in_array( $column_id, $hidden_columns, true ) ? ' hidden' : ''; ?>">
							<?php if ( in_array( $column_id, $allowed_cols, true ) ) : ?>
								<a href="<?php echo $sort_url( $column_id ); ?>"><?php echo esc_html( $column_label ); ?><?php echo $sort_indicator( $column_id ); ?></a>
							<?php else : ?>
								<?php echo esc_html( $column_label ); ?>
							<?php endif; ?>
						</th>
						<?php endforeach; ?>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $clients ) ) : ?>
					<tr>
						<td colspan="<?php echo esc_attr( $visible_column_count ); ?>" class="colspanchange" style="padding: 16px;">
							<em><?php esc_html_e( 'No client sites registered yet. Add one below.', 'stuh' ); ?></em>
						</td>
					</tr>
					<?php else : ?>
					<?php $row_index = 0; foreach ( $clients as $c ) :
						$enabled = (bool) ( $c['enabled'] ?? true );
						$row_bg  = ( $row_index % 2 === 0 ) ? 'background-color:#f6f7f7;' : '';
						$search_telemetry = is_array( $telemetry[ $c['id'] ] ?? null ) ? $telemetry[ $c['id'] ] : [];
						$row_index++;
					?>
					<tr class="stuh-client-row" data-client-id="<?php echo esc_attr( $c['id'] ); ?>" data-search="<?php echo esc_attr( self::client_search_text( $c, $search_telemetry ) ); ?>" style="<?php echo $row_bg; ?>">
						<?php
						$report = $telemetry[ $c['id'] ] ?? null;
						$data   = is_array( $report['data'] ?? null ) ? $report['data'] : [];
						foreach ( $columns as $column_id => $column_label ) :
						?>
						<td class="column-<?php echo esc_attr( $column_id ); ?><?php echo in_array( $column_id, $hidden_columns, true ) ? ' hidden' : ''; ?>">
						<?php if ( 'site_url' === $column_id ) : ?>
							<?php
							$all_urls = $c['site_urls'] ?? ( ( $c['site_url'] ?? '' ) !== '' ? [ $c['site_url'] ] : [] );
							foreach ( $all_urls as $url_index => $u ) :
							?>
							<a href="<?php echo esc_url( $u ); ?>" target="_blank" rel="noopener">
								<?php echo esc_html( preg_replace( '#^https?://#', '', $u ) ); ?>
							</a><?php if ( ! $enabled && 0 === $url_index ) : ?> <span class="post-state"><strong>&mdash; <?php esc_html_e( 'Disabled', 'stuh' ); ?></strong></span><?php endif; ?><br>
							<?php endforeach; ?>
							<?php self::render_client_row_actions( $c, $enabled ); ?>
						<?php elseif ( 'tags' === $column_id ) : ?>
							<?php $tags = (array) ( $c['tags'] ?? [] ); ?>
							<?php if ( $tags ) : ?>
								<?php foreach ( $tags as $tag ) : ?>
									<button type="button" class="stuh-client-tag stuh-client-tag--<?php echo esc_attr( sanitize_html_class( strtolower( $tag ) ) ); ?>" data-tag="<?php echo esc_attr( $tag ); ?>"><?php echo esc_html( $tag ); ?></button>
								<?php endforeach; ?>
							<?php else : ?>
								<em>&mdash;</em>
							<?php endif; ?>
						<?php elseif ( 'created_at' === $column_id ) : ?>
							<?php echo esc_html( $c['created_at'] ? date_i18n( 'Y-m-d', $c['created_at'] ) : '—' ); ?>
						<?php elseif ( 'last_seen' === $column_id ) : ?>
							<?php if ( $c['last_seen'] ) : ?>
								<?php echo esc_html( date_i18n( 'Y-m-d H:i', $c['last_seen'] ) ); ?>
							<?php else : ?>
								<em>Never</em>
							<?php endif; ?>
						<?php elseif ( 'last_seen_ip' === $column_id ) : ?>
							<?php
								$lsip    = $c['last_seen_ip'] ?? '';
								$lslabel = $lsip ? self::ip_label( $lsip ) : '';
							?>
							<?php if ( $lsip ) : ?>
								<?php if ( $lslabel ) : ?>
									<?php echo esc_html( $lslabel ); ?><br>
								<?php endif; ?>
								<code><?php echo esc_html( $lsip ); ?></code>
							<?php else : ?>
								<em>&mdash;</em>
							<?php endif; ?>
						<?php elseif ( 'telemetry_wp' === $column_id || 'telemetry_php' === $column_id ) : ?>
							<?php
							$value             = self::telemetry_column_value( $column_id, $data );
							$wordpress_version = self::telemetry_column_value( 'telemetry_wp', $data );
							$php_version       = self::telemetry_column_value( 'telemetry_php', $data );
							$php_wordpress_supported = self::is_php_version_supported_by_wordpress( $php_version, $wordpress_version );
							$php_regularly_supported = self::is_php_version_regularly_supported( $php_version );
							$wp_safety = 'telemetry_wp' === $column_id && $value
								? self::wordpress_version_safety( $wordpress_version, $php_version )
								: [ 'status' => 'unknown', 'latest' => '', 'update' => '' ];
							$is_problem = ( 'telemetry_wp' === $column_id && 'outdated' === $wp_safety['status'] )
								|| ( 'telemetry_php' === $column_id && $value && false === $php_wordpress_supported );
							$is_warning = ( 'telemetry_wp' === $column_id
									&& 'current' === $wp_safety['status']
									&& $wp_safety['latest']
									&& $value !== $wp_safety['latest'] )
								|| ( 'telemetry_php' === $column_id && $value && ! $is_problem && false === $php_regularly_supported );
							$style             = $is_problem
								? ' style="color:#d63638;font-weight:600;"'
								: ( $is_warning ? ' style="color:#dba617;font-weight:600;"' : '' );
							$title = '';
							if ( 'telemetry_wp' === $column_id && 'outdated' === $wp_safety['status'] ) {
								$title = sprintf( __( 'Security or maintenance update available: %s', 'stuh' ), $wp_safety['update'] );
							} elseif ( 'telemetry_wp' === $column_id && 'current' === $wp_safety['status'] && $wp_safety['latest'] && $value !== $wp_safety['latest'] ) {
								$title = sprintf( __( 'Current within this branch. Newest WordPress release: %s', 'stuh' ), $wp_safety['latest'] );
							} elseif ( 'telemetry_wp' === $column_id && 'unknown' === $wp_safety['status'] ) {
								$title = __( 'Could not verify the WordPress update status.', 'stuh' );
							}
							?>
							<span<?php echo $style; ?><?php echo $title ? ' title="' . esc_attr( $title ) . '"' : ''; ?>><?php echo esc_html( $value ); ?></span>
						<?php elseif ( 'telemetry_smtp' === $column_id ) : ?>
							<?php
							$smtp_status = self::smtp_diagnostic_status( (array) ( $data['smtp'] ?? [] ) );
							$value       = self::telemetry_column_value( $column_id, $data );
							?>
							<?php if ( 'healthy' === $smtp_status ) : ?>
								<span style="color:#46b450;font-weight:600;">&#10003; <?php echo esc_html( $value ); ?></span>
							<?php elseif ( 'warning' === $smtp_status ) : ?>
								<span style="color:#dba617;font-weight:600;"><?php echo esc_html( $value ); ?></span>
							<?php elseif ( 'error' === $smtp_status ) : ?>
								<span style="color:#d63638;font-weight:600;"><?php echo esc_html( $value ); ?></span>
							<?php else : ?>
								<?php echo esc_html( $value ); ?>
							<?php endif; ?>
						<?php elseif ( 'diagnostics' === $column_id ) : ?>
							<?php if ( is_array( $report ) && ! empty( $report['received_at'] ) ) : ?>
								<details>
									<summary>
										<?php echo esc_html( date_i18n( 'Y-m-d H:i', $report['received_at'] ) ); ?>
										<?php if ( ! empty( $report['request_type'] ) ) : ?>
											&mdash; <?php echo esc_html( $report['request_type'] ); ?>
										<?php endif; ?>
									</summary>
									<pre style="max-height:240px;overflow:auto;white-space:pre-wrap;"><?php echo esc_html( wp_json_encode( $report['data'] ?? [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre>
								</details>
							<?php else : ?>
								<em>None received</em>
							<?php endif; ?>
						<?php else : ?>
							<?php
							$packages = is_array( $data['packages'] ?? null ) ? $data['packages'] : [];
							if ( 'telemetry_packages' === $column_id && ! empty( $packages ) ) {
								$dialog_id = 'stuh-packages-' . md5( (string) $c['id'] );
								$value     = self::telemetry_column_value( $column_id, $data );
								?>
								<a href="#TB_inline?width=700&amp;height=500&amp;inlineId=<?php echo esc_attr( $dialog_id ); ?>" class="thickbox">
									<?php echo esc_html( $value ); ?>
								</a>
								<?php self::render_packages_dialog( $dialog_id, $packages ); ?>
								<?php
							} else {
								$value = self::telemetry_column_value( $column_id, $data );
								echo esc_html( $value );
							}
							?>
						<?php endif; ?>
						</td>
						<?php endforeach; ?>
					</tr>
					<!-- Inline edit-URLs row (hidden by default) -->
					<tr id="stuh-edit-urls-<?php echo esc_attr( $c['id'] ); ?>" class="stuh-client-detail-row" data-client-id="<?php echo esc_attr( $c['id'] ); ?>" style="display:none;background:#f6f7f7;">
						<td colspan="<?php echo esc_attr( $visible_column_count ); ?>" class="colspanchange" style="padding:12px 16px;">
							<form method="post">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="edit_client_urls">
								<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
								<label style="display:block;font-weight:600;margin-bottom:6px;">
									<?php esc_html_e( 'Allowed URLs (one per line)', 'stuh' ); ?>
								</label>
								<textarea name="site_urls_raw" rows="4" class="large-text code" style="max-width:600px;font-size:13px;"><?php
									$edit_urls = $c['site_urls'] ?? ( ( $c['site_url'] ?? '' ) !== '' ? [ $c['site_url'] ] : [] );
									echo esc_textarea( implode( "\n", $edit_urls ) );
								?></textarea>
								<p class="description" style="margin-top:4px;">
									<?php esc_html_e( 'Each line must be a full URL. The first URL is used as the primary display URL.', 'stuh' ); ?>
								</p>
								<button type="submit" class="button button-primary" style="margin-top:8px;">
									<?php esc_html_e( 'Save URLs', 'stuh' ); ?>
								</button>
							</form>
						</td>
					</tr>
					<tr id="stuh-edit-tags-<?php echo esc_attr( $c['id'] ); ?>" class="stuh-client-detail-row" data-client-id="<?php echo esc_attr( $c['id'] ); ?>" style="display:none;background:#f6f7f7;">
						<td colspan="<?php echo esc_attr( $visible_column_count ); ?>" class="colspanchange" style="padding:12px 16px;">
							<form method="post">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="edit_client_tags">
								<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
								<label for="stuh-client-tags-<?php echo esc_attr( $c['id'] ); ?>" style="display:block;font-weight:600;margin-bottom:6px;">
									<?php esc_html_e( 'Tags', 'stuh' ); ?>
								</label>
								<input type="text" id="stuh-client-tags-<?php echo esc_attr( $c['id'] ); ?>" name="client_tags" class="regular-text" value="<?php echo esc_attr( implode( ', ', (array) ( $c['tags'] ?? [] ) ) ); ?>">
								<p class="description" style="margin-top:4px;">
									<?php esc_html_e( 'Separate tags with commas or new lines.', 'stuh' ); ?>
								</p>
								<button type="submit" class="button button-primary">
									<?php esc_html_e( 'Save Tags', 'stuh' ); ?>
								</button>
							</form>
						</td>
					</tr>
					<?php endforeach; ?>
					<?php endif; ?>
					<tr id="stuh-client-no-matches" style="display:none;">
						<td colspan="<?php echo esc_attr( $visible_column_count ); ?>" class="colspanchange" style="padding:16px;">
							<em><?php esc_html_e( 'No client sites match this search.', 'stuh' ); ?></em>
						</td>
					</tr>
				</tbody>
			</table>
			<script>
			(function() {
				var search = document.getElementById('stuh-client-search');
				var rows = Array.prototype.slice.call(document.querySelectorAll('.stuh-client-row'));
				var detailRows = Array.prototype.slice.call(document.querySelectorAll('.stuh-client-detail-row'));
				var count = document.getElementById('stuh-client-search-count');
				var noMatches = document.getElementById('stuh-client-no-matches');
				var sortLinks = Array.prototype.slice.call(document.querySelectorAll('.wp-list-table thead .manage-column a'));

				if (!search || !rows.length) {
					return;
				}

				function applyFilter() {
					var query = search.value.trim().toLocaleLowerCase();
					var terms = query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
					var visible = 0;

					rows.forEach(function(row) {
						var searchableText = row.dataset.search.toLocaleLowerCase();
						var matches = terms.every(function(term) {
							var excluded = term.charAt(0) === '-' && term.length > 1;
							term = (excluded ? term.slice(1) : term).replace(/^"|"$/g, '');
							if (excluded) {
								return searchableText.indexOf(term) === -1;
							}
							return !term || searchableText.indexOf(term) !== -1;
						});
						row.style.display = matches ? '' : 'none';
						if (matches) {
							row.style.backgroundColor = visible % 2 === 0 ? '#f6f7f7' : '';
							visible++;
						}
					});
					detailRows.forEach(function(row) {
						if (query && row.style.display !== 'none') {
							row.style.display = 'none';
						}
					});
					noMatches.style.display = query && visible === 0 ? '' : 'none';
					count.textContent = query ? visible + ' matching client' + (visible === 1 ? '' : 's') : '';
				}

				search.addEventListener('input', function() {
					var url = new URL(window.location.href);
					if (search.value.trim()) {
						url.searchParams.set('stuh_search', search.value);
					} else {
						url.searchParams.delete('stuh_search');
					}
					window.history.replaceState({}, '', url);
					sortLinks.forEach(function(link) {
						var sortUrl = new URL(link.href);
						if (search.value.trim()) {
							sortUrl.searchParams.set('stuh_search', search.value);
						} else {
							sortUrl.searchParams.delete('stuh_search');
						}
						link.href = sortUrl;
					});
					applyFilter();
				});

				document.querySelectorAll('.stuh-client-tag').forEach(function(tag) {
					tag.addEventListener('click', function() {
						search.value = tag.dataset.tag;
						search.dispatchEvent(new Event('input', { bubbles: true }));
						search.focus();
					});
				});

				applyFilter();
			})();
			</script>

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
					<td>
						<?php
						$uv_label = self::ip_label( $uv['ip'] );
						if ( $uv_label ) :
						?>
							<?php echo esc_html( $uv_label ); ?><br>
						<?php endif; ?>
						<code><?php echo esc_html( $uv['ip'] ); ?></code>
					</td>
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
						<label for="site_url"><?php esc_html_e( 'Site URLs', 'stuh' ); ?></label>
					</th>
					<td>
						<textarea id="site_url" name="site_url" rows="3"
								  class="large-text code" placeholder="https://example.com&#10;https://example.nl&#10;https://example.de" required></textarea>
						<p class="description">
							<?php esc_html_e( 'Enter one URL per line. All URLs must match the WordPress site URL of the client (without trailing slash). For multilingual sites on different TLDs, add each domain on a separate line.', 'stuh' ); ?>
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

		<?php if ( isset( $_GET['stuh_update_check'] ) ) : ?>
			<?php if ( 'update_available' === $_GET['stuh_update_check'] ) : ?>
			<div class="notice notice-warning is-dismissible">
				<p>
					<?php esc_html_e( 'An update is available for Switch Updater Host.', 'stuh' ); ?>
					<a href="<?php echo esc_url( admin_url( 'update-core.php' ) ); ?>">
						<?php esc_html_e( 'Go to Updates &rarr;', 'stuh' ); ?>
					</a>
				</p>
			</div>
			<?php else : ?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Switch Updater Host is up to date.', 'stuh' ); ?></p>
			</div>
			<?php endif; ?>
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
					<tr>
						<th scope="row">
							<?php esc_html_e( 'Allow Unverified Updates', 'stuh' ); ?>
						</th>
						<td>
							<label>
								<input type="checkbox" name="allow_unverified" value="1"
									<?php checked( $s['allow_unverified'] ?? false ); ?>>
								<?php esc_html_e( 'Allow sites without a registered API key to fetch updates', 'stuh' ); ?>
							</label>
							<p class="description">
								<?php esc_html_e( 'When enabled, any site can access the update endpoints without authentication. Unverified requests are still logged. Use with caution.', 'stuh' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save Settings', 'stuh' ) ); ?>
			</form>

			<hr>
			<h2><?php esc_html_e( 'IP Whitelist', 'stuh' ); ?></h2>
			<p><?php esc_html_e( 'IPs listed here always have access to the update endpoints, even without an API key.', 'stuh' ); ?></p>

			<?php $whitelist = self::get_whitelist(); ?>
			<?php if ( ! empty( $whitelist ) ) : ?>
			<table class="wp-list-table widefat fixed striped" style="max-width:700px;margin-bottom:16px;">
				<thead>
					<tr>
						<th style="width:30%;"><?php esc_html_e( 'Label', 'stuh' ); ?></th>
						<th style="width:30%;"><?php esc_html_e( 'IP Address', 'stuh' ); ?></th>
						<th style="width:20%;"><?php esc_html_e( 'Added', 'stuh' ); ?></th>
						<th style="width:20%;"><?php esc_html_e( 'Actions', 'stuh' ); ?></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $whitelist as $wl ) : ?>
					<tr>
						<td><strong><?php echo esc_html( $wl['label'] ); ?></strong></td>
						<td><code><?php echo esc_html( $wl['ip'] ); ?></code></td>
						<td><?php echo esc_html( date_i18n( 'Y-m-d', $wl['created_at'] ) ); ?></td>
						<td>
							<form method="post" style="display:inline-block;"
								  onsubmit="return confirm('Remove this IP from the whitelist?');">
								<?php wp_nonce_field( 'stuh_admin' ); ?>
								<input type="hidden" name="stuh_action" value="delete_whitelist">
								<input type="hidden" name="wl_id" value="<?php echo esc_attr( $wl['id'] ); ?>">
								<button type="submit" class="button" style="color:#d63638;border-color:#d63638;">
									<?php esc_html_e( 'Remove', 'stuh' ); ?>
								</button>
							</form>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php else : ?>
			<p><em><?php esc_html_e( 'No IPs whitelisted yet.', 'stuh' ); ?></em></p>
			<?php endif; ?>

			<form method="post" style="max-width:700px;">
				<?php wp_nonce_field( 'stuh_admin' ); ?>
				<input type="hidden" name="stuh_action" value="add_whitelist">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="wl_name"><?php esc_html_e( 'Label', 'stuh' ); ?></label>
						</th>
						<td>
							<input type="text" id="wl_name" name="wl_name"
								   class="regular-text" placeholder="<?php esc_attr_e( 'e.g. Office', 'stuh' ); ?>" required>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="wl_ip"><?php esc_html_e( 'IP Address', 'stuh' ); ?></label>
						</th>
						<td>
							<input type="text" id="wl_ip" name="wl_ip"
								   class="regular-text" placeholder="<?php esc_attr_e( '203.0.113.1', 'stuh' ); ?>" required>
							<p class="description"><?php esc_html_e( 'IPv4 or IPv6. Ranges are not supported.', 'stuh' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Add to Whitelist', 'stuh' ), 'secondary' ); ?>
			</form>

			<hr>
			<h2><?php esc_html_e( 'Plugin Updates', 'stuh' ); ?></h2>
			<p>
				<?php
				$plugin_data = get_plugin_data( __FILE__ );
				/* translators: %s: current version number */
				printf( esc_html__( 'Current version: %s', 'stuh' ), '<strong>' . esc_html( $plugin_data['Version'] ) . '</strong>' );
				?>
			</p>
			<form method="post">
				<?php wp_nonce_field( 'stuh_admin' ); ?>
				<input type="hidden" name="stuh_action" value="check_for_updates">
				<?php submit_button( __( 'Check for Updates Now', 'stuh' ), 'secondary' ); ?>
			</form>

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
				$result = null;
				if ( ! is_wp_error( $file ) && isset( $file['content'] ) ) {
					$content = base64_decode( $file['content'] );
					if ( preg_match( '/Version:\s*(.+?)$/m', $content, $m ) ) {
						$result = [ 'version' => trim( $m[1] ), 'ref' => $sha ];
					}
				}
				return $result;
			}
			// Commits API failed — fall through to releases as a safety net.
		}

		$result = null;
		$rel    = $this->request( 'GET', $this->api . '/repos/' . $repo . '/releases/latest' );
		if ( ! is_wp_error( $rel ) && isset( $rel['tag_name'] ) ) {
			$result = [ 'version' => ltrim( $rel['tag_name'], 'v' ), 'ref' => $rel['tag_name'] ];
		}
		return $result;
	}

	public function get_version_from_tag( string $repo, string $tag, string $path = '/' ): ?array {
		$rel    = $this->request( 'GET', $this->api . '/repos/' . $repo . '/releases/tags/' . rawurlencode( $tag ) );
		$result = null;
		if ( ! is_wp_error( $rel ) && isset( $rel['tag_name'] ) ) {
			$result = [ 'version' => ltrim( $rel['tag_name'], 'v' ), 'ref' => $rel['tag_name'] ];
		}
		return $result;
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
		$temp_zip    = $temp_dir . '/download.zip';
		$response    = wp_remote_get( $zipball_url, [
			'timeout'    => 300,
			'headers'    => $this->headers(),
			'stream'     => true,
			'filename'   => $temp_zip,
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

		if ( ! file_exists( $temp_zip ) || filesize( $temp_zip ) === 0 ) {
			$this->rrmdir( $temp_dir );
			return new WP_Error( 'empty_zip', 'Empty response from GitHub' );
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
