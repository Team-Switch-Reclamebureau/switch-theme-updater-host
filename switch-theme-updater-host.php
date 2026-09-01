<?php
/**
 * Plugin Name: Team Switch - Theme Updater Host
 * Plugin URI: https://github.com/Team-Switch-Reclamebureau/switch-theme-updater-host
 * Description: Central update proxy that authenticates client sites and relays GitHub releases without sharing the GitHub token. Manage all client sites from one place and remotely revoke access.
 * Version: 0.4.2
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
define( 'STUH_OPTION_EXTERNAL_PARTIES', 'stuh_external_parties' );
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
		add_action( 'stuh_check_client_homepage', [ $this, 'run_scheduled_homepage_check' ] );
		add_action( 'stuh_retry_client_homepage', [ $this, 'run_scheduled_homepage_retry' ] );

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
	 * @return array<string, array{label: string, url: string}>
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
	 * Return the label and management URL for an IP.
	 * Exact IP entries take precedence over wildcard prefixes; the longest matching
	 * wildcard prefix wins.
	 *
	 * @return array{label: string, url: string}
	 */
	public static function ip_details( string $ip ): array {
		$labels = self::get_ip_labels();
		if ( isset( $labels[ $ip ] ) && is_array( $labels[ $ip ] ) ) {
			return [
				'label' => is_string( $labels[ $ip ]['label'] ?? null ) ? $labels[ $ip ]['label'] : '',
				'url'   => is_string( $labels[ $ip ]['url'] ?? null ) ? $labels[ $ip ]['url'] : '',
			];
		}

		$details        = [ 'label' => '', 'url' => '' ];
		$matched_length = 0;
		foreach ( $labels as $pattern => $candidate_details ) {
			if ( ! is_string( $pattern ) || ! is_array( $candidate_details ) || ! str_ends_with( $pattern, '*' ) ) {
				continue;
			}

			$prefix = substr( $pattern, 0, -1 );
			if ( '' !== $prefix && str_starts_with( $ip, $prefix ) && strlen( $prefix ) > $matched_length ) {
				$details        = [
					'label' => is_string( $candidate_details['label'] ?? null ) ? $candidate_details['label'] : '',
					'url'   => is_string( $candidate_details['url'] ?? null ) ? $candidate_details['url'] : '',
				];
				$matched_length = strlen( $prefix );
			}
		}

		return $details;
	}

	/**
	 * Return the human-readable label for an IP, or an empty string if none is defined.
	 */
	public static function ip_label( string $ip ): string {
		return self::ip_details( $ip )['label'];
	}

	public static function get_settings(): array {
		$opt = get_option( STUH_OPTION_SETTINGS, [] );
		return wp_parse_args( $opt, [ 'token' => '', 'allow_unverified' => false ] );
	}

	public static function get_clients(): array {
		return (array) get_option( STUH_OPTION_CLIENTS, [] );
	}

	/**
	 * Return whether a client has not been seen in the last 24 hours.
	 *
	 * @param array<string, mixed> $client
	 */
	private static function is_client_stale( array $client ): bool {
		$last_seen = (int) ( $client['last_seen'] ?? 0 );
		return $last_seen > 0 && ( time() - $last_seen ) > DAY_IN_SECONDS;
	}

	private static function save_clients( array $clients ): void {
		update_option( STUH_OPTION_CLIENTS, array_values( $clients ) );
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_external_parties(): array {
		return (array) get_option( STUH_OPTION_EXTERNAL_PARTIES, [] );
	}

	/**
	 * @param array<int, array<string, mixed>> $parties
	 */
	private static function save_external_parties( array $parties ): void {
		update_option( STUH_OPTION_EXTERNAL_PARTIES, array_values( $parties ) );
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
	private static function client_search_text( array $client, array $telemetry, array $external_parties = [] ): string {
		$homepage_health = is_array( $client['homepage_health'] ?? null ) ? $client['homepage_health'] : [];
		$party_names     = [];
		foreach ( [ 'domain_external_party_id', 'server_external_party_id', 'email_external_party_id' ] as $party_key ) {
			$party_id = (string) ( $client[ $party_key ] ?? '' );
			if ( isset( $external_parties[ $party_id ] ) ) {
				$party_names[] = (string) $external_parties[ $party_id ];
			}
		}
		$values = [
			...array_map( 'strval', (array) ( $client['site_urls'] ?? [] ) ),
			(string) ( $client['site_url'] ?? '' ),
			...array_map( 'strval', (array) ( $client['tags'] ?? [] ) ),
			...$party_names,
			(string) ( $client['last_seen_ip'] ?? '' ),
			self::ip_label( (string) ( $client['last_seen_ip'] ?? '' ) ),
			(string) ( $homepage_health['status_code'] ?? '' ),
			(string) ( $homepage_health['message'] ?? '' ),
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
		self::check_client_homepage( $client, $data );
	}

	/**
	 * Fetch a client's homepage, persist its health, and notify the host admin
	 * when a new problem is detected.
	 *
	 * @param array<string, mixed> $client Authenticated client record.
	 * @param array<string, mixed> $data   Decoded diagnostics.
	 * @param bool                 $is_confirmation_retry Whether this is a delayed confirmation check.
	 * @return array<string, mixed>|null Persisted health result, or null when the client could not be checked.
	 */
	private static function check_client_homepage( array $client, array $data, bool $is_confirmation_retry = false ): ?array {
		$client_id = is_string( $client['id'] ?? null ) ? $client['id'] : '';
		if ( '' === $client_id ) {
			error_log( '[STUH homepage] Cannot check a client without an ID' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return null;
		}

		$lock_key = 'stuh_homepage_check_' . md5( $client_id );
		if ( ! $is_confirmation_retry && get_transient( $lock_key ) ) {
			return null;
		}
		set_transient( $lock_key, 1, MINUTE_IN_SECONDS );

		$site             = is_array( $data['site'] ?? null ) ? $data['site'] : [];
		$reported_home    = is_string( $site['home_url'] ?? null ) ? esc_url_raw( $site['home_url'] ) : '';
		$registered_home  = is_string( $client['site_url'] ?? null ) ? esc_url_raw( $client['site_url'] ) : '';
		$homepage_url     = self::is_http_url( $reported_home ) ? $reported_home : $registered_home;

		if ( ! self::is_http_url( $homepage_url ) ) {
			error_log( sprintf( '[STUH homepage] Client %s has no valid homepage URL', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return null;
		}

		error_log( sprintf( '[STUH homepage] Checking homepage for client %s: %s', $client_id, $homepage_url ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		$response = wp_remote_get(
			$homepage_url,
			[
				'timeout'     => 15,
				'redirection' => 0,
				'sslverify'   => self::client_sslverify( $client ),
			]
		);

		$health = [
			'checked_at'        => time(),
			'url'               => $homepage_url,
			'ok'                => false,
			'status_code'       => null,
			'status'            => 'request_error',
			'message'           => '',
			'alert_fingerprint' => '',
		];

		if ( is_wp_error( $response ) ) {
			$health['message'] = sprintf(
				__( 'Homepage request failed: %s', 'stuh' ),
				$response->get_error_message()
			);
			error_log( sprintf( '[STUH homepage] Request failed for client %s (%s): %s', $client_id, $homepage_url, $health['message'] ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		} else {
			$status_code           = wp_remote_retrieve_response_code( $response );
			$body                  = wp_remote_retrieve_body( $response );
			$health['status_code'] = $status_code;

			if ( $status_code < 200 || $status_code >= 400 ) {
				$health['status']  = 'http_error';
				$health['message'] = sprintf( __( 'Homepage returned HTTP %d.', 'stuh' ), $status_code );
			} elseif ( self::contains_wordpress_critical_error( $body ) ) {
				$health['status']  = 'wordpress_critical_error';
				$health['message'] = sprintf(
					__( 'Homepage returned HTTP %d but contains a WordPress critical error.', 'stuh' ),
					$status_code
				);
			} else {
				$health['ok']      = true;
				$health['status']  = 'healthy';
				$health['message'] = sprintf( __( 'Homepage returned HTTP %d.', 'stuh' ), $status_code );
			}

			error_log( sprintf( '[STUH homepage] Result for client %s (%s): HTTP %s, status=%s, message=%s', $client_id, $homepage_url, (string) $status_code, (string) ( $health['status'] ?? 'unknown' ), (string) $health['message'] ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}

		$confirmation_pending = false;
		if ( ! $is_confirmation_retry && in_array( $health['status'], [ 'request_error', 'http_error' ], true ) ) {
			$retry_args = [ $client_id ];
			if ( wp_next_scheduled( 'stuh_retry_client_homepage', $retry_args ) ) {
				$confirmation_pending = true;
				$health['status']     .= '_pending_retry';
				$health['message']    .= ' ' . __( 'A confirmation check is pending.', 'stuh' );
			} elseif ( wp_schedule_single_event( time() + ( 10 * MINUTE_IN_SECONDS ), 'stuh_retry_client_homepage', $retry_args ) ) {
				$confirmation_pending = true;
				$health['status']     .= '_pending_retry';
				$health['message']    .= ' ' . __( 'A confirmation check is scheduled in 10 minutes.', 'stuh' );
				error_log( sprintf( '[STUH homepage] Scheduled failure retry for client %s in 10 minutes', $client_id ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			} else {
				$health['status']  .= '_retry_failed';
				$health['message'] .= ' ' . __( 'The confirmation check could not be scheduled.', 'stuh' );
				error_log( sprintf( '[STUH homepage] Could not schedule failure retry for client %s', $client_id ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			}
		}

		$clients = self::get_clients();
		foreach ( $clients as $index => $stored_client ) {
			if ( $client['id'] !== ( $stored_client['id'] ?? '' ) ) {
				continue;
			}

			$previous_health = is_array( $stored_client['homepage_health'] ?? null ) ? $stored_client['homepage_health'] : [];
			if ( $confirmation_pending ) {
				$health['alert_fingerprint'] = (string) ( $previous_health['alert_fingerprint'] ?? '' );
			} elseif ( ! $health['ok'] ) {
				$fingerprint = hash( 'sha256', implode( '|', [
					(string) $health['status'],
					(string) $health['status_code'],
					(string) $health['message'],
				] ) );
				$previous_fingerprint = (string) ( $previous_health['alert_fingerprint'] ?? '' );

				if ( $fingerprint === $previous_fingerprint ) {
					$health['alert_fingerprint'] = $fingerprint;
				} elseif ( self::send_homepage_health_alert( $homepage_url, $health ) ) {
					$health['alert_fingerprint'] = $fingerprint;
				}
			}

			$clients[ $index ]['homepage_health'] = $health;
			self::save_clients( $clients );
			return $health;
		}

		error_log( sprintf( '[STUH homepage] Could not persist health for client %s', $client['id'] ?? '(unknown)' ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		return null;
	}

	private static function is_http_url( string $url ): bool {
		$parts = wp_parse_url( $url );
		return is_array( $parts )
			&& in_array( strtolower( (string) ( $parts['scheme'] ?? '' ) ), [ 'http', 'https' ], true )
			&& '' !== (string) ( $parts['host'] ?? '' );
	}

	private static function contains_wordpress_critical_error( string $html ): bool {
		$needles = [
			'there has been a critical error on this website',
			'there has been a critical error on your website',
			'<b>fatal error</b>',
			'fatal error:',
		];

		foreach ( $needles as $needle ) {
			if ( false !== stripos( $html, $needle ) ) {
				return true;
			}
		}

		return 1 === preg_match( '/class\s*=\s*["\'][^"\']*\bwp-die-message\b/i', $html );
	}

	/**
	 * @param array<string, mixed> $health
	 */
	private static function send_homepage_health_alert( string $homepage_url, array $health ): bool {
		$admin_email = sanitize_email( (string) get_option( 'admin_email' ) );
		if ( ! is_email( $admin_email ) ) {
			error_log( '[STUH homepage] Host admin email is invalid; health alert was not sent' ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return false;
		}

		$sent = wp_mail(
			$admin_email,
			sprintf( __( '[Website health] Problem detected on %s', 'stuh' ), self::client_url_label( $homepage_url ) ),
			sprintf(
				__(
					"A homepage health check detected a problem.\n\nWebsite: %1\$s\nProblem: %2\$s\nChecked: %3\$s\n\nReview the client site in WordPress:\n%4\$s",
					'stuh'
				),
				$homepage_url,
				(string) $health['message'],
				wp_date( 'Y-m-d H:i:s T', (int) $health['checked_at'] ),
				admin_url( 'admin.php?page=stuh' )
			)
		);

		if ( ! $sent ) {
			error_log( sprintf( '[STUH homepage] Failed to email health alert for %s', $homepage_url ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}

		return $sent;
	}

	/**
	 * Run a queued homepage check outside the admin request.
	 */
	public function run_scheduled_homepage_check( string $client_id ): void {
		$this->run_client_homepage_check( $client_id, false );
	}

	/**
	 * Confirm an HTTP or request failure after the ten-minute delay.
	 */
	public function run_scheduled_homepage_retry( string $client_id ): void {
		$this->run_client_homepage_check( $client_id, true );
	}

	/**
	 * @param bool $is_confirmation_retry Whether this check confirms an earlier failure.
	 */
	private function run_client_homepage_check( string $client_id, bool $is_confirmation_retry ): void {
		$client = null;
		foreach ( self::get_clients() as $candidate ) {
			if ( $client_id === ( $candidate['id'] ?? '' ) ) {
				$client = $candidate;
				break;
			}
		}

		if ( null === $client ) {
			error_log( sprintf( '[STUH homepage] Scheduled check could not find client %s', $client_id ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			return;
		}

		$telemetry = self::get_telemetry();
		$report    = is_array( $telemetry[ $client_id ] ?? null ) ? $telemetry[ $client_id ] : [];
		$data      = is_array( $report['data'] ?? null ) ? $report['data'] : [];
		self::check_client_homepage( $client, $data, $is_confirmation_retry );
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

		if ( ! self::valid_repo( $repo ) ) {
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

		if ( ! self::valid_repo( $repo ) ) {
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

		if ( ! self::valid_repo( $repo ) ) {
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

	private static function valid_repo( string $repo ): bool {
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
			__( 'External Parties', 'stuh' ),
			__( 'External Parties', 'stuh' ),
			'manage_options',
			'stuh-external-parties',
			[ $this, 'render_external_parties_page' ]
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
			'site'            => __( 'Site', 'stuh' ),
			'site_url'        => __( 'Domain', 'stuh' ),
			'domain_owner'    => __( 'Domain Owner', 'stuh' ),
			'homepage_status' => __( 'Homepage Status', 'stuh' ),
			'tags'            => __( 'Tags', 'stuh' ),
			'created_at'      => __( 'Created', 'stuh' ),
			'last_seen'       => __( 'Last Seen', 'stuh' ),
			'last_seen_ip'    => __( 'Server', 'stuh' ),
			'server_owner'    => __( 'Server Owner', 'stuh' ),
			'telemetry_site'  => __( 'Reported Site URL', 'stuh' ),
			'telemetry_home'  => __( 'Home URL', 'stuh' ),
			'telemetry_admin_email' => __( 'Admin Email', 'stuh' ),
			'email_owner'     => __( 'Email Owner', 'stuh' ),
			'telemetry_locale'=> __( 'Locale', 'stuh' ),
			'telemetry_wp'    => __( 'WordPress', 'stuh' ),
			'telemetry_php'   => __( 'PHP', 'stuh' ),
			'telemetry_updater' => __( 'Updater', 'stuh' ),
			'telemetry_pending_updates' => __( 'Updates', 'stuh' ),
			'telemetry_multisite' => __( 'Multisite', 'stuh' ),
			'telemetry_search_engine_visibility' => __( 'Search Engine Visibility', 'stuh' ),
			'telemetry_multilanguage' => __( 'Multilanguage', 'stuh' ),
			'telemetry_packages'  => __( 'Packages', 'stuh' ),
			'telemetry_active_theme' => __( 'Active Theme', 'stuh' ),
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
	private static function render_client_row_actions( array $client, bool $enabled, string $login_url ): void {
		$login_url = esc_url( $login_url );
		?>
		<div class="row-actions stuh-client-row-actions">
			<?php if ( '' !== $login_url ) : ?>
			<span class="login">
				<a href="<?php echo esc_url( $login_url ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Login', 'stuh' ); ?></a> |
			</span>
			<?php endif; ?>
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
			<?php if ( $enabled ) : ?>
			<span class="refresh-diagnostics">
				<form method="post">
					<?php wp_nonce_field( 'stuh_admin' ); ?>
					<input type="hidden" name="stuh_action" value="refresh_client_diagnostics">
					<input type="hidden" name="client_id" value="<?php echo esc_attr( $client['id'] ); ?>">
					<button type="submit"><?php esc_html_e( 'Refresh', 'stuh' ); ?></button>
				</form> |
			</span>
			<?php endif; ?>
			<span class="edit-urls">
				<button type="button" onclick="(function(btn){ var row = document.getElementById('stuh-edit-urls-<?php echo esc_js( $client['id'] ); ?>'); var hidden = row.style.display === 'none' || row.style.display === ''; row.style.display = hidden ? 'table-row' : 'none'; btn.textContent = hidden ? 'Cancel' : 'Edit URLs'; })(this)"><?php esc_html_e( 'Edit URLs', 'stuh' ); ?></button> |
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
	 * Render an ownership value and its edit action.
	 *
	 * @param array<string, mixed> $client
	 * @param array<string, array<string, mixed>> $external_parties_by_id
	 */
	private static function render_external_party_owner( array $client, array $external_parties_by_id, string $connection_type ): void {
		$party_id = (string) ( $client[ $connection_type . '_external_party_id' ] ?? '' );
		$party    = $external_parties_by_id[ $party_id ] ?? null;
		?>
		<?php if ( is_array( $party ) ) : ?>
			<?php $dialog_id = 'stuh-party-' . $connection_type . '-' . md5( (string) $client['id'] . $party_id ); ?>
			<a href="#TB_inline?width=420&amp;height=260&amp;inlineId=<?php echo esc_attr( $dialog_id ); ?>" class="thickbox">
				<?php echo esc_html( $party['name'] ?? '' ); ?>
			</a>
			<?php self::render_external_party_contact_dialog( $dialog_id, $party ); ?>
		<?php else : ?>
			-
		<?php endif; ?>
		<div class="row-actions stuh-client-row-actions">
			<span class="edit-owner">
				<button type="button" id="stuh-toggle-<?php echo esc_attr( $connection_type ); ?>-owner-<?php echo esc_attr( $client['id'] ); ?>" onclick="(function(btn){ var row = document.getElementById('stuh-edit-<?php echo esc_js( $connection_type ); ?>-owner-<?php echo esc_js( $client['id'] ); ?>'); var hidden = row.style.display === 'none' || row.style.display === ''; row.style.display = hidden ? 'table-row' : 'none'; btn.textContent = hidden ? 'Cancel' : 'Edit'; })(this)"><?php esc_html_e( 'Edit', 'stuh' ); ?></button>
			</span>
		</div>
		<?php
	}

	/**
	 * Render an external party's contact details in a ThickBox dialog.
	 *
	 * @param array<string, mixed> $party
	 */
	private static function render_external_party_contact_dialog( string $dialog_id, array $party ): void {
		$contact_name = (string) ( $party['contact_name'] ?? '' );
		$email        = (string) ( $party['email'] ?? '' );
		?>
		<div id="<?php echo esc_attr( $dialog_id ); ?>" style="display:none;">
			<div style="padding:16px;">
				<h2 style="margin-top:0;"><?php echo esc_html( $party['name'] ?? '' ); ?></h2>
				<table class="widefat striped">
					<tbody>
						<tr>
							<th style="width:35%;"><?php esc_html_e( 'Contact name', 'stuh' ); ?></th>
							<td><?php echo '' !== $contact_name ? esc_html( $contact_name ) : '—'; ?></td>
						</tr>
						<tr>
							<th><?php esc_html_e( 'Contact email', 'stuh' ); ?></th>
							<td>
								<?php if ( is_email( $email ) ) : ?>
									<a href="mailto:<?php echo esc_attr( $email ); ?>"><?php echo esc_html( $email ); ?></a>
								<?php else : ?>
									&mdash;
								<?php endif; ?>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the ownership editor below a client row.
	 *
	 * @param array<string, mixed>              $client
	 * @param array<int, array<string, mixed>> $external_parties
	 */
	private static function render_external_party_owner_editor( array $client, array $external_parties, string $connection_type, int $column_count ): void {
		$field       = $connection_type . '_external_party_id';
		$selected_id = (string) ( $client[ $field ] ?? '' );
		$labels      = [
			'domain' => __( 'Domain Owner', 'stuh' ),
			'server' => __( 'Server Owner', 'stuh' ),
			'email'  => __( 'Email Owner', 'stuh' ),
		];
		$label       = $labels[ $connection_type ] ?? __( 'Owner', 'stuh' );
		?>
		<tr id="stuh-edit-<?php echo esc_attr( $connection_type ); ?>-owner-<?php echo esc_attr( $client['id'] ); ?>" class="stuh-client-detail-row" data-client-id="<?php echo esc_attr( $client['id'] ); ?>" style="display:none;background:#f6f7f7;">
			<td colspan="<?php echo esc_attr( $column_count ); ?>" class="colspanchange" style="padding:12px 16px;">
				<form method="post">
					<?php wp_nonce_field( 'stuh_admin' ); ?>
					<input type="hidden" name="stuh_action" value="assign_external_party">
					<input type="hidden" name="client_id" value="<?php echo esc_attr( $client['id'] ); ?>">
					<input type="hidden" name="connection_type" value="<?php echo esc_attr( $connection_type ); ?>">
					<label for="stuh-<?php echo esc_attr( $connection_type ); ?>-owner-<?php echo esc_attr( $client['id'] ); ?>" style="display:block;font-weight:600;margin-bottom:6px;">
						<?php echo esc_html( $label ); ?>
					</label>
					<select id="stuh-<?php echo esc_attr( $connection_type ); ?>-owner-<?php echo esc_attr( $client['id'] ); ?>" name="external_party_id">
						<option value=""><?php esc_html_e( '-', 'stuh' ); ?></option>
						<?php foreach ( $external_parties as $party ) : ?>
							<option value="<?php echo esc_attr( $party['id'] ); ?>" <?php selected( $selected_id, $party['id'] ); ?>>
								<?php echo esc_html( $party['name'] ); ?>
							</option>
						<?php endforeach; ?>
					</select>
					<p class="description"><?php esc_html_e( 'A dash means this is owned by us.', 'stuh' ); ?></p>
					<button type="submit" class="button button-primary"><?php esc_html_e( 'Save Owner', 'stuh' ); ?></button>
					<button type="button" class="button" onclick="(function(){ document.getElementById('stuh-edit-<?php echo esc_js( $connection_type ); ?>-owner-<?php echo esc_js( $client['id'] ); ?>').style.display='none'; var toggle = document.getElementById('stuh-toggle-<?php echo esc_js( $connection_type ); ?>-owner-<?php echo esc_js( $client['id'] ); ?>'); if (toggle) { toggle.textContent='Edit'; } })();"><?php esc_html_e( 'Cancel', 'stuh' ); ?></button>
				</form>
			</td>
		</tr>
		<?php
	}

	/**
	 * Return a theme's GitHub repository URL from its GitHub Repo header.
	 *
	 * @param array<string, mixed> $theme
	 */
	private static function theme_github_repo_url( array $theme ): string {
		$github_repo = $theme['github_repo'] ?? '';
		if ( ! is_scalar( $github_repo ) ) {
			return '';
		}

		$github_repo = trim( (string) $github_repo );
		if ( ! self::valid_repo( $github_repo ) ) {
			return '';
		}

		return 'https://github.com/' . $github_repo;
	}

	/**
	 * Render one active-theme name, linking it to its GitHub repository.
	 *
	 * @param array<string, mixed> $theme
	 */
	private static function render_active_theme_name( array $theme ): void {
		$theme_name    = is_scalar( $theme['name'] ?? null ) ? (string) $theme['name'] : '';
		$theme_version = is_scalar( $theme['version'] ?? null ) ? (string) $theme['version'] : '';
		$github_url    = self::theme_github_repo_url( $theme );

		if ( '' !== $github_url && '' !== $theme_name ) {
			printf(
				'<a href="%1$s" target="_blank" rel="noopener">%2$s</a>',
				esc_url( $github_url ),
				esc_html( $theme_name )
			);
		} else {
			echo esc_html( $theme_name );
		}

		if ( '' !== $theme_version ) {
			printf(
				' <span style="display:inline-block;padding:1px 6px;border-radius:10px;background:#f0f0f1;color:#50575e;font-size:11px;font-weight:600;line-height:1.5;">%s</span>',
				esc_html( $theme_version )
			);
		}
	}

	/**
	 * Return the client URL as it is displayed in the list and sorted.
	 */
	private static function client_url_label( string $url ): string {
		return preg_replace( '#^https?://(?:www\.)?#i', '', $url );
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
			case 'telemetry_search_engine_visibility':
				if ( ! array_key_exists( 'search_engine_visibility', $site ) ) {
					return '';
				}
				return ! empty( $site['search_engine_visibility'] )
					? __( 'Visible', 'stuh' )
					: __( 'Discouraged', 'stuh' );
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
			case 'telemetry_active_theme':
				$active_theme = is_array( $data['active_theme'] ?? null ) ? $data['active_theme'] : [];
				if ( [] === $active_theme ) {
					return '';
				}
				$theme_name = is_scalar( $active_theme['name'] ?? null ) ? (string) $active_theme['name'] : '';
				$theme_version = is_scalar( $active_theme['version'] ?? null ) ? (string) $active_theme['version'] : '';
				$theme_display = trim( $theme_name . ( '' !== $theme_version ? ' (' . $theme_version . ')' : '' ) );
				$parent_theme = is_array( $active_theme['parent_theme'] ?? null ) ? $active_theme['parent_theme'] : [];
				if ( [] === $parent_theme ) {
					return $theme_display;
				}
				$parent_name = is_scalar( $parent_theme['name'] ?? null ) ? (string) $parent_theme['name'] : '';
				$parent_version = is_scalar( $parent_theme['version'] ?? null ) ? (string) $parent_theme['version'] : '';
				$parent_display = trim( $parent_name . ( '' !== $parent_version ? ' (' . $parent_version . ')' : '' ) );
				if ( '' === $theme_display ) {
					return $parent_display;
				}
				if ( '' === $parent_display ) {
					return $theme_display;
				}
				return sprintf( __( '%1$s > %2$s', 'stuh' ), $theme_display, $parent_display );
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

	/**
	 * Return the client list URL while retaining its active filters.
	 */
	private static function client_list_url(): string {
		$args = [ 'page' => 'stuh' ];

		$search = sanitize_text_field( wp_unslash( $_GET['stuh_search'] ?? '' ) );
		if ( '' !== $search ) {
			$args['stuh_search'] = $search;
		}

		$status = sanitize_key( wp_unslash( $_GET['stuh_status'] ?? '' ) );
		if ( in_array( $status, [ 'enabled', 'disabled' ], true ) ) {
			$args['stuh_status'] = $status;
		}

		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

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
						'domain_external_party_id' => '',
						'server_external_party_id' => '',
						'email_external_party_id'  => '',
					];
					self::save_clients( $clients );
					set_transient(
						'stuh_new_key_' . get_current_user_id(),
						[ 'key' => $raw_key, 'site' => $urls[0] ],
						120 // shown for 2 minutes max
					);
				}
				wp_safe_redirect( self::client_list_url() );
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
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'bulk_update_clients':
				$bulk_action = sanitize_key( $_POST['bulk_action'] ?? '' );
				$client_ids  = [];
				if ( isset( $_POST['client_ids'] ) && is_array( $_POST['client_ids'] ) ) {
					foreach ( wp_unslash( $_POST['client_ids'] ) as $client_id ) {
						if ( is_scalar( $client_id ) ) {
							$client_ids[] = sanitize_text_field( $client_id );
						}
					}
				}
				if ( in_array( $bulk_action, [ 'enable', 'disable' ], true ) && $client_ids ) {
					$selected_client_ids = array_flip( $client_ids );
					foreach ( $clients as &$c ) {
						if ( isset( $selected_client_ids[ $c['id'] ] ) ) {
							$c['enabled'] = 'enable' === $bulk_action;
						}
					}
					unset( $c );
					self::save_clients( $clients );
				} elseif ( 'check_homepage_status' === $bulk_action && $client_ids ) {
					$selected_client_ids = array_flip( $client_ids );
					$queued_count        = 0;
					$already_queued      = 0;

					foreach ( $clients as $client ) {
						$client_id = (string) ( $client['id'] ?? '' );
						if ( ! isset( $selected_client_ids[ $client_id ] ) ) {
							continue;
						}

						$args = [ $client_id ];
						if ( wp_next_scheduled( 'stuh_check_client_homepage', $args ) ) {
							$already_queued++;
							continue;
						}

						if ( wp_schedule_single_event( time(), 'stuh_check_client_homepage', $args ) ) {
							$queued_count++;
						}
					}

					if ( $queued_count > 0 ) {
						spawn_cron( time() );
					}

					$failed_count = count( $selected_client_ids ) - $queued_count - $already_queued;
					set_transient(
						'stuh_bulk_homepage_check_' . get_current_user_id(),
						[
							'type'    => $failed_count > 0 ? 'warning' : 'success',
							'message' => sprintf(
								__( 'Homepage checks are running in the background: %1$d queued, %2$d already queued, %3$d could not be queued.', 'stuh' ),
								$queued_count,
								$already_queued,
								$failed_count
							),
						],
						MINUTE_IN_SECONDS
					);
				}
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'delete_client':
				$id      = sanitize_text_field( $_POST['client_id'] ?? '' );
				$clients = array_values( array_filter( $clients, fn( $c ) => $c['id'] !== $id ) );
				self::save_clients( $clients );
				$telemetry = self::get_telemetry();
				unset( $telemetry[ $id ] );
				self::save_telemetry( $telemetry );
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'retry_failed_smtp_emails':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::retry_failed_smtp_emails( $client );
				set_transient(
					'stuh_smtp_retry_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'install_pending_updates':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::install_pending_updates( $client );
				set_transient(
					'stuh_pending_updates_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'install_wordpress_update':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::install_wordpress_update( $client );
				set_transient(
					'stuh_wordpress_update_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'refresh_client_diagnostics':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::refresh_client_diagnostics( $client );
				set_transient(
					'stuh_diagnostics_refresh_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'skip_new_bundled_themes':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::skip_new_bundled_themes( $client );
				if ( 'success' === $result['type'] && $client ) {
					$telemetry = self::get_telemetry();
					if ( is_array( $telemetry[ $id ] ?? null ) ) {
						$telemetry[ $id ]['data'] = is_array( $telemetry[ $id ]['data'] ?? null ) ? $telemetry[ $id ]['data'] : [];
						$telemetry[ $id ]['data']['wp_config'] = is_array( $telemetry[ $id ]['data']['wp_config'] ?? null ) ? $telemetry[ $id ]['data']['wp_config'] : [];
						$telemetry[ $id ]['data']['wp_config']['core_upgrade_skip_new_bundled'] = true;
						self::save_telemetry( $telemetry );
					}
				}
				set_transient(
					'stuh_core_upgrade_setting_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'set_post_revisions':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::set_post_revisions( $client );
				if ( 'success' === $result['type'] && $client ) {
					$telemetry = self::get_telemetry();
					if ( is_array( $telemetry[ $id ] ?? null ) ) {
						$telemetry[ $id ]['data'] = is_array( $telemetry[ $id ]['data'] ?? null ) ? $telemetry[ $id ]['data'] : [];
						$telemetry[ $id ]['data']['wp_config'] = is_array( $telemetry[ $id ]['data']['wp_config'] ?? null ) ? $telemetry[ $id ]['data']['wp_config'] : [];
						$telemetry[ $id ]['data']['wp_config']['post_revisions'] = 10;
						self::save_telemetry( $telemetry );
					}
				}
				set_transient(
					'stuh_post_revisions_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'toggle_search_engine_visibility':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::toggle_search_engine_visibility( $client );
				if ( 'success' === $result['type'] && $client ) {
					$telemetry = self::get_telemetry();
					if ( is_array( $telemetry[ $id ] ?? null ) ) {
						$telemetry[ $id ]['data'] = is_array( $telemetry[ $id ]['data'] ?? null ) ? $telemetry[ $id ]['data'] : [];
						$telemetry[ $id ]['data']['site'] = is_array( $telemetry[ $id ]['data']['site'] ?? null ) ? $telemetry[ $id ]['data']['site'] : [];
						$telemetry[ $id ]['data']['site']['search_engine_visibility'] = $result['visible'];
						self::save_telemetry( $telemetry );
					}
				}
				set_transient(
					'stuh_search_engine_visibility_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'disable_debugging':
				$id     = sanitize_text_field( $_POST['client_id'] ?? '' );
				$client = null;
				foreach ( $clients as $candidate ) {
					if ( $candidate['id'] === $id ) {
						$client = $candidate;
						break;
					}
				}

				$result = self::disable_debugging( $client );
				if ( 'success' === $result['type'] && $client ) {
					$telemetry = self::get_telemetry();
					if ( is_array( $telemetry[ $id ] ?? null ) ) {
						$telemetry[ $id ]['data'] = is_array( $telemetry[ $id ]['data'] ?? null ) ? $telemetry[ $id ]['data'] : [];
						$telemetry[ $id ]['data']['debug'] = is_array( $telemetry[ $id ]['data']['debug'] ?? null ) ? $telemetry[ $id ]['data']['debug'] : [];
						$telemetry[ $id ]['data']['debug']['wp_debug'] = false;
						self::save_telemetry( $telemetry );
					}
				}
				set_transient(
					'stuh_disable_debugging_' . get_current_user_id(),
					$result,
					MINUTE_IN_SECONDS
				);
				wp_safe_redirect( self::client_list_url() );
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
				wp_safe_redirect( self::client_list_url() );
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
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'assign_external_party':
				$id              = sanitize_text_field( wp_unslash( $_POST['client_id'] ?? '' ) );
				$connection_type = sanitize_key( wp_unslash( $_POST['connection_type'] ?? '' ) );
				$party_id        = sanitize_text_field( wp_unslash( $_POST['external_party_id'] ?? '' ) );
				$party_ids       = array_column( self::get_external_parties(), 'id' );
				if ( ! in_array( $connection_type, [ 'domain', 'server', 'email' ], true ) || ( '' !== $party_id && ! in_array( $party_id, $party_ids, true ) ) ) {
					wp_die( esc_html__( 'Invalid external-party assignment.', 'stuh' ) );
				}
				$client_found = false;
				foreach ( $clients as &$c ) {
					if ( $c['id'] === $id ) {
						$c[ $connection_type . '_external_party_id' ] = $party_id;
						$client_found = true;
						break;
					}
				}
				unset( $c );
				if ( ! $client_found ) {
					wp_die( esc_html__( 'The selected client site could not be found.', 'stuh' ) );
				}
				self::save_clients( $clients );
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'add_external_party':
				$name         = sanitize_text_field( trim( (string) wp_unslash( $_POST['external_party_name'] ?? '' ) ) );
				$contact_name = sanitize_text_field( trim( (string) wp_unslash( $_POST['external_party_contact_name'] ?? '' ) ) );
				$email        = sanitize_email( (string) wp_unslash( $_POST['external_party_email'] ?? '' ) );
				$parties      = self::get_external_parties();
				$exists       = array_filter(
					$parties,
					static fn( array $party ): bool => 0 === strcasecmp( (string) ( $party['name'] ?? '' ), $name )
				);
				$status = 'invalid';
				if ( '' !== $name && ( '' === $email || is_email( $email ) ) && ! $exists ) {
					$parties[] = [
						'id'           => uniqid( 'stuh_party_', true ),
						'name'         => $name,
						'contact_name' => $contact_name,
						'email'        => $email,
						'created_at'   => time(),
					];
					self::save_external_parties( $parties );
					$status = 'added';
				} elseif ( $exists ) {
					$status = 'duplicate';
				} elseif ( '' !== $email && ! is_email( $email ) ) {
					$status = 'invalid_email';
				}
				wp_safe_redirect( add_query_arg( 'stuh_party_status', $status, admin_url( 'admin.php?page=stuh-external-parties' ) ) );
				exit;

			case 'save_external_party':
				$party_id     = sanitize_text_field( wp_unslash( $_POST['external_party_id'] ?? '' ) );
				$name         = sanitize_text_field( trim( (string) wp_unslash( $_POST['external_party_name'] ?? '' ) ) );
				$contact_name = sanitize_text_field( trim( (string) wp_unslash( $_POST['external_party_contact_name'] ?? '' ) ) );
				$email        = sanitize_email( (string) wp_unslash( $_POST['external_party_email'] ?? '' ) );
				$parties      = self::get_external_parties();
				$duplicate    = array_filter(
					$parties,
					static fn( array $party ): bool => ( $party['id'] ?? '' ) !== $party_id
						&& 0 === strcasecmp( (string) ( $party['name'] ?? '' ), $name )
				);
				$status = 'invalid';
				if ( $duplicate ) {
					$status = 'duplicate';
				} elseif ( '' !== $email && ! is_email( $email ) ) {
					$status = 'invalid_email';
				} elseif ( '' !== $name ) {
					foreach ( $parties as &$party ) {
						if ( ( $party['id'] ?? '' ) === $party_id ) {
							$party['name']         = $name;
							$party['contact_name'] = $contact_name;
							$party['email']        = $email;
							$status                = 'updated';
							break;
						}
					}
					unset( $party );
					if ( 'updated' === $status ) {
						self::save_external_parties( $parties );
					}
				}
				wp_safe_redirect( add_query_arg( 'stuh_party_status', $status, admin_url( 'admin.php?page=stuh-external-parties' ) ) );
				exit;

			case 'delete_external_party':
				$party_id = sanitize_text_field( wp_unslash( $_POST['external_party_id'] ?? '' ) );
				$parties  = array_values(
					array_filter(
						self::get_external_parties(),
						static fn( array $party ): bool => ( $party['id'] ?? '' ) !== $party_id
					)
				);
				self::save_external_parties( $parties );
				foreach ( $clients as &$c ) {
					foreach ( [ 'domain_external_party_id', 'server_external_party_id', 'email_external_party_id' ] as $field ) {
						if ( ( $c[ $field ] ?? '' ) === $party_id ) {
							$c[ $field ] = '';
						}
					}
				}
				unset( $c );
				self::save_clients( $clients );
				wp_safe_redirect( add_query_arg( 'stuh_party_status', 'deleted', admin_url( 'admin.php?page=stuh-external-parties' ) ) );
				exit;

			case 'regenerate_key':
				$id       = sanitize_text_field( $_POST['client_id'] ?? '' );
				$site_url = '';
				foreach ( $clients as &$c ) {
					if ( $c['id'] === $id ) {
						$raw_key          = bin2hex( random_bytes( 24 ) );
						$c['api_key']      = $raw_key;
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
				wp_safe_redirect( self::client_list_url() );
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
				wp_safe_redirect( self::client_list_url() );
				exit;

			case 'clear_unverified':
				delete_option( STUH_OPTION_UNVERIFIED );
				wp_safe_redirect( self::client_list_url() );
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
						'domain_external_party_id' => '',
						'server_external_party_id' => '',
						'email_external_party_id'  => '',
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
				wp_safe_redirect( self::client_list_url() );
				exit;
		}
	}

	/**
	 * Ask a client site to install all currently pending plugin and theme updates.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function install_pending_updates( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		if ( ! ( $client['enabled'] ?? true ) ) {
			return [
				'type'    => 'error',
				'message' => __( 'Updates cannot be installed for a disabled client site.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/updates/install-pending',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 300,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not install updates: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not install updates: %s', 'stuh' ), $message ),
			];
		}

		$updated = is_array( $body['updated'] ?? null ) ? $body['updated'] : [];
		$failed  = is_array( $body['failed'] ?? null ) ? $body['failed'] : [];
		if ( ! empty( $body['queued'] ) ) {
			return [
				'type'    => 'success',
				'message' => sprintf(
					__( 'Plugin and theme updates have been queued for %s. The reported update count will refresh after they finish.', 'stuh' ),
					$site_url
				),
			];
		}

		$count   = is_array( $updated['plugins'] ?? null ) ? count( $updated['plugins'] ) : 0;
		$count  += is_array( $updated['themes'] ?? null ) ? count( $updated['themes'] ) : 0;

		if ( $failed ) {
			$first_failure = sanitize_text_field( (string) reset( $failed ) );
			return [
				'type' => $count > 0 ? 'warning' : 'error',
				'message' => sprintf(
					_n(
						'Installed %1$d update for %2$s, but %3$d update failed: %4$s',
						'Installed %1$d updates for %2$s, but %3$d updates failed: %4$s',
						$count,
						'stuh'
					),
					$count,
					$site_url,
					count( $failed ),
					$first_failure
				),
			];
		}

		return [
			'type' => 'success',
			'message' => $count > 0
				? sprintf(
					_n(
						'Installed %1$d update for %2$s.',
						'Installed %1$d updates for %2$s.',
						$count,
						'stuh'
					),
					$count,
					$site_url
				)
				: sprintf( __( 'No plugin or theme updates are currently pending for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Ask a client site to install its pending WordPress core update.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function install_wordpress_update( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		if ( ! ( $client['enabled'] ?? true ) ) {
			return [
				'type'    => 'error',
				'message' => __( 'WordPress cannot be updated for a disabled client site.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/updates/install-core',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 300,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not update WordPress: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not update WordPress: %s', 'stuh' ), $message ),
			];
		}

		$failed = is_array( $body['failed'] ?? null ) ? $body['failed'] : [];
		if ( ! empty( $body['queued'] ) ) {
			return [
				'type'    => 'success',
				'message' => sprintf(
					__( 'The WordPress update has been queued for %s. The reported version will refresh after it finishes.', 'stuh' ),
					$site_url
				),
			];
		}

		if ( $failed ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not update WordPress on %1$s: %2$s', 'stuh' ),
					$site_url,
					sanitize_text_field( (string) reset( $failed ) )
				),
			];
		}

		return [
			'type'    => 'success',
			'message' => ! empty( $body['updated']['core'] )
				? sprintf( __( 'Updated WordPress on %s.', 'stuh' ), $site_url )
				: sprintf( __( 'No WordPress update is currently pending for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Fetch and store current diagnostics from a client site.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function refresh_client_diagnostics( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		if ( ! ( $client['enabled'] ?? true ) ) {
			return [
				'type'    => 'error',
				'message' => __( 'Diagnostics cannot be refreshed for a disabled client site.', 'stuh' ),
			];
		}

		$site_url  = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key   = (string) ( $client['api_key'] ?? '' );
		$client_id = (string) ( $client['id'] ?? '' );
		if ( '' === $site_url || '' === $api_key || '' === $client_id ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL, identifier, or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/diagnostics',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 60,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not refresh diagnostics: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not refresh diagnostics: %s', 'stuh' ), $message ),
			];
		}

		if ( ! empty( $body['queued'] ) ) {
			return [
				'type'    => 'success',
				'message' => sprintf(
					__( 'A diagnostics refresh has been queued for %s. The client data will refresh after it finishes.', 'stuh' ),
					$site_url
				),
			];
		}

		$data = $body['data'] ?? null;
		if ( 1 !== (int) ( $body['version'] ?? 0 ) || ! is_array( $data ) || array_is_list( $data ) ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site returned an invalid diagnostics response.', 'stuh' ),
			];
		}

		$telemetry               = self::get_telemetry();
		$telemetry[ $client_id ] = [
			'version'      => 1,
			'request_type' => 'manual',
			'received_at'  => time(),
			'data'         => $data,
		];
		self::save_telemetry( $telemetry );
		self::check_client_homepage( $client, $data );

		return [
			'type'    => 'success',
			'message' => sprintf( __( 'Refreshed diagnostics for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Ask a client site to retry FluentSMTP's failed emails.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function retry_failed_smtp_emails( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/fluent-smtp/retry-failed-emails',
			[
				'headers' => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout' => 30,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not retry failed emails: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		$retry       = is_array( $body ) && is_array( $body['retry'] ?? null ) ? $body['retry'] : [];
		$diagnostics = is_array( $body ) && is_array( $body['diagnostics'] ?? null ) ? $body['diagnostics'] : [];

		if ( true === ( $retry['success'] ?? null ) && is_array( $retry['data'] ?? null ) ) {
			$totals = $retry['data'];
			$diagnostics_succeeded = true === ( $diagnostics['success'] ?? null );
			$diagnostics_message   = $diagnostics_succeeded
				? __( 'Diagnostics were updated.', 'stuh' )
				: sprintf(
					__( 'Diagnostics could not be updated: %s', 'stuh' ),
					sanitize_text_field( (string) ( $diagnostics['message'] ?? __( 'unknown error', 'stuh' ) ) )
				);

			return [
				'type' => $diagnostics_succeeded ? 'success' : 'warning',
				'message' => sprintf(
					__( 'Retried %1$d failed emails for %2$s: %3$d sent, %4$d still failed. %5$s', 'stuh' ),
					(int) ( $totals['attempted'] ?? 0 ),
					$site_url,
					(int) ( $totals['sent'] ?? 0 ),
					(int) ( $totals['failed'] ?? 0 ),
					$diagnostics_message
				),
			];
		}

		if ( $status_code < 200 || $status_code >= 300 ) {
			$message = ! empty( $retry['message'] )
				? sanitize_text_field( (string) $retry['message'] )
				: ( is_array( $body ) && ! empty( $body['message'] )
					? sanitize_text_field( (string) $body['message'] )
					: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code ) );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not retry failed emails: %s', 'stuh' ), $message ),
			];
		}

		return [
			'type'    => 'success',
			'message' => sprintf(
				__( 'The failed-email retry command was completed for %s.', 'stuh' ),
				$site_url
			),
		];
	}

	/**
	 * Ask a client site to skip installing new bundled themes during WordPress core upgrades.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function skip_new_bundled_themes( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/core-upgrade/skip-new-bundled-themes',
			[
				'headers' => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout' => 30,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not skip new bundled themes: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) || true !== ( $body['core_upgrade_skip_new_bundled'] ?? null ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: ( $status_code >= 200 && $status_code < 300
					? __( 'The client site returned an unexpected response.', 'stuh' )
					: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code ) );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not skip new bundled themes: %s', 'stuh' ), $message ),
			];
		}

		return [
			'type'    => 'success',
			'message' => sprintf( __( 'New bundled themes will now be skipped for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Ask a client site to retain ten post revisions.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function set_post_revisions( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/wp-config/set-post-revisions',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 30,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not set post revisions: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) || 10 !== ( $body['post_revisions'] ?? null ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: ( $status_code >= 200 && $status_code < 300
					? __( 'The client site returned an unexpected response.', 'stuh' )
					: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code ) );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not set post revisions: %s', 'stuh' ), $message ),
			];
		}

		return [
			'type'    => 'success',
			'message' => sprintf( __( 'Post revisions are now set to 10 for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Ask a client site to toggle WordPress's search engine visibility setting.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string, visible?: bool}
	 */
	private static function toggle_search_engine_visibility( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/site/toggle-search-engine-visibility',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 30,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not update search engine visibility: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) || ! array_key_exists( 'search_engine_visibility', $body ) || ! is_bool( $body['search_engine_visibility'] ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: ( $status_code >= 200 && $status_code < 300
					? __( 'The client site returned an unexpected response.', 'stuh' )
					: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code ) );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not update search engine visibility: %s', 'stuh' ), $message ),
			];
		}

		$visible = $body['search_engine_visibility'];
		return [
			'type'    => 'success',
			'visible' => $visible,
			'message' => sprintf(
				$visible
					? __( 'Search engine visibility is now enabled for %s.', 'stuh' )
					: __( 'Search engine visibility is now disabled for %s.', 'stuh' ),
				$site_url
			),
		];
	}

	/**
	 * Ask a client site to disable WordPress debugging.
	 *
	 * @param array<string, mixed>|null $client
	 * @return array{type: string, message: string}
	 */
	private static function disable_debugging( ?array $client ): array {
		if ( ! $client ) {
			return [
				'type'    => 'error',
				'message' => __( 'The selected client site could not be found.', 'stuh' ),
			];
		}

		$site_url = esc_url_raw( (string) ( $client['site_url'] ?? '' ) );
		$api_key  = (string) ( $client['api_key'] ?? '' );
		if ( '' === $site_url || '' === $api_key ) {
			return [
				'type'    => 'error',
				'message' => __( 'The client site has no URL or configured client key.', 'stuh' ),
			];
		}

		$response = wp_remote_post(
			trailingslashit( $site_url ) . 'wp-json/stu-client/v1/wp-config/disable-debugging',
			[
				'headers'   => [ 'X-STU-Key' => $api_key ],
				'sslverify' => self::client_sslverify( $client ),
				'timeout'   => 30,
			]
		);
		if ( is_wp_error( $response ) ) {
			return [
				'type'    => 'error',
				'message' => sprintf(
					__( 'Could not disable debugging: %s', 'stuh' ),
					$response->get_error_message()
				),
			];
		}

		$status_code = wp_remote_retrieve_response_code( $response );
		$body        = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $status_code < 200 || $status_code >= 300 || ! is_array( $body ) || false !== ( $body['wp_debug'] ?? null ) ) {
			$message = is_array( $body ) && ! empty( $body['message'] )
				? sanitize_text_field( (string) $body['message'] )
				: ( $status_code >= 200 && $status_code < 300
					? __( 'The client site returned an unexpected response.', 'stuh' )
					: sprintf( __( 'The client site returned HTTP %d.', 'stuh' ), $status_code ) );

			return [
				'type'    => 'error',
				'message' => sprintf( __( 'Could not disable debugging: %s', 'stuh' ), $message ),
			];
		}

		return [
			'type'    => 'success',
			'message' => sprintf( __( 'Debugging is now disabled for %s.', 'stuh' ), $site_url ),
		];
	}

	/**
	 * Whether requests to this client should verify its TLS certificate.
	 *
	 * An explicit GHTU_SSLVERIFY=false client setting is reported through
	 * authenticated telemetry and opts that client out of certificate verification.
	 *
	 * @param array<string, mixed> $client
	 */
	private static function client_sslverify( array $client ): bool {
		$telemetry = self::get_telemetry();
		$report    = is_array( $telemetry[ $client['id'] ?? '' ] ?? null ) ? $telemetry[ $client['id'] ?? '' ] : [];
		$data      = is_array( $report['data'] ?? null ) ? $report['data'] : [];
		$wp_config = is_array( $data['wp_config'] ?? null ) ? $data['wp_config'] : [];

		return false !== ( $wp_config['ssl_verify'] ?? true );
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
		$external_parties = self::get_external_parties();
		$external_party_names = [];
		$external_party_search_values = [];
		$external_parties_by_id = [];
		foreach ( $external_parties as $party ) {
			if ( isset( $party['id'], $party['name'] ) ) {
				$party_id = (string) $party['id'];
				$external_party_names[ $party_id ] = (string) $party['name'];
				$external_parties_by_id[ $party_id ] = $party;
				$external_party_search_values[ $party_id ] = implode(
					' ',
					array_filter(
						[
							(string) $party['name'],
							(string) ( $party['contact_name'] ?? '' ),
							(string) ( $party['email'] ?? '' ),
						]
					)
				);
			}
		}
		$enabled_client_count = count( array_filter( $clients, fn( array $client ): bool => (bool) ( $client['enabled'] ?? true ) ) );
		$disabled_client_count = count( $clients ) - $enabled_client_count;
		$stale_client_count = count( array_filter( $clients, fn( array $client ): bool => self::is_client_stale( $client ) ) );
		$selected_status = sanitize_key( wp_unslash( $_GET['stuh_status'] ?? '' ) );
		if ( ! in_array( $selected_status, [ 'enabled', 'disabled', 'stale' ], true ) ) {
			$selected_status = 'all';
		}
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
		$visible_column_count = count( array_diff_key( $columns, array_flip( $hidden_columns ) ) ) + 1;
		$uid     = get_current_user_id();
		$new_key = get_transient( 'stuh_new_key_' . $uid );
		if ( $new_key ) {
			delete_transient( 'stuh_new_key_' . $uid );
		}
		$smtp_retry = get_transient( 'stuh_smtp_retry_' . $uid );
		if ( $smtp_retry ) {
			delete_transient( 'stuh_smtp_retry_' . $uid );
		}
		$pending_updates = get_transient( 'stuh_pending_updates_' . $uid );
		if ( $pending_updates ) {
			delete_transient( 'stuh_pending_updates_' . $uid );
		}
		$wordpress_update = get_transient( 'stuh_wordpress_update_' . $uid );
		if ( $wordpress_update ) {
			delete_transient( 'stuh_wordpress_update_' . $uid );
		}
		$diagnostics_refresh = get_transient( 'stuh_diagnostics_refresh_' . $uid );
		if ( $diagnostics_refresh ) {
			delete_transient( 'stuh_diagnostics_refresh_' . $uid );
		}
		$core_upgrade_setting = get_transient( 'stuh_core_upgrade_setting_' . $uid );
		if ( $core_upgrade_setting ) {
			delete_transient( 'stuh_core_upgrade_setting_' . $uid );
		}
		$post_revisions = get_transient( 'stuh_post_revisions_' . $uid );
		if ( $post_revisions ) {
			delete_transient( 'stuh_post_revisions_' . $uid );
		}
		$search_engine_visibility = get_transient( 'stuh_search_engine_visibility_' . $uid );
		if ( $search_engine_visibility ) {
			delete_transient( 'stuh_search_engine_visibility_' . $uid );
		}
		$disable_debugging = get_transient( 'stuh_disable_debugging_' . $uid );
		if ( $disable_debugging ) {
			delete_transient( 'stuh_disable_debugging_' . $uid );
		}
		$bulk_homepage_check = get_transient( 'stuh_bulk_homepage_check_' . $uid );
		if ( $bulk_homepage_check ) {
			delete_transient( 'stuh_bulk_homepage_check_' . $uid );
		}
		?>
		<div class="wrap stuh-client-sites">
			<h1><?php esc_html_e( 'Team Switch — Client Sites', 'stuh' ); ?></h1>

			<?php if ( $new_key ) : ?>
			<div class="notice notice-success" style="padding: 16px 16px 8px;">
				<h3 style="margin-top: 0;">&#128274; New API Key</h3>
				<p><strong>This key is shown only once. Copy it before leaving this page.</strong></p>
				<code id="stuh-api-key" style="display:block;font-size:14px;background:#f0f0f1;padding:10px 14px;border-radius:4px;word-break:break-all;user-select:all;margin-bottom:12px;"><?php echo esc_html( $new_key['key'] ); ?></code>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $smtp_retry ) ) : ?>
			<div class="notice notice-<?php echo in_array( $smtp_retry['type'] ?? '', [ 'success', 'warning' ], true ) ? esc_attr( $smtp_retry['type'] ) : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $smtp_retry['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $pending_updates ) ) : ?>
			<div class="notice notice-<?php echo in_array( $pending_updates['type'] ?? '', [ 'success', 'warning' ], true ) ? esc_attr( $pending_updates['type'] ) : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $pending_updates['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $wordpress_update ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $wordpress_update['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $wordpress_update['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $diagnostics_refresh ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $diagnostics_refresh['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $diagnostics_refresh['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $bulk_homepage_check ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $bulk_homepage_check['type'] ?? '' ) ? 'success' : 'warning'; ?> is-dismissible">
				<p><?php echo esc_html( $bulk_homepage_check['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $core_upgrade_setting ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $core_upgrade_setting['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $core_upgrade_setting['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $post_revisions ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $post_revisions['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $post_revisions['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $search_engine_visibility ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $search_engine_visibility['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $search_engine_visibility['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<?php if ( is_array( $disable_debugging ) ) : ?>
			<div class="notice notice-<?php echo 'success' === ( $disable_debugging['type'] ?? '' ) ? 'success' : 'error'; ?> is-dismissible">
				<p><?php echo esc_html( $disable_debugging['message'] ?? '' ); ?></p>
			</div>
			<?php endif; ?>

			<ul class="subsubsub stuh-client-status-filters" aria-label="<?php esc_attr_e( 'Filter client sites by status', 'stuh' ); ?>">
				<li class="all"><a href="#" class="<?php echo 'all' === $selected_status ? 'current' : ''; ?>" data-status="all"<?php echo 'all' === $selected_status ? ' aria-current="page"' : ''; ?>><?php esc_html_e( 'All', 'stuh' ); ?> <span class="count">(<?php echo esc_html( count( $clients ) ); ?>)</span></a> |</li>
				<li class="enabled"><a href="#" class="<?php echo 'enabled' === $selected_status ? 'current' : ''; ?>" data-status="enabled"<?php echo 'enabled' === $selected_status ? ' aria-current="page"' : ''; ?>><?php esc_html_e( 'Enabled', 'stuh' ); ?> <span class="count">(<?php echo esc_html( $enabled_client_count ); ?>)</span></a> |</li>
				<li class="disabled"><a href="#" class="<?php echo 'disabled' === $selected_status ? 'current' : ''; ?>" data-status="disabled"<?php echo 'disabled' === $selected_status ? ' aria-current="page"' : ''; ?>><?php esc_html_e( 'Disabled', 'stuh' ); ?> <span class="count">(<?php echo esc_html( $disabled_client_count ); ?>)</span></a> |</li>
				<li class="stale"><a href="#" class="<?php echo 'stale' === $selected_status ? 'current' : ''; ?>" data-status="stale"<?php echo 'stale' === $selected_status ? ' aria-current="page"' : ''; ?>><?php esc_html_e( 'Stale', 'stuh' ); ?> <span class="count">(<?php echo esc_html( $stale_client_count ); ?>)</span></a></li>
			</ul>

			<?php
			// Sorting.
			$allowed_cols = array_diff( array_keys( $columns ), [ 'diagnostics' ] );
			$orderby      = in_array( $_GET['orderby'] ?? '', $allowed_cols, true ) ? $_GET['orderby'] : 'site_url';
			$order        = strtolower( $_GET['order'] ?? 'asc' ) === 'desc' ? 'desc' : 'asc';
			$opposite     = $order === 'asc' ? 'desc' : 'asc';
			$search_query = sanitize_text_field( wp_unslash( $_GET['stuh_search'] ?? '' ) );

			usort( $clients, function( $a, $b ) use ( $orderby, $order, $telemetry, $external_party_names ) {
				$va = $a[ $orderby ] ?? '';
				$vb = $b[ $orderby ] ?? '';
				if ( 'homepage_status' === $orderby ) {
					$health_a = is_array( $a['homepage_health'] ?? null ) ? $a['homepage_health'] : [];
					$health_b = is_array( $b['homepage_health'] ?? null ) ? $b['homepage_health'] : [];
					$va       = sprintf( '%d-%03d', ! empty( $health_a['ok'] ) ? 2 : ( $health_a ? 1 : 0 ), (int) ( $health_a['status_code'] ?? 0 ) );
					$vb       = sprintf( '%d-%03d', ! empty( $health_b['ok'] ) ? 2 : ( $health_b ? 1 : 0 ), (int) ( $health_b['status_code'] ?? 0 ) );
				}
				if ( 'site' === $orderby ) {
					$data_a = is_array( $telemetry[ $a['id'] ]['data'] ?? null ) ? $telemetry[ $a['id'] ]['data'] : [];
					$data_b = is_array( $telemetry[ $b['id'] ]['data'] ?? null ) ? $telemetry[ $b['id'] ]['data'] : [];
					$site_a = is_array( $data_a['site'] ?? null ) ? $data_a['site'] : [];
					$site_b = is_array( $data_b['site'] ?? null ) ? $data_b['site'] : [];
					$va     = is_string( $site_a['title'] ?? null ) ? $site_a['title'] : '';
					$vb     = is_string( $site_b['title'] ?? null ) ? $site_b['title'] : '';
				}
				if ( 'site_url' === $orderby ) {
					$va = self::client_url_label( (string) $va );
					$vb = self::client_url_label( (string) $vb );
				}
				if ( 'tags' === $orderby ) {
					$va = implode( ', ', (array) $va );
					$vb = implode( ', ', (array) $vb );
				}
				if ( in_array( $orderby, [ 'domain_owner', 'server_owner', 'email_owner' ], true ) ) {
					$connection_type = str_replace( '_owner', '', $orderby );
					$field           = $connection_type . '_external_party_id';
					$va              = $external_party_names[ (string) ( $a[ $field ] ?? '' ) ] ?? '';
					$vb              = $external_party_names[ (string) ( $b[ $field ] ?? '' ) ] ?? '';
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
				if ( ( $va === null || $va === '' ) && ( $vb === null || $vb === '' ) ) return 0;
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
			<p class="search-box" style="float:right;margin:8px 0 0;">
				<label class="screen-reader-text" for="stuh-client-search"><?php esc_html_e( 'Search client sites', 'stuh' ); ?></label>
				<span id="stuh-client-search-count" aria-live="polite"></span>
				<input type="search" id="stuh-client-search" value="<?php echo esc_attr( $search_query ); ?>" placeholder="<?php esc_attr_e( 'Search tags, URLs, plugins, themes, and more... Use -term to exclude.', 'stuh' ); ?>">
			</p>
			<div class="clear"></div>
			<form id="stuh-client-bulk-actions" method="post" class="tablenav top">
				<?php wp_nonce_field( 'stuh_admin' ); ?>
				<input type="hidden" name="stuh_action" value="bulk_update_clients">
				<div class="alignleft actions bulkactions">
					<label for="stuh-bulk-action-selector-top" class="screen-reader-text"><?php esc_html_e( 'Select bulk action', 'stuh' ); ?></label>
					<select name="bulk_action" id="stuh-bulk-action-selector-top">
						<option value=""><?php esc_html_e( 'Bulk actions', 'stuh' ); ?></option>
						<option value="enable"><?php esc_html_e( 'Enable', 'stuh' ); ?></option>
						<option value="disable"><?php esc_html_e( 'Disable', 'stuh' ); ?></option>
						<option value="check_homepage_status"><?php esc_html_e( 'Check homepage status', 'stuh' ); ?></option>
					</select>
					<button type="submit" class="button action"><?php esc_html_e( 'Apply', 'stuh' ); ?></button>
					<?php if ( $client_tags ) : ?>
					<div class="stuh-client-tag-filters" aria-label="<?php esc_attr_e( 'Filter client sites by tag', 'stuh' ); ?>">
						<strong><?php esc_html_e( 'Filter by tag:', 'stuh' ); ?></strong>
						<?php foreach ( $client_tags as $tag ) : ?>
						<button type="button" class="stuh-client-tag stuh-client-tag--<?php echo esc_attr( sanitize_html_class( strtolower( $tag ) ) ); ?>" data-tag="<?php echo esc_attr( $tag ); ?>"><?php echo esc_html( $tag ); ?></button>
						<?php endforeach; ?>
					</div>
					<?php endif; ?>
				</div>
			</form>

			<table class="wp-list-table widefat" style="margin-top: 20px;">
				<thead>
					<tr>
						<td class="manage-column column-cb check-column">
							<label class="screen-reader-text" for="cb-select-all-1"><?php esc_html_e( 'Select all client sites', 'stuh' ); ?></label>
							<input id="cb-select-all-1" type="checkbox">
						</td>
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
						$enabled  = (bool) ( $c['enabled'] ?? true );
						$is_stale = self::is_client_stale( $c );
						$homepage_health = is_array( $c['homepage_health'] ?? null ) ? $c['homepage_health'] : [];
						$homepage_unhealthy = $homepage_health && empty( $homepage_health['ok'] );
						$row_bg   = $homepage_unhealthy
							? 'background-color:#fbeaea;'
							: ( $is_stale
							? 'background-color:#fff9f2;'
							: ( ( $row_index % 2 === 0 ) ? 'background-color:#f6f7f7;' : '' ) );
						$search_telemetry = is_array( $telemetry[ $c['id'] ] ?? null ) ? $telemetry[ $c['id'] ] : [];
						$row_index++;
					?>
					<tr class="stuh-client-row<?php echo $is_stale ? ' stuh-client-row--stale' : ''; ?><?php echo $homepage_unhealthy ? ' stuh-client-row--unhealthy' : ''; ?>" data-client-id="<?php echo esc_attr( $c['id'] ); ?>" data-status="<?php echo $enabled ? 'enabled' : 'disabled'; ?>" data-stale="<?php echo $is_stale ? 'true' : 'false'; ?>" data-search="<?php echo esc_attr( self::client_search_text( $c, $search_telemetry, $external_party_search_values ) ); ?>" style="<?php echo esc_attr( $row_bg ); ?>">
						<th scope="row" class="check-column">
							<label class="screen-reader-text" for="cb-select-<?php echo esc_attr( $c['id'] ); ?>"><?php echo esc_html( sprintf( __( 'Select %s', 'stuh' ), $c['site_url'] ?? '' ) ); ?></label>
							<input id="cb-select-<?php echo esc_attr( $c['id'] ); ?>" type="checkbox" name="client_ids[]" value="<?php echo esc_attr( $c['id'] ); ?>" form="stuh-client-bulk-actions">
						</th>
						<?php
						$report = $telemetry[ $c['id'] ] ?? null;
						$data   = is_array( $report['data'] ?? null ) ? $report['data'] : [];
						foreach ( $columns as $column_id => $column_label ) :
						?>
						<td class="column-<?php echo esc_attr( $column_id ); ?><?php echo in_array( $column_id, $hidden_columns, true ) ? ' hidden' : ''; ?>">
						<?php if ( 'site' === $column_id ) : ?>
							<?php
							$site             = is_array( $data['site'] ?? null ) ? $data['site'] : [];
							$site_title       = is_string( $site['title'] ?? null ) ? $site['title'] : '';
							$site_description = is_string( $site['description'] ?? null ) ? $site['description'] : '';
							$favicon_url      = is_string( $site['favicon_url'] ?? null ) ? esc_url( $site['favicon_url'] ) : '';
							?>
							<?php if ( '' !== $site_title || '' !== $site_description ) : ?>
								<?php if ( '' !== $site_title ) : ?>
									<span class="stuh-client-site-heading">
										<?php if ( '' !== $favicon_url ) : ?>
											<img class="stuh-client-favicon" src="<?php echo esc_url( $favicon_url ); ?>" alt="" width="16" height="16">
										<?php endif; ?>
										<strong class="stuh-client-site-title"><?php echo esc_html( $site_title ); ?></strong>
									</span>
								<?php endif; ?>
								<?php if ( '' !== $site_description ) : ?>
									<span class="stuh-client-site-description"><?php echo esc_html( $site_description ); ?></span>
								<?php endif; ?>
							<?php else : ?>
								<em>&mdash;</em>
							<?php endif; ?>
						<?php elseif ( 'site_url' === $column_id ) : ?>
							<?php
							$all_urls   = $c['site_urls'] ?? ( ( $c['site_url'] ?? '' ) !== '' ? [ $c['site_url'] ] : [] );
							$site       = is_array( $data['site'] ?? null ) ? $data['site'] : [];
							$login_url  = is_string( $site['login_url'] ?? null ) ? $site['login_url'] : '';
							foreach ( $all_urls as $url_index => $u ) :
							?>
							<a href="<?php echo esc_url( $u ); ?>" target="_blank" rel="noopener">
								<?php echo esc_html( self::client_url_label( $u ) ); ?>
							</a><?php if ( ! $enabled && 0 === $url_index ) : ?> <span class="post-state"><strong>&mdash; <?php esc_html_e( 'Disabled', 'stuh' ); ?></strong></span><?php endif; ?><br>
							<?php endforeach; ?>
							<?php self::render_client_row_actions( $c, $enabled, $login_url ); ?>
						<?php elseif ( in_array( $column_id, [ 'domain_owner', 'server_owner', 'email_owner' ], true ) ) : ?>
							<?php self::render_external_party_owner( $c, $external_parties_by_id, str_replace( '_owner', '', $column_id ) ); ?>
						<?php elseif ( 'homepage_status' === $column_id ) : ?>
							<?php if ( $homepage_health ) : ?>
								<?php
								$status_code = (int) ( $homepage_health['status_code'] ?? 0 );
								$status_text = $status_code > 0
									? sprintf( __( 'HTTP %d', 'stuh' ), $status_code )
									: __( 'Request failed', 'stuh' );
								if ( 'wordpress_critical_error' === ( $homepage_health['status'] ?? '' ) ) {
									$status_text .= ' — ' . __( 'WordPress critical error', 'stuh' );
								}
								?>
								<span style="color:<?php echo ! empty( $homepage_health['ok'] ) ? '#008a20' : '#b32d2e'; ?>;font-weight:600;" title="<?php echo esc_attr( (string) ( $homepage_health['message'] ?? '' ) ); ?>">
									<?php echo ! empty( $homepage_health['ok'] ) ? '&#10003;' : '&#10007;'; ?>
									<?php echo esc_html( $status_text ); ?>
								</span><br>
								<small><?php echo esc_html( wp_date( 'Y-m-d H:i', (int) ( $homepage_health['checked_at'] ?? 0 ) ) ); ?></small>
							<?php else : ?>
								<em><?php esc_html_e( 'Not checked', 'stuh' ); ?></em>
							<?php endif; ?>
						<?php elseif ( 'tags' === $column_id ) : ?>
							<?php $tags = (array) ( $c['tags'] ?? [] ); ?>
							<?php if ( $tags ) : ?>
								<?php foreach ( $tags as $tag ) : ?>
									<button type="button" class="stuh-client-tag stuh-client-tag--<?php echo esc_attr( sanitize_html_class( strtolower( $tag ) ) ); ?>" data-tag="<?php echo esc_attr( $tag ); ?>"><?php echo esc_html( $tag ); ?></button>
								<?php endforeach; ?>
							<?php else : ?>
								<em>&mdash;</em>
							<?php endif; ?>
							<p class="row-actions stuh-client-row-actions" style="margin:4px 0 0;">
								<span class="edit-tags">
									<button type="button" onclick="(function(btn){ var row = document.getElementById('stuh-edit-tags-<?php echo esc_js( $c['id'] ); ?>'); var hidden = row.style.display === 'none' || row.style.display === ''; row.style.display = hidden ? 'table-row' : 'none'; btn.textContent = hidden ? 'Cancel' : 'Edit Tags'; })(this)"><?php esc_html_e( 'Edit Tags', 'stuh' ); ?></button>
								</span>
							</p>
						<?php elseif ( 'created_at' === $column_id ) : ?>
							<?php echo esc_html( $c['created_at'] ? date_i18n( 'Y-m-d', $c['created_at'] ) : '—' ); ?>
						<?php elseif ( 'last_seen' === $column_id ) : ?>
							<?php if ( $c['last_seen'] ) : ?>
								<?php
								$last_seen = (int) $c['last_seen'];
								$elapsed   = time() - $last_seen;
								$display   = $elapsed <= DAY_IN_SECONDS
									? sprintf( __( '%s ago', 'stuh' ), human_time_diff( $last_seen, time() ) )
									: wp_date( 'Y-m-d H:i', $last_seen, wp_timezone() );
								echo esc_html( $display );
								?>
							<?php else : ?>
								<em>Never</em>
							<?php endif; ?>
						<?php elseif ( 'last_seen_ip' === $column_id ) : ?>
							<?php
								$lsip      = $c['last_seen_ip'] ?? '';
								$lsdetails = $lsip ? self::ip_details( $lsip ) : [ 'label' => '', 'url' => '' ];
							?>
							<?php if ( $lsip ) : ?>
								<?php if ( $lsdetails['label'] ) : ?>
									<?php if ( $lsdetails['url'] ) : ?>
										<a href="<?php echo esc_url( $lsdetails['url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $lsdetails['label'] ); ?></a><br>
									<?php else : ?>
										<?php echo esc_html( $lsdetails['label'] ); ?><br>
									<?php endif; ?>
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
							<?php if ( 'telemetry_wp' === $column_id && $enabled && $value && ( 'outdated' === $wp_safety['status'] || ( $wp_safety['latest'] && $value !== $wp_safety['latest'] ) ) ) : ?>
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post" onsubmit="return confirm('<?php echo esc_js( __( 'Install the pending WordPress core update on this client site?', 'stuh' ) ); ?>');">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="install_wordpress_update">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Update', 'stuh' ); ?></button>
									</form>
								</div>
							<?php endif; ?>
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
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="retry_failed_smtp_emails">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Retry', 'stuh' ); ?></button>
									</form>
								</div>
							<?php else : ?>
								<?php echo esc_html( $value ); ?>
							<?php endif; ?>
						<?php elseif ( 'telemetry_pending_updates' === $column_id ) : ?>
							<?php $pending_updates_count = self::telemetry_column_value( $column_id, $data ); ?>
							<?php echo esc_html( $pending_updates_count ); ?>
							<?php if ( $enabled && is_numeric( $pending_updates_count ) && (int) $pending_updates_count > 0 ) : ?>
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post" onsubmit="return confirm('<?php echo esc_js( __( 'Install all pending plugin and theme updates on this client site?', 'stuh' ) ); ?>');">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="install_pending_updates">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Update', 'stuh' ); ?></button>
									</form>
								</div>
							<?php endif; ?>
						<?php elseif ( 'telemetry_debug' === $column_id ) : ?>
							<?php $debug = is_array( $data['debug'] ?? null ) ? $data['debug'] : []; ?>
							<?php $debug_enabled = ! empty( $debug['wp_debug'] ); ?>
							<?php if ( $debug_enabled ) : ?>
								<span style="color:<?php echo ! empty( $debug['debug_display'] ) ? '#d63638' : '#dba617'; ?>;font-weight:600;"><?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?></span>
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="disable_debugging">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Disable Debugging', 'stuh' ); ?></button>
									</form>
								</div>
							<?php else : ?>
								<?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?>
							<?php endif; ?>
						<?php elseif ( 'telemetry_search_engine_visibility' === $column_id ) : ?>
							<?php $site = is_array( $data['site'] ?? null ) ? $data['site'] : []; ?>
							<?php $search_engine_visibility = ! empty( $site['search_engine_visibility'] ); ?>
							<span<?php echo $search_engine_visibility ? '' : ' style="color:#d63638;font-weight:600;"'; ?>><?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?></span>
							<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
								<form method="post">
									<?php wp_nonce_field( 'stuh_admin' ); ?>
									<input type="hidden" name="stuh_action" value="toggle_search_engine_visibility">
									<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
									<button type="submit"><?php esc_html_e( 'Change', 'stuh' ); ?></button>
								</form>
							</div>
						<?php elseif ( 'telemetry_post_revisions' === $column_id ) : ?>
							<?php $wp_config = is_array( $data['wp_config'] ?? null ) ? $data['wp_config'] : []; ?>
							<?php $post_revisions = $wp_config['post_revisions'] ?? null; ?>
							<?php $post_revisions_are_ten = 10 === $post_revisions || '10' === $post_revisions; ?>
							<?php if ( ! $post_revisions_are_ten ) : ?>
								<span style="color:#d63638;font-weight:600;"><?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?></span>
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="set_post_revisions">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Fix', 'stuh' ); ?></button>
									</form>
								</div>
							<?php else : ?>
								<?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?>
							<?php endif; ?>
						<?php elseif ( 'telemetry_core_upgrade_skip_new_bundled' === $column_id ) : ?>
							<?php $wp_config = is_array( $data['wp_config'] ?? null ) ? $data['wp_config'] : []; ?>
							<?php $skip_new_bundled_themes = true === ( $wp_config['core_upgrade_skip_new_bundled'] ?? null ) || 'true' === ( $wp_config['core_upgrade_skip_new_bundled'] ?? null ); ?>
							<?php if ( ! $skip_new_bundled_themes ) : ?>
								<span style="color:#d63638;font-weight:600;"><?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?></span>
								<div class="row-actions stuh-client-row-actions" style="margin-top:4px;">
									<form method="post">
										<?php wp_nonce_field( 'stuh_admin' ); ?>
										<input type="hidden" name="stuh_action" value="skip_new_bundled_themes">
										<input type="hidden" name="client_id" value="<?php echo esc_attr( $c['id'] ); ?>">
										<button type="submit"><?php esc_html_e( 'Fix', 'stuh' ); ?></button>
									</form>
								</div>
							<?php else : ?>
								<?php echo esc_html( self::telemetry_column_value( $column_id, $data ) ); ?>
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
						<?php elseif ( 'telemetry_active_theme' === $column_id ) : ?>
							<?php
							$active_theme = is_array( $data['active_theme'] ?? null ) ? $data['active_theme'] : [];
							$parent_theme = is_array( $active_theme['parent_theme'] ?? null ) ? $active_theme['parent_theme'] : [];
							self::render_active_theme_name( $active_theme );
							if ( [] !== $parent_theme ) {
								$theme_name    = is_scalar( $active_theme['name'] ?? null ) ? (string) $active_theme['name'] : '';
								$theme_version = is_scalar( $active_theme['version'] ?? null ) ? (string) $active_theme['version'] : '';
								if ( '' !== trim( $theme_name . $theme_version ) ) {
									echo '<br>';
								}
								self::render_active_theme_name( $parent_theme );
							}
							?>
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
					<?php self::render_external_party_owner_editor( $c, $external_parties, 'domain', $visible_column_count ); ?>
					<?php self::render_external_party_owner_editor( $c, $external_parties, 'server', $visible_column_count ); ?>
					<?php self::render_external_party_owner_editor( $c, $external_parties, 'email', $visible_column_count ); ?>
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
				var statusFilters = Array.prototype.slice.call(document.querySelectorAll('.stuh-client-status-filters a'));
				var selectAll = document.getElementById('cb-select-all-1');
				var clientCheckboxes = Array.prototype.slice.call(document.querySelectorAll('input[name="client_ids[]"]'));
				var selectedStatus = <?php echo wp_json_encode( $selected_status ); ?>;

				if (!search || !rows.length) {
					return;
				}

				function applyFilter() {
					var query = search.value.trim().toLocaleLowerCase();
					var terms = query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
					var visible = 0;

					rows.forEach(function(row) {
						var searchableText = row.dataset.search.toLocaleLowerCase();
						var matchesStatus = selectedStatus === 'all'
							|| (selectedStatus === 'stale' ? row.dataset.stale === 'true' : row.dataset.status === selectedStatus);
						var matches = matchesStatus && terms.every(function(term) {
							var excluded = term.charAt(0) === '-' && term.length > 1;
							term = (excluded ? term.slice(1) : term).replace(/^"|"$/g, '');
							if (excluded) {
								return searchableText.indexOf(term) === -1;
							}
							return !term || searchableText.indexOf(term) !== -1;
						});
						row.style.display = matches ? '' : 'none';
						if (matches) {
							row.style.backgroundColor = row.dataset.stale === 'true'
								? '#fff9f2'
								: (visible % 2 === 0 ? '#f6f7f7' : '');
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
					updateSelectAll();
				}

				function updateSelectAll() {
					var visibleCheckboxes = clientCheckboxes.filter(function(checkbox) {
						return checkbox.closest('.stuh-client-row').style.display !== 'none';
					});
					selectAll.checked = visibleCheckboxes.length > 0 && visibleCheckboxes.every(function(checkbox) {
						return checkbox.checked;
					});
					selectAll.indeterminate = !selectAll.checked && visibleCheckboxes.some(function(checkbox) {
						return checkbox.checked;
					});
				}

				selectAll.addEventListener('change', function() {
					clientCheckboxes.forEach(function(checkbox) {
						if (checkbox.closest('.stuh-client-row').style.display !== 'none') {
							checkbox.checked = selectAll.checked;
						}
					});
					updateSelectAll();
				});

				clientCheckboxes.forEach(function(checkbox) {
					checkbox.addEventListener('change', updateSelectAll);
				});

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

				statusFilters.forEach(function(filter) {
					filter.addEventListener('click', function(event) {
						event.preventDefault();
						selectedStatus = filter.dataset.status;
						var url = new URL(window.location.href);
						if (selectedStatus === 'all') {
							url.searchParams.delete('stuh_status');
						} else {
							url.searchParams.set('stuh_status', selectedStatus);
						}
						window.history.replaceState({}, '', url);
						statusFilters.forEach(function(statusFilter) {
							var isCurrent = statusFilter === filter;
							statusFilter.classList.toggle('current', isCurrent);
							if (isCurrent) {
								statusFilter.setAttribute('aria-current', 'page');
							} else {
								statusFilter.removeAttribute('aria-current');
							}
						});
						applyFilter();
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
	// Admin page: external parties
	// --------------------------------------------------------

	public function render_external_parties_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ) );
		}

		$parties = self::get_external_parties();
		usort( $parties, static fn( array $a, array $b ): int => strcasecmp( (string) ( $a['name'] ?? '' ), (string) ( $b['name'] ?? '' ) ) );
		$status = sanitize_key( wp_unslash( $_GET['stuh_party_status'] ?? '' ) );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'External Parties', 'stuh' ); ?></h1>
			<p><?php esc_html_e( 'Manage third parties that own or manage client domains and servers.', 'stuh' ); ?></p>

			<?php if ( 'added' === $status ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'External party added.', 'stuh' ); ?></p></div>
			<?php elseif ( 'updated' === $status ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'External party updated.', 'stuh' ); ?></p></div>
			<?php elseif ( 'deleted' === $status ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'External party deleted and its client connections removed.', 'stuh' ); ?></p></div>
			<?php elseif ( 'duplicate' === $status ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'An external party with that name already exists.', 'stuh' ); ?></p></div>
			<?php elseif ( 'invalid_email' === $status ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Enter a valid contact email address.', 'stuh' ); ?></p></div>
			<?php elseif ( 'invalid' === $status ) : ?>
				<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'Enter a party name, contact name, and valid contact email address.', 'stuh' ); ?></p></div>
			<?php endif; ?>

			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th scope="col" class="manage-column column-primary"><?php esc_html_e( 'Party name', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Contact name', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Contact email', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Added', 'stuh' ); ?></th>
					</tr>
				</thead>
				<tfoot>
					<tr>
						<th scope="col" class="manage-column column-primary"><?php esc_html_e( 'Party name', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Contact name', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Contact email', 'stuh' ); ?></th>
						<th scope="col" class="manage-column"><?php esc_html_e( 'Added', 'stuh' ); ?></th>
					</tr>
				</tfoot>
				<tbody>
				<?php if ( $parties ) : ?>
					<?php foreach ( $parties as $party ) : ?>
						<tr>
							<td class="column-primary" data-colname="<?php esc_attr_e( 'Party name', 'stuh' ); ?>">
								<strong><?php echo esc_html( $party['name'] ?? '' ); ?></strong>
								<div class="row-actions">
									<span class="edit">
										<button type="button" class="button-link" onclick="(function(){ var row = document.getElementById('stuh-edit-party-<?php echo esc_js( $party['id'] ); ?>'); row.style.display = row.style.display === 'none' ? 'table-row' : 'none'; })();"><?php esc_html_e( 'Edit', 'stuh' ); ?></button>
									</span>
									<?php if ( is_email( $party['email'] ?? '' ) ) : ?>
										| <span class="email"><a href="mailto:<?php echo esc_attr( $party['email'] ); ?>"><?php esc_html_e( 'Email', 'stuh' ); ?></a></span>
									<?php endif; ?>
									| <span class="delete">
										<form method="post" style="display:inline;" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this external party and remove all of its client connections?', 'stuh' ) ); ?>');">
											<?php wp_nonce_field( 'stuh_admin' ); ?>
											<input type="hidden" name="stuh_action" value="delete_external_party">
											<input type="hidden" name="external_party_id" value="<?php echo esc_attr( $party['id'] ); ?>">
											<button type="submit" class="button-link button-link-delete"><?php esc_html_e( 'Delete', 'stuh' ); ?></button>
										</form>
									</span>
								</div>
								<button type="button" class="toggle-row"><span class="screen-reader-text"><?php esc_html_e( 'Show more details', 'stuh' ); ?></span></button>
							</td>
							<td data-colname="<?php esc_attr_e( 'Contact name', 'stuh' ); ?>">
								<?php echo '' !== ( $party['contact_name'] ?? '' ) ? esc_html( $party['contact_name'] ) : '<span aria-hidden="true">—</span>'; ?>
							</td>
							<td data-colname="<?php esc_attr_e( 'Contact email', 'stuh' ); ?>">
								<?php if ( is_email( $party['email'] ?? '' ) ) : ?>
									<a href="mailto:<?php echo esc_attr( $party['email'] ); ?>"><?php echo esc_html( $party['email'] ); ?></a>
								<?php else : ?>
									<span aria-hidden="true">—</span>
								<?php endif; ?>
							</td>
							<td data-colname="<?php esc_attr_e( 'Added', 'stuh' ); ?>"><?php echo esc_html( ! empty( $party['created_at'] ) ? date_i18n( 'Y-m-d', (int) $party['created_at'] ) : '—' ); ?></td>
						</tr>
						<tr id="stuh-edit-party-<?php echo esc_attr( $party['id'] ); ?>" style="display:none;">
							<td colspan="4">
								<form method="post">
									<?php wp_nonce_field( 'stuh_admin' ); ?>
									<input type="hidden" name="stuh_action" value="save_external_party">
									<input type="hidden" name="external_party_id" value="<?php echo esc_attr( $party['id'] ); ?>">
									<table class="form-table" role="presentation">
										<tr>
											<th scope="row"><label for="stuh-party-name-<?php echo esc_attr( $party['id'] ); ?>"><?php esc_html_e( 'Party name', 'stuh' ); ?></label></th>
											<td><input type="text" id="stuh-party-name-<?php echo esc_attr( $party['id'] ); ?>" name="external_party_name" class="regular-text" value="<?php echo esc_attr( $party['name'] ?? '' ); ?>" required></td>
										</tr>
										<tr>
											<th scope="row"><label for="stuh-party-contact-<?php echo esc_attr( $party['id'] ); ?>"><?php esc_html_e( 'Contact name', 'stuh' ); ?></label></th>
											<td><input type="text" id="stuh-party-contact-<?php echo esc_attr( $party['id'] ); ?>" name="external_party_contact_name" class="regular-text" value="<?php echo esc_attr( $party['contact_name'] ?? '' ); ?>"></td>
										</tr>
										<tr>
											<th scope="row"><label for="stuh-party-email-<?php echo esc_attr( $party['id'] ); ?>"><?php esc_html_e( 'Contact email', 'stuh' ); ?></label></th>
											<td><input type="email" id="stuh-party-email-<?php echo esc_attr( $party['id'] ); ?>" name="external_party_email" class="regular-text" value="<?php echo esc_attr( $party['email'] ?? '' ); ?>"></td>
										</tr>
									</table>
									<?php submit_button( __( 'Update External Party', 'stuh' ), 'primary', 'submit', false ); ?>
									<button type="button" class="button" onclick="document.getElementById('stuh-edit-party-<?php echo esc_js( $party['id'] ); ?>').style.display='none';"><?php esc_html_e( 'Cancel', 'stuh' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php else : ?>
					<tr><td colspan="4"><?php esc_html_e( 'No external parties added yet.', 'stuh' ); ?></td></tr>
				<?php endif; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Add External Party', 'stuh' ); ?></h2>
			<form method="post">
				<?php wp_nonce_field( 'stuh_admin' ); ?>
				<input type="hidden" name="stuh_action" value="add_external_party">
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="stuh-external-party-name"><?php esc_html_e( 'Party name', 'stuh' ); ?></label></th>
						<td><input type="text" id="stuh-external-party-name" name="external_party_name" class="regular-text" placeholder="<?php esc_attr_e( 'Hosting provider or domain registrar', 'stuh' ); ?>" required></td>
					</tr>
					<tr>
						<th scope="row"><label for="stuh-external-party-contact-name"><?php esc_html_e( 'Contact name', 'stuh' ); ?></label></th>
						<td><input type="text" id="stuh-external-party-contact-name" name="external_party_contact_name" class="regular-text"></td>
					</tr>
					<tr>
						<th scope="row"><label for="stuh-external-party-email"><?php esc_html_e( 'Contact email', 'stuh' ); ?></label></th>
						<td><input type="email" id="stuh-external-party-email" name="external_party_email" class="regular-text"></td>
					</tr>
				</table>
				<?php submit_button( __( 'Add External Party', 'stuh' ), 'primary', 'submit', false ); ?>
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
