<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class STUH_Analytics {
	private const CONNECTION = 'stuh_google_connection';
	private const MAPPINGS = 'stuh_google_mappings';
	private const SCOPE = 'https://www.googleapis.com/auth/analytics.readonly';
	private const GTM_SCOPE = 'https://www.googleapis.com/auth/tagmanager.readonly';
	private const METRICS = [ 'activeUsers', 'sessions', 'screenPageViews', 'engagementRate', 'keyEvents' ];

	public static function init(): void {
		add_action( 'admin_menu', [ self::class, 'register_menu' ], 20 );
		add_action( 'admin_post_stuh_google_action', [ self::class, 'handle_action' ] );
		add_action( 'admin_post_stuh_google_oauth_callback', [ self::class, 'callback' ] );
		add_action( 'stuh_google_refresh_report', [ self::class, 'refresh_report' ] );
		add_action( 'stuh_google_discover', [ self::class, 'discover_client' ] );
	}

	public static function register_menu(): void {
		if ( current_user_can( 'manage_options' ) ) {
			add_submenu_page( 'stuh', __( 'Google Analytics', 'stuh' ), __( 'Google Analytics', 'stuh' ), 'manage_options', 'stuh-analytics', [ self::class, 'render_reports' ] );
		} else {
			add_menu_page( __( 'Google Analytics', 'stuh' ), __( 'Google Analytics', 'stuh' ), 'edit_others_posts', 'stuh-analytics', [ self::class, 'render_reports' ], 'dashicons-chart-area' );
		}
	}

	private static function config( string $name ): string {
		$value = defined( $name ) ? constant( $name ) : getenv( $name );
		return is_string( $value ) ? trim( $value ) : '';
	}

	private static function configuration_error(): ?WP_Error {
		if ( '' === self::config( 'ANALYTICS_CLIENT_ID' ) || '' === self::config( 'ANALYTICS_CLIENT_SECRET' ) ) {
			return new WP_Error( 'google_configuration', __( 'Configure ANALYTICS_CLIENT_ID and ANALYTICS_CLIENT_SECRET on the host server first. WordPress does not automatically load .env files.', 'stuh' ) );
		}
		if ( strlen( self::config( 'STUH_GOOGLE_TOKEN_KEY' ) ) < 32 || ! function_exists( 'openssl_encrypt' ) || ! function_exists( 'openssl_decrypt' ) ) {
			return new WP_Error( 'google_encryption', __( 'Configure a stable STUH_GOOGLE_TOKEN_KEY of at least 32 random characters outside the database, and enable PHP OpenSSL.', 'stuh' ) );
		}
		if ( 'https' !== wp_parse_url( self::callback_url(), PHP_URL_SCHEME ) ) {
			return new WP_Error( 'google_https', __( 'Google authorization requires an HTTPS WordPress admin URL.', 'stuh' ) );
		}
		return null;
	}

	private static function callback_url(): string {
		return admin_url( 'admin-post.php?action=stuh_google_oauth_callback' );
	}

	private static function page_url( string $client_id = '' ): string {
		return '' === $client_id
			? admin_url( 'admin.php?page=stuh-settings#stuh-google-settings' )
			: add_query_arg( [ 'page' => 'stuh', 'client_id' => $client_id, 'client_tab' => 'analytics' ], admin_url( 'admin.php' ) );
	}

	private static function require_admin(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ), '', [ 'response' => 403 ] );
		}
	}

	private static function require_viewer(): void {
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'edit_others_posts' ) ) {
			wp_die( esc_html__( 'Insufficient permissions', 'stuh' ), '', [ 'response' => 403 ] );
		}
	}

	private static function input( array $source, string $key ): string {
		return isset( $source[ $key ] ) && is_string( $source[ $key ] ) ? trim( wp_unslash( $source[ $key ] ) ) : '';
	}

	private static function finish( string $message, bool $error = false, string $client_id = '' ): void {
		set_transient( 'stuh_google_notice_' . get_current_user_id(), [ 'message' => $message, 'error' => $error ], 5 * MINUTE_IN_SECONDS );
		$url = '' !== $client_id && 'analytics' === self::input( $_POST, 'return_page' ) ? self::reports_url( $client_id ) : self::page_url( $client_id );
		if ( ! current_user_can( 'manage_options' ) ) {
			$url = self::reports_url( $client_id );
		}
		wp_safe_redirect( $url );
		exit;
	}

	private static function notice(): void {
		$key = 'stuh_google_notice_' . get_current_user_id();
		$notice = get_transient( $key );
		if ( is_array( $notice ) ) {
			delete_transient( $key );
			echo '<div class="notice ' . ( $notice['error'] ? 'notice-error' : 'notice-success' ) . '"><p>' . esc_html( $notice['message'] ) . '</p></div>';
		}
	}

	private static function connection() {
		$stored = get_option( self::CONNECTION, '' );
		if ( '' === $stored ) {
			return new WP_Error( 'google_disconnected', __( 'Connect Google in Updater Host > Settings > Google Analytics.', 'stuh' ) );
		}
		$error = self::configuration_error();
		if ( $error ) {
			return $error;
		}
		$raw = is_string( $stored ) ? base64_decode( $stored, true ) : false;
		if ( false === $raw || strlen( $raw ) <= 28 ) {
			return new WP_Error( 'google_credentials', __( 'Stored Google credentials are invalid. Disconnect and reconnect Google.', 'stuh' ) );
		}
		$json = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', hash( 'sha256', self::config( 'STUH_GOOGLE_TOKEN_KEY' ), true ), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ), self::CONNECTION );
		$data = false !== $json ? json_decode( $json, true ) : null;
		if ( ! is_array( $data ) || empty( $data['id'] ) || empty( $data['refresh_token'] ) || ! isset( $data['access_token'], $data['expires_at'], $data['client_id'] ) ) {
			return new WP_Error( 'google_credentials', __( 'Cannot decrypt Google credentials. Restore the original token key or disconnect and reconnect Google.', 'stuh' ) );
		}
		if ( ! hash_equals( $data['client_id'], self::config( 'ANALYTICS_CLIENT_ID' ) ) ) {
			return new WP_Error( 'google_client_changed', __( 'The Google OAuth client has changed. Disconnect and reconnect Google.', 'stuh' ) );
		}
		return $data;
	}

	private static function save_connection( array $connection ) {
		$iv = random_bytes( 12 );
		$tag = '';
		$ciphertext = openssl_encrypt( wp_json_encode( $connection ), 'aes-256-gcm', hash( 'sha256', self::config( 'STUH_GOOGLE_TOKEN_KEY' ), true ), OPENSSL_RAW_DATA, $iv, $tag, self::CONNECTION );
		if ( false === $ciphertext ) {
			return new WP_Error( 'google_encrypt', __( 'Could not encrypt Google credentials.', 'stuh' ) );
		}
		if ( ! update_option( self::CONNECTION, base64_encode( $iv . $tag . $ciphertext ), false ) ) {
			return new WP_Error( 'google_storage', __( 'Could not save Google credentials.', 'stuh' ) );
		}
		return true;
	}

	private static function request( string $url, array $args = [] ) {
		$debug_gtm = defined( 'WP_DEBUG' ) && WP_DEBUG && str_starts_with( $url, 'https://tagmanager.googleapis.com/tagmanager/v2/' );
		$endpoint = explode( '?', $url, 2 )[0];
		if ( $debug_gtm ) {
			error_log( '[STUH GTM] Request: ' . wp_json_encode( [ 'method' => $args['method'] ?? 'GET', 'endpoint' => $endpoint ] ) );
		}
		$response = wp_remote_request( $url, array_merge( [ 'timeout' => 20, 'redirection' => 0 ], $args ) );
		if ( is_wp_error( $response ) ) {
			if ( $debug_gtm ) {
				error_log( '[STUH GTM] Request failed: ' . wp_json_encode( [ 'endpoint' => $endpoint, 'code' => $response->get_error_code() ] ) );
			}
			return new WP_Error( 'google_network', __( 'Unable to reach Google. Check server connectivity and retry.', 'stuh' ) );
		}
		$status = wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $debug_gtm ) {
			error_log( '[STUH GTM] Response: ' . wp_json_encode( [ 'endpoint' => $endpoint, 'status' => $status, 'response_type' => get_debug_type( $data ) ] ) );
		}
		if ( $status < 200 || $status >= 300 ) {
			$error = is_array( $data ) ? ( $data['error'] ?? '' ) : '';
			$reason = is_array( $error ) ? ( $error['status'] ?? '' ) : $error;
			$reason = is_string( $reason ) && preg_match( '/^[A-Za-z0-9_]+$/D', $reason ) ? $reason : 'request_failed';
			return new WP_Error( 'google_http', sprintf( __( 'Google returned HTTP %1$d (%2$s). Check access, enabled APIs, and quotas; reconnect if authorization was revoked.', 'stuh' ), $status, $reason ), [ 'status' => $status ] );
		}
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'google_response', __( 'Google returned an invalid response.', 'stuh' ) );
		}
		return $data;
	}

	private static function access_token() {
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}
		if ( $connection['expires_at'] > time() + 60 ) {
			return $connection['access_token'];
		}
		$data = self::request( 'https://oauth2.googleapis.com/token', [
			'method' => 'POST',
			'body' => [
				'client_id' => self::config( 'ANALYTICS_CLIENT_ID' ),
				'client_secret' => self::config( 'ANALYTICS_CLIENT_SECRET' ),
				'refresh_token' => $connection['refresh_token'],
				'grant_type' => 'refresh_token',
			],
		] );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( empty( $data['access_token'] ) || ! is_string( $data['access_token'] ) || ! isset( $data['expires_in'] ) || ! is_numeric( $data['expires_in'] ) || $data['expires_in'] <= 0 ) {
			return new WP_Error( 'google_token', __( 'Google returned an invalid access token response. Reconnect Google.', 'stuh' ) );
		}
		$connection['access_token'] = $data['access_token'];
		$connection['expires_at'] = time() + (int) $data['expires_in'];
		if ( isset( $data['refresh_token'] ) && is_string( $data['refresh_token'] ) && '' !== $data['refresh_token'] ) {
			$connection['refresh_token'] = $data['refresh_token'];
		}
		$current = self::connection();
		if ( is_wp_error( $current ) || $current['id'] !== $connection['id'] ) {
			return new WP_Error( 'google_connection_changed', __( 'The Google connection changed during token refresh. Retry.', 'stuh' ) );
		}
		$saved = self::save_connection( $connection );
		return is_wp_error( $saved ) ? $saved : $connection['access_token'];
	}

	private static function api( string $path, ?array $body = null, string $service = 'admin' ) {
		$token = self::access_token();
		if ( is_wp_error( $token ) ) {
			return $token;
		}
		$args = [ 'headers' => [ 'Authorization' => 'Bearer ' . $token ] ];
		if ( null !== $body ) {
			$args['method'] = 'POST';
			$args['headers']['Content-Type'] = 'application/json';
			$args['body'] = wp_json_encode( $body );
		}
		$base = match ( $service ) {
			'admin' => 'https://analyticsadmin.googleapis.com/v1beta/',
			'data' => 'https://analyticsdata.googleapis.com/v1beta/',
			'gtm' => 'https://tagmanager.googleapis.com/tagmanager/v2/',
		};
		return self::request( $base . $path, $args );
	}

	private static function start(): void {
		$error = self::configuration_error();
		if ( $error ) {
			self::finish( $error->get_error_message(), true );
		}
		$state = bin2hex( random_bytes( 32 ) );
		$verifier = bin2hex( random_bytes( 32 ) );
		if ( ! set_transient( 'stuh_google_state_' . get_current_user_id(), [ 'hash' => hash( 'sha256', $state ), 'verifier' => $verifier ], 10 * MINUTE_IN_SECONDS ) ) {
			self::finish( __( 'Could not save the authorization state. Retry.', 'stuh' ), true );
		}
		$url = add_query_arg( [
			'client_id' => self::config( 'ANALYTICS_CLIENT_ID' ),
			'redirect_uri' => self::callback_url(),
			'response_type' => 'code',
			'scope' => self::SCOPE . ' ' . self::GTM_SCOPE,
			'access_type' => 'offline',
			'prompt' => 'consent',
			'state' => $state,
			'code_challenge' => rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ),
			'code_challenge_method' => 'S256',
		], 'https://accounts.google.com/o/oauth2/v2/auth' );
		wp_redirect( $url );
		exit;
	}

	public static function callback(): void {
		self::require_admin();
		$key = 'stuh_google_state_' . get_current_user_id();
		$pending = get_transient( $key );
		delete_transient( $key );
		$state = self::input( $_GET, 'state' );
		if ( ! is_array( $pending ) || '' === $state || ! hash_equals( $pending['hash'], hash( 'sha256', $state ) ) ) {
			wp_die( esc_html__( 'Invalid or expired Google authorization state. Start Connect Google again.', 'stuh' ), '', [ 'response' => 403 ] );
		}
		if ( '' !== self::input( $_GET, 'error' ) || '' === self::input( $_GET, 'code' ) ) {
			self::finish( __( 'Google authorization was declined or did not return a code. Try connecting again.', 'stuh' ), true );
		}
		$error = self::configuration_error();
		if ( $error ) {
			self::finish( $error->get_error_message(), true );
		}
		$data = self::request( 'https://oauth2.googleapis.com/token', [
			'method' => 'POST',
			'body' => [
				'client_id' => self::config( 'ANALYTICS_CLIENT_ID' ),
				'client_secret' => self::config( 'ANALYTICS_CLIENT_SECRET' ),
				'code' => self::input( $_GET, 'code' ),
				'code_verifier' => $pending['verifier'],
				'redirect_uri' => self::callback_url(),
				'grant_type' => 'authorization_code',
			],
		] );
		if ( is_wp_error( $data ) ) {
			self::finish( $data->get_error_message(), true );
		}
		$scopes = explode( ' ', is_string( $data['scope'] ?? null ) ? $data['scope'] : '' );
		if ( ! in_array( self::SCOPE, $scopes, true ) || empty( $data['refresh_token'] ) || ! is_string( $data['refresh_token'] ) || empty( $data['access_token'] ) || ! is_string( $data['access_token'] ) || ! is_numeric( $data['expires_in'] ?? null ) || $data['expires_in'] <= 0 ) {
			self::finish( __( 'Google did not grant offline, read-only Analytics access. Reconnect and approve Analytics access.', 'stuh' ), true );
		}
		$saved = self::save_connection( [
			'id' => bin2hex( random_bytes( 16 ) ),
			'client_id' => self::config( 'ANALYTICS_CLIENT_ID' ),
			'access_token' => $data['access_token'],
			'refresh_token' => $data['refresh_token'],
			'expires_at' => time() + (int) $data['expires_in'],
			'scopes' => $scopes,
		] );
		if ( ! is_wp_error( $saved ) ) {
			foreach ( STUH_Plugin::get_clients() as $client ) {
				self::queue_discovery( $client );
			}
		}
		self::finish( is_wp_error( $saved ) ? $saved->get_error_message() : __( 'Google connected. Load properties next. Existing site mappings must be confirmed again after reconnecting.', 'stuh' ), is_wp_error( $saved ) );
	}

	private static function properties_key( string $connection_id ): string {
		return 'stuh_google_properties_' . $connection_id;
	}

	private static function load_properties() {
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}
		$properties = [];
		$page = '';
		$seen = [];
		do {
			$data = self::api( 'accountSummaries?' . http_build_query( [ 'pageSize' => 200, 'pageToken' => $page ] ) );
			if ( is_wp_error( $data ) ) {
				return $data;
			}
			if ( isset( $data['accountSummaries'] ) && ! is_array( $data['accountSummaries'] ) ) {
				return new WP_Error( 'google_properties', __( 'Google returned an invalid property list.', 'stuh' ) );
			}
			foreach ( $data['accountSummaries'] ?? [] as $account ) {
				if ( ! is_array( $account ) || ( isset( $account['propertySummaries'] ) && ! is_array( $account['propertySummaries'] ) ) ) {
					return new WP_Error( 'google_properties', __( 'Google returned an invalid account entry.', 'stuh' ) );
				}
				foreach ( $account['propertySummaries'] ?? [] as $property ) {
					if ( ! is_array( $property ) || ! is_string( $property['property'] ?? null ) || ! preg_match( '#^properties/([0-9]+)$#D', $property['property'], $match ) || ! is_string( $property['displayName'] ?? null ) ) {
						return new WP_Error( 'google_properties', __( 'Google returned an invalid property entry.', 'stuh' ) );
					}
					$properties[ $match[1] ] = $property['displayName'];
				}
			}
			$page = $data['nextPageToken'] ?? '';
			if ( ! is_string( $page ) || ( '' !== $page && isset( $seen[ $page ] ) ) ) {
				return new WP_Error( 'google_pagination', __( 'Google returned invalid property pagination.', 'stuh' ) );
			}
			$seen[ $page ] = true;
		} while ( '' !== $page );
		natcasesort( $properties );
		$key = self::properties_key( $connection['id'] );
		if ( ! set_transient( $key, $properties, HOUR_IN_SECONDS ) && get_transient( $key ) !== $properties ) {
			return new WP_Error( 'google_storage', __( 'Could not cache the property list. Retry.', 'stuh' ) );
		}
		return $properties;
	}

	private static function mappings(): array {
		$mappings = get_option( self::MAPPINGS, [] );
		return is_array( $mappings ) ? $mappings : [];
	}

	private static function property_mapping( array $connection, string $property, string $hostname ) {
		$details = self::api( 'properties/' . $property );
		if ( is_wp_error( $details ) ) {
			return $details;
		}
		if ( ( $details['name'] ?? '' ) !== 'properties/' . $property || ! is_string( $details['timeZone'] ?? null ) || ! in_array( $details['timeZone'], timezone_identifiers_list( DateTimeZone::ALL_WITH_BC ), true ) || ! is_string( $details['displayName'] ?? null ) ) {
			return new WP_Error( 'google_property', __( 'Google returned invalid property details or timezone.', 'stuh' ) );
		}
		return [ 'connection_id' => $connection['id'], 'property_id' => $property, 'name' => $details['displayName'], 'hostname' => $hostname, 'timezone' => $details['timeZone'] ];
	}

	private static function container_ids( array $data ) {
		$ids = $data['gtm_container_ids'] ?? [];
		if ( ! is_array( $ids ) || ! array_is_list( $ids ) ) {
			return new WP_Error( 'google_gtm_diagnostics', __( 'Invalid GTM diagnostics: gtm_container_ids must be an array of container ID strings, or null.', 'stuh' ) );
		}
		foreach ( $ids as $id ) {
			if ( ! is_string( $id ) || ! preg_match( '/^GTM-[A-Z0-9]+$/D', $id ) ) {
				return new WP_Error( 'google_gtm_diagnostics', __( 'Invalid GTM container ID in client diagnostics.', 'stuh' ) );
			}
		}
		$ids = array_values( array_unique( $ids ) );
		sort( $ids );
		return $ids;
	}

	private static function parameter( array $entity, string $key ): ?string {
		foreach ( is_array( $entity['parameter'] ?? null ) ? $entity['parameter'] : [] as $parameter ) {
			if ( is_array( $parameter ) && ( $parameter['key'] ?? '' ) === $key && is_string( $parameter['value'] ?? null ) ) {
				return $parameter['value'];
			}
		}
		return null;
	}

	private static function published_measurements( array $version ) {
		if ( ! is_array( $version['tag'] ?? [] ) || ! is_array( $version['variable'] ?? [] ) ) {
			return new WP_Error( 'google_gtm_response', __( 'Google returned invalid published GTM configuration.', 'stuh' ) );
		}
		$constants = [];
		foreach ( $version['variable'] ?? [] as $variable ) {
			if ( is_array( $variable ) && ( $variable['type'] ?? '' ) === 'c' && is_string( $variable['name'] ?? null ) ) {
				$constants[ $variable['name'] ] = self::parameter( $variable, 'value' );
			}
		}
		$ids = [];
		foreach ( $version['tag'] ?? [] as $tag ) {
			if ( ! is_array( $tag ) ) {
				return new WP_Error( 'google_gtm_response', __( 'Google returned an invalid GTM tag.', 'stuh' ) );
			}
			if ( ! empty( $tag['paused'] ) ) {
				continue;
			}
			$type = $tag['type'] ?? '';
			if ( ! in_array( $type, [ 'googtag', 'gaawc', 'gaawe' ], true ) ) {
				continue;
			}
			$value = self::parameter( $tag, 'googtag' === $type ? 'tagId' : 'measurementId' );
			$override = 'gaawe' === $type ? self::parameter( $tag, 'measurementIdOverride' ) : null;
			if ( null !== $override && '' !== $override ) {
				$value = $override;
			}
			if ( 'gaawe' === $type && ( null === $value || '' === $value ) ) {
				continue;
			}
			if ( is_string( $value ) && preg_match( '/^\{\{([^{}]+)\}\}$/D', $value, $match ) ) {
				$value = $constants[ $match[1] ] ?? null;
			}
			if ( ! is_string( $value ) || ! preg_match( '/^G-[A-Z0-9]+$/D', $value ) ) {
				return new WP_Error( 'google_gtm_dynamic', __( 'Published GTM Analytics tags use an unresolved variable, Google tag alias, or unsupported destination. Select the property manually; discovery will not guess.', 'stuh' ) );
			}
			$ids[] = $value;
		}
		if ( ! $ids ) {
			return new WP_Error( 'google_gtm_empty', __( 'No supported GA4 destination was found in the published GTM container. Custom HTML, custom templates, and server-side routing require manual mapping.', 'stuh' ) );
		}
		return array_values( array_unique( $ids ) );
	}

	private static function container_measurements( string $container_id, string $connection_id ) {
		$key = 'stuh_google_gtm_' . hash( 'sha256', $connection_id . $container_id );
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$container = self::api( 'accounts/containers:lookup?' . http_build_query( [ 'tagId' => $container_id ] ), null, 'gtm' );
		if ( is_wp_error( $container ) ) {
			return $container;
		}
		if ( ( $container['publicId'] ?? '' ) !== $container_id || ! is_string( $container['path'] ?? null ) || ! preg_match( '#^accounts/[0-9]+/containers/[0-9]+$#D', $container['path'] ) ) {
			return new WP_Error( 'google_gtm_response', __( 'Google returned an invalid GTM container.', 'stuh' ) );
		}
		$version = self::api( $container['path'] . '/versions:live', null, 'gtm' );
		$ids = is_wp_error( $version ) ? $version : self::published_measurements( $version );
		if ( ! is_wp_error( $ids ) ) {
			if ( ! set_transient( $key, $ids, HOUR_IN_SECONDS ) && get_transient( $key ) !== $ids ) {
				return new WP_Error( 'google_storage', __( 'Could not cache the GTM destination lookup. Retry.', 'stuh' ) );
			}
		}
		return $ids;
	}

	private static function stream_index( array $connection ) {
		$key = 'stuh_google_streams_' . $connection['id'];
		$cached = get_transient( $key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$properties = get_transient( self::properties_key( $connection['id'] ) );
		if ( ! is_array( $properties ) ) {
			$properties = self::load_properties();
		}
		if ( is_wp_error( $properties ) ) {
			return $properties;
		}
		$index = [];
		foreach ( $properties as $property => $name ) {
			$page = '';
			$seen = [];
			do {
				$data = self::api( 'properties/' . $property . '/dataStreams?' . http_build_query( [ 'pageSize' => 200, 'pageToken' => $page ] ) );
				if ( is_wp_error( $data ) ) {
					return $data;
				}
				if ( ! is_array( $data['dataStreams'] ?? [] ) ) {
					return new WP_Error( 'google_streams', __( 'Google returned an invalid data stream list.', 'stuh' ) );
				}
				foreach ( $data['dataStreams'] ?? [] as $stream ) {
					if ( ! is_array( $stream ) || ! is_string( $stream['type'] ?? null ) ) {
						return new WP_Error( 'google_streams', __( 'Google returned an invalid data stream.', 'stuh' ) );
					}
					if ( 'WEB_DATA_STREAM' !== $stream['type'] ) {
						continue;
					}
					$web = $stream['webStreamData'] ?? null;
					if ( ! is_array( $web ) || ! is_string( $web['measurementId'] ?? null ) || ! preg_match( '/^G-[A-Z0-9]+$/D', $web['measurementId'] ) || ! is_string( $web['defaultUri'] ?? null ) ) {
						return new WP_Error( 'google_streams', __( 'Google returned invalid web stream details.', 'stuh' ) );
					}
					$hostname = wp_parse_url( $web['defaultUri'], PHP_URL_HOST );
					$index[ $web['measurementId'] ][] = [ 'property_id' => (string) $property, 'hostname' => is_string( $hostname ) ? strtolower( $hostname ) : '' ];
				}
				$page = $data['nextPageToken'] ?? '';
				if ( ! is_string( $page ) || ( '' !== $page && isset( $seen[ $page ] ) ) ) {
					return new WP_Error( 'google_streams', __( 'Google returned invalid data stream pagination.', 'stuh' ) );
				}
				$seen[ $page ] = true;
			} while ( '' !== $page );
		}
		if ( ! set_transient( $key, $index, HOUR_IN_SECONDS ) && get_transient( $key ) !== $index ) {
			return new WP_Error( 'google_storage', __( 'Could not cache the GA4 stream index. Retry.', 'stuh' ) );
		}
		return $index;
	}

	private static function resolve_mapping( array $connection, array $ids, string $hostname ) {
		$measurements = [];
		foreach ( $ids as $id ) {
			$result = self::container_measurements( $id, $connection['id'] );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			$measurements = array_merge( $measurements, $result );
		}
		$index = self::stream_index( $connection );
		if ( is_wp_error( $index ) ) {
			return $index;
		}
		$properties = [];
		foreach ( array_unique( $measurements ) as $measurement ) {
			$matches = array_filter( $index[ $measurement ] ?? [], static fn( array $stream ): bool => $stream['hostname'] === $hostname );
			if ( 1 !== count( $matches ) ) {
				return new WP_Error( 'google_gtm_match', __( 'A GTM destination has no unique accessible GA4 web stream matching this site hostname. Check Google access and stream URLs, or select the property manually.', 'stuh' ) );
			}
			$properties[] = reset( $matches )['property_id'];
		}
		$properties = array_values( array_unique( $properties ) );
		if ( 1 !== count( $properties ) ) {
			return new WP_Error( 'google_gtm_ambiguous', __( 'Published GTM tags resolve to multiple GA4 properties. Select the intended property manually.', 'stuh' ) );
		}
		$mapping = self::property_mapping( $connection, $properties[0], $hostname );
		if ( ! is_wp_error( $mapping ) ) {
			$mapping['source'] = 'gtm';
			$mapping['gtm_container_ids'] = $ids;
		}
		return $mapping;
	}

	private static function discovery_key( string $client_id ): string {
		return 'stuh_google_discovery_' . hash( 'sha256', $client_id );
	}

	private static function discovery_context( array $client, array $connection ) {
		$report = STUH_Plugin::get_telemetry()[ $client['id'] ] ?? [];
		$data = is_array( $report['data'] ?? null ) ? $report['data'] : [];
		$ids = self::container_ids( $data );
		if ( is_wp_error( $ids ) ) {
			return $ids;
		}
		$hostname = wp_parse_url( $client['site_url'] ?? '', PHP_URL_HOST );
		if ( ! is_string( $hostname ) || ! filter_var( $hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
			return new WP_Error( 'google_gtm_hostname', __( 'The registered client URL has no valid hostname for automatic mapping.', 'stuh' ) );
		}
		return [ 'ids' => $ids, 'hostname' => strtolower( $hostname ), 'connection_id' => $connection['id'] ];
	}

	private static function discovery_status( string $client_id, array $status ): void {
		$key = self::discovery_key( $client_id );
		if ( ! update_option( $key, $status, false ) && get_option( $key ) !== $status ) {
			error_log( '[STUH Analytics] Could not store GTM discovery status for client ' . $client_id );
		}
	}

	public static function queue_discovery( array $client, bool $force = false ) {
		$client_id = (string) $client['id'];
		if ( isset( self::mappings()[ $client_id ] ) || '' === get_option( self::CONNECTION, '' ) ) {
			return false;
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}
		$context = self::discovery_context( $client, $connection );
		if ( is_wp_error( $context ) ) {
			self::discovery_status( $client_id, [ 'message' => $context->get_error_message(), 'error' => true ] );
			return $context;
		}
		$status = get_option( self::discovery_key( $client_id ), [] );
		$fingerprint = self::fingerprint( $context );
		if ( ! empty( $status['disabled'] ) || ( ! $force && ( $status['fingerprint'] ?? '' ) === $fingerprint && ( $status['checked_at'] ?? 0 ) > time() - HOUR_IN_SECONDS ) ) {
			return false;
		}
		$status = [ 'fingerprint' => $fingerprint, 'checked_at' => time(), 'error' => false ];
		if ( ! $context['ids'] ) {
			$status['message'] = __( 'No GTM container IDs were reported by this client. Automatic mapping needs a detected container; manual mapping is still available.', 'stuh' );
			self::discovery_status( $client_id, $status );
			return false;
		}
		if ( ! in_array( self::GTM_SCOPE, $connection['scopes'] ?? [], true ) ) {
			$error = new WP_Error( 'google_gtm_scope', __( 'Enable the Google Tag Manager API, add tagmanager.readonly in Google Auth Platform, and reconnect Google to allow automatic mapping.', 'stuh' ) );
			self::discovery_status( $client_id, array_merge( $status, [ 'message' => $error->get_error_message(), 'error' => true ] ) );
			return $error;
		}
		if ( wp_next_scheduled( 'stuh_google_discover', [ $client_id ] ) ) {
			return true;
		}
		$result = wp_schedule_single_event( time(), 'stuh_google_discover', [ $client_id ], true );
		$error = is_wp_error( $result ) ? $result : ( $result ? null : new WP_Error( 'google_gtm_schedule', __( 'Could not schedule GTM discovery. Check WP-Cron.', 'stuh' ) ) );
		self::discovery_status( $client_id, array_merge( $status, [
			'message' => $error ? $error->get_error_message() : __( 'Automatic GTM mapping queued. Reload after WP-Cron runs.', 'stuh' ),
			'error' => null !== $error,
		] ) );
		return $error ?? true;
	}

	public static function discover_client( string $client_id ): void {
		$clients = array_values( array_filter( STUH_Plugin::get_clients(), static fn( array $client ): bool => $client['id'] === $client_id ) );
		if ( ! $clients || isset( self::mappings()[ $client_id ] ) ) {
			return;
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			self::discovery_status( $client_id, [ 'message' => $connection->get_error_message(), 'error' => true ] );
			return;
		}
		$context = self::discovery_context( $clients[0], $connection );
		$status = get_option( self::discovery_key( $client_id ), [] );
		if ( ! empty( $status['disabled'] ) ) {
			return;
		}
		if ( is_wp_error( $context ) || ! $context['ids'] || ! in_array( self::GTM_SCOPE, $connection['scopes'] ?? [], true ) ) {
			self::queue_discovery( $clients[0], true );
			return;
		}
		$result = self::resolve_mapping( $connection, $context['ids'], $context['hostname'] );
		$current = self::connection();
		$current_clients = array_values( array_filter( STUH_Plugin::get_clients(), static fn( array $client ): bool => $client['id'] === $client_id ) );
		// Network calls must not overwrite manual choices or map an obsolete diagnostics snapshot.
		if ( is_wp_error( $current ) || $current['id'] !== $connection['id'] || ! $current_clients || self::discovery_context( $current_clients[0], $current ) !== $context || ! empty( get_option( self::discovery_key( $client_id ), [] )['disabled'] ) ) {
			return;
		}
		$mappings = self::mappings();
		if ( isset( $mappings[ $client_id ] ) ) {
			return;
		}
		if ( ! is_wp_error( $result ) ) {
			$mappings[ $client_id ] = $result;
			if ( ! update_option( self::MAPPINGS, $mappings, false ) ) {
				$result = new WP_Error( 'google_storage', __( 'Could not save the automatically discovered mapping.', 'stuh' ) );
			} else {
				$scheduled = self::schedule( $client_id );
				if ( is_wp_error( $scheduled ) ) {
					$result = $scheduled;
				}
			}
		}
		self::discovery_status( $client_id, [
			'fingerprint' => self::fingerprint( $context ),
			'checked_at' => time(),
			'error' => is_wp_error( $result ),
			'message' => is_wp_error( $result ) ? $result->get_error_message() : __( 'Automatically mapped from published GTM tags and a matching GA4 web stream. Analytics refresh queued.', 'stuh' ),
		] );
	}

	private static function report_key( string $client_id ): string {
		return 'stuh_google_report_' . hash( 'sha256', $client_id );
	}

	private static function fingerprint( array $mapping ): string {
		return hash( 'sha256', wp_json_encode( $mapping ) );
	}

	private static function schedule( string $client_id ) {
		if ( wp_next_scheduled( 'stuh_google_refresh_report', [ $client_id ] ) ) {
			return true;
		}
		$result = wp_schedule_single_event( time(), 'stuh_google_refresh_report', [ $client_id ], true );
		return is_wp_error( $result ) ? $result : ( $result ? true : new WP_Error( 'google_schedule', __( 'Could not schedule the Analytics refresh. Check WP-Cron.', 'stuh' ) ) );
	}

	public static function forget_client( string $client_id ) {
		$mappings = self::mappings();
		$key = self::report_key( $client_id );
		$discovery_key = self::discovery_key( $client_id );
		if ( ! isset( $mappings[ $client_id ] ) && false === get_option( $key, false ) && false === get_option( $discovery_key, false ) ) {
			return true;
		}
		unset( $mappings[ $client_id ] );
		if ( $mappings !== self::mappings() && ! update_option( self::MAPPINGS, $mappings, false ) ) {
			return new WP_Error( 'google_storage', __( 'Could not remove the Analytics mapping. Retry.', 'stuh' ) );
		}
		if ( false !== get_option( $key, false ) && ! delete_option( $key ) ) {
			return new WP_Error( 'google_storage', __( 'Could not remove the cached Analytics report. Retry.', 'stuh' ) );
		}
		if ( false !== get_option( $discovery_key, false ) && ! delete_option( $discovery_key ) ) {
			return new WP_Error( 'google_storage', __( 'Could not remove the GTM discovery status. Retry.', 'stuh' ) );
		}
		$result = wp_clear_scheduled_hook( 'stuh_google_discover', [ $client_id ], true );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		$result = wp_clear_scheduled_hook( 'stuh_google_refresh_report', [ $client_id ], true );
		return is_wp_error( $result ) ? $result : true;
	}

	public static function handle_action(): void {
		$action = self::input( $_POST, 'operation' );
		if ( 'refresh' === $action ) {
			self::require_viewer();
		} else {
			self::require_admin();
		}
		check_admin_referer( 'stuh_google' );
		if ( 'connect' === $action ) {
			self::start();
		}
		if ( 'disconnect' === $action ) {
			$connection = self::connection();
			$revoked = null;
			if ( ! is_wp_error( $connection ) ) {
				$revoked = wp_remote_post( 'https://oauth2.googleapis.com/revoke', [ 'timeout' => 15, 'redirection' => 0, 'body' => [ 'token' => $connection['refresh_token'] ] ] );
				delete_transient( self::properties_key( $connection['id'] ) );
				delete_transient( 'stuh_google_streams_' . $connection['id'] );
			}
			if ( ! delete_option( self::CONNECTION ) && '' !== get_option( self::CONNECTION, '' ) ) {
				self::finish( __( 'Could not remove local Google credentials. Check database access and retry disconnecting.', 'stuh' ), true );
			}
			delete_transient( 'stuh_google_state_' . get_current_user_id() );
			$cleanup_failed = false;
			$client_ids = array_unique( array_merge( array_keys( self::mappings() ), array_column( STUH_Plugin::get_clients(), 'id' ) ) );
			foreach ( $client_ids as $client_id ) {
				$cleanup_failed = is_wp_error( self::forget_client( (string) $client_id ) ) || $cleanup_failed;
			}
			if ( $cleanup_failed ) {
				self::finish( __( 'Google credentials removed, but some local Analytics mappings, reports, or scheduled tasks could not be removed. Check database and WP-Cron access, then remove the remaining mappings.', 'stuh' ), true );
			}
			delete_option( self::MAPPINGS );
			$failed = is_wp_error( $connection ) || is_wp_error( $revoked ) || 200 !== wp_remote_retrieve_response_code( $revoked );
			self::finish( $failed ? __( 'Local Google credentials, mappings, and reports removed. Google revocation could not be confirmed; remove the app from your Google account permissions too.', 'stuh' ) : __( 'Google disconnected and cached reports removed.', 'stuh' ), $failed );
		}
		if ( 'properties' === $action ) {
			$connection = self::connection();
			if ( ! is_wp_error( $connection ) ) {
				delete_transient( 'stuh_google_streams_' . $connection['id'] );
			}
			$result = self::load_properties();
			self::finish( is_wp_error( $result ) ? $result->get_error_message() : sprintf( __( 'Loaded %d accessible GA4 properties.', 'stuh' ), count( $result ) ), is_wp_error( $result ) );
		}
		if ( 'discover_all' === $action ) {
			$queued = 0;
			$failed = 0;
			foreach ( STUH_Plugin::get_clients() as $client ) {
				$result = self::queue_discovery( $client, true );
				$queued += true === $result ? 1 : 0;
				$failed += is_wp_error( $result ) ? 1 : 0;
			}
			self::finish( sprintf( __( 'Queued %1$d GTM discovery checks; %2$d could not be queued. Existing and paused mappings are preserved. See client details for status.', 'stuh' ), $queued, $failed ), $failed > 0 );
		}
		$client_id = self::input( $_POST, 'client_id' );
		$clients = array_filter( STUH_Plugin::get_clients(), static fn( array $client ): bool => $client['id'] === $client_id );
		if ( ! $clients ) {
			self::finish( __( 'The selected client site could not be found.', 'stuh' ), true );
		}
		$mappings = self::mappings();
		if ( 'unmap' === $action ) {
			$result = self::forget_client( $client_id );
			if ( ! is_wp_error( $result ) ) {
				self::discovery_status( $client_id, [ 'disabled' => true, 'message' => __( 'Automatic mapping paused after removing the mapping. Use Retry automatic mapping to enable it again.', 'stuh' ), 'error' => false ] );
			}
			self::finish( is_wp_error( $result ) ? $result->get_error_message() : __( 'Analytics mapping and report removed.', 'stuh' ), is_wp_error( $result ), $client_id );
		}
		if ( 'discover' === $action ) {
			if ( false !== get_option( self::discovery_key( $client_id ), false ) && ! delete_option( self::discovery_key( $client_id ) ) ) {
				self::finish( __( 'Could not reset GTM discovery. Retry.', 'stuh' ), true, $client_id );
			}
			$result = self::queue_discovery( reset( $clients ), true );
			self::finish( is_wp_error( $result ) ? $result->get_error_message() : __( 'GTM discovery requested. See the automatic mapping status below.', 'stuh' ), is_wp_error( $result ), $client_id );
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			self::finish( $connection->get_error_message(), true, $client_id );
		}
		if ( 'map' === $action ) {
			$property = self::input( $_POST, 'property_id' );
			$hostname = strtolower( self::input( $_POST, 'hostname' ) );
			if ( ! preg_match( '/^[0-9]+$/D', $property ) || ! filter_var( $hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
				self::finish( __( 'Select a GA4 property and enter a valid hostname without a scheme, port, or path.', 'stuh' ), true, $client_id );
			}
			$mapping = self::property_mapping( $connection, $property, $hostname );
			if ( is_wp_error( $mapping ) ) {
				self::finish( $mapping->get_error_message(), true, $client_id );
			}
			$mappings[ $client_id ] = $mapping;
			if ( $mappings !== self::mappings() && ! update_option( self::MAPPINGS, $mappings, false ) ) {
				self::finish( __( 'Could not save the Analytics mapping.', 'stuh' ), true, $client_id );
			}
			$key = self::report_key( $client_id );
			if ( false !== get_option( $key, false ) && ! delete_option( $key ) ) {
				self::finish( __( 'Mapping saved, but the old cached report could not be removed. Retry saving the mapping.', 'stuh' ), true, $client_id );
			}
		} elseif ( 'refresh' !== $action || ! isset( $mappings[ $client_id ] ) || $mappings[ $client_id ]['connection_id'] !== $connection['id'] ) {
			self::finish( __( 'Invalid Analytics action or mapping. Confirm the property mapping first.', 'stuh' ), true, $client_id );
		}
		$result = self::schedule( $client_id );
		self::finish( is_wp_error( $result ) ? $result->get_error_message() : __( 'Analytics refresh queued. Reload after WP-Cron runs.', 'stuh' ), is_wp_error( $result ), $client_id );
	}

	private static function report_rows( array $report, array $metrics, array $dimensions = [] ) {
		if ( ! is_array( $report['metricHeaders'] ?? null ) || ! is_array( $report['dimensionHeaders'] ?? [] ) || array_column( $report['metricHeaders'], 'name' ) !== $metrics || array_column( $report['dimensionHeaders'] ?? [], 'name' ) !== $dimensions ) {
			return new WP_Error( 'google_report_shape', __( 'Google returned unexpected report columns.', 'stuh' ) );
		}
		$rows = $report['rows'] ?? [];
		if ( ! is_array( $rows ) || (int) ( $report['rowCount'] ?? 0 ) < count( $rows ) || ( ! $rows && ! empty( $report['rowCount'] ) ) ) {
			return new WP_Error( 'google_report_shape', __( 'Google returned invalid report rows.', 'stuh' ) );
		}
		$result = [];
		foreach ( $rows as $row ) {
			if ( ! is_array( $row ) || ! is_array( $row['metricValues'] ?? null ) || ! is_array( $row['dimensionValues'] ?? [] ) ) {
				return new WP_Error( 'google_report_shape', __( 'Google returned invalid report values.', 'stuh' ) );
			}
			$values = array_column( $row['metricValues'] ?? [], 'value' );
			$labels = array_column( $row['dimensionValues'] ?? [], 'value' );
			if ( count( $values ) !== count( $metrics ) || count( $labels ) !== count( $dimensions ) || count( array_filter( $values, 'is_numeric' ) ) !== count( $values ) || count( array_filter( $labels, 'is_string' ) ) !== count( $labels ) ) {
				return new WP_Error( 'google_report_shape', __( 'Google returned invalid report values.', 'stuh' ) );
			}
			$result[] = [ 'dimensions' => $labels, 'metrics' => array_combine( $metrics, array_map( 'floatval', $values ) ) ];
		}
		return $result;
	}

	private static function history_ranges( DateTimeImmutable $today ): array {
		$start = $today->modify( 'first day of this month' );
		$ranges = [ [ 'startDate' => $start->modify( '-24 months' )->format( 'Y-m-d' ), 'endDate' => $start->modify( '-1 day' )->format( 'Y-m-d' ), 'name' => 'complete' ] ];
		$days = (int) $today->format( 'j' ) - 1;
		if ( $days > 0 ) {
			$prior = $start->modify( '-12 months' );
			$ranges[] = [ 'startDate' => $start->format( 'Y-m-d' ), 'endDate' => $today->modify( '-1 day' )->format( 'Y-m-d' ), 'name' => 'current_mtd' ];
			$ranges[] = [ 'startDate' => $prior->format( 'Y-m-d' ), 'endDate' => $prior->modify( '+' . ( min( $days, (int) $prior->format( 't' ) ) - 1 ) . ' days' )->format( 'Y-m-d' ), 'name' => 'previous_mtd' ];
		}
		return $ranges;
	}

	private static function monthly_history( DateTimeImmutable $today, array $rows ) {
		$month_start = $today->modify( 'first day of this month' );
		$ranges = self::history_ranges( $today );
		$months = [];
		$allowed = [];
		for ( $offset = 12; $offset >= 1; $offset-- ) {
			$current = $month_start->modify( '-' . $offset . ' months' );
			$previous = $month_start->modify( '-' . ( $offset + 12 ) . ' months' );
			$months[] = [ 'month' => $current->format( 'Y-m' ), 'previous_month' => $previous->format( 'Y-m' ), 'current' => null, 'previous' => null ];
			$allowed[ $current->format( 'Ym' ) ] = true;
			$allowed[ $previous->format( 'Ym' ) ] = true;
		}
		$values = [];
		$partial = [ 'current_mtd' => null, 'previous_mtd' => null ];
		foreach ( $rows as $row ) {
			$month = $row['dimensions'][0];
			$value = $row['metrics']['activeUsers'];
			$range = $row['dimensions'][1] ?? 'complete';
			if ( ! is_finite( $value ) || $value < 0 ) {
				return new WP_Error( 'google_history', __( 'Google returned invalid or duplicate monthly active-user data.', 'stuh' ) );
			}
			if ( 'complete' !== $range ) {
				$expected = 'current_mtd' === $range ? $month_start : $month_start->modify( '-12 months' );
				if ( 3 !== count( $ranges ) || ! array_key_exists( $range, $partial ) || null !== $partial[ $range ] || $month !== $expected->format( 'Ym' ) ) {
					return new WP_Error( 'google_history', __( 'Google returned invalid month-to-date data.', 'stuh' ) );
				}
				$partial[ $range ] = $value;
				continue;
			}
			if ( ! isset( $allowed[ $month ] ) || array_key_exists( $month, $values ) ) {
				return new WP_Error( 'google_history', __( 'Google returned invalid or duplicate monthly active-user data.', 'stuh' ) );
			}
			$values[ $month ] = $value;
		}
		foreach ( $months as &$month ) {
			$month['current'] = $values[ str_replace( '-', '', $month['month'] ) ] ?? null;
			$month['previous'] = $values[ str_replace( '-', '', $month['previous_month'] ) ] ?? null;
		}
		unset( $month );
		$months[] = [
			'month' => $month_start->format( 'Y-m' ),
			'previous_month' => $month_start->modify( '-12 months' )->format( 'Y-m' ),
			'current' => $partial['current_mtd'],
			'previous' => $partial['previous_mtd'],
			'in_progress' => true,
			'current_end' => $ranges[1]['endDate'] ?? null,
			'previous_end' => $ranges[2]['endDate'] ?? null,
		];
		return [
			'period' => [ 'startDate' => $month_start->modify( '-12 months' )->format( 'Y-m-d' ), 'endDate' => $month_start->modify( '-1 day' )->format( 'Y-m-d' ) ],
			'previous_period' => [ 'startDate' => $month_start->modify( '-24 months' )->format( 'Y-m-d' ), 'endDate' => $month_start->modify( '-12 months -1 day' )->format( 'Y-m-d' ) ],
			'months' => $months,
			'includes_current' => true,
		];
	}

	private static function fetch_report( array $mapping ) {
		$today = new DateTimeImmutable( 'today', new DateTimeZone( $mapping['timezone'] ) );
		$current = [ 'startDate' => $today->modify( '-28 days' )->format( 'Y-m-d' ), 'endDate' => $today->modify( '-1 day' )->format( 'Y-m-d' ) ];
		$previous = [ 'startDate' => $today->modify( '-56 days' )->format( 'Y-m-d' ), 'endDate' => $today->modify( '-29 days' )->format( 'Y-m-d' ) ];
		$base = [
			'dateRanges' => [ $current ],
			'dimensionFilter' => [ 'filter' => [ 'fieldName' => 'hostName', 'stringFilter' => [ 'matchType' => 'EXACT', 'value' => $mapping['hostname'], 'caseSensitive' => false ] ] ],
		];
		$totals = array_merge( $base, [ 'metrics' => array_map( static fn( string $name ): array => [ 'name' => $name ], self::METRICS ) ] );
		$pages = array_merge( $base, [ 'dimensions' => [ [ 'name' => 'pagePath' ] ], 'metrics' => [ [ 'name' => 'screenPageViews' ] ], 'orderBys' => [ [ 'metric' => [ 'metricName' => 'screenPageViews' ], 'desc' => true ] ], 'limit' => 10 ] );
		$channels = array_merge( $base, [ 'dimensions' => [ [ 'name' => 'sessionDefaultChannelGroup' ] ], 'metrics' => [ [ 'name' => 'sessions' ] ], 'orderBys' => [ [ 'metric' => [ 'metricName' => 'sessions' ], 'desc' => true ] ], 'limit' => 10 ] );
		$monthly = array_merge( $base, [
			'dateRanges' => self::history_ranges( $today ),
			'dimensions' => [ [ 'name' => 'yearMonth' ] ],
			'metrics' => [ [ 'name' => 'activeUsers' ] ],
			'orderBys' => [ [ 'dimension' => [ 'dimensionName' => 'yearMonth' ] ] ],
			'limit' => 26,
			'keepEmptyRows' => true,
		] );
		$data = self::api( 'properties/' . $mapping['property_id'] . ':batchRunReports', [ 'requests' => [ $totals, array_merge( $totals, [ 'dateRanges' => [ $previous ] ] ), $pages, $channels, $monthly ] ], 'data' );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( ! isset( $data['reports'] ) || ! is_array( $data['reports'] ) || count( $data['reports'] ) !== 5 ) {
			return new WP_Error( 'google_report_shape', __( 'Google did not return all five requested reports.', 'stuh' ) );
		}
		$parsed = [];
		$limited = false;
		foreach ( $data['reports'] as $index => $report ) {
			if ( ! is_array( $report ) ) {
				return new WP_Error( 'google_report_shape', __( 'Google returned an invalid report.', 'stuh' ) );
			}
			$metrics = match ( $index ) { 0, 1 => self::METRICS, 2 => [ 'screenPageViews' ], 3 => [ 'sessions' ], 4 => [ 'activeUsers' ] };
			$dimensions = match ( $index ) { 0, 1 => [], 2 => [ 'pagePath' ], 3 => [ 'sessionDefaultChannelGroup' ], 4 => count( $monthly['dateRanges'] ) > 1 ? [ 'yearMonth', 'dateRange' ] : [ 'yearMonth' ] };
			$rows = self::report_rows( $report, $metrics, $dimensions );
			if ( is_wp_error( $rows ) ) {
				$rows->add_data( [ 'report_diagnostics' => [
					'report' => [ 'current_totals', 'previous_totals', 'pages', 'channels', 'monthly_active_users' ][ $index ],
					'expected_metrics' => $metrics,
					'expected_dimensions' => $dimensions,
					'rows_type' => get_debug_type( $report['rows'] ?? null ),
					'returned_rows' => is_array( $report['rows'] ?? null ) ? count( $report['rows'] ) : null,
					'row_count_type' => get_debug_type( $report['rowCount'] ?? null ),
					'row_count' => is_scalar( $report['rowCount'] ?? null ) && is_numeric( $report['rowCount'] ) ? (float) $report['rowCount'] : null,
				] ] );
				return $rows;
			}
			if ( $index < 2 && count( $rows ) > 1 ) {
				return new WP_Error( 'google_report_shape', __( 'Google returned multiple totals rows.', 'stuh' ) );
			}
			if ( 4 === $index && (int) ( $report['rowCount'] ?? 0 ) !== count( $rows ) ) {
				return new WP_Error( 'google_history', __( 'Google returned an incomplete monthly active-user report.', 'stuh' ) );
			}
			$parsed[] = $index < 2 ? ( $rows[0]['metrics'] ?? array_fill_keys( self::METRICS, 0.0 ) ) : $rows;
			$metadata = $report['metadata'] ?? [];
			$limited = $limited || ! empty( $metadata['subjectToThresholding'] ) || ! empty( $metadata['dataLossFromOtherRow'] ) || ! empty( $metadata['samplingMetadatas'] );
		}
		$history = self::monthly_history( $today, $parsed[4] );
		if ( is_wp_error( $history ) ) {
			return $history;
		}
		return [ 'current' => $parsed[0], 'previous' => $parsed[1], 'pages' => $parsed[2], 'channels' => $parsed[3], 'period' => $current, 'previous_period' => $previous, 'limited' => $limited, 'history' => $history ];
	}

	public static function refresh_report( string $client_id ): void {
		$mapping = self::mappings()[ $client_id ] ?? null;
		if ( ! $mapping || ! array_filter( STUH_Plugin::get_clients(), static fn( array $client ): bool => $client['id'] === $client_id ) ) {
			return;
		}
		$connection = self::connection();
		$result = is_wp_error( $connection ) ? $connection : ( $connection['id'] !== $mapping['connection_id'] ? new WP_Error( 'google_mapping', __( 'Google was reconnected. Confirm the property mapping for this site again.', 'stuh' ) ) : self::fetch_report( $mapping ) );
		if ( is_wp_error( $result ) ) {
			$context = [
				'client_id' => $client_id,
				'property_id' => $mapping['property_id'],
				'code' => $result->get_error_code(),
				'message' => $result->get_error_message(),
			];
			$details = $result->get_error_data();
			if ( is_array( $details ) && isset( $details['report_diagnostics'] ) ) {
				$context['report_diagnostics'] = $details['report_diagnostics'];
			}
			error_log( '[STUH Analytics] Report refresh failed: ' . wp_json_encode( $context ) );
		}
		// Do not publish a result if an administrator changed the mapping during the request.
		if ( ( self::mappings()[ $client_id ] ?? null ) !== $mapping ) {
			return;
		}
		$key = self::report_key( $client_id );
		$cached = get_option( $key, [] );
		$record = is_array( $cached ) && ( $cached['fingerprint'] ?? '' ) === self::fingerprint( $mapping ) ? $cached : [];
		$record['fingerprint'] = self::fingerprint( $mapping );
		$record['attempted_at'] = time();
		$record['error'] = is_wp_error( $result ) ? $result->get_error_message() : '';
		if ( ! is_wp_error( $result ) ) {
			$record['data'] = $result;
			$record['fetched_at'] = time();
		}
		if ( ! update_option( $key, $record, false ) && get_option( $key ) !== $record ) {
			error_log( '[STUH Analytics] Could not store report for client ' . $client_id );
		}
	}

	private static function form_start( string $operation, string $client_id = '' ): void {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'stuh_google' );
		echo '<input type="hidden" name="action" value="stuh_google_action"><input type="hidden" name="operation" value="' . esc_attr( $operation ) . '"><input type="hidden" name="client_id" value="' . esc_attr( $client_id ) . '">';
		if ( 'stuh-analytics' === self::input( $_GET, 'page' ) ) {
			echo '<input type="hidden" name="return_page" value="analytics">';
		}
	}

	public static function render_settings(): void {
		self::require_admin();
		echo '<section id="stuh-google-settings"><h2>' . esc_html__( 'Google Analytics', 'stuh' ) . '</h2>';
		self::notice();
		echo '<p>' . esc_html__( 'Read-only GA4 reporting. Google credentials stay on this host and are never sent to client sites.', 'stuh' ) . '</p>';
		echo '<p>' . esc_html__( 'Authorized redirect URI:', 'stuh' ) . ' <code>' . esc_html( self::callback_url() ) . '</code></p>';
		$error = self::configuration_error();
		if ( $error ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $error->get_error_message() ) . '</p></div>';
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) && 'google_disconnected' !== $connection->get_error_code() ) {
			echo '<p>' . esc_html( $connection->get_error_message() ) . '</p>';
		}
		if ( ! $error ) {
			self::form_start( 'connect' );
			submit_button( is_wp_error( $connection ) ? __( 'Connect Google', 'stuh' ) : __( 'Reconnect Google', 'stuh' ) );
			echo '</form>';
		}
		if ( '' !== get_option( self::CONNECTION, '' ) ) {
			self::form_start( 'disconnect' );
			submit_button( __( 'Disconnect Google and remove cached reports', 'stuh' ), 'secondary' );
			echo '</form>';
		}
		if ( ! is_wp_error( $connection ) ) {
			echo '<p>' . esc_html__( 'Google is connected. Reconnecting requires confirming existing site mappings again. Disconnecting removes all local Analytics mappings and reports.', 'stuh' ) . '</p>';
			if ( ! in_array( self::GTM_SCOPE, $connection['scopes'] ?? [], true ) ) {
				echo '<p role="alert">' . esc_html__( 'Automatic GTM mapping needs the Google Tag Manager API and tagmanager.readonly access. Add that scope in Google Auth Platform, then reconnect Google. Existing Analytics reporting still works.', 'stuh' ) . '</p>';
			}
			self::form_start( 'properties' );
			submit_button( __( 'Load / refresh accessible properties', 'stuh' ), 'secondary' );
			echo '</form>';
			$properties = get_transient( self::properties_key( $connection['id'] ) );
			if ( is_array( $properties ) ) {
				echo '<p>' . esc_html( sprintf( __( '%d accessible properties cached for one hour. Open the client site details to select a property.', 'stuh' ), count( $properties ) ) ) . '</p>';
			}
			self::form_start( 'discover_all' );
			submit_button( __( 'Discover unmapped client sites from GTM', 'stuh' ), 'secondary' );
			echo '</form>';
		}
		echo '<p><a href="' . esc_url( self::reports_url() ) . '">' . esc_html__( 'View Analytics reports', 'stuh' ) . '</a></p></section>';
	}

	private static function reports_url( string $client_id = '' ): string {
		$args = [ 'page' => 'stuh-analytics' ];
		if ( '' !== $client_id ) {
			$args['client_id'] = $client_id;
		}
		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}

	public static function render_reports(): void {
		self::require_viewer();
		$clients = STUH_Plugin::get_clients();
		$mappings = self::mappings();
		$connection = self::connection();
		$report_clients = array_values( array_filter( $clients, static function( array $client ) use ( $mappings, $connection ): bool {
			$id = (string) $client['id'];
			$mapping = $mappings[ $id ] ?? null;
			if ( ! $mapping || is_wp_error( $connection ) || $mapping['connection_id'] !== $connection['id'] ) {
				return false;
			}
			$record = self::column_record( $id, $mapping );
			return isset( $record['data']['current']['activeUsers'] );
		} ) );
		$site_label = static fn( array $client ): string => preg_replace( '#^https?://#i', '', (string) ( $client['site_url'] ?? $client['id'] ) );
		usort( $report_clients, static fn( array $a, array $b ): int => strcasecmp( $site_label( $a ), $site_label( $b ) ) );
		$client_id = self::input( $_GET, 'client_id' );
		if ( '' === $client_id && $report_clients ) {
			$client_id = (string) $report_clients[0]['id'];
		}
		$selected = null;
		foreach ( $clients as $client ) {
			if ( $client['id'] === $client_id ) {
				$selected = $client;
				break;
			}
		}
		if ( '' !== $client_id && null === $selected ) {
			wp_die( esc_html__( 'The selected client site could not be found.', 'stuh' ) );
		}
		echo '<div class="wrap stuh-client-sites"><h1>' . esc_html__( 'Google Analytics', 'stuh' ) . '</h1>';
		self::notice();
		if ( current_user_can( 'manage_options' ) ) {
			echo '<p><a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Google Analytics settings', 'stuh' ) . '</a></p>';
		}
		if ( is_wp_error( $connection ) ) {
			echo '<p role="alert">' . esc_html( $connection->get_error_message() ) . '</p>';
		}
		if ( ! $report_clients ) {
			self::render_demo();
			echo '</div>';
			return;
		}
		if ( $report_clients ) {
			echo '<form method="get" action="' . esc_url( admin_url( 'admin.php' ) ) . '" class="stuh-analytics-selector"><input type="hidden" name="page" value="stuh-analytics"><label for="stuh-analytics-client">' . esc_html__( 'Client site', 'stuh' ) . '</label> <select id="stuh-analytics-client" name="client_id">';
			foreach ( $report_clients as $client ) {
				$id = (string) $client['id'];
				echo '<option value="' . esc_attr( $id ) . '"' . ( $id === $client_id ? ' selected' : '' ) . '>' . esc_html( $site_label( $client ) ) . '</option>';
			}
			echo '</select> <button type="submit" class="button">' . esc_html__( 'View report', 'stuh' ) . '</button></form>';
		}
		if ( null !== $selected ) {
			echo '<section id="stuh-analytics"><h2>' . esc_html( $selected['site_url'] ?? $client_id ) . '</h2>';
			$mapping = $mappings[ $client_id ] ?? [];
			if ( ! $mapping ) {
				echo '<p>' . esc_html__( 'No Analytics property is connected to this site.', 'stuh' ) . '</p>';
			} elseif ( ! is_wp_error( $connection ) && $mapping['connection_id'] === $connection['id'] ) {
				echo '<p><strong>' . esc_html__( 'GA4 property', 'stuh' ) . ':</strong> ' . esc_html( $mapping['name'] . ' (' . $mapping['property_id'] . ')' ) . '</p>';
				self::render_report( $client_id, $mapping, true );
			} elseif ( ! is_wp_error( $connection ) ) {
				echo '<p>' . esc_html__( 'Google was reconnected. Save this site mapping again before viewing reports.', 'stuh' ) . '</p>';
			}
			if ( current_user_can( 'manage_options' ) ) {
				echo '<p><a href="' . esc_url( self::page_url( $client_id ) . '#stuh-analytics' ) . '">' . esc_html__( 'Manage this site mapping', 'stuh' ) . '</a></p>';
			}
			echo '</section>';
		}
		echo '</div>';
	}

	private static function render_demo(): void {
		$today = new DateTimeImmutable( 'today', new DateTimeZone( 'UTC' ) );
		$month_start = $today->modify( 'first day of this month' );
		$ranges = self::history_ranges( $today );
		$seasonal = [ 950, 1040, 1180, 1090, 1260, 1420, 1360, 1510, 1450, 1620, 1540, 1710 ];
		$rows = [];
		for ( $offset = 24; $offset >= 1; $offset-- ) {
			$index = 24 - $offset;
			$rows[] = [
				'dimensions' => count( $ranges ) > 1 ? [ $month_start->modify( '-' . $offset . ' months' )->format( 'Ym' ), 'complete' ] : [ $month_start->modify( '-' . $offset . ' months' )->format( 'Ym' ) ],
				'metrics' => [ 'activeUsers' => (float) round( $seasonal[ $index % 12 ] * ( $index >= 12 ? 1.24 : 1 ) ) ],
			];
		}
		if ( count( $ranges ) > 1 ) {
			foreach ( [ 'current_mtd' => 1380, 'previous_mtd' => 1120 ] as $range => $total ) {
				$date = 'current_mtd' === $range ? $month_start : $month_start->modify( '-12 months' );
				$days = min( (int) $today->format( 'j' ) - 1, (int) $date->format( 't' ) );
				$rows[] = [ 'dimensions' => [ $date->format( 'Ym' ), $range ], 'metrics' => [ 'activeUsers' => (float) round( $total * $days / (int) $date->format( 't' ) ) ] ];
			}
		}
		$history = self::monthly_history( $today, $rows );
		if ( is_wp_error( $history ) ) {
			wp_die( esc_html( $history->get_error_message() ) );
		}
		$data = [
			'current' => [ 'activeUsers' => 1840.0, 'sessions' => 2680.0, 'screenPageViews' => 7240.0, 'engagementRate' => 0.684, 'keyEvents' => 86.0 ],
			'previous' => [ 'activeUsers' => 1520.0, 'sessions' => 2310.0, 'screenPageViews' => 6180.0, 'engagementRate' => 0.621, 'keyEvents' => 67.0 ],
			'previous_period' => [ 'startDate' => $today->modify( '-56 days' )->format( 'Y-m-d' ), 'endDate' => $today->modify( '-29 days' )->format( 'Y-m-d' ) ],
			'pages' => [
				[ 'dimensions' => [ '/' ], 'metrics' => [ 'screenPageViews' => 2840.0 ] ],
				[ 'dimensions' => [ '/services/' ], 'metrics' => [ 'screenPageViews' => 1860.0 ] ],
				[ 'dimensions' => [ '/about/' ], 'metrics' => [ 'screenPageViews' => 1420.0 ] ],
				[ 'dimensions' => [ '/contact/' ], 'metrics' => [ 'screenPageViews' => 1120.0 ] ],
			],
			'channels' => [
				[ 'dimensions' => [ 'Organic Search' ], 'metrics' => [ 'sessions' => 1240.0 ] ],
				[ 'dimensions' => [ 'Direct' ], 'metrics' => [ 'sessions' => 820.0 ] ],
				[ 'dimensions' => [ 'Referral' ], 'metrics' => [ 'sessions' => 380.0 ] ],
				[ 'dimensions' => [ 'Organic Social' ], 'metrics' => [ 'sessions' => 240.0 ] ],
			],
			'history' => $history,
		];
		echo '<div class="notice notice-info inline"><p>' . esc_html__( 'Demo data - no client Analytics reports available.', 'stuh' ) . '</p></div>';
		echo '<div class="stuh-analytics-selector"><label for="stuh-analytics-client">' . esc_html__( 'Client site', 'stuh' ) . '</label> <select id="stuh-analytics-client" disabled><option selected>' . esc_html__( 'demo.example (Demo)', 'stuh' ) . '</option></select></div>';
		echo '<section id="stuh-analytics" class="stuh-analytics-demo"><h2>' . esc_html__( 'demo.example - Demo', 'stuh' ) . '</h2><p>' . esc_html( $today->modify( '-28 days' )->format( 'Y-m-d' ) . ' to ' . $today->modify( '-1 day' )->format( 'Y-m-d' ) . ' / UTC' ) . '</p>';
		self::render_charts( $data );
		echo '</section>';
	}

	private static function render_discovery( array $client, array $connection ): void {
		$client_id = (string) $client['id'];
		$context = self::discovery_context( $client, $connection );
		if ( is_wp_error( $context ) ) {
			echo '<p role="alert">' . esc_html( $context->get_error_message() ) . '</p>';
			return;
		}
		echo '<p><strong>' . esc_html__( 'Reported GTM containers:', 'stuh' ) . '</strong> ' . esc_html( $context['ids'] ? implode( ', ', $context['ids'] ) : __( 'None reported', 'stuh' ) ) . '</p>';
		$mapping = self::mappings()[ $client_id ] ?? [];
		if ( $mapping ) {
			echo '<p>' . esc_html( 'gtm' === ( $mapping['source'] ?? '' ) ? __( 'This property was mapped automatically from published GTM tags. Existing mappings are never replaced automatically.', 'stuh' ) : __( 'Existing property mapping preserved. Automatic GTM discovery does not overwrite manual selections.', 'stuh' ) ) . '</p>';
			if ( 'gtm' === ( $mapping['source'] ?? '' ) && ( $mapping['gtm_container_ids'] ?? [] ) !== $context['ids'] ) {
				echo '<p role="alert">' . esc_html__( 'Reported GTM containers changed after automatic mapping. Review this property selection; the existing mapping has been kept.', 'stuh' ) . '</p>';
			}
			return;
		}
		$result = self::queue_discovery( $client );
		$status = get_option( self::discovery_key( $client_id ), [] );
		if ( ! empty( $status['message'] ) ) {
			echo '<p' . ( ! empty( $status['error'] ) ? ' role="alert"' : '' ) . '>' . esc_html( $status['message'] ) . '</p>';
		} elseif ( is_wp_error( $result ) ) {
			echo '<p role="alert">' . esc_html( $result->get_error_message() ) . '</p>';
		}
		if ( wp_next_scheduled( 'stuh_google_discover', [ $client_id ] ) ) {
			echo '<p>' . esc_html__( 'GTM discovery is pending in WP-Cron.', 'stuh' ) . '</p>';
		}
		self::form_start( 'discover', $client_id );
		submit_button( __( 'Retry automatic mapping', 'stuh' ), 'secondary' );
		echo '</form>';
	}

	private static function column_record( string $client_id, array $mapping ): array {
		$record = get_option( self::report_key( $client_id ), [] );
		return is_array( $record ) && ( $record['fingerprint'] ?? '' ) === self::fingerprint( $mapping ) ? $record : [];
	}

	public static function monthly_active_users( string $client_id ) {
		self::require_viewer();
		$mapping = self::mappings()[ $client_id ] ?? null;
		if ( ! $mapping ) {
			return new WP_Error( 'google_mapping', __( 'No Analytics property is connected to this site.', 'stuh' ) );
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			return $connection;
		}
		if ( $mapping['connection_id'] !== $connection['id'] ) {
			return new WP_Error( 'google_mapping', __( 'Google was reconnected. Confirm the property mapping for this site again.', 'stuh' ) );
		}
		$record = self::column_record( $client_id, $mapping );
		if ( ! isset( $record['data']['history']['months'] ) ) {
			return new WP_Error( 'google_history', ! empty( $record['error'] ) ? $record['error'] : __( 'Refresh Analytics to load monthly active users for this site.', 'stuh' ) );
		}
		$months = [];
		foreach ( $record['data']['history']['months'] as $row ) {
			if ( empty( $row['in_progress'] ) ) {
				$months[ $row['previous_month'] ] = $row['previous'];
			}
		}
		foreach ( $record['data']['history']['months'] as $row ) {
			$months[ $row['month'] ] = $row['current'];
		}
		$warnings = [];
		if ( ! empty( $record['error'] ) ) {
			$warnings[] = $record['error'];
		}
		if ( ( $record['fetched_at'] ?? 0 ) < time() - 4 * HOUR_IN_SECONDS ) {
			$warnings[] = __( 'Stale Analytics report; showing the last successful data.', 'stuh' );
		}
		if ( ! empty( $record['data']['limited'] ) ) {
			$warnings[] = __( 'Google flagged thresholding, sampling, or other-row data loss in this report.', 'stuh' );
		}
		return [ 'months' => $months, 'warnings' => $warnings ];
	}

	public static function column_sort_values( array $clients ): array {
		$mappings = self::mappings();
		$connection = $mappings ? self::connection() : null;
		$values = [];
		foreach ( $clients as $client ) {
			$id = (string) $client['id'];
			$mapping = $mappings[ $id ] ?? null;
			$values[ $id ] = null;
			if ( ! $mapping || null === $connection || is_wp_error( $connection ) || $mapping['connection_id'] !== $connection['id'] ) {
				continue;
			}
			$record = self::column_record( $id, $mapping );
			$values[ $id ] = $record['data']['current']['activeUsers'] ?? null;
		}
		return $values;
	}

	public static function render_client_column( string $client_id, ?string $report_url = null ): void {
		self::require_admin();
		$mapping = self::mappings()[ $client_id ] ?? null;
		$url = $report_url ?? self::page_url( $client_id ) . '#stuh-analytics';
		if ( ! $mapping ) {
			echo '<a class="stuh-analytics-disconnected" href="' . esc_url( $url ) . '">' . esc_html__( 'Not connected', 'stuh' ) . '</a>';
			return;
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) || $connection['id'] !== $mapping['connection_id'] ) {
			$message = is_wp_error( $connection ) ? $connection->get_error_message() : __( 'Google was reconnected. Confirm this site mapping again.', 'stuh' );
			echo '<a href="' . esc_url( $url ) . '" title="' . esc_attr( $message ) . '">' . esc_html__( 'Reconnect required', 'stuh' ) . '</a>';
			return;
		}
		$record = self::column_record( $client_id, $mapping );
		$data = $record['data'] ?? null;
		$tooltip = $mapping['name'] . ' (' . $mapping['property_id'] . ') / ' . $mapping['hostname'];
		if ( ! is_array( $data ) ) {
			$error = $record['error'] ?? '';
			echo '<a href="' . esc_url( $url ) . '" title="' . esc_attr( $tooltip . ( $error ? ' / ' . $error : '' ) ) . '">' . esc_html( $error ? __( 'Connected - report failed', 'stuh' ) : __( 'Connected - report pending', 'stuh' ) ) . '</a>';
			return;
		}
		$url = $report_url ?? self::reports_url( $client_id );
		$current = $data['current']['activeUsers'];
		$previous = $data['previous']['activeUsers'];
		$tooltip .= ' / ' . sprintf( __( 'Active users: %1$s to %2$s; previous: %3$s to %4$s. Last updated: %5$s.', 'stuh' ), $data['period']['startDate'], $data['period']['endDate'], $data['previous_period']['startDate'], $data['previous_period']['endDate'], wp_date( 'Y-m-d H:i T', $record['fetched_at'] ) );
		if ( ! empty( $record['error'] ) ) {
			$tooltip .= ' / ' . $record['error'];
		}
		if ( ! empty( $data['limited'] ) ) {
			$tooltip .= ' / ' . __( 'Google flagged reporting limitations.', 'stuh' );
		}
		echo '<span title="' . esc_attr( $tooltip ) . '"><a class="stuh-analytics-users" href="' . esc_url( $url ) . '" aria-label="' . esc_attr( sprintf( __( 'Connected: %s active users in the last 28 complete days', 'stuh' ), number_format_i18n( $current ) ) ) . '">' . esc_html( number_format_i18n( $current ) ) . '</a> ';
		if ( $previous > 0 || 0.0 === (float) $current ) {
			$change = $previous > 0 ? round( ( $current - $previous ) / $previous * 100, 1 ) : 0.0;
			$direction = $change > 0 ? 'up' : ( $change < 0 ? 'down' : 'neutral' );
			$label = ( $change > 0 ? '+' : ( $change < 0 ? '-' : '' ) ) . number_format_i18n( abs( $change ), 1 ) . '%';
			echo '<span class="stuh-analytics-change stuh-analytics-change--' . esc_attr( $direction ) . '">' . esc_html( $label ) . '</span>';
		} else {
			echo '<span title="' . esc_attr__( 'Percentage change is unavailable because the previous period had zero active users.', 'stuh' ) . '">' . esc_html__( 'N/A', 'stuh' ) . '</span>';
		}
		echo '<small class="stuh-analytics-caption">' . esc_html__( 'Active users (28 days)', 'stuh' ) . '</small>';
		if ( ! empty( $record['error'] ) || $record['fetched_at'] < time() - 4 * HOUR_IN_SECONDS ) {
			echo '<small class="stuh-analytics-caption">' . esc_html__( 'Stale data', 'stuh' ) . '</small>';
		}
		echo '</span>';
	}

	public static function render_client_panel( array $client ): void {
		self::require_admin();
		$client_id = (string) $client['id'];
		echo '<section id="stuh-analytics" class="stuh-analytics"><h2>' . esc_html__( 'Google Analytics', 'stuh' ) . '</h2>';
		self::notice();
		if ( '' === get_option( self::CONNECTION, '' ) ) {
			echo '<p><a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Connect Google to show GA4 reports for this site.', 'stuh' ) . '</a></p></section>';
			return;
		}
		$connection = self::connection();
		if ( is_wp_error( $connection ) ) {
			echo '<p>' . esc_html( $connection->get_error_message() ) . ' <a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Google settings', 'stuh' ) . '</a></p></section>';
			return;
		}
		self::render_discovery( $client, $connection );
		$mapping = self::mappings()[ $client_id ] ?? [];
		$properties = get_transient( self::properties_key( $connection['id'] ) );
		if ( ! is_array( $properties ) ) {
			echo '<p><a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Load accessible properties in Google Analytics settings to select or change a property.', 'stuh' ) . '</a></p>';
			$properties = [];
		}
		if ( $mapping ) {
			$properties[ $mapping['property_id'] ] = $mapping['name'];
		}
		if ( $properties ) {
			self::form_start( 'map', $client_id );
			echo '<p><label>' . esc_html__( 'GA4 property', 'stuh' ) . ' <select name="property_id" required><option value="">' . esc_html__( 'Select a property', 'stuh' ) . '</option>';
			foreach ( $properties as $id => $name ) {
				echo '<option value="' . esc_attr( $id ) . '"' . ( (string) $id === ( $mapping['property_id'] ?? '' ) ? ' selected' : '' ) . '>' . esc_html( $name . ' (' . $id . ')' ) . '</option>';
			}
			echo '</select></label></p><p><label>' . esc_html__( 'Hostname (exact GA4 value)', 'stuh' ) . ' <input name="hostname" type="text" required value="' . esc_attr( $mapping['hostname'] ?? wp_parse_url( $client['site_url'] ?? '', PHP_URL_HOST ) ?? '' ) . '"></label></p>';
			echo '<p class="description">' . esc_html__( 'Reports include only this hostname. example.com and www.example.com are different; use the hostname recorded in GA4. A mapping does not prove that tracking is installed or consent is working.', 'stuh' ) . '</p>';
			submit_button( __( 'Save mapping and refresh', 'stuh' ), 'secondary' );
			echo '</form>';
		}
		if ( ! $mapping ) {
			echo '</section>';
			return;
		}
		self::form_start( 'unmap', $client_id );
		submit_button( __( 'Remove Analytics mapping', 'stuh' ), 'secondary' );
		echo '</form>';
		if ( $mapping['connection_id'] !== $connection['id'] ) {
			echo '<p>' . esc_html__( 'Google was reconnected. Save this mapping again before viewing reports.', 'stuh' ) . '</p></section>';
			return;
		}
		self::render_report( $client_id, $mapping );
		echo '</section>';
	}

	private static function metric_value( string $metric, float $value ): string {
		return 'engagementRate' === $metric ? number_format_i18n( 100 * $value, 1 ) . '%' : number_format_i18n( $value, 'keyEvents' === $metric && floor( $value ) !== $value ? 2 : 0 );
	}

	private static function render_chart( string $title, array $rows, ?float $scale = null ): void {
		echo '<figure class="stuh-analytics-chart"><figcaption><h3>' . esc_html( $title ) . '</h3></figcaption>';
		if ( ! $rows ) {
			echo '<p>' . esc_html__( 'No data returned for this hostname and period.', 'stuh' ) . '</p></figure>';
			return;
		}
		$maximum = $scale ?? max( array_column( $rows, 'value' ) );
		echo '<ol class="stuh-analytics-bars">';
		foreach ( $rows as $row ) {
			$width = $maximum > 0 ? min( 100, max( 0, $row['value'] / $maximum * 100 ) ) : 0;
			echo '<li><div class="stuh-analytics-bar-label"><span>' . esc_html( $row['label'] ) . '</span><strong>' . esc_html( $row['display'] ) . '</strong></div>';
			echo '<svg class="stuh-analytics-bar stuh-analytics-bar--' . esc_attr( $row['period'] ) . '" viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true" focusable="false"><rect class="stuh-analytics-bar-track" width="100" height="12" rx="2"/><rect width="' . esc_attr( number_format( $width, 3, '.', '' ) ) . '" height="12" rx="2"/></svg></li>';
		}
		echo '</ol></figure>';
	}

	private static function render_charts( array $data ): void {
		if ( isset( $data['history'] ) ) {
			self::render_history_chart( $data['history'] );
			if ( empty( $data['history']['includes_current'] ) ) {
				echo '<p>' . esc_html__( 'Refresh Analytics to include the ongoing month.', 'stuh' ) . '</p>';
			}
		} else {
			echo '<p>' . esc_html__( 'Refresh Analytics to load yearly data.', 'stuh' ) . '</p>';
		}
		echo '<p>' . esc_html( sprintf( __( 'Previous period: %1$s to %2$s.', 'stuh' ), $data['previous_period']['startDate'], $data['previous_period']['endDate'] ) ) . '</p>';
		$labels = [ 'activeUsers' => __( 'Active users', 'stuh' ), 'sessions' => __( 'Sessions', 'stuh' ), 'screenPageViews' => __( 'Page views', 'stuh' ), 'engagementRate' => __( 'Engagement rate', 'stuh' ), 'keyEvents' => __( 'Key events', 'stuh' ) ];
		echo '<div class="stuh-analytics-charts">';
		foreach ( $labels as $metric => $label ) {
			$rows = [];
			foreach ( [ 'current' => __( 'Last 28 days', 'stuh' ), 'previous' => __( 'Previous 28 days', 'stuh' ) ] as $period => $period_label ) {
				$value = $data[ $period ][ $metric ];
				$rows[] = [ 'label' => $period_label, 'value' => $value, 'display' => self::metric_value( $metric, $value ), 'period' => $period ];
			}
			self::render_chart( $label, $rows, 'engagementRate' === $metric ? 1.0 : null );
		}
		echo '</div><div class="stuh-analytics-charts stuh-analytics-charts--rankings">';
		foreach ( [ 'pages' => __( 'Top pages - page views', 'stuh' ), 'channels' => __( 'Top channels - sessions', 'stuh' ) ] as $key => $title ) {
			$rows = [];
			foreach ( $data[ $key ] as $row ) {
				$value = reset( $row['metrics'] );
				$rows[] = [ 'label' => $row['dimensions'][0], 'value' => $value, 'display' => number_format_i18n( $value ), 'period' => 'current' ];
			}
			self::render_chart( $title, $rows );
		}
		echo '</div>';
	}

	private static function render_history_chart( array $history ): void {
		$title = __( 'Active users - year over year', 'stuh' );
		$series = [ 'current' => __( 'Last 12 complete months', 'stuh' ), 'previous' => __( 'Previous 12 months', 'stuh' ) ];
		$maximum = 0.0;
		$has_data = false;
		foreach ( $history['months'] as $month ) {
			foreach ( $series as $key => $label ) {
				if ( null !== $month[ $key ] ) {
					$maximum = max( $maximum, $month[ $key ] );
					$has_data = true;
				}
			}
		}
		echo '<figure class="stuh-analytics-chart stuh-analytics-history"><figcaption><h3>' . esc_html( $title ) . '</h3></figcaption><ul class="stuh-analytics-legend">';
		foreach ( $series as $key => $label ) {
			$period = 'current' === $key ? $history['period'] : $history['previous_period'];
			echo '<li class="stuh-analytics-legend--' . esc_attr( $key ) . '">' . esc_html( $label . ': ' . $period['startDate'] . ' to ' . $period['endDate'] ) . '</li>';
		}
		echo '</ul><p>' . esc_html__( 'Lighter points are month to date, through yesterday. Gaps indicate missing data.', 'stuh' ) . '</p>';
		if ( $has_data ) {
			$intervals = max( 1, count( $history['months'] ) - 1 );
			$maximum = max( 4, ceil( $maximum / 4 ) * 4 );
			echo '<div class="stuh-analytics-line-scroll" tabindex="0" role="region" aria-label="' . esc_attr( $title ) . '"><svg class="stuh-analytics-line-chart" viewBox="0 0 920 240" role="img" aria-label="' . esc_attr( $title ) . '"><desc>' . esc_html__( 'Solid blue: last 12 complete months. Dashed grey: preceding 12 months. Exact values are available in the monthly data table below.', 'stuh' ) . '</desc>';
			for ( $tick = 0; $tick <= 4; $tick++ ) {
				$y = 200 - $tick * 40;
				echo '<line class="stuh-analytics-gridline" x1="70" y1="' . esc_attr( $y ) . '" x2="870" y2="' . esc_attr( $y ) . '"/><text x="60" y="' . esc_attr( $y + 5 ) . '" text-anchor="end">' . esc_html( number_format_i18n( $maximum * $tick / 4 ) ) . '</text>';
			}
			foreach ( $history['months'] as $index => $month ) {
				$x = 70 + $index * 800 / $intervals;
				$date = new DateTimeImmutable( $month['month'] . '-01', new DateTimeZone( 'UTC' ) );
				echo '<text class="' . ( ! empty( $month['in_progress'] ) ? 'stuh-analytics-in-progress' : '' ) . '" x="' . esc_attr( number_format( $x, 2, '.', '' ) ) . '" y="225" text-anchor="middle">' . esc_html( wp_date( 'M', $date->getTimestamp(), new DateTimeZone( 'UTC' ) ) . ( ! empty( $month['in_progress'] ) ? '*' : '' ) ) . '</text>';
			}
			foreach ( $series as $key => $label ) {
				$segments = [];
				$points = [];
				$dots = '';
				$partial_line = '';
				foreach ( $history['months'] as $index => $month ) {
					$value = $month[ $key ];
					if ( null === $value ) {
						if ( $points ) {
							$segments[] = $points;
							$points = [];
						}
						continue;
					}
					$x = number_format( 70 + $index * 800 / $intervals, 2, '.', '' );
					$y = number_format( 200 - $value / $maximum * 160, 2, '.', '' );
					if ( ! empty( $month['in_progress'] ) ) {
						if ( $points ) {
							$partial_line = '<polyline class="stuh-analytics-in-progress" points="' . esc_attr( end( $points ) . ' ' . $x . ',' . $y ) . '"/>';
						}
					} else {
						$points[] = $x . ',' . $y;
					}
					$month_label = 'current' === $key ? $month['month'] : $month['previous_month'];
					$dots .= '<circle class="' . ( ! empty( $month['in_progress'] ) ? 'stuh-analytics-in-progress' : '' ) . '" cx="' . esc_attr( $x ) . '" cy="' . esc_attr( $y ) . '" r="2.5"><title>' . esc_html( $month_label . ': ' . number_format_i18n( $value ) ) . '</title></circle>';
				}
				if ( $points ) {
					$segments[] = $points;
				}
				echo '<g class="stuh-analytics-series stuh-analytics-series--' . esc_attr( $key ) . '">';
				foreach ( $segments as $segment ) {
					if ( count( $segment ) > 1 ) {
						echo '<polyline points="' . esc_attr( implode( ' ', $segment ) ) . '"/>';
					}
				}
				echo $partial_line . $dots . '</g>';
			}
			foreach ( $history['months'] as $index => $month ) {
				$x = 70 + $index * 800 / $intervals;
				$tooltip_x = min( 638, max( 70, $x - 116 ) );
				$labels = [];
				foreach ( $series as $key => $label ) {
					$month_label = 'current' === $key ? $month['month'] : $month['previous_month'];
					$end = $month[ $key . '_end' ] ?? null;
					$labels[] = $month_label . ( $end ? ' (1-' . substr( $end, 8 ) . ')' : '' ) . ': ' . ( null === $month[ $key ] ? __( 'No data reported', 'stuh' ) : number_format_i18n( $month[ $key ] ) );
				}
				$heading = ! empty( $month['in_progress'] ) ? __( 'Month to date - in progress', 'stuh' ) : __( 'Monthly active users', 'stuh' );
				$description = $heading . '. ' . implode( '; ', $labels );
				$hit_start = max( 50, $x - 400 / $intervals );
				$hit_end = min( 890, $x + 400 / $intervals );
				echo '<g class="stuh-analytics-month-hover" tabindex="0" role="img" aria-label="' . esc_attr( $description ) . '"><rect class="stuh-analytics-month-hit" x="' . esc_attr( number_format( $hit_start, 2, '.', '' ) ) . '" y="32" width="' . esc_attr( number_format( $hit_end - $hit_start, 2, '.', '' ) ) . '" height="200"/>';
				echo '<g class="stuh-analytics-month-tooltip" aria-hidden="true"><rect x="' . esc_attr( number_format( $tooltip_x, 2, '.', '' ) ) . '" y="0" width="232" height="76" rx="5"/>';
				foreach ( array_merge( [ $heading ], $labels ) as $line => $text ) {
					echo '<text x="' . esc_attr( number_format( $tooltip_x + 10, 2, '.', '' ) ) . '" y="' . esc_attr( 20 + $line * 22 ) . '">' . esc_html( $text ) . '</text>';
				}
				echo '</g></g>';
			}
			echo '</svg></div>';
		} else {
			echo '<p>' . esc_html__( 'No monthly data available.', 'stuh' ) . '</p>';
		}
		echo '<details class="stuh-analytics-monthly-data"><summary>' . esc_html__( 'View monthly values', 'stuh' ) . '</summary><div class="stuh-analytics-line-scroll"><table class="widefat striped"><caption class="screen-reader-text">' . esc_html( $title ) . '</caption><thead><tr><th scope="col">' . esc_html__( 'Month', 'stuh' ) . '</th><th scope="col">' . esc_html( $series['current'] ) . '</th><th scope="col">' . esc_html__( 'Prior-year month', 'stuh' ) . '</th><th scope="col">' . esc_html( $series['previous'] ) . '</th></tr></thead><tbody>';
		foreach ( $history['months'] as $month ) {
			$suffix = ! empty( $month['in_progress'] ) ? ' (' . __( 'month to date', 'stuh' ) . ')' : '';
			echo '<tr><th scope="row">' . esc_html( $month['month'] . $suffix ) . '</th><td>' . esc_html( null === $month['current'] ? __( 'No data reported', 'stuh' ) : number_format_i18n( $month['current'] ) ) . '</td><td>' . esc_html( $month['previous_month'] . $suffix ) . '</td><td>' . esc_html( null === $month['previous'] ? __( 'No data reported', 'stuh' ) : number_format_i18n( $month['previous'] ) ) . '</td></tr>';
		}
		echo '</tbody></table></div></details></figure>';
	}

	private static function render_report( string $client_id, array $mapping, bool $charts = false ): void {
		$record = self::column_record( $client_id, $mapping );
		if ( ( $record['fetched_at'] ?? 0 ) < time() - 4 * HOUR_IN_SECONDS && ( $record['attempted_at'] ?? 0 ) < time() - 15 * MINUTE_IN_SECONDS ) {
			$scheduled = self::schedule( $client_id );
			if ( is_wp_error( $scheduled ) ) {
				echo '<p>' . esc_html( $scheduled->get_error_message() ) . '</p>';
			}
		}
		if ( ! empty( $record['error'] ) ) {
			echo '<p role="alert">' . esc_html( $record['error'] ) . '</p>';
		}
		if ( wp_next_scheduled( 'stuh_google_refresh_report', [ $client_id ] ) ) {
			echo '<p>' . esc_html__( 'Analytics refresh pending. Reload after WP-Cron runs.', 'stuh' ) . '</p>';
		}
		self::form_start( 'refresh', $client_id );
		submit_button( __( 'Refresh Analytics', 'stuh' ), 'secondary' );
		echo '</form>';
		if ( empty( $record['data'] ) ) {
			echo '<p>' . esc_html__( 'No successful report yet.', 'stuh' ) . '</p>';
			return;
		}
		$data = $record['data'];
		$stale = ! empty( $record['error'] ) || $record['fetched_at'] < time() - 4 * HOUR_IN_SECONDS;
		echo '<p><strong>' . esc_html( $stale ? __( 'Stale report - last successful data', 'stuh' ) : __( 'Last successful report', 'stuh' ) ) . '</strong>: ' . esc_html( wp_date( 'Y-m-d H:i T', $record['fetched_at'] ) ) . '</p>';
		echo '<p>' . esc_html( $data['period']['startDate'] . ' to ' . $data['period']['endDate'] . ' / ' . $mapping['timezone'] . ' / ' . $mapping['hostname'] ) . '</p>';
		if ( $data['limited'] ) {
			echo '<p>' . esc_html__( 'Google flagged thresholding, sampling, or other-row data loss in this report.', 'stuh' ) . '</p>';
		}
		if ( $charts ) {
			self::render_charts( $data );
			return;
		}
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Metric', 'stuh' ) . '</th><th>' . esc_html__( 'Last 28 days', 'stuh' ) . '</th><th>' . esc_html__( 'Previous 28 days', 'stuh' ) . '</th></tr></thead><tbody>';
		$labels = [ 'activeUsers' => __( 'Active users', 'stuh' ), 'sessions' => __( 'Sessions', 'stuh' ), 'screenPageViews' => __( 'Page views', 'stuh' ), 'engagementRate' => __( 'Engagement rate', 'stuh' ), 'keyEvents' => __( 'Key events', 'stuh' ) ];
		foreach ( $labels as $metric => $label ) {
			echo '<tr><th>' . esc_html( $label ) . '</th>';
			foreach ( [ 'current', 'previous' ] as $period ) {
				$value = $data[ $period ][ $metric ];
				echo '<td>' . esc_html( self::metric_value( $metric, $value ) ) . '</td>';
			}
			echo '</tr>';
		}
		echo '</tbody></table>';
		foreach ( [ 'pages' => __( 'Top pages - page views', 'stuh' ), 'channels' => __( 'Top channels - sessions', 'stuh' ) ] as $key => $title ) {
			echo '<h3>' . esc_html( $title ) . '</h3><table class="widefat striped"><tbody>';
			foreach ( $data[ $key ] as $row ) {
				echo '<tr><td>' . esc_html( $row['dimensions'][0] ) . '</td><td>' . esc_html( number_format_i18n( reset( $row['metrics'] ) ) ) . '</td></tr>';
			}
			if ( ! $data[ $key ] ) {
				echo '<tr><td>' . esc_html__( 'No data returned for this hostname and period.', 'stuh' ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
	}
}
