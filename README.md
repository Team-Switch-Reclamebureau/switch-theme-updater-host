# Switch Theme Updater Host

The host authenticates Switch Updater clients, brokers GitHub package updates,
and securely retains short-lived sanitized clone artifacts for authorized host
administrators.

## Website details

Click a website's title or domain in **Updater Host → Client Sites** to open its
details page. Six compact panels group website/access, health/updates,
hosting/contacts, WordPress settings, themes/plugins, and diagnostics.
Aligned label/value rows show every field, even columns hidden by Screen
Options. Separate, always-visible inventory tables show themes first and plugins
second, including names, identifiers, versions, and active status. Raw diagnostics
expand on demand.
Available actions stay visible beside the relevant details, including URL, tag,
and ownership editing, health checks, access controls, and applicable remote
maintenance actions. Actions return to the same website; deleting it returns to
the list. **Back to Client Sites** retains the list's search and status filters.

Use **Open site**, immediately before **Login** in the main table's row actions,
to visit the first registered URL in a new tab. Login remains available when the
client reports a login URL.

Run the standalone view regression checks with `php tests/client-details.php`.

## Google Analytics (GA4)

**Updater Host → Settings → Google Analytics** connects one agency Google account using
read-only OAuth. Client sites do not receive Google credentials and do not need
a client-plugin update for manual property mapping. Clients that report
`gtm_container_ids` can also be mapped automatically through read-only access
to published Google Tag Manager configuration. Tracking installation and tag
editing/publishing are not included.

### Server configuration

Enable the **Google Analytics Data API** and **Google Analytics Admin API** in a
Google Cloud project. For automatic GTM mapping, also enable the **Tag Manager
API**. Configure the Google Auth Platform audience and these read-only scopes:

- `https://www.googleapis.com/auth/analytics.readonly`
- `https://www.googleapis.com/auth/tagmanager.readonly`

Existing Analytics-only connections continue reporting, but must reconnect
and grant the additional scope before GTM discovery can run. The connecting
Google account needs read access to the relevant GTM containers as well as
Viewer access to the GA4 properties. An Internal audience
only permits accounts in the project's Workspace organization, although those
accounts may have access to externally owned client properties.

Create a **Web application** OAuth client and register the exact redirect URI
shown in the Settings page's Google Analytics section. For the current host this is:

```text
https://teamswitch.dev/wp-admin/admin-post.php?action=stuh_google_oauth_callback
```

Configure these values in the host's `wp-config.php`, before WordPress loads, or
as real environment variables available to PHP:

```php
define( 'ANALYTICS_CLIENT_ID', 'your-google-oauth-client-id' );
define( 'ANALYTICS_CLIENT_SECRET', 'your-google-oauth-client-secret' );
define( 'STUH_GOOGLE_TOKEN_KEY', 'your-stable-random-token-encryption-key' );
```

Generate a token key with `php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'`.
Keep that key stable, back it up securely, and keep it outside the database.
PHP OpenSSL and an HTTPS admin URL are required. Tokens are authenticated and
encrypted with AES-256-GCM in a non-autoloaded WordPress option. Changing the
key without restoring the original requires disconnecting and reconnecting.
Constants take precedence over environment variables.

WordPress and this plugin do **not** load `.env` files. Git-ignoring such a file
does not prevent HTTP access to it: do not deploy secrets in a publicly served
plugin directory. Do not commit credentials. `ANALYTICS_VIEW_ID` is not used:
GA4 reporting uses a numeric **property ID**, selected per client, not a legacy
Universal Analytics view ID or a `G-...` measurement ID.

### Connecting and mapping

1. Deploy the updated plugin, including its `includes` directory.
2. Open **Updater Host → Settings → Google Analytics → Connect Google** as a host
   administrator, and authorize an account with at least Viewer access to the
   required GA4 properties.
3. Click **Load / refresh accessible properties**. This follows all account
   summary pages and caches the accessible property list for one hour.
4. Open a client's details, select its GA4 property, and confirm the exact
   hostname recorded by GA4, without a scheme, port, or path.
5. Click **Save mapping and refresh**, then reload after WP-Cron runs.

Every report is filtered to the selected hostname, even when the property
contains other sites. `example.com` and `www.example.com` are separate values.
This first version reports one hostname per client; it does not automatically
combine domains, select a stream, install tracking, or validate consent.

The dashboard shows active users, sessions, page views, engagement rate and key
events for the last 28 complete days and the preceding 28 days, using the
property timezone captured when saving the mapping. It also shows the top ten
pages and traffic channels for the latest period. Fractional key-event counts
are retained. Google processing delays, consent settings, sampling and
thresholding can affect the figures; reported limitations are displayed.
Re-save the mapping if the property's timezone changes.

**Updater Host → Google Analytics** is the reporting page. A client site
dropdown lists only sites with a successful cached report for the current
Google connection and property mapping, sorted alphabetically without URL
schemes. It defaults to the first listed site. Valid zero-traffic and stale
reports remain available; pending reports and obsolete mappings are excluded.
When no client has a usable report, the reporting page shows an explicitly
labeled **demo.example** dummy site with sample charts, including the ongoing
month and hover values. Demo data is generated only for display: it is never
saved as a client, property mapping, or cached report and never calls Google or
schedules refreshes. Real zero-traffic reports still count as available data
and are not replaced by samples.
Five bar charts compare
active users, sessions, page views, engagement rate, and key events across the
two 28-day periods. Each metric has its own scale; engagement uses a fixed
0-100% scale. Horizontal ranking charts show top pages and traffic channels.
All bars have visible text labels and exact values, including fractional key
events.

Above those charts, a **monthly active users** line graph compares the last
12 complete calendar months against the preceding 12, with the ongoing month
appended as a **13th point**. For example, during November 2026 the full-month
comparison covers November 2025-October 2026 versus November 2024-October 2025,
then adds November 2026 month-to-date against November 2025 month-to-date.
The partial point uses data through yesterday and the same elapsed calendar
days in the prior year (clamped to that month's length). On the first day of a
month, both partial points remain unavailable until a complete day exists.
All boundaries use the mapped property's timezone. The fifth report in the
existing Google batch requests `activeUsers` by `yearMonth`, with a named
24-month complete range and two separate named month-to-date ranges.
These are monthly unique-user counts, not sums of daily users or yearly totals.

Both lines share a zero-based vertical scale. The latest period is solid blue
and the prior period dashed grey. The ongoing month's points and their
connecting segments are lighter, with an asterisk on the month label.
Hover over any month, or focus it with the keyboard, to see both years'
values and the partial-month cutoffs. Reported zeroes are plotted; omitted months
are gaps, not assumed zero traffic. New properties, tracking changes and Google
reporting restrictions can limit older data. A **View monthly values**
disclosure exposes the exact months and counts (or **No data reported**) for
screen readers and keyboard users. On narrow screens the line graph can be
scrolled horizontally inside its card.

The monthly history shares the existing report cache, refresh action and stale
data handling. After deploying this feature, use **Refresh Analytics** once to
populate history for an already-cached report; older 12-point reports remain
visible with a refresh prompt to load the ongoing month. These are aggregate monthly and
28-day comparison charts, not daily time-series charts.
The client details page retains its 28-day data in tables. Refresh actions return to the
selected report and queue work through WP-Cron, never a synchronous Google
request. Connection, property-list refresh, and bulk discovery controls live
in Settings; per-site mapping controls remain on client details. Existing
connections and mappings do not need to be recreated for this navigation change.

The existing **Analytics** column now shows the property connection status,
or the cached active users for the last 28 complete days followed by the change
against the preceding 28 days. Increases are green, decreases red, and unchanged
counts neutral. A zero previous-period count shows `N/A` when the current count
is positive (a percentage increase is undefined), or `0.0%` when both are zero.
Pending and failed reports are distinguished from zero traffic; stale counts
are labeled. Hover for the property, periods, last update and applicable error
or Google reporting limitation. Available counts link to the Google Analytics
page with that client selected; sites without data keep their client details link.
The list reads cached reports only; it does not call Google or queue report
refreshes. Open the client details or use its refresh action to update data.
Disconnected labels are light grey and user counts are black. Click the
Analytics heading to sort numerically by active users in either direction;
sites without a report for the current connection and mapping stay last.

### Automatic mapping from GTM diagnostics

The client diagnostics contract is:

```json
{
  "analytics": "disabled",
  "gtm_container_ids": ["GTM-ABC1234"]
}
```

`gtm_container_ids` is an array of container ID strings, or `null` when no
container was detected. Missing, null, and empty values do not produce a
mapping. Malformed arrays are reported rather than partially accepted. The
legacy `analytics` text field is independent: `disabled` does not suppress GTM
discovery.

Authenticated telemetry, connecting Google, or opening an unmapped client
details page can queue a discovery job. These paths make no discovery API
requests themselves. Administrators can also use **Discover unmapped client
sites from GTM** in Settings under Google Analytics or **Retry automatic mapping**
on a client details page. WP-Cron performs the actual lookups:

1. Look up each reported GTM container and read its **published version**, not
   an unpublished workspace.
2. Read `G-...` destinations from Google tags and legacy GA4 configuration
   tags, including literal constant-variable references and explicit GA4 event
   destinations. Paused tags are excluded.
3. Match those measurement IDs against accessible GA4 web streams, following
   all property and stream-list pages.
4. Require each discovered destination to have one accessible stream whose
   default URL hostname exactly matches the client's primary registered URL.
   All destinations must resolve to the same property.
5. Save that property's numeric ID and timezone, mark the mapping as
   GTM-discovered, and queue its first Analytics report.

Container destinations and the shared stream index are cached for one hour.
Unmapped discovery attempts are also retried no more than hourly unless
diagnostics change or an administrator explicitly retries. No hostname
normalization merges `www` and bare domains. Shared containers with ambiguous
destinations, inaccessible streams, dynamic/lookup/JavaScript variables,
`GT-...` Google tag aliases, custom HTML/templates, and server-side routing
can require manual mapping. The panel displays discovery failures rather than
guessing a property. A match does not prove that the tags fire, consent is
configured correctly, or traffic is being received.

Existing mappings, including manual choices and previously discovered
mappings, are never automatically replaced. Changed reported containers are
flagged on previously discovered mappings for review. Removing a mapping
pauses automatic mapping for that client so it is not immediately recreated;
**Retry automatic mapping** explicitly enables it again.

Opening a mapped client page queues a background refresh if its successful
report is older than four hours, with a 15-minute retry delay after failures.
The page itself never calls Google. **Refresh Analytics** queues an immediate
retry. WP-Cron must be functioning; low-traffic hosts should run it with a real
server scheduler. Failed refreshes preserve the last successful report and
clearly mark it stale, rather than displaying zero traffic. Until the first
successful report, the panel explicitly says no report is available.

Only administrators with `manage_options` can connect Google, map properties
or view reports. OAuth uses a short-lived, user-bound, single-use state and
PKCE. Reconnecting requires confirming existing mappings again before showing
reports from the new connection. Disconnecting attempts Google token revocation
and removes local credentials, mappings and reports; an unconfirmed revocation
is surfaced with instructions to remove the app in Google account permissions.
Removing a mapping or deleting its client removes its cached report and queued
refresh too.

Run `php tests/analytics.php` and `php tests/client-details.php` for standalone
regression checks. Google HTTP responses are mocked; a live OAuth connection
and a report from an authorized GA4 property still need deployment validation.

## Batched version checks

New clients use authenticated `POST /wp-json/stu-host/v1/versions`. Authentication
and telemetry processing use the same permission callback as `GET /version`,
once per batch. The existing `GET /version` endpoint and response are unchanged
for older clients; clients can be upgraded before or after the host.

Send JSON containing `packages`, an array of 1 to 100 objects:

```json
{
  "packages": [
    {"repo": "owner/plugin", "mode": "releases"},
    {"repo": "owner/theme", "mode": "commits", "branch": "main", "path": "/"},
    {"repo": "owner/theme", "mode": "tag", "ref": "v1.0"}
  ]
}
```

Only `repo` is required. Defaults are `mode: releases`, `branch: main`,
`path: /`, and an empty `ref`. Modes are `releases`, `commits`, and `tag`.
The response has a `results` array in input order. Each item is either the
existing `{"version": "...", "ref": "..."}` result or
`{"error": {"code": "...", "message": "...", "status": 404}}`.
Package-level errors do not abort other lookups. Identical lookups within a
batch are resolved once. Invalid payloads are rejected by WordPress REST schema
validation before the endpoint runs.

GitHub lookups still run sequentially on the host. This endpoint reduces
client-to-host requests, repeated WordPress bootstrapping, authentication, and
telemetry work; it does not add persistent version caching.

Run the standalone regression checks with `php tests/batch-versions.php`.
They mock GitHub responses without contacting external services.

## Package download failures

GitHub package downloads return a local ZIP path on success or a `WP_Error` on
failure. The download endpoint reports failures as HTTP 502 with the error
message; local self-updates pass the error to the WordPress upgrader instead of
falling back to a loopback request.

If an update reports `Failed to extract zip`, check the host's PHP temporary
directory permissions, available disk space, and the downloaded archive.
PHP's `ZipArchive` extension is required for extraction and repackaging.

Run the standalone download regression checks with
`php tests/download-zipball.php`. These use mocked HTTP responses and local ZIP
fixtures, without contacting GitHub.

## PHP version colors and tooltips

Hover over a PHP version in Client Sites to see its support status and dates:

- **Red:** PHP is end-of-life, or outside the locally configured PHP support
  range for the site's WordPress version.
- **Orange:** PHP receives security fixes only, or the installed patch version
  is behind the latest release in its branch.
- **Normal:** PHP is actively supported, no newer patch is listed, and no local
  compatibility problem was found. Missing patch versions are explicitly
  identified as unverified in the tooltip.

PHP lifecycle dates and latest patch versions are fetched from
`https://endoflife.date/api/php.json` and cached across all client sites for one
hour. Dates are evaluated in UTC, with
support ending after the listed date. Only the public release catalogue is
requested; no client URLs or telemetry are sent to that service.

Patch comparisons stay within the installed major/minor branch and ignore
distribution suffixes. Tooltips show the installed and latest versions when an
update is available. This detects release lag, not specific vulnerabilities;
catalogue updates can lag upstream releases, and hosting providers may backport
fixes without changing the upstream PHP version.

WordPress/PHP compatibility uses the local table checked on 2026-10-21 against
the [official compatibility chart](https://make.wordpress.org/core/handbook/references/php-compatibility-and-wordpress-versions/),
not a live compatibility API:

| WordPress | Compatible PHP branches |
|-----------|-------------------------|
| 7.1, 7.0 | 7.4 through 8.5 |
| 6.9 | 7.2 through 8.5 |
| 6.8, 6.7 | 7.2 through 8.4 |
| 6.6 | 7.2 through 8.3 |
| 6.5, 6.4 | 7.0 through 8.3 |

Compatibility does not imply PHP still receives security fixes; the separate
live lifecycle check flags end-of-life branches red even within these ranges.
WordPress versions not listed have an unknown compatibility status.
Tooltips distinguish the local check from the live lifecycle check and
explicitly report unknown versions or unavailable data. Failed
requests or invalid responses are cached for 15 minutes before retrying; no
active-support status is assumed on failure. A known local compatibility
problem still appears red when the lifecycle service is unavailable.

Run the standalone regression checks with `php tests/php-versions.php`.
They use mocked HTTP responses, without contacting external services.

## SSL certificate column

The Client Sites table includes an SSL column (also available in Screen Options).
It checks only the first registered URL's hostname, using TLS on port 443, or the
explicit port for an HTTPS URL. HTTP redirects and other registered URLs are not
followed.

Let's Encrypt certificates display `Let's Encrypt`. Other certificates display
the number of complete days remaining; negative values indicate expiration.
Click the SSL heading to sort numerically in either direction, with Let's
Encrypt, pending checks, and failed checks placed after certificates with a
day count. Hover over the result to see the issuer and expiration date.

Checks run through WP-Cron when the table is opened, with results refreshed after
24 hours (failed checks after one hour). The last result and its check time stay
visible while a refresh is pending. Reload the table after WP-Cron runs to see
new results, or use **Check SSL** in a cell to check that site immediately.
PHP OpenSSL and stream sockets are required; failures are shown in the column.
This inspects certificate metadata, including expired or untrusted certificates;
it does not certify chain trust or hostname validity.

Run the standalone regression checks with `php tests/ssl-column.php`. They cover
issuer detection, expiry sorting, caching, and certificate capture against a
temporary local TLS server.

## Clone job progress

The authenticated `GET /clones/{job_id}` status response includes a `stage`
field. New and claimed jobs begin at `queued`; clients report
`exporting`, `uploading_database`, `archiving_theme`, `uploading_theme`,
`archiving_parent_theme`, `uploading_parent_theme`, and `finalizing` through
the authenticated client progress endpoint. This lets clone consumers show the
current operation while the job status remains `claimed`.

When a client administrator cancels an active clone, the client reports
`Cancellation requested from client plugin.` through the authenticated failure
endpoint. The host changes the claimed job to `failed`, records that message,
and removes its uploaded artifact parts.

## Child-theme clone support

Clone-job status returns a `package_inventory` containing the active theme and,
when it is a child theme, its required parent theme. Theme inventory entries use
`active` and `required` respectively, allowing clone consumers to reconstruct
both theme dependencies.

For unmanaged themes, clone jobs retain separate verified ZIP artifacts:

- Active theme: `theme_artifact_sha256`, `theme_artifact_size`, and
  `theme_stylesheet`, downloaded from `/clones/{job_id}/theme-download`.
- Required parent theme: `parent_theme_artifact_sha256`,
  `parent_theme_artifact_size`, and `parent_theme_stylesheet`, downloaded from
  `/clones/{job_id}/parent-theme-download`.

Both endpoints require an authenticated host administrator, serve only `ready`,
unexpired jobs, and set `Cache-Control: no-store`. Artifacts expire after 24
hours. The established single active-theme artifact and endpoint remain
available for compatibility with older clients and consumers.
