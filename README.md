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
