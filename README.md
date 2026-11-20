# Switch Theme Updater Host

The host authenticates Switch Updater clients, brokers GitHub package updates,
and securely retains short-lived sanitized clone artifacts for authorized host
administrators.

## Website details

Click a website's title or domain in **Updater Host → Client Sites** to open its
details page. Five tabs organize its contents:

- **Overview**: website/access, health/updates, hosting/contacts and WordPress settings.
- **Plugins & Themes**: active theme and separate inventory tables showing themes
  first, then plugins, including identifiers, versions and active status.
- **Forms**: monthly Gravity Forms history and historical JSON uploads. The table
  combines both sources using the highest count per form/month. Imported winning
  counts are italicized; equal counts use normal client-reported styling. Missing
  months remain visible as dashes, distinct from reported zero counts.
- **Analytics**: Google Analytics connection status, property mapping and reports.
- **Diagnostics**: the latest report and expandable raw diagnostics.

Aligned label/value rows show every field, even columns hidden by Screen Options.
Available actions stay visible beside the relevant details, including URL, tag,
and ownership editing, health checks, access controls, and applicable remote
maintenance actions. Actions return to the same website and tab; deleting it returns to
the list. **Back to Client Sites** retains the list's search and status filters.

Use **Open site**, immediately before **Login** in the main table's row actions,
to visit the first registered URL in a new tab. Login remains available when the
client reports a login URL.

Run the standalone view regression checks with `php tests/client-details.php`.

## Gripp / FMP

FMP is available to administrators and editors (the `edit_others_posts`
capability). Administrators open it under **Updater Host → FMP**; editors have
a standalone **FMP** menu because the other Updater Host pages remain admin-only.
Editors can view dashboard/details, refresh data and save their own Screen
Options. Gripp connection settings, token replacement and disconnect remain
restricted to administrators (`manage_options`).

Open **Updater Host → Settings → Gripp** and enter a Gripp API v3 token.
Create the token in Gripp with an API role that has **read** access to umbrella
projects (`umbrellaproject`, **Projecten / Retainers**) and linked orders
(`project`, **Opdrachten**) and logged hours (`hour`). Details usage charts
additionally require read access to `invoiceline` and `invoice`;
write permissions are not needed. Connecting verifies project access before
replacing an existing connection. No Gripp account URL is needed: the integration
uses Gripp's fixed HTTPS API endpoint.

**Updater Host → FMP** shows Gripp's **Projecten / Retainers** list, including
archived umbrella projects, with their number, name, start date, deadline and
archive status, plus budget, monthly allowance, used and remaining budget,
allowance to date, and budget schedule.
The **Active projects** column counts all non-archived linked orders, including
zero-value and overdue projects, using the same definition as the details table.
Counts include every linked-order page, share the dashboard cache, and can be
shown or hidden using Screen Options.
**Real budget left to date** subtracts logged hours valued at EUR 90/hour from
the allowance to date. It includes all linked orders (also archived and
zero-value orders), Concept entries and time corrections through today, excluding
future-dated time and products whose names contain **(ND / intern)**. The marker
is matched case-insensitively with optional spacing around the slash. Those hours
(including corrections) are ignored throughout FMP: dashboard spent hours, charts,
active-project/product totals, monthly carry-over, and Word reports. A month
with only these hours does not keep an active project visible. Order values and
invoices are unchanged. Positive balances are green, negative red, and zero neutral.
Missing budget/schedule dates show Unavailable. This column respects Screen
Options and Euros / Hours; existing commitment-based columns are unchanged.
Dashboard loading requires read access to hours, orders and `offerprojectline`
to identify excluded products. Every
order/time page is loaded and cached with the dashboard; API errors are explicit,
never a fabricated zero balance.
Click a project title in either table to open its **FMP project details** screen.
Each umbrella project / retainer has an administrator-only **Settings** tab.
The tabs are **Overview**, **Monthly reports**, then **Settings**. Administrators
and editors can open Overview and Monthly reports; Settings remains admin-only.
Overview contains the budget chart and cards. Monthly reports contains the
shared month filter, active projects, Gravity Forms, formatted preview and
Copy for Word button. Applying the filter stays on Monthly reports.
Select one or more registered client sites and choose **Save linked sites**;
unchecking all sites removes the links. The selection is stored per Gripp
umbrella project ID on this host, not in Gripp, and survives dashboard refreshes.
Editors can still view the overview but cannot open or change these settings.
Removed client sites are flagged in settings and their links are cleared on save.
Linked sites' reported Gravity Forms counts appear in Monthly reports; saving
links does not request new reports or start additional data collection.
Administrators can select **Hide from Word** beside individual forms and save
the selection to omit them from the formatted Word preview and copy. Hidden
forms remain visible in the Monthly reports table; settings are per linked
client site and FMP project.

### Gravity Forms reports from client sites

Clients can include `gravity_forms` in the existing version-1 `X-STU-Metadata`
JSON object (gzip-compressed, then Base64URL-encoded as usual):

```json
{
  "gravity_forms": [
    {
      "form_id": 1,
      "form_title": "Contact",
      "months": {"2026-10": 12, "2026-11": 8}
    }
  ]
}
```

The host retains the **highest reported entry count per client site, form and
calendar month**, not per FMP project. Form IDs are unique only within that site. Each form needs
a positive integer ID, a string title and a months object with `YYYY-MM` keys
and non-negative integer counts. Only these aggregate fields are retained; do
not send individual entries or personal submission data.

The client-reported source is available at
`STUH_Plugin::get_telemetry()[$client_id]['gravity_forms']`, containing
`received_at` (Unix timestamp) and `forms` (the normalized array above).
It is separate from the latest diagnostics `data`, so reports without the
`gravity_forms` field preserve the previous report and its timestamp.
Valid reports merge into saved history: new forms/months are added and existing
counts only increase. Lower counts, explicit zeros, omitted forms/months and
`gravity_forms: []` never erase existing counts. Repeated reports do not add
counts together. Reported form titles update to the latest title, and
`received_at` records the latest valid report, even when counts do not increase.
This preserves history when client sites automatically delete old entries.
A malformed report is logged and rejected in full, preserving saved history
without blocking update checks or other diagnostics. Deleting a client still
removes its saved report with its telemetry. Previously overwritten counts
cannot be recovered unless they are reported again.
Existing metadata size limits apply. Receiving reports does not require the
site to be linked to an FMP project.

#### Importing historical Gravity Forms counts

Administrators can open **Client Sites**, select a website, then use
the **Forms** tab's **Import Gravity Forms history** section. Choose a `.json` file
(maximum 1 MB) and click **Import history**. The file may contain the array the
client reports, or an object containing a `gravity_forms` array:

```json
[
  {
    "form_id": 1,
    "form_title": "Contact",
    "months": {"2024-12": 12, "2025-01": 8, "2026-10": 20}
  }
]
```

Use the site's actual form IDs so imports and client reports can be combined.
Both sources use the same validation, but are stored independently:

- Client reports remain in `get_telemetry()[$client_id]['gravity_forms']` and
  retain their historical maximum per form/month, as described above.
- The latest upload is in `get_telemetry()[$client_id]['gravity_forms_import']`,
  also containing `received_at` and `forms`. **Every valid upload completely
  replaces the previous imported snapshot**, including omitted forms/months.
  Corrected uploads can lower imported counts. Upload `[]` to clear only the
  imported source.
- Imports never change reported counts or their timestamp. Live reports never
  change the imported snapshot or copy imported counts into reported history.
- `STUH_Plugin::get_gravity_forms_report($client_id)` combines both sources for
  FMP tables, month options and Word matrices. Each form/month uses the **highest
  count across the two sources**, not their sum. Reported form titles take
  precedence over imported titles for matching IDs. Combined results are
  calculated when read, not saved back into either source.

Imports are isolated to the selected client site, preserve other diagnostics
and do not mark the site as having checked in.
Only aggregate counts are saved; uploaded files are not retained or published.
Invalid files and storage errors are explicit and leave previous data intact.
Replacing or clearing imported history appears immediately in linked FMP reports and Word matrices;
no Gripp refresh or new client report is needed.

The Monthly reports tab of an FMP with linked sites shows a **Gravity Forms** table with the
client site, form title and entry count. Forms remain separate per site, even
when IDs or titles match. The shared **Calendar month** dropdown above Active
projects filters both tables; **All months** sums each form's reported counts.
Month options include both logged-hour months and linked sites' reported months.
Explicit zero counts display as zero; missing months display **Not reported**.
Sites without a report, sites reporting no forms and removed sites each show
an explicit status rather than fabricated counts. Administrators and editors
can view this table. No client-site or Gripp requests are made for form counts.

Run `php tests/batch-versions.php` for report-ingestion regression checks.

### Active projects

In Monthly reports, **Active projects** lists all non-archived linked projects
(Gripp **Opdrachten**), with number, name, **actual logged hours** and order
value excluding VAT. Numbers open the corresponding order in Gripp in a new tab,
using the order's internal ID and the order-view navigation fragment (not the
umbrella-project route). Start and delivery dates are omitted.
Actual hours include Concept entries, zero-value work and time corrections,
through today in the WordPress timezone. All time-entry pages are loaded for
each batch of up to 250 order IDs; fractional hours are summed before rounding
the displayed total to two decimals. They always display as hours, independent
of the Euros / Hours preference, which only converts the order value.
Indented sub-rows summarize actual hours **per Gripp product** (for example
Webdevelopment, Art Direction or Project Management), using the product's label.
All order lines (regels) referencing the same product ID are combined within
each project. Different product IDs remain separate even if their labels match.
Trailing numeric references such as `(8026)` are hidden from product labels in
the table and Word report; descriptive parentheses are kept.
Time without an order line or product appears under **No product**, so it still reconciles to
the project total. Projects without time have zero hours and no breakdown.
The shared **Calendar month** dropdown filters this table and Gravity Forms, showing
only that month's project and product hours and hiding projects without time
entries in that month. **All months** (the default) restores the full table.
Options include months with recorded time, linked form reports and the current month. Corrections
remain included, including months whose entries cancel to zero. Order values,
the budget chart and summary cards do not change. Monthly breakdowns share the
same cache, so changing the filter does not reload Gripp data while it is fresh.
At the bottom of Monthly reports, the **Word preview** and **Copy for Word**
button provide the formatted report. There is no TXT preview or download endpoint.
Each active order is a heading (`Opdracht <number> <title>`) followed by product
names and actual hours, with decimal commas and two decimals. Order values and
duplicate project totals are omitted; the report always uses actual hours
regardless of the Euros / Hours preference.

The report uses **Montserrat 10 pt**, with blank lines
before each order heading and the summary. Order headings are bold pink, the hours
summary is bold, the closing balance is pink, and numbers are right-aligned in
borderless tables. Gravity Forms stays grouped by site and uses a matrix in the
Word content: forms as columns, reported months newest first, a **Totaal** column,
and pink annual subtotal rows. The selected report month's entire row is bold;
**All months** does not highlight an individual month.
It includes every calendar month from the earliest report through the selected
month, including empty months (**All months** spans the earliest to latest report).
If no earlier reports exist, the selected month still appears with `-` counts.
Annual subtotals
sum only the included months. Missing counts appear as `-`, distinct from zero;
totals sum available reported counts, with an explicit overflow status if needed.
Teal column headers, alternating row shading and Montserrat 10 pt are applied
inline for Word. Dashboard form tables retain their existing month filter.
Pasting into Word with
**Keep Source Formatting** preserves this styling (exact fonts/layout depend on
Word's paste settings). Montserrat must be installed on the computer running
Word; otherwise Word substitutes an available font. Clipboard data includes HTML
and a plain-text alternative for applications that do not support rich text.
If automatic rich-text copying is unavailable or denied, the report is selected
and an explicit message explains how to copy it manually with Ctrl+C / Command+C.
Without JavaScript, the formatted preview remains selectable for manual copying.
Run `node --test tests/fmp-export.js` for clipboard success/failure checks.

The order breakdown is followed by Gravity Forms matrices grouped by client
site. Each site's URL appears once as a heading. Missing reports have explicit
status messages, and missing month counts are shown as `-`, never invented zeros.
Between the order breakdown and Gravity Forms, an hours summary shows **Uren begin van de maand**,
**Beschikbare uren in de periode**, **Totaal gewerkt**, and
**Uren eind van de maand** (using "periode" for All months):

- Opening hours = allowance accrued before the selected month / EUR 90 minus
  all earlier logged hours. This is **Real budget left to date** at the end of
  the previous month, in hours: only the surplus or deficit carried forward,
  not including the new month's regular budget. It equals the previous month's
  **Uren eind van de maand**, and negative balances remain negative.
- Available hours = that calendar month's allowance / EUR 90, using the existing
  Gripp budget schedule, including partial project months and the project deadline.
  A selected calendar month includes its full allowance, even in the current month;
  logged hours still only run through today.
- Worked hours include **all linked orders, including archived orders**, Concept
  entries, zero-value work and corrections. This can exceed the active-only
  breakdown because archived orders are included.
- Closing hours = opening + available - worked.
  This is the new **Real budget left to date** using the selected month's full
  allowance (whereas the live dashboard accrues the current month through today).

Immediately after the closing-hours summary, the pink heading
**Lopende projecten ten laste van het FMP** lists all active projects, including
those without hours in the selected month. Each project occupies one row with its
total lifetime hours through today, without product lines. The monthly product
breakdown above the summary remains filtered by the selected month.

Archived projects and projects with **Afgerond op** (`project.enddate`) set
appear after the active-project totals and before Gravity Forms.
Under the pink heading **Afgerond en ten laste van het FMP**, each project appears
on one row with its total lifetime hours through today, regardless of the selected
month, without separate product lines.
They are excluded from the active-project breakdown; their hours already count
in the existing balance calculations and are not deducted again.

**All months** starts at zero and uses the accrued allowance through today and
all recorded hours through today, including work outside the project dates.
Calculations use unrounded logged hours; rounding is only for display. Summary
data is cached per umbrella project and connection for five minutes and cleared
on refresh/reconnect/disconnect. Missing budgets/dates or API failures show an
explicit error instead of offering a misleading export or preview.
Administrators and editors can view and copy the formatted report, using the
same permissions, cached data and month filter as Monthly reports.
Sub-rows include only recorded time through today, keep corrections, and always
display hours; each displayed value is rounded independently to two decimals.
All FMP spent-hour calculations require read access to `offerprojectline`.
All referenced line pages are loaded and validated against their parent order;
missing/inaccessible lines or API failures show an explicit error, never a
misleading partial breakdown. The breakdown shares the active-project cache.
Active means
not archived in Gripp and without a completion date, regardless of delivery date; archived orders still count
in the existing budget and usage calculations. Every API page is loaded, and
the table is cached for five minutes per umbrella project and connection.
**Refresh projects**, reconnecting and disconnecting clear this cache.
The table remains available when budget dates or usage data are unavailable;
API failures display an error instead of an empty or partial list.
Summary cards show total and monthly budget, committed order value, remaining
budget, actual recorded time and invoiced value. An interactive
chart plots budget on the Y axis and months (with years) on the X axis:
the dashed horizontal line is the total budget, and the blue diagonal accumulates
the monthly allowance from zero at the start to the full budget at the deadline.
Partial months use the same daily proration as the dashboard.
The default interactive view shows accumulated allowance, actual recorded time
and monthly hours. Total budget and invoiced value remain available through the
single interactive legend; selecting an overlay also shows that dataset.
**Drag horizontally across a period to zoom directly into it.** The selected
period is highlighted while dragging; **Reset zoom** appears in the compact
date toolbar only when zoomed and restores the full period.
The Y axis automatically fits the visible portions of enabled series, with
padding instead of fixed zero/full-project limits. This also works between
monthly points; hiding a series removes it from the automatic Y range.
The date range is announced in the toolbar. Series visibility and the
Euros / Hours preference are preserved when zooming. Calendar dates are plotted
in UTC to prevent browser timezone shifts. Month labels adapt to the available
width without removing data points; zooming reveals more detailed labels.
Published GitHub releases from linked sites' active themes appear as red squares
on the recorded-time line, interpolated at their UTC publication dates within
that line's bounds. Shared repositories are counted once; parent themes and
drafts are excluded. The legend identifies the release squares; hover for
version/date details. Markers follow recorded-time visibility and zoom, including the
provisional segment, and appear in the static fallback. Release history uses
the host's GitHub credentials, loads all pages, and is cached for one hour
(failures for five minutes); API errors are shown below the chart.
Charts use locally bundled **uPlot 1.6.32** (MIT license, included under
`assets/vendor/uplot/`), sourced from the published npm package
<https://www.npmjs.com/package/uplot/v/1.6.32>. No CDN requests or external
transmission of project data are needed. Its assets load only on FMP details.
Without JavaScript, the scrollable SVG remains available with the full-series
static legend; a failed library load
also displays a warning.
Below the chart, use **Secondary dataset → Apply overlay**. The **Forms** group
offers **All forms** or one form identified by its client site and form ID.
The **Analytics** group offers monthly active users for **All websites** or
one linked website. **None** restores the budget-only chart. Monthly counts use a
separate **right-hand Y axis**, independent of Euros / Hours and the budget
scale; both axes fit the visible period when zooming. The overlay also appears
in the static SVG. Exact values remain available by hovering the chart;
there is no monthly-values disclosure or raw-data table beneath it.

All-forms entries and all-websites Analytics users are summed across the FMP's linked sites.
These two options display stacked areas: one colored layer per form or website,
with matching legend entries. The top boundary is the total, while hover values
show each source's own count. Toggle a source in the
legend to restack the remaining layers; zoom and the right-hand scale follow
the visible total. Areas stay behind the budget lines, and current-month
boundaries remain dotted. Single-form and single-website selections stay as lines.
Analytics totals are site counts, not deduplicated visitors across sites.
**All forms** sums available reported counts per month, even when forms have
different histories. Forms without data for a month are excluded from that
month's sum; months without any reports remain gaps, not zeros. Unavailable
sites are flagged but do not suppress other sites' form counts.
All-websites Analytics totals still require data from every linked site; missing
months remain gaps and unavailable site reports prevent a partial Analytics total.
Selecting one website uses only its history and warnings, independently of other sites.
Forms hidden from Word remain available for chart overlays.
Only months within the existing budget/usage chart period through the current
month are included. Analytics uses saved monthly history (including preceding
complete months), not rolling 28-day totals, with an explicitly partial ongoing
month in each property's timezone. Stale reports and Google reporting
limitations are surfaced. Overlays do not fetch or refresh client or Google
data; refresh Analytics through its existing report screen when needed.
The red usage line shows **all recorded hours**, including Concept entries and
hours on fixed-price or zero-value orders, valued at **EUR 90 per hour**,
excluding products marked **(ND / intern)**.
Gold bars show **actual hours in each calendar month**, rather than cumulative
hours. They include corrections (negative totals draw below zero), exclude
**(ND / intern)** time, and show only logged time through today for the current
month. Like the lines, bars follow the Euros / Hours setting at EUR 90/hour;
their hover values also show the actual hours.
The bars remain available in the static SVG when JavaScript is unavailable.
Line points and bars share a single position per calendar month; axis and hover
labels show the month and year rather than a day. The zero starting baseline is
placed before the first project month. Current-month recorded time, invoiced
values and secondary data (active users or form entries) use dotted final
segments because their totals can still change. The current monthly-hours bar
also has a dotted outline; completed months retain their normal strokes.
Missing reports remain gaps.
The gap between actual recorded time and accumulated allowance is shaded red
above the allowance and green below it, switching color at line crossings.
Shading stops where recorded-time data ends and is hidden when either line is
hidden in the interactive chart. This also applies to the provisional segment.
The dashed green usage line shows **sent invoice value excluding VAT**, not
billable-hour eligibility or order commitments. It includes linked-order invoice
lines and lines directly linked to the umbrella project, deduplicated by line ID.
Each line contributes quantity times selling price after its percentage discount,
rounded to cents; credits reduce the cumulative total. Only this project's lines
are counted on shared invoices. Draft invoices are excluded; payment is not required.
Usage is grouped by recording date or invoice date respectively, with cumulative
month-end points and a partial-month point through today. Future-dated usage is
excluded. The timeline extends for usage before the start or after the deadline;
the Y scale includes overruns and negative credit balances. Actual usage is not
projected into future months.
In Hours mode, actual time is recorded time; invoice values are divided by EUR 90
and are **hour equivalents**, not invoiced time-entry quantities.
The dashboard's existing budget-left calculations still use committed order value.
Usage is fetched only for project details and cached for five minutes for the
current project and connection; **Refresh projects** also clears that cache.
An API failure displays an error and leaves usage unavailable, never zero.
Hover points for exact values or expand
**View monthly values** for an accessible data table. The chart and summary honor
the Euros / Hours Screen Option. Missing budgets or missing/invalid dates show
an explanation instead of a fabricated chart; zero budgets remain valid.
**Back to FMP** retains the original list page and selected unit.
Project numbers open the corresponding umbrella project in
**switch.gripp.com** in a new tab, using the application's encoded navigation
fragment and the internal record ID (for example, number 1002 is record 2).
The link retains the project-view routing state, not unrelated grid/calendar
filters from a copied browser URL.
On each page, **Current projects** and **Past deadline projects** are displayed
in separate tables. A deadline before today in the WordPress timezone moves a
project to the latter, even if it is over budget or lacks budget/start-date data.
Projects due today or without a deadline remain current. Past-deadline projects
are assumed finished for this view only; their Gripp status is not changed.
Use WordPress **Screen Options** at the top of FMP to show or hide columns.
Preferences are saved per administrator and apply to both tables together.
The **Euros / Hours** selector in **Screen Options** converts all budget figures in both tables at
**EUR 90 per hour** (EUR 6,480 = 72 hours; EUR 540/month = 6 hours/month).
Dashboard hours are budget equivalents, not logged time, and are displayed to two decimal
places. Calculations and cached data stay in cents; colors and schedule statuses
are unchanged. Click **Apply** to save the unit per administrator. This saved
preference applies to both tables, including after pagination, refresh and later
visits, and takes precedence over unit parameters in older URLs.
Dashboard rows use `umbrellaproject.get`; `project.get` totals linked orders and
identifies their recorded time and invoice lines on the details screen.
Old cached ordinary orders and reports without budget data are ignored automatically;
an existing connection does not need to be replaced if its API role already
has read access to umbrella projects, orders and hours.
Gripp date objects are displayed as calendar dates, preserving
the date supplied by Gripp without timezone conversion. Gripp's zero-date
placeholder is treated as an unset date.
Use **Previous projects / Next projects** to browse every
project, in stable ID order, with up to 250 projects per page. The current page
is cached for five minutes; **Refresh projects** reloads it immediately.
API/authentication/rate-limit failures are shown explicitly, not as empty lists.

Budget used is the sum of **all linked order totals excluding VAT**, including
archived orders and negative credit values. It represents committed order value,
not logged hours, invoices or completed work. Every linked-order page is loaded;
failed or invalid pages produce an error rather than a partial or zero total.
No linked orders means zero used. Budget left is total budget minus used value;
overruns remain visible as negative amounts. Monetary values are calculated in
cents and displayed in EUR using the WordPress locale.

The start date and deadline are inclusive. Full calendar months count as one;
partial months count as covered days divided by days in that calendar month.
For example, January 1 through December 31 is 12 months:
**EUR 6,480 / 12 = EUR 540 per month**. Allowance to date uses the same proration,
through today in the WordPress timezone, capped between zero and the total budget.
**Budget left to date** is allowance to date minus used budget: positive amounts
are green, negative amounts red, and zero or unavailable amounts stay neutral.
Monthly amounts are rounded only for display; cumulative allowances use the
unrounded rate to avoid rounding drift.

Budget schedule compares used value with allowance to date: ahead, behind or on
schedule. Over-budget, not-started and past-deadline projects are labeled
separately. This indicates **budget pacing**, not delivery progress.
Missing budgets, missing dates or deadlines before the start date explicitly
disable schedule calculations; an explicitly zero budget remains valid.

Only host administrators can manage the connection or view FMP. The API token
is encrypted using AES-256-GCM in a non-autoloaded WordPress option, using the
host's WordPress authentication salts. PHP OpenSSL is required. Keep those salts
stable; after rotating them, reconnect Gripp. Tokens are never prefilled into
forms or sent to client sites. Disconnecting removes the locally stored token
and cached project page; it does not revoke the token in Gripp.

API reference: <https://api.gripp.com/public/api3.php>.
Run the standalone regression checks with `php tests/gripp.php`.
Run the interactive chart auto-scaling checks with `node --test tests/fmp-chart.js`.

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
Multi-range responses are validated as complete month/range groups, including
Google's expanded rows with a pre-expansion `rowCount`. Zero-filled rows outside
their named range are ignored; nonzero out-of-range values, duplicates and
incomplete groups fail the refresh without replacing the last successful report.
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
Refresh failures are logged with the `[STUH Analytics]` prefix, client/property
IDs and error details. Invalid report rows also include the report name and
row-count/type diagnostics, without report contents or credentials. With
`WP_DEBUG` and `WP_DEBUG_LOG` enabled, these entries go to WordPress's configured
debug log (normally `wp-content/debug.log`).
With `WP_DEBUG` enabled, Tag Manager API requests also log their method,
endpoint (without query parameters), HTTP status/response type or network
error code under `[STUH GTM]`. Headers, tokens and container contents are not logged.

Administrators and editors (`edit_others_posts`) can view reports and request
Analytics refreshes. Editors have a standalone **Google Analytics** menu;
other Updater Host pages remain admin-only. Only administrators with
`manage_options` can connect/disconnect Google, manage properties, trigger GTM
discovery or change site mappings. OAuth uses a short-lived, user-bound, single-use state and
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
