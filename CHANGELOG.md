# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project has no tagged release yet;
changes are listed under *Unreleased* until the first public version.

## [Unreleased]

### Added

- **Interface language (French / English)**: a globe button in the sidebar rail opens a language
  menu; the choice is remembered per browser. The application shell and every Pandore page
  (dashboard, devices, compliance, Secure Score, alerts, vulnerabilities, CVE watch,
  applications), every Vanitas page (overview, endpoints and their detail page, groups,
  compliance, vulnerabilities, end-of-life software, applications and deployments, Windows
  updates, activity log, enrollment, profiles, suspicious activity) and the in-app Vanitas
  documentation are translated, as are the Excel exports; dates and numbers follow the
  language's format. Messages coming from the backend and the demo data are still French.
- **Demo mode** (`npm run demo`): the dashboard runs entirely in the browser with a generated,
  fictional and deterministic dataset — no backend, tenant or secret. A "Mode démo" badge marks
  every page; writes are refused. `npm run build:demo` produces a static demo build. The README
  screenshots are captured from it (`frontend/scripts/capture-screenshots.ps1`). See
  [docs/demo.md](docs/demo.md).
- English documentation: README, architecture, installation, configuration and usage guides,
  diagrams (`docs/images/`), contribution guide, security policy, code of conduct, issue and
  pull request templates, and a GitHub Actions workflow for the backend, dashboard and Vanitas
  server tests.
- Unified sidebar: a rail to switch between the Pandore and Vanitas "worlds" and a collapsible
  navigation column; `Ctrl K` focuses the global search.

### Changed

- **Vanitas overview redesigned** ("bento" layout): a fleet posture card and six KPI tiles at
  the top, each tile carrying its 7-day change and 30-day sparkline (the separate "Trends"
  band is merged into them, and the two "silent" thresholds now share one tile). Below, two
  reorderable columns like the Pandore overview: drag a block by its handle, resize the main
  column's blocks with − / +, reset the layout; the layout is remembered per browser. Same
  data and links as before; loading shows skeletons.
- **Vanitas application catalog redesigned** in the same style: four summary figures (count,
  formats, total size, latest publication), format filters, sorting, a cards / list switch
  (remembered per browser) and a copy button for each install command.
- **Vanitas suspicious activity redesigned** as a list + detail view: clickable summary tiles
  (they apply the matching filter), severity and status filter chips with counts, events
  grouped by day, and the event detail (triage, containment, JSON, prior alerts, Defender
  correlation) in a side panel instead of a popup. Isolated endpoints are shown as cards. The
  endpoint pages keep the detail popup.
- **Vanitas compliance redesigned** as rules + detail: one summary band (compliance rate, the
  endpoints split into compliant / non-compliant / not checked yet, active rules), filterable
  rules with a per-rule result bar, and the selected rule's detail (enable / disable, script
  editor, delete, results filtered by outcome) in a side panel instead of a popup.
- **Vanitas pages now share one background**: the page header (title, search) sat on Pandore's
  navy background above a near-black Vanitas block, leaving a visible seam. In the Vanitas world the
  whole main column now uses the Vanitas background from the brand guidelines.
- **One sort control across Vanitas**: Endpoints, Vulnerabilities and the App catalog replace their
  native drop-downs with a shared "Sorted by" button and menu (criteria with their natural order,
  then ascending / descending). The sort direction can now be reversed; keyboard and screen
  reader friendly (arrow keys, Escape returns focus to the button).
- **Vanitas documentation rewritten** for the redesigned screens: the table of contents follows
  the Vanitas menu, a full-text search shows how many matches each section has and highlights
  them, and one section is shown at a time with an "Open the page" link, an "In short" box (what
  it is for / what you do there / required access), a numbered sketch of the screen with its
  legend, the text, and Previous / Next. Four pages that had no section are now covered
  (End-of-life software, Deployed applications, Updates, Add an endpoint), in French and English.
- **Vanitas profiles and accounts redesigned** as list + detail: a summary band (admins /
  readers, readers with a profile vs. with no access — linking to the first one —, unused
  profiles, non-admin accounts with terminal write access), a "Profiles / Accounts" switch, a
  permission matrix with segmented None / Read / Read-write selectors, and the accounts table
  replaced by a list + panel showing each account's effective access. Password reset now happens
  in the panel (masked, confirmed, 8 characters minimum) instead of a browser prompt that showed
  the password in clear.
- **Vanitas Applications (installer management) redesigned** as list + detail: a summary band
  (formats with a clickable legend, installers already deployed, agent version and how many
  endpoints run it), an "Installers / Vanitas agent" switch, and a side panel instead of card
  grids. New: each installer shows its deployment state (never / in progress / failures / all
  succeeded) with a link to Deployed applications, and each agent version shows its adoption
  across the fleet. The add, deploy, edit and agent-upload popups are unchanged.
- **Vanitas "Add an endpoint" redesigned** as a 3-step flow (server address, token, install
  command with a silent / with-install-log variant) with a collapsible troubleshooting list
  (1619, 1603, 401), a prerequisites checklist with the MSI build command, and a live tracking
  card: after generating a token, the endpoint list is refreshed every 10 s and the newly
  enrolled endpoint appears with a link to its details.
- **Vanitas activity log redesigned** as a day-grouped list + detail: a summary band (events over
  the period, category split with a clickable legend, failures, most active actor), outcome chips,
  the error line shown under each failed command, and the full detail in a side panel instead of
  a popup, with links to the endpoint concerned and to that endpoint's whole log. The Type and
  Period filters are unchanged (the period calendar now fits on phones).
- **Vanitas updates redesigned** as list + detail: a summary band (the six patch states in one bar
  with a clickable legend, pending fixes, active policies), an "Endpoints / Policies by group"
  switch on the list, and the detail in a side panel instead of a popup and a side column. The
  reboot window is drawn on a 24-hour strip (readable across midnight) for an endpoint and while
  editing a group policy.
- **Vanitas deployed applications redesigned** as list + detail: a summary band (installations
  split into succeeded / pending / failed with a clickable legend, success rate excluding pending,
  targeted endpoints), a list with a per-application split bar (failures first) and the detail in
  a side panel instead of an accordion. New: "Retry the failures" re-queues the install on every
  failed endpoint (double confirmation), and "+ Deploy" leads to the installer catalog.
- **Vanitas groups redesigned** as list + detail: a summary band (static / dynamic groups, fleet
  coverage with a link to endpoints without a group, groups with a patch window, most exposed
  group), a searchable list with an inline creation form, and the group detail in a side panel
  with Members / Actions / Subgroups tabs instead of a full page. Endpoints can now be added to a
  static group from the group itself, and the Endpoints page gains a "No group" filter.
- **Vanitas endpoints redesigned** as list + preview: a summary band (endpoints, connectivity
  split into online / offline > 24 h / silent > 7 d with a clickable legend, certificates expiring
  within 30 days, agent version spread), a compact searchable / sortable list with filter chips
  (including critical CVEs) and a side preview (last contact, certificate, apps, vulnerabilities,
  compliance, system disk, groups, latest commands). The full endpoint page opens from the
  preview; group changes and removal moved from the row to the preview.
- **Vanitas end-of-life software redesigned** as products + detail: occurrences are grouped by
  product/version (one entry per product, its endpoints in the detail), with a summary band
  (products, affected endpoints, a clickable EOL / soon split, endoflife.date source), state and
  type chips, and a side panel with the end-of-support date, the catalog update suggestion and the
  affected endpoints (each opens the endpoint page). The Excel export still lists every occurrence.
- **Vanitas vulnerabilities redesigned** as CVEs + detail: a summary band (distinct CVEs, a
  clickable severity split, affected endpoints, average exposure), searchable / sortable CVE
  list with severity chips, and the CVE detail (products, CERT-FR advisory, exposed devices,
  NVD link) in a side panel. Severity colours come from the Pandore CVE palette. The endpoint
  page keeps the detail popup.
- **Compliance now comes from Intune's reporting API** (`getDeviceStatusByCompliacePolicyReport`,
  `getDevicePoliciesComplianceReport`, `getPolicyNonComplianceMetadata`) instead of the legacy
  per-device endpoints. Counts now match the Intune portal, and the built-in "Default Device
  Compliance Policy" is included.
- The compliance rate is strict and identical everywhere: only devices in the `compliant`
  state count as compliant (devices in grace period or with an unknown state no longer do).
  History points computed with the previous formula are ignored for trends.
- A partial daily history point (one data source failing at the time) is retried instead of
  blocking the whole day.
- Layout fixes so every page fits screens from 375 px to 1440 px wide.
- The "Étoile" column and filter of the deployed-apps page and Excel export are now labelled
  "Département" (they show the user's Entra ID `department` attribute). Policy-name handling no
  longer assumes a specific organisation prefix: any `[XYZ] ` prefix is ignored.
- The search field and the Refresh button sit side by side; the redundant Pandore / Vanitas
  switch in the page header and the unused 7/14/30/90-day selector were removed.

### Fixed

- Vanitas file sizes were always shown in GB ("0.0 GB" for a 5 MB installer); they now use
  KB, MB or GB depending on the size.
- Demo mode: command ids were only unique per endpoint, so the fleet-wide command lists
  (Vanitas overview) rendered rows with duplicate React keys.
- The Vanitas server could not start on a fresh database: a migration created the
  `agent_packages` table a second time.
- The Vanitas status in the sidebar stayed on "…" forever when the server was unreachable.

Earlier development history is kept in the maintainer's internal journal (in French) and is not
part of the public repository.
