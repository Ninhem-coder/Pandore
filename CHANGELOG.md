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
