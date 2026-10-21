# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The project has no tagged release yet;
changes are listed under *Unreleased* until the first public version.

## [Unreleased]

### Added

- English documentation: README, architecture, installation, configuration and usage guides,
  diagrams (`docs/images/`), contribution guide, security policy, code of conduct, issue and
  pull request templates, and a GitHub Actions workflow for the backend, dashboard and Vanitas
  server tests.
- Unified sidebar: a rail to switch between the Pandore and Vanitas "worlds" and a collapsible
  navigation column; `Ctrl K` focuses the global search.

### Changed

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

- The Vanitas server could not start on a fresh database: a migration created the
  `agent_packages` table a second time.
- The Vanitas status in the sidebar stayed on "…" forever when the server was unreachable.

Earlier development history is kept in the maintainer's internal journal (in French) and is not
part of the public repository.
