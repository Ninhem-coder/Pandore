# Usage

A tour of the dashboard and the MCP integration. The interface is currently in **French**; each
page is listed with its French label and an English description.

- [Navigation](#navigation)
- [Pandore pages](#pandore-pages)
- [Vanitas pages](#vanitas-pages)
- [Accounts and permissions](#accounts-and-permissions)
- [Using Pandore from Claude Desktop (MCP)](#using-pandore-from-claude-desktop-mcp)
- [Common tasks](#common-tasks)

## Navigation

- The **left rail** switches between the two "worlds": the shield opens **Pandore** (Intune and
  Defender), the reticle opens **Vanitas** (self-hosted agents). Clicking the active world again
  collapses the navigation column.
- The **global search** in the page header accepts a device name or a CVE ID
  (`CVE-2024-3400`) and jumps to the matching page. `Ctrl K` (or the search icon in the rail)
  focuses it.
- **Rafraîchir** (*Refresh*) reloads the dashboard data; the timestamp below it shows when the
  data was generated. Data is otherwise loaded once and cached.

## Pandore pages

| Page (French label) | What it shows |
|---|---|
| **Dashboard** | KPIs (Defender machines, Intune devices and compliance rate, non-compliant and non-onboarded devices, active alerts), 7/30-day trends from the daily history, devices at risk, devices enrolled in the last 7 days, Defender alerts, top recommendations, and signals (Secure Score, criticality, watched CVEs, CERT-FR advisories). Tiles can be dragged, resized and reset. |
| **Appareils → Inventaire** (*Inventory*) | Every device with its sources (Intune, Defender, Vanitas), user, compliance, exposure, sensor health and last contact. |
| **Appareils → Fiche appareil** (*Device page*) | One device across all sources: identity and network, hardware, OS, detected applications, vulnerabilities, per-policy compliance with per-setting detail, alerts, and Vanitas suspicious events. |
| **Sécurité → Conformité** (*Compliance*) | Compliance rate, policies tracked, prioritised failing policies, non-compliant devices grouped by OS and policy, 90-day trend. |
| **Sécurité → Secure Score** | Score history, comparison with similar organisations, devices by exposure level, most vulnerable software, the full control catalogue with remediation steps. |
| **Sécurité → Alertes** (*Alerts*) | Defender alerts with breakdowns by severity, status and classification, detection sources, named threats, column filters and expandable evidence. |
| **Vulnérabilités → Vulnérabilités** | CVE inventory of the tenant with exposed devices, search and details. |
| **Vulnérabilités → Suivi CVE** (*CVE watch*) | CVEs you pin; they are re-checked automatically. Includes CERT-FR advisories matched against your software. |
| **Applications → Catalogue** | The internal application library (packaged or manual entries) with downloadable `.intunewin` packages. |
| **Applications → Applications déployées** (*Deployed apps*) | Intune-deployed apps with install status and assignments, plus detected software and versions. |
| **Applications → Ajouter / Modifier une application** (*Add / Edit*) | A wizard that packages an MSI or a GitHub release into `.intunewin` with detection rules, and edits library entries. Nothing is published to Intune automatically. |

## Vanitas pages

| Page (French label) | What it shows |
|---|---|
| **Vue d'ensemble** (*Overview*) | Online agents, suspicious activity, compliance, end-of-life software, trends, command activity, patch posture, groups and recent alerts. |
| **Catalogue d'application** | Installers available for deployment. |
| **Activités suspectes** (*Suspicious activity*) | Events from the agents' behavioural detection, with triage (acknowledge, false positive, escalate) and network isolation status. |
| **Conformité** | Your PowerShell compliance rules and their result per device; create rules here. |
| **Vulnérabilités** | CVEs matched to the software inventory of the agents. |
| **Logiciels obsolètes** (*End-of-life software*) | Software and OS versions past their end of support. |
| **Postes** (*Devices*) | Enrolled agents with status, certificate expiry and last command. Opens a full device page: hardware, OS, network, apps, vulnerabilities, compliance, event log, command history, remote PowerShell terminal, certificate, Windows updates. |
| **Groupes** | Device groups with dynamic membership rules; push an application or an agent update to a group. |
| **Applications déployées** | Applications pushed by Vanitas and their result per device. |
| **Mises à jour** (*Updates*) | Windows update policies per group (ring, maintenance window, grace period) and per-device status. |
| **Journal** (*Activity log*) | Every command and administrative action, with filters and a calendar view. |
| **Ajouter un poste** (*Add a device*) | Generates a one-time enrollment token and the matching `msiexec` command. |
| **Applications** | Upload installers (or fetch a GitHub release) and new agent versions. |
| **Profils** (*Profiles*) | Accounts and per-module read/write permission profiles (admins only). |
| **Documentation** | In-app documentation of Vanitas (French). |

## Accounts and permissions

- **admin**: full access, including account and profile management.
- **viewer**: read-only on Pandore; on Vanitas, only the modules granted by the assigned
  profile (devices, terminal, applications, compliance, groups, suspicious activity), in read or
  write mode. A viewer without a profile sees no Vanitas data.

Permissions are enforced by the backend; hiding menu items is only a convenience.

## Using Pandore from Claude Desktop (MCP)

After [connecting Claude Desktop](installation.md#5-optional-connect-claude-desktop), two
servers are available:

- **intune-local**: devices, compliance policies and reports, apps and assignments, users,
  configuration profiles, Secure Score, application library.
- **defender-local**: machines, alerts, vulnerabilities, recommendations, exposure score,
  advanced hunting queries, CERT-FR matching, CVE watchlist.

Example questions:

- "Which devices are non-compliant with the BitLocker policy, grouped by OS?"
- "List high-severity Defender alerts from the last 24 hours."
- "Which machines are exposed to CVE-2024-3400?"
- "What are the top five Secure Score recommendations by impact?"

The answers come from the same functions as the dashboard, with the same permissions as the
app registrations.

## Common tasks

**Find why a device is non-compliant.** Compliance → open the failing policy → select the
device → the per-setting panel shows each setting, its state and any error.

**Check exposure to a new vulnerability.** Type the CVE ID in the global search. To follow it
over time, pin it in **Suivi CVE**.

**Push an application with Vanitas.** Upload the installer in **Applications**, then use
**Groupes** (push to a group) or the device page. Results appear in **Applications déployées**
and **Journal**.

**Open a remote shell.** **Postes** → device → *Terminal*. Requires write access to the terminal
module; every session is recorded in the activity log.
