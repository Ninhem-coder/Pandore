# Configuration

All settings come from environment variables, usually placed in a git-ignored `.env` file.
A variable already set in the shell takes precedence over the same key in `backend/.env`.

- [Pandore backend — `backend/.env`](#pandore-backend--backendenv)
- [Vanitas server — `endpoint-agent/server/.env`](#vanitas-server--endpoint-agentserverenv)
- [Vanitas agent](#vanitas-agent)
- [Local data files](#local-data-files)

## Pandore backend — `backend/.env`

Template: [`backend/.env.example`](../backend/.env.example).

### Microsoft authentication (required)

| Variable | Default | Description |
|---|---|---|
| `AUTH_MODE` | `client_credentials` | `client_credentials` (app-only, client secret) or `interactive` (delegated sign-in, public client app) |
| `MDE_TENANT_ID` | — | Tenant ID of the Defender for Endpoint app registration |
| `MDE_CLIENT_ID` | — | Application (client) ID of that registration |
| `MDE_CLIENT_SECRET` | — | Client secret of that registration |
| `AZURE_TENANT_ID` | — | Tenant ID of the Microsoft Graph app registration |
| `AZURE_CLIENT_ID` | — | Application (client) ID of that registration |
| `AZURE_CLIENT_SECRET` | — | Client secret of that registration (not used in `interactive` mode) |

### API endpoints (optional)

| Variable | Default |
|---|---|
| `MDE_API_BASE` | `https://api.securitycenter.microsoft.com` |
| `GRAPH_API_BASE` | `https://graph.microsoft.com/v1.0` |
| `GRAPH_API_BETA` | `https://graph.microsoft.com/beta` |

### Web server

| Variable | Default | Description |
|---|---|---|
| `API_HOST` | `127.0.0.1` | Interface the API listens on (port 8000). Only change it if remote access is intended and protected. |
| `CORS_ORIGIN` | `http://localhost:5173` | Allowed browser origin (fallback; the Vite dev server proxies `/api`) |
| `SESSION_COOKIE_SECURE` | `false` | Set to `true` when the backend is served over HTTPS |

### Vanitas integration (optional)

| Variable | Default | Description |
|---|---|---|
| `VANITAS_SERVER_URL` | `https://localhost:8443` | URL used by the backend to reach the Vanitas server |
| `VANITAS_CA_CERT_PATH` | `endpoint-agent/server/data/ca/ca.pem` | Public CA certificate used to verify the Vanitas server |
| `VANITAS_SHELL_TOKEN` | empty | Shared secret sent as `X-Shell-Token`; must equal `SHELL_SESSION_TOKEN` on the server |
| `VANITAS_AGENT_SERVER_URL` | empty | Server URL as reachable **from endpoints**, used to build the install command on the "Add a device" page |

### E-mail alerts (optional)

Used by the Vanitas alert jobs. E-mails are skipped (and logged) while `SMTP_HOST` or
`SMTP_TO` is empty; alerts are still recorded and shown in the dashboard.

| Variable | Default |
|---|---|
| `SMTP_HOST` | empty |
| `SMTP_PORT` | `587` |
| `SMTP_USE_TLS` | `true` |
| `SMTP_USERNAME`, `SMTP_PASSWORD` | empty |
| `SMTP_FROM`, `SMTP_TO` | empty |

### Background jobs

| Variable | Default | Description |
|---|---|---|
| `HISTORY_SNAPSHOT_CHECK_SECONDS` | `3600` | How often the daily metrics snapshot is checked |
| `WATCHLIST_REFRESH_SECONDS` | `3600` | Watched-CVE refresh interval |
| `VANITAS_ALERT_CHECK_SECONDS` | `3600` | Vanitas alert evaluation interval |
| `VANITAS_ALERT_STALE_HOURS` | `12` | An agent silent for longer triggers an alert |
| `VANITAS_ALERT_CERT_WARNING_DAYS` | `30` | Alert this many days before an agent certificate expires |
| `VANITAS_PURGE_RETENTION_DAYS` | `90` | Retention of Vanitas history |
| `VANITAS_PURGE_CHECK_SECONDS` | `86400` | Purge interval |

### Application packaging (optional)

| Variable | Default | Description |
|---|---|---|
| `INTUNEWIN_TOOL_PATH` | empty | Path to Microsoft's `IntuneWinAppUtil.exe` (Win32 Content Prep Tool), required by the packaging wizard |

## Vanitas server — `endpoint-agent/server/.env`

Template: [`endpoint-agent/server/.env.example`](../endpoint-agent/server/.env.example).

| Variable | Default | Description |
|---|---|---|
| `CA_KEY_PASSPHRASE` | — (required) | Encrypts the CA private key at rest. The most sensitive secret of the platform. |
| `SHELL_SESSION_TOKEN` | empty | Shared secret for dashboard-facing routes; every such route answers 401 while empty |
| `NVD_API_KEY` | empty | Optional NVD API key (faster CVE matching) |
| `CVE_REFRESH_INTERVAL_HOURS` | `12` | Background CVE matching interval |
| `HOST` | `127.0.0.1` | Listening interface of `scripts/run_server.py` |
| `PORT` | `8443` | Listening port |
| `ALEMBIC_DATABASE_URL` | — | Database URL override for Alembic tooling and tests |

## Vanitas agent

The agent reads `appsettings.json` (installed next to the executable) and environment variables
using the .NET convention `Agent__<Key>`. The MSI sets `Agent__ServerUrl` and
`Agent__EnrollmentToken` from its `SERVERURL` and `ENROLLMENTTOKEN` properties.

| Key | Default | Description |
|---|---|---|
| `ServerUrl` | `https://localhost:8443` | Vanitas server URL |
| `EnrollmentToken` | empty | One-time enrollment token (only used on first start) |
| `CollectionIntervalHours` | `6` | Inventory collection interval |
| `CommandPollIntervalMinutes` | `5` | How often pending commands are fetched |
| `ComplianceCheckIntervalHours` | `6` | Compliance rule execution interval |
| `ComplianceScriptTimeoutSeconds` | `60` | Timeout per compliance script |
| `ShellSessionPollIntervalSeconds` | `1` | Remote shell polling interval |
| `ShellSessionIdleTimeoutMinutes` | `15` | Idle remote shell sessions are closed after this delay |

## Local data files

Created automatically at runtime and excluded from Git:

| File | Content |
|---|---|
| `backend/data/auth_users.json`, `auth_sessions.json` | Accounts (Argon2 hashes) and active sessions |
| `backend/data/vanitas_profiles.json` | Vanitas permission profiles |
| `backend/data/history.json` | 90 days of daily metrics |
| `backend/data/watched_cves.json`, `app_library.json` | CVE watchlist and application library index |
| `backend/data/app_name_cache.json`, `vanitas_alert_state.json` | Regenerable caches |
| `endpoint-agent/server/data/` | Vanitas SQLite database, CA, uploaded installers |
