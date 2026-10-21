# Installation

This guide installs Pandore step by step, then the optional Vanitas platform. Commands are
given for **Windows PowerShell** (the environment the project is developed and tested on). On
macOS or Linux, use `.venv/bin/python` instead of `.\.venv\Scripts\python.exe` and `cp`
instead of `copy`. The Vanitas **agent** is Windows-only.

1. [Create the Entra ID app registrations](#1-create-the-entra-id-app-registrations)
2. [Set up the Pandore backend](#2-set-up-the-pandore-backend)
3. [Set up the dashboard](#3-set-up-the-dashboard)
4. [(Optional) Set up Vanitas](#4-optional-set-up-vanitas)
5. [(Optional) Connect Claude Desktop](#5-optional-connect-claude-desktop)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

| Tool | Version | Used by |
|---|---|---|
| Python | **3.12** (tested). Python 3.15 failed to install `pyyaml`, a transitive dependency, for lack of prebuilt wheels. | Pandore backend, Vanitas server |
| Node.js | 22 LTS or newer (tested with 24 LTS) | Dashboard |
| .NET SDK | 8.0, on Windows | Vanitas agent and MSI (optional) |
| Microsoft 365 | Intune and Defender for Endpoint, an admin able to grant consent in Entra ID | Data sources |

> [!TIP]
> On Windows, the Python install manager can add a specific version next to another one:
> `py install 3.12`, then create virtual environments with `py -V:3.12 -m venv .venv`.

## 1. Create the Entra ID app registrations

Pandore reads data with **application permissions** (app-only, no user sign-in). The code uses
two app registrations — one for Microsoft Graph and one for Defender for Endpoint — but a single
registration holding both sets of permissions works as well if you put the same values in both
blocks of `.env`.

For each registration: **Entra ID → App registrations → New registration**, then
**Certificates & secrets → New client secret**, then **API permissions → Add a permission →
Application permissions**, and finally **Grant admin consent**.

**Microsoft Graph** (values `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`):

| Permission | Needed for |
|---|---|
| `DeviceManagementManagedDevices.Read.All` | Devices, detected apps, compliance reports |
| `DeviceManagementConfiguration.Read.All` | Compliance policies, configuration profiles |
| `DeviceManagementApps.Read.All` | Deployed apps, assignments, install status |
| `User.Read.All`, `Group.Read.All` | User and group names |
| `SecurityEvents.Read.All` | Microsoft Secure Score |

**WindowsDefenderATP** — under *APIs my organization uses* (values `MDE_TENANT_ID`,
`MDE_CLIENT_ID`, `MDE_CLIENT_SECRET`):

| Permission | Needed for |
|---|---|
| `Machine.Read.All` | Machines, exposure level, sensor health |
| `Alert.Read.All` (`Alert.ReadWrite.All` for the single-alert detail view) | Alerts |
| `AdvancedQuery.Read.All` | Advanced hunting (software inventory, vulnerabilities) |
| `Score.Read.All` | Exposure score |
| `SecurityRecommendation.Read.All` | Security recommendations |
| `Vulnerability.Read.All` | Vulnerabilities and CVE details |

> [!NOTE]
> These lists were derived from the API endpoints called by the code. If a page shows an
> empty list or a 403 error, check the permission first: an endpoint that has never been
> exercised on your tenant may simply lack consent.

**Optional — interactive (delegated) mode.** Set `AUTH_MODE=interactive` to sign in with a user
account instead of a secret. This needs a separate *public client* registration (redirect URI
`http://localhost` of type *Mobile and desktop applications*, "Allow public client flows" set to
Yes, the same permissions as **delegated** permissions). Put its tenant and client IDs in
`AZURE_TENANT_ID` / `AZURE_CLIENT_ID`.

## 2. Set up the Pandore backend

```powershell
cd backend
py -V:3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
```

Edit `backend/.env` and fill in the six Microsoft values. Everything else is optional — see
[configuration.md](configuration.md).

> [!TIP]
> `requirements.txt` uses minimum versions. For a reproducible install with the exact
> versions last tested, use `pip install -r requirements.lock` instead.

Create the first administrator account (the password is asked interactively and stored as an
Argon2 hash in `backend/data/auth_users.json`):

```powershell
.\.venv\Scripts\python.exe manage_users.py create alice admin
```

Other commands: `manage_users.py list`, `manage_users.py passwd <user>`,
`manage_users.py delete <user>`. Roles are `admin` and `viewer`.

Start the API:

```powershell
.\.venv\Scripts\python.exe api_server.py
```

It listens on `http://127.0.0.1:8000`. Check it with `http://127.0.0.1:8000/api/health` (the
only route, with login, that does not require a session).

Run the tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -q
```

The test suite imports the configuration, so it needs either a filled `backend/.env` or the six
`MDE_*` / `AZURE_*` variables set to any placeholder value; no test calls Microsoft.

## 3. Set up the dashboard

```powershell
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173> and sign in. During development Vite proxies `/api` to the backend
on port 8000, so both must run.

Other commands:

```powershell
npx vitest run      # unit tests
npx vite build      # production build into frontend/dist/
```

> [!TIP]
> If PowerShell blocks `npm` / `npx` ("running scripts is disabled on this system"), use
> `npm.cmd` / `npx.cmd`.

## 4. (Optional) Set up Vanitas

Vanitas has two parts: a **server** (any OS with Python) and an **agent** (Windows endpoints).

### 4.1 Server

```powershell
cd endpoint-agent\server
py -V:3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
```

In `endpoint-agent/server/.env`:

- set `CA_KEY_PASSPHRASE` to a strong passphrase;
- set `SHELL_SESSION_TOKEN` to a random value, for example
  `python -c "import secrets; print(secrets.token_urlsafe(32))"`;
- optionally set `NVD_API_KEY` (free, speeds up CVE matching).

Copy the **same** `SHELL_SESSION_TOKEN` value into `backend/.env` as `VANITAS_SHELL_TOKEN`.

Create the certificate authority and the server certificate (run once — the script refuses to
overwrite an existing CA unless you pass `--force`, which invalidates every issued
certificate):

```powershell
.\.venv\Scripts\python.exe scripts\generate_ca.py
```

Start the server (HTTPS on port 8443; the database is created and migrated automatically):

```powershell
.\.venv\Scripts\python.exe scripts\run_server.py
```

Restart the Pandore backend so it picks up `VANITAS_SHELL_TOKEN`. The Vanitas pages of the
dashboard should now load (with an empty fleet).

Run the server tests:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest tests/ -q
```

### 4.2 Agent and MSI

On a Windows machine with the .NET 8 SDK, from `endpoint-agent/agent/`:

```powershell
cd EndpointAgent
dotnet publish -c Release -r win-x64 -p:SelfContained=true -p:PublishSingleFile=true -o publish
cd ..\Installer
dotnet build
```

The MSI is written to `endpoint-agent/agent/Installer/bin/x64/Debug/EndpointAgent.msi`. Always
publish with `-o publish`: the installer packages that folder.

Optional code signing: `endpoint-agent/server/scripts/generate_codesign_cert.ps1` creates a
self-signed code-signing certificate. Deploy its public part to `Cert:\LocalMachine\Root` and
`Cert:\LocalMachine\TrustedPublisher` on target machines before a large deployment.

### 4.3 Enroll an endpoint

1. In the dashboard, open **Vanitas → Ajouter un poste** (*Add a device*) and generate a
   one-time enrollment token. Admins can also run
   `endpoint-agent/server/scripts/create_enrollment_token.py`.
2. Install the MSI on the endpoint (as administrator), for example:

   ```powershell
   msiexec /i EndpointAgent.msi ENROLLMENTTOKEN=<token> SERVERURL=https://<server>:8443 /qn
   ```

   The same command line works as an Intune Win32 app install command; the uninstall command
   is `msiexec /x EndpointAgent.msi /qn`.
3. The service starts, enrolls, and the device appears under **Vanitas → Postes** within
   seconds. Use one token per device; tokens are single-use.

> [!IMPORTANT]
> A change to the agent's code only takes effect after `dotnet publish`, rebuilding the MSI and
> reinstalling it on the endpoint.

## 5. (Optional) Connect Claude Desktop

Copy the two entries of [`backend/claude_mcp_config.example.json`](../backend/claude_mcp_config.example.json)
into Claude Desktop's configuration file (`claude_desktop_config.json`), replacing
`C:\\path\\to\\Pandore` with the location of this repository, then restart Claude Desktop. The
MCP servers read the same `backend/.env` as the API.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `pip install` fails building `pyyaml` or another package | Python version too recent; use Python 3.12. |
| Dashboard shows "Impossible de joindre l'API locale" | The backend is not running on port 8000. |
| A page shows an empty list or a 403 | Missing API permission or admin consent on the app registration. |
| Vanitas pages show "Serveur Vanitas injoignable" | Vanitas server stopped, wrong `VANITAS_SERVER_URL`, missing `ca.pem`, or token mismatch. |
| Vanitas server exits right after "Running upgrade" | Look at its log; a migration failed on the SQLite database. |
| `msiexec` returns error 1639 | Quote paths that contain spaces in the command line. |
