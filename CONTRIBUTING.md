# Contributing to Pandore

Thank you for your interest in Pandore. Bug reports, documentation fixes and code contributions
are all welcome. By participating you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

- [Ways to contribute](#ways-to-contribute)
- [Development setup](#development-setup)
- [Running the checks](#running-the-checks)
- [Coding conventions](#coding-conventions)
- [Pull requests](#pull-requests)
- [License](#license)

## Ways to contribute

- **Report a bug** with the bug report template. Include versions, the page or API route, and
  what you expected. Never paste secrets, tenant IDs, device names or user names.
- **Suggest a feature** with the feature request template; explain the problem first.
- **Improve the documentation**, including translating the user interface (currently French).
- **Report a vulnerability privately** — see [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

Follow [docs/installation.md](docs/installation.md). In short:

```powershell
# Backend
cd backend
py -V:3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Dashboard
cd ..\frontend
npm install

# Vanitas server (optional)
cd ..\endpoint-agent\server
py -V:3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-dev.txt
```

You do not need a Microsoft 365 tenant to run the tests. For user-interface work, the
[demo mode](docs/demo.md) (`npm run demo`) runs the dashboard with fictional data and no
backend. A tenant (ideally a test tenant) is only needed to check behaviour against real data.

If you add an API call to the dashboard, add the matching route to `frontend/src/demo/server.js`
so the demo keeps working. Never use real tenant data in the demo dataset or in screenshots.

## Running the checks

Run the checks of every part you touched before opening a pull request:

| Part | Command (from its folder) |
|---|---|
| Backend | `.\.venv\Scripts\python.exe -m pytest tests/ -q` (needs `backend/.env` or placeholder `MDE_*` / `AZURE_*` variables) |
| Dashboard | `npx vitest run` and `npx vite build` |
| Vanitas server | `.\.venv\Scripts\python.exe -m pytest tests/ -q` |
| Vanitas agent | `dotnet test EndpointAgent.sln` (in `endpoint-agent/agent`, Windows) |

The same checks (except the agent) run in GitHub Actions on every pull request.

## Coding conventions

The most important rules; the architecture page explains the reasons.

**Backend (Python)**

- Business functions live in their domain module (`intune/`, `defender/`, `vanitas/`) and are
  decorated with `@handle_tool_errors`. Add the REST route in the matching `routers/<domain>.py`
  — never directly in `api_server.py`.
- A new public function must be registered in the domain's `mcp_server.py` (`_TOOLS`) or listed
  in `EXCLUDED_FROM_MCP` with a reason; `tests/test_mcp_tool_parity.py` enforces it.
- Business errors are returned with HTTP 200 as `{"error": true, ...}` (or a one-item list).
  Raise `ValueError` for business errors; `RuntimeError` is reserved for authentication failures.
- Validate any external ID before using it in a Graph URL (`validate_graph_id`, `IdPath`) and
  escape user input in OData filters and KQL queries.
- For Intune data, prefer the reporting endpoints (`POST /deviceManagement/reports/...`) — see
  [Microsoft Graph pitfalls](docs/architecture.md#microsoft-graph-pitfalls).
- Never hard-code a secret. Configuration goes through environment variables, documented in
  `.env.example` and [docs/configuration.md](docs/configuration.md).

**Dashboard (React)**

- Plain JavaScript and React function components; no TypeScript.
- Expensive data gets its own on-demand hook; never add it to `useDashboardData`.
- Check API responses with `isErrorPayload` / `listPayloadError` (errors arrive with HTTP 200).
- `styles.css` is large: search for a selector before adding a rule, and scope new rules to the
  page or component so they cannot override other pages.
- Colours, fonts and radii come from tokens (`:root` in `styles.css`, `theme.js`); follow the
  brand guidelines in `Design/`.

**Vanitas server**

- Schema changes go through Alembic: change `app/models.py`, then
  `.\.venv\Scripts\python.exe -m alembic revision --autogenerate -m "describe change"`, review the
  generated file, and make it safe on both a fresh and an existing database.

**Language**

- Much of the existing code is commented in French. New code, comments, commit messages and
  documentation should be in **English**.

## Pull requests

1. Create a branch from the default branch.
2. Keep changes focused; separate refactoring from behaviour changes.
3. Add or update tests for behaviour changes.
4. Update the documentation and `CHANGELOG.md` (section *Unreleased*) when users are affected.
5. Fill in the pull request template, including how you tested.

## License

Pandore is released under the [MIT License](LICENSE). By submitting a contribution, you agree
that it is licensed under the same terms.
