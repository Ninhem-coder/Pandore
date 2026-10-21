# Vanitas — self-hosted endpoint agent

Vanitas is the optional endpoint platform of [Pandore](../README.md): a Windows service
installed on each endpoint and a server that manages the fleet. The Pandore dashboard is its
user interface; the browser never talks to this server directly.

| Folder | Content |
|---|---|
| `server/` | FastAPI application (`app/`), SQLAlchemy models, Alembic migrations, admin scripts, pytest suite |
| `agent/EndpointAgent/` | .NET 8 Worker Service: inventory, compliance scripts, Windows updates, behavioural detection, command execution |
| `agent/EndpointAgent.Tests/` | xUnit tests for the agent |
| `agent/Installer/` | WiX Toolset 4 project producing `EndpointAgent.msi` |

## Design principles

- **Outbound only.** Agents poll the server; no inbound port is opened on endpoints.
- **Certificate identity.** Each agent gets its own client certificate from a private CA (mTLS)
  after a one-time enrollment token; the private key never leaves the endpoint.
- **Closed command catalog.** The server only accepts command types defined in
  `server/app/commands.py`. Installers and scripts are hash-checked before running as SYSTEM.
- **Local filtering.** Behavioural detection sends only events that match a rule.

## Getting started

Installation, CA creation, MSI build and enrollment are documented in
[docs/installation.md](../docs/installation.md#4-optional-set-up-vanitas). The architecture
(enrollment, command and detection flows) is described in
[docs/architecture.md](../docs/architecture.md#vanitas).

## Tests

```powershell
cd server
.\.venv\Scripts\python.exe -m pytest tests/ -q

cd ..\agent
dotnet test EndpointAgent.sln
```

## Development notes

The detailed milestone journal (in French) is in [MILESTONES.fr.md](MILESTONES.fr.md).
