# Security policy

Pandore reads security data from Microsoft 365, and Vanitas can execute commands as SYSTEM on
Windows endpoints. Security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report vulnerabilities privately with GitHub's **"Report a vulnerability"** button in the
repository's *Security* tab (private vulnerability reporting). Include:

- the affected component (backend, dashboard, Vanitas server, agent, installer);
- the version or commit;
- steps to reproduce or a proof of concept;
- the impact you expect.

Do not include real credentials, tenant identifiers or personal data in the report.

You can expect an acknowledgment within a few days. Fixes are released as soon as practical,
and reporters are credited in the release notes unless they prefer otherwise.

## Supported versions

Only the latest state of the default branch receives security fixes.

## Scope

In scope: authentication and authorization of the Pandore API, the server-to-server link to
Vanitas, Vanitas enrollment, mTLS and certificate handling, the command channel, installer and
script integrity checks, injection (OData, KQL, HTML) and secret handling.

Out of scope: vulnerabilities in Microsoft services, issues that require an already compromised
administrator account or endpoint, and findings from automated scanners without a demonstrated
impact.

## Hardening guidance for operators

- Keep `backend/.env` and `endpoint-agent/server/.env` private; rotate the Microsoft client
  secrets if they may have been exposed.
- Keep the Pandore API on `127.0.0.1` (the default) unless you add HTTPS and network
  restrictions; set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- Protect `endpoint-agent/server/data/ca/` and `CA_KEY_PASSPHRASE`: together they allow
  issuing agent certificates. Regenerate the CA if you suspect a leak.
- Use a long random `SHELL_SESSION_TOKEN`; the Vanitas server denies dashboard requests when it
  is empty.
- Grant only the API permissions listed in [docs/installation.md](docs/installation.md), and only
  give Vanitas write rights (terminal, applications) to accounts that need them.
