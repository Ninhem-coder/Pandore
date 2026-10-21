# Demo mode

The demo mode runs the dashboard **without a backend, a Microsoft 365 tenant or a Vanitas
server**. Every request is answered in the browser from a fictional, generated dataset. Use it to
discover the product, to work on the user interface, or to take screenshots.

```powershell
cd frontend
npm install
npm run demo        # http://localhost:5180
```

You are signed in automatically as `admin.demo`. A **"Mode démo · données fictives"** badge is
shown in the page header so that no screenshot can be mistaken for real data.

## What the data looks like

- ~130 Intune devices (`DEMO-WKS-001`, `DEMO-MAC-01`, `DEMO-MOB-01`, …), ~120 Defender machines,
  12 compliance policies, 46 alerts, ~300 CVEs, a 30-day Secure Score history and 90 days of
  daily metrics.
- 18 Vanitas agents with inventory, vulnerabilities, compliance rules, groups, update policies,
  suspicious events and an activity log.
- Users live on the reserved `demo.example` domain; every name and ID is generated.
- The dataset is **deterministic** (fixed seed): every launch shows the same fleet. Dates are
  relative to the current time, so the data always looks recent.
- `DEMO-WKS-007` is a showcase device: non-compliant, unencrypted, with active high-severity
  alerts.

## What works

All read-only pages render with data. Actions that would change something (create, edit,
delete, queue a command, upload, remote shell) answer with the backend's normal business error,
"Action non disponible en mode démo", and nothing is stored.

## How it works

| File | Role |
|---|---|
| `frontend/.env.demo` | Sets `VITE_DEMO=true` for `vite --mode demo` |
| `frontend/src/api.js` | When `DEMO_MODE` is true, routes every request to the demo backend instead of `fetch` |
| `frontend/src/demo/data.js` | Seeded generator of the fictional dataset |
| `frontend/src/demo/server.js` | Fake backend: one handler per API route, same JSON shapes as the real API |
| `frontend/src/demo/server.test.js` | Checks shapes, consistency and that only fictional data is served |

The demo module is loaded with a dynamic import inside a branch that is constant-false in a normal
build, so **`npm run build` does not include it**. `npm run build:demo` produces a static demo build
in `frontend/dist-demo/` that can be hosted on any static web server.

When you add a page or an API call, add the matching route to `demo/server.js` so the demo keeps
working; unknown routes return the business-error payload.

## Deep links (demo only)

In demo mode, `?page=<tab key>` opens a page directly, and `&device=<name>` opens a device page,
for example `http://localhost:5180/?page=device-overview&device=DEMO-WKS-007`. Tab keys are the
`key` values of `NAV_TREE` (`frontend/src/components/Sidebar.jsx`) and `VANITAS_NAV`
(`frontend/src/components/VanitasSidebar.jsx`). These parameters are ignored outside demo mode.

## Refreshing the README screenshots

With `npm run demo` running, on Windows:

```powershell
cd frontend
powershell -ExecutionPolicy Bypass -File scripts\capture-screenshots.ps1
```

The script drives Microsoft Edge in headless mode at 1440×900 and writes the images to
`docs/images/screenshots/`.
