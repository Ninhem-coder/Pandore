import { useState } from "react";
import { currentLocale, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

/** Building blocks shared by the French and English bodies of the Vanitas documentation
 * (VanitasDocsTab.jsx): table of contents, section/callout chrome and the illustrations
 * (rebuilt with the real page CSS classes — see `Illustration`). Labels go through `tr`. */
// Labels: vdoc.sec.<id> (getter added below), also used as each section's <h2>.
export const SECTIONS = [
  { id: "intro" },
  { id: "roles" },
  { id: "overview" },
  { id: "devices" },
  { id: "groups" },
  { id: "compliance" },
  { id: "vulnerabilities" },
  { id: "applications" },
  { id: "terminal" },
  { id: "activity" },
  { id: "alerts" },
  { id: "suspicious-activity" },
  { id: "glossary" },
];
for (const s of SECTIONS) {
  Object.defineProperty(s, "label", { get: () => tr(`vdoc.sec.${s.id}`), enumerable: true });
}

export function Section({ id, children }) {
  return (
    <section id={id} className="vanitas-docs-section">
      <h2>{tr(`vdoc.sec.${id}`)}</h2>
      <div className="vanitas-docs-body">{children}</div>
    </section>
  );
}

export function Callout({ tone = "warn", title, children }) {
  return (
    <div className={`vanitas-docs-callout tone-${tone}`}>
      <p className="vanitas-docs-callout-title">{title}</p>
      <div>{children}</div>
    </div>
  );
}

/** Illustration d'une section — PAS une capture d'écran (aucun outil de ce dashboard ne peut
 * enregistrer une capture en fichier image, constaté en essayant), mais une reconstitution
 * fidèle au pixel près des mêmes classes CSS que la vraie page (`.vanitas-hud-kpi`/
 * `.vanitas-hud-table`/`.vanitas-hud-status-pill`/`.vanitas-health-tile`/`.vanitas-detail-nav`...),
 * construite à partir de VRAIES valeurs observées sur un jeu de données de démonstration (3
 * postes fictifs enrôlés puis retirés, jamais le parc réel) plutôt que des chiffres inventés au
 * hasard. Se remet à jour toute seule avec le design du site (mêmes tokens, mêmes classes),
 * contrairement à une image figée qui se démoderait au prochain reskin. */
export function Illustration({ label, children }) {
  return (
    <div className="vanitas-docs-illustration">
      <div className="vanitas-docs-illustration-frame">{children}</div>
      <p className="vanitas-docs-illustration-caption">{label}</p>
    </div>
  );
}

export function OverviewPreview() {
  const tiles = [
    { label: tr("vdoc.ov.endpoints"), tag: "TOTAL", value: 3, sub: tr("vdoc.ov.online"), tone: "var(--hud-accent)" },
    { label: tr("vdoc.ov.suspicious"), tag: tr("vdoc.ov.untriaged"), value: 0, sub: tr("vdoc.ov.noHigh"), tone: "var(--hud-warn)" },
    { label: tr("vdoc.ov.silent"), tag: "< 12H", value: 0, sub: tr("vdoc.ov.threshold"), tone: "var(--hud-good)" },
    { label: tr("vdoc.ov.cert"), tag: tr("vdoc.ov.cert30"), value: 0, sub: tr("vdoc.ov.renewSoon"), tone: "var(--hud-good)" },
    { label: tr("vdoc.ov.eol"), tag: tr("vdoc.ov.fleet"), value: 3, sub: tr("vdoc.ov.eolSub"), tone: "var(--hud-warn)" },
    { label: tr("vdoc.ov.compliance"), tag: tr("vdoc.ov.rate"), value: "97%", sub: tr("vdoc.ov.compliantEvals"), tone: "var(--hud-good)" },
  ];
  return (
    <Illustration label={tr("vdoc.ov.caption")}>
      <div className="vanitas-hud-strip vanitas-docs-mini-strip">
        {tiles.map((t) => (
          <div className="vanitas-hud-kpi" style={{ "--tone": t.tone }} key={t.label}>
            <div className="label">
              {t.label}
              <span className="tag">{t.tag}</span>
            </div>
            <div className="value">{t.value}</div>
            <p className="vanitas-docs-illustration-caption" style={{ margin: "6px 0 0", textAlign: "left" }}>
              {t.sub}
            </p>
          </div>
        ))}
      </div>
    </Illustration>
  );
}

export function DevicesPreview() {
  const rows = [
    { host: "DEMO-WKS-01", os: tr("vdoc.win11"), state: tr("vdoc.online"), tone: "ok", cmd: tr("vdoc.cmd.diag") },
    { host: "DEMO-WKS-02", os: tr("vdoc.win11"), state: tr("vdoc.online"), tone: "ok", cmd: tr("vdoc.cmd.hw") },
    { host: "DEMO-SRV-01", os: "Windows Server 2019 Standard", state: tr("vdoc.silent"), tone: "bad", cmd: "—" },
  ];
  return (
    <Illustration label={tr("vdoc.dev.caption")}>
      <table className="vanitas-hud-table vanitas-docs-mini-table">
        <thead>
          <tr>
            <th>{tr("vdoc.col.endpoint")}</th>
            <th>{tr("vdoc.col.system")}</th>
            <th>{tr("vdoc.col.state")}</th>
            <th>{tr("vdoc.col.lastCmd")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.host}>
              <td className="vanitas-hud-host">
                <span className="name">{r.host}</span>
              </td>
              <td>{r.os}</td>
              <td>
                <span className={`vanitas-hud-status-pill ${r.tone}`}>{r.state}</span>
              </td>
              <td className="vanitas-hud-card-note">{r.cmd}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Illustration>
  );
}

/** Navigation de démonstration — mêmes libellés/groupes que `NAV_ITEMS` réel de
 * VanitasDeviceDetail.jsx, réduit aux 5 panes les plus représentatifs de la profondeur réelle
 * (11 panes au total : Vue d'ensemble, Système d'exploitation, Matériel, Identité & réseau,
 * Certificat & enrôlement, Vulnérabilités, Conformité, Activités suspectes, Applications,
 * Commandes, Terminal) plutôt que les 11, pour rester lisible dans le cadre de l'illustration. */
// Libellés : vdoc.dd.grp.<group> / vdoc.dd.<key>.
const DEVICE_PREVIEW_NAV = [
  { group: "system", items: ["os"] },
  { group: "security", items: ["cert", "suspicious"] },
  { group: "admin", items: ["terminal"] },
];

export function DeviceDetailPreview() {
  const [pane, setPane] = useState("overview");
  return (
    <Illustration label={tr("vdoc.dd.caption")}>
      <div className="vanitas-docs-mini-hero">
        <div>
          <p className="vanitas-docs-mini-card-title" style={{ marginBottom: 2 }}>
            DEMO-WKS-01
          </p>
          <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.heroSub")}</p>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button type="button" className="vanitas-danger-btn" disabled title={tr("vdoc.notClickable")}>
            {tr("vdoc.dd.uninstall")}
          </button>
          <button type="button" className="vanitas-danger-btn" disabled title={tr("vdoc.notClickable")}>
            {tr("vdoc.dd.remove")}
          </button>
        </div>
      </div>

      <div className="vanitas-health-strip vanitas-docs-mini-health-strip">
        <button
          type="button"
          className={`vanitas-health-tile${pane === "cert" ? " active" : ""}`}
          style={{ "--tile-accent": "var(--low)" }}
          onClick={() => setPane("cert")}
        >
          <div className="vanitas-health-label">{tr("vdoc.dd.certTile")}</div>
          <div className="vanitas-health-value low">{tr("vdoc.dd.days83")}</div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${pane === "suspicious" ? " active" : ""}`}
          style={{ "--tile-accent": "var(--amber, #e7a33c)" }}
          onClick={() => setPane("suspicious")}
        >
          <div className="vanitas-health-label">{tr("vdoc.dd.suspicious")}</div>
          <div className="vanitas-health-value" style={{ color: "var(--amber, #e7a33c)" }}>
            1
          </div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${pane === "os" ? " active" : ""}`}
          style={{ "--tile-accent": "var(--star)" }}
          onClick={() => setPane("os")}
        >
          <div className="vanitas-health-label">{tr("vdoc.dd.disk")}</div>
          <div className="vanitas-health-value star">61 %</div>
        </button>
        <button
          type="button"
          className={`vanitas-health-tile${pane === "terminal" ? " active" : ""}`}
          style={{ "--tile-accent": "var(--star)" }}
          onClick={() => setPane("terminal")}
        >
          <div className="vanitas-health-label">{tr("vdoc.dd.cmds7")}</div>
          <div className="vanitas-health-value star">4</div>
        </button>
      </div>

      <div className="vanitas-detail-layout vanitas-docs-mini-detail">
        <nav className="vanitas-detail-nav">
          <button
            type="button"
            className={`vanitas-detail-nav-item${pane === "overview" ? " active" : ""}`}
            onClick={() => setPane("overview")}
          >
            {tr("vdoc.dd.overview")}
          </button>
          {DEVICE_PREVIEW_NAV.map((g) => (
            <div key={g.group}>
              <div className="vanitas-detail-nav-group-label">{tr(`vdoc.dd.grp.${g.group}`)}</div>
              {g.items.map((item) => (
                <button
                  key={item}
                  type="button"
                  className={`vanitas-detail-nav-item${pane === item ? " active" : ""}`}
                  onClick={() => setPane(item)}
                >
                  {tr(`vdoc.dd.${item}`)}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="vanitas-detail-content">
          {pane === "overview" && (
            <div className="vanitas-docs-mini-groups">
              <div className="vanitas-hud-card vanitas-docs-mini-card">
                <p className="vanitas-docs-mini-card-title">{tr("vdoc.dd.identity")}</p>
                <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.identitySub")}</p>
              </div>
              <div className="vanitas-hud-card vanitas-docs-mini-card">
                <p className="vanitas-docs-mini-card-title">{tr("vdoc.dd.availability")}</p>
                <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.onlineNow")}</p>
              </div>
              <div className="vanitas-hud-card vanitas-docs-mini-card">
                <p className="vanitas-docs-mini-card-title">{tr("vdoc.dd.certTile")}</p>
                <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.certLeft")}</p>
              </div>
              <div className="vanitas-hud-card vanitas-docs-mini-card">
                <p className="vanitas-docs-mini-card-title">{tr("vdoc.dd.disk")}</p>
                <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.diskUsed")}</p>
              </div>
            </div>
          )}
          {pane === "os" && (
            <div className="vanitas-hud-card vanitas-docs-mini-card">
              <p className="vanitas-docs-mini-card-title">{tr("vdoc.win11")}</p>
              <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.build")}</p>
              <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.updates")}</p>
            </div>
          )}
          {pane === "cert" && (
            <div className="vanitas-hud-card vanitas-docs-mini-card">
              <p className="vanitas-docs-mini-card-title">{tr("vdoc.dd.certValid")}</p>
              <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.certRenew")}</p>
              <p className="vanitas-docs-mini-card-sub">{tr("vdoc.dd.certSubject")}</p>
            </div>
          )}
          {pane === "suspicious" && (
            <table className="vanitas-hud-table vanitas-docs-mini-table">
              <thead>
                <tr>
                  <th>{tr("vdoc.col.severity")}</th>
                  <th>{tr("vdoc.col.signal")}</th>
                  <th>{tr("vdoc.col.rule")}</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <span className="vanitas-hud-sev-pill high">{tr("vdoc.sev.high")}</span>
                  </td>
                  <td>{tr("vdoc.sig.process")}</td>
                  <td>
                    <div>{tr("vdoc.ex.certutil")}</div>
                    <div className="vanitas-hud-card-note" style={{ fontFamily: "var(--hud-mono)" }}>
                      process-lolbin-certutil-decode
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          )}
          {pane === "terminal" && (
            <div>
              <Callout tone="high" title={tr("vdoc.dd.termTitle")}>
                <p>{tr("vdoc.dd.termBody")}</p>
              </Callout>
              <div
                className="vanitas-docs-mini-card"
                style={{ marginTop: 10, fontFamily: "var(--hud-mono)", fontSize: 12, padding: "10px 14px" }}
              >
                <div>&gt; Get-Service WinDefend</div>
                <div style={{ color: "var(--hud-ink-faint)" }}>Status : Running</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </Illustration>
  );
}

export function GroupsPreview() {
  return (
    <Illustration label={tr("vdoc.gr.caption")}>
      <div className="vanitas-docs-mini-groups">
        <div className="vanitas-hud-card vanitas-docs-mini-card">
          <p className="vanitas-docs-mini-card-title">{tr("vdoc.gr.test")}</p>
          <p className="vanitas-docs-mini-card-sub">{tr("vdoc.gr.testSub")}</p>
        </div>
        <div className="vanitas-hud-card vanitas-docs-mini-card">
          <p className="vanitas-docs-mini-card-title">{tr("vdoc.gr.servers")}</p>
          <p className="vanitas-docs-mini-card-sub">{tr("vdoc.gr.serversSub")}</p>
        </div>
      </div>
      <div className="vanitas-hud-card vanitas-docs-mini-card" style={{ marginTop: 10 }}>
        <p className="vanitas-docs-mini-card-title">{tr("vdoc.gr.detail")}</p>
        <div className="vanitas-docs-mini-pills">
          <span className="vanitas-hud-status-pill ok">{tr("vdoc.gr.oneEndpoint")}</span>
          <span className="vanitas-hud-status-pill warn">{tr("vdoc.gr.avgVulns")}</span>
          <span className="vanitas-hud-status-pill bad">{tr("vdoc.gr.avgRisk")}</span>
        </div>
        <p className="vanitas-docs-mini-card-sub" style={{ marginTop: 8 }}>
          {tr("vdoc.gr.nested")}
        </p>
      </div>
    </Illustration>
  );
}

export function SuspiciousActivityPreview() {
  const rows = [
    { host: "DEMO-WKS-01", signal: tr("vdoc.sig.process"), tone: "high", summary: tr("vdoc.ex.certutil"), rule: "process-lolbin-certutil-decode" },
    { host: "DEMO-WKS-02", signal: tr("vdoc.sig.eventlog"), tone: "medium", summary: tr("vdoc.ex.rdp"), rule: "eventlog-rdp-off-hours" },
    { host: "DEMO-SRV-01", signal: tr("vdoc.sig.usb"), tone: "low", summary: tr("vdoc.ex.usb"), rule: "usb-volume-inserted" },
  ];
  return (
    <Illustration label={tr("vdoc.su.caption")}>
      <div className="strip vanitas-docs-mini-strip">
        <div className="strip-item c-high">
          <div className="strip-body">
            <div className="strip-label">{tr("vdoc.su.high")}</div>
            <div className="strip-value">1</div>
            <div className="strip-sub">{tr("vdoc.su.events")}</div>
          </div>
        </div>
        <div className="strip-item c-med">
          <div className="strip-body">
            <div className="strip-label">{tr("vdoc.su.med")}</div>
            <div className="strip-value">1</div>
            <div className="strip-sub">{tr("vdoc.su.events")}</div>
          </div>
        </div>
        <div className="strip-item c-low">
          <div className="strip-body">
            <div className="strip-label">{tr("vdoc.su.low")}</div>
            <div className="strip-value">1</div>
            <div className="strip-sub">{tr("vdoc.su.events")}</div>
          </div>
        </div>
      </div>
      <table className="vanitas-hud-table vanitas-docs-mini-table">
        <thead>
          <tr>
            <th>{tr("vdoc.col.severity")}</th>
            <th>{tr("vdoc.col.endpoint")}</th>
            <th>{tr("vdoc.col.signal")}</th>
            <th>{tr("vdoc.col.rule")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.host}>
              <td>
                <span className={`vanitas-hud-sev-pill ${r.tone}`}>{tr(`vdoc.sev.${r.tone}`)}</span>
              </td>
              <td className="vanitas-hud-host">
                <span className="name">{r.host}</span>
              </td>
              <td>{r.signal}</td>
              <td>
                <div>{r.summary}</div>
                <div className="vanitas-hud-card-note" style={{ fontFamily: "var(--hud-mono)" }}>
                  {r.rule}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Illustration>
  );
}

export function CompliancePreview() {
  return (
    <Illustration label={tr("vdoc.co.caption")}>
      <div className="vanitas-hud-card vanitas-docs-mini-card">
        <p className="vanitas-docs-mini-card-title">{tr("vdoc.co.rule")}</p>
        <div className="vanitas-docs-mini-pills">
          <span className="vanitas-hud-status-pill ok">{tr("vdoc.co.compliant")}</span>
          <span className="vanitas-hud-status-pill bad">{tr("vdoc.co.noncompliant")}</span>
          <span className="vanitas-hud-status-pill warn">{tr("vdoc.co.error")}</span>
        </div>
        <p className="vanitas-docs-mini-card-sub" style={{ marginTop: 8 }}>
          {trRich("vdoc.co.result", {
            expected: <span style={{ color: "var(--hud-good)" }}>{tr("vdoc.co.on")}</span>,
            actual: <span style={{ color: "var(--hud-high)" }}>{tr("vdoc.co.off")}</span>,
          })}
        </p>
      </div>
    </Illustration>
  );
}

export function EolPreview() {
  const rows = [
    { host: "DEMO-SRV-01", type: tr("vdoc.eol.os"), name: "Windows Server 2019 Standard", date: "2020-11-10", catalog: false },
    { host: "DEMO-SRV-01", type: ".NET Framework", name: ".NET Framework 4.5.2", date: "2022-04-26", catalog: false },
    { host: "DEMO-WKS-02", type: tr("vdoc.eol.software"), name: "Mozilla Firefox 118.0", date: "2023-10-24", catalog: true },
  ];
  return (
    <Illustration label={tr("vdoc.eol.caption")}>
      <table className="vanitas-hud-table vanitas-docs-mini-table">
        <thead>
          <tr>
            <th>{tr("vdoc.col.endpoint")}</th>
            <th>{tr("vdoc.col.type")}</th>
            <th>{tr("vdoc.col.software")}</th>
            <th>{tr("vdoc.col.eolDate")}</th>
            <th>{tr("vdoc.col.catalog")}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td className="vanitas-hud-host">
                <span className="name">{r.host}</span>
              </td>
              <td>{r.type}</td>
              <td>{r.name}</td>
              <td>
                <span className="vanitas-hud-status-pill bad">{new Date(`${r.date}T00:00:00`).toLocaleDateString(currentLocale())}</span>
              </td>
              <td>
                {r.catalog ? (
                  <button type="button" className="vanitas-ghost-btn" disabled title={tr("vdoc.notClickable")}>
                    {tr("vdoc.eol.update")}
                  </button>
                ) : (
                  "—"
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Illustration>
  );
}

export function ApplicationsPreview() {
  return (
    <Illustration label={tr("vdoc.ap.caption")}>
      <div className="vanitas-hud-card vanitas-docs-mini-card">
        <p className="vanitas-docs-mini-card-title">{tr("vdoc.ap.agent")}</p>
        <p className="vanitas-docs-mini-card-sub">{tr("vdoc.ap.agentSub")}</p>
      </div>
      <div className="vanitas-hud-card vanitas-docs-mini-card" style={{ marginTop: 10 }}>
        <p className="vanitas-docs-mini-card-title">{tr("vdoc.ap.deployment")}</p>
        <div className="vanitas-docs-mini-pills">
          <span className="vanitas-hud-status-pill ok">{tr("vdoc.ap.ok")}</span>
          <span className="vanitas-hud-status-pill bad">{tr("vdoc.ap.fail")}</span>
          <span className="vanitas-hud-status-pill warn">{tr("vdoc.ap.pending")}</span>
        </div>
      </div>
    </Illustration>
  );
}

export function ActivityPreview() {
  const rows = [
    { cat: "poste" },
    { cat: "application" },
    { cat: "conformite" },
    { cat: "groupe" },
  ];
  return (
    <Illustration label={tr("vdoc.ac.caption")}>
      <div className="vanitas-docs-mini-activity">
        {rows.map((r, i) => (
          <div className="vanitas-docs-mini-activity-row" key={i}>
            <span className={`vanitas-docs-mini-activity-tag tone-${r.cat}`}>{tr(`val.cat.${r.cat}`)}</span>
            <span>Nicolas {tr(`vdoc.ac.${r.cat}`)}</span>
          </div>
        ))}
      </div>
    </Illustration>
  );
}
