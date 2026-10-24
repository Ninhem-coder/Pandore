import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { IconDownload, IconShield } from "../components/icons.jsx";
import { exportConformiteToExcel } from "../export.js";
import {
  isErrorPayload,
  useVanitasAgents,
  useVanitasComplianceRules,
  useVanitasComplianceRulesSummary,
  useVanitasComplianceSummary,
} from "../hooks/useDashboardData.js";
import { ConfirmButton, VanitasWizardShell, fmtRelative } from "./vanitasShared.jsx";
import { getLang, localizedTable, tr } from "../i18n/core.js";
import { trRich } from "../i18n/rich.jsx";

// "Règles de conformité" (page d'Administration séparée) a été retirée le 2026-09-09 (demande
// de Nicolas — "on gère tout depuis Conformité") : `TEMPLATE` vit désormais ici, seul
// consommateur restant (repris tel quel, plus jamais dupliqué puisqu'il n'y a plus qu'un
// endroit où l'écrire).
const TEMPLATE = `# ── Contrat de conformité (lu par l'agent Vanitas) ──────────────────────────────
# Ce script DOIT se terminer par :
#   exit 0   -> poste CONFORME
#   exit 1   -> poste NON CONFORME (ou tout autre code non nul)
#
# Piège réel (confirmé en testant) : afficher une erreur (Write-Error, Write-Warning...)
# SANS appeler "exit" explicitement laisse le script CONFORME par défaut, même si un
# problème a bien été détecté. Toujours terminer par un "exit" explicite.
#
# Optionnel (2026-09-09, demande de Nicolas — "savoir pourquoi c'est pas conforme") : la
# dernière ligne de sortie peut être un objet JSON {"reason": "...", "expected": "...",
# "actual": "..."} pour afficher un détail structuré (attendu/obtenu) dans le dashboard au lieu
# du texte brut. Facultatif et rétrocompatible — un script qui n'émet que du texte libre
# continue de s'afficher exactement comme avant.

if ($true) {
    Write-Output "Vérification réussie"
    exit 0
} else {
    # Exemple de détail structuré (dernière ligne, JSON compact) :
    # Write-Output (@{reason="BitLocker désactivé sur C:"; expected="on"; actual="off"} | ConvertTo-Json -Compress)
    Write-Output "Problème détecté : ..."
    exit 1
}
`;
const TEMPLATE_EN = `# ── Compliance contract (read by the Vanitas agent) ─────────────────────────────
# This script MUST end with:
#   exit 0   -> endpoint COMPLIANT
#   exit 1   -> endpoint NON-COMPLIANT (or any other non-zero code)
#
# Real pitfall (confirmed by testing): printing an error (Write-Error, Write-Warning...)
# WITHOUT calling "exit" explicitly leaves the script COMPLIANT by default, even if a
# problem was detected. Always end with an explicit "exit".
#
# Optional: the last output line can be a JSON object {"reason": "...", "expected": "...",
# "actual": "..."} to show a structured detail (expected/actual) in the dashboard instead of
# the raw text. Optional and backward compatible — a script that only prints free text keeps
# displaying exactly as before.

if ($true) {
    Write-Output "Check passed"
    exit 0
} else {
    # Structured detail example (last line, compact JSON):
    # Write-Output (@{reason="BitLocker disabled on C:"; expected="on"; actual="off"} | ConvertTo-Json -Compress)
    Write-Output "Problem detected: ..."
    exit 1
}
`;

/** Script template in the current interface language. */
function template() {
  return getLang() === "fr" ? TEMPLATE : TEMPLATE_EN;
}

function stateLabel(compliant) {
  if (compliant === true) return tr("vc.compliant");
  if (compliant === false) return tr("vc.nonCompliant");
  return tr("vc.error");
}

function stateTone(compliant) {
  if (compliant === true) return "good";
  if (compliant === false) return "bad";
  return "warn";
}

function CompliancePill({ compliant }) {
  return <span className={`vanitas-hud-compliance-pill ${stateTone(compliant)}`}>{stateLabel(compliant)}</span>;
}

/**
 * Détail structuré optionnel (2026-09-09, demande de Nicolas — "savoir pourquoi c'est pas
 * conforme plutôt que d'avoir que la data conforme/non conforme") : un script peut émettre en
 * dernière ligne un objet JSON `{"reason","expected","actual"}` plutôt que du texte libre — voir
 * le commentaire ajouté au TEMPLATE plus haut dans ce fichier. Tente l'ensemble de
 * `detail` d'abord (script qui n'émet QUE du JSON), puis sa dernière ligne seule (script qui logue
 * du texte AVANT sa ligne JSON finale) — jamais d'exception remontée : un script qui n'émet que
 * du texte libre (l'écrasante majorité, y compris toute règle déjà en place aujourd'hui) retombe
 * simplement sur `null`, affiché tel quel comme avant ce jalon.
 */
function parseStructuredDetail(detail) {
  if (!detail) return null;
  // 🔧 Bug réel trouvé en testant (2026-09-09) : le filtre "a bien reason/expected/actual" ne
  // portait QUE sur la branche "dernière ligne" — un script émettant un JSON SANS RAPPORT
  // (ex. {"foo":"bar"}) comme SEULE sortie passait le premier `tryParse` tel quel, puis
  // `DetailCell` n'affichait plus rien du tout (ni raison ni pastilles, tous `undefined`)
  // plutôt que de retomber sur le texte brut. Le filtre s'applique maintenant aux DEUX
  // branches, jamais un JSON "inattendu" ne fait disparaître le détail silencieusement.
  function tryParse(text) {
    try {
      const obj = JSON.parse(text);
      if (obj && typeof obj === "object" && !Array.isArray(obj) && (obj.reason || obj.expected !== undefined || obj.actual !== undefined)) {
        return obj;
      }
      return null;
    } catch {
      return null;
    }
  }
  const trimmed = detail.trim();
  const whole = tryParse(trimmed);
  if (whole) return whole;
  const lines = trimmed.split("\n");
  const lastLine = lines[lines.length - 1]?.trim();
  if (lastLine && lastLine !== trimmed) {
    const parsed = tryParse(lastLine);
    if (parsed) return parsed;
  }
  return null;
}

/** Une ligne du tableau de détail d'une règle — texte brut si le script n'a rien de structuré à
 * offrir (comportement inchangé), sinon la raison + des pastilles attendu/obtenu. */
function DetailCell({ detail }) {
  const structured = parseStructuredDetail(detail);
  if (!structured) return detail || "—";
  return (
    <>
      {structured.reason && <div className="compliance-detail-reason">{structured.reason}</div>}
      {(structured.expected !== undefined || structured.actual !== undefined) && (
        <div className="compliance-detail-compare">
          {structured.expected !== undefined && <span className="compliance-cmp-tag">{tr("vc.expected", { value: String(structured.expected) })}</span>}
          {structured.actual !== undefined && (
            <span
              className={`compliance-cmp-tag ${
                structured.expected !== undefined
                  ? String(structured.actual) === String(structured.expected)
                    ? "actual-good"
                    : "actual-bad"
                  : ""
              }`}
            >
              {tr("vc.actual", { value: String(structured.actual) })}
            </span>
          )}
        </div>
      )}
    </>
  );
}

const CREATE_STEP_LABELS = localizedTable("vc.step", ["1", "2", "3"]);

/**
 * Assistant "Créer une règle" (2026-09-09, maquette validée par Nicolas — "on pourrait pas
 * mettre la possibilité d'ajouter des conformités via l'onglet des conformités direct avec un
 * bouton create") : création accessible directement depuis "Conformité" — la page
 * "Règles de conformité" (Administration) qui portait ce formulaire à l'origine a été retirée
 * le même jour ("on gère tout depuis Conformité"), cette page est donc désormais la SEULE
 * surface de gestion du catalogue (création ICI, activation/modification/suppression via
 * `RuleDetailModal` plus bas). Même endpoint (`createComplianceRule`), même invariant serveur
 * "toute règle créée repart désactivée" — non répété ici côté frontend, déjà appliqué par le
 * backend quel que soit l'appelant.
 */
function CreateRuleWizard({ onClose, onCreated }) {
  const [name, setName] = useState("");
  const [script, setScript] = useState(template);
  const [stepIdx, setStepIdx] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  function goTo(idx) {
    setStepIdx(Math.max(0, Math.min(idx, 2)));
  }

  function handleFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setScript(String(reader.result ?? ""));
    reader.readAsText(file);
  }

  async function handleCreate() {
    if (!name.trim() || !script.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.createComplianceRule(name.trim(), script);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        goTo(2);
        onCreated();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <VanitasWizardShell onClose={onClose}>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <IconShield />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{tr("vc.createTitle")}</h2>
          <p>{tr("vc.createSubtitle")}</p>
        </div>
      </div>

      <div className="vanitas-wiz-steps">
        {[1, 2, 3].map((n, i) => (
          <button
            type="button"
            key={n}
            className={`vanitas-wiz-step${i === stepIdx ? " active" : i < stepIdx ? " done" : ""}`}
            onClick={() => goTo(i)}
          >
            <span className="vanitas-wiz-step-idx">{n}</span>
            <span className="vanitas-wiz-step-lbl">{CREATE_STEP_LABELS[n]}</span>
          </button>
        ))}
      </div>

      <div className="vanitas-wiz-body">
        {stepIdx === 0 && (
          <>
            <div>
              <p className="filter-chip-group-label">{tr("vc.ruleName")}</p>
              <input
                className="filter-input"
                style={{ flex: "none", width: "100%" }}
                type="text"
                placeholder={tr("vc.ruleNamePlaceholder")}
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoFocus
              />
            </div>
            <p style={{ fontFamily: "var(--hud-sans)", fontSize: "12px", color: "var(--hud-ink-dim)", lineHeight: 1.6, margin: 0 }}>
              {trRich("vc.ruleExplain", { system: <b style={{ color: "var(--hud-ink)" }}>SYSTEM</b> })}
            </p>
            <div className="wizard-actions">
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!name.trim()} onClick={() => goTo(1)}>
                {tr("vc.next")}
              </button>
            </div>
          </>
        )}

        {stepIdx === 1 && (
          <>
            <div className="compliance-wiz-warn">
              {trRich("vc.exitWarn", {
                exit0: <code>exit 0</code>,
                exit1: <code>exit 1</code>,
                exit: <code>exit</code>,
                compliant: <b>{tr("vc.compliantUpper")}</b>,
              })}
            </div>
            <div>
              <p className="filter-chip-group-label">{tr("vc.psScript")}</p>
              <textarea className="vanitas-rule-script-input" value={script} onChange={(e) => setScript(e.target.value)} spellCheck={false} rows={14} disabled={busy} />
              <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "8px" }}>
                <label className="vanitas-rule-file-btn">
                  {tr("vc.dropPs1")}
                  <input type="file" accept=".ps1" onChange={handleFile} disabled={busy} hidden />
                </label>
              </div>
            </div>
            {error && <p className="error-note">{error}</p>}
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={() => goTo(0)} disabled={busy}>
                {tr("vc.back")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!script.trim() || busy} onClick={handleCreate}>
                {busy ? tr("vc.creating") : tr("vc.createRule")}
              </button>
            </div>
          </>
        )}

        {stepIdx === 2 && (
          <>
            <div className="vanitas-wiz-result-panel">
              <div className="vanitas-wiz-result-check">
                <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M4 10.5l4 4 8-9" />
                </svg>
              </div>
              <div className="vanitas-wiz-result-title">{tr("vc.created")}</div>
              <div style={{ fontFamily: "var(--hud-mono)", fontSize: "13px", color: "var(--hud-accent)" }}>{name}</div>
              <p className="vanitas-hud-empty-note" style={{ textAlign: "left" }}>
                {trRich("vc.createdNote", { disabled: <b style={{ color: "var(--hud-ink)" }}>{tr("vc.disabledWord")}</b> })}
              </p>
            </div>
            <div className="wizard-actions">
              <button type="button" className="vanitas-wiz-primary-btn" onClick={onClose}>
                {tr("vc.close")}
              </button>
            </div>
          </>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/** Décompte conformes / non conformes / erreur des résultats d'une règle. */
function ruleCounts(devices) {
  let ok = 0;
  let ko = 0;
  let err = 0;
  for (const d of devices) {
    if (d.compliant === true) ok++;
    else if (d.compliant === false) ko++;
    else err++;
  }
  return { ok, ko, err };
}

/**
 * Panneau de détail d'une règle (refonte liste + détail du 2026-10-23, maquette validée par
 * Nicolas — remplace la popup `RuleDetailModal`, même logique) : mini-KPI conformes/non
 * conformes/erreur, filtres par résultat + recherche par poste, tableau poste/statut/détail/
 * dernier contrôle. `devices` déjà en mémoire (dérivé de `byAgent`, voir plus bas) — aucun nouvel
 * appel réseau pour sélectionner une règle.
 *
 * SEULE surface de gestion du catalogue (2026-09-09, "on gère tout depuis Conformité") :
 * Activer/Désactiver, Modifier (éditeur en place), Supprimer. `script_content` n'est JAMAIS
 * chargé pour la simple consultation (raison de sécurité déjà documentée sur
 * `useVanitasComplianceRulesSummary` — ce champ transporte du code qui s'exécute en SYSTEM sur
 * tout le parc) : `useVanitasComplianceRules()` (catalogue complet) n'est sollicité qu'au clic
 * explicite sur "Modifier". `key={rule.id}` posé par l'appelant : changer de règle repart d'un
 * état propre (édition, filtres).
 */
function RuleDetailPanel({ rule, onChanged, onDeleted }) {
  const [query, setQuery] = useState("");
  const [resultFilter, setResultFilter] = useState("all");
  const [editing, setEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState(rule.name);
  const [scriptDraft, setScriptDraft] = useState("");
  const [scriptLoaded, setScriptLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const fullRules = useVanitasComplianceRules();

  useEffect(() => {
    if (!editing || scriptLoaded || fullRules.state.status !== "done") return;
    const full = fullRules.state.data.find((r) => r.id === rule.id);
    if (full) {
      setNameDraft(full.name);
      setScriptDraft(full.script_content);
      setScriptLoaded(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editing, scriptLoaded, fullRules.state.status, fullRules.state.data]);

  function startEditing() {
    setError(null);
    fullRules.ensureLoaded();
    setEditing(true);
  }
  function cancelEditing() {
    setEditing(false);
    setScriptLoaded(false);
    setError(null);
  }

  async function handleToggleEnabled() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updateComplianceRule(rule.id, { enabled: !rule.enabled });
      if (isErrorPayload(payload)) setError(payload.message);
      else onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveEdit() {
    if (!nameDraft.trim() || !scriptDraft.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.updateComplianceRule(rule.id, { name: nameDraft.trim(), scriptContent: scriptDraft });
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        setEditing(false);
        setScriptLoaded(false);
        onChanged();
        fullRules.refresh();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDelete() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.deleteComplianceRule(rule.id);
      if (isErrorPayload(payload)) {
        setError(payload.message);
        setBusy(false);
      } else {
        onDeleted();
      }
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  const counts = useMemo(() => ruleCounts(rule.devices), [rule.devices]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    // Non conformes puis erreurs puis conformes : ce qui demande une action en premier.
    const rank = (d) => (d.compliant === false ? 0 : d.compliant === true ? 2 : 1);
    return rule.devices
      .filter((d) => {
        if (resultFilter === "ko" && d.compliant !== false) return false;
        if (resultFilter === "ok" && d.compliant !== true) return false;
        if (resultFilter === "err" && (d.compliant === true || d.compliant === false)) return false;
        return !q || d.hostname.toLowerCase().includes(q);
      })
      .sort((a, b) => rank(a) - rank(b) || a.hostname.localeCompare(b.hostname));
  }, [rule.devices, query, resultFilter]);

  const hasStructured = useMemo(() => rule.devices.some((d) => parseStructuredDetail(d.detail)), [rule.devices]);

  return (
    <aside className="vcp-card vcp-detail" aria-label={tr("vc.detailAria")}>
      <div className="vcp-detail-head">
        <div className="vcp-detail-title">
          <h2>{rule.name}</h2>
          <span className="vcp-sub">
            {rule.devices.length > 0 ? tr("vc.evalSummary", { count: rule.devices.length }) : tr("vc.neverEvaluated")}
          </span>
        </div>
        <span className={`vcp-pill ${rule.enabled ? "on" : "off"}`}>{tr(rule.enabled ? "vc.enabled" : "vc.disabled")}</span>
      </div>

      {!editing && (
        <div className="vcp-actions">
          <button type="button" className="vanitas-queue-btn" onClick={handleToggleEnabled} disabled={busy}>
            {tr(rule.enabled ? "vc.disable" : "vc.enable")}
          </button>
          <button type="button" className="vanitas-ghost-btn" onClick={startEditing} disabled={busy}>
            {tr("vc.editScript")}
          </button>
          <ConfirmButton label={tr("vc.delete")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" onConfirm={handleDelete} disabled={busy} />
        </div>
      )}

      {!rule.enabled && !editing && (
        <div className="vcp-callout" role="note">
          <svg width="18" height="18" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden="true">
            <path d="M10 3l8 14H2z" />
            <path d="M10 8v4M10 14.5v.5" />
          </svg>
          <span>{tr("vc.disabledCallout")}</span>
        </div>
      )}

      {error && <p className="error-note">{error}</p>}

      {editing ? (
        !scriptLoaded ? (
          <p className="vanitas-hud-empty-note">{tr("vc.loadingScript")}</p>
        ) : (
          <div className="vcp-edit">
            <label className="vcp-lbl" htmlFor="vcp-rule-name">
              {tr("vc.name")}
            </label>
            <input id="vcp-rule-name" className="vcp-input" type="text" value={nameDraft} onChange={(e) => setNameDraft(e.target.value)} disabled={busy} />
            <label className="vcp-lbl" htmlFor="vcp-rule-script">
              {tr("vc.psScript")}
            </label>
            <textarea
              id="vcp-rule-script"
              className="vanitas-rule-script-input"
              value={scriptDraft}
              onChange={(e) => setScriptDraft(e.target.value)}
              spellCheck={false}
              rows={14}
              disabled={busy}
            />
            <span className="vcp-sub">{tr("vc.saveNote")}</span>
            <div className="vcp-actions vcp-actions-end">
              <button type="button" className="vanitas-ghost-btn" onClick={cancelEditing} disabled={busy}>
                {tr("vc.cancel")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" disabled={!nameDraft.trim() || !scriptDraft.trim() || busy} onClick={handleSaveEdit}>
                {busy ? tr("vc.saving") : tr("vc.save")}
              </button>
            </div>
          </div>
        )
      ) : rule.devices.length === 0 ? (
        <p className="vcp-empty">{rule.enabled ? tr("vc.noResultYet") : tr("vc.ruleDisabled")}</p>
      ) : (
        <>
          <div className="vcp-kpis">
            <div className="vcp-kpi">
              <span className="vcp-lbl">{tr("vc.compliantPl")}</span>
              <span className="vcp-val good">{counts.ok}</span>
            </div>
            <div className="vcp-kpi">
              <span className="vcp-lbl">{tr("vc.nonCompliantPl")}</span>
              <span className="vcp-val bad">{counts.ko}</span>
            </div>
            <div className="vcp-kpi">
              <span className="vcp-lbl">{tr("vc.error")}</span>
              <span className="vcp-val warn">{counts.err}</span>
            </div>
          </div>
          {hasStructured && (
            <p className="compliance-json-hint">
              <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M4 10.5l4 4 8-9" />
              </svg>
              {tr("vc.structuredHint")}
            </p>
          )}
          <div className="vcp-toolbar">
            <label className="vcp-search-wrap">
              <span className="vcp-sr">{tr("vc.filterEndpoint")}</span>
              <input type="search" className="vcp-search" placeholder={tr("vc.filterEndpoint")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
            <div className="vcp-chips" role="group" aria-label={tr("vc.resultFilterAria")}>
              {[
                ["all", tr("vc.allM")],
                ["ko", tr("vc.nonCompliantPl")],
                ["err", tr("vc.error")],
                ["ok", tr("vc.compliantPl")],
              ].map(([key, label]) => (
                <button key={key} type="button" className={`vcp-chip${resultFilter === key ? " on" : ""}`} aria-pressed={resultFilter === key} onClick={() => setResultFilter(key)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="vcp-table-wrap">
            <table className="compliance-detail-table">
              <thead>
                <tr>
                  <th>{tr("vc.col.endpoint")}</th>
                  <th>{tr("vc.col.status")}</th>
                  <th>{tr("vc.col.detail")}</th>
                  <th>{tr("vc.col.lastCheck")}</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((d) => (
                  <tr key={d.agentId}>
                    <td className="host">{d.hostname}</td>
                    <td>
                      <CompliancePill compliant={d.compliant} />
                    </td>
                    <td>
                      <DetailCell detail={d.detail} />
                    </td>
                    <td className="vanitas-hud-cmd-none">{d.collectedAt ? fmtRelative(d.collectedAt) : "—"}</td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={4} className="vanitas-hud-cmd-none" style={{ padding: "16px" }}>
                      {tr("vc.noFilterResult")}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </aside>
  );
}

/**
 * "Vanitas" > Conformité (jalon 11) — vue fleet-wide. Règles = scripts PowerShell fournis par
 * Nicolas, PAS des vérifications codées en dur — voir le `TEMPLATE` plus haut pour le contrat
 * exit-code/tri-état.
 *
 * Historique : 2026-09-09 (maquette validée) — liste COMPLÈTE des règles avec compteurs, table
 * des postes retirée, "+ Créer une règle" (`CreateRuleWizard`), page "Règles de conformité"
 * (Administration) retirée ("on gère tout depuis Conformité").
 *
 * Refonte liste + détail (2026-10-23, maquette canvas validée par Nicolas) : bandeau de synthèse
 * unique (taux, répartition des postes en une barre — y compris les postes "pas encore vérifiés",
 * déjà calculés mais jamais affichés —, règles actives), règles filtrables à gauche avec barre
 * empilée par règle, détail de la règle sélectionnée dans un panneau latéral (plus de popup).
 * Classes `.vcp-*`.
 *
 * Le détail par agent n'est PAS servi pour tous les postes d'un coup côté serveur — cette page
 * fait ses propres appels `api.vanitas.agentCompliance(id)` pour chaque agent connu, en état
 * LOCAL, proportionné à l'échelle de ce projet. `rules` transpose cette MÊME donnée par règle —
 * aucun nouvel appel réseau pour le détail d'une règle.
 */
export default function VanitasComplianceTab() {
  const agents = useVanitasAgents();
  const rulesSummary = useVanitasComplianceRulesSummary();
  const fleetSummary = useVanitasComplianceSummary();

  const [byAgent, setByAgent] = useState({}); // { [agentId]: { status, results, collected_at } }
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [ruleFilter, setRuleFilter] = useState("all");
  const [showCreateWizard, setShowCreateWizard] = useState(false);
  const detailRef = useRef(null);

  useEffect(() => {
    agents.ensureLoaded();
    rulesSummary.ensureLoaded();
    fleetSummary.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    for (const agent of agents.state.data ?? []) {
      if (byAgent[agent.id]) continue;
      setByAgent((prev) => ({ ...prev, [agent.id]: { status: "loading", results: [], collected_at: null } }));
      api.vanitas.agentCompliance(agent.id).then(
        (payload) => {
          if (isErrorPayload(payload)) {
            setByAgent((prev) => ({ ...prev, [agent.id]: { status: "error", results: [], collected_at: null } }));
          } else {
            setByAgent((prev) => ({
              ...prev,
              [agent.id]: { status: "done", results: payload.results, collected_at: payload.collected_at },
            }));
          }
        },
        () => setByAgent((prev) => ({ ...prev, [agent.id]: { status: "error", results: [], collected_at: null } }))
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.state.data]);

  const counts = useMemo(() => {
    const list = agents.state.data ?? [];
    let compliant = 0;
    let nonCompliant = 0;
    let notYetChecked = 0;
    for (const a of list) {
      const entry = byAgent[a.id];
      if (!entry || entry.status !== "done" || entry.results.length === 0) {
        notYetChecked++;
        continue;
      }
      const allGood = entry.results.every((r) => r.compliant === true);
      if (allGood) compliant++;
      else nonCompliant++;
    }
    return { total: list.length, compliant, nonCompliant, notYetChecked };
  }, [agents.state.data, byAgent]);

  // Taux = part des évaluations conformes, tous postes et toutes règles confondus — même calcul
  // que la tuile "Conformité" de la Vue d'ensemble (`GET /compliance/summary`, un seul appel).
  const complianceRate = useMemo(() => {
    let ok = 0;
    let total = 0;
    for (const r of fleetSummary.state.data ?? []) {
      ok += r.compliant_count ?? 0;
      total += (r.compliant_count ?? 0) + (r.non_compliant_count ?? 0) + (r.error_count ?? 0);
    }
    return total ? Math.round((ok / total) * 100) : null;
  }, [fleetSummary.state.data]);

  // Transpose `byAgent` (par poste) en règles (par règle) — même donnée déjà chargée, jamais un
  // 2e aller-retour réseau. Fusionné avec `rulesSummary` pour lister TOUTES les règles (activées
  // ou non), pas seulement celles qui ont déjà des résultats.
  const rules = useMemo(() => {
    const hostnameById = Object.fromEntries((agents.state.data ?? []).map((a) => [a.id, a.hostname]));
    const devicesByRule = {};
    for (const [agentId, entry] of Object.entries(byAgent)) {
      if (entry.status !== "done") continue;
      for (const r of entry.results) {
        (devicesByRule[r.rule_id] ??= []).push({
          agentId,
          hostname: hostnameById[agentId] ?? agentId,
          compliant: r.compliant,
          detail: r.detail,
          collectedAt: entry.collected_at,
        });
      }
    }
    return (rulesSummary.state.data ?? []).map((r) => {
      const devices = devicesByRule[r.id] ?? [];
      return { id: r.id, name: r.name, enabled: r.enabled, devices, counts: ruleCounts(devices) };
    });
  }, [rulesSummary.state.data, byAgent, agents.state.data]);

  const enabledRuleCount = rules.filter((r) => r.enabled).length;
  const failing = (r) => r.counts.ko + r.counts.err > 0;
  const ruleFilterCounts = {
    all: rules.length,
    on: enabledRuleCount,
    off: rules.length - enabledRuleCount,
    fail: rules.filter(failing).length,
  };

  // Règles en échec d'abord (le plus d'échecs en tête), puis par nom.
  const visibleRules = useMemo(
    () =>
      rules
        .filter((r) => (ruleFilter === "on" ? r.enabled : ruleFilter === "off" ? !r.enabled : ruleFilter === "fail" ? failing(r) : true))
        .sort((a, b) => b.counts.ko + b.counts.err - (a.counts.ko + a.counts.err) || a.name.localeCompare(b.name)),
    [rules, ruleFilter]
  );

  const selectedRule = visibleRules.find((r) => r.id === selectedRuleId) ?? visibleRules[0] ?? null;

  function selectRule(id) {
    setSelectedRuleId(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const [exportState, setExportState] = useState({ status: "idle", error: null });
  async function handleExport() {
    setExportState({ status: "exporting", error: null });
    try {
      await exportConformiteToExcel(rules);
      setExportState({ status: "idle", error: null });
    } catch (err) {
      setExportState({ status: "idle", error: err.message || tr("v.exportFailed") });
    }
  }

  const loading = agents.state.status === "loading";
  const error = agents.state.error || rulesSummary.state.error || fleetSummary.state.error;

  if (loading) {
    return (
      <div className="vanitas-hud vcp">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  const ringDash = complianceRate === null ? 0 : (complianceRate / 100) * 226.2;

  return (
    <div className="vanitas-hud vcp">
      {error && <p className="vanitas-hud-error">{error}</p>}

      <section className="vcp-card vcp-sum" aria-label={tr("vc.sumAria")}>
        <div className="vcp-sum-rate">
          <svg width="56" height="56" viewBox="0 0 84 84" aria-hidden="true">
            <circle cx="42" cy="42" r="36" fill="none" stroke="var(--hud-line)" strokeWidth="9" />
            <circle cx="42" cy="42" r="36" fill="none" stroke="var(--hud-good)" strokeWidth="9" strokeLinecap="round" strokeDasharray={`${ringDash} 226.2`} transform="rotate(-90 42 42)" />
          </svg>
          <div className="vcp-sum-col">
            <span className="vcp-lbl">{tr("vc.rate")}</span>
            <span className="vcp-val good">{complianceRate === null ? "—" : `${complianceRate} %`}</span>
            <span className="vcp-sub vcp-small">{tr("vc.rateSub")}</span>
          </div>
        </div>

        <div className="vcp-sum-fleet">
          <span className="vcp-lbl">{tr("vc.fleetSplit", { count: counts.total })}</span>
          <span
            className="vcp-sum-bar"
            role="img"
            aria-label={`${tr("vc.leg.compliant", { count: counts.compliant })}, ${tr("vc.leg.nonCompliant", { count: counts.nonCompliant })}, ${tr("vc.leg.unchecked", { count: counts.notYetChecked })}`}
          >
            <i className="good" style={{ flex: counts.compliant }} />
            <i className="bad" style={{ flex: counts.nonCompliant }} />
            <i className="none" style={{ flex: counts.notYetChecked }} />
          </span>
          <div className="vcp-legend">
            <span className="vcp-leg">
              <i className="good" />
              {tr("vc.leg.compliant", { count: counts.compliant })} <span className="vcp-sub">· {tr("vc.leg.compliantHint")}</span>
            </span>
            <button type="button" className="vcp-leg vcp-leg-btn" onClick={() => setRuleFilter("fail")}>
              <i className="bad" />
              {tr("vc.leg.nonCompliant", { count: counts.nonCompliant })} <span className="vcp-sub">· {tr("vc.leg.nonCompliantHint")}</span>
            </button>
            <span className="vcp-leg">
              <i className="none" />
              {tr("vc.leg.unchecked", { count: counts.notYetChecked })}
            </span>
          </div>
        </div>

        <div className="vcp-sum-col">
          <span className="vcp-lbl">{tr("vc.rulesActive")}</span>
          <span className="vcp-val accent">
            {enabledRuleCount} <small>/ {rules.length}</small>
          </span>
          {rules.length - enabledRuleCount > 0 && (
            <button type="button" className="vcp-leg vcp-leg-btn" onClick={() => setRuleFilter("off")}>
              <i className="none" />
              {tr("vc.disabledCount", { count: rules.length - enabledRuleCount })}
            </button>
          )}
        </div>
      </section>

      <div className="vcp-split">
        <section className="vcp-card vcp-rules" aria-label={tr("vc.rules")}>
          <div className="vcp-rules-head">
            <h2 className="vcp-h2">{tr("vc.rules")}</h2>
            <div className="vcp-actions">
              <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
                <IconDownload />
                {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
              </button>
              <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowCreateWizard(true)}>
                {tr("vc.newRule")}
              </button>
            </div>
          </div>
          {exportState.error && <p className="error-note" style={{ margin: 0 }}>{exportState.error}</p>}
          <div className="vcp-chips" role="group" aria-label={tr("vc.filterAria")}>
            {["all", "on", "off", "fail"].map((key) => (
              <button key={key} type="button" className={`vcp-chip${ruleFilter === key ? " on" : ""}`} aria-pressed={ruleFilter === key} onClick={() => setRuleFilter(key)}>
                {tr(`vc.filter.${key}`)} <b>{ruleFilterCounts[key]}</b>
              </button>
            ))}
          </div>
          {rules.length === 0 ? (
            <p className="vcp-empty">{tr("vc.noRule")}</p>
          ) : visibleRules.length === 0 ? (
            <p className="vcp-empty">{tr("vc.noFilterResult")}</p>
          ) : (
            <div className="vcp-rule-list">
              {visibleRules.map((r) => {
                const total = r.devices.length;
                const isSel = selectedRule?.id === r.id;
                return (
                  <button key={r.id} type="button" className={`vcp-rule${isSel ? " sel" : ""}`} aria-pressed={isSel} onClick={() => selectRule(r.id)}>
                    <span className="vcp-rule-name">{r.name}</span>
                    <span className={`vcp-pill ${r.enabled ? "on" : "off"}`}>{tr(r.enabled ? "vc.enabled" : "vc.disabled")}</span>
                    {total > 0 ? (
                      <>
                        <span className="vcp-stack" role="img" aria-label={tr("vc.stackAria", { ok: r.counts.ok, ko: r.counts.ko, err: r.counts.err })}>
                          <i className="good" style={{ flex: r.counts.ok }} />
                          <i className="bad" style={{ flex: r.counts.ko }} />
                          <i className="warn" style={{ flex: r.counts.err }} />
                        </span>
                        <span className="vcp-counts">
                          <span>{trRich("vc.cnt.ok", { count: r.counts.ok, n: <b className="good">{r.counts.ok}</b> })}</span>
                          {r.counts.ko > 0 && <span>{trRich("vc.cnt.ko", { count: r.counts.ko, n: <b className="bad">{r.counts.ko}</b> })}</span>}
                          {r.counts.err > 0 && <span>{trRich("vc.cnt.err", { count: r.counts.err, n: <b className="warn">{r.counts.err}</b> })}</span>}
                        </span>
                      </>
                    ) : (
                      <span className="vcp-counts">{tr("vc.neverRuns")}</span>
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vcp-detail-slot">
          {selectedRule ? (
            <RuleDetailPanel
              key={selectedRule.id}
              rule={selectedRule}
              onChanged={() => rulesSummary.refresh()}
              onDeleted={() => {
                setSelectedRuleId(null);
                rulesSummary.refresh();
              }}
            />
          ) : (
            <div className="vcp-card vcp-empty-panel">
              <p className="vcp-sub">{tr("vc.pickRule")}</p>
            </div>
          )}
        </div>
      </div>

      {showCreateWizard && (
        <CreateRuleWizard onClose={() => setShowCreateWizard(false)} onCreated={() => rulesSummary.refresh()} />
      )}
    </div>
  );
}
