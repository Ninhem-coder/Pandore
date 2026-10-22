import { useEffect, useMemo, useState } from "react";
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

/**
 * Popup de détail d'une règle (2026-09-09, retour de Nicolas — "on pourrait pas juste mettre
 * les conformités [...] et le nombre réussi/échec et quand on clique dessus ça ouvre une page
 * avec les informations, les appareils et s'ils ont réussi ou quoi") : mini-KPI conformes/non
 * conformes/erreur, recherche par poste, tableau poste/statut/détail/dernier contrôle. `devices`
 * déjà en mémoire (dérivé de `byAgent`, voir plus bas) — aucun nouvel appel réseau pour ouvrir
 * cette popup.
 *
 * Gagne Activer/Désactiver/Modifier/Supprimer le même jour (retour de Nicolas — "supprime
 * Règles de conformité vu qu'on gère tout depuis Conformité") : cette popup devient la SEULE
 * surface de gestion du catalogue, plus seulement de consultation — la page "Règles de
 * conformité" (Administration) qui portait ces actions est retirée avec ce changement.
 * `script_content` n'est JAMAIS chargé pour la simple consultation (raison de sécurité déjà
 * documentée sur `useVanitasComplianceRulesSummary` — ce champ transporte du code qui
 * s'exécute en SYSTEM sur tout le parc) : `useVanitasComplianceRules()` (catalogue complet)
 * n'est sollicité qu'au clic explicite sur "Modifier", jamais à l'ouverture de la popup.
 */
function RuleDetailModal({ rule, onClose, onChanged }) {
  const [query, setQuery] = useState("");
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
      } else {
        onChanged();
        onClose();
      }
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  const counts = useMemo(() => {
    let compliant = 0;
    let nonCompliant = 0;
    let error = 0;
    for (const d of rule.devices) {
      if (d.compliant === true) compliant++;
      else if (d.compliant === false) nonCompliant++;
      else error++;
    }
    return { compliant, nonCompliant, error };
  }, [rule.devices]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return rule.devices;
    return rule.devices.filter((d) => d.hostname.toLowerCase().includes(q));
  }, [rule.devices, query]);

  const hasStructured = useMemo(() => rule.devices.some((d) => parseStructuredDetail(d.detail)), [rule.devices]);

  return (
    <VanitasWizardShell onClose={onClose} wide>
      <div className="vanitas-wiz-header">
        <div className="vanitas-wiz-header-icon">
          <IconShield />
        </div>
        <div className="vanitas-wiz-header-text">
          <h2>{rule.name}</h2>
          <p>
            {tr(rule.enabled ? "vc.enabled" : "vc.disabled")}
            {rule.devices.length > 0 ? tr("vc.evaluated", { count: rule.devices.length }) : tr("vc.notEvaluated")}
          </p>
        </div>
      </div>
      <div className="vanitas-wiz-body">
        {!editing && (
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <button type="button" className="vanitas-queue-btn" onClick={handleToggleEnabled} disabled={busy}>
              {tr(rule.enabled ? "vc.disable" : "vc.enable")}
            </button>
            <button type="button" className="vanitas-queue-btn" onClick={startEditing} disabled={busy}>
              {tr("vc.edit")}
            </button>
            <ConfirmButton label={tr("vc.delete")} confirmLabel={tr("v.confirm")} className="vanitas-danger-btn" onConfirm={handleDelete} disabled={busy} />
          </div>
        )}

        {error && <p className="error-note">{error}</p>}

        {editing ? (
          !scriptLoaded ? (
            <p className="vanitas-hud-empty-note">{tr("vc.loadingScript")}</p>
          ) : (
            <>
              <div>
                <p className="filter-chip-group-label">{tr("vc.name")}</p>
                <input className="filter-input" style={{ flex: "none", width: "100%" }} type="text" value={nameDraft} onChange={(e) => setNameDraft(e.target.value)} disabled={busy} />
              </div>
              <div>
                <p className="filter-chip-group-label">{tr("vc.psScript")}</p>
                <textarea className="vanitas-rule-script-input" value={scriptDraft} onChange={(e) => setScriptDraft(e.target.value)} spellCheck={false} rows={14} disabled={busy} />
              </div>
              <div className="wizard-actions">
                <button type="button" className="vanitas-ghost-btn" onClick={cancelEditing} disabled={busy}>
                  {tr("vc.cancel")}
                </button>
                <button type="button" className="vanitas-wiz-primary-btn" disabled={!nameDraft.trim() || !scriptDraft.trim() || busy} onClick={handleSaveEdit}>
                  {busy ? tr("vc.saving") : tr("vc.save")}
                </button>
              </div>
            </>
          )
        ) : (
          <>
            {rule.devices.length === 0 ? (
              <p className="vanitas-hud-empty-note">
                {rule.enabled
                  ? tr("vc.noResultYet")
                  : tr("vc.ruleDisabled")}
              </p>
            ) : (
              <>
                <div className="compliance-detail-kpis">
                  <div className="compliance-detail-kpi good">
                    <div className="lbl">{tr("vc.compliantPl")}</div>
                    <div className="val">{counts.compliant}</div>
                  </div>
                  <div className="compliance-detail-kpi bad">
                    <div className="lbl">{tr("vc.nonCompliantPl")}</div>
                    <div className="val">{counts.nonCompliant}</div>
                  </div>
                  {counts.error > 0 && (
                    <div className="compliance-detail-kpi warn">
                      <div className="lbl">{tr("vc.error")}</div>
                      <div className="val">{counts.error}</div>
                    </div>
                  )}
                </div>
                {hasStructured && (
                  <p className="compliance-json-hint">
                    <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M4 10.5l4 4 8-9" />
                    </svg>
                    {tr("vc.structuredHint")}
                  </p>
                )}
                <div className="vanitas-hud-search">
                  <span className="prompt">&gt;</span>
                  <input type="text" placeholder={tr("vc.filterEndpoint")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
                </div>
                <div className="compliance-detail-table-wrap">
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
            <div className="wizard-actions">
              <button type="button" className="vanitas-ghost-btn" onClick={onClose}>
                {tr("vc.close")}
              </button>
            </div>
          </>
        )}
      </div>
    </VanitasWizardShell>
  );
}

/**
 * "Vanitas" > Conformité (jalon 11) — vue fleet-wide, identité HUD déjà établie (`.vanitas-hud`,
 * mêmes classes que "Vue d'ensemble"/"Postes"). Règles = scripts PowerShell fournis par
 * Nicolas, PAS des vérifications codées en dur — voir le `TEMPLATE` plus haut pour le contrat
 * exit-code/tri-état.
 *
 * Redessinée le 2026-09-09 (maquette validée par Nicolas) — quatre retours successifs :
 * 1. "Règles en échec" (classement par impact) → liste COMPLÈTE des règles (activées ou non)
 *    avec leurs compteurs réussi/échec directement visibles, clic → popup de détail par poste.
 * 2. Table des postes en bas de page retirée ("elle sert à rien on l'a dans les conformités") —
 *    son contenu est maintenant équivalent, transposé par règle plutôt que par poste.
 * 3. Bouton "+ Créer une règle" (popup 3 étapes, `CreateRuleWizard`) directement sur cette page.
 * 4. La page "Règles de conformité" (Administration, `VanitasComplianceRulesTab.jsx`) est
 *    RETIRÉE ("on gère tout depuis Conformité") — ses capacités de gestion (activer/désactiver/
 *    modifier/supprimer) ont été migrées dans `RuleDetailModal` ci-dessus, qui devient la SEULE
 *    surface d'administration du catalogue.
 *
 * Le détail par agent (`byAgent`, `useKeyedFetch` PAS utilisé ici) n'est PAS assez pour peupler
 * un TABLEAU de tous les postes d'un coup (il faut le résultat de CHAQUE agent, pas un seul à la
 * fois) — cette page fait donc ses propres appels `api.vanitas.agentCompliance(id)` pour chaque
 * agent connu, en état LOCAL, proportionné à l'échelle de ce projet (une poignée d'agents,
 * jamais des centaines). `byRule` (nouveau) transpose cette MÊME donnée par règle plutôt que par
 * poste — aucun nouvel appel réseau pour le popup de détail par règle.
 */
export default function VanitasComplianceTab() {
  const agents = useVanitasAgents();
  const rulesSummary = useVanitasComplianceRulesSummary();
  const fleetSummary = useVanitasComplianceSummary();

  const [byAgent, setByAgent] = useState({}); // { [agentId]: { status, results, collected_at } }
  const [selectedRuleId, setSelectedRuleId] = useState(null);
  const [showCreateWizard, setShowCreateWizard] = useState(false);

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

  const enabledRuleCount = (rulesSummary.state.data ?? []).filter((r) => r.enabled).length;

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

  // Transpose `byAgent` (par poste) en `byRule` (par règle) — même donnée déjà chargée, jamais
  // un 2e aller-retour réseau. Fusionné avec `rulesSummary` pour lister TOUTES les règles
  // (activées ou non), pas seulement celles qui ont déjà des résultats.
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
    return (rulesSummary.state.data ?? []).map((r) => ({
      id: r.id,
      name: r.name,
      enabled: r.enabled,
      devices: devicesByRule[r.id] ?? [],
    }));
  }, [rulesSummary.state.data, byAgent, agents.state.data]);

  const selectedRule = selectedRuleId ? rules.find((r) => r.id === selectedRuleId) ?? null : null;

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
      <div className="vanitas-hud">
        <p className="vanitas-hud-empty-note">{tr("v.loading")}</p>
      </div>
    );
  }

  return (
    <div className="vanitas-hud">
      {error && <p className="vanitas-hud-error">{error}</p>}

      <div className="vanitas-hud-strip">
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent)" }}>
          <div className="label">
            {tr("vc.kpi.endpoints")}
            <span className="tag">{tr("vc.kpi.total")}</span>
          </div>
          <div className="value">{counts.total}</div>
          <div className="bar">
            <i style={{ width: "100%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-good)" }}>
          <div className="label">
            {tr("vc.kpi.compliant")}
            <span className="tag">100%</span>
          </div>
          <div className="value">{counts.compliant}</div>
          <div className="bar">
            <i style={{ width: counts.total ? `${Math.round((counts.compliant / counts.total) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-high)" }}>
          <div className="label">
            {tr("vc.kpi.nonCompliant")}
            <span className="tag">≥ 1</span>
          </div>
          <div className="value">{counts.nonCompliant}</div>
          <div className="bar">
            <i style={{ width: counts.total ? `${Math.round((counts.nonCompliant / counts.total) * 100)}%` : "0%" }} />
          </div>
        </div>
        <div className="vanitas-hud-kpi vanitas-hud-frame" style={{ "--tone": "var(--hud-accent2)" }}>
          <div className="label">
            {tr("vc.kpi.rules")}
            <span className="tag">{tr("vc.kpi.active")}</span>
          </div>
          <div className="value">{enabledRuleCount}</div>
          <div className="bar">
            <i style={{ width: enabledRuleCount ? "100%" : "0%" }} />
          </div>
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>{tr("vc.rules")}</h2>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <span className="vanitas-hud-card-note">{tr("vc.clickDetail")}</span>
            <button type="button" className="vanitas-export-btn" onClick={handleExport} disabled={exportState.status === "exporting"}>
              <IconDownload />
              {exportState.status === "exporting" ? tr("v.exporting") : tr("v.exportExcel")}
            </button>
            <button type="button" className="vanitas-wiz-primary-btn" onClick={() => setShowCreateWizard(true)}>
              {tr("vc.newRule")}
            </button>
          </div>
        </div>
        {exportState.error && <p className="error-note" style={{ margin: "0 0 12px" }}>{exportState.error}</p>}
        {rules.length === 0 ? (
          <p className="vanitas-hud-empty-note">{tr("vc.noRule")}</p>
        ) : (
          <div>
            {rules.map((r) => {
              const compliantCount = r.devices.filter((d) => d.compliant === true).length;
              const nonCompliantCount = r.devices.filter((d) => d.compliant === false).length;
              const errorCount = r.devices.filter((d) => d.compliant !== true && d.compliant !== false).length;
              return (
                <div className="compliance-rule-row" key={r.id} onClick={() => setSelectedRuleId(r.id)}>
                  <div className="compliance-rule-main">
                    <span className="compliance-rule-name">{r.name}</span>
                    <span className={`compliance-rule-badge ${r.enabled ? "on" : "off"}`}>{tr(r.enabled ? "vc.enabled" : "vc.disabled")}</span>
                  </div>
                  {r.devices.length > 0 ? (
                    <div className="compliance-rule-counts">
                      <span className="good">✓ {compliantCount}</span>
                      {nonCompliantCount > 0 && <span className="bad">✗ {nonCompliantCount}</span>}
                      {errorCount > 0 && <span className="warn">⚠ {errorCount}</span>}
                    </div>
                  ) : (
                    <span className="compliance-rule-none">{tr("vc.notEvaluatedShort")}</span>
                  )}
                  <span className="vanitas-hud-chev">›</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {selectedRule && (
        <RuleDetailModal rule={selectedRule} onClose={() => setSelectedRuleId(null)} onChanged={() => rulesSummary.refresh()} />
      )}
      {showCreateWizard && (
        <CreateRuleWizard onClose={() => setShowCreateWizard(false)} onCreated={() => rulesSummary.refresh()} />
      )}
    </div>
  );
}
