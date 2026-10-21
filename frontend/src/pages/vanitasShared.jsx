import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api } from "../api.js";
import { isErrorPayload } from "../hooks/useDashboardData.js";

// Durée de vie d'un certificat agent (jalon 3, server/app/ca.py) — partagée entre la liste
// (VanitasDevicesTab.jsx) et la fiche poste (VanitasDeviceDetail.jsx), d'où cette extraction.
export const CERT_VALIDITY_DAYS = 90;

// Seuils partagés "poste à surveiller" (jalon 8 pour Postes, jalon HUD 2026-09-06 pour la Vue
// d'ensemble — la même définition de "certificat qui expire bientôt"/"poste silencieux" doit
// donner les mêmes comptes sur les deux pages, jamais deux seuils qui divergent en silence).
export const CERT_WARNING_DAYS = 30;
export const STALE_HOURS = 24 * 7;

// Barre segmentée de validité du certificat (jalon 8, `VanitasDevicesTab.jsx`) — extraite ici
// le 2026-09-06 pour être réutilisée telle quelle par "Prochaines expirations" de la Vue
// d'ensemble, plutôt que dupliquée : même donnée (jours restants), même échelle
// (CERT_VALIDITY_DAYS), même code couleur — un vrai composant partagé, pas juste un mécanisme
// qui se ressemble.
const CERT_SEG_COUNT = 12;

export function certTone(days) {
  if (days === null) return "neutral";
  if (days < 0) return "high";
  if (days < CERT_WARNING_DAYS) return "warn";
  return "good";
}

export function toneVar(tone) {
  if (tone === "high") return "var(--hud-high)";
  if (tone === "warn") return "var(--hud-warn)";
  if (tone === "good") return "var(--hud-good)";
  return "var(--hud-ink-faint)";
}

export function CertSegBar({ days, segments = CERT_SEG_COUNT }) {
  const pct = days === null ? 0 : Math.max(0, Math.min(1, days / CERT_VALIDITY_DAYS));
  const lit = Math.round(pct * segments);
  const tone = toneVar(certTone(days));
  return (
    <div className="vanitas-hud-seg-row" style={{ "--tone": tone }}>
      {Array.from({ length: segments }, (_, i) => (
        <div key={i} className={`vanitas-hud-seg${i < lit ? " lit" : ""}`} />
      ))}
    </div>
  );
}

/**
 * Profils Vanitas (2026-09-10, demande de Nicolas — "comme dans Intune... un read pour voir et
 * un read-write pour lecture-écriture"). `VANITAS_MODULES` reflète EXACTEMENT
 * `backend/auth/vanitas_profiles.py::MODULES` — 5 fonctionnalités avec une vraie distinction
 * lecture/écriture (voir la maquette validée). `hasVanitasAccess(user, module, level)` est la
 * SEULE fonction de résolution de permission côté frontend — jamais une 2e copie de cette
 * logique ailleurs (VanitasSidebar.jsx/VanitasDeviceDetail.jsx la réutilisent telle quelle) —
 * miroir de `auth/vanitas_profiles.py::has_access` : un admin a toujours accès à tout, un
 * compte sans profil (`vanitas_perms` = tout à "none") n'a accès à rien, "write" satisfait
 * aussi une exigence "read". Ce masquage frontend reste un CONFORT D'UI — l'application réelle
 * de la règle est toujours côté serveur (`require_vanitas_read/write`, api_server.py).
 */
export const VANITAS_MODULES = [
  { key: "postes", label: "Postes" },
  { key: "terminal", label: "Terminal" },
  { key: "applications", label: "Applications" },
  { key: "conformite", label: "Conformité" },
  { key: "groupes", label: "Groupes" },
  // Activités suspectes (jalon "détection d'activités suspectes sur les postes") — triage du
  // journal d'événements comportementaux remontés par l'agent (processus/event log/réseau/USB).
  { key: "activites_suspectes", label: "Activités suspectes" },
];

export function hasVanitasAccess(user, module, level = "read") {
  if (!user) return false;
  if (user.role === "admin") return true;
  const granted = user.vanitas_perms?.[module] ?? "none";
  if (level === "read") return granted === "read" || granted === "write";
  return granted === "write";
}

/** `true` dès qu'un profil quelconque est assigné (peu importe ce qu'il accorde) — miroir de
 * `auth/__init__.py::require_vanitas_any`, pour les pages d'observation fleet-wide (Vue
 * d'ensemble/Journal/Vulnérabilités/Logiciels obsolètes) qui ne correspondent à aucun module
 * précis. */
export function hasAnyVanitasAccess(user) {
  if (!user) return false;
  if (user.role === "admin") return true;
  return Object.values(user.vanitas_perms ?? {}).some((level) => level !== "none");
}

/**
 * Groupes de postes — règles dynamiques multi-critères (2026-09-10, suite à une revue de la
 * fonctionnalité comparée à Intune/Jamf/Tanium : "critère limité au nom de poste, en inclusion
 * seule"). `GROUP_RULE_FIELDS` bornés à ce que l'agent collecte RÉELLEMENT (voir
 * `endpoint-agent/server/app/group_membership.py::FIELDS`, même liste des deux côtés) — jamais
 * un champ inventé (pas de "site"/"département", aucune donnée de ce genre n'est collectée).
 * `GroupRuleBuilder` est PARTAGÉ entre la création (VanitasGroupsTab.jsx) et la modification
 * (VanitasGroupDetail.jsx) d'un groupe — même UI des deux côtés, jamais deux formulaires de
 * règle qui pourraient diverger.
 */
export const GROUP_RULE_FIELDS = [
  { key: "hostname", label: "Nom du poste", type: "text", placeholder: "ex. *-wks*", operators: ["glob", "not_glob", "contains", "not_contains", "equals", "not_equals"] },
  { key: "os", label: "Système d'exploitation", type: "text", placeholder: "ex. Windows 11", operators: ["contains", "not_contains", "equals", "not_equals"] },
  {
    key: "status", label: "Statut", type: "select", operators: ["equals", "not_equals"],
    options: [{ value: "online", label: "En ligne" }, { value: "offline", label: "Silencieux" }],
  },
  { key: "agent_version", label: "Version de l'agent", type: "text", placeholder: "ex. 1.1.0", operators: ["contains", "not_contains", "equals", "not_equals"] },
];

export const GROUP_RULE_OPERATOR_LABELS = {
  contains: "contient",
  not_contains: "ne contient pas",
  equals: "est exactement",
  not_equals: "n'est pas",
  glob: "correspond au motif (*, ?)",
  not_glob: "ne correspond pas au motif (*, ?)",
};

function groupRuleFieldDef(key) {
  return GROUP_RULE_FIELDS.find((f) => f.key === key) ?? GROUP_RULE_FIELDS[0];
}

/** Résumé lisible d'une règle — utilisé dans la liste des groupes et le détail, jamais du JSON
 * brut affiché à Nicolas. `null`/pas de condition → `null` (groupe statique). */
export function summarizeGroupRules(rules) {
  if (!rules?.conditions?.length) return null;
  const joiner = rules.combinator === "any" ? " OU " : " ET ";
  return rules.conditions
    .map((c) => `${groupRuleFieldDef(c.field).label} ${GROUP_RULE_OPERATOR_LABELS[c.operator] ?? c.operator} « ${c.value} »`)
    .join(joiner);
}

export function GroupRuleBuilder({ rules, onChange, disabled }) {
  const combinator = rules?.combinator ?? "all";
  const conditions = rules?.conditions ?? [];

  function commit(nextConditions, nextCombinator = combinator) {
    onChange(nextConditions.length ? { combinator: nextCombinator, conditions: nextConditions } : null);
  }
  function addCondition() {
    commit([...conditions, { field: "hostname", operator: "glob", value: "" }]);
  }
  function updateCondition(idx, patch) {
    commit(conditions.map((c, i) => (i === idx ? { ...c, ...patch } : c)));
  }
  function removeCondition(idx) {
    commit(conditions.filter((_, i) => i !== idx));
  }

  return (
    <div className="vanitas-rule-builder">
      {conditions.length > 1 && (
        <div className="vanitas-hud-chips" style={{ marginBottom: "10px" }}>
          <button type="button" className={`vanitas-hud-chip${combinator === "all" ? " active" : ""}`} onClick={() => commit(conditions, "all")} disabled={disabled}>
            <span className="led" />TOUTES LES CONDITIONS (ET)
          </button>
          <button type="button" className={`vanitas-hud-chip${combinator === "any" ? " active" : ""}`} onClick={() => commit(conditions, "any")} disabled={disabled}>
            <span className="led" />AU MOINS UNE (OU)
          </button>
        </div>
      )}
      {conditions.map((c, idx) => {
        const fieldDef = groupRuleFieldDef(c.field);
        return (
          <div className="vanitas-rule-condition" key={idx}>
            <select
              className="filter-input"
              value={c.field}
              onChange={(e) => {
                const nextField = groupRuleFieldDef(e.target.value);
                updateCondition(idx, { field: e.target.value, operator: nextField.operators[0], value: "" });
              }}
              disabled={disabled}
            >
              {GROUP_RULE_FIELDS.map((f) => (
                <option key={f.key} value={f.key}>
                  {f.label}
                </option>
              ))}
            </select>
            <select className="filter-input" value={c.operator} onChange={(e) => updateCondition(idx, { operator: e.target.value })} disabled={disabled}>
              {fieldDef.operators.map((op) => (
                <option key={op} value={op}>
                  {GROUP_RULE_OPERATOR_LABELS[op]}
                </option>
              ))}
            </select>
            {fieldDef.type === "select" ? (
              <select className="filter-input" value={c.value} onChange={(e) => updateCondition(idx, { value: e.target.value })} disabled={disabled}>
                <option value="">Choisir…</option>
                {fieldDef.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                className="filter-input"
                placeholder={fieldDef.placeholder}
                value={c.value}
                onChange={(e) => updateCondition(idx, { value: e.target.value })}
                disabled={disabled}
              />
            )}
            <button type="button" className="vanitas-ghost-btn" onClick={() => removeCondition(idx)} disabled={disabled} aria-label="Retirer cette condition">
              ✕
            </button>
          </div>
        );
      })}
      <button type="button" className="vanitas-ghost-btn" onClick={addCondition} disabled={disabled}>
        + Ajouter une condition
      </button>
    </div>
  );
}

export const COMMAND_LABELS = {
  force_inventory: "Forcer un inventaire",
  restart_service: "Redémarrer le service",
  system_diagnostic: "Diagnostic système",
  check_windows_updates: "Vérifier les mises à jour Windows",
  hardware_inventory: "Inventaire matériel",
  uninstall_agent: "Désinstaller l'agent",
  // Jalon 11 — 3ᵉ point de synchronisation du catalogue de commandes, en plus de
  // `server/app/commands.py::COMMAND_TYPES` et du switch de `CommandExecutor.cs` (facile à
  // oublier, repéré en concevant ce jalon) : sans cette entrée, le bouton générique "Lancer"
  // afficherait le type brut "compliance_check" plutôt qu'un libellé lisible.
  compliance_check: "Forcer une vérification de conformité",
  // Push d'application (2026-09-08) — 3ᵉ point de synchronisation, même raison que
  // "compliance_check" ci-dessus.
  install_application: "Installation d'application",
  // Mise à jour de l'agent lui-même (2026-09-11) — même raison, 4ᵉ point de synchronisation
  // (voir aussi `server/app/commands.py::COMMAND_TYPES`, `UpdateRunner.cs`).
  update_agent: "Mise à jour de l'agent",
  // Journal d'événements Windows à la demande (2026-09-16) — 5ᵉ point de synchronisation, même
  // raison (voir aussi `server/app/commands.py::COMMAND_TYPES`, `Commands/EventLogFetcher.cs`).
  fetch_event_log: "Journal d'événements Windows",
  // Jalon "Mises à jour Vanitas" (2026-09-17) — 6ᵉ point de synchronisation, même raison (voir
  // aussi `server/app/commands.py::COMMAND_TYPES`, `CommandExecutor.cs::ForceReboot`).
  force_reboot: "Redémarrage forcé (mises à jour)",
  // Jalon "confinement" (2026-09-17) — 7ᵉ point de synchronisation, même raison (voir aussi
  // `server/app/commands.py::COMMAND_TYPES`, `ContainmentRunner.cs`). Boutons dédiés dans
  // `VanitasSuspiciousActivityTab.jsx`, jamais le menu générique "Lancer" — mêmes précédents que
  // "force_reboot".
  kill_process: "Tuer le process",
  isolate_network: "Isoler le réseau",
  lift_isolation: "Lever l'isolement",
};
export const COMMAND_TYPES = Object.keys(COMMAND_LABELS);

// Jalon 7 — "uninstall_agent" reste dans le catalogue (queue_command.py, l'agent doit savoir
// l'exécuter) mais JAMAIS sélectionnable dans un menu déroulant générique partagé avec des
// commandes anodines : un mauvais item choisi par erreur dans une liste de 6 options n'a pas
// les mêmes conséquences selon qu'il s'agit d'un diagnostic ou d'une désinstallation. Elle a sa
// propre action dédiée (voir `ConfirmButton` + `VanitasDeviceDetail.jsx`), à confirmation
// explicite en deux clics plutôt qu'un simple "Lancer". "install_application" (2026-09-08) et
// "update_agent" (2026-09-11) rejoignent ce même ensemble pour une raison SUPPLÉMENTAIRE :
// elles ont besoin d'un `installer_id`/`agent_package_id` que ce menu générique n'a aucun
// moyen de fournir — leurs propres points d'entrée dédiés vivent dans
// `VanitasInstallersTab.jsx`/`VanitasGroupDetail.jsx` (installeurs) et
// `VanitasDeviceDetail.jsx`/`VanitasGroupDetail.jsx` (mise à jour de l'agent, poste ou groupe).
// "fetch_event_log" (2026-09-16) rejoint l'ensemble pour cette SEULE raison "paramètres
// supplémentaires" — ce n'est PAS une commande dangereuse (lecture seule), mais elle a besoin
// d'un `event_log_query` (canaux/période/ID) que ce menu ne sait pas fournir ; son propre pane
// dédié vit dans `VanitasDeviceDetail.jsx` (pane "Journal d'événements").
export const DANGEROUS_COMMAND_TYPES = new Set([
  "uninstall_agent",
  "install_application",
  "update_agent",
  "fetch_event_log",
  // Redémarre la machine SANS attendre de fenêtre de maintenance — son propre bouton à
  // confirmation dédié vit dans `VanitasPatchTab.jsx`, jamais ce menu générique.
  "force_reboot",
  // Jalon "confinement" (2026-09-17) — mêmes boutons à confirmation dédiés dans
  // `VanitasSuspiciousActivityTab.jsx`, jamais ce menu générique (même raison que
  // "force_reboot" juste au-dessus).
  "kill_process",
  "isolate_network",
  "lift_isolation",
]);
export const SAFE_COMMAND_TYPES = COMMAND_TYPES.filter((t) => !DANGEROUS_COMMAND_TYPES.has(t));

export function fmtRelative(value) {
  if (!value) return "jamais";
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "jamais";
  const diffH = (Date.now() - then) / 3_600_000;
  if (diffH < 1) return "à l'instant";
  if (diffH < 24) return `il y a ${Math.round(diffH)} h`;
  return `il y a ${Math.round(diffH / 24)} j`;
}

export function fmtDate(value) {
  return value ? new Date(value).toLocaleDateString("fr-FR") : "—";
}

export function fmtDateTime(value) {
  return value ? new Date(value).toLocaleString("fr-FR") : "—";
}

export function fmtBytes(bytes) {
  const n = Number(bytes);
  if (!bytes || Number.isNaN(n) || n <= 0) return "—";
  const gb = n / 1_000_000_000;
  return `${gb.toFixed(1).replace(".", ",")} Go`;
}

export function daysUntil(isoDate) {
  if (!isoDate) return null;
  return (new Date(isoDate).getTime() - Date.now()) / 86_400_000;
}

/** Compare deux versions "x.y.z" NUMÉRIQUEMENT (2026-09-11, "mise à jour de l'agent") — même
 * logique que `_parse_agent_version`/comparaison côté backend (api_server.py), transposée en
 * JS pour ne jamais lire "1.9.0" < "1.10.0" lexicographiquement. `null` si l'une des deux
 * versions n'a pas ce format (repli honnête, jamais un "à jour" par défaut trompeur). */
export function compareVersions(a, b) {
  const pa = (a ?? "").trim().split(".").map((p) => Number.parseInt(p, 10));
  const pb = (b ?? "").trim().split(".").map((p) => Number.parseInt(p, 10));
  if (!pa.length || !pb.length || pa.some(Number.isNaN) || pb.some(Number.isNaN)) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Dernière version du code de l'agent (2026-09-11, retour de Nicolas sur la tuile "Agent" —
 * "je pense pas que je le déploierai via application vu que les modifs c'est toi qui va les
 * faire principalement") : constante à incrémenter À LA MAIN à chaque bump de version de
 * l'agent, MÊME VALEUR que `<Version>` dans `EndpointAgent.csproj` ET `<Package Version>` dans
 * `Product.wxs` (voir le commentaire permanent dans `Product.wxs` sur la synchronisation des
 * trois). Sert à signaler un poste en retard sur le CODE SOURCE même si aucun paquet n'a encore
 * été uploadé dans le catalogue Vanitas ("Applications") — le catalogue reste le seul moyen de
 * PUSHER réellement une mise à jour, cette constante ne fait qu'informer. */
export const LATEST_AGENT_VERSION = "1.2.1";

export function isOnline(agent) {
  return Boolean(agent?.last_seen) && (Date.now() - new Date(agent.last_seen).getTime()) / 3_600_000 < 24;
}

/** Parse le JSON renvoyé par une commande "system_diagnostic"/"check_windows_updates" (voir
 * Commands/CommandExecutor.cs côté agent) — jamais garanti (l'agent peut ne l'avoir jamais
 * exécutée, ou avoir échoué), d'où le try/catch : un résultat illisible retombe sur `null`
 * plutôt que de casser la page. */
export function parseCommandResult(resultText) {
  if (!resultText) return null;
  try {
    return JSON.parse(resultText);
  } catch {
    return null;
  }
}

/** La commande la plus récente TERMINÉE AVEC SUCCÈS d'un type donné, déjà triée created_at
 * desc côté serveur (GET /agents/{id}/commands) — objet brut (pas juste son résultat parsé)
 * pour garder accès à `created_at`/`completed_at`, utile pour afficher "dernière vérification
 * il y a…" à côté du résultat lui-même. */
export function latestCommandOf(commands, type) {
  return (commands ?? []).find((c) => c.command_type === type && c.status === "completed" && c.success) ?? null;
}

/** Résultat déjà parsé de `latestCommandOf` — pratique quand seul le contenu importe (pas le
 * moment où la commande a tourné). */
export function latestCommandResult(commands, type) {
  const command = latestCommandOf(commands, type);
  return command ? parseCommandResult(command.result) : null;
}

export function severityTone(severity) {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL" || s === "HIGH") return "high";
  if (s === "MEDIUM") return "medium";
  if (s === "LOW") return "low";
  return "neutral";
}

export function severityLabelFr(severity) {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL") return "Critique";
  if (s === "HIGH") return "Élevée";
  if (s === "MEDIUM") return "Moyenne";
  if (s === "LOW") return "Faible";
  return "Non renseignée";
}

export function CommandForm({ agentId, onQueued, initialType }) {
  const [type, setType] = useState(initialType ?? SAFE_COMMAND_TYPES[0]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function handleLaunch() {
    setBusy(true);
    setError(null);
    try {
      const payload = await api.vanitas.queueCommand(agentId, type);
      if (isErrorPayload(payload)) {
        setError(payload.message);
      } else {
        onQueued();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="vanitas-queue-form">
      <div style={{ display: "flex", gap: "8px" }}>
        <select className="filter-input" value={type} onChange={(e) => setType(e.target.value)} disabled={busy}>
          {SAFE_COMMAND_TYPES.map((t) => (
            <option key={t} value={t}>
              {COMMAND_LABELS[t]}
            </option>
          ))}
        </select>
        <button type="button" className="vanitas-queue-btn" onClick={handleLaunch} disabled={busy}>
          {busy ? "Envoi…" : "Lancer"}
        </button>
      </div>
      {error && <p className="error-note">{error}</p>}
    </div>
  );
}

/** Confirmation en deux clics (jalon 7) — le seul mécanisme de confirmation de tout ce
 * dashboard, réservé aux DEUX actions vraiment destructrices/irréversibles ("Désinstaller à
 * distance"/"Retirer de l'inventaire") : aucune popup dédiée pour ce seul besoin (aucun
 * mécanisme de ce genre n'existe ailleurs dans ce projet — proportionné au risque plutôt qu'un
 * nouveau composant modal). Premier clic → le bouton affiche `confirmLabel` pendant
 * `armedForMs` ; un `setTimeout` réinitialise si aucun second clic n'arrive. Second clic dans
 * cette fenêtre → exécute réellement `onConfirm`. */
export function ConfirmButton({ label, confirmLabel, onConfirm, className, disabled, armedForMs = 5000, title, onClick }) {
  const [armed, setArmed] = useState(false);
  const timeoutRef = useRef(null);

  useEffect(() => () => clearTimeout(timeoutRef.current), []);

  function handleClick(e) {
    // `onClick` optionnel (jalon 8, action posée dans une ligne de tableau cliquable, voir
    // VanitasDevicesTab.jsx) : stoppe la propagation AVANT le premier clic ET le second, sinon
    // le clic de confirmation remonterait aussi jusqu'au `onClick` de la ligne parente.
    onClick?.(e);
    if (!armed) {
      setArmed(true);
      timeoutRef.current = setTimeout(() => setArmed(false), armedForMs);
      return;
    }
    clearTimeout(timeoutRef.current);
    setArmed(false);
    onConfirm();
  }

  // `armed` posée comme classe en plus de `className` (jalon 8) — chaque appelant décide de son
  // propre style d'état "armé" (`.vanitas-danger-btn.armed`/`.vanitas-hud-purge-btn.armed`),
  // aucun style par défaut imposé ici.
  const classes = [className, armed ? "armed" : null].filter(Boolean).join(" ");

  return (
    <button type="button" className={classes || undefined} onClick={handleClick} disabled={disabled} title={title}>
      {armed ? (confirmLabel ?? "Confirmer ?") : label}
    </button>
  );
}

/**
 * Chrome partagé des popups Vanitas "étape par étape" (2026-09-09) — extrait de
 * `VanitasInstallersTab.jsx` (assistant "Ajouter un installeur") pour être réutilisé tel quel
 * par le popup "Créer une règle" de `VanitasComplianceTab.jsx` : la structure (overlay/shell/
 * fermeture Échap/clic en dehors) est strictement générique, aucune hypothèse propre aux
 * installeurs — seul le CONTENU (`children`) diffère d'un appelant à l'autre. Portée sur
 * `document.body` via `createPortal` (même raison que SettingsModal.jsx/ActivityDetailModal.jsx :
 * un `position: fixed` hérite de tout ancêtre portant un `transform`, même une matrice identité
 * issue d'une animation déjà terminée). Classes `.vanitas-wiz-*` (styles.css), qui redéclarent
 * localement les jetons `--hud-*` puisque portées hors de l'arbre `.vanitas-hud`.
 */
export function VanitasWizardShell({ onClose, wide, children }) {
  const shellRef = useRef(null);

  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === "Escape") onClose();
    }
    function handlePointerDown(e) {
      if (shellRef.current && !shellRef.current.contains(e.target)) onClose();
    }
    document.addEventListener("keydown", handleKeyDown);
    document.addEventListener("pointerdown", handlePointerDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.removeEventListener("pointerdown", handlePointerDown);
    };
  }, [onClose]);

  return createPortal(
    <div className="vanitas-wiz-overlay">
      <div className={`vanitas-wiz-shell${wide ? " wide" : ""}`} ref={shellRef} role="dialog" aria-modal="true">
        <button type="button" className="vanitas-wiz-close" onClick={onClose} aria-label="Fermer">
          <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <path d="M5 5l10 10M15 5L5 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>
        {children}
      </div>
    </div>,
    document.body
  );
}
