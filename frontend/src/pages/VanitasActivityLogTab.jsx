import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import CopyButton from "../components/CopyButton.jsx";
import { IconLaptop, IconLayers, IconShield, IconUpload } from "../components/icons.jsx";
import { useVanitasActivityLog } from "../hooks/useDashboardData.js";
import { COMMAND_LABELS, fmtDateTime } from "./vanitasShared.jsx";

// Même motif EXACT que `HISTORY_RANGES`/`HistoryRangePicker` de OverviewTab.jsx (déjà dupliqué
// une première fois par l'ex-"Commandes", voir historique de ce fichier) — "90 j" correspond à
// la totalité de l'historique CONSERVÉ côté serveur (rétention 90 jours, `audit_events` inclus
// depuis ce jalon, voir `routes/maintenance.py` côté Vanitas), pas besoin d'une option "Tout".
const RANGES = [
  { key: "7", label: "7 j", days: 7 },
  { key: "14", label: "14 j", days: 14 },
  { key: "30", label: "30 j", days: 30 },
  { key: "90", label: "90 j", days: 90 },
];

// Plage personnalisée (2026-09-09, demande de Nicolas — "je voudrai même qu'on puisse choisir
// une plage de date") — 5e option à côté des 4 boutons jour, PAS un remplacement : les deux
// se comportent comme un seul groupe de boutons radio, `rangeKey` vaut soit une clé de
// `RANGES` soit `CUSTOM_RANGE_KEY`, jamais les deux en même temps.
const CUSTOM_RANGE_KEY = "custom";

// Un identifiant/catégorie par ligne (demande explicite de Nicolas — "chaque log en fonction
// de ce qu'il touche a un identifiant, filtrable") — mêmes icônes que la nav Vanitas
// (VanitasSidebar.jsx : Postes/Applications/Conformité/Groupes) pour une lecture cohérente
// dans tout le dashboard, pas une nouvelle iconographie propre à cette page. Couleurs = tokens
// --hud-* existants, jamais inventées (recherche faite avant de concevoir cette page : GitHub/
// Datadog/Linear réservent la couleur à la catégorie, jamais au texte).
const CATEGORY_META = {
  poste: { label: "Poste", color: "var(--hud-accent)", dim: "var(--hud-accent-dim)", Icon: IconLaptop },
  application: { label: "Application", color: "var(--hud-warn)", dim: "var(--hud-warn-soft)", Icon: IconUpload },
  conformite: { label: "Conformité", color: "var(--hud-accent2)", dim: "var(--hud-accent2-dim)", Icon: IconShield },
  groupe: { label: "Groupe", color: "var(--hud-good)", dim: "var(--hud-good-soft)", Icon: IconLayers },
};
const CATEGORY_ORDER = ["poste", "application", "conformite", "groupe"];

// Verbe affiché pour une entrée "audit" (mutation admin sur un catalogue) — clé
// `${category}:${action}`, voir `endpoint-agent/server/app/routes/*.py` pour la liste exacte
// des couples déjà écrits. Une entrée "commande" (source === "command") a son propre verbe
// fixe ("a lancé"), voir le rendu de la phrase plus bas.
const AUDIT_VERBS = {
  "groupe:created": "a créé le groupe",
  "groupe:updated": "a modifié le groupe",
  "groupe:deleted": "a supprimé le groupe",
  "groupe:agent_added": "a ajouté un poste au groupe",
  "groupe:agent_removed": "a retiré un poste du groupe",
  "application:created": "a ajouté l'installeur",
  "application:updated": "a modifié l'installeur",
  "application:deleted": "a supprimé l'installeur",
  "application:pushed": "a poussé l'installeur",
  "conformite:created": "a créé la règle",
  "conformite:updated": "a modifié la règle",
  "conformite:deleted": "a supprimé la règle",
  "conformite:enabled": "a activé la règle",
  "conformite:disabled": "a désactivé la règle",
  "poste:removed": "a retiré le poste",
  // "Ajouter un poste" (2026-09-11) — target_label porte déjà le fragment du token
  // (`Token d'enrôlement (…xxxxxxxx)`), voir routes/enrollment_tokens.py.
  "poste:enrollment_token_created": "a généré un",
};

// Titre du popup de détail (2026-09-09, demande de Nicolas — "on est d'accord qu'on a tout
// mis ?") : forme nominale de AUDIT_VERBS ci-dessus, un couple par action possible — même
// exhaustivité, pas de repli générique au-delà de `action` brut si un couple manquait.
const AUDIT_TITLES = {
  "groupe:created": "Groupe créé",
  "groupe:updated": "Groupe modifié",
  "groupe:deleted": "Groupe supprimé",
  "groupe:agent_added": "Poste ajouté au groupe",
  "groupe:agent_removed": "Poste retiré du groupe",
  "application:created": "Installeur ajouté",
  "application:updated": "Installeur modifié",
  "application:deleted": "Installeur supprimé",
  "application:pushed": "Installeur poussé",
  "conformite:created": "Règle créée",
  "conformite:updated": "Règle modifiée",
  "conformite:deleted": "Règle supprimée",
  "conformite:enabled": "Règle activée",
  "conformite:disabled": "Règle désactivée",
  "poste:removed": "Poste retiré",
  "poste:enrollment_token_created": "Token d'enrôlement généré",
};

function entryTitle(entry) {
  if (entry.source === "command") return COMMAND_LABELS[entry.action] ?? entry.action;
  return AUDIT_TITLES[`${entry.category}:${entry.action}`] ?? entry.action;
}

// `parameters` (2026-09-09) : JSON déjà décodé côté serveur (routes/activity.py::
// _command_parameters) — seul `install_application` en porte un aujourd'hui, d'où des
// libellés spécifiques plutôt qu'une table générique par type de commande.
const PARAM_LABELS = {
  installer_id: "Installeur (id)",
  original_filename: "Fichier",
  install_command: "Commande",
  sha256: "SHA-256",
};

function fmtDuration(startIso, endIso) {
  const sec = Math.max(0, Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000));
  if (sec < 60) return `${sec} s`;
  const min = Math.floor(sec / 60);
  return `${min} min ${sec % 60} s`;
}

function fmtShortDate(iso) {
  return new Date(`${iso}T00:00:00`).toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
}

function toIsoDate(d) {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// ── Filtre "Type" (2026-09-09, retour de Nicolas — "rassembler [poste/application/
// conformité/groupe] dans un Filtre Type qui s'ouvre") : remplace les 5 pastilles toujours
// visibles par UN SEUL bouton-filtre ouvrant une liste à cocher, MULTI-sélection (ex. Poste
// ET Groupe en même temps) — un vrai gain fonctionnel par rapport à l'ancien mécanisme
// (radio à un seul choix actif), pas juste un habillage visuel.
function TypeFilterDropdown({ selected, counts, onToggle, onToggleAll, isOpen, onRequestToggle, rootRef }) {
  const allSelected = selected.size === CATEGORY_ORDER.length;
  const chosen = CATEGORY_ORDER.filter((k) => selected.has(k));
  const label = allSelected ? "Type" : chosen.length === 1 ? CATEGORY_META[chosen[0]].label : `Type · ${chosen.length}`;

  return (
    <div className="vanitas-filter-dropdown" ref={rootRef}>
      <button
        type="button"
        className={`vanitas-filter-trigger${allSelected ? "" : " active"}`}
        onClick={onRequestToggle}
        aria-expanded={isOpen}
      >
        {!allSelected && (
          <span className="dot-stack">
            {chosen.map((k) => (
              <span key={k} style={{ background: CATEGORY_META[k].color }} />
            ))}
          </span>
        )}
        <span>{label}</span>
        <svg className="chevron" viewBox="0 0 10 6" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
          <path d="M1 1l4 4 4-4" />
        </svg>
      </button>
      {isOpen && (
        <div className="vanitas-filter-popover">
          {CATEGORY_ORDER.map((key) => {
            const meta = CATEGORY_META[key];
            const checked = selected.has(key);
            return (
              <button
                type="button"
                key={key}
                className={`vanitas-type-item${checked ? " checked" : ""}`}
                style={{ "--c": meta.color }}
                onClick={() => onToggle(key)}
              >
                <span className="box">
                  <svg viewBox="0 0 10 8" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M1 4l3 3 5-6" />
                  </svg>
                </span>
                <span className="label">{meta.label}</span>
                <span className="n">{counts[key]}</span>
              </button>
            );
          })}
          <div className="vanitas-type-divider" />
          <div className="vanitas-type-footer">
            <button type="button" onClick={onToggleAll}>
              {allSelected ? "Rien sélectionner" : "Tout sélectionner"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

const MONTHS_FR = [
  "janvier", "février", "mars", "avril", "mai", "juin",
  "juillet", "août", "septembre", "octobre", "novembre", "décembre",
];
const WEEKDAYS_FR = ["L", "M", "M", "J", "V", "S", "D"];

function sameDay(a, b) {
  return Boolean(a) && Boolean(b) && a.toDateString() === b.toDateString();
}

// Grille à 42 cases (6 semaines, lundi en tête) — jours du mois précédent/suivant inclus en
// `muted` pour ne jamais laisser une rangée à moitié vide.
function buildMonthCells(monthDate) {
  const year = monthDate.getFullYear();
  const month = monthDate.getMonth();
  const firstDay = new Date(year, month, 1);
  const startOffset = (firstDay.getDay() + 6) % 7;
  const cells = [];
  for (let i = 0; i < startOffset; i++) {
    cells.push({ date: new Date(year, month, 1 - (startOffset - i)), muted: true });
  }
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  for (let day = 1; day <= daysInMonth; day++) cells.push({ date: new Date(year, month, day), muted: false });
  while (cells.length % 7 !== 0 || cells.length < 42) {
    const last = cells[cells.length - 1].date;
    cells.push({ date: new Date(last.getFullYear(), last.getMonth(), last.getDate() + 1), muted: true });
  }
  return cells;
}

function CalendarMonth({ monthDate, today, oldestAllowed, rangeStart, rangeEnd, hoverDate, onDayClick, onDayHover }) {
  const cells = buildMonthCells(monthDate);
  const effectiveEnd = rangeEnd || hoverDate;
  const lo = rangeStart && effectiveEnd ? (rangeStart < effectiveEnd ? rangeStart : effectiveEnd) : null;
  const hi = rangeStart && effectiveEnd ? (rangeStart < effectiveEnd ? effectiveEnd : rangeStart) : null;
  return (
    <div className="vanitas-cal-month">
      <div className="vanitas-cal-month-title">
        {MONTHS_FR[monthDate.getMonth()]} {monthDate.getFullYear()}
      </div>
      <div className="vanitas-cal-grid">
        {WEEKDAYS_FR.map((w, i) => (
          <div className="vanitas-cal-weekday" key={i}>
            {w}
          </div>
        ))}
        {cells.map(({ date, muted }, i) => {
          const disabled = date < oldestAllowed || date > today;
          const classes = ["vanitas-cal-day"];
          if (muted) classes.push("muted");
          if (disabled) classes.push("disabled");
          if (sameDay(date, today)) classes.push("today");
          if (sameDay(date, rangeStart)) classes.push("range-start");
          if (sameDay(date, rangeEnd)) classes.push("range-end");
          if (lo && hi && date > lo && date < hi) classes.push("in-range");
          return (
            <button
              type="button"
              key={i}
              className={classes.join(" ")}
              disabled={disabled}
              onClick={() => onDayClick(date)}
              onMouseEnter={() => onDayHover(date)}
            >
              {date.getDate()}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Filtre "Période" (2026-09-09, retour de Nicolas — "mettre la période en filtre" + "un
// calendrier sur lequel on peut choisir une timeline") : les 4 presets jour restent, mais
// "Personnalisée" n'est plus 2 champs `<input type="date">` nus — un vrai calendrier à 2 mois
// (mois précédent + mois courant), sélection par clic début/fin avec aperçu au survol,
// dates hors des 90 jours de rétention serveur grisées et non cliquables. État du calendrier
// LOCAL à ce composant (jamais commité au parent avant "Appliquer") — annuler ou fermer sans
// valider ne doit rien changer au filtre déjà actif.
function PeriodFilterDropdown({ rangeKey, customFrom, customTo, onApplyPreset, onApplyCustom, isOpen, onRequestToggle, onClose, rootRef }) {
  const [viewLeft, setViewLeft] = useState(() => {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth() - 1, 1);
  });
  const [rangeStart, setRangeStart] = useState(null);
  const [rangeEnd, setRangeEnd] = useState(null);
  const [hoverDate, setHoverDate] = useState(null);

  useEffect(() => {
    if (!isOpen) return;
    if (rangeKey === CUSTOM_RANGE_KEY && customFrom && customTo) {
      const s = new Date(`${customFrom}T00:00:00`);
      const e = new Date(`${customTo}T00:00:00`);
      setRangeStart(s);
      setRangeEnd(e);
      setViewLeft(new Date(e.getFullYear(), e.getMonth() - 1, 1));
    } else {
      setRangeStart(null);
      setRangeEnd(null);
    }
    setHoverDate(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const oldestAllowed = new Date(today.getTime() - 90 * 24 * 60 * 60 * 1000);
  const viewRight = new Date(viewLeft.getFullYear(), viewLeft.getMonth() + 1, 1);

  function handleDayClick(date) {
    if (!rangeStart || rangeEnd) {
      setRangeStart(date);
      setRangeEnd(null);
    } else if (date < rangeStart) {
      setRangeEnd(rangeStart);
      setRangeStart(date);
    } else {
      setRangeEnd(date);
    }
  }

  function handlePresetClick(key) {
    onApplyPreset(key);
    onClose();
  }

  function handleApply() {
    if (!rangeStart || !rangeEnd) return;
    onApplyCustom(toIsoDate(rangeStart), toIsoDate(rangeEnd));
    onClose();
  }

  const label =
    rangeKey === CUSTOM_RANGE_KEY && customFrom && customTo
      ? `${fmtShortDate(customFrom)} → ${fmtShortDate(customTo)}`
      : RANGES.find((r) => r.key === rangeKey)?.label ?? "90 j";

  return (
    <div className="vanitas-filter-dropdown" ref={rootRef}>
      <button type="button" className="vanitas-filter-trigger active" onClick={onRequestToggle} aria-expanded={isOpen}>
        <svg className="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="3" width="12" height="11" rx="1.5" />
          <path d="M5 1.5v3M11 1.5v3M2 6.5h12" />
        </svg>
        <span>{label}</span>
        <svg className="chevron" viewBox="0 0 10 6" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
          <path d="M1 1l4 4 4-4" />
        </svg>
      </button>
      {isOpen && (
        <div className="vanitas-filter-popover wide">
          <div className="vanitas-preset-row">
            {RANGES.map((r) => (
              <button
                type="button"
                key={r.key}
                className={`vanitas-preset-btn${rangeKey === r.key ? " active" : ""}`}
                onClick={() => handlePresetClick(r.key)}
              >
                {r.label}
              </button>
            ))}
          </div>
          <div className="vanitas-cal-months">
            <div>
              <div className="vanitas-cal-month-head">
                <button
                  type="button"
                  className="vanitas-cal-nav-btn"
                  aria-label="Mois précédent"
                  onClick={() => setViewLeft(new Date(viewLeft.getFullYear(), viewLeft.getMonth() - 1, 1))}
                >
                  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
                    <path d="M7.5 2.5L3.5 6l4 3.5" />
                  </svg>
                </button>
              </div>
              <CalendarMonth
                monthDate={viewLeft}
                today={today}
                oldestAllowed={oldestAllowed}
                rangeStart={rangeStart}
                rangeEnd={rangeEnd}
                hoverDate={hoverDate}
                onDayClick={handleDayClick}
                onDayHover={setHoverDate}
              />
            </div>
            <div>
              <div className="vanitas-cal-month-head vanitas-cal-month-head-right">
                <button
                  type="button"
                  className="vanitas-cal-nav-btn"
                  aria-label="Mois suivant"
                  onClick={() => setViewLeft(new Date(viewLeft.getFullYear(), viewLeft.getMonth() + 1, 1))}
                >
                  <svg viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round">
                    <path d="M4.5 2.5l4 3.5-4 3.5" />
                  </svg>
                </button>
              </div>
              <CalendarMonth
                monthDate={viewRight}
                today={today}
                oldestAllowed={oldestAllowed}
                rangeStart={rangeStart}
                rangeEnd={rangeEnd}
                hoverDate={hoverDate}
                onDayClick={handleDayClick}
                onDayHover={setHoverDate}
              />
            </div>
          </div>
          <div className="vanitas-cal-footer">
            <span className="vanitas-cal-range-readout">
              {rangeStart && rangeEnd ? (
                <>
                  <b>{rangeStart.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" })}</b> →{" "}
                  <b>{rangeEnd.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" })}</b>
                </>
              ) : rangeStart ? (
                <>
                  <b>{rangeStart.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" })}</b> → choisis une date de fin
                </>
              ) : (
                "Ou choisis une plage précise ci-dessus"
              )}
            </span>
            <div className="vanitas-cal-actions">
              <button type="button" className="vanitas-cal-btn ghost" onClick={onClose}>
                Annuler
              </button>
              <button type="button" className="vanitas-cal-btn primary" disabled={!rangeStart || !rangeEnd} onClick={handleApply}>
                Appliquer
              </button>
            </div>
          </div>
          <div className="vanitas-retention-hint">Grisées : hors des 90 derniers jours (purge automatique côté serveur)</div>
        </div>
      )}
    </div>
  );
}

function fmtDay(date) {
  const now = new Date();
  const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const startOfYesterday = new Date(startOfToday);
  startOfYesterday.setDate(startOfYesterday.getDate() - 1);
  const d = new Date(date);
  const startOfDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  if (startOfDay.getTime() === startOfToday.getTime()) return "Aujourd'hui";
  if (startOfDay.getTime() === startOfYesterday.getTime()) return "Hier";
  return startOfDay.toLocaleDateString("fr-FR", { day: "2-digit", month: "long", year: "numeric" });
}

// Étiquette de la colonne méta (2026-09-09, retour de Nicolas — "pour les trucs qui datent
// en jours, mets la date plutôt que 'il y a 3 jours'") : garde le relatif fin grain (minutes/
// heures, précis et lisible d'un coup d'œil) mais bascule sur la date+heure réelle dès qu'une
// entrée dépasse 24h — "il y a 3 jours" demandait un calcul mental, la date ne demande aucune
// interprétation. Distinct de `fmtRelative` (vanitasShared.jsx, partagée par tout le reste de
// Vanitas pour "dernier contact" — pas concernée par cette demande, propre à cette colonne).
function activityMetaLabel(value) {
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return "jamais";
  const diffH = (Date.now() - then) / 3_600_000;
  if (diffH < 1) return "à l'instant";
  if (diffH < 24) return `il y a ${Math.round(diffH)} h`;
  const d = new Date(value);
  return `${d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" })} à ${d.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" })}`;
}

function sentenceParts(entry) {
  if (entry.source === "command") {
    return { verb: "a lancé", target: `${COMMAND_LABELS[entry.action] ?? entry.action} sur ${entry.target_label}` };
  }
  const verb = AUDIT_VERBS[`${entry.category}:${entry.action}`] ?? entry.action;
  return { verb, target: `« ${entry.target_label} »` };
}

function ActivityRow({ entry, onOpen }) {
  const meta = CATEGORY_META[entry.category] ?? CATEGORY_META.poste;
  const { verb, target } = sentenceParts(entry);
  const outcomeLabel = entry.outcome === "ok" ? "Succès" : entry.outcome === "fail" ? "Échec" : "En attente";

  return (
    <div
      className="vanitas-activity-row"
      style={{ "--cat-color": meta.color, "--cat-dim": meta.dim }}
      onClick={() => onOpen(entry)}
      role="button"
      tabIndex={0}
    >
      <span className="vanitas-activity-badge">
        <meta.Icon />
        {meta.label}
      </span>
      <div className="vanitas-activity-body">
        <div className="vanitas-activity-sentence">
          <span className="actor">{entry.actor || "Inconnu"}</span> {verb} <span className="target">{target}</span>
        </div>
        {entry.detail && (
          <div className="vanitas-activity-detail">
            {entry.detail.length > 160 ? `${entry.detail.slice(0, 160)}…` : entry.detail}
          </div>
        )}
      </div>
      <div className="vanitas-activity-meta">
        <span title={fmtDateTime(entry.created_at)}>{activityMetaLabel(entry.created_at)}</span>
        {entry.outcome && (
          <span className={`vanitas-activity-outcome ${entry.outcome}`}>
            <span className="dot" />
            {outcomeLabel}
          </span>
        )}
      </div>
    </div>
  );
}

// Bouton "Copier" du détail complet — dupliqué (~15 lignes, même convention déjà établie sur
// ce dashboard — voir DeployAppWizard.jsx/EditAppTab.jsx/AppCatalogTab.jsx) plutôt que partagé.
function renderTerminalDetail(text) {
  return text.split("\n").map((line, i) => {
    const cls = line.startsWith("[stderr]") ? " stderr" : /^Code de sortie/.test(line) ? " exit" : "";
    return (
      <div key={i} className={`activity-detail-term-line${cls}`}>
        {line}
      </div>
    );
  });
}

/**
 * Popup de détail complet (2026-09-09, maquette validée par Nicolas avant implémentation —
 * "on est d'accord qu'on a tout mis ?" a mené à ajouter `completed_at`/`parameters`, les deux
 * seuls champs du modèle réel qui n'étaient exposés nulle part avant ce jalon). Carte "paysage"
 * (retour de Nicolas : "le détail à droite et les autres informations à gauche") — colonne
 * gauche fixe (identité + fiche), colonne droite flexible (le détail brut, potentiellement
 * long) — chacune défile indépendamment plutôt que de laisser le détail pousser la hauteur de
 * toute la carte.
 *
 * PAS de lien "Voir le poste/groupe/..." malgré la maquette : construire une vraie navigation
 * croisée entre onglets Vanitas aurait exigé de répliquer le mécanisme `searchNav`/
 * `initialQuery` de Dashboard.jsx (aujourd'hui strictement réservé à l'arbre Intune, aucun
 * onglet Vanitas n'y répond) — hors du périmètre de cette demande précise (le contenu du
 * popup), laissé de côté plutôt que construit à la va-vite.
 *
 * `createPortal` sur `document.body` (même précédent que SettingsModal.jsx/WidgetsTestTab.jsx
 * pour la même raison : un `position: fixed` hérite de tout ancêtre portant un `transform`,
 * même une matrice identité issue d'une animation déjà terminée).
 */
function ActivityDetailModal({ entry, onClose }) {
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

  const meta = CATEGORY_META[entry.category] ?? CATEGORY_META.poste;
  const { verb, target } = sentenceParts(entry);
  const title = entryTitle(entry);
  const outcomeLabel = entry.outcome === "ok" ? "Succès" : entry.outcome === "fail" ? "Échec" : "En attente";
  const paramEntries = entry.parameters ? Object.entries(entry.parameters) : [];

  return createPortal(
    <div className="activity-detail-overlay">
      <div
        className="activity-detail-shell"
        style={{ "--cat": meta.color, "--cat-soft": meta.dim }}
        ref={shellRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <button type="button" className="activity-detail-close" onClick={onClose} aria-label="Fermer">
          <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
            <path d="M5 5l10 10M15 5L5 15" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>

        <div className="activity-detail-col-left">
          <div className="activity-detail-icon">
            <meta.Icon />
          </div>
          <h2 className="activity-detail-title">{title}</h2>
          <p className="activity-detail-subtitle">
            <b>{entry.actor || "Inconnu"}</b> {verb} <span className="target">{target}</span>
          </p>
          {entry.outcome && (
            <span className={`activity-detail-outcome-pill ${entry.outcome}`}>
              <span className="dot" />
              {outcomeLabel}
            </span>
          )}

          <div className="activity-detail-divider" />

          <div className="activity-detail-info-list">
            <div className="activity-detail-info-row">
              <span className="label">Identifiant</span>
              <span className="value mono">{entry.id}</span>
            </div>
            <div className="activity-detail-info-row">
              <span className="label">Source</span>
              <span className="value">{entry.source === "command" ? "Commande poste" : "Journal d'audit"}</span>
            </div>
            <div className="activity-detail-info-row">
              <span className="label">Catégorie</span>
              <span className="value accent">{meta.label}</span>
            </div>
            <div className="activity-detail-info-row">
              <span className="label">Créée le</span>
              <span className="value mono">{fmtDateTime(entry.created_at)}</span>
            </div>
            {entry.completed_at ? (
              <>
                <div className="activity-detail-info-row">
                  <span className="label">Terminée le</span>
                  <span className="value mono">{fmtDateTime(entry.completed_at)}</span>
                </div>
                <div className="activity-detail-info-row">
                  <span className="label">Durée</span>
                  <span className="value mono">{fmtDuration(entry.created_at, entry.completed_at)}</span>
                </div>
              </>
            ) : (
              entry.source === "command" && (
                <div className="activity-detail-info-row">
                  <span className="label">Durée</span>
                  <span className="value mono">en cours…</span>
                </div>
              )
            )}
          </div>
        </div>

        <div className="activity-detail-col-right">
          {paramEntries.length > 0 && (
            <>
              <div className="activity-detail-section-row">
                <span className="label">Paramètres de la commande</span>
              </div>
              <div className="activity-detail-params">
                {paramEntries.map(([k, v]) => (
                  <div className="activity-detail-params-row" key={k}>
                    <span className="k">{PARAM_LABELS[k] ?? k}</span>
                    <span className="v" title={String(v)}>
                      {String(v)}
                    </span>
                  </div>
                ))}
              </div>
              <div className="activity-detail-divider" style={{ margin: "18px 0" }} />
            </>
          )}
          <div className="activity-detail-section-row">
            <span className="label">Détail complet</span>
            {entry.detail && <CopyButton className="activity-detail-copy-btn" text={entry.detail} />}
          </div>
          <div className="activity-detail-body">
            {entry.detail ? (
              <div className="activity-detail-terminal">{renderTerminalDetail(entry.detail)}</div>
            ) : (
              <div className="activity-detail-empty">Aucun détail supplémentaire enregistré pour cette entrée.</div>
            )}
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}

/**
 * "Vanitas" > Administration > Journal (2026-09-09, demande de Nicolas — "changer Commandes en
 * onglet de Log pour chaque action... rechercher en fonction des informations dans les
 * colonnes... un identifiant sur ce qu'il touche, filtrable, qui a créé quoi"). Remplace
 * l'ancien "Commandes" (liste plate de `AgentCommand` seules + formulaire de lancement fleet-
 * wide, voir historique de ce fichier) — le formulaire de lancement générique n'est PAS
 * reconduit ici (demande explicite : "un onglet de Log", pas "un onglet de Log EN PLUS de
 * Commandes") ; lancer une commande reste possible depuis la fiche de chaque poste
 * (`VanitasDeviceDetail.jsx`), inchangé.
 *
 * Maquette validée par Nicolas avant implémentation (recherche de patterns réels — GitHub
 * audit log, Linear, Vercel, Stripe, Datadog Audit Trail — voir l'artefact publié) : liseré +
 * badge coloré par catégorie, phrase "acteur a fait quoi « cible »" plutôt qu'un tableau de
 * colonnes brut, regroupement par jour, recherche libre + pastilles de catégorie avec
 * compteur, ligne dépliable pour le détail complet.
 */
export default function VanitasActivityLogTab() {
  const log = useVanitasActivityLog();
  const [query, setQuery] = useState("");
  const [selectedCategories, setSelectedCategories] = useState(() => new Set(CATEGORY_ORDER));
  const [rangeKey, setRangeKey] = useState("90");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [selectedEntry, setSelectedEntry] = useState(null);
  const [openFilter, setOpenFilter] = useState(null); // null | "type" | "period"
  const typeRef = useRef(null);
  const periodRef = useRef(null);

  useEffect(() => {
    log.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Un seul panneau de filtre ouvert à la fois, fermé au clic en dehors des DEUX — même
  // motif `pointerdown`+ref que ActivityDetailModal, adapté à 2 racines au lieu d'une.
  useEffect(() => {
    if (!openFilter) return undefined;
    function handlePointerDown(e) {
      const insideType = typeRef.current && typeRef.current.contains(e.target);
      const insidePeriod = periodRef.current && periodRef.current.contains(e.target);
      if (!insideType && !insidePeriod) setOpenFilter(null);
    }
    document.addEventListener("pointerdown", handlePointerDown);
    return () => document.removeEventListener("pointerdown", handlePointerDown);
  }, [openFilter]);

  function toggleCategory(key) {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function toggleAllCategories() {
    setSelectedCategories((prev) => (prev.size === CATEGORY_ORDER.length ? new Set() : new Set(CATEGORY_ORDER)));
  }

  const entries = log.state.data;

  const inRange = useMemo(() => {
    if (rangeKey === CUSTOM_RANGE_KEY) {
      // Bornes inclusives — `customTo` couvre la journée entière (23:59:59.999), sinon une
      // entrée du jour choisi lui-même aurait été exclue (comparée à minuit pile).
      const fromTime = customFrom ? new Date(`${customFrom}T00:00:00`).getTime() : null;
      const toTime = customTo ? new Date(`${customTo}T23:59:59.999`).getTime() : null;
      if (fromTime == null && toTime == null) return entries;
      return entries.filter((e) => {
        const t = new Date(e.created_at).getTime();
        if (Number.isNaN(t)) return true;
        if (fromTime != null && t < fromTime) return false;
        if (toTime != null && t > toTime) return false;
        return true;
      });
    }
    const range = RANGES.find((r) => r.key === rangeKey);
    if (!range) return entries;
    const cutoff = Date.now() - range.days * 24 * 60 * 60 * 1000;
    return entries.filter((e) => {
      const t = new Date(e.created_at).getTime();
      return Number.isNaN(t) || t >= cutoff;
    });
  }, [entries, rangeKey, customFrom, customTo]);

  const counts = useMemo(() => {
    const c = { poste: 0, application: 0, conformite: 0, groupe: 0 };
    inRange.forEach((e) => {
      if (c[e.category] !== undefined) c[e.category]++;
    });
    return c;
  }, [inRange]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return inRange.filter((e) => {
      if (!selectedCategories.has(e.category)) return false;
      if (!q) return true;
      const { verb, target } = sentenceParts(e);
      const haystack = [
        e.actor, CATEGORY_META[e.category]?.label, verb, target, e.detail, e.target_label,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [inRange, query, selectedCategories]);

  const sorted = useMemo(
    () => [...filtered].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)),
    [filtered]
  );

  let lastDay = null;

  return (
    <div className="vanitas-hud">
      {log.state.error && <p className="vanitas-hud-error">{log.state.error}</p>}

      <div className="vanitas-hud-toolbar" style={{ marginBottom: "12px" }}>
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder="Rechercher (auteur, action, cible, détail)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
        <TypeFilterDropdown
          selected={selectedCategories}
          counts={counts}
          onToggle={toggleCategory}
          onToggleAll={toggleAllCategories}
          isOpen={openFilter === "type"}
          onRequestToggle={() => setOpenFilter((f) => (f === "type" ? null : "type"))}
          rootRef={typeRef}
        />
        <PeriodFilterDropdown
          rangeKey={rangeKey}
          customFrom={customFrom}
          customTo={customTo}
          onApplyPreset={setRangeKey}
          onApplyCustom={(from, to) => {
            setCustomFrom(from);
            setCustomTo(to);
            setRangeKey(CUSTOM_RANGE_KEY);
          }}
          isOpen={openFilter === "period"}
          onRequestToggle={() => setOpenFilter((f) => (f === "period" ? null : "period"))}
          onClose={() => setOpenFilter(null)}
          rootRef={periodRef}
        />
      </div>

      <p className="vanitas-activity-note">
        {sorted.length} / {inRange.length} entrée{inRange.length > 1 ? "s" : ""} — au-delà de 90
        jours, le journal est purgé automatiquement côté serveur (sessions terminal non
        concernées, conservées indéfiniment).
      </p>

      {log.state.status === "loading" ? (
        <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
      ) : sorted.length === 0 ? (
        <p className="vanitas-hud-empty-note">
          {entries.length === 0 ? "Aucune activité enregistrée pour l'instant." : "0 résultat — aucune entrée ne correspond à ce filtre."}
        </p>
      ) : (
        sorted.map((entry) => {
          const day = fmtDay(entry.created_at);
          const showDay = day !== lastDay;
          lastDay = day;
          return (
            <div key={entry.id}>
              {showDay && <div className="vanitas-activity-day">{day}</div>}
              <ActivityRow entry={entry} onOpen={setSelectedEntry} />
            </div>
          );
        })
      )}

      {selectedEntry && <ActivityDetailModal entry={selectedEntry} onClose={() => setSelectedEntry(null)} />}
    </div>
  );
}
