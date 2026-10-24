import { useEffect, useMemo, useRef, useState } from "react";
import CopyButton from "../components/CopyButton.jsx";
import { IconLaptop, IconLayers, IconShield, IconUpload } from "../components/icons.jsx";
import { useVanitasActivityLog, useVanitasAgents } from "../hooks/useDashboardData.js";
import { COMMAND_LABELS, fmtDateTime } from "./vanitasShared.jsx";
import { currentLocale, localizedTable, tr } from "../i18n/core.js";

// Même motif EXACT que `HISTORY_RANGES`/`HistoryRangePicker` de OverviewTab.jsx (déjà dupliqué
// une première fois par l'ex-"Commandes", voir historique de ce fichier) — "90 j" correspond à
// la totalité de l'historique CONSERVÉ côté serveur (rétention 90 jours, `audit_events` inclus
// depuis ce jalon, voir `routes/maintenance.py` côté Vanitas), pas besoin d'une option "Tout".
const RANGES = [7, 14, 30, 90].map((days) => ({
  key: String(days),
  get label() {
    return tr("val.range.days", { count: days });
  },
  days,
}));

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
// Labels: val.cat.<key> (getter added below).
const CATEGORY_META = {
  poste: { color: "var(--hud-accent)", dim: "var(--hud-accent-dim)", Icon: IconLaptop },
  application: { color: "var(--hud-warn)", dim: "var(--hud-warn-soft)", Icon: IconUpload },
  conformite: { color: "var(--hud-accent2)", dim: "var(--hud-accent2-dim)", Icon: IconShield },
  groupe: { color: "var(--hud-good)", dim: "var(--hud-good-soft)", Icon: IconLayers },
};
for (const [key, meta] of Object.entries(CATEGORY_META)) {
  Object.defineProperty(meta, "label", { get: () => tr(`val.cat.${key}`), enumerable: true });
}
const CATEGORY_ORDER = ["poste", "application", "conformite", "groupe"];

// Verbe affiché pour une entrée "audit" (mutation admin sur un catalogue) — clé
// `${category}:${action}`, voir `endpoint-agent/server/app/routes/*.py` pour la liste exacte
// des couples déjà écrits. Une entrée "commande" (source === "command") a son propre verbe
// fixe ("a lancé"), voir le rendu de la phrase plus bas. Libellés : val.verb.<category>.<action>
// (verbe de la phrase) et val.title.<category>.<action> (titre du popup de détail) — repli sur
// `action` brut si un couple manquait.
function auditText(kind, entry) {
  const key = `val.${kind}.${entry.category}.${entry.action}`;
  const text = tr(key);
  return text === key ? entry.action : text;
}

// Titre du popup de détail (2026-09-09, demande de Nicolas — "on est d'accord qu'on a tout
// mis ?") : forme nominale du verbe ci-dessus (val.title.*), un couple par action possible.
function entryTitle(entry) {
  if (entry.source === "command") return COMMAND_LABELS[entry.action] ?? entry.action;
  return auditText("title", entry);
}

// `parameters` (2026-09-09) : JSON déjà décodé côté serveur (routes/activity.py::
// _command_parameters) — seul `install_application` en porte un aujourd'hui, d'où des
// libellés spécifiques plutôt qu'une table générique par type de commande.
const PARAM_LABELS = {
  ...localizedTable("val.param", ["installer_id", "original_filename", "install_command"]),
  sha256: "SHA-256",
};

function fmtDuration(startIso, endIso) {
  const sec = Math.max(0, Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000));
  if (sec < 60) return `${sec} s`;
  const min = Math.floor(sec / 60);
  return `${min} min ${sec % 60} s`;
}

function fmtShortDate(iso) {
  return new Date(`${iso}T00:00:00`).toLocaleDateString(currentLocale(), { day: "2-digit", month: "short" });
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
  const label = allSelected ? tr("val.type") : chosen.length === 1 ? CATEGORY_META[chosen[0]].label : tr("val.typeN", { count: chosen.length });

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
              {allSelected ? tr("val.selectNone") : tr("val.selectAll")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Mois via Intl (langue courante) ; initiales des jours (lundi en tête) via val.weekdays.
function monthName(date) {
  return date.toLocaleDateString(currentLocale(), { month: "long" });
}

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
        {monthName(monthDate)} {monthDate.getFullYear()}
      </div>
      <div className="vanitas-cal-grid">
        {tr("val.weekdays").split(",").map((w, i) => (
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
      : RANGES.find((r) => r.key === rangeKey)?.label ?? tr("val.range.days", { count: 90 });

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
                  aria-label={tr("val.prevMonth")}
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
                  aria-label={tr("val.nextMonth")}
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
                  <b>{rangeStart.toLocaleDateString(currentLocale(), { day: "2-digit", month: "short" })}</b> →{" "}
                  <b>{rangeEnd.toLocaleDateString(currentLocale(), { day: "2-digit", month: "short" })}</b>
                </>
              ) : rangeStart ? (
                <>
                  <b>{rangeStart.toLocaleDateString(currentLocale(), { day: "2-digit", month: "short" })}</b> → {tr("val.pickEnd")}
                </>
              ) : (
                tr("val.pickRange")
              )}
            </span>
            <div className="vanitas-cal-actions">
              <button type="button" className="vanitas-cal-btn ghost" onClick={onClose}>
                {tr("val.cancel")}
              </button>
              <button type="button" className="vanitas-cal-btn primary" disabled={!rangeStart || !rangeEnd} onClick={handleApply}>
                {tr("val.apply")}
              </button>
            </div>
          </div>
          <div className="vanitas-retention-hint">{tr("val.retention")}</div>
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
  if (startOfDay.getTime() === startOfToday.getTime()) return tr("val.today");
  if (startOfDay.getTime() === startOfYesterday.getTime()) return tr("val.yesterday");
  return startOfDay.toLocaleDateString(currentLocale(), { day: "2-digit", month: "long", year: "numeric" });
}

// Étiquette de la colonne méta (2026-09-09, retour de Nicolas — "pour les trucs qui datent
// en jours, mets la date plutôt que 'il y a 3 jours'") : garde le relatif fin grain (minutes/
// heures, précis et lisible d'un coup d'œil) mais bascule sur la date+heure réelle dès qu'une
// entrée dépasse 24h — "il y a 3 jours" demandait un calcul mental, la date ne demande aucune
// interprétation. Distinct de `fmtRelative` (vanitasShared.jsx, partagée par tout le reste de
// Vanitas pour "dernier contact" — pas concernée par cette demande, propre à cette colonne).
function activityMetaLabel(value) {
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return tr("val.never");
  const diffH = (Date.now() - then) / 3_600_000;
  if (diffH < 1) return tr("val.justNow");
  if (diffH < 24) return tr("val.hoursAgo", { count: Math.round(diffH) });
  const d = new Date(value);
  return tr("val.dateAt", {
    date: d.toLocaleDateString(currentLocale(), { day: "2-digit", month: "2-digit" }),
    time: d.toLocaleTimeString(currentLocale(), { hour: "2-digit", minute: "2-digit" }),
  });
}

function sentenceParts(entry) {
  if (entry.source === "command") {
    return { verb: tr("val.ran"), target: tr("val.cmdOn", { command: COMMAND_LABELS[entry.action] ?? entry.action, target: entry.target_label }) };
  }
  return { verb: auditText("verb", entry), target: tr("val.quoted", { label: entry.target_label }) };
}

// Ligne d'erreur la plus parlante d'un échec, affichée sous la ligne du journal (refonte
// 2026-10-24) : stderr ou code de sortie en priorité, sinon la dernière ligne non vide.
function errorExcerpt(detail) {
  if (!detail) return null;
  const lines = detail.split("\n").map((l) => l.trim()).filter(Boolean);
  return lines.find((l) => /^\[stderr\]|^(Code de sortie|Exit code)|erreur|error/i.test(l)) ?? lines[lines.length - 1] ?? null;
}

function ActivityRow({ entry, selected, onSelect }) {
  const meta = CATEGORY_META[entry.category] ?? CATEGORY_META.poste;
  const { verb, target } = sentenceParts(entry);
  const excerpt = entry.outcome === "fail" ? errorExcerpt(entry.detail) : null;

  return (
    <button
      type="button"
      className={`vlg-ev${selected ? " sel" : ""}`}
      style={{ "--cat-color": meta.color, "--cat-dim": meta.dim }}
      aria-pressed={selected}
      onClick={() => onSelect(entry.id)}
    >
      <span className="vlg-stripe" />
      <span className="vlg-ico" aria-hidden="true">
        <meta.Icon />
      </span>
      <span className="vlg-txt">
        <b>{entry.actor || tr("val.unknown")}</b> {verb} <span className="vlg-target">{target}</span>
      </span>
      <span className="vlg-time" title={fmtDateTime(entry.created_at)}>
        {activityMetaLabel(entry.created_at)}
      </span>
      <span className="vlg-meta">
        <span>{meta.label}</span>
        {entry.outcome && (
          <>
            <span>·</span>
            <span className={`vlg-outcome ${entry.outcome}`}>● {outcomeLabel(entry.outcome)}</span>
          </>
        )}
        {excerpt && (
          <>
            <span>·</span>
            <span className="vlg-excerpt" title={excerpt}>
              {excerpt}
            </span>
          </>
        )}
      </span>
    </button>
  );
}

function outcomeLabel(outcome) {
  return tr(outcome === "ok" || outcome === "fail" ? `val.outcome.${outcome}` : "val.outcome.pending");
}

function renderTerminalDetail(text) {
  return text.split("\n").map((line, i) => {
    const cls = line.startsWith("[stderr]") ? " stderr" : /^(Code de sortie|Exit code)/.test(line) ? " exit" : "";
    return (
      <div key={i} className={`activity-detail-term-line${cls}`}>
        {line}
      </div>
    );
  });
}

/**
 * Détail d'une entrée (2026-09-09 en popup, panneau latéral depuis la refonte du 2026-10-24) —
 * mêmes champs qu'avant (`completed_at`/`parameters` inclus, "on est d'accord qu'on a tout
 * mis ?"). Nouveau : "Voir le poste" / "Tout le journal de ce poste" quand la cible est un poste
 * connu. L'API du journal ne renvoie pas d'`agent_id` (`routes/activity.py::ActivityEntryOut`) —
 * rapprochement par nom de poste sur la liste des agents déjà en cache.
 */
function ActivityDetailPanel({ entry, agent, onOpenAgent, onFilterHost }) {
  const meta = CATEGORY_META[entry.category] ?? CATEGORY_META.poste;
  const { verb, target } = sentenceParts(entry);
  const paramEntries = entry.parameters ? Object.entries(entry.parameters) : [];

  return (
    <aside className="vlg-card vlg-detail" style={{ "--cat-color": meta.color, "--cat-dim": meta.dim }} aria-label={tr("vlg.detailAria")}>
      <div className="vlg-detail-head">
        <span className="vlg-detail-ico" aria-hidden="true">
          <meta.Icon />
        </span>
        <div className="vlg-detail-title">
          <h2>{entryTitle(entry)}</h2>
          <span className="vlg-detail-sentence">
            <b>{entry.actor || tr("val.unknown")}</b> {verb} <span className="vlg-target">{target}</span>
          </span>
        </div>
        {entry.outcome && <span className={`vlg-pill ${entry.outcome}`}>{outcomeLabel(entry.outcome)}</span>}
      </div>

      <dl className="vlg-info">
        <dt>{tr("val.info.category")}</dt>
        <dd>
          <span className="vlg-cat-dot" /> {meta.label}
        </dd>
        <dt>{tr("val.info.source")}</dt>
        <dd>{tr(entry.source === "command" ? "val.source.command" : "val.source.audit")}</dd>
        <dt>{tr("val.info.created")}</dt>
        <dd className="vlg-mono">{fmtDateTime(entry.created_at)}</dd>
        {entry.completed_at ? (
          <>
            <dt>{tr("val.info.completed")}</dt>
            <dd className="vlg-mono">
              {fmtDateTime(entry.completed_at)} · {fmtDuration(entry.created_at, entry.completed_at)}
            </dd>
          </>
        ) : (
          entry.source === "command" && (
            <>
              <dt>{tr("val.info.duration")}</dt>
              <dd className="vlg-mono">{tr("val.running")}</dd>
            </>
          )
        )}
        <dt>{tr("val.info.id")}</dt>
        <dd className="vlg-mono vlg-muted">{entry.id}</dd>
      </dl>

      {paramEntries.length > 0 && (
        <div className="vlg-block">
          <span className="vlg-lbl">{tr("val.params")}</span>
          <div className="vlg-params">
            {paramEntries.map(([k, v]) => (
              <div key={k} className="vlg-param">
                <span className="vlg-muted">{PARAM_LABELS[k] ?? k}</span>
                <span className="vlg-mono" title={String(v)}>
                  {String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="vlg-block">
        <div className="vlg-block-head">
          <span className="vlg-lbl">{tr("val.fullDetail")}</span>
          {entry.detail && <CopyButton className="activity-detail-copy-btn" text={entry.detail} />}
        </div>
        {entry.detail ? (
          <div className="activity-detail-terminal vlg-term">{renderTerminalDetail(entry.detail)}</div>
        ) : (
          <p className="vlg-sub" style={{ margin: 0 }}>{tr("val.noDetail")}</p>
        )}
      </div>

      {agent && (
        <div className="vlg-foot">
          <button type="button" className="vanitas-ghost-btn" onClick={() => onOpenAgent(agent.id)}>
            {tr("vlg.openHost", { host: agent.hostname })}
          </button>
          <button type="button" className="vanitas-ghost-btn" onClick={() => onFilterHost(agent.hostname)}>
            {tr("vlg.hostLog")}
          </button>
        </div>
      )}
    </aside>
  );
}

/**
 * "Vanitas" > Administration > Journal (2026-09-09, demande de Nicolas — "changer Commandes en
 * onglet de Log pour chaque action... rechercher en fonction des informations dans les
 * colonnes... un identifiant sur ce qu'il touche, filtrable, qui a créé quoi"). Remplace
 * l'ancien "Commandes" ; lancer une commande reste possible depuis la fiche de chaque poste.
 *
 * Refonte liste + détail (2026-10-24, maquette canvas validée par Nicolas) : bandeau de synthèse
 * (événements sur la période, répartition par catégorie en barre avec légende cliquable, échecs
 * cliquables, acteur le plus actif), liste toujours groupée par jour avec l'extrait d'erreur sous
 * chaque échec, pastilles de résultat, détail dans un panneau latéral au lieu de la popup. Les
 * filtres Type (multi-sélection) et Période (calendrier) sont inchangés. Classes `.vlg-*`.
 */
export default function VanitasActivityLogTab({ onNavigateVanitas, vanitasNav }) {
  const log = useVanitasActivityLog();
  const agents = useVanitasAgents();
  const [query, setQuery] = useState("");
  const [selectedCategories, setSelectedCategories] = useState(() => new Set(CATEGORY_ORDER));
  const [outcomeFilter, setOutcomeFilter] = useState("all");
  const [rangeKey, setRangeKey] = useState("90");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [openFilter, setOpenFilter] = useState(null); // null | "type" | "period"
  const typeRef = useRef(null);
  const periodRef = useRef(null);
  const detailRef = useRef(null);

  useEffect(() => {
    log.ensureLoaded();
    agents.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Pré-remplissage de la recherche depuis une autre page (`vanitasNav.payload.query`), même
  // convention que Logiciels obsolètes.
  useEffect(() => {
    if (vanitasNav?.payload?.query) setQuery(vanitasNav.payload.query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vanitasNav?.token]);

  // Un seul panneau de filtre ouvert à la fois, fermé au clic en dehors des DEUX.
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
      // Bornes inclusives — `customTo` couvre la journée entière (23:59:59.999).
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

  const outcomeCounts = useMemo(() => {
    const c = { all: inRange.length, fail: 0, pending: 0, ok: 0 };
    inRange.forEach((e) => {
      if (e.outcome === "fail" || e.outcome === "ok") c[e.outcome]++;
      else if (e.source === "command") c.pending++;
    });
    return c;
  }, [inRange]);

  const topActor = useMemo(() => {
    const byActor = new Map();
    inRange.forEach((e) => {
      const a = e.actor || tr("val.unknown");
      byActor.set(a, (byActor.get(a) ?? 0) + 1);
    });
    const best = [...byActor.entries()].sort((a, b) => b[1] - a[1])[0];
    return best ? { name: best[0], count: best[1], actors: byActor.size } : null;
  }, [inRange]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return inRange.filter((e) => {
      if (!selectedCategories.has(e.category)) return false;
      if (outcomeFilter === "fail" && e.outcome !== "fail") return false;
      if (outcomeFilter === "ok" && e.outcome !== "ok") return false;
      if (outcomeFilter === "pending" && !(e.source === "command" && e.outcome !== "ok" && e.outcome !== "fail")) return false;
      if (!q) return true;
      const { verb, target } = sentenceParts(e);
      const haystack = [e.actor, CATEGORY_META[e.category]?.label, verb, target, e.detail, e.target_label]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [inRange, query, selectedCategories, outcomeFilter]);

  const sorted = useMemo(() => [...filtered].sort((a, b) => new Date(b.created_at) - new Date(a.created_at)), [filtered]);

  const selected = sorted.find((e) => e.id === selectedId) ?? sorted[0] ?? null;
  const agentByHost = useMemo(() => {
    const m = new Map();
    for (const a of agents.state.data ?? []) m.set(a.hostname?.toLowerCase(), a);
    return m;
  }, [agents.state.data]);
  const selectedAgent = selected && (selected.source === "command" || selected.category === "poste") ? agentByHost.get(selected.target_label?.toLowerCase()) ?? null : null;

  function selectEntry(id) {
    setSelectedId(id);
    if (detailRef.current && window.matchMedia?.("(max-width: 980px)").matches) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const rangeSub =
    rangeKey === CUSTOM_RANGE_KEY
      ? customFrom && customTo
        ? tr("vlg.rangeCustom", { from: fmtShortDate(customFrom), to: fmtShortDate(customTo) })
        : tr("vlg.rangeCustomOpen")
      : tr("vlg.rangeDays", { count: Number(rangeKey) });

  let lastDay = null;

  return (
    <div className="vanitas-hud vlg">
      {log.state.error && <p className="vanitas-hud-error">{log.state.error}</p>}

      <section className="vlg-card vlg-sum" aria-label={tr("vlg.sumAria")}>
        <div className="vlg-col">
          <span className="vlg-lbl">{tr("vlg.events")}</span>
          <span className="vlg-val accent">{inRange.length}</span>
          <span className="vlg-sub vlg-small">{rangeSub}</span>
        </div>
        <div className="vlg-sum-state">
          <span className="vlg-lbl">{tr("vlg.byCategory")}</span>
          <span className="vlg-bar" role="img" aria-label={CATEGORY_ORDER.map((k) => `${counts[k]} ${CATEGORY_META[k].label}`).join(", ")}>
            {CATEGORY_ORDER.map((k) => (counts[k] ? <i key={k} style={{ flex: counts[k], background: CATEGORY_META[k].color }} /> : null))}
          </span>
          <div className="vlg-legend">
            {CATEGORY_ORDER.map((k) => (
              <button key={k} type="button" className="vlg-leg" onClick={() => setSelectedCategories(new Set([k]))}>
                <i style={{ background: CATEGORY_META[k].color }} />
                <b>{counts[k]}</b> {CATEGORY_META[k].label.toLowerCase()}
              </button>
            ))}
          </div>
        </div>
        <div className="vlg-col vlg-sum-third">
          <span className="vlg-lbl">{tr("vlg.fails")}</span>
          <button type="button" className="vlg-val vlg-val-btn" style={outcomeCounts.fail ? { color: "var(--hud-high)" } : undefined} onClick={() => setOutcomeFilter("fail")}>
            {outcomeCounts.fail}
          </button>
          <span className="vlg-sub vlg-small">{tr("vlg.failsSub")}</span>
        </div>
        <div className="vlg-col vlg-sum-fourth">
          <span className="vlg-lbl">{tr("vlg.topActor")}</span>
          {topActor ? (
            <>
              <button type="button" className="vlg-actor" onClick={() => setQuery(topActor.name)}>
                {topActor.name}
              </button>
              <span className="vlg-sub vlg-small">{tr("vlg.topActorSub", { count: topActor.count, actors: topActor.actors })}</span>
            </>
          ) : (
            <span className="vlg-sub">—</span>
          )}
        </div>
      </section>

      <div className="vlg-split">
        <section className="vlg-card vlg-list" aria-label={tr("vlg.listAria")}>
          <div className="vlg-toolbar">
            <label className="vlg-search-wrap">
              <span className="vlg-sr">{tr("vlg.search")}</span>
              <input type="search" className="vlg-input" placeholder={tr("vlg.search")} value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" />
            </label>
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
          <span className="vlg-chips" role="group" aria-label={tr("vlg.outcomeAria")}>
            {[
              ["all", tr("vlg.f.all"), "var(--vlg-muted)"],
              ["fail", tr("vlg.f.fail"), "var(--hud-high)"],
              ["pending", tr("vlg.f.pending"), "var(--hud-accent)"],
              ["ok", tr("vlg.f.ok"), "var(--hud-good)"],
            ].map(([k, label, color]) => (
              <button key={k} type="button" className={`vlg-chip${outcomeFilter === k ? " on" : ""}`} aria-pressed={outcomeFilter === k} onClick={() => setOutcomeFilter(k)}>
                <i className="dot" style={{ background: color }} />
                {label} <b>{outcomeCounts[k]}</b>
              </button>
            ))}
          </span>
          <span className="vlg-sub">{tr("val.note", { shown: sorted.length, count: inRange.length })}</span>

          {log.state.status === "loading" ? (
            <p className="vlg-empty">{tr("v.loading")}</p>
          ) : sorted.length === 0 ? (
            <p className="vlg-empty">{entries.length === 0 ? tr("val.empty") : tr("val.noResult")}</p>
          ) : (
            <div className="vlg-rows">
              {sorted.map((entry) => {
                const day = fmtDay(entry.created_at);
                const showDay = day !== lastDay;
                lastDay = day;
                return (
                  <div key={entry.id} className="vlg-row-wrap">
                    {showDay && <div className="vlg-day">{day}</div>}
                    <ActivityRow entry={entry} selected={selected?.id === entry.id} onSelect={selectEntry} />
                  </div>
                );
              })}
            </div>
          )}
        </section>

        <div ref={detailRef} className="vlg-detail-slot">
          {selected ? (
            <ActivityDetailPanel
              key={selected.id}
              entry={selected}
              agent={selectedAgent}
              onOpenAgent={(agentId) => onNavigateVanitas?.("vanitas-devices", { selectAgentId: agentId })}
              onFilterHost={(host) => {
                setQuery(host);
                setOutcomeFilter("all");
                setSelectedCategories(new Set(CATEGORY_ORDER));
              }}
            />
          ) : (
            <div className="vlg-card vlg-empty-panel">
              <p className="vlg-sub">{tr("vlg.pick")}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
