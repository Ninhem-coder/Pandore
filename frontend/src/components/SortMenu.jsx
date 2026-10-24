import { useEffect, useId, useRef, useState } from "react";
import { tr } from "../i18n/core.js";

/**
 * Contrôle de tri commun aux pages Vanitas (2026-10-24, direction A validée par Nicolas sur le
 * canvas — remplace les `<select>` natifs, rendus différemment selon la page et sans choix du
 * sens) : un bouton « ↓ Trié par <critère> ▾ » qui ouvre un menu — critères (coche sur l'actif,
 * indice de l'ordre naturel) puis sens croissant / décroissant.
 *
 * `options` : `[{ value, label, hint, dir }]` où `dir` ("asc" | "desc") est l'ordre NATUREL du
 * critère, celui qu'on obtient en le choisissant (ex. « Dernier contact » → desc, plus récent
 * d'abord ; « Nom » → asc). Choisir un critère remet donc le sens à son ordre naturel ; les
 * boutons de sens l'inversent ensuite. `onChange(value, dir)` reçoit toujours les deux.
 *
 * Accessibilité : `aria-haspopup="menu"`/`aria-expanded`, items `menuitemradio`, flèches
 * haut/bas pour se déplacer, Échap ou clic extérieur pour fermer (le focus revient au bouton).
 */
export default function SortMenu({ options, value, dir, onChange, className = "" }) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const buttonRef = useRef(null);
  const itemRefs = useRef([]);
  const menuId = useId();
  const current = options.find((o) => o.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return undefined;
    function onPointerDown(e) {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    }
    function onKeyDown(e) {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    }
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    // Focus sur le critère actif à l'ouverture.
    const idx = Math.max(0, options.findIndex((o) => o.value === value));
    itemRefs.current[idx]?.focus();
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  function onMenuKeyDown(e) {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const items = itemRefs.current.filter(Boolean);
    const i = items.indexOf(document.activeElement);
    const next = e.key === "ArrowDown" ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
    items[next]?.focus();
  }

  function pick(option) {
    onChange(option.value, option.dir);
    setOpen(false);
    buttonRef.current?.focus();
  }

  return (
    <div ref={rootRef} className={`sortmenu ${className}`}>
      <button
        ref={buttonRef}
        type="button"
        className={`sortmenu-btn${open ? " open" : ""}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="sortmenu-arrow" aria-hidden="true">
          {dir === "desc" ? "↓" : "↑"}
        </span>
        <span className="sortmenu-pre">{tr("sort.by")}</span>
        <span className="sortmenu-cur">{current.label}</span>
        <span className="sortmenu-caret" aria-hidden="true">
          ▾
        </span>
      </button>
      {open && (
        <div id={menuId} className="sortmenu-menu" role="menu" aria-label={tr("sort.menu")} onKeyDown={onMenuKeyDown}>
          <span className="sortmenu-head">{tr("sort.menu")}</span>
          {options.map((o, i) => {
            const on = o.value === current.value;
            return (
              <button
                key={o.value}
                ref={(el) => (itemRefs.current[i] = el)}
                type="button"
                role="menuitemradio"
                aria-checked={on}
                className={`sortmenu-opt${on ? " on" : ""}`}
                onClick={() => pick(o)}
              >
                <span className="sortmenu-check" aria-hidden="true">
                  {on ? "✓" : ""}
                </span>
                <span>{o.label}</span>
                {o.hint && <span className="sortmenu-hint">{o.hint}</span>}
              </button>
            );
          })}
          <div className="sortmenu-dir" role="group" aria-label={tr("sort.direction")}>
            {["asc", "desc"].map((d, j) => (
              <button
                key={d}
                ref={(el) => (itemRefs.current[options.length + j] = el)}
                type="button"
                role="menuitemradio"
                aria-checked={dir === d}
                className={dir === d ? "on" : ""}
                onClick={() => {
                  onChange(current.value, d);
                  setOpen(false);
                  buttonRef.current?.focus();
                }}
              >
                {tr(d === "asc" ? "sort.asc" : "sort.desc")}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
