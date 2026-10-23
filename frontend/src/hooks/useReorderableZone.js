import { useLayoutEffect, useRef, useState } from "react";

/** Glisser-déposer EN DIRECT (reorder dès `dragenter`, pas seulement au `drop`) + animation
 * FLIP, persisté dans `localStorage` sous `storageKey`. Une zone = une liste ordonnée de clés de
 * tuiles ; on réordonne À L'INTÉRIEUR d'une zone, jamais d'une zone à l'autre (décision de
 * Nicolas pour la Vue d'ensemble Pandore, reprise telle quelle par celle de Vanitas).
 *
 * Extrait d'OverviewTab.jsx (2026-10-23) pour être partagé avec VanitasOverviewTab.jsx —
 * comportement inchangé. `sizes` (index de cran par clé) est optionnel : une zone sans
 * redimensionnement passe `{}` et n'appelle jamais `resize`. `sizeCount` = nombre de crans
 * disponibles, `defaultSize` = cran supposé d'une clé absente de `sizes` lors d'un `resize`. */
export default function useReorderableZone(defaultOrder, defaultSizes, storageKey, { sizeCount = 1, defaultSize = 0 } = {}) {
  const [layout, setLayout] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      if (saved && Array.isArray(saved.order) && saved.order.length === defaultOrder.length && defaultOrder.every((k) => saved.order.includes(k))) {
        return { order: saved.order, sizes: saved.sizes || defaultSizes };
      }
    } catch {
      // localStorage indisponible/corrompu — agencement par défaut, pas bloquant.
    }
    return { order: defaultOrder, sizes: defaultSizes };
  });

  const nodesRef = useRef(new Map());
  const rectsRef = useRef(new Map());
  const dragKeyRef = useRef(null);
  const [draggingKey, setDraggingKey] = useState(null);

  function registerNode(key, node) {
    if (node) nodesRef.current.set(key, node);
    else nodesRef.current.delete(key);
  }

  function captureRects() {
    const map = new Map();
    nodesRef.current.forEach((node, key) => map.set(key, node.getBoundingClientRect()));
    rectsRef.current = map;
  }

  useLayoutEffect(() => {
    nodesRef.current.forEach((node, key) => {
      const before = rectsRef.current.get(key);
      if (!before) return;
      const after = node.getBoundingClientRect();
      const dx = before.left - after.left;
      const dy = before.top - after.top;
      if (!dx && !dy) return;
      node.style.transition = "none";
      node.style.transform = `translate(${dx}px, ${dy}px)`;
      // eslint-disable-next-line no-unused-expressions
      node.offsetHeight; // force le reflow avant de relâcher
      node.style.transition = "transform 0.32s cubic-bezier(0.2, 0.8, 0.2, 1)";
      node.style.transform = "";
    });
    rectsRef.current = new Map();
    try {
      localStorage.setItem(storageKey, JSON.stringify(layout));
    } catch {
      // best effort
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout]);

  function moveBefore(sourceKey, targetKey) {
    if (sourceKey === targetKey) return;
    captureRects();
    setLayout((prev) => {
      const next = prev.order.filter((k) => k !== sourceKey);
      next.splice(next.indexOf(targetKey), 0, sourceKey);
      return { ...prev, order: next };
    });
  }

  function resize(key, delta) {
    captureRects();
    setLayout((prev) => {
      const current = prev.sizes[key] ?? defaultSize;
      const nextIndex = Math.max(0, Math.min(sizeCount - 1, current + delta));
      return { ...prev, sizes: { ...prev.sizes, [key]: nextIndex } };
    });
  }

  return {
    order: layout.order,
    sizes: layout.sizes,
    registerNode,
    draggingKey,
    resize,
    dragHandleProps: (key) => ({
      draggable: true,
      onDragStart: () => {
        dragKeyRef.current = key;
        setDraggingKey(key);
      },
      onDragEnd: () => {
        dragKeyRef.current = null;
        setDraggingKey(null);
      },
    }),
    // Réordonne DÈS l'entrée sur une autre tuile — c'est ce qui donne la sensation de
    // preview en direct demandée par Nicolas : les autres tuiles se décalent immédiatement,
    // avant même de relâcher le clic.
    onDragEnter: (key) => {
      if (dragKeyRef.current) moveBefore(dragKeyRef.current, key);
    },
    onDrop: () => {
      dragKeyRef.current = null;
      setDraggingKey(null);
    },
    resetLayout: () => {
      captureRects();
      setLayout({ order: defaultOrder, sizes: defaultSizes });
    },
  };
}
