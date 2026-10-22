import { describe, it, expect } from "vitest";
import {
  prettyDetail,
  sinceIsoFor,
  SeverityPill,
  StatusPill,
  SignalTypeBadge,
  SEVERITY_LABEL,
  SIGNAL_TYPE_LABEL,
  STATUS_LABEL,
} from "./VanitasSuspiciousActivityTab.jsx";

/**
 * Jalon "détection d'activités suspectes sur les postes" (2026-09-14) — même principe que
 * NewDevicesList.test.js/RiskDevicesList.test.js pour les petits composants de présentation
 * (aucun hook interne, donc appelables directement comme des fonctions, sans jsdom/RTL — cette
 * codebase n'a ni l'un ni l'autre) et que theme.test.js pour la logique pure (`prettyDetail`/
 * `sinceIsoFor`). `SuspiciousEventsTable`/`SuspiciousEventDetailModal`/le composant par défaut
 * ne sont PAS testés ici : ils utilisent `useState`/`useMemo`/`useEffect` en interne, donc un
 * appel direct planterait (« Invalid hook call ») faute d'un vrai rendu React — cohérent avec le
 * reste de cette suite, qui ne teste que la logique pure et les composants sans hook.
 */

describe("vocabulaire FR — jalon activités suspectes", () => {
  it("couvre les 3 sévérités du backend (low/med/high)", () => {
    expect(Object.keys(SEVERITY_LABEL).sort()).toEqual(["high", "low", "med"]);
  });

  it("couvre les 4 types de signal du backend", () => {
    expect(Object.keys(SIGNAL_TYPE_LABEL).sort()).toEqual(["event_log", "network", "process", "usb"]);
  });

  it("couvre les 4 statuts de triage du backend", () => {
    expect(Object.keys(STATUS_LABEL).sort()).toEqual(["acknowledged", "escalated", "false_positive", "new"]);
  });
});

describe("SeverityPill", () => {
  it("mappe 'med' vers la classe CSS existante 'medium' (.vanitas-hud-sev-pill), jamais 'med'", () => {
    const el = SeverityPill({ severity: "med" });
    expect(el.props.className).toBe("vanitas-hud-sev-pill medium");
    expect(el.props.children).toBe("Moyenne");
  });

  it("mappe low/high directement (déjà identiques aux classes CSS)", () => {
    expect(SeverityPill({ severity: "low" }).props.className).toBe("vanitas-hud-sev-pill low");
    expect(SeverityPill({ severity: "high" }).props.className).toBe("vanitas-hud-sev-pill high");
  });

  it("retombe sur 'neutral' pour une sévérité inconnue plutôt que de planter", () => {
    const el = SeverityPill({ severity: "wat" });
    expect(el.props.className).toBe("vanitas-hud-sev-pill neutral");
  });
});

describe("StatusPill", () => {
  it("mappe chaque statut de triage vers le ton .vanitas-hud-status-pill attendu", () => {
    expect(StatusPill({ status: "new" }).props.className).toBe("vanitas-hud-status-pill warn");
    expect(StatusPill({ status: "acknowledged" }).props.className).toBe("vanitas-hud-status-pill pending");
    expect(StatusPill({ status: "false_positive" }).props.className).toBe("vanitas-hud-status-pill ok");
    expect(StatusPill({ status: "escalated" }).props.className).toBe("vanitas-hud-status-pill bad");
  });
});

describe("SignalTypeBadge", () => {
  it("affiche le libellé FR du type de signal", () => {
    const el = SignalTypeBadge({ signalType: "usb" });
    expect(el.props.children).toBe("Support amovible (USB)");
  });

  it("affiche le type brut si inconnu, sans planter", () => {
    const el = SignalTypeBadge({ signalType: "mystere" });
    expect(el.props.children).toBe("mystere");
  });
});

describe("prettyDetail", () => {
  it("renvoie null pour une valeur absente", () => {
    expect(prettyDetail(null)).toBeNull();
    expect(prettyDetail(undefined)).toBeNull();
  });

  it("formate un objet déjà parsé (contrat du détail unitaire GET /suspicious-events/{id})", () => {
    expect(prettyDetail({ process: "certutil.exe", args: "-decode" })).toBe(
      JSON.stringify({ process: "certutil.exe", args: "-decode" }, null, 2)
    );
  });

  it("parse une chaîne JSON (au cas où la liste renverrait le détail non décodé)", () => {
    expect(prettyDetail('{"port": 4444}')).toBe(JSON.stringify({ port: 4444 }, null, 2));
  });

  it("renvoie une chaîne non-JSON telle quelle plutôt que de planter", () => {
    expect(prettyDetail("texte libre, pas du JSON")).toBe("texte libre, pas du JSON");
  });
});

describe("sinceIsoFor", () => {
  it("renvoie undefined pour 'all' (pas de borne basse)", () => {
    expect(sinceIsoFor("all")).toBeUndefined();
  });

  it("renvoie undefined pour une clé inconnue plutôt qu'une date fausse", () => {
    expect(sinceIsoFor("nope")).toBeUndefined();
  });

  it("renvoie une date ISO passée, à ~24h près du nombre de jours attendu", () => {
    const iso = sinceIsoFor("7");
    const deltaMs = Date.now() - new Date(iso).getTime();
    const deltaDays = deltaMs / 86_400_000;
    expect(deltaDays).toBeGreaterThan(6.9);
    expect(deltaDays).toBeLessThan(7.1);
  });

  it("30 jours et 90 jours donnent des bornes strictement croissantes", () => {
    const d7 = new Date(sinceIsoFor("7")).getTime();
    const d30 = new Date(sinceIsoFor("30")).getTime();
    const d90 = new Date(sinceIsoFor("90")).getTime();
    // Plus la fenêtre est large, plus la borne basse est ANCIENNE (timestamp plus petit).
    expect(d90).toBeLessThan(d30);
    expect(d30).toBeLessThan(d7);
  });
});
