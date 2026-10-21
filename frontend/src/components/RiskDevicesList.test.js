import { describe, it, expect, vi } from "vitest";
import RiskDevicesList from "./RiskDevicesList.jsx";

/**
 * Tests du rendu conditionnel <button>/<div> de RiskDevicesList (revue de code du
 * 2026-08-20). Le composant n'utilise aucun hook (pure fonction de ses props) : l'appeler
 * directement, sans rendu React/DOM, renvoie l'arbre d'éléments React tel quel (objets
 * `{type, props}`) — suffisant pour vérifier quelle balise est choisie et que l'`onClick`
 * appelle bien `onSelectDevice` avec le bon nom, sans avoir besoin de jsdom/React Testing
 * Library (absents de ce projet, voir vite.config.js).
 */

const device = { id: "1", computerDnsName: "lse-wks-mvi-2", exposureLevel: "High", alertCount: 2, osPlatform: "Windows 11" };

describe("RiskDevicesList — lignes cliquables", () => {
  it("rend un <button> quand onSelectDevice est fourni et le device a un nom, et appelle le callback avec ce nom", () => {
    const onSelectDevice = vi.fn();
    const el = RiskDevicesList({ devices: [device], onSelectDevice });
    const row = el.props.children[0];

    expect(row.type).toBe("button");
    row.props.onClick();
    expect(onSelectDevice).toHaveBeenCalledWith("lse-wks-mvi-2");
    expect(onSelectDevice).toHaveBeenCalledTimes(1);
  });

  it("retombe sur un <div> non interactif quand onSelectDevice n'est pas fourni", () => {
    const el = RiskDevicesList({ devices: [device] });
    const row = el.props.children[0];
    expect(row.type).toBe("div");
  });

  it("retombe sur un <div> quand le device n'a pas de nom, même avec onSelectDevice fourni", () => {
    const onSelectDevice = vi.fn();
    const el = RiskDevicesList({
      devices: [{ id: "2", exposureLevel: "Low", alertCount: 0 }],
      onSelectDevice,
    });
    const row = el.props.children[0];
    expect(row.type).toBe("div");
  });

  it("affiche le message vide sans planter quand la liste est vide", () => {
    const el = RiskDevicesList({ devices: [], onSelectDevice: vi.fn() });
    expect(el.type).toBe("p");
  });
});
