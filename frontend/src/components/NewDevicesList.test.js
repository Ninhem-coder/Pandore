import { describe, it, expect, vi } from "vitest";
import NewDevicesList from "./NewDevicesList.jsx";

/**
 * Même principe que RiskDevicesList.test.js (voir son commentaire) : NewDevicesList n'utilise
 * aucun hook, donc l'appeler directement comme une fonction suffit à vérifier le rendu
 * conditionnel <button>/<div> et le câblage d'onSelectDevice, sans jsdom/RTL.
 */

const device = { id: "1", computerDnsName: "guillaume_noinville_iPhone18,3", firstSeen: "2026-08-19T00:00:00Z", osPlatform: "iOS", onboardingStatus: "Onboarded" };

describe("NewDevicesList — lignes cliquables", () => {
  it("rend un <button> quand onSelectDevice est fourni et le device a un nom, et appelle le callback avec ce nom", () => {
    const onSelectDevice = vi.fn();
    const el = NewDevicesList({ devices: [device], onSelectDevice });
    const row = el.props.children[0];

    expect(row.type).toBe("button");
    row.props.onClick();
    expect(onSelectDevice).toHaveBeenCalledWith("guillaume_noinville_iPhone18,3");
  });

  it("retombe sur un <div> non interactif quand onSelectDevice n'est pas fourni", () => {
    const el = NewDevicesList({ devices: [device] });
    const row = el.props.children[0];
    expect(row.type).toBe("div");
  });

  it("retombe sur un <div> quand le device n'a pas de nom, même avec onSelectDevice fourni", () => {
    const onSelectDevice = vi.fn();
    const el = NewDevicesList({
      devices: [{ id: "2", firstSeen: "2026-08-19T00:00:00Z" }],
      onSelectDevice,
    });
    const row = el.props.children[0];
    expect(row.type).toBe("div");
  });

  it("affiche le message vide sans planter quand la liste est vide", () => {
    const el = NewDevicesList({ devices: [], onSelectDevice: vi.fn() });
    expect(el.type).toBe("p");
  });
});
