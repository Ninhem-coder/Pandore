import { describe, expect, it } from "vitest";
import { demoRequest } from "./server.js";

const get = (path) => demoRequest("GET", path);

describe("demo backend", () => {
  it("signs in a demo administrator", async () => {
    const me = await get("/api/auth/me");
    expect(me.role).toBe("admin");
    expect(me.username).toBe("admin.demo");
  });

  it("serves the Intune summary with a strict compliance rate", async () => {
    const s = await get("/api/intune/summary");
    expect(s.totalDevices).toBeGreaterThan(100);
    expect(s.complianceRate).toBe(`${((s.compliantCount / s.totalDevices) * 100).toFixed(1)}%`);
  });

  it("keeps the compliance detail consistent with the policy summary", async () => {
    const [summary, detail] = await Promise.all([get("/api/intune/compliance-policy-summary"), get("/api/intune/compliance-detail")]);
    const failing = summary.reduce((n, p) => n + p.failedCount + p.errorCount, 0);
    expect(detail.aggregateTotalCount).toBe(failing);
    expect(detail.policies.length).toBeGreaterThan(0);
  });

  it("only uses fictional device names and the reserved demo domain", async () => {
    const inventory = await get("/api/device-inventory");
    const managed = inventory.filter((d) => d.has_intune);
    expect(managed.length).toBeGreaterThan(100);
    for (const d of managed) {
      expect(d.name).toMatch(/^DEMO-/);
      expect(d.user).toMatch(/@demo\.example$/);
    }
    const agents = await get("/api/vanitas/agents");
    expect(agents.every((a) => a.hostname.startsWith("DEMO-"))).toBe(true);
  });

  it("opens the showcase device with Intune and Defender data", async () => {
    const ov = await get("/api/device-overview?device_name=DEMO-WKS-007");
    expect(ov.intune.found).toBe(true);
    expect(ov.defender.found).toBe(true);
    expect(ov.intune.device.complianceState).toBe("noncompliant");
    expect(ov.defender.alerts.some((a) => a.status === "New")).toBe(true);
    expect(Object.keys(ov.intune.device).some((k) => k.startsWith("_"))).toBe(false);
  });

  it("returns the newest Secure Score first", async () => {
    const history = await get("/api/intune/secure-score?days=30");
    expect(history).toHaveLength(30);
    expect(history[0].createdDateTime > history[29].createdDateTime).toBe(true);
  });

  it("refuses writes and unknown routes with the business-error contract", async () => {
    expect(await demoRequest("POST", "/api/vanitas/groups", { name: "x" })).toMatchObject({ error: true, type: "DemoMode" });
    expect(await demoRequest("DELETE", "/api/vanitas/agents/abc")).toMatchObject({ error: true });
    expect(await get("/api/intune/unknown-route")).toMatchObject({ error: true });
  });

  it("is deterministic from one load to the next", async () => {
    const a = await get("/api/vanitas/compliance/summary");
    const b = await get("/api/vanitas/compliance/summary");
    expect(a).toEqual(b);
  });
});
