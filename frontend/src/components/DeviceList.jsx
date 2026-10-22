import { currentLocale, tr } from "../i18n/core.js";
/** Port de build_new_devices_html() : compteur + liste scrollable (max-height 380px,
 * voir .devices-list dans styles.css) — même habillage que la carte HTML du skill. */
export default function DeviceList({ devices, emptyLabel }) {
  const rows = (devices || []).filter((d) => !d?.error);

  if (rows.length === 0) {
    return <p className="devices-empty">{emptyLabel}</p>;
  }

  const plural = rows.length > 1 ? "s" : "";

  return (
    <div className="devices-panel">
      <p className="devices-count-label">
        {rows.length} device{plural} détecté{plural}
      </p>
      <ul className="devices-list">
        {rows.map((d, i) => (
          <li className="device-row" key={d.id ?? d.computerDnsName ?? i}>
            <div className="device-main">
              <span className="device-name">{d.computerDnsName ?? tr("common.unknownDevice")}</span>
              <span className="device-meta">
                {d.osPlatform ?? "?"} · {d.lastSeen ? new Date(d.lastSeen).toLocaleString(currentLocale()) : tr("common.unknownDate")}
              </span>
            </div>
            <span className="device-badge">{d.onboardingStatus ?? "?"}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
