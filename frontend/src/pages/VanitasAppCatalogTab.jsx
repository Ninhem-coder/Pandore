import { useEffect, useMemo, useState } from "react";
import { useVanitasInstallers } from "../hooks/useDashboardData.js";
import { fmtBytes, fmtDateTime } from "./vanitasShared.jsx";

/**
 * "Vanitas" > Catalogue d'application (2026-09-09, retour de Nicolas — "je pensais faire en
 * sorte d'avoir Application dans l'onglet Administration pour rajouter faire des modifications
 * sur une application et Catalogue d'application en dessous de Vue d'ensemble avec toutes les
 * applications qu'on a publié depuis Application dans un premier temps") : remontée en item nu
 * juste sous "Vue d'ensemble" (comme "Catalogue d'application" côté Pandore, `Sidebar.jsx`),
 * accessible à TOUT compte connecté — la distinction admin/lecture ne porte que sur l'AJOUT/la
 * MODIFICATION (`VanitasInstallersTab.jsx`, "Application" sous "Administration"), jamais sur la
 * simple consultation, même philosophie que le catalogue Pandore (`GET .../app-library` déjà
 * lecture libre).
 *
 * "Dans un premier temps" (mot de Nicolas) : liste en lecture seule des installeurs déjà
 * publiés, aucune action d'écriture ici (ni ajout, ni modification, ni suppression — tout ça
 * reste dans "Application"). Même hook `useVanitasInstallers()` que la page d'administration,
 * même cache partagé — parcourir ce catalogue ne redéclenche jamais l'appel réseau si
 * "Application" a déjà été visitée dans la session (et réciproquement).
 */
export default function VanitasAppCatalogTab() {
  const installers = useVanitasInstallers();
  const [query, setQuery] = useState("");

  useEffect(() => {
    installers.ensureLoaded();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return installers.state.data;
    return installers.state.data.filter((i) =>
      [i.name, i.version, i.original_filename]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [installers.state.data, query]);

  return (
    <div className="vanitas-hud">
      {installers.state.error && <p className="vanitas-hud-error">{installers.state.error}</p>}

      <div className="vanitas-hud-toolbar" style={{ marginBottom: "12px" }}>
        <div className="vanitas-hud-search">
          <span className="prompt">&gt;</span>
          <input
            type="text"
            placeholder="Rechercher une application (nom, version, fichier)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoComplete="off"
          />
        </div>
      </div>

      <div className="vanitas-hud-card vanitas-hud-frame">
        <div className="vanitas-hud-card-head">
          <h2>
            {filtered.length} / {installers.state.data.length} application
            {installers.state.data.length > 1 ? "s" : ""}
          </h2>
          <span className="vanitas-hud-card-note">GÉRER DEPUIS « APPLICATION » (ADMINISTRATION)</span>
        </div>
        {installers.state.status === "loading" ? (
          <p className="vanitas-hud-empty-note">CHARGEMENT…</p>
        ) : installers.state.data.length === 0 ? (
          <p className="vanitas-hud-empty-note">
            Aucune application publiée pour l'instant — ajoutes-en une depuis « Application »
            (Administration).
          </p>
        ) : filtered.length === 0 ? (
          <p className="vanitas-hud-empty-note">0 résultat pour ce filtre.</p>
        ) : (
          <div className="vanitas-hud-table-wrap">
            <table className="vanitas-hud-table">
              <thead>
                <tr>
                  <th>Nom</th>
                  <th>Fichier</th>
                  <th>Taille</th>
                  <th>Publiée le</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((i) => (
                  <tr key={i.id}>
                    <td className="vanitas-hud-host">
                      <span className="name">
                        {i.name}
                        {i.version ? ` · v${i.version}` : ""}
                      </span>
                      <span className="id">{i.install_command}</span>
                    </td>
                    <td className="cve-mono cve-small">{i.original_filename}</td>
                    <td>{fmtBytes(i.size_bytes)}</td>
                    <td className="cve-small">{fmtDateTime(i.uploaded_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
