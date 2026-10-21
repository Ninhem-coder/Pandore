/**
 * Squelette de chargement pour le panneau "Par OS" (3e camembert) et la grille
 * `ComplianceOsGrid` pendant que GET /api/intune/compliance-detail répond — cet appel fait
 * un aller-retour Graph par politique EN ÉCHEC (méthode "policy-first", voir
 * intune/compliance_detail.py::get_compliance_detail, V3), plus un unique `list_devices()`
 * pour résoudre l'OS — corrigé à la revue de code du 2026-08-20, ce commentaire décrivait
 * encore l'ancienne méthode "device-first" (V2, un appel par device non conforme,
 * abandonnée le 2026-08-06). Reste sensiblement plus long que le reste de l'onglet. Un
 * simple "Chargement…" texte laissait l'utilisateur dans le doute ; ce squelette reprend la
 * forme du contenu final (camembert rond, lignes de légende, cartes OS) pour indiquer
 * clairement OÙ le contenu va apparaître, sans afficher de faux pourcentage.
 */
export function DonutSkeleton() {
  return (
    <div className="compliance-layout-sm">
      <div className="skeleton-donut" />
      <div className="skeleton-lines">
        <div className="skeleton skeleton-line" style={{ width: "92%" }} />
        <div className="skeleton skeleton-line" style={{ width: "78%" }} />
        <div className="skeleton skeleton-line" style={{ width: "85%" }} />
      </div>
    </div>
  );
}

export function OsGridSkeleton() {
  return (
    <div className="skeleton-os-grid" aria-hidden="true">
      <div className="skeleton skeleton-os-card" />
      <div className="skeleton skeleton-os-card" />
      <div className="skeleton skeleton-os-card" />
    </div>
  );
}
