"""
Microsoft Secure Score (tenant M365, distinct de l'Exposure Score MDE) — extrait de
`intune/tools.py` (1373 lignes) à la revue d'architecture du 2026-08-17, deuxième passe
(découpage par domaine : `intune/devices.py`, `intune/compliance.py`,
`intune/compliance_detail.py`, `intune/apps.py`, `intune/users.py`, ce fichier).

Comme le reste des modules issus de ce découpage : fonctions "nues" réutilisées à la fois
par le serveur MCP (`intune/mcp_server.py`) et par l'API REST du dashboard (`api_server.py`).
"""
from common.http_client import handle_tool_errors
from intune.client import client


@handle_tool_errors
def get_secure_score(days: int = 30) -> list[dict]:
    """
    Historique du Microsoft Secure Score (endpoint /security/secureScores, distinct de
    l'Exposure Score MDE : celui-ci couvre tout le tenant M365 — Identité, Données,
    Appareils, Apps, Infrastructure — pas seulement les endpoints Defender).

    Contrairement à l'Exposure Score, l'historique est géré NATIVEMENT par Graph (90 jours
    glissants, un point par jour, trié du plus récent au plus ancien) : pas besoin d'un
    fichier d'historique ni d'une tâche planifiée pour la tendance, `days` (plafonné à 90)
    suffit à demander directement la fenêtre voulue via `$top`.

    Chaque entrée porte, en plus de `currentScore`/`maxScore` : `controlScores` (le détail
    par contrôle pour ce jour-là — controlCategory/controlName/score) et
    `averageComparativeScores` (benchmarks : AllTenants/TotalSeats/IndustryTypes, dans la
    MÊME échelle de points que currentScore/maxScore, PAS déjà en pourcentage — diviser par
    maxScore du même jour pour comparer).

    Permission Graph requise : **SecurityEvents.Read.All (Application)**. C'est un scope
    DIFFÉRENT de ceux déjà consentis pour /deviceManagement/* et /users sur cette même app
    registration (AZURE_CLIENT_ID) — à ajouter explicitement dans Entra (avec consentement
    admin) si cet appel renvoie un HTTPStatusError 403 : ce n'est pas un bug de ce code, la
    permission n'est simplement pas encore accordée.
    """
    top = max(1, min(int(days or 30), 90))
    data = client.get("/security/secureScores", params={"$top": top})
    return data.get("value", [])


@handle_tool_errors
def list_secure_score_control_profiles() -> list[dict]:
    """
    Catalogue des contrôles Secure Score (endpoint /security/secureScoreControlProfiles) :
    pour chaque contrôle, `title`, `remediation` (quoi faire), `actionUrl` (lien direct vers
    le bon blade admin), `implementationCost`/`userImpact` (low/moderate/high), `tier`
    (Core/Defense in Depth/Advanced), `maxScore`.

    C'est ce catalogue, rapproché du `controlScores` du jour le plus récent renvoyé par
    `get_secure_score`, qui permet de calculer un gain potentiel (maxScore - score obtenu)
    par contrôle plutôt que d'afficher un score global sans plan d'action — voir
    `theme.js::computeSecureScoreQuickWins` côté frontend.

    Jointure `secureScoreControlProfile.id == controlScore.controlName` : c'est le
    comportement documenté de cette API, mais IL N'A PAS PU ÊTRE VÉRIFIÉ sur le tenant
    de production (nécessite la permission SecurityEvents.Read.All, pas encore accordée au
    moment de l'écriture de cet outil) — à confirmer sur données réelles dès que possible,
    même principe que les jointures Intune de ce fichier, jamais supposées bonnes sans
    preuve chiffrée sur ce tenant précis.

    Même permission que get_secure_score (SecurityEvents.Read.All, Application).
    """
    return client.get_all_pages("/security/secureScoreControlProfiles")
