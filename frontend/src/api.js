/**
 * Petit client fetch pour l'API locale (backend/api_server.py, proxifiée sous /api
 * par Vite en dev). Chaque fonction peut lever si l'appel réseau échoue (l'appelant
 * gère l'état loading/erreur) ; une erreur "métier" (auth Defender/Intune en échec,
 * etc.) revient elle en payload {error: true, ...} — voir handle_tool_errors côté backend.
 */
// `credentials: "include"` ajouté aux 5 helpers (2026-09-07, authentification multi-comptes) —
// sans lui, le navigateur n'envoie jamais le cookie de session posé par POST /api/auth/login
// sur les appels suivants, même en same-origin dans certaines configurations strictes. Voir
// backend/auth/ pour le reste du mécanisme (le contrat d'erreur ci-dessus reste inchangé : un
// 401 lève toujours comme n'importe quel autre HTTP non-2xx, à charge de AuthGate de
// distinguer ce cas précis pour afficher LoginForm plutôt qu'un message d'erreur générique).
//
// `errorMessage()` (2026-09-08, page Paramètres) — un `HTTPException(status, detail)` FastAPI
// sérialise en `{"detail": "..."}` ; jusqu'ici jamais lu, chaque helper levait juste "HTTP 400"
// sans le VRAI motif ("Mot de passe actuel incorrect.", "Le compte « X » existe déjà."...). Un
// message générique suffisait pour les erreurs déjà connues d'avance (ex. LoginForm.jsx, qui
// affiche volontairement un message fixe pour ne pas confirmer l'existence d'un compte), mais
// la gestion des comptes a de VRAIES validations métier à faire remonter telles quelles.
async function errorMessage(res, path) {
  try {
    const data = await res.json();
    if (data && typeof data.detail === "string" && data.detail) {
      return data.detail;
    }
  } catch {
    // Corps non-JSON ou vide — repli sur le message générique ci-dessous.
  }
  return `${path} → HTTP ${res.status}`;
}

async function getJSON(path) {
  const res = await fetch(path, { credentials: "include" });
  if (!res.ok) {
    throw new Error(await errorMessage(res, path));
  }
  return res.json();
}

// Ajoutés pour "Suivi CVE" (2026-08-10) — premiers verbes non-GET de ce fichier, tout le
// reste de l'app n'ayant jusqu'ici que des lectures. Même contrat d'erreur que getJSON (lève
// sur échec réseau/HTTP, laisse l'appelant gérer l'état loading/erreur).
async function postJSON(path, body) {
  const res = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    throw new Error(await errorMessage(res, path));
  }
  return res.json();
}

// Ajouté pour la modification d'une entrée de bibliothèque (2026-08-26, EditAppTab.jsx) —
// même contrat que postJSON, verbe HTTP différent (remplace intégralement la ressource plutôt
// que d'en créer une nouvelle).
async function putJSON(path, body) {
  const res = await fetch(path, {
    method: "PUT",
    credentials: "include",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    throw new Error(await errorMessage(res, path));
  }
  return res.json();
}

async function deleteJSON(path) {
  const res = await fetch(path, { method: "DELETE", credentials: "include" });
  if (!res.ok) {
    throw new Error(await errorMessage(res, path));
  }
  return res.json();
}

// Ajouté pour l'assistant de packaging Win32 (2026-08-26) — premier upload de fichier de ce
// dashboard (voir DeployAppWizard.jsx). PAS de header `Content-Type` posé à la main,
// contrairement à postJSON : le navigateur fixe lui-même la boundary multipart sur un body
// `FormData`, la poser manuellement casserait l'encodage.
async function postForm(path, formData) {
  const res = await fetch(path, { method: "POST", credentials: "include", body: formData });
  if (!res.ok) {
    throw new Error(await errorMessage(res, path));
  }
  return res.json();
}

export const api = {
  // Authentification multi-comptes (2026-09-07) — voir AuthGate.jsx pour l'appelant.
  auth: {
    login: (username, password) => postJSON("/api/auth/login", { username, password }),
    logout: () => postJSON("/api/auth/logout"),
    me: () => getJSON("/api/auth/me"),
    // Page "Paramètres" (2026-09-08) — self-service (son propre compte) + gestion des comptes
    // réservée admin (require_admin côté serveur, jamais fait confiance au frontend seul).
    updateMe: (body) => putJSON("/api/auth/me", body),
    listUsers: () => getJSON("/api/auth/users"),
    createUser: (body) => postJSON("/api/auth/users", body),
    updateUser: (username, body) => putJSON(`/api/auth/users/${encodeURIComponent(username)}`, body),
    deleteUser: (username) => deleteJSON(`/api/auth/users/${encodeURIComponent(username)}`),
  },
  defenderSummary: () => getJSON("/api/defender/summary"),
  exposureScore: () => getJSON("/api/defender/exposure-score"),
  recommendations: (top = 8) => getJSON(`/api/defender/recommendations?top=${top}`),
  nonOnboarded: () => getJSON("/api/defender/non-onboarded"),
  // Vue d'ensemble v2 (2026-08-10) : "Top devices à risque" (exposureLevel/riskScore) et
  // "Nouveaux devices (7j)" (firstSeen) sont dérivés côté client de ces deux listes — voir
  // selectors.js::computeTopRiskDevices / computeNewDevices. `top=0` sur /machines récupère
  // tout le parc onboardé (pagination complète côté backend).
  defenderMachines: (top = 0) => getJSON(`/api/defender/machines?top=${top}`),
  defenderAlerts: (top = 200) => getJSON(`/api/defender/alerts?top=${top}`),
  // Détail d'une alerte (2026-08-17, V43 — demande Nicolas : "défiler l'alerte et regarder ce
  // qu'il se passe") : /api/alerts/{id} renvoie evidence/comments/mitreTechniques/
  // determination/investigationState en plus des champs déjà présents dans la liste — voir
  // defender/tools.py::get_alert. Chargé à la demande, à l'ouverture d'une ligne, pas au
  // chargement de la liste (200 alertes → 200 appels réseau si c'était systématique).
  defenderAlertDetail: (alertId) => getJSON(`/api/defender/alerts/${encodeURIComponent(alertId)}`),
  intuneSummary: () => getJSON("/api/intune/summary"),
  compliancePolicySummary: () => getJSON("/api/intune/compliance-policy-summary"),
  // Sans plafond par défaut : la méthode "device-first" fait un appel Graph par device
  // non conforme (voir intune/tools.py::get_compliance_detail) — potentiellement
  // coûteux sur un grand parc, mais c'est la méthode fiable (celle du skill
  // audit-exposure-score) ; `maxDevices` reste dispo comme garde-fou si besoin.
  complianceDetail: (maxDevices = null) =>
    getJSON(`/api/intune/compliance-detail${maxDevices ? `?max_devices=${maxDevices}` : ""}`),
  // Page "Vulnérabilités" (sous-catégorie Defender, 2026-08-10) : recherche par CVE (ex.
  // "CVE-2024-3400") ou par nom de logiciel/éditeur — voir
  // defender/tools.py::search_vulnerabilities. Chargée à la demande, sur soumission du
  // formulaire de recherche, jamais au chargement du dashboard (contrairement aux appels
  // de useDashboardData) : contrairement aux autres onglets, cette page n'a pas de vue
  // "par défaut" tant que Nicolas n'a pas tapé une recherche.
  searchVulnerabilities: (query, maxResults = 20) =>
    getJSON(`/api/defender/vulnerabilities?query=${encodeURIComponent(query)}&max_results=${maxResults}`),
  // Onglet "Suivi CVE" (2026-08-10) — CVE "épinglées" pour re-vérification automatique côté
  // backend (defender/watchlist.py + boucle de fond dans api_server.py), distinct de la
  // recherche ponctuelle ci-dessus. Voir CveWatchTab.jsx.
  watchedCves: () => getJSON("/api/defender/watched-cves"),
  addWatchedCve: (cveCode) => postJSON("/api/defender/watched-cves", { cve_code: cveCode }),
  removeWatchedCve: (cveCode) => deleteJSON(`/api/defender/watched-cves/${encodeURIComponent(cveCode)}`),
  refreshWatchedCve: (cveCode) => postJSON(`/api/defender/watched-cves/${encodeURIComponent(cveCode)}/refresh`),
  // Onglet "Secure Score" (indépendant, 2026-08-10) — endpoints Graph /security/*, distincts
  // de l'Exposure Score MDE. `days` : historique déjà géré nativement par Graph (90j max),
  // pas de fichier d'historique local nécessaire ici contrairement à l'Exposure Score.
  secureScore: (days = 30) => getJSON(`/api/intune/secure-score?days=${days}`),
  secureScoreControlProfiles: () => getJSON("/api/intune/secure-score-control-profiles"),
  // Détail PAR PARAMÈTRE (settingStates) d'une politique précise pour un device donné —
  // ajouté le 2026-08-12 après le correctif porté côté serveur MCP Node.js puis backend
  // local (voir intune/tools.py::get_device_compliance_status et le docstring associé).
  // Équivalent de la page "Setting / State / State details" du portail Intune. Utilisé par
  // le clic sur une ligne device de ComplianceOsGrid.jsx (drill-down à la demande, pas
  // préchargé : un appel Graph par (device, politique) ouverte).
  deviceComplianceStatus: (deviceId, policyId) =>
    getJSON(`/api/intune/devices/${encodeURIComponent(deviceId)}/compliance-status?policy_id=${encodeURIComponent(policyId)}`),
  // Inventaire COMPLET des CVE du parc, SANS enrichissement catalogue (2026-09-01) — source de
  // données réelle de VulnerabilitiesTab.jsx : aucun paramètre `top`, la table entière est
  // renvoyée en un seul appel (un `summarize` Advanced Hunting, pas d'aller-retour par CVE).
  vulnerabilityInventory: () => getJSON(`/api/defender/vulnerability-inventory`),
  // Onglet "Secure Score" > "Par criticité" (2026-08-12) — top logiciels vulnérables + chemins
  // disque pour un niveau d'exposition MDE donné (High/Medium/Low), voir SecureScoreTab.jsx et
  // defender/tools.py::get_top_vulnerable_apps_by_exposure.
  exposureVulnerableApps: (level, top = 5) =>
    getJSON(`/api/defender/exposure-vulnerable-apps?level=${encodeURIComponent(level)}&top=${top}`),
  // "Par criticité" v2 (2026-08-12) — détail par DEVICE précis (clic sur une ligne device
  // dans un bloc de criticité), voir defender/tools.py::get_device_vulnerable_software.
  deviceVulnerableSoftware: (deviceId, top = 5) =>
    getJSON(`/api/defender/machines/${encodeURIComponent(deviceId)}/vulnerable-software?top=${top}`),
  // "Vulnérabilités" > bloc ANSSI/CERT-FR (2026-08-12) — rapprochement avis CERT-FR récents ↔
  // inventaire logiciel COMPLET du parc, voir defender/anssi.py::get_anssi_matches. Mis en
  // cache 30 min côté backend ; `refresh=true` (bouton "Rafraîchir") le contourne.
  anssiMatches: (windowDays = 14, refresh = false) =>
    getJSON(`/api/defender/anssi-matches?window_days=${windowDays}${refresh ? "&refresh=true" : ""}`),
  // Historique quotidien (conformité Intune, exposure score Defender) — un point par jour
  // calendaire, jusqu'à 90 jours, calculé côté backend par une boucle de fond (voir
  // common/history.py + api_server.py::_history_snapshot_loop). Pas de paramètre de fenêtre
  // ici : le backend renvoie déjà tout ce qu'il conserve, le découpage par fenêtre (7j/30j/
  // tout) se fait côté client comme pour le Secure Score.
  history: () => getJSON("/api/history"),
  // Vue "360°" d'un appareil (2026-08-18) — rapproche Intune + Defender par nom, voir
  // backend/device_overview.py. Chargée à la demande, sur soumission du formulaire de
  // recherche, comme searchVulnerabilities ci-dessus.
  deviceOverview: (deviceName) => getJSON(`/api/device-overview?device_name=${encodeURIComponent(deviceName)}`),
  // Inventaire fleet-wide (2026-09-02) — Intune + Defender réconciliés par nom, voir
  // backend/device_overview.py::get_device_inventory. Un seul appel, chargé une fois (voir
  // useDeviceInventory, useDashboardData.js).
  deviceInventory: () => getJSON(`/api/device-inventory`),
  // Fusion "Application déployée" + "discovered apps", dédupliquée par nom (2026-09-02,
  // demande de Nicolas — "je veux pas 600 doublons ... je veux cependant voir toutes les
  // versions") — voir intune/apps.py::get_apps_catalog.
  appsCatalog: () => getJSON("/api/intune/apps-catalog"),
  // Groupes d'assignation (Requises/Disponibles/Exclues) d'une app déployée — chargé à la
  // demande uniquement quand le panneau détail est "agrandi" (2026-09-02, demande de Nicolas),
  // voir intune/apps.py::get_app_assignments.
  appAssignments: (appId) => getJSON(`/api/intune/apps/${encodeURIComponent(appId)}/assignments`),
  // Devices détectés pour UNE discovered app précise (un id brut par couple nom+version, voir
  // intune/apps.py::get_discovered_app_devices) — réutilisé pour le clic "voir les devices"
  // d'une version dans "Application déployée" (2026-09-02, demande de Nicolas). Capacité
  // backend déjà en place, ce helper frontend avait été retiré le 2026-08-26 faute d'appelant
  // à l'époque (bibliothèque d'app remplaçant le catalogue "discovered apps" de cette page) —
  // ré-ajouté ici pour ce nouvel usage.
  discoveredAppDevices: (appId) => getJSON(`/api/intune/discovered-apps/${encodeURIComponent(appId)}/devices`),
  // État d'installation d'une app déployée, device par device (accordéon au clic sur une
  // ligne, chargé à la demande via useAppInstallStatus) — voir intune/apps.py::get_app_install_status.
  appInstallStatus: (appId, osFilter, versionBelow) => {
    const params = new URLSearchParams();
    if (osFilter) params.set("os_filter", osFilter);
    if (versionBelow) params.set("version_below", versionBelow);
    const qs = params.toString();
    return getJSON(`/api/intune/apps/${encodeURIComponent(appId)}/install-status${qs ? `?${qs}` : ""}`);
  },
  // Bandeau KPI "Taux d'installation moyen"/"Échecs d'installation" de l'onglet
  // "Application déployée" (2026-08-25) — agrégat calculé côté Graph (un appel par app, pas
  // par device), chargé automatiquement au montage via useAppInstallSummary — voir
  // intune/apps.py::get_apps_install_summary.
  appInstallSummary: () => getJSON("/api/intune/apps/install-summary"),
  // Assistant de packaging Win32 (2026-08-26, demande de Nicolas) — Catalogue d'application >
  // "Déployer une application" (DeployAppWizard.jsx). Prépare un livrable (.intunewin +
  // commandes + script de détection), NE PUBLIE RIEN sur Intune — voir intune/packaging.py.
  // Toutes les étapes sont keyées par `jobId` (créé par `createJob`, voir DeployAppWizard.jsx).
  packaging: {
    createJob: () => postJSON("/api/intune/packaging/jobs"),
    uploadSource: (jobId, file) => {
      const form = new FormData();
      form.append("file", file);
      return postForm(`/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/source/upload`, form);
    },
    // `githubReleases` (2026-08-26, demande de Nicolas : "voir toutes les versions dans le
    // repo git pour pouvoir le changer") — liste TOUTES les releases (juste tag/nom/date, pas
    // les assets), distincte de `githubLookup` (assets d'UNE release précise).
    githubReleases: (jobId, owner, repo) =>
      postJSON(`/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/source/github-releases`, { owner, repo }),
    // `tag` optionnel — absent, se comporte comme avant (dernière release).
    githubLookup: (jobId, owner, repo, tag) =>
      postJSON(`/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/source/github-lookup`, { owner, repo, tag }),
    // `owner`/`repo` optionnels (2026-08-27, demande de Nicolas : "enregistrer le lien du
    // dépôt Git... pour proposer les versions dispo sur le repo lors de la modification") — le
    // dépôt d'origine de l'asset, retenu côté backend jusque sur l'entrée de bibliothèque.
    githubFetch: (jobId, downloadUrl, assetName, owner, repo) =>
      postJSON(`/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/source/github-fetch`, {
        download_url: downloadUrl,
        asset_name: assetName,
        owner,
        repo,
      }),
    // `uninstallCommand` (2026-08-27, demande de Nicolas : "possibilité de mettre un script
    // powershell pour le package") — ignorée côté backend pour une source MSI (auto-générée),
    // utilisée UNIQUEMENT pour une source PowerShell (saisie manuelle, pas de générateur
    // possible pour un script arbitraire) — voir intune/packaging.py::package_app.
    package: (jobId, { installMode, options, applicationName, version, detectionMode, uninstallCommand }) =>
      postJSON(`/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/package`, {
        install_mode: installMode,
        options,
        application_name: applicationName,
        version,
        detection_mode: detectionMode,
        uninstall_command: uninstallCommand,
      }),
    // Pas un getJSON : c'est un fichier binaire (zip), pas du JSON — DeployAppWizard.jsx
    // pointe un <a href={...} download> directement dessus plutôt que de le récupérer en JS
    // (le fichier est déjà généré serveur-side, contrairement à l'export Excel de export.js
    // qui lui construit le fichier EN JS et doit donc passer par un Blob).
    downloadUrl: (jobId) => `/api/intune/packaging/jobs/${encodeURIComponent(jobId)}/download`,
  },
  // Bibliothèque d'application (2026-08-26, demande de Nicolas — remplace le catalogue d'apps
  // détectées de AppCatalogTab.jsx) — voir intune/app_library.py. `addManual`/`addPackaged`
  // suivent la même convention snake_case→camelCase que packaging.package ci-dessus.
  appLibrary: {
    list: () => getJSON("/api/intune/app-library"),
    // `icon`/`iconContentType` (2026-08-26, demande de Nicolas : "mettre un logo à
    // l'application... pour le voir dans le catalogue") — `icon` est déjà le base64 pur (sans
    // le préfixe `data:...;base64,`), extrait côté appelant via FileReader avant cet appel.
    addManual: ({ displayName, publisher, version, note, icon, iconContentType }) =>
      postJSON("/api/intune/app-library/manual", {
        display_name: displayName,
        publisher,
        version,
        note,
        icon,
        icon_content_type: iconContentType,
      }),
    addPackaged: (jobId, { displayName, publisher, note, icon, iconContentType }) =>
      postJSON("/api/intune/app-library/packaged", {
        job_id: jobId,
        display_name: displayName,
        publisher,
        note,
        icon,
        icon_content_type: iconContentType,
      }),
    // `update` (2026-08-26, demande de Nicolas : "modifier les applications... la version et
    // tous les autres champs qu'il y avait lors de la configuration", EditAppTab.jsx) —
    // `installMode`/`options`/`detectionMode` ignorés côté backend pour une entrée manuelle,
    // `removeIcon` distingue explicitement "retirer le logo" de "logo non renvoyé, garder
    // l'existant" (voir app_library.py::update_library_app).
    // `uninstallCommand` (2026-08-27) — même convention à 3 états que `icon`/`removeIcon` :
    // `undefined`/`null` = ne pas y toucher, chaîne vide = l'effacer, non vide = la remplacer.
    // Ignorée côté backend pour une entrée MSI (auto-générée) ou manuelle.
    update: (
      entryId,
      {
        displayName,
        publisher,
        version,
        note,
        icon,
        iconContentType,
        removeIcon,
        installMode,
        options,
        detectionMode,
        uninstallCommand,
      }
    ) =>
      putJSON(`/api/intune/app-library/${encodeURIComponent(entryId)}`, {
        display_name: displayName,
        publisher,
        version,
        note,
        icon,
        icon_content_type: iconContentType,
        remove_icon: removeIcon,
        install_mode: installMode,
        options,
        detection_mode: detectionMode,
        uninstall_command: uninstallCommand,
      }),
    // `repackage` (2026-08-26, demande de Nicolas : "voir toutes les versions dans le repo
    // git pour pouvoir le changer", EditAppTab.jsx) — remplace le livrable ET les commandes/
    // script d'une entrée packagée par le résultat d'un job DÉJÀ packagé (appeler
    // `packaging.package` avant celui-ci) — voir app_library.py::repackage_library_app.
    repackage: (entryId, jobId) =>
      postJSON(`/api/intune/app-library/${encodeURIComponent(entryId)}/repackage`, { job_id: jobId }),
    remove: (entryId) => deleteJSON(`/api/intune/app-library/${encodeURIComponent(entryId)}`),
    // Pas un getJSON : fichier binaire (zip), même raisonnement que packaging.downloadUrl.
    downloadUrl: (entryId) => `/api/intune/app-library/${encodeURIComponent(entryId)}/download`,
    // "Système de mise à jour automatique" (2026-08-27, demande de Nicolas, AppCatalogTab.jsx)
    // — vérifie toutes les entrées packagées avec un dépôt GitHub connu, repackage celles qui
    // ont une version plus récente, renvoie `{results: [...]}` (un statut par entrée vérifiée)
    // — voir app_library.py::check_for_updates.
    checkUpdates: () => postJSON("/api/intune/app-library/check-updates"),
  },

  // Vanitas (2026-09-04, jalon 5) — projet personnel séparé `endpoint-agent/` (agent .NET en
  // mTLS ↔ serveur FastAPI), proxifié par backend/vanitas/client.py (jamais d'appel direct
  // navigateur → serveur Vanitas, voir ce module pour pourquoi). Nommé "Vanitas" pour ne pas se
  // confondre avec "Pandore", le nom/la marque du dashboard lui-même (logo Sidebar.jsx).
  vanitas: {
    agents: () => getJSON("/api/vanitas/agents"),
    agentDetail: (agentId) => getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}`),
    agentVulnerabilities: (agentId) =>
      getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/vulnerabilities`),
    agentCommands: (agentId) => getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/commands`),
    // `installerId` (2026-09-08, "push d'application") — requis pour
    // `commandType === "install_application"`, ignoré sinon. `agentPackageId` (2026-09-11,
    // "mise à jour de l'agent") — requis pour `commandType === "update_agent"`, ignoré sinon.
    // `eventId` (jalon "confinement", 2026-09-17) — référence l'alerte "activité suspecte"
    // déclenchante, requis pour `commandType === "kill_process"`, optionnel pour
    // `"isolate_network"`, ignoré sinon.
    queueCommand: (agentId, commandType, installerId = null, agentPackageId = null, eventLogQuery = null, eventId = null) =>
      postJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/commands`, {
        command_type: commandType,
        installer_id: installerId,
        agent_package_id: agentPackageId,
        event_log_query: eventLogQuery,
        event_id: eventId,
      }),
    commands: () => getJSON("/api/vanitas/commands"),
    // Tendance quotidienne du parc Vanitas (jalon 2026-09-17) — `[{date, vanitas:{...}}]`,
    // même fichier d'historique que `/api/history` mais restreint au domaine Vanitas.
    history: () => getJSON("/api/vanitas/history"),
    // "Vue d'ensemble" HUD (2026-09-06) — CVE les plus répandues sur le parc, fleet-wide (pas
    // de agentId, contrairement à agentVulnerabilities ci-dessus).
    topVulnerabilities: (limit = 5) => getJSON(`/api/vanitas/vulnerabilities/top?limit=${limit}`),
    removeAgent: (agentId) => deleteJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}`),
    // "Ajouter un poste" (2026-09-11) — génère un token d'enrôlement ; la commande msiexec est
    // reconstruite côté frontend à partir du token + du champ URL de la page.
    createEnrollmentToken: () => postJSON("/api/vanitas/enrollment-tokens", {}),
    // Pré-remplissage du champ URL dès l'ouverture de la page (voir api_server.py pour le
    // détail des deux valeurs possibles) — corrige le bug du 2026-09-11 (champ vide → Nicolas
    // y a tapé l'adresse de CE dashboard par erreur).
    enrollmentDefaults: () => getJSON("/api/vanitas/enrollment-defaults"),
    // Terminal PowerShell interactif (jalon 9) — "lancer" une session reste queueCommand
    // ci-dessus (command_type="start_shell_session"), pas de méthode dédiée pour ça.
    latestShellSession: (agentId) =>
      getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/shell/sessions/latest`),
    shellSession: (sessionId) => getJSON(`/api/vanitas/shell/sessions/${encodeURIComponent(sessionId)}`),
    shellSessionEvents: (sessionId, sinceId) =>
      getJSON(`/api/vanitas/shell/sessions/${encodeURIComponent(sessionId)}/events?since_id=${sinceId}`),
    sendShellInput: (sessionId, line) =>
      postJSON(`/api/vanitas/shell/sessions/${encodeURIComponent(sessionId)}/input`, { line }),
    stopShellSession: (sessionId) =>
      postJSON(`/api/vanitas/shell/sessions/${encodeURIComponent(sessionId)}/stop`, {}),
    // Conformité (jalon 11) — règles PowerShell fournies par Nicolas, PAS codées en dur.
    // `complianceRules` (catalogue complet, `script_content` inclus) est protégé côté serveur
    // Vanitas par le même secret que le terminal (jalon 9) ; `complianceRulesSummary`
    // (id/nom/état, sans le script) est en libre accès comme le reste des lectures.
    complianceRulesSummary: () => getJSON("/api/vanitas/compliance/rules/summary"),
    complianceRules: () => getJSON("/api/vanitas/compliance/rules"),
    createComplianceRule: (name, scriptContent) =>
      postJSON("/api/vanitas/compliance/rules", { name, script_content: scriptContent }),
    updateComplianceRule: (ruleId, { name, scriptContent, enabled } = {}) =>
      putJSON(`/api/vanitas/compliance/rules/${encodeURIComponent(ruleId)}`, {
        name,
        script_content: scriptContent,
        enabled,
      }),
    deleteComplianceRule: (ruleId) => deleteJSON(`/api/vanitas/compliance/rules/${encodeURIComponent(ruleId)}`),
    agentCompliance: (agentId) => getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/compliance`),
    complianceSummary: () => getJSON("/api/vanitas/compliance/summary"),
    // Logiciels/OS obsolètes — EOL (2026-09-08). Fleet-wide : pas de route dédiée côté serveur
    // Vanitas, un appel par agent (voir vanitas/eol.py côté backend).
    agentEol: (agentId) => getJSON(`/api/vanitas/agents/${encodeURIComponent(agentId)}/eol`),
    // "Description & plan d'action (CERT-FR)" (2026-09-10) — avis CERT-FR le plus récent
    // citant cette CVE précise, voir defender/anssi.py::get_cve_avis. `null` = pas d'avis
    // trouvé (résultat légitime, pas une erreur).
    cveAvis: (cveId) => getJSON(`/api/vanitas/cve-avis/${encodeURIComponent(cveId)}`),
    // Alertes (2026-09-08) — journal des alertes déclenchées par les boucles de fond
    // (agent silencieux / nouvelle vuln critique / nouvel échec de conformité), voir
    // vanitas/alert_state.py. Seule surface visible tant que le SMTP n'est pas configuré.
    recentAlerts: (limit = 20) => getJSON(`/api/vanitas/alerts/recent?limit=${limit}`),
    // Groupes de postes (2026-09-08) — même convention que les méthodes *ComplianceRule.
    // Étendu le 2026-09-08 : many-to-many (un poste peut appartenir à plusieurs groupes
    // statiques). Étendu le 2026-09-10 (revue de la fonctionnalité comparée à Intune/Jamf/
    // Tanium) : `rules` (multi-critères, plusieurs champs + AND/OR + exclusion) remplace
    // l'ancien `pattern` (glob sur le hostname seul) ; `clear_rules` (même convention "3 états"
    // que `icon`/`removeIcon` côté app_library) repasse un groupe dynamique en statique.
    // Groupes IMBRIQUÉS (même jalon) : `addChildGroup`/`removeChildGroup`.
    groups: () => getJSON("/api/vanitas/groups"),
    groupMembers: (groupId) => getJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}/members`),
    createGroup: (name, rules = null) => postJSON("/api/vanitas/groups", { name, rules }),
    updateGroup: (groupId, { name, rules, clearRules } = {}) =>
      putJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}`, {
        name,
        rules,
        clear_rules: clearRules ?? false,
      }),
    deleteGroup: (groupId) => deleteJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}`),
    // Mises à jour Windows — jalon "Mises à jour Vanitas" (2026-09-17, maquette validée par
    // Nicolas). Politique PERSISTANTE par groupe, distincte de `updateGroup` (nom/règles) — deux
    // routes séparées côté serveur, voir `endpoint-agent/server/app/routes/groups.py`.
    patchStatus: () => getJSON("/api/vanitas/patch-status"),
    updatePatchPolicy: (groupId, { enabled, windowStart, windowEnd, graceDays }) =>
      putJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}/patch-policy`, {
        enabled,
        window_start: windowStart,
        window_end: windowEnd,
        grace_days: graceDays,
      }),
    addAgentToGroup: (agentId, groupId) =>
      postJSON(
        `/api/vanitas/agents/${encodeURIComponent(agentId)}/groups/${encodeURIComponent(groupId)}`
      ),
    removeAgentFromGroup: (agentId, groupId) =>
      deleteJSON(
        `/api/vanitas/agents/${encodeURIComponent(agentId)}/groups/${encodeURIComponent(groupId)}`
      ),
    addChildGroup: (parentId, childId) =>
      postJSON(
        `/api/vanitas/groups/${encodeURIComponent(parentId)}/children/${encodeURIComponent(childId)}`
      ),
    removeChildGroup: (parentId, childId) =>
      deleteJSON(
        `/api/vanitas/groups/${encodeURIComponent(parentId)}/children/${encodeURIComponent(childId)}`
      ),
    // Catalogue d'installeurs applicatifs (2026-09-08, "un push d'application un peu comme
    // dans Pandore, via les groupes") — upload une fois, repoussé ensuite vers n'importe quel
    // groupe/poste. Contrairement à la bibliothèque d'application de Pandore, le fichier gardé
    // est TOUJOURS l'installeur brut : c'est l'agent Vanitas qui l'exécute lui-même.
    installers: () => getJSON("/api/vanitas/installers"),
    uploadInstaller: (formData) => postForm("/api/vanitas/installers", formData),
    updateInstaller: (installerId, { name, version, install_command }) =>
      putJSON(`/api/vanitas/installers/${encodeURIComponent(installerId)}`, { name, version, install_command }),
    deleteInstaller: (installerId) => deleteJSON(`/api/vanitas/installers/${encodeURIComponent(installerId)}`),
    pushInstallToGroup: (groupId, installerId) =>
      postJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}/push-install`, { installer_id: installerId }),
    // Source GitHub pour un installeur (2026-09-11, "tu peux regler ca" — parité avec
    // l'assistant de packaging Win32 de Pandore). `githubInstallerReleases`/`githubInstallerRelease`
    // ne font QUE lister (aucun octet transféré) ; `addInstallerFromGithub` télécharge l'asset
    // choisi ET l'ajoute au catalogue EN UN SEUL appel serveur — jamais de round-trip des
    // octets par le navigateur (voir `vanitas_github_installer.py`/`vanitas_installer_from_github`).
    githubInstallerReleases: (owner, repo) =>
      getJSON(`/api/vanitas/installers/github-releases?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}`),
    githubInstallerRelease: (owner, repo, tag) =>
      getJSON(
        `/api/vanitas/installers/github-release?owner=${encodeURIComponent(owner)}&repo=${encodeURIComponent(repo)}` +
          (tag ? `&tag=${encodeURIComponent(tag)}` : "")
      ),
    addInstallerFromGithub: ({ owner, repo, downloadUrl, assetName, name, version, installCommand }) =>
      postJSON("/api/vanitas/installers/github", {
        owner,
        repo,
        download_url: downloadUrl,
        asset_name: assetName,
        name,
        version,
        install_command: installCommand,
      }),
    // "Applications déployées" (2026-09-10) — un élément par installeur déjà poussé au moins
    // une fois, groupes visés + statut le plus récent par poste (voir routes/installers.py::
    // list_installer_deployments côté serveur Vanitas).
    installerDeployments: () => getJSON("/api/vanitas/installer-deployments"),
    // Journal d'activité (2026-09-09) — fusion côté serveur Vanitas de AgentCommand (postes)
    // et AuditEvent (mutations admin), voir routes/activity.py.
    activityLog: () => getJSON("/api/vanitas/activity-log"),
    // Mise à jour de l'agent Vanitas lui-même (2026-09-11, "la mise à jour de l'agent via
    // Vanitas c'est bien d'actu ?" → non, jusqu'ici 100% manuel — voir agent_package.py côté
    // serveur). Catalogue de paquets `.msi` séparé du catalogue d'installeurs applicatifs
    // ci-dessus : c'est Vanitas lui-même qui se met à jour, toujours via `msiexec /i ... /qn
    // /norestart` (commande FIXE, jamais configurable — <MajorUpgrade> de Product.wxs gère le
    // reste). Déclenchement TOUJOURS manuel — l'alerte de décalage de version (voir
    // `_vanitas_agent_health_loop` côté backend Pandore) reste purement informative.
    agentPackages: () => getJSON("/api/vanitas/agent-packages"),
    latestAgentPackage: () => getJSON("/api/vanitas/agent-packages/latest"),
    uploadAgentPackage: (formData) => postForm("/api/vanitas/agent-packages", formData),
    deleteAgentPackage: (packageId) =>
      deleteJSON(`/api/vanitas/agent-packages/${encodeURIComponent(packageId)}`),
    pushUpdateToGroup: (groupId, agentPackageId) =>
      postJSON(`/api/vanitas/groups/${encodeURIComponent(groupId)}/push-update`, {
        agent_package_id: agentPackageId,
      }),
    // Profils Vanitas (2026-09-10) — catalogue de matrices lecture/écriture par module,
    // admin-only côté serveur (`require_admin`, pas `require_vanitas_*` : gérer QUI a accès à
    // quoi est une action d'administration Pandore, pas une capacité Vanitas parmi d'autres).
    // `perms` = `{postes, terminal, applications, conformite, groupes}` (voir
    // VANITAS_MODULES, vanitasShared.jsx).
    profiles: () => getJSON("/api/vanitas/profiles"),
    createProfile: (name, perms) => postJSON("/api/vanitas/profiles", { name, perms }),
    updateProfile: (profileId, { name, perms } = {}) =>
      putJSON(`/api/vanitas/profiles/${encodeURIComponent(profileId)}`, { name, perms }),
    deleteProfile: (profileId) => deleteJSON(`/api/vanitas/profiles/${encodeURIComponent(profileId)}`),
    // Activités suspectes (jalon "détection d'activités suspectes sur les postes") — télémétrie
    // comportementale native de l'agent Vanitas (processus/journal d'événements/réseau/USB),
    // filtrée localement côté agent avant remontée. Nouveau module de permission
    // "activites_suspectes" (voir VANITAS_MODULES, vanitasShared.jsx). `params` = un sous-
    // ensemble de `{agentId, signalType, severity, status, since}`, tous optionnels — un appel
    // sans argument renvoie tout le journal (échelle "quelques postes").
    suspiciousEvents: ({ agentId, signalType, severity, status, since, until } = {}) => {
      const params = new URLSearchParams();
      if (agentId) params.set("agent_id", agentId);
      if (signalType) params.set("signal_type", signalType);
      if (severity) params.set("severity", severity);
      if (status) params.set("status", status);
      if (since) params.set("since", since);
      // `until` (jalon "confinement", 2026-09-17) — borne haute, utilisée pour la fenêtre
      // "alertes précédentes" du détail d'alerte (voir SuspiciousEventDetailModal).
      if (until) params.set("until", until);
      const qs = params.toString();
      return getJSON(`/api/vanitas/suspicious-events${qs ? `?${qs}` : ""}`);
    },
    suspiciousEvent: (eventId) => getJSON(`/api/vanitas/suspicious-events/${encodeURIComponent(eventId)}`),
    // Bandeau KPI (`{by_severity, by_status}`) de l'onglet transverse — voir
    // VanitasSuspiciousActivityTab.jsx.
    suspiciousEventsSummary: () => getJSON("/api/vanitas/suspicious-events/summary"),
    // Corrélation Defender (chargée en lazy à l'ouverture du panneau de détail, PAS au
    // chargement de la liste) — route Pandore native (device_overview.py), pas un proxy Vanitas.
    suspiciousEventCorrelation: (eventId) =>
      getJSON(`/api/vanitas/suspicious-events/${encodeURIComponent(eventId)}/correlation`),
    // Triage (Accuser réception / Faux positif / Escalader) — `body` = `{status, note}`.
    updateSuspiciousEvent: (eventId, body) =>
      putJSON(`/api/vanitas/suspicious-events/${encodeURIComponent(eventId)}`, body),
  },
};
