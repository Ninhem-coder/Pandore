/**
 * Dérivations métier extraites de `theme.js` à la revue d'architecture du 2026-08-17 :
 * ces fonctions transforment les réponses brutes de l'API locale (backend/api_server.py)
 * en données prêtes à afficher (agrégats, jointures, tris, entrées de camembert) — par
 * opposition aux design tokens purs (couleurs, libellés, seuils) restés dans `theme.js`.
 *
 * Import volontairement à sens unique : ce fichier importe des tokens depuis `theme.js`
 * (palettes, clés de gravité) quand une dérivation en a besoin, mais `theme.js` n'importe
 * jamais rien d'ici — les tokens ne dépendent pas de la logique métier qui les consomme.
 */
import { FAILING_CATEGORIES, GENERIC_PALETTE, SEVERITY } from "./theme.js";

/**
 * Répartition du Secure Score par catégorie (Identité/Données/Appareils/Apps/Infra) :
 * somme des scores obtenus (controlScores du jour le plus récent) et des scores max
 * possibles (maxScore du catalogue controlProfiles), regroupés par controlCategory.
 *
 * Approximation assumée : `maxByCategory` somme le maxScore de TOUS les contrôles du
 * catalogue pour cette catégorie, y compris ceux qui ne s'appliquent pas forcément à ce
 * tenant (service non activé) — Graph ne distingue pas clairement "non applicable" de
 * "applicable mais à 0" dans ce catalogue. Le pourcentage par catégorie doit donc être lu
 * comme un ordre de grandeur, pas une valeur d'audit exacte.
 */
export function computeSecureScoreByCategory(controlScores, controlProfiles) {
  const scoreByCategory = {};
  for (const c of controlScores || []) {
    if (!c || typeof c.score !== "number") continue;
    const cat = c.controlCategory || "Autre";
    scoreByCategory[cat] = (scoreByCategory[cat] || 0) + c.score;
  }

  const maxByCategory = {};
  for (const p of controlProfiles || []) {
    if (!p || p.error || typeof p.maxScore !== "number") continue;
    const cat = p.controlCategory || "Autre";
    maxByCategory[cat] = (maxByCategory[cat] || 0) + p.maxScore;
  }

  return Object.keys(maxByCategory)
    .map((cat) => {
      const max = maxByCategory[cat];
      const score = scoreByCategory[cat] || 0;
      return {
        category: cat,
        score,
        maxScore: max,
        percentage: max > 0 ? Math.round((score / max) * 100) : null,
      };
    })
    .sort((a, b) => (b.percentage ?? 0) - (a.percentage ?? 0));
}

/**
 * Jointure commune `controlScore` (score obtenu ce jour) x `controlProfile` (fiche
 * catalogue : titre, remédiation, menaces couvertes, coût/impact, tier, lien d'action) — un
 * seul endroit pour cette jointure plutôt que de la dupliquer entre "Gains rapides" et la
 * liste complète des recommandations ci-dessous (ajoutée le 2026-08-12), pour qu'elles ne
 * divergent jamais sur les champs exposés.
 */
function joinControlWithProfile(controlScore, profileById) {
  const c = controlScore;
  const profile = profileById.get(c.controlName);
  const maxScore = typeof profile?.maxScore === "number" ? profile.maxScore : null;
  const gap = maxScore != null ? Math.max(0, maxScore - c.score) : null;
  return {
    controlName: c.controlName,
    category: c.controlCategory,
    description: profile?.title || c.description || c.controlName,
    score: c.score,
    maxScore,
    gap,
    // Implémenté = aucun écart mesurable (gap connu et nul) — distinct de `gap === null`
    // (non calculable, jointure sans profil trouvé) qui reste affiché comme "inconnu".
    implemented: gap != null && gap <= 0,
    actionUrl: profile?.actionUrl || null,
    implementationCost: profile?.implementationCost || null,
    userImpact: profile?.userImpact || null,
    tier: profile?.tier || null,
    // Quoi faire concrètement pour ce contrôle — texte libre Graph, affiché tel quel (pas de
    // traduction : c'est une instruction technique précise, la traduire risquerait de la
    // rendre ambiguë ou fausse).
    remediation: profile?.remediation || null,
    // Catégories de menace que ce contrôle atténue (accountBreach/phishing/malware/…) — voir
    // theme.js::translateThreat pour l'affichage.
    threats: Array.isArray(profile?.threats) ? profile.threats : [],
    // 3 champs Graph réels, jamais exploités avant la popup de détail (2026-09-01, comparaison
    // avec Vanta/Drata/le portail Microsoft natif) : `service` (produit Microsoft concerné),
    // `actionType` (Config/Review/Behavior — voir ACTION_TYPE_LABEL_FR, SecureScoreTab.jsx) et
    // `remediationImpact` (phrase descriptive de l'impact utilisateur attendu). Les trois sont
    // déjà présents dans la réponse brute de secureScoreControlProfiles (aucun `$select` posé
    // par list_secure_score_control_profiles, voir intune/secure_score.py) — pas de nouvel
    // appel réseau nécessaire pour les exposer.
    service: profile?.service || null,
    actionType: profile?.actionType || null,
    remediationImpact: profile?.remediationImpact || null,
  };
}

/**
 * "Gains rapides" : rapproche chaque contrôle du jour (`controlScores`, un score déjà
 * obtenu) de sa fiche catalogue (`controlProfiles`, qui porte le score max possible,
 * l'`actionUrl`, le coût/impact d'implémentation), calcule l'écart (maxScore - score) et
 * garde les plus gros écarts en tête — la liste "à corriger en premier pour le plus de
 * points" plutôt qu'un score brut sans plan d'action.
 *
 * Jointure `profile.id === controlScore.controlName` — voir l'avertissement dans
 * backend/intune/tools.py::list_secure_score_control_profiles : documentée mais PAS ENCORE
 * VÉRIFIÉE sur données réelles du tenant de production. Si la jointure ne matche jamais
 * (permission pas encore accordée, ou comportement Graph différent de la documentation),
 * cette fonction renvoie simplement une liste vide (aucun `gap` calculable) plutôt qu'une
 * erreur — dégradation silencieuse assumée ici, mais À VÉRIFIER en priorité dès que
 * SecurityEvents.Read.All est accordé et que de vraies données arrivent.
 */
export function computeSecureScoreQuickWins(controlScores, controlProfiles, { topN = 8 } = {}) {
  const profileById = new Map(
    (controlProfiles || []).filter((p) => p && !p.error && p.id).map((p) => [p.id, p])
  );

  return (controlScores || [])
    .filter((c) => c && typeof c.score === "number")
    .map((c) => joinControlWithProfile(c, profileById))
    .filter((r) => r.gap != null && r.gap > 0)
    .sort((a, b) => b.gap - a.gap)
    .slice(0, topN);
}

/**
 * Référentiel COMPLET des contrôles Secure Score de ce tenant (2026-08-12, demande de
 * Nicolas — la page ne doit pas se limiter aux 8 plus gros gains, mais servir de référence
 * consultable de bonnes pratiques pour un profil cybersécurité junior : ce qui est DÉJÀ en
 * place ET ce qui reste à faire, avec la marche à suivre et les menaces couvertes pour
 * chacun). Même jointure que `computeSecureScoreQuickWins` (voir `joinControlWithProfile`)
 * mais sans filtre sur le gap ni plafond de taille : chaque contrôle noté ce jour apparaît,
 * qu'il soit déjà acquis (`implemented: true`) ou encore à corriger. Regroupé par catégorie
 * puis trié par écart décroissant AU SEIN de chaque catégorie (comme les "Gains rapides"),
 * pour que les priorités les plus rentables d'une catégorie apparaissent en premier.
 */
export function computeSecureScoreAllControls(controlScores, controlProfiles) {
  const profileById = new Map(
    (controlProfiles || []).filter((p) => p && !p.error && p.id).map((p) => [p.id, p])
  );

  const rows = (controlScores || [])
    .filter((c) => c && typeof c.score === "number")
    .map((c) => joinControlWithProfile(c, profileById));

  const byCategory = new Map();
  for (const r of rows) {
    const cat = r.category || "Autre";
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat).push(r);
  }

  return Array.from(byCategory.entries())
    .map(([category, controls]) => ({
      category,
      controls: controls.sort((a, b) => (b.gap ?? -1) - (a.gap ?? -1)),
      toDoCount: controls.filter((c) => !c.implemented).length,
    }))
    .sort((a, b) => b.toDoCount - a.toDoCount);
}

/**
 * Tendance quotidienne (2026-08-18, demande de Nicolas) : dérive, à partir de l'historique
 * brut renvoyé par GET /api/history (voir backend/common/history.py — un point par jour
 * calendaire, jusqu'à 90 jours, éventuel trou si le backend n'a pas tourné un jour donné),
 * la valeur courante et l'écart vs 7 jours et vs 30 jours pour deux métriques : le taux de
 * conformité Intune et l'exposure score Defender.
 *
 * "vs N jours" cherche le DERNIER point connu à une date ≤ (aujourd'hui - N jours), pas le
 * point exactement N entrées plus tôt dans le tableau — un historique avec des trous
 * (dashboard pas ouvert certains jours) reste comparé à la bonne date plutôt qu'à un jour
 * décalé. Renvoie `null` pour un delta si aucun point ne couvre cette fenêtre (historique
 * trop jeune).
 *
 * `current` arrondi à 1 décimale (2026-08-20, correction de revue de code) : Defender renvoie
 * un exposure score avec de nombreuses décimales (ex. 26.988728272748943), et seuls
 * `delta7`/`delta30` étaient arrondis jusqu'ici — la valeur "courante" s'affichait brute sur
 * la carte "Exposure score (Defender)" de la Vue d'ensemble. Les tests existants ne l'avaient
 * jamais attrapé car leurs fixtures utilisent des scores déjà ronds.
 *
 * `rangeDays` (2026-08-20, sélecteur de plage temporelle de la Vue d'ensemble, voir
 * OverviewTab.jsx::HistoryRangePicker) : ne limite QUE la série renvoyée pour le tracé du
 * sparkline — `current`/`delta7`/`delta30` restent calculés sur l'historique complet, ce
 * sont des indicateurs de tendance à sens fixe, pas une fenêtre d'affichage. `null`
 * (comportement par défaut, historique complet) conserve exactement le comportement d'avant
 * l'ajout du sélecteur.
 */
export function computeHistoryTrend(points, rangeDays = null) {
  const sorted = (Array.isArray(points) ? points : [])
    .filter((p) => p && typeof p.date === "string")
    .slice()
    .sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

  function metric(domain, field) {
    const series = sorted
      .map((p) => ({
        date: p.date,
        value: p[domain] && typeof p[domain][field] === "number" ? p[domain][field] : null,
      }))
      .filter((e) => e.value != null);

    if (series.length === 0) {
      return { current: null, delta7: null, delta30: null, series: [] };
    }

    const currentEntry = series[series.length - 1];

    function deltaAt(daysAgo) {
      const cutoff = new Date(`${currentEntry.date}T00:00:00Z`);
      cutoff.setUTCDate(cutoff.getUTCDate() - daysAgo);
      const cutoffIso = cutoff.toISOString().slice(0, 10);
      const past = series.filter((e) => e.date <= cutoffIso).pop();
      return past ? Math.round((currentEntry.value - past.value) * 10) / 10 : null;
    }

    const displaySeries = rangeDays ? series.slice(-rangeDays) : series;

    return {
      current: Math.round(currentEntry.value * 10) / 10,
      delta7: deltaAt(7),
      delta30: deltaAt(30),
      series: displaySeries.map((e) => e.value),
    };
  }

  return {
    intune: metric("intune", "complianceRate"),
    defender: metric("defender", "exposureScore"),
    // Ajouté pour la refonte "Conformité" (2026-08-28, maquette validée par Nicolas) : le
    // snapshot quotidien stocke déjà `intune.nonCompliantCount` (voir
    // backend/api_server.py::_take_history_snapshot) mais rien ne l'exposait encore côté
    // sélecteur — seul `complianceRate` était extrait. Clé séparée plutôt qu'imbriquée sous
    // `intune` pour ne rien changer à la forme déjà consommée par OverviewTab.jsx.
    intuneNonCompliant: metric("intune", "nonCompliantCount"),
  };
}

/**
 * Tendance quotidienne du parc Vanitas (jalon "tendances Vanitas", 2026-09-17) — même logique
 * que `computeHistoryTrend` mais sur le domaine `vanitas` (endpoint séparé `/api/vanitas/history`,
 * forme `[{date, vanitas:{...}}]`). Chaque métrique renvoie `{current, delta7, delta30, series}` ;
 * un jour sans point `vanitas` (antérieur au jalon, ou domaine en erreur ce jour-là) est ignoré
 * de la série de cette métrique plutôt que tracé comme un zéro trompeur.
 */
export function computeVanitasTrend(points, rangeDays = null) {
  const sorted = (Array.isArray(points) ? points : [])
    .filter((p) => p && typeof p.date === "string")
    .slice()
    .sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));

  function metric(field) {
    const series = sorted
      .map((p) => ({
        date: p.date,
        value: p.vanitas && typeof p.vanitas[field] === "number" ? p.vanitas[field] : null,
      }))
      .filter((e) => e.value != null);

    if (series.length === 0) return { current: null, delta7: null, delta30: null, series: [] };

    const currentEntry = series[series.length - 1];

    function deltaAt(daysAgo) {
      const cutoff = new Date(`${currentEntry.date}T00:00:00Z`);
      cutoff.setUTCDate(cutoff.getUTCDate() - daysAgo);
      const cutoffIso = cutoff.toISOString().slice(0, 10);
      const past = series.filter((e) => e.date <= cutoffIso).pop();
      return past ? Math.round((currentEntry.value - past.value) * 10) / 10 : null;
    }

    const displaySeries = rangeDays ? series.slice(-rangeDays) : series;

    return {
      current: Math.round(currentEntry.value * 10) / 10,
      delta7: deltaAt(7),
      delta30: deltaAt(30),
      series: displaySeries.map((e) => e.value),
    };
  }

  return {
    complianceRate: metric("complianceRate"),
    onlineAgents: metric("onlineAgents"),
    suspiciousNew: metric("suspiciousNew"),
    suspiciousHigh: metric("suspiciousHigh"),
    eolOccurrences: metric("eolOccurrences"),
    patchOk: metric("patchOk"),
    patchPending: metric("patchPending"),
  };
}

/* ── "Top devices à risque" / "Nouveaux devices" (Vue d'ensemble v2, 2026-08-10) ──
   Dérivées côté client à partir de /api/defender/machines (exposureLevel, riskScore,
   firstSeen) et /api/defender/alerts (pour compter les alertes actives par machine) —
   aucun nouvel endpoint backend nécessaire, ces deux appels existaient déjà pour d'autres
   usages (onglet Defender, hunting). */

// Ordre de sévérité Microsoft (exposureLevel ET riskScore partagent ce vocabulaire) :
// plus l'indice est haut, plus la machine est prioritaire.
const RISK_LEVEL_RANK = { High: 3, Medium: 2, Low: 1, Informational: 0, None: 0 };

function riskRank(level) {
  return RISK_LEVEL_RANK[level] ?? -1;
}

/**
 * Classe les machines par risque décroissant : d'abord `exposureLevel`, puis `riskScore`
 * en départage, puis le nombre d'alertes actives (calculé ici depuis la liste d'alertes,
 * jointe par `machineId`). Une machine sans aucun signal de risque (exposureLevel/riskScore
 * absents et 0 alerte) est exclue — "top devices à risque" n'a pas vocation à lister tout
 * le parc, seulement ce qui mérite l'attention de la DSI.
 */
export function computeTopRiskDevices(machines, alerts, limit = 5) {
  const rows = (machines || []).filter((m) => !m?.error && m?.id);

  const alertCounts = new Map();
  for (const a of alerts || []) {
    if (a?.error || !a?.machineId) continue;
    // Un statut "Resolved" ne représente plus un risque actif — on ne compte que le reste
    // (New, InProgress, ou tout statut non explicitement résolu, par prudence).
    if (a.status === "Resolved") continue;
    alertCounts.set(a.machineId, (alertCounts.get(a.machineId) || 0) + 1);
  }

  // "Low" vaut 1 dans RISK_LEVEL_RANK (pour départager le tri), mais un device en Low
  // pur sans aucune alerte n'a rien d'anormal — seul Medium/High ou une alerte active
  // le qualifie pour ce panneau (sinon on afficherait quasiment tout le parc).
  return rows
    .map((m) => ({ ...m, alertCount: alertCounts.get(m.id) || 0 }))
    .filter((m) => riskRank(m.exposureLevel) >= 2 || riskRank(m.riskScore) >= 2 || m.alertCount > 0)
    .sort((a, b) => {
      const byExposure = riskRank(b.exposureLevel) - riskRank(a.exposureLevel);
      if (byExposure !== 0) return byExposure;
      const byAlerts = b.alertCount - a.alertCount;
      if (byAlerts !== 0) return byAlerts;
      return riskRank(b.riskScore) - riskRank(a.riskScore);
    })
    .slice(0, limit);
}

/** Machines vues pour la première fois il y a `withinDays` jours ou moins, triées de la
 * plus récente à la plus ancienne. `now` est injectable pour les tests. */
export function computeNewDevices(machines, withinDays = 7, limit = 5, now = new Date()) {
  const cutoff = now.getTime() - withinDays * 24 * 60 * 60 * 1000;

  return (machines || [])
    .filter((m) => !m?.error && m?.firstSeen)
    .map((m) => ({ ...m, _firstSeenMs: new Date(m.firstSeen).getTime() }))
    .filter((m) => Number.isFinite(m._firstSeenMs) && m._firstSeenMs >= cutoff)
    .sort((a, b) => b._firstSeenMs - a._firstSeenMs)
    .slice(0, limit);
}

const isFailing = (category) => FAILING_CATEGORIES.includes(category);

/**
 * Regroupe la sortie de GET /api/intune/compliance-detail (liste de politiques, chacune
 * avec ses devices en échec + leur OS réel) par OS plutôt que par politique — c'est ce
 * regroupement qui alimente `.compliance-os-grid` de l'onglet "Conformité Intune" (une
 * politique peut apparaître sous plusieurs blocs OS si elle touche plusieurs OS ; on se
 * fie à l'OS du device, pas au nom de la politique, qui n'est qu'une convention de
 * nommage côté Intune). Retourne aussi `byOS` (occurrences device × politique, pour le
 * troisième camembert "Par OS") triées par volume décroissant.
 */
export function groupComplianceDetailByOS(complianceDetail) {
  const policies = complianceDetail?.policies || [];
  const osMap = new Map(); // os -> { os, devices: Map<clé, pireCatégorie>, policies: Map<...> }

  for (const policy of policies) {
    for (const device of policy.devices || []) {
      // `operatingSystem` est désormais toujours renseigné côté backend (chaîne de résolution
      // nom -> id -> utilisateur -> plateforme de la politique). Le "Inconnu" ne subsiste ici
      // que comme garde-fou défensif si le backend renvoyait un jour un champ vide.
      const os = device.operatingSystem || "Inconnu";
      if (!osMap.has(os)) osMap.set(os, { os, deviceStates: new Map(), policies: new Map() });
      const osEntry = osMap.get(os);
      // Comptage par APPAREIL DISTINCT, pas par occurrence. Un poste en échec sur 12
      // politiques était compté 12 fois : la carte Windows dépassait alors la taille réelle du
      // parc Windows (711 appareils), ce qui rendait le chiffre ininterprétable. On retient
      // pour chaque appareil sa situation la plus grave, toutes politiques confondues.
      const key = (device.deviceName || "").trim().toLowerCase() || device.deviceId;
      const cat = device.complianceCategory || "Non conforme";
      const previous = osEntry.deviceStates.get(key);
      if (previous === undefined || SEVERITY.indexOf(cat) < SEVERITY.indexOf(previous)) {
        osEntry.deviceStates.set(key, cat);
      }
      if (!osEntry.policies.has(policy.id)) {
        osEntry.policies.set(policy.id, {
          id: policy.id,
          displayName: policy.displayName,
          count: 0,
          // failedCount = total fleet-wide de CETTE politique, tous OS confondus (agrégat
          // deviceStatusOverview). Conservé à côté de `count` (qui, lui, ne compte que les
          // lignes de CET OS) pour que la carte puisse afficher "12 / 38" plutôt qu'un "12"
          // nu que l'utilisateur compare ensuite au 38 de la légende du camembert en
          // croyant à une incohérence.
          failedCount: policy.failedCount ?? null,
          devices: [],
        });
      }
      const policyEntry = osEntry.policies.get(policy.id);
      // `count` = appareils en faute seulement, pour rester cohérent avec l'en-tête de la
      // carte ; `devices` garde TOUTES les lignes, y compris non applicables et en attente,
      // puisque c'est le tableau détaillé qui doit les montrer.
      if (isFailing(cat)) policyEntry.count += 1;
      else policyEntry.informationalCount = (policyEntry.informationalCount || 0) + 1;
      policyEntry.devices.push(device);
    }
  }

  const osGroups = Array.from(osMap.values())
    .map((g) => {
      // Deux comptes distincts, et c'est volontaire :
      //   - `categories` / `count` : les appareils réellement en faute, seuls mis en avant ;
      //   - `informational` : non applicables et en attente, affichés à part, jamais additionnés
      //     au précédent (c'est cette confusion qui avait fait bouger les chiffres Android).
      const categories = {};
      const informational = {};
      let count = 0;
      for (const cat of g.deviceStates.values()) {
        if (isFailing(cat)) {
          categories[cat] = (categories[cat] || 0) + 1;
          count += 1;
        } else {
          informational[cat] = (informational[cat] || 0) + 1;
        }
      }
      return {
        os: g.os,
        count,
        categories,
        informational,
        policies: Array.from(g.policies.values()).sort((a, b) => b.count - a.count),
      };
    })
    // Les OS qui n'ont aucun appareil en faute n'ont rien à faire dans une grille d'échecs.
    .filter((g) => g.count > 0)
    .sort((a, b) => b.count - a.count);

  const byOS = Object.fromEntries(osGroups.map((g) => [g.os, g.count]));

  // Réconciliation explicite entre les deux sources Graph DIFFÉRENTES qui alimentent cet
  // onglet :
  //  - `aggregateTotal`  : somme des deviceStatusOverview.failedCount (ce que montre le
  //                        camembert "Échecs par politique") ;
  //  - `retrievedTotal`  : nombre de lignes nominatives réellement récupérées via
  //                        /deviceStatuses (ce que montrent le camembert "Par OS" et les
  //                        cartes par OS).
  // Les deux ne peuvent PAS être égales par construction : l'agrégat est un compteur mis en
  // cache côté Microsoft (il porte son propre lastUpdateDateTime) et une politique dont le
  // détail a échoué reste comptée dans l'agrégat. Plutôt que de laisser l'utilisateur
  // découvrir l'écart en additionnant à la main, on le calcule et on l'affiche.
  const retrievedTotal = policies.reduce((sum, p) => sum + (p.devices?.length || 0), 0);
  const unavailableTotal = (complianceDetail?.unavailablePolicies || []).reduce(
    (sum, p) => sum + (p.failedCount || 0),
    0
  );

  // Répartition par état, en APPAREILS DISTINCTS eux aussi (même raison que ci-dessus : en
  // occurrences, les totaux dépassaient la taille du parc et n'étaient plus interprétables).
  // Chaque appareil compte une fois, dans sa situation la plus grave.
  const worstByDevice = new Map();
  for (const policy of policies) {
    for (const device of policy.devices || []) {
      const key = (device.deviceName || "").trim().toLowerCase() || device.deviceId;
      const cat = device.complianceCategory || "Non conforme";
      const previous = worstByDevice.get(key);
      if (previous === undefined || SEVERITY.indexOf(cat) < SEVERITY.indexOf(previous)) {
        worstByDevice.set(key, cat);
      }
    }
  }
  const byCategory = {};
  const informationalByCategory = {};
  let distinctDevices = 0;
  for (const cat of worstByDevice.values()) {
    if (isFailing(cat)) {
      byCategory[cat] = (byCategory[cat] || 0) + 1;
      distinctDevices += 1;
    } else {
      informationalByCategory[cat] = (informationalByCategory[cat] || 0) + 1;
    }
  }
  // `aggregateTotalCount` vient du backend et représente ce qu'annonçait l'agrégat Graph
  // AVANT exclusion des lignes d'affectation sans device (voir
  // intune/tools.py::_is_placeholder_status_row). Il est conservé pour expliquer l'écart, pas
  // pour être affiché comme un décompte de devices.
  const aggregateTotal = complianceDetail?.aggregateTotalCount ?? retrievedTotal + unavailableTotal;

  return {
    osGroups,
    byOS,
    byCategory,
    informationalByCategory,
    distinctDevices,
    retrievedTotal,
    aggregateTotal,
    unavailableTotal,
    placeholderRows: complianceDetail?.placeholderRows ?? 0,
    resolvedFromPlaceholders: complianceDetail?.resolvedFromPlaceholders ?? 0,
    unresolvedPlaceholderRows: complianceDetail?.unresolvedPlaceholderRows ?? 0,
    reclassifiedByDeviceState: complianceDetail?.reclassifiedByDeviceState ?? 0,
    // V40 (2026-08-13) : lignes réelles exclues côté backend car le device résolu est d'une
    // autre plateforme que la politique (garde-fou anti "Android listé sous Windows" —
    // voir intune/tools.py::_local_policy_state). Jamais dans osGroups/byOS, mais compté ici
    // pour rester visible plutôt que de disparaître sans trace.
    platformMismatchCount: complianceDetail?.platformMismatchCount ?? 0,
    // Candidats fantômes dont la vérification Graph a échoué pendant le préchauffage — ni
    // conformes ni en échec, juste non vérifiés (revue de code du 2026-08-20 : un raté réseau
    // isolé ne doit plus se compter silencieusement comme un vrai device non conforme, voir
    // backend/intune/compliance_detail.py::_resolve_placeholder_devices).
    unverifiedCandidates: complianceDetail?.unverifiedCandidates ?? 0,
    placeholderOnlyPolicies: complianceDetail?.placeholderOnlyPolicies || [],
    // V40 : garde-fou de complétude — devrait toujours être vide (voir intune/tools.py::
    // _compute_compliance_detail). Une entrée ici signale une politique tombée hors des
    // deux mécanismes de traçabilité existants, jamais vue nulle part dans l'onglet.
    missingPolicies: complianceDetail?.missingPolicies || [],
  };
}

/**
 * Construit les entrées d'un camembert (fraction/couleur/label/valeur) à partir d'un
 * objet {clé: nombre} — port direct de la logique répétée dans build_*_donut_html
 * (build_exposure_html.py) : tri décroissant, calcul de fraction, résolution de
 * couleur/libellé. `colors`/`labels` sont des mappings optionnels {clé -> valeur} ;
 * sinon la palette générique est utilisée dans l'ordre décroissant.
 *
 * `pinLast` : clés à forcer en DERNIÈRE position, après le tri décroissant. Nécessaire
 * pour les agrégats du type "Autres politiques" : ce n'est pas une catégorie comparable
 * aux autres mais une somme de résidus, donc la classer par sa valeur la place au milieu
 * du classement, AU-DESSUS de politiques réelles qui ont pourtant plus de devices en échec
 * qu'aucune des politiques qu'elle agrège (bug remonté par Nicolas : "Autres" apparaissait
 * en 6e position sur 8, devant deux politiques nommées). Sans cette option, l'ordre voulu
 * (agrégat en dernier) était systématiquement détruit par le tri de cette fonction.
 */
export function buildDonutEntries(
  data,
  { colors, labels, defaultColor = "#6B6E76", palette = GENERIC_PALETTE, pinLast = [] } = {}
) {
  const pinned = new Set(pinLast);
  const all = Object.entries(data || {})
    .filter(([, v]) => typeof v === "number" && v > 0)
    .sort((a, b) => b[1] - a[1]);

  // Tri décroissant pour les catégories réelles, puis les agrégats épinglés en fin de liste
  // (eux-mêmes triés entre eux, au cas où il y en aurait plusieurs un jour).
  const entries = [...all.filter(([k]) => !pinned.has(k)), ...all.filter(([k]) => pinned.has(k))];
  const total = entries.reduce((sum, [, v]) => sum + v, 0);

  return {
    total,
    entries: entries.map(([key, value], i) => ({
      key,
      value,
      fraction: total > 0 ? value / total : 0,
      color: colors?.[key] ?? palette[i % palette.length] ?? defaultColor,
      label: labels?.[key] ?? key,
    })),
  };
}

/**
 * Lecture combinée "un coup d'œil" pour la Vue Appareil 360° (backend/device_overview.py) :
 * réduit l'état Intune (conformité) + Defender (exposition, alertes actives) à un seul
 * triplet {tone, label, reasons} affiché en bandeau sous le nom de l'appareil — sans quoi
 * Nicolas devrait lire les deux cartes en détail pour se faire une opinion, ce qui annule
 * une bonne partie de l'intérêt d'une vue "360°".
 *
 * Volontairement PESSIMISTE (le pire signal l'emporte) plutôt qu'une moyenne : un appareil
 * conforme Intune mais avec une alerte Defender active de sévérité "High" n'est pas "à
 * moitié sain", c'est un appareil à traiter en priorité. `reasons` explicite toujours
 * POURQUOI (jamais un badge de couleur sans justification) — même principe que les autres
 * badges de tone du dashboard (SummaryCard, ComplianceOsGrid).
 *
 * `partial: true` signale que la lecture ne s'appuie que sur un seul des deux systèmes
 * (l'autre n'a pas trouvé l'appareil) — affiché comme une nuance ("vue partielle"), jamais
 * masqué : un appareil "Sain" vu uniquement par Intune n'a simplement pas été vérifié côté
 * Defender, ce n'est pas la même garantie qu'un "Sain" confirmé par les deux systèmes.
 *
 * Renvoie `null` si l'appareil n'a été trouvé dans AUCUN des deux systèmes — dans ce cas
 * l'appelant affiche l'état "introuvable" dédié plutôt qu'un bandeau de posture vide de sens.
 */
export function computeDevicePosture({ intune, defender } = {}) {
  if (!intune?.found && !defender?.found) return null;

  const complianceState = intune?.found ? intune.device?.complianceState : null;
  const exposureLevel = defender?.found ? defender.machine?.exposureLevel : null;
  const activeAlerts = defender?.found
    ? (defender.alerts || []).filter((a) => a && !a.error && (a.status === "New" || a.status === "InProgress"))
    : [];
  const hasHighSeverityAlert = activeAlerts.some((a) => a.severity === "High");

  let tone = "good";
  const reasons = [];

  if (complianceState === "noncompliant") {
    tone = "danger";
    reasons.push("appareil non conforme (Intune)");
  } else if (complianceState === "inGracePeriod") {
    tone = "warning";
    reasons.push("en période de grâce (Intune)");
  }

  if (exposureLevel === "High" || hasHighSeverityAlert) {
    tone = "danger";
    if (exposureLevel === "High") reasons.push("exposition élevée (Defender)");
    if (hasHighSeverityAlert) reasons.push("alerte active de sévérité élevée");
  } else if (exposureLevel === "Medium" && tone !== "danger") {
    tone = "warning";
    reasons.push("exposition moyenne (Defender)");
  }

  if (activeAlerts.length > 0 && !hasHighSeverityAlert && tone === "good") {
    tone = "warning";
    reasons.push(`${activeAlerts.length} alerte${activeAlerts.length > 1 ? "s" : ""} active${activeAlerts.length > 1 ? "s" : ""}`);
  }

  // Homonyme Intune/DNS Defender (2026-08-20) : `get_device`/`get_machine` renvoient la
  // première correspondance en cas de plusieurs appareils portant le même nom, mais le
  // signalent via `ambiguousMatches` plutôt que de le passer sous silence — voir
  // intune/devices.py et defender/machines.py. On le fait remonter ici pour que la vue 360°
  // n'affiche pas LA fiche de cet appareil comme si elle était certaine quand plusieurs
  // appareils portent ce nom.
  const intuneAmbiguous = intune?.found ? intune.device?.ambiguousMatches : null;
  const defenderAmbiguous = defender?.found ? defender.machine?.ambiguousMatches : null;
  if (intuneAmbiguous > 1) {
    if (tone === "good") tone = "warning";
    reasons.push(`${intuneAmbiguous} appareils Intune portent ce nom, celui affiché n'est pas garanti`);
  }
  if (defenderAmbiguous > 1) {
    if (tone === "good") tone = "warning";
    reasons.push(`${defenderAmbiguous} machines Defender portent ce nom, celle affichée n'est pas garantie`);
  }

  const label = { good: "Sain", warning: "À surveiller", danger: "Critique" }[tone];
  const partial = !intune?.found || !defender?.found;

  return { tone, label, reasons, partial, activeAlertsCount: activeAlerts.length };
}

/**
 * Prépare les données d'une CVE (telle que renvoyée par `api.searchVulnerabilities`, un
 * élément de `VulnerabilitiesTab.jsx::VulnCard`) pour l'export Excel — bouton "Exporter
 * Excel" ajouté à VulnCard le 2026-08-21 (demande de Nicolas). Fonction PURE, sans aucune
 * dépendance à `write-excel-file` : la génération du fichier .xlsx proprement dite (mise en
 * forme des cellules, déclenchement du téléchargement) reste dans `export.js`, pour pouvoir
 * tester ici le CONTENU de l'export sans dépendre de cette librairie ni du DOM — même
 * séparation logique/E-S que le reste de ce fichier vis-à-vis de `theme.js`.
 *
 * Volontairement limité aux données déjà affichées par VulnCard/VulnDeviceTable pour cette
 * CVE, sans nouvel appel API : `search_vulnerabilities` (backend) n'expose ni riskScore, ni
 * exposureLevel, ni l'utilisateur connecté par device — ce niveau de détail existe déjà côté
 * export de référence (skill audit-vuln-defender/Get-CveExposedDevices.ps1, colonnes
 * RiskScore/ExposureLevel/UtilisateurConnecte/...) mais nécessiterait un aller-retour
 * Graph/MDE par device exposé ; hors périmètre d'un bouton "exporter ce qui est déjà à
 * l'écran".
 */
export function buildCveExportData(v) {
  const summary = [
    { label: "CVE", value: v?.cve_code || "" },
    { label: "Sévérité", value: v?.severity || "Inconnu" },
    { label: "Score CVSS", value: typeof v?.cvss_score === "number" ? v.cvss_score : null },
    { label: "Niveau d'exploitation", value: v?.exploitability_level || "" },
    { label: "Correctif disponible", value: v?.security_update_available ? "Oui" : "Non connu" },
    { label: "Devices exposés", value: v?.affected_count ?? (v?.devices?.length || 0) },
    { label: "1ère détection (évidence logicielle)", value: v?.first_seen || null },
    { label: "Dernière détection (évidence logicielle)", value: v?.last_seen || null },
  ];

  // Chemins joints par un saut de ligne (pas " | " comme le script PowerShell de référence) :
  // la cellule Excel est mise en retour à la ligne (`wrap: true`, voir export.js) pour rester
  // fidèle au rendu à l'écran de PathList (un chemin par ligne), plutôt que de choisir une
  // convention différente entre le dashboard et son export.
  const devices = (v?.devices || []).map((d) => ({
    device: d?.hostname || "",
    rbacGroup: d?.rbac_group || "",
    diskPaths: Array.isArray(d?.disk_paths) && d.disk_paths.length > 0 ? d.disk_paths.join("\n") : "",
    registryPaths: Array.isArray(d?.registry_paths) && d.registry_paths.length > 0 ? d.registry_paths.join("\n") : "",
  }));

  return { summary, devices };
}

// Ordre des états d'installation dans la feuille "Vue d'ensemble" de l'export par département
// (voir buildAppInstallExportData ci-dessous) — même vocabulaire camelCase que
// `installState` renvoyé par get_app_install_status (backend/intune/apps.py), PAS les
// libellés FR (ceux-ci vivent dans DeployedAppsTab.jsx::INSTALL_STATE_LABEL_FR, traduits au
// moment de construire les en-têtes de colonnes dans export.js plutôt que dupliqués ici).
const INSTALL_STATE_EXPORT_ORDER = ["installed", "failed", "pendingInstall", "notInstalled", "notApplicable"];

/**
 * Regroupe le détail par device d'une app (get_app_install_status, déjà chargé côté client
 * pour le panneau détail — voir AppDetailPanel dans DeployedAppsTab.jsx) par "département"
 * (2026-08-25, demande de Nicolas : "un export excel... une feuille par départements et une
 * feuille de vue d'ensemble avec les comptes par département et l'appli concernée").
 *
 * "Département" = `department` Entra ID de l'utilisateur assigné au device, résolu côté backend
 * (`intune/apps.py::_department_by_upn`) — PAS une correspondance construite ici, on
 * regroupe juste sur ce champ déjà présent sur chaque device. Un device sans `department`
 * (utilisateur non renseigné, ou device sans utilisateur assigné) atterrit dans le
 * regroupement "Non renseignée" plutôt que d'être exclu silencieusement de l'export.
 *
 * L'export porte sur TOUS les devices chargés pour cette app, pas seulement ceux visibles
 * après les filtres actifs à l'écran (recherche/état/département) — un export doit rester complet
 * indépendamment de ce que l'utilisateur est en train de regarder au moment du clic.
 */
export function buildAppInstallExportData(app, devices) {
  const list = devices || [];
  const byStar = {};
  for (const d of list) {
    const star = d.department || "Non renseignée";
    (byStar[star] ||= []).push(d);
  }

  // Tri par nombre de devices décroissant, "Non renseignée" toujours en dernier (regroupement
  // technique, pas un vrai département — pas la peine qu'il remonte en tête juste parce qu'il a
  // beaucoup de devices sans utilisateur assigné).
  const starNames = Object.keys(byStar).sort((a, b) => {
    if (a === "Non renseignée") return 1;
    if (b === "Non renseignée") return -1;
    return byStar[b].length - byStar[a].length;
  });

  const overview = starNames.map((star) => {
    const ds = byStar[star];
    const counts = Object.fromEntries(INSTALL_STATE_EXPORT_ORDER.map((k) => [k, 0]));
    let other = 0;
    for (const d of ds) {
      if (d.installState && d.installState in counts) counts[d.installState] += 1;
      else other += 1;
    }
    return { star, total: ds.length, ...counts, other };
  });

  // Une feuille par département, devices triés par nom pour rester exploitables manuellement dans
  // Excel (même intention que le tri appliqué ailleurs dans ce fichier aux tableaux exportés).
  for (const star of starNames) {
    byStar[star] = [...byStar[star]].sort((a, b) => (a.deviceName || "").localeCompare(b.deviceName || ""));
  }

  return {
    appName: app?.displayName || "Application inconnue",
    starNames,
    overview,
    byStar,
  };
}

/* ══════════════════════ Export Excel — Vanitas (2026-09-17) ══════════════════════
   Un bouton "Exporter Excel" par page fleet-wide de Vanitas (Postes, Conformité,
   Vulnérabilités, Logiciels obsolètes, Activités suspectes, Applications déployées, Mises à
   jour) — demande de Nicolas, même geste que les 2 exports Pandore ci-dessus : génération
   100% client (voir export.js), export de la donnée COMPLÈTE déjà en mémoire pour cette page,
   indépendamment des filtres/recherche actifs à l'écran au moment du clic (même principe que
   `buildAppInstallExportData`) — SAUF Activités suspectes, où les filtres (sévérité/statut/
   période) délimitent une investigation et font donc partie du périmètre exporté par choix
   explicite, pas par limitation technique (voir `buildSuspiciousEventsExportData`). */

/** Postes — une ligne par agent enrôlé, groupes résolus en noms plutôt qu'en ids bruts.
 * `isOnlineFn` = `isOnline` de vanitasShared.jsx, passé en paramètre plutôt que réimporté ici
 * pour ne jamais dupliquer/diverger du seuil de fraîcheur (24h) qu'il encode. */
export function buildPostesExportData(agents, groupById, latestCommandByAgent, isOnlineFn) {
  return (agents || []).map((a) => ({
    hostname: a.hostname || "",
    online: isOnlineFn(a),
    lastSeen: a.last_seen || null,
    agentVersion: a.agent_version || "",
    certNotAfter: a.cert_not_after || null,
    appsCount: a.apps_count ?? 0,
    groups: (a.group_ids || []).map((gid) => groupById.get(gid)?.name).filter(Boolean).join(", "),
    lastCommand: latestCommandByAgent.get(a.id)?.command_type || "",
    lastCommandAt: latestCommandByAgent.get(a.id)?.created_at || null,
  }));
}

/** Conformité — un résumé par règle + une ligne par (règle × poste), même découpage que
 * l'export CVE (Résumé + détail) ci-dessus. */
export function buildConformiteExportData(rules) {
  const summary = (rules || []).map((r) => {
    let compliant = 0,
      nonCompliant = 0,
      unknown = 0;
    for (const d of r.devices || []) {
      if (d.compliant === true) compliant++;
      else if (d.compliant === false) nonCompliant++;
      else unknown++;
    }
    return { name: r.name, enabled: !!r.enabled, total: (r.devices || []).length, compliant, nonCompliant, unknown };
  });

  const detail = [];
  for (const r of rules || []) {
    for (const d of r.devices || []) {
      detail.push({
        rule: r.name,
        hostname: d.hostname,
        status: d.compliant === true ? "Conforme" : d.compliant === false ? "Non conforme" : "Inconnu",
      });
    }
  }

  return { summary, detail };
}

/** Vulnérabilités — une ligne par (CVE × poste exposé), sur TOUT le parc (paramètre `groups`
 * déjà non filtré côté page, voir VanitasVulnerabilitiesTab.jsx). */
export function buildVulnerabilitiesExportData(groups) {
  const rows = [];
  for (const g of groups || []) {
    for (const d of g.devices || []) {
      rows.push({
        cveId: g.cve_id,
        severity: g.severity || "Inconnu",
        cvssScore: typeof g.cvss_score === "number" ? g.cvss_score : null,
        published: g.published || null,
        hostname: d.hostname,
        product: d.product_name || "",
        installedVersion: d.installed_version || "",
        versionAffected: d.version_affected ? "Oui" : "Non",
      });
    }
  }
  return rows;
}

/** Logiciels obsolètes (EOL) — une ligne par occurrence (poste × logiciel/OS), `rows` déjà
 * non filtré côté page (VanitasEolTab.jsx::allRows) et `typeLabels` = TYPE_LABEL_FR de cette
 * même page (pas dupliqué ici, ce fichier ne connaît que la forme des données, pas leurs
 * libellés d'affichage — même séparation que INSTALL_STATE_COLUMN_LABEL_FR côté export.js). */
export function buildEolExportData(rows, typeLabels) {
  return (rows || []).map((r) => ({
    hostname: r.hostname,
    type: typeLabels?.[r.type] || r.type,
    name: r.name,
    version: r.version || "",
    isEol: !!r.is_eol,
    daysUntilEol: r.days_until_eol ?? null,
    eolDate: r.eol_date || null,
    message: r.message || "",
  }));
}

/** Activités suspectes — export de la liste TELLE QUE FILTRÉE à l'écran (voir commentaire
 * d'en-tête ci-dessus) : `events` = `filtered` de VanitasSuspiciousActivityTab.jsx,
 * `labels` = ses maps SEVERITY_LABEL_FR/SIGNAL_TYPE_LABEL_FR/STATUS_LABEL_FR. */
export function buildSuspiciousEventsExportData(events, labels) {
  return (events || []).map((e) => ({
    hostname: e.hostname,
    severity: labels?.severity?.[e.severity] || e.severity || "",
    signalType: labels?.signalType?.[e.signal_type] || e.signal_type || "",
    matchedRule: e.matched_rule || "",
    summary: e.summary || "",
    occurredAt: e.occurred_at || null,
    status: labels?.status?.[e.status] || e.status || "",
    handledBy: e.handled_by || "",
    handledAt: e.handled_at || null,
    handledNote: e.handled_note || "",
  }));
}

/** Applications déployées (Vanitas) — même découpage à deux niveaux que
 * `buildAppInstallExportData` (Pandore) mais regroupé par INSTALLEUR plutôt que par département
 * (Vanitas n'a pas de notion de département Entra ID, voir `target_label` = groupe Vanitas ciblé,
 * pas un département) : une feuille "Vue d'ensemble" (une ligne par appli, décompte ok/échec/
 * attente) + une feuille par appli avec le détail poste par poste. */
export function buildVanitasDeployedAppsExportData(rows) {
  const overview = (rows || []).map((r) => {
    const counts = { ok: 0, bad: 0, pending: 0 };
    for (const d of r.devices || []) counts[d.status] = (counts[d.status] || 0) + 1;
    return {
      name: r.name,
      version: r.version || "",
      targets: (r.targets || []).join(", "),
      total: (r.devices || []).length,
      ...counts,
    };
  });

  const byApp = {};
  for (const r of rows || []) {
    byApp[r.name] = [...(r.devices || [])].sort((a, b) => (a.hostname || "").localeCompare(b.hostname || ""));
  }

  return { appNames: (rows || []).map((r) => r.name), overview, byApp };
}

/** Mises à jour Vanitas (patch) — une ligne par poste suivi, `entries` déjà non filtré côté
 * page (VanitasPatchTab.jsx::entries) ; les 4 buckets sont comptés (pas listés un par un,
 * les titres de mise à jour individuels restent consultables depuis la fiche poste). */
export function buildPatchStatusExportData(entries) {
  return (entries || []).map((e) => ({
    hostname: e.hostname,
    group: e.group_name || "",
    status: e.status,
    available: (e.available || []).length,
    todo: (e.todo || []).length,
    inProgress: (e.in_progress || []).length,
    installed: (e.installed || []).length,
    installedAt: e.installed_at || null,
    forcedAt: e.forced_at || null,
    updatedAt: e.updated_at || null,
  }));
}
