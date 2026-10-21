# Endpoint Agent — supervision de poste de travail

Projet personnel, séparé du dashboard Pandore (`backend/`/`frontend/` à la racine du
repo). Objectif final : un agent installé sur les postes de travail qui remonte l'inventaire
applicatif (puis les vulnérabilités associées) et permet d'exécuter des vérifications à
distance, pour un usage à l'échelle d'un vrai petit parc, avec la sécurité comme priorité.

On avance par jalons validés un par un plutôt que de tout construire d'un coup.

## Jalon 1 — ✅ Terminé et vérifié de bout en bout

Plomberie de base agent ↔ serveur : enrôlement par token à usage unique, inventaire des
applications installées, consultable côté serveur.

- `server/` — API FastAPI (enrôlement, réception d'inventaire, consultation).
- `agent/` — agent .NET (Windows Service), collecte l'inventaire local et le pousse au serveur.

## Jalon 2 — ✅ Terminé et vérifié de bout en bout

Rapprochement CVE : croise l'inventaire déjà remonté avec l'API NVD (gratuite — `cve-bin-tool`
écarté, GPL-3.0 et ne résout pas le vrai problème pour un inventaire Windows générique, voir
le plan). Rafraîchissement automatique 2×/jour (tâche de fond, `cve_matching.refresh_fleet`) —
le rafraîchissement manuel ciblé par agent (`POST /agents/{id}/refresh-vulnerabilities`) a été
retiré le 2026-09-09 (revue de code, jamais câblé côté dashboard).

- `server/app/nvd_client.py` — client API NVD 2.0 (recherche CPE + récupération des CVE).
- `server/app/cve_matching.py` — correspondance approximative nom→CPE (même philosophie que
  le rapprochement ANSSI/CERT-FR du dashboard DSI : jamais présentée comme une certitude) +
  vérification de version affectée.
- `server/app/routes/vulnerabilities.py` — `GET /agents/{id}/vulnerabilities`.
- Prérequis optionnel : une clé API NVD gratuite (`server/.env`, voir `.env.example`) —
  accélère le rythme d'appel, fonctionne aussi sans (juste plus lentement).

⚠️ **Limite connue, découverte en testant sur l'inventaire réel de ce poste** : certaines CVE
anciennes dans NVD n'ont aucune borne de version renseignée (ex. CVE-2007-2176 sur Firefox) —
notre code suit alors NVD à la lettre et les considère comme affectant TOUTES les versions, y
compris les plus récentes. C'est un vrai défaut de qualité de la donnée source NVD, pas un bug
de notre logique — pas corrigé par une heuristique inventée (deviner une date de fin de vie
que NVD ne donne pas serait pire). À garder en tête en lisant les résultats.

## Jalon 3 — ✅ Terminé et vérifié de bout en bout

Bascule complète de l'auth par token API vers mTLS — chaque agent prouve son identité par
possession de sa clé privée à chaque requête, plutôt qu'un secret partagé qui transite en
clair. **Cutover net** (pas de double mécanisme) : `Agent.api_token_hash`/`SecretStore.cs`
(token DPAPI du jalon 1) entièrement retirés.

- Mini-CA interne (`cryptography`, ECDSA P-256) : `server/scripts/generate_ca.py` (one-shot,
  refuse d'écraser sans `--force` — régénérer la CA invalide tous les certificats déjà émis),
  `server/app/ca.py` (signature de CSR, CN imposé = `agent_id`, validité **90 jours**). Clé de
  la CA chiffrée au repos (`CA_KEY_PASSPHRASE`, `.env` — le secret le plus sensible du projet).
- Enrôlement v2 (`POST /enroll`) : l'agent génère sa paire de clés + une CSR directement dans
  `Cert:\LocalMachine\My` (`agent/.../Communication/CertificateStore.cs`) — **la clé privée ne
  quitte jamais la machine**, seule la CSR (clé publique) part vers le serveur. Le token
  d'enrôlement à usage unique du jalon 1 reste le mécanisme de bootstrap de confiance initial.
- Renouvellement automatique (`POST /agents/{id}/renew`) : le `Worker` vérifie l'expiration à
  chaque cycle, renouvelle (même clé, nouveau certificat) dès qu'il reste moins de 30 jours —
  authentifié par le certificat ACTUEL, pas par un chemin d'auth séparé.
- `security.get_current_agent` extrait le CN du certificat pair mTLS vérifié par uvicorn
  (nécessite un monkeypatch documenté de `HttpToolsProtocol.on_url`, uvicorn n'exposant pas
  nativement le certificat client aux routes FastAPI).
- Validation stricte du certificat SERVEUR côté agent contre la CA du projet
  (`X509ChainTrustMode.CustomRootTrust`) — jamais ajoutée aux autorités racines de confiance de
  Windows. Seule exception délibérée : le tout premier `/enroll` (avant que l'agent n'ait vu la
  CA) accepte le certificat serveur sans validation — confiance initiale déjà établie par le
  token à usage unique, limite de bootstrap acceptée (même logique que la confiance au premier
  contact d'un client SSH).

⚠️ **Écrire dans `Cert:\LocalMachine\My` nécessite un process élevé** (`X509KeyStorageFlags.
MachineKeySet`) — attendu et sans conséquence pour un vrai Windows Service (tourne avec les
privilèges appropriés), mais à garder en tête pour tout test manuel via `dotnet run`.

**Vérifié en conditions réelles, de bout en bout, base et magasin de certificats vidés** :
enrôlement (CSR → certificat signé → import dans le magasin), push d'inventaire authentifié
uniquement par certificat, renouvellement forcé (nouveau numéro de série confirmé, certificat
immédiatement accepté pour la requête suivante), puis un cycle complet depuis un état
totalement vierge (aucun agent en base, aucun certificat installé).

## Jalon 4 — ✅ Terminé et vérifié de bout en bout

Canal de commande : le serveur peut demander à un agent d'exécuter une action prédéfinie (pas
de shell libre), l'agent l'exécute et remonte un résultat — journalisé pour l'audit. Première
capacité "le serveur agit sur le poste" (jusqu'ici tout n'allait que dans le sens agent →
serveur).

- **Pas de signature cryptographique séparée** — le mTLS du jalon 3 authentifie déjà les deux
  sens du canal, et l'agent n'exécute jamais que des handlers codés en dur
  (`Commands/CommandExecutor.cs`) : le catalogue fermé + le canal déjà authentifié suffisent.
- **Poll dédié, 5 min** (`Communication/CommandPoller.cs`, timer indépendant du `Worker` qui
  reste à 6h pour l'inventaire) — une commande lancée par l'admin est exécutée en quelques
  minutes.
- **Catalogue initial (4 commandes)** : `force_inventory` (pousse l'inventaire tout de suite),
  `system_diagnostic` (disque/uptime/OS), `check_windows_updates` (liste les mises à jour
  Windows en attente, lecture seule — API COM `Microsoft.Update.Session`, liaison tardive),
  `restart_service` (arrêt propre du process — voir limite ci-dessous).
- Admin : `server/scripts/queue_command.py <agent_id> <command_type>` (ou `--all`) — même
  convention que `create_enrollment_token.py`. Audit : `GET /agents/{id}/commands`
  (volontairement non authentifiée, même précédent que `GET /agents/{id}/vulnerabilities`
  depuis le jalon 2).

⚠️ **`restart_service`** ne peut, tant qu'il n'existe pas de vrai Windows Service installé
(packaging MSI, jalon 5), que demander l'arrêt propre du process courant — pas de politique de
récupération pour le relancer automatiquement. En dev, le process s'arrête et doit être
relancé à la main. **Résolu au jalon 5** (voir plus bas) — packagé en vrai Windows Service avec
une politique de récupération, `restart_service` redémarre désormais tout seul.

🔧 **Bug réel trouvé et corrigé en testant** : le handler `restart_service` appelait
`IHostApplicationLifetime.StopApplication()` avant de laisser le POST du résultat partir —
`StopApplication()` annule le `CancellationToken` de la boucle, qui annulait aussitôt ce même
POST, laissant la commande bloquée sur "running" pour toujours. Corrigé en séparant le rapport
de résultat (toujours en premier) de la demande d'arrêt (ensuite, côté `CommandPoller`).

**Vérifié en conditions réelles, contre l'agent enrôlé de ce poste** : les 4 types de commande
exécutés avec de vraies données (59 apps réenvoyées, vrai disque/uptime/OS, 3 vraies mises à
jour Windows en attente détectées via l'API COM réelle — jamais testée avant ce jalon —, arrêt
propre confirmé après rapport du résultat). Anti-usurpation testée (certificat d'un agent sur
l'`agent_id` d'un autre → 403, même mécanisme que `/inventory`/`/renew`).

## Jalon 5 — ✅ Terminé et vérifié de bout en bout

Passage à l'échelle : packaging MSI signé (vrai Windows Service), et intégration dans le
dashboard Pandore (dépôt principal) sous une catégorie "Vanitas"
à part entière — bascule dans le masthead ("Tenant Intune" / "Vanitas"), propre Sidebar, 3
pages (Vue d'ensemble / Postes / Commandes). Deux volets indépendants.

### A/B/C — Serveur, proxy dashboard, frontend Vanitas

- Serveur : `AgentSummary` gagne `cert_serial`/`cert_not_after` ; `app/commands.py::
  create_command()` factorise la création d'une commande (réutilisée par `queue_command.py` ET
  la nouvelle route HTTP) ; `GET /commands` (fleet-wide, jointure `hostname`) et
  `POST /agents/{id}/commands` (queue une commande sans passer par le script CLI) —
  volontairement non authentifiées, même précédent que le reste des routes admin de ce serveur.
- Dashboard DSI (dépôt principal) : `backend/vanitas/client.py` — SEUL point de proxy depuis le
  dashboard vers ce serveur (jamais d'appel direct navigateur → serveur Vanitas, son certificat
  auto-signé n'est pas fiable pour un navigateur), `httpx.Client(verify=<ca.pem>)`. Routes
  `/api/vanitas/*` (`backend/api_server.py`).
- Frontend (dépôt principal) : bascule de masthead (`Dashboard.jsx`, état `source`), sidebar
  dédiée (`VanitasSidebar.jsx`), 3 pages (`VanitasOverviewTab.jsx`/`VanitasDevicesTab.jsx`/
  `VanitasCommandsTab.jsx`) — testées avec les vraies données de l'agent enrôlé sur ce poste,
  formulaire de commande testé en réel (queue → exécution → résultat visible dans l'audit).

🔧 **Bug réel trouvé et corrigé en construisant cette partie** : `DateTime(timezone=True)`
(SQLAlchemy/SQLite) perd son fuseau au retour de lecture — un horodatage écrit UTC-aware
revenait naïf, faussant tous les calculs de "il y a X" côté dashboard selon le décalage horaire
local. Corrigé par un `TypeDecorator` dédié (`UTCDateTime`, `server/app/models.py`) qui
réattache `timezone.utc` si absent à la lecture — appliqué aux 11 colonnes datetime du modèle.

### D — Packaging : vrai Windows Service, signé, enrôlement automatique

- **WiX Toolset v4** (`agent/Installer/`, projet SDK-style) — choisi explicitement pour éviter
  le mur de licence "Open Source Maintenance Fee" de WiX v7 (`wix.exe : error WIX7015`).
  Installe le binaire self-contained (`dotnet publish -r win-x64 --self-contained
  -p:PublishSingleFile=true`), l'enregistre comme un VRAI service Windows (`ServiceInstall`/
  `ServiceControl`, compte `LocalSystem` — nécessaire pour écrire dans
  `Cert:\LocalMachine\My`), et pose une politique de récupération
  (`util:ServiceConfig`, extension `WixToolset.Util.wixext`) : 3 échecs redémarrent (pas
  seulement le premier), délai de 10s, remise à zéro du compteur après 24h sans incident.
- **Enrôlement automatique à l'installation** — `ENROLLMENTTOKEN` (propriété MSI publique) est
  posé comme variable d'environnement MACHINE persistante (`Agent__EnrollmentToken`,
  `<Environment System="yes" Part="all">`), lue directement depuis le registre par le SERVICE
  lui-même à son premier démarrage (`Worker.cs::TryAutoEnrollAsync`), qui s'enrôle avec le même
  code que `--enroll` puis efface la variable une fois le token consommé avec succès (jamais
  laissée en clair au-delà). `Agent__ServerUrl` suit le même mécanisme pour l'URL du serveur.
  Utilisable en ligne de commande Intune Win32 :
  `msiexec /i EndpointAgent.msi ENROLLMENTTOKEN=xxx SERVERURL=https://... /qn`.
- **Certificat de signature de code auto-signé** (`server/scripts/generate_codesign_cert.ps1`,
  `New-SelfSignedCertificate -Type CodeSigningCert`, RSA 4096) — PFX protégé par mot de passe
  (gitignoré, `server/data/codesign/`), certificat public (`.cer`) à importer sur chaque poste
  cible dans `Cert:\LocalMachine\Root` **et** `Cert:\LocalMachine\TrustedPublisher` (import GPO/
  Intune, ou manuel — voir section Déploiement ci-dessous). MSI signé via `signtool sign /fd
  SHA256 /tr <serveur d'horodatage RFC3161>`, vérifié (`signtool verify /pa`).

🔧 **Bug réel trouvé et corrigé en testant la politique de récupération (étape la plus
piégeuse de ce jalon)** : `restart_service` appelait `IHostApplicationLifetime.
StopApplication()` — un arrêt PROPRE, que le Service Control Manager voit comme une demande
volontaire (exit code 0), exactement comme un `net stop` par un admin. Les politiques de
récupération Windows ne se déclenchent QUE sur une terminaison **inattendue** du process,
jamais sur un arrêt propre — confirmé en conditions réelles : le service restait `Stopped`
indéfiniment. Corrigé en remplaçant `StopApplication()` par `Environment.Exit(1)` (le résultat
de la commande est déjà rapporté au serveur avant cet appel) — le process disparaît sans passer
par la séquence d'arrêt propre, le SCM le voit comme une terminaison inattendue et applique la
politique de récupération sans condition supplémentaire à activer. **Reproduit et vérifié dans
les deux sens** : avec `StopApplication()`, service `Stopped` indéfiniment ; avec
`Environment.Exit(1)`, service `Stopped` → `Running` en ~8 secondes sans aucune intervention
manuelle, cohérent avec le délai de 10s configuré.

⚠️ **Pièges rencontrés en packageant, tous contournés** (pour une future session sur ce
projet) :
- Une première approche (action MSI DIFFÉRÉE relançant `EndpointAgent.exe --enroll` pendant
  l'installation) a été abandonnée après un vrai test : fenêtre console visible/gelable (piège
  "Sélection" classique de Windows), blocage reproduit même une fois la fenêtre masquée —
  remplacée par le mécanisme "variable d'environnement + auto-enrôlement au démarrage du
  service" décrit plus haut, bien plus simple et fiable.
- **Windows Installer peut silencieusement RÉUTILISER l'ancien binaire** lors d'un
  réinstall/rebuild successif (comparaison de version jugeant le fichier "déjà à jour" même
  quand le code a changé) — confirmé en comparant taille/date du fichier installé vs
  fraîchement publié. Contournement systématique pendant les tests : arrêter le service et
  supprimer le dossier d'installation à la main AVANT chaque réinstallation. Pas encore corrigé
  à la source (donner à l'exe une vraie version qui s'incrémente à chaque publish) — à faire si
  ce cycle de test redevient fréquent.
- La désinstallation MSI via `msiexec /x` a une fois rapporté un succès (log + code retour 0)
  sans que le service soit réellement arrêté/supprimé — anomalie non élucidée, contournée par
  une séquence manuelle plus fiable (`Stop-Service` + `sc.exe delete` + suppression du dossier
  + `msiexec /x` en nettoyage de l'enregistrement résiduel).
- La désinstallation/réinstallation MSI ne touche jamais à `Cert:\LocalMachine\My` — un agent
  réinstallé sans retirer son certificat reprend silencieusement son ancienne identité au lieu
  de se ré-enrôler. Comportement correct et voulu (cohérent avec un vrai redéploiement de poste
  qui ne doit pas dupliquer l'agent côté serveur), juste à garder en tête en testant.

**Vérifié en conditions réelles, de bout en bout, sur ce poste** : MSI construit et SIGNÉ
(`signtool verify /pa` → succès, horodatage RFC3161), désinstallation complète (service, dossier,
certificat agent, enregistrement MSI), réinstallation depuis le MSI signé avec un nouveau token
→ **nouvel agent auto-enrôlé sans aucune intervention manuelle** (`b8a08a9e...`, 59 applications
poussées), visible à la fois via l'API du serveur Vanitas ET via le proxy du dashboard DSI
(`/api/vanitas/agents`). Politique de récupération testée avec une VRAIE commande
`restart_service` passée par le canal de commande du jalon 4 : service redémarré tout seul en
~8 secondes, toujours enrôlé et fonctionnel après coup (pas de boucle de crash).

## Jalon 6 — ✅ Terminé et vérifié de bout en bout

Dans la foulée du jalon 5, la page "Postes" du dashboard a été refondue en une vraie fiche par
poste (`frontend/src/pages/VanitasDeviceDetail.jsx` — hero, bandeau de santé cliquable, nav
latérale groupée, bento "Vue d'ensemble" dense) inspirée d'un outil d'inventaire existant
(capture GLPI de Nicolas), remplaçant l'ancien rail étroit empilant des cartes. Deux de ses
panneaux (`Matériel`, `Identité & réseau`) affichaient alors honnêtement "pas encore collecté" —
ce jalon ajoute la collecte manquante.

- **Nouvelle commande `hardware_inventory`** (5ᵉ du catalogue fermé, `server/app/commands.py`)
  — mêmes 3 points de synchronisation manuelle que les commandes existantes (catalogue serveur,
  `Commands/CommandExecutor.cs` côté agent, libellé FR `vanitasShared.jsx`). Résultat JSON
  stocké tel quel dans `AgentCommand.result`, même mécanisme que `system_diagnostic`/
  `check_windows_updates`, aucune nouvelle route. Colonne passée de `String(4000)` à `Text`
  (non bornée) — un premier élargissement à `String(8000)` s'est avéré encore limite une fois
  les périphériques PCI ajoutés (voir plus bas) ; SQLite n'impose de toute façon aucune limite
  réelle sur une colonne texte, aucune migration nécessaire pour l'un ou l'autre changement.
- **`Inventory/HardwareInventoryCollector.cs`** (nouveau, `System.Management`/WMI) — identité
  machine (`Win32_ComputerSystemProduct`), BIOS/carte mère (`Win32_BIOS`/`Win32_BaseBoard`),
  châssis (`Win32_SystemEnclosure`), mémoire par barrette (`Win32_PhysicalMemory`), disques
  physiques (`Win32_DiskDrive`), carte(s) graphique(s) (`Win32_VideoController`), identité
  réseau (`Win32_NetworkAdapterConfiguration`/`Win32_ComputerSystem.UserName`/`IPGlobalProperties`
  pour le nom DNS complet, WMI n'exposant pas cette info sur `Win32_ComputerSystem`), et
  **périphériques PCI** (`Win32_PnPEntity` filtré sur `DeviceID` commençant par `PCI\`,
  regroupés par `PNPClass` — mêmes catégories que le Gestionnaire de périphériques Windows —
  pilote résolu via `Win32_PnPSignedDriver` apparié par `DeviceID`) — demandé par Nicolas après
  avoir vu l'équivalent dans un autre outil d'inventaire (capture GLPI), ajouté le jour même.
  Chaque section a son propre try/catch : une classe WMI en échec sur un modèle de machine
  particulier n'empêche jamais les autres sections d'apparaître. **Scope volontairement réduit** :
  pas de S.M.A.R.T. (complexité WMI supplémentaire pour un gain jugé secondaire).
- Mode `--hardware-diag` (`Program.cs`) — imprime le résultat brut du collecteur sans passer par
  le canal de commande ni le serveur, même esprit que `--enroll` : pratique pour vérifier une
  section WMI sur un nouveau modèle de machine sans avoir à queue une vraie commande.
- **Panneau "Matériel"** (`VanitasDeviceDetail.jsx`) : accordéon `<details>`/`<summary>` natif
  par catégorie PCI (Réseau/Contrôleurs de stockage/Affichage-GPU/Bus série/Système/Ports...),
  pas de mécanisme JS dédié pour un simple replié/déplié indépendant par groupe.

🔧 **Deux bugs réels trouvés et corrigés en testant contre ce poste** :
1. `Win32_PhysicalMemory.Capacity` et `Win32_DiskDrive.Size` (propriétés WMI `uint64`)
   reviennent en `ulong` boxé, pas en `string` — le code d'origine ne gérait que le cas
   `string` (par analogie hâtive avec d'autres propriétés WMI numériques du projet), donc
   `CapacityBytes`/`SizeBytes`/`TotalMemoryBytes` restaient systématiquement `null`. Corrigé
   par un convertisseur tolérant (`ToNullableLong`, accepte `ulong`/`long`/`uint`/`int`/
   `string`) plutôt que de supposer une seule représentation.
2. La requête WQL `WHERE DeviceID LIKE 'PCI\%'` renvoyait 0 résultat sur ce poste malgré de
   vrais périphériques PCI présents — l'échappement du backslash dans une chaîne WQL s'est
   montré peu fiable. Corrigé en énumérant tous les `Win32_PnPEntity` et en filtrant par
   `DeviceId.StartsWith("PCI\\")` côté C#, sans ambiguïté de syntaxe.

**Vérifié en conditions réelles, de bout en bout, sur ce poste** (Dell Latitude 5430) : collecte
isolée (`--hardware-diag`) confirmée avec de vraies valeurs (16 Go RAM en 2 barrettes 3200 MT/s,
disque NVMe 512 Go, GPU Intel Iris Xe, IP/utilisateur Azure AD/nom DNS réels, 24 périphériques
PCI répartis en 7 catégories — dont les 2 mêmes cartes réseau visibles dans le Gestionnaire de
périphériques de Nicolas) ; commande `hardware_inventory` queue → exécutée → résultat stocké
côté serveur (JSON complet, ~7300 caractères avec les périphériques PCI inclus) ; panneaux
"Matériel"/"Identité & réseau" du dashboard testés avec ce vrai résultat (rendu correct, aucune
donnée fabriquée, accordéon PCI cliquable) ET sur un agent n'ayant jamais exécuté la commande
(état vide honnête + raccourci de lancement, comme `system_diagnostic`/`check_windows_updates`
avant lui). `npx vite build` propre, aucune erreur console.

⚠️ Le VRAI Windows Service installé sur ce poste (jalon 5) tourne encore avec le binaire
D'AVANT ce jalon — la vérification ci-dessus a été faite via `dotnet run` (lecture seule de la
clé privée du certificat déjà enrôlé, nécessite aussi l'élévation, pas juste l'écriture comme
documenté au jalon 3) pour éviter de repasser par tout le cycle MSI. **À repackager/réinstaller**
si Nicolas veut que le service réellement déployé dispose de `hardware_inventory` en continu.

## 🔧 Bug du jalon 2 trouvé et corrigé pendant le jalon 6 : une même CVE affichée des dizaines
de fois

Signalé par Nicolas (capture d'écran) : la page "Vulnérabilités" affichait 76 196 lignes pour
un agent, avec des CVE visiblement répétées à l'identique des dizaines de fois pour un même
logiciel (ex. CVE-2008-6536 sur 7-Zip, 36 fois).

**Diagnostic confirmé AVANT correction** (pas deviné) : ce n'était PAS un bug de duplication en
base ni une race condition entre process serveur (un doute initial levé en inspectant les
process réellement en cours — la paire parent/enfant `python.exe -m uvicorn` observée sur ce
poste s'est avérée un simple détail de bootstrap Windows d'uvicorn, le parent restant inactif
0% CPU pendant que l'enfant fait tout le travail, PAS deux instances applicatives concurrentes).
Le vrai mécanisme : une CVE peut avoir PLUSIEURS lignes `CveFinding` pour un même produit — une
par condition de version disjointe que NVD liste (ex. 36 versions de 7-Zip listées
individuellement entre 2008 et 2015). `vulnerabilities_for_snapshot()`
(`server/app/routes/vulnerabilities.py`) renvoyait UNE ENTRÉE PAR LIGNE sans regrouper —
confirmé en base : sur cet agent, 76 196 lignes brutes mais seulement 6 342 couples (produit,
CVE) distincts, et **98,9 % des lignes avaient déjà `version_affected: false`** (le code avait
déjà déterminé que la version installée n'était PAS concernée, mais les affichait quand même).

**Corrigé** : les lignes sont maintenant regroupées par (produit, CVE) — `True` si au moins une
condition confirme que la version installée est concernée, `None` si aucune ne confirme mais
qu'au moins une reste indéterminable (jamais tranché à tort), sinon **exclue** (toutes les
conditions écartent positivement la version installée — ne jamais présenter un faux positif
déjà écarté par le code lui-même comme un risque réel). Résultat sur cet agent : 76 196 → 848
lignes, chaque couple (produit, CVE) une seule fois, 7-Zip repassé à 0 CVE (26.02 n'est
réellement concerné par aucune condition connue).

**Vérifié en conditions réelles** : compte avant/après confirmé via l'API brute ET dans le
dashboard (rechargement complet nécessaire — le cache client 2h servait encore l'ancien
résultat sinon). Aucune migration de schéma nécessaire (changement de logique applicative pur).

## Jalon 7 : désinstallation à distance + retrait d'inventaire

Demande de Nicolas : pouvoir gérer le CYCLE DE VIE d'un agent depuis le dashboard — le
désinstaller à distance sur son poste, et/ou retirer sa fiche de l'inventaire serveur (deux
actions liées mais indépendantes : un poste peut être décommissionné/réinstallé sans jamais
recevoir la commande de désinstallation, il faut quand même pouvoir retirer sa fiche).

Ce sont les deux premières actions VRAIMENT destructrices/irréversibles de ce dashboard — le
reste du projet n'a AUCUN mécanisme de confirmation nulle part (ex.
`AppCatalogTab.jsx::handleRemove` supprime une entrée de catalogue en un clic direct). Nouveau
composant `ConfirmButton` (`vanitasShared.jsx`) réutilisé par les deux boutons : premier clic →
le bouton affiche "Confirmer ?" pendant 5s (réinitialisé par `setTimeout` si aucun second clic
n'arrive), second clic dans la fenêtre → exécute réellement. Pas de nouvelle popup/modal pour
ce seul besoin, proportionné au risque.

### A. Désinstallation à distance — 6ᵉ commande du catalogue existant

Même mécanisme que les 5 commandes déjà en place (jalon 4/5/6) — aucune nouvelle route, aucun
nouveau modèle serveur. `CommandExecutor.cs::UninstallAgent()` :
- Retrouve le `ProductCode` MSI réel en scannant le registre
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (vue 64 bits) à la recherche de
  l'entrée dont `DisplayName == "Endpoint Agent"` — jamais codé en dur (le ProductCode change à
  chaque rebuild WiX). Refuse explicitement de deviner si 0 ou plusieurs entrées matchent
  (état ambigu), plutôt que de risquer de désinstaller le mauvais produit.
- Lance `msiexec /X{ProductCode} /qn /norestart` en process détaché, puis retire le certificat
  agent (`CertificateStore.RemoveCurrentCertificate`, devenue publique). **Pas
  d'`Environment.Exit`** ici contrairement à `restart_service` : on ne simule pas un crash,
  l'arrêt du service doit rester propre aux yeux du SCM — c'est `ServiceControl
  Stop="uninstall"` (déjà dans `Installer/Product.wxs` depuis le jalon 5) qui demande l'arrêt
  propre au moment voulu par msiexec lui-même.
- Le résultat rapporté est optimiste ("désinstallation lancée") — l'agent ne peut PAS confirmer
  après coup que la désinstallation a réussi, il vient de se supprimer.

### 🔧 Bug réel trouvé et corrigé en testant pour de vrai (deux fois) : la commande restait
"running" indéfiniment malgré une désinstallation réussie

Les deux premiers tests de bout en bout (sur un agent réel authentifié explicitement par
Nicolas, puis sur un agent de test frais) ont chacun confirmé la désinstallation OS PARFAITE
(service/fichiers/certificat/registre tous réellement supprimés en quelques secondes) mais la
commande restait bloquée à `"status":"running"` côté serveur, jamais `"completed"`.

**Première hypothèse (fausse)** : `msiexec` lancé de façon synchrone À L'INTÉRIEUR de
`UninstallAgent()` pouvait devancer le rapport de résultat HTTP encore en vol — "corrigé" en
ajoutant un 4ᵉ élément au tuple retourné par chaque handler de commande, `Action?
PostReportAction`, invoqué par `CommandPoller.PollOnceAsync` SEULEMENT APRÈS
`ReportCommandResultAsync`. Retesté pour de vrai : **toujours cassé à l'identique**.

**Vraie cause, trouvée en relisant `ServerClient.cs`** : `ReportCommandResultAsync` (comme
TOUT appel de ce client) a besoin du certificat agent COURANT pour s'authentifier en mTLS
(`CertificateStore.FindCurrentCertificate() ?? throw new InvalidOperationException(...)`) —
or `CertificateStore.RemoveCurrentCertificate()` était appelé de façon EAGER dans
`UninstallAgent()`, avant même le `return` de la méthode, donc AVANT que
`ReportCommandResultAsync` n'ait eu l'occasion de partir. Le certificat était donc déjà
supprimé au moment de rapporter le résultat : l'appel HTTP authentifié levait une exception,
avalée silencieusement par le `try/catch` de `CommandPoller`, jamais rapportée. Corrigé en
déplaçant le retrait du certificat DANS l'action différée (`PostReportAction`), juste avant le
lancement de msiexec — jamais avant le retour de `UninstallAgent()`. Leçon générale au-delà de
ce cas précis : différer "ce qui pourrait tuer le process" ne suffit pas, il faut différer TOUT
ce qui invaliderait l'authentification du rapport de résultat lui-même.

**Vérifié en conditions réelles, troisième test, les deux volets à la fois** : agent de test
fraîchement enrôlé → commande `uninstall_agent` queue → poll agent (5 min) → désinstallation OS
confirmée (service disparu, `Get-Service` ne retourne plus rien) → **ET** commande confirmée
`"status":"completed"`, `"success":true` côté serveur, avec le vrai ProductCode et le texte de
résultat attendu (aucune corruption d'encodage réelle — un mojibake observé une fois n'était
qu'un artefact de mon propre affichage lors du diagnostic, pas un bug serveur).

### B. Retrait de l'inventaire — nouvel endpoint DELETE, aucune nouvelle capacité agent

- `server/app/models.py::Agent` — nouvelle relation `commands` (cascade `all, delete-orphan`),
  symétrique à `snapshots` déjà en place : supprimer un agent supprime tout son historique de
  commandes avec lui, pas seulement son inventaire.
- `server/app/routes/agents.py` — `DELETE /agents/{agent_id}` (404 si absent, sinon 204).
- `backend/vanitas/client.py::remove_agent` + `DELETE /api/vanitas/agents/{agent_id}`
  (`api_server.py`) + `api.vanitas.removeAgent` (frontend) — même chaîne de proxy que le reste
  du module.
- `useVanitasAgents()` gagne un `refresh()` (invalide le cache 2h + relance `ensureLoaded`,
  même patron que le bouton "Rafraîchir" du dashboard principal) — sans ça, un agent retiré
  serait resté visible dans la liste jusqu'à expiration du cache.

⚠️ Pensé pour un poste déjà décommissionné/désinstallé, pas comme un substitut à la
désinstallation : utilisé sur un agent encore réellement actif, son prochain push
d'inventaire/poll de commande recevra simplement une 404 (déjà le comportement existant,
inchangé) — l'agent continue de tourner sur le poste mais disparaît du dashboard tant qu'il
n'est pas ré-enrôlé.

**Vérifié en conditions réelles** : route testée via curl sur des agents de test dédiés AVANT
tout usage sur un agent réel, puis réellement utilisée en fin de session pour nettoyer les 2
fiches d'agents jetables laissées par les tests de désinstallation ci-dessus (200 sur les
deux, disparues de `GET /agents` ensuite) — confirme le mécanisme de bout en bout, pas
seulement en isolation.

`uninstall_agent` est explicitement exclu du menu déroulant générique de `CommandForm`
(`DANGEROUS_COMMAND_TYPES`/`SAFE_COMMAND_TYPES`, `vanitasShared.jsx`) — jamais sélectionnable
par erreur parmi des commandes anodines, accessible uniquement via son propre bouton
`ConfirmButton` dédié sur la fiche poste.

## Jalon 8 : refonte "HUD cyberpunk" de la page "Postes"

Demande de Nicolas : "tous mes inventaires se ressemblent... je veux que ce soit différent",
puis "façon cyberpunk mais en restant pro" après une première piste écartée (nature morte/
memento mori — cohérente avec le nom "Vanitas" mais jugée trop éloignée du besoin réel).

**Identité SCOPÉE** sous une classe `.vanitas-hud` (posée sur le conteneur racine de
`VanitasDevicesTab.jsx`) plutôt que dans `:root` du dashboard — jamais mélangée aux tokens du
"dossier sombre" qui habille le reste de Pandore. Cyan (`--hud-accent`) = accent de marque
(cadres à coins, focus, curseur) ; magenta (`--hud-accent2`) = dimension à part (compteur
d'applications, jamais une gravité) ; vert/ambre/rouge restent strictement sémantiques
(statut), jamais réutilisés comme accent — séparation délibérée entre accent de marque et
couleur sémantique. Polices dédiées (Rajdhani/IBM Plex Sans/Space Mono), grille en filigrane
très discrète en fond, cadres à coins d'angle façon targeting HUD, barre de certificat
segmentée (façon barre de vie) plutôt qu'un dégradé plat, pastille de statut qui pulse pour
"en ligne" en vrai (CSS `@keyframes`).

**Retrait de l'inventaire directement depuis une ligne de la liste** (nouveau, en plus de la
fiche poste déjà en place depuis le jalon 7) — bouton `RETIRER`/`CONFIRMER` (`ConfirmButton`,
deux clics), clic dans la cellule d'actions coupé de la propagation pour ne jamais déclencher
la navigation vers la fiche poste. `ConfirmButton` (`vanitasShared.jsx`) gagne au passage une
classe CSS `armed` posée automatiquement au premier clic — avant, seul le texte du bouton
changeait, aucun repère visuel de l'état "armé".

**Testé en conditions réelles, données réelles du tenant** : 4 agents de test insérés
directement en base pour peupler KPI/filtres/tri/recherche/dernière commande, retrait via le
bouton confirmé de bout en bout (agent réellement supprimé côté serveur, KPI mis à jour sans
recharger la page). Un faux négatif rencontré en testant (le 2ᵉ clic de confirmation semblait
ne rien faire) s'est avéré être un résidu de Hot Module Reload sur `vanitasShared.jsx`, pas un
bug réel — confirmé disparu après un rechargement complet. `npx vite build` propre, `npx
vitest run` : 106 passed. Données de test nettoyées après vérification.

## Jalon 9 : terminal PowerShell interactif à distance

Demande de Nicolas : "on pourrait mettre en place un système qui permet de lancer une
connexion PowerShell avec l'ordinateur à distance ?" — un vrai shell interactif, pas une
version atténuée "un script en un coup" (confirmé par question directe). C'est un changement
d'architecture, pas une commande de plus : le jalon 4 avait délibérément choisi un catalogue
fermé de commandes prédéfinies précisément pour éviter qu'un accès au dashboard ne devienne un
accès shell arbitraire sur tous les postes enrôlés — ce jalon lève cette garantie en
connaissance de cause. Deux points tranchés explicitement avec Nicolas avant de concevoir la
suite :
1. Vrai shell interactif complet (pas un script à la demande).
2. Un secret partagé (`X-Shell-Token`) en plus du modèle de confiance "loopback uniquement"
   qui suffisait jusqu'ici pour le reste de Vanitas — spécifiquement pour les routes qui
   permettent d'observer/piloter une session déjà ouverte, vu le saut de puissance (RCE niveau
   SYSTEM, l'agent tourne en LocalSystem depuis le jalon 5) par rapport à tout le reste.

### Pourquoi pas un WebSocket

Un agent Explore (lecture complète du code réel avant toute conception) a confirmé trois
obstacles concrets à une architecture WebSocket "classique" (agent `ClientWebSocket` ↔ serveur
`@app.websocket()` ↔ dashboard) : (1) l'extraction du certificat mTLS pair (`security.py::
get_current_agent`) repose sur un monkeypatch de `HttpToolsProtocol.on_url` qui suppose un
scope ASGI `"http"`, jamais testé pour un scope `"websocket"` ; (2) le navigateur ne parle
JAMAIS directement au serveur Vanitas aujourd'hui, tout passe par `backend/vanitas/client.py`
(le backend du dashboard Pandore) — un WebSocket ajouterait un relais à 3 sauts sans aucun
précédent dans ce code ; (3) complexité disproportionnée (reconnexion, heartbeat, trames
partielles) pour un projet personnel à cette échelle, face à un aller-retour d'~1s largement
suffisant pour taper des commandes de dépannage.

**Retenu** : un 7ᵉ type de commande du catalogue existant, `start_shell_session` — mais dont
le handler ne bloque JAMAIS `CommandPoller`. Un agent Plan, chargé de stress-tester une
première mouture de cette conception (PAS de la redessiner), a trouvé un vrai problème
d'architecture avant qu'une seule ligne de code métier ne soit écrite : faire tourner toute la
session (des minutes, potentiellement des heures) À L'INTÉRIEUR du `foreach` synchrone de
`CommandPoller.PollOnceAsync` aurait gelé tout le canal de commande de cet agent pour toute la
durée de la session — plus aucune autre commande, y compris `restart_service` (la seule porte
de sortie en cas de poste qui déraille), n'aurait pu être traitée. Exactement le pire moment
pour perdre cette porte de sortie : un dépannage par shell est souvent déclenché PARCE QUE le
poste se comporte déjà mal.

**Corrigé avant implémentation** : `CommandExecutor.cs::"start_shell_session"` délègue à
`Commands/ShellSessionRunner.cs`, qui lance la vraie session dans une tâche de fond
(`Task.Run`, jamais attendue) et retourne IMMÉDIATEMENT un résultat de succès — exactement
comme les 6 autres commandes, aucun changement de contrat. La session réelle (spawn du process
PowerShell, boucle d'entrée/sortie) tourne complètement DÉCOUPLÉE de `CommandPoller` : elle
fait ses propres appels HTTP directs (créer la session, poll d'entrée, poster la sortie) sur
son propre cycle serré (~1s), jamais via le canal de commande fermé. Un garde-fou statique
(`_activeTask`) refuse une 2ᵉ session tant qu'une première est active pour cet agent.

**Serveur** (`server/app/routes/shell.py`, nouveau fichier, + deux nouvelles tables
`ShellSession`/`ShellSessionEvent` dans `models.py`) : côté AGENT (mTLS, `Depends
(get_current_agent)`, routes HTTP normales — aucun risque avec le monkeypatch mentionné
plus haut) créer la session, poll d'entrée (curseur `last_delivered_input_id`), poster la
sortie, fermer. Côté DASHBOARD (`Depends(require_shell_token)`) lire le statut (+ `is_stale`
calculé à la volée, pas de tâche de fond dédiée), lire les événements depuis un curseur,
envoyer une ligne, demander l'arrêt. **`ShellSessionEvent` sert à la fois de file de relais ET
de journal d'audit permanent** — une seule table, jamais purgée. Volontairement **sans**
relation/cascade vers `Agent` (contrairement à `AgentCommand`) : retirer un poste décommissionné
de l'inventaire (jalon 7) ne doit jamais effacer la trace de ce qui a été exécuté dessus via un
shell SYSTEM — même raisonnement déjà accepté sur `EnrollmentToken.used_by_agent_id`.

### 🔧 Bugs réels trouvés en testant (pas devinés)

Une commande CLI ponctuelle (`--shell-diag`, même précédent que `--hardware-diag`/
`--find-product-code`) a permis de dérisquer le point le plus délicat — le spawn d'un
`powershell.exe` persistant avec stdin/stdout redirigés — AVANT de le brancher sur le reste :

1. **PowerShell, en mode redirigé, réécrit en écho le PROMPT + la ligne d'entrée telle
   qu'envoyée** avant même que la commande ne s'exécute (confirmé sur le flux brut). Cette
   ligne d'écho contient donc TOUJOURS le marqueur de fin de commande comme sous-chaîne
   (puisqu'il fait partie du texte envoyé) — un `Contains` matchait dessus, jamais sur la
   vraie sortie, décalant tout le regroupement d'un cran (chaque "résultat" affichait en fait
   la sortie de la commande PRÉCÉDENTE). Corrigé par une égalité STRICTE (après trim) sur le
   marqueur, plus `Contains`, et par un filtre explicite qui ignore la ligne d'écho (jamais
   montrée à l'admin — pure plomberie interne).
2. **`Encoding.UTF8` (la propriété statique) émet un BOM** (U+FEFF) en tête du flux — sur
   `StandardInput`, ce BOM se retrouve collé au TOUT PREMIER caractère envoyé, corrompant la
   toute première commande de chaque session (confirmé : PowerShell rapportait le nom de la
   commande comme "terme non reconnu"). Corrigé avec `new UTF8Encoding(false)` (sans BOM) pour
   les trois flux plutôt que la propriété statique.
3. **Accents corrompus sur la sortie PowerShell native** ("système" → "systŠme" sur un
   `Write-Output`) avant tout encodage explicite — .NET décodait le flux avec l'encodage
   console OEM par défaut. Corrigé par `StandardOutputEncoding`/`StandardErrorEncoding` en
   UTF-8 (sans BOM) des deux côtés — confirmé : `Write-Output "système été à côté"`
   round-trippe désormais parfaitement, y compris à travers tout le pipeline réel (dashboard →
   backend → serveur Vanitas → agent → PowerShell → retour).
4. ⚠️ **Limite connue, PAS corrigée** : un exécutable console NATIF externe (`whoami.exe`,
   `chcp.com`...) écrit sa propre sortie selon le codepage console actif — un mécanisme Windows
   indépendant de l'encodage .NET ci-dessus, qui ne gouverne que la sortie PROPRE à PowerShell.
   Confirmé en isolation : même après un `chcp 65001` explicite, le message de confirmation DE
   `chcp` lui-même restait corrompu. Un accent dans la sortie d'un outil natif externe (pas une
   commande PowerShell) peut donc encore s'afficher mal — rabbit hole de codepage Windows sous
   redirection complète, hors scope de ce jalon ; la quasi-totalité du dépannage réel (`Get-*`,
   `Write-Output`, variables) n'est pas concernée.
5. **Un arrêt FORCÉ du service pendant une session active peut laisser un process PowerShell
   orphelin** — repéré en testant (pas en lisant le code) : plusieurs redéploiements de cet
   agent avec `Stop-Service -Force` pendant qu'une session était encore ouverte ont laissé 1-2
   `powershell.exe` orphelins (visibles via `Get-Process powershell`, session 0 = session des
   services). Cause : le nettoyage (`Process.Kill(entireProcessTree: true)`) vit dans le bloc
   `finally` de `ShellSessionRunner.RunAsync` — si le PROCESS PARENT lui-même (l'agent) est tué
   avant que ce bloc n'ait une chance de s'exécuter, il ne peut jamais tourner. Le chemin
   d'arrêt NORMAL (bouton "Fermer la session", ou timeout d'inactivité) reste, lui, testé et
   confirmé propre — cette limite ne concerne qu'un arrêt BRUTAL du service pendant une session
   (crash, `Stop-Service -Force`, redémarrage Windows Update), pas la désinstallation à distance
   normale (`uninstall_agent`, jalon 7, qui n'a de sens que hors session).
6. 🔧 **Bug réel signalé par Nicolas APRÈS la clôture initiale du jalon** : "je vois pas les
   resultat de commandes" — une commande comme `ls`/`Get-ChildItem` (sortie volumineuse,
   plusieurs centaines d'événements `OutputDataReceived` pour un seul résultat tabulaire)
   n'affichait JAMAIS de sortie dans le terminal, alors que l'entrée apparaissait bien et que
   l'agent restait actif. Diagnostiqué en trois temps, jamais deviné : (1) requêtes SQLite
   directes confirmant que de VRAIS événements de sortie existaient bien pour une session
   ANTÉRIEURE (donc pas "aucune sortie n'a jamais fonctionné"), mais absents pour la session de
   reproduction précise ; (2) `Get-Process powershell | Select Id,CPU` interrogé à deux reprises
   à quelques secondes d'écart (confirmé par Nicolas : "le CPU reste quasi stable") — le process
   PowerShell avait DÉJÀ fini d'exécuter la commande, ce n'est donc pas un blocage du process
   lui-même ; (3) conclusion : l'égalité stricte (`Trim() ==`) sur le marqueur de fin de
   commande échouait à reconnaître la ligne de marqueur pour ce type de sortie — probablement
   parce que le marqueur arrive collé à un fragment de la dernière ligne de résultat plutôt que
   comme une ligne autonome, sur un flux à volume élevé. **Corrigé** en repassant sur une
   détection par `Contains` (le marqueur peut apparaître n'importe où dans la ligne, pas
   seulement en égalité stricte), en préservant tout le texte AVANT le marqueur dans le
   résultat plutôt que de le jeter, et en ajoutant un filet de sécurité (flush du tampon
   accumulé si le marqueur n'est jamais détecté avant le timeout de 30s — un 2ᵉ trou resté
   ouvert depuis le premier tour de tests, qui aurait sinon perdu silencieusement tout le
   buffer accumulé dans ce cas). **Confirmé corrigé en trois temps** : `--shell-diag` isolé
   (`Get-ChildItem C:\Windows\System32` puis une 2ᵉ commande, les deux résultats bien
   récupérés) ; au curl direct contre l'agent réel redéployé (`GET .../events?since_id=0` →
   606906 octets contenant la liste complète et exacte de `C:\Windows\System32`) ; et **dans la
   vraie UI navigateur** (le listing complet rendu dans `.vanitas-hud-terminal-log`, puis une
   commande de suivi — `Write-Output "apres-ls-ok"` — confirmée elle aussi round-trippée
   correctement après ce gros volume, preuve que la session reste saine après ce cas).
7. 🔧 **Bug réel signalé par Nicolas** : "la double soumission des commandes" — une capture
   d'écran plus tôt dans ce jalon montrait déjà chaque commande apparaissant deux fois dans le
   défilement. Revue complète de la chaîne AVANT de corriger quoi que ce soit (formulaire
   `VanitasDeviceDetail.jsx`, hook `useShellSession.js`, `api.js::postJSON`, route FastAPI
   `POST .../input`) : aucune n'insère jamais un événement en double côté serveur, `postJSON`
   n'a pas de retry, et le hook n'affiche jamais la ligne de façon optimiste (elle réapparaît
   au prochain `tick()` une fois créée côté serveur) — pas de duplication structurelle trouvée
   à ce niveau. **Cause probable identifiée** : `handleTerminalSubmit` lisait `terminalInput`
   (un `useState`) et le vidait via `setTerminalInput("")`, mais cette remise à zéro — comme
   toute mise à jour d'état React — n'est commise qu'au prochain rendu, PAS de façon
   synchrone : une deuxième soumission (double clic rapide sur "Envoyer", ou Entrée suivi d'un
   clic quasi simultané) tombant dans cette fenêtre lisait encore l'ANCIENNE valeur du texte et
   renvoyait donc la même ligne une 2ᵉ fois. Plausible en particulier parce que ce terminal
   n'affiche AUCUN retour visuel immédiat après l'envoi (choix de conception assumé, voir le
   commentaire de `useShellSession.js` — la ligne ne réapparaît qu'au prochain `tick()`, ~1s
   plus tard) : un utilisateur impatient a de bonnes raisons de retaper/recliquer très vite en
   pensant que rien ne s'est passé. **Corrigé** par un garde-fou basé sur un `useRef` (pas un
   `useState`) dans `handleTerminalSubmit` — un `ref` se met à jour de façon SYNCHRONE, sans
   attendre un rendu : posé à `true` avant tout appel asynchrone, vérifié en tout PREMIER, remis
   à `false` dans un `finally`. Ferme la fenêtre de course quelle que soit sa cause exacte
   (Entrée + clic, double clic, tout autre déclencheur), sans changer le comportement pour un
   envoi normal. **Testé en direct contre l'agent réel** : trois `form.requestSubmit()`
   synchrones DANS LE MÊME tick JavaScript (plus agressif que n'importe quel double clic humain
   réel, qui laisse toujours au moins un cycle de rendu React entre les deux événements) →
   confirmé un SEUL événement d'entrée créé côté serveur (`guard-test-once`) — contre trois
   attendus sans le correctif. Commande de suivi immédiatement après confirmée fonctionnelle
   normalement (le garde-fou ne reste pas bloqué à `true`).

### Frontend (`VanitasDeviceDetail.jsx`, nouveau pane "Terminal")

`ConfirmButton` (deux clics, jalon 7) pour LANCER une session seulement — jamais par commande
tapée à l'intérieur, inutilisable sinon — précisant dans son `title` le niveau SYSTEM. Après
confirmation : état "en attente que l'agent démarre la session (jusqu'à 5 min, même délai que
n'importe quelle commande)" jusqu'à ce qu'une session apparaisse active (nouvelle route de
DÉCOUVERTE `GET /agents/{id}/shell/sessions/latest`, le dashboard ne connaît pas l'id de
session à l'avance), puis bascule sur le terminal (défilement + ligne de saisie). Nouveau hook
dédié `useShellSession.js` — PAS `cache.js`/`useKeyedFetch` (pensés pour un TTL de 2h,
inadaptés à un flux qui doit rafraîchir toutes les ~1s ; confirmé par l'agent Explore
qu'aucun mécanisme de rafraîchissement périodique n'existe ailleurs dans ce dashboard).
Identité HUD du jalon 8 réutilisée pour ce pane (`.vanitas-hud`) — un terminal est le cas
d'usage le plus naturel pour cette identité.

### Testé en conditions réelles, de bout en bout (agent réel, service réel, vraie UI navigateur)

Trois cycles complets de redéploiement (publish + MSI + réinstallation réelle) pour corriger
les bugs 1-3 ci-dessus au fur et à mesure qu'ils étaient trouvés. Validations finales :
- **Le point critique du jalon** : `start_shell_session` puis `force_inventory` queuées
  immédiatement l'une après l'autre → `force_inventory` terminée en quelques secondes PENDANT
  que la session de terminal était encore active — confirme que la session n'a jamais bloqué
  le canal de commande normal.
- État persistant confirmé sur une VRAIE session : une variable PowerShell définie dans une
  commande, relue correctement dans une commande SÉPARÉE ultérieure — preuve d'un vrai process
  persistant, pas une exécution isolée à chaque ligne.
- Accents confirmés intacts de bout en bout : `Write-Output "système été à côté"` round-trippe
  parfaitement à travers tout le pipeline réel.
- Session fermée proprement via le bouton dashboard (`stop_requested` vu par la boucle serrée
  de l'agent en ~1-4s, statut passé à `closed`).
- **Testé dans la vraie UI du dashboard** (pas seulement au curl) : confirmation en deux
  clics, attente de démarrage, terminal live, commande réelle tapée (`Get-Date`) et sortie
  affichée, fermeture propre — tout confirmé via lecture directe du DOM.
- `pytest tests/test_mcp_tool_parity.py` : 2 passed (changement 100% Vanitas, hors périmètre
  Intune/Defender). `npx vite build` propre, `npx vitest run` : 106 passed.
- **Cycle de test supplémentaire, APRÈS le signalement du bug #6 ci-dessus** : redéploiement
  (publish + MSI + réinstallation réelle) pour charger le correctif, nouvelle session ouverte
  dans la vraie UI, `Get-ChildItem C:\Windows\System32` tapé et son résultat complet confirmé
  affiché dans le terminal (plus plausible qu'un simple "ça ne plante plus" : le contenu exact
  du listing a été relu dans le DOM), commande de suivi confirmée elle aussi fonctionnelle
  juste après, session refermée proprement.

## Roadmap

- ~~**Jalon 1**~~ — agent ↔ serveur, enrôlement simple par token, inventaire applicatif.
- ~~**Jalon 2**~~ — rapprochement CVE sur l'inventaire déjà remonté (API NVD).
- ~~**Jalon 3**~~ — bascule de l'auth par token vers mTLS (mini-CA interne, certificat par
  agent, renouvellement automatique).
- ~~**Jalon 4**~~ — canal de commande : catalogue fermé de commandes prédéfinies, exécutées
  par l'agent, résultat + journal d'audit remontés au serveur.
- ~~**Jalon 5**~~ — passage à l'échelle : packaging MSI signé (vrai Windows Service, politique
  de récupération), enrôlement automatique à l'installation, intégration dans le dashboard DSI
  (catégorie "Vanitas" dédiée).
- ~~**Jalon 6**~~ — refonte de la fiche poste (hero/bandeau de santé/nav groupée) + collecte
  matérielle, réseau et périphériques PCI via WMI (`hardware_inventory`) pour combler les deux
  derniers panneaux honnêtement vides. Corrigé au passage un vrai bug du jalon 2 (CVE affichées
  en double).
- ~~**Jalon 7**~~ — désinstallation à distance (6ᵉ commande du catalogue) + retrait
  d'inventaire (`DELETE /agents/{id}`), confirmation en deux clics pour ces deux actions
  destructrices. Corrigé au passage un vrai bug de timing (le certificat agent était retiré
  avant que le rapport de résultat n'ait pu s'authentifier avec lui).
- ~~**Jalon 8**~~ — refonte visuelle "HUD cyberpunk" de la page "Postes" (identité propre à
  Vanitas, cyan/magenta sur fond bleu-nuit, scopée sous `.vanitas-hud`) après trois maquettes
  comparées (sobre / memento mori / HUD) — voir plus bas pour la conception détaillée.
- ~~**Jalon 9**~~ — terminal PowerShell interactif à distance (7ᵉ commande du catalogue,
  `start_shell_session`) : lève délibérément la garantie "catalogue fermé" du jalon 4 pour un
  vrai shell, en gardant l'agent toujours sortant (aucun port entrant). Voir plus bas pour la
  conception (pourquoi pas un WebSocket) et les bugs réels trouvés en testant.
- ~~**Jalon 10**~~ — refonte HUD de "Vue d'ensemble" (maquette validée par Nicolas, "en te
  basant sur les informations qu'on prend sur les postes") + nouvel endpoint fleet-wide "Top 5
  vulnérabilités les plus répandues". Voir plus bas pour le détail.
- ~~**Jalon 11**~~ — conformité "comme dans Intune", mais les règles sont des scripts
  PowerShell UPLOADÉS PAR NICOLAS (pas codées en dur), exécutés en SYSTEM sur le parc, contrat
  exit-code 0/1. 8ᵉ commande du catalogue (`compliance_check`), même découplage que le jalon 9.
  Voir plus bas pour la conception, le vrai piège PowerShell trouvé en testant, et le vrai bug
  de build/déploiement (rien à voir avec le code applicatif) qui a bloqué le redéploiement.

## Jalon 10 : refonte HUD de "Vue d'ensemble" + top 5 vulnérabilités du parc

Demande de Nicolas, en deux temps : (1) une maquette "façon cyberpunk mais pro" pour "Vue
d'ensemble", "en te basant sur les informations qu'on prend sur les postes" — reprendre les
MÊMES dimensions que "Postes" (jalon 8 : statut en ligne, certificat, dernière commande), pas
de nouvelle donnée pour cet écran ; (2) après validation de la maquette, "un module en plus
pour les vulnérabilité[s], un top 5 de cell[es] qui sont le plus vu[es]" — puis "ok ca me va
met ca en place" (implémentation réelle).

L'ancien "Vue d'ensemble" (`.strip`/`SummaryCard`, motif générique du reste du dashboard
Pandore) est remplacé par l'identité HUD de "Postes" (`.vanitas-hud`, jalon 8) — bandeau KPI à
5 tuiles (Postes/En ligne/Certificat < 30j/Silencieux > 7j/Commandes 7j), "Postes à
surveiller" (liste triée par priorité, dérivée des mêmes seuils que "Postes" — cert < 30j,
silencieux > 7j), "Top 5 vulnérabilités", "Activité récente" (flux fleet-wide des commandes),
et un rail à droite (répartition en ligne/silencieux, prochaines expirations de certificat,
commandes 7j par statut). Aucune nouvelle route pour tout ça — trois listes déjà chargées
ailleurs (`useVanitasAgents`/`useVanitasCommands`) suffisent, tout est dérivé côté client.

**Seule vraie nouveauté de données : l'agrégat "Top 5 vulnérabilités"**. Jusqu'ici, le
rapprochement CVE (`GET /agents/{id}/vulnerabilities`, jalon 2) est calculé PAR AGENT, à la
demande, en croisant l'inventaire de SON dernier snapshot avec le cache `CveFinding` — jamais
agrégé fleet-wide. Plutôt que de faire récupérer par le dashboard le détail CVE de chaque
agent un par un (un agent peut avoir des centaines de CVE, voir la fiche poste), nouvel
endpoint dédié côté serveur Vanitas : `GET /vulnerabilities/top?limit=5`
(`server/app/routes/vulnerabilities.py::get_top_vulnerabilities`) — réutilise
`vulnerabilities_for_snapshot` (déjà déduplique par (produit, cve_id) et déjà purgée des faux
positifs de version, voir son docstring existant) sur le dernier snapshot de CHAQUE agent,
agrégé en mémoire dans la même requête : une CVE est comptée par NOMBRE D'AGENTS DISTINCTS
touchés (un agent avec 2 logiciels partageant la même CVE ne compte qu'une fois), classée par
ce compte puis par CVSS décroissant. Calculé à la demande plutôt que matérialisé en base —
proportionné à l'échelle de ce projet (une poignée d'agents).

`CertSegBar`/`certTone`/`toneVar`/`CERT_WARNING_DAYS`/`STALE_HOURS` (jusque-là locaux à
`VanitasDevicesTab.jsx`) extraits vers `vanitasShared.jsx` — réutilisés tels quels par
"Prochaines expirations" de la Vue d'ensemble, pour que les deux pages appliquent EXACTEMENT
les mêmes seuils "certificat qui expire bientôt"/"poste silencieux" plutôt que deux définitions
qui pourraient diverger en silence.

**Testé en conditions réelles** (2026-09-06) : redémarrage des deux serveurs (Vanitas + proxy
Pandore) pour charger le nouveau code — un piège d'exploitation Windows rencontré au passage :
tuer le process "parent" `python -c "import uvicorn; uvicorn.run(...)"` par son PID a aussi tué
le VRAI serveur actif (uvicorn tourne en fait comme processus enfant de ce parent sur ce
poste) — les deux ont dû être relancés ensemble. `curl`/`httpx` direct contre le nouvel
endpoint : 5 vraies CVE renvoyées, triées par CVSS décroissant (le seul agent réel n'a qu'un
poste donc `device_count=1` partout — la logique de tri par nombre de postes n'a pas encore pu
être vérifiée sur un vrai cas où deux CVE ont un décompte différent, mais la boucle
d'agrégation elle-même a été relue attentivement plutôt que supposée correcte). Dans le
navigateur, données réelles du tenant : bandeau KPI confirmé (1 poste, 1 en ligne, 0 cert < 30j,
0 silencieux, 11 commandes/7j), "Postes à surveiller" confirmé vide à raison (le seul poste réel
est sain), "Top 5 vulnérabilités" confirmé avec les 5 vraies CVE (sévérité traduite en
français, barre de propagation), "Activité récente"/"Répartition du parc"/"Prochaines
expirations"/"Commandes — 7 j" tous confirmés avec les vraies données de l'agent réel
(`DEMO-WKS-109`, certificat à 90 j). `npx vite build` propre, `npx vitest run` : 106 passed.

## Jalon 11 : conformité via scripts PowerShell fournis par Nicolas

Demande de Nicolas : "je veux mettre en place une sorte de conformité comme dans Intune."
Différence structurante tranchée avec lui avant la conception (`AskUserQuestion`) : les règles
ne sont PAS des vérifications WMI codées en dur (BitLocker/pare-feu/Defender, comme j'avais
proposé par défaut) — il veut les écrire lui-même en PowerShell et les uploader depuis le
dashboard, exactement le principe d'un script de détection Intune déjà utilisé côté packaging
Win32 de l'autre moitié de ce dashboard : le script tourne, son CODE DE SORTIE dit conforme
(`exit 0`) ou non conforme (tout code non nul), sa sortie texte devient la preuve affichée.
Aucun contrat JSON structuré — volontairement le plus simple possible. Deuxième point tranché :
vérification **automatique périodique** (comme l'inventaire) **+ bouton "Forcer une
vérification"** à la demande.

Un agent Explore (×3, en parallèle) a confirmé qu'aucune donnée de conformité n'existe nulle
part dans le pipeline actuel, puis un agent Plan a stress-testé une première mouture de la
conception (lecture réelle de `Worker.cs`/`ShellSessionRunner.cs`/`CommandPoller.cs`/
`shell.py`/`security.py` avant de critiquer) et trouvé plusieurs vrais problèmes AVANT qu'une
ligne de code métier ne soit écrite — notamment le piège PowerShell ci-dessous, découvert
"sur le papier" par l'agent puis PRÉCISÉ empiriquement en testant (voir plus bas, le premier
diagnostic de l'agent s'est avéré trop large).

### Architecture

`compliance_check` (8ᵉ commande du catalogue) suit EXACTEMENT le même schéma de découplage que
"start_shell_session" au jalon 9— garde-fou statique (une seule vérification à la fois par
agent, PARTAGÉ entre le déclenchement automatique et à la demande), retour synchrone immédiat,
la tâche de fond fait son propre appel HTTP direct pour poster le résultat final. Nouveau
`Compliance/ComplianceRunner.cs` (collecte + garde-fou) + nouveau `Communication/
ComplianceLoop.cs` (`BackgroundService` À PART, pas greffé sur `Worker.cs` qui a déjà son
propre couple renouvellement-de-certificat + inventaire sur un seul timer — même raisonnement
qui avait déjà justifié de séparer `CommandPoller` du `Worker` au jalon 4).

Côté serveur, trois nouvelles tables (`ComplianceRule`/`ComplianceSnapshot`/`ComplianceResult`)
et un nouveau `routes/compliance.py` à TROIS tiers d'auth : agent (mTLS, fetch du catalogue +
dépôt des résultats), dashboard en lecture libre (résumé du catalogue SANS le script, résultats
par agent, agrégat fleet-wide — même tier que `vulnerabilities.py`), et dashboard protégé par
`require_shell_token` (le MÊME secret que le jalon 9, réutilisé tel quel plutôt qu'un second
secret qui n'isolerait aucune population de confiance supplémentaire ici) pour le catalogue
COMPLET (avec `script_content`) et sa gestion (créer/éditer/supprimer) — définir du code qui
s'exécute en SYSTEM sur tout le parc, sans surveillance, en continu, est au moins aussi
sensible qu'une session shell observée par un humain.

`compliant` est un booléen NULLABLE (tri-état) : `None` = erreur d'exécution (timeout, échec de
lancement), distinct de `False` (le contrôle a bien tourné et trouvé un vrai problème) — les
confondre fausserait le classement "règles en échec par impact". Toute règle créée/éditée
repart à `enabled=False` côté serveur (jamais fait confiance au payload pour ce champ précis) —
contrairement à une session shell (un humain tape et regarde en direct), une règle s'exécute
SANS surveillance sur tout le parc : un second clic explicite ("Activer") est nécessaire.

### 🔧 Piège PowerShell réel sur le contrat exit-code — précisé EN TESTANT, pas juste supposé

La crainte initiale de conception ("une exception non interceptée ne suffit pas à faire
échouer le contrôle, `powershell.exe -File` renverrait 0 quand même") s'est avérée **fausse**
sur PowerShell 5.1 une fois testée via `--compliance-diag` (nouveau flag CLI, même précédent
que `--hardware-diag`/`--shell-diag`, mais réutilisant directement `ComplianceRunner.
RunRuleAsync` plutôt que d'en dupliquer une copie) : un `throw` non intercepté (erreur
TERMINANTE) produit bien un code de sortie non nul — confirmé, `compliant: False` correct.

**Le VRAI piège, plus étroit** : une erreur NON TERMINANTE (`Write-Error` sans `-ErrorAction
Stop`, la plupart des erreurs de cmdlet par défaut) affiche un message d'erreur en rouge MAIS
laisse le code de sortie à 0 — confirmé empiriquement (`Write-Error "..."` seul, sans aucun
`exit`, → exit code 0). Un script qui se contente de SIGNALER un problème sans `throw`/`exit 1`
explicite sera donc enregistré CONFORME à tort. Documenté dans le gabarit pré-rempli de
l'éditeur de règles ET le bandeau d'avertissement de la page "Règles de conformité" — pas
corrigeable côté agent, c'est un comportement natif de PowerShell.

Autres points du contrat, réutilisant les leçons déjà acquises au jalon 9 dès le premier jet
(pas redécouvertes) : encodage UTF-8 sans BOM sur les 3 flux, `-ExecutionPolicy Bypass`
explicite (sans lui, une politique `Restricted`/`AllSigned` ferait échouer TOUT script
silencieusement, indiscernable d'une vraie non-conformité), un fichier temporaire PAR EXÉCUTION
DE RÈGLE (`%TEMP%\VanitasCompliance\<guid>.ps1`, jamais un fichier partagé pour tout le lot —
un `Kill(entireProcessTree:true)` sur timeout peut laisser un descripteur de fichier
momentanément tenu par un processus fils).

### 🔧 Bug réel de build/déploiement — rien à voir avec le code applicatif, mais a bloqué tout
le redéploiement pendant un moment

En republiant l'agent pour tester en conditions réelles, le binaire installé restait
OBSTINÉMENT l'ancien malgré plusieurs cycles complets de désinstallation/réinstallation
réussis (confirmés par des logs `msiexec` verbeux, exit code 0 à chaque étape). Diagnostiqué
en extrayant le contenu du MSI directement (`msiexec /a ... TARGETDIR=...`, sans passer par un
vrai install/service) plutôt que de continuer à soupçonner la mécanique d'installation : **le
MSI lui-même contenait le vieux binaire**. Cause racine : `Installer/Product.wxs` référence
`..\EndpointAgent\publish\EndpointAgent.exe` (un dossier `publish/` À PLAT, directement sous
`EndpointAgent/`) — mais `dotnet publish -c Release -r win-x64 ...` SANS `-o publish` écrit à
la place vers l'emplacement PAR DÉFAUT de .NET (`bin/Release/net8.0-windows/win-x64/publish/`),
un dossier complètement différent, laissant le VRAI dossier référencé par WiX intact depuis un
build antérieur sans rapport. `dotnet publish ... -o publish` (avec l'option de sortie
explicite, exécuté depuis `agent/EndpointAgent/`) est donc indispensable avant tout rebuild du
MSI — sans ça, `dotnet build` sur `Installer.wixproj` "réussit" à chaque fois tout en
repackageant silencieusement un binaire périmé. Repéré une fois (pas un bug répété depuis),
mais à garder en tête pour tout futur redéploiement de ce projet.

### Testé en conditions réelles, de bout en bout (2026-09-06)

Après correction du bug de build ci-dessus et un vrai cycle complet de redéploiement (le
service tourne toujours sous la MÊME identité/certificat qu'avant — le certificat client
survit à la désinstallation MSI, `TryAutoEnrollAsync` le retrouve et saute le
ré-enrôlement — sans conséquence : seul le BINAIRE devait changer pour ce test, confirmé par
la taille/date du fichier installé) :
- **Le point critique du jalon** (même validation que le jalon 9) : `compliance_check` puis
  `force_inventory` queuées immédiatement l'une après l'autre → les deux terminées à 4 secondes
  d'écart, confirmant que la vérification de conformité n'a jamais bloqué le canal de commande.
- Une vraie règle ("Service EndpointAgent actif" — vérifie que le service tourne, un contrôle
  réellement utile) créée/activée/déclenchée pour de vrai → **vrai script PowerShell exécuté
  par le vrai agent**, résultat `compliant: true` correctement remonté et agrégé fleet-wide.
- Une 2ᵉ règle de test délibérément non conforme (`exit 1`) → `compliant: false`, `detail`
  capturant bien la sortie du script, classée EN PREMIER dans "Règles en échec — classées par
  impact" (1 poste d'impact contre 0 pour la règle conforme) — confirmé dans le navigateur
  après un rechargement complet (le cache partagé de 2h, jalon 10, retourne bien des données
  périmées sans rechargement — comportement attendu, pas un bug).
- Les trois surfaces UI confirmées avec les vraies données : "Conformité" (vue fleet-wide HUD),
  la fiche poste (`VanitasDeviceDetail.jsx`, nouvel item "Conformité" du groupe "Sécurité"), et
  "Règles de conformité" (catalogue : création via le vrai formulaire du navigateur, bascule
  activer/désactiver, suppression).
- Règle de test supprimée après vérification, un dernier `compliance_check` confirmant l'état
  final propre (1 seule règle réelle, agent 100% conforme).
- `npx vite build` propre, `npx vitest run` : 106 passed, `pytest
  tests/test_mcp_tool_parity.py` : 2 passed (changement 100% Vanitas, hors périmètre Intune/
  Defender).

## Déploiement sur un vrai poste (Intune Win32, ou manuel)

1. Distribuer le certificat public de signature (`server/data/codesign/codesign.cer`, jamais
   le `.pfx`) sur les postes cibles — import dans `Cert:\LocalMachine\Root` **et**
   `Cert:\LocalMachine\TrustedPublisher` (script de démarrage GPO, ou profil de certificat
   Intune) — sans ça, l'installation silencieuse (`/qn`) du MSI signé fonctionne quand même
   (Windows Installer n'exige pas un éditeur de confiance pour un simple `/i`), mais Windows
   SmartScreen/Defender peuvent avertir sur un premier lancement manuel.
2. Générer un token d'enrôlement PAR POSTE (`server/scripts/create_enrollment_token.py`, usage
   unique) — jamais le même token pour plusieurs postes.
3. Commande d'installation Intune Win32 (ligne de commande d'installation) :
   `msiexec /i EndpointAgent.msi ENROLLMENTTOKEN=<token> SERVERURL=https://<serveur>:8443 /qn`
   — commande de désinstallation : `msiexec /x EndpointAgent.msi /qn`.
4. Le service démarre seul, s'auto-enrôle au premier démarrage, apparaît dans le dashboard
   ("Vanitas" > "Postes") en quelques secondes.

## Sécurité — principes qui ne changent pas d'un jalon à l'autre

- Agent → serveur toujours en sortant (poll), jamais de port entrant ouvert sur les postes.
- Depuis le jalon 3 : identité de l'agent prouvée par certificat mTLS (clé privée jamais
  transmise, stockée dans le magasin de certificats Windows), renouvelé automatiquement avant
  expiration — plus de secret partagé qui transite en clair dans un header.
- Depuis le jalon 4 : pas de shell libre — uniquement un catalogue fermé de commandes
  prédéfinies, transporté sur le canal déjà authentifié par mTLS.
