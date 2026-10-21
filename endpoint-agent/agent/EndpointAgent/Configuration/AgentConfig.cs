namespace EndpointAgent.Configuration;

/// <summary>
/// Réglages de l'agent, liés depuis la section "Agent" de appsettings.json.
/// </summary>
public sealed class AgentConfig
{
    public const string SectionName = "Agent";

    /// <summary>URL de base du serveur de contrôle (ex. https://endpoint-agent.local:8123).</summary>
    public string ServerUrl { get; set; } = string.Empty;

    /// <summary>Intervalle entre deux remontées d'inventaire.</summary>
    public int CollectionIntervalHours { get; set; } = 6;

    /// <summary>Intervalle entre deux vérifications de commandes en attente (jalon 4) — séparé
    /// et bien plus court que l'inventaire, pour qu'une commande lancée par l'admin soit
    /// exécutée en quelques minutes plutôt que d'attendre le prochain cycle d'inventaire.</summary>
    public int CommandPollIntervalMinutes { get; set; } = 5;

    /// <summary>
    /// Token d'enrôlement à usage unique, fourni une seule fois à l'installation. Une fois
    /// l'agent enrôlé, l'authentification réelle passe par le certificat client mTLS émis à
    /// l'enrôlement (magasin de certificats Windows, pas un fichier de secret séparé) — ce
    /// champ n'a plus d'utilité après le premier enrôlement réussi, il peut être vidé.
    /// (Correctif du 2026-09-09 : le commentaire précédent renvoyait vers un
    /// `Communication/SecretStore.cs` jamais créé — le design final n'utilise que le mTLS.)
    /// </summary>
    public string? EnrollmentToken { get; set; }

    /// <summary>Cadence de la boucle interne d'une session de terminal (jalon 9) — SÉPARÉE de
    /// <see cref="CommandPollIntervalMinutes"/> : cette boucle tourne dans sa propre tâche de
    /// fond, jamais dans le cycle normal de <c>CommandPoller</c> (voir Commands/
    /// ShellSessionRunner.cs).</summary>
    public int ShellSessionPollIntervalSeconds { get; set; } = 1;

    /// <summary>Ferme automatiquement une session de terminal après ce délai d'inactivité (aucune
    /// nouvelle ligne tapée) — évite un process PowerShell orphelin si l'onglet du dashboard est
    /// fermé sans cliquer "Fermer la session".</summary>
    public int ShellSessionIdleTimeoutMinutes { get; set; } = 15;

    /// <summary>Intervalle entre deux cycles automatiques de vérification de conformité (jalon
    /// 11) — SÉPARÉ de <see cref="CollectionIntervalHours"/> (inventaire) : sa propre boucle
    /// dédiée (<c>Communication/ComplianceLoop.cs</c>), pas greffée sur le <c>Worker</c>
    /// existant qui a déjà le renouvellement de certificat + l'inventaire sur un seul
    /// timer.</summary>
    public int ComplianceCheckIntervalHours { get; set; } = 6;

    /// <summary>Délai maximum accordé à CHAQUE script de règle de conformité avant d'être tué
    /// (`Process.Kill(entireProcessTree: true)`) — global pour toutes les règles en v1, pas de
    /// surcharge par règle (proportionné à l'échelle de ce projet). Un dépassement est enregistré
    /// comme une ERREUR d'exécution, jamais une non-conformité (voir ComplianceResult.compliant,
    /// tri-état).</summary>
    public int ComplianceScriptTimeoutSeconds { get; set; } = 60;

    /// <summary>Délai maximum accordé au téléchargement + à l'exécution d'un installeur
    /// applicatif (2026-09-08, "push d'application via les groupes") avant d'être tué
    /// (`Process.Kill(entireProcessTree: true)`) — plus généreux que
    /// <see cref="ComplianceScriptTimeoutSeconds"/> : un vrai setup (MSI/EXE) peut prendre
    /// plusieurs minutes, contrairement à un script de contrôle de quelques secondes.</summary>
    public int InstallTimeoutSeconds { get; set; } = 600;

    // --- Détection d'activités suspectes (nouveau jalon, 2026-09-14 — voir Detection/) --------

    /// <summary>Coupe-circuit GLOBAL du jalon détection d'activités suspectes — si `false`,
    /// aucun watcher/poller/uploader n'est enregistré dans le conteneur DI (voir Program.cs),
    /// comportement strictement identique à l'agent avant ce jalon.</summary>
    public bool SuspiciousActivityEnabled { get; set; } = true;

    /// <summary>Signal "processus suspects" (4688 + moteur LOLBin/persistance/chemin suspect).</summary>
    public bool ProcessDetectionEnabled { get; set; } = true;

    /// <summary>Signal "journal d'événements" (4720+4732 compte admin, 4624 RDP, 4625 échecs
    /// d'authentification, 1102 purge de journal) — même watcher physique que
    /// <see cref="ProcessDetectionEnabled"/> (un seul EventLogWatcher sur le canal Security),
    /// interrupteur logique séparé pour pouvoir couper l'un sans l'autre.</summary>
    public bool EventLogDetectionEnabled { get; set; } = true;

    /// <summary>Signal "connexions réseau sortantes" (poll `iphlpapi.dll`).</summary>
    public bool NetworkDetectionEnabled { get; set; } = true;

    /// <summary>Signal "support amovible USB" (branchement + agrégation de copie de fichiers).</summary>
    public bool UsbDetectionEnabled { get; set; } = true;

    /// <summary>Intervalle entre deux polls des connexions TCP sortantes — voir
    /// <c>Detection/NetworkConnectionPoller.cs</c> ; angle mort assumé, une connexion ouverte ET
    /// fermée entre deux polls n'est jamais vue (voir le plan).</summary>
    public int NetworkPollIntervalSeconds { get; set; } = 45;

    /// <summary>Intervalle de rafraîchissement du catalogue de règles de détection servi par
    /// `GET /agents/{id}/suspicious-rules` — voir <c>Detection/SuspiciousRulesProvider.cs</c>,
    /// permet d'ajuster les seuils sans recompiler l'agent.</summary>
    public int SuspiciousRulesRefreshIntervalMinutes { get; set; } = 30;

    /// <summary>Intervalle entre deux cycles d'upload du buffer d'événements suspects — voir
    /// <c>Detection/SuspiciousEventUploader.cs</c>. Court-circuité par un envoi anticipé pour un
    /// événement <c>Immediate</c> (purge de journal, création de compte admin).</summary>
    public int SuspiciousEventUploadIntervalMinutes { get; set; } = 3;

    /// <summary>Plafond du buffer EN MÉMOIRE (`Channel&lt;SuspiciousEventRecord&gt;`) — au-delà,
    /// débordement vers le fichier JSON-lines disque (voir <c>Detection/SuspiciousEventBuffer.cs</c>).</summary>
    public int SuspiciousEventMaxInMemoryBuffer { get; set; } = 1000;

    /// <summary>Âge maximum d'une entrée du buffer DISQUE avant purge — un pont de coupure
    /// réseau, PAS une source de vérité d'historique (voir le plan, "Risques à assumer").</summary>
    public int SuspiciousEventMaxDiskBufferAgeHours { get; set; } = 48;

    /// <summary>Taille maximale d'un lot posté à `POST /agents/{id}/suspicious-events` par appel.</summary>
    public int SuspiciousEventBatchMaxSize { get; set; } = 200;

    // --- Mises à jour Windows (jalon "Mises à jour Vanitas", 2026-09-17) --------------------

    /// <summary>Cadence de <c>Communication/PatchLoop.cs</c> — boucle DÉDIÉE, séparée de
    /// <see cref="ComplianceCheckIntervalHours"/> (même raisonnement que la séparation
    /// <c>CommandPoller</c>/<c>Worker</c> au jalon 4) : plus fréquente qu'un cycle de conformité
    /// classique, pour qu'une fenêtre de redémarrage de quelques heures ait une vraie chance
    /// d'être détectée pendant qu'elle est ouverte plutôt qu'un jour plus tard.</summary>
    public int PatchCheckIntervalMinutes { get; set; } = 15;

    /// <summary>Délai laissé à l'utilisateur avant l'exécution réelle de <c>shutdown.exe /r</c>
    /// (fenêtre atteinte OU délai de grâce dépassé) — jamais 0, même en délai de grâce dépassé :
    /// laisse le temps à un travail non sauvegardé d'être fermé, cohérent avec le message que
    /// Windows affiche pendant ce délai.</summary>
    public int PatchRebootDelaySeconds { get; set; } = 60;
}
