using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace EndpointAgent.Detection;

/// <summary>
/// Moteur de règles LOCAL pour la détection d'activités suspectes (nouveau jalon, 2026-09-14) —
/// reçoit le DTO de règles servi par le serveur (voir <see cref="SuspiciousRulesProvider"/>),
/// applique le mapping de sévérité tranché avec Nicolas (voir le plan §1) et retourne un
/// <see cref="SuspiciousEventRecord"/> prêt à être enfilé, ou `null` si rien ne matche.
///
/// Volontairement SANS AUCUNE dépendance Windows (pas de WMI / EventLogWatcher / P-Invoke ici) —
/// toute la mécanique de collecte vit dans les watchers de ce même dossier
/// (<c>ProcessAndEventLogWatcher</c>, <c>NetworkConnectionPoller</c>, <c>UsbActivityWatcher</c>),
/// qui appellent ces méthodes avec des types primitifs déjà extraits (le comptage stateful —
/// fenêtre glissante d'échecs d'authentification, agrégation de copies de fichiers — reste côté
/// watcher, cette classe ne fait qu'ÉVALUER un compte déjà calculé). C'est ce qui rend le moteur
/// testable sans machine Windows réelle, voir EndpointAgent.Tests.
///
/// ⚠️ Vocabulaire de sévérité : le contrat serveur n'a QUE "low"/"med"/"high" — jamais "medium"
/// (voir <see cref="SeverityMed"/>).
/// </summary>
public static class SuspiciousActivityRuleEngine
{
    public const string SeverityLow = "low";
    public const string SeverityMed = "med";
    public const string SeverityHigh = "high";

    public const string SignalProcess = "process";
    public const string SignalEventLog = "event_log";
    public const string SignalNetwork = "network";
    public const string SignalUsb = "usb";

    // ---------------------------------------------------------------------------------------
    // Processus (4688)
    // ---------------------------------------------------------------------------------------

    /// <summary>Un seul événement 4688 peut en théorie matcher plusieurs règles (ex. "sc.exe
    /// stop WinDefend" est à la fois une commande visant un service de sécurité ET, plus
    /// largement, une commande "sc.exe" — voir <see cref="ProcessRulesDto.persistenceCommands"/>
    /// qui contient "sc.exe create", pas "sc.exe stop", donc pas de collision réelle avec le jeu
    /// de règles par défaut, mais rien ne garantit qu'un jeu de règles personnalisé n'en crée
    /// pas) — priorité à la règle la PLUS sévère plutôt que de générer plusieurs événements pour
    /// la même création de processus : LOLBin (high) > arrêt de service de sécurité (high) >
    /// persistance (med) > chemin suspect (low). Un seul événement est retourné, jamais
    /// plusieurs.</summary>
    public static SuspiciousEventRecord? EvaluateProcessCreation(
        string? newProcessName, string? commandLine, string? parentProcessName, int? pid, DateTime occurredAtUtc, ProcessRulesDto rules)
    {
        var processBaseName = GetProcessBaseName(newProcessName);
        var line = commandLine ?? string.Empty;
        var detail = DetailFor(newProcessName, commandLine, parentProcessName, pid);

        if (processBaseName is not null)
        {
            var lolbinMatch = MatchLolbin(processBaseName, line, rules.lolbins);
            if (lolbinMatch is not null)
            {
                return BuildRecord(SignalProcess, SeverityHigh, lolbinMatch.Value.MatchedRule, lolbinMatch.Value.Summary, occurredAtUtc, detail);
            }
        }

        if (MatchesAny(line, rules.securityServiceNames, out var serviceName) && LooksLikeServiceStopCommand(line))
        {
            return BuildRecord(
                SignalProcess, SeverityHigh, $"process-security-service-stop-{Slugify(serviceName!)}",
                $"Commande d'arrêt/désactivation du service de sécurité \"{serviceName}\" détectée : {line}",
                occurredAtUtc, detail);
        }

        if (MatchesAny(line, rules.persistenceCommands, out var persistenceCommand))
        {
            return BuildRecord(
                SignalProcess, SeverityMed, $"process-persistence-{Slugify(persistenceCommand!)}",
                $"Commande de persistance détectée : {line}",
                occurredAtUtc, detail);
        }

        if (MatchesSuspiciousPath(newProcessName, rules.suspiciousPaths))
        {
            return BuildRecord(
                SignalProcess, SeverityLow, "process-suspicious-path",
                $"Exécution depuis un chemin suspect : {newProcessName}",
                occurredAtUtc, detail);
        }

        return null;
    }

    private static string? GetProcessBaseName(string? processPath)
    {
        if (string.IsNullOrWhiteSpace(processPath)) return null;
        try
        {
            return Path.GetFileName(processPath);
        }
        catch
        {
            return processPath;
        }
    }

    /// <summary>Retourne le matched_rule + résumé pour le PREMIER LOLBin/argument matché.
    /// Contrat par défaut : une liste `suspiciousArgs` VIDE signifie que le binaire est sensible
    /// en lui-même (ex. `mshta.exe`) — toute invocation est suspecte, indépendamment des
    /// arguments passés. Interprétation nécessaire non explicitée noir sur blanc dans le contrat
    /// (qui décrit "LOLBin avec argument suspect matché"), mais c'est la seule lecture cohérente
    /// avec `{"name": "mshta.exe", "suspiciousArgs": []}` dans le jeu de règles par défaut —
    /// documenté au rapport final.</summary>
    private static (string MatchedRule, string Summary)? MatchLolbin(string processBaseName, string commandLine, IReadOnlyList<LolbinRuleDto>? lolbins)
    {
        if (lolbins is null) return null;
        foreach (var lolbin in lolbins)
        {
            if (lolbin is null || !string.Equals(lolbin.name, processBaseName, StringComparison.OrdinalIgnoreCase)) continue;

            var baseSlug = Slugify(StripExeSuffix(processBaseName));

            if (lolbin.suspiciousArgs is null || lolbin.suspiciousArgs.Count == 0)
            {
                return ($"process-lolbin-{baseSlug}", $"{processBaseName} invoqué (LOLBin sensible).");
            }

            foreach (var arg in lolbin.suspiciousArgs)
            {
                if (!string.IsNullOrEmpty(arg) && commandLine.Contains(arg, StringComparison.OrdinalIgnoreCase))
                {
                    return ($"process-lolbin-{baseSlug}-{Slugify(arg)}", $"{processBaseName} invoqué avec l'argument suspect \"{arg}\".");
                }
            }
        }
        return null;
    }

    private static bool MatchesAny(string commandLine, IReadOnlyList<string>? candidates, out string? matched)
    {
        matched = null;
        if (candidates is null) return false;
        foreach (var candidate in candidates)
        {
            if (!string.IsNullOrEmpty(candidate) && commandLine.Contains(candidate, StringComparison.OrdinalIgnoreCase))
            {
                matched = candidate;
                return true;
            }
        }
        return false;
    }

    private static readonly string[] ServiceStopVerbs = { "stop", "disable", "start= disabled", "start=disabled" };

    /// <summary>Il n'existe PAS d'événement natif "service arrêté" dans notre surveillance
    /// (canal Security uniquement, pas le canal System où vit 7036/7040) — l'arrêt d'un service
    /// de sécurité est donc détecté INDIRECTEMENT via la commande qui le provoque
    /// (`sc.exe stop WinDefend`, `net stop WinDefend`, `Stop-Service WinDefend`...), vue en 4688.
    /// Heuristique simple : le nom du service apparaît dans la ligne de commande ET la ligne
    /// contient un verbe d'arrêt/désactivation connu.</summary>
    private static bool LooksLikeServiceStopCommand(string commandLine) =>
        ServiceStopVerbs.Any(v => commandLine.Contains(v, StringComparison.OrdinalIgnoreCase));

    /// <summary>Traduit un motif "%VARIABLE%" du catalogue de règles en fragment de chemin
    /// générique — PAS un `Environment.ExpandEnvironmentVariables` classique : l'agent tourne en
    /// SYSTEM, dont les variables utilisateur (%TEMP%, %APPDATA%...) ne correspondent JAMAIS au
    /// profil de l'utilisateur qui a réellement lancé le processus observé (le `NewProcessName`
    /// d'un 4688 est un chemin LITTÉRAL, ex. "C:\Users\alice\AppData\Local\Temp\x.exe"). Angle
    /// mort assumé : seules les 3 variables du contrat par défaut sont mappées ; une variable
    /// utilisateur inédite ajoutée côté serveur sans mise à jour de cette table ne matchera
    /// jamais (dégradation silencieuse plutôt qu'un plantage).</summary>
    private static readonly Dictionary<string, string> KnownUserPathFragments = new(StringComparer.OrdinalIgnoreCase)
    {
        ["%TEMP%"] = @"\AppData\Local\Temp",
        ["%TMP%"] = @"\AppData\Local\Temp",
        ["%APPDATA%"] = @"\AppData\Roaming",
        ["%LOCALAPPDATA%"] = @"\AppData\Local",
    };

    private static bool MatchesSuspiciousPath(string? newProcessName, IReadOnlyList<string>? suspiciousPaths)
    {
        if (string.IsNullOrWhiteSpace(newProcessName) || suspiciousPaths is null) return false;
        foreach (var pattern in suspiciousPaths)
        {
            if (string.IsNullOrEmpty(pattern)) continue;
            var fragment = ExpandPathPattern(pattern);
            if (fragment.Length > 0 && newProcessName.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static string ExpandPathPattern(string pattern)
    {
        foreach (var (token, fragment) in KnownUserPathFragments)
        {
            if (pattern.StartsWith(token, StringComparison.OrdinalIgnoreCase))
            {
                return fragment + pattern[token.Length..].Replace('/', '\\');
            }
        }
        // Motif déjà littéral (pas de %VARIABLE% reconnue) — utilisé tel quel.
        return pattern;
    }

    private static string StripExeSuffix(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;

    private static string Slugify(string value)
    {
        var chars = value.ToLowerInvariant().Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray();
        var slug = new string(chars);
        while (slug.Contains("--", StringComparison.Ordinal)) slug = slug.Replace("--", "-");
        return slug.Trim('-');
    }

    // `pid` (jalon "confinement", 2026-09-17) — absent jusqu'ici du détail process alors que le
    // signal réseau le porte déjà (voir NetworkDetail) : "Tuer le process" depuis une alerte a
    // besoin d'un PID exact à tenter en premier, le nom+chemin ne servant que de repli si ce PID
    // a expiré entretemps. Le 4688 le fournit déjà (NewProcessId, déjà parsé par l'appelant),
    // il ne manquait que le fil jusqu'ici.
    private static Dictionary<string, object?> DetailFor(string? processName, string? commandLine, string? parentProcessName, int? pid) => new()
    {
        ["process_name"] = processName,
        ["command_line"] = commandLine,
        ["parent_process_name"] = parentProcessName,
        ["pid"] = pid,
    };

    // ---------------------------------------------------------------------------------------
    // Journal d'événements (4720+4732, 4624 LogonType=10, 4625, 1102)
    // ---------------------------------------------------------------------------------------

    /// <summary>Corrélation 4720→4732 déjà faite côté watcher (par SID, voir
    /// <c>ProcessAndEventLogWatcher</c>) — cette méthode construit juste l'événement, toujours
    /// `high` et toujours `Immediate` (voir le plan, §Buffer local : "un événement marqué
    /// Immediate = true ... purge de journal, création de compte admin").</summary>
    public static SuspiciousEventRecord EvaluateAdminAccountCreated(
        string targetUserName, string? subjectUserName, DateTime occurredAtUtc) => BuildRecord(
            SignalEventLog, SeverityHigh, "eventlog-admin-account-created",
            subjectUserName is null
                ? $"Compte \"{targetUserName}\" ajouté au groupe Administrateurs."
                : $"Compte \"{targetUserName}\" ajouté au groupe Administrateurs (par {subjectUserName}).",
            occurredAtUtc,
            new Dictionary<string, object?> { ["target_user"] = targetUserName, ["subject_user"] = subjectUserName },
            immediate: true);

    /// <summary>Plage horaire normale = [start, end), heure LOCALE du poste (les astreintes se
    /// raisonnent en heure locale, pas en UTC). Angle mort documenté : pas de gestion d'une plage
    /// qui traverse minuit (ex. "22:00"-"06:00") en V1 — non nécessaire pour le contrat par
    /// défaut ("07:00"-"20:00"), pas rencontré comme un besoin réel à ce stade.</summary>
    public static SuspiciousEventRecord? EvaluateRdpLogon(
        string targetUserName, string? sourceAddress, DateTime occurredAtUtc, EventLogRulesDto rules)
    {
        if (!TryParseHourMinute(rules.rdpNormalHoursStart, out var start) || !TryParseHourMinute(rules.rdpNormalHoursEnd, out var end))
        {
            return null; // config serveur invalide — ne jamais planter, juste ne rien détecter
        }

        var localTimeOfDay = TimeOnly.FromDateTime(DateTime.SpecifyKind(occurredAtUtc, DateTimeKind.Utc).ToLocalTime());
        if (localTimeOfDay >= start && localTimeOfDay < end)
        {
            return null; // horaire normal
        }

        return BuildRecord(
            SignalEventLog, SeverityMed, "eventlog-rdp-outside-hours",
            $"Connexion RDP de \"{targetUserName}\" hors plage horaire normale ({rules.rdpNormalHoursStart}-{rules.rdpNormalHoursEnd}).",
            occurredAtUtc,
            new Dictionary<string, object?> { ["target_user"] = targetUserName, ["source_address"] = sourceAddress });
    }

    private static bool TryParseHourMinute(string? value, out TimeOnly result) =>
        TimeOnly.TryParseExact(value, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out result);

    /// <summary>Le comptage glissant par compte (fenêtre `authFailureWindowMinutes`) est tenu
    /// par le watcher — cette méthode ne fait qu'évaluer si le compte déjà calculé franchit
    /// `authFailureThreshold`.</summary>
    public static SuspiciousEventRecord? EvaluateAuthFailureThreshold(
        string targetUserName, int failureCountInWindow, DateTime occurredAtUtc, EventLogRulesDto rules)
    {
        if (failureCountInWindow < Math.Max(1, rules.authFailureThreshold))
        {
            return null;
        }
        return BuildRecord(
            SignalEventLog, SeverityMed, "eventlog-auth-failure-threshold",
            $"{failureCountInWindow} échecs d'authentification pour \"{targetUserName}\" en moins de {rules.authFailureWindowMinutes} min.",
            occurredAtUtc,
            new Dictionary<string, object?>
            {
                ["target_user"] = targetUserName,
                ["failure_count"] = failureCountInWindow,
                ["window_minutes"] = rules.authFailureWindowMinutes,
            });
    }

    public static SuspiciousEventRecord EvaluateLogCleared(string? subjectUserName, DateTime occurredAtUtc) => BuildRecord(
        SignalEventLog, SeverityHigh, "eventlog-log-cleared",
        subjectUserName is null ? "Purge du journal d'événements Sécurité." : $"Purge du journal d'événements Sécurité (par {subjectUserName}).",
        occurredAtUtc,
        new Dictionary<string, object?> { ["subject_user"] = subjectUserName },
        immediate: true);

    // ---------------------------------------------------------------------------------------
    // Connexions réseau sortantes
    // ---------------------------------------------------------------------------------------

    /// <summary>`allowPrivateRanges` ne s'applique QU'à la règle "port non listé" (low) — un port
    /// explicitement dans `blockedPorts` (ex. 4444, un port C2 classique) reste `high` même en
    /// interne : un poste compromis qui pivote vers un autre poste du LAN sur un port de C2
    /// connu est tout aussi suspect qu'une connexion externe.</summary>
    public static SuspiciousEventRecord? EvaluateNetworkConnection(
        string remoteAddress, int remotePort, string? processName, int processId, DateTime occurredAtUtc, NetworkRulesDto rules)
    {
        if (rules.blockedPorts is not null && rules.blockedPorts.Contains(remotePort))
        {
            return BuildRecord(
                SignalNetwork, SeverityHigh, "network-blocked-port",
                $"Connexion sortante vers un port bloqué {remotePort} ({remoteAddress}) depuis {processName ?? "processus inconnu"}.",
                occurredAtUtc, NetworkDetail(remoteAddress, remotePort, processName, processId));
        }

        if (rules.allowPrivateRanges && IsPrivateOrLoopback(remoteAddress))
        {
            return null; // trafic LAN toléré — réduit le bruit des ports non standards utilisés
                          // par des applications internes légitimes (voir le plan).
        }

        if (rules.allowedPorts is null || !rules.allowedPorts.Contains(remotePort))
        {
            return BuildRecord(
                SignalNetwork, SeverityLow, "network-unlisted-port",
                $"Connexion sortante vers un port non autorisé {remotePort} ({remoteAddress}) depuis {processName ?? "processus inconnu"}.",
                occurredAtUtc, NetworkDetail(remoteAddress, remotePort, processName, processId));
        }

        return null;
    }

    private static Dictionary<string, object?> NetworkDetail(string remoteAddress, int remotePort, string? processName, int processId) => new()
    {
        ["remote_address"] = remoteAddress,
        ["remote_port"] = remotePort,
        ["process_name"] = processName,
        ["pid"] = processId,
    };

    private static bool IsPrivateOrLoopback(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] switch
            {
                10 => true,
                172 => b[1] is >= 16 and <= 31,
                192 => b[1] == 168,
                169 => b[1] == 254, // link-local
                _ => false,
            };
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC || (b[0] == 0xFE && (b[1] & 0xC0) == 0x80); // ULA fc00::/7, link-local fe80::/10
        }
        return false;
    }

    // ---------------------------------------------------------------------------------------
    // Support amovible USB
    // ---------------------------------------------------------------------------------------

    public static SuspiciousEventRecord EvaluateUsbInsertion(string driveLetter, DateTime occurredAtUtc) => BuildRecord(
        SignalUsb, SeverityLow, "usb-device-connected",
        $"Support amovible connecté ({driveLetter}).",
        occurredAtUtc,
        new Dictionary<string, object?> { ["drive_letter"] = driveLetter });

    /// <summary>Comptage déjà agrégé par le watcher (debounce `fileCopyDebounceSeconds`) — cette
    /// méthode ne fait qu'évaluer si le compte dépasse `fileCopyAggregateThreshold`. Un seul
    /// événement par rafale, jamais un événement par fichier (voir le plan : "agréger plutôt
    /// qu'alerter fichier par fichier").</summary>
    public static SuspiciousEventRecord? EvaluateUsbFileCopyBurst(
        string driveLetter, int fileCountInWindow, DateTime occurredAtUtc, UsbRulesDto rules)
    {
        if (fileCountInWindow < Math.Max(1, rules.fileCopyAggregateThreshold))
        {
            return null;
        }
        return BuildRecord(
            SignalUsb, SeverityMed, "usb-file-copy-burst",
            $"Copie de fichiers en rafale détectée sur {driveLetter} ({fileCountInWindow} fichiers en moins de {rules.fileCopyDebounceSeconds}s).",
            occurredAtUtc,
            new Dictionary<string, object?>
            {
                ["drive_letter"] = driveLetter,
                ["file_count"] = fileCountInWindow,
                ["debounce_seconds"] = rules.fileCopyDebounceSeconds,
            });
    }

    // ---------------------------------------------------------------------------------------

    private static SuspiciousEventRecord BuildRecord(
        string signalType, string severity, string matchedRule, string summary, DateTime occurredAtUtc,
        Dictionary<string, object?> detail, bool immediate = false) => new(
            LocalEventId: Guid.NewGuid().ToString(),
            OccurredAtUtc: DateTime.SpecifyKind(occurredAtUtc, DateTimeKind.Utc),
            SignalType: signalType,
            Severity: severity,
            MatchedRule: matchedRule,
            Summary: summary,
            Detail: detail,
            Immediate: immediate);
}
