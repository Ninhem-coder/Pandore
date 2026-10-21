using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Xml.Linq;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Un seul <see cref="EventLogWatcher"/> sur le canal `Security` (nouveau jalon, 2026-09-14) —
/// couvre à la fois le signal "processus suspects" (4688) et le signal "journal d'événements"
/// (4720+4732 compte admin, 4624 LogonType=10 RDP, 4625 échec d'authentification, 1102 purge de
/// journal), voir le plan §1 : "Un seul watcher pour les deux premiers signaux (même canal
/// Security)". Souscription native poussée (zéro polling), aucune dépendance neuve.
///
/// `ExecuteAsync` s'abonne puis retourne IMMÉDIATEMENT (pas de boucle bloquante) — la
/// souscription reste vivante tant que ce `BackgroundService` existe (référence conservée dans
/// `_watcher`), la désinscription/`Dispose` a lieu via `stoppingToken.Register`, appelé par le
/// host au moment de `StopAsync`.
/// </summary>
public sealed class ProcessAndEventLogWatcher : BackgroundService
{
    // Combine les 5 EventID "simples" avec le filtre LogonType=10 pour 4624 (RDP), qui a besoin
    // d'inspecter EventData plutôt que le seul System/EventID — évite de faire remonter TOUTES
    // les connexions locales/réseau (LogonType 2/3/etc.), hors scope de ce signal précis.
    private const string XPathQuery =
        "*[System[(EventID=4688 or EventID=4720 or EventID=4732 or EventID=4625 or EventID=1102)]] " +
        "or (*[System[EventID=4624]] and *[EventData[Data[@Name='LogonType']='10']])";

    // Fenêtre de tolérance pour corréler 4720 (création de compte) → 4732 (ajout au groupe
    // Administrateurs) — en pratique quasi simultanés, mais rien ne garantit un délai nul selon
    // la charge de l'audit Windows.
    private static readonly TimeSpan AdminCorrelationWindow = TimeSpan.FromMinutes(5);

    private readonly ILogger<ProcessAndEventLogWatcher> _logger;
    private readonly AgentConfig _config;
    private readonly SuspiciousRulesProvider _rulesProvider;
    private readonly SuspiciousEventBuffer _buffer;
    private readonly ProcessNameCache _processNameCache;

    private readonly object _authFailureLock = new();
    private readonly Dictionary<string, List<DateTime>> _authFailuresByAccount = new(StringComparer.OrdinalIgnoreCase);

    // Corrélation 4720→4732 par SID (TargetSid / MemberSid) — jamais par nom de compte : le
    // format exact du champ `MemberName` d'un 4732 n'est pas garanti (SID brut vs nom résolu
    // selon le contexte), alors que TargetSid (4720) et MemberSid (4732) désignent tous les deux,
    // sans ambiguïté, le SID du compte concerné.
    private readonly object _pendingAccountsLock = new();
    private readonly Dictionary<string, (string UserName, DateTime CreatedAtUtc)> _recentlyCreatedAccountsBySid = new(StringComparer.OrdinalIgnoreCase);

    private EventLogWatcher? _watcher;

    public ProcessAndEventLogWatcher(
        ILogger<ProcessAndEventLogWatcher> logger,
        IOptions<AgentConfig> config,
        SuspiciousRulesProvider rulesProvider,
        SuspiciousEventBuffer buffer,
        ProcessNameCache processNameCache)
    {
        _logger = logger;
        _config = config.Value;
        _rulesProvider = rulesProvider;
        _buffer = buffer;
        _processNameCache = processNameCache;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, XPathQuery);
            _watcher = new EventLogWatcher(query);
            _watcher.EventRecordWritten += OnEventRecordWritten;
            _watcher.Enabled = true;
            _logger.LogInformation("Surveillance du journal Security démarrée (processus, comptes, RDP, échecs d'authentification, purge de journal).");
        }
        catch (Exception ex)
        {
            // Ne fait JAMAIS planter l'agent — un canal Security inaccessible (droits, GPO,
            // service Eventlog arrêté) désactive juste ce signal, pas tout l'agent.
            _logger.LogError(ex, "Échec du démarrage de la surveillance du journal Security — signaux processus/journal désactivés.");
        }

        stoppingToken.Register(() =>
        {
            try
            {
                if (_watcher is not null)
                {
                    _watcher.Enabled = false;
                    _watcher.EventRecordWritten -= OnEventRecordWritten;
                    _watcher.Dispose();
                }
            }
            catch
            {
                // Arrêt du service — sans conséquence.
            }
        });

        return Task.CompletedTask;
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        // Callback sur un thread dédié à l'EventLogWatcher, jamais le thread de ExecuteAsync.
        // Try/catch large : une exception ici ferait taire le watcher pour de bon (comportement
        // documenté d'EventLogWatcher), pas seulement l'événement en cours.
        try
        {
            using var record = e.EventRecord;
            if (record is null) return;
            HandleEventRecord(record);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Échec du traitement d'un événement du journal Security.");
        }
    }

    private void HandleEventRecord(EventRecord record)
    {
        var occurredAtUtc = (record.TimeCreated ?? DateTime.UtcNow).ToUniversalTime();
        // 🔧 Audit de perf du 2026-09-16 : un seul `ToXml()`/parse par événement, réutilisé par
        // TOUS les champs demandés ci-dessous — avant ce correctif, `GetEventDataValue`
        // reparsait le XML complet À CHAQUE NOM DE CHAMP (2 à 3 fois par événement selon le
        // type, ex. `HandleProcessCreation` l'appelait 4 fois), sur l'événement de LOIN le plus
        // fréquent du canal Security (4688, un par lancement de process sur tout le poste).
        var data = GetEventData(record);

        switch (record.Id)
        {
            case 4688 when _config.ProcessDetectionEnabled:
                HandleProcessCreation(data, occurredAtUtc);
                break;
            case 4720 when _config.EventLogDetectionEnabled:
                HandleAccountCreated(data, occurredAtUtc);
                break;
            case 4732 when _config.EventLogDetectionEnabled:
                HandleGroupMembershipAdded(data, occurredAtUtc);
                break;
            case 4624 when _config.EventLogDetectionEnabled:
                HandleRdpLogon(data, occurredAtUtc);
                break;
            case 4625 when _config.EventLogDetectionEnabled:
                HandleAuthFailure(data, occurredAtUtc);
                break;
            case 1102 when _config.EventLogDetectionEnabled:
                HandleLogCleared(data, occurredAtUtc);
                break;
        }
    }

    private void HandleProcessCreation(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        var newProcessName = data.GetValueOrDefault("NewProcessName");
        var commandLine = data.GetValueOrDefault("CommandLine");
        var parentProcessName = data.GetValueOrDefault("ParentProcessName");

        var hasPid = TryParseHexProcessId(data.GetValueOrDefault("NewProcessId"), out var pid);
        if (hasPid && !string.IsNullOrEmpty(newProcessName))
        {
            _processNameCache.Record(pid, SafeGetFileName(newProcessName));
        }

        var rules = _rulesProvider.Current?.process;
        if (rules is null) return; // pas encore de règles disponibles (démarrage / serveur injoignable)

        var evt = SuspiciousActivityRuleEngine.EvaluateProcessCreation(newProcessName, commandLine, parentProcessName, hasPid ? pid : null, occurredAtUtc, rules);
        if (evt is not null)
        {
            _buffer.Enqueue(evt);
        }
    }

    private void HandleAccountCreated(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        var targetUserName = data.GetValueOrDefault("TargetUserName");
        var targetSid = data.GetValueOrDefault("TargetSid");
        if (string.IsNullOrEmpty(targetSid) || string.IsNullOrEmpty(targetUserName)) return;

        lock (_pendingAccountsLock)
        {
            _recentlyCreatedAccountsBySid[targetSid] = (targetUserName, occurredAtUtc);
            PruneExpiredAccounts(occurredAtUtc);
        }
    }

    private void HandleGroupMembershipAdded(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        // Pour un 4732, `TargetUserName` désigne le GROUPE modifié (pas le compte ajouté) —
        // c'est `MemberSid` qui identifie le compte, voir le commentaire sur
        // `_recentlyCreatedAccountsBySid`.
        var groupName = data.GetValueOrDefault("TargetUserName");
        var memberSid = data.GetValueOrDefault("MemberSid");
        var subjectUserName = data.GetValueOrDefault("SubjectUserName");

        if (groupName is null || !IsAdministratorsGroup(groupName) || string.IsNullOrEmpty(memberSid)) return;

        string? memberUserName;
        lock (_pendingAccountsLock)
        {
            PruneExpiredAccounts(occurredAtUtc);
            if (!_recentlyCreatedAccountsBySid.TryGetValue(memberSid, out var pending))
            {
                // Ajout au groupe Administrateurs d'un compte PAS créé récemment par ce poste
                // (compte préexistant, ou compte de domaine) — hors scope de cette règle précise
                // ("4720+4732" du plan), pas un faux négatif silencieux : un ajout isolé au
                // groupe Administrateurs sans création de compte associée reste un signal
                // légitime d'administration courante, pas nécessairement suspect en lui-même.
                return;
            }
            memberUserName = pending.UserName;
            _recentlyCreatedAccountsBySid.Remove(memberSid);
        }

        var evt = SuspiciousActivityRuleEngine.EvaluateAdminAccountCreated(memberUserName, subjectUserName, occurredAtUtc);
        _buffer.Enqueue(evt);
    }

    // Le nom INTERNE (SAM) du groupe BUILTIN "Administrators" n'est normalement PAS localisé
    // (seul son libellé d'AFFICHAGE dans l'UI l'est) — les deux graphies sont acceptées par
    // prudence plutôt que de supposer laquelle apparaît réellement dans un 4732 sur un poste FR,
    // non vérifié sur un vrai poste à ce stade (à confirmer en vérification finale, voir le plan §2).
    private static bool IsAdministratorsGroup(string groupName) =>
        string.Equals(groupName, "Administrators", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(groupName, "Administrateurs", StringComparison.OrdinalIgnoreCase);

    private void HandleRdpLogon(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        var targetUserName = data.GetValueOrDefault("TargetUserName");
        var sourceAddress = data.GetValueOrDefault("IpAddress");
        if (string.IsNullOrEmpty(targetUserName)) return;

        var rules = _rulesProvider.Current?.eventLog;
        if (rules is null) return;

        var evt = SuspiciousActivityRuleEngine.EvaluateRdpLogon(targetUserName, sourceAddress, occurredAtUtc, rules);
        if (evt is not null)
        {
            _buffer.Enqueue(evt);
        }
    }

    private void HandleAuthFailure(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        var targetUserName = data.GetValueOrDefault("TargetUserName");
        if (string.IsNullOrEmpty(targetUserName)) return;

        var rules = _rulesProvider.Current?.eventLog;
        if (rules is null) return;

        var windowMinutes = Math.Max(1, rules.authFailureWindowMinutes);
        int countInWindow;
        lock (_authFailureLock)
        {
            if (!_authFailuresByAccount.TryGetValue(targetUserName, out var timestamps))
            {
                timestamps = new List<DateTime>();
                _authFailuresByAccount[targetUserName] = timestamps;
            }
            timestamps.Add(occurredAtUtc);
            var cutoff = occurredAtUtc - TimeSpan.FromMinutes(windowMinutes);
            timestamps.RemoveAll(t => t < cutoff);
            countInWindow = timestamps.Count;

            // Une fois le seuil dépassé et l'événement émis, le compteur est remis à zéro pour
            // éviter de RÉ-ÉMETTRE un événement à chaque échec suivant tant que la fenêtre
            // glissante reste au-dessus du seuil (bruit) — un nouveau franchissement du seuil
            // redéclenchera une alerte fraîche.
            if (countInWindow >= Math.Max(1, rules.authFailureThreshold))
            {
                timestamps.Clear();
            }

            // 🔧 Audit de perf du 2026-09-16 (mineur) : sans ce retrait, la CLÉ (nom de compte)
            // restait indéfiniment dans le dictionnaire même une fois sa liste vidée — croissance
            // non bornée sur la durée de vie de l'agent (un compte qui échoue une seule fois hors
            // fenêtre, ou qui vient de déclencher le seuil ci-dessus, y restait pour toujours).
            if (timestamps.Count == 0)
            {
                _authFailuresByAccount.Remove(targetUserName);
            }
        }

        var evt = SuspiciousActivityRuleEngine.EvaluateAuthFailureThreshold(targetUserName, countInWindow, occurredAtUtc, rules);
        if (evt is not null)
        {
            _buffer.Enqueue(evt);
        }
    }

    private void HandleLogCleared(IReadOnlyDictionary<string, string> data, DateTime occurredAtUtc)
    {
        var subjectUserName = data.GetValueOrDefault("SubjectUserName");
        var evt = SuspiciousActivityRuleEngine.EvaluateLogCleared(subjectUserName, occurredAtUtc);
        _buffer.Enqueue(evt);
    }

    private void PruneExpiredAccounts(DateTime nowUtc)
    {
        var expired = _recentlyCreatedAccountsBySid
            .Where(kv => nowUtc - kv.Value.CreatedAtUtc > AdminCorrelationWindow)
            .Select(kv => kv.Key)
            .ToList();
        foreach (var key in expired)
        {
            _recentlyCreatedAccountsBySid.Remove(key);
        }
    }

    private static string? SafeGetFileName(string path)
    {
        try
        {
            return Path.GetFileName(path);
        }
        catch
        {
            return path;
        }
    }

    /// <summary>`NewProcessId` sur un 4688 est rapporté en HEXADÉCIMAL préfixé "0x..." par le
    /// fournisseur d'audit Windows (contrairement à la plupart des autres champs numériques d'un
    /// EventRecord) — piège documenté de 4688, pas deviné : `int.Parse` seul échouerait
    /// silencieusement.</summary>
    private static bool TryParseHexProcessId(string? value, out int pid)
    {
        pid = 0;
        if (string.IsNullOrEmpty(value)) return false;
        var trimmed = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        return int.TryParse(trimmed, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out pid);
    }

    /// <summary>Extrait TOUS les champs `&lt;Data Name="..."&gt;` du XML de l'événement, en un
    /// seul passage — PAS `EventRecord.Properties` (accès par INDICE positionnel, plus rapide
    /// mais cassant au moindre changement de schéma Microsoft entre versions de Windows) : le
    /// parsing par NOM via le XML est plus robuste. 🔧 Corrigé le 2026-09-16 (audit de perf) :
    /// l'ancienne version (`GetEventDataValue`) reparsait le XML complet À CHAQUE NOM DE CHAMP
    /// demandé (2 à 4 fois par événement selon le type), sur l'événement de loin le plus fréquent
    /// du canal Security (4688) — un seul `ToXml()`/`XDocument.Parse` par événement suffit,
    /// réutilisé pour tous les champs via ce dictionnaire.</summary>
    private static IReadOnlyDictionary<string, string> GetEventData(EventRecord record)
    {
        try
        {
            var xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var el in doc.Descendants(ns + "Data"))
            {
                var name = (string?)el.Attribute("Name");
                if (name is not null && !result.ContainsKey(name))
                {
                    result[name] = el.Value;
                }
            }
            return result;
        }
        catch
        {
            return new Dictionary<string, string>();
        }
    }
}
