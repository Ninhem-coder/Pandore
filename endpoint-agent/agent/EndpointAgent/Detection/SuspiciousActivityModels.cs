using System.Globalization;

namespace EndpointAgent.Detection;

/// <summary>
/// Modèles du nouveau jalon "détection d'activités suspectes" (2026-09-14). Deux familles de
/// types dans ce fichier, à ne pas confondre :
/// <list type="bullet">
/// <item>Les DTO de règles (<see cref="SuspiciousRulesDto"/> et ses sous-objets) — désérialisés
/// TELS QUELS depuis `GET /agents/{id}/suspicious-rules` (contrat serveur figé, noms de champs
/// en camelCase EXACTS, voir le plan — pas de policy de casse, même convention que les DTO
/// snake_case déjà en place dans <c>Communication/ServerClient.cs</c> : le nom du champ C#
/// correspond caractère pour caractère au JSON plutôt que de compter sur une résolution
/// insensible à la casse).</item>
/// <item><see cref="SuspiciousEventRecord"/> — le modèle INTERNE d'un événement déjà détecté
/// (propriétés PascalCase classiques, c'est un type de travail agent-only, jamais désérialisé
/// depuis le serveur) et <see cref="SuspiciousEventDto"/>, sa projection en JSON pour
/// `POST /agents/{id}/suspicious-events` (là aussi noms de champs EXACTS du contrat, snake_case).</item>
/// </list>
/// </summary>
public sealed record LolbinRuleDto(string name, List<string> suspiciousArgs);

public sealed record ProcessRulesDto(
    List<string> suspiciousPaths,
    List<LolbinRuleDto> lolbins,
    List<string> securityServiceNames,
    List<string> persistenceCommands);

public sealed record EventLogRulesDto(
    string rdpNormalHoursStart,
    string rdpNormalHoursEnd,
    int authFailureThreshold,
    int authFailureWindowMinutes);

public sealed record NetworkRulesDto(
    List<int> allowedPorts,
    List<int> blockedPorts,
    bool allowPrivateRanges);

public sealed record UsbRulesDto(
    int fileCopyDebounceSeconds,
    int fileCopyAggregateThreshold);

/// <summary>Racine du catalogue de règles servi par `GET /agents/{id}/suspicious-rules` — mis en
/// cache localement par <see cref="SuspiciousRulesProvider"/> (voir ce fichier pour le
/// fetch+cache+durcissement de répertoire, calqué sur <c>Compliance/ComplianceRunner.cs</c>).</summary>
public sealed record SuspiciousRulesDto(
    ProcessRulesDto process,
    EventLogRulesDto eventLog,
    NetworkRulesDto network,
    UsbRulesDto usb);

/// <summary>
/// Un événement suspect déjà détecté et qualifié par <see cref="SuspiciousActivityRuleEngine"/> —
/// modèle de travail interne à l'agent (buffer mémoire, débordement disque JSON-lines, upload).
/// <paramref name="LocalEventId"/> est un GUID généré UNE SEULE FOIS à la création de ce record
/// (voir <c>SuspiciousActivityRuleEngine.BuildRecord</c>) — c'est LUI qui porte l'idempotence
/// côté serveur (contrainte unique `(agent_id, local_event_id)`), pas un identifiant recalculé à
/// chaque tentative d'upload : un même événement rejoué après un timeout réseau garde le même
/// GUID du début à la fin de son cycle de vie dans le buffer.
/// </summary>
public sealed record SuspiciousEventRecord(
    string LocalEventId,
    DateTime OccurredAtUtc,
    string SignalType,
    string Severity,
    string MatchedRule,
    string Summary,
    Dictionary<string, object?> Detail,
    bool Immediate = false);

/// <summary>Projection JSON de <see cref="SuspiciousEventRecord"/> pour
/// `POST /agents/{id}/suspicious-events` — noms de champs EXACTS du contrat serveur (snake_case),
/// voir <see cref="SuspiciousEventRecordExtensions.ToDto"/>.</summary>
public sealed record SuspiciousEventDto(
    string local_event_id,
    string occurred_at,
    string signal_type,
    string severity,
    string matched_rule,
    string summary,
    Dictionary<string, object?> detail);

public static class SuspiciousEventRecordExtensions
{
    /// <summary>Format "yyyy-MM-ddTHH:mm:ssZ" — le contrat attend de l'UTC explicite (suffixe
    /// "Z"), jamais un décalage local ni le format "O" par défaut de .NET (qui inclurait des
    /// fractions de seconde et un "Z" seulement si `DateTimeKind.Utc`, une dépendance implicite
    /// plus fragile qu'un format explicite ici).</summary>
    public static SuspiciousEventDto ToDto(this SuspiciousEventRecord record) => new(
        local_event_id: record.LocalEventId,
        occurred_at: DateTime.SpecifyKind(record.OccurredAtUtc, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
        signal_type: record.SignalType,
        severity: record.Severity,
        matched_rule: record.MatchedRule,
        summary: record.Summary,
        detail: record.Detail);
}
