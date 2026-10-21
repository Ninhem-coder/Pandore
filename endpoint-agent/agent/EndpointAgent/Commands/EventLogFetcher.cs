using System.Diagnostics.Eventing.Reader;
using System.Text.Json;

namespace EndpointAgent.Commands;

/// <summary>
/// "Journal d'événements Windows à la demande" (2026-09-16) — recherche PONCTUELLE, paramétrée
/// par l'utilisateur depuis le dashboard (canaux, période, ID inclus/exclus, niveaux), à
/// distinguer nettement du pipeline "Activités suspectes" (<c>Detection/</c>) qui filtre en
/// CONTINU et ne remonte jamais qu'un événement déjà matché par une règle locale. Ici, c'est
/// l'inverse : l'utilisateur choisit sa requête, l'agent l'exécute une fois et renvoie ce qu'il
/// trouve — jamais de règle, jamais de mémoire d'un cycle à l'autre.
///
/// SYNCHRONE comme "system_diagnostic"/"hardware_inventory" (voir CommandExecutor) : une
/// recherche a une durée bornée par le plafond d'événements, pas besoin de découpler la commande
/// de son résultat comme "start_shell_session"/"compliance_check".
/// </summary>
public static class EventLogFetcher
{
    private sealed record QueryDto(
        List<string> channels,
        string since,
        string until,
        List<int>? event_ids_include,
        List<int>? event_ids_exclude,
        List<string>? levels,
        long? after_record_id,
        int? max_events
    );

    // Longueur de troncature défensive — un providers verbeux (ex. un 4688 avec une longue
    // ligne de commande) ne doit jamais, à lui seul, faire gonfler le résultat au point de
    // menacer la colonne `AgentCommand.result` (leçon déjà tirée sur `hardware_inventory`,
    // voir le commentaire de cette colonne dans models.py côté serveur).
    private const int DescriptionMaxLength = 2000;
    private const int XmlMaxLength = 4000;

    public static (bool Success, string? Result, bool RequestStop, Action? PostReportAction) Fetch(string? parametersJson)
    {
        if (string.IsNullOrWhiteSpace(parametersJson))
        {
            return (false, "Paramètres de recherche manquants.", false, null);
        }

        QueryDto? query;
        try
        {
            query = JsonSerializer.Deserialize<QueryDto>(parametersJson);
        }
        catch (JsonException ex)
        {
            return (false, $"Paramètres de recherche invalides : {ex.Message}", false, null);
        }
        if (query is null || query.channels.Count == 0)
        {
            return (false, "Au moins un canal doit être sélectionné.", false, null);
        }

        // Le curseur RecordId n'a de sens QUE pour un seul canal à la fois — chaque canal
        // Windows a sa propre séquence de RecordId indépendante, l'appliquer identiquement à
        // plusieurs canaux mélangerait des repères sans rapport (voir le plan de ce jalon).
        // Avec plusieurs canaux, le plafond est simplement réparti entre eux et la pagination
        // ("voir la suite") reste désactivée côté frontend — comportement assumé, pas un bug.
        var maxEvents = Math.Clamp(query.max_events ?? 2000, 1, 2000);
        var perChannelCap = query.channels.Count == 1 ? maxEvents : Math.Max(1, maxEvents / query.channels.Count);

        var xpath = BuildXPath(query);
        var results = new List<object>();
        var anyTruncated = false;
        long? nextAfterRecordId = null;

        foreach (var channel in query.channels)
        {
            EventLogReader reader;
            try
            {
                var q = new EventLogQuery(channel, PathType.LogName, xpath);
                reader = new EventLogReader(q);
            }
            catch (EventLogNotFoundException)
            {
                // Canal absent sur ce poste (ex. "ForwardedEvents" jamais configuré) — ignoré
                // silencieusement, ce n'est pas une erreur de recherche.
                continue;
            }
            catch (EventLogInvalidDataException ex)
            {
                return (false, $"Requête invalide sur le canal {channel} : {ex.Message}", false, null);
            }

            using (reader)
            {
                var countThisChannel = 0;
                EventRecord? record;
                while (countThisChannel < perChannelCap && (record = reader.ReadEvent()) is not null)
                {
                    using (record)
                    {
                        results.Add(ToPayload(record, channel));
                        countThisChannel++;
                        if (query.channels.Count == 1)
                        {
                            nextAfterRecordId = record.RecordId;
                        }
                    }
                }
                // Un événement de plus existait-il après notre plafond ? `ReadEvent()` une fois
                // de plus nous le dit sans avoir à sur-lire un lot entier supplémentaire.
                if (countThisChannel >= perChannelCap)
                {
                    using var probe = reader.ReadEvent();
                    if (probe is not null) anyTruncated = true;
                }
            }
        }

        var payload = new
        {
            events = results,
            returned = results.Count,
            has_more = anyTruncated,
            next_after_record_id = query.channels.Count == 1 && anyTruncated ? nextAfterRecordId : null,
        };
        return (true, JsonSerializer.Serialize(payload), false, null);
    }

    /// <summary>Construit la requête XPath — période + ID inclus/exclus + curseur RecordId +
    /// niveaux, tous optionnels sauf la période. Les valeurs de niveau/mot-clé viennent des
    /// énumérations documentées <see cref="StandardEventLevel"/>/<see cref="StandardEventKeywords"/>
    /// plutôt que d'une constante hexadécimale devinée à la main.</summary>
    private static string BuildXPath(QueryDto query)
    {
        // Comparaisons `>=`/`<=` littérales : cette chaîne est interprétée directement comme
        // une expression XPath 1.0 par le moteur EvtQuery, jamais réanalysée comme du XML — pas
        // d'échappement d'entité nécessaire, contrairement à un `<QueryList>` structuré.
        var conditions = new List<string>
        {
            $"TimeCreated[@SystemTime>='{query.since}' and @SystemTime<='{query.until}']",
        };

        if (query.event_ids_include is { Count: > 0 })
        {
            conditions.Add("(" + string.Join(" or ", query.event_ids_include.Select(id => $"EventID={id}")) + ")");
        }
        if (query.event_ids_exclude is { Count: > 0 })
        {
            conditions.AddRange(query.event_ids_exclude.Select(id => $"EventID!={id}"));
        }
        if (query.after_record_id is { } cursor)
        {
            conditions.Add($"EventRecordID>{cursor}");
        }
        if (query.levels is { Count: > 0 } levels)
        {
            var levelConds = new List<string>();
            var successVal = (long)StandardEventKeywords.AuditSuccess;
            var failureVal = (long)StandardEventKeywords.AuditFailure;
            if (levels.Contains("audit_success")) levelConds.Add($"band(Keywords,{successVal})");
            if (levels.Contains("audit_failure")) levelConds.Add($"band(Keywords,{failureVal})");
            if (levels.Contains("critical")) levelConds.Add($"Level={(int)StandardEventLevel.Critical}");
            if (levels.Contains("error")) levelConds.Add($"Level={(int)StandardEventLevel.Error}");
            if (levels.Contains("warning")) levelConds.Add($"Level={(int)StandardEventLevel.Warning}");
            if (levels.Contains("information")) levelConds.Add($"Level={(int)StandardEventLevel.Informational}");
            if (levelConds.Count > 0)
            {
                conditions.Add("(" + string.Join(" or ", levelConds) + ")");
            }
        }

        return $"*[System[{string.Join(" and ", conditions)}]]";
    }

    private static string ClassifyLevel(EventRecord record)
    {
        if (record.Keywords is { } kw)
        {
            if ((kw & (long)StandardEventKeywords.AuditFailure) != 0) return "audit_failure";
            if ((kw & (long)StandardEventKeywords.AuditSuccess) != 0) return "audit_success";
        }
        return record.Level switch
        {
            (byte)StandardEventLevel.Critical => "critical",
            (byte)StandardEventLevel.Error => "error",
            (byte)StandardEventLevel.Warning => "warning",
            (byte)StandardEventLevel.Verbose => "verbose",
            _ => "information",
        };
    }

    private static object ToPayload(EventRecord record, string channel)
    {
        string description;
        try
        {
            description = record.FormatDescription() ?? "(pas de description disponible pour ce fournisseur)";
        }
        catch (EventLogException)
        {
            // Provider dont le fichier de message n'est plus résolvable sur ce poste (déjà
            // désinstallé, DLL manquante...) — pas une erreur de recherche, juste une
            // description indisponible pour CET événement précis.
            description = "(description indisponible — fournisseur non résolu sur ce poste)";
        }
        if (description.Length > DescriptionMaxLength)
        {
            description = description[..DescriptionMaxLength] + "…";
        }

        string xml;
        try
        {
            xml = record.ToXml();
        }
        catch (EventLogException)
        {
            xml = "";
        }
        if (xml.Length > XmlMaxLength)
        {
            xml = xml[..XmlMaxLength] + "…";
        }

        return new
        {
            record_id = record.RecordId ?? 0,
            time = record.TimeCreated?.ToUniversalTime().ToString("o") ?? "",
            level = ClassifyLevel(record),
            event_id = record.Id,
            provider = record.ProviderName ?? "",
            task_category = record.TaskDisplayName,
            channel,
            description,
            xml,
        };
    }
}
