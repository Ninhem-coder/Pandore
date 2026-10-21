using System.Text.Json;
using System.Threading.Channels;
using EndpointAgent.Configuration;
using EndpointAgent.Security;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Buffer local des événements suspects détectés (nouveau jalon, 2026-09-14) — un
/// <see cref="Channel{T}"/> en mémoire borné à <see cref="AgentConfig.SuspiciousEventMaxInMemoryBuffer"/>,
/// débordement vers un fichier JSON-lines append-only sous
/// `%ProgramData%\EndpointAgent\suspicious-events\pending.jsonl` (répertoire durci via
/// <see cref="DirectoryHardening"/>, même mécanique que <c>Compliance/ComplianceRunner.cs</c>).
///
/// Contrat "ne retire du buffer qu'après un POST 2xx" (voir le plan) implémenté ainsi : un lot
/// préparé par <see cref="PrepareBatch"/> n'est JAMAIS considéré comme définitivement consommé —
/// <see cref="SuspiciousEventUploader"/> appelle explicitement soit <see cref="RemoveFromDisk"/>
/// (succès) soit <see cref="PersistUnsentBatch"/> (échec, y compris pour les entrées qui
/// venaient du canal mémoire et n'étaient donc pas encore sur disque).
///
/// Ce fichier n'est PAS une source de vérité d'historique (voir le plan, "Risques à assumer") :
/// <see cref="AgentConfig.SuspiciousEventMaxDiskBufferAgeHours"/> purge les entrées trop
/// anciennes, un pont de coupure réseau, pas un journal durable.
/// </summary>
public sealed class SuspiciousEventBuffer
{
    private readonly ILogger<SuspiciousEventBuffer> _logger;
    private readonly AgentConfig _config;
    private readonly Channel<SuspiciousEventRecord> _channel;
    private readonly SemaphoreSlim _immediateSignal = new(0, int.MaxValue);
    private static readonly object FileLock = new();

    private static readonly string DiskDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EndpointAgent", "suspicious-events");
    private static readonly string PendingFilePath = Path.Combine(DiskDirectory, "pending.jsonl");

    public SuspiciousEventBuffer(ILogger<SuspiciousEventBuffer> logger, IOptions<AgentConfig> config)
    {
        _logger = logger;
        _config = config.Value;
        _channel = Channel.CreateBounded<SuspiciousEventRecord>(
            new BoundedChannelOptions(Math.Max(1, _config.SuspiciousEventMaxInMemoryBuffer))
            {
                // `Wait` + `TryWrite` (jamais `WriteAsync`) : un canal plein doit faire échouer
                // l'écriture IMMÉDIATEMENT (voir Enqueue ci-dessous, débordement disque), jamais
                // bloquer le thread appelant — souvent un thread de callback d'EventLogWatcher /
                // ManagementEventWatcher, pas un thread qu'on peut se permettre de suspendre.
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
            });
    }

    /// <summary>Signal consommé par <see cref="SuspiciousEventUploader"/> pour un envoi anticipé
    /// (`Task.WhenAny`) — jamais un vrai canal push permanent, juste un raccourci du polling
    /// normal pour les événements marqués <see cref="SuspiciousEventRecord.Immediate"/> (purge de
    /// journal, création de compte admin — voir le plan).</summary>
    public Task WaitForImmediateSignalAsync(CancellationToken ct) => _immediateSignal.WaitAsync(ct);

    public void Enqueue(SuspiciousEventRecord record)
    {
        if (!_channel.Writer.TryWrite(record))
        {
            _logger.LogWarning("Buffer mémoire des événements suspects plein — débordement vers le disque ({Rule}).", record.MatchedRule);
            AppendToDisk(new[] { record }, deduplicate: false);
        }

        if (record.Immediate)
        {
            _immediateSignal.Release();
        }
    }

    /// <summary>Prépare un lot à uploader : d'abord les entrées débordées sur disque (les plus
    /// anciennes — un pont de coupure réseau doit être vidé en priorité), puis complète avec le
    /// canal mémoire. Rien n'est retiré DÉFINITIVEMENT ici (voir le commentaire d'en-tête).</summary>
    public List<SuspiciousEventRecord> PrepareBatch(int maxSize)
    {
        var batch = new List<SuspiciousEventRecord>(Math.Max(1, maxSize));
        batch.AddRange(ReadDiskPending(maxSize));
        while (batch.Count < maxSize && _channel.Reader.TryRead(out var fromChannel))
        {
            batch.Add(fromChannel);
        }
        return batch;
    }

    /// <summary>Purge SEULE (sans préparer de lot) les entrées disque plus vieilles que
    /// <see cref="AgentConfig.SuspiciousEventMaxDiskBufferAgeHours"/> — 🔧 audit de perf du
    /// 2026-09-16 : avant ce correctif, la purge par âge ne s'exécutait QUE via
    /// <see cref="PrepareBatch"/>, jamais appelée par <c>SuspiciousEventUploader</c> tant qu'aucun
    /// certificat agent n'est disponible (retourne avant d'appeler `PrepareBatch`, voir
    /// `UploadOnceAsync`). Un poste dont l'enrôlement échoue en boucle (serveur injoignable au
    /// premier démarrage) ou dont le certificat a été retiré manuellement, mais dont la détection
    /// continue de tourner, pouvait donc voir son buffer disque grossir SANS LIMITE. Appelée
    /// indépendamment de l'état d'enrôlement, à chaque cycle de <c>SuspiciousEventUploader</c>.
    /// `ReadDiskPending(0)` fait le même travail de purge que pour un vrai lot, simplement sans
    /// jamais rien ajouter au résultat (`result.Count &lt; 0` est toujours faux).</summary>
    public void PurgeExpiredDiskEntries() => ReadDiskPending(0);

    /// <summary>Persiste un lot qui n'a PAS pu être envoyé (échec réseau/serveur) — les entrées
    /// qui venaient déjà du disque sont simplement laissées en place (jamais retirées avant un
    /// succès), les entrées qui venaient du canal mémoire sont ajoutées pour la première fois.
    /// Dédoublonné par <see cref="SuspiciousEventRecord.LocalEventId"/> : idempotent même si
    /// appelé plusieurs fois pour le même lot.</summary>
    public void PersistUnsentBatch(IReadOnlyList<SuspiciousEventRecord> batch)
    {
        if (batch.Count == 0) return;
        AppendToDisk(batch, deduplicate: true);
    }

    /// <summary>Retire du disque les entrées d'un lot envoyé avec succès (2xx) — jamais avant.
    /// Les entrées qui venaient du canal mémoire (jamais écrites sur disque) sont un no-op ici.</summary>
    public void RemoveFromDisk(IReadOnlyList<SuspiciousEventRecord> sentBatch)
    {
        var idsToRemove = sentBatch.Select(e => e.LocalEventId).ToHashSet();
        lock (FileLock)
        {
            try
            {
                if (!File.Exists(PendingFilePath)) return;
                var remaining = new List<string>();
                foreach (var line in File.ReadAllLines(PendingFilePath))
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var record = TryDeserializeLine(line);
                    if (record is not null && idsToRemove.Contains(record.LocalEventId)) continue;
                    remaining.Add(line);
                }
                File.WriteAllLines(PendingFilePath, remaining);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Échec du nettoyage du buffer disque des événements suspects après envoi réussi.");
            }
        }
    }

    private List<SuspiciousEventRecord> ReadDiskPending(int maxCount)
    {
        var result = new List<SuspiciousEventRecord>();
        lock (FileLock)
        {
            try
            {
                if (!File.Exists(PendingFilePath)) return result;

                var maxAge = TimeSpan.FromHours(Math.Max(1, _config.SuspiciousEventMaxDiskBufferAgeHours));
                var cutoff = DateTime.UtcNow - maxAge;
                var lines = File.ReadAllLines(PendingFilePath);
                var kept = new List<string>();
                var purged = 0;

                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    var record = TryDeserializeLine(line);
                    if (record is null) continue; // ligne corrompue — abandonnée silencieusement

                    if (record.OccurredAtUtc < cutoff)
                    {
                        purged++;
                        continue; // trop vieux — voir le plan, "pas une source de vérité"
                    }

                    kept.Add(line);
                    if (result.Count < maxCount)
                    {
                        result.Add(record);
                    }
                }

                if (purged > 0)
                {
                    _logger.LogWarning(
                        "{Count} événement(s) suspect(s) en buffer disque purgé(s) (plus vieux que {Hours}h).",
                        purged, _config.SuspiciousEventMaxDiskBufferAgeHours);
                }

                if (purged > 0 || kept.Count != lines.Length)
                {
                    File.WriteAllLines(PendingFilePath, kept);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Échec de la lecture du buffer disque des événements suspects.");
            }
        }
        return result;
    }

    private void AppendToDisk(IReadOnlyList<SuspiciousEventRecord> records, bool deduplicate)
    {
        lock (FileLock)
        {
            try
            {
                DirectoryHardening.EnsureSecureDirectory(DiskDirectory);

                IEnumerable<SuspiciousEventRecord> toAppend = records;
                if (deduplicate && File.Exists(PendingFilePath))
                {
                    var existingIds = File.ReadAllLines(PendingFilePath)
                        .Select(TryDeserializeLine)
                        .Where(r => r is not null)
                        .Select(r => r!.LocalEventId)
                        .ToHashSet();
                    toAppend = records.Where(r => !existingIds.Contains(r.LocalEventId));
                }

                var lines = toAppend.Select(SerializeLine).ToList();
                if (lines.Count > 0)
                {
                    File.AppendAllLines(PendingFilePath, lines);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Échec de l'écriture du buffer disque des événements suspects — {Count} événement(s) potentiellement perdu(s).", records.Count);
            }
        }
    }

    private static string SerializeLine(SuspiciousEventRecord record) => JsonSerializer.Serialize(record);

    private SuspiciousEventRecord? TryDeserializeLine(string line)
    {
        try
        {
            return JsonSerializer.Deserialize<SuspiciousEventRecord>(line);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Ligne corrompue dans le buffer disque des événements suspects — abandonnée.");
            return null;
        }
    }
}
