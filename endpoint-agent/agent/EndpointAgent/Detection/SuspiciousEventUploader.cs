using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Vide périodiquement <see cref="SuspiciousEventBuffer"/> vers
/// `POST /agents/{id}/suspicious-events` — calqué sur <c>Communication/ComplianceLoop.cs</c>
/// (timer indépendant dédié, même raisonnement : un 5ᵉ sujet n'a sa place dans aucune boucle
/// existante). Ne retire un événement du buffer qu'après un POST 2xx (voir
/// <see cref="SuspiciousEventBuffer"/>). Un événement <see cref="SuspiciousEventRecord.Immediate"/>
/// (purge de journal, création de compte admin) déclenche un envoi anticipé via `Task.WhenAny` —
/// reste du polling court-circuité, jamais un nouveau canal push (voir le plan).
/// </summary>
public sealed class SuspiciousEventUploader : BackgroundService
{
    private readonly ILogger<SuspiciousEventUploader> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;
    private readonly SuspiciousEventBuffer _buffer;

    public SuspiciousEventUploader(
        ILogger<SuspiciousEventUploader> logger,
        IOptions<AgentConfig> config,
        ServerClient serverClient,
        SuspiciousEventBuffer buffer)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
        _buffer = buffer;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, _config.SuspiciousEventUploadIntervalMinutes));
        _logger.LogInformation("Démarrage de l'upload des événements suspects (intervalle {Interval}).", interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            await UploadOnceAsync(stoppingToken);

            try
            {
                await Task.WhenAny(
                    Task.Delay(interval, stoppingToken),
                    _buffer.WaitForImmediateSignalAsync(stoppingToken));
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task UploadOnceAsync(CancellationToken cancellationToken)
    {
        // 🔧 Audit de perf du 2026-09-16 : purge par âge appelée ICI, AVANT le retour anticipé
        // sur absence de certificat ci-dessous — sinon un poste non-enrôlé (ou dont le
        // certificat a été retiré) dont la détection continue de tourner voyait son buffer
        // disque grossir sans limite, la purge normale (via `PrepareBatch`) n'étant jamais
        // atteinte tant qu'aucun certificat n'est disponible.
        _buffer.PurgeExpiredDiskEntries();

        using var cert = CertificateStore.FindCurrentCertificate();
        if (cert is null)
        {
            return; // pas encore enrôlé — silencieux, même comportement d'attente que le Worker.
        }
        var agentId = CertificateStore.GetAgentId(cert);
        var batchMaxSize = Math.Max(1, _config.SuspiciousEventBatchMaxSize);

        // Vide plusieurs lots dans le MÊME cycle s'il y a du retard à rattraper (ex. agent resté
        // longtemps hors ligne) — s'arrête dès qu'un lot échoue (pas d'acharnement dans la même
        // passe, le prochain cycle réessaiera) ou dès que le buffer est vidé.
        while (!cancellationToken.IsCancellationRequested)
        {
            var batch = _buffer.PrepareBatch(batchMaxSize);
            if (batch.Count == 0)
            {
                break;
            }

            try
            {
                await _serverClient.PostSuspiciousEventsAsync(agentId, batch.Select(r => r.ToDto()).ToList(), cancellationToken);
                _buffer.RemoveFromDisk(batch);
                _logger.LogInformation("Événements suspects envoyés ({Count}).", batch.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Échec de l'envoi des événements suspects — conservation dans le buffer, nouvelle tentative au prochain cycle.");
                _buffer.PersistUnsentBatch(batch);
                break;
            }

            if (batch.Count < batchMaxSize)
            {
                break; // plus rien à vider pour ce cycle
            }
        }
    }
}
