using EndpointAgent.Configuration;
using EndpointAgent.Patching;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Communication;

/// <summary>
/// Boucle périodique DÉDIÉE aux mises à jour Windows (jalon "Mises à jour Vanitas",
/// 2026-09-17) — même raisonnement que <see cref="ComplianceLoop"/> : un sujet de plus qui n'a
/// sa place ni dans <see cref="Worker"/> (inventaire, plusieurs heures) ni dans
/// <see cref="CommandPoller"/> (canal de commande, quelques minutes), avec son propre rythme
/// (voir <see cref="AgentConfig.PatchCheckIntervalMinutes"/>).
/// </summary>
public class PatchLoop : BackgroundService
{
    private readonly ILogger<PatchLoop> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;

    public PatchLoop(ILogger<PatchLoop> logger, IOptions<AgentConfig> config, ServerClient serverClient)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, _config.PatchCheckIntervalMinutes));
        _logger.LogInformation("Démarrage de la boucle de mise à jour Windows (intervalle {Interval}).", interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            await RunOnceAsync(stoppingToken);

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        using var cert = CertificateStore.FindCurrentCertificate();
        if (cert is null)
        {
            // Pas encore enrôlé — silencieux, même comportement d'attente que Worker/ComplianceLoop.
            return;
        }
        var agentId = CertificateStore.GetAgentId(cert);

        await PatchRunner.RunOnceAsync(_serverClient, _config, agentId, _logger, cancellationToken);
    }
}
