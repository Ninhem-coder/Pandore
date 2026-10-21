using EndpointAgent.Compliance;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Communication;

/// <summary>
/// Boucle périodique DÉDIÉE à la conformité (jalon 11) — timer indépendant du <see
/// cref="Worker"/> (renouvellement de certificat + inventaire, plusieurs heures sur UN SEUL
/// timer) et de <see cref="CommandPoller"/> (canal de commande, quelques minutes) : un 3ᵉ sujet
/// n'a sa place dans aucune des deux boucles existantes, même raisonnement qui a déjà justifié
/// de séparer <c>CommandPoller</c> du <c>Worker</c> au jalon 4.
/// </summary>
public class ComplianceLoop : BackgroundService
{
    private readonly ILogger<ComplianceLoop> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;

    public ComplianceLoop(
        ILogger<ComplianceLoop> logger,
        IOptions<AgentConfig> config,
        ServerClient serverClient)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromHours(Math.Max(1, _config.ComplianceCheckIntervalHours));
        _logger.LogInformation("Démarrage de la boucle de conformité (intervalle {Interval}).", interval);

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
            // Pas encore enrôlé — silencieux, même comportement d'attente que le Worker.
            return;
        }
        var agentId = CertificateStore.GetAgentId(cert);

        // Awaited directement : c'est SA PROPRE boucle dédiée, la bloquer le temps du contrôle
        // est sans conséquence sur le reste de l'agent (contrairement au foreach partagé de
        // CommandPoller, voir ComplianceRunner). Le garde-fou statique de ComplianceRunner gère
        // lui-même le cas où une vérification à la demande est déjà en cours.
        await ComplianceRunner.RunPeriodicAsync(_serverClient, _config, agentId, _logger, cancellationToken);
    }
}
