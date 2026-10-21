using EndpointAgent.Commands;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Communication;

/// <summary>
/// Boucle périodique DÉDIÉE au canal de commande (jalon 4) — timer indépendant du
/// <see cref="Worker"/> (inventaire, plusieurs heures) : une commande lancée par l'admin doit
/// être vue et exécutée en quelques minutes, pas au prochain cycle d'inventaire.
/// </summary>
public class CommandPoller : BackgroundService
{
    private readonly ILogger<CommandPoller> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;

    public CommandPoller(
        ILogger<CommandPoller> logger,
        IOptions<AgentConfig> config,
        ServerClient serverClient)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, _config.CommandPollIntervalMinutes));

        while (!stoppingToken.IsCancellationRequested)
        {
            await PollOnceAsync(stoppingToken);

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

    private async Task PollOnceAsync(CancellationToken cancellationToken)
    {
        using var cert = CertificateStore.FindCurrentCertificate();
        if (cert is null)
        {
            // Pas encore enrôlé — silencieux, même comportement d'attente que le Worker.
            return;
        }
        var agentId = CertificateStore.GetAgentId(cert);

        IReadOnlyList<PendingCommand> pending;
        try
        {
            pending = await _serverClient.FetchPendingCommandsAsync(agentId, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Échec de la vérification des commandes en attente, nouvelle tentative au prochain cycle.");
            return;
        }

        foreach (var command in pending)
        {
            _logger.LogInformation("Exécution de la commande {Id} ({Type})...", command.Id, command.CommandType);
            var (success, result, requestStop, postReportAction) = await CommandExecutor.ExecuteAsync(
                command, _serverClient, _config, agentId, _logger, cancellationToken);

            try
            {
                // Avec le jeton de la boucle (stoppingToken) — celui-ci n'est jamais annulé par
                // l'appel Environment.Exit() ci-dessous (qui termine le PROCESS entier plutôt que
                // ce CancellationToken), donc ce POST a toujours l'occasion de partir en premier.
                await _serverClient.ReportCommandResultAsync(agentId, command.Id, success, result, cancellationToken);
                _logger.LogInformation("Résultat de la commande {Id} rapporté avec succès.", command.Id);
            }
            catch (Exception ex)
            {
                // Le résultat n'a pas pu être rapporté — la commande reste "running" côté
                // serveur, visible dans l'audit plutôt que silencieusement perdue.
                _logger.LogError(ex, "Échec du rapport de résultat pour la commande {Id}.", command.Id);
            }

            // Jalon 7 : une action qui risque de tuer ce process (ex. "uninstall_agent" lançant
            // msiexec, qui arrêtera le service via le SCM) est TOUJOURS différée jusqu'ici,
            // après le rapport de résultat ci-dessus — jamais exécutée à l'intérieur du handler
            // lui-même (voir CommandExecutor.ExecuteAsync, bug réel trouvé en testant : le
            // rapport partait parfois APRÈS que msiexec ait déjà arrêté le service).
            postReportAction?.Invoke();

            if (requestStop)
            {
                _logger.LogInformation("Arrêt du service demandé par une commande.");

                // Testé en conditions réelles (jalon 5, étape 11) : IHostApplicationLifetime
                // .StopApplication() effectue un arrêt PROPRE — le service rapporte
                // SERVICE_STOPPED avec un code de sortie 0 au Service Control Manager, exactement
                // comme un `net stop` demandé par un admin. La politique de récupération
                // (<util:ServiceConfig>, Installer/Product.wxs) ne se déclenche QUE sur une
                // terminaison INATTENDUE du processus, jamais sur un arrêt propre volontaire —
                // confirmé : le service restait "Stopped" indéfiniment avec ce mécanisme.
                // Environment.Exit avec un code non nul fait disparaître le PROCESS sans passer
                // par cette séquence d'arrêt propre : le SCM le voit comme une terminaison
                // inattendue et applique la politique de récupération sans condition
                // supplémentaire à activer. Le résultat de la commande est déjà rapporté au
                // serveur juste au-dessus (await ReportCommandResultAsync) avant cet appel.
                Environment.Exit(1);
                return;
            }
        }
    }
}
