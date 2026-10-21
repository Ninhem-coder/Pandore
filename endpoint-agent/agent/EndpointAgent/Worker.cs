using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent;

/// <summary>
/// Boucle périodique : vérifie l'expiration du certificat (renouvelle si besoin), collecte
/// l'inventaire applicatif local et le pousse au serveur — authentifié par mTLS.
///
/// Suppose que l'agent a déjà été enrôlé au préalable (`--enroll`, voir Program.cs) — ce n'est
/// pas ce Worker qui gère le premier enrôlement, seulement le fonctionnement normal ensuite.
/// </summary>
public class Worker : BackgroundService
{
    // 90 jours de validité côté serveur (voir server/app/ca.py) — 30 jours de marge laisse
    // largement le temps de plusieurs tentatives en cas de panne réseau/serveur ponctuelle
    // avant l'expiration réelle.
    private static readonly TimeSpan RenewalThreshold = TimeSpan.FromDays(30);

    private readonly ILogger<Worker> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;

    public Worker(ILogger<Worker> logger, IOptions<AgentConfig> config, ServerClient serverClient)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await TryAutoEnrollAsync(stoppingToken);

        using (var probe = CertificateStore.FindCurrentCertificate())
        {
            if (probe is null)
            {
                _logger.LogError(
                    "Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé " +
                    "(relancer avec --enroll). Le service reste installé mais ne fait rien tant " +
                    "que ce n'est pas fait.");
                return;
            }
        }

        var interval = TimeSpan.FromHours(Math.Max(1, _config.CollectionIntervalHours));
        _logger.LogInformation("Démarrage de la boucle de collecte (intervalle {Interval}).", interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            await RenewCertificateIfNeededAsync(stoppingToken);
            await CollectAndPushAsync(stoppingToken);

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

    /// <summary>
    /// Auto-enrôlement au premier démarrage du service (jalon 5). Si le MSI a reçu
    /// ENROLLMENTTOKEN à l'installation, il est posé comme variable d'environnement MACHINE
    /// (`Agent__EnrollmentToken`, voir Installer/Product.wxs) plutôt que persisté dans
    /// appsettings.json ou passé à un process séparé via une action différée — cette dernière
    /// approche s'est avérée fragile en testant en conditions réelles (fenêtre console
    /// visible/gelable, blocages difficiles à diagnostiquer à distance) et a été abandonnée au
    /// profit de celle-ci : le service lit directement le registre machine
    /// (`EnvironmentVariableTarget.Machine` — pas besoin d'avoir été démarré APRÈS la pose de la
    /// variable, contrairement à un simple `Environment.GetEnvironmentVariable(name)` qui ne
    /// verrait que l'environnement hérité au lancement du process), s'enrôle avec le MÊME code
    /// que `--enroll`, puis EFFACE la variable une fois le token consommé avec succès — jamais
    /// laissé en clair dans le registre au-delà. Sur échec (réseau, serveur injoignable...), la
    /// variable N'EST PAS effacée : un redémarrage du service retentera avec le même token,
    /// cohérent avec la tolérance aux pannes déjà en place pour le renouvellement/l'inventaire.
    ///
    /// ⚠️ Risque ASSUMÉ (audit de sécurité du 2026-09-16) : `HKLM\SYSTEM\CurrentControlSet\
    /// Control\Session Manager\Environment` (où vit cette variable machine) a par défaut une
    /// ACL de LECTURE pour tout utilisateur authentifié localement, pas seulement les admins —
    /// entre la fin de l'installation MSI et ce premier cycle d'auto-enrôlement (quasi immédiat,
    /// le service démarre automatiquement), un utilisateur standard déjà en session sur le poste
    /// pourrait lire ce token. Volontairement PAS corrigé en resserrant l'ACL de cette clé
    /// registre : elle est partagée par TOUTES les variables d'environnement machine du poste,
    /// une ACL plus stricte casserait la lecture d'autres logiciels légitimes — un risque plus
    /// large que celui qu'on cherche à fermer. Impact borné : le token est à usage unique
    /// (consommé par `EnrollAsync` puis effacé sur succès), donc un rejeu après la première
    /// consommation légitime est déjà impossible ; la seule fenêtre réelle est une course très
    /// courte pour ENRÔLER À LA PLACE de l'agent légitime, pas pour rejouer indéfiniment.
    /// </summary>
    private async Task TryAutoEnrollAsync(CancellationToken cancellationToken)
    {
        using (var existing = CertificateStore.FindCurrentCertificate())
        {
            if (existing is not null)
            {
                return; // déjà enrôlé, rien à faire
            }
        }

        var token = Environment.GetEnvironmentVariable("Agent__EnrollmentToken", EnvironmentVariableTarget.Machine);
        _logger.LogInformation(
            "Vérification du token d'enrôlement (variable d'environnement machine) : {Length} caractère(s) trouvé(s).",
            token?.Length ?? -1);
        if (string.IsNullOrWhiteSpace(token))
        {
            return; // pas de token disponible — attend un --enroll manuel
        }

        _logger.LogInformation("Token d'enrôlement trouvé (variable d'environnement machine) — enrôlement automatique.");
        try
        {
            var result = await _serverClient.EnrollAsync(token, Environment.MachineName, cancellationToken);
            _logger.LogInformation("Enrôlé automatiquement avec succès. AgentId = {AgentId}", result.AgentId);
            Environment.SetEnvironmentVariable("Agent__EnrollmentToken", null, EnvironmentVariableTarget.Machine);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Échec de l'enrôlement automatique — nouvelle tentative au prochain redémarrage du service.");
        }
    }

    private async Task RenewCertificateIfNeededAsync(CancellationToken cancellationToken)
    {
        string agentId;
        DateTime notAfterUtc;
        using (var cert = CertificateStore.FindCurrentCertificate())
        {
            if (cert is null)
            {
                _logger.LogError("Certificat agent introuvable au moment du renouvellement — ré-enrôlement nécessaire.");
                return;
            }
            agentId = CertificateStore.GetAgentId(cert);
            notAfterUtc = cert.NotAfter.ToUniversalTime();
        }

        if (notAfterUtc - DateTime.UtcNow > RenewalThreshold)
        {
            return;
        }

        _logger.LogInformation(
            "Certificat expirant le {NotAfter:u} (moins de {ThresholdDays} jours) — renouvellement automatique.",
            notAfterUtc, RenewalThreshold.TotalDays);

        try
        {
            await _serverClient.RenewAsync(agentId, cancellationToken);
        }
        catch (Exception ex)
        {
            // Le certificat actuel reste valide jusqu'à son expiration réelle — une panne
            // ponctuelle ne doit jamais arrêter le service, on retente au prochain cycle.
            _logger.LogError(ex, "Échec du renouvellement du certificat, nouvelle tentative au prochain cycle.");
        }
    }

    private async Task CollectAndPushAsync(CancellationToken cancellationToken)
    {
        using var cert = CertificateStore.FindCurrentCertificate();
        if (cert is null)
        {
            _logger.LogError("Certificat agent introuvable — envoi d'inventaire annulé pour ce cycle.");
            return;
        }
        var agentId = CertificateStore.GetAgentId(cert);

        try
        {
            await InventoryPusher.CollectAndPushAsync(_serverClient, agentId, _logger, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Échec de l'envoi de l'inventaire, nouvelle tentative au prochain cycle.");
        }
    }
}
