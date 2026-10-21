using System.Text.Json;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using EndpointAgent.Security;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Fetch + cache local du catalogue de règles de détection (nouveau jalon, 2026-09-14) — calqué
/// sur <c>Compliance/ComplianceRunner.cs</c> ("fetch de règles serveur + cache local +
/// durcissement de répertoire", voir le plan §Moteur de règles local), mais réuni en UNE seule
/// classe ici plutôt que scindé en logique statique + <c>BackgroundService</c> séparé : les
/// règles de conformité ont aussi besoin d'un déclenchement À LA DEMANDE (commande dashboard),
/// ce qui justifiait la séparation ; les règles de détection, elles, n'ont qu'un seul
/// consommateur (cette boucle périodique), une seule classe suffit.
///
/// Exposé comme SINGLETON (voir Program.cs — <c>AddSingleton</c> + <c>AddHostedService(sp =>
/// sp.GetRequiredService&lt;SuspiciousRulesProvider&gt;())</c>, jamais <c>AddHostedService&lt;T&gt;()</c>
/// seul qui créerait une DEUXIÈME instance distincte de celle injectée dans les watchers) : les
/// watchers lisent <see cref="Current"/> directement, sans repasser par le réseau à chaque
/// évaluation.
/// </summary>
public sealed class SuspiciousRulesProvider : BackgroundService
{
    private readonly ILogger<SuspiciousRulesProvider> _logger;
    private readonly AgentConfig _config;
    private readonly ServerClient _serverClient;
    private readonly object _lock = new();
    private SuspiciousRulesDto? _current;

    private static readonly string CacheDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EndpointAgent", "suspicious-events");
    private static readonly string CacheFilePath = Path.Combine(CacheDirectory, "rules-cache.json");

    public SuspiciousRulesProvider(ILogger<SuspiciousRulesProvider> logger, IOptions<AgentConfig> config, ServerClient serverClient)
    {
        _logger = logger;
        _config = config.Value;
        _serverClient = serverClient;
        // Chargé dès la construction (avant même le premier cycle réseau) — pour survivre à un
        // redémarrage de l'agent pendant une coupure serveur, voir le plan.
        _current = LoadFromDiskCache();
    }

    /// <summary>Dernier catalogue de règles connu — `null` tant qu'aucun fetch n'a réussi ET
    /// qu'aucun cache disque n'existe (premier démarrage, serveur injoignable) : les watchers
    /// doivent alors s'abstenir d'évaluer plutôt que de deviner des valeurs par défaut codées en
    /// dur (voir le plan, "la mécanique de collecte reste du code C# compilé, les PARAMÈTRES sont
    /// servis par le serveur").</summary>
    public SuspiciousRulesDto? Current
    {
        get { lock (_lock) { return _current; } }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, _config.SuspiciousRulesRefreshIntervalMinutes));
        _logger.LogInformation("Démarrage du rafraîchissement des règles de détection d'activités suspectes (intervalle {Interval}).", interval);

        while (!stoppingToken.IsCancellationRequested)
        {
            await RefreshOnceAsync(stoppingToken);

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

    private async Task RefreshOnceAsync(CancellationToken cancellationToken)
    {
        using var cert = CertificateStore.FindCurrentCertificate();
        if (cert is null)
        {
            return; // pas encore enrôlé — silencieux, même comportement d'attente que le Worker.
        }
        var agentId = CertificateStore.GetAgentId(cert);

        try
        {
            var rules = await _serverClient.FetchSuspiciousRulesAsync(agentId, cancellationToken);
            lock (_lock)
            {
                _current = rules;
            }
            SaveToDiskCache(rules);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec de la récupération des règles de détection d'activités suspectes — conservation du catalogue précédent.");
        }
    }

    private static SuspiciousRulesDto? LoadFromDiskCache()
    {
        try
        {
            if (!File.Exists(CacheFilePath)) return null;
            var json = File.ReadAllText(CacheFilePath);
            return JsonSerializer.Deserialize<SuspiciousRulesDto>(json);
        }
        catch
        {
            // Cache corrompu/illisible — pas fatal, équivalent à "pas de cache" (voir Current).
            return null;
        }
    }

    private void SaveToDiskCache(SuspiciousRulesDto rules)
    {
        try
        {
            DirectoryHardening.EnsureSecureDirectory(CacheDirectory);
            File.WriteAllText(CacheFilePath, JsonSerializer.Serialize(rules));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Échec de l'écriture du cache local des règles de détection d'activités suspectes.");
        }
    }
}
