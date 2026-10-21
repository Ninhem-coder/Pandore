using EndpointAgent.Inventory;

namespace EndpointAgent.Communication;

/// <summary>
/// Collecte l'inventaire applicatif local et le pousse au serveur — factorisé ici pour n'exister
/// qu'à un seul endroit : appelé par <see cref="Worker"/> à chaque cycle périodique ET par
/// <c>Commands/CommandExecutor.cs</c> (jalon 4) pour la commande "forcer un inventaire immédiat".
/// </summary>
public static class InventoryPusher
{
    /// <summary>Renvoie le nombre d'applications envoyées. Laisse remonter toute exception —
    /// à l'appelant de décider comment la logger/rapporter (le Worker l'avale pour ne jamais
    /// interrompre sa boucle, le CommandExecutor la transforme en résultat d'échec).</summary>
    public static async Task<int> CollectAndPushAsync(
        ServerClient serverClient,
        string agentId,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var apps = InstalledAppsCollector.Collect();
        // OsInfoCollector (jalon EOL, 2026-09-08) — même isolement défensif que le reste des
        // collecteurs : un échec WMI renvoie `null`, jamais une exception qui empêcherait
        // l'envoi de l'inventaire applicatif lui-même.
        var osInfo = OsInfoCollector.Collect();
        // Traçabilité de version (2026-09-08) — `<Version>` du .csproj, lue via la réflexion
        // sur cet assembly lui-même (jamais une constante dupliquée à la main, qui finirait
        // par diverger du vrai binaire déployé).
        var agentVersion = typeof(InventoryPusher).Assembly.GetName().Version?.ToString();
        await serverClient.PushInventoryAsync(agentId, apps, osInfo, agentVersion, cancellationToken);
        logger.LogInformation("Inventaire envoyé avec succès ({Count} applications).", apps.Count);
        return apps.Count;
    }
}
