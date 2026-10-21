using System.Diagnostics;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using Microsoft.Win32;

namespace EndpointAgent.Patching;

/// <summary>
/// Cœur du jalon "Mises à jour Vanitas" (2026-09-17, maquette validée par Nicolas) — un cycle
/// complet : consulte la politique du poste, décide s'il faut redémarrer MAINTENANT (fenêtre
/// atteinte ou délai de grâce dépassé), sinon scanne/filtre/installe les mises à jour de
/// sécurité si la politique du groupe est active, et rapporte l'état au serveur à chaque étape.
///
/// Réutilise la MÊME API COM Windows Update que <c>CommandExecutor.CheckWindowsUpdates</c>
/// (lecture seule, jalon 4) — étendue ici à la lecture de <c>MsrcSeverity</c> (filtre sécurité)
/// et au téléchargement/à l'installation réels (<c>IUpdateDownloader</c>/<c>IUpdateInstaller</c>),
/// jamais utilisés jusqu'ici dans ce projet.
///
/// Décision "faut-il redémarrer MAINTENANT ?" faite ICI, côté agent, contre SON PROPRE horloge
/// locale (la fenêtre "20h-6h" n'a de sens qu'en heure locale du poste) — le serveur ne fait que
/// fournir la politique (fenêtre + délai de grâce) et le point de départ du délai de grâce
/// (`installed_at`, en UTC, comparé lui aussi côté agent contre `DateTime.UtcNow` pour rester
/// fiable indépendamment du fuseau/de l'heure d'été du poste).
/// </summary>
public static class PatchRunner
{
    // MSRC ne connaît que 4 niveaux ("Critical"/"Important"/"Moderate"/"Low") — "Sécurité et
    // critique uniquement" (cadrage validé avec Nicolas) se traduit par ces deux-là, jamais une
    // mise à jour de fonctionnalité (`MsrcSeverity` vide dans ce cas, exclue par construction).
    private static readonly HashSet<string> SecuritySeverities = new(StringComparer.OrdinalIgnoreCase)
    {
        "Critical",
        "Important",
    };

    public static async Task RunOnceAsync(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            var policy = await serverClient.FetchPatchPolicyAsync(agentId, cancellationToken);
            var rebootPending = IsRebootPending();

            if (rebootPending)
            {
                await HandlePendingRebootAsync(serverClient, config, agentId, policy, logger, cancellationToken);
                return;
            }

            await ScanAndInstallAsync(serverClient, config, agentId, policy, logger, cancellationToken);
        }
        catch (Exception ex)
        {
            // Même discipline que RenewCertificateIfNeededAsync (Worker.cs) : une panne
            // ponctuelle (réseau, API Windows Update momentanément indisponible) ne doit jamais
            // arrêter la boucle — nouvelle tentative au prochain cycle.
            logger.LogError(ex, "Échec du cycle de mise à jour Windows, nouvelle tentative au prochain cycle.");
        }
    }

    /// <summary>Un redémarrage est déjà en attente (installation d'un cycle précédent, ou même
    /// d'un Windows Update automatique hors de ce projet) — décide s'il faut le déclencher
    /// MAINTENANT. Deux signaux REGISTRE natifs Windows, jamais un état inventé par cet agent :
    /// même mécanisme que <c>Get-WindowsUpdate -RebootRequired</c>/la plupart des outils RMM.</summary>
    private static bool IsRebootPending()
    {
        const string cbsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
        const string wuKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";

        using var cbs = Registry.LocalMachine.OpenSubKey(cbsKey);
        if (cbs is not null) return true;

        using var wu = Registry.LocalMachine.OpenSubKey(wuKey);
        return wu is not null;
    }

    private static async Task HandlePendingRebootAsync(
        ServerClient serverClient, AgentConfig config, string agentId, PatchPolicyDto policy,
        ILogger logger, CancellationToken cancellationToken)
    {
        var graceExceeded = false;
        if (policy.installed_at is not null)
        {
            var installedAtUtc = DateTime.Parse(policy.installed_at, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
            var grace = TimeSpan.FromDays(Math.Max(1, policy.grace_days ?? 5));
            graceExceeded = DateTime.UtcNow - installedAtUtc >= grace;
        }

        var inWindow = policy.enabled && WithinWindow(DateTime.Now.TimeOfDay, policy.window_start, policy.window_end);

        // Toujours re-signaler "en attente de redémarrage" au serveur À CHAQUE cycle, même
        // quand rien ne change — `installed`/`available`/`todo` vides ici ne veulent PAS dire
        // "plus rien à installer" (voir `routes/patch.py::push_patch_status`, qui préserve la
        // dernière liste connue tant que `reboot_pending=true`).
        await PushStatusAsync(serverClient, agentId, new List<PatchItemDto>(), new List<PatchItemDto>(), new List<PatchItemDto>(), new List<PatchItemDto>(), rebootPending: true, cancellationToken);

        if (!graceExceeded && !inWindow)
        {
            logger.LogInformation("Redémarrage en attente, hors fenêtre et délai de grâce non dépassé — patiente.");
            return;
        }

        logger.LogWarning(
            graceExceeded
                ? "Délai de grâce dépassé — redémarrage forcé dans {Delay}s."
                : "Fenêtre de maintenance atteinte — redémarrage dans {Delay}s.",
            config.PatchRebootDelaySeconds);
        TriggerReboot(config, graceExceeded ? "Délai de grâce dépassé (mise à jour de sécurité)" : "Fenêtre de maintenance");
    }

    /// <summary>Fenêtre "HH:MM"→"HH:MM", avec repli logique sur le passage de minuit (ex.
    /// 20:00→06:00, la borne de fin est le lendemain) — comparée à l'heure LOCALE actuelle du
    /// poste.</summary>
    internal static bool WithinWindow(TimeSpan now, string? start, string? end)
    {
        if (string.IsNullOrWhiteSpace(start) || string.IsNullOrWhiteSpace(end)) return false;
        if (!TimeSpan.TryParse(start, out var startTs) || !TimeSpan.TryParse(end, out var endTs)) return false;

        if (startTs <= endTs)
        {
            return now >= startTs && now < endTs;
        }
        // Fenêtre à cheval sur minuit (20h→6h) : "dans la fenêtre" si après le début OU avant la fin.
        return now >= startTs || now < endTs;
    }

    private static void TriggerReboot(AgentConfig config, string reason)
    {
        var comment = $"Windows a besoin de redémarrer pour terminer l'installation de mises à jour de sécurité ({reason}).";
        Process.Start(new ProcessStartInfo
        {
            FileName = "shutdown.exe",
            Arguments = $"/r /t {Math.Max(10, config.PatchRebootDelaySeconds)} /c \"{comment}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
    }

    private static async Task ScanAndInstallAsync(
        ServerClient serverClient, AgentConfig config, string agentId, PatchPolicyDto policy,
        ILogger logger, CancellationToken cancellationToken)
    {
        var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session")
            ?? throw new InvalidOperationException("API Windows Update (Microsoft.Update.Session) indisponible sur ce poste.");
        dynamic session = Activator.CreateInstance(sessionType)!;
        dynamic searcher = session.CreateUpdateSearcher();
        dynamic searchResult = searcher.Search("IsInstalled=0 and IsHidden=0");

        var securityUpdates = new List<dynamic>();
        var available = new List<PatchItemDto>();
        int count = searchResult.Updates.Count;
        for (int i = 0; i < count; i++)
        {
            dynamic update = searchResult.Updates.Item(i);
            string severity = (string)(update.MsrcSeverity ?? "");
            PatchItemDto item = ToPatchItem(update);
            if (policy.enabled && SecuritySeverities.Contains(severity))
            {
                securityUpdates.Add(update);
            }
            else
            {
                // Hors périmètre : soit non-sécurité (fonctionnalité...), soit sécurité mais
                // politique du groupe désactivée — les deux se lisent "disponible, jamais
                // ciblée automatiquement" du point de vue du dashboard (voir la maquette).
                available.Add(item);
            }
        }

        if (securityUpdates.Count == 0)
        {
            await PushStatusAsync(serverClient, agentId, available, new List<PatchItemDto>(), new List<PatchItemDto>(), new List<PatchItemDto>(), rebootPending: false, cancellationToken);
            return;
        }

        var inProgressItems = securityUpdates.Select(u => (PatchItemDto)ToPatchItem(u)).ToList();
        logger.LogInformation("{Count} mise(s) à jour de sécurité ciblée(s) par la politique — téléchargement en cours.", inProgressItems.Count);
        // Poussé en "in_progress" (pas "todo") : le téléchargement/l'installation démarre
        // IMMÉDIATEMENT après ce push (Download()/Install() ci-dessous sont synchrones et
        // bloquants) — "todo" désignerait au contraire une mise à jour ciblée mais pas encore
        // commencée, ce qui n'est déjà plus le cas ici.
        await PushStatusAsync(serverClient, agentId, available, new List<PatchItemDto>(), inProgressItems, new List<PatchItemDto>(), rebootPending: false, cancellationToken);

        dynamic updateCollection = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.UpdateColl")!)!;
        foreach (var update in securityUpdates)
        {
            update.AcceptEula();
            updateCollection.Add(update);
        }

        dynamic downloader = session.CreateUpdateDownloader();
        downloader.Updates = updateCollection;
        downloader.Download();

        dynamic installer = session.CreateUpdateInstaller();
        installer.Updates = updateCollection;
        dynamic installResult = installer.Install();

        var installed = new List<PatchItemDto>();
        var stillTodo = new List<PatchItemDto>();
        for (int i = 0; i < securityUpdates.Count; i++)
        {
            dynamic result = installResult.GetUpdateResult(i);
            int resultCode = (int)result.ResultCode; // 2 = Succeeded, 3 = SucceededWithErrors (COM OperationResultCode)
            PatchItemDto item = ToPatchItem(securityUpdates[i]);
            if (resultCode == 2 || resultCode == 3)
            {
                installed.Add(item);
            }
            else
            {
                logger.LogWarning("Échec d'installation pour {Item} (code {Code}) — nouvelle tentative au prochain cycle.", item.title, resultCode);
                stillTodo.Add(item);
            }
        }

        var rebootPendingNow = IsRebootPending();
        logger.LogInformation("{Installed} mise(s) à jour installée(s), {Failed} en échec, redémarrage requis : {Reboot}.", installed.Count, stillTodo.Count, rebootPendingNow);
        await PushStatusAsync(serverClient, agentId, available, stillTodo, new List<PatchItemDto>(), installed, rebootPendingNow, cancellationToken);
    }

    private static PatchItemDto ToPatchItem(dynamic update)
    {
        string kb = "—";
        try
        {
            dynamic kbArticleIds = update.KBArticleIDs;
            int kbCount = kbArticleIds.Count;
            if (kbCount > 0)
            {
                var ids = new List<string>();
                for (int i = 0; i < kbCount; i++)
                {
                    ids.Add($"KB{(string)kbArticleIds.Item(i)}");
                }
                kb = string.Join("/", ids);
            }
        }
        catch
        {
            // Certaines mises à jour (rares) n'exposent aucun numéro KB — le titre seul reste
            // exploitable pour l'affichage, jamais une raison de faire échouer tout le cycle.
        }
        return new PatchItemDto(kb, (string)update.Title);
    }

    private static Task PushStatusAsync(
        ServerClient serverClient, string agentId,
        List<PatchItemDto> available, List<PatchItemDto> todo, List<PatchItemDto> inProgress, List<PatchItemDto> installed,
        bool rebootPending, CancellationToken cancellationToken)
    {
        var status = new PatchStatusDto(available, todo, inProgress, installed, rebootPending);
        return serverClient.PostPatchStatusAsync(agentId, status, cancellationToken);
    }
}
