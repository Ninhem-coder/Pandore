using System.Diagnostics;
using System.Text.Json;
using EndpointAgent.Communication;
using EndpointAgent.Compliance;
using EndpointAgent.Configuration;
using EndpointAgent.Inventory;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace EndpointAgent.Commands;

/// <summary>
/// Dispatch d'une <see cref="PendingCommand"/> reçue du serveur vers l'un des handlers
/// prédéfinis (jalon 4) — jamais de texte/script arbitraire exécuté, un type de commande
/// inconnu échoue proprement plutôt que d'être interprété. Catalogue tenu synchronisé à la
/// main avec <c>server/app/commands.py::COMMAND_TYPES</c>.
/// </summary>
public static class CommandExecutor
{
    /// <summary><paramref name="RequestStop"/> : ne PAS terminer le process ici — le faire
    /// AVANT le rapport de résultat a été le premier bug observé en testant (le résultat de
    /// "restart_service" ne partait jamais, la commande restait "running" pour toujours).
    /// L'appelant (<c>CommandPoller</c>) doit rapporter le résultat D'ABORD, puis terminer le
    /// process ENSUITE — via <c>Environment.Exit()</c>, pas un arrêt propre du host (voir le
    /// commentaire dans <c>CommandPoller</c> : un arrêt propre ne déclenche PAS la politique de
    /// récupération du Windows Service, confirmé en testant au jalon 5).
    ///
    /// <paramref name="PostReportAction"/> (jalon 7) : même risque que <paramref
    /// name="RequestStop"/>, sous une forme différente — repéré en testant "uninstall_agent"
    /// pour de vrai : lancer `msiexec /X` DANS le handler lui-même (avant même que l'appelant
    /// n'ait eu la main pour rapporter le résultat) laisse msiexec arrêter le service — via le
    /// SCM, une vraie terminaison de CE process — pendant que le POST HTTP de rapport est
    /// encore en vol, souvent avant qu'il n'ait eu le temps d'aboutir. Confirmé : la commande
    /// restait "running" indéfiniment malgré une désinstallation réellement réussie. Toute
    /// action qui risque de faire mourir le process (lancer msiexec, killer le process...) doit
    /// donc être DIFFÉRÉE ici plutôt qu'exécutée immédiatement — l'appelant l'invoque lui-même
    /// UNIQUEMENT après que le rapport de résultat a été envoyé avec succès.</summary>
    public static async Task<(bool Success, string? Result, bool RequestStop, Action? PostReportAction)> ExecuteAsync(
        PendingCommand command,
        ServerClient serverClient,
        AgentConfig config,
        string agentId,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            return command.CommandType switch
            {
                "force_inventory" => await ForceInventoryAsync(serverClient, agentId, logger, cancellationToken),
                "restart_service" => (true, "Arrêt demandé — le Windows Service redémarre automatiquement via sa politique de récupération (voir Installer/Product.wxs). En dev (dotnet run, pas de vrai service), relancer manuellement.", true, null),
                "system_diagnostic" => SystemDiagnostic(),
                "check_windows_updates" => CheckWindowsUpdates(),
                "hardware_inventory" => HardwareInventory(),
                "uninstall_agent" => UninstallAgent(),
                // Jalon 9 — contrairement aux 6 autres, ce handler ne bloque JAMAIS le reste du
                // cycle : voir le commentaire complet sur ShellSessionRunner (la session réelle
                // tourne dans sa propre tâche de fond, découplée de CommandPoller). `cancellationToken`
                // ici EST déjà le `stoppingToken` du BackgroundService (voir CommandPoller.
                // PollOnceAsync, qui le transmet tel quel) — sa durée de vie couvre toute la
                // session, pas juste ce cycle de poll, donc rien de plus à plomber.
                "start_shell_session" => ShellSessionRunner.Start(serverClient, config, agentId, logger, cancellationToken),
                // Jalon 11 — même raisonnement de découplage que "start_shell_session" juste
                // au-dessus : plusieurs scripts de règle tournent séquentiellement, chacun borné
                // par un timeout, la somme pourrait sinon bloquer le canal de commande.
                "compliance_check" => ComplianceRunner.StartOnDemand(serverClient, config, agentId, logger, cancellationToken),
                // Push d'application (2026-09-08) — SYNCHRONE, contrairement aux deux
                // handlers juste au-dessus (voir InstallRunner) : le vrai succès/échec de
                // l'installation est renvoyé directement, `CommandPoller` attend la fin comme
                // pour "system_diagnostic"/"hardware_inventory".
                "install_application" => await InstallRunner.RunAsync(command.ParametersJson, serverClient, config, logger, cancellationToken),
                // Mise à jour de l'agent (2026-09-11) — voir UpdateRunner pour le détail du
                // découplage téléchargement (synchrone) / lancement de msiexec (différé via
                // PostReportAction, même mécanisme que "uninstall_agent" juste en dessous).
                "update_agent" => await UpdateRunner.RunAsync(command.ParametersJson, serverClient, logger, cancellationToken),
                // Journal d'événements Windows à la demande (2026-09-16) — SYNCHRONE comme
                // "system_diagnostic"/"hardware_inventory" juste au-dessus : voir EventLogFetcher.
                "fetch_event_log" => EventLogFetcher.Fetch(command.ParametersJson),
                // Jalon "Mises à jour Vanitas" (2026-09-17) — redémarrage IMMÉDIAT de la machine
                // depuis le dashboard, HORS de toute fenêtre de maintenance ("Forcer le
                // redémarrage maintenant"). SYNCHRONE : lancer `shutdown.exe` a un effet
                // déterministe, rien à attendre de plus avant de rapporter le résultat.
                "force_reboot" => ForceReboot(config),
                // Jalon "confinement" (2026-09-17) — SYNCHRONE comme "force_reboot" juste
                // au-dessus : voir ContainmentRunner pour le détail (repli PID→nom/chemin pour
                // le kill, politique par défaut du pare-feu plutôt qu'une règle "block all" pour
                // l'isolement — un rejet explicite primerait sinon sur l'autorisation dédiée au
                // canal de gestion, rendant la levée à distance impossible).
                "kill_process" => ContainmentRunner.KillProcess(command.ParametersJson, logger),
                "isolate_network" => ContainmentRunner.IsolateNetwork(config),
                "lift_isolation" => ContainmentRunner.LiftIsolation(),
                _ => (false, $"Type de commande inconnu : {command.CommandType}", false, null),
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Échec de l'exécution de la commande {CommandType}.", command.CommandType);
            return (false, ex.Message, false, null);
        }
    }

    private static async Task<(bool, string?, bool, Action?)> ForceInventoryAsync(
        ServerClient serverClient, string agentId, ILogger logger, CancellationToken cancellationToken)
    {
        var count = await InventoryPusher.CollectAndPushAsync(serverClient, agentId, logger, cancellationToken);
        return (true, $"{count} applications envoyées.", false, null);
    }

    /// <summary>Redémarrage IMMÉDIAT de la MACHINE (pas le Windows Service, voir
    /// "restart_service" plus haut) — même délai de courtoisie que <c>PatchRunner.
    /// TriggerReboot</c> (jalon "Mises à jour Vanitas"), pour laisser un travail non sauvegardé
    /// le temps de se fermer plutôt qu'un arrêt à la seconde du clic dashboard.</summary>
    private static (bool, string?, bool, Action?) ForceReboot(AgentConfig config)
    {
        var delay = Math.Max(10, config.PatchRebootDelaySeconds);
        Process.Start(new ProcessStartInfo
        {
            FileName = "shutdown.exe",
            Arguments = $"/r /t {delay} /c \"Redémarrage demandé depuis le dashboard Vanitas.\"",
            UseShellExecute = false,
            CreateNoWindow = true,
        });
        return (true, $"Redémarrage programmé dans {delay} secondes.", false, null);
    }

    private static (bool, string?, bool, Action?) SystemDiagnostic()
    {
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
        var drive = new DriveInfo(systemDrive);
        var uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);

        var payload = new
        {
            hostname = Environment.MachineName,
            os_version = Environment.OSVersion.VersionString,
            uptime = uptime.ToString(),
            disk_free_bytes = drive.AvailableFreeSpace,
            disk_total_bytes = drive.TotalSize,
        };
        return (true, JsonSerializer.Serialize(payload), false, null);
    }

    /// <summary>Recherche (lecture seule, aucune installation) via l'API COM native Windows
    /// Update — liaison tardive (`dynamic`), pas de package NuGet dédié, même esprit que la
    /// lecture directe du registre pour l'inventaire. Confirmé fonctionnel en conditions
    /// réelles (jalon 4) — la recherche peut prendre plusieurs minutes, c'est normal.</summary>
    private static (bool, string?, bool, Action?) CheckWindowsUpdates()
    {
        var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session")
            ?? throw new InvalidOperationException("API Windows Update (Microsoft.Update.Session) indisponible sur ce poste.");

        dynamic session = Activator.CreateInstance(sessionType)!;
        dynamic searcher = session.CreateUpdateSearcher();
        dynamic searchResult = searcher.Search("IsInstalled=0 and IsHidden=0");

        var titles = new List<string>();
        int count = searchResult.Updates.Count;
        for (int i = 0; i < count; i++)
        {
            dynamic update = searchResult.Updates.Item(i);
            titles.Add((string)update.Title);
        }

        var payload = new { pending_count = count, titles };
        return (true, JsonSerializer.Serialize(payload), false, null);
    }

    /// <summary>Identité machine, BIOS/carte mère, châssis, mémoire, disques, GPU et identité
    /// réseau (jalon 6) — voir <see cref="HardwareInventoryCollector"/> pour le détail de la
    /// collecte WMI (chaque section isolée, jamais de S.M.A.R.T. ni de détail PCI, scope V1).
    /// Clés en snake_case dans le JSON, même convention que les autres commandes de ce fichier
    /// (le reste du projet — backend Python, frontend — est snake_case partout).</summary>
    private static (bool, string?, bool, Action?) HardwareInventory()
    {
        var hw = HardwareInventoryCollector.Collect();
        var payload = new
        {
            manufacturer = hw.Manufacturer,
            model = hw.Model,
            serial_number = hw.SerialNumber,
            uuid = hw.Uuid,
            bios_manufacturer = hw.BiosManufacturer,
            bios_version = hw.BiosVersion,
            bios_release_date = hw.BiosReleaseDate,
            motherboard_manufacturer = hw.MotherboardManufacturer,
            motherboard_model = hw.MotherboardModel,
            motherboard_serial_number = hw.MotherboardSerialNumber,
            chassis_type = hw.ChassisType,
            total_memory_bytes = hw.TotalMemoryBytes,
            memory_modules = hw.MemoryModules.Select(m => new
            {
                slot = m.Slot,
                capacity_bytes = m.CapacityBytes,
                speed_mhz = m.SpeedMhz,
                manufacturer = m.Manufacturer,
                part_number = m.PartNumber,
            }),
            disks = hw.Disks.Select(d => new
            {
                model = d.Model,
                interface_type = d.InterfaceType,
                size_bytes = d.SizeBytes,
                media_type = d.MediaType,
            }),
            graphics_cards = hw.GraphicsCards.Select(g => new
            {
                name = g.Name,
                driver_version = g.DriverVersion,
                adapter_ram_bytes = g.AdapterRamBytes,
            }),
            primary_ip_address = hw.PrimaryIpAddress,
            network_adapters = hw.NetworkAdapters.Select(n => new
            {
                description = n.Description,
                ip_addresses = n.IpAddresses,
                mac_address = n.MacAddress,
            }),
            session_user = hw.SessionUser,
            domain = hw.Domain,
            dns_host_name = hw.DnsHostName,
            pci_devices = hw.PciDevices.Select(p => new
            {
                category = p.Category,
                name = p.Name,
                manufacturer = p.Manufacturer,
                device_id = p.DeviceId,
                driver = p.Driver,
                status = p.Status,
            }),
        };
        return (true, JsonSerializer.Serialize(payload), false, null);
    }

    private const string UninstallSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// <summary>Retrouve le ProductCode MSI de CET agent en scannant le registre Uninstall
    /// (vue 64 bits — même vue que celle où le MSI s'enregistre, `StandardDirectory
    /// Id="ProgramFiles64Folder"` dans Installer/Product.wxs) à la recherche de l'entrée dont
    /// `DisplayName` vaut "Endpoint Agent" (`Package Name` dans Product.wxs). Le nom de la
    /// SOUS-CLÉ trouvée EST le ProductCode — jamais codé en dur, il change à chaque rebuild du
    /// MSI (confirmé au jalon 5, WiX v4 en génère un nouveau à chaque build).
    ///
    /// ⚠️ Repéré en testant (jalon 7) : un cycle désinstall/réinstall manuel incomplet (service
    /// arrêté et dossier supprimé À LA MAIN avant un `msiexec /x`, plutôt que de laisser le
    /// MSI piloter tout le cycle) peut laisser la base Windows Installer croire PLUSIEURS
    /// ProductCode "Endpoint Agent" installés à la fois (même nom, même version, statut
    /// "installé" pour chacun — Windows Installer lui-même ne peut alors plus les distinguer,
    /// confirmé via le COM `WindowsInstaller.Installer`/`ProductsEx`, pas seulement l'ARP).
    /// Jamais de choix à l'aveugle dans ce cas : plusieurs correspondances → aucune n'est
    /// retournée, l'appelant doit le signaler explicitement plutôt que de risquer un
    /// `msiexec /X` sur le mauvais des N candidats.</summary>
    private static string? FindOwnProductCode(out int matchCount)
    {
        var matches = new List<string>();
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var uninstallKey = baseKey.OpenSubKey(UninstallSubKey);
        if (uninstallKey is not null)
        {
            foreach (var subKeyName in uninstallKey.GetSubKeyNames())
            {
                // Le nom de la sous-clé EST le ProductCode et sera interpolé tel quel dans
                // `msiexec /X{productCode}` (voir UninstallAgent) — on n'accepte donc QUE une
                // sous-clé dont le nom est un GUID braced bien formé (`{XXXXXXXX-...}`, la forme
                // que Windows Installer garantit pour un vrai ProductCode). Défense en profondeur
                // : la clé provient du registre HKLM (nécessite déjà admin pour être corrompue),
                // mais valider le format ici plutôt que faire confiance à "ça vient du registre"
                // garantit qu'aucun texte arbitraire ne puisse jamais atteindre la ligne de
                // commande msiexec, quel que soit l'état du registre.
                if (!Guid.TryParseExact(subKeyName, "B", out _))
                {
                    continue;
                }
                using var subKey = uninstallKey.OpenSubKey(subKeyName);
                if (subKey?.GetValue("DisplayName") as string == "Endpoint Agent")
                {
                    matches.Add(subKeyName);
                }
            }
        }
        matchCount = matches.Count;
        return matches.Count == 1 ? matches[0] : null;
    }

    /// <summary>Désinstallation à distance (jalon 7) — retrouve le ProductCode réel, puis
    /// DIFFÈRE à la fois le retrait du certificat ET le lancement de `msiexec /X{ProductCode}
    /// /qn` via <c>PostReportAction</c> (voir le commentaire sur <see cref="ExecuteAsync"/>).
    ///
    /// 🔧 Deux bugs réels trouvés en testant pour de vrai (pas seulement lus dans le code) —
    /// la commande restait "running" indéfiniment malgré une désinstallation réussie :
    /// 1. Lancer msiexec ICI MÊME (avant le rapport de résultat) laissait parfois msiexec
    ///    arrêter le service (donc CE process) avant que le POST de résultat n'ait fini de
    ///    partir — d'où le report différé via <c>PostReportAction</c>.
    /// 2. **Le vrai coupable, repéré en testant une deuxième fois APRÈS avoir corrigé le
    ///    premier point** : <c>ServerClient.ReportCommandResultAsync</c> (comme TOUS les appels
    ///    de ce client) a besoin du certificat agent COURANT pour s'authentifier en mTLS
    ///    (`CertificateStore.FindCurrentCertificate() ?? throw ...`). Retirer le certificat
    ///    ICI, avant le retour de cette méthode, le supprimait donc AVANT que le rapport de
    ///    résultat n'ait eu l'occasion de partir — l'appel levait une exception avalée par le
    ///    try/catch de <c>CommandPoller</c>, jamais rapportée. Le retrait du certificat doit
    ///    donc, lui aussi, être différé jusqu'après le rapport — jamais juste "avant une action
    ///    qui pourrait tuer le process", mais avant TOUT ce qui invaliderait l'authentification
    ///    du rapport lui-même.
    ///
    /// Contrairement à "restart_service", AUCUN <c>Environment.Exit</c> ici : on ne simule pas
    /// un crash, l'arrêt du service doit rester PROPRE aux yeux du Service Control Manager.
    /// C'est `ServiceControl Stop="uninstall"` (Installer/Product.wxs, jalon 5) qui demande
    /// l'arrêt propre au moment voulu par msiexec lui-même — le Generic Host
    /// (`AddWindowsService()`) répond déjà correctement à un arrêt demandé par le SCM, aucun
    /// code supplémentaire nécessaire ici pour ce point.
    ///
    /// Le résultat rapporté est optimiste ("désinstallation lancée") — l'agent ne peut PAS
    /// confirmer après coup que la désinstallation a réussi, il vient de se supprimer.</summary>
    private static (bool, string?, bool, Action?) UninstallAgent()
    {
        var productCode = FindOwnProductCode(out var matchCount);
        if (matchCount == 0)
        {
            return (false, "Impossible de retrouver l'entrée de désinstallation MSI (\"Endpoint Agent\") dans le registre — installation non standard ou déjà partiellement désinstallée.", false, null);
        }
        if (productCode is null)
        {
            return (false, $"{matchCount} entrées \"Endpoint Agent\" trouvées dans le registre Uninstall — état ambigu (probablement un ancien cycle install/désinstall manuel incomplet), refus de deviner laquelle désinstaller. Nettoyage manuel nécessaire avant de relancer cette commande.", false, null);
        }

        void FinishUninstall()
        {
            // Retiré ICI, jamais avant le retour de cette méthode : le certificat doit encore
            // être présent pour que le rapport de résultat (juste avant cet appel, voir
            // CommandPoller) puisse s'authentifier en mTLS.
            CertificateStore.RemoveCurrentCertificate();
            Process.Start(new ProcessStartInfo
            {
                FileName = "msiexec.exe",
                Arguments = $"/X{productCode} /qn /norestart",
                UseShellExecute = false,
                CreateNoWindow = true,
            });
        }

        return (true, $"Désinstallation lancée ({productCode}) — le service va s'arrêter et se retirer du poste dans les prochaines secondes. Impossible de confirmer le succès après coup : l'agent vient de déclencher sa propre suppression.", false, FinishUninstall);
    }
}
