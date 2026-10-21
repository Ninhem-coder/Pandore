using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Text.Json;
using EndpointAgent.Configuration;

namespace EndpointAgent.Commands;

/// <summary>
/// Jalon "confinement" (mini-EDR, 2026-09-17, demande de Nicolas) — deux actions déclenchées
/// MANUELLEMENT depuis le détail d'une alerte "activité suspecte" (jamais par la détection
/// elle-même, voir la maquette validée) : tuer un process et isoler le réseau du poste.
///
/// SYNCHRONE comme "force_reboot"/"system_diagnostic" — un effet déterministe et borné, rien à
/// attendre de plus avant de rapporter le résultat à <c>CommandExecutor</c>.
///
/// 🔧 Revue de sécurité du 2026-09-17 (relecture demandée par Nicolas juste après ce jalon,
/// AVANT tout déploiement réel) — 2 failles corrigées ici : (1) <see cref="RunNetsh"/> ne
/// vérifiait jamais le code de sortie de <c>netsh</c>, donc <see cref="IsolateNetwork"/> pouvait
/// rapporter un succès alors que rien n'était bloqué (faux sentiment de confinement), OU
/// inversement finir avec la politique par défaut bloquante posée mais les règles d'autorisation
/// manquantes (poste réellement injoignable, y compris pour lever l'isolement) ; (2) le repli
/// "par nom seul" de <see cref="KillProcess"/> (cas explicitement prévu quand le signal réseau ne
/// fournit qu'un nom court) tuait TOUT process portant ce nom sur la machine sans aucune
/// vérification — corrigé en refusant de tuer à l'aveugle dès qu'il y a plus d'UNE
/// correspondance, et en ajoutant une liste de process système jamais ciblables.
/// </summary>
public static class ContainmentRunner
{
    private const string FirewallRulePrefix = "VanitasIsolation";

    // Jamais ciblés par kill_process, PID exact ou repli confondus — un signal mal attribué
    // (course sur réutilisation de PID, événement 4688 corrompu/usurpé) ne doit jamais pouvoir
    // faire planter/geler la machine via un de ces process. Comparaison sur le nom de base, sans
    // extension, insensible à la casse.
    private static readonly HashSet<string> ProtectedProcessNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "lsass", "csrss", "wininit", "smss", "services", "winlogon", "system",
    };

    private sealed record KillProcessParametersDto(int? pid, string? process_name);

    /// <summary>Tue un process — PID exact d'abord (le plus précis), repli par nom + chemin
    /// EXACT si le PID a expiré/été réattribué entre la détection et le clic (délai inhérent à
    /// une action manuelle). Repli "par nom seul" (aucun chemin fourni, cas du signal réseau)
    /// accepté UNIQUEMENT s'il n'existe qu'UNE SEULE correspondance sur la machine — au-delà,
    /// refus explicite plutôt que de tuer plusieurs process sans certitude que ce soit le bon
    /// (un nom générique comme <c>svchost.exe</c>/<c>chrome.exe</c> tuerait sinon des process
    /// sans rapport). Jamais un process de <see cref="ProtectedProcessNames"/> ni l'agent
    /// lui-même, quel que soit le chemin emprunté.</summary>
    public static (bool, string?, bool, Action?) KillProcess(string? parametersJson, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(parametersJson))
            return (false, "Paramètres manquants pour kill_process.", false, null);

        KillProcessParametersDto? dto;
        try
        {
            dto = JsonSerializer.Deserialize<KillProcessParametersDto>(parametersJson);
        }
        catch (Exception ex)
        {
            return (false, $"Paramètres illisibles pour kill_process : {ex.Message}", false, null);
        }
        if (dto is null || (dto.pid is null && string.IsNullOrWhiteSpace(dto.process_name)))
            return (false, "Ni PID ni nom de process fournis pour kill_process.", false, null);

        if (IsProtected(dto.process_name))
            return (false, $"Refus : \"{dto.process_name}\" est un process système protégé, jamais terminé par cette commande.", false, null);

        if (dto.pid is int pid)
        {
            if (pid == Environment.ProcessId)
                return (false, "Refus : le PID cible est celui de l'agent Vanitas lui-même.", false, null);
            try
            {
                using var proc = Process.GetProcessById(pid);
                if (IsProtected(proc.ProcessName))
                    return (false, $"Refus : PID {pid} est \"{proc.ProcessName}\", un process système protégé.", false, null);
                var currentPath = TryGetMainModulePath(proc);
                // Sans nom attendu (repli réseau où `process_name` est déjà juste "name.exe") on
                // fait confiance au PID seul ; avec un nom attendu, on vérifie qu'il correspond
                // encore avant de tuer (le PID a pu être réattribué à un AUTRE process depuis).
                var matches = string.IsNullOrWhiteSpace(dto.process_name)
                    || string.Equals(currentPath, dto.process_name, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(proc.ProcessName + ".exe", System.IO.Path.GetFileName(dto.process_name), StringComparison.OrdinalIgnoreCase);
                if (matches)
                {
                    proc.Kill();
                    return (true, $"Process {pid} ({proc.ProcessName}) terminé.", false, null);
                }
                logger.LogWarning(
                    "kill_process : PID {Pid} existe mais correspond maintenant à {Actual}, pas à {Expected} — repli par nom/chemin.",
                    pid, currentPath ?? proc.ProcessName, dto.process_name);
            }
            catch (ArgumentException)
            {
                // PID introuvable (process déjà terminé) — repli ci-dessous, pas une erreur.
            }
        }

        if (string.IsNullOrWhiteSpace(dto.process_name))
            return (false, $"PID {dto.pid} introuvable et aucun nom de process pour le repli.", false, null);

        var hasFullPath = dto.process_name.Contains('\\');
        var baseName = System.IO.Path.GetFileNameWithoutExtension(dto.process_name);
        var candidates = Process.GetProcessesByName(baseName);
        try
        {
            if (hasFullPath)
            {
                // Chemin complet fourni : ne garder que les process dont le chemin correspond
                // EXACTEMENT, jamais un repli sur le nom seul quand un chemin était disponible.
                var matched = candidates.Where(p => string.Equals(TryGetMainModulePath(p), dto.process_name, StringComparison.OrdinalIgnoreCase)).ToList();
                var killed = 0;
                var denied = 0;
                foreach (var proc in matched)
                {
                    if (TryKill(proc)) killed++;
                    else denied++;
                }
                return BuildFallbackResult(killed, denied, dto, baseName);
            }

            // Pas de chemin fourni (cas légitime du signal réseau, `process_name` déjà court) :
            // une seule correspondance sur toute la machine, sinon refus — voir le commentaire de
            // classe ci-dessus (revue de sécurité du 2026-09-17).
            if (candidates.Length > 1)
            {
                return (
                    false,
                    $"{candidates.Length} process nommés \"{baseName}\" trouvés sans chemin pour désambiguïser — refus de tuer à l'aveugle (PID {dto.pid?.ToString() ?? "absent"} introuvable).",
                    false,
                    null
                );
            }
            if (candidates.Length == 0)
                return (false, $"Aucun process nommé \"{baseName}\" trouvé (PID {dto.pid?.ToString() ?? "absent"} introuvable).", false, null);

            var only = candidates[0];
            var ok = TryKill(only);
            return BuildFallbackResult(ok ? 1 : 0, ok ? 0 : 1, dto, baseName);
        }
        finally
        {
            foreach (var p in candidates) p.Dispose();
        }
    }

    private static (bool, string?, bool, Action?) BuildFallbackResult(int killed, int denied, KillProcessParametersDto dto, string baseName)
    {
        if (killed > 0)
        {
            var deniedNote = denied > 0 ? $" ({denied} refus d'accès)" : "";
            return (true, $"{killed} process \"{baseName}\" terminé(s) par repli nom/chemin (PID {dto.pid?.ToString() ?? "absent"} introuvable){deniedNote}.", false, null);
        }
        if (denied > 0)
            return (false, $"{denied} process \"{baseName}\" trouvé(s) mais accès refusé au Kill() — process protégé par l'OS.", false, null);
        return (false, $"Aucun process correspondant à \"{dto.process_name}\" trouvé (PID {dto.pid?.ToString() ?? "absent"} introuvable).", false, null);
    }

    /// <summary>Tente <see cref="Process.Kill()"/>, renvoie <c>false</c> pour un Accès refusé
    /// (process protégé par l'OS — visible dans le résultat rapporté, jamais confondu avec
    /// "déjà terminé") et <c>true</c> pour un succès ; un process déjà terminé entre
    /// l'énumération et cet appel compte comme un succès (rien à tuer, objectif déjà atteint).</summary>
    private static bool TryKill(Process proc)
    {
        try
        {
            proc.Kill();
            return true;
        }
        catch (Win32Exception)
        {
            return false; // Accès refusé — distingué d'un "déjà terminé" pour l'audit.
        }
        catch (InvalidOperationException)
        {
            return true; // Déjà terminé entre l'énumération et le Kill() — objectif déjà atteint.
        }
    }

    private static bool IsProtected(string? nameOrPath)
    {
        if (string.IsNullOrEmpty(nameOrPath)) return false;
        var baseName = System.IO.Path.GetFileNameWithoutExtension(nameOrPath);
        return ProtectedProcessNames.Contains(baseName);
    }

    /// <summary>Isole le poste du réseau — PAS via une règle "block all" (un rejet EXPLICITE
    /// prime toujours sur une autorisation explicite dans Windows Firewall, quel que soit
    /// l'ordre : une règle "allow serveur Vanitas" ajoutée À CÔTÉ d'une règle "block all"
    /// resterait bloquée, rendant la levée d'isolement à distance impossible). À la place : la
    /// politique PAR DÉFAUT du profil passe à "Block" (jouée seulement quand AUCUNE règle ne
    /// matche, donc de priorité plus BASSE qu'une autorisation explicite), combinée à une règle
    /// d'autorisation explicite ciblant les IP résolues du serveur Vanitas — même principe que
    /// "Isoler l'appareil" de Defender (garder un canal de gestion ouvert).
    ///
    /// Les IP du serveur sont RÉSOLUES UNE FOIS ici et épinglées dans la règle (pas le nom
    /// d'hôte) : une requête DNS sortante serait elle-même bloquée par la politique par défaut,
    /// un poste isolé ne doit pas dépendre de DNS pour retrouver son propre canal de gestion.
    /// TOUTES les adresses résolues sont autorisées (pas seulement la première) — un DNS à
    /// plusieurs enregistrements (répartition de charge) ne doit pas isoler le canal de gestion
    /// lui-même si l'agent se reconnecte ensuite sur une adresse différente de la même
    /// résolution. Chaque étape vérifie le code de sortie de `netsh` : un échec à n'importe
    /// quelle étape ANNULE ce qui a déjà été posé plutôt que de continuer vers un état
    /// incohérent (ex. politique bloquante posée sans règle d'autorisation — poste injoignable
    /// même pour lever l'isolement).
    ///
    /// Limite connue, non résolue ici : si l'adresse du serveur change APRÈS l'isolement (bail
    /// DHCP renouvelé, bascule) alors que le poste est isolé, la règle d'autorisation pointe vers
    /// une adresse périmée et le poste ne peut plus recevoir `lift_isolation` à distance —
    /// nécessiterait une re-résolution périodique pendant l'isolement, hors périmètre de ce
    /// jalon (le serveur Vanitas tourne sur une IP fixe en pratique).</summary>
    public static (bool, string?, bool, Action?) IsolateNetwork(AgentConfig config)
    {
        if (!Uri.TryCreate(config.ServerUrl, UriKind.Absolute, out var serverUri))
            return (false, $"ServerUrl invalide ({config.ServerUrl}) — isolement refusé pour ne pas risquer de couper le seul canal de levée.", false, null);

        IPAddress[] resolved;
        try
        {
            resolved = Dns.GetHostAddresses(serverUri.Host).Where(a => !a.IsIPv6LinkLocal).ToArray();
        }
        catch (Exception ex)
        {
            return (false, $"Résolution DNS du serveur Vanitas échouée ({ex.Message}) — isolement refusé.", false, null);
        }
        if (resolved.Length == 0)
            return (false, "Résolution DNS du serveur Vanitas n'a renvoyé aucune adresse exploitable — isolement refusé.", false, null);

        var remoteIpList = string.Join(",", resolved.Select(a => a.ToString()));

        if (!RunNetsh($"advfirewall firewall add rule name=\"{FirewallRulePrefix}-Allow-Out\" dir=out action=allow enable=yes remoteip={remoteIpList} protocol=TCP", out var err1))
            return (false, $"Échec de la règle d'autorisation sortante — isolement ABANDONNÉ avant tout blocage : {err1}", false, null);

        if (!RunNetsh($"advfirewall firewall add rule name=\"{FirewallRulePrefix}-Allow-In\" dir=in action=allow enable=yes remoteip={remoteIpList} protocol=TCP", out var err2))
        {
            RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRulePrefix}-Allow-Out\"", out _);
            return (false, $"Échec de la règle d'autorisation entrante — isolement ABANDONNÉ, règle sortante retirée : {err2}", false, null);
        }

        if (!RunNetsh("advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", out var err3))
        {
            RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRulePrefix}-Allow-Out\"", out _);
            RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRulePrefix}-Allow-In\"", out _);
            return (false, $"Échec du changement de politique par défaut — isolement ABANDONNÉ, règles d'autorisation retirées : {err3}", false, null);
        }

        return (true, $"Poste isolé — tout le trafic est bloqué par défaut, seule(s) {remoteIpList} (serveur Vanitas) reste(nt) autorisée(s).", false, null);
    }

    /// <summary>Symétrique de <see cref="IsolateNetwork"/> — restaure la politique par défaut
    /// des profils puis retire les règles d'autorisation dédiées (jamais l'inverse : retirer les
    /// règles d'autorisation AVANT de restaurer la politique par défaut couperait le poste de son
    /// propre canal de gestion pendant la fenêtre entre les deux commandes). Si l'une des étapes
    /// échoue, tente quand même les suivantes (contrairement à `IsolateNetwork` qui annule tout
    /// à la première erreur) : ici, mieux vaut un état partiellement restauré qu'un abandon total
    /// qui laisserait le poste bloqué avec un message d'échec et aucune règle retirée.</summary>
    public static (bool, string?, bool, Action?) LiftIsolation()
    {
        var okPolicy = RunNetsh("advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound", out var errPolicy);
        var okOut = RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRulePrefix}-Allow-Out\"", out var errOut);
        var okIn = RunNetsh($"advfirewall firewall delete rule name=\"{FirewallRulePrefix}-Allow-In\"", out var errIn);

        if (okPolicy && okOut && okIn)
            return (true, "Isolement réseau levé — politique par défaut des profils restaurée.", false, null);

        var failures = new List<string>();
        if (!okPolicy) failures.Add($"politique par défaut ({errPolicy})");
        if (!okOut) failures.Add($"règle sortante ({errOut})");
        if (!okIn) failures.Add($"règle entrante ({errIn})");
        return (false, $"Levée d'isolement partielle — échec sur : {string.Join(", ", failures)}. Réessayer.", false, null);
    }

    private static string? TryGetMainModulePath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            // Accès refusé (process SYSTEM/protégé) — pas fatal, juste pas de vérification de
            // chemin possible pour celui-ci.
            return null;
        }
    }

    /// <summary>Lance `netsh.exe`, attend sa fin (10s max) et renvoie si le code de sortie
    /// indique un succès — 🔧 CORRIGÉ (revue du 2026-09-17) : la version précédente ignorait
    /// totalement le résultat, laissant `IsolateNetwork`/`LiftIsolation` rapporter un succès même
    /// en cas d'échec réel de `netsh`. Lecture ASYNCHRONE de stdout/stderr (Task, pas
    /// `ReadToEnd()` synchrone avant `WaitForExit`) : évite l'interblocage classique si une des
    /// deux sorties remplit son tampon pendant que l'autre n'est pas encore lue — improbable pour
    /// une sortie aussi courte que celle de `netsh`, mais gratuit à éviter correctement.</summary>
    private static bool RunNetsh(string arguments, out string output)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            },
        };

        if (!process.Start())
        {
            output = "impossible de démarrer netsh.exe";
            return false;
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        var exited = process.WaitForExit(10_000);

        if (!exited)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Terminé entre-temps — pas une erreur pour cet appel.
            }
            output = "netsh.exe n'a pas répondu dans le délai imparti (10s)";
            return false;
        }

        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        output = string.IsNullOrWhiteSpace(stderr) ? stdout.Trim() : stderr.Trim();
        return process.ExitCode == 0;
    }
}
