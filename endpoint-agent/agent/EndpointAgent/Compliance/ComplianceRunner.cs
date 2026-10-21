using System.Diagnostics;
using System.Text;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using EndpointAgent.Security;

namespace EndpointAgent.Compliance;

/// <summary>
/// Vérification de conformité — jalon 11. Deux points d'entrée, un seul garde-fou statique
/// partagé (même principe que <c>Commands/ShellSessionRunner.cs</c> au jalon 9) : jamais deux
/// vérifications en même temps pour cet agent, que le déclenchement soit périodique ou à la
/// demande.
///
/// Règle = un script PowerShell fourni par Nicolas via le dashboard (`ComplianceRule.
/// script_content`), PAS une vérification codée en dur ici. Contrat volontairement le plus
/// simple possible : code de sortie 0 = conforme, tout code non nul = non conforme, la sortie
/// texte capturée devient la preuve affichée.
///
/// ⚠️ Piège PowerShell réel, précisé EN TESTANT `--compliance-diag` (pas juste supposé) : la
/// crainte initiale ("une exception non interceptée ne suffit pas à faire échouer le
/// contrôle") s'est avérée FAUSSE sur PowerShell 5.1 — un `throw` non intercepté (erreur
/// TERMINANTE) produit bien un code de sortie non nul, confirmé empiriquement. Le VRAI piège
/// est plus étroit : une erreur NON TERMINANTE (`Write-Error` sans `-ErrorAction Stop`, la
/// plupart des erreurs de cmdlet par défaut) affiche un message d'erreur en rouge MAIS laisse
/// le code de sortie à 0 — confirmé aussi empiriquement (`Write-Error "..."` seul → exit 0).
/// Un script qui se contente de signaler un problème sans `throw`/`exit 1` explicite sera donc
/// enregistré CONFORME à tort. Rappelé dans le gabarit pré-rempli de l'éditeur de règles côté
/// dashboard, pas quelque chose de corrigeable ici côté agent.
/// </summary>
public static class ComplianceRunner
{
    private static readonly object _lock = new();
    private static Task? _activeTask;
    private static readonly UTF8Encoding _utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    // 🔧 Audit de sécurité du 2026-09-16 : même plafond que `Commands/InstallRunner.cs` — un
    // script de conformité qui boucle en produisant de la sortie pendant tout son timeout
    // pouvait faire grossir la mémoire de l'agent et `ComplianceResultDto.detail` (texte non
    // borné côté serveur) sans limite, potentiellement sur TOUT le parc si la règle est poussée
    // en masse.
    private const int MaxCapturedOutputChars = 100_000;

    /// <summary>Appelée directement (awaited) par <c>Communication/ComplianceLoop.cs</c> à
    /// chaque cycle périodique — bloquer SA PROPRE boucle dédiée le temps du contrôle est sans
    /// risque, contrairement au `foreach` partagé de <c>CommandPoller</c>. Si une vérification à
    /// la demande (<see cref="StartOnDemand"/>) est déjà en cours, ce cycle est silencieusement
    /// ignoré (log Information) — le prochain cycle périodique retentera.</summary>
    public static async Task RunPeriodicAsync(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken cancellationToken)
    {
        Task task;
        lock (_lock)
        {
            if (_activeTask is { IsCompleted: false })
            {
                logger.LogInformation("Une vérification de conformité est déjà en cours — ce cycle périodique est ignoré.");
                return;
            }
            task = _activeTask = RunAsync(serverClient, config, agentId, logger, cancellationToken);
        }
        await task;
    }

    /// <summary>Appelée par <c>Commands/CommandExecutor.cs</c> pour la commande
    /// "compliance_check" — retourne IMMÉDIATEMENT, jamais attendue par l'appelant (même schéma
    /// que <c>ShellSessionRunner.Start</c> au jalon 9) : plusieurs scripts tournent
    /// séquentiellement, chacun borné par un timeout, la somme pourrait sinon bloquer le canal
    /// de commande le temps du contrôle.</summary>
    public static (bool Success, string? Result, bool RequestStop, Action? PostReportAction) StartOnDemand(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            if (_activeTask is { IsCompleted: false })
            {
                return (false, "Une vérification de conformité est déjà en cours.", false, null);
            }
            _activeTask = Task.Run(() => RunAsync(serverClient, config, agentId, logger, cancellationToken));
        }
        return (true, "Vérification de conformité lancée en arrière-plan.", false, null);
    }

    private static async Task RunAsync(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            IReadOnlyList<ComplianceRuleDto> rules;
            try
            {
                rules = await serverClient.FetchComplianceRulesAsync(agentId, cancellationToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Échec de la récupération du catalogue de règles de conformité.");
                return;
            }

            if (rules.Count == 0)
            {
                // Aucune règle activée — ne poste RIEN (pas de ComplianceSnapshot vide créé côté
                // serveur, rien à rapporter).
                logger.LogInformation("Aucune règle de conformité activée — rien à vérifier.");
                return;
            }

            var results = new List<ComplianceResultDto>(rules.Count);
            foreach (var rule in rules)
            {
                results.Add(await RunRuleAsync(rule, config, logger, cancellationToken));
            }

            try
            {
                await serverClient.PostComplianceResultsAsync(agentId, results, cancellationToken);
                logger.LogInformation("Résultats de conformité envoyés ({Count} règles).", results.Count);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Échec de l'envoi des résultats de conformité.");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Échec inattendu de la vérification de conformité.");
        }
    }

    /// <summary>Exécute UN script — try/catch propre à cette règle (une règle qui plante ne doit
    /// jamais interrompre les autres). Fichier temporaire dédié à CETTE exécution (un GUID par
    /// règle, pas un fichier partagé pour tout le lot) : un `Kill(entireProcessTree: true)` sur
    /// timeout peut laisser un descripteur de fichier momentanément tenu par un processus fils,
    /// réutiliser le même chemin pour la règle suivante pourrait lever une exception.
    ///
    /// `public` (pas `private`) pour être appelable directement par `Program.cs --compliance-diag`
    /// SANS serveur ni catalogue réel — mêmes précédent que `--hardware-diag`/`--shell-diag`,
    /// mais ici réutilise le VRAI code plutôt que d'en dupliquer une copie (la logique
    /// d'exécution d'un script n'a pas le même besoin de dérisquage isolé que la redirection
    /// stdin/stdout du jalon 9, qui elle avait besoin d'itérer sans dépendre d'aucune autre
    /// classe).</summary>
    public static async Task<ComplianceResultDto> RunRuleAsync(
        ComplianceRuleDto rule, AgentConfig config, ILogger logger, CancellationToken cancellationToken)
    {
        var tempDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "EndpointAgent", "Compliance");
        var scriptPath = Path.Combine(tempDir, $"{Guid.NewGuid():N}.ps1");

        try
        {
            DirectoryHardening.EnsureSecureDirectory(tempDir);
            await File.WriteAllTextAsync(scriptPath, rule.script_content, _utf8NoBom, cancellationToken);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    // -ExecutionPolicy Bypass : sans lui, une politique Restricted/AllSigned sur
                    // le poste ferait échouer TOUT script silencieusement, indiscernable d'une
                    // vraie non-conformité (piège réel trouvé en concevant ce jalon, pas en
                    // testant). Mêmes leçons d'encodage UTF-8 sans BOM que ShellSessionRunner
                    // (jalon 9), réutilisées dès le départ plutôt que redécouvertes.
                    Arguments = $"-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = _utf8NoBom,
                    StandardErrorEncoding = _utf8NoBom,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };

            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            var outputTruncated = false;
            void AppendBounded(StringBuilder sb, string? line)
            {
                if (line is null) return;
                if (sb.Length >= MaxCapturedOutputChars) { outputTruncated = true; return; }
                sb.AppendLine(line);
            }
            process.OutputDataReceived += (_, e) => AppendBounded(stdout, e.Data);
            process.ErrorDataReceived += (_, e) => AppendBounded(stderr, e.Data);

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            var timeoutSeconds = Math.Max(1, config.ComplianceScriptTimeoutSeconds);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                // 🔧 Bug de sécurité corrigé le 2026-09-07 : l'ancien code ne tuait le process
                // QUE si c'était le timeout de CETTE règle qui avait déclenché l'annulation
                // (`when (!cancellationToken.IsCancellationRequested)`). Un arrêt NORMAL du
                // service (ex. `restart_service`, arrêt Windows) pendant l'exécution d'un
                // script tombait dans ce `catch` mais SAUTAIT ce garde, laissant le
                // `powershell.exe` (potentiellement du code fourni par le serveur, exécuté en
                // SYSTEM) orphelin et actif jusqu'à expiration de son propre timeout — l'arrêt
                // du service ne l'arrêtait pas, alors que c'est précisément le geste qu'un
                // admin ferait pour stopper une règle suspecte. Le kill doit avoir lieu dans
                // TOUS les cas d'annulation, peu importe quel jeton l'a déclenchée.
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Le process a peut-être déjà disparu entre-temps — sans conséquence.
                }

                if (cancellationToken.IsCancellationRequested)
                {
                    // Arrêt du service, pas un timeout de règle — propager l'annulation plutôt
                    // que de mentir avec un résultat "Timeout dépassé" ; `RunAsync` l'attrape
                    // déjà via son `catch (Exception)` générique et n'enverra rien au serveur,
                    // cohérent avec un arrêt de service en cours.
                    throw;
                }

                logger.LogWarning("Règle de conformité {Rule} : timeout dépassé ({Seconds}s).", rule.name, timeoutSeconds);
                return new ComplianceResultDto(rule.id, rule.name, null, $"Timeout dépassé ({timeoutSeconds}s).");
            }

            var detail = stdout.ToString().Trim();
            var errText = stderr.ToString().Trim();
            if (errText.Length > 0)
            {
                detail = detail.Length > 0 ? $"{detail}\n[stderr] {errText}" : $"[stderr] {errText}";
            }
            if (outputTruncated)
            {
                detail += "\n[…sortie tronquée, dépassait la limite de capture…]";
            }

            return new ComplianceResultDto(rule.id, rule.name, process.ExitCode == 0, detail);
        }
        // `when (ex is not OperationCanceledException)` : sans cette garde, le `throw;` d'arrêt
        // de service ci-dessus (annulation PROPRE, process déjà tué) serait rattrapé ICI et
        // transformé en un faux "Échec de lancement : A task was canceled." — l'annulation doit
        // continuer de se propager intacte jusqu'à `RunAsync`, qui sait déjà ne rien poster au
        // serveur dans ce cas.
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Échec de LANCEMENT (politique d'exécution malgré -ExecutionPolicy Bypass,
            // interpréteur introuvable...) — erreur d'exécution, PAS une non-conformité.
            logger.LogError(ex, "Échec du lancement de la règle de conformité {Rule}.", rule.name);
            return new ComplianceResultDto(rule.id, rule.name, null, $"Échec de lancement : {ex.Message}");
        }
        finally
        {
            try
            {
                File.Delete(scriptPath);
            }
            catch
            {
                // Toléré — un descripteur momentanément tenu par un processus fils ne doit
                // jamais faire échouer la règle pour un simple souci de nettoyage.
            }
        }
    }

    // Le durcissement DACL (correctif de sécurité du 2026-09-07 — élévation de privilèges
    // locale via %TEMP%\VanitasCompliance, un dossier machine-wide où tout utilisateur standard
    // pouvait pré-créer/pré-posséder le sous-dossier avant le premier cycle) vit désormais dans
    // `Security/DirectoryHardening.cs`, partagé avec `Commands/InstallRunner` (2026-09-08) —
    // même risque de course locale sur un répertoire de travail écrit par SYSTEM puis relu par
    // un process enfant, donc exactement le même remède.
}
