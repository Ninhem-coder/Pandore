using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using EndpointAgent.Security;

namespace EndpointAgent.Commands;

/// <summary>
/// Exécution d'un installeur applicatif poussé depuis le dashboard, via un groupe ou un poste
/// unique (2026-09-08, "un push d'application un peu comme dans Pandore, via les groupes").
///
/// CONTRAIREMENT à <c>Compliance/ComplianceRunner.StartOnDemand</c> et
/// <c>ShellSessionRunner.Start</c> (les 2 seuls handlers fire-and-forget de ce projet, tous deux
/// justifiés par une durée indéfinie/périodique et un mécanisme de résultat séparé), ce handler
/// reste SYNCHRONE — comme "system_diagnostic"/"hardware_inventory" : <c>CommandExecutor</c>
/// attend le vrai résultat (succès/échec + sortie du process) et le rapporte directement dans
/// la ligne <c>AgentCommand</c>, sans rien construire de plus. Une installation a une durée
/// bornée et déterministe, contrairement à un shell interactif ou un cycle périodique — pas
/// besoin de découpler la commande de son résultat.
///
/// Même gabarit que <see cref="Compliance.ComplianceRunner.RunRuleAsync"/> : répertoire de
/// travail dédié sous `%ProgramData%`, DACL durcie via <see cref="DirectoryHardening"/> (même
/// correctif de sécurité du 2026-09-07, même risque de course locale), process enfant borné par
/// un timeout, nettoyage systématique en `finally`.
/// </summary>
public static class InstallRunner
{
    private static readonly UTF8Encoding _utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    // 🔧 Audit de sécurité du 2026-09-16 : stdout/stderr accumulés sans plafond pendant toute la
    // durée du process (jusqu'à `InstallTimeoutSeconds`, 600s par défaut) — un installeur verbeux
    // pouvait faire grossir la mémoire de l'agent et la colonne `AgentCommand.result` (Text non
    // bornée côté serveur) de façon disproportionnée. Même seuil d'esprit que
    // `EventLogFetcher.DescriptionMaxLength`/`XmlMaxLength`, adapté à de la sortie de process
    // (plus verbeuse qu'une description d'événement).
    private const int MaxCapturedOutputChars = 100_000;

    private sealed record InstallParametersDto(
        string installer_id, string original_filename, string install_command, string sha256);

    public static async Task<(bool Success, string? Result, bool RequestStop, Action? PostReportAction)> RunAsync(
        string? parametersJson, ServerClient serverClient, AgentConfig config, ILogger logger, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(parametersJson))
        {
            return (false, "Commande install_application reçue sans paramètres.", false, null);
        }

        InstallParametersDto parameters;
        try
        {
            parameters = JsonSerializer.Deserialize<InstallParametersDto>(parametersJson)
                ?? throw new InvalidOperationException("Paramètres vides.");
        }
        catch (Exception ex)
        {
            return (false, $"Paramètres invalides : {ex.Message}", false, null);
        }

        var workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "EndpointAgent", "Installs", Guid.NewGuid().ToString("N"));
        // Path.GetFileName (pas parameters.original_filename brut) — revue de sécurité du
        // 2026-09-09 : le serveur valide déjà ce nom, mais si un nom "drive-relative" Windows
        // (ex. "C:secret.txt") passait quand même, Path.Combine l'aurait traité comme un
        // chemin ABSOLU et ignoré ENTIÈREMENT `workDir`, écrivant hors du répertoire durci par
        // DirectoryHardening. Défense en profondeur — ne jamais faire confiance uniquement à la
        // validation serveur pour un chemin de fichier local écrit/exécuté en SYSTEM.
        var destPath = Path.Combine(workDir, Path.GetFileName(parameters.original_filename));

        try
        {
            DirectoryHardening.EnsureSecureDirectory(workDir);

            logger.LogInformation("Téléchargement de l'installeur {InstallerId} ({Filename})...",
                parameters.installer_id, parameters.original_filename);
            await serverClient.DownloadInstallerAsync(parameters.installer_id, destPath, cancellationToken);

            var actualSha256 = await ComputeSha256Async(destPath, cancellationToken);
            if (!string.Equals(actualSha256, parameters.sha256, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning(
                    "SHA-256 de l'installeur téléchargé ne correspond pas (attendu {Expected}, obtenu {Actual}) — abandon.",
                    parameters.sha256, actualSha256);
                return (false, "Échec de vérification d'intégrité (SHA-256 ne correspond pas) — installation abandonnée.", false, null);
            }

            return await RunInstallCommandAsync(parameters.install_command, workDir, config, logger, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Échec du push d'application ({Filename}).", parameters.original_filename);
            return (false, $"Échec : {ex.Message}", false, null);
        }
        finally
        {
            try
            {
                Directory.Delete(workDir, recursive: true);
            }
            catch
            {
                // Toléré — un descripteur momentanément tenu par le process d'installation (ex.
                // un installeur qui se relance lui-même en arrière-plan) ne doit jamais faire
                // échouer la commande pour un simple souci de nettoyage.
            }
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    /// <summary>Lance <paramref name="installCommand"/> via `cmd.exe /c` — la commande vient du
    /// catalogue d'installeurs (texte déjà tapé par un admin à l'upload, ex. `msiexec /i
    /// "7z2602-x64.msi" /qn /norestart` ou `powershell -executionpolicy bypass -file
    /// ".\install.ps1"`), laisser `cmd.exe` la parser lui-même évite de réinventer un découpage
    /// exécutable/arguments qui gérerait mal les guillemets. `WorkingDirectory` = le répertoire
    /// où l'installeur vient d'être téléchargé, sous EXACTEMENT le nom référencé par la
    /// commande (même motif que `Pandore.msi` + `msiexec /i Pandore.msi ...` côté Pandore).</summary>
    private static async Task<(bool, string?, bool, Action?)> RunInstallCommandAsync(
        string installCommand, string workDir, AgentConfig config, ILogger logger, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {installCommand}",
                WorkingDirectory = workDir,
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

        logger.LogInformation("Lancement de l'installation : {Command}", installCommand);
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var timeoutSeconds = Math.Max(1, config.InstallTimeoutSeconds);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException)
        {
            // Même correctif que ComplianceRunner (2026-09-07) : le kill doit se déclencher pour
            // TOUTE source d'annulation (timeout de CETTE installation OU arrêt du service),
            // jamais seulement la première.
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
                throw;
            }

            logger.LogWarning("Installation : timeout dépassé ({Seconds}s).", timeoutSeconds);
            return (false, $"Timeout dépassé ({timeoutSeconds}s) — installation interrompue.", false, null);
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
        var summary = $"Code de sortie {process.ExitCode}.";
        detail = detail.Length > 0 ? $"{summary}\n{detail}" : summary;

        return (process.ExitCode == 0, detail, false, null);
    }
}
