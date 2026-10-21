using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using EndpointAgent.Security;

namespace EndpointAgent.Commands;

/// <summary>
/// Mise à jour de l'agent lui-même, poussée depuis Vanitas (2026-09-11) — demande de Nicolas
/// suite à la question "la mise à jour de l'agent via Vanitas c'est bien d'actu ?" (réponse :
/// non, jusqu'ici entièrement manuelle). Combine les deux mécanismes déjà éprouvés séparément
/// ailleurs dans ce fichier plutôt que d'en inventer un troisième :
/// - le téléchargement + la vérification SHA-256 SYNCHRONES de <see cref="InstallRunner"/>
///   (une mise à jour a une durée bornée pour CETTE étape, comme une installation classique) ;
/// - le report DIFFÉRÉ via <c>PostReportAction</c> de <c>CommandExecutor.UninstallAgent</c> pour
///   la partie qui tue le process courant — lancer `msiexec /i` DANS ce handler, avant que le
///   rapport de résultat n'ait fini de partir, reproduirait exactement le bug déjà rencontré et
///   corrigé sur "uninstall_agent" (le service s'arrête pendant que le POST de résultat est
///   encore en vol, la commande reste "running" indéfiniment côté serveur malgré un succès réel).
///
/// AUCUNE recherche de ProductCode ici, contrairement à "uninstall_agent" : le mécanisme
/// `&lt;MajorUpgrade&gt;` déjà configuré dans `Installer/Product.wxs` (UpgradeCode STABLE)
/// reconnaît tout seul l'installation existante dès qu'on lui présente un nouveau `.msi` — un
/// simple `msiexec /i &lt;fichier&gt; /qn /norestart` suffit, WiX orchestre l'arrêt de
/// l'ancienne version, le remplacement des fichiers et le redémarrage du service.
///
/// Le certificat mTLS de l'agent N'EST PAS retiré (contrairement à "uninstall_agent") : il vit
/// dans le magasin de certificats Windows (<see cref="CertificateStore"/>), jamais touché par
/// les fichiers du MSI — il survit tel quel à la mise à jour, aucun ré-enrôlement nécessaire.
/// </summary>
public static class UpdateRunner
{
    private sealed record UpdateParametersDto(string package_id, string original_filename, string sha256);

    public static async Task<(bool Success, string? Result, bool RequestStop, Action? PostReportAction)> RunAsync(
        string? parametersJson, ServerClient serverClient, ILogger logger, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(parametersJson))
        {
            return (false, "Commande update_agent reçue sans paramètres.", false, null);
        }

        UpdateParametersDto parameters;
        try
        {
            parameters = JsonSerializer.Deserialize<UpdateParametersDto>(parametersJson)
                ?? throw new InvalidOperationException("Paramètres vides.");
        }
        catch (Exception ex)
        {
            return (false, $"Paramètres invalides : {ex.Message}", false, null);
        }

        // Répertoire de travail dédié, même DACL durcie que InstallRunner/ComplianceRunner
        // (2026-09-07, même risque de course locale sur un dossier écrit par SYSTEM). Jamais
        // nettoyé en `finally` ICI, contrairement à InstallRunner : le fichier doit survivre
        // jusqu'au lancement RÉEL de `msiexec /i` dans `PostReportAction`, qui s'exécute
        // APRÈS le retour de cette méthode — un `Directory.Delete` synchrone ici supprimerait
        // le `.msi` avant que msiexec n'ait pu le lire. Limitation connue et acceptée (même
        // esprit que l'absence de purge automatique déjà documentée pour d'autres répertoires
        // de travail de ce projet, côté Pandore comme ici) : un dossier orphelin par mise à
        // jour effectuée, à nettoyer manuellement si ça s'accumule.
        var workDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "EndpointAgent", "Updates", Guid.NewGuid().ToString("N"));
        var destPath = Path.Combine(workDir, Path.GetFileName(parameters.original_filename));

        try
        {
            DirectoryHardening.EnsureSecureDirectory(workDir);

            logger.LogInformation("Téléchargement du paquet de mise à jour {PackageId} ({Filename})...",
                parameters.package_id, parameters.original_filename);
            await serverClient.DownloadAgentPackageAsync(parameters.package_id, destPath, cancellationToken);

            var actualSha256 = await ComputeSha256Async(destPath, cancellationToken);
            if (!string.Equals(actualSha256, parameters.sha256, StringComparison.OrdinalIgnoreCase))
            {
                logger.LogWarning(
                    "SHA-256 du paquet de mise à jour téléchargé ne correspond pas (attendu {Expected}, obtenu {Actual}) — abandon.",
                    parameters.sha256, actualSha256);
                try { Directory.Delete(workDir, recursive: true); } catch { /* best effort */ }
                return (false, "Échec de vérification d'intégrité (SHA-256 ne correspond pas) — mise à jour abandonnée.", false, null);
            }

            void LaunchUpdate()
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "msiexec.exe",
                    Arguments = $"/i \"{destPath}\" /qn /norestart",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                });
            }

            return (
                true,
                $"Mise à jour lancée ({parameters.original_filename}) — le service va s'arrêter puis redémarrer automatiquement dans la nouvelle version. Impossible de confirmer le succès après coup : l'agent vient de déclencher sa propre mise à jour.",
                false,
                LaunchUpdate);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Échec de la mise à jour de l'agent ({Filename}).", parameters.original_filename);
            try { Directory.Delete(workDir, recursive: true); } catch { /* best effort */ }
            return (false, $"Échec : {ex.Message}", false, null);
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
