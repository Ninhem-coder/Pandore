using System.Diagnostics;
using System.Text;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace EndpointAgent.Detection;

/// <summary>
/// Active de façon IDEMPOTENTE, une seule fois au démarrage, les sous-catégories d'audit
/// nécessaires à la détection d'activités suspectes (nouveau jalon, 2026-09-14) — un poste non
/// durci n'a pas ces sous-catégories activées par défaut (voir le plan §1).
///
/// `IHostedService` (pas `BackgroundService`) : c'est une vérification PONCTUELLE au démarrage,
/// pas une boucle — `StartAsync` fait le travail et retourne, `StopAsync` est un no-op.
///
/// ⚠️ Limite assumée, documentée dans le plan et non "résolue" ici : une GPO de domaine qui force
/// ces sous-catégories à "désactivé" l'emporte à chaque `gpupdate` — coordination requise avec
/// l'administration AD, hors du contrôle de l'agent. Cette classe ne fait JAMAIS planter l'agent
/// si l'activation échoue, seulement un avertissement loggé.
///
/// ⚠️ Autre limite non couverte ici (hors du périmètre EXACT demandé — "Process Creation" et
/// "Account Management" uniquement) : la catégorie "Logon/Logoff" (sous-catégorie "Logon", GUID
/// {0CCE9215-69AE-11D9-BED3-505054503030}), nécessaire pour que 4624/4625 soient réellement
/// journalisés, N'EST PAS forcée par cette classe. Sur la plupart des postes elle est déjà
/// activée par la stratégie d'audit de base par défaut de Windows, mais un poste durci qui l'a
/// explicitement désactivée ferait taire silencieusement les signaux RDP/échecs
/// d'authentification malgré un code de détection par ailleurs correct — à surveiller en
/// vérification finale (voir le plan §Vérification).
/// </summary>
public sealed class AuditPolicyEnsurer : IHostedService
{
    private readonly ILogger<AuditPolicyEnsurer> _logger;
    private readonly AgentConfig _config;

    // GUID des sous-catégories d'audit ciblées — jamais le NOM textuel ("Process Creation",
    // "Gestion des comptes utilisateur"...) : `auditpol` accepte le GUID indépendamment de la
    // langue d'affichage de Windows, alors que les noms textuels sont LOCALISÉS (piège réel d'un
    // outil qui tournerait sur un parc mixte FR/EN, pas deviné — évité dès la conception plutôt
    // que découvert en test sur un poste non anglophone).
    private const string ProcessCreationSubcategoryGuid = "{0CCE922B-69AE-11D9-BED3-505054503030}";
    private const string UserAccountManagementSubcategoryGuid = "{0CCE9235-69AE-11D9-BED3-505054503030}";
    private const string SecurityGroupManagementSubcategoryGuid = "{0CCE9237-69AE-11D9-BED3-505054503030}";

    public AuditPolicyEnsurer(ILogger<AuditPolicyEnsurer> logger, IOptions<AgentConfig> config)
    {
        _logger = logger;
        _config = config.Value;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_config.SuspiciousActivityEnabled)
        {
            return;
        }

        if (_config.ProcessDetectionEnabled)
        {
            await EnsureSubcategoryEnabledAsync("Process Creation", ProcessCreationSubcategoryGuid, cancellationToken);
            EnsureCommandLineLoggingRegistryKey();
        }

        if (_config.EventLogDetectionEnabled)
        {
            // "Account Management" du plan est en réalité une CATÉGORIE (6 sous-catégories) —
            // seules les 2 nécessaires à 4720 (création de compte) et 4732 (ajout à un groupe)
            // sont activées ici, plus précis que d'activer toute la catégorie pour un besoin qui
            // ne couvre que ces deux événements.
            await EnsureSubcategoryEnabledAsync("User Account Management", UserAccountManagementSubcategoryGuid, cancellationToken);
            await EnsureSubcategoryEnabledAsync("Security Group Management", SecurityGroupManagementSubcategoryGuid, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task EnsureSubcategoryEnabledAsync(string displayName, string subcategoryGuid, CancellationToken cancellationToken)
    {
        try
        {
            var getOutput = await RunAuditPolAsync($"/get /subcategory:\"{subcategoryGuid}\"", cancellationToken);

            // Parsing best-effort : la sortie d'`auditpol /get` est un texte LOCALISÉ (les
            // libellés "Success"/"No Auditing" deviennent p. ex. "Succès"/"Aucun audit" sur un
            // Windows FR) — plutôt que de risquer un faux "déjà activé" sur un OS non anglophone,
            // toute sortie qui ne contient pas de façon certaine un jeton anglais reconnu de
            // succès est traitée comme "état indéterminé" et déclenche `/set` quand même :
            // idempotent et sans effet de bord si c'était déjà activé.
            if (LooksAlreadyEnabled(getOutput))
            {
                _logger.LogInformation("Stratégie d'audit \"{Name}\" déjà activée (Success).", displayName);
                return;
            }

            var setOutput = await RunAuditPolAsync($"/set /subcategory:\"{subcategoryGuid}\" /success:enable", cancellationToken);
            if (LooksLikeAuditPolFailure(setOutput))
            {
                _logger.LogWarning(
                    "Échec de l'activation de la stratégie d'audit \"{Name}\" (sortie auditpol : {Output}) — " +
                    "une GPO de domaine force peut-être ce réglage ; coordination requise avec l'administration AD.",
                    displayName, setOutput);
            }
            else
            {
                _logger.LogInformation("Stratégie d'audit \"{Name}\" activée.", displayName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Échec de la vérification/activation de la stratégie d'audit \"{Name}\" — la détection correspondante " +
                "pourra rester silencieuse tant que ce n'est pas corrigé (GPO ou activation manuelle).", displayName);
        }
    }

    private static bool LooksAlreadyEnabled(string output) =>
        output.Contains("Success", StringComparison.OrdinalIgnoreCase) &&
        !output.Contains("No Auditing", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeAuditPolFailure(string output) =>
        output.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("failed", StringComparison.OrdinalIgnoreCase);

    /// <summary>Clé registre `ProcessCreationIncludeCmdLine_Enabled=1` (voir le plan) — sans
    /// elle, un 4688 est journalisé mais SANS la ligne de commande (`CommandLine` reste vide),
    /// rendant inopérants tous les matchs LOLBin/persistance/chemin suspect qui inspectent la
    /// ligne de commande. `CreateSubKey` crée les clés intermédiaires manquantes si besoin (même
    /// registre HKLM que le reste de l'agent, vue 64 bits explicite comme ailleurs dans ce
    /// projet — voir Program.cs `--find-product-code`).</summary>
    private void EnsureCommandLineLoggingRegistryKey()
    {
        const string KeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
        const string ValueName = "ProcessCreationIncludeCmdLine_Enabled";

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.CreateSubKey(KeyPath, writable: true);
            var current = key?.GetValue(ValueName);
            if (current is int existing && existing == 1)
            {
                _logger.LogInformation("Journalisation de la ligne de commande (4688) déjà activée.");
                return;
            }

            key?.SetValue(ValueName, 1, RegistryValueKind.DWord);
            _logger.LogInformation("Journalisation de la ligne de commande (4688) activée ({KeyPath}\\{ValueName}).", KeyPath, ValueName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Échec de l'activation de la clé registre {KeyPath}\\{ValueName} — les événements 4688 seront " +
                "journalisés SANS ligne de commande, dégradant les détections LOLBin/persistance/chemin suspect.",
                KeyPath, ValueName);
        }
    }

    /// <summary>Lance `auditpol.exe` et capture stdout+stderr — même style try/catch que
    /// <c>Compliance/ComplianceRunner.RunRuleAsync</c>, mais sans fichier temporaire (arguments
    /// passés directement, pas de script).</summary>
    private static async Task<string> RunAuditPolAsync(string arguments, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "auditpol.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            },
        };

        var stdout = new StringBuilder();
        process.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        process.ErrorDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        await process.WaitForExitAsync(cancellationToken);

        return stdout.ToString();
    }
}
