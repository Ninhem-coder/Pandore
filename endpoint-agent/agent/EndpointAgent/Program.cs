using System.Runtime.InteropServices;
using System.Text.Json;
using EndpointAgent;
using EndpointAgent.Communication;
using EndpointAgent.Compliance;
using EndpointAgent.Configuration;
using EndpointAgent.Detection;
using EndpointAgent.Inventory;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

// Mode de test ponctuel (jalon 6) : imprime le résultat brut de HardwareInventoryCollector
// sans passer par le canal de commande ni le serveur — utile pour vérifier que chaque section
// WMI renvoie de vraies valeurs sur CE poste avant de la brancher à une commande. Ne construit
// même pas le host (inutile, aucune config/réseau nécessaire).
if (args.Contains("--hardware-diag"))
{
    var result = HardwareInventoryCollector.Collect();
    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}

// Mode de test ponctuel (jalon 7) : imprime SEULEMENT le ProductCode trouvé pour "Endpoint
// Agent" dans le registre Uninstall — jamais de retrait de certificat, jamais de msiexec réel
// ici, exprès (voir Commands/CommandExecutor.cs::FindOwnProductCode, logique dupliquée ici à
// l'identique plutôt que d'exposer cette méthode juste pour ce test). Sert à confirmer que la
// recherche retrouve bien le VRAI ProductCode actuellement installé AVANT de risquer un vrai
// `msiexec /X` via la commande "uninstall_agent".
if (args.Contains("--find-product-code"))
{
    using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
    using var uninstallKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
    var found = new List<string>();
    if (uninstallKey is not null)
    {
        foreach (var subKeyName in uninstallKey.GetSubKeyNames())
        {
            using var subKey = uninstallKey.OpenSubKey(subKeyName);
            if (subKey?.GetValue("DisplayName") as string == "Endpoint Agent")
            {
                found.Add(subKeyName);
            }
        }
    }
    Console.WriteLine(found.Count switch
    {
        0 => "Aucune entrée \"Endpoint Agent\" trouvée.",
        1 => $"ProductCode trouvé : {found[0]}",
        _ => $"{found.Count} entrées trouvées (état ambigu) : {string.Join(", ", found)}",
    });
    return 0;
}

// Mode de test ponctuel (jalon 9) : valide la technique de redirection stdin/stdout d'un
// process PowerShell persistant + marqueur de fin de commande (Write-Output), SANS toucher au
// serveur ni à ShellSessionRunner — dérisque le point le plus délicat de ce jalon avant de le
// brancher sur quoi que ce soit (même démarche que --hardware-diag/--find-product-code).
if (args.Contains("--shell-diag"))
{
    using var process = new System.Diagnostics.Process
    {
        StartInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoLogo -NoProfile",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = new System.Text.UTF8Encoding(false),
            StandardErrorEncoding = new System.Text.UTF8Encoding(false),
            StandardInputEncoding = new System.Text.UTF8Encoding(false),
            UseShellExecute = false,
            CreateNoWindow = true,
        },
        EnableRaisingEvents = true,
    };

    var results = new List<string>();
    var buffer = new System.Text.StringBuilder();
    string? expectedMarker = null;
    string? expectedEchoSuffix = null;
    TaskCompletionSource<bool>? markerSeen = null;
    var ioLock = new object();

    process.OutputDataReceived += (_, e) =>
    {
        if (e.Data is null) return;
        Console.WriteLine($"[RAW OUT @ {DateTime.Now:HH:mm:ss.fff}] {e.Data}");
        lock (ioLock)
        {
            // 🔧 Deux bugs réels trouvés EN TESTANT (pas devinés) :
            // 1. PowerShell, en mode redirigé, réécrit en écho le PROMPT + la ligne d'entrée
            //    TELLE QU'ENVOYÉE avant même que la commande ne s'exécute — confirmé sur le
            //    flux brut. Cette ligne d'écho contient donc TOUJOURS le marqueur comme
            //    sous-chaîne (il fait partie du texte envoyé), d'où le point 2 : `Contains`
            //    matchait sur l'écho, jamais sur la vraie sortie, décalant tout d'un cran.
            //    Corrigé : `expectedEchoSuffix` (la ligne exacte envoyée, sans le prompt qui
            //    varie selon le répertoire courant) sert à IGNORER cette ligne d'écho — elle ne
            //    doit jamais atterrir dans la sortie affichée à l'admin, pure plomberie interne.
            // 2. Égalité STRICTE (après trim) sur le marqueur, jamais `Contains` — seule la
            //    vraie ligne produite par `Write-Output` ne contient QUE le marqueur.
            if (expectedEchoSuffix is not null && e.Data.EndsWith(expectedEchoSuffix, StringComparison.Ordinal))
            {
                // Écho du prompt+commande — ignoré, jamais bufferisé.
            }
            else if (expectedMarker is not null && e.Data.Contains(expectedMarker, StringComparison.Ordinal))
            {
                var idx = e.Data.IndexOf(expectedMarker, StringComparison.Ordinal);
                var before = e.Data[..idx];
                if (before.Length > 0) buffer.Append(before);
                results.Add(buffer.ToString());
                buffer.Clear();
                markerSeen?.TrySetResult(true);
            }
            else
            {
                buffer.AppendLine(e.Data);
            }
        }
    };
    process.ErrorDataReceived += (_, e) =>
    {
        if (e.Data is not null) Console.WriteLine($"[stderr] {e.Data}");
    };

    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();

    async Task RunOneAsync(string command)
    {
        var marker = $"<<<END-{Guid.NewGuid():N}>>>";
        var sentLine = $"{command}; Write-Output \"{marker}\"; [Console]::Out.Flush()";
        lock (ioLock) { expectedMarker = marker; expectedEchoSuffix = sentLine; markerSeen = new TaskCompletionSource<bool>(); }
        await process.StandardInput.WriteLineAsync(sentLine);
        await process.StandardInput.FlushAsync();
        await Task.WhenAny(markerSeen.Task, Task.Delay(TimeSpan.FromSeconds(10)));
    }

    await RunOneAsync("Get-ChildItem C:\\Windows\\System32");
    await RunOneAsync("Write-Output \"apres-ls-ok\"");

    for (int i = 0; i < results.Count; i++)
    {
        Console.WriteLine($"--- résultat #{i + 1} ---");
        Console.WriteLine(results[i].Trim());
    }

    process.Kill(entireProcessTree: true);
    Console.WriteLine($"Process tué proprement (entireProcessTree). HasExited={process.HasExited}");
    return 0;
}

// Mode de test ponctuel (jalon 11) : valide le contrat exit-code/timeout/nettoyage du fichier
// temporaire de `Compliance/ComplianceRunner.RunRuleAsync` SANS serveur ni catalogue réel —
// même précédent que `--hardware-diag`/`--find-product-code`, mais réutilise directement le
// VRAI code d'exécution plutôt que d'en dupliquer une copie (voir le commentaire sur
// `RunRuleAsync`). Cinq scripts choisis pour couvrir les cas réels attendus — dont le VRAI
// piège du contrat exit-code, précisé EN TESTANT (pas deviné à l'avance, voir le commentaire
// d'en-tête de ComplianceRunner.cs) : une exception NON INTERCEPTÉE (`throw`) échoue déjà
// correctement sur PowerShell 5.1 (confirmé ci-dessous, diag-4), le vrai piège est une erreur
// NON TERMINANTE (`Write-Error` sans `-ErrorAction Stop`, diag-5) qui reste CONFORME à tort.
if (args.Contains("--compliance-diag"))
{
    var config = new AgentConfig { ComplianceScriptTimeoutSeconds = 5 };
    var logger = NullLogger.Instance;

    var rules = new[]
    {
        new ComplianceRuleDto("diag-1", "Conforme (exit 0)", "Write-Output 'tout va bien'; exit 0"),
        new ComplianceRuleDto("diag-2", "Non conforme (exit 1)", "Write-Output 'probleme detecte'; exit 1"),
        new ComplianceRuleDto("diag-3", "Timeout (boucle infinie)", "while ($true) { Start-Sleep -Seconds 1 }"),
        new ComplianceRuleDto("diag-4", "Exception interceptée par PowerShell (throw, SANS exit explicite)", "throw 'boom'"),
        new ComplianceRuleDto("diag-5", "Piège réel : erreur NON terminante (Write-Error, SANS exit explicite)", "Write-Error 'probleme signale mais pas de throw/exit'"),
    };

    foreach (var rule in rules)
    {
        var result = await ComplianceRunner.RunRuleAsync(rule, config, logger, CancellationToken.None);
        Console.WriteLine($"--- {result.rule_name} ---");
        Console.WriteLine($"compliant = {result.compliant?.ToString() ?? "null (erreur d'exécution)"}");
        Console.WriteLine($"detail = {result.detail}");
        Console.WriteLine();
    }
    return 0;
}

// Mode de test ponctuel (2026-09-08, revue de sécurité — voir ServerClient.cs::
// CreateAuthenticatedHandler) : charge un fichier de certificat PEM/CER et affiche s'il
// passerait la vérification EKU=serverAuth + hôte attendu, SANS passer par une vraie connexion
// TLS. Usage : --cert-validation-diag <chemin-cert> <hote-attendu>
// (ex. --cert-validation-diag data/ca/server.pem localhost, exécuté depuis endpoint-agent/server/
// pour tester le VRAI certificat serveur déjà déployé).
if (args.Contains("--cert-validation-diag"))
{
    var idx = Array.IndexOf(args, "--cert-validation-diag");
    var certPath = args.Length > idx + 1 ? args[idx + 1] : null;
    var expectedHost = args.Length > idx + 2 ? args[idx + 2] : null;
    if (certPath is null || expectedHost is null)
    {
        Console.WriteLine("Usage: --cert-validation-diag <chemin-cert> <hote-attendu>");
        return 1;
    }

    using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath);
    var hasEku = ServerClient.HasServerAuthEku(cert);
    var hostMatches = ServerClient.MatchesRequestedHost(cert, expectedHost);
    Console.WriteLine($"Subject       = {cert.Subject}");
    Console.WriteLine($"EKU serverAuth = {hasEku}");
    Console.WriteLine($"Hôte attendu   = {expectedHost}");
    Console.WriteLine($"Hôte correspond = {hostMatches}");
    Console.WriteLine($"ACCEPTÉ globalement = {hasEku && hostMatches}");
    return 0;
}

// EndpointAgent.exe est un exécutable console (nécessaire pour que `dotnet run -- --enroll`
// affiche sa sortie pendant les tests manuels) — mais un Windows Service basé sur ce template
// peut quand même faire apparaître une fenêtre console (défaut documenté du template Worker
// Service), invisible normalement (session 0) mais pas toujours selon le contexte de démarrage
// — repéré en testant le jalon 5. `IsWindowsService()` ne vaut TRUE que lancé par le vrai
// Service Control Manager, jamais en `dotnet run`/exécution manuelle : aucun changement pour
// les tests interactifs habituels de ce projet.
var builder = Host.CreateApplicationBuilder(args);

if (WindowsServiceHelpers.IsWindowsService())
{
    HideConsoleWindow();
}

// Permet de tourner comme un vrai service Windows une fois installé (sc.exe create / MSI au
// jalon 5) — reste un simple exécutable console pendant le dev tant qu'il n'est pas
// réellement lancé par le Service Control Manager, aucun changement de comportement.
builder.Services.AddWindowsService();

builder.Services.Configure<AgentConfig>(builder.Configuration.GetSection(AgentConfig.SectionName));
// ServerClient construit son propre HttpClient par appel (le certificat CLIENT à présenter
// change selon le contexte, voir Communication/ServerClient.cs) — pas de client HTTP partagé
// à enregistrer ici, juste sa config.
builder.Services.AddSingleton<ServerClient>();

if (args.Contains("--enroll"))
{
    // Mode ponctuel pour le tout premier lancement sur un poste : génère la paire de clés +
    // CSR, consomme le token d'enrôlement de la config, importe le certificat signé dans le
    // magasin Windows (Cert:\LocalMachine\My — voir CertificateStore), puis quitte sans
    // démarrer le Worker. À relancer sans cet argument ensuite pour le fonctionnement normal
    // (boucle périodique).
    using var enrollHost = builder.Build();
    var config = enrollHost.Services.GetRequiredService<IOptions<AgentConfig>>().Value;

    // Le token peut aussi être fourni via `--token=xxx` (enrôlement manuel sans toucher à
    // appsettings.json — l'installation via MSI, elle, passe par une variable d'environnement
    // machine, voir Worker.cs::TryAutoEnrollAsync, pas cet argument). Priorité sur la config si
    // les deux sont présents. Note : `Host.CreateApplicationBuilder` inclut en principe un
    // provider de configuration en ligne de commande, mais celui-ci s'est avéré NE PAS
    // remonter la valeur en testant (`--Agent:EnrollmentToken=...` restait vide une fois lié) —
    // cause non élucidée, contournée ici par un parsing explicite plutôt que d'en dépendre.
    var tokenArg = args.FirstOrDefault(a => a.StartsWith("--token=", StringComparison.Ordinal));
    var enrollmentToken = tokenArg is not null ? tokenArg["--token=".Length..] : config.EnrollmentToken;

    if (string.IsNullOrWhiteSpace(config.ServerUrl))
    {
        Console.Error.WriteLine("Agent:ServerUrl n'est pas renseigné dans appsettings.json.");
        return 1;
    }
    if (string.IsNullOrWhiteSpace(enrollmentToken))
    {
        Console.Error.WriteLine("Aucun token d'enrôlement : ni Agent:EnrollmentToken dans appsettings.json, ni --token= en ligne de commande.");
        return 1;
    }

    var serverClient = enrollHost.Services.GetRequiredService<ServerClient>();

    try
    {
        var result = await serverClient.EnrollAsync(enrollmentToken, Environment.MachineName, CancellationToken.None);
        Console.WriteLine($"Enrôlé avec succès. AgentId = {result.AgentId}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Échec de l'enrôlement : {ex.Message}");
        return 1;
    }
}

builder.Services.AddHostedService<Worker>();
builder.Services.AddHostedService<CommandPoller>();
builder.Services.AddHostedService<ComplianceLoop>();
builder.Services.AddHostedService<PatchLoop>();

// Détection d'activités suspectes (nouveau jalon, 2026-09-14) — lu directement depuis
// `builder.Configuration` (pas depuis un service DI, le host n'est pas encore construit à ce
// stade) pour décider QUELS services enregistrer : un watcher désactivé n'est même pas démarré,
// pas seulement inactif (coupe-circuit `SuspiciousActivityEnabled` + interrupteurs par
// catégorie, voir le plan §1 "Config").
var suspiciousActivityConfig = builder.Configuration.GetSection(AgentConfig.SectionName).Get<AgentConfig>() ?? new AgentConfig();
if (suspiciousActivityConfig.SuspiciousActivityEnabled)
{
    builder.Services.AddSingleton<ProcessNameCache>();
    builder.Services.AddSingleton<SuspiciousEventBuffer>();

    // `SuspiciousRulesProvider` doit être à la fois un SINGLETON (les watchers lisent `.Current`
    // directement par injection) ET un `BackgroundService` démarré par le host — enregistrer
    // `AddHostedService<SuspiciousRulesProvider>()` en plus de `AddSingleton<...>()` créerait une
    // DEUXIÈME instance distincte (chaque enregistrement a son propre cycle de vie DI), d'où le
    // factory `AddHostedService(sp => sp.GetRequiredService<...>())` qui réutilise EXPLICITEMENT
    // l'instance singleton déjà enregistrée.
    builder.Services.AddSingleton<SuspiciousRulesProvider>();
    builder.Services.AddHostedService(sp => sp.GetRequiredService<SuspiciousRulesProvider>());

    builder.Services.AddHostedService<AuditPolicyEnsurer>();
    builder.Services.AddHostedService<SuspiciousEventUploader>();

    if (suspiciousActivityConfig.ProcessDetectionEnabled || suspiciousActivityConfig.EventLogDetectionEnabled)
    {
        // Un seul watcher physique pour les 2 signaux (même canal Security) — voir le plan.
        builder.Services.AddHostedService<ProcessAndEventLogWatcher>();
    }
    if (suspiciousActivityConfig.NetworkDetectionEnabled)
    {
        builder.Services.AddHostedService<NetworkConnectionPoller>();
    }
    if (suspiciousActivityConfig.UsbDetectionEnabled)
    {
        builder.Services.AddHostedService<UsbActivityWatcher>();
    }
}

using var host = builder.Build();
await host.RunAsync();
return 0;

/// <summary>Masque (sans la libérer) la fenêtre console éventuellement allouée à ce process —
/// `FreeConsole()` casserait `Console.WriteLine` pour le reste de l'exécution (les logs
/// `ILogger` par défaut écrivent sur la console), alors que `ShowWindow(..., SW_HIDE)` laisse
/// le flux fonctionner normalement, juste invisible.</summary>
static void HideConsoleWindow()
{
    var handle = GetConsoleWindow();
    if (handle != IntPtr.Zero)
    {
        ShowWindow(handle, SW_HIDE);
    }
}

partial class Program
{
    private const int SW_HIDE = 0;

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
