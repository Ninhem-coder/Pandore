using System.Formats.Asn1;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using EndpointAgent.Configuration;
using EndpointAgent.Detection;
using EndpointAgent.Inventory;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Communication;

public sealed record InstalledAppInfo(string Name, string? Version, string? Publisher, string? InstallDate);

public sealed record EnrollResult(string AgentId);

/// <summary>
/// Client HTTP vers le serveur de contrôle — enrôlement, remontée d'inventaire et
/// renouvellement de certificat, tous authentifiés par mTLS depuis le jalon 3 (plus de token
/// Bearer). Construit un <see cref="HttpClient"/> dédié par appel plutôt qu'un client partagé
/// injecté : le certificat CLIENT à présenter change selon le contexte (aucun à l'enrôlement,
/// le certificat courant de l'agent ensuite), et .NET ne permet pas de changer le handler d'un
/// HttpClient déjà construit. Sans conséquence vu la fréquence d'appel de cet agent (quelques
/// requêtes toutes les heures) — pas un serveur sous charge où réutiliser les sockets compterait.
/// </summary>
public sealed class ServerClient
{
    private readonly AgentConfig _config;
    private readonly ILogger<ServerClient> _logger;

    public ServerClient(IOptions<AgentConfig> config, ILogger<ServerClient> logger)
    {
        _config = config.Value;
        _logger = logger;
    }

    /// <summary>
    /// Premier enrôlement : aucun certificat agent n'existe encore, et le certificat de la CA
    /// n'a lui non plus jamais été vu par cette machine — la validation du certificat SERVEUR
    /// est donc délibérément permissive à CET appel précis. La confiance initiale repose sur le
    /// token d'enrôlement à usage unique (transmis hors bande, jalon 1), pas sur la chaîne TLS.
    /// Toute requête suivante (inventaire, renouvellement) valide strictement le serveur contre
    /// la CA reçue ici — limite connue et acceptée du bootstrap, du même ordre que la confiance
    /// au premier contact (TOFU) d'un client SSH.
    /// </summary>
    public async Task<EnrollResult> EnrollAsync(string enrollmentToken, string hostname, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Enrôlement auprès de {ServerUrl}...", _config.ServerUrl);

        var (privateKey, csrPem) = CertificateStore.GenerateKeyAndCsr();
        try
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            };
            using var client = CreateClient(handler);

            var response = await client.PostAsJsonAsync(
                "/enroll",
                new { enrollment_token = enrollmentToken, hostname, csr_pem = csrPem },
                cancellationToken);
            await EnsureSuccessAsync(response, cancellationToken);

            var payload = await response.Content.ReadFromJsonAsync<EnrollResponseDto>(cancellationToken: cancellationToken)
                ?? throw new InvalidOperationException("Réponse d'enrôlement vide ou invalide.");

            CertificateStore.ImportCertificate(privateKey, payload.certificate_pem);
            CertificateStore.SaveCaCertificate(payload.ca_certificate_pem);

            return new EnrollResult(payload.agent_id);
        }
        finally
        {
            privateKey.Dispose();
        }
    }

    /// <summary>Renouvelle le certificat de l'agent (même clé, nouveau certificat) — authentifié
    /// par le certificat ACTUEL, encore valide, présenté en mTLS. Voir Worker.cs pour le
    /// déclenchement (surveillance de l'expiration).</summary>
    public async Task RenewAsync(string agentId, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");

        var (privateKey, csrPem) = CertificateStore.GenerateKeyAndCsr();
        try
        {
            using var handler = CreateAuthenticatedHandler(currentCert);
            using var client = CreateClient(handler);

            _logger.LogInformation("Renouvellement du certificat (agent {AgentId})...", agentId);
            var response = await client.PostAsJsonAsync(
                $"/agents/{agentId}/renew",
                new { csr_pem = csrPem },
                cancellationToken);
            await EnsureSuccessAsync(response, cancellationToken);

            var payload = await response.Content.ReadFromJsonAsync<RenewResponseDto>(cancellationToken: cancellationToken)
                ?? throw new InvalidOperationException("Réponse de renouvellement vide ou invalide.");

            CertificateStore.ImportCertificate(privateKey, payload.certificate_pem);
            _logger.LogInformation("Certificat renouvelé avec succès.");
        }
        finally
        {
            privateKey.Dispose();
        }
    }

    /// <summary><paramref name="osInfo"/> (jalon EOL, 2026-09-08) est optionnel côté serveur
    /// (`InventoryPushRequest`, `os_caption`/`os_version`/`os_build_number` tous nullable) —
    /// `null` ici (échec du collecteur WMI, voir `OsInfoCollector`) envoie simplement ces 3
    /// champs à `null` dans le corps, jamais une erreur. <paramref name="agentVersion"/> (jalon
    /// traçabilité de version, 2026-09-08) même contrat optionnel.</summary>
    public async Task PushInventoryAsync(
        string agentId,
        IReadOnlyList<InstalledAppInfo> apps,
        OsInfo? osInfo,
        string? agentVersion,
        CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        _logger.LogInformation("Envoi de l'inventaire ({Count} applications)...", apps.Count);
        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/inventory",
            new
            {
                apps = apps.Select(a => new
                {
                    name = a.Name,
                    version = a.Version,
                    publisher = a.Publisher,
                    install_date = a.InstallDate,
                }),
                os_caption = osInfo?.Caption,
                os_version = osInfo?.Version,
                os_build_number = osInfo?.BuildNumber,
                os_architecture = osInfo?.Architecture,
                os_registered_user = osInfo?.RegisteredUser,
                os_install_date = osInfo?.InstallDate,
                os_utc_offset = osInfo?.UtcOffset,
                agent_version = agentVersion,
            },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Commandes en attente pour cet agent (jalon 4) — le serveur les marque
    /// "running" au moment où il les sert, elles ne sont donc renvoyées qu'une seule fois.</summary>
    public async Task<IReadOnlyList<PendingCommand>> FetchPendingCommandsAsync(string agentId, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.GetAsync($"/agents/{agentId}/commands/pending", cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        var payload = await response.Content.ReadFromJsonAsync<List<PendingCommandDto>>(cancellationToken: cancellationToken)
            ?? new List<PendingCommandDto>();

        return payload.Select(p => new PendingCommand(p.id, p.command_type, p.parameters)).ToList();
    }

    /// <summary>Rapporte le résultat d'exécution d'une commande (jalon 4).</summary>
    public async Task ReportCommandResultAsync(
        string agentId,
        int commandId,
        bool success,
        string? result,
        CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/commands/{commandId}/result",
            new { success, result },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Canal mTLS réutilisable pour toute la durée d'une session shell (🔧 audit
    /// sécurité/perf du 2026-09-16) — CONTRAIREMENT au reste de cette classe (un
    /// <see cref="HttpClient"/> par appel, sans conséquence à la fréquence normale de cet agent,
    /// voir le commentaire d'en-tête de la classe), <see cref="PollShellInputAsync"/> tourne en
    /// boucle serrée (~1s, <c>ShellSessionPollIntervalSeconds</c>) pendant potentiellement des
    /// heures (une session n'est bornée que par l'inactivité) : reconstruire à chaque tick un
    /// certificat depuis le magasin Windows + un <see cref="HttpClientHandler"/> + une
    /// négociation TLS complète (poignée de main ECDSA) pour poster quelques octets JSON est un
    /// coût réel et évitable. Le certificat agent ne change JAMAIS en cours de session (un
    /// renouvellement se produit à l'échelle de jours, voir <c>Worker.RenewCertificateIfNeededAsync</c>,
    /// jamais pendant une session shell active), donc le construire une seule fois par session
    /// est sûr. <see cref="ShellSessionRunner"/> ouvre CE canal une fois à la création de la
    /// session et le dispose à sa fermeture — jamais partagé entre deux sessions.</summary>
    public sealed class ShellChannel : IDisposable
    {
        public HttpClient Client { get; }
        private readonly HttpClientHandler _handler;
        private readonly X509Certificate2 _cert;

        internal ShellChannel(X509Certificate2 cert, HttpClientHandler handler, HttpClient client)
        {
            _cert = cert;
            _handler = handler;
            Client = client;
        }

        public void Dispose()
        {
            Client.Dispose();
            _handler.Dispose();
            _cert.Dispose();
        }
    }

    public ShellChannel OpenShellChannel()
    {
        var cert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        var handler = CreateAuthenticatedHandler(cert);
        var client = CreateClient(handler);
        return new ShellChannel(cert, handler, client);
    }

    /// <summary>Crée une session de terminal PowerShell (jalon 9) — appelée par
    /// <c>ShellSessionRunner</c> depuis SA PROPRE tâche de fond, jamais depuis le cycle normal
    /// de <c>CommandPoller</c> (voir le commentaire dans Commands/CommandExecutor.cs sur
    /// pourquoi ce découplage existe).</summary>
    public async Task<string> CreateShellSessionAsync(string agentId, HttpClient client, CancellationToken cancellationToken)
    {
        var response = await client.PostAsync($"/agents/{agentId}/shell/sessions", content: null, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        var payload = await response.Content.ReadFromJsonAsync<CreateSessionDto>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Réponse de création de session vide ou invalide.");
        return payload.id;
    }

    /// <summary>Récupère les nouvelles lignes tapées par l'admin (et le drapeau d'arrêt) —
    /// appelée en boucle serrée (~1s) par <c>ShellSessionRunner</c>, jamais par
    /// <c>CommandPoller</c>. <paramref name="client"/> vient de <see cref="OpenShellChannel"/>,
    /// réutilisé pour toute la session — voir <see cref="ShellChannel"/>.</summary>
    public async Task<ShellPollResult> PollShellInputAsync(string agentId, string sessionId, HttpClient client, CancellationToken cancellationToken)
    {
        var response = await client.GetAsync($"/agents/{agentId}/shell/sessions/{sessionId}/poll-input", cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        var payload = await response.Content.ReadFromJsonAsync<PollInputDto>(cancellationToken: cancellationToken)
            ?? new PollInputDto(new List<string>(), false);
        return new ShellPollResult(payload.lines, payload.stop_requested);
    }

    /// <summary>Poste un ou plusieurs fragments de sortie (stdout/stderr) déjà regroupés par
    /// <c>ShellSessionRunner</c> — un appel par cycle de la boucle serrée, pas un par ligne.</summary>
    public async Task PostShellOutputAsync(
        string agentId, string sessionId, IReadOnlyList<(string Source, string Content)> chunks, HttpClient client, CancellationToken cancellationToken)
    {
        if (chunks.Count == 0)
        {
            return;
        }

        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/shell/sessions/{sessionId}/output",
            new { chunks = chunks.Select(c => new { content = c.Content, source = c.Source }) },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Rapporte la fermeture définitive d'une session (jalon 9) — "closed" (arrêt
    /// demandé par le dashboard OU sortie propre du process) ou "timed_out" (inactivité).</summary>
    public async Task CloseShellSessionAsync(string agentId, string sessionId, string status, HttpClient client, CancellationToken cancellationToken)
    {
        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/shell/sessions/{sessionId}/close",
            new { status },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Catalogue des règles de conformité ACTIVÉES (jalon 11) — appelée par
    /// <c>Compliance/ComplianceRunner</c> depuis sa boucle périodique dédiée OU depuis la
    /// commande à la demande, jamais depuis <c>CommandPoller</c> directement.</summary>
    public async Task<IReadOnlyList<ComplianceRuleDto>> FetchComplianceRulesAsync(string agentId, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.GetAsync($"/agents/{agentId}/compliance/rules", cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        return await response.Content.ReadFromJsonAsync<List<ComplianceRuleDto>>(cancellationToken: cancellationToken)
            ?? new List<ComplianceRuleDto>();
    }

    /// <summary>Poste le lot complet des résultats d'un cycle de vérification de conformité
    /// (jalon 11) — un seul appel, crée un `ComplianceSnapshot` + ses résultats côté
    /// serveur.</summary>
    public async Task PostComplianceResultsAsync(
        string agentId, IReadOnlyList<ComplianceResultDto> results, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/compliance/results",
            new { results },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Télécharge l'installeur <paramref name="installerId"/> (2026-09-08, "push
    /// d'application via les groupes") directement vers <paramref name="destPath"/> — jamais
    /// chargé entièrement en mémoire (`ResponseHeadersRead` + copie en flux), un installeur
    /// pouvant faire des centaines de Mo, contrairement à tout le reste de ce client (payloads
    /// JSON, quelques Ko). Timeout étendu (pas le défaut `HttpClient`, trop court pour un
    /// transfert de fichier) via <c>Timeout</c> posé directement sur le client créé ici, dédié à
    /// cet appel.</summary>
    public async Task DownloadInstallerAsync(string installerId, string destPath, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);
        client.Timeout = TimeSpan.FromMinutes(15);

        using var response = await client.GetAsync(
            $"/installers/{installerId}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        await using var httpStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var fileStream = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await httpStream.CopyToAsync(fileStream, cancellationToken);
    }

    /// <summary>Mise à jour de l'agent (2026-09-11) — même mécanique exacte que
    /// <see cref="DownloadInstallerAsync"/>, transposée à `/agent-package/{id}/download`. Pas
    /// factorisée en une seule méthode générique : les deux routes serveur sont distinctes
    /// (catalogue d'installeurs vs paquet agent), et ce client suit la convention déjà en place
    /// dans ce fichier d'une méthode dédiée par endpoint plutôt qu'une abstraction partagée.</summary>
    public async Task DownloadAgentPackageAsync(string packageId, string destPath, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);
        client.Timeout = TimeSpan.FromMinutes(15);

        using var response = await client.GetAsync(
            $"/agent-package/{packageId}/download", HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        await using var httpStream = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var fileStream = new FileStream(destPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await httpStream.CopyToAsync(fileStream, cancellationToken);
    }

    /// <summary>Poste un lot d'événements suspects détectés localement (nouveau jalon détection
    /// comportementale, 2026-09-14) — idempotent côté serveur via `local_event_id` (contrainte
    /// unique composite `(agent_id, local_event_id)` documentée dans le plan), un replay du même
    /// lot après un timeout réseau ne duplique donc rien. Appelée par
    /// <c>Detection/SuspiciousEventUploader</c>, qui ne retire ces événements de son buffer
    /// qu'après un 2xx ici.</summary>
    public async Task PostSuspiciousEventsAsync(
        string agentId, IReadOnlyList<SuspiciousEventDto> events, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.PostAsJsonAsync(
            $"/agents/{agentId}/suspicious-events",
            new { events },
            cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Catalogue des règles de détection d'activités suspectes (nouveau jalon,
    /// 2026-09-14) — appelée par <c>Detection/SuspiciousRulesProvider</c> depuis sa boucle de
    /// rafraîchissement dédiée, même principe que <see cref="FetchComplianceRulesAsync"/>.</summary>
    public async Task<SuspiciousRulesDto> FetchSuspiciousRulesAsync(string agentId, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.GetAsync($"/agents/{agentId}/suspicious-rules", cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        return await response.Content.ReadFromJsonAsync<SuspiciousRulesDto>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Réponse de règles de détection d'activités suspectes vide ou invalide.");
    }

    /// <summary>Politique de mise à jour Windows APPLICABLE à cet agent (jalon "Mises à jour
    /// Vanitas", 2026-09-17) — résolue CÔTÉ SERVEUR à partir des groupes de l'agent (voir
    /// <c>server/app/routes/patch.py::_resolve_policy</c>), jamais recalculée ici : l'agent ne
    /// fait qu'appliquer ce qu'on lui répond.</summary>
    public async Task<PatchPolicyDto> FetchPatchPolicyAsync(string agentId, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.GetAsync($"/agents/{agentId}/patch-policy", cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);

        return await response.Content.ReadFromJsonAsync<PatchPolicyDto>(cancellationToken: cancellationToken)
            ?? throw new InvalidOperationException("Réponse de politique de patch vide ou invalide.");
    }

    /// <summary>Pousse le dernier état connu du cycle de mise à jour (jalon "Mises à jour
    /// Vanitas") — un upsert complet à chaque appel, même motif que
    /// <see cref="PostComplianceResultsAsync"/> (le dernier envoi fait foi côté serveur).</summary>
    public async Task PostPatchStatusAsync(string agentId, PatchStatusDto status, CancellationToken cancellationToken)
    {
        using var currentCert = CertificateStore.FindCurrentCertificate()
            ?? throw new InvalidOperationException("Aucun certificat agent trouvé — l'agent doit d'abord être enrôlé.");
        using var handler = CreateAuthenticatedHandler(currentCert);
        using var client = CreateClient(handler);

        var response = await client.PostAsJsonAsync($"/agents/{agentId}/patch-status", status, cancellationToken);
        await EnsureSuccessAsync(response, cancellationToken);
    }

    /// <summary>Présente <paramref name="clientCert"/> à chaque requête, et valide le
    /// certificat du serveur contre la CA du projet (jamais contre le magasin "Autorités
    /// racines de confiance" de Windows) via <see cref="X509ChainTrustMode.CustomRootTrust"/> —
    /// mécanisme .NET recommandé pour épingler une CA privée sans y ajouter Windows tout
    /// entier.
    ///
    /// 🔧 Corrigé le 2026-09-08 (revue de sécurité, HIGH) : chaîner jusqu'à la CA pinnée ne
    /// suffisait PAS à distinguer un VRAI certificat serveur (`scripts/generate_ca.py`, EKU=
    /// serverAuth, émis UNE SEULE FOIS à la création de la CA) d'un certificat CLIENT d'un
    /// agent quelconque (`app/ca.py::sign_csr`, EKU=clientAuth, émis à CHAQUE enrôlement/
    /// renouvellement) — les deux chaînent également jusqu'à la MÊME CA privée, et aucune
    /// vérification d'EKU ni d'identité (SAN/hostname) n'était faite au-delà du chaînage.
    /// Un attaquant en possession du certificat CLIENT d'un seul poste déjà compromis pouvait
    /// donc, en se plaçant sur le chemin réseau d'un AUTRE agent (spoofing ARP/DNS local), se
    /// faire passer pour le serveur légitime et lui pousser des commandes arbitraires (dont
    /// `start_shell_session`) — RCE niveau SYSTEM fleet-wide à partir d'un seul poste compromis.
    /// Le vrai certificat serveur avait DÉJÀ le bon profil (EKU=serverAuth + SAN=localhost/
    /// 127.0.0.1, confirmé en inspectant `data/ca/server.pem` avant d'écrire ce correctif) —
    /// seule la vérification côté agent manquait, aucun changement serveur nécessaire.</summary>
    private HttpClientHandler CreateAuthenticatedHandler(X509Certificate2 clientCert)
    {
        var caCert = CertificateStore.LoadCaCertificate();
        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(clientCert);
        handler.ServerCertificateCustomValidationCallback = (request, presentedCert, _, _) =>
        {
            if (presentedCert is null)
            {
                return false;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(caCert);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(presentedCert))
            {
                return false;
            }

            if (!HasServerAuthEku(presentedCert))
            {
                _logger.LogWarning(
                    "Certificat présenté par {Host} chaîne jusqu'à la CA mais n'a pas l'EKU " +
                    "serverAuth — refusé (usurpation possible d'un certificat client).",
                    request.RequestUri?.Host);
                return false;
            }

            // Hôte attendu dérivé de la requête RÉELLE (`Agent:ServerUrl`), jamais codé en dur
            // ici — fonctionne que ServerUrl pointe vers "localhost", une IP ou un vrai nom DNS.
            if (!MatchesRequestedHost(presentedCert, request.RequestUri?.Host))
            {
                _logger.LogWarning(
                    "Certificat présenté ne correspond pas à l'hôte demandé ({Host}) — refusé.",
                    request.RequestUri?.Host);
                return false;
            }

            return true;
        };
        return handler;
    }

    private const string ServerAuthEkuOid = "1.3.6.1.5.5.7.3.1";

    // `internal` (pas `private`) UNIQUEMENT pour que `Program.cs --cert-validation-diag` puisse
    // tester ces 3 méthodes directement contre de VRAIS fichiers de certificat, sans avoir à
    // rejouer toute la mécanique HttpClientHandler/mTLS — même précédent que `ComplianceRunner.
    // RunRuleAsync` rendue `public` pour `--compliance-diag` (jalon 11) : réutilise le VRAI code,
    // pas une copie isolée qui pourrait diverger silencieusement.
    internal static bool HasServerAuthEku(X509Certificate2 cert)
    {
        foreach (var extension in cert.Extensions)
        {
            if (extension is X509EnhancedKeyUsageExtension eku)
            {
                foreach (var oid in eku.EnhancedKeyUsages)
                {
                    if (oid.Value == ServerAuthEkuOid)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    internal static bool MatchesRequestedHost(X509Certificate2 cert, string? expectedHost)
    {
        if (string.IsNullOrEmpty(expectedHost))
        {
            return false;
        }
        foreach (var name in GetSubjectAlternativeNames(cert))
        {
            if (string.Equals(name, expectedHost, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Extrait les entrées dNSName/iPAddress du SAN en parsant le DER brut via
    /// <see cref="AsnReader"/> — PAS `X509Extension.Format()` (le texte produit est LOCALISÉ
    /// par l'OS, ex. "Nom DNS=..." en français vs "DNS Name=..." en anglais : un parsing par
    /// sous-chaîne littérale aurait échoué silencieusement sur un poste non anglophone, piège
    /// repéré en écrivant ce correctif, pas en le testant).</summary>
    private static IEnumerable<string> GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        const string SubjectAlternativeNameOid = "2.5.29.17";
        var extension = cert.Extensions[SubjectAlternativeNameOid];
        if (extension is null)
        {
            yield break;
        }

        var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
        var sequence = reader.ReadSequence();
        while (sequence.HasData)
        {
            var tag = sequence.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 2)
            {
                // dNSName [2] IA5String (implicit)
                yield return sequence.ReadCharacterString(
                    UniversalTagNumber.IA5String, new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 7)
            {
                // iPAddress [7] OCTET STRING (implicit)
                var bytes = sequence.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7));
                yield return new System.Net.IPAddress(bytes).ToString();
            }
            else
            {
                sequence.ReadEncodedValue();
            }
        }
    }

    private HttpClient CreateClient(HttpMessageHandler handler)
    {
        if (string.IsNullOrWhiteSpace(_config.ServerUrl))
        {
            throw new InvalidOperationException("Agent:ServerUrl n'est pas renseigné dans appsettings.json.");
        }
        return new HttpClient(handler, disposeHandler: false) { BaseAddress = new Uri(_config.ServerUrl) };
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        throw new InvalidOperationException($"Le serveur a répondu {(int)response.StatusCode} : {body}");
    }

    private sealed record EnrollResponseDto(string agent_id, string certificate_pem, string ca_certificate_pem);
    private sealed record RenewResponseDto(string certificate_pem);
    private sealed record PendingCommandDto(int id, string command_type, string? parameters);
    private sealed record CreateSessionDto(string id);
    private sealed record PollInputDto(List<string> lines, bool stop_requested);
}

/// <summary>Une commande servie par le serveur, prête à être exécutée par
/// <c>Commands/CommandExecutor.cs</c>.</summary>
public sealed record PendingCommand(int Id, string CommandType, string? ParametersJson);

/// <summary>Résultat d'un `poll-input` de session de terminal (jalon 9).</summary>
public sealed record ShellPollResult(IReadOnlyList<string> Lines, bool StopRequested);

/// <summary>Une règle de conformité activée, telle que servie par le serveur (jalon 11) — nom
/// de champ en snake_case pour matcher directement le JSON du serveur (System.Text.Json,
/// insensible à la casse par défaut sur la désérialisation des propriétés).</summary>
/// <summary>Politique de mise à jour Windows résolue côté serveur — voir
/// <c>PatchLoop.cs</c>/<c>server/app/routes/patch.py::PatchPolicyOut</c>. `installed_at` :
/// ISO 8601 UTC ou <c>null</c>, comparaison de délai de grâce faite CÔTÉ AGENT (voir
/// <c>PatchRunner.GraceExceeded</c>) contre son horloge UTC — jamais un booléen précalculé, pour
/// ne jamais dupliquer cette logique à deux endroits.</summary>
public sealed record PatchPolicyDto(bool enabled, string? window_start, string? window_end, int? grace_days, string? installed_at);

public sealed record PatchItemDto(string kb, string title);

public sealed record PatchStatusDto(
    IReadOnlyList<PatchItemDto> available,
    IReadOnlyList<PatchItemDto> todo,
    IReadOnlyList<PatchItemDto> in_progress,
    IReadOnlyList<PatchItemDto> installed,
    bool reboot_pending);

public sealed record ComplianceRuleDto(string id, string name, string script_content);

/// <summary>Le résultat d'UNE règle, prêt à être posté en lot (jalon 11) — `compliant` est
/// tri-état (`null` = erreur d'exécution, voir ComplianceRunner).</summary>
public sealed record ComplianceResultDto(string rule_id, string rule_name, bool? compliant, string? detail);
