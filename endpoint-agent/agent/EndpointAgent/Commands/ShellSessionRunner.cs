using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using EndpointAgent.Communication;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Commands;

/// <summary>
/// Session de terminal PowerShell interactif — jalon 9.
///
/// Lancée par <see cref="CommandExecutor"/> (type de commande "start_shell_session") mais
/// tourne ENTIÈREMENT dans sa propre tâche de fond, DÉCOUPLÉE du cycle normal de
/// <c>CommandPoller</c> — c'est le correctif du point critique trouvé en concevant ce jalon
/// (voir le commentaire sur <see cref="CommandExecutor.ExecuteAsync"/>) : faire tourner une
/// session (potentiellement des minutes/heures) DANS le `foreach` synchrone de
/// `CommandPoller.PollOnceAsync` aurait gelé tout le canal de commande de cet agent pour toute
/// la durée de la session — plus aucune autre commande (y compris "restart_service", la seule
/// porte de sortie en cas de poste qui déraille) n'aurait pu être traitée. Cette classe fait
/// donc ses PROPRES appels HTTP directs (<see cref="ServerClient.CreateShellSessionAsync"/> et
/// consorts), jamais via le canal de commande fermé.
/// </summary>
public static class ShellSessionRunner
{
    private static readonly object _lock = new();
    private static Task? _activeTask;
    private static readonly UTF8Encoding _utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>Un seul appel synchrone rapide — lance la vraie session en tâche de fond
    /// (jamais attendue) et retourne IMMÉDIATEMENT, exactement comme les 6 autres commandes du
    /// catalogue. Garde-fou "une seule session active par agent à la fois" : une 2ᵉ demande
    /// pendant qu'une session tourne déjà est refusée, jamais mise en file.</summary>
    public static (bool Success, string? Result, bool RequestStop, Action? PostReportAction) Start(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken serviceLifetimeToken)
    {
        lock (_lock)
        {
            if (_activeTask is { IsCompleted: false })
            {
                return (false, "Une session de terminal est déjà active pour cet agent — une seule à la fois.", false, null);
            }
            _activeTask = Task.Run(() => RunAsync(serverClient, config, agentId, logger, serviceLifetimeToken));
        }
        return (true, "Session de terminal démarrée en arrière-plan.", false, null);
    }

    private static async Task RunAsync(
        ServerClient serverClient, AgentConfig config, string agentId, ILogger logger, CancellationToken ct)
    {
        string? sessionId = null;
        Process? process = null;
        var finalStatus = "closed";
        ServerClient.ShellChannel? channel = null;

        try
        {
            // Canal mTLS ouvert UNE FOIS pour toute la session (🔧 audit sécurité/perf
            // 2026-09-16) — voir le commentaire de `ServerClient.ShellChannel` : sans lui,
            // chaque poll (~1s) refait une négociation TLS complète. Construit DANS ce `try`
            // (pas avant) : cette méthode tourne fire-and-forget (`Task.Run` dans `Start`,
            // jamais attendue), une exception avant le `try` (agent pas encore enrôlé)
            // échapperait au `catch` ci-dessous.
            channel = serverClient.OpenShellChannel();

            sessionId = await serverClient.CreateShellSessionAsync(agentId, channel.Client, ct);
            logger.LogInformation("Session de terminal {SessionId} créée.", sessionId);

            process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoLogo -NoProfile",
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    // 🔧 Deux bugs réels trouvés EN TESTANT contre une VRAIE session (pas
                    // devinés) :
                    // 1. Sans encodage explicite, les accents sortaient corrompus ("système" →
                    //    "systŠme" sur un vrai `whoami`) — .NET décodait le flux avec l'encodage
                    //    console OEM par défaut (souvent cp850 en France) alors que PowerShell
                    //    écrit ses PROPRES chaînes (Write-Output, variables...) en UTF-8 une
                    //    fois redirigé — confirmé : `Write-Output "système"` round-trippe
                    //    parfaitement avec cet encodage explicite des deux côtés.
                    // 2. `Encoding.UTF8` (la propriété STATIQUE) émet un BOM (U+FEFF) en tête du
                    //    flux — sur `StandardInput`, ce BOM se retrouve collé au TOUT PREMIER
                    //    caractère envoyé, corrompant la toute première commande de la session
                    //    (confirmé : PowerShell rapportait le nom de la commande comme "terme
                    //    non reconnu", un `﻿` invisible collé devant). `new UTF8Encoding(false)`
                    //    (sans BOM, `_utf8NoBom`) pour les trois flux plutôt que la propriété
                    //    statique.
                    //
                    // ⚠️ Limite connue, PAS corrigée dans ce jalon : un exécutable console natif
                    // externe (`whoami.exe`, `chcp.com`...) écrit sa propre sortie selon le
                    // CODEPAGE CONSOLE actif — un mécanisme Windows totalement indépendant de cet
                    // encodage .NET, qui ne gouverne que la sortie PROPRE à PowerShell. Confirmé
                    // en isolation : même après un `chcp 65001` explicite, le message de
                    // confirmation DE `chcp` lui-même restait corrompu. Un accent dans la sortie
                    // d'un outil natif externe (pas une commande PowerShell) peut donc encore
                    // s'afficher mal — rabbit hole de codepage Windows sous redirection complète,
                    // hors scope de ce jalon. La quasi-totalité du dépannage réel (Get-*,
                    // Write-Output, variables) n'est pas concernée.
                    StandardOutputEncoding = _utf8NoBom,
                    StandardErrorEncoding = _utf8NoBom,
                    StandardInputEncoding = _utf8NoBom,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
                EnableRaisingEvents = true,
            };

            // Regroupe la sortie ligne à ligne jusqu'au marqueur de fin de commande (voir
            // WriteCommandAsync) — Write-Output (flux de succès standard) plutôt que Write-Host
            // (sémantique "hôte", moins garantie une fois la sortie redirigée) pour le marqueur
            // lui-même : les deux finissent sur stdout ici, mais Write-Output est le choix
            // documenté pour ce genre de sentinelle hors-bande.
            //
            // 🔧 Deux bugs réels trouvés EN TESTANT en isolation (`--shell-diag`, PAS devinés) :
            // 1. PowerShell, en mode redirigé, réécrit en écho le PROMPT + la ligne d'entrée
            //    TELLE QU'ENVOYÉE avant même que la commande ne s'exécute (confirmé sur le flux
            //    brut). Cette ligne d'écho contient donc TOUJOURS le marqueur comme sous-chaîne
            //    (il fait partie du texte envoyé) — un `Contains` matchait dessus, jamais sur la
            //    vraie sortie, décalant tout le regroupement d'un cran. `_expectedEchoSuffix`
            //    (la ligne exacte envoyée, sans le prompt qui varie selon le répertoire courant)
            //    sert à IGNORER cette ligne d'écho, jamais affichée à l'admin — pure plomberie.
            // 2. Égalité STRICTE (après trim) sur le marqueur, jamais `Contains` — seule la
            //    vraie ligne produite par `Write-Output` ne contient QUE le marqueur.
            var stdoutBuffer = new StringBuilder();
            var pendingChunks = new ConcurrentQueue<(string Source, string Content)>();
            TaskCompletionSource<bool>? markerSeen = null;
            string? expectedMarker = null;
            string? expectedEchoSuffix = null;
            var ioLock = new object();

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                lock (ioLock)
                {
                    if (expectedEchoSuffix is not null && e.Data.EndsWith(expectedEchoSuffix, StringComparison.Ordinal))
                    {
                        // Écho du prompt+commande — ignoré, jamais bufferisé.
                    }
                    else if (expectedMarker is not null && e.Data.Contains(expectedMarker, StringComparison.Ordinal))
                    {
                        // 🔧 Bug réel trouvé EN TESTANT contre une VRAIE session (pas deviné) :
                        // une égalité STRICTE (`Trim() == expectedMarker`) ratait le marqueur
                        // pour une sortie volumineuse/tabulaire (`ls` d'un dossier avec des
                        // milliers d'entrées) — confirmé : `ls` restait indéfiniment sans
                        // sortie, alors que PowerShell avait bien fini de s'exécuter (CPU
                        // retombé à zéro côté process, vérifié en conditions réelles). Le
                        // marqueur peut se retrouver COLLÉ à du contenu réel sur la même ligne
                        // "logique" livrée par `OutputDataReceived` selon la façon dont
                        // PowerShell segmente son flux pour une sortie formatée en tableau —
                        // `Contains` + extraction de ce qui précède le marqueur (au lieu de
                        // `Trim() ==`, qui exigeait que la ligne soit UNIQUEMENT le marqueur)
                        // couvre ce cas sans rien perdre.
                        var idx = e.Data.IndexOf(expectedMarker, StringComparison.Ordinal);
                        var before = e.Data[..idx];
                        if (before.Length > 0)
                        {
                            stdoutBuffer.Append(before);
                        }
                        pendingChunks.Enqueue(("stdout", stdoutBuffer.ToString()));
                        stdoutBuffer.Clear();
                        markerSeen?.TrySetResult(true);
                    }
                    else
                    {
                        stdoutBuffer.AppendLine(e.Data);
                    }
                }
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is null) return;
                // Pas de corrélation par marqueur côté stderr (PowerShell n'écrit jamais notre
                // sentinelle dessus) — chaque ligne devient son propre fragment de sortie,
                // affichable immédiatement plutôt que d'attendre une hypothétique fin de commande.
                pendingChunks.Enqueue(("stderr", e.Data));
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Envoie une ligne et attend son marqueur de fin (borné à 30s) — factorisé pour être
            // réutilisé à la fois par la ligne de bootstrap ci-dessous (encodage) et par les
            // vraies lignes tapées par l'admin dans la boucle plus bas.
            async Task SendAndWaitAsync(string command)
            {
                var marker = $"<<<END-{Guid.NewGuid():N}>>>";
                var sentLine = $"{command}; Write-Output \"{marker}\"; [Console]::Out.Flush()";
                lock (ioLock)
                {
                    expectedMarker = marker;
                    expectedEchoSuffix = sentLine;
                    markerSeen = new TaskCompletionSource<bool>();
                }
                await process.StandardInput.WriteLineAsync(sentLine);
                await process.StandardInput.FlushAsync();
                var completed = await Task.WhenAny(markerSeen.Task, Task.Delay(TimeSpan.FromSeconds(30), ct));
                if (completed != markerSeen.Task)
                {
                    // 🔧 Filet de sécurité — le marqueur n'est jamais apparu dans les 30s (une
                    // commande réellement bloquante type Read-Host, ou un cas de fusion de
                    // ligne pas couvert par la détection ci-dessus) : flushe quand même ce qui a
                    // été accumulé plutôt que de le perdre silencieusement pour toujours (c'était
                    // le comportement AVANT ce correctif — un vrai bug, jamais volontaire).
                    lock (ioLock)
                    {
                        if (stdoutBuffer.Length > 0)
                        {
                            pendingChunks.Enqueue(("stdout", stdoutBuffer.ToString()));
                            stdoutBuffer.Clear();
                        }
                        expectedMarker = null;
                        expectedEchoSuffix = null;
                    }
                }
            }

            var pollInterval = TimeSpan.FromSeconds(Math.Max(1, config.ShellSessionPollIntervalSeconds));
            var idleTimeout = TimeSpan.FromMinutes(Math.Max(1, config.ShellSessionIdleTimeoutMinutes));
            var lastActivity = DateTime.UtcNow;
            var stopRequested = false;

            while (!ct.IsCancellationRequested && !stopRequested)
            {
                if (process.HasExited)
                {
                    logger.LogWarning("Le process PowerShell de la session {SessionId} s'est terminé de lui-même.", sessionId);
                    break;
                }

                ShellPollResult poll;
                try
                {
                    poll = await serverClient.PollShellInputAsync(agentId, sessionId, channel.Client, ct);
                }
                catch (Exception ex)
                {
                    // Un échec de poll (réseau, serveur momentanément indisponible) ne doit pas
                    // tuer la session — nouvelle tentative au cycle suivant, même philosophie
                    // que CommandPoller pour la boucle normale.
                    logger.LogError(ex, "Échec du poll d'entrée pour la session {SessionId}, nouvelle tentative.", sessionId);
                    await Task.Delay(pollInterval, ct);
                    continue;
                }

                if (poll.StopRequested)
                {
                    stopRequested = true;
                    break;
                }

                foreach (var line in poll.Lines)
                {
                    lastActivity = DateTime.UtcNow;
                    // Attente bornée à 30s DANS SendAndWaitAsync : une commande qui ne se
                    // termine jamais (ex. Read-Host en attente d'une entrée qu'on ne peut pas
                    // lui donner) ne doit pas bloquer la boucle indéfiniment — la sortie déjà
                    // tamponnée est postée telle quelle au cycle suivant même si le marqueur
                    // n'est jamais apparu, et la session reste vivante (le filet de sécurité
                    // final reste l'inactivité globale, pas un timeout par commande).
                    await SendAndWaitAsync(line);
                }

                var chunks = new List<(string, string)>();
                while (pendingChunks.TryDequeue(out var chunk))
                {
                    chunks.Add(chunk);
                }
                if (chunks.Count > 0)
                {
                    await serverClient.PostShellOutputAsync(agentId, sessionId, chunks, channel.Client, ct);
                }

                if (DateTime.UtcNow - lastActivity > idleTimeout)
                {
                    logger.LogInformation("Session de terminal {SessionId} fermée pour inactivité.", sessionId);
                    finalStatus = "timed_out";
                    break;
                }

                await Task.Delay(pollInterval, ct);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Échec de la session de terminal.");
        }
        finally
        {
            if (process is not null && !process.HasExited)
            {
                try
                {
                    // `entireProcessTree: true` (.NET 5+) — évite de laisser un petit-fils
                    // orphelin (ex. un `Start-Process` lancé pendant la session).
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Le process a peut-être déjà disparu entre le HasExited et le Kill —
                    // sans conséquence, on ferme la session côté serveur dans tous les cas.
                }
            }
            process?.Dispose();

            if (sessionId is not null && channel is not null)
            {
                try
                {
                    await serverClient.CloseShellSessionAsync(agentId, sessionId, finalStatus, channel.Client, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Échec du rapport de fermeture pour la session {SessionId}.", sessionId);
                }
            }
            channel?.Dispose();
        }
    }
}
