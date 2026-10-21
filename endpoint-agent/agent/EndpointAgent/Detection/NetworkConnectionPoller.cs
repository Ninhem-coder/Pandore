using System.Net;
using System.Runtime.InteropServices;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Connexions TCP sortantes (nouveau jalon, 2026-09-14) — poll périodique via P/Invoke
/// `iphlpapi.dll` (`GetExtendedTcpTable`, `TCP_TABLE_OWNER_PID_ALL`), PAS
/// `IPGlobalProperties.GetActiveTcpConnections()` : l'API managée ne donne pas le PID
/// propriétaire, indispensable pour attribuer un nom de processus (voir le plan §1, tableau des
/// signaux — audit WFP 5156 écarté, volume trop élevé pour le canal Security partagé).
///
/// ⚠️ Angle mort ASSUMÉ, documenté dans le plan : une connexion ouverte ET fermée entre deux
/// polls (<see cref="AgentConfig.NetworkPollIntervalSeconds"/>, 30-60s) n'est jamais vue —
/// alternative ETW (Microsoft-Windows-Kernel-Network) écartée pour ce jalon (dépendance jugée
/// trop lourde).
/// </summary>
public sealed class NetworkConnectionPoller : BackgroundService
{
    private readonly ILogger<NetworkConnectionPoller> _logger;
    private readonly AgentConfig _config;
    private readonly SuspiciousRulesProvider _rulesProvider;
    private readonly SuspiciousEventBuffer _buffer;
    private readonly ProcessNameCache _processNameCache;

    // Ne réémet pas un événement à CHAQUE poll pour la MÊME connexion déjà signalée (elle reste
    // visible dans GetExtendedTcpTable tant qu'elle est ouverte) — vidé et reconstruit à chaque
    // cycle pour ne garder que les connexions VUES à CE cycle.
    private HashSet<(int Pid, string RemoteAddress, int RemotePort)> _alreadyReported = new();

    public NetworkConnectionPoller(
        ILogger<NetworkConnectionPoller> logger,
        IOptions<AgentConfig> config,
        SuspiciousRulesProvider rulesProvider,
        SuspiciousEventBuffer buffer,
        ProcessNameCache processNameCache)
    {
        _logger = logger;
        _config = config.Value;
        _rulesProvider = rulesProvider;
        _buffer = buffer;
        _processNameCache = processNameCache;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(5, _config.NetworkPollIntervalSeconds));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                PollOnce();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Échec du poll des connexions réseau — nouvelle tentative au prochain cycle.");
            }

            try
            {
                await Task.Delay(interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    private void PollOnce()
    {
        var rules = _rulesProvider.Current?.network;
        if (rules is null) return; // pas encore de règles disponibles

        var connections = GetTcpConnections();
        var seenThisCycle = new HashSet<(int, string, int)>();

        foreach (var conn in connections)
        {
            // Seules les connexions SORTANTES réellement établies vers un tiers sont
            // pertinentes — écarte écoute/fermeture/adresse distante vide.
            if (conn.State != TcpState.Established) continue;
            if (conn.RemoteAddress is "0.0.0.0" or "::" || conn.RemotePort == 0) continue;

            var key = (conn.Pid, conn.RemoteAddress, conn.RemotePort);
            seenThisCycle.Add(key);
            if (_alreadyReported.Contains(key)) continue;

            var processName = _processNameCache.TryGetName(conn.Pid) ?? TryGetProcessNameByPid(conn.Pid);
            var evt = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
                conn.RemoteAddress, conn.RemotePort, processName, conn.Pid, DateTime.UtcNow, rules);
            if (evt is not null)
            {
                _buffer.Enqueue(evt);
            }
        }

        _alreadyReported = seenThisCycle;
    }

    /// <summary>Filet de secours si <see cref="ProcessNameCache"/> n'a pas (encore) vu le 4688
    /// de ce PID (ex. process démarré avant l'agent, ou avant l'activation de l'audit) —
    /// `Process.GetProcessById` échoue silencieusement si le process a déjà terminé entre
    /// l'observation de la connexion et cette résolution, sans conséquence (nom simplement
    /// inconnu pour cet événement).</summary>
    private static string? TryGetProcessNameByPid(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return process.ProcessName + ".exe";
        }
        catch
        {
            return null;
        }
    }

    // ---------------------------------------------------------------------------------------
    // P/Invoke iphlpapi.dll : GetExtendedTcpTable / TCP_TABLE_OWNER_PID_ALL (IPv4 uniquement —
    // voir l'angle mort documenté sur GetTcpConnections)
    // ---------------------------------------------------------------------------------------

    private enum TcpState
    {
        Closed = 1, Listen = 2, SynSent = 3, SynRcvd = 4, Established = 5,
        FinWait1 = 6, FinWait2 = 7, CloseWait = 8, Closing = 9, LastAck = 10, TimeWait = 11, DeleteTcb = 12,
    }

    private sealed record TcpConnectionInfo(int Pid, string RemoteAddress, int RemotePort, TcpState State);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, int reserved);

    private const int AfInet = 2;
    private const int TcpTableOwnerPidAll = 5;
    private const uint ErrorInsufficientBuffer = 122;

    /// <summary>N'énumère QUE IPv4 (`AF_INET`) — cohérent avec le scope V1 du plan ; IPv6 sortant
    /// non couvert, angle mort assumé (pas rencontré comme prioritaire sur un parc bureautique
    /// standard majoritairement IPv4).</summary>
    private static List<TcpConnectionInfo> GetTcpConnections()
    {
        var results = new List<TcpConnectionInfo>();
        var bufferSize = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, sort: false, AfInet, TcpTableOwnerPidAll, 0);

        // Jusqu'à 3 tentatives : la table peut grossir entre l'appel de dimensionnement et la
        // lecture réelle (ERROR_INSUFFICIENT_BUFFER), rare mais possible sous forte activité
        // réseau — pas une boucle infinie, abandonne proprement au bout de 3 essais.
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                var result = GetExtendedTcpTable(buffer, ref bufferSize, sort: false, AfInet, TcpTableOwnerPidAll, 0);
                if (result == 0)
                {
                    ParseTable(buffer, results);
                    return results;
                }
                if (result != ErrorInsufficientBuffer)
                {
                    return results; // autre erreur — abandonne ce cycle, réessaiera au prochain poll
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return results;
    }

    private static void ParseTable(IntPtr buffer, List<TcpConnectionInfo> results)
    {
        var rowCount = Marshal.ReadInt32(buffer);
        var rowPtr = IntPtr.Add(buffer, 4);
        var rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

        for (var i = 0; i < rowCount; i++)
        {
            var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(IntPtr.Add(rowPtr, i * rowSize));
            results.Add(new TcpConnectionInfo(
                Pid: unchecked((int)row.owningPid),
                RemoteAddress: new IPAddress(row.remoteAddr).ToString(),
                RemotePort: NtohsPort(row.remotePort),
                State: (TcpState)row.state));
        }
    }

    /// <summary>Le port dans `MIB_TCPROW_OWNER_PID` est stocké dans les 2 octets de poids FAIBLE
    /// du champ `uint`, eux-mêmes en ordre RÉSEAU (big-endian) — jamais la valeur brute telle
    /// quelle (piège P/Invoke documenté de cette structure, pas deviné : sans ce décalage
    /// d'octets, tous les ports observés seraient faux).</summary>
    private static int NtohsPort(uint rawPort) =>
        ((int)(rawPort & 0xFF) << 8) | (int)((rawPort >> 8) & 0xFF);
}
