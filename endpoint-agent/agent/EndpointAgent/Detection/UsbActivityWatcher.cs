using System.Management;
using EndpointAgent.Configuration;
using Microsoft.Extensions.Options;

namespace EndpointAgent.Detection;

/// <summary>
/// Support amovible USB (nouveau jalon, 2026-09-14) — `ManagementEventWatcher` sur
/// `Win32_VolumeChangeEvent` (EventType=2 branchement, EventType=3 retrait, filtré DriveType=2
/// amovible) pour le branchement, `FileSystemWatcher` DYNAMIQUE sur la racine du volume pour la
/// copie de fichiers (voir le plan §1). `System.Management` déjà présent dans le `.csproj`
/// (jalon 6, <c>Inventory/HardwareInventoryCollector.cs</c>) — pas de dépendance neuve.
/// </summary>
public sealed class UsbActivityWatcher : BackgroundService
{
    private readonly ILogger<UsbActivityWatcher> _logger;
    private readonly SuspiciousRulesProvider _rulesProvider;
    private readonly SuspiciousEventBuffer _buffer;

    private readonly object _watchersLock = new();
    private readonly Dictionary<string, VolumeFileCopyTracker> _activeVolumeWatchers = new(StringComparer.OrdinalIgnoreCase);

    private ManagementEventWatcher? _volumeWatcher;

    public UsbActivityWatcher(ILogger<UsbActivityWatcher> logger, SuspiciousRulesProvider rulesProvider, SuspiciousEventBuffer buffer)
    {
        _logger = logger;
        _rulesProvider = rulesProvider;
        _buffer = buffer;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            var query = new WqlEventQuery(
                "SELECT * FROM Win32_VolumeChangeEvent WHERE (EventType = 2 OR EventType = 3) AND DriveType = 2");
            _volumeWatcher = new ManagementEventWatcher(query);
            _volumeWatcher.EventArrived += OnVolumeChangeEvent;
            _volumeWatcher.Start();
            _logger.LogInformation("Surveillance des supports amovibles démarrée.");
        }
        catch (Exception ex)
        {
            // Ne fait JAMAIS planter l'agent — un WMI inaccessible (service arrêté, GPO)
            // désactive juste ce signal, pas tout l'agent.
            _logger.LogError(ex, "Échec du démarrage de la surveillance USB — signal désactivé.");
        }

        stoppingToken.Register(() =>
        {
            try
            {
                _volumeWatcher?.Stop();
                _volumeWatcher?.Dispose();
            }
            catch
            {
                // Arrêt du service — sans conséquence.
            }

            lock (_watchersLock)
            {
                foreach (var tracker in _activeVolumeWatchers.Values)
                {
                    tracker.Dispose();
                }
                _activeVolumeWatchers.Clear();
            }
        });

        return Task.CompletedTask;
    }

    private void OnVolumeChangeEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var eventType = Convert.ToInt32(e.NewEvent.Properties["EventType"]?.Value);
            var driveName = e.NewEvent.Properties["DriveName"]?.Value as string; // ex. "E:"
            if (string.IsNullOrEmpty(driveName)) return;

            if (eventType == 2)
            {
                HandleInsertion(driveName);
            }
            else if (eventType == 3)
            {
                HandleRemoval(driveName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Échec du traitement d'un événement de changement de volume.");
        }
    }

    private void HandleInsertion(string driveName)
    {
        var evt = SuspiciousActivityRuleEngine.EvaluateUsbInsertion(driveName, DateTime.UtcNow);
        _buffer.Enqueue(evt);

        try
        {
            var root = driveName.EndsWith('\\') ? driveName : driveName + "\\";
            var tracker = new VolumeFileCopyTracker(driveName, root, _rulesProvider, _buffer, _logger);
            lock (_watchersLock)
            {
                if (_activeVolumeWatchers.TryGetValue(driveName, out var existing))
                {
                    existing.Dispose();
                }
                _activeVolumeWatchers[driveName] = tracker;
            }
        }
        catch (Exception ex)
        {
            // Un volume qui ne monte pas de lettre exploitable (mode "charge uniquement", voir
            // le plan) ou disparaît immédiatement après l'événement d'insertion fait échouer la
            // création du FileSystemWatcher — angle mort assumé, le signal "branchement" (déjà
            // enfilé ci-dessus) reste néanmoins remonté.
            _logger.LogWarning(ex, "Impossible de surveiller la copie de fichiers sur {Drive}.", driveName);
        }
    }

    private void HandleRemoval(string driveName)
    {
        lock (_watchersLock)
        {
            if (_activeVolumeWatchers.Remove(driveName, out var tracker))
            {
                tracker.Dispose();
            }
        }
    }

    /// <summary>Un `FileSystemWatcher` + agrégation par debounce pour UN volume — instancié à
    /// l'insertion, disposé au retrait (voir <see cref="UsbActivityWatcher"/>). Compte les
    /// créations de fichiers dans une fenêtre glissante de `fileCopyDebounceSeconds` ; au-delà de
    /// `fileCopyAggregateThreshold`, un seul événement AGRÉGÉ est émis (jamais un événement par
    /// fichier — voir le plan : "agréger plutôt qu'alerter fichier par fichier").</summary>
    private sealed class VolumeFileCopyTracker : IDisposable
    {
        private readonly string _driveName;
        private readonly SuspiciousRulesProvider _rulesProvider;
        private readonly SuspiciousEventBuffer _buffer;
        private readonly ILogger _logger;
        private readonly FileSystemWatcher? _fsWatcher;

        private readonly object _lock = new();
        private readonly List<DateTime> _createdTimestamps = new();
        private bool _alreadyReportedThisBurst;

        public VolumeFileCopyTracker(
            string driveName, string root, SuspiciousRulesProvider rulesProvider, SuspiciousEventBuffer buffer, ILogger logger)
        {
            _driveName = driveName;
            _rulesProvider = rulesProvider;
            _buffer = buffer;
            _logger = logger;

            _fsWatcher = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName,
                // Débit élevé (copie massive) : agrandit le buffer interne au-delà du défaut de
                // 8 Ko — un `FileSystemWatcher` qui déborde perd silencieusement des événements
                // (comportement documenté .NET, voir l'angle mort assumé dans le plan). 64 Ko est
                // le maximum supporté par l'API sous-jacente.
                InternalBufferSize = 65536,
            };
            _fsWatcher.Created += OnFileCreated;
            _fsWatcher.Error += (_, e) => _logger.LogWarning(
                e.GetException(), "FileSystemWatcher en erreur sur {Drive} (débordement de buffer probable sous forte charge I/O).", _driveName);
            _fsWatcher.EnableRaisingEvents = true;
        }

        private void OnFileCreated(object sender, FileSystemEventArgs e)
        {
            var rules = _rulesProvider.Current?.usb;
            if (rules is null) return;

            var debounce = TimeSpan.FromSeconds(Math.Max(1, rules.fileCopyDebounceSeconds));
            int countInWindow;
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                _createdTimestamps.Add(now);
                _createdTimestamps.RemoveAll(t => now - t > debounce);
                countInWindow = _createdTimestamps.Count;

                if (countInWindow < rules.fileCopyAggregateThreshold)
                {
                    _alreadyReportedThisBurst = false;
                    return;
                }
                if (_alreadyReportedThisBurst)
                {
                    return; // rafale déjà signalée — pas de ré-émission tant qu'elle continue
                }
                _alreadyReportedThisBurst = true;
            }

            var evt = SuspiciousActivityRuleEngine.EvaluateUsbFileCopyBurst(_driveName, countInWindow, DateTime.UtcNow, rules);
            if (evt is not null)
            {
                _buffer.Enqueue(evt);
            }
        }

        public void Dispose()
        {
            if (_fsWatcher is not null)
            {
                _fsWatcher.EnableRaisingEvents = false;
                _fsWatcher.Dispose();
            }
        }
    }
}
