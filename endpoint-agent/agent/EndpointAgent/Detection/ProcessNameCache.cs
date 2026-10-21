using System.Collections.Concurrent;

namespace EndpointAgent.Detection;

/// <summary>
/// Cache PID→nom de processus, alimenté par <see cref="ProcessAndEventLogWatcher"/> à chaque
/// 4688 observé, consommé par <see cref="NetworkConnectionPoller"/> (voir le plan : "résolu en
/// PID→process via le cache alimenté par le watcher 4688, sinon Process.GetProcessById").
/// Singleton partagé entre les deux (voir Program.cs).
///
/// ⚠️ Angle mort ASSUMÉ, pas corrigé en V1 : les PID Windows sont RÉUTILISÉS après la fin d'un
/// process. Une entrée vieillissante peut donc, en théorie, désigner le mauvais processus si un
/// nouveau process récupère le même PID avant que SON PROPRE 4688 ne rafraîchisse l'entrée.
/// Risque jugé faible à l'échelle du poll réseau (30-60s, voir <see cref="NetworkConnectionPoller"/>)
/// mais non nul — une correction rigoureuse nécessiterait de suivre aussi l'heure de démarrage du
/// process (ETW le donnerait, pas 4688 seul), hors scope de ce jalon.
/// </summary>
public sealed class ProcessNameCache
{
    private const int MaxEntries = 5000;
    private readonly ConcurrentDictionary<int, string> _names = new();
    private readonly ConcurrentQueue<int> _insertionOrder = new();

    public void Record(int pid, string? processName)
    {
        if (string.IsNullOrWhiteSpace(processName)) return;

        if (_names.TryAdd(pid, processName))
        {
            _insertionOrder.Enqueue(pid);
            // Éviction FIFO approximative — suffisant pour borner la mémoire sur un agent qui
            // tourne des semaines, pas besoin d'un LRU précis pour ce simple cache best-effort.
            while (_names.Count > MaxEntries && _insertionOrder.TryDequeue(out var oldestPid))
            {
                _names.TryRemove(oldestPid, out _);
            }
        }
        else
        {
            _names[pid] = processName; // PID déjà connu (réutilisé, ou 2e 4688 du même process) — rafraîchi
        }
    }

    public string? TryGetName(int pid) => _names.TryGetValue(pid, out var name) ? name : null;
}
