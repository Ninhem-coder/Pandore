using EndpointAgent.Communication;
using Microsoft.Win32;

namespace EndpointAgent.Inventory;

/// <summary>
/// Énumère les applications installées en lisant directement le registre (les clés
/// "Uninstall" que Windows utilise aussi pour peupler Programmes et fonctionnalités), plutôt
/// que de dépendre de winget/Get-Package — plus léger, aucune dépendance externe, pas de
/// sous-processus PowerShell juste pour lister des apps.
/// </summary>
public static class InstalledAppsCollector
{
    private const string UninstallSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public static IReadOnlyList<InstalledAppInfo> Collect()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var apps = new List<InstalledAppInfo>();

        // Vue 64 bits + vue 32 bits (WOW6432Node, redirigée automatiquement par RegistryView)
        // pour couvrir toutes les apps installées machine-wide, + HKCU pour les apps
        // installées sans droits admin (jamais présentes côté HKLM).
        ReadFrom(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), seen, apps);
        ReadFrom(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32), seen, apps);
        ReadFrom(Registry.CurrentUser, seen, apps);

        return apps;
    }

    private static void ReadFrom(RegistryKey baseKey, HashSet<string> seen, List<InstalledAppInfo> apps)
    {
        using var _ = baseKey;
        using var uninstallKey = baseKey.OpenSubKey(UninstallSubKey);
        if (uninstallKey is null)
        {
            return;
        }

        foreach (var subKeyName in uninstallKey.GetSubKeyNames())
        {
            using var subKey = uninstallKey.OpenSubKey(subKeyName);
            if (subKey is null)
            {
                continue;
            }

            var displayName = subKey.GetValue("DisplayName") as string;
            if (string.IsNullOrWhiteSpace(displayName))
            {
                continue; // pas de nom exploitable (souvent des correctifs/entrées techniques)
            }

            // Convention déjà utilisée par Programmes et fonctionnalités : SystemComponent=1
            // marque des entrées techniques (composants Windows, redistribuables) que Windows
            // lui-même n'affiche pas comme des "applications" — même filtre appliqué ici.
            if (subKey.GetValue("SystemComponent") is int systemComponent && systemComponent == 1)
            {
                continue;
            }

            var version = subKey.GetValue("DisplayVersion") as string;

            // Une même app peut apparaître dans plusieurs vues du registre (ex. 32 et 64 bits) —
            // dédoublonnée par (nom, version), la première occurrence rencontrée l'emporte.
            if (!seen.Add($"{displayName}|{version}"))
            {
                continue;
            }

            apps.Add(new InstalledAppInfo(
                Name: displayName,
                Version: version,
                Publisher: subKey.GetValue("Publisher") as string,
                InstallDate: subKey.GetValue("InstallDate") as string));
        }
    }
}
