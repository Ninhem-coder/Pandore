using System.Management;
using System.Runtime.InteropServices;

namespace EndpointAgent.Inventory;

public sealed record OsInfo(
    string? Caption,
    string? Version,
    string? BuildNumber,
    string? Architecture,
    string? RegisteredUser,
    DateTime? InstallDate,
    string? UtcOffset
);

/// <summary>
/// Version/build de l'OS (jalon "logiciels/OS obsolètes (EOL)", 2026-09-08) — vient compléter
/// l'inventaire applicatif (`InstalledAppsCollector`), jusqu'ici la seule donnée remontée par
/// l'envoi périodique à `/agents/{id}/inventory`. Même motif isolé/défensif que
/// `HardwareInventoryCollector` : une seule méthode statique, son propre try/catch INTERNE,
/// `null` en cas d'échec plutôt que de faire échouer tout l'envoi d'inventaire pour ce seul
/// champ décoratif.
///
/// Étendu (2026-09-11, panneau "Système d'exploitation" de la fiche poste, retour de Nicolas —
/// "possible d'avoir plus d'information ?") avec Architecture/RegisteredUser/InstallDate/
/// UtcOffset — MÊME requête WMI que Caption/Version/BuildNumber (colonnes ajoutées au SELECT,
/// aucun coût réseau/CPU supplémentaire), sauf Architecture (API .NET pure, `RuntimeInformation`,
/// jamais WMI — plus fiable et déjà localement disponible).
/// </summary>
public static class OsInfoCollector
{
    public static OsInfo? Collect()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Caption, Version, BuildNumber, RegisteredUser, InstallDate FROM Win32_OperatingSystem");
            foreach (ManagementObject item in searcher.Get())
            {
                DateTime? installDate = null;
                if (item["InstallDate"] is string raw)
                {
                    try { installDate = ManagementDateTimeConverter.ToDateTime(raw); }
                    catch { /* format WMI inattendu — pas grave, ce champ reste `null` */ }
                }

                return new OsInfo(
                    (item["Caption"] as string)?.Trim(),
                    item["Version"] as string,
                    item["BuildNumber"] as string,
                    RuntimeInformation.OSArchitecture.ToString(),
                    (item["RegisteredUser"] as string)?.Trim(),
                    installDate,
                    FormatUtcOffset(TimeZoneInfo.Local.GetUtcOffset(DateTime.Now))
                );
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return null;
    }

    /// <summary>"UTC+01:00"/"UTC-05:00" — un décalage horaire structuré plutôt que le nom
    /// localisé de `TimeZoneInfo.DisplayName` (ex. "Romance Standard Time" en anglais,
    /// "Heure d'Europe centrale" en français selon la locale Windows du poste) : même piège de
    /// texte localisé déjà rencontré et évité sur la validation SAN du certificat serveur côté
    /// agent (2026-09-08) — ne jamais dépendre d'un texte dont le contenu varie avec la langue
    /// du système.</summary>
    private static string FormatUtcOffset(TimeSpan offset)
    {
        var sign = offset < TimeSpan.Zero ? "-" : "+";
        var abs = offset.Duration();
        return $"UTC{sign}{abs.Hours:D2}:{abs.Minutes:D2}";
    }
}
