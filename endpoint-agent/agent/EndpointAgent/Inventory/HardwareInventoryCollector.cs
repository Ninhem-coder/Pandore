using System.Management;
using System.Net.NetworkInformation;

namespace EndpointAgent.Inventory;

public sealed record IdentityInfo(string? Vendor, string? Model, string? SerialNumber, string? Uuid);
public sealed record BiosInfo(string? Manufacturer, string? Version, string? ReleaseDate);
public sealed record MotherboardInfo(string? Manufacturer, string? Model, string? SerialNumber);
public sealed record MemoryModuleInfo(string? Slot, long? CapacityBytes, int? SpeedMhz, string? Manufacturer, string? PartNumber);
public sealed record DiskInfo(string? Model, string? InterfaceType, long? SizeBytes, string? MediaType);
public sealed record GpuInfo(string? Name, string? DriverVersion, long? AdapterRamBytes);
public sealed record NetworkAdapterInfo(string? Description, IReadOnlyList<string> IpAddresses, string? MacAddress);
public sealed record SessionIdentityInfo(string? User, string? Domain, string? DnsHostName);
public sealed record PciDeviceInfo(string Category, string? Name, string? Manufacturer, string? DeviceId, string? Driver, string? Status);

public sealed record HardwareInventoryResult(
    string? Manufacturer,
    string? Model,
    string? SerialNumber,
    string? Uuid,
    string? BiosManufacturer,
    string? BiosVersion,
    string? BiosReleaseDate,
    string? MotherboardManufacturer,
    string? MotherboardModel,
    string? MotherboardSerialNumber,
    string? ChassisType,
    long? TotalMemoryBytes,
    IReadOnlyList<MemoryModuleInfo> MemoryModules,
    IReadOnlyList<DiskInfo> Disks,
    IReadOnlyList<GpuInfo> GraphicsCards,
    string? PrimaryIpAddress,
    IReadOnlyList<NetworkAdapterInfo> NetworkAdapters,
    string? SessionUser,
    string? Domain,
    string? DnsHostName,
    IReadOnlyList<PciDeviceInfo> PciDevices
);

/// <summary>
/// Collecte l'identité machine, le BIOS/carte mère, le châssis, la mémoire, les disques
/// physiques, la/les carte(s) graphique(s), l'identité réseau et les périphériques PCI
/// (regroupés par classe, ex. Réseau/Contrôleurs de stockage/Audio) via WMI (jalon 6) — jamais
/// de S.M.A.R.T. (scope volontairement réduit, voir le plan : gain jugé secondaire pour la
/// complexité WMI supplémentaire).
///
/// Chaque section est collectée INDÉPENDAMMENT, avec son propre try/catch INTERNE (pas un
/// wrapper générique partagé — les tuples de valeurs et les records ne se prêtent pas au même
/// mécanisme de "nullable générique" en C#, plus simple d'isoler chaque méthode elle-même) :
/// une classe WMI absente/en échec sur un modèle de machine particulier (ex. pas de carte
/// graphique dédiée, pilote WMI non standard d'un fabricant) ne doit jamais faire échouer tout
/// le diagnostic, seulement omettre cette section du résultat — même philosophie que les
/// enrichissements "décoratifs" du dashboard DSI (`apps.py::_win32_app_versions`, isolé de la
/// même façon).
/// </summary>
public static class HardwareInventoryCollector
{
    /// <summary>Les propriétés WMI de type `uint64` (Win32_PhysicalMemory.Capacity,
    /// Win32_DiskDrive.Size...) reviennent en boxed `ulong` sur ce poste — mais la doc
    /// Microsoft n'exclut pas qu'elles reviennent en `string` sur certaines configurations
    /// (valeurs hors plage Int64 notamment) : les deux formes sont acceptées plutôt que de
    /// supposer une seule représentation, corrigé après avoir vu `Capacity`/`Size` revenir
    /// `null` en testant contre ce vrai poste (le code d'origine ne gérait QUE le cas string).
    /// </summary>
    private static long? ToNullableLong(object? value) => value switch
    {
        null => null,
        ulong ul => (long)ul,
        long l => l,
        uint ui => ui,
        int i => i,
        string s when long.TryParse(s, out var parsed) => parsed,
        _ => null,
    };

    public static HardwareInventoryResult Collect()
    {
        var identity = CollectIdentity();
        var bios = CollectBios();
        var motherboard = CollectMotherboard();
        var chassis = CollectChassisType();
        var memory = CollectMemory();
        var disks = CollectDisks();
        var gpus = CollectGraphicsCards();
        var network = CollectNetwork();
        var session = CollectSessionIdentity();
        var pciDevices = CollectPciDevices();

        return new HardwareInventoryResult(
            Manufacturer: identity?.Vendor,
            Model: identity?.Model,
            SerialNumber: identity?.SerialNumber,
            Uuid: identity?.Uuid,
            BiosManufacturer: bios?.Manufacturer,
            BiosVersion: bios?.Version,
            BiosReleaseDate: bios?.ReleaseDate,
            MotherboardManufacturer: motherboard?.Manufacturer,
            MotherboardModel: motherboard?.Model,
            MotherboardSerialNumber: motherboard?.SerialNumber,
            ChassisType: chassis,
            TotalMemoryBytes: memory.Total,
            MemoryModules: memory.Modules,
            Disks: disks,
            GraphicsCards: gpus,
            PrimaryIpAddress: SelectPrimaryIpAddress(network),
            NetworkAdapters: network,
            SessionUser: session?.User,
            Domain: session?.Domain,
            DnsHostName: session?.DnsHostName,
            PciDevices: pciDevices
        );
    }

    private static IdentityInfo? CollectIdentity()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Vendor, Name, IdentifyingNumber, UUID FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject item in searcher.Get())
            {
                return new IdentityInfo(
                    item["Vendor"] as string,
                    item["Name"] as string,
                    item["IdentifyingNumber"] as string,
                    item["UUID"] as string
                );
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return null;
    }

    private static BiosInfo? CollectBios()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
            foreach (ManagementObject item in searcher.Get())
            {
                var releaseDate = item["ReleaseDate"] as string;
                return new BiosInfo(
                    item["Manufacturer"] as string,
                    item["SMBIOSBIOSVersion"] as string,
                    releaseDate is not null ? ManagementDateTimeConverter.ToDateTime(releaseDate).ToString("yyyy-MM-dd") : null
                );
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return null;
    }

    private static MotherboardInfo? CollectMotherboard()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Manufacturer, Product, SerialNumber FROM Win32_BaseBoard");
            foreach (ManagementObject item in searcher.Get())
            {
                return new MotherboardInfo(
                    item["Manufacturer"] as string,
                    item["Product"] as string,
                    item["SerialNumber"] as string
                );
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return null;
    }

    // Sous-ensemble des codes Win32_SystemEnclosure.ChassisTypes réellement rencontrés sur un
    // parc bureautique — un code absent de cette table retombe sur "Autre" plutôt que de
    // planter (voir DMTF SMBIOS spec, table "Chassis Types" pour la liste complète).
    private static readonly Dictionary<ushort, string> ChassisTypeLabels = new()
    {
        [3] = "Tour", [4] = "Tour basse", [6] = "Mini tour", [7] = "Tour",
        [8] = "Portable", [9] = "Notebook", [10] = "Portable (autre)", [14] = "Sous-notebook",
        [17] = "Serveur", [23] = "Rack", [30] = "Tablette", [31] = "Convertible", [32] = "Détachable",
    };

    private static string? CollectChassisType()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT ChassisTypes FROM Win32_SystemEnclosure");
            foreach (ManagementObject item in searcher.Get())
            {
                if (item["ChassisTypes"] is ushort[] { Length: > 0 } types)
                {
                    return ChassisTypeLabels.TryGetValue(types[0], out var label) ? label : "Autre";
                }
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return null;
    }

    private static (long? Total, List<MemoryModuleInfo> Modules) CollectMemory()
    {
        var modules = new List<MemoryModuleInfo>();
        long total = 0;
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT DeviceLocator, Capacity, Speed, Manufacturer, PartNumber FROM Win32_PhysicalMemory");
            foreach (ManagementObject item in searcher.Get())
            {
                var capacity = ToNullableLong(item["Capacity"]);
                if (capacity is > 0) total += capacity.Value;
                modules.Add(new MemoryModuleInfo(
                    Slot: (item["DeviceLocator"] as string)?.Trim(),
                    CapacityBytes: capacity,
                    SpeedMhz: item["Speed"] is uint speed ? (int)speed : null,
                    Manufacturer: (item["Manufacturer"] as string)?.Trim(),
                    PartNumber: (item["PartNumber"] as string)?.Trim()
                ));
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return (total > 0 ? total : null, modules);
    }

    private static List<DiskInfo> CollectDisks()
    {
        var disks = new List<DiskInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Model, InterfaceType, Size, MediaType FROM Win32_DiskDrive");
            foreach (ManagementObject item in searcher.Get())
            {
                disks.Add(new DiskInfo(
                    Model: (item["Model"] as string)?.Trim(),
                    InterfaceType: item["InterfaceType"] as string,
                    SizeBytes: ToNullableLong(item["Size"]),
                    MediaType: item["MediaType"] as string
                ));
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return disks;
    }

    private static List<GpuInfo> CollectGraphicsCards()
    {
        var gpus = new List<GpuInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController");
            foreach (ManagementObject item in searcher.Get())
            {
                gpus.Add(new GpuInfo(
                    Name: item["Name"] as string,
                    DriverVersion: item["DriverVersion"] as string,
                    // AdapterRAM est un uint32 côté WMI — plafonne silencieusement à 4 Go sur
                    // les GPU récents (bug WMI documenté, jamais corrigé par Microsoft) :
                    // gardée telle quelle plutôt que de deviner une "vraie" valeur, jamais
                    // présentée comme fiable au-delà de cette limite.
                    AdapterRamBytes: item["AdapterRAM"] is uint ram ? ram : null
                ));
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return gpus;
    }

    /// <summary>Mots-clés observés dans <c>Description</c> pour les adaptateurs virtuels
    /// (VMware/VirtualBox/Hyper-V/VPN/loopback) — repéré en comparant les données réelles d'un
    /// poste ayant à la fois du Wi-Fi physique et plusieurs hyperviseurs locaux : l'ancienne
    /// logique ("première IP non link-local") retenait l'adaptateur VMware plutôt que le Wi-Fi
    /// réel, simplement parce qu'il apparaissait en premier dans l'énumération WMI.</summary>
    private static readonly string[] VirtualAdapterKeywords =
        { "virtual", "vmware", "virtualbox", "hyper-v", "tap-windows", "loopback", "tunnel", "vpn" };

    private static bool LooksVirtual(string? description) =>
        description != null && VirtualAdapterKeywords.Any(k => description.Contains(k, StringComparison.OrdinalIgnoreCase));

    /// <summary>Préfère une IP portée par un adaptateur physique à une IP portée par un
    /// adaptateur virtuel — ne retombe sur une IP virtuelle que si AUCUNE IP physique
    /// exploitable n'existe (jamais de résultat vide si une IP quelconque est disponible).</summary>
    private static string? SelectPrimaryIpAddress(IEnumerable<NetworkAdapterInfo> adapters) =>
        adapters
            .SelectMany(a => a.IpAddresses.Select(ip => (ip, isVirtual: LooksVirtual(a.Description))))
            .Where(x => !x.ip.StartsWith("169.254."))
            .OrderBy(x => x.isVirtual)
            .Select(x => x.ip)
            .FirstOrDefault();

    private static List<NetworkAdapterInfo> CollectNetwork()
    {
        var adapters = new List<NetworkAdapterInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Description, IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
            foreach (ManagementObject item in searcher.Get())
            {
                var ips = (item["IPAddress"] as string[])?.Where(ip => ip.Contains('.')).ToList() ?? new List<string>();
                if (ips.Count == 0) continue; // adaptateur activé mais sans IPv4 exploitable
                adapters.Add(new NetworkAdapterInfo(
                    Description: item["Description"] as string,
                    IpAddresses: ips,
                    MacAddress: item["MACAddress"] as string
                ));
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return adapters;
    }

    private static SessionIdentityInfo? CollectSessionIdentity()
    {
        string? user = null;
        string? domain = null;
        try
        {
            using var searcher = new ManagementObjectSearcher("SELECT UserName, Domain FROM Win32_ComputerSystem");
            foreach (ManagementObject item in searcher.Get())
            {
                // UserName reflète l'utilisateur INTERACTIF actuellement connecté sur la
                // console, même interrogé depuis un service tournant en LocalSystem —
                // mécanisme standard des agents d'inventaire (GLPI/OCS), pas un accès direct à
                // la session utilisateur. Vide si personne n'est connecté à la console (poste
                // verrouillé sans session, ou agent démarré avant tout logon).
                user = item["UserName"] as string;
                domain = item["Domain"] as string;
                break;
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }

        string? dnsHostName = null;
        try
        {
            // Win32_ComputerSystem n'a PAS de propriété "DNSHostName" (contrairement à
            // Win32_NetworkAdapterConfiguration, un niveau plus bas et par interface) — le
            // vrai nom DNS complet vient de l'API réseau .NET, pas de WMI.
            var ipProps = IPGlobalProperties.GetIPGlobalProperties();
            var dnsDomain = string.IsNullOrEmpty(ipProps.DomainName) ? null : ipProps.DomainName;
            dnsHostName = dnsDomain is null ? ipProps.HostName : $"{ipProps.HostName}.{dnsDomain}";
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }

        return new SessionIdentityInfo(user, domain, dnsHostName);
    }

    // Correspondance WMI PNPClass → libellé FR — mêmes catégories que le Gestionnaire de
    // périphériques Windows (qui regroupe lui-même ses entrées par PNPClass). Une classe
    // absente de cette table garde son nom WMI brut plutôt qu'un "Autre" qui perdrait
    // l'information — contrairement à ChassisTypeLabels (un code numérique brut n'aurait, lui,
    // aucun sens à afficher tel quel).
    private static readonly Dictionary<string, string> PnpClassLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Net"] = "Réseau",
        ["HDC"] = "Contrôleurs de stockage",
        ["SCSIAdapter"] = "Contrôleurs de stockage",
        ["Display"] = "Affichage / GPU",
        ["USB"] = "Bus série (USB, etc.)",
        ["Media"] = "Audio",
        ["System"] = "Système",
        ["Ports"] = "Ports",
        ["Bluetooth"] = "Bluetooth",
        ["SecurityDevices"] = "Sécurité",
        ["Biometric"] = "Biométrie",
        ["SmartCardReader"] = "Lecteurs de cartes à puce",
        ["Sensor"] = "Capteurs",
    };

    /// <summary>Périphériques réellement rattachés au bus PCI (`DeviceID LIKE 'PCI\%'`) —
    /// c'est ce filtre précis, pas "tous les périphériques Plug and Play", qui correspond au
    /// compte "périphériques PCI" du Gestionnaire de périphériques (un périphérique USB
    /// branché, par exemple, a un DeviceID préfixé "USB\", pas "PCI\" ; seul son CONTRÔLEUR
    /// hôte USB, lui, est un vrai périphérique PCI — c'est lui qui apparaît ici sous "Bus série
    /// (USB, etc.)", pas chaque clé USB branchée). Pilote résolu via Win32_PnPSignedDriver,
    /// apparié par DeviceID (requête séparée, jointe en mémoire — un seul aller-retour WMI
    /// pour tous les pilotes plutôt qu'un par périphérique).</summary>
    private static List<PciDeviceInfo> CollectPciDevices()
    {
        var driverByDeviceId = new Dictionary<string, string>();
        try
        {
            using var driverSearcher = new ManagementObjectSearcher(
                "SELECT DeviceID, DriverVersion, DriverProviderName FROM Win32_PnPSignedDriver");
            foreach (ManagementObject driver in driverSearcher.Get())
            {
                var id = driver["DeviceID"] as string;
                if (id is null) continue;
                var version = driver["DriverVersion"] as string;
                var provider = driver["DriverProviderName"] as string;
                var label = provider is not null && version is not null
                    ? $"{provider} {version}"
                    : version ?? provider;
                if (label is not null) driverByDeviceId[id] = label;
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }

        var devices = new List<PciDeviceInfo>();
        try
        {
            // Filtré en mémoire plutôt que via WQL `LIKE 'PCI\%'` — l'échappement du backslash
            // dans une chaîne WQL s'est montré peu fiable en testant (la requête WQL renvoyait
            // 0 résultat sur un poste qui a pourtant de vrais périphériques PCI) ; énumérer
            // tous les Win32_PnPEntity et filtrer par `StartsWith` est plus lent d'un poil mais
            // sans ambiguïté de syntaxe.
            // `Status` (2026-09-11, retour de Nicolas — panneau "Matériel", "possible d'avoir
            // plus d'information ?") — même requête, colonne ajoutée au SELECT : "OK" pour un
            // périphérique qui fonctionne normalement, sinon une chaîne WMI ("Error"/"Degraded"/
            // "Unknown"...) reportée telle quelle côté serveur/frontend, jamais retraduite ici
            // (le mapping FR/badge vit côté UI, pas dans le collecteur).
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, Manufacturer, DeviceID, PNPClass, Status FROM Win32_PnPEntity");
            foreach (ManagementObject item in searcher.Get())
            {
                var deviceId = item["DeviceID"] as string;
                if (deviceId is null || !deviceId.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase)) continue;
                var pnpClass = item["PNPClass"] as string;
                var category = pnpClass is not null && PnpClassLabels.TryGetValue(pnpClass, out var label)
                    ? label
                    : (pnpClass ?? "Autres");
                devices.Add(new PciDeviceInfo(
                    Category: category,
                    Name: item["Name"] as string,
                    Manufacturer: item["Manufacturer"] as string,
                    DeviceId: deviceId,
                    Driver: deviceId is not null && driverByDeviceId.TryGetValue(deviceId, out var drv) ? drv : null,
                    Status: item["Status"] as string
                ));
            }
        }
        catch { /* section isolée, voir le commentaire d'en-tête */ }
        return devices;
    }
}
