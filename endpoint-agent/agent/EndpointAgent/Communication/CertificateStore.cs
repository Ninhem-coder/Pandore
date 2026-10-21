using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EndpointAgent.Communication;

/// <summary>
/// Génère la paire de clés/CSR de l'agent et gère son certificat dans le magasin Windows
/// (<c>Cert:\LocalMachine\My</c>) — la clé privée ne quitte jamais cette machine, ni même ce
/// process au-delà de sa durée de vie en mémoire pendant l'enrôlement/le renouvellement.
///
/// Le certificat de la CA (public, pas secret) est stocké à part, en simple fichier —
/// utilisé pour vérifier le certificat du SERVEUR à chaque connexion (voir ServerClient),
/// jamais importé dans le magasin "Autorités racines de confiance" de Windows : ça aurait
/// rendu la CA de ce projet fiable pour TOUT sur cette machine, pas seulement nos appels.
/// </summary>
public static class CertificateStore
{
    // Doit correspondre EXACTEMENT au CN posé par scripts/generate_ca.py côté serveur.
    private const string CaIssuerDistinguishedName = "CN=EndpointAgent Root CA";

    private static readonly string CaCertificatePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "EndpointAgent",
        "ca.pem");

    /// <summary>Génère une paire de clés ECDSA P-256 + une CSR. La clé doit être conservée en
    /// mémoire par l'appelant jusqu'à réception du certificat signé (<see cref="ImportCertificate"/>)
    /// — le round-trip réseau est le seul moment où l'agent est "sans certificat".</summary>
    public static (ECDsa PrivateKey, string CsrPem) GenerateKeyAndCsr()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Le sujet demandé ici n'a aucune valeur — la CA impose toujours sa propre identité
        // (CN = agent_id) à la signature, voir server/app/ca.py::sign_csr.
        var request = new CertificateRequest(
            "CN=endpoint-agent", key, HashAlgorithmName.SHA256);

        byte[] csrDer = request.CreateSigningRequest();
        string csrPem = PemEncoding.WriteString("CERTIFICATE REQUEST", csrDer);
        return (key, csrPem);
    }

    /// <summary>Apparie le certificat signé reçu du serveur avec la clé privée déjà en
    /// mémoire, et l'importe dans <c>Cert:\LocalMachine\My</c> (persisté par Windows, pas un
    /// simple fichier). Retire l'ancien certificat émis par notre CA s'il y en avait un
    /// (renouvellement).</summary>
    public static void ImportCertificate(ECDsa privateKey, string certificatePem)
    {
        using var publicOnly = X509Certificate2.CreateFromPem(certificatePem);
        using var withKey = publicOnly.CopyWithPrivateKey(privateKey);

        // .NET n'associe pas automatiquement une clé ECDsa générée en mémoire à un conteneur
        // de clé persisté par Windows — le round-trip PFX (export puis réimport avec
        // MachineKeySet+PersistKeySet) est le mécanisme standard pour que la clé survive
        // réellement au-delà de ce process, dans le magasin de la machine.
        byte[] pfxBytes = withKey.Export(X509ContentType.Pfx, (string?)null);
        using var persisted = new X509Certificate2(
            pfxBytes, (string?)null,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

        RemoveCurrentCertificate();

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Add(persisted);
    }

    /// <summary>Le certificat agent actuellement installé, ou null si jamais enrôlé.</summary>
    public static X509Certificate2? FindCurrentCertificate()
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly);
        foreach (var cert in store.Certificates)
        {
            if (cert.Issuer == CaIssuerDistinguishedName)
            {
                return new X509Certificate2(cert);
            }
        }
        return null;
    }

    /// <summary>Publique depuis le jalon 7 — réutilisée par
    /// <c>Commands/CommandExecutor.cs::UninstallAgent</c> pour ne jamais laisser un certificat
    /// orphelin dans <c>Cert:\LocalMachine\My</c> une fois le service désinstallé (auparavant
    /// appelée uniquement en interne, avant un ré-import lors d'un renouvellement).</summary>
    public static void RemoveCurrentCertificate()
    {
        var existing = FindCurrentCertificate();
        if (existing is null)
        {
            return;
        }

        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadWrite);
        store.Remove(existing);
    }

    /// <summary>L'agent_id est le CN du certificat — imposé par la CA à la signature, jamais
    /// stocké séparément.</summary>
    public static string GetAgentId(X509Certificate2 cert) =>
        cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

    public static void SaveCaCertificate(string caCertificatePem)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(CaCertificatePath)!);
        File.WriteAllText(CaCertificatePath, caCertificatePem);
    }

    public static X509Certificate2 LoadCaCertificate()
    {
        if (!File.Exists(CaCertificatePath))
        {
            throw new InvalidOperationException(
                "Certificat de la CA introuvable — l'agent doit d'abord être enrôlé (--enroll).");
        }
        // CreateFromPemFile(path) à UN SEUL argument cherche une clé privée dans CE MÊME
        // fichier (keyPemFilePath vaut alors implicitement le même chemin) — ca.pem ne
        // contient que le certificat public, d'où l'échec réel observé en testant
        // ("the key contents do not contain a PEM..."). CreateFromPem(string) est la bonne
        // surcharge pour un certificat seul, sans clé associée.
        return X509Certificate2.CreateFromPem(File.ReadAllText(CaCertificatePath));
    }
}
