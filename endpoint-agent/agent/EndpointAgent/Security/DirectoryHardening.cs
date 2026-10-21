using System.Security.AccessControl;
using System.Security.Principal;

namespace EndpointAgent.Security;

/// <summary>
/// Durcissement DACL partagé (2026-09-08) — extrait de <c>Compliance/ComplianceRunner.
/// EnsureSecureComplianceDirectory</c> (correctif de sécurité du 2026-09-07, élévation de
/// privilèges locale) pour être réutilisé tel quel par <c>Commands/InstallRunner</c> (push
/// d'application) : un répertoire de travail qui reçoit un fichier écrit par SYSTEM puis relu
/// par un process enfant est exactement le même risque dans les deux cas (course locale si un
/// utilisateur standard peut pré-créer/pré-posséder le dossier), donc EXACTEMENT le même
/// remède — dupliquer ce code aurait risqué de corriger un futur bug d'un seul côté.
/// </summary>
public static class DirectoryHardening
{
    /// <summary>Crée <paramref name="path"/> si besoin et réécrit sa DACL à CHAQUE appel (pas
    /// seulement à la création) — jamais fait confiance à un dossier préexistant, quelle qu'en
    /// soit l'origine : héritage coupé, seuls SYSTEM et Administrators locaux gardent un accès
    /// (Full Control), aucun autre principal.</summary>
    public static void EnsureSecureDirectory(string path)
    {
        Directory.CreateDirectory(path);

        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }
}
