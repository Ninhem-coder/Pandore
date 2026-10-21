using EndpointAgent.Detection;

namespace EndpointAgent.Tests.Detection;

/// <summary>
/// Tests de <see cref="SuspiciousActivityRuleEngine"/> — la seule classe du nouveau jalon
/// "détection d'activités suspectes" (2026-09-14) SANS dépendance Windows (pas de WMI/
/// EventLogWatcher/P-Invoke), donc la seule testable ici sans machine Windows réelle. Les
/// watchers (Detection/ProcessAndEventLogWatcher.cs, NetworkConnectionPoller.cs,
/// UsbActivityWatcher.cs) restent vérifiés en conditions réelles (voir le plan §Vérification).
///
/// Jeu de règles de test calqué sur le jeu de règles PAR DÉFAUT donné dans le contrat serveur.
/// </summary>
public class SuspiciousActivityRuleEngineTests
{
    private static ProcessRulesDto DefaultProcessRules() => new(
        suspiciousPaths: new List<string> { "%TEMP%", "%APPDATA%", "%LOCALAPPDATA%\\Temp" },
        lolbins: new List<LolbinRuleDto>
        {
            new("certutil.exe", new List<string> { "-decode", "-urlcache", "-decodehex" }),
            new("mshta.exe", new List<string>()),
            new("rundll32.exe", new List<string> { "javascript:" }),
            new("powershell.exe", new List<string> { "-enc", "-encodedcommand", "-nop", "-w hidden" }),
            new("regsvr32.exe", new List<string> { "/i:http" }),
        },
        securityServiceNames: new List<string> { "WinDefend", "Sense", "wuauserv" },
        persistenceCommands: new List<string> { "schtasks.exe /create", "sc.exe create", "new-service" });

    private static EventLogRulesDto DefaultEventLogRules() => new(
        rdpNormalHoursStart: "07:00",
        rdpNormalHoursEnd: "20:00",
        authFailureThreshold: 5,
        authFailureWindowMinutes: 10);

    private static NetworkRulesDto DefaultNetworkRules() => new(
        allowedPorts: new List<int> { 80, 443, 53, 123, 445, 3389 },
        blockedPorts: new List<int> { 4444, 1337, 6667 },
        allowPrivateRanges: true);

    private static UsbRulesDto DefaultUsbRules() => new(
        fileCopyDebounceSeconds: 5,
        fileCopyAggregateThreshold: 20);

    // -------------------------------------------------------------------------------------
    // Processus
    // -------------------------------------------------------------------------------------

    [Fact]
    public void EvaluateProcessCreation_LolbinWithMatchedArg_ReturnsHighSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Windows\System32\certutil.exe",
            "certutil.exe -decode payload.b64 payload.exe",
            "cmd.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result!.Severity);
        Assert.Equal(SuspiciousActivityRuleEngine.SignalProcess, result.SignalType);
        Assert.Equal("process-lolbin-certutil-decode", result.MatchedRule);
        Assert.False(result.Immediate);
    }

    [Fact]
    public void EvaluateProcessCreation_LolbinWithoutSuspiciousArgsConfigured_AnyInvocationMatches()
    {
        // mshta.exe a une liste suspiciousArgs VIDE dans le contrat par défaut — toute invocation
        // est suspecte (voir le commentaire de MatchLolbin).
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Windows\System32\mshta.exe",
            "mshta.exe http://example.invalid/payload.hta",
            "explorer.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result!.Severity);
        Assert.Equal("process-lolbin-mshta", result.MatchedRule);
    }

    [Fact]
    public void EvaluateProcessCreation_LolbinNameMatchesButNoSuspiciousArg_DoesNotMatchLolbinRule()
    {
        // certutil.exe invoqué SANS aucun des arguments suspects configurés — pas de match LOLBin
        // (et pas de chemin suspect ici non plus).
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Windows\System32\certutil.exe",
            "certutil.exe -verify somefile.cer",
            "cmd.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.Null(result);
    }

    [Fact]
    public void EvaluateProcessCreation_SuspiciousPathWithoutLolbin_ReturnsLowSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Users\alice\AppData\Local\Temp\update.exe",
            @"C:\Users\alice\AppData\Local\Temp\update.exe",
            "explorer.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityLow, result!.Severity);
        Assert.Equal("process-suspicious-path", result.MatchedRule);
    }

    [Fact]
    public void EvaluateProcessCreation_SecurityServiceStopCommand_ReturnsHighSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Windows\System32\sc.exe",
            "sc.exe stop WinDefend",
            "cmd.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result!.Severity);
        Assert.Equal("process-security-service-stop-windefend", result.MatchedRule);
    }

    [Fact]
    public void EvaluateProcessCreation_PersistenceCommand_ReturnsMedSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Windows\System32\schtasks.exe",
            "schtasks.exe /create /tn Updater /tr payload.exe /sc onlogon",
            "cmd.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityMed, result!.Severity);
        Assert.StartsWith("process-persistence-", result.MatchedRule);
    }

    [Fact]
    public void EvaluateProcessCreation_NoMatch_ReturnsNull()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateProcessCreation(
            @"C:\Program Files\Notepad++\notepad++.exe",
            @"C:\Program Files\Notepad++\notepad++.exe C:\temp\notes.txt",
            "explorer.exe",
            4821,
            DateTime.UtcNow,
            DefaultProcessRules());

        Assert.Null(result);
    }

    // -------------------------------------------------------------------------------------
    // Journal d'événements
    // -------------------------------------------------------------------------------------

    [Fact]
    public void EvaluateAdminAccountCreated_AlwaysHighSeverityAndImmediate()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateAdminAccountCreated("newadmin", "attacker", DateTime.UtcNow);

        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result.Severity);
        Assert.Equal(SuspiciousActivityRuleEngine.SignalEventLog, result.SignalType);
        Assert.Equal("eventlog-admin-account-created", result.MatchedRule);
        Assert.True(result.Immediate);
    }

    [Fact]
    public void EvaluateLogCleared_AlwaysHighSeverityAndImmediate()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateLogCleared("someadmin", DateTime.UtcNow);

        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result.Severity);
        Assert.Equal("eventlog-log-cleared", result.MatchedRule);
        Assert.True(result.Immediate);
    }

    [Fact]
    public void EvaluateRdpLogon_WithinNormalHours_ReturnsNull()
    {
        // 12:00 UTC — converti en heure locale par la méthode elle-même ; on encadre largement
        // la plage 07:00-20:00 pour que ce test reste vrai quel que soit le fuseau de la machine
        // qui l'exécute (CI ou poste de Nicolas).
        var noonUtc = DateTime.SpecifyKind(DateTime.UtcNow.Date.AddHours(12), DateTimeKind.Utc);
        var localHour = noonUtc.ToLocalTime().Hour;
        Assert.InRange(localHour, 7, 19); // garde-fou : ce test suppose un fuseau raisonnable (UTC-5 à UTC+7)

        var result = SuspiciousActivityRuleEngine.EvaluateRdpLogon("bob", "10.0.0.5", noonUtc, DefaultEventLogRules());

        Assert.Null(result);
    }

    [Fact]
    public void EvaluateRdpLogon_OutsideNormalHours_ReturnsMedSeverity()
    {
        var middleOfNightUtc = DateTime.SpecifyKind(DateTime.UtcNow.Date.AddHours(3), DateTimeKind.Utc);

        var result = SuspiciousActivityRuleEngine.EvaluateRdpLogon("bob", "203.0.113.5", middleOfNightUtc, DefaultEventLogRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityMed, result!.Severity);
        Assert.Equal("eventlog-rdp-outside-hours", result.MatchedRule);
    }

    [Fact]
    public void EvaluateAuthFailureThreshold_BelowThreshold_ReturnsNull()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateAuthFailureThreshold("bob", failureCountInWindow: 3, DateTime.UtcNow, DefaultEventLogRules());

        Assert.Null(result);
    }

    [Fact]
    public void EvaluateAuthFailureThreshold_AtOrAboveThreshold_ReturnsMedSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateAuthFailureThreshold("bob", failureCountInWindow: 5, DateTime.UtcNow, DefaultEventLogRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityMed, result!.Severity);
        Assert.Equal("eventlog-auth-failure-threshold", result.MatchedRule);
    }

    // -------------------------------------------------------------------------------------
    // Réseau
    // -------------------------------------------------------------------------------------

    [Fact]
    public void EvaluateNetworkConnection_BlockedPort_ReturnsHighSeverityEvenForPublicAddress()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "203.0.113.10", 4444, "malware.exe", 1234, DateTime.UtcNow, DefaultNetworkRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result!.Severity);
        Assert.Equal("network-blocked-port", result.MatchedRule);
    }

    [Fact]
    public void EvaluateNetworkConnection_BlockedPortOnPrivateAddress_StillReturnsHighSeverity()
    {
        // allowPrivateRanges ne s'applique QU'à la règle "port non listé" — un port bloqué reste
        // bloqué même sur le LAN (voir le commentaire de la méthode évaluée).
        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "192.168.1.50", 4444, "malware.exe", 1234, DateTime.UtcNow, DefaultNetworkRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityHigh, result!.Severity);
    }

    [Fact]
    public void EvaluateNetworkConnection_UnlistedPortOnPublicAddress_ReturnsLowSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "203.0.113.10", 8080, "curl.exe", 5678, DateTime.UtcNow, DefaultNetworkRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityLow, result!.Severity);
        Assert.Equal("network-unlisted-port", result.MatchedRule);
    }

    [Fact]
    public void EvaluateNetworkConnection_UnlistedPortOnPrivateAddress_ReturnsNullWhenPrivateRangesAllowed()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "10.0.0.42", 8080, "internal-app.exe", 5678, DateTime.UtcNow, DefaultNetworkRules());

        Assert.Null(result);
    }

    [Fact]
    public void EvaluateNetworkConnection_UnlistedPortOnPrivateAddress_ReturnsLowWhenPrivateRangesNotAllowed()
    {
        var rules = DefaultNetworkRules() with { allowPrivateRanges = false };

        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "10.0.0.42", 8080, "internal-app.exe", 5678, DateTime.UtcNow, rules);

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityLow, result!.Severity);
    }

    [Fact]
    public void EvaluateNetworkConnection_AllowedPort_ReturnsNull()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateNetworkConnection(
            "203.0.113.10", 443, "chrome.exe", 9999, DateTime.UtcNow, DefaultNetworkRules());

        Assert.Null(result);
    }

    // -------------------------------------------------------------------------------------
    // USB
    // -------------------------------------------------------------------------------------

    [Fact]
    public void EvaluateUsbInsertion_AlwaysLowSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateUsbInsertion("E:", DateTime.UtcNow);

        Assert.Equal(SuspiciousActivityRuleEngine.SeverityLow, result.Severity);
        Assert.Equal(SuspiciousActivityRuleEngine.SignalUsb, result.SignalType);
        Assert.Equal("usb-device-connected", result.MatchedRule);
        Assert.False(result.Immediate);
    }

    [Fact]
    public void EvaluateUsbFileCopyBurst_BelowThreshold_ReturnsNull()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateUsbFileCopyBurst("E:", fileCountInWindow: 10, DateTime.UtcNow, DefaultUsbRules());

        Assert.Null(result);
    }

    [Fact]
    public void EvaluateUsbFileCopyBurst_AtOrAboveThreshold_ReturnsMedSeverity()
    {
        var result = SuspiciousActivityRuleEngine.EvaluateUsbFileCopyBurst("E:", fileCountInWindow: 25, DateTime.UtcNow, DefaultUsbRules());

        Assert.NotNull(result);
        Assert.Equal(SuspiciousActivityRuleEngine.SeverityMed, result!.Severity);
        Assert.Equal("usb-file-copy-burst", result.MatchedRule);
    }

    // -------------------------------------------------------------------------------------
    // Vocabulaire de sévérité (contrat serveur : low|med|high, jamais "medium")
    // -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(SuspiciousActivityRuleEngine.SeverityLow, "low")]
    [InlineData(SuspiciousActivityRuleEngine.SeverityMed, "med")]
    [InlineData(SuspiciousActivityRuleEngine.SeverityHigh, "high")]
    public void SeverityConstants_MatchServerContractVocabulary(string constant, string expected)
    {
        Assert.Equal(expected, constant);
    }
}
