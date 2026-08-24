namespace Yubix.Core;

/// <summary>
/// Resolves every filesystem location Yubix touches. When YUBIX_ROOT is set
/// (fake-root dev mode) all paths are re-rooted under it, the session bus is
/// used instead of the system bus, and polkit checks are skipped.
/// </summary>
public sealed class YubixPaths
{
    public const string SelfTestServiceName = "yubix-selftest";

    public string Root { get; }
    public bool FakeMode => Root.Length > 0;

    public YubixPaths(string? root = null)
    {
        root ??= Environment.GetEnvironmentVariable("YUBIX_ROOT") ?? "";
        Root = root.TrimEnd('/');
    }

    private string P(string abs) => Root + abs;

    public string EtcPamD => P("/etc/pam.d");
    public string VendorPamD => P("/usr/lib/pam.d");
    public string MappingFile => P("/etc/u2f_mappings");
    public string StagedMappingFile => P("/etc/u2f_mappings.staged");
    public string StateDir => P("/var/lib/yubix");
    public string StateFile => P("/var/lib/yubix/state.json");
    public string BackupsDir => P("/var/lib/yubix/backups");
    public string PendingFlagFile => P("/var/lib/yubix/pending-apply");
    /// <summary>Shell-parseable twin of the state's surface records, written at
    /// ConfirmKeep/RestoreDefaults for the pacman hook (yubix-pamcheck) and
    /// yubix-restore --strip — no .NET needed at hook time.</summary>
    public string SnapshotFile => P("/var/lib/yubix/pamcheck.snapshot");
    /// <summary>Findings the pacman hook left for the GUI to surface.</summary>
    public string AttentionFile => P("/var/lib/yubix/attention");
    /// <summary>Symlink naming the active display manager — decides which
    /// PAM service backs the login surface (plasmalogin vs sddm).</summary>
    public string DisplayManagerLink => P("/etc/systemd/system/display-manager.service");

    public string EtcService(string service) => Path.Combine(EtcPamD, service);
    public string VendorService(string service) => Path.Combine(VendorPamD, service);
    public string SelfTestServicePath => EtcService(SelfTestServiceName);

    /// <summary>Path pam_u2f should be told to use. In fake mode the real
    /// module still runs inside the fake service dir, so the authfile path is
    /// the re-rooted one (absolute either way, so pam_u2f opens it as root).</summary>
    public string AuthfileArgument(bool staged) => staged ? StagedMappingFile : MappingFile;
}
