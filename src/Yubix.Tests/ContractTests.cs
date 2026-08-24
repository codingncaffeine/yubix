using System.Diagnostics;
using Yubix.Core;
using Xunit;

namespace Yubix.Tests;

/// <summary>Pins the exact PAM line we emit. A silently lost option here is a
/// shipped behavior change (a dropped `nouserok` under `required` would lock
/// out every unenrolled user with the rest of the suite still green).</summary>
public class PamLineContractTests
{
    [Fact]
    public void PasswordlessLineIsExact() => Assert.Equal(
        "auth sufficient pam_u2f.so authfile=/etc/u2f_mappings origin=pam://linux-login appid=pam://linux-login cue nouserok nodetect # yubix",
        PamGenerator.BuildU2fLine(SurfaceMode.Passwordless, "pam://linux-login", "/etc/u2f_mappings"));

    [Fact]
    public void TwoFactorLineIsExact() => Assert.Equal(
        "auth required pam_u2f.so authfile=/etc/u2f_mappings origin=pam://linux-login appid=pam://linux-login cue nouserok nodetect # yubix",
        PamGenerator.BuildU2fLine(SurfaceMode.TwoFactor, "pam://linux-login", "/etc/u2f_mappings"));

    [Fact]
    public void OffModeHasNoLine() => Assert.Throws<ArgumentException>(
        () => PamGenerator.BuildU2fLine(SurfaceMode.Off, "pam://linux-login", "/etc/u2f_mappings"));
}

public class SurfacesTests
{
    [Fact]
    public void LoginTwoFactorIsGated()
    {
        // KDE bug 513560: the Plasma Login Manager crashes on 2FA stacks.
        Assert.False(Surfaces.ModeAllowed(Surfaces.Login, SurfaceMode.TwoFactor));
        Assert.True(Surfaces.ModeAllowed(Surfaces.Login, SurfaceMode.Passwordless));
        Assert.True(Surfaces.ModeAllowed(Surfaces.Login, SurfaceMode.Off));
        foreach (var id in new[] { Surfaces.Sudo, Surfaces.Polkit, Surfaces.LockScreen })
            Assert.True(Surfaces.ModeAllowed(id, SurfaceMode.TwoFactor));
    }

    [Fact]
    public void ServiceMappingIsPinned()
    {
        Assert.Equal("sudo", Surfaces.ServiceFor(Surfaces.Sudo));
        Assert.Equal("polkit-1", Surfaces.ServiceFor(Surfaces.Polkit));
        Assert.Equal("kde", Surfaces.ServiceFor(Surfaces.LockScreen));
        Assert.Equal("plasmalogin", Surfaces.ServiceFor(Surfaces.Login));
        Assert.Throws<ArgumentException>(() => Surfaces.ServiceFor("tty"));
    }
}

public class StateStoreTests
{
    [Fact]
    public void SaveLoadRoundTripsAndPinsJsonContract()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            var state = new YubixState
            {
                Keys =
                {
                    new EnrolledKey
                    {
                        User = "alice", Nickname = "Blue 5C",
                        AddedUtc = new DateTime(2026, 8, 24, 12, 0, 0, DateTimeKind.Utc),
                        CredentialCount = 2,
                    },
                },
                AppliedModes = { ["sudo"] = SurfaceMode.TwoFactor, ["login"] = SurfaceMode.Passwordless },
                CreatedFiles = { "/etc/pam.d/kde" },
            };
            StateStore.Save(paths, state);

            var json = File.ReadAllText(paths.StateFile);
            Assert.Contains("\"twoFactor\"", json);    // camelCase enum values
            Assert.Contains("\"passwordless\"", json);
            Assert.Contains("\"createdFiles\"", json); // camelCase property names
            Assert.Contains("/etc/pam.d/kde", json);

            var loaded = StateStore.Load(paths);
            Assert.Equal("pam://linux-login", loaded.Origin);
            Assert.Single(loaded.Keys);
            Assert.Equal("Blue 5C", loaded.Keys[0].Nickname);
            Assert.Equal(2, loaded.Keys[0].CredentialCount);
            Assert.Equal(SurfaceMode.TwoFactor, loaded.AppliedModes["sudo"]);
            Assert.Equal(new[] { "/etc/pam.d/kde" }, loaded.CreatedFiles);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void CorruptStateFileReturnsDefaults()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.StateDir);
            File.WriteAllText(paths.StateFile, "{ this is not json");
            var loaded = StateStore.Load(paths);
            Assert.Equal("pam://linux-login", loaded.Origin);
            Assert.Empty(loaded.Keys);
            Assert.Empty(loaded.CreatedFiles);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

public class DriftTests
{
    private const string Vendor = "#%PAM-1.0\nauth include system-auth\n";
    private static readonly string Line =
        PamGenerator.BuildU2fLine(SurfaceMode.Passwordless, "pam://linux-login", "/etc/u2f_mappings");
    private static readonly string Generated =
        PamGenerator.Render(Vendor, SurfaceMode.Passwordless, Line);

    private static SurfaceRecord Record(bool vendorExisted = true) => new()
    {
        Created = true,
        VendorExisted = vendorExisted,
        VendorSha256 = vendorExisted ? Drift.Sha256Hex(Vendor) : null,
        GeneratedSha256 = Drift.Sha256Hex(Generated),
    };

    [Fact]
    public void Sha256HexKnownVector() => Assert.Equal(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Drift.Sha256Hex("abc"));

    [Fact]
    public void CleanStateHasNoFlags()
    {
        Assert.Empty(Drift.Classify(Record(), Generated, Vendor));
        Assert.Empty(Drift.Classify(null, "anything", "anything")); // nothing recorded
    }

    [Fact]
    public void EveryDriftKindIsDetected()
    {
        // Override deleted entirely (e.g. pacman --overwrite install).
        Assert.Equal(new[] { "overrideMissing" }, Drift.Classify(Record(), null, Vendor));
        // Our line gone but file present — pacdiff overwrite aftermath.
        Assert.Equal(new[] { "markerLost" }, Drift.Classify(Record(), Vendor, Vendor));
        // Marker still present but the file was edited around it.
        Assert.Equal(new[] { "thirdPartyEdit" },
            Drift.Classify(Record(), Generated + "session optional pam_env.so\n", Vendor));
        // Vendor file changed in an update while our stale copy shadows it.
        Assert.Equal(new[] { "vendorDrift" },
            Drift.Classify(Record(), Generated, Vendor + "auth optional pam_kwallet5.so\n"));
        // Vendor twin vanished (package rename/migration).
        Assert.Equal(new[] { "orphanedOverride" }, Drift.Classify(Record(), Generated, null));
        // A package now ships the file we created from nothing.
        Assert.Equal(new[] { "vendorAppeared" },
            Drift.Classify(Record(vendorExisted: false), Generated, Vendor));
        // Flags compose: line lost AND vendor drifted.
        Assert.Equal(new[] { "markerLost", "vendorDrift" },
            Drift.Classify(Record(), Vendor, Vendor + "x\n"));
    }

    [Fact]
    public void EveryFlagHasHumanWording()
    {
        foreach (var flag in new[]
        {
            "overrideMissing", "markerLost", "thirdPartyEdit",
            "orphanedOverride", "vendorDrift", "vendorAppeared",
        })
            Assert.NotEqual(flag, Drift.Describe(flag));
    }
}

/// <summary>Executes the real data/yubix-restore script — the boot failsafe's
/// only moving part — against manifests produced by Transaction, and asserts
/// it reaches the same end state as the managed Restore.</summary>
public class RestoreScriptTests
{
    private static string ScriptPath()
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "data", "yubix-restore")))
            dir = Path.GetDirectoryName(dir);
        Assert.NotNull(dir);
        return Path.Combine(dir!, "data", "yubix-restore");
    }

    private static (int ExitCode, string Output) RunScript(string fakeRoot, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(ScriptPath());
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["YUBIX_ROOT"] = fakeRoot;
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(15_000), "yubix-restore did not exit");
        return (p.ExitCode, stdout + stderr);
    }

    private static (YubixPaths Paths, string SudoPath, string KdePath, TransactionResult Tx) ApplyFixture(string root)
    {
        var paths = new YubixPaths(root);
        Directory.CreateDirectory(paths.EtcPamD);
        var sudoPath = paths.EtcService("sudo");
        var kdePath = paths.EtcService("kde");
        File.WriteAllText(sudoPath, "original sudo\n");
        // kde does not exist -> the manifest must delete it on restore.
        var tx = Transaction.Apply(paths, new List<FileChange>
        {
            new(sudoPath, "modified sudo\n"),
            new(kdePath, "new kde override\n"),
        }, "apply");
        return (paths, sudoPath, kdePath, tx);
    }

    [Fact]
    public void ScriptReplayMatchesManagedRestore()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (_, sudoPath, kdePath, tx) = ApplyFixture(root);
            var (exit, output) = RunScript(root, tx.ManifestPath);
            Assert.True(exit == 0, output);
            Assert.Equal("original sudo\n", File.ReadAllText(sudoPath));
            Assert.False(File.Exists(kdePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailsafeRevertsAndDisarmsFlag()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (paths, sudoPath, kdePath, tx) = ApplyFixture(root);
            File.WriteAllText(paths.PendingFlagFile,
                $"manifest={tx.ManifestPath}\ndeadline=2026-01-01T00:00:00.0000000Z\n");

            var (exit, output) = RunScript(root, "--failsafe");
            Assert.True(exit == 0, output);
            Assert.Equal("original sudo\n", File.ReadAllText(sudoPath));
            Assert.False(File.Exists(kdePath));
            Assert.False(File.Exists(paths.PendingFlagFile));

            // No flag left -> nothing to do; must exit 0 and never fail the boot.
            var (exitAgain, _) = RunScript(root, "--failsafe");
            Assert.Equal(0, exitAgain);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void FailedRestoreKeepsFailsafeArmed()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (paths, _, _, tx) = ApplyFixture(root);
            File.WriteAllText(paths.PendingFlagFile,
                $"manifest={tx.ManifestPath}\ndeadline=2026-01-01T00:00:00.0000000Z\n");
            var backup = Directory.GetFiles(tx.BackupDir).Single(f => !f.EndsWith("manifest.txt"));
            File.Delete(backup);

            var (exit, output) = RunScript(root, "--failsafe");
            Assert.NotEqual(0, exit);
            // The flag must survive a failed restore so the next boot retries.
            Assert.True(File.Exists(paths.PendingFlagFile), output);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void LastModeFindsMostRecentManifest()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (_, sudoPath, _, _) = ApplyFixture(root);
            var (exit, output) = RunScript(root, "--last");
            Assert.True(exit == 0, output);
            Assert.Equal("original sudo\n", File.ReadAllText(sudoPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}

/// <summary>The uninstall/self-heal path (`yubix-restore --strip`) and the
/// pacman-hook checker (`yubix-pamcheck`), executed for real against
/// snapshot files shaped exactly like the helper writes them.</summary>
public class StripAndPamcheckTests
{
    private static readonly string U2fLine =
        PamGenerator.BuildU2fLine(SurfaceMode.Passwordless, "pam://linux-login", "/etc/u2f_mappings");

    private static string RepoFile(string rel)
    {
        var dir = AppContext.BaseDirectory;
        while (dir is not null && !File.Exists(Path.Combine(dir, "data", "yubix-restore")))
            dir = Path.GetDirectoryName(dir);
        Assert.NotNull(dir);
        return Path.Combine(dir!, rel);
    }

    private static (int ExitCode, string Output) Run(
        string script, string fakeRoot, IDictionary<string, string>? env = null, params string[] args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sh",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(RepoFile(script));
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["YUBIX_ROOT"] = fakeRoot;
        if (env is not null)
            foreach (var (k, v) in env) psi.Environment[k] = v;
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(15_000), "script did not exit");
        return (p.ExitCode, stdout + stderr);
    }

    /// <summary>An edited sudo file, a created kde override, and the snapshot
    /// rows the helper would have written for them at ConfirmKeep.</summary>
    private static (YubixPaths Paths, string SudoPath, string KdePath) StripFixture(string root, bool withSnapshot)
    {
        var paths = new YubixPaths(root);
        Directory.CreateDirectory(paths.EtcPamD);
        Directory.CreateDirectory(paths.StateDir);
        var sudoPath = paths.EtcService("sudo");
        var kdePath = paths.EtcService("kde");
        File.WriteAllText(sudoPath, "#%PAM-1.0\n" + U2fLine + "\nauth include system-auth\n");
        File.WriteAllText(kdePath, U2fLine + "\nauth include system-auth\n");
        if (withSnapshot)
            File.WriteAllText(paths.SnapshotFile,
                $"sudo\tpasswordless\t0\t{sudoPath}\t-\t{paths.VendorService("sudo")}\t-\t0\n" +
                $"kde\tpasswordless\t1\t{kdePath}\t-\t{paths.VendorService("kde")}\t-\t1\n");
        return (paths, sudoPath, kdePath);
    }

    [Fact]
    public void StripSnapshotDrivenRemovesCreatedAndEditsInPlace()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (paths, sudoPath, kdePath) = StripFixture(root, withSnapshot: true);
            var (exit, output) = Run("data/yubix-restore", root, null, "--strip");
            Assert.True(exit == 0, output);
            // Edited file: only the marker line goes; the rest survives.
            Assert.Equal("#%PAM-1.0\nauth include system-auth\n", File.ReadAllText(sudoPath));
            // Created override: deleted outright.
            Assert.False(File.Exists(kdePath));
            // Snapshot consumed.
            Assert.False(File.Exists(paths.SnapshotFile));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void StripFallbackWithoutSnapshotStripsMarkerLinesOnly()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (_, sudoPath, kdePath) = StripFixture(root, withSnapshot: false);
            var untouched = new YubixPaths(root).EtcService("login");
            File.WriteAllText(untouched, "auth include system-auth\n");

            var (exit, output) = Run("data/yubix-restore", root, null, "--strip");
            Assert.True(exit == 0, output);
            Assert.Equal("#%PAM-1.0\nauth include system-auth\n", File.ReadAllText(sudoPath));
            // Without created-ness knowledge the fallback strips lines but keeps files.
            Assert.Equal("auth include system-auth\n", File.ReadAllText(kdePath));
            Assert.Equal("auth include system-auth\n", File.ReadAllText(untouched));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static Dictionary<string, string> PamcheckEnv(string root, bool modulePresent = true)
    {
        var module = Path.Combine(root, "pam_u2f.so");
        if (modulePresent) File.WriteAllText(module, "");
        return new Dictionary<string, string>
        {
            ["YUBIX_PAM_U2F_SO"] = module,
            ["YUBIX_RESTORE"] = RepoFile("data/yubix-restore"),
            ["YUBIX_PAMCHECK_SYSTEMCTL"] = "false", // deterministic: skip the polkit unit check
        };
    }

    [Fact]
    public void PamcheckSilentAndCleanWhenEverythingMatches()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            Directory.CreateDirectory(paths.VendorPamD);
            Directory.CreateDirectory(paths.StateDir);
            var sudoPath = paths.EtcService("sudo");
            var vendorKde = paths.VendorService("kde");
            var kdePath = paths.EtcService("kde");
            File.WriteAllText(vendorKde, "auth include system-auth\n");
            File.WriteAllText(sudoPath, "#%PAM-1.0\n" + U2fLine + "\nauth include system-auth\n");
            File.WriteAllText(kdePath, U2fLine + "\nauth include system-auth\n");
            File.WriteAllText(paths.AttentionFile, "stale finding from last time\n");
            File.WriteAllText(paths.SnapshotFile,
                $"sudo\tpasswordless\t0\t{sudoPath}\t{Drift.Sha256Hex(File.ReadAllText(sudoPath))}\t{paths.VendorService("sudo")}\t-\t0\n" +
                $"kde\tpasswordless\t1\t{kdePath}\t{Drift.Sha256Hex(File.ReadAllText(kdePath))}\t{vendorKde}\t{Drift.Sha256Hex("auth include system-auth\n")}\t1\n");

            var (exit, output) = Run("data/yubix-pamcheck", root, PamcheckEnv(root));
            Assert.True(exit == 0, output);
            Assert.Equal("", output.Trim());
            // A clean run clears stale findings.
            Assert.False(File.Exists(paths.AttentionFile));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PamcheckReportsMarkerLossAndVendorDrift()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            Directory.CreateDirectory(paths.VendorPamD);
            Directory.CreateDirectory(paths.StateDir);
            var sudoPath = paths.EtcService("sudo");
            var vendorKde = paths.VendorService("kde");
            var kdePath = paths.EtcService("kde");
            // sudo lost its marker line (the pacdiff-overwrite aftermath)…
            File.WriteAllText(sudoPath, "#%PAM-1.0\nauth include system-auth\n");
            File.WriteAllText(sudoPath + ".pacnew", "#%PAM-1.0\nauth include system-auth\n");
            // …and the kde vendor file drifted under a still-intact override.
            File.WriteAllText(kdePath, U2fLine + "\nauth include system-auth\n");
            File.WriteAllText(vendorKde, "auth include system-auth\nauth optional pam_kwallet5.so\n");
            File.WriteAllText(paths.SnapshotFile,
                $"sudo\tpasswordless\t0\t{sudoPath}\t-\t{paths.VendorService("sudo")}\t-\t0\n" +
                $"kde\tpasswordless\t1\t{kdePath}\t-\t{vendorKde}\t{Drift.Sha256Hex("auth include system-auth\n")}\t1\n");

            var (exit, output) = Run("data/yubix-pamcheck", root, PamcheckEnv(root));
            Assert.True(exit == 0, output); // warnings must never fail a transaction
            Assert.True(File.Exists(paths.AttentionFile), output);
            var attention = File.ReadAllText(paths.AttentionFile);
            Assert.Contains("sudo: the Yubix line was lost", attention);
            Assert.Contains("sudo.pacnew appeared", attention);
            Assert.Contains("kde: vendor file", attention);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void PamcheckSelfHealsWhenModuleIsGone()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var (paths, sudoPath, kdePath) = StripFixture(root, withSnapshot: true);
            var (exit, output) = Run("data/yubix-pamcheck", root, PamcheckEnv(root, modulePresent: false));
            Assert.True(exit == 0, output);
            // Dangling lines against a nonexistent module were stripped…
            Assert.Equal("#%PAM-1.0\nauth include system-auth\n", File.ReadAllText(sudoPath));
            Assert.False(File.Exists(kdePath));
            // …and the user is told about it.
            Assert.Contains("stripped its PAM lines", File.ReadAllText(paths.AttentionFile));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
