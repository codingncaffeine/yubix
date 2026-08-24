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
