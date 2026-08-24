using Yubix.Core;
using Xunit;

namespace Yubix.Tests;

public class PamGeneratorTests
{
    // Captured from a real CachyOS install (2026-08).
    private const string SudoBase = """
        #%PAM-1.0
        auth		include		system-auth
        account		include		system-auth
        session		include		system-auth
        session		optional	pam_systemd.so class=none
        """;

    private const string PlasmaloginBase = """
        #%PAM-1.0

        # SPDX-License-Identifier: CC0-1.0
        # SPDX-FileCopyrightText: none

        auth        include     system-login
        -auth       optional    pam_gnome_keyring.so
        -auth       optional    pam_kwallet5.so

        account     include     system-login

        password    include     system-login
        -password   optional    pam_gnome_keyring.so    use_authtok

        session     optional    pam_keyinit.so          force revoke
        session     include     system-login
        """;

    private const string Origin = "pam://linux-login";
    private const string Authfile = "/etc/u2f_mappings";

    private static string Line(SurfaceMode mode) =>
        PamGenerator.BuildU2fLine(mode, Origin, Authfile);

    [Fact]
    public void PasswordlessInsertsBeforeAuthInclude()
    {
        var result = PamGenerator.Render(SudoBase, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        var lines = result.Split('\n');
        var u2fIdx = Array.FindIndex(lines, l => l.Contains("pam_u2f.so"));
        var includeIdx = Array.FindIndex(lines, l => l.Contains("auth") && l.Contains("include") && l.Contains("system-auth"));
        Assert.True(u2fIdx >= 0 && includeIdx >= 0 && u2fIdx < includeIdx);
        Assert.Contains("sufficient", lines[u2fIdx]);
        Assert.Contains(PamGenerator.Marker, lines[u2fIdx]);
    }

    [Fact]
    public void TwoFactorInsertsBeforeAuthInclude()
    {
        // Before the include: a `sufficient` entry inside the included stack
        // must never be able to short-circuit past the required second factor.
        var result = PamGenerator.Render(SudoBase, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        var lines = result.Split('\n');
        var u2fIdx = Array.FindIndex(lines, l => l.Contains("pam_u2f.so"));
        var includeIdx = Array.FindIndex(lines, l => l.Contains("auth") && l.Contains("include"));
        Assert.True(u2fIdx >= 0 && u2fIdx == includeIdx - 1);
        Assert.Contains("required", lines[u2fIdx]);
    }

    [Fact]
    public void OffModeIsByteExactOnNewlineTerminatedInput()
    {
        var input = SudoBase + "\n";
        Assert.Equal(input, PamGenerator.Render(input, SurfaceMode.Off, ""));
    }

    [Fact]
    public void DoubleRenderIsStable()
    {
        foreach (var mode in new[] { SurfaceMode.Passwordless, SurfaceMode.TwoFactor })
        {
            var once = PamGenerator.Render(SudoBase, mode, Line(mode));
            Assert.Equal(once, PamGenerator.Render(once, mode, Line(mode)));
        }
        var off = PamGenerator.Render(SudoBase, SurfaceMode.Off, "");
        Assert.Equal(off, PamGenerator.Render(off, SurfaceMode.Off, ""));
    }

    [Fact]
    public void RenderIsIdempotentAcrossModeChanges()
    {
        var v1 = PamGenerator.Render(SudoBase, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        var v2 = PamGenerator.Render(v1, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        var v3 = PamGenerator.Render(v2, SurfaceMode.Off, "");
        Assert.Single(v2.Split('\n').Where(l => l.Contains("pam_u2f.so")));
        Assert.DoesNotContain("pam_u2f.so", v3);
        Assert.Equal(PamGenerator.Render(SudoBase, SurfaceMode.Off, ""), v3);
    }

    [Fact]
    public void PlasmaloginPasswordlessLandsFirst()
    {
        var result = PamGenerator.Render(PlasmaloginBase, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        var lines = result.Split('\n');
        var u2fIdx = Array.FindIndex(lines, l => l.Contains("pam_u2f.so"));
        var incIdx = Array.FindIndex(lines, l => l.TrimStart().StartsWith("auth") && l.Contains("system-login"));
        Assert.True(u2fIdx < incIdx);
    }

    [Fact]
    public void DetectModeRoundTrips()
    {
        Assert.Equal(SurfaceMode.Off, PamGenerator.DetectMode(SudoBase));
        var pw = PamGenerator.Render(SudoBase, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        Assert.Equal(SurfaceMode.Passwordless, PamGenerator.DetectMode(pw));
        var tfa = PamGenerator.Render(SudoBase, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        Assert.Equal(SurfaceMode.TwoFactor, PamGenerator.DetectMode(tfa));
    }

    [Fact]
    public void ForeignLinesDetectedButOursIgnored()
    {
        var withChwd = "auth sufficient pam_fprintd.so # chwd-fprintd\n" + SudoBase;
        var foreign = PamGenerator.ForeignAuthLines(withChwd);
        Assert.Single(foreign);
        Assert.Contains("chwd", foreign[0]);

        var ours = PamGenerator.Render(SudoBase, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        Assert.Empty(PamGenerator.ForeignAuthLines(ours));
    }

    [Fact]
    public void MissingAnchorThrows()
    {
        Assert.Throws<UnsupportedLayoutException>(() =>
            PamGenerator.Render("session optional pam_env.so\n", SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless)));
    }

    [Fact]
    public void TwoFactorOnPlasmaloginLandsBeforeIncludeAndOptionalLines()
    {
        var result = PamGenerator.Render(PlasmaloginBase, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        var lines = result.Split('\n');
        var u2fIdx = Array.FindIndex(lines, l => l.Contains("pam_u2f.so"));
        var incIdx = Array.FindIndex(lines, l => l.TrimStart().StartsWith("auth") && l.Contains("system-login"));
        var optIdx = Array.FindIndex(lines, l => l.Contains("pam_kwallet5.so"));
        Assert.True(u2fIdx >= 0 && u2fIdx == incIdx - 1);
        Assert.True(u2fIdx < optIdx);
    }

    [Fact]
    public void SubstackAnchorWorks()
    {
        var substackBase = "#%PAM-1.0\nauth substack system-login\naccount include system-login\n";
        var result = PamGenerator.Render(substackBase, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        var lines = result.Split('\n');
        Assert.Equal(1, Array.FindIndex(lines, l => l.Contains("pam_u2f.so")));
        Assert.Contains("substack", lines[2]);
    }

    [Fact]
    public void UserCommentMentioningMarkerIsNotOurs()
    {
        var content = "# yubix broke here once, watch this file\n" + SudoBase + "\n";
        Assert.False(PamGenerator.HasMarker(content));
        Assert.Equal(SurfaceMode.Off, PamGenerator.DetectMode(content));
        Assert.Equal(content, PamGenerator.Render(content, SurfaceMode.Off, ""));

        var withOurs = PamGenerator.Render(content, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        Assert.True(PamGenerator.HasMarker(withOurs));
        Assert.Equal(content, PamGenerator.Render(withOurs, SurfaceMode.Off, ""));
    }

    [Fact]
    public void MultipleStaleManagedLinesAllStripped()
    {
        var stale =
            "auth sufficient pam_u2f.so authfile=/old origin=o appid=o cue # yubix\n" +
            "auth\trequired\tpam_u2f.so authfile=/older origin=o appid=o cue  #  yubix\n" +
            SudoBase + "\n";
        var result = PamGenerator.Render(stale, SurfaceMode.Passwordless, Line(SurfaceMode.Passwordless));
        Assert.Single(result.Split('\n').Where(l => l.Contains("pam_u2f.so")));
    }

    [Fact]
    public void RealForeignU2fLineDetectedButCommentedLinesIgnored()
    {
        var content =
            "auth required pam_u2f.so authfile=/etc/custom cue\n" +
            "#auth sufficient pam_u2f.so disabled by admin\n" +
            SudoBase + "\n";
        var foreign = PamGenerator.ForeignAuthLines(content);
        Assert.Single(foreign);
        Assert.Contains("/etc/custom", foreign[0]);
    }
}

public class MappingFileTests
{
    [Fact]
    public void ExtractsFromPrefixedOutput()
    {
        var cred = MappingFile.ExtractCredential("alice:KH123,PK456,es256,+presence\n", "alice");
        Assert.Equal("KH123,PK456,es256,+presence", cred);
    }

    [Fact]
    public void ExtractsFromNoUserOutput()
    {
        var cred = MappingFile.ExtractCredential(":KH123,PK456,es256,+presence", "alice");
        Assert.Equal("KH123,PK456,es256,+presence", cred);
    }

    [Fact]
    public void MergeAppendsToExistingUserLine()
    {
        var one = MappingFile.Merge("", "alice", "C1,P1,es256,+presence");
        var two = MappingFile.Merge(one, "alice", "C2,P2,es256,+presence");
        Assert.Equal("alice:C1,P1,es256,+presence:C2,P2,es256,+presence\n", two);
        Assert.Equal(2, MappingFile.CredentialCount(two, "alice"));
    }

    [Fact]
    public void MergeKeepsOtherUsers()
    {
        var content = MappingFile.Merge("bob:X,Y,es256,+presence", "alice", "C1,P1,es256,+presence");
        Assert.Contains("bob:X,Y", content);
        Assert.Contains("alice:C1,P1", content);
        Assert.Equal(new[] { "bob", "alice" }, MappingFile.Users(content).ToArray());
    }

    [Fact]
    public void MergePreservesMultiUserOrder()
    {
        var content = "bob:B1,K1,es256,+presence\ncarol:C1,K1,es256,+presence\n";
        var merged = MappingFile.Merge(content, "bob", "B2,K2,es256,+presence");
        Assert.Equal("bob:B1,K1,es256,+presence:B2,K2,es256,+presence\ncarol:C1,K1,es256,+presence\n", merged);
    }

    [Fact]
    public void CredentialCountForAbsentUserIsZero() =>
        Assert.Equal(0, MappingFile.CredentialCount("bob:X,Y,es256,+presence\n", "alice"));

    [Fact]
    public void ExtractCredentialErrorAndEdgeBranches()
    {
        // No output at all, and output that is not a credential: both throw.
        Assert.Throws<FormatException>(() => MappingFile.ExtractCredential("", "alice"));
        Assert.Throws<FormatException>(() => MappingFile.ExtractCredential("alice:nocommahere", "alice"));
        // Bare credential (no colon), e.g. hand-fed content.
        Assert.Equal("KH,PK,es256,+presence", MappingFile.ExtractCredential("KH,PK,es256,+presence", "alice"));
        // Multi-line output (warnings before the credential): last line wins.
        Assert.Equal("KH,PK,es256,+presence",
            MappingFile.ExtractCredential("some warning text\nalice:KH,PK,es256,+presence\n", "alice"));
        // Unexpected username prefix: everything after the first colon.
        Assert.Equal("KH,PK,es256,+presence", MappingFile.ExtractCredential("bob:KH,PK,es256,+presence", "alice"));
    }
}

public class TransactionTests
{
    [Fact]
    public void ApplyBacksUpAndRestoreRoundTrips()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            var sudoPath = paths.EtcService("sudo");
            var kdePath = paths.EtcService("kde");
            File.WriteAllText(sudoPath, "original sudo\n");
            // kde does not exist -> created file must be deleted on restore.

            var tx = Transaction.Apply(paths, new List<FileChange>
            {
                new(sudoPath, "modified sudo\n"),
                new(kdePath, "new kde override\n"),
            }, "test");

            Assert.Equal("modified sudo\n", File.ReadAllText(sudoPath));
            Assert.Equal("new kde override\n", File.ReadAllText(kdePath));

            Transaction.Restore(tx.ManifestPath);
            Assert.Equal("original sudo\n", File.ReadAllText(sudoPath));
            Assert.False(File.Exists(kdePath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ManifestIsShellReplayableFormat()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            var dest = paths.EtcService("sudo");
            File.WriteAllText(dest, "x\n");
            var tx = Transaction.Apply(paths, new List<FileChange> { new(dest, "y\n") }, "test");
            var manifest = File.ReadAllText(tx.ManifestPath);
            Assert.Matches(@"^restore\t\S+\t\S+\n$", manifest);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ManifestDeleteLineFormatForCreatedFiles()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            var dest = paths.EtcService("kde"); // does not exist yet
            var tx = Transaction.Apply(paths, new List<FileChange> { new(dest, "override\n") }, "test");
            Assert.Equal($"delete\t{dest}\n", File.ReadAllText(tx.ManifestPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BackupNamesForSameBasenameDoNotCollide()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            Directory.CreateDirectory(paths.VendorPamD);
            var etcSudo = paths.EtcService("sudo");
            var vendorSudo = paths.VendorService("sudo");
            File.WriteAllText(etcSudo, "etc content\n");
            File.WriteAllText(vendorSudo, "vendor content\n");

            var tx = Transaction.Apply(paths, new List<FileChange>
            {
                new(etcSudo, "etc changed\n"),
                new(vendorSudo, "vendor changed\n"),
            }, "test");

            // Two distinct backups plus the manifest — not one clobbering the other.
            Assert.Equal(3, Directory.GetFiles(tx.BackupDir).Length);
            Transaction.Restore(tx.ManifestPath);
            Assert.Equal("etc content\n", File.ReadAllText(etcSudo));
            Assert.Equal("vendor content\n", File.ReadAllText(vendorSudo));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void NullContentDeletesAndRestoreBringsBack()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            var dest = paths.EtcService("kde");
            File.WriteAllText(dest, "created by yubix earlier\n");

            var tx = Transaction.Apply(paths, new List<FileChange> { new(dest, null) }, "test");
            Assert.False(File.Exists(dest));

            Transaction.Restore(tx.ManifestPath);
            Assert.Equal("created by yubix earlier\n", File.ReadAllText(dest));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void WriteAtomicallySetsRequestedModeBitsAndLeavesNoLitter()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var f = Path.Combine(root, "f");
            Transaction.WriteAtomically(f, "x\n");
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead,
                File.GetUnixFileMode(f));

            var g = Path.Combine(root, "g");
            Transaction.WriteAtomically(g, "y\n", UnixFileMode.UserRead | UnixFileMode.UserWrite);
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(g));

            Transaction.WriteAtomically(f, "z\n");
            Assert.Equal("z\n", File.ReadAllText(f));
            Assert.DoesNotContain(Directory.GetFiles(root), p => p.Contains("yubix-tmp"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void StateDirsAreCreatedPrivate()
    {
        var root = Directory.CreateTempSubdirectory("yubix-test").FullName;
        try
        {
            var paths = new YubixPaths(root);
            Directory.CreateDirectory(paths.EtcPamD);
            var dest = paths.EtcService("sudo");
            File.WriteAllText(dest, "x\n");
            var tx = Transaction.Apply(paths, new List<FileChange> { new(dest, "y\n") }, "test");

            var expected = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            Assert.Equal(expected, File.GetUnixFileMode(paths.StateDir));
            Assert.Equal(expected, File.GetUnixFileMode(paths.BackupsDir));
            Assert.Equal(expected, File.GetUnixFileMode(tx.BackupDir));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
