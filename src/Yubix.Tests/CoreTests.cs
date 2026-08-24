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
    public void TwoFactorInsertsAfterAuthInclude()
    {
        var result = PamGenerator.Render(SudoBase, SurfaceMode.TwoFactor, Line(SurfaceMode.TwoFactor));
        var lines = result.Split('\n');
        var u2fIdx = Array.FindIndex(lines, l => l.Contains("pam_u2f.so"));
        var includeIdx = Array.FindIndex(lines, l => l.Contains("auth") && l.Contains("include"));
        Assert.True(u2fIdx == includeIdx + 1);
        Assert.Contains("required", lines[u2fIdx]);
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
}
