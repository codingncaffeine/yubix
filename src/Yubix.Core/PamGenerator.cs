using System.Text;
using System.Text.RegularExpressions;

namespace Yubix.Core;

/// <summary>
/// Generates and recognizes the single PAM line Yubix manages per service.
/// Strategy (see docs/PLAN.md §5): passwordless inserts a `sufficient` line
/// BEFORE the service's `auth include` line; 2FA inserts a `required` line
/// AFTER it. Every managed line carries the trailing marker comment so it can
/// be found, replaced, and stripped idempotently.
/// </summary>
public static partial class PamGenerator
{
    public const string Marker = "# yubix";

    [GeneratedRegex(@"^\s*(-?auth)\s+(include|substack)\s+\S+", RegexOptions.Compiled)]
    private static partial Regex AuthIncludeRegex();

    [GeneratedRegex(@"^\s*auth\s+(sufficient|required)\s+pam_u2f\.so", RegexOptions.Compiled)]
    private static partial Regex YubixLineRegex();

    public static string BuildU2fLine(SurfaceMode mode, string origin, string authfile)
    {
        if (mode == SurfaceMode.Off)
            throw new ArgumentException("no line for mode Off");
        var control = mode == SurfaceMode.Passwordless ? "sufficient" : "required";
        return $"auth {control} pam_u2f.so authfile={authfile} origin={origin} appid={origin} cue nouserok {Marker}";
    }

    public static bool HasMarker(string content) =>
        content.Split('\n').Any(l => l.Contains(Marker, StringComparison.Ordinal));

    /// <summary>Detects which mode a service file currently encodes, by our marker line.</summary>
    public static SurfaceMode DetectMode(string content)
    {
        foreach (var line in content.Split('\n'))
        {
            if (!line.Contains(Marker, StringComparison.Ordinal)) continue;
            var m = YubixLineRegex().Match(line);
            if (!m.Success) continue;
            return m.Groups[1].Value == "sufficient" ? SurfaceMode.Passwordless : SurfaceMode.TwoFactor;
        }
        return SurfaceMode.Off;
    }

    /// <summary>Lines that mention pam_u2f or pam_fprintd but are not ours —
    /// e.g. hand-made configs or chwd's fingerprint-sudo line.</summary>
    public static List<string> ForeignAuthLines(string content) =>
        content.Split('\n')
            .Where(l => !l.Contains(Marker, StringComparison.Ordinal))
            .Where(l => !l.TrimStart().StartsWith('#'))
            .Where(l => l.Contains("pam_u2f.so") || l.Contains("pam_fprintd.so"))
            .Select(l => l.Trim())
            .ToList();

    /// <summary>
    /// Renders the desired content for a service. Strips any previous Yubix
    /// line first (idempotent), then inserts per mode. Throws
    /// <see cref="UnsupportedLayoutException"/> when the base file has no
    /// `auth include`/`substack` anchor to position against.
    /// </summary>
    public static string Render(string baseContent, SurfaceMode mode, string u2fLine)
    {
        var lines = baseContent.Replace("\r\n", "\n").Split('\n')
            .Where(l => !l.Contains(Marker, StringComparison.Ordinal))
            .ToList();

        // Drop a single trailing blank produced by split-on-final-newline.
        if (lines.Count > 0 && lines[^1].Length == 0)
            lines.RemoveAt(lines.Count - 1);

        if (mode != SurfaceMode.Off)
        {
            var idx = lines.FindIndex(l => AuthIncludeRegex().IsMatch(l));
            if (idx < 0)
                throw new UnsupportedLayoutException(
                    "no 'auth include' line found to anchor the pam_u2f entry");
            lines.Insert(mode == SurfaceMode.Passwordless ? idx : idx + 1, u2fLine);
        }

        var sb = new StringBuilder();
        foreach (var l in lines) sb.Append(l).Append('\n');
        return sb.ToString();
    }

    /// <summary>Scratch service used for the pre-apply live self-test. Contains
    /// only pam_u2f — it cannot lock anything and never touches faillock.</summary>
    public static string RenderSelfTestService(string origin, string authfile) =>
        $"auth required pam_u2f.so authfile={authfile} origin={origin} appid={origin} cue\n" +
        "account required pam_permit.so\n";

    /// <summary>Fake-mode scratch service: validates the whole child/conversation
    /// pipeline via pam_wrapper without needing a physical key.</summary>
    public const string FakeSelfTestService =
        "auth required pam_permit.so\naccount required pam_permit.so\n";
}

public sealed class UnsupportedLayoutException : Exception
{
    public UnsupportedLayoutException(string message) : base(message) { }
}
