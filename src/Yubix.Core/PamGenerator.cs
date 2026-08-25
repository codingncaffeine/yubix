using System.Text;
using System.Text.RegularExpressions;

namespace Yubix.Core;

/// <summary>
/// Generates and recognizes the single PAM line Yubix manages per service.
/// Strategy (see docs/PLAN.md §5): both modes insert BEFORE the service's
/// `auth include` line — passwordless as `sufficient`, 2FA as `required`.
/// Inserting the required line first means nothing inside the included stack
/// (a `sufficient` entry, say) can ever short-circuit past the second factor.
/// Every managed line carries the trailing marker comment so it can be found,
/// replaced, and stripped idempotently.
/// </summary>
public static partial class PamGenerator
{
    public const string Marker = "# yubix";

    [GeneratedRegex(@"^\s*(-?auth)\s+(include|substack)\s+\S+", RegexOptions.Compiled)]
    private static partial Regex AuthIncludeRegex();

    // The FULL shape of a line we manage: auth control + pam_u2f.so + the
    // trailing marker. Matching anything looser (any line containing
    // "# yubix") would strip a user's own comment that mentions the marker.
    [GeneratedRegex(@"^\s*auth\s+(sufficient|required)\s+pam_u2f\.so\s.*#\s*yubix\s*$", RegexOptions.Compiled)]
    private static partial Regex ManagedLineRegex();

    public static string BuildU2fLine(SurfaceMode mode, string origin, string authfile)
    {
        if (mode == SurfaceMode.Off)
            throw new ArgumentException("no line for mode Off");
        var control = mode == SurfaceMode.Passwordless ? "sufficient" : "required";
        // nodetect: skip pam_u2f's pre-flight credential probe. Many YubiKey
        // firmwares cannot answer it silently, leaving the key dark and
        // waiting for a "wake-up" touch before the real (blinking) touch —
        // the classic double-touch complaint. Skipping it means one touch,
        // blinking immediately.
        return $"auth {control} pam_u2f.so authfile={authfile} origin={origin} appid={origin} cue nouserok nodetect {Marker}";
    }

    public static bool HasMarker(string content) =>
        content.Split('\n').Any(l => ManagedLineRegex().IsMatch(l));

    /// <summary>Detects which mode a service file currently encodes, by our managed line.</summary>
    public static SurfaceMode DetectMode(string content)
    {
        foreach (var line in content.Split('\n'))
        {
            var m = ManagedLineRegex().Match(line);
            if (!m.Success) continue;
            return m.Groups[1].Value == "sufficient" ? SurfaceMode.Passwordless : SurfaceMode.TwoFactor;
        }
        return SurfaceMode.Off;
    }

    /// <summary>Lines that mention pam_u2f or pam_fprintd but are not ours —
    /// e.g. hand-made configs or chwd's fingerprint-sudo line.</summary>
    public static List<string> ForeignAuthLines(string content) =>
        content.Split('\n')
            .Where(l => !ManagedLineRegex().IsMatch(l))
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
            .Where(l => !ManagedLineRegex().IsMatch(l))
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
            lines.Insert(idx, u2fLine);
        }

        var sb = new StringBuilder();
        foreach (var l in lines) sb.Append(l).Append('\n');
        return sb.ToString();
    }

    // Any auth-stack line, including the leading-dash "ignore a missing
    // module" form the desktops use for their wallet helpers.
    [GeneratedRegex(@"^\s*-?auth\s+\S", RegexOptions.Compiled)]
    private static partial Regex AuthLineRegex();

    private static readonly string[] WalletHelpers =
        { "pam_gnome_keyring.so", "pam_kwallet5.so", "pam_kwallet.so" };

    /// <summary>
    /// Wallet/keyring helpers sitting after the anchor, which a passwordless
    /// line silently skips: `sufficient` returns from the auth stack the
    /// instant the key is accepted, so nothing below it runs. That is
    /// user-visible — those modules unlock the wallet with the password the
    /// user no longer types, so it stays locked for the session. Two-factor
    /// mode is unaffected; a `required` line lets the stack carry on.
    /// Reported, never repaired: moving our line below the anchor would let a
    /// `sufficient` entry inside the included stack short-circuit past the
    /// second factor, which is the whole reason for the ordering.
    /// </summary>
    public static List<string> ShortCircuitedHelpers(string content)
    {
        var lines = content.Replace("\r\n", "\n").Split('\n');
        var found = new List<string>();
        var anchor = Array.FindIndex(lines, l => AuthIncludeRegex().IsMatch(l));
        if (anchor < 0) return found;

        for (var i = anchor; i < lines.Length; i++)
        {
            if (!AuthLineRegex().IsMatch(lines[i])) continue;
            foreach (var helper in WalletHelpers)
                if (lines[i].Contains(helper) && !found.Contains(helper))
                    found.Add(helper);
        }
        return found;
    }

    /// <summary>Scratch service used for the pre-apply live self-test. Contains
    /// only pam_u2f — it cannot lock anything and never touches faillock.</summary>
    public static string RenderSelfTestService(string origin, string authfile) =>
        $"auth required pam_u2f.so authfile={authfile} origin={origin} appid={origin} cue nodetect\n" +
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
