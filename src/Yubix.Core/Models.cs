using System.Text.Json;
using System.Text.Json.Serialization;

namespace Yubix.Core;

public enum SurfaceMode
{
    Off,
    Passwordless,
    TwoFactor,
}

/// <summary>The authentication surfaces Yubix manages, keyed by stable ids.</summary>
public static class Surfaces
{
    public const string Sudo = "sudo";
    public const string Polkit = "polkit";
    public const string LockScreen = "lockscreen";
    public const string Login = "login";

    public static readonly string[] All = { Sudo, Polkit, LockScreen, Login };

    /// <summary>PAM service file name backing each surface.</summary>
    public static string ServiceFor(string surfaceId) => surfaceId switch
    {
        Sudo => "sudo",
        Polkit => "polkit-1",
        LockScreen => "kde",
        Login => "plasmalogin",
        _ => throw new ArgumentException($"unknown surface '{surfaceId}'"),
    };

    /// <summary>Login-screen 2FA is gated until KDE bug 513560 is verified fixed.</summary>
    public static bool ModeAllowed(string surfaceId, SurfaceMode mode) =>
        surfaceId != Login || mode != SurfaceMode.TwoFactor;
}

public sealed class EnrolledKey
{
    public string User { get; set; } = "";
    public string Nickname { get; set; } = "";
    public DateTime AddedUtc { get; set; }
    public int CredentialCount { get; set; }
}

/// <summary>What we knew about a surface at apply time — the baseline the
/// drift checks compare the live files against after OS updates.</summary>
public sealed class SurfaceRecord
{
    public bool Created { get; set; }
    public bool VendorExisted { get; set; }
    /// <summary>sha256 of the vendor file content the override was derived from.</summary>
    public string? VendorSha256 { get; set; }
    /// <summary>sha256 of the full file exactly as Yubix wrote it.</summary>
    public string? GeneratedSha256 { get; set; }
}

/// <summary>Persisted helper state (/var/lib/yubix/state.json).</summary>
public sealed class YubixState
{
    public string Origin { get; set; } = "pam://linux-login";
    public List<EnrolledKey> Keys { get; set; } = new();
    public Dictionary<string, SurfaceMode> AppliedModes { get; set; } = new();
    /// <summary>/etc/pam.d files that did not exist before Yubix created them
    /// (vendor-shadow overrides). Mode Off deletes these instead of rewriting.</summary>
    public List<string> CreatedFiles { get; set; } = new();
    /// <summary>Per-surface apply-time baselines for the drift checks, keyed by surface id.</summary>
    public Dictionary<string, SurfaceRecord> SurfaceRecords { get; set; } = new();
}

public sealed class ApplyConfig
{
    public Dictionary<string, SurfaceMode> Modes { get; set; } = new();
    public int CountdownSeconds { get; set; } = 90;
}

public sealed class SelfTestConfig
{
    /// <summary>PAM service to test; null/empty = the throwaway scratch service.</summary>
    public string? Service { get; set; }
    public string User { get; set; } = "";
    public string? Pin { get; set; }
    public string? Password { get; set; }
    /// <summary>Scratch test only: promote the staged mapping to live on success.</summary>
    public bool Promote { get; set; }
}

public static class Json
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        WriteIndented = false,
    };

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static T? Deserialize<T>(string json) => JsonSerializer.Deserialize<T>(json, Options);
}
