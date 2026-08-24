using Tmds.DBus.Protocol;

namespace Yubix.Helper;

/// <summary>
/// Authorizes D-Bus callers through polkit. The caller's pid/start-time/uid
/// triple is resolved from its unique bus name and handed to pkcheck, which
/// pops the desktop authentication agent when interaction is needed.
/// Authorized unique names are cached for the daemon's lifetime (the polkit
/// action itself uses auth_admin_keep, so re-prompts stay rare regardless).
/// </summary>
internal static class Polkit
{
    public const string ActionId = "io.github.codingncaffeine.yubix.manage";

    private static readonly HashSet<string> Authorized = new();
    private static readonly SemaphoreSlim Gate = new(1, 1);

    public static async Task<bool> CheckAsync(Connection connection, string sender)
    {
        if (string.IsNullOrEmpty(sender)) return false;

        await Gate.WaitAsync();
        try
        {
            if (Authorized.Contains(sender)) return true;

            uint uid = await DBusCalls.GetUidAsync(connection, sender);
            if (uid == 0)
            {
                Authorized.Add(sender);
                return true;
            }

            uint pid = await DBusCalls.GetPidAsync(connection, sender);
            ulong startTime = ReadProcStartTime(pid);

            var (exit, _, _) = await External.RunAsync(
                "pkcheck",
                new[]
                {
                    "--action-id", ActionId,
                    "--process", $"{pid},{startTime},{uid}",
                    "--allow-user-interaction",
                },
                timeoutMs: 300_000);

            if (exit == 0)
            {
                Authorized.Add(sender);
                return true;
            }
            return false;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>starttime is field 22 of /proc/pid/stat; fields after the
    /// parenthesized comm start at field 3, so index 19 after the ')'.</summary>
    private static ulong ReadProcStartTime(uint pid)
    {
        var stat = File.ReadAllText($"/proc/{pid}/stat");
        var rest = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
        return ulong.Parse(rest[19]);
    }
}
