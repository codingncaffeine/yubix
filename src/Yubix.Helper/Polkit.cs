using Tmds.DBus.Protocol;

namespace Yubix.Helper;

/// <summary>
/// Authorizes D-Bus callers through polkit. The caller's pid/start-time/uid
/// triple is resolved from its unique bus name and handed to pkcheck, which
/// pops the desktop authentication agent when interaction is needed.
/// A granted authorization is cached per unique name for a limited window —
/// unique names are never reused within a bus instance, so the cache cannot
/// authorize a different process, and the expiry keeps a one-time grant from
/// silently becoming a forever grant. pkcheck runs OUTSIDE any lock: one
/// caller stuck in an auth dialog must not block the daemon for others.
/// </summary>
internal static class Polkit
{
    public const string ActionId = "io.github.codingncaffeine.yubix.manage";

    private static readonly TimeSpan GrantWindow = TimeSpan.FromMinutes(15);
    private static readonly Dictionary<string, DateTime> Granted = new(); // unique name → expiry (UTC)

    public static async Task<bool> CheckAsync(Connection connection, string sender)
    {
        if (string.IsNullOrEmpty(sender)) return false;

        lock (Granted)
        {
            if (Granted.TryGetValue(sender, out var expiry) && DateTime.UtcNow < expiry)
                return true;
        }

        uint uid = await DBusCalls.GetUidAsync(connection, sender);
        if (uid != 0)
        {
            uint pid = await DBusCalls.GetPidAsync(connection, sender);
            ulong startTime = ReadProcStartTime(pid);

            // Generous enough for a human to type a password into the agent
            // dialog, bounded so a stalled agent cannot pin the child forever.
            var (exit, _, _) = await External.RunAsync(
                "pkcheck",
                new[]
                {
                    "--action-id", ActionId,
                    "--process", $"{pid},{startTime},{uid}",
                    "--allow-user-interaction",
                },
                timeoutMs: 120_000);
            if (exit != 0) return false;
        }

        lock (Granted)
        {
            foreach (var stale in Granted.Where(g => g.Value <= DateTime.UtcNow).Select(g => g.Key).ToList())
                Granted.Remove(stale);
            Granted[sender] = DateTime.UtcNow.Add(GrantWindow);
        }
        return true;
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
