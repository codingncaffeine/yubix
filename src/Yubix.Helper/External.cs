using System.Diagnostics;
using System.Text;

namespace Yubix.Helper;

internal static class External
{
    public static async Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? stdin = null,
        int timeoutMs = 60_000,
        IReadOnlyDictionary<string, string?>? environment = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                if (value is null) psi.Environment.Remove(key);
                else psi.Environment[key] = value;
            }
        }

        using var process = new Process { StartInfo = psi };
        try
        {
            if (!process.Start())
                return (-1, "", $"failed to start {fileName}");
        }
        catch (Exception ex)
        {
            return (-1, "", $"failed to start {fileName}: {ex.Message}");
        }

        if (stdin is not null)
        {
            try
            {
                await process.StandardInput.WriteAsync(stdin);
            }
            catch
            {
                // Process may exit before reading stdin; not fatal.
            }
        }
        process.StandardInput.Close();

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            return (-2, await SafeRead(stdoutTask), $"{fileName} timed out after {timeoutMs / 1000}s");
        }

        return (process.ExitCode, await SafeRead(stdoutTask), await SafeRead(stderrTask));
    }

    private static async Task<string> SafeRead(Task<string> task)
    {
        try { return await task; } catch { return ""; }
    }

    public static string Tail(string text, int maxChars = 400)
    {
        text = text.Trim();
        return text.Length <= maxChars ? text : "…" + text[^maxChars..];
    }
}

/// <summary>Parses `fido2-token -L` output into device descriptions.</summary>
internal static class FidoDevices
{
    public sealed record Device(string Path, string Description);

    public static async Task<List<Device>> ListAsync()
    {
        var devices = new List<Device>();
        var (exit, stdout, _) = await External.RunAsync("fido2-token", new[] { "-L" }, timeoutMs: 10_000);
        if (exit != 0) return devices;

        foreach (var line in stdout.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            var colon = trimmed.IndexOf(':');
            if (colon <= 0) continue;
            var path = trimmed[..colon];
            var desc = trimmed[(colon + 1)..].Trim();
            var paren = desc.IndexOf('(');
            if (paren >= 0)
            {
                var end = desc.LastIndexOf(')');
                desc = end > paren ? desc[(paren + 1)..end] : desc[(paren + 1)..];
            }
            devices.Add(new Device(path, desc.Trim()));
        }
        return devices;
    }
}
