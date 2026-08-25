using System.Text.Json.Nodes;
using Tmds.DBus;

namespace Yubix.App;

[DBusInterface("io.github.codingncaffeine.yubix.Manager1")]
public interface IYubixManager : IDBusObject
{
    Task<string> GetStatusAsync();
    Task<string> PreflightAsync();
    Task<string> ListDevicesAsync();
    Task<string> EnrollAsync(string user, string nickname, string pin);
    Task<string> RemoveKeyAsync(string user, uint index);
    Task<string> SelfTestAsync(string configJson);
    Task<string> ApplyAsync(string configJson);
    Task<string> ConfirmKeepAsync();
    Task<string> RevertAsync();
    Task<string> RestoreDefaultsAsync();
    Task<string> AcknowledgeAttentionAsync();
}

public sealed class HelperResult
{
    public bool Ok { get; init; }
    public string? Error { get; init; }
    public JsonNode? Data { get; init; }

    public static HelperResult Failure(string message) => new() { Ok = false, Error = message };

    public static HelperResult Parse(string raw)
    {
        try
        {
            var node = JsonNode.Parse(raw);
            if (node is null) return Failure("empty helper reply");
            return new HelperResult
            {
                Ok = node["ok"]?.GetValue<bool>() ?? false,
                Error = node["error"]?.GetValue<string>(),
                Data = node["data"],
            };
        }
        catch (Exception ex)
        {
            return Failure("bad helper reply: " + ex.Message);
        }
    }
}

/// <summary>
/// Thin D-Bus client for the root helper. Connects lazily; a connection error
/// resets the proxy so the next call retries (covers helper restarts).
/// In fake-root mode (YUBIX_ROOT set) the session bus is used instead.
/// </summary>
public sealed class HelperClient
{
    public const string ServiceName = "io.github.codingncaffeine.yubix";
    private static readonly ObjectPath ManagerPath = new("/io/github/codingncaffeine/yubix");

    public bool FakeMode { get; } =
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("YUBIX_ROOT"));

    private Connection? _connection;
    private IYubixManager? _manager;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<HelperResult> CallAsync(Func<IYubixManager, Task<string>> call)
    {
        await _gate.WaitAsync();
        try
        {
            if (_manager is null)
            {
                var address = FakeMode ? Address.Session : Address.System;
                if (string.IsNullOrEmpty(address))
                    return HelperResult.Failure("no D-Bus bus address found");
                _connection = new Connection(address);
                await _connection.ConnectAsync();
                _manager = _connection.CreateProxy<IYubixManager>(ServiceName, ManagerPath);
            }
            return HelperResult.Parse(await call(_manager));
        }
        catch (Exception ex)
        {
            Drop();
            return HelperResult.Failure(ex.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Drop()
    {
        _manager = null;
        try { _connection?.Dispose(); } catch { }
        _connection = null;
    }

    /// <summary>
    /// Drops the bus connection deterministically when the window closes,
    /// rather than leaving it to process teardown. Ungated on purpose: it must
    /// not block behind an in-flight call while the window is going away.
    ///
    /// This does NOT silence the unhandled TaskCanceledException printed at
    /// exit — that one comes from Avalonia's own D-Bus connection
    /// (Avalonia.FreeDesktop, for portals and platform settings), not this
    /// one. Verified by running with no helper on the bus at all, so this
    /// client never connects: the trace is identical. Its teardown emits onto
    /// the Avalonia dispatcher after the dispatcher has stopped. Nothing in
    /// this codebase can reach it; the process still exits 0 and no work is
    /// lost. Disabling UseDBusFilePicker/UseDBusMenu does not help either,
    /// because DBusPlatformSettings connects regardless.
    /// </summary>
    public void Disconnect() => Drop();
}
