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
                // Built off the UI thread deliberately. Tmds.DBus captures the
                // ambient SynchronizationContext when the connection is set up
                // and delivers disconnect notifications through a *blocking*
                // Send on it. Captured from the UI thread, the teardown at exit
                // marshals onto an Avalonia dispatcher that has already stopped
                // and the wait is cancelled — which printed an unhandled
                // TaskCanceledException on every close. Nothing here needs the
                // UI thread: this client exposes no signals, only calls.
                (_connection, _manager) = await Task.Run(async () =>
                {
                    var connection = new Connection(address);
                    await connection.ConnectAsync();
                    return (connection,
                        connection.CreateProxy<IYubixManager>(ServiceName, ManagerPath));
                });
            }
            return HelperResult.Parse(await call(_manager));
        }
        catch (Exception ex)
        {
            _manager = null;
            _connection?.Dispose();
            _connection = null;
            return HelperResult.Failure(ex.Message);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Drops the bus connection while the UI thread is still running. Without
    /// this it is torn down during process shutdown instead, and Tmds.DBus's
    /// disconnect callback marshals onto an Avalonia dispatcher that has
    /// already stopped — which printed an unhandled TaskCanceledException on
    /// every exit. Deliberately ungated: it must not block behind an in-flight
    /// call while the window is closing.
    /// </summary>
    public void Disconnect()
    {
        _manager = null;
        try { _connection?.Dispose(); } catch { }
        _connection = null;
    }
}
