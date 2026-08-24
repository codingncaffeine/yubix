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
    Task<string> SelfTestAsync(string configJson);
    Task<string> ApplyAsync(string configJson);
    Task<string> ConfirmKeepAsync();
    Task<string> RevertAsync();
    Task<string> RestoreDefaultsAsync();
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
}
