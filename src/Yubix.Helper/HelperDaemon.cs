using Tmds.DBus.Protocol;
using Yubix.Core;

namespace Yubix.Helper;

public static class HelperDaemon
{
    public const string BusName = "io.github.codingncaffeine.yubix";
    public const string ObjectPath = "/io/github/codingncaffeine/yubix";
    public const string Interface = "io.github.codingncaffeine.yubix.Manager1";

    public static async Task<int> RunAsync()
    {
        var paths = new YubixPaths();
        var address = paths.FakeMode ? Address.Session : Address.System;
        if (string.IsNullOrEmpty(address))
        {
            Console.Error.WriteLine("yubix-helper: no D-Bus address available");
            return 1;
        }

        var connection = new Connection(address);
        await connection.ConnectAsync();

        var service = new HelperService(paths);
        // 1 = DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER. Anything else (with
        // DO_NOT_QUEUE: 3 = name exists) means another helper is serving —
        // carrying on would leave this instance answering nobody while
        // callers reach the other one.
        var reply = await DBusCalls.RequestNameAsync(connection, BusName);
        if (reply != 1)
        {
            Console.Error.WriteLine(
                $"yubix-helper: {BusName} is already owned — another yubix-helper is running; exiting");
            return 1;
        }
        // No idle exit under a fake root: that helper is started by hand, not
        // bus-activated, so exiting would strand the app with nothing to
        // reconnect to.
        var idle = paths.FakeMode ? null : new IdleExit(service);
        connection.AddMethodHandler(new ManagerHandler(connection, paths, service, idle));

        Console.WriteLine(
            $"yubix-helper: serving {BusName} on the {(paths.FakeMode ? "session" : "system")} bus" +
            (paths.FakeMode ? $" (fake root: {paths.Root})" : ""));

        if (idle is null)
        {
            await Task.Delay(Timeout.Infinite);
            return 0;
        }

        await idle.WaitAsync();
        Console.WriteLine(
            "yubix-helper: idle — exiting; D-Bus starts it again on the next call");
        return 0;
    }
}

/// <summary>
/// Ends the process once it has been idle long enough. A root service that can
/// rewrite PAM files otherwise stays resident for the rest of the machine's
/// uptime after a single status read, which is not what bus activation is for.
/// Restarting is the bus's job and callers never see it happen.
///
/// It is not a security boundary — anything that can talk to the bus can start
/// the helper again. What it buys is a process that cannot stay wedged
/// (a stuck call or child would otherwise persist until reboot) and does not
/// idle in memory for hours.
/// </summary>
internal sealed class IdleExit
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CheckEvery = TimeSpan.FromMinutes(1);

    private readonly HelperService _service;
    private readonly TaskCompletionSource _done =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Timer _timer;
    private long _lastActivityTicks = DateTime.UtcNow.Ticks;
    private int _inFlight;

    public IdleExit(HelperService service)
    {
        _service = service;
        _timer = new Timer(_ => Check(), null, CheckEvery, CheckEvery);
    }

    public Task WaitAsync() => _done.Task;

    public void CallStarted()
    {
        Interlocked.Increment(ref _inFlight);
        Touch();
    }

    public void CallFinished()
    {
        Interlocked.Decrement(ref _inFlight);
        Touch();
    }

    private void Touch() => Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);

    private void Check()
    {
        // A call in flight can be an enrollment waiting on a touch, which
        // legitimately takes half a minute of doing nothing.
        if (Volatile.Read(ref _inFlight) > 0) return;
        if (_service.HasPendingApply) return;

        var last = new DateTime(Interlocked.Read(ref _lastActivityTicks), DateTimeKind.Utc);
        if (DateTime.UtcNow - last < Window) return;

        _timer.Dispose();
        _done.TrySetResult();
    }
}

internal sealed class ManagerHandler : IMethodHandler
{
    private readonly Connection _connection;
    private readonly YubixPaths _paths;
    private readonly HelperService _service;
    private readonly IdleExit? _idle;

    public ManagerHandler(Connection connection, YubixPaths paths, HelperService service,
        IdleExit? idle = null)
    {
        _connection = connection;
        _paths = paths;
        _service = service;
        _idle = idle;
    }

    public string Path => HelperDaemon.ObjectPath;

    public bool RunMethodHandlerSynchronously(Message message) => false;

    public async ValueTask HandleMethodAsync(MethodContext context)
    {
        // Counts for the idle clock even when the call turns out to be a probe
        // or an unknown member: someone is talking to us either way.
        _idle?.CallStarted();
        try
        {
            await DispatchAsync(context);
        }
        finally
        {
            _idle?.CallFinished();
        }
    }

    private async ValueTask DispatchAsync(MethodContext context)
    {
        var request = context.Request;
        string iface = request.InterfaceAsString ?? "";
        string member = request.MemberAsString ?? "";
        string sender = request.SenderAsString ?? "";

        if (iface == "org.freedesktop.DBus.Introspectable" && member == "Introspect")
        {
            ReplyString(context, IntrospectXml);
            return;
        }

        if (iface != HelperDaemon.Interface)
        {
            ReplyString(context, HelperService.Err($"unknown interface '{iface}'"));
            return;
        }

        string result;
        try
        {
            if (!_paths.FakeMode && !SkipsPolkit(member) && !await Polkit.CheckAsync(_connection, sender))
            {
                ReplyString(context, HelperService.Err("not authorized (polkit denied)"));
                return;
            }

            var reader = request.GetBodyReader();
            result = member switch
            {
                "GetStatus" => await _service.GetStatusAsync(),
                "Preflight" => await _service.PreflightAsync(),
                "ListDevices" => await _service.ListDevicesAsync(),
                "Enroll" => await _service.EnrollAsync(
                    reader.ReadString(), reader.ReadString(), reader.ReadString()),
                "RemoveKey" => await _service.RemoveKeyAsync(reader.ReadString(), reader.ReadUInt32()),
                "SelfTest" => await _service.SelfTestAsync(reader.ReadString()),
                "Apply" => await _service.ApplyAsync(reader.ReadString()),
                "ConfirmKeep" => await _service.ConfirmKeepAsync(),
                "Revert" => await _service.RevertAsync("user request"),
                "RestoreDefaults" => await _service.RestoreDefaultsAsync(),
                "AcknowledgeAttention" => await _service.AcknowledgeAttentionAsync(),
                _ => HelperService.Err($"unknown method '{member}'"),
            };
        }
        catch (Exception ex)
        {
            result = HelperService.Err(ex.Message);
        }

        ReplyString(context, result);
    }

    /// <summary>Members that skip polkit: they touch no PAM file, no key and
    /// no backup, the bus is local-only, and gating them meant an
    /// authentication dialog for merely opening the app. AcknowledgeAttention
    /// does write — it deletes the notice file — but only discards a message
    /// the caller was just shown, and the same findings are also in the
    /// journal and pacman's log, so there is nothing to gain by suppressing
    /// them here.</summary>
    private static bool SkipsPolkit(string member) =>
        member is "GetStatus" or "Preflight" or "ListDevices" or "AcknowledgeAttention";

    private static void ReplyString(MethodContext context, string value)
    {
        // Deliberately no `using`: the send is queued asynchronously, and
        // disposing the writer returns its pooled buffers while the frame is
        // still in flight, corrupting the message (the bus then drops us).
        var writer = context.CreateReplyWriter("s");
        writer.WriteString(value);
        context.Reply(writer.CreateMessage());
    }

    private static readonly string IntrospectXml = $"""
        <!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
         "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
        <node>
          <interface name="{HelperDaemon.Interface}">
            <method name="GetStatus"><arg type="s" direction="out"/></method>
            <method name="Preflight"><arg type="s" direction="out"/></method>
            <method name="ListDevices"><arg type="s" direction="out"/></method>
            <method name="Enroll">
              <arg type="s" direction="in"/><arg type="s" direction="in"/>
              <arg type="s" direction="in"/><arg type="s" direction="out"/>
            </method>
            <method name="RemoveKey">
              <arg type="s" direction="in"/><arg type="u" direction="in"/>
              <arg type="s" direction="out"/>
            </method>
            <method name="SelfTest"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
            <method name="Apply"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
            <method name="ConfirmKeep"><arg type="s" direction="out"/></method>
            <method name="Revert"><arg type="s" direction="out"/></method>
            <method name="RestoreDefaults"><arg type="s" direction="out"/></method>
            <method name="AcknowledgeAttention"><arg type="s" direction="out"/></method>
          </interface>
        </node>
        """;
}

internal static class DBusCalls
{
    // MessageWriter is a mutable struct — it must be passed by ref, or the
    // body gets written into a copy and a header-only (malformed) frame is
    // sent, which makes the bus drop the connection.
    private delegate void BodyWriter(ref MessageWriter writer);

    public static Task<uint> RequestNameAsync(Connection connection, string name)
        => CallDBus(connection, "RequestName", "su", (ref MessageWriter writer) =>
        {
            writer.WriteString(name);
            writer.WriteUInt32(4); // DBUS_NAME_FLAG_DO_NOT_QUEUE
        });

    public static Task<uint> GetPidAsync(Connection connection, string busName)
        => CallDBus(connection, "GetConnectionUnixProcessID", "s",
            (ref MessageWriter writer) => writer.WriteString(busName));

    public static Task<uint> GetUidAsync(Connection connection, string busName)
        => CallDBus(connection, "GetConnectionUnixUser", "s",
            (ref MessageWriter writer) => writer.WriteString(busName));

    private static Task<uint> CallDBus(
        Connection connection, string member, string signature, BodyWriter writeArgs)
    {
        // No `using` on the writer: the send is queued asynchronously and the
        // pooled buffers must stay alive until it completes.
        var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(
            destination: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            @interface: "org.freedesktop.DBus",
            member: member,
            signature: signature);
        writeArgs(ref writer);
        return connection.CallMethodAsync(
            writer.CreateMessage(),
            static (Message m, object? _) => m.GetBodyReader().ReadUInt32(),
            (object?)null);
    }
}
