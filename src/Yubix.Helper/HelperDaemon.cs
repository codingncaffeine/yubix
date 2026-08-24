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
        connection.AddMethodHandler(new ManagerHandler(connection, paths, service));

        Console.WriteLine(
            $"yubix-helper: serving {BusName} on the {(paths.FakeMode ? "session" : "system")} bus" +
            (paths.FakeMode ? $" (fake root: {paths.Root})" : ""));

        await Task.Delay(Timeout.Infinite);
        return 0;
    }
}

internal sealed class ManagerHandler : IMethodHandler
{
    private readonly Connection _connection;
    private readonly YubixPaths _paths;
    private readonly HelperService _service;

    public ManagerHandler(Connection connection, YubixPaths paths, HelperService service)
    {
        _connection = connection;
        _paths = paths;
        _service = service;
    }

    public string Path => HelperDaemon.ObjectPath;

    public bool RunMethodHandlerSynchronously(Message message) => false;

    public async ValueTask HandleMethodAsync(MethodContext context)
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
            if (!_paths.FakeMode && !IsReadOnly(member) && !await Polkit.CheckAsync(_connection, sender))
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
                "SelfTest" => await _service.SelfTestAsync(reader.ReadString()),
                "Apply" => await _service.ApplyAsync(reader.ReadString()),
                "ConfirmKeep" => await _service.ConfirmKeepAsync(),
                "Revert" => await _service.RevertAsync("user request"),
                "RestoreDefaults" => await _service.RestoreDefaultsAsync(),
                _ => HelperService.Err($"unknown method '{member}'"),
            };
        }
        catch (Exception ex)
        {
            result = HelperService.Err(ex.Message);
        }

        ReplyString(context, result);
    }

    /// <summary>Read-only queries skip polkit: they change nothing, the bus
    /// is local-only, and gating them meant an authentication dialog for
    /// merely opening the app.</summary>
    private static bool IsReadOnly(string member) =>
        member is "GetStatus" or "Preflight" or "ListDevices";

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
            <method name="SelfTest"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
            <method name="Apply"><arg type="s" direction="in"/><arg type="s" direction="out"/></method>
            <method name="ConfirmKeep"><arg type="s" direction="out"/></method>
            <method name="Revert"><arg type="s" direction="out"/></method>
            <method name="RestoreDefaults"><arg type="s" direction="out"/></method>
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
