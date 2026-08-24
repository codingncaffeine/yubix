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
        connection.AddMethodHandler(new ManagerHandler(connection, paths, service));
        await DBusCalls.RequestNameAsync(connection, BusName);

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
            if (!_paths.FakeMode && !await Polkit.CheckAsync(_connection, sender))
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

    private static void ReplyString(MethodContext context, string value)
    {
        using var writer = context.CreateReplyWriter("s");
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
    public static Task<uint> RequestNameAsync(Connection connection, string name)
        => CallDBus(connection, "RequestName", writer =>
        {
            writer.WriteString(name);
            writer.WriteUInt32(4); // DBUS_NAME_FLAG_DO_NOT_QUEUE
        }, "su");

    public static Task<uint> GetPidAsync(Connection connection, string busName)
        => CallDBus(connection, "GetConnectionUnixProcessID",
            writer => writer.WriteString(busName), "s");

    public static Task<uint> GetUidAsync(Connection connection, string busName)
        => CallDBus(connection, "GetConnectionUnixUser",
            writer => writer.WriteString(busName), "s");

    private static Task<uint> CallDBus(
        Connection connection, string member, Action<MessageWriter> writeArgs, string signature)
    {
        using var writer = connection.GetMessageWriter();
        writer.WriteMethodCallHeader(
            destination: "org.freedesktop.DBus",
            path: "/org/freedesktop/DBus",
            @interface: "org.freedesktop.DBus",
            member: member,
            signature: signature);
        writeArgs(writer);
        return connection.CallMethodAsync(
            writer.CreateMessage(),
            static (Message m, object? _) => m.GetBodyReader().ReadUInt32(),
            (object?)null);
    }
}
