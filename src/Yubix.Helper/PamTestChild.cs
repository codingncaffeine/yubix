using System.Runtime.InteropServices;
using System.Text.Json;
using Yubix.Core;

namespace Yubix.Helper;

/// <summary>
/// Child-process mode (`yubix-helper --pam-test <service> <user>`): performs a
/// real PAM authentication via libpam with a managed conversation function.
/// Secrets arrive as one JSON object on stdin ({"pin":...,"password":...});
/// progress and the final verdict are emitted as JSON lines on stdout:
///   {"e":"info","t":"Please touch the FIDO authenticator."}
///   {"e":"prompt","t":"..."}        (a secret was requested and supplied)
///   {"e":"result","ok":true,"code":0,"msg":"success"}
/// The parent enforces the timeout and can kill this process at any point —
/// libpam is not cancellation-safe in-process, which is why this is a child.
/// </summary>
internal static class PamTestChild
{
    private const int PamSuccess = 0;
    private const int PamConvErr = 19;
    private const int PromptEchoOff = 1;
    private const int PromptEchoOn = 2;
    private const int ErrorMsg = 3;
    private const int TextInfo = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct PamMessage
    {
        public int Style;
        public IntPtr Msg;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PamResponse
    {
        public IntPtr Resp;
        public int RetCode;
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int PamConvFn(int numMsg, IntPtr messages, out IntPtr responses, IntPtr appData);

    [StructLayout(LayoutKind.Sequential)]
    private struct PamConv
    {
        public PamConvFn Callback;
        public IntPtr AppData;
    }

    [DllImport("libpam.so.0", CharSet = CharSet.Ansi)]
    private static extern int pam_start(string service, string user, ref PamConv conv, out IntPtr handle);

    [DllImport("libpam.so.0")]
    private static extern int pam_authenticate(IntPtr handle, int flags);

    [DllImport("libpam.so.0")]
    private static extern int pam_end(IntPtr handle, int status);

    [DllImport("libpam.so.0")]
    private static extern IntPtr pam_strerror(IntPtr handle, int errnum);

    private static string? _pin;
    private static string? _password;
    // Rooted so the GC can never collect the delegate while libpam holds it.
    private static PamConvFn? _rootedCallback;

    public static int Run(string service, string user)
    {
        // The conversation must never read the wrong per-user config.
        Environment.SetEnvironmentVariable("XDG_CONFIG_HOME", null);

        try
        {
            var stdin = Console.In.ReadToEnd();
            if (!string.IsNullOrWhiteSpace(stdin))
            {
                using var doc = JsonDocument.Parse(stdin);
                if (doc.RootElement.TryGetProperty("pin", out var pin))
                    _pin = pin.GetString();
                if (doc.RootElement.TryGetProperty("password", out var pw))
                    _password = pw.GetString();
            }
        }
        catch
        {
            // No secrets supplied — touch-only flows work without any.
        }

        _rootedCallback = Converse;
        var conv = new PamConv { Callback = _rootedCallback, AppData = IntPtr.Zero };

        var rc = pam_start(service, user, ref conv, out var handle);
        if (rc != PamSuccess)
        {
            Emit(new { e = "result", ok = false, code = rc, msg = $"pam_start failed ({rc})" });
            return 0;
        }

        rc = pam_authenticate(handle, 0);
        var msg = Marshal.PtrToStringAnsi(pam_strerror(handle, rc)) ?? $"code {rc}";
        pam_end(handle, rc);

        Emit(new { e = "result", ok = rc == PamSuccess, code = rc, msg });
        return 0;
    }

    private static int Converse(int numMsg, IntPtr messages, out IntPtr responses, IntPtr appData)
    {
        responses = IntPtr.Zero;
        if (numMsg <= 0) return PamConvErr;

        var respSize = Marshal.SizeOf<PamResponse>();
        var respArray = Marshal.AllocHGlobal(numMsg * respSize);
        // Zero the response array first: libpam frees resp pointers on error paths.
        for (var i = 0; i < numMsg * respSize; i++)
            Marshal.WriteByte(respArray, i, 0);

        for (var i = 0; i < numMsg; i++)
        {
            // Linux-PAM passes an array of pam_message pointers.
            var msgPtr = Marshal.ReadIntPtr(messages, i * IntPtr.Size);
            var message = Marshal.PtrToStructure<PamMessage>(msgPtr);
            var text = Marshal.PtrToStringAnsi(message.Msg) ?? "";

            switch (message.Style)
            {
                case TextInfo:
                    Emit(new { e = "info", t = text });
                    break;
                case ErrorMsg:
                    Emit(new { e = "error", t = text });
                    break;
                case PromptEchoOff:
                case PromptEchoOn:
                    var isPin = text.Contains("PIN", StringComparison.OrdinalIgnoreCase);
                    var answer = isPin ? _pin : _password;
                    if (answer is null)
                    {
                        Emit(new { e = "error", t = $"no secret available for prompt: {text}" });
                        Marshal.FreeHGlobal(respArray);
                        return PamConvErr;
                    }
                    Emit(new { e = "prompt", t = text });
                    var resp = new PamResponse
                    {
                        Resp = Marshal.StringToHGlobalAnsi(answer),
                        RetCode = 0,
                    };
                    Marshal.StructureToPtr(resp, respArray + i * respSize, false);
                    break;
            }
        }

        responses = respArray;
        return PamSuccess;
    }

    private static void Emit(object payload)
    {
        Console.WriteLine(JsonSerializer.Serialize(payload, Json.Options));
        Console.Out.Flush();
    }
}
