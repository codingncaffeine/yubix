using System.Globalization;
using System.Text.Json.Nodes;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using Yubix.Core;

namespace Yubix.App;

public partial class MainWindow : Window
{
    private enum OverlayState { None, EnrollForm, Touch, Countdown, Message, ConfirmRestore, ConfirmTwoFactor, ConfirmRemoveKey, Busy }

    private readonly HelperClient _helper = new();
    private OverlayState _overlayState = OverlayState.None;
    private DispatcherTimer? _countdownTimer;
    private DateTime _deadlineUtc;
    private bool _updatingUi;
    private bool _busy;
    private bool _simulatedDevice;
    private int _enrolledKeyCount;
    private Dictionary<string, string>? _pendingModes;
    private (string User, uint Index, string Nickname)? _pendingRemoveKey;

    private static readonly IBrush BadgeOnBrush = new SolidColorBrush(Color.Parse("#153A41"));
    private static readonly IBrush BadgeOnText = new SolidColorBrush(Color.Parse("#5BD5E8"));
    private static readonly IBrush BadgeOffBrush = new SolidColorBrush(Color.Parse("#2C2C33"));
    private static readonly IBrush BadgeOffText = new SolidColorBrush(Color.Parse("#9A9AA3"));

    public MainWindow()
    {
        InitializeComponent();
        Opened += async (_, _) => await RefreshAllAsync(initial: true);
    }

    // ---------- data refresh ----------

    private async Task RefreshAllAsync(bool initial = false)
    {
        if (initial)
            Log(_helper.FakeMode
                ? "fake-root mode: session bus, no real /etc is touched"
                : "connecting to the Yubix helper (making changes will ask you to authenticate)");

        var status = await _helper.CallAsync(m => m.GetStatusAsync());
        if (!status.Ok)
        {
            StatusPill.Text = "Helper unavailable";
            DeviceText.Text = "Cannot reach the Yubix helper service: " + status.Error;
            Log("helper error: " + status.Error);
            return;
        }

        StatusPill.Text = _helper.FakeMode ? "Connected (fake mode)" : "Helper connected";
        var data = status.Data!;

        // Packages
        var packages = data["packages"];
        var missing = new List<string>();
        if (packages?["pamU2f"]?.GetValue<bool>() != true) missing.Add("pam-u2f");
        if (packages?["fido2Token"]?.GetValue<bool>() != true) missing.Add("libfido2");
        if (missing.Count > 0 && !_helper.FakeMode)
            Log("missing packages: " + string.Join(", ", missing) +
                " — install with: sudo pacman -S --needed pam-u2f libfido2");

        // Keys
        KeysPanel.Children.Clear();
        var keys = data["keys"] as JsonArray;
        _enrolledKeyCount = keys?.Count ?? 0;
        if (keys is { Count: > 0 })
        {
            KeysEmptyText.IsVisible = false;
            // The Nth listed key for a user is the Nth credential on their
            // mapping line — that per-user index is what RemoveKey takes.
            var perUserIndex = new Dictionary<string, uint>();
            foreach (var key in keys)
            {
                var user = key?["user"]?.GetValue<string>() ?? "";
                var nickname = key?["nickname"]?.GetValue<string>() ?? "key";
                var index = perUserIndex.GetValueOrDefault(user);
                perUserIndex[user] = index + 1;

                var added = key?["addedUtc"]?.GetValue<DateTime>();
                var row = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
                row.Children.Add(new TextBlock
                {
                    Classes = { "muted" },
                    VerticalAlignment = VerticalAlignment.Center,
                    Text = $"🔑  {nickname} — user {user}" +
                           (added is null ? "" : $", added {added:yyyy-MM-dd}"),
                });
                var removeBtn = new Button
                {
                    Classes = { "subtle" },
                    Content = "Remove…",
                    FontSize = 12,
                    Padding = new Thickness(10, 4),
                };
                removeBtn.Click += (_, _) => OnRemoveKey(user, index, nickname);
                Grid.SetColumn(removeBtn, 1);
                row.Children.Add(removeBtn);
                KeysPanel.Children.Add(row);
            }
        }
        else
        {
            KeysEmptyText.IsVisible = true;
        }

        // Surfaces
        var surfaces = data["surfaces"];
        _updatingUi = true;
        try
        {
            SetSurfaceUi(surfaces?["sudo"], SudoModeBox, SudoBadge, SudoBadgeText);
            SetSurfaceUi(surfaces?["lockscreen"], LockModeBox, LockBadge, LockBadgeText);
            SetSurfaceUi(surfaces?["login"], LoginModeBox, LoginBadge, LoginBadgeText, maxIndex: 1);
        }
        finally
        {
            _updatingUi = false;
        }

        // Pending apply left over from a crash?
        if (data["pending"] is not null && _overlayState != OverlayState.Countdown)
            Log("warning: an unconfirmed apply is pending — use “Revert last change” to clear it");

        // OS-update watchdog: findings the pacman hook left while the app was
        // closed, plus live drift/health checks recomputed by the helper.
        if (data["attention"] is JsonArray attention)
            foreach (var a in attention)
                Log("⚠ update check: " + a?.GetValue<string>());
        if (surfaces is not null)
            foreach (var kv in surfaces.AsObject())
            {
                if (kv.Value?["drift"] is JsonArray drift)
                    foreach (var flag in drift)
                        Log($"⚠ {kv.Key}: {Drift.Describe(flag?.GetValue<string>() ?? "")}");
                if (kv.Value?["pacnewPresent"]?.GetValue<bool>() == true)
                    Log($"⚠ {kv.Key}: a .pacnew file is waiting in /etc/pam.d — merge it; an overwrite would drop the Yubix line");
            }
        var health = data["health"];
        if (health?["polkitSandboxOk"]?.GetValue<bool>() == false)
            Log("⚠ polkit's auth helper lost the pam-u2f drop-in — admin-prompt key auth will fail (reinstall pam-u2f)");
        if (health?["loginServiceSupported"]?.GetValue<bool>() == false)
            Log($"⚠ unsupported login screen ({health?["displayManagerService"]?.GetValue<string>()}) — Yubix manages plasmalogin and sddm; the login surface won't apply to this one");
        if (health?["lockscreenNativeU2f"]?.GetValue<bool>() == true)
            Log("ℹ this Plasma has native lock-screen key support (kde-u2f) — a future Yubix version will migrate to it");
        if (data["staleLoginServices"] is JsonArray stale)
            foreach (var s in stale)
                Log($"⚠ the display manager changed: '{s?.GetValue<string>()}' still carries a Yubix line that is no longer used — Restore Defaults cleans it, then re-apply");

        await RefreshDevicesAsync();
    }

    private static int ModeToIndex(string? mode) => mode switch
    {
        "passwordless" => 1,
        "twoFactor" => 2,
        _ => 0,
    };

    private void SetSurfaceUi(JsonNode? surface, ComboBox box, Border badge, TextBlock badgeText, int maxIndex = 2)
    {
        var mode = surface?["mode"]?.GetValue<string>();
        var available = surface?["available"]?.GetValue<bool>() ?? false;
        var index = Math.Min(ModeToIndex(mode), maxIndex);
        box.SelectedIndex = index;
        box.IsEnabled = available && !_busy;

        badgeText.Text = !available ? "n/a" : index switch
        {
            1 => "touch",
            2 => "2FA",
            _ => "off",
        };
        badge.Background = index > 0 ? BadgeOnBrush : BadgeOffBrush;
        badgeText.Foreground = index > 0 ? BadgeOnText : BadgeOffText;

        var foreign = surface?["foreign"] as JsonArray;
        if (foreign is { Count: > 0 })
            ToolTip.SetTip(badge, "Existing auth lines found:\n" +
                string.Join("\n", foreign.Select(f => f?.GetValue<string>())));
    }

    private async Task RefreshDevicesAsync()
    {
        var result = await _helper.CallAsync(m => m.ListDevicesAsync());
        if (!result.Ok)
        {
            DeviceText.Text = "Device check failed: " + result.Error;
            return;
        }
        _simulatedDevice = result.Data?["simulated"]?.GetValue<bool>() ?? false;
        var devices = result.Data?["devices"] as JsonArray;
        DeviceText.Text = devices is { Count: > 0 }
            ? (_simulatedDevice ? "⚠️  " : "✅  ") +
              string.Join("   •   ", devices.Select(d => d?["description"]?.GetValue<string>())) +
              (_helper.FakeMode && !_simulatedDevice ? "   (real key, demo sandbox)" : "")
            : "No security key detected — plug in your YubiKey (or any FIDO2 key) and hit Refresh.";
    }

    // ---------- event handlers ----------

    private async void OnRefresh(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        await RefreshAllAsync();
        Log("status refreshed");
    }

    private void OnModeChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (_updatingUi) return;
        FooterHint.Text = "Unapplied changes — click “Apply changes” to run the safety-checked apply.";
    }

    private void OnRemoveKey(string user, uint index, string nickname)
    {
        if (_busy) return;
        _pendingRemoveKey = (user, index, nickname);
        ShowOverlay(OverlayState.ConfirmRemoveKey,
            $"Remove “{nickname}”?",
            $"The key will immediately stop working for user “{user}” everywhere. " +
            "Password login is never affected, and any other enrolled keys keep working. " +
            "If this is the last key, all surfaces simply fall back to password for this user. " +
            "(Undo from a terminal: sudo yubix-restore --last.)",
            primary: "Remove key", secondary: "Cancel");
    }

    private void OnEnroll(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        NickBox.Text = "";
        PinBox.Text = "";
        string enrollIntro;
        if (_helper.FakeMode && _simulatedDevice)
        {
            enrollIntro = "DEMO (no key detected): enrollment will be simulated instantly with no touch steps. " +
                          "Plug in your key and hit Refresh to demo the real hardware flow.";
        }
        else
        {
            enrollIntro = $"The key will be enrolled for user “{Environment.UserName}”. You'll touch it twice: " +
                          "once to enroll, then once on a live test that proves it works — only then does it become usable.";
            if (_helper.FakeMode)
                enrollIntro += " (Demo sandbox: your real key is used, but all file changes stay inside the demo copy of the system.)";
        }
        ShowOverlay(OverlayState.EnrollForm, "Enroll this security key", enrollIntro,
            primary: "Start enrollment", secondary: "Cancel");
    }

    private async void OnApply(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;

        var modes = new Dictionary<string, string>
        {
            ["sudo"] = IndexToMode(SudoModeBox.SelectedIndex),
            ["polkit"] = IndexToMode(SudoModeBox.SelectedIndex),
            ["lockscreen"] = IndexToMode(LockModeBox.SelectedIndex),
            ["login"] = IndexToMode(LoginModeBox.SelectedIndex),
        };

        // 2FA makes the key mandatory on those surfaces — with a single
        // enrolled key that's a real lockout risk, so demand acknowledgment.
        if (modes.ContainsValue("twoFactor") && _enrolledKeyCount < 2)
        {
            _pendingModes = modes;
            ShowOverlay(OverlayState.ConfirmTwoFactor,
                "2FA with a single key — are you sure?",
                "Password + touch means a password alone will NO LONGER work on those surfaces. " +
                "With only one enrolled key, losing or breaking it locks them until you recover — " +
                "TTY login (Ctrl+Alt+F3) always still works with your password, and running " +
                "“yubix-restore --last” there undoes everything. Enrolling a second backup key " +
                "first is strongly recommended.",
                primary: "I understand — apply anyway", secondary: "Cancel");
            return;
        }

        await DoApplyAsync(modes);
    }

    private async Task DoApplyAsync(Dictionary<string, string> modes)
    {
        SetBusy(true);
        ShowOverlay(OverlayState.Busy, "Applying…",
            "Backing up originals and writing the new PAM configuration.", primary: null, secondary: null);

        var config = Json.Serialize(new { modes, countdownSeconds = 90 });
        var result = await _helper.CallAsync(m => m.ApplyAsync(config));
        SetBusy(false);

        if (!result.Ok)
        {
            ShowOverlay(OverlayState.Message, "Nothing applied", result.Error ?? "unknown error",
                primary: "OK", secondary: null);
            Log("apply refused: " + result.Error);
            return;
        }

        _deadlineUtc = result.Data?["deadlineUtc"]?.GetValue<DateTime>().ToUniversalTime()
                       ?? DateTime.UtcNow.AddSeconds(90);
        Log("applied — confirm within the countdown or everything auto-reverts");
        ShowOverlay(OverlayState.Countdown,
            "Keep these settings?",
            "The new configuration is live. Open a NEW terminal and try sudo now if you want proof. " +
            "If you do nothing, Yubix restores everything automatically.",
            primary: "Keep settings", secondary: "Revert now");
        OverlayCountdown.IsVisible = true;
        StartCountdownTimer();
    }

    private async void OnRevert(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        SetBusy(true);
        var result = await _helper.CallAsync(m => m.RevertAsync());
        SetBusy(false);
        Log(result.Ok ? "reverted last change" : "revert: " + result.Error);
        await RefreshAllAsync();
    }

    private void OnRestoreDefaults(object? sender, RoutedEventArgs e)
    {
        if (_busy) return;
        ShowOverlay(OverlayState.ConfirmRestore,
            "Restore everything to default?",
            "Removes every Yubix change from PAM: password-only authentication everywhere, exactly like a fresh system. Enrolled key data is kept.",
            primary: "Restore defaults", secondary: "Cancel");
    }

    private async void OnOverlayPrimary(object? sender, RoutedEventArgs e)
    {
        switch (_overlayState)
        {
            case OverlayState.EnrollForm:
                await RunEnrollFlowAsync();
                break;

            case OverlayState.Countdown:
                StopCountdownTimer();
                var confirm = await _helper.CallAsync(m => m.ConfirmKeepAsync());
                HideOverlay();
                Log(confirm.Ok ? "settings confirmed and kept ✔" : "confirm failed: " + confirm.Error);
                await RefreshAllAsync();
                break;

            case OverlayState.ConfirmTwoFactor:
                var pendingModes = _pendingModes;
                _pendingModes = null;
                HideOverlay();
                if (pendingModes is not null) await DoApplyAsync(pendingModes);
                break;

            case OverlayState.ConfirmRemoveKey:
                var pendingRemove = _pendingRemoveKey;
                _pendingRemoveKey = null;
                if (pendingRemove is null) { HideOverlay(); break; }
                ShowOverlay(OverlayState.Busy, "Removing key…",
                    "Rewriting the key mapping (a backup is kept).", primary: null, secondary: null);
                var remove = await _helper.CallAsync(m =>
                    m.RemoveKeyAsync(pendingRemove.Value.User, pendingRemove.Value.Index));
                HideOverlay();
                if (remove.Ok)
                {
                    var note = remove.Data?["note"]?.GetValue<string>();
                    Log($"removed “{pendingRemove.Value.Nickname}”" + (note is null ? "" : " — " + note));
                }
                else
                {
                    Log("remove failed: " + remove.Error);
                }
                await RefreshAllAsync();
                break;

            case OverlayState.ConfirmRestore:
                ShowOverlay(OverlayState.Busy, "Restoring…", "Removing all Yubix PAM changes.",
                    primary: null, secondary: null);
                var restore = await _helper.CallAsync(m => m.RestoreDefaultsAsync());
                HideOverlay();
                Log(restore.Ok ? "restored to defaults" : "restore failed: " + restore.Error);
                await RefreshAllAsync();
                break;

            case OverlayState.Message:
            default:
                HideOverlay();
                break;
        }
    }

    private async void OnOverlaySecondary(object? sender, RoutedEventArgs e)
    {
        switch (_overlayState)
        {
            case OverlayState.Countdown:
                StopCountdownTimer();
                var result = await _helper.CallAsync(m => m.RevertAsync());
                HideOverlay();
                Log(result.Ok ? "reverted on request" : "revert failed: " + result.Error);
                await RefreshAllAsync();
                break;

            default:
                HideOverlay();
                break;
        }
    }

    // ---------- flows ----------

    private async Task RunEnrollFlowAsync()
    {
        var nickname = string.IsNullOrWhiteSpace(NickBox.Text) ? "Security key" : NickBox.Text!.Trim();
        var pin = PinBox.Text ?? "";
        var user = Environment.UserName;

        SetBusy(true);
        try
        {
            var sim = _helper.FakeMode && _simulatedDevice;
            ShowOverlay(OverlayState.Touch,
                sim ? "Simulating enrollment (demo)" : "Touch your key",
                sim ? "Demo mode: creating a simulated credential — no touch needed."
                    : "Enrolling… when the key starts blinking, touch it.",
                primary: null, secondary: null);
            OverlayTouchGlyph.IsVisible = true;

            var enroll = await _helper.CallAsync(m => m.EnrollAsync(user, nickname, pin));
            if (!enroll.Ok)
            {
                ShowOverlay(OverlayState.Message, "Enrollment failed", enroll.Error ?? "unknown error",
                    primary: "OK", secondary: null);
                Log("enrollment failed: " + enroll.Error);
                return;
            }
            Log($"enrolled “{nickname}” for {user} (staged)");

            ShowOverlay(OverlayState.Touch,
                sim ? "Simulating verification (demo)" : "Touch again to verify",
                sim ? "Demo mode: running the live PAM self-test against the simulated credential."
                    : "Yubix is now live-testing the enrollment through real PAM on a throwaway service. Touch the key when it blinks — nothing becomes usable until this passes.",
                primary: null, secondary: null);
            OverlayTouchGlyph.IsVisible = true;

            var testConfig = Json.Serialize(new { user, pin = pin.Length > 0 ? pin : null, promote = true });
            var test = await _helper.CallAsync(m => m.SelfTestAsync(testConfig));

            if (test.Ok && test.Data?["success"]?.GetValue<bool>() == true)
            {
                ShowOverlay(OverlayState.Message,
                    sim ? "Simulated key verified ✔ (demo)" : "Key verified ✔",
                    $"“{nickname}” enrolled and live-tested successfully. You can now enable it for sudo, the lock screen, or login below." +
                    (sim ? " (Demo — this was a simulated credential, not your real key.)"
                         : _helper.FakeMode ? " (Demo sandbox — your real key authenticated through real PAM; only demo files were written.)" : ""),
                    primary: "Done", secondary: null);
                Log("self-test passed — enrollment promoted to live mapping");
            }
            else
            {
                var msg = test.Error ?? test.Data?["message"]?.GetValue<string>() ?? "unknown error";
                ShowOverlay(OverlayState.Message, "Verification failed",
                    "The live test did not pass, so nothing was activated. " + msg,
                    primary: "OK", secondary: null);
                Log("self-test failed: " + msg);
            }
        }
        finally
        {
            SetBusy(false);
            await RefreshAllAsync();
        }
    }

    // ---------- countdown ----------

    private void StartCountdownTimer()
    {
        StopCountdownTimer();
        _countdownTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _countdownTimer.Tick += async (_, _) =>
        {
            var remaining = _deadlineUtc - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                StopCountdownTimer();
                HideOverlay();
                Log("countdown expired — helper auto-reverted everything");
                await RefreshAllAsync();
                return;
            }
            OverlayCountdown.Text = Math.Ceiling(remaining.TotalSeconds)
                .ToString(CultureInfo.InvariantCulture);
        };
        _countdownTimer.Start();
    }

    private void StopCountdownTimer()
    {
        _countdownTimer?.Stop();
        _countdownTimer = null;
    }

    // ---------- overlay & misc ----------

    private void ShowOverlay(OverlayState state, string title, string body,
        string? primary, string? secondary)
    {
        _overlayState = state;
        OverlayTitle.Text = title;
        OverlayBody.Text = body;
        OverlayCountdown.IsVisible = false;
        OverlayTouchGlyph.IsVisible = false;
        OverlayForm.IsVisible = state == OverlayState.EnrollForm;
        OverlayPrimaryBtn.IsVisible = primary is not null;
        OverlayPrimaryBtn.Content = primary ?? "";
        OverlaySecondaryBtn.IsVisible = secondary is not null;
        OverlaySecondaryBtn.Content = secondary ?? "";
        Overlay.IsVisible = true;
    }

    private void HideOverlay()
    {
        _overlayState = OverlayState.None;
        Overlay.IsVisible = false;
    }

    private static string IndexToMode(int index) => index switch
    {
        1 => "passwordless",
        2 => "twoFactor",
        _ => "off",
    };

    private void SetBusy(bool busy)
    {
        _busy = busy;
        ApplyBtn.IsEnabled = !busy;
        RestoreBtn.IsEnabled = !busy;
        EnrollBtn.IsEnabled = !busy;
        RefreshBtn.IsEnabled = !busy;
        RevertBtn.IsEnabled = !busy;
    }

    private void Log(string message)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        var existing = LogText.Text ?? "";
        var lines = new List<string> { line };
        lines.AddRange(existing.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(39));
        LogText.Text = string.Join('\n', lines);
    }
}
