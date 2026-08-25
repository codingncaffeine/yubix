using System.Globalization;
using System.Text.RegularExpressions;
using Yubix.Core;

namespace Yubix.Helper;

/// <summary>
/// All privileged operations. Serialized behind one gate — the helper serves a
/// single desktop app; simplicity beats throughput here.
/// </summary>
public sealed partial class HelperService
{
    // The strict shape kills header/mapping injection: no colon, whitespace,
    // or newline can ever reach a u2f_mappings line or a PAM child argv.
    [GeneratedRegex(@"^[a-zA-Z_][a-zA-Z0-9._-]{0,31}$")]
    private static partial Regex UserNameRegex();

    private readonly YubixPaths _paths;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private YubixState _state;

    private sealed record PendingApply(
        string ManifestPath, DateTime DeadlineUtc, YubixState PreState, Timer Timer);

    private PendingApply? _pending;

    public HelperService(YubixPaths paths)
    {
        _paths = paths;
        _state = StateStore.Load(paths);
        RecoverPendingOnStartup();
    }

    /// <summary>A pending-apply flag on disk with no live countdown means a
    /// previous helper died mid-apply or mid-countdown. The change was never
    /// confirmed, so revert it NOW instead of stranding it until reboot (the
    /// boot failsafe remains the backstop if even this fails).</summary>
    private void RecoverPendingOnStartup()
    {
        try
        {
            if (!File.Exists(_paths.PendingFlagFile)) return;
            var manifest = ParseFlag("manifest");
            if (manifest is null || !File.Exists(manifest))
            {
                Console.Error.WriteLine(
                    "yubix-helper: pending-apply flag found but its manifest is missing — leaving the flag armed");
                return;
            }
            Transaction.Restore(manifest);
            File.Delete(_paths.PendingFlagFile);
            _state = StateStore.Load(_paths);
            Console.WriteLine("yubix-helper: reverted an unconfirmed apply left by a previous helper run");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"yubix-helper: startup revert failed: {ex.Message} (the boot failsafe is still armed)");
        }
    }

    // ---------- result helpers ----------

    public static string Err(string message) => Json.Serialize(new { ok = false, error = message });
    private static string Ok(object? data = null) => Json.Serialize(new { ok = true, data });

    private async Task<string> Locked(Func<Task<string>> body)
    {
        await _gate.WaitAsync();
        try { return await body(); }
        catch (UnsupportedLayoutException ex) { return Err("unsupported PAM layout: " + ex.Message); }
        catch (Exception ex) { return Err(ex.Message); }
        finally { _gate.Release(); }
    }

    // ---------- GetStatus ----------

    /// <summary>Basename of the display-manager symlink target ("sddm.service"),
    /// read raw so a dangling link in a fake root still resolves.</summary>
    private string? ReadDmUnit()
    {
        try
        {
            var link = new FileInfo(_paths.DisplayManagerLink);
            var target = link.LinkTarget;
            return target is null ? null : Path.GetFileName(target);
        }
        catch { return null; }
    }

    private string ResolveLoginService() => Surfaces.ResolveLoginService(_paths, ReadDmUnit());

    public Task<string> GetStatusAsync() => Locked(async () =>
    {
        var loginService = ResolveLoginService();
        var surfaces = new Dictionary<string, object>();
        foreach (var id in Surfaces.All)
        {
            var service = Surfaces.ServiceFor(id, loginService);
            var etcPath = _paths.EtcService(service);
            var vendorPath = _paths.VendorService(service);
            string? current = File.Exists(etcPath) ? File.ReadAllText(etcPath) : null;
            string? vendorContent = File.Exists(vendorPath) ? File.ReadAllText(vendorPath) : null;
            string? baseContent = current ?? vendorContent;

            surfaces[id] = new
            {
                service,
                available = baseContent is not null,
                mode = current is null ? SurfaceMode.Off : PamGenerator.DetectMode(current),
                createdByYubix = _state.CreatedFiles.Contains(etcPath),
                overrideExists = current is not null,
                foreign = baseContent is null ? new List<string>() : PamGenerator.ForeignAuthLines(baseContent),
                drift = Drift.Classify(_state.SurfaceRecords.GetValueOrDefault(id), current, vendorContent),
                pacnewPresent = File.Exists(etcPath + ".pacnew"),
                pacsavePresent = File.Exists(etcPath + ".pacsave"),
                shortCircuited = baseContent is null
                    ? new List<string>()
                    : PamGenerator.ShortCircuitedHelpers(baseContent),
            };
        }

        var mappingExists = File.Exists(_paths.MappingFile);
        var status = new
        {
            fakeMode = _paths.FakeMode,
            origin = _state.Origin,
            packages = new
            {
                pamU2f = File.Exists("/usr/lib/security/pam_u2f.so"),
                pamu2fcfg = File.Exists("/usr/bin/pamu2fcfg"),
                fido2Token = File.Exists("/usr/bin/fido2-token"),
            },
            mapping = new
            {
                exists = mappingExists,
                stagedExists = File.Exists(_paths.StagedMappingFile),
                users = mappingExists
                    ? MappingFile.Users(File.ReadAllText(_paths.MappingFile)).ToList()
                    : new List<string>(),
            },
            keys = _state.Keys,
            surfaces,
            pending = ReadPendingInfo(),
            attention = ReadAttentionLines(),
            health = await CheckSystemHealthAsync(),
            // A DM switch (plasmalogin <-> sddm) can strand a Yubix line in
            // the no-longer-active login service's file — surface that.
            staleLoginServices = Surfaces.KnownLoginServices
                .Where(s => s != loginService)
                .Where(s => File.Exists(_paths.EtcService(s)) &&
                    (PamGenerator.HasMarker(File.ReadAllText(_paths.EtcService(s))) ||
                     _state.CreatedFiles.Contains(_paths.EtcService(s))))
                .ToList(),
        };
        return Ok(status);
    });

    /// <summary>Findings the pacman hook (yubix-pamcheck) left behind after a
    /// transaction that ran while the app was closed.</summary>
    private List<string> ReadAttentionLines()
    {
        try
        {
            if (File.Exists(_paths.AttentionFile))
                return File.ReadAllLines(_paths.AttentionFile)
                    .Where(l => l.Trim().Length > 0).Take(20).ToList();
        }
        catch { }
        return new List<string>();
    }

    private sealed record SystemHealth(
        bool? PolkitSandboxOk,
        bool LockscreenNativeU2f,
        bool PamU2fConfPresent,
        string? DisplayManagerService,
        bool LoginServiceSupported);

    /// <summary>Ways the OS can break key auth without touching a PAM file we
    /// wrote. Real mode only — none of this exists inside a fake root.</summary>
    private async Task<SystemHealth?> CheckSystemHealthAsync()
    {
        if (_paths.FakeMode) return null;

        // polkit 126+ hard-sandboxes its auth helper; pam_u2f only reaches
        // /dev/hidraw through pam-u2f's shipped drop-in. A polkit update that
        // detaches it kills admin-prompt key auth with zero PAM changes.
        bool? polkitSandboxOk = null;
        var (exit, unitText, _) = await External.RunAsync(
            "systemctl", new[] { "cat", "polkit-agent-helper@.service" }, timeoutMs: 10_000);
        if (exit == 0)
            polkitSandboxOk = unitText.Contains("PrivateDevices=no") && unitText.Contains("char-hidraw");

        // Plasma 6.8 ships a native lock-screen U2F path (kde-u2f service +
        // kscreenlockerrc [Authenticators]); our 6.7-style kde override stops
        // being the intended integration once that lands.
        var lockscreenNativeU2f = File.Exists(_paths.VendorService("kde-u2f"));
        var (klExit, klOut, _) = await External.RunAsync(
            "pacman", new[] { "-Q", "kscreenlocker" }, timeoutMs: 10_000);
        if (klExit == 0 && ParsePacmanVersion(klOut) is { } klVersion && klVersion >= new Version(6, 8))
            lockscreenNativeU2f = true;

        // The login-screen PAM service already changed names once (sddm →
        // plasmalogin on CachyOS); detect the next switch via the DM alias.
        var dmService = ReadDmUnit();

        return new SystemHealth(
            polkitSandboxOk,
            lockscreenNativeU2f,
            // pam_u2f 1.4.0's global defaults file can alter options we don't
            // pin (pinverification, …) underneath our line.
            PamU2fConfPresent: File.Exists("/etc/security/pam_u2f.conf"),
            DisplayManagerService: dmService,
            LoginServiceSupported: dmService is null || Surfaces.LoginServiceForDm(dmService) is not null);
    }

    private object? ReadPendingInfo()
    {
        if (_pending is not null)
            return new { deadlineUtc = _pending.DeadlineUtc, manifest = _pending.ManifestPath };
        if (!File.Exists(_paths.PendingFlagFile)) return null;
        // Flag exists but no in-memory pending: a previous helper died mid-apply.
        return new { deadlineUtc = (DateTime?)null, manifest = ParseFlag("manifest"), stale = true };
    }

    private string? ParseFlag(string key)
    {
        try
        {
            foreach (var line in File.ReadAllLines(_paths.PendingFlagFile))
                if (line.StartsWith(key + "=", StringComparison.Ordinal))
                    return line[(key.Length + 1)..];
        }
        catch { }
        return null;
    }

    // ---------- Preflight ----------

    public Task<string> PreflightAsync() => Locked(async () =>
    {
        var checks = new List<object>();
        void Check(string id, bool ok, string detail, string severity = "error") =>
            checks.Add(new { id, ok, detail, severity });

        var root = _paths.FakeMode || Environment.IsPrivilegedProcess;
        Check("helper-root", root, root ? "helper has root privileges" : "helper is not running as root");

        if (_paths.FakeMode)
        {
            Check("packages", true, "fake mode: module checks skipped", "info");
            Check("device", true, "fake mode: device check skipped", "info");
        }
        else
        {
            Check("pam-u2f", File.Exists("/usr/lib/security/pam_u2f.so"),
                "pam_u2f module (pam-u2f package)");
            Check("pamu2fcfg", File.Exists("/usr/bin/pamu2fcfg"),
                "pamu2fcfg enrollment tool (pam-u2f package)");
            Check("fido2-token", File.Exists("/usr/bin/fido2-token"),
                "fido2-token device tool (libfido2 package)");

            var (u2fVersionOk, u2fVersionDetail) = await CheckPamU2fVersionAsync();
            Check("pam-u2f-version", u2fVersionOk, u2fVersionDetail);

            var health = await CheckSystemHealthAsync();
            if (health?.PolkitSandboxOk is not null)
                Check("polkit-sandbox", health.PolkitSandboxOk.Value,
                    health.PolkitSandboxOk.Value
                        ? "polkit auth helper can reach the security key (pam-u2f drop-in attached)"
                        : "polkit's auth helper sandbox is missing the pam-u2f drop-in — key auth in admin prompts would fail (reinstall pam-u2f)",
                    "warning");
            if (health?.PamU2fConfPresent == true)
                Check("pam-u2f-conf", false,
                    "/etc/security/pam_u2f.conf exists — its global defaults can change unpinned pam_u2f options underneath Yubix's line",
                    "warning");

            var devices = await FidoDevices.ListAsync();
            Check("device", devices.Count > 0,
                devices.Count > 0
                    ? $"security key detected: {devices[0].Description}"
                    : "no FIDO2 security key detected — insert your key");
        }

        var loginService = ResolveLoginService();
        foreach (var id in Surfaces.All)
        {
            var service = Surfaces.ServiceFor(id, loginService);
            var etcPath = _paths.EtcService(service);
            var vendorPath = _paths.VendorService(service);
            var baseContent = File.Exists(etcPath) ? File.ReadAllText(etcPath)
                : File.Exists(vendorPath) ? File.ReadAllText(vendorPath) : null;
            if (baseContent is null)
            {
                Check($"surface-{id}", false, $"PAM service '{service}' not found", "warning");
                continue;
            }
            try
            {
                PamGenerator.Render(baseContent, SurfaceMode.Passwordless,
                    PamGenerator.BuildU2fLine(SurfaceMode.Passwordless, _state.Origin, _paths.MappingFile));
                var foreign = PamGenerator.ForeignAuthLines(baseContent);
                var skipped = PamGenerator.ShortCircuitedHelpers(baseContent);
                var notes = new List<string>();
                if (foreign.Count > 0)
                    notes.Add($"existing auth lines present: {string.Join(" | ", foreign)}");
                if (skipped.Count > 0)
                    notes.Add($"touch-only mode returns before {string.Join(", ", skipped)} runs, "
                        + "so the wallet/keyring will not auto-unlock");
                Check($"surface-{id}", true,
                    notes.Count > 0
                        ? $"'{service}' ready (note: {string.Join("; ", notes)})"
                        : $"'{service}' ready");
            }
            catch (UnsupportedLayoutException ex)
            {
                Check($"surface-{id}", false, $"'{service}': {ex.Message}", "warning");
            }
        }

        Check("no-pending", _pending is null && !File.Exists(_paths.PendingFlagFile),
            "no unconfirmed apply in progress", "warning");

        var allOk = checks.All(c => (bool)c.GetType().GetProperty("ok")!.GetValue(c)!);
        return Ok(new { allOk, checks });
    });

    // ---------- Devices ----------

    public Task<string> ListDevicesAsync() => Locked(async () =>
    {
        // Even in fake-root mode, prefer the REAL key when one is plugged in:
        // the sandbox isolates files, not hardware — the demo should exercise
        // the full enroll/touch/authenticate chain. Simulation is only the
        // fallback when no device is present (keeps CI and keyless demos working).
        var devices = await FidoDevices.ListAsync();
        if (devices.Count > 0)
            return Ok(new
            {
                simulated = false,
                devices = devices.Select(d => new { d.Path, d.Description }),
            });
        if (_paths.FakeMode)
            return Ok(new
            {
                simulated = true,
                devices = new[] { new { Path = "/dev/fake0", Description = "Simulated key (no real key detected)" } },
            });
        return Ok(new { simulated = false, devices = Array.Empty<object>() });
    });

    // ---------- Enroll ----------

    public Task<string> EnrollAsync(string user, string nickname, string pin) => Locked(async () =>
    {
        if (string.IsNullOrWhiteSpace(user)) return Err("no user given");
        if (!UserNameRegex().IsMatch(user))
            return Err($"invalid username '{External.Tail(user, 40)}' (letters, digits, '._-', max 32 chars)");
        nickname = string.IsNullOrWhiteSpace(nickname) ? "Security key" : nickname.Trim();
        if (nickname.Length > 64) nickname = nickname[..64];

        string credential;
        bool simulated = false;
        var realDevices = await FidoDevices.ListAsync();
        if (_paths.FakeMode && realDevices.Count == 0)
        {
            credential = $"FAKEKH{Guid.NewGuid():N},FAKEPK,es256,+presence";
            simulated = true;
        }
        else
        {
            var (exit, stdout, stderr) = await External.RunAsync(
                "pamu2fcfg",
                new[] { "-u", user, "-o", _state.Origin, "-i", _state.Origin },
                stdin: string.IsNullOrEmpty(pin) ? null : pin + "\n",
                timeoutMs: 60_000);
            if (exit != 0)
                return Err($"enrollment failed ({(exit == -2 ? "timed out waiting for touch" : $"exit {exit}")}): {External.Tail(stderr)}");
            credential = MappingFile.ExtractCredential(stdout, user);
        }

        var existing = File.Exists(_paths.StagedMappingFile)
            ? File.ReadAllText(_paths.StagedMappingFile)
            : File.Exists(_paths.MappingFile) ? File.ReadAllText(_paths.MappingFile) : "";
        var merged = MappingFile.Merge(existing, user, credential);
        Transaction.WriteAtomically(_paths.StagedMappingFile, merged,
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var count = MappingFile.CredentialCount(merged, user);
        var key = new EnrolledKey
        {
            User = user,
            Nickname = nickname,
            AddedUtc = DateTime.UtcNow,
            CredentialCount = count,
        };
        _state.Keys.Add(key);
        StateStore.Save(_paths, _state);

        return Ok(new { user, nickname, credentialCount = count, simulated, staged = true });
    });

    // ---------- RemoveKey ----------

    public Task<string> RemoveKeyAsync(string user, uint index) => Locked(() =>
    {
        if (string.IsNullOrWhiteSpace(user)) return Task.FromResult(Err("no user given"));
        if (!UserNameRegex().IsMatch(user)) return Task.FromResult(Err("invalid username"));
        if (File.Exists(_paths.StagedMappingFile))
            return Task.FromResult(Err(
                "an unverified enrollment is staged — finish its self-test (or Restore Defaults) before removing keys"));
        if (!File.Exists(_paths.MappingFile))
            return Task.FromResult(Err("no keys are enrolled"));

        string newContent;
        try
        {
            newContent = MappingFile.RemoveCredential(
                File.ReadAllText(_paths.MappingFile), user, (int)index);
        }
        catch (ArgumentException ex)
        {
            return Task.FromResult(Err(ex.Message));
        }

        // Backed up like any other change, so `yubix-restore --last` can undo
        // a fat-fingered removal. An empty mapping is deleted outright —
        // GetStatus and the Apply guard then read "nothing enrolled".
        Transaction.Apply(_paths, new List<FileChange>
        {
            new(_paths.MappingFile, newContent.Length == 0 ? null : newContent),
        }, "remove-key");

        // Enrollments only append, so the Nth credential on the user's line
        // is the Nth state entry for that user; drop it, refresh the counts.
        var userKeys = _state.Keys.Where(k => k.User == user).ToList();
        if (index < userKeys.Count) _state.Keys.Remove(userKeys[(int)index]);
        var remaining = MappingFile.CredentialCount(newContent, user);
        foreach (var k in _state.Keys.Where(k => k.User == user)) k.CredentialCount = remaining;
        StateStore.Save(_paths, _state);

        return Task.FromResult(Ok(new
        {
            removed = true,
            user,
            remaining,
            // Removing the last key never locks anyone out: nouserok makes
            // pam_u2f return PAM_IGNORE for credential-less users, so even
            // 2FA surfaces degrade to password-only for them.
            note = remaining == 0
                ? "last key removed for this user — every surface falls back to password for them"
                : null,
        }));
    });

    // ---------- SelfTest ----------

    public Task<string> SelfTestAsync(string configJson) => Locked(async () =>
    {
        var cfg = Json.Deserialize<SelfTestConfig>(configJson) ?? new SelfTestConfig();
        if (string.IsNullOrWhiteSpace(cfg.User)) return Err("no user given");
        if (!UserNameRegex().IsMatch(cfg.User)) return Err("invalid username");

        var scratch = string.IsNullOrEmpty(cfg.Service);
        // Only our own surfaces may be live-tested — anything else would turn
        // the root helper into a generic PAM authentication oracle.
        if (!scratch && !Surfaces.All.Select(Surfaces.ServiceFor).Contains(cfg.Service))
            return Err($"self-test is limited to yubix-managed services; '{cfg.Service}' is not one");
        var serviceName = scratch ? YubixPaths.SelfTestServiceName : cfg.Service!;

        if (scratch)
        {
            var stagedExists = File.Exists(_paths.StagedMappingFile);
            if (!stagedExists && !File.Exists(_paths.MappingFile))
                return Err("nothing enrolled yet — enroll a key first");
            var authfile = _paths.AuthfileArgument(staged: stagedExists);
            // Real pam_u2f runs even in fake mode when the mapping holds real
            // credentials — pam_wrapper only redirects the service directory,
            // so the module, the authfile path, and the physical key are all
            // exercised for real. Only simulated (FAKEKH) credentials fall
            // back to the pam_permit plumbing test.
            var simulatedCreds = File.ReadAllText(authfile).Contains("FAKEKH", StringComparison.Ordinal);
            var content = _paths.FakeMode && simulatedCreds
                ? PamGenerator.FakeSelfTestService
                : PamGenerator.RenderSelfTestService(_state.Origin, authfile);
            Transaction.WriteAtomically(_paths.SelfTestServicePath, content);
        }

        try
        {
            var (events, result) = await RunPamChildAsync(serviceName, cfg);
            var success = result?.Ok == true;

            if (success && scratch && cfg.Promote && File.Exists(_paths.StagedMappingFile))
            {
                File.Move(_paths.StagedMappingFile, _paths.MappingFile, overwrite: true);
                File.SetUnixFileMode(_paths.MappingFile,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite |
                    UnixFileMode.GroupRead | UnixFileMode.OtherRead);
            }

            return Ok(new
            {
                success,
                code = result?.Code ?? -1,
                message = result?.Msg ?? "self-test child produced no result",
                promoted = success && scratch && cfg.Promote,
                events,
            });
        }
        finally
        {
            if (scratch && File.Exists(_paths.SelfTestServicePath))
                File.Delete(_paths.SelfTestServicePath);
        }
    });

    private sealed record ChildResult(bool Ok, int Code, string Msg);

    private async Task<(List<object> Events, ChildResult? Result)> RunPamChildAsync(
        string serviceName, SelfTestConfig cfg)
    {
        var (exe, argPrefix) = SelfInvocation();
        var args = argPrefix.Concat(new[] { "--pam-test", serviceName, cfg.User }).ToList();

        var env = new Dictionary<string, string?> { ["XDG_CONFIG_HOME"] = null };
        if (_paths.FakeMode)
        {
            env["LD_PRELOAD"] = "libpam_wrapper.so";
            env["PAM_WRAPPER"] = "1";
            env["PAM_WRAPPER_SERVICE_DIR"] = _paths.EtcPamD;
        }

        var stdin = Json.Serialize(new { pin = cfg.Pin, password = cfg.Password });
        var (exit, stdout, stderr) = await External.RunAsync(exe, args, stdin, 90_000, env);

        var events = new List<object>();
        ChildResult? result = null;
        foreach (var line in stdout.Split('\n'))
        {
            var trimmed = line.Trim();
            if (!trimmed.StartsWith('{')) continue;
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(trimmed);
                var e = doc.RootElement.GetProperty("e").GetString();
                if (e == "result")
                {
                    result = new ChildResult(
                        doc.RootElement.GetProperty("ok").GetBoolean(),
                        doc.RootElement.GetProperty("code").GetInt32(),
                        doc.RootElement.GetProperty("msg").GetString() ?? "");
                }
                else
                {
                    events.Add(new
                    {
                        type = e,
                        text = doc.RootElement.TryGetProperty("t", out var t) ? t.GetString() : null,
                    });
                }
            }
            catch { }
        }

        if (result is null && exit == -2)
            result = new ChildResult(false, -2, "timed out (no touch within 90s?)");
        if (result is null)
            result = new ChildResult(false, exit, $"child failed: {External.Tail(stderr)}");
        return (events, result);
    }

    /// <summary>Re-invoke ourselves whether we run as an apphost binary or via `dotnet dll`.</summary>
    private static (string Exe, string[] ArgPrefix) SelfInvocation()
    {
        var processPath = Environment.ProcessPath ?? "";
        if (Path.GetFileName(processPath) is "dotnet" or "dotnet.exe")
        {
            var dll = System.Reflection.Assembly.GetEntryAssembly()!.Location;
            return (processPath, new[] { "exec", dll });
        }
        return (processPath, Array.Empty<string>());
    }

    // ---------- Apply / ConfirmKeep / Revert ----------

    public Task<string> ApplyAsync(string configJson) => Locked(async () =>
    {
        var cfg = Json.Deserialize<ApplyConfig>(configJson) ?? new ApplyConfig();
        if (cfg.Modes.Count == 0) return Err("no surface modes given");
        if (_pending is not null || File.Exists(_paths.PendingFlagFile))
            return Err("an unconfirmed apply is already in progress — confirm or revert it first");

        var enablingAnything = cfg.Modes.Values.Any(m => m != SurfaceMode.Off);
        if (enablingAnything && !File.Exists(_paths.MappingFile))
            return Err("no verified key enrollment found — enroll and run the self-test first");

        if (enablingAnything && !_paths.FakeMode)
        {
            var (versionOk, versionDetail) = await CheckPamU2fVersionAsync();
            if (!versionOk) return Err(versionDetail);
        }

        foreach (var (id, mode) in cfg.Modes)
        {
            if (!Surfaces.All.Contains(id))
                return Err($"unknown surface '{id}'");
            if (!Surfaces.ModeAllowed(id, mode))
                return Err(
                    "two-factor login screen is disabled until the Plasma Login Manager crash (KDE bug 513560) is fixed upstream");
        }

        var preState = Json.Deserialize<YubixState>(Json.Serialize(_state))!;
        var changes = new List<FileChange>();
        var newlyCreated = new List<string>();
        var loginService = ResolveLoginService();

        foreach (var (id, mode) in cfg.Modes)
        {
            var service = Surfaces.ServiceFor(id, loginService);
            var etcPath = _paths.EtcService(service);
            var vendorPath = _paths.VendorService(service);
            var etcExists = File.Exists(etcPath);
            var baseContent = etcExists ? File.ReadAllText(etcPath)
                : File.Exists(vendorPath) ? File.ReadAllText(vendorPath) : null;

            if (baseContent is null)
            {
                if (mode == SurfaceMode.Off) continue;
                return Err($"surface '{id}': PAM service '{service}' not found on this system");
            }

            if (mode == SurfaceMode.Off)
            {
                _state.SurfaceRecords.Remove(id);
                if (!etcExists) continue;
                if (_state.CreatedFiles.Contains(etcPath))
                {
                    changes.Add(new FileChange(etcPath, null));
                    continue;
                }
                changes.Add(new FileChange(etcPath,
                    PamGenerator.Render(baseContent, SurfaceMode.Off, "")));
                continue;
            }

            var line = PamGenerator.BuildU2fLine(mode, _state.Origin, _paths.MappingFile);
            var rendered = PamGenerator.Render(baseContent, mode, line);
            changes.Add(new FileChange(etcPath, rendered));
            if (!etcExists) newlyCreated.Add(etcPath);

            // Baseline for the post-update drift checks: what we derived the
            // file from and exactly what we wrote.
            var vendorExists = File.Exists(vendorPath);
            _state.SurfaceRecords[id] = new SurfaceRecord
            {
                Created = !etcExists || _state.CreatedFiles.Contains(etcPath),
                VendorExisted = vendorExists,
                VendorSha256 = vendorExists ? Drift.Sha256Hex(File.ReadAllText(vendorPath)) : null,
                GeneratedSha256 = Drift.Sha256Hex(rendered),
            };
        }

        if (changes.Count == 0)
            return Err("nothing to change");

        var countdown = Math.Clamp(cfg.CountdownSeconds, 15, 600);
        var deadline = DateTime.UtcNow.AddSeconds(countdown);

        // The write order IS the safety story: backups + manifest reach disk
        // first (Prepare), then the pending flag arms the boot failsafe, and
        // only then are the PAM files touched (Commit). A crash at any point
        // leaves either untouched files or an armed failsafe that reverts.
        var tx = Transaction.Prepare(_paths, changes, "apply");
        Transaction.WriteAtomically(_paths.PendingFlagFile,
            $"manifest={tx.ManifestPath}\ndeadline={deadline.ToString("O", CultureInfo.InvariantCulture)}\n",
            UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Transaction.Commit(changes);

        var timer = new Timer(_ => AutoRevert("countdown expired without confirmation"),
            null, countdown * 1000, Timeout.Infinite);
        _pending = new PendingApply(tx.ManifestPath, deadline, preState, timer);

        foreach (var (id, mode) in cfg.Modes) _state.AppliedModes[id] = mode;
        foreach (var path in newlyCreated)
            if (!_state.CreatedFiles.Contains(path)) _state.CreatedFiles.Add(path);
        foreach (var change in changes.Where(c => c.NewContent is null))
            _state.CreatedFiles.Remove(change.Dest);
        // State is saved only on ConfirmKeep — a revert restores preState.

        return Ok(new
        {
            deadlineUtc = deadline,
            countdownSeconds = countdown,
            manifest = tx.ManifestPath,
            backupDir = tx.BackupDir,
        });
    });

    public Task<string> ConfirmKeepAsync() => Locked(() =>
    {
        if (_pending is null)
        {
            // A stale flag with no live timer means a crashed helper: clear it
            // only via Revert/failsafe, never via Confirm.
            return Task.FromResult(File.Exists(_paths.PendingFlagFile)
                ? Err("stale pending apply found (helper restarted) — use Revert; the boot failsafe would also undo it")
                : Err("nothing pending to confirm"));
        }

        _pending.Timer.Dispose();
        _pending = null;
        if (File.Exists(_paths.PendingFlagFile)) File.Delete(_paths.PendingFlagFile);
        StateStore.Save(_paths, _state);
        WriteSnapshot();
        ClearAttention();
        return Task.FromResult(Ok(new { confirmed = true }));
    });

    /// <summary>Shell-parseable twin of the confirmed surface state, for the
    /// pacman hook (yubix-pamcheck) and `yubix-restore --strip` — neither may
    /// depend on .NET at hook/uninstall time. Tab-separated columns:
    /// svc, mode, created, etcPath, generatedSha256, vendorPath, vendorSha256, vendorExisted.</summary>
    private void WriteSnapshot()
    {
        var lines = new List<string>();
        var loginService = ResolveLoginService();
        foreach (var (id, mode) in _state.AppliedModes)
        {
            if (mode == SurfaceMode.Off) continue;
            var service = Surfaces.ServiceFor(id, loginService);
            var rec = _state.SurfaceRecords.GetValueOrDefault(id);
            lines.Add(string.Join('\t',
                service,
                mode == SurfaceMode.Passwordless ? "passwordless" : "twoFactor",
                rec?.Created == true ? "1" : "0",
                _paths.EtcService(service),
                rec?.GeneratedSha256 ?? "-",
                _paths.VendorService(service),
                rec?.VendorSha256 ?? "-",
                rec?.VendorExisted == true ? "1" : "0"));
        }
        if (lines.Count == 0)
        {
            if (File.Exists(_paths.SnapshotFile)) File.Delete(_paths.SnapshotFile);
            return;
        }
        Transaction.WriteAtomically(_paths.SnapshotFile, string.Join('\n', lines) + "\n",
            UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private void ClearAttention()
    {
        if (File.Exists(_paths.AttentionFile)) File.Delete(_paths.AttentionFile);
    }

    public Task<string> RevertAsync(string reason) => Locked(() =>
    {
        if (_pending is not null)
        {
            var manifest = _pending.ManifestPath;
            DoRevert(reason);
            return Task.FromResult(Ok(new { reverted = true, manifest, reason }));
        }

        var staleManifest = ParseFlag("manifest");
        if (staleManifest is not null && File.Exists(staleManifest))
        {
            Transaction.Restore(staleManifest);
            File.Delete(_paths.PendingFlagFile);
            _state = StateStore.Load(_paths);
            return Task.FromResult(Ok(new { reverted = true, manifest = staleManifest, stale = true }));
        }

        return Task.FromResult(Err("nothing pending to revert"));
    });

    private void AutoRevert(string reason)
    {
        _gate.Wait();
        try { DoRevert(reason); }
        catch { /* the boot failsafe still stands behind us */ }
        finally { _gate.Release(); }
    }

    private void DoRevert(string reason)
    {
        if (_pending is null) return;
        _pending.Timer.Dispose();
        Transaction.Restore(_pending.ManifestPath);
        if (File.Exists(_paths.PendingFlagFile)) File.Delete(_paths.PendingFlagFile);
        _state = _pending.PreState;
        _pending = null;
        Console.WriteLine($"yubix-helper: reverted apply ({reason})");
    }

    // ---------- RestoreDefaults ----------

    public Task<string> RestoreDefaultsAsync() => Locked(() =>
    {
        if (_pending is not null) DoRevert("restore-defaults requested");

        var changes = new List<FileChange>();
        var loginService = ResolveLoginService();
        // Clean every known login service, not just the active one: a display
        // manager switch must not strand a stale Yubix line behind.
        var services = Surfaces.All.Select(id => Surfaces.ServiceFor(id, loginService))
            .Concat(Surfaces.KnownLoginServices)
            .Distinct();
        foreach (var service in services)
        {
            var etcPath = _paths.EtcService(service);
            if (!File.Exists(etcPath)) continue;
            var content = File.ReadAllText(etcPath);
            if (_state.CreatedFiles.Contains(etcPath))
                changes.Add(new FileChange(etcPath, null));
            else if (PamGenerator.HasMarker(content))
                changes.Add(new FileChange(etcPath, PamGenerator.Render(content, SurfaceMode.Off, "")));
        }

        string? manifest = null;
        if (changes.Count > 0)
            manifest = Transaction.Apply(_paths, changes, "restore-defaults").ManifestPath;

        if (File.Exists(_paths.StagedMappingFile)) File.Delete(_paths.StagedMappingFile);
        foreach (var change in changes) _state.CreatedFiles.Remove(change.Dest);
        _state.AppliedModes = Surfaces.All.ToDictionary(s => s, _ => SurfaceMode.Off);
        _state.SurfaceRecords.Clear();
        StateStore.Save(_paths, _state);
        WriteSnapshot();
        ClearAttention();

        return Task.FromResult(Ok(new { restored = changes.Count, manifest }));
    });

    // ---------- pam-u2f version gate ----------

    /// <summary>pam-u2f older than 1.3.1 predates the CVE-2025-23013 fix, on
    /// which our `nouserok` lines rely: since 1.3.1 an unenrolled user (or a
    /// missing/foreign authfile) makes pam_u2f return PAM_IGNORE, falling
    /// through to the password module — before it, nouserok could short-
    /// circuit auth entirely. Refuse to enable anything on older modules.</summary>
    private static async Task<(bool Ok, string Detail)> CheckPamU2fVersionAsync()
    {
        var (exit, stdout, _) = await External.RunAsync(
            "pacman", new[] { "-Q", "pam-u2f" }, timeoutMs: 10_000);
        if (exit != 0)
            return (false, "cannot determine the pam-u2f version (pacman -Q pam-u2f failed) — is pam-u2f installed?");
        var version = ParsePacmanVersion(stdout);
        if (version is null)
            return (false, $"cannot parse the pam-u2f version from '{stdout.Trim()}'");
        return version >= new Version(1, 3, 1)
            ? (true, $"pam-u2f {version} (has the CVE-2025-23013 nouserok fix from 1.3.1)")
            : (false, $"pam-u2f {version} is older than 1.3.1 and lacks the CVE-2025-23013 nouserok fix — update pam-u2f first");
    }

    /// <summary>Parses `pacman -Q name` output ("pam-u2f 1.4.0-1", possibly
    /// with an epoch like "1:2.0-3") into the upstream version part.</summary>
    private static Version? ParsePacmanVersion(string pacmanOutput)
    {
        var parts = pacmanOutput.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return null;
        var v = parts[1];
        var colon = v.IndexOf(':');            // strip the epoch
        if (colon >= 0) v = v[(colon + 1)..];
        var dash = v.IndexOf('-');             // strip the pkgrel
        if (dash >= 0) v = v[..dash];

        var nums = new List<int>();
        foreach (var seg in v.Split('.'))
        {
            var digits = new string(seg.TakeWhile(char.IsAsciiDigit).ToArray());
            if (digits.Length == 0) break;
            nums.Add(int.Parse(digits, CultureInfo.InvariantCulture));
            if (nums.Count == 3) break;
        }
        return nums.Count switch
        {
            0 => null,
            1 => new Version(nums[0], 0),
            2 => new Version(nums[0], nums[1]),
            _ => new Version(nums[0], nums[1], nums[2]),
        };
    }
}
