using System.Globalization;
using Yubix.Core;

namespace Yubix.Helper;

/// <summary>
/// All privileged operations. Serialized behind one gate — the helper serves a
/// single desktop app; simplicity beats throughput here.
/// </summary>
public sealed class HelperService
{
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

    public Task<string> GetStatusAsync() => Locked(() =>
    {
        var surfaces = new Dictionary<string, object>();
        foreach (var id in Surfaces.All)
        {
            var service = Surfaces.ServiceFor(id);
            var etcPath = _paths.EtcService(service);
            var vendorPath = _paths.VendorService(service);
            string? current = File.Exists(etcPath) ? File.ReadAllText(etcPath) : null;
            string? baseContent = current ?? (File.Exists(vendorPath) ? File.ReadAllText(vendorPath) : null);

            surfaces[id] = new
            {
                service,
                available = baseContent is not null,
                mode = current is null ? SurfaceMode.Off : PamGenerator.DetectMode(current),
                createdByYubix = _state.CreatedFiles.Contains(etcPath),
                overrideExists = current is not null,
                foreign = baseContent is null ? new List<string>() : PamGenerator.ForeignAuthLines(baseContent),
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
        };
        return Task.FromResult(Ok(status));
    });

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

            var devices = await FidoDevices.ListAsync();
            Check("device", devices.Count > 0,
                devices.Count > 0
                    ? $"security key detected: {devices[0].Description}"
                    : "no FIDO2 security key detected — insert your key");
        }

        foreach (var id in Surfaces.All)
        {
            var service = Surfaces.ServiceFor(id);
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
                Check($"surface-{id}", true,
                    foreign.Count > 0
                        ? $"'{service}' ready (note: existing auth lines present: {string.Join(" | ", foreign)})"
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
        nickname = string.IsNullOrWhiteSpace(nickname) ? "Security key" : nickname.Trim();

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

    // ---------- SelfTest ----------

    public Task<string> SelfTestAsync(string configJson) => Locked(async () =>
    {
        var cfg = Json.Deserialize<SelfTestConfig>(configJson) ?? new SelfTestConfig();
        if (string.IsNullOrWhiteSpace(cfg.User)) return Err("no user given");

        var scratch = string.IsNullOrEmpty(cfg.Service);
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

    public Task<string> ApplyAsync(string configJson) => Locked(() =>
    {
        var cfg = Json.Deserialize<ApplyConfig>(configJson) ?? new ApplyConfig();
        if (cfg.Modes.Count == 0) return Task.FromResult(Err("no surface modes given"));
        if (_pending is not null || File.Exists(_paths.PendingFlagFile))
            return Task.FromResult(Err("an unconfirmed apply is already in progress — confirm or revert it first"));

        var enablingAnything = cfg.Modes.Values.Any(m => m != SurfaceMode.Off);
        if (enablingAnything && !File.Exists(_paths.MappingFile))
            return Task.FromResult(Err("no verified key enrollment found — enroll and run the self-test first"));

        foreach (var (id, mode) in cfg.Modes)
        {
            if (!Surfaces.All.Contains(id))
                return Task.FromResult(Err($"unknown surface '{id}'"));
            if (!Surfaces.ModeAllowed(id, mode))
                return Task.FromResult(Err(
                    "two-factor login screen is disabled until the Plasma Login Manager crash (KDE bug 513560) is fixed upstream"));
        }

        var preState = Json.Deserialize<YubixState>(Json.Serialize(_state))!;
        var changes = new List<FileChange>();
        var newlyCreated = new List<string>();

        foreach (var (id, mode) in cfg.Modes)
        {
            var service = Surfaces.ServiceFor(id);
            var etcPath = _paths.EtcService(service);
            var vendorPath = _paths.VendorService(service);
            var etcExists = File.Exists(etcPath);
            var baseContent = etcExists ? File.ReadAllText(etcPath)
                : File.Exists(vendorPath) ? File.ReadAllText(vendorPath) : null;

            if (baseContent is null)
            {
                if (mode == SurfaceMode.Off) continue;
                return Task.FromResult(Err($"surface '{id}': PAM service '{service}' not found on this system"));
            }

            if (mode == SurfaceMode.Off)
            {
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
            changes.Add(new FileChange(etcPath, PamGenerator.Render(baseContent, mode, line)));
            if (!etcExists) newlyCreated.Add(etcPath);
        }

        if (changes.Count == 0)
            return Task.FromResult(Err("nothing to change"));

        var countdown = Math.Clamp(cfg.CountdownSeconds, 15, 600);
        var tx = Transaction.Apply(_paths, changes, "apply");
        var deadline = DateTime.UtcNow.AddSeconds(countdown);

        Transaction.WriteAtomically(_paths.PendingFlagFile,
            $"manifest={tx.ManifestPath}\ndeadline={deadline.ToString("O", CultureInfo.InvariantCulture)}\n",
            UnixFileMode.UserRead | UnixFileMode.UserWrite);

        var timer = new Timer(_ => AutoRevert("countdown expired without confirmation"),
            null, countdown * 1000, Timeout.Infinite);
        _pending = new PendingApply(tx.ManifestPath, deadline, preState, timer);

        foreach (var (id, mode) in cfg.Modes) _state.AppliedModes[id] = mode;
        foreach (var path in newlyCreated)
            if (!_state.CreatedFiles.Contains(path)) _state.CreatedFiles.Add(path);
        foreach (var change in changes.Where(c => c.NewContent is null))
            _state.CreatedFiles.Remove(change.Dest);
        // State is saved only on ConfirmKeep — a revert restores preState.

        return Task.FromResult(Ok(new
        {
            deadlineUtc = deadline,
            countdownSeconds = countdown,
            manifest = tx.ManifestPath,
            backupDir = tx.BackupDir,
        }));
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
        return Task.FromResult(Ok(new { confirmed = true }));
    });

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
        foreach (var id in Surfaces.All)
        {
            var etcPath = _paths.EtcService(Surfaces.ServiceFor(id));
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
        StateStore.Save(_paths, _state);

        return Task.FromResult(Ok(new { restored = changes.Count, manifest }));
    });
}
