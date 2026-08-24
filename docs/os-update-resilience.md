# Surviving OS updates

Yubix modifies PAM configuration that packages also own. This document records
how pacman/Plasma updates can invalidate that setup, and the watchdog Yubix
ships against each case. Researched 2026-08-24 on a live CachyOS install;
sources at the bottom.

## The threat model

| # | What happens | Why it matters |
|---|---|---|
| 1 | **Vendor drift.** `/etc/pam.d/{polkit-1,kde,plasmalogin}` overrides are *copies* of `/usr/lib/pam.d` vendor files plus one line; every later vendor change is silently shadowed. | Stale auth stacks; wallet/keyring lines are exactly what Plasma updates touch. plasma-login-manager was iterated twice in Aug 2026 alone. |
| 2 | **pacnew aftermath.** `/etc/pam.d/sudo` *is* in sudo's backup array, so pacman never overwrites the Yubix line — it writes `sudo.pacnew`. But `pacdiff`'s "(o)verwrite" runs **outside any transaction** and silently drops the line. | In 2FA mode that's a silent security downgrade; hooks can't see pacdiff. |
| 3 | **polkit sandbox.** polkit 126+ hard-sandboxes its auth helper (`PrivateDevices=yes`); pam_u2f reaches `/dev/hidraw` only through pam-u2f's drop-in on `polkit-agent-helper@.service`. An update that detaches it kills admin-prompt key auth with zero PAM changes (this exact breakage shipped to everyone in early 2025). | 2FA polkit becomes impossible. |
| 4 | **Module removal.** `pacman -Rs yubix` cascades pam-u2f away; a dangling `auth required pam_u2f.so` is module-unknown = deny. | Bricked 2FA surfaces (TTY still works). |
| 5 | **Renames/migrations.** polkit moved its PAM file `/etc → /usr/lib` in 2024 (breaking YubiKey users); CachyOS just renamed sddm → plasmalogin. Overrides become silent no-op orphans. | Feature silently off, or pacman file-conflict aborts. |
| 6 | **Plasma 6.8 (2026-10-14).** kscreenlocker MR !318 (merged) adds a native multi-authenticator greeter: `kde-u2f` PAM service + `kscreenlockerrc [Authenticators] Universal2Factor`. The MR ships **no** PAM file — distro packaging decides. | The 6.7-style `kde` override stops being the intended integration. |
| 7 | **pam-u2f itself**: no option rename ever (1.1.0→1.4.0), no 2.x planned; everything critical is pinned in our line. New in 1.4.0: `/etc/security/pam_u2f.conf` global defaults can change *unpinned* options underneath us. | Low risk; conf file is worth surfacing. |

## What Yubix ships against it

**Apply-time baselines.** At apply, per surface, `state.json` records the
sha256 of the vendor file the override was derived from and of the exact file
Yubix wrote (`SurfaceRecord`). `Drift.Classify` then distinguishes every case
mechanically — the Debian `pam-auth-update` idea: *auto-repair is safe exactly
when the current file still matches what we last wrote.*

**Live checks on every GetStatus/Preflight** (helper, `Drift.cs`):
per-surface `markerLost` / `thirdPartyEdit` / `vendorDrift` /
`orphanedOverride` / `vendorAppeared` / `overrideMissing`, plus `.pacnew`
presence, the polkit drop-in check (`systemctl cat` must show
`PrivateDevices=no` + `char-hidraw`), `pam_u2f.conf` presence, the
`display-manager.service` alias target, and a Plasma-6.8/`kde-u2f` heads-up.
The GUI logs each finding in the Activity panel. These catch what hooks
cannot: pacdiff and manual edits happen outside transactions.

**A pacman hook for updates while the app is closed.**
`zz-yubix-pam-check.hook` (PostTransaction, Path triggers on `etc/pam.d/*`,
`usr/lib/pam.d/*`, the pam_u2f module/conf, and the polkit agent unit — pacnew
extraction triggers Path hooks under the original filename, and removals
trigger on all owned paths) runs `/usr/lib/yubix/yubix-pamcheck`: POSIX sh, no
.NET, reading `/var/lib/yubix/pamcheck.snapshot` (a tab-separated twin of the
surface records written at ConfirmKeep). Findings go to
`/var/lib/yubix/attention` (surfaced in the GUI), the journal, pacman's
output/log, and a desktop notification on each logged-in user's session bus
(the CachyOS reboot-required hook idiom). Always exits 0; silent and fast when
clean.

**One self-heal, chosen deliberately:** if pam_u2f.so is gone while managed
lines remain (threat 4), the hook runs `yubix-restore --strip` so password
login keeps working. Everything else is warn-only — auto-rewriting auth config
from a pacman hook is how you create the lockouts Yubix exists to prevent.

**Uninstall hygiene.** `yubix.install pre_remove` runs `yubix-restore --strip`
(snapshot-driven: delete created overrides, strip marker lines from edited
files; falls back to a marker scan) before the failsafe unit is disabled.
Enrolled key data is left in place.

**Deliberately not shipped:** a PreTransaction `AbortOnFail` guard on pam-u2f
removal — pacman's dependency system already blocks plain `-R pam-u2f`, and an
abort hook cannot tell "removing pam-u2f" from "removing yubix itself" (hooks
run before pre_remove and only see matched targets), so it would block Yubix's
own uninstall.

## Later (v1.5+)

- One-click repair: re-render an override from the new vendor base when the
  current file sha still equals `generatedSha256`; guided merge-onto-pacnew
  for sudo.
- kde-u2f migration wizard — blocked on actual Arch/CachyOS 6.8 packaging
  (whether/what they ship as `/usr/lib/pam.d/kde-u2f`; kscreenlocker MR !352
  is still moving the greeter auth plumbing).
- A systemd path unit watching `/etc/pam.d` for near-real-time pacdiff
  detection.

## Sources

- `man alpm-hooks`, `man pacman` (HANDLING CONFIG FILES), `man pam_u2f` — local.
- pam-u2f NEWS: https://github.com/Yubico/pam-u2f/blob/main/NEWS
- kscreenlocker MR !318 (merged for 6.8) and !352:
  https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/318
  https://invent.kde.org/plasma/kscreenlocker/-/merge_requests/352
- polkit sandbox vs pam_u2f: https://github.com/polkit-org/polkit/issues/622,
  https://github.com/polkit-org/polkit/pull/626 (referenced by the shipped drop-in)
- The 2024 polkit PAM-file migration breaking YubiKey users:
  https://forum.endeavouros.com/t/what-is-the-successor-to-etc-pam-d-polkit-1-yubikey-authentication-does-not-work-anymore/50295
