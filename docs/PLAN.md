# Yubix — Development Plan

**Project:** Yubix — a GUI app for CachyOS that sets up YubiKey / FIDO2 login and sudo with zero command-line work, and makes locking yourself out effectively impossible.
**Repo:** https://github.com/codingncaffeine/yubix
**Plan date:** 2026-08-24 · researched against live system + current upstream sources

---

## TL;DR

- The niche is **genuinely empty**: Yubico killed its desktop GUI (YubiKey Manager Qt, EOL 2026-02-19), Yubico Authenticator only manages the key itself, Fedora's authselect is CLI-only, and GNOME/KDE ship **no** settings module for this. The only living third-party attempt (omarchy-fido2-key-suite, Aug 2026) is locked to the Omarchy/Hyprland distro. Meanwhile CachyOS/KDE/Garuda forums show steady demand and real lockout horror stories.
- Perfect timing: **Plasma 6.8 (due 2026-10-14) adds a first-class `kde-u2f` lock-screen slot with an auth-type picker — but ships no setup GUI and no enrollment tool.** KDE has publicly acknowledged the tooling gap. Yubix becomes the missing piece.
- Safety is the core product, not a feature: staged enrollment → live self-test on a **throwaway PAM service** → transactional apply with **countdown auto-revert** → **boot-time failsafe** → TTY login never touched. Every change is reversible by deleting our files; we never edit `system-auth`.
- Stack (user decision 2026-08-24): **.NET 10 + Avalonia UI** for a modern-looking GUI, with the same root D-Bus + polkit helper design in C# and a zero-dependency POSIX-sh emergency restore script. CachyOS precedent exists for adopted C# apps (Shelly was C# when it became the default package manager GUI in April 2026); repo adoption remains the goal (Shelly, limine-snapper-sync, noctalia all made the jump).

---

## 1. Why this app, and why now

**The pain (verified, with receipts):**
- Setting up a YubiKey for login/sudo on Arch-family systems today means hand-editing 3–5 files in `/etc/pam.d/`, running `pamu2fcfg` with the right flags, and knowing a dozen footguns. One wrong `required` line locks you out of your own machine — pam-u2f issue #110 (recovery-boot required), a Garuda user needed a btrfs snapshot restore after a hung login screen, and every guide's first advice is "keep a root shell open."
- CachyOS-specific breakage is documented on their own forum: a system update silently deleted a user's `kde`/`kde-fingerprint` PAM files (left as `.pacsave`), breaking FIDO unlock; another update broke a working YubiKey login setup in Feb 2026.
- A CachyOS user hit the Plasma Login Manager crash bug (KDE bug 513560) in Jan 2026 trying to do this by hand.

**The gap (verified 2026-08-24):**
| Existing tool | What it does | Why it doesn't solve this |
|---|---|---|
| Yubico Authenticator 7 | Key-side management (PINs, passkeys, OATH) | Never touches PAM; no login setup |
| YubiKey Manager Qt | (was) key-side GUI | EOL 2026-02-19, archived |
| Fedora authselect | Templates pam_u2f into system-auth | CLI-only, no enrollment, Fedora-specific |
| omarchy-fido2-key-suite | Lock/sudo/polkit FIDO2 for Omarchy | Hyprland/Omarchy-only, brand new (Aug 2026) |
| GNOME/KDE settings | Fingerprint enrollment exists | Zero security-key modules; KDE 6.8 ships the lock-screen picker **without** any setup GUI |

No general-purpose GUI configurator for pam_u2f exists on any toolkit. First mover advantage is real.

---

## 2. Verified environment facts (this machine + upstream)

**This box (fresh CachyOS, 2026-08):** KDE Plasma 6.7.4 on Wayland · **Plasma Login Manager** (`plasmalogin.service` — CachyOS default since Jan 2026, replacing SDDM) · btrfs + snapper + snap-pac + limine + limine-snapper-sync (snapshot infra preinstalled) · kernel 7.2-cachyos · systemd 261 · pambase 20260616 · no FIDO2 packages installed yet · PAM state completely clean.

**PAM layout that shapes the whole design:**
- Vendor PAM files live in `/usr/lib/pam.d/`: `plasmalogin`, `plasmalogin-greeter`, `plasmalogin-autologin`, `kde`, `kde-fingerprint`, `kde-smartcard`, `polkit-1`, `systemd-run0`. Linux-PAM rule (confirmed in libpam source): **a file in `/etc/pam.d/` with the same name fully shadows the vendor file** — no merging. So for these services we never edit anything that exists; we *add* an override file, and revert = delete it.
- `sudo`, `su`, `login` ship directly in `/etc/pam.d/` — for `sudo` only, we do a marked in-place single-line insertion, the exact idiom CachyOS itself already uses (`chwd`'s fingerprint feature inserts `auth sufficient pam_fprintd.so # chwd-fprintd` into `/etc/pam.d/sudo`).
- `systemd-run0` and `pkexec` authenticate through `polkit-1` — covering polkit covers them for free.

**Packages (current repos):** pam-u2f **1.4.0** (config-file support; includes the CVE-2025-23013 fix from 1.3.1 — the "user deletes their own mapping file to bypass 2FA" class), libfido2 1.17.0, yubikey-manager 5.9.1. `pamtester` is **not** packaged (AUR-only, upstream frozen since ~2009) → we build self-testing natively on libpam instead. `yubico-pam` (OTP) is legacy — upstream archived Feb 2025; we use FIDO2/pam_u2f exclusively.

**Critical pam_u2f facts baked into the design:**
- Default `origin`/`appid` is `pam://$HOSTNAME`, recomputed **at auth time** → a hostname change (DHCP, rename) bricks authentication. We always pin a fixed literal origin at both enrollment and auth.
- The mapping file must be **central and root-owned** (`/etc/u2f_mappings`, `root:root 0644`): per-user files are user-writable (2FA self-bypass) and break on encrypted homes. Mode must be 0644, not 0600, because the KDE lock-screen greeter runs as the session user and must read it (verified failure reports with 0600).
- Failed touches do **not** increment `pam_faillock` (verified against Arch's system-auth flow) — but wrong passwords typed during 2FA do, and an existing faillock lock will make our tests fail confusingly → preflight checks and offers `faillock --reset`.
- `nouserok` (post-1.3.1: returns PAM_IGNORE) makes rollout per-user safe: users without enrolled keys keep password-only behavior.
- `nodetect` is always set: pam_u2f's default pre-flight credential probe cannot be answered silently by many YubiKey firmwares — the key waits **dark** for a "wake-up" touch before the real blinking touch (double-touch complaint; confirmed live on a YubiKey 5C NFC fw 5.7.4, and the Arch wiki documents the same workaround). Cost: the touch cue can show even when the right key isn't inserted — cosmetic, acceptable.

**Desktop integration reality (per surface):**
| Surface | PAM service | Behavior today (Plasma 6.7) | Notes |
|---|---|---|---|
| sudo (terminal) | `sudo` | Full conversation; cue text shows | Best-understood surface |
| polkit prompts (pkexec, run0, System Settings) | `polkit-1` | **Best surface**: KDE agent starts PAM immediately — key blinks the moment the dialog opens; cue shown inline | PIN prompt renders as generic password box (cosmetic) |
| Lock screen | `kde` (6.7) → **`kde-u2f`** (6.8) | Greeter renders cue; runs parallel stacks since 6.0 but only fingerprint/smartcard slots exist in 6.7 | 6.8 adds the `kde-u2f` slot + `kscreenlockerrc [Authenticators] Universal2Factor=true` + picker UI |
| Login screen | `plasmalogin` | Works **passwordless-style only**: select user → press Enter on empty password → touch blinking key. Cue is never rendered (PLM drops PAM info messages — verified in source). `required` (2FA) mode **crashed PLM** as of Jan–Mar 2026 (KDE bug 513560, CONFIRMED, unfixed) | v1 ships passwordless login only; 2FA login gated until 513560 is verified fixed |
| TTY console | `login` | **Never touched by Yubix. Ever.** | The guaranteed escape hatch (Ctrl+Alt+F3) |

**Known UX caveat to disclose honestly in the UI:** any passwordless login/unlock leaves **KWallet locked** (pam_kwallet5 needs the typed password). Same for GNOME keyring. Not fixable by us; the app explains it and lets users choose 2FA mode (password+touch) where wallet auto-unlock matters.

---

## 3. Product definition

**Name:** **Yubix** (YubiKey + Linux) — decided 2026-08-24. Residual note: it still carries the "Yubi-" prefix that Yubico's brand guidelines guard, and the app works with any FIDO2 key, not just YubiKeys; low-but-nonzero risk of a rename request if the project gets big — revisit only if actually challenged.

**Audience & promise:** any CachyOS user with a security key. Plug in key → click through wizard → touch key → protected. Zero terminal use. Uninstall/disable restores stock behavior exactly.

**Surfaces & modes (v1):**
- **Sudo & admin prompts** (`sudo` + `polkit-1` together): Off / **Touch instead of password** (`sufficient`, first line) / **Password + touch, 2FA** (`required`, after `system-auth` include).
- **Lock screen** (`kde` on 6.7; `kde-u2f` + kscreenlockerrc flip on ≥6.8): Off / Touch instead of password / Password + touch.
- **Login screen** (`plasmalogin` override): Off / Touch instead of password (with the "press Enter, then touch" explainer). 2FA mode hidden until upstream bug 513560 is confirmed fixed.
- Per-user enrollment with named keys ("Blue 5C NFC — desk", "Nano — keychain"), backup-key nudge, optional FIDO2 PIN requirement (`pinverification=1`) as the "something you know" factor for strict setups.

**First-run rehearsal (user idea, 2026-08-24):** on first launch Yubix starts in a sandboxed rehearsal — the app spawns its own session-scoped helper against a private fake root (copies of the real PAM files) and walks the user through the FULL pipeline with their REAL key: enroll (real touches), live PAM self-test, apply, countdown, revert. On completion it auto-writes a plain-language results report to the user's Desktop (key model/firmware, each check pass/fail, timestamp), then offers the explicit switch to real mode behind an honest warning ("real mode changes how you actually log in — still backed up, reversible, countdown-protected, TTY always keeps your password"). Linear flow, not a persistent demo/full toggle (a lingering demo mode invites enrolled-but-not-protected confusion); rehearsal stays re-runnable from a menu.

**Main screens:**
1. **Dashboard** — key-detected card (model/serial via libfido2), enrolled keys list, three surface toggles with mode dropdowns and live status badges, per-surface "Test now" button, prominent "Restore everything to default".
2. **First-run wizard** — install packages → insert & name key → touch to enroll → choose surfaces/modes (plain-language security explanations incl. KWallet caveat) → **live self-test** → apply with countdown → backup-key nudge.
3. **Safety center** — backups list, snapper snapshot link, escape-hatch documentation ("TTY login always works with your password"), emergency restore instructions.

---

## 4. Safety architecture — "the app verifies everything on its own before the OS can lock you out"

This is the product's soul, in seven layers:

1. **Preflight gate.** Packages present, key plugged and responsive (libfido2), no active faillock lock, no foreign pam_u2f/fprintd lines we'd conflict with (detect `chwd-fprintd`; in 2FA mode warn that fingerprint-sudo would bypass the key and offer to disable it), origin pinned.
2. **Staged enrollment.** `pamu2fcfg` output goes to `/etc/u2f_mappings.staged`, format-validated — the live file is untouched.
3. **Scratch-service live test (the heart).** Helper writes a throwaway `/etc/pam.d/yubix-selftest` pointing at the *staged* mapping, forks a killable child, runs a real `pam_authenticate()` as the target user with a custom conversation (cue → GUI banner, PIN prompt → GUI field; env scrubbed of `XDG_CONFIG_HOME`; no pam-u2f timeout exists so the child is bounded by the device's touch timeout + our kill switch). **The user physically touches the key and sees it succeed before any real service changes.** Success atomically promotes the staged mapping to `/etc/u2f_mappings` (root:root 0644). The scratch service is deleted; it can never lock anything (TTY/`login` doesn't use it, faillock untouched).
4. **Transactional apply.** Snapper pre-snapshot (infra is preinstalled on CachyOS; skipped gracefully on non-btrfs) → originals backed up to `/var/lib/yubix/backups/<timestamp>/` → override files/marked edits written atomically (temp + rename, 0644 root:root). Vendor files in `/usr/lib/pam.d/` are never modified; `system-auth` is never modified; `login` (TTY) is never modified.
5. **Countdown auto-revert.** Immediately after apply, the app re-verifies against the *real* modified services (fresh `pam_authenticate` on `sudo` etc., requiring a fresh touch) while the GUI shows "Keep these settings?" with a 90-second countdown. No confirmation — because verification failed, the GUI crashed, or the user walked away — and the **root helper** (which armed the timer *before* the changes and survives GUI death) restores every backup automatically.
6. **Boot failsafe.** Before applying, the helper enables a oneshot `yubix-failsafe.service` (`Before=display-manager.service`, conditioned on a pending-apply flag). If the machine reboots or crashes mid-apply, the next boot reverts to password login *before* the login screen even starts. The flag is cleared only by explicit confirmation.
7. **Standing escape hatches.** TTY password login always works; passwordless modes are inherently lockout-proof (password remains valid); strict 2FA is gated behind *either* ≥2 enrolled keys *or* an explicit informed acknowledgment; `yubix-restore` is a dependency-light CLI restorer runnable from a TTY; snapper rollback documented as the nuclear option; pacman pre-remove scriptlet restores defaults on uninstall.

**Update-drift protection (the CachyOS forum incident class):** an alpm hook fires when pambase / plasma-login-manager / kscreenlocker / polkit / pam-u2f are upgraded — it re-derives our overrides from the *new* vendor files (3-way: new vendor base + our marked line), handles `.pacnew`/`.pacsave` on `/etc/pam.d/sudo`, repairs or notifies. Updates can no longer silently break or orphan the setup.

---

## 5. Technical architecture

```
┌──────────────────────────┐        D-Bus (system bus)        ┌───────────────────────────────┐
│  Yubix.App (Avalonia UI, │ ───── polkit-authorized ───────▶ │  Yubix.Helper (root daemon,   │
│  .NET 10, runs as user)  │                                  │  .NET 10; owns ALL /etc       │
│                          │ ◀──── status / results ───────── │  writes, enrollment, tests,   │
└──────────────────────────┘                                  │  revert deadline, backups)    │
                                                              └───────────────────────────────┘
```

- **`Yubix.App`** — Avalonia 11 (Fluent theme, light/dark), MVVM; talks to the helper over the system bus (Tmds.DBus). Runs unprivileged; the only file it writes is the user's own `kscreenlockerrc`.
- **`Yubix.Helper`** — root, D-Bus-activated systemd service `io.github.codingncaffeine.yubix`; every method gated by one polkit action (`…manage`, auth_admin, cached per caller). Blocking-call API (no signals needed in v1): `GetStatus`, `Preflight`, `ListDevices`, `Enroll`, `SelfTest`, `Apply`, `ConfirmKeep`, `Revert`, `RestoreDefaults`.
- **`Yubix.Core`** — shared library holding the PAM parser/generator, transaction/backup manifests, mapping-file merge, and state models; fully unit-testable without root.
- **PAM self-test** — the helper re-invokes its own binary as a killable child (`--pam-test`), which P/Invokes libpam (`pam_start`/`pam_authenticate`) with a managed conversation callback (cue → progress event, PIN/password prompts → supplied secrets), env scrubbed of `XDG_CONFIG_HOME`, JSON events streamed over stdout, hard timeout enforced by the parent.
- **Enrollment** — helper shells out to `pamu2fcfg` (`-u <user> -o <origin> -i <origin>`, `-n` for additional keys); device listing parses `fido2-token -L` (both ship with pam-u2f/libfido2).
- **Fake-root dev mode** — `YUBIX_ROOT=<dir>` switches the whole stack to a fake `/etc` tree, the session bus, no polkit, and pam_wrapper for the PAM child — the entire pipeline is testable end-to-end without root, which is also the CI story.
- **State:** `/var/lib/yubix/state.json` — pinned origin, enrolled key metadata, applied surface/mode map, backup manifest. Pinned origin default: `pam://linux-login` (fixed literal, hostname-proof; expert-configurable before first enrollment).
- **Restorer `/usr/bin/yubix-restore`** — a plain POSIX sh script that replays the plain-text backup manifest (`restore`/`delete` lines). Zero runtime dependencies, auditable at a glance, works from a TTY or emergency shell even if the .NET runtime itself is broken.

**Exact PAM changes per surface/mode** (all lines tagged `# yubix` for idempotent parsing, the chwd idiom):

- `sudo` — passwordless: insert **before** `auth include system-auth`:
  `auth sufficient pam_u2f.so authfile=/etc/u2f_mappings origin=pam://linux-login appid=pam://linux-login cue nouserok nodetect # yubix`
  2FA: same line with `required`, inserted **after** the include (Yubico-documented pattern; Arch's system-auth control flow verified compatible).
- `polkit-1` — create `/etc/pam.d/polkit-1` as vendor copy + the same line (position per mode as above).
- `plasmalogin` — create `/etc/pam.d/plasmalogin` as vendor copy + `sufficient … nouserok` first line (Arch-wiki-endorsed; passwordless only in v1).
- Lock screen 6.7 — create `/etc/pam.d/kde` as vendor copy + line. Lock screen ≥6.8 — create `/etc/pam.d/kde-u2f` modeled on the shipped `kde-fingerprint` (with `required`, never `sufficient`, per the Arch wiki's bypass warning for alternative stacks) and set `[Authenticators] Universal2Factor=true` in the user's `kscreenlockerrc`; the 6.8 lock screen then shows its native picker.
- Never touched: `system-auth`, `login`, `su`, `su-l`, vendor files.

**Testing strategy:** xUnit tests for the PAM generator/parser and transaction engine against captured real files; full-pipeline integration tests via the fake-root mode with pam_wrapper (no root needed); GitHub Actions CI in an `archlinux` container (`dotnet build` + `dotnet test`); a VM checklist for release testing (fresh CachyOS ISO, Plasma 6.7 and 6.8-beta); stretch goal — a virtual CTAP/uhid authenticator for true end-to-end CI.

---

## 6. Milestones

| # | Deliverable | Acceptance test |
|---|---|---|
| M0 | Repo scaffolding: .NET solution (App/Helper/Core/Tests), helper skeleton + polkit wiring, packaging files, CI, README | `pacman -U` a local build; GUI launches; helper answers `GetStatus` over D-Bus |
| M1 | Read-only intelligence: device detection, PAM-state parser (incl. foreign lines), Plasma/DM version detection, dashboard | Dashboard truthfully describes a hand-modified system |
| M2 | Enrollment + scratch self-test (safety core; still touches no real service) | Enroll two keys, self-test passes with touch, mapping promoted atomically |
| M3 | Sudo + polkit apply: backups, countdown revert, boot failsafe, `yubix-restore` | Kill -9 the GUI mid-apply → auto-revert; reboot mid-apply → failsafe restores; touch-only sudo works |
| M4 | Lock screen: `kde` path (6.7) and `kde-u2f` + kscreenlockerrc path (6.8, ships 2026-10-14) | Lock/unlock by touch on both Plasma versions |
| M5 | Login screen: `plasmalogin` passwordless; upstream engagement on bug 513560 (2FA gated) | Cold-boot login via Enter+touch; wallet caveat surfaced in UI |
| M6 | Update-drift alpm hook, uninstall restore scriptlet, notifications, docs/site | Simulated pambase/plasma upgrade repairs overrides automatically |
| M7 | Packaging & distribution: PKGBUILD → AUR → CachyOS repo proposal + forum thread; SDDM/GDM surface support for other CachyOS editions | Installable from AUR; proposal submitted |

Sequencing rationale: M2/M3 deliver the full "sudo without lockout risk" experience first (the most-used surface, lowest integration risk), lock screen next, login screen last because it depends on upstream PLM behavior.

---

## 7. Risk register

| Risk | Mitigation |
|---|---|
| PLM crash on `required` u2f (bug 513560, unfixed) | 2FA login mode hidden until verified fixed; engage upstream with our repro; passwordless path is wiki-endorsed |
| KWallet/keyring stays locked on passwordless login | Honest UI disclosure; recommend 2FA mode for wallet users; track upstream |
| System update replaces/removes PAM files (`.pacnew`/`.pacsave`) | alpm hook re-derives overrides; the forum-documented breakage becomes a non-event |
| User loses all keys in 2FA mode | TTY escape hatch untouched; ≥2-key gate; `yubix-restore`; snapper snapshot |
| Hostname change breaks auth | Origin pinned to fixed literal at enrollment and auth |
| User self-bypass of 2FA / CVE-2025-23013 class | Root-owned central mapping 0644; pam-u2f ≥1.3.1 asserted in preflight |
| faillock lock makes tests fail confusingly | Preflight detects, explains, offers reset |
| Plasma 6.8 changes land differently than the merged MR | M4 has a 6.7 path that keeps working; 6.8 path feature-flagged |
| Avalonia on Wayland currently runs via XWayland | Fine on KDE (XWayland present by default); native Wayland backend tracked upstream |
| "Yubi-" prefix trademark exposure | Monitor; rename only if actually challenged (app is FIDO2-generic) |
| Multi-DM CachyOS editions (GDM/LightDM/ly/SDDM) | DM detection; only offer surfaces we've validated; GDM patterns are documented-good, others staged in M7 |

---

## 8. Decisions taken (veto anytime) & open questions

**Decided:** Name: **Yubix** · .NET 10 + Avalonia UI (user pick for looks; Shelly-era C# precedent in CachyOS) with a C# root D-Bus/polkit helper and POSIX-sh emergency restorer · FIDO2/pam-u2f only (no legacy OTP) · central root-owned mapping `/etc/u2f_mappings` 0644 · pinned origin `pam://linux-login` · override-files-only strategy, `system-auth`/TTY never touched · v1 scope = sudo+polkit, lock screen, login screen on the KDE edition · countdown-revert + boot-failsafe as non-negotiable core · GitHub identity: commits authored only as `codingncaffeine` (noreply), no other attribution.

**Open questions (non-blocking, needed by M7):**
1. License — recommendation: GPL-3.0-or-later (matches CachyOS tooling norms).
2. LUKS full-disk unlock via `systemd-cryptenroll --fido2-device` as a v2 feature?
3. v2 "expert mode" for hardened setups (user idea, 2026-08-24): opt-in TTY coverage and failsafe opt-out behind heavy confirmations — deliberately out of v1, whose promise is lockout-impossibility; note 2FA mode already removes the password-alone path on protected surfaces.

---

## 9. Key sources

- KDE bug 513560 (PLM + pam_u2f crash, CONFIRMED): bugs.kde.org/show_bug.cgi?id=513560 · CachyOS forum repro: discuss.cachyos.org/t/22226
- Plasma 6.8 lock-screen auth rework (`kde-u2f`, picker): kscreenlocker MR !318 (merged 2026-07-20) · This Week in Plasma 2026-08-22
- pam-u2f 1.4.0 NEWS + man pages · YSA-2025-01 / CVE-2025-23013 · Arch Wiki "Universal 2nd Factor" (rev 2026-07-24)
- CachyOS: Jan 2026 release notes (PLM + limine defaults) · chwd fprint profile (PAM-edit precedent) · CachyOS-PKGBUILDS repo (adoption pipeline)
- Prior art: github.com/Erijl/omarchy-fido2-key-suite · token2/fido2-manage · maximbaz/yubikey-touch-detector (companion tool, 532★)
- Lockout evidence: Yubico/pam-u2f#110 · Garuda forum t/46571 · CachyOS forum t/19214, t/21873
