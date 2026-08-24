<p align="center">
  <img src="assets/banner.jpg" alt="Yubix — the painless YubiKey setup for sudo &amp; login on Linux" width="100%"/>
</p>

# Yubix

**Use your YubiKey (or any FIDO2 security key) for login and sudo on CachyOS — safely, with zero terminal work.**

Setting up a security key for Linux login normally means hand-editing PAM files where a single typo locks you out of your own machine. Yubix replaces all of that with a dark, native desktop app and an obsessive safety net.

> ⚠️ **Status: early development.** The core pipeline (enroll → live self-test → transactional apply → countdown auto-revert → boot failsafe) is implemented and under active testing. Not yet packaged for general use.

## What it does

- **Enroll keys by touch** — no `pamu2fcfg`, no config files. Two touches: one to enroll, one on a live verification test.
- **Pick where the key works** — sudo & admin prompts, the Plasma lock screen, the login screen. Each with *touch instead of password* or *password + touch (2FA)*.
- **Never lock you out**:
  - Enrollment is verified against a **throwaway PAM service** before anything real changes.
  - Applying starts a **countdown** — no confirmation, and everything auto-reverts.
  - A **boot failsafe** reverts unconfirmed changes before the login screen even starts if the machine reboots mid-change.
  - **TTY login (Ctrl+Alt+F3) is never modified** — your password always works there.
  - Every change is backed up; `yubix-restore` (plain POSIX sh) can undo everything from an emergency shell.

## Architecture

| Component | What it is |
|---|---|
| `yubix` | Avalonia UI (.NET 10) desktop app — dark graphite + CachyOS teal |
| `yubix-helper` | Root D-Bus service (`io.github.codingncaffeine.yubix`), polkit-authorized; owns all `/etc` writes, enrollment, PAM self-tests, backups, and the revert deadline |
| `Yubix.Core` | Shared PAM generator/transaction engine (fully unit-tested) |
| `yubix-restore` | Dependency-free shell script that replays backup manifests |

PAM strategy: vendor files in `/usr/lib/pam.d/` are shadowed with override files in `/etc/pam.d/` (revert = delete); `/etc/pam.d/sudo` gets a single marker-tagged line (the same idiom CachyOS's `chwd` uses). `system-auth` is never touched. Full details in [docs/PLAN.md](docs/PLAN.md).

## Building from source

```sh
sudo pacman -S --needed dotnet-sdk pam-u2f libfido2
git clone https://github.com/codingncaffeine/yubix
cd yubix
dotnet build
```

Run the whole stack against a **fake root** (no real `/etc` is touched, session bus, no polkit — great for development):

```sh
export YUBIX_ROOT=/tmp/yubix-fakeroot
mkdir -p $YUBIX_ROOT/etc/pam.d $YUBIX_ROOT/usr/lib/pam.d $YUBIX_ROOT/var/lib/yubix
dotnet run --project src/Yubix.Helper &   # helper on the session bus
dotnet run --project src/Yubix.App        # the app, talking to it
```

Tests: `dotnet test`

## License

TBD (leaning GPL-3.0-or-later).
