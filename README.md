# GlobalProtect-OpenConnect GUI

A Go/Fyne system tray GUI for GlobalProtect VPN. It owns the portal HTTP flow
and delegates tunnel management to `openconnect` via a subprocess. SAML browser
auth is handled by the external `gpauth` binary.

## How it works

1. **First connect** — opens your browser via `gpauth`, captures the SAML auth
   cookie, calls the GlobalProtect portal API to get a `portal-userauthcookie`,
   then launches `sudo openconnect --protocol=gp --cookie-on-stdin`.

2. **Reconnect** — reuses the cached portal cookie to skip the browser flow.
   If the server rejects it (`auth-failed`), the cache is cleared and the
   browser reopens automatically.

3. **Disconnect** — reads the PID from `/var/run/openconnect.lock` and sends
   `SIGTERM` via `sudo kill`.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| `openconnect` | `sudo apt install openconnect` |
| `gpauth` | Must be on `$PATH`; handles SAML browser auth |
| Passwordless sudo | See below |
| System tray | D-Bus + a desktop environment with a tray (GNOME, KDE, etc.) |

## Installation

### From source

Install build dependencies (one-time):

```bash
sudo apt install golang libgl1-mesa-dev xorg-dev libayatana-appindicator3-dev
```

Build (as your normal user), then install:

```bash
make build
sudo make install
```

Or use the convenience target that does both:

```bash
make full-install
```

This copies the binary to `/usr/local/bin/gpoc-gui`, installs the icon and
desktop entry, and writes the sudoers rule.

### From a pre-built binary

Download the latest `gpoc-gui` binary from the
[Releases page](https://github.com/nix-codes/globalprotect-openconnect-gui/releases)
and install runtime dependencies:

```bash
sudo apt install openconnect libayatana-appindicator3-1
```

Copy the binary to your `$PATH`, then write the sudoers rule (see
[Passwordless sudo](#passwordless-sudo) below):

```bash
sudo install -m 755 gpoc-gui /usr/local/bin/gpoc-gui
echo '%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openconnect, /usr/bin/kill' \
  | sudo tee /etc/sudoers.d/gpoc-gui
```

### Passwordless sudo

The app needs to run `openconnect` as root and send signals to it. The
sudoers rule written by the install script is:

```
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openconnect, /usr/bin/kill
```

## Usage

```bash
gpoc-gui
```

The app starts as a system tray icon (grey VPN shield = disconnected).
Right-click the tray icon to connect, disconnect, or open settings.

On first run, open settings and enter your portal hostname
(e.g. `vpn.mycompany.io`).

## File locations

| File | Purpose |
|------|---------|
| `~/.config/gpoc-gui/config.json` | Portal hostname and browser preference |
| `~/.config/gpoc-gui/auth.json`   | Cached SAML auth data and portal cookies (mode 0600) |

## Attributions

- [Vpn icons created by Smashicons - Flaticon](https://www.flaticon.com/free-icons/vpn)
