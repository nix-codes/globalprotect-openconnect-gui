# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make build      # go mod tidy + go build -o gpoc-gui .
make run        # build then run the binary
make clean      # remove the binary
make deps       # go mod tidy only

go test ./...                        # run all tests
go test ./internal/vpn/...           # run tests for a single package
go vet ./...                         # static analysis
```

Build requires Fyne system libraries: `libgl1-mesa-dev`, `xorg-dev`, `libayatana-appindicator3-dev`.

## Architecture

The app owns the GlobalProtect portal HTTP flow and delegates only tunnel management to `openconnect` via a subprocess. SAML browser auth is handled by the external `gpauth` binary.

### State machine

`internal/vpn/manager.go` defines 6 states and drives transitions by parsing `openconnect` log output line-by-line:

- `"Connected as "` → **Connected**
- `"GlobalProtect gateway refused"` or `"auth-failed"` → **AuthFailed**
- process EOF → **Disconnected** or **Error**

State changes are sent on a `chan vpn.State` (`stateCh`) to the UI goroutine, which is the only place Fyne widgets are mutated (`applyState` in `internal/ui/app.go`).

### Connection flow

1. Load `~/.config/gpoc-gui/auth.json` (cached `portalCookieFromConfig`).
2. If present, attempt seamless reconnect:
   - `portal.GetConfig` with cached cookie → fresh `portal-userauthcookie`
   - `portal.GatewayLogin` → URL-encoded openconnect token
   - `mgr.Connect(gateway, token)` → `sudo openconnect --protocol=gp --cookie-on-stdin`
3. On cache miss or error: run `gpauth` (SAML browser flow), then call `portal.GetConfig` and `portal.GatewayLogin` with fresh SAML data.
4. On `AuthFailed`: clear cache and repeat from step 3.

### Disconnect

Reads the openconnect PID from `/var/run/openconnect.lock` and runs `sudo -n kill -SIGTERM <pid>`.

### Sudoers rule

```
%sudo ALL=(ALL) NOPASSWD: /usr/sbin/openconnect, /usr/bin/kill
```

Install with `sudo make install` or run `scripts/install-sudoers.sh` as root.

### Config & credential files

| Path | Contents |
|------|----------|
| `~/.config/gpoc-gui/config.json` | `Portal` (hostname) and `Browser` string |
| `~/.config/gpoc-gui/auth.json` | `CachedAuth`: `SamlAuthData` + portal cookies + timestamp, mode 0600 |

### Icon generation

`internal/ui/png.go` generates tray icons at runtime (filled circle PNGs) — grey/amber/green for disconnected/connecting/connected. There are no static image assets for these icons.
