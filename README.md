> **This project is a continuation and major update of the original [adblock-dns](https://github.com/dmtkfs/adblock-dns) by [dmtkfs](https://github.com/dmtkfs).**

# Adblock‑DNS mit eingebauten Webinterface

**Adblock‑DNS** is a lightweight, system‑level DNS proxy that blocks known ad‑serving domains. It’s “set and forget” for non‑technical users via a Windows tray app, and includes a CLI for power users.

## Features
- **True DNS forwarder** (no recursion risk). Defaults to Quad9: `9.9.9.9:53` (fallback `149.112.112.112:53`).
- **UDP + TCP** listeners with automatic TCP retry on truncation.
- **Suffix‑based blocking** by default (`example.com` covers `*.example.com`).
- **Block responses:** `null` (A=0.0.0.0, AAAA=::; others NODATA) or `nxdomain`.
- **Whitelist** via `whitelist.txt` (beside the executable).
- **Dry‑run** mode logs what would be blocked without blocking.
- **Portable logs**: `adblock.log` lives next to the executable.
- **Tray app (Windows):** Start/Stop, Dry‑run toggle, Open log, status (last refresh).

## Downloads
Grab the latest binaries from the **Releases** page:
- `adblock-tray-windows-amd64.exe` - Windows tray app
- `adblock-cli-windows-amd64.exe` - CLI

## Quick Start (Tray, Windows)
1. Download `adblock-tray-windows-amd64.exe` to a folder where it can write files.
2. Double‑click to run; control it from the system tray.
3. Set your network adapter’s DNS to `127.0.0.1` to enable system‑wide blocking.

**Files next to the EXE:**
- `adblock.log` - logs  
- `whitelist.txt` - one domain per line; `#` comments allowed (suffix matching)

## Quick Start (CLI)
```powershell
.\adblock-cli-windows-amd64.exe --v
````

## Linux (CLI)

The tray app is Windows‑only, but the **CLI** runs on Linux.

**Build**

```bash
GOOS=linux GOARCH=amd64 go build -o adblock-cli-linux-amd64 ./cmd/cli
```

**Quick test (no system changes)**

```bash
./adblock-cli-linux-amd64 --listen 127.0.0.1:5353 --v
dig +short example.com @127.0.0.1 -p 5353
dig +short adservice.google.com @127.0.0.1 -p 5353   # likely blocked
```

**Binding to port 53**

```bash
# Either run as root:
sudo ./adblock-cli-linux-amd64 --listen 127.0.0.1:53 --v

# Or grant the binary the low‑port capability:
sudo setcap 'cap_net_bind_service=+ep' ./adblock-cli-linux-amd64
./adblock-cli-linux-amd64 --listen 127.0.0.1:53 --v
```

**Note on systemd‑resolved**
On some distros (e.g., Ubuntu), `systemd-resolved` may already listen on :53. Either stop/adjust it, or keep using a higher port (e.g., 5353) and point your resolver there.

**Files**
`whitelist.txt` and `adblock.log` live next to the executable on Linux as well.

### CLI Flags

```
--listen       addr:port (default 127.0.0.1:53)
--interval     refresh interval (default 24h)
--dry-run      log block hits but do not block
--v            verbose logging ([BL]/[WL])
--match        exact|suffix           (default suffix)
--block-mode   null|nxdomain          (default null)
--upstream     ip[:port] (repeatable or comma‑sep; default 9.9.9.9:53,149.112.112.112:53)
```

## Build from Source

```bash
git clone https://github.com/x/adblock-dns.git
cd adblock-dns
go build -o adblock-cli.exe ./cmd/cli
go build -ldflags="-H=windowsgui" -o adblock-tray.exe ./cmd/tray
```

## Logs & Troubleshooting

* `adblock.log` is written next to the EXE (CLI and tray).
* Tray toggles **Dry‑run** and **Start/Stop** at runtime; status shows last refresh.
* If port 53 is in use, stop the conflicting service or run with `--listen 127.0.0.1:5353` and point your adapter to that port.

## Uninstall

Delete the EXE, `adblock.log`, and `whitelist.txt`. No system changes are made.

---

## Disclaimer

This software is provided **as-is** for educational and personal use only. The authors are **not responsible** for any misuse, data loss, network disruption, or unintended consequences resulting from its use. Use at your own risk and **only** on systems and networks you own or have explicit permission to operate on.

## Blocklists & Acknowledgements
Adblock‑DNS uses community‑maintained hosts lists and refreshes them periodically (default every 24h):

- StevenBlack/hosts
- AdAway hosts

These lists are fetched read‑only at runtime and merged in memory; your local `whitelist.txt` always takes precedence.  
Thanks to the maintainers and community contributors of these projects.

## No Affiliation or Endorsement

This project is not affiliated with, endorsed by, or sponsored by any ad network, content provider, DNS service, or third-party entity mentioned directly or indirectly through blocklists or functionality. Domain blocking is based solely on publicly available community-maintained lists. No claims are made about the intent, legality, or practices of any organization.

## License

MIT - see [LICENSE](LICENSE)
