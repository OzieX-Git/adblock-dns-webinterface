> **This project is a continuation and major update of the original [adblock-dns](https://github.com/dmtkfs/adblock-dns) by [dmtkfs](https://github.com/dmtkfs).**

# Adblock‑DNS with a built-in web interface

**Adblock‑DNS** is a lightweight, system‑level DNS proxy that blocks known ad‑serving domains. It runs as a Windows tray application with a **full graphical configuration interface (WebView)**, making it easy for non‑technical users to control every aspect of the app.

For power users, a CLI version was previously available; its compatibility with the latest internals has not been verified. If you need CLI support, please open an issue and I will investigate.

---

## ✨ Features

- **True DNS proxy** – forwards queries to upstream resolvers (default: Quad9 `9.9.9.9` / `149.112.112.112`).
- **UDP + TCP** listeners, automatic TCP retry on truncation.
- **Suffix‑based blocking** – `example.com` blocks `*.example.com`.
- **Block modes:** `null` (A=0.0.0.0, AAAA=::) or `nxdomain`.
- **Whitelist** via `whitelist.txt` (beside the executable).
- **Local blocklist** (`blocklist.txt`) and **remote sources** (`sources.txt`) – refreshed on startup and periodically.
- **Dry‑run mode** – logs what would be blocked without actually blocking.
- **Portable logs**: `adblock.log` lives next to the executable.
- **Comprehensive WebView (GUI** 🖥️**)**:
  - Edit blocklist, sources and whitelist directly in the browser.
  - View and filter the application log in real time.
  - Configure upstream DNS servers (reachability check, reset to defaults, automatic proxy restart).
  - **Statistics & Analytics** – SQLite database with hourly/daily blocked requests and top domains, displayed as charts.
  - **Deduplication & file comparison** – find and remove duplicate domains, merge new blocklists, sort/clean entries with backup.
  - Toggle on/off: autostart, verbose logging, DNS cache flush, statistics collection, backup creation.
  - Adjustable log file size limit.
- **🛡️ Crash resilience** – the app detects unexpected terminations and automatically restores your DNS settings on next start, so you never lose internet connectivity.
- **Status icon** in the system tray: green (running), blue (dry‑run), red (stopped).
- **Delayed tray menu** – “Quit” and “WebView” are disabled for a few seconds on start to prevent accidental clicks while the proxy initialises.
- **Tray app (Windows):** Start/Stop, Dry‑run toggle, Webview toggle, status (last refresh).

---

## 📥 Downloads

Pre‑built binaries can be found on the **Releases** page.

- `adblock-dns-windows-amd64.exe` – Windows tray application with WebView.

(If you need the CLI, please open an issue – I will provide a build or investigate the current state.)

---

## 🚀 Quick Start (Windows Tray App)

1. Download the latest `adblock-webinterface-tray-windows-amd64.exe` to a folder where it can write files.
2. **Run as administrator** (the app will request elevation automatically).
3. The tray icon appears. The proxy starts immediately and sets your active network adapter’s DNS to `127.0.0.1`.
4. Right‑click the tray icon to:
   - **Start / Stop** the proxy.
   - Toggle **Dry‑run**.
   - Open the **WebView** (full configuration panel).
   - **Quit** (restores original DNS settings).

**Files created next to the EXE:**
- `adblock.log` – application logs and configuration headers.
- `blocklist.txt` – local list of blocked domains.
- `sources.txt` – remote blocklist URLs (one per line).
- `whitelist.txt` – domains that are always allowed (suffix matching).
- `stats.db` – statistics database (created when statistics are enabled).

---

🐧 Linux (CLI)

highly recommended to build it from [Source](https://github.com/dmtkfs/adblock-dns)

---


## 🌐 WebView Configuration

Once the app is running, open the **WebView** from the tray menu. A browser tab opens at `http://127.0.0.1:8080` and offers the following panels:

| Tab | Function |
|-----|----------|
| 📂 **Files** | Edit `blocklist.txt`, `sources.txt` or `whitelist.txt` with syntax highlighting and search. |
| 📋 **Log** | View the application log with **real‑time tail** (check “Realtime”), **filter** lines, and **clear** log. |
| ⚙️ **Upstreams** | Set primary/secondary DNS servers (with reachability check). The proxy is automatically restarted after saving. |
| 🔍 **Compare** | Upload a new blocklist and compare it to the current one; add only new domains. |
| 📊 **Statistics** | Charts of hourly/daily blocked requests and top blocked domains. Flushing interval and cleanup settings are available (dev mode only). |
| 🛠️ **Misc** | Toggle various protected settings (dev mode required): autostart, verbose logging, backup creation, statistics collection, log size limit. |

**Dev Mode:** Start the app with the `-dev` command‑line argument to unlock all protected checkboxes and the “Misc” tab.

---

## 🛡️ Crash Recovery

The program includes **Go panic recovery**. If the app encounters an internal fatal error (panic), it catches the panic and immediately resets the DNS of your active network adapter to automatic (DHCP). This prevents you from being left without internet due to a code bug.

A recovery log entry is written to `crash.log` in the application directory.

---

## 📈 Statistics

When enabled (checkbox in “Misc” or via dev mode), the proxy records:

- Total blocked requests (separated by real block and dry‑run).
- Hourly and daily counters stored in `stats.db`.
- Per‑domain block counts – viewable as a table of top domains in the WebView.

Statistics can be reset from the Statistics panel (dev mode) and the flush interval and cleanup tick settings can be adjusted.

---

## ⚠️ CLI Compatibility note

The CLI version that existed in earlier releases has **not been tested** with the current codebase. If you rely on the CLI, please open an issue – I will prioritise fixing or rebuilding it on request.
These flags refer to the original CLI. Whether they still work unchanged with the current proxy code has not been verified.
If you encounter problems, please open an [issue](https://github.com/OzieX-Git/adblock-dns-webinterface/issues).


---

## 🔨 Build from Source

```bash
git clone https://github.com/x/adblock-dns.git
cd adblock-dns
go build -ldflags="-H=windowsgui" -o adblock-dns.exe .
```

## ⚠️ Disclaimer

This software is provided **as-is** for educational and personal use only. The authors are **not responsible** for any misuse, data loss, network disruption, or unintended consequences resulting from its use. Use at your own risk and **only** on systems and networks you own or have explicit permission to operate on.

[Virustotal.com](https://www.virustotal.com/gui/file/170e79417d597bfcf98604ea34baf97003b3818adf149c7576f361b830f968de?nocache=1)

## 📚 Blocklists & Acknowledgements

Adblock‑DNS uses community‑maintained hosts lists and refreshes them periodically (default every 24 h).  
The actual URLs are stored in `sources.txt` (beside the executable); the following two are commonly recommended:

- [StevenBlack/hosts](https://github.com/StevenBlack/hosts) (unified list)
- [AdAway hosts](https://adaway.org/hosts.txt)

These lists are fetched read‑only at runtime and merged in memory; your local `whitelist.txt` always takes precedence.  
Thank you to the maintainers and community contributors of these projects.

## 🔗 No Affiliation or Endorsement

This project is not affiliated with, endorsed by, or sponsored by any ad network, content provider, DNS service, or third‑party entity mentioned directly or indirectly through blocklists or functionality. Domain blocking is based solely on publicly available community‑maintained lists. No claims are made about the intent, legality, or practices of any organization.

## 📄 License

MIT – see [LICENSE](LICENSE)
