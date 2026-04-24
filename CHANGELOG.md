
---

## CHANGELOG.md

```markdown
# Changelog - Adblock-DNS

## [2.0.0] - WebView Integration & Major Enhancements (2026‑04‑23)

### 🖥️ WebView Configuration Panel
- **Integrated HTTP server** on `127.0.0.1:8080` with a full single‑page application accessible from the tray.
- **File Editor**: Edit `blocklist.txt`, `sources.txt`, `whitelist.txt` directly in the browser with search functionality (smart scrolling, line positioning, only horizontal when necessary).
- **Log Viewer**: View the application log in real time (check “Realtime” for 2‑second tail), filter lines client‑side, clear log.
- **Upstream Configuration**: Set primary/secondary DNS servers; reachability check; reset to Quad9 defaults; automatic proxy restart after changes.
- **Compare & Merge**: Upload a new blocklist and compare it to the current one; show added domains; apply changes with backup.
- **Deduplication & Sorting**: Detect duplicate entries in any blocklist file, remove duplicates, optionally sort alphabetically, preserve comments, export commented lines – all with automatic backup.
- **Statistics Analytics**: SQLite database (`stats.db`) stores hourly/daily blocked counts and per‑domain stats; interactive charts (Chart.js) for the last 24 hours and 30 days, plus top‑20 blocked domains table.
- **Misc Settings** (most require dev mode): toggle autostart, verbose logging, DNS flush, statistics collection, backup creation; adjust max log file size; statistics flushing interval and cleanup ticks.

### 📊 Statistics & Flushing
- Added SQLite storage for hourly, daily and domain block counters.
- Customizable flush interval (10–86400 seconds) and domain map cleanup ticks (0 = never) – settings persisted in log headers.
- Configurable via WebView (Statistics panel, “Flushing Settings”) with automatic flusher restart after saving.

### 🛡️ Crash Resilience
- Go panic recovery: catches any internal panic and immediately resets DNS (removes static DNS entries) to avoid loss of internet. Writes a `crash.log` for debugging.

### 🧪 User‑Facing Improvements
- **Systray status** now shows only “Running” / “Stopped” / “Dry‑run” (the list‑refresh date was removed).
- **Delayed tray menu activation**: “Quit” and “WebView” are disabled for 3 seconds after start to prevent accidental clicks during initialisation.
- **Search in file editor**: enter term, press Enter to find. Scrolls vertically to exact line, horizontally only if the match is longer than the visible area.
- **Realtime log viewer** with client‑side filtering and auto‑scroll.
- **Reorder of Misc settings** for logical flow (Autostart, Flush DNS, Backups, Verbose, Stats, Log size).
- **Statistics panel** now features collapsible “Flushing Settings” at the bottom.

### 🔧 Technical / Code Quality
- **Thread‑safe option access**: `proxy.GetCurrentOpts()` provides a consistent snapshot of the current configuration.
- **Domain counters cleanup**: stale entries (count=0) are periodically removed from the in‑memory map via `CleanupDomainCounts()`.
- Flusher interval increased from 15s to 60s (production‑ready).
- Proper event binding for log refresh and clear buttons (prevents double‑function definitions).

### 🐛 Last Bug Fixes
- Fixed tray status showing “Stopped” after successful start.
- Resolved crash on startup due to nil pointer when accessing tray items before creation.
- Corrected log real‑time view event bindings and duplicate clear‑log function.
- Improved horizontal scrolling behaviour in search to remain stationary for short matches.
- Fixed search not jumping to found position (missing scroll logic for long lines).
- Fixed search not executing on Enter (event listener misassignment).
- Corrected horizontal scroll calculation to respect editor padding.
- Disabled word wrap in editor (`wrap="off"`) for accurate line counting.
- Adjusted vertical scroll target to place found line in upper third of viewport.

### 🔧 Known Issues
- **CLI compatibility** (previous `cmd/cli`) has not been tested with the new architecture. If you require CLI support, please open an issue.

---

## [1.1.0] - Windows DNS Integration Improvements
- **Dynamic Interface Detection**: Added automatic detection of the active network interface using PowerShell, replacing hardcoded "Ethernet-Adapter".
- **Admin Privilege Handling**: Added automatic restart with administrator privileges for Windows to allow changing system DNS settings.
- **Local Blocklist Support**: Added support for a local `blocklist.txt` and `sources.txt` file in the executable directory.
- **Robust DNS Restoration**:
    - Fixed DNS restoration on application exit.
    - Added support for restoring multiple (alternate) DNS servers.
    - Improved `netsh` command formatting to handle interface names with spaces.
- **Localization Fix**: Replaced English‑based `netsh` output parsing with structured PowerShell cmdlets (`Get-NetIPInterface`, `Get-DnsClientServerAddress`) to ensure the app works on non‑English Windows installations.
- **Code Quality**: Fixed indentation inconsistencies and duplicate variable declarations.

## [1.0.0] - Initial Release
- Initial implementation of DNS proxy with ad‑blocking capabilities.
- System tray integration for Windows.
- Support for multiple blocklist sources.
