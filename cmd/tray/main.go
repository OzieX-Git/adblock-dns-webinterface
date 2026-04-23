package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall" // ← hinzugefügt für HideWindow und CreateProcess
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/dmtkfs/adblock-dns/internal/proxy"
	"github.com/getlantern/systray"
	"github.com/miekg/dns"
)

var statsDB *sql.DB

var statsEnabled = false // Standard: deaktiviert

var csrfToken string

var devMode bool

var autostartEnabled = false // Standard: deaktiviert

var verboseEnabled = false // Debug-Logs in der Logdatei

//go:embed icon_green.ico
var iconGreen []byte

//go:embed icon_red.ico
var iconRed []byte

//go:embed icon_blue.ico
var iconBlue []byte

type dnsSnapshot struct {
	InterfaceAlias string   `json:"interfaceAlias"`
	UseDHCP        bool     `json:"useDhcp"`
	Servers        []string `json:"servers"`
}

var (
	originalDNSSettings      dnsSnapshot
	originalDNSSettingsSaved bool
	activeInterface          string
	appMutex                 windows.Handle
	currentDryRun            bool
)

func isAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
		`if ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544') { exit 0 } else { exit 1 }`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} // ← Fenster verstecken
	_, err := cmd.CombinedOutput()
	return err == nil
}

func runAsAdmin() {
	if runtime.GOOS != "windows" {
		return
	}
	exe, _ := os.Executable()
	args := strings.Join(os.Args[1:], " ")

	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	dir, _ := windows.UTF16PtrFromString("")

	// SW_HIDE = 0 → versteckt das Fenster des neu gestarteten Prozesses
	err := windows.ShellExecute(0, verb, file, params, dir, windows.SW_HIDE)
	if err != nil {
		log.Printf("ShellExecute failed: %v, trying PowerShell fallback", err)
		// Fallback: PowerShell (fensterlos)
		psCmd := fmt.Sprintf(`Start-Process -FilePath "%s" -ArgumentList "%s" -Verb Runas -WindowStyle Hidden`, exe, args)
		cmd := exec.Command("powershell", "-Command", psCmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run()
	}
	os.Exit(0)
}

func startStatsFlusher(ctx context.Context) {
	interval := time.Duration(statsFlushInterval) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("[FLUSHER] Started with %v ticker, cleanup every %d flushes", interval, statsCleanupTicks)
	var flushCount int
	for {
		select {
		case <-ctx.Done():
			log.Println("[FLUSHER] Context done, stopping")
			flushStatsToDB()
			return
		case <-ticker.C:
			flushCount++
			// Einmal täglich (nach ~1440 Flushes) die Domain‑Map bereinigen
			if statsCleanupTicks > 0 && flushCount%statsCleanupTicks == 0 {
				proxy.CleanupDomainCounts()
			}
			log.Printf("[FLUSHER] Tick #%d at %v, calling flushStatsToDB",
				flushCount, time.Now().Format("15:04:05"))
			flushStatsToDB()
		}
	}
}

var (
	statsFlusherCtx    context.Context
	statsFlusherCancel context.CancelFunc
	statsFlushInterval = 60   // Sekunden zwischen zwei DB‑Schreibvorgängen
	statsCleanupTicks  = 1440 // Anzahl Flushes zwischen Domain‑Bereinigungen (0 = nie)
)

func setStatsEnabled(enabled bool) {
	log.Printf("[STATS] setStatsEnabled called with enabled=%v (current=%v, flusherRunning=%v)",
		enabled, statsEnabled, statsFlusherCtx != nil)

	// Nur zurückkehren, wenn sich nichts ändert UND der Flusher bereits läuft
	if enabled == statsEnabled && statsFlusherCtx != nil {
		return
	}
	statsEnabled = enabled
	proxy.SetStatsEnabled(enabled)
	if enabled {
		log.Println("[STATS] Enabling stats and starting flusher")
		// Flusher starten
		ctx, cancel := context.WithCancel(context.Background())
		statsFlusherCtx = ctx
		statsFlusherCancel = cancel
		go startStatsFlusher(ctx)
	} else {
		log.Println("[STATS] Disabling stats and stopping flusher")
		// Flusher stoppen und letzte Daten schreiben
		if statsFlusherCancel != nil {
			statsFlusherCancel()
			flushStatsToDB()
			statsFlusherCtx = nil
			statsFlusherCancel = nil
		}
	}
	writeLogHeader()
}

func flushStatsToDB() {
	if statsDB == nil {
		log.Println("[FLUSH] statsDB is nil")
		return
	}
	now := time.Now()
	hourKey := now.Format("2006-01-02T15")
	dayKey := now.Format("2006-01-02")

	hourVal := proxy.PopHourlyBlocked()
	if hourVal > 0 {
		_, err := statsDB.Exec(`INSERT INTO hourly_stats(hour, blocked) VALUES(?, ?) 
					  ON CONFLICT(hour) DO UPDATE SET blocked = blocked + ?`,
			hourKey, hourVal, hourVal)
		if err != nil {
			log.Printf("[DB-ERROR] hourly_stats insert: %v", err)
		}
	}

	dayVal := proxy.PopDailyBlocked()
	if dayVal > 0 {
		_, err := statsDB.Exec(`INSERT INTO daily_stats(day, blocked) VALUES(?, ?) 
					  ON CONFLICT(day) DO UPDATE SET blocked = blocked + ?`,
			dayKey, dayVal, dayVal)
		if err != nil {
			log.Printf("[DB-ERROR] daily_stats insert: %v", err)
		}
	}

	domainCountsMap := proxy.PopDomainCounts()
	for domain, count := range domainCountsMap {
		if count > 0 {
			_, err := statsDB.Exec(`INSERT INTO domain_stats(domain, count) VALUES(?, ?) 
						  ON CONFLICT(domain) DO UPDATE SET count = count + ?`,
				domain, count, count)
			if err != nil {
				log.Printf("[DB-ERROR] domain_stats insert: %v", err)
			}
		}
	}
	log.Printf("[FLUSH] hour=%d day=%d domains=%d", hourVal, dayVal, len(domainCountsMap))
}

// ensureConfigFiles erstellt die benötigten Konfigurationsdateien mit
// Beispielinhalten, falls sie nicht existieren.
func ensureConfigFiles() {
	files := map[string]string{
		"blocklist.txt": `#Beispiel:
#
#0.0.0.0 <-IP->
0.0.0.0 0.0.0.0
`,
		"sources.txt": `#Beispiel:
#https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts
`,
		"whitelist.txt": `#Beispiel: Anti-Cheat Provider DNS
# Easy Anti-Cheat
eac-cdn.easyanticheat.net
download.easyanticheat.net

# BattlEye
battleye.com
be.fileburst.com

# Riot Vanguard
riotgames.com
lol.secure.dyn.riotcdn.net
valorant.secure.dyn.riotcdn.net

# Activision / Ricochet
callofduty.com
activision.com
blzddist1-a.akamaihd.net

# Ubisoft / Denuvo
ubisoft.com
static3.cdn.ubi.com
denuvo.com
`,
	}

	for name, content := range files {
		path := filepath.Join(exeDir(), name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.WriteFile(path, []byte(content), 0644); err != nil {
				log.Printf("Fehler beim Erstellen von %s: %v", name, err)
			} else {
				log.Printf("Standarddatei %s wurde erstellt", name)
			}
		}
	}
}

func exeDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}

func logPath() string {
	return filepath.Join(exeDir(), "adblock.log")
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func runPowerShellHidden(script string) ([]byte, error) {
	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden",
		"-Command", script,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} // ← Zusätzliche Sicherheit
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("powershell failed: %w: %s", err, string(output))
	}
	return output, nil
}

func runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} // ← Kein Konsolenfenster
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh failed: %w: %s", err, string(output))
	}
	return nil
}

func initStatsDB() error {
	dbPath := filepath.Join(exeDir(), "stats.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS hourly_stats (hour TEXT PRIMARY KEY, blocked INTEGER DEFAULT 0)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS daily_stats (day TEXT PRIMARY KEY, blocked INTEGER DEFAULT 0)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS domain_stats (domain TEXT PRIMARY KEY, count INTEGER DEFAULT 0)`)
	if err != nil {
		return err
	}
	statsDB = db
	return nil
}

func flushDNS() {
	flushDNSMu.RLock()
	enabled := flushDNSEnabled
	flushDNSMu.RUnlock()
	if !enabled {
		return
	}
	if runtime.GOOS != "windows" {
		return
	}
	cmd := exec.Command("ipconfig", "/flushdns")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("DNS flush failed: %v - %s", err, string(output))
	} else {
		log.Printf("DNS cache flushed")
	}
}

func setDNSStatic(alias string, servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}
	if err := runNetsh("interface", "ip", "set", "dns", alias, "static", servers[0], "primary"); err != nil {
		return err
	}
	for i, s := range servers[1:] {
		if err := runNetsh("interface", "ip", "add", "dns", alias, s, fmt.Sprintf("index=%d", i+2)); err != nil {
			log.Printf("Warning: failed to add secondary DNS %s: %v", s, err)
		}
	}
	return nil
}

// findActiveInterface findet die primäre Netzwerkschnittstelle mit Internetzugang
func findActiveInterface() string {
	if runtime.GOOS != "windows" {
		return "eth0"
	}

	output, err := runPowerShellHidden(
		`Get-NetConnectionProfile | Where-Object IPv4Connectivity -eq "Internet" | Select-Object -ExpandProperty InterfaceAlias`,
	)
	if err != nil {
		log.Printf("Warning: Failed to find active interface: %v", err)
		return "Ethernet"
	}

	iface := strings.TrimSpace(string(output))
	if iface == "" {
		log.Printf("Warning: No active interface found, using 'Ethernet'")
		return "Ethernet"
	}

	log.Printf("Found active interface: %s", iface)
	return iface
}

func saveOriginalDNSSettings() {
	if runtime.GOOS != "windows" {
		return
	}

	if originalDNSSettingsSaved {
		return // Already saved
	}

	if activeInterface == "" {
		log.Printf("Cannot save DNS settings: no active interface found")
		return
	}

	script := fmt.Sprintf(`
$addr = Get-DnsClientServerAddress -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction Stop
$cfg  = Get-NetIPInterface -InterfaceAlias %s -AddressFamily IPv4 -ErrorAction Stop
$obj = [pscustomobject]@{
  interfaceAlias = %s
  useDhcp        = [bool]($cfg.Dhcp -eq 'Enabled')
  servers        = @($addr.ServerAddresses | Where-Object { $_ -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
}
$obj | ConvertTo-Json -Compress
`,
		psQuote(activeInterface),
		psQuote(activeInterface),
		psQuote(activeInterface),
	)

	output, err := runPowerShellHidden(script)
	if err != nil {
		log.Printf("Failed to read DNS settings: %v", err)
		return
	}

	var snap dnsSnapshot
	if err := json.Unmarshal(output, &snap); err != nil {
		log.Printf("Failed to parse DNS settings: %v; output=%s", err, string(output))
		return
	}

	if len(snap.Servers) == 0 {
		snap.Servers = nil
	}

	originalDNSSettings = snap
	originalDNSSettingsSaved = true
	log.Printf("Saved DNS settings for %s: DHCP=%v servers=%v", snap.InterfaceAlias, snap.UseDHCP, snap.Servers)
}

func isGatewayIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.") ||
		strings.HasPrefix(ip, "169.254.")
}

func restoreOriginalDNSSettings() error {
	if runtime.GOOS != "windows" || !originalDNSSettingsSaved {
		return nil
	}

	ifaceName := originalDNSSettings.InterfaceAlias
	if ifaceName == "" {
		return fmt.Errorf("no interface name saved")
	}

	// Check if we have real DNS servers (not localhost, not gateway IPs, not empty)
	hasRealDNS := false
	for _, s := range originalDNSSettings.Servers {
		if s != "127.0.0.1" && !isGatewayIP(s) {
			hasRealDNS = true
			break
		}
	}

	if hasRealDNS {
		log.Printf("Restoring DNS: static %v on %s", originalDNSSettings.Servers, ifaceName)
		return setDNSStatic(ifaceName, originalDNSSettings.Servers)
	}

	// No real DNS servers saved (was DHCP, or only had 127.0.0.1/gateway) → reset to DHCP
	log.Printf("Restoring DNS: reset to DHCP (automatic) on %s", ifaceName)
	return runNetsh("interface", "ip", "delete", "dns", ifaceName, "all")
}

func setAutostart(enable bool) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	if enable {
		return key.SetStringValue("AdblockDNS", exePath)
	} else {
		return key.DeleteValue("AdblockDNS")
	}
}

func onExit() {
	stopConfigEditor() // Server beenden
	if proxy.Running() {
		proxy.Stop()
	}
	if runtime.GOOS == "windows" {
		if !originalDNSSettingsSaved {
			log.Printf("No DNS settings were saved, skipping restore")
		} else if err := restoreOriginalDNSSettings(); err != nil {
			log.Printf("Failed to restore DNS settings: %v", err)
		} else {
			log.Printf("DNS settings restored successfully")
		}
	}
	flushDNS()
}

func updateStatus(mi *systray.MenuItem) {
	for {
		running := proxy.Running()
		// Icon je nach Status setzen
		switch {
		case !running:
			systray.SetIcon(iconRed)
		case currentDryRun:
			systray.SetIcon(iconBlue)
		default:
			systray.SetIcon(iconGreen)
		}

		state := "Stopped"
		if running {
			if currentDryRun {
				state = "Dry‑run"
			} else {
				state = "Running"
			}
		}
		mi.SetTitle(fmt.Sprintf("Status: %s", state))
		time.Sleep(1 * time.Second)
	}
}

func checkSingleInstance() bool {
	mutexName, _ := windows.UTF16PtrFromString("Global\\AdblockDNSTrayApp")
	mutex, err := windows.CreateMutex(nil, false, mutexName)
	if err != nil {
		log.Printf("CreateMutex failed: %v", err)
		return false
	}
	// Wenn der Mutex bereits existiert (ERROR_ALREADY_EXISTS), ist eine andere Instanz aktiv
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		windows.CloseHandle(mutex)
		return false
	}
	appMutex = mutex
	return true
}

var (
	httpServer       *http.Server
	editorMenuItem   *systray.MenuItem
	startItem        *systray.MenuItem
	stopItem         *systray.MenuItem
	dryItem          *systray.MenuItem
	currentUpstreams = []string{"9.9.9.9:53", "149.112.112.112:53"}
	flushDNSEnabled  bool
	upstreamsMu      sync.RWMutex
	flushDNSMu       sync.RWMutex
	backupEnabled    = true // Standard: aktiviert
	logMaxSizeMB     = 5    // Standard: 5 MB
)

const configHeaderPrefix = "#CONFIG "

// readLogHeader liest alle Einstellungen aus den #CONFIG‑Zeilen am Anfang der Logdatei.
func readLogHeader() {
	path := logPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if !strings.HasPrefix(line, configHeaderPrefix) {
			break
		}
		parseConfigLine(line)
	}
}

func parseConfigLine(line string) {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "#CONFIG flushdns="):
		flushDNSEnabled = strings.ToLower(strings.TrimPrefix(line, "#CONFIG flushdns=")) == "true"
	case strings.HasPrefix(line, "#CONFIG upstreams="):
		value := strings.TrimPrefix(line, "#CONFIG upstreams=")
		servers := strings.Split(value, ",")
		var result []string
		for _, s := range servers {
			s = strings.TrimSpace(s)
			if s != "" {
				result = append(result, s)
			}
		}
		if len(result) > 0 {
			upstreamsMu.Lock()
			currentUpstreams = result
			upstreamsMu.Unlock()
		}
	case strings.HasPrefix(line, "#CONFIG backup="):
		backupEnabled = strings.ToLower(strings.TrimPrefix(line, "#CONFIG backup=")) == "true"
	case strings.HasPrefix(line, "#CONFIG logmaxsize="):
		fmt.Sscanf(line, "#CONFIG logmaxsize=%d", &logMaxSizeMB)
	case strings.HasPrefix(line, "#CONFIG -dev="):
		devMode = strings.ToLower(strings.TrimPrefix(line, "#CONFIG -dev=")) == "true"
	case strings.HasPrefix(line, "#CONFIG verbose="):
		verboseEnabled = strings.ToLower(strings.TrimPrefix(line, "#CONFIG verbose=")) == "true"
	case strings.HasPrefix(line, "#CONFIG autostart="):
		autostartEnabled = strings.ToLower(strings.TrimPrefix(line, "#CONFIG autostart=")) == "true"
	case strings.HasPrefix(line, "#CONFIG stats="):
		statsEnabled = strings.ToLower(strings.TrimPrefix(line, "#CONFIG stats=")) == "true"
		log.Printf("[CONFIG] statsEnabled parsed as %v", statsEnabled)
	case strings.HasPrefix(line, "#CONFIG statsflushinterval="):
		if _, err := fmt.Sscanf(line, "#CONFIG statsflushinterval=%d", &statsFlushInterval); err != nil {
			log.Printf("Error parsing statsflushinterval: %v", err)
		}
	case strings.HasPrefix(line, "#CONFIG statscleanupticks="):
		if _, err := fmt.Sscanf(line, "#CONFIG statscleanupticks=%d", &statsCleanupTicks); err != nil {
			log.Printf("Error parsing statscleanupticks: %v", err)
		}
	}
}

// writeLogHeader schreibt den aktuellen Konfigurationsheader in die Logdatei.
func writeLogHeader() error {
	path := logPath()
	data, err := os.ReadFile(path)
	var restLines []string
	if err == nil {
		lines := strings.Split(string(data), "\n")
		skip := true
		for _, line := range lines {
			if skip && strings.HasPrefix(line, configHeaderPrefix) {
				continue
			}
			skip = false
			restLines = append(restLines, line)
		}
	}

	upstreamsMu.RLock()
	upstreamsCopy := strings.Join(currentUpstreams, ",")
	upstreamsMu.RUnlock()

	var headerLines []string
	headerLines = append(headerLines, "#CONFIG flushdns="+strconv.FormatBool(flushDNSEnabled))
	headerLines = append(headerLines, "#CONFIG upstreams="+upstreamsCopy)
	headerLines = append(headerLines, "#CONFIG backup="+strconv.FormatBool(backupEnabled))
	headerLines = append(headerLines, "#CONFIG -dev="+strconv.FormatBool(devMode))
	headerLines = append(headerLines, "#CONFIG autostart="+strconv.FormatBool(autostartEnabled))
	headerLines = append(headerLines, "#CONFIG verbose="+strconv.FormatBool(verboseEnabled))
	headerLines = append(headerLines, "#CONFIG stats="+strconv.FormatBool(statsEnabled))
	headerLines = append(headerLines, "#CONFIG statsflushinterval="+strconv.Itoa(statsFlushInterval))
	headerLines = append(headerLines, "#CONFIG statscleanupticks="+strconv.Itoa(statsCleanupTicks))
	headerLines = append(headerLines, "#CONFIG logmaxsize="+strconv.Itoa(logMaxSizeMB))

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	for _, l := range headerLines {
		fmt.Fprintln(f, l)
	}
	for _, l := range restLines {
		fmt.Fprintln(f, l)
	}
	return nil
}

const dedupeMarker = "# ->Start Adblock analyses hier<-"

// upstreamsForUI entfernt den Port :53 für die Anzeige
func upstreamsForUI(servers []string) []string {
	var result []string
	for _, s := range servers {
		host, _, err := net.SplitHostPort(s)
		if err == nil {
			result = append(result, host)
		} else {
			result = append(result, s)
		}
	}
	for len(result) < 2 {
		result = append(result, "")
	}
	return result[:2]
}

// extractDomainsFromBlocklist parst einen Hosts-Datei-Inhalt und gibt eine Map der Domains zurück.
// Berücksichtigt nur Zeilen mit "0.0.0.0 domain" oder "127.0.0.1 domain".
func extractDomainsFromBlocklist(content string) map[string]struct{} {
	domains := make(map[string]struct{})
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// Nur typische Block-IPs akzeptieren
		ip := fields[0]
		if ip != "0.0.0.0" && ip != "127.0.0.1" {
			continue
		}
		domain := fields[1]
		// Domain normalisieren (optional)
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			domains[domain] = struct{}{}
		}
	}
	return domains
}

// splitAtMarker teilt den Dateiinhalt in Kopf (alles vor dem Marker)
// und Körper (alles ab dem Marker). Wenn der Marker nicht gefunden wird,
// ist der Kopf der gesamte Inhalt und der Körper leer.
func splitAtMarker(content string) (head string, body string) {
	lines := strings.Split(content, "\n")
	var headLines, bodyLines []string
	markerFound := false

	for _, line := range lines {
		if !markerFound && strings.TrimSpace(line) == dedupeMarker {
			markerFound = true
			headLines = append(headLines, line)
			continue
		}
		if markerFound {
			bodyLines = append(bodyLines, line)
		} else {
			headLines = append(headLines, line)
		}
	}
	if !markerFound {
		// Kein Marker: gesamte Datei als Body, Head bleibt leer
		return "", content
	}
	head = strings.Join(headLines, "\n")
	body = strings.Join(bodyLines, "\n")
	return
}

func generateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback – sollte nie passieren
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func checkCSRF(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	return token == csrfToken
}

// startConfigEditor startet den lokalen Webserver und öffnet den Browser.
func startConfigEditor() {
	if csrfToken == "" {
		csrfToken = generateCSRFToken()
	}
	if httpServer != nil {
		// Server läuft bereits – Browser erneut öffnen
		openBrowser("http://127.0.0.1:8080")
		return
	}

	// Port testen
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Printf("❌ WebView kann nicht starten – Port 8080 belegt: %v", err)
		return
	}
	ln.Close()

	mux := http.NewServeMux()

	// ⚠️ ALLE mux.HandleFunc AUFRUFE MÜSSEN HIER STEHEN, BEVOR DER SERVER GESTARTET WIRD!

	// Hauptseite
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := strings.Replace(editorHTML, "%CSRF_TOKEN%", csrfToken, 1)
		w.Write([]byte(html))
	})

	// API: Datei lesen
	mux.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		filename := r.URL.Query().Get("name")
		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[filename] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}
		path := filepath.Join(exeDir(), filename)
		http.ServeFile(w, r, path)
	})

	// API: Datei speichern
	mux.HandleFunc("/api/save", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			File    string `json:"file"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.File] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}
		path := filepath.Join(exeDir(), req.File)
		if err := os.WriteFile(path, []byte(req.Content), 0644); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Config file %s updated via web editor", req.File)
		w.WriteHeader(http.StatusOK)
	})

	// API: Status des Proxys abfragen
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		resp := struct {
			Running     bool      `json:"running"`
			LastUpdated time.Time `json:"lastUpdated"`
			DryRun      bool      `json:"dryRun"`
		}{
			Running:     proxy.Running(),
			LastUpdated: proxy.LastUpdated(),
			DryRun:      currentDryRun,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// API: Logdatei auslesen
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.ServeFile(w, r, logPath())
	})

	// API: Logdatei leeren
	mux.HandleFunc("/api/log/clear", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		path := logPath()
		if err := os.Truncate(path, 0); err != nil {
			if err := os.WriteFile(path, []byte{}, 0644); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if err := writeLogHeader(); err != nil {
			log.Printf("Failed to write log header after clear: %v", err)
		}
		log.Printf("Log file cleared via web editor")
		w.WriteHeader(http.StatusOK)
	})

	// API: Proxy starten
	mux.HandleFunc("/api/proxy/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if proxy.Running() {
			w.WriteHeader(http.StatusOK)
			return
		}

		upstreamsMu.RLock()
		upstreams := make([]string, len(currentUpstreams))
		copy(upstreams, currentUpstreams)
		upstreamsMu.RUnlock()

		opts := proxy.Options{
			Listen:    "127.0.0.1:53",
			Interval:  24 * time.Hour,
			DryRun:    currentDryRun,
			Verbose:   verboseEnabled,
			Upstreams: upstreams,
			MatchMode: "suffix",
			BlockMode: "null",
		}
		if err := proxy.Start(opts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if startItem != nil {
			startItem.Disable()
			stopItem.Enable()
		}
		if dryItem != nil {
			dryItem.Enable()
		}
		// DNS nur unter Windows setzen
		if runtime.GOOS == "windows" {
			ensureActiveInterface()
			if !originalDNSSettingsSaved {
				saveOriginalDNSSettings()
			}
			if err := setDNSStatic(activeInterface, []string{"127.0.0.1"}); err != nil {
				log.Printf("Failed to set DNS: %v", err)
			}
		}
		log.Printf("Proxy started via web interface")
		w.WriteHeader(http.StatusOK)
	})

	// API: Proxy stoppen
	mux.HandleFunc("/api/proxy/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if !proxy.Running() {
			w.WriteHeader(http.StatusOK)
			return
		}
		proxy.Stop()
		proxy.SetDryRun(false)
		currentDryRun = false
		if dryItem != nil {
			dryItem.Uncheck()
			dryItem.Disable()
		}
		// Tray-Menü aktualisieren
		if stopItem != nil {
			stopItem.Disable()
			startItem.Enable()
		}
		if runtime.GOOS == "windows" {
			if err := restoreOriginalDNSSettings(); err != nil {
				log.Printf("Failed to restore DNS: %v", err)
			}
		}
		log.Printf("Proxy stopped via web interface")
		w.WriteHeader(http.StatusOK)
	})

	// API: Dry-Run setzen
	mux.HandleFunc("/api/proxy/dryrun", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		proxy.SetDryRun(req.Enabled)
		currentDryRun = req.Enabled
		// Tray-Checkbox aktualisieren
		if dryItem != nil {
			if req.Enabled {
				dryItem.Check()
			} else {
				dryItem.Uncheck()
			}
		}
		log.Printf("Dry-run set to %v via web interface", req.Enabled)
		w.WriteHeader(http.StatusOK)
	})

	// API: Proxy neu starten (um Upstream-Änderungen zu übernehmen)
	mux.HandleFunc("/api/proxy/restart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		wasRunning := proxy.Running()
		if wasRunning {
			proxy.Stop()
			time.Sleep(200 * time.Millisecond)
		}
		upstreamsMu.RLock()
		upstreams := make([]string, len(currentUpstreams))
		copy(upstreams, currentUpstreams)
		upstreamsMu.RUnlock()

		opts := proxy.Options{
			Listen:    "127.0.0.1:53",
			Interval:  24 * time.Hour,
			DryRun:    currentDryRun,
			Verbose:   verboseEnabled,
			Upstreams: upstreams,
			MatchMode: "suffix",
			BlockMode: "null",
		}
		if err := proxy.Start(opts); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if startItem != nil {
			startItem.Disable()
			stopItem.Enable()
		}
		log.Printf("Proxy restarted with upstreams: %v", upstreams)
		w.WriteHeader(http.StatusOK)
	})

	// API: Statistiken abrufen
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		blocked, dryRun := proxy.Stats()
		resp := struct {
			BlockedTotal uint64 `json:"blockedTotal"`
			DryRunTotal  uint64 `json:"dryRunTotal"`
		}{blocked, dryRun}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// API: Upstreams lesen
	mux.HandleFunc("/api/upstreams", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			upstreamsMu.RLock()
			servers := make([]string, len(currentUpstreams))
			copy(servers, currentUpstreams)
			upstreamsMu.RUnlock()
			uiServers := upstreamsForUI(servers)
			json.NewEncoder(w).Encode(uiServers)
			return
		}
		if r.Method == http.MethodPost {
			if !checkCSRF(r) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			var servers []string
			if err := json.NewDecoder(r.Body).Decode(&servers); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if len(servers) == 0 {
				http.Error(w, "at least one upstream required", http.StatusBadRequest)
				return
			}
			upstreamsMu.Lock()
			currentUpstreams = make([]string, len(servers))
			copy(currentUpstreams, servers)
			upstreamsMu.Unlock()

			if err := writeLogHeader(); err != nil {
				log.Printf("Failed to write log header: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("Upstreams updated and saved: %v", servers)
			w.WriteHeader(http.StatusOK)
			return
		}
	})

	// API: Upstreams auf Default zurücksetzen
	mux.HandleFunc("/api/upstreams/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		defaults := []string{"9.9.9.9:53", "149.112.112.112:53"}
		upstreamsMu.Lock()
		currentUpstreams = defaults
		upstreamsMu.Unlock()

		if err := writeLogHeader(); err != nil {
			log.Printf("Failed to write log header: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Upstreams reset to defaults and saved")
		w.WriteHeader(http.StatusOK)
	})

	// API: FlushDNS-Einstellung lesen / setzen
	mux.HandleFunc("/api/flushdns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			flushDNSMu.RLock()
			enabled := flushDNSEnabled
			flushDNSMu.RUnlock()
			json.NewEncoder(w).Encode(map[string]bool{"enabled": enabled})
			return
		}
		if r.Method == http.MethodPost {
			if !checkCSRF(r) {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			var req struct{ Enabled bool }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			flushDNSMu.Lock()
			flushDNSEnabled = req.Enabled
			flushDNSMu.Unlock()

			if err := writeLogHeader(); err != nil {
				log.Printf("Failed to write log header: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("FlushDNS set to %v via web interface", req.Enabled)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// API: Troubleshoot - Diagnose des Systemzustands
	mux.HandleFunc("/api/troubleshoot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		type result struct {
			ProxyRunning      bool     `json:"proxyRunning"`
			ListenerAddr      string   `json:"listenerAddr"`
			SystemDNS         []string `json:"systemDNS"`
			ActiveInterface   string   `json:"activeInterface"`
			Upstreams         []string `json:"upstreams"`
			UpstreamReachable []bool   `json:"upstreamReachable"`
			Conflicts         []string `json:"conflicts"`
			ConflictCount     int      `json:"conflictCount"`
		}

		res := result{
			ProxyRunning:    proxy.Running(),
			ListenerAddr:    "127.0.0.1:53",
			ActiveInterface: activeInterface,
		}

		// Aktuelle Upstreams aus dem Speicher lesen
		upstreamsMu.RLock()
		res.Upstreams = make([]string, len(currentUpstreams))
		copy(res.Upstreams, currentUpstreams)
		upstreamsMu.RUnlock()

		// Upstreams auf Erreichbarkeit prüfen (UDP-Dial)
		res.UpstreamReachable = make([]bool, len(res.Upstreams))
		for i, addr := range res.Upstreams {
			conn, err := net.DialTimeout("udp", addr, 2*time.Second)
			if err == nil {
				conn.Close()
				res.UpstreamReachable[i] = true
			}
		}

		// Konflikte zwischen blocklist.txt und whitelist.txt prüfen
		blockPath := filepath.Join(exeDir(), "blocklist.txt")
		blockData, err := os.ReadFile(blockPath)
		if err == nil {
			blockDomains := extractDomainsFromBlocklist(string(blockData))
			whitePath := filepath.Join(exeDir(), "whitelist.txt")
			whiteData, err := os.ReadFile(whitePath)
			if err == nil {
				whiteDomains := make(map[string]struct{})
				for _, line := range strings.Split(string(whiteData), "\n") {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					fields := strings.Fields(line)
					if len(fields) == 0 {
						continue
					}
					domain := strings.ToLower(strings.TrimSpace(fields[0]))
					if domain != "" {
						whiteDomains[domain] = struct{}{}
					}
				}
				conflicts := []string{}
				for domain := range blockDomains {
					if _, exists := whiteDomains[domain]; exists {
						conflicts = append(conflicts, domain)
					}
				}
				sort.Strings(conflicts)
				res.Conflicts = conflicts
				res.ConflictCount = len(conflicts)
			}
		}

		// System-DNS des aktiven Interfaces auslesen (Windows)
		if runtime.GOOS == "windows" && activeInterface != "" {
			out, err := runPowerShellHidden(fmt.Sprintf(
				`(Get-DnsClientServerAddress -InterfaceAlias '%s' -AddressFamily IPv4).ServerAddresses`,
				strings.ReplaceAll(activeInterface, "'", "''")))
			if err == nil {
				raw := strings.TrimSpace(string(out))
				if raw != "" {
					res.SystemDNS = strings.Fields(raw)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})

	// API: Blocklisten vergleichen und neue Domains anhängen
	mux.HandleFunc("/api/compare", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			CurrentFile string `json:"currentFile"` // Dateiname (z.B. "blocklist.txt")
			NewContent  string `json:"newContent"`  // Inhalt der neuen Liste
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Erlaubte Dateien
		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.CurrentFile] {
			http.Error(w, "invalid current file", http.StatusBadRequest)
			return
		}

		// Aktuelle Datei einlesen
		currentPath := filepath.Join(exeDir(), req.CurrentFile)
		currentData, err := os.ReadFile(currentPath)
		if err != nil {
			http.Error(w, "failed to read current file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Domains aus aktueller Datei extrahieren (nur Blockeinträge: 0.0.0.0 domain)
		currentDomains := extractDomainsFromBlocklist(string(currentData))

		// Domains aus neuer Liste extrahieren
		newDomains := extractDomainsFromBlocklist(req.NewContent)

		// Neue Domains ermitteln (in new, aber nicht in current)
		var addedDomains []string
		for domain := range newDomains {
			if _, exists := currentDomains[domain]; !exists {
				addedDomains = append(addedDomains, domain)
			}
		}

		// Antwort vorbereiten
		resp := struct {
			AddedCount    int      `json:"addedCount"`
			NewDomains    []string `json:"newDomains,omitempty"`    // max. 20 zur Vorschau
			AllNewDomains []string `json:"allNewDomains,omitempty"` // Vollständige Liste
			Error         string   `json:"error,omitempty"`
		}{
			AddedCount:    len(addedDomains),
			AllNewDomains: addedDomains,
		}
		// Vorschau der ersten 60 neuen Domains
		if len(addedDomains) > 0 {
			preview := addedDomains
			if len(preview) > 60 {
				preview = preview[:60]
			}
			resp.NewDomains = preview
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// API: Neue Domains tatsächlich an die Datei anhängen
	mux.HandleFunc("/api/compare/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			CurrentFile string   `json:"currentFile"`
			NewDomains  []string `json:"newDomains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.CurrentFile] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}
		if len(req.NewDomains) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}

		path := filepath.Join(exeDir(), req.CurrentFile)

		if backupEnabled {
			originalData, err := os.ReadFile(path)
			if err == nil {
				backupPath := path + "." + time.Now().Format("20060102_150405") + ".bak"
				if err := os.WriteFile(backupPath, originalData, 0644); err != nil {
					log.Printf("Failed to create backup: %v", err)
				}
			}
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		// Kommentar und neue Einträge schreiben
		f.WriteString("\n# New Domains Blocked added\n")
		for _, domain := range req.NewDomains {
			fmt.Fprintf(f, "0.0.0.0 %s\n", domain)
		}
		log.Printf("Added %d new domains to %s via compare", len(req.NewDomains), req.CurrentFile)
		w.WriteHeader(http.StatusOK)
	})

	// API: Datei auf Duplikate prüfen
	mux.HandleFunc("/api/deduplicate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			File    string `json:"file"`
			Details bool   `json:"details,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.File] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}
		path := filepath.Join(exeDir(), req.File)
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		content := string(data)
		_, body := splitAtMarker(content)

		// Häufigkeit jeder Domain zählen
		domainCount := make(map[string]int)
		lines := strings.Split(body, "\n")
		validLineCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				validLineCount++
				domain := strings.ToLower(strings.TrimSpace(fields[1]))
				if domain != "" {
					domainCount[domain]++
				}
			}
		}

		uniqueCount := len(domainCount)
		duplicateCount := validLineCount - uniqueCount

		// Duplikate sammeln
		var duplicates []string
		if req.Details {
			for domain, count := range domainCount {
				if count > 1 {
					duplicates = append(duplicates, domain)
				}
			}
			sort.Strings(duplicates)
		}

		resp := struct {
			UniqueCount    int      `json:"uniqueCount"`
			DuplicateCount int      `json:"duplicateCount"`
			MarkerFound    bool     `json:"markerFound"`
			Duplicates     []string `json:"duplicates,omitempty"`
		}{
			UniqueCount:    uniqueCount,
			DuplicateCount: duplicateCount,
			MarkerFound:    strings.Contains(content, dedupeMarker),
			Duplicates:     duplicates,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/deduplicate/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			File             string `json:"file"`
			SortAlphabetical bool   `json:"sortAlphabetical"`
			KeepCommented    bool   `json:"keepCommented"`
			ExportCommented  bool   `json:"exportCommented"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Logischer Ausschluss: Wenn sortiert wird, können Kommentare nicht behalten werden
		if req.SortAlphabetical {
			req.KeepCommented = false
		}

		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.File] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}

		path := filepath.Join(exeDir(), req.File)
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		content := string(data)
		head, body := splitAtMarker(content)

		// Backup erstellen, NACHDEM data gelesen wurde
		if backupEnabled {
			backupPath := path + "." + time.Now().Format("20060102_150405") + ".bak"
			if err := os.WriteFile(backupPath, data, 0644); err != nil {
				log.Printf("Failed to create backup: %v", err)
			}
		}

		// --- Extraktion der eindeutigen Domains ---
		uniqueDomainsSet := make(map[string]struct{})
		lines := strings.Split(body, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				domain := strings.ToLower(strings.TrimSpace(fields[1]))
				if domain != "" {
					uniqueDomainsSet[domain] = struct{}{}
				}
			}
		}

		// In Slice umwandeln
		var uniqueDomains []string
		for d := range uniqueDomainsSet {
			uniqueDomains = append(uniqueDomains, d)
		}
		if req.SortAlphabetical {
			sort.Strings(uniqueDomains)
		}

		// --- Body neu aufbauen ---
		var newBodyLines []string

		if req.KeepCommented && !req.SortAlphabetical {
			// Kommentare und Leerzeilen in der ursprünglichen Reihenfolge beibehalten
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					newBodyLines = append(newBodyLines, line)
				}
			}
		}

		// Eindeutige Blockeinträge anhängen
		for _, domain := range uniqueDomains {
			newBodyLines = append(newBodyLines, fmt.Sprintf("0.0.0.0 %s", domain))
		}

		newBody := strings.Join(newBodyLines, "\n")

		// --- Datei schreiben ---
		f, err := os.Create(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		f.WriteString(head)
		if !strings.HasSuffix(head, "\n") {
			f.WriteString("\n")
		}
		if !strings.Contains(content, dedupeMarker) {
			f.WriteString(dedupeMarker + "\n")
		}
		f.WriteString("\n# Deduplicated entries\n")
		f.WriteString(newBody)

		// Export der kommentierten Zeilen (wie gehabt)
		// ...

		log.Printf("Deduplicated %s (sort=%v, keepCommented=%v)", req.File, req.SortAlphabetical, req.KeepCommented)
		w.WriteHeader(http.StatusOK)
	})

	// API: Sortieren und Bereinigen ohne Duplikate zu entfernen
	mux.HandleFunc("/api/sortclean/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct {
			File             string `json:"file"`
			SortAlphabetical bool   `json:"sortAlphabetical"`
			KeepCommented    bool   `json:"keepCommented"`
			ExportCommented  bool   `json:"exportCommented"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Logischer Ausschluss: Wenn sortiert wird, können Kommentare nicht behalten werden
		if req.SortAlphabetical {
			req.KeepCommented = false
		}

		allowed := map[string]bool{
			"blocklist.txt": true,
			"sources.txt":   true,
			"whitelist.txt": true,
		}
		if !allowed[req.File] {
			http.Error(w, "invalid file", http.StatusBadRequest)
			return
		}

		path := filepath.Join(exeDir(), req.File)
		data, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if backupEnabled {
			backupPath := path + "." + time.Now().Format("20060102_150405") + ".bak"
			if err := os.WriteFile(backupPath, data, 0644); err != nil {
				log.Printf("Failed to create backup: %v", err)
				// Trotzdem fortfahren? Oder Fehler zurückgeben?
			}
		}
		content := string(data)
		head, body := splitAtMarker(content)

		lines := strings.Split(body, "\n")

		// --- Extraktion der Blockeinträge (alle, nicht nur eindeutige) ---
		var blockEntries []string
		var otherLines []string

		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				// Kommentare/Leerzeilen werden entweder behalten oder verworfen
				if req.KeepCommented {
					otherLines = append(otherLines, line)
				}
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && (fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
				domain := strings.ToLower(strings.TrimSpace(fields[1]))
				if domain != "" {
					blockEntries = append(blockEntries, fmt.Sprintf("0.0.0.0 %s", domain))
				}
			} else if req.KeepCommented {
				// Andere Zeilen (z.B. falsch formatierte) als Kommentar behalten? Oder ignorieren.
				// Wir entscheiden: wenn KeepCommented true, behalten wir die Zeile wie sie ist.
				otherLines = append(otherLines, line)
			}
		}

		// Sortieren falls gewünscht
		if req.SortAlphabetical {
			sort.Strings(blockEntries)
		}

		// Body neu aufbauen: zuerst die anderen Zeilen (Kommentare/Leerzeilen in Originalreihenfolge),
		// dann die (ggf. sortierten) Blockeinträge.
		var newBodyLines []string
		if req.KeepCommented {
			newBodyLines = append(newBodyLines, otherLines...)
		}
		newBodyLines = append(newBodyLines, blockEntries...)

		newBody := strings.Join(newBodyLines, "\n")

		// Datei schreiben
		f, err := os.Create(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		f.WriteString(head)
		if !strings.HasSuffix(head, "\n") {
			f.WriteString("\n")
		}
		if !strings.Contains(content, dedupeMarker) {
			f.WriteString(dedupeMarker + "\n")
		}
		f.WriteString("\n# Sorted and cleaned entries\n")
		f.WriteString(newBody)

		// Export der kommentierten Zeilen (optional)
		if req.ExportCommented && req.KeepCommented {
			// Exportiere die kommentierten Zeilen, die wir gesammelt haben, in commented_entries.txt
			// ...
		}

		log.Printf("Sorted and cleaned %s (sort=%v, keepCommented=%v)", req.File, req.SortAlphabetical, req.KeepCommented)
		w.WriteHeader(http.StatusOK)
	})

	// API: Backup-Einstellung setzen (nur im Dev-Modus)
	mux.HandleFunc("/api/backup/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if !devMode {
			http.Error(w, "dev mode required", http.StatusForbidden)
			return
		}
		var req struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		backupEnabled = req.Enabled
		if err := writeLogHeader(); err != nil {
			log.Printf("Failed to write log header: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/backup/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"enabled": backupEnabled})
	})

	mux.HandleFunc("/api/logmaxsize/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"maxSizeMB": logMaxSizeMB})
	})

	mux.HandleFunc("/api/logmaxsize/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if !devMode {
			http.Error(w, "dev mode required", http.StatusForbidden)
			return
		}
		var req struct{ MaxSizeMB int }
		json.NewDecoder(r.Body).Decode(&req)
		if req.MaxSizeMB < 1 || req.MaxSizeMB > 100 {
			http.Error(w, "invalid size", http.StatusBadRequest)
			return
		}
		logMaxSizeMB = req.MaxSizeMB
		if err := writeLogHeader(); err != nil {
			log.Printf("Failed to write log header: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/api/devmode", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"devMode": devMode})
	})

	// API: DNS-Server Erreichbarkeit prüfen
	mux.HandleFunc("/api/check-dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		var req struct{ IP string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ip := req.IP
		if ip == "" {
			http.Error(w, "missing IP", http.StatusBadRequest)
			return
		}
		// Einfache UDP-Verbindung zu Port 53 testen
		addr := ip + ":53"
		conn, err := net.DialTimeout("udp", addr, 3*time.Second)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]bool{"reachable": false})
			return
		}
		defer conn.Close()
		// Optional: Test-DNS-Query senden, um echten DNS-Server zu verifizieren
		m := new(dns.Msg)
		m.SetQuestion("google.com.", dns.TypeA)
		m.RecursionDesired = true
		c := &dns.Client{Timeout: 3 * time.Second}
		_, _, err = c.Exchange(m, addr)
		reachable := err == nil
		json.NewEncoder(w).Encode(map[string]bool{"reachable": reachable})
	})

	// GET /api/autostart
	mux.HandleFunc("/api/autostart", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"enabled": autostartEnabled})
	})

	// POST /api/autostart/set (nur Dev‑Modus, mit CSRF)
	mux.HandleFunc("/api/autostart/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if !devMode {
			http.Error(w, "dev mode required", http.StatusForbidden)
			return
		}
		var req struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		autostartEnabled = req.Enabled
		if err := setAutostart(autostartEnabled); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// GET /api/verbose
	mux.HandleFunc("/api/verbose", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]bool{"enabled": verboseEnabled})
	})

	// POST /api/verbose/set (nur Dev‑Modus, mit CSRF)
	mux.HandleFunc("/api/verbose/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		if !devMode {
			http.Error(w, "dev mode required", http.StatusForbidden)
			return
		}
		var req struct{ Enabled bool }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verboseEnabled = req.Enabled
		proxy.SetVerbose(verboseEnabled)
		if err := writeLogHeader(); err != nil {
			log.Printf("Failed to write log header: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	// GET /api/stats/hourly
	mux.HandleFunc("/api/stats/hourly", func(w http.ResponseWriter, r *http.Request) {
		if statsDB == nil {
			http.Error(w, "stats not available", http.StatusServiceUnavailable)
			return
		}
		rows, err := statsDB.Query(`SELECT hour, blocked FROM hourly_stats
									WHERE hour >= datetime('now', '-1 day')
									ORDER BY hour`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var result []map[string]interface{}
		for rows.Next() {
			var hour string
			var blocked int
			rows.Scan(&hour, &blocked)
			result = append(result, map[string]interface{}{"hour": hour, "blocked": blocked})
		}
		json.NewEncoder(w).Encode(result)
	})

	// GET /api/stats/daily
	mux.HandleFunc("/api/stats/daily", func(w http.ResponseWriter, r *http.Request) {
		if statsDB == nil {
			http.Error(w, "stats not available", http.StatusServiceUnavailable)
			return
		}
		rows, err := statsDB.Query(`SELECT day, blocked FROM daily_stats
									WHERE day >= date('now', '-30 days')
									ORDER BY day`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var result []map[string]interface{}
		for rows.Next() {
			var day string
			var blocked int
			rows.Scan(&day, &blocked)
			result = append(result, map[string]interface{}{"day": day, "blocked": blocked})
		}
		json.NewEncoder(w).Encode(result)
	})

	// GET /api/stats/top-domains
	mux.HandleFunc("/api/stats/top-domains", func(w http.ResponseWriter, r *http.Request) {
		if statsDB == nil {
			http.Error(w, "stats not available", http.StatusServiceUnavailable)
			return
		}
		rows, err := statsDB.Query(`SELECT domain, count FROM domain_stats
									ORDER BY count DESC LIMIT 20`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var result []map[string]interface{}
		for rows.Next() {
			var domain string
			var count int
			rows.Scan(&domain, &count)
			result = append(result, map[string]interface{}{"domain": domain, "count": count})
		}
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/api/stats/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		// Nur im Dev-Modus erlauben (optional, kann auch für alle freigegeben werden)
		if !devMode {
			http.Error(w, "dev mode required", http.StatusForbidden)
			return
		}
		if statsDB == nil {
			http.Error(w, "stats not available", http.StatusServiceUnavailable)
			return
		}
		_, err := statsDB.Exec(`DELETE FROM hourly_stats`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = statsDB.Exec(`DELETE FROM daily_stats`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = statsDB.Exec(`DELETE FROM domain_stats`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// GET /api/stats/enabled
	mux.HandleFunc("/api/stats/enabled", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"enabled": statsEnabled})
	})

	// POST /api/stats/enable (Dev‑Modus, CSRF)
	mux.HandleFunc("/api/stats/enable", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkCSRF(r) || !devMode {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var req struct{ Enabled bool }
		json.NewDecoder(r.Body).Decode(&req)
		setStatsEnabled(req.Enabled)
		w.WriteHeader(http.StatusOK)
	})

	// GET / POST: /api/stats/flushinterval
	mux.HandleFunc("/api/stats/flushinterval", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]int{"seconds": statsFlushInterval})
			return
		}
		if r.Method == http.MethodPost {
			if !checkCSRF(r) || !devMode {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var req struct{ Seconds int }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Seconds < 10 || req.Seconds > 86400 {
				http.Error(w, "invalid interval (10-86400)", http.StatusBadRequest)
				return
			}
			statsFlushInterval = req.Seconds
			if err := writeLogHeader(); err != nil {
				log.Printf("Failed to write log header: %v", err)
			}
			// Flusher mit neuem Intervall neu starten
			if statsEnabled {
				log.Printf("[FLUSHER] Restarting with new interval %ds", req.Seconds)
				setStatsEnabled(false)
				setStatsEnabled(true)
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	// GET / POST: /api/stats/cleanupticks
	mux.HandleFunc("/api/stats/cleanupticks", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]int{"ticks": statsCleanupTicks})
			return
		}
		if r.Method == http.MethodPost {
			if !checkCSRF(r) || !devMode {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			var req struct{ Ticks int }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Ticks < 0 {
				http.Error(w, "invalid ticks", http.StatusBadRequest)
				return
			}
			statsCleanupTicks = req.Ticks
			if err := writeLogHeader(); err != nil {
				log.Printf("Failed to write log header: %v", err)
			}
			// ---- Flusher neu starten, falls aktiv ----
			if statsEnabled {
				log.Printf("[FLUSHER] Restarting with new cleanup ticks %d", req.Ticks)
				setStatsEnabled(false)
				setStatsEnabled(true)
			}
			// Kein Flusher-Neustart nötig – die Schleife liest die Variable bei jedem Tick neu
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})

	httpServer = &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: mux,
	}

	// Server in Goroutine starten
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("HTTP server panic: %v", r)
			}
		}()
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()
	openBrowser("http://127.0.0.1:8080")

	if editorMenuItem != nil {
		editorMenuItem.SetTitle("Stop WebView")
	}
}

func stopConfigEditor() {
	if httpServer == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}
	httpServer = nil
	if editorMenuItem != nil {
		editorMenuItem.SetTitle("WebView")
	}
	log.Println("WebView stopped")
}

// openBrowser öffnet die URL im Standardbrowser.
func openBrowser(url string) {
	var args []string
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		args = []string{"url.dll,FileProtocolHandler", url}
		cmd = exec.Command("rundll32", args...)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	if cmd == nil {
		log.Printf("openBrowser: Kein Befehl für Betriebssystem %s", runtime.GOOS)
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		log.Printf("openBrowser: Fehler beim Starten des Browsers: %v", err)
	}
}

const editorHTML = `<!DOCTYPE html>
<html>
<head>
	<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
	<meta name="csrf-token" content="%CSRF_TOKEN%">
    <meta charset="UTF-8">
    <title>Adblock-DNS WebView</title>
    <style>
        /* Darkmode (Standard) */
        :root {
            --bg-color: #1e1e1e;
            --text-color: #d4d4d4;
            --header-bg: #0078d4;
            --header-text: white;
            --container-bg: #252526;
            --border-color: #3e3e42;
            --button-bg: #0e639c;
            --button-hover: #1177bb;
            --status-bar-bg: #2d2d30;
            --textarea-bg: #1e1e1e;
            --textarea-text: #d4d4d4;
            --tab-bg: #3c3c3c;
            --tab-active-bg: #1e1e1e;
            --tab-text: #cccccc;
        }
        
        /* Lightmode */
        .light-mode {
            --bg-color: #f5f5f5;
            --text-color: #333;
            --header-bg: #0078d4;
            --header-text: white;
            --container-bg: #ffffff;
            --border-color: #ccc;
            --button-bg: #0078d4;
            --button-hover: #005a9e;
            --status-bar-bg: #ffffff;
            --textarea-bg: #ffffff;
            --textarea-text: #333;
            --tab-bg: #e0e0e0;
            --tab-active-bg: #ffffff;
            --tab-text: #333;
        }

        body {
            font-family: sans-serif;
            margin: 20px;
            background: var(--bg-color);
            color: var(--text-color);
            transition: background 0.2s, color 0.2s;
        }
        h1 { color: var(--header-text); margin: 0; }
        .header-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--header-bg);
            padding: 10px 20px;
            border-radius: 4px 4px 0 0;
        }
		.editor-header {
			display: flex;
			align-items: center;
			gap: 10px;
			padding: 10px 20px;
			border-bottom: 1px solid var(--border-color);
			flex-wrap: wrap;  /* ← ermöglicht Umbruch bei Platzmangel */
		}
        .container {
            max-width: 1000px;
            margin: 0 auto;
            background: var(--container-bg);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }
        .status-bar {
            background: var(--status-bar-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 8px 20px;
            display: flex;
            gap: 20px;
            font-size: 13px;
            align-items: center;
            flex-wrap: wrap;
        }
        .status-item { display: flex; align-items: center; gap: 5px; }
        .control-group {
            display: flex;
            gap: 8px;
            margin-left: 20px;
        }
        .control-group button {
            background: var(--button-bg);
            color: white;
            border: none;
            padding: 4px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 4px;
        }
        .control-group button:hover {
            background: var(--button-hover);
        }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; background: #ccc; }
        .status-dot.running { background: #4caf50; }
        .status-dot.stopped { background: #f44336; }
        .theme-toggle {
            margin-left: auto;
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-color);
            padding: 4px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .theme-toggle:hover {
            background: var(--button-bg);
            color: white;
        }
        .file-selector {
            padding: 20px;
        }
        .tab-bar { display: flex; border-bottom: 1px solid var(--border-color); padding: 0 20px; }
		.tab {
            padding: 8px 16px; cursor: pointer; background: var(--tab-bg);
            border: 1px solid var(--border-color); border-bottom: none;
            margin-right: 4px; border-radius: 4px 4px 0 0; color: var(--tab-text);
        }
        .tab.active { background: var(--tab-active-bg); border-bottom: 1px solid var(--tab-active-bg); margin-bottom: -1px; }
        .file-buttons { display: flex; gap: 15px; margin-top: 15px; }
        .file-btn {
            flex: 1; padding: 15px; font-size: 16px; cursor: pointer;
            background: var(--button-bg); color: white; border: none; border-radius: 4px;
            text-align: center;
        }
        .file-btn:hover { background: var(--button-hover); }
        .editor-header {
            display: flex; align-items: center; gap: 10px;
            padding: 10px 20px;
            border-bottom: 1px solid var(--border-color);
        }
        .back-btn {
            padding: 6px 12px; font-size: 14px; cursor: pointer;
            background: #666; color: white; border: none; border-radius: 4px;
        }
        .back-btn:hover { background: #444; }
        textarea {
            width: 100%; height: 400px; font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px; padding: 12px; border: none;
            background: var(--textarea-bg); color: var(--textarea-text);
            box-sizing: border-box; resize: vertical;
        }
        .button-bar {
            padding: 10px 20px; display: flex; gap: 10px;
            border-top: 1px solid var(--border-color);
        }
        button {
            padding: 8px 16px; font-size: 14px; cursor: pointer;
            background: var(--button-bg); color: white; border: none; border-radius: 4px;
        }
		button:disabled {
			opacity: 0.5;
			cursor: not-allowed;
			pointer-events: none;  /* Verhindert jegliche Hover-Effekte */
		}
        button:hover { background: var(--button-hover); }
        #statusMsg { margin-left: 10px; color: #4caf50; }
        .hidden { display: none; }
    </style>
</head>
<body>
	<input type="hidden" id="devModeFlag" value="false">
    <div class="container">
        <div class="header-row">
            <h1>Adblock-DNS WebView</h1>
        </div>
        <div class="status-bar">
            <div class="status-item">
                <span class="status-dot" id="proxyDot"></span>
                <span>DNS Proxy: <span id="proxyState">Checking...</span></span>
            </div>
            <div class="status-item">
                <span>📋 Lists updated: <span id="listUpdated">-</span></span>
            </div>
            <div class="status-item">
                <span>🧪 Dry-run: <span id="dryRunState">-</span></span>
            </div>
            <div class="status-item">
                <span>🚫 Blocked: <span id="blockedTotal">0</span></span>
            </div>
            <div class="status-item">
                <span>🧪 Dry-run blocked: <span id="dryRunTotal">0</span></span>
            </div>
            <div class="control-group">
                <button id="startProxyBtn" title="Startet den DNS-Proxy. Der DNS deines aktiven Netzwerkadapters wird auf 127.0.0.1 umgestellt.">▶ Start</button>
                <button id="stopProxyBtn" title="Stoppt den DNS-Proxy und stellt die ursprünglichen DNS-Einstellungen wieder her.">⏹ Stop</button>
                <button id="toggleDryRunBtn" title="Dry-run: Blockiert keine Anfragen, sondern protokolliert nur, was blockiert worden wäre.">🧪 Dry-run</button>
            </div>
            <button class="theme-toggle" id="themeToggle" title="Toggle dark/light mode">🌙 Dark</button>
        </div>

        <!-- Tabs -->
        <div class="tab-bar">
			<div class="tab" data-tab="stats" id="statsTab" style="display:none;">📊 Statistics</div>
    		<div class="tab active" data-tab="selector">📂 Files</div>
    		<div class="tab" data-tab="log">📋 Log</div>
    		<div class="tab" data-tab="upstreams">⚙️ Upstreams</div>
			<div class="tab" data-tab="compare">🔍 Compare</div>
			<div class="tab" data-tab="misc" id="miscTab" style="display:none;">🛠️ Misc</div>
		</div>

        <!-- Dateiauswahl (anfangs sichtbar) -->
        <div id="selectorPanel">
            <div class="file-selector">
                <h2>Select a file to edit</h2>
                <div class="file-buttons">
                    <button class="file-btn" data-file="blocklist.txt">📄 Blocklist</button>
                    <button class="file-btn" data-file="sources.txt">🌐 Sources</button>
                    <button class="file-btn" data-file="whitelist.txt">✅ Whitelist</button>
                </div>
            </div>
        </div>

        <!-- Log-Panel (mit Filter & Realtime) -->
		<div id="logPanel" class="hidden">
			<div class="editor-header" style="flex-wrap: wrap; gap: 10px;">
				<span style="font-weight: bold;">📋 Application Log</span>
				<div style="display: flex; align-items: center; gap: 8px; margin-left: 20px;">
					<input type="text" id="logFilterInput" placeholder="Filter..." style="padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text); width: 180px;">
					<label style="display: flex; align-items: center; gap: 4px; white-space: nowrap;">
						<input type="checkbox" id="realtimeLogCheck"> Realtime
					</label>
				</div>
				<div style="margin-left: auto; display: flex; gap: 10px;">
					<button id="refreshLogBtn">🔄 Refresh</button>
					<button id="clearLogBtn" style="background: #d32f2f;">🗑️ Clear</button>
				</div>
			</div>
			<textarea id="logViewer" readonly spellcheck="false" style="height: 400px;"></textarea>
		</div>

		<!-- Upstreams-Panel (anfangs versteckt) -->
		<div id="upstreamsPanel" class="hidden">
    		<div class="editor-header">
        		<span style="font-weight: bold;">⚙️ Upstream DNS Servers</span>
        		<div style="margin-left: auto; display: flex; gap: 10px;">
            		<button id="saveUpstreamsBtn">💾 Save</button>
            		<button id="resetUpstreamsBtn" style="background: #d32f2f;">↺ Reset to Default</button>
					<button id="troubleshootBtn" style="background: #4caf50;">🔍 Troubleshoot</button>
        		</div>
    		</div>
    		<div style="padding: 20px;">
       		 <div style="margin-bottom: 15px;">
            		<label style="display: block; margin-bottom: 5px;">Primary DNS:</label>
            		<input type="text" id="primaryDNS" placeholder="e.g. 9.9.9.9" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text);">
        		</div>
        		<div style="margin-bottom: 15px;">
            		<label style="display: block; margin-bottom: 5px;">Secondary DNS:</label>
            		<input type="text" id="secondaryDNS" placeholder="e.g. 149.112.112.112" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text);">
        		</div>
        		<div class="button-bar">
					<span id="upstreamsStatusMsg" style="color: #4caf50;"></span>
				</div>
				<div id="troubleshootResult" style="margin-top: 20px; padding: 12px; background: var(--textarea-bg); border-radius: 4px; font-size: 13px; display: none; border-left: 4px solid #4caf50;">
				</div>
    		</div>
		</div>

		<!-- Misc-Panel (angepasste Reihenfolge) -->
		<div id="miscPanel" class="hidden">
			<div class="editor-header">
				<span style="font-weight: bold;">🛠️ Miscellaneous Settings</span>
			</div>
			<div style="padding: 20px;">

				<!-- 1. Autostart -->
				<div style="margin-bottom: 25px;">
					<label style="display: flex; align-items: center; gap: 8px;">
						<input type="checkbox" id="autostartCheckbox" disabled>
						<span>Start with Windows (autostart)</span>
					</label>
					<p style="font-size:12px; color:#888; margin-top:5px;">This setting is protected. Enable dev mode to change.</p>
				</div>

				<!-- 2. Flush DNS -->
				<div style="margin-bottom: 25px;">
					<label style="display: flex; align-items: center; gap: 8px;">
						<input type="checkbox" id="flushDNSCheckbox">
						<span>Flush DNS cache on start/stop</span>
					</label>
					<p style="font-size:12px; color:#888; margin-top:5px;">Automatically run 'ipconfig /flushdns' when proxy starts or stops.</p>
				</div>

				<!-- 3. Backups -->
				<div style="margin-bottom: 25px;">
					<label style="display: flex; align-items: center; gap: 8px;">
						<input type="checkbox" id="backupCheckbox" checked disabled>
						<span>Create backups before critical changes (deduplication, sort, compare)</span>
					</label>
					<p style="font-size:12px; color:#888; margin-top:5px;">This setting is protected. Enable dev mode to change.</p>
				</div>

				<!-- 4. Verbose -->
				<div style="margin-bottom: 25px;">
					<label style="display: flex; align-items: center; gap: 8px;">
						<input type="checkbox" id="verboseCheckbox" disabled>
						<span>Verbose logging (debug)</span>
					</label>
					<p style="font-size:12px; color:#888; margin-top:5px;">This setting is protected. Enable dev mode to change.</p>
				</div>

				<!-- 5. Statistics -->
				<div style="margin-bottom: 25px;">
					<label style="display: flex; align-items: center; gap: 8px;">
						<input type="checkbox" id="statsCheckbox" disabled>
						<span>Enable statistics collection (blocked domains, charts)</span>
					</label>
					<p style="font-size:12px; color:#888; margin-top:5px;">This setting is protected. Enable dev mode to change.</p>
				</div>

				<!-- 6. Max log file size -->
				<div>
					<label style="display: block; margin-bottom: 5px;">Max log file size (MB):</label>
					<input type="number" id="logMaxSizeInput" min="1" max="100" value="5" style="width: 100px; padding: 6px;" disabled>
					<button id="saveLogSizeBtn" style="margin-left: 10px;" disabled>Save</button>
					<span id="logSizeStatus" style="margin-left: 10px;"></span>
				</div>

			</div>
		</div>

		<!-- Statistics Panel -->
		<div id="statsPanel" class="hidden">
			<div class="editor-header">
				<span style="font-weight: bold;">📊 Statistics & Analytics</span>
				<div style="margin-left: auto;">
					<button id="refreshStatsBtn">🔄 Refresh</button>
					<button id="resetStatsBtn" style="background:#d32f2f; display:none;">🗑️ Reset Statistics</button>
				</div>
			</div>
			<div style="padding: 20px;">
				<h3>🚫 Blocked Requests (Last 24 Hours)</h3>
				<canvas id="hourlyChart" width="400" height="150"></canvas>
				<h3 style="margin-top: 30px;">📅 Blocked Requests (Last 30 Days)</h3>
				<canvas id="dailyChart" width="400" height="150"></canvas>
				<h3 style="margin-top: 30px;">🏆 Top Blocked Domains</h3>
				<table id="topDomainsTable" style="width:100%; border-collapse: collapse; color: var(--text-color);">
					<thead><tr><th>Domain</th><th>Hits</th></tr></thead>
					<tbody></tbody>
				</table>
				<!-- Flushing‑Einstellungen (aufklappbar) -->
				<details style="margin-top: 30px; border-top: 1px solid var(--border-color); padding-top: 15px;">
					<summary style="cursor: pointer; font-weight: bold; color: var(--text-color); font-size: 1.1em;">
						⚙️ Flushing Settings
					</summary>
					<div style="padding-top: 10px;">
						<label style="display: block; margin-bottom: 5px;">Flush interval (seconds):</label>
						<input type="number" id="statsFlushIntervalInput" min="10" max="86400" value="60" style="width: 120px; padding: 6px;" disabled>
						<button id="saveFlushIntervalBtn" style="margin-left: 10px;" disabled>Save</button>
						<span id="flushIntervalStatus" style="margin-left: 10px;"></span>
						<br>
						<label style="display: block; margin-top: 10px; margin-bottom: 5px;">Cleanup interval (ticks, 0=never):</label>
						<input type="number" id="statsCleanupTicksInput" min="0" value="1440" style="width: 120px; padding: 6px;" disabled>
						<button id="saveCleanupTicksBtn" style="margin-left: 10px;" disabled>Save</button>
						<span id="cleanupTicksStatus" style="margin-left: 10px;"></span>
					</div>
				</details>
			</div>
		</div>

		<!-- Compare-Panel (anfangs versteckt) -->
		<div id="comparePanel" class="hidden">
			<div class="editor-header">
				<span style="font-weight: bold;">🔍 Compare and Merge Blocklists</span>
			</div>
			<div style="padding: 20px;">
				<div style="margin-bottom: 15px;">
					<label style="display: block; margin-bottom: 5px;">Current list (to be updated):</label>
					<select id="currentFileSelect" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text);">
						<option value="blocklist.txt">blocklist.txt</option>
					</select>
				</div>
				<div style="margin-bottom: 15px;">
					<label style="display: block; margin-bottom: 5px;">New list file:</label>
					<input type="file" id="newListFile" accept=".txt,.hosts,text/plain" style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text);">
				</div>
				<button id="compareBtn" style="margin-bottom: 15px;">🔍 Compare</button>
				<div id="compareResult" style="display: none; margin-top: 15px; padding: 12px; background: var(--textarea-bg); border-radius: 4px; font-size: 13px;">
					<div id="compareSummary"></div>
					<div id="comparePreview" style="max-height: 200px; overflow-y: auto; margin: 10px 0;"></div>
					<button id="applyCompareBtn" style="background: #4caf50; display: none;">✅ Apply and Add New Domains</button>
					<span id="compareStatusMsg" style="margin-left: 10px; color: #4caf50;"></span>
				</div>
				<div style="margin-top: 25px; border-top: 1px solid var(--border-color); padding-top: 15px;">
					<h4>🧹 Deduplicate Current File</h4>
					<details style="margin-bottom: 15px; background: var(--textarea-bg); padding: 8px 12px; border-radius: 4px; border: 1px solid var(--border-color);">
						<summary style="cursor: pointer; font-weight: bold; color: var(--text-color);">ℹ️ How to preserve your table of contents</summary>
						<div style="margin-top: 10px; font-size: 12px; line-height: 1.5;">
							<p>This is required so that it doesn't corrupt the table of contents.<br>
							The line must be exactly as shown; otherwise, the request will not work.</p>
							<p>Place the following marker exactly as shown <strong>before</strong> your block entries:</p>
							<pre style="background: var(--bg-color); color: var(--text-color); padding: 8px; border-radius: 4px; overflow-x: auto; font-family: 'Consolas', monospace; font-size: 11px;"># -&gt;Start Adblock analyses hier&lt;-</pre>
							<p>Everything above this marker will be kept exactly as is. Duplicate detection and sorting only apply to lines below the marker.</p>
							<p style="margin-top: 8px;"><strong>Current marker status:</strong> <span id="markerStatusDisplay">Not checked yet</span></p>
						</div>
					</details>
					<div style="margin: 10px 0;">
						<label style="display: flex; align-items: center; gap: 8px;">
							<input type="checkbox" id="sortAlphabeticalCheck">
							<span>Sort alphabetically</span>
						</label>
						<label style="display: flex; align-items: center; gap: 8px; margin-top: 5px;">
							<input type="checkbox" id="keepCommentedCheck">
							<span>Keep commented entries</span>
						</label>
						<label style="display: flex; align-items: center; gap: 8px; margin-top: 5px;">
							<input type="checkbox" id="exportCommentedCheck">
							<span>Export commented entries as separate file</span>
						</label>
					</div>
					<button id="checkDuplicatesBtn" style="margin-right: 10px;">🔎 Check for Duplicates</button>
					<button id="applyDeduplicateBtn" style="background: #d32f2f; display: none;">⚠️ Apply Deduplication</button>
					<button id="sortCleanBtn" style="background: #2196F3; display: none;">🧹 Sort & Clean</button>
					<button id="showDuplicatesBtn" style="background: #ff9800; display: none;">📋 Show Duplicates</button>
					<span id="dedupeStatusMsg" style="margin-left: 10px;"></span>
					<div id="dedupeResult" style="margin-top: 10px;"></div>
				</div>
			</div>
		</div>

        <!-- Editor-Bereich (anfangs versteckt) -->
		<div id="editorSection" class="hidden">
			<div class="editor-header">
				<button class="back-btn" id="backBtn">← Back to file selection</button>
				<span id="currentFileLabel" style="font-weight: bold;"></span>
			</div>
			<!-- Suchleiste (permanent vorhanden, erst mit Datei aktiviert) -->
			<div id="searchBar" style="padding: 5px 20px; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; gap: 5px;">
				<input type="text" id="searchInput" placeholder="Search in file..." style="padding: 4px 8px; width: 200px; border-radius: 4px; border: 1px solid var(--border-color); background: var(--textarea-bg); color: var(--textarea-text);" disabled>
				<button id="searchPrevBtn" title="Previous (Shift+Enter)" style="padding: 4px 8px; font-size:12px;" disabled>▲</button>
				<button id="searchNextBtn" title="Next (Enter)" style="padding: 4px 8px; font-size:12px;" disabled>▼</button>
				<span id="searchStatus" style="font-size:12px; color: var(--text-color);"></span>
			</div>
			<textarea id="editor" spellcheck="false" placeholder="Loading..." wrap="off"></textarea>
			<div class="button-bar">
				<button id="saveBtn">Save Changes</button>
				<button id="reloadBtn">Reload from Disk</button>
				<span id="statusMsg"></span>
			</div>
		</div>

    <script>
        (function() {
			// Checkboxen referenzieren (NUR EINMAL)
			const sortCheck = document.getElementById('sortAlphabeticalCheck');
			const keepCommentsCheck = document.getElementById('keepCommentedCheck');

			// Gegenseitige Deaktivierung (Sort ⇄ Keep Comments)
			function updateMutualExclusion(changedCheckbox) {
				if (changedCheckbox === sortCheck && sortCheck.checked) {
					keepCommentsCheck.checked = false;
					keepCommentsCheck.disabled = true;
				} else if (changedCheckbox === keepCommentsCheck && keepCommentsCheck.checked) {
					sortCheck.checked = false;
					sortCheck.disabled = true;
				} else {
					// Wenn keine Checkbox aktiv ist, beide wieder aktivieren
					if (!sortCheck.checked && !keepCommentsCheck.checked) {
						sortCheck.disabled = false;
						keepCommentsCheck.disabled = false;
					}
				}
			}

			sortCheck.addEventListener('change', function() {
				updateMutualExclusion(sortCheck);
			});

			keepCommentsCheck.addEventListener('change', function() {
				updateMutualExclusion(keepCommentsCheck);
			});

			document.getElementById('resetStatsBtn').addEventListener('click', async () => {
				if (!confirm('Alle gesammelten Statistiken löschen? Dies kann nicht rückgängig gemacht werden.')) return;
				try {
					await apiFetch('/api/stats/reset', { method: 'POST' });
					loadStatistics(); // Diagramme neu laden (jetzt leer)
				} catch (err) {
					alert('Fehler beim Zurücksetzen: ' + err.message);
				}
			});

			// Initialen Zustand setzen
			updateMutualExclusion(null);

			function getCSRFToken() {
				const meta = document.querySelector('meta[name="csrf-token"]');
				return meta ? meta.content : '';
			}

			async function apiFetch(url, options = {}) {
				if (!options.method) options.method = 'GET';
				if (options.method !== 'GET' && options.method !== 'HEAD') {
					options.headers = options.headers || {};
					options.headers['X-CSRF-Token'] = getCSRFToken();
				}
				return fetch(url, options);
			}

			// Funktion zur gegenseitigen Deaktivierung
			function updateCheckboxState() {
				if (sortCheck.checked) {
					keepCommentsCheck.checked = false;   // Häkchen entfernen
					keepCommentsCheck.disabled = true;   // Ausgrauen
				} else {
					keepCommentsCheck.disabled = false;  // Wieder aktivieren
				}
			}

			// Event-Listener für Sortier-Checkbox
			sortCheck.addEventListener('change', updateCheckboxState);

			// Beim Laden der Seite einmal aufrufen
			updateCheckboxState();
			// Dry-Run
			const blockedTotalEl = document.getElementById('blockedTotal');
			const dryRunTotalEl = document.getElementById('dryRunTotal');

			async function refreshStats() {
    			try {
        			const resp = await apiFetch('/api/stats');
        			if (!resp.ok) throw new Error('Stats unavailable');
        			const data = await resp.json();
        			blockedTotalEl.textContent = data.blockedTotal;
        			dryRunTotalEl.textContent = data.dryRunTotal;
    			} catch (err) {
        			console.error('Stats error:', err);
    			}
			}
            // FlushDNS Checkbox
			const flushDNSCheckbox = document.getElementById('flushDNSCheckbox');

			async function loadFlushDNSSetting() {
				try {
					const resp = await apiFetch('/api/flushdns');
					if (!resp.ok) throw new Error(await resp.text());
					const data = await resp.json();
					flushDNSCheckbox.checked = data.enabled;
				} catch (err) {
					console.error('Failed to load flushdns setting:', err);
				}
			}

			const statsPanel = document.getElementById('statsPanel');
			let hourlyChart, dailyChart;

			async function loadStatistics() {
				try {
					// Stündliche Daten
					const hourlyResp = await apiFetch('/api/stats/hourly');
					const hourlyData = await hourlyResp.json();
					renderHourlyChart(hourlyData);

					// Tägliche Daten
					const dailyResp = await apiFetch('/api/stats/daily');
					const dailyData = await dailyResp.json();
					renderDailyChart(dailyData);

					// Top Domains
					const topResp = await apiFetch('/api/stats/top-domains');
					const topData = await topResp.json();
					renderTopDomainsTable(topData);
				} catch (err) {
					console.error('Failed to load statistics:', err);
				}
			}

			function renderHourlyChart(data) {
				const ctx = document.getElementById('hourlyChart').getContext('2d');
				if (hourlyChart) hourlyChart.destroy();
				hourlyChart = new Chart(ctx, {
					type: 'bar',
					data: {
						labels: data.map(d => d.hour.substring(11) + ':00'),
						datasets: [{
							label: 'Blocked',
							data: data.map(d => d.blocked),
							backgroundColor: '#4caf50'
						}]
					},
					options: {
						responsive: true,
						maintainAspectRatio: true,
					}
				});
			}

			function renderDailyChart(data) {
				const ctx = document.getElementById('dailyChart').getContext('2d');
				if (dailyChart) dailyChart.destroy();
				dailyChart = new Chart(ctx, {
					type: 'bar',
					data: {
						labels: data.map(d => d.day.substring(5)), // MM-DD
						datasets: [{
							label: 'Blocked',
							data: data.map(d => d.blocked),
							backgroundColor: '#2196F3'
						}]
					},
					options: {
						responsive: true,
						maintainAspectRatio: true,
					}
				});
			}

			function renderTopDomainsTable(data) {
				const tbody = document.querySelector('#topDomainsTable tbody');
				tbody.innerHTML = '';
				data.forEach(item => {
					const row = tbody.insertRow();
					row.insertCell().textContent = item.domain;
					row.insertCell().textContent = item.count;
				});
			}

			// Event Listener für Refresh-Button
			document.getElementById('refreshStatsBtn').addEventListener('click', loadStatistics);

			async function loadBackupSetting() {
				try {
					const resp = await apiFetch('/api/backup/get');
					const data = await resp.json();
					document.getElementById('backupCheckbox').checked = data.enabled;
				} catch (err) {
					console.error('Failed to load backup setting:', err);
				}
			}

			async function loadLogMaxSizeSetting() {
				try {
					const resp = await apiFetch('/api/logmaxsize/get');
					const data = await resp.json();
					document.getElementById('logMaxSizeInput').value = data.maxSizeMB;
				} catch (err) {
					console.error('Failed to load logmaxsize setting:', err);
				}
			}

			async function saveFlushDNSSetting(enabled) {
				try {
					await apiFetch('/api/flushdns', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ enabled: enabled })
					});
				} catch (err) {
					console.error('Failed to save flushdns setting:', err);
				}
			}

			flushDNSCheckbox.addEventListener('change', () => {
				saveFlushDNSSetting(flushDNSCheckbox.checked);
			});
			// Sofort laden
			loadFlushDNSSetting();
			loadBackupSetting();
			// Theme-Management
            const themeToggle = document.getElementById('themeToggle');
            const html = document.documentElement;
            
            function setTheme(isDark) {
                if (isDark) {
                    html.classList.remove('light-mode');
                    themeToggle.textContent = '🌙 Dark';
                } else {
                    html.classList.add('light-mode');
                    themeToggle.textContent = '☀️ Light';
                }
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
            }
            
            const savedTheme = localStorage.getItem('theme');
            const prefersDark = savedTheme === 'dark' || (savedTheme === null);
            setTheme(prefersDark);
            
            themeToggle.addEventListener('click', () => {
                const isDark = !html.classList.contains('light-mode');
                setTheme(!isDark);
            });

            // --- Proxy Control ---
            const startBtn = document.getElementById('startProxyBtn');
            const stopBtn = document.getElementById('stopProxyBtn');
            const dryRunBtn = document.getElementById('toggleDryRunBtn');

            async function startProxy() {
                try {
                    const resp = await apiFetch('/api/proxy/start', { method: 'POST' });
                    if (!resp.ok) throw new Error(await resp.text());
                    refreshStatus();
                } catch (err) {
                    alert('Failed to start proxy: ' + err.message);
                }
            }

            async function stopProxy() {
                try {
                    const resp = await apiFetch('/api/proxy/stop', { method: 'POST' });
                    if (!resp.ok) throw new Error(await resp.text());
					 // Dry‑Run lokal zurücksetzen
					dryRunState.textContent = 'OFF';
					if (dryRunBtn) {
						dryRunBtn.textContent = '🧪 Dry-run (OFF)';
						dryRunBtn.disabled = true;
					}
                    refreshStatus();
                } catch (err) {
                    alert('Failed to stop proxy: ' + err.message);
                }
            }

            async function toggleDryRun() {
                try {
                    const current = dryRunState.textContent === 'ON';
                    const newState = !current;
                    const resp = await apiFetch('/api/proxy/dryrun', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled: newState })
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    refreshStatus();
                } catch (err) {
                    alert('Failed to toggle dry-run: ' + err.message);
                }
            }

            startBtn.addEventListener('click', startProxy);
            stopBtn.addEventListener('click', stopProxy);
            dryRunBtn.addEventListener('click', toggleDryRun);

            // Panels
            const selectorPanel = document.getElementById('selectorPanel');
            const logPanel = document.getElementById('logPanel');
            const editorSection = document.getElementById('editorSection');
			const miscPanel = document.getElementById('miscPanel');


			// ========== Log Panel (mit Filter & Realtime) ==========
			const logViewer = document.getElementById('logViewer');
			const refreshLogBtn = document.getElementById('refreshLogBtn');
			const clearLogBtn = document.getElementById('clearLogBtn');
			const logFilterInput = document.getElementById('logFilterInput');
			const realtimeLogCheck = document.getElementById('realtimeLogCheck');

			let logRefreshTimer = null;
			let rawLogContent = '';           // ungefilterter Originalinhalt
			let currentFilter = '';

			// Filter anwenden und Textarea aktualisieren
			function applyLogFilter() {
				const filter = logFilterInput.value.trim().toLowerCase();
				currentFilter = filter;
				if (!rawLogContent) {
					logViewer.value = '';
					return;
				}
				if (filter === '') {
					logViewer.value = rawLogContent;
				} else {
					const lines = rawLogContent.split('\n');
					const filtered = lines.filter(line => line.toLowerCase().includes(filter));
					logViewer.value = filtered.join('\n');
				}
				// Automatisches Scrollen, wenn Checkbox aktiv ist
				if (realtimeLogCheck.checked) {
					logViewer.scrollTop = logViewer.scrollHeight;
				}
			}

			// Log vom Server laden
			async function loadLog() {
				try {
					const resp = await apiFetch('/api/log?t=' + Date.now());
					if (!resp.ok) throw new Error(await resp.text());
					const text = await resp.text();
					rawLogContent = text;
					applyLogFilter();
				} catch (err) {
					logViewer.value = 'Error loading log: ' + err.message;
					rawLogContent = '';
				}
			}

			// Realtime-Timer starten/stoppen
			function toggleRealtimeLog() {
				if (realtimeLogCheck.checked) {
					// Timer starten (alle 2 Sekunden)
					if (logRefreshTimer) clearInterval(logRefreshTimer);
					logRefreshTimer = setInterval(() => {
						loadLog();
					}, 2000);
					// Sofort einmal laden und ans Ende scrollen
					loadLog().then(() => {
						logViewer.scrollTop = logViewer.scrollHeight;
					});
				} else {
					// Timer stoppen
					if (logRefreshTimer) {
						clearInterval(logRefreshTimer);
						logRefreshTimer = null;
					}
				}
			}
			// Event Listener korrekt binden
			refreshLogBtn.addEventListener('click', () => {
				loadLog().then(() => {
					logViewer.scrollTop = logViewer.scrollHeight;
				});
			});

			clearLogBtn.addEventListener('click', async () => {
				if (!confirm('Delete all log entries? This cannot be undone.')) return;
				try {
					const resp = await apiFetch('/api/log/clear', { method: 'POST' });
					if (!resp.ok) throw new Error(await resp.text());
					rawLogContent = '';
					logViewer.value = '';
					// Falls Realtime aktiv ist, übernimmt der nächste Timer das leere Log
				} catch (err) {
					alert('Failed to clear log: ' + err.message);
				}
			});

			logFilterInput.addEventListener('input', applyLogFilter);
			realtimeLogCheck.addEventListener('change', toggleRealtimeLog);

			// Beim Wechsel auf den Log-Tab laden (vorhandene Tab-Logik nutzen)
			// Die Tab‑Logik ruft bereits loadLog() auf, also kein zusätzlicher Code nötig.
			// Beim Schließen des Fensters Timer aufräumen
			window.addEventListener('beforeunload', () => {
				if (logRefreshTimer) clearInterval(logRefreshTimer);
			});


			// Compare Panel
			const comparePanel = document.getElementById('comparePanel');
			const currentFileSelect = document.getElementById('currentFileSelect');
			const newListFile = document.getElementById('newListFile');
			const compareBtn = document.getElementById('compareBtn');
			const compareResult = document.getElementById('compareResult');
			const compareSummary = document.getElementById('compareSummary');
			const comparePreview = document.getElementById('comparePreview');
			const applyCompareBtn = document.getElementById('applyCompareBtn');
			const compareStatusMsg = document.getElementById('compareStatusMsg');
			const sortAlphabeticalCheck = document.getElementById('sortAlphabeticalCheck');
			const keepCommentedCheck = document.getElementById('keepCommentedCheck');

			let pendingNewDomains = [];

			async function runCompare() {
				const file = newListFile.files[0];
				if (!file) {
					alert('Please select a new list file.');
					return;
				}
				const currentFile = currentFileSelect.value;
				const content = await file.text();
				
				compareStatusMsg.textContent = '';
				compareResult.style.display = 'block';
				compareSummary.innerHTML = 'Comparing...';
				comparePreview.innerHTML = '';
				applyCompareBtn.style.display = 'none';
				
				try {
					const resp = await apiFetch('/api/compare', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ currentFile: currentFile, newContent: content })
					});
					const data = await resp.json();
					if (!resp.ok) throw new Error(data.error || 'Comparison failed');
					
					pendingNewDomains = data.allNewDomains || [];
					compareSummary.innerHTML = '<strong>' + data.addedCount + '</strong> new domain(s) found.';
					if (data.newDomains && data.newDomains.length > 0) {
						let previewHtml = '<strong>Preview (first 60):</strong><ul>';
						data.newDomains.forEach(d => { previewHtml += '<li>' + d + '</li>'; });
						previewHtml += '</ul>';
						comparePreview.innerHTML = previewHtml;
						applyCompareBtn.style.display = 'inline-block';
					} else {
						comparePreview.innerHTML = 'No new domains to add.';
					}
				} catch (err) {
					compareSummary.innerHTML = '<span style="color:#f44336;">Error: ' + err.message + '</span>';
				}
			}

			async function applyCompare() {
				const currentFile = currentFileSelect.value;
				if (pendingNewDomains.length === 0) return;
				try {
					compareStatusMsg.textContent = 'Adding domains...';
					compareStatusMsg.style.color = 'blue';
					const resp = await apiFetch('/api/compare/apply', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ currentFile: currentFile, newDomains: pendingNewDomains })
					});
					if (!resp.ok) throw new Error(await resp.text());
					compareStatusMsg.textContent = 'Added ' + pendingNewDomains.length + ' domains successfully.';
					compareStatusMsg.style.color = 'green';
					applyCompareBtn.style.display = 'none';
					pendingNewDomains = [];
					// Optional: Proxy neustarten, falls blocklist.txt geändert wurde
					if (currentFile === 'blocklist.txt') {
						const statusResp = await apiFetch('/api/status');
						const statusData = await statusResp.json();
						if (statusData.running) {
							await apiFetch('/api/proxy/restart', { method: 'POST' });
						}
					}
				} catch (err) {
					compareStatusMsg.textContent = 'Error: ' + err.message;
					compareStatusMsg.style.color = 'red';
				}
			}

			compareBtn.addEventListener('click', runCompare);
			applyCompareBtn.addEventListener('click', applyCompare);

			// Deduplication Button
			const checkDuplicatesBtn = document.getElementById('checkDuplicatesBtn');
			const applyDeduplicateBtn = document.getElementById('applyDeduplicateBtn');
			const dedupeResult = document.getElementById('dedupeResult');
			const dedupeStatusMsg = document.getElementById('dedupeStatusMsg');
			const showDuplicatesBtn = document.getElementById('showDuplicatesBtn');
			const exportCommentedCheck = document.getElementById('exportCommentedCheck');
			const sortCleanBtn = document.getElementById('sortCleanBtn');

			let duplicateList = [];
			let pendingDedupeFile = '';

			async function applySortClean() {
				if (!pendingDedupeFile) return;
				try {
					dedupeStatusMsg.textContent = 'Sorting and cleaning...';
					dedupeStatusMsg.style.color = 'blue';
					const resp = await apiFetch('/api/sortclean/apply', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({
							file: pendingDedupeFile,
							sortAlphabetical: sortAlphabeticalCheck.checked,
							keepCommented: keepCommentedCheck.checked,
							exportCommented: exportCommentedCheck.checked
						})
					});
					if (!resp.ok) throw new Error(await resp.text());
					dedupeStatusMsg.textContent = 'Sort & clean successful!';
					dedupeStatusMsg.style.color = 'green';
					sortCleanBtn.style.display = 'none';
					applyDeduplicateBtn.style.display = 'none';
					showDuplicatesBtn.style.display = 'none';
					dedupeResult.innerHTML = '';
					if (pendingDedupeFile === 'blocklist.txt') {
						const statusResp = await apiFetch('/api/status');
						const statusData = await statusResp.json();
						if (statusData.running) {
							await apiFetch('/api/proxy/restart', { method: 'POST' });
						}
					}
				} catch (err) {
					dedupeStatusMsg.textContent = 'Error: ' + err.message;
					dedupeStatusMsg.style.color = 'red';
				}
			}

			sortCleanBtn.addEventListener('click', applySortClean);

			async function checkDuplicates() {
				const file = currentFileSelect.value;
				pendingDedupeFile = file;
				dedupeStatusMsg.textContent = '';
				dedupeResult.innerHTML = 'Checking...';
				try {
					const resp = await apiFetch('/api/deduplicate', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ file: file })
					});
					const data = await resp.json();
					if (!resp.ok) throw new Error(data.error || 'Check failed');
					const markerSpan = document.getElementById('markerStatusDisplay');
					if (markerSpan) {
						markerSpan.textContent = data.markerFound ? '✅ Found' : '❌ Not found';
						markerSpan.style.color = data.markerFound ? '#4caf50' : '#f44336';
					}
					
					dedupeResult.innerHTML = '<strong>' + data.uniqueCount + '</strong> unique entries, <strong>' + data.duplicateCount + '</strong> duplicate entries found.';
					if (data.markerFound) {
						dedupeResult.innerHTML += '<br><span style="color:#4caf50;">✅ Marker found – analyzing from marker.</span>';
					} else {
						dedupeResult.innerHTML += '<br><span style="color:#ff9800;">⚠️ Marker not found – analyzing entire file.</span>';
					}
					if (data.duplicateCount > 0) {
						applyDeduplicateBtn.style.display = 'inline-block';
						showDuplicatesBtn.style.display = 'inline-block';
						sortCleanBtn.style.display = 'inline-block';
					} else {
						applyDeduplicateBtn.style.display = 'none';
						showDuplicatesBtn.style.display = 'none';
						sortCleanBtn.style.display = 'inline-block';
					}
				} catch (err) {
					dedupeResult.innerHTML = '<span style="color:#f44336;">Error: ' + err.message + '</span>';
				}
			}

			async function applyDeduplicate() {
				if (!pendingDedupeFile) return;
				try {
					dedupeStatusMsg.textContent = 'Deduplicating...';
					dedupeStatusMsg.style.color = 'blue';
					const resp = await apiFetch('/api/deduplicate/apply', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({
							file: pendingDedupeFile,
							sortAlphabetical: sortAlphabeticalCheck.checked,
							keepCommented: keepCommentedCheck.checked,
							exportCommented: exportCommentedCheck.checked
						})
					});
					if (!resp.ok) throw new Error(await resp.text());
					dedupeStatusMsg.textContent = 'Deduplication successful!';
					dedupeStatusMsg.style.color = 'green';
					applyDeduplicateBtn.style.display = 'none';
					showDuplicatesBtn.style.display = 'none';
					dedupeResult.innerHTML = '';
					if (pendingDedupeFile === 'blocklist.txt') {
						const statusResp = await apiFetch('/api/status');
						const statusData = await statusResp.json();
						if (statusData.running) {
							await apiFetch('/api/proxy/restart', { method: 'POST' });
						}
					}
				} catch (err) {
					dedupeStatusMsg.textContent = 'Error: ' + err.message;
					dedupeStatusMsg.style.color = 'red';
				}
			}

			checkDuplicatesBtn.addEventListener('click', checkDuplicates);
			applyDeduplicateBtn.addEventListener('click', applyDeduplicate);

			// Show Duplicates in Modal
			async function showDuplicates() {
				const file = currentFileSelect.value;
				try {
					dedupeStatusMsg.textContent = 'Loading duplicates...';
					dedupeStatusMsg.style.color = 'blue';
					const resp = await apiFetch('/api/deduplicate', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ file: file, details: true })
					});
					const data = await resp.json();
					if (!resp.ok) throw new Error(data.error || 'Request failed');
					
					if (data.duplicates && data.duplicates.length > 0) {
						duplicateList = data.duplicates;
						let html = '<strong>Duplicate domains (' + duplicateList.length + '):</strong><ul style="max-height:200px; overflow-y:auto;">';
						duplicateList.forEach(d => { html += '<li>' + d + '</li>'; });
						html += '</ul>';
						dedupeResult.innerHTML = html;
					} else {
						dedupeResult.innerHTML = 'No duplicate domains found.';
					}
					dedupeStatusMsg.textContent = '';
				} catch (err) {
					dedupeStatusMsg.textContent = 'Error: ' + err.message;
					dedupeStatusMsg.style.color = 'red';
				}
			}

			showDuplicatesBtn.addEventListener('click', showDuplicates);


            // Upstreams Panel
			const upstreamsPanel = document.getElementById('upstreamsPanel');
			const primaryDNS = document.getElementById('primaryDNS');
			const secondaryDNS = document.getElementById('secondaryDNS');
			const saveUpstreamsBtn = document.getElementById('saveUpstreamsBtn');
			const resetUpstreamsBtn = document.getElementById('resetUpstreamsBtn');
			const upstreamsStatusMsg = document.getElementById('upstreamsStatusMsg');
			const troubleshootBtn = document.getElementById('troubleshootBtn');
			const troubleshootResult = document.getElementById('troubleshootResult');

			async function loadUpstreams() {
				loadFlushDNSSetting();
				try {
					const resp = await apiFetch('/api/upstreams');
					if (!resp.ok) throw new Error(await resp.text());
					const servers = await resp.json();
					primaryDNS.value = servers[0] || '';
					secondaryDNS.value = servers[1] || '';
				} catch (err) {
					primaryDNS.value = '';
					secondaryDNS.value = '';
					upstreamsStatusMsg.textContent = 'Error loading upstreams: ' + err.message;
				}
			}

			function isValidIP(ip) {
				if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
				return ip.split('.').every(o => parseInt(o) <= 255);
			}

			async function checkDNSReachable(ip) {
				const resp = await apiFetch('/api/check-dns', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ ip: ip })
				});
				const data = await resp.json();
				return data.reachable;
			}

			async function saveUpstreams() {
				const primary = primaryDNS.value.trim();
				const secondary = secondaryDNS.value.trim();
				if (primary && !isValidIP(primary)) {
					alert('Primary DNS must be a valid IPv4 address (e.g. 9.9.9.9)');
					return;
				}
				if (secondary && !isValidIP(secondary)) {
					alert('Secondary DNS must be a valid IPv4 address (e.g. 149.112.112.112)');
					return;
				}
				const servers = [];
				if (primary) {
					upstreamsStatusMsg.textContent = 'Checking primary DNS...';
					upstreamsStatusMsg.style.color = '#ff9800';
					if (!await checkDNSReachable(primary)) {
						alert('Primary DNS server is not reachable or does not respond to DNS queries.');
						upstreamsStatusMsg.textContent = '';
						return;
					}
					servers.push(primary + ':53');
				}
				if (secondary) {
					upstreamsStatusMsg.textContent = 'Checking secondary DNS...';
					if (!await checkDNSReachable(secondary)) {
						alert('Secondary DNS server is not reachable or does not respond to DNS queries.');
						upstreamsStatusMsg.textContent = '';
						return;
					}
					servers.push(secondary + ':53');
				}
				if (servers.length === 0) {
					alert('At least one DNS server is required.');
					return;
				}
				try {
					const resp = await apiFetch('/api/upstreams', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify(servers)
					});
					if (!resp.ok) throw new Error(await resp.text());
					upstreamsStatusMsg.textContent = 'Saved. Restarting proxy...';
					upstreamsStatusMsg.style.color = '#ff9800';
					await restartProxy();
					upstreamsStatusMsg.textContent = 'Saved and proxy restarted.';
					upstreamsStatusMsg.style.color = '#4caf50';
					setTimeout(() => upstreamsStatusMsg.textContent = '', 3000);
				} catch (err) {
					alert('Failed to save upstreams: ' + err.message);
					upstreamsStatusMsg.textContent = '';
				}
			}

			async function restartProxy() {
				try {
					upstreamsStatusMsg.textContent = 'Restarting proxy...';
					upstreamsStatusMsg.style.color = 'blue';
					const resp = await apiFetch('/api/proxy/restart', { method: 'POST' });
					if (!resp.ok) throw new Error(await resp.text());
					upstreamsStatusMsg.textContent = 'Proxy restarted successfully!';
					upstreamsStatusMsg.style.color = 'green';
					setTimeout(() => upstreamsStatusMsg.textContent = '', 2000);
					refreshStatus();
					return true;
				} catch (err) {
					upstreamsStatusMsg.textContent = 'Restart failed: ' + err.message;
					upstreamsStatusMsg.style.color = 'red';
					console.error('Restart failed:', err);
        			throw err; // Weitergeben an den Aufrufer
				}
			}

			async function resetUpstreams() {
				if (!confirm('Reset upstream servers to default (Quad9)?')) return;
				try {
					const resp = await apiFetch('/api/upstreams/reset', { method: 'POST' });
					if (!resp.ok) throw new Error(await resp.text());
					await loadUpstreams(); // Felder aktualisieren
					upstreamsStatusMsg.textContent = 'Reset to defaults. Restarting proxy...';
					upstreamsStatusMsg.style.color = '#ff9800';
					
					// Automatischer Proxy-Neustart
					await restartProxy();
					
					upstreamsStatusMsg.textContent = 'Reset and proxy restarted.';
					upstreamsStatusMsg.style.color = '#4caf50';
					setTimeout(() => upstreamsStatusMsg.textContent = '', 3000);
				} catch (err) {
					alert('Failed to reset: ' + err.message);
				}
			}

			saveUpstreamsBtn.addEventListener('click', saveUpstreams);
			resetUpstreamsBtn.addEventListener('click', resetUpstreams);

			async function runTroubleshoot() {
				troubleshootResult.style.display = 'block';
				troubleshootResult.innerHTML = '<span style="color: #4caf50;">⏳ Running diagnostics...</span>';
				try {
					const resp = await apiFetch('/api/troubleshoot');
					if (!resp.ok) throw new Error(await resp.text());
					const data = await resp.json();
					
					let html = '<h3 style="margin-top:0; color: var(--text-color);">🔍 Diagnostic Results</h3><ul style="padding-left:20px;">';
					html += '<li><strong>Proxy running:</strong> ' + (data.proxyRunning ? '✅ Yes' : '❌ No') + ' (' + data.listenerAddr + ')</li>';
					html += '<li><strong>Active interface:</strong> ' + (data.activeInterface || 'N/A') + '</li>';
					html += '<li><strong>System DNS servers:</strong> ' + (data.systemDNS && data.systemDNS.length ? data.systemDNS.join(', ') : 'None detected') + '</li>';
					html += '<li><strong>Upstream servers:</strong><ul style="margin-top:4px;">';
					data.upstreams.forEach((s, i) => {
						html += '<li>' + s + ' - ' + (data.upstreamReachable[i] ? '✅ Reachable' : '❌ Unreachable') + '</li>';
					});
					html += '</ul></li></ul>';
					
					const issues = [];
					if (!data.proxyRunning) issues.push('Proxy is not running. Click "Start" or "Restart Proxy".');
					else if (!data.systemDNS || !data.systemDNS.includes('127.0.0.1')) issues.push('System DNS is not set to 127.0.0.1. Restart the proxy or check admin rights.');
					if (data.upstreamReachable.some(v => !v)) issues.push('Some upstreams are unreachable. Verify the IP addresses.');
					
					if (issues.length > 0) {
						html += '<div style="margin-top:12px; padding:8px; background:#d32f2f20; border-radius:4px; color:#f44336;">';
						html += '<strong>⚠️ Issues found:</strong><ul style="margin:4px 0 0 20px;">';
						issues.forEach(issue => { html += '<li>' + issue + '</li>'; });
						html += '</ul></div>';
					} else {
						html += '<div style="margin-top:12px; padding:8px; background:#4caf5020; border-radius:4px; color:#4caf50;"><strong>✅ All systems operational.</strong></div>';
					}
					// Konflikte anzeigen
					if (data.conflictCount === 0) {
						html += '<div style="margin-top:12px; padding:8px; background:#4caf5020; border-radius:4px; color:#4caf50;"><strong>✅ No conflicts between blocklist and whitelist.</strong></div>';
					} else {
						html += '<div style="margin-top:12px; padding:8px; background:#d32f2f20; border-radius:4px; color:#f44336;">';
						html += '<strong>⚠️ Conflicts (' + data.conflictCount + ' domains both blocked and whitelisted):</strong>';
						html += '<ul style="max-height:150px; overflow-y:auto; margin-top:5px;">';
						data.conflicts.forEach(d => { html += '<li>' + d + '</li>'; });
						html += '</ul></div>';
					}
					
					troubleshootResult.innerHTML = html;
				} catch (err) {
					troubleshootResult.innerHTML = '<span style="color:#f44336;">❌ Diagnostics failed: ' + err.message + '</span>';
				}
			}

			troubleshootBtn.addEventListener('click', runTroubleshoot);

			// Autostart Checkbox
			const autostartCheckbox = document.getElementById('autostartCheckbox');

			async function loadAutostartSetting() {
				try {
					const resp = await apiFetch('/api/autostart');
					const data = await resp.json();
					autostartCheckbox.checked = data.enabled;
				} catch (err) {
					console.error('Failed to load autostart setting:', err);
				}
			}

			const verboseCheckbox = document.getElementById('verboseCheckbox');

			async function loadVerboseSetting() {
				try {
					const resp = await apiFetch('/api/verbose');
					const data = await resp.json();
					verboseCheckbox.checked = data.enabled;
				} catch (err) {
					console.error('Failed to load verbose setting:', err);
				}
			}


			// In setupDevModeListeners():
			verboseCheckbox.addEventListener('change', async () => {
				await apiFetch('/api/verbose/set', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ enabled: verboseCheckbox.checked })
				});
			});

			// Beim Start laden (nach loadAutostartSetting):
			loadVerboseSetting();


			async function loadStatsSetting() {
					const resp = await apiFetch('/api/stats/enabled');
					if (!resp.ok) {
						console.error('Stats not available');
						statsCheckbox.disabled = true;
						return;
					}
					const data = await resp.json();
					statsCheckbox.checked = data.enabled;
					statsTab.style.display = data.enabled ? 'block' : 'none';
				}

			// Dev-Mode
			async function checkDevMode() {
				const statsCheckbox = document.getElementById('statsCheckbox');
				const resp = await apiFetch('/api/devmode');
				const data = await resp.json();
				if (data.devMode) {
					document.getElementById('backupCheckbox').disabled = false;
					document.getElementById('logMaxSizeInput').disabled = false;
					document.getElementById('saveLogSizeBtn').disabled = false;
					// Tab einblenden
        			document.getElementById('miscTab').style.display = 'block';
					document.getElementById('resetStatsBtn').style.display = 'inline-block';
					autostartCheckbox.disabled = false;
					verboseCheckbox.disabled = false;
					statsCheckbox.disabled = false;
				}

				resetStatsBtn.addEventListener('click', async () => {
					if (!confirm('Delete all statistics? This cannot be undone.')) return;
					await apiFetch('/api/stats/reset', { method: 'POST' });
					loadStatistics();
				});
				// LogMaxSize laden (unabhängig vom Dev‑Mode)
				loadLogMaxSizeSetting();
				loadAutostartSetting();
			}

            // Tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => {
    			tab.addEventListener('click', () => {
        			const target = tab.dataset.tab;
        			tabs.forEach(t => t.classList.remove('active'));
        			tab.classList.add('active');

        			selectorPanel.classList.add('hidden');
        			logPanel.classList.add('hidden');
        			editorSection.classList.add('hidden');
        			upstreamsPanel.classList.add('hidden');

					if (target === 'compare') {
						comparePanel.classList.remove('hidden');
					} else {
						comparePanel.classList.add('hidden');
					}

        			if (target === 'selector') {
            			selectorPanel.classList.remove('hidden');
        			} else if (target === 'log') {
            			logPanel.classList.remove('hidden');
            			loadLog();
        			} else if (target === 'upstreams') {
            			upstreamsPanel.classList.remove('hidden');
            			loadUpstreams();
        			}
					if (target === 'misc') {
						miscPanel.classList.remove('hidden');
					} else {
						miscPanel.classList.add('hidden');
					}
					if (target === 'stats') {
					statsPanel.classList.remove('hidden');
					loadStatistics();
				} else {
					statsPanel.classList.add('hidden');
				}
    			});
			});


            // Editor
            const editor = document.getElementById('editor');
			// ========== Suchleiste im Editor ==========
			const searchBar = document.getElementById('searchBar');
			const searchInput = document.getElementById('searchInput');
			const searchPrevBtn = document.getElementById('searchPrevBtn');
			const searchNextBtn = document.getElementById('searchNextBtn');
			const searchStatus = document.getElementById('searchStatus');

			let searchTerm = '';
			let lastSearchIndex = -1;

			function activateSearch(enabled) {
				searchInput.disabled = !enabled;
				searchPrevBtn.disabled = !enabled;
				searchNextBtn.disabled = !enabled;
				if (enabled) {
					searchInput.value = '';
					searchStatus.textContent = '';
					searchTerm = '';
					lastSearchIndex = -1;
				}
			}


			function getEditorPadding() {
				const style = window.getComputedStyle(editor);
				return {
					top: parseFloat(style.paddingTop) || 0,
					right: parseFloat(style.paddingRight) || 0,
					bottom: parseFloat(style.paddingBottom) || 0,
					left: parseFloat(style.paddingLeft) || 0
				};
			}

			function getCharWidth() {
				const style = window.getComputedStyle(editor);
				const tmp = document.createElement('span');
				tmp.style.font = style.font;
				tmp.style.visibility = 'hidden';
				tmp.style.position = 'absolute';
				tmp.style.whiteSpace = 'pre';
				tmp.textContent = '0';  // Monospace, jede Ziffer gleiche Breite
				document.body.appendChild(tmp);
				const width = tmp.getBoundingClientRect().width;
				document.body.removeChild(tmp);
				return width || 8;
			}

			function getLineHeight() {
				const style = window.getComputedStyle(editor);
				const lh = style.lineHeight;
				if (lh === 'normal') {
					const tmp = document.createElement('span');
					tmp.style.font = style.font;
					tmp.style.lineHeight = 'normal';
					tmp.style.visibility = 'hidden';
					tmp.style.position = 'absolute';
					tmp.textContent = 'Ag';
					document.body.appendChild(tmp);
					const height = tmp.getBoundingClientRect().height;
					document.body.removeChild(tmp);
					return height || 20;
				}
				const num = parseFloat(lh);
				return Number.isNaN(num) ? 20 : num;
			}

			function doSearch(forward = true) {
				const term = searchInput.value.trim();
				if (!term) {
					searchStatus.textContent = '';
					editor.setSelectionRange(0, 0);
					return;
				}
				const content = editor.value;
				if (!content.length) return;

				if (term !== searchTerm) {
					searchTerm = term;
					lastSearchIndex = -1;
				}

				const startIdx = forward ? (lastSearchIndex + 1) : (lastSearchIndex - 1);
				let foundIdx = -1;

				if (forward) {
					foundIdx = content.indexOf(searchTerm, startIdx);
					if (foundIdx === -1 && lastSearchIndex > 0) {
						foundIdx = content.indexOf(searchTerm, 0);
					}
				} else {
					if (lastSearchIndex <= 0) lastSearchIndex = content.length;
					foundIdx = content.lastIndexOf(searchTerm, lastSearchIndex - 1);
					if (foundIdx === -1) {
						foundIdx = content.lastIndexOf(searchTerm, content.length);
					}
				}

				if (foundIdx !== -1) {
					editor.focus();
					editor.setSelectionRange(foundIdx, foundIdx + searchTerm.length);

					// --- Position als Zeile/Spalte berechnen ---
					const textBefore = content.slice(0, foundIdx);
					const lineNumber = textBefore.split('\n').length - 1;               // 0‑basiert
					const lastNewline = textBefore.lastIndexOf('\n');
					const columnNumber = (lastNewline === -1) ? textBefore.length : textBefore.length - lastNewline - 1;

					// --- Maße des Editors ---
					const lineH = getLineHeight();
					const charW = getCharWidth();
					const pad = getEditorPadding();

					// Vertikaler Sichtbereich (ohne Padding)
					const innerHeight = editor.clientHeight - pad.top - pad.bottom;
					const visibleLines = Math.floor(innerHeight / lineH);

					// Zeile im oberen Drittel positionieren
					const targetLine = Math.max(0, lineNumber - Math.floor(visibleLines / 3));
					editor.scrollTop = targetLine * lineH + pad.top;

					// --- Horizontal: nur scrollen, wenn Treffer außerhalb des sichtbaren Bereichs ---
					const visibleWidth = editor.clientWidth - pad.left - pad.right;
					const trefferStartX = columnNumber * charW + pad.left;
					const trefferEndeX = (columnNumber + searchTerm.length) * charW + pad.left;
					const currentScrollX = editor.scrollLeft;
					const leftEdge = currentScrollX;
					const rightEdge = currentScrollX + visibleWidth;

					if (trefferStartX < leftEdge || trefferEndeX > rightEdge) {
						let newScrollX = currentScrollX;
						if (trefferStartX < leftEdge) {
							// Treffer liegt links vom sichtbaren Bereich → davor anzeigen
							newScrollX = Math.max(0, trefferStartX - 10);
						} else if (trefferEndeX > rightEdge) {
							// Treffer ragt rechts heraus → soweit scrollen, dass das Ende sichtbar wird
							newScrollX = Math.max(0, trefferEndeX - visibleWidth + 10);
						}
						editor.scrollLeft = newScrollX;
					}
					// (bei vollständig sichtbarem Treffer bleibt scrollLeft unverändert)

					lastSearchIndex = foundIdx;
					searchStatus.textContent = 'Found at ' + foundIdx + ' (line ' + (lineNumber + 1) + ')';
					searchStatus.style.color = 'var(--text-color)';
				} else {
					searchStatus.textContent = 'Not found';
					searchStatus.style.color = '#f44336';
					lastSearchIndex = -1;
				}
			}

			// --- Event-Listener ---

			searchInput.addEventListener('input', () => {
				// Nur Suchstatus zurücksetzen, nicht suchen
				searchTerm = '';
				lastSearchIndex = -1;
				searchStatus.textContent = '';
			});

			searchInput.addEventListener('keydown', (e) => {
				if (e.key === 'Enter') {
					e.preventDefault();
					console.log('Enter erkannt, forward=' + !e.shiftKey);  // Debug-Ausgabe
					if (e.shiftKey) {
						doSearch(false);
					} else {
						doSearch(true);
					}
				}
			});

			searchNextBtn.addEventListener('click', () => doSearch(true));
			searchPrevBtn.addEventListener('click', () => doSearch(false));

            const statusMsg = document.getElementById('statusMsg');
            const currentFileLabel = document.getElementById('currentFileLabel');
            
            let currentFile = '';
            let editorInitialized = false;
			let originalContent = '';

            const proxyDot = document.getElementById('proxyDot');
            const proxyState = document.getElementById('proxyState');
            const listUpdated = document.getElementById('listUpdated');
            const dryRunState = document.getElementById('dryRunState');

            async function refreshStatus() {
    			try {
        			const resp = await apiFetch('/api/status');
        			if (!resp.ok) throw new Error('Status unavailable');
        			const data = await resp.json();

        			proxyState.textContent = data.running ? 'Running' : 'Stopped';
        			proxyDot.className = 'status-dot' + (data.running ? ' running' : ' stopped');

        			if (data.lastUpdated && data.lastUpdated !== '0001-01-01T00:00:00Z') {
            			const d = new Date(data.lastUpdated);
            			listUpdated.textContent = d.toLocaleString();
        			} else {
            			listUpdated.textContent = 'Never';
        			}

        			dryRunState.textContent = data.dryRun ? 'ON' : 'OFF';

        			if (startBtn) startBtn.disabled = data.running;
        			if (stopBtn) stopBtn.disabled = !data.running;
        			if (dryRunBtn) {
						dryRunBtn.disabled = !data.running;   // ← Nur aktiv, wenn Proxy läuft
						dryRunBtn.textContent = data.dryRun ? '🧪 Dry-run (ON)' : '🧪 Dry-run (OFF)';
					}
        
        			// Statistiken aktualisieren
        			await refreshStats();
    			} catch (err) {
        			proxyState.textContent = 'Error';
        			console.error('Status error:', err);
    			}
			}

			async function refreshStats() {
    			try {
        			const resp = await apiFetch('/api/stats');
        			if (!resp.ok) throw new Error('Stats unavailable');
        			const data = await resp.json();
        			blockedTotalEl.textContent = data.blockedTotal;
        			dryRunTotalEl.textContent = data.dryRunTotal;
    			} catch (err) {
        			console.error('Stats error:', err);
    			}
			}

            async function loadFileAndShow(filename) {
                if (!editorInitialized) {
                    editorInitialized = true;
                    document.getElementById('saveBtn').addEventListener('click', saveFile);
                    document.getElementById('reloadBtn').addEventListener('click', () => loadFileContent(currentFile));
                }
                
                try {
                    statusMsg.textContent = 'Loading...';
                    statusMsg.style.color = '#4caf50';
                    const resp = await apiFetch('/api/file?name=' + encodeURIComponent(filename) + '&t=' + Date.now());
                    if (!resp.ok) throw new Error(await resp.text());
                    const text = await resp.text();
                    editor.value = text;
                    currentFile = filename;
                    currentFileLabel.textContent = 'Editing: ' + filename;
                    statusMsg.textContent = '';

					// Suchleiste aktivieren & zurücksetzen
					activateSearch(true);
                    
                    selectorPanel.classList.add('hidden');
                    editorSection.classList.remove('hidden');
                } catch (err) {
                    statusMsg.textContent = 'Error loading: ' + err.message;
                    statusMsg.style.color = '#f44336';
                }	
            }

            async function loadFileContent(filename) {
                try {
                    statusMsg.textContent = 'Reloading...';
                    statusMsg.style.color = '#4caf50';
                    const resp = await apiFetch('/api/file?name=' + encodeURIComponent(filename) + '&t=' + Date.now());
                    if (!resp.ok) throw new Error(await resp.text());
                    const text = await resp.text();
                    editor.value = text;
					originalContent = text;
                    statusMsg.textContent = 'Reloaded';
                    setTimeout(() => statusMsg.textContent = '', 1500);
                } catch (err) {
                    statusMsg.textContent = 'Reload failed: ' + err.message;
                    statusMsg.style.color = '#f44336';
                }
            }

            async function saveFile() {
                try {
                    const resp = await apiFetch('/api/save', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ file: currentFile, content: editor.value })
                    });
                    if (!resp.ok) throw new Error(await resp.text());
                    statusMsg.textContent = 'Saved successfully!';
                    statusMsg.style.color = '#4caf50';
                    setTimeout(() => statusMsg.textContent = '', 2000);
					// Prüfen, ob Proxy läuft, dann neu starten
					const statusResp = await apiFetch('/api/status');
					const statusData = await statusResp.json();
					if (statusData.running) {
						await apiFetch('/api/proxy/restart', { method: 'POST' });
						console.log('Proxy restarted after config change');
					}
				} catch (err) {
					statusMsg.textContent = 'Save failed: ' + err.message;
					statusMsg.style.color = '#f44336';
				}
			}

            function showFileSelector() {
				activateSearch(false); 
                editorSection.classList.add('hidden');
                selectorPanel.classList.remove('hidden');
                tabs.forEach(t => t.classList.remove('active'));
                document.querySelector('[data-tab="selector"]').classList.add('active');
                currentFile = '';
                statusMsg.textContent = '';
            }

            document.querySelectorAll('.file-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    const filename = btn.dataset.file;
                    loadFileAndShow(filename);
                });
            });

            document.getElementById('backBtn').addEventListener('click', showFileSelector);

            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.key === 's' && !editorSection.classList.contains('hidden')) {
                    e.preventDefault();
                    saveFile();
                }
            });

			function setupDevModeListeners() {
                const backupCheck = document.getElementById('backupCheckbox');
                const logSizeInput = document.getElementById('logMaxSizeInput');
                const saveLogSizeBtn = document.getElementById('saveLogSizeBtn');
                const logSizeStatus = document.getElementById('logSizeStatus');
				const statsCheckbox = document.getElementById('statsCheckbox');

				statsCheckbox.addEventListener('change', async () => {
					await apiFetch('/api/stats/enable', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ enabled: statsCheckbox.checked })
					});
					statsTab.style.display = statsCheckbox.checked ? 'block' : 'none';
					if (statsCheckbox.checked) loadStatistics();
				});

				// Nach dem Laden:
				loadStatsSetting();

				autostartCheckbox.addEventListener('change', async () => {
					await apiFetch('/api/autostart/set', {
						method: 'POST',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify({ enabled: autostartCheckbox.checked })
					});
				});


                backupCheck.addEventListener('change', async () => {
                    await apiFetch('/api/backup/set', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ enabled: backupCheck.checked })
                    });
                });

                saveLogSizeBtn.addEventListener('click', async () => {
                    const newSize = parseInt(logSizeInput.value);
                    if (newSize < 1 || newSize > 100) {
                        logSizeStatus.textContent = 'Invalid size (1-100 MB)';
                        logSizeStatus.style.color = '#f44336';
                        return;
                    }
                    const resp = await apiFetch('/api/logmaxsize/set', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ maxSizeMB: newSize })
                    });
                    if (resp.ok) {
                        logSizeStatus.textContent = 'Saved.';
                        logSizeStatus.style.color = '#4caf50';
                    } else {
                        logSizeStatus.textContent = 'Failed.';
                        logSizeStatus.style.color = '#f44336';
                    }
                    setTimeout(() => logSizeStatus.textContent = '', 2000);
                });
				// --- Statistics Flusher settings (dev mode only) ---
				const statsFlushIntervalInput = document.getElementById('statsFlushIntervalInput');
				const saveFlushIntervalBtn = document.getElementById('saveFlushIntervalBtn');
				const flushIntervalStatus = document.getElementById('flushIntervalStatus');
				const statsCleanupTicksInput = document.getElementById('statsCleanupTicksInput');
				const saveCleanupTicksBtn = document.getElementById('saveCleanupTicksBtn');
				const cleanupTicksStatus = document.getElementById('cleanupTicksStatus');

				async function loadStatsFlushSettings() {
					try {
						const resp = await apiFetch('/api/stats/flushinterval');
						if (resp.ok) {
							const data = await resp.json();
							statsFlushIntervalInput.value = data.seconds;
						}
					} catch (e) {}
					try {
						const resp = await apiFetch('/api/stats/cleanupticks');
						if (resp.ok) {
							const data = await resp.json();
							statsCleanupTicksInput.value = data.ticks;
						}
					} catch (e) {}
				}

				saveFlushIntervalBtn.addEventListener('click', async () => {
					const seconds = parseInt(statsFlushIntervalInput.value);
					if (isNaN(seconds) || seconds < 10 || seconds > 86400) {
						flushIntervalStatus.textContent = 'Invalid (10-86400)';
						return;
					}
					try {
						const resp = await apiFetch('/api/stats/flushinterval', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ seconds: seconds })
						});
						if (resp.ok) {
							flushIntervalStatus.textContent = 'Saved.';
						} else {
							flushIntervalStatus.textContent = 'Failed.';
						}
					} catch (err) {
						flushIntervalStatus.textContent = 'Error.';
					}
					setTimeout(() => flushIntervalStatus.textContent = '', 2000);
				});

				saveCleanupTicksBtn.addEventListener('click', async () => {
					const ticks = parseInt(statsCleanupTicksInput.value);
					if (isNaN(ticks) || ticks < 0) {
						cleanupTicksStatus.textContent = 'Invalid';
						return;
					}
					try {
						const resp = await apiFetch('/api/stats/cleanupticks', {
							method: 'POST',
							headers: { 'Content-Type': 'application/json' },
							body: JSON.stringify({ ticks: ticks })
						});
						if (resp.ok) {
							cleanupTicksStatus.textContent = 'Saved.';
						} else {
							cleanupTicksStatus.textContent = 'Failed.';
						}
					} catch (err) {
						cleanupTicksStatus.textContent = 'Error.';
					}
					setTimeout(() => cleanupTicksStatus.textContent = '', 2000);
				});

				// Elemente für Dev‑Mode aktivieren
				statsFlushIntervalInput.disabled = false;
				saveFlushIntervalBtn.disabled = false;
				statsCleanupTicksInput.disabled = false;
				saveCleanupTicksBtn.disabled = false;

				loadStatsFlushSettings();
            }

            refreshStatus();
            loadFlushDNSSetting();
            setInterval(refreshStatus, 10000);
            checkDevMode();
            setupDevModeListeners();
        })();
    </script>
</body>
</html>`

func checkLogSizeAndAsk() {
	info, err := os.Stat(logPath())
	if err != nil {
		return
	}
	maxBytes := int64(logMaxSizeMB) * 1024 * 1024
	if info.Size() <= maxBytes {
		return
	}
	if runtime.GOOS == "windows" {
		msg, _ := windows.UTF16PtrFromString(fmt.Sprintf("Log file exceeds %d MB. Clear it now?", logMaxSizeMB))
		title, _ := windows.UTF16PtrFromString("Adblock-DNS")
		ret, _ := windows.MessageBox(0, msg, title, windows.MB_YESNO|windows.MB_ICONQUESTION)
		if ret == 6 {
			os.Truncate(logPath(), 0)
			if err := writeLogHeader(); err != nil {
				log.Printf("Failed to write log header: %v", err)
			}
		}
	}
}

func main() {
	// 1. Panik‑Abfangung – muss als erstes stehen!
	defer func() {
		if r := recover(); r != nil {
			// Schreiben Sie die Fehlermeldung so gut es geht in eine Datei,
			// da das normale Logging unter Umständen nicht mehr verfügbar ist.
			crashLogPath := filepath.Join(exeDir(), "crash.log")
			msg := fmt.Sprintf("FATAL PANIC at %s: %v\n", time.Now().Format(time.RFC3339), r)
			os.WriteFile(crashLogPath, []byte(msg), 0644)

			// DNS‑Wiederherstellung – absolut notwendig, damit der Nutzer Internet behält
			if runtime.GOOS == "windows" {
				iface := findActiveInterface()
				if iface != "" {
					// Alle statischen DNS‑Server des aktiven Adapters entfernen
					_ = runNetsh("interface", "ip", "delete", "dns", iface, "all")
				}
			}
			// Programm endgültig beenden
			os.Exit(1)
		}
	}()
	logFile, _ := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	defer logFile.Close()

	log.SetOutput(logFile)

	// Header lesen
	readLogHeader()

	// Dev-Modus prüfen (Kommandozeile überschreibt)
	if len(os.Args) > 1 && os.Args[1] == "-dev" {
		devMode = true
		log.Println("Dev mode enabled (via command line)")
	}

	// Autostart setzen
	if runtime.GOOS == "windows" {
		if err := setAutostart(autostartEnabled); err != nil {
			log.Printf("Failed to set autostart: %v", err)
		}
	}

	// Log-Größe prüfen
	checkLogSizeAndAsk()

	if runtime.GOOS == "windows" {
		if !isAdmin() {
			log.Printf("Not running as administrator, restarting with admin privileges...")
			runAsAdmin()
			return
		}
	}

	if !checkSingleInstance() {
		if runtime.GOOS == "windows" {
			msg, _ := windows.UTF16PtrFromString("Adblock DNS is already running.")
			title, _ := windows.UTF16PtrFromString("Adblock-DNS")
			windows.MessageBox(0, msg, title, windows.MB_OK|windows.MB_ICONINFORMATION)
		}
		os.Exit(0)
	}

	if err := initStatsDB(); err != nil {
		log.Printf("Failed to init stats DB: %v", err)
		statsEnabled = false
		_ = writeLogHeader()
	} else {
		log.Printf("[MAIN] initStatsDB done. statsEnabled=%v", statsEnabled)
		setStatsEnabled(statsEnabled) // aktiviert den Flusher UND proxy.SetStatsEnabled
	}

	ensureConfigFiles()
	// Entferne die doppelten Aufrufe von loadUpstreamsFromLog() etc. hier
	systray.Run(onReady, onExit)
}

func ensureActiveInterface() {
	if activeInterface == "" {
		activeInterface = findActiveInterface()
		log.Printf("Active interface set to: %s", activeInterface)
	}
}

func onReady() {
	// Initiales Icon setzen (grün)
	systray.SetIcon(iconGreen)
	systray.SetTitle("Adblock-DNS")
	systray.SetTooltip("DNS ad blocker")

	status := systray.AddMenuItem("Status: Starting…", "")
	status.Disable()

	// Verwende die globalen Variablen startItem, stopItem, dryItem
	startItem = systray.AddMenuItem("Start", "Start DNS proxy")
	stopItem = systray.AddMenuItem("Stop", "Stop DNS proxy")
	stopItem.Disable()
	dryItem = systray.AddMenuItemCheckbox("Dry-run", "Log only; do not block", false)
	currentDryRun = dryItem.Checked()

	editorMenuItem = systray.AddMenuItem("WebView", "Open web view for configuration")
	// Direkt deaktivieren
	editorMenuItem.Disable()

	quit := systray.AddMenuItem("Quit", "Quit Adblock-DNS")
	quit.Disable()

	// WebView-Menüpunkt erst nach kurzer Verzögerung aktivieren,
	// damit das System Zeit zum Initialisieren hat.
	go func() {
		time.Sleep(3 * time.Second)
		editorMenuItem.Enable()
		quit.Enable()
	}()

	// --- Proxy Optionen vorbereiten ---
	upstreamsMu.RLock()
	upstreams := make([]string, len(currentUpstreams))
	copy(upstreams, currentUpstreams)
	upstreamsMu.RUnlock()

	// Basis‑Optionen thread‑safe vom Proxy‑Package holen
	opts := proxy.GetCurrentOpts()
	// Explizit überschreiben, was wir hier im Tray‑Start setzen wollen
	opts.Listen = "127.0.0.1:53"
	opts.Interval = 24 * time.Hour
	opts.DryRun = dryItem.Checked()
	opts.Verbose = verboseEnabled
	opts.Upstreams = upstreams
	// MatchMode und BlockMode bleiben auf den bereits im Proxy gespeicherten Werten
	// (standardmäßig "suffix" / "null", falls nicht anders gesetzt)

	// start automatically
	if err := proxy.Start(opts); err != nil {
		log.Printf("start error: %v", err)
	} else {
		startItem.Disable()
		stopItem.Enable()
		if runtime.GOOS == "windows" {
			activeInterface = findActiveInterface()
			saveOriginalDNSSettings()
			if err := setDNSStatic(activeInterface, []string{"127.0.0.1"}); err != nil {
				log.Printf("Failed to set DNS: %v", err)
			}
			flushDNS() // ← Cache leeren
		}
		// Status-Menütext aktualisieren
		state := "Running"
		if currentDryRun {
			state = "Dry‑run"
		}
		status.SetTitle(fmt.Sprintf("Status: %s", state))
	}

	// Falls der Proxy nicht läuft, Status korrekt setzen
	if !proxy.Running() {
		status.SetTitle("Status: Stopped")
	}

	go updateStatus(status)

	// Klick-Ereignisse
	go func() {
		for {
			select {
			case <-startItem.ClickedCh:
				if !proxy.Running() {
					// Optionen für den Start neu zusammenbauen (insb. aktuelle Upstreams)
					upstreamsMu.RLock()
					upstreams := make([]string, len(currentUpstreams))
					copy(upstreams, currentUpstreams)
					upstreamsMu.RUnlock()

					opts := proxy.GetCurrentOpts()
					opts.Listen = "127.0.0.1:53"
					opts.Interval = 24 * time.Hour
					opts.DryRun = currentDryRun
					opts.Verbose = verboseEnabled
					opts.Upstreams = upstreams

					if err := proxy.Start(opts); err != nil {
						log.Printf("start error: %v", err)
					} else {
						startItem.Disable()
						stopItem.Enable()
						dryItem.Enable()
						if runtime.GOOS == "windows" {
							ensureActiveInterface()
							if !originalDNSSettingsSaved {
								saveOriginalDNSSettings()
							}
							if err := setDNSStatic(activeInterface, []string{"127.0.0.1"}); err != nil {
								log.Printf("Failed to set DNS: %v", err)
							}
							flushDNS()
						}
					}
				}
			case <-stopItem.ClickedCh:
				if proxy.Running() {
					proxy.Stop()
					stopItem.Disable()
					startItem.Enable()
					proxy.SetDryRun(false)
					currentDryRun = false
					dryItem.Uncheck()
					dryItem.Disable()
					if runtime.GOOS == "windows" {
						if err := restoreOriginalDNSSettings(); err != nil {
							log.Printf("Failed to restore DNS settings: %v", err)
						}
						flushDNS()
					}
				}
			case <-dryItem.ClickedCh:
				if dryItem.Checked() {
					dryItem.Uncheck()
					proxy.SetDryRun(false)
					currentDryRun = false
				} else {
					dryItem.Check()
					proxy.SetDryRun(true)
					currentDryRun = true
				}
			case <-editorMenuItem.ClickedCh:
				if httpServer == nil {
					startConfigEditor()
				} else {
					stopConfigEditor()
				}
			case <-quit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
