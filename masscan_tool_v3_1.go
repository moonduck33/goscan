package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────────────

type Config struct {
	InputFile   string
	OutputDir   string
	Ports       []string
	Rate        int
	Workers     int
	ExcludeFile string
	ResumeFile  string
}

type scanResult struct {
	port  string
	count int
	file  string
	err   error
}

type PortInfo struct {
	Port   int    `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
}

type MasscanRecord struct {
	IP    string     `json:"ip"`
	Ports []PortInfo `json:"ports"`
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	cfg, doInit := parseFlags()

	if doInit {
		writeStarterConfig()
		return
	}

	if err := ensureMasscan(); err != nil {
		log.Fatalf("masscan: %v", err)
	}
	if _, err := os.Stat(cfg.InputFile); os.IsNotExist(err) {
		log.Fatalf("input file not found: %s", cfg.InputFile)
	}
	if cfg.ExcludeFile != "" {
		if _, err := os.Stat(cfg.ExcludeFile); os.IsNotExist(err) {
			log.Fatalf("exclude file not found: %s", cfg.ExcludeFile)
		}
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		log.Fatalf("cannot create output dir: %v", err)
	}

	// Validate and clean the input file before handing it to masscan.
	// Masscan exits on the very first invalid line — one bad entry kills
	// the whole scan. prepareInputFile strips anything that isn't a valid
	// IPv4 address and returns a clean temp file if needed.
	cleanInput, cleanupInput, err := prepareInputFile(cfg.InputFile)
	if err != nil {
		log.Fatalf("input validation: %v", err)
	}
	defer cleanupInput()
	cfg.InputFile = cleanInput

	printBanner(cfg)


	results := make([]scanResult, len(cfg.Ports))
	sem := make(chan struct{}, cfg.Workers)
	var wg sync.WaitGroup

	for i, port := range cfg.Ports {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			jsonFile := filepath.Join(cfg.OutputDir, fmt.Sprintf("masscan_%s.json", p))
			ipFile := filepath.Join(cfg.OutputDir, fmt.Sprintf("ips_%s.txt", p))

			if err := runMasscan(cfg, p, jsonFile); err != nil {
				results[idx] = scanResult{port: p, err: err}
				return
			}
			count, err := parseAndWriteIPs(jsonFile, ipFile)
			results[idx] = scanResult{port: p, count: count, file: ipFile, err: err}
		}(i, port)
	}

	wg.Wait()

	allFile := filepath.Join(cfg.OutputDir, "ips_all.txt")
	var ipFiles []string
	for _, r := range results {
		if r.err == nil && r.file != "" {
			ipFiles = append(ipFiles, r.file)
		}
	}
	total, combineErr := combineIPs(ipFiles, allFile)

	printSummary(results, allFile, total, combineErr)
}

// ── Flags + Config file ───────────────────────────────────────────────────────

func parseFlags() (Config, bool) {
	var portsStr, configPath string
	var doInit bool
	cfg := Config{}

	flag.StringVar(&configPath, "config", "", "Config file path (default: ./masscan-tool.conf if it exists)")
	flag.BoolVar(&doInit, "init", false, "Write a starter masscan-tool.conf to the current directory and exit")

	flag.StringVar(&cfg.InputFile, "i", "rango.txt", "")
	flag.StringVar(&cfg.InputFile, "input", "rango.txt", "Input file with IPs or CIDR ranges (one per line)")
	flag.StringVar(&cfg.OutputDir, "o", ".", "")
	flag.StringVar(&cfg.OutputDir, "output", ".", "Output directory for all result files")
	flag.StringVar(&portsStr, "p", "80,443", "")
	flag.StringVar(&portsStr, "ports", "80,443", "Comma-separated ports to scan (e.g. 80,443,8080)")
	flag.IntVar(&cfg.Rate, "r", 6000, "")
	flag.IntVar(&cfg.Rate, "rate", 6000, "Masscan packet rate in pps")
	flag.IntVar(&cfg.Workers, "w", 2, "")
	flag.IntVar(&cfg.Workers, "workers", 2, "Number of ports to scan concurrently")
	flag.StringVar(&cfg.ExcludeFile, "exclude", "", "File with IPs/CIDRs to skip (passed to masscan --excludefile)")
	flag.StringVar(&cfg.ResumeFile, "resume", "", "Resume an interrupted scan — path to masscan's paused.conf")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: masscan-tool [flags]

Flags:
  --init                   Generate a starter masscan-tool.conf and exit
  --config   string        Config file path (default: ./masscan-tool.conf)
  -i, --input    string    IP/range input file          (default: rango.txt)
  -o, --output   string    Output directory             (default: .)
  -p, --ports    string    Comma-separated ports        (default: 80,443)
  -r, --rate     int       Packet rate in pps           (default: 6000)
  -w, --workers  int       Concurrent port scans        (default: 2)
      --exclude  string    Exclude file (IPs/CIDRs to skip)
      --resume   string    Path to masscan paused.conf to resume

CLI flags always override config file values.

Examples:
  masscan-tool --init
  masscan-tool
  masscan-tool -p 80,443,8080 -r 10000
  masscan-tool --resume paused.conf
  masscan-tool --exclude cdn_ranges.txt -p 80,443`)
		fmt.Fprintln(os.Stderr)
	}

	flag.Parse()

	// Which flags did the user actually provide on the CLI?
	cliSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { cliSet[f.Name] = true })

	// Determine config file to load
	cfgFile := configPath
	if cfgFile == "" {
		cfgFile = "masscan-tool.conf" // auto-detect
	}

	if m, err := loadConfig(cfgFile); err == nil {
		if configPath != "" {
			fmt.Printf("[config] loaded %s\n", cfgFile)
		} else {
			fmt.Printf("[config] loaded %s\n", cfgFile)
		}
		// Apply config values only for options not set on the CLI
		if v, ok := m["input"]; ok && !cliSet["input"] && !cliSet["i"] {
			cfg.InputFile = v
		}
		if v, ok := m["output"]; ok && !cliSet["output"] && !cliSet["o"] {
			cfg.OutputDir = v
		}
		if v, ok := m["ports"]; ok && !cliSet["ports"] && !cliSet["p"] {
			portsStr = v
		}
		if v, ok := m["rate"]; ok && !cliSet["rate"] && !cliSet["r"] {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Rate = n
			}
		}
		if v, ok := m["workers"]; ok && !cliSet["workers"] && !cliSet["w"] {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Workers = n
			}
		}
		if v, ok := m["exclude"]; ok && !cliSet["exclude"] {
			cfg.ExcludeFile = v
		}
	} else if configPath != "" {
		// User explicitly passed --config but file not found
		log.Fatalf("config: %v", err)
	}
	// If the default masscan-tool.conf doesn't exist, silently continue

	for _, p := range strings.Split(portsStr, ",") {
		if p = strings.TrimSpace(p); p != "" {
			cfg.Ports = append(cfg.Ports, p)
		}
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = []string{"80", "443"}
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	// Resume mode: one masscan at a time to avoid paused.conf conflicts
	if cfg.ResumeFile != "" && cfg.Workers > 1 {
		fmt.Println("[resume] forcing workers=1 to avoid paused.conf conflicts")
		cfg.Workers = 1
	}

	return cfg, doInit
}

// loadConfig parses a simple key = value config file.
// Lines starting with # are comments. Inline comments after values are stripped.
func loadConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	m := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Strip inline comment (e.g.  value # comment)
		if idx := strings.Index(val, " #"); idx >= 0 {
			val = strings.TrimSpace(val[:idx])
		}
		m[key] = val
	}
	return m, sc.Err()
}

// writeStarterConfig writes masscan-tool.conf with all options documented.
func writeStarterConfig() {
	const name = "masscan-tool.conf"
	if _, err := os.Stat(name); err == nil {
		fmt.Fprintf(os.Stderr, "[init] %s already exists — delete it first if you want to regenerate\n", name)
		os.Exit(1)
	}

	const content = `# masscan-tool configuration file
# CLI flags always override these values.
# Lines starting with # are comments.

# ── Input / Output ────────────────────────────────────────
# File containing IPs or CIDR ranges to scan (one per line)
input = rango.txt

# Directory where all result files are written
output = ./results

# ── Scan options ──────────────────────────────────────────
# Ports to scan (comma-separated)
ports = 80,443

# Masscan packet rate in packets per second.
# Start low (1000–5000) and raise once you know your network can handle it.
# Residential: 1000–3000   VPS: 5000–50000   Dedicated: 100000+
rate = 6000

# Number of ports to scan at the same time.
# Each port runs its own masscan process.
workers = 2

# ── Optional ──────────────────────────────────────────────
# Exclude file: IPs or CIDRs to skip, one per line.
# Useful for skipping CDN ranges (Cloudflare, Akamai, etc.)
# Passed directly to masscan as --excludefile.
# exclude = exclude.txt
`

	if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
		log.Fatalf("[init] %v", err)
	}
	fmt.Printf("[init] created %s\n\n", name)
	fmt.Println("  Edit the file, then just run:  masscan-tool")
	fmt.Println("  Override any value on the fly: masscan-tool -r 10000 -p 80,443,8080")
	fmt.Println("  Use a different config file:   masscan-tool --config /path/to/other.conf")
}

// ── Input validation ──────────────────────────────────────────────────────────

// prepareInputFile reads the input file and filters out any line that isn't a
// valid IPv4 address. Masscan exits hard on the first bad line it sees, so
// even a single empty line or stray hostname kills the whole scan.
//
// If no bad lines are found the original file path is returned unchanged.
// If bad lines are found a cleaned temporary file is created, and the caller
// must call the returned cleanup func (deferred in main) to remove it.
func prepareInputFile(path string) (cleanPath string, cleanup func(), err error) {
	cleanup = func() {} // no-op unless we create a temp file

	f, err := os.Open(path)
	if err != nil {
		return path, cleanup, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)

	var valid, skipped int
	var badExamples []string // keep a few for the warning message

	// Temp file — only committed if we actually find bad lines.
	tmp, err := os.CreateTemp("", "masscan-clean-*.txt")
	if err != nil {
		return path, cleanup, err
	}
	tmpPath := tmp.Name()
	bw := bufio.NewWriterSize(tmp, 1<<20) // 1 MB write buffer

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			skipped++
			if len(badExamples) < 3 {
				badExamples = append(badExamples, fmt.Sprintf("%q", line))
			}
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil || ip.To4() == nil {
			skipped++
			if len(badExamples) < 3 {
				badExamples = append(badExamples, fmt.Sprintf("%q", line))
			}
			continue
		}
		bw.WriteString(line + "\n")
		valid++
	}

	if err := sc.Err(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return path, cleanup, err
	}

	bw.Flush()
	tmp.Close()

	if skipped == 0 {
		// File is already clean — remove temp and use original.
		os.Remove(tmpPath)
		fmt.Printf("[input] %d IPs validated — file is clean\n", valid)
		return path, func() {}, nil
	}

	// Bad lines found — report and use the cleaned temp file.
	fmt.Printf("[input] WARNING: %d invalid lines removed, %d valid IPs kept\n", skipped, valid)
	if len(badExamples) > 0 {
		fmt.Printf("[input] examples of removed lines: %s\n", strings.Join(badExamples, ", "))
	}
	fmt.Printf("[input] using cleaned temp file: %s\n", tmpPath)

	cleanup = func() { os.Remove(tmpPath) }
	return tmpPath, cleanup, nil
}

// ── Scanner ───────────────────────────────────────────────────────────────────

func runMasscan(cfg Config, port, outputFile string) error {
	fmt.Printf("\n[scan] port %-6s  rate=%d pps  output=%s\n", port, cfg.Rate, outputFile)
	if cfg.ExcludeFile != "" {
		fmt.Printf("[scan] port %-6s  excluding ranges from %s\n", port, cfg.ExcludeFile)
	}
	if cfg.ResumeFile != "" {
		fmt.Printf("[scan] port %-6s  resuming from %s\n", port, cfg.ResumeFile)
	}
	start := time.Now()

	args := []string{
		"masscan",
		"-iL", cfg.InputFile,
		"-p", port,
		"--rate", strconv.Itoa(cfg.Rate),
		"-oJ", outputFile,
	}
	if cfg.ExcludeFile != "" {
		args = append(args, "--excludefile", cfg.ExcludeFile)
	}
	if cfg.ResumeFile != "" {
		args = append(args, "--resume", cfg.ResumeFile)
	}

	cmd := exec.Command("sudo", args...)

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start masscan: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go liveCounter(ctx, outputFile, port)

	prefix := fmt.Sprintf("  [port %s]", port)
	var sw sync.WaitGroup
	relay := func(r io.Reader) {
		defer sw.Done()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				fmt.Printf("%s %s\n", prefix, line)
			}
		}
	}
	sw.Add(2)
	go relay(stderr)
	go relay(stdout)
	sw.Wait()
	cancel()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("masscan: %w", err)
	}

	fmt.Printf("[scan] port %-6s done in %s\n", port, time.Since(start).Round(time.Second))
	return nil
}

func liveCounter(ctx context.Context, jsonFile, port string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n := countRecordsInFile(jsonFile); n > 0 {
				fmt.Printf("  [port %s] ~%d hosts found so far\n", port, n)
			}
		}
	}
}

func countRecordsInFile(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	var n int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "{") || strings.HasPrefix(line, ",{") {
			n++
		}
	}
	return n
}

// ── JSON + IP files ───────────────────────────────────────────────────────────

func parseMasscanJSON(path string) ([]MasscanRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []MasscanRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, ",")
		line = strings.Trim(line, "[]")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec MasscanRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.IP == "" || rec.IP == "0.0.0.0" {
			continue
		}
		records = append(records, rec)
	}
	return records, sc.Err()
}

func parseAndWriteIPs(jsonFile, ipFile string) (int, error) {
	records, err := parseMasscanJSON(jsonFile)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", jsonFile, err)
	}

	seen := make(map[string]bool, len(records))
	for _, r := range records {
		seen[r.IP] = true
	}

	f, err := os.Create(ipFile)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", ipFile, err)
	}
	defer f.Close()

	sorted := sortedKeys(seen)
	bw := bufio.NewWriter(f)
	for _, ip := range sorted {
		bw.WriteString(ip + "\n")
	}
	return len(sorted), bw.Flush()
}

func combineIPs(files []string, outputFile string) (int, error) {
	seen := make(map[string]bool)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, ip := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if ip = strings.TrimSpace(ip); ip != "" {
				seen[ip] = true
			}
		}
	}

	sorted := sortedKeys(seen)

	f, err := os.Create(outputFile)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", outputFile, err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	for _, ip := range sorted {
		bw.WriteString(ip + "\n")
	}
	return len(sorted), bw.Flush()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── Install ───────────────────────────────────────────────────────────────────

func ensureMasscan() error {
	if _, err := exec.LookPath("masscan"); err == nil {
		fmt.Println("[+] masscan found")
		return nil
	}
	fmt.Println("[!] masscan not found — attempting auto-install...")
	switch runtime.GOOS {
	case "linux":
		return installLinux()
	case "darwin":
		return installMac()
	default:
		return fmt.Errorf("cannot auto-install on %s — install masscan manually", runtime.GOOS)
	}
}

func installLinux() error {
	type pm struct{ bin, flag string }
	for _, p := range []pm{{"apt-get", "-y"}, {"dnf", "-y"}, {"yum", "-y"}} {
		path, err := exec.LookPath(p.bin)
		if err != nil {
			continue
		}
		var steps [][]string
		if p.bin == "apt-get" {
			steps = [][]string{
				{"sudo", path, "update", "-y"},
				{"sudo", path, "install", "-y", "masscan"},
			}
		} else {
			steps = [][]string{{"sudo", path, "install", p.flag, "masscan"}}
		}
		for _, args := range steps {
			c := exec.Command(args[0], args[1:]...)
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("%s: %v", p.bin, err)
			}
		}
		fmt.Printf("[+] masscan installed via %s\n", p.bin)
		return nil
	}
	return buildFromSource()
}

func installMac() error {
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("homebrew not found — run: brew install masscan")
	}
	cmd := exec.Command("brew", "install", "masscan")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("brew install masscan: %v", err)
	}
	fmt.Println("[+] masscan installed via homebrew")
	return nil
}

func buildFromSource() error {
	fmt.Println("[*] building masscan from source (requires git + make)...")
	tmp, err := os.MkdirTemp("", "masscan-src")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	for _, step := range [][]string{
		{"git", "clone", "--depth=1", "https://github.com/robertdavidgraham/masscan.git", tmp},
		{"make", "-C", tmp},
		{"sudo", "make", "-C", tmp, "install"},
	} {
		c := exec.Command(step[0], step[1:]...)
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("'%s' failed: %v", step[0], err)
		}
	}
	fmt.Println("[+] masscan installed from source")
	return nil
}

// ── Display ───────────────────────────────────────────────────────────────────

const colW = 54

func printBanner(cfg Config) {
	hr := strings.Repeat("─", colW)
	fmt.Printf("\n┌─ masscan-tool %s┐\n", hr[15:])
	bfield("Input  ", cfg.InputFile)
	bfield("Ports  ", strings.Join(cfg.Ports, ", "))
	bfield("Rate   ", fmt.Sprintf("%d pps", cfg.Rate))
	bfield("Workers", fmt.Sprintf("%d concurrent", cfg.Workers))
	bfield("Output ", cfg.OutputDir)
	if cfg.ExcludeFile != "" {
		bfield("Exclude", cfg.ExcludeFile)
	}
	if cfg.ResumeFile != "" {
		bfield("Resume ", cfg.ResumeFile)
	}
	fmt.Printf("└%s┘\n\n", hr)
}

func printSummary(results []scanResult, allFile string, total int, combineErr error) {
	hr := strings.Repeat("─", colW)
	fmt.Printf("\n┌─ Results %s┐\n", hr[9:])
	for _, r := range results {
		if r.err != nil {
			srow(fmt.Sprintf("port %s", r.port), fmt.Sprintf("✗ %v", r.err))
		} else {
			srow(fmt.Sprintf("port %s", r.port),
				fmt.Sprintf("%5d IPs  →  %s", r.count, filepath.Base(r.file)))
		}
	}
	fmt.Printf("│ %-*s │\n", colW-2, "")
	if combineErr != nil {
		srow("combined", fmt.Sprintf("✗ %v", combineErr))
	} else {
		srow("combined", fmt.Sprintf("%5d IPs  →  %s", total, filepath.Base(allFile)))
	}
	fmt.Printf("└%s┘\n", hr)
}

func bfield(label, value string) {
	fmt.Printf("│  %-8s %-*s│\n", label+":", colW-12, value)
}

func srow(label, value string) {
	fmt.Printf("│  %-10s %-*s│\n", label, colW-14, value)
}
