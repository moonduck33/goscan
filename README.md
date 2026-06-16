# GoScan-Tool

A Go wrapper around masscan that scans a list of IPs across multiple ports,
validates input, deduplicates results, and writes sorted IP files.

No external Go dependencies — just Go and masscan.

---

## Requirements

- **Go 1.21+** → https://go.dev/dl
- **masscan** → auto-installed on first run (Linux/Mac only)
- Linux or Mac (masscan does not run natively on Windows)

---

## Build

```bash
# Linux / Mac
go build -o masscan-tool masscan_tool_v3.go

# Cross-compile a Windows exe from Linux/Mac
GOOS=windows GOARCH=amd64 go build -o masscan-tool.exe masscan_tool_v3.go
```

Run without building (quick test):
```bash
go run masscan_tool_v3.go --help
```

---

## First time setup

Generate a starter config file:
```bash
./masscan-tool --init
```

This creates `masscan-tool.conf` in your current directory:
```ini
# masscan-tool configuration file
# CLI flags always override these values.

input   = rango.txt        # IP/range file to scan
output  = ./results        # folder for all output files
ports   = 80,443           # ports to scan
rate    = 6000             # packets per second
workers = 2                # how many ports to scan at once

# exclude = exclude.txt    # uncomment to skip IPs/CIDRs
```

Edit it once, then just run:
```bash
./masscan-tool
```

---

## All flags

| Flag        | Short | Default            | Description                              |
|-------------|-------|--------------------|------------------------------------------|
| `--input`   | `-i`  | `rango.txt`        | File with IPs or CIDR ranges to scan     |
| `--output`  | `-o`  | `.` (current dir)  | Folder where all result files go         |
| `--ports`   | `-p`  | `80,443`           | Comma-separated ports to scan            |
| `--rate`    | `-r`  | `6000`             | Masscan packet rate (pps)                |
| `--workers` | `-w`  | `2`                | Ports to scan at the same time           |
| `--exclude` |       | *(none)*           | File with IPs/CIDRs to skip             |
| `--resume`  |       | *(none)*           | Resume interrupted scan (paused.conf)    |
| `--config`  |       | `masscan-tool.conf`| Custom config file path                  |
| `--init`    |       |                    | Generate starter config and exit         |

**CLI flags always override the config file.**

---

## Usage examples

```bash
# Run using config file defaults
./masscan-tool

# Override specific values (rest come from config)
./masscan-tool -p 80,443,8080 -r 10000

# Specify everything on the command line
./masscan-tool -i targets.txt -o ./results -p 22,80,443 -r 5000

# Skip CDN/hosting ranges
./masscan-tool --exclude cdn_ranges.txt

# Use a different config file
./masscan-tool --config /path/to/other.conf

# Resume an interrupted scan
./masscan-tool --resume paused.conf
```

---

## Output files

Everything is written to your `--output` directory:

```
results/
├── masscan_80.json     ← raw masscan output for port 80
├── masscan_443.json    ← raw masscan output for port 443
├── ips_80.txt          ← unique IPs with port 80 open  (sorted)
├── ips_443.txt         ← unique IPs with port 443 open (sorted)
└── ips_all.txt         ← all IPs combined, deduplicated (sorted)
```

---

## Input validation

Before every scan, the tool reads your input file and checks every line.
Masscan exits hard on the first invalid entry it sees — one bad line kills
the whole scan.

If bad lines are found they are stripped automatically and masscan runs on
a cleaned temp file. You will see a warning like this:

```
[input] WARNING: 5 invalid lines removed, 500000 valid IPs kept
[input] examples of removed lines: "", "hostname.example.com", "999.1.2.3"
[input] using cleaned temp file: /tmp/masscan-clean-123.txt
```

If your file is already clean:
```
[input] 427373 IPs validated — file is clean
```

The temp file is deleted automatically when the scan finishes.

If you ever get an `invalid IP address on line #XXXXXXX` error from masscan
with an older version of the tool, the quick manual fix is:
```bash
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' ip_range.txt > ip_range_clean.txt
./masscan-tool -i ip_range_clean.txt
```

---

## Exclude file

Create a plain text file with IPs or CIDRs to skip, one per line.
Lines starting with `#` are comments:

```
# cdn_ranges.txt

# Cloudflare
104.16.0.0/12
172.64.0.0/13

# AWS CloudFront
13.224.0.0/14

# Akamai
23.32.0.0/11
```

Use it:
```bash
# Via flag
./masscan-tool --exclude cdn_ranges.txt

# Via config file
echo "exclude = cdn_ranges.txt" >> masscan-tool.conf
```

---

## Resume

If a scan is interrupted (Ctrl+C), masscan saves its state to `paused.conf`
in the current directory. Resume it with:

```bash
./masscan-tool --resume paused.conf
```

Workers are automatically forced to 1 in resume mode to prevent multiple
masscan processes from conflicting over the same `paused.conf`.

---

## Rate guide

| Setup               | Recommended rate |
|---------------------|------------------|
| Home / residential  | 1,000 – 3,000    |
| VPS                 | 5,000 – 50,000   |
| Dedicated server    | 100,000+         |

Start low and increase if results feel stable. Too high a rate drops packets
and gives incomplete results — you won't get an error, just missing hosts.

---

## Progress output

While scanning you will see masscan's live progress relayed per port, plus
a host count every 10 seconds:

```
[scan] port 80      rate=6000 pps  output=results/masscan_80.json
[scan] port 443     rate=6000 pps  output=results/masscan_443.json
  [port 80]  Scanning: rate: 5994-kpps, 12.3% done, 0:43 remaining
  [port 443] Scanning: rate: 5981-kpps, 11.8% done, 0:45 remaining
  [port 80]  ~1420 hosts found so far
  [port 443] ~887 hosts found so far
[scan] port 80      done in 1m12s
[scan] port 443     done in 1m15s

┌─ Results ──────────────────────────────────────────────┐
│  port 80     1847 IPs  →  ips_80.txt                   │
│  port 443    1103 IPs  →  ips_443.txt                  │
│                                                        │
│  combined    2391 IPs  →  ips_all.txt                  │
└────────────────────────────────────────────────────────┘
```

---

## Full pipeline with iptools

```bash
# 1. Extract domains from a credential dump or leak file
./iptools extract -r ./dumps/ --popular popular_domains.txt -o domains.txt

# 2. Resolve domains to IPv4 addresses
./iptools resolve domains.txt -o ips.txt -t 150

# 3. Expand each IP to its full /24 range
./iptools range ips.txt -o rango.txt

# 4. Scan for open ports
./masscan-tool -i rango.txt -p 80,443 -r 5000 -o ./results
```

---

## Help

```bash
./masscan-tool --help
```
