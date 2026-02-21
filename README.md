# Certographer

Certographer scans internal IP ranges and host targets for TLS certificates, then outputs JSON results. It's like a map builder for certificates... a certificate cartographer if you will. Get it ? :P

## Quick Start

1. Download and extract the repository.
2. Create a virtual environment.
3. Install requirements.
4. Run a scan.

### Windows

```bash
py -m venv venv
venv\Scripts\activate
py -m pip install -r requirements.txt
py Certographer.py --target 192.168.1.0/24 --output testscan.json --workers 1500
```

### macOS/Linux

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python3 Certographer.py --target 192.168.1.0/24 --output testscan.json --workers 1500
```


## Target Types (`--target`, repeatable)

- CIDR range: `192.168.100.0/24`
- DNS hostname: `google.com`
- Hostname and explicit IP pair: `google.com,74.125.202.100`

If no `--target` values are provided, Certographer scans default RFC1918 CIDRs.

## Examples

### Scan a single host

```bash
python3 Certographer.py --target 192.168.100.101/32 --port 443
```

### Scan a DNS name (SNI)

```bash
python3 Certographer.py --target google.com --port 443
```

### Scan a hostname against a specific IP (SNI + explicit destination IP)

```bash
python3 Certographer.py --target google.com,74.125.202.100 --port 443
```

### Include IP-only TLS results along with SNI results

```bash
python3 Certographer.py --target google.com --port 443 --include-ip-results
```

### Scan multiple ports

```bash
python3 Certographer.py --target 192.168.100.0/24 --port 443 --port 8443 --port 9443 --port 4443
```

### Write JSON Lines output to a file (Splunk-friendly)

```bash
python3 Certographer.py --json-lines --output results.jsonl
```

### Enable reverse DNS lookups

```bash
python3 Certographer.py --target 10.10.10.0/24 --reverse-dns
```

### My favorite (includes homelab dns server) ###
```bash
python3 Certographer.py --target 192.168.100.0/24 --reverse-dns --include-ip-results --output "10.10.10.10.scanresults.json" --dns-server 192.168.100.180 --queue-size 1500
```

## Common Options

- `--target`: Target CIDR range, DNS name, or `hostname,ip` pair (repeatable). Defaults to RFC1918 ranges if omitted.
- `--port`: Port to scan (repeatable). Defaults to internal port list.
- `--workers`: Number of worker threads.
- `--timeout`: Connection timeout in seconds.
- `--queue-size`: Max queued targets waiting for workers.
- `--dns-server`: DNS server to use for PTR/A/AAAA lookups (repeatable).
- `--json-lines`: Output one JSON object per line.
- `--output`: Write JSON output to a file.
- `--include-ip-results`: Include IP-only TLS results even when hostname/SNI results are found.
- `--reverse-dns`: Enable reverse DNS lookups and verification (default is off).
- `--description`: Adds an optional `scan_description` field to the output.

## Output Metadata

Each JSON result includes these scan metadata fields:

- `scan_target`: The input target value that produced the connection attempt.
- `dns_servers`: DNS server list used for lookups (or `["system"]`).
- `reverse_dns_used`: `true` when `--reverse-dns` is enabled, otherwise `false`.

When `--reverse-dns` is enabled, results also include:

- `reverse_dns`
- `reverse_dns_verified`

`reverse_dns` contains PTR hostnames returned for the scanned IP.  
`reverse_dns_verified` is the subset of those names that pass forward-confirmation (the hostname resolves back to the same IP).

## Defaults

- CIDR ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Ports: `3389, 443, 4443, 4433, 4444, 80, 8000, 8080, 8089, 8443, 8444, 9443, 9444, 10443, 12443, 2083, 2087, 2096, 2078`
- Workers: `min(512, CPU count * 32)`
- Timeout: `1.5` seconds
- Queue size: `20000`
- Reverse DNS: `off`
- JSON Lines: `off`
- Output file: `stdout`


## Common TLS Ports and Example Services

- `3389`: Remote Desktop Protocol (RDP)
- `443`: HTTPS (web apps, reverse proxies, APIs)
- `4443`: Alternate HTTPS (admin consoles, appliance UIs)
- `4433`: Alternate HTTPS (custom web services, embedded devices)
- `4444`: Alternate HTTPS (management consoles, legacy apps)
- `80`: HTTP with TLS upgrade or misconfigured HTTPS
- `8000`: HTTP/HTTPS alt (dev servers, frameworks)
- `8080`: HTTP/HTTPS alt (proxies, app servers, dashboards)
- `8089`: HTTPS Splunk backend default port
- `8443`: HTTPS alt (Tomcat, Kubernetes dashboards, dev tools)
- `8444`: HTTPS alt (custom web apps, embedded UIs)
- `9443`: HTTPS alt (OpenShift, app consoles, gateways)
- `9444`: HTTPS alt (management UIs, internal tools)
- `10443`: HTTPS alt (custom services, appliance UIs)
- `12443`: HTTPS alt (reverse proxies, custom services)
- `2083`: cPanel (WHM/cPanel HTTPS)
- `2087`: WHM (WebHost Manager HTTPS)
- `2096`: cPanel webmail HTTPS
- `2078`: cPanel webmail HTTP with TLS upgrade
