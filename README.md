Certographer: internal certificate scanner that checks DNS for hostnames and walks IP ranges.

Usage
  python3 Certographer.py

Scan a single host
  `python3 Certographer.py --cidr 192.168.100.101/32 --port 443`

Scan a DNS name (uses SNI)
 ` python3 Certographer.py --target google.com --port 443`

Include IP-only TLS results along with SNI results
  `python3 Certographer.py --target google.com --port 443 --include-ip-results`

Scan multiple ports
  `python3 Certographer.py --cidr 192.168.100.0/24 --port 443 --port 8443 --port 9443 --port 4443`

Write JSON Lines output to a file (Splunk-friendly)
  `python3 Certographer.py --json-lines --output results.jsonl`

Common options
  --cidr CIDR range to scan (repeatable). Defaults to RFC1918 ranges.
  --target Target CIDR or DNS name to scan (repeatable).
  --port Port to scan (repeatable). Defaults to 443.
  --workers Number of worker threads.
  --timeout Connection timeout in seconds.
  --queue-size Max queued targets waiting for workers.
  --dns-server DNS server to use for PTR/A/AAAA lookups (repeatable).
  --json-lines Output one JSON object per line.
  --output Write JSON output to a file.
  --include-ip-results Include IP-only TLS results even when hostname/SNI results are found.
  --no-reverse-dns Disable reverse DNS lookups and verification.

Defaults
  CIDR ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  Ports: 443, 4443, 4433, 4444, 80, 8080, 8089, 8443, 8444, 9443, 9444, 10443, 12443, 2083, 2087, 2096, 2078
  Workers: min(512, CPU count * 32)
  Timeout: 1.5 seconds
  Queue size: 20000
  JSON Lines: off
  Output file: stdout

Common TLS ports and example services
  - 443: HTTPS (web apps, reverse proxies, APIs)
  - 4443: Alternate HTTPS (admin consoles, appliance UIs)
  - 4433: Alternate HTTPS (custom web services, embedded devices)
  - 4444: Alternate HTTPS (management consoles, legacy apps)
  - 80: HTTP with TLS upgrade or misconfigured HTTPS
  - 8080: HTTP/HTTPS alt (proxies, app servers, dashboards)
  - 8089: HTTPS Splunk backend default port
  - 8443: HTTPS alt (Tomcat, Kubernetes dashboards, dev tools)
  - 8444: HTTPS alt (custom web apps, embedded UIs)
  - 9443: HTTPS alt (OpenShift, app consoles, gateways)
  - 9444: HTTPS alt (management UIs, internal tools)
  - 10443: HTTPS alt (custom services, appliance UIs)
  - 12443: HTTPS alt (reverse proxies, custom services)
  - 2083: cPanel (WHM/cPanel HTTPS)
  - 2087: WHM (WebHost Manager HTTPS)
  - 2096: cPanel webmail HTTPS
  - 2078: cPanel webmail HTTP with TLS upgrade


___________________________________________
#QucikStart#
 1. Download the repository zip file and extract it to a folder
 2. Create a new virtual environment (assuming terminal is already in the extracted directory)
    a. Windows
      `py -m venv venv`
    b. Nix
      `python3 -m venv venv`
 3. Install requirements
    a. Windows
      `py -m pip install -r requirements.txt`
    b. Nix
      `python3 -m pip install -r requirements.txt`
 4. Run a network scan exporting json results to a folder
    a. Windows
      `py Certographer.py --target 192.168.1.0/24 --output "testscan.json" --workers 1500`
    b. Nix
      `python3 Certographer.py --target 192.168.1.0/24 --output "testscan.json" --workers 1500`
