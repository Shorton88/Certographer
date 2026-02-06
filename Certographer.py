import argparse
import ipaddress
import json
import os
import queue
import socket
import ssl
import threading
import tempfile
import time
import logging

try:
    import dns
    import dns.exception
    import dns.resolver
    import dns.reversename
except ImportError:
    dns = None


DEFAULT_CIDRS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
DEFAULT_PORTS = (443,4443,4433,4444,80,8000,8080,8089,8443,8444,9443,9444,10443,12443,2083,2087,2096,2078)

_dns_cache_lock = threading.Lock()
_reverse_dns_cache: dict[tuple[str, tuple[str, ...]], list[str]] = {}
_forward_dns_cache: dict[tuple[str, tuple[str, ...]], set[str]] = {}


def _normalize_hostname(name: str) -> str:
    return name.rstrip(".").lower()


def _dns_cache_key(dns_servers: list[str] | None) -> tuple[str, ...]:
    if dns_servers:
        return tuple(dns_servers)
    return ("system",)


def _reverse_dns(
    ip: str,
    dns_servers: list[str] | None,
    resolver: "dns.resolver.Resolver | None",
) -> list[str]:
    cache_key = (ip, _dns_cache_key(dns_servers))
    with _dns_cache_lock:
        cached = _reverse_dns_cache.get(cache_key)
    if cached is not None:
        return cached

    names: list[str] = []
    if resolver is None:
        try:
            primary, aliases, _ = socket.gethostbyaddr(ip)
            names.append(primary)
            names.extend(aliases)
        except (socket.herror, socket.gaierror):
            names = []
    else:
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = resolver.resolve(reverse_name, "PTR")
            names = [str(rdata) for rdata in answers]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.exception.Timeout,
            dns.resolver.NoNameservers,
        ):
            names = []

    normalized = []
    seen = set()
    for name in names:
        normalized_name = _normalize_hostname(name)
        if normalized_name and normalized_name not in seen:
            seen.add(normalized_name)
            normalized.append(normalized_name)

    with _dns_cache_lock:
        _reverse_dns_cache[cache_key] = normalized
    return normalized


def _forward_dns(
    hostname: str,
    dns_servers: list[str] | None,
    resolver: "dns.resolver.Resolver | None",
) -> set[str]:
    cache_key = (_normalize_hostname(hostname), _dns_cache_key(dns_servers))
    with _dns_cache_lock:
        cached = _forward_dns_cache.get(cache_key)
    if cached is not None:
        return cached

    resolved: set[str] = set()
    if resolver is None:
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
                if family == socket.AF_INET:
                    resolved.add(sockaddr[0])
                elif family == socket.AF_INET6:
                    resolved.add(sockaddr[0])
        except socket.gaierror:
            resolved = set()
    else:
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname, record_type)
                for rdata in answers:
                    resolved.add(rdata.address)
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
                dns.resolver.NoNameservers,
            ):
                continue

    with _dns_cache_lock:
        _forward_dns_cache[cache_key] = resolved
    return resolved


def resolve_hostnames(
    ip: str,
    dns_servers: list[str] | None,
    resolver: "dns.resolver.Resolver | None",
) -> tuple[list[str], list[str]]:
    reverse_names = _reverse_dns(ip, dns_servers, resolver)
    verified = []
    for name in reverse_names:
        if ip in _forward_dns(name, dns_servers, resolver):
            verified.append(name)
    return reverse_names, verified


def build_dns_resolver(
    dns_servers: list[str] | None, timeout: float
) -> "dns.resolver.Resolver | None":
    if not dns_servers:
        return None
    if dns is None:
        raise RuntimeError("dnspython is required for custom DNS servers")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = dns_servers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


class Progress:
    def __init__(self, total: int) -> None:
        self.total = total
        self.processed = 0
        self.lock = threading.Lock()

    def increment(self) -> None:
        with self.lock:
            self.processed += 1

    def snapshot(self) -> tuple[int, int]:
        with self.lock:
            return self.processed, self.total


class ScanStats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.unique_thumbprints: set[str] = set()
        self.hosts_with_certs: set[str] = set()
        self.subject_names: set[str] = set()

    def record(self, ip: str, result: dict) -> None:
        thumbprint = result.get("thumbprint_sha1")
        common_name = result.get("common_name")
        sans = result.get("sans") or []
        with self.lock:
            if thumbprint:
                self.unique_thumbprints.add(thumbprint)
            self.hosts_with_certs.add(ip)
            if common_name:
                self.subject_names.add(common_name)
            for name in sans:
                if name:
                    self.subject_names.add(name)

    def snapshot(self) -> tuple[int, int, int]:
        with self.lock:
            return (
                len(self.unique_thumbprints),
                len(self.hosts_with_certs),
                len(self.subject_names),
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan internal IP ranges for TLS certificates and output JSON-formatted results."
        )
    )
    parser.add_argument(
        "--cidr",
        action="append",
        help=(
            "CIDR range to scan (repeatable). Defaults to RFC1918 ranges if omitted."
        ),
    )
    parser.add_argument(
        "--target",
        action="append",
        help="Target CIDR or DNS name to scan (repeatable).",
    )
    parser.add_argument(
        "--port",
        type=int,
        action="append",
        help="Port to scan (repeatable). Defaults to 443.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(512, (os.cpu_count() or 4) * 32),
        help="Number of worker threads. Default scales with CPU count.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Connection timeout in seconds.",
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=20000,
        help="Max queued targets waiting for workers.",
    )
    parser.add_argument(
        "--dns-server",
        action="append",
        help="DNS server to use for PTR/A/AAAA lookups (repeatable).",
    )
    parser.add_argument(
        "--json-lines",
        action="store_true",
        help="Output one JSON object per line instead of a JSON array.",
    )
    parser.add_argument(
        "--output",
        help="Write JSON output to a file instead of stdout.",
    )
    parser.add_argument(
        "--include-ip-results",
        action="store_true",
        help=(
            "Include IP-only TLS results even when hostname/SNI results are found."
        ),
    )
    parser.add_argument(
        "--no-reverse-dns",
        action="store_true",
        help="Disable reverse DNS lookups and verification.",
    )
    return parser.parse_args()


def iter_targets(cidrs: list[str], ports: list[int]):
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            ip_str = str(ip)
            for port in ports:
                yield ip_str, port, []


def iter_hostname_targets(ip_to_names: dict[str, list[str]], ports: list[int]):
    for ip, names in ip_to_names.items():
        for port in ports:
            yield ip, port, names


def count_targets(cidrs: list[str], ip_to_names: dict[str, list[str]], ports: list[int]) -> int:
    total_hosts = count_hosts(cidrs) + len(ip_to_names)
    return total_hosts * len(ports)


def count_hosts(cidrs: list[str]) -> int:
    total_hosts = 0
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version == 4:
            if network.prefixlen >= 31:
                host_count = network.num_addresses
            else:
                host_count = max(network.num_addresses - 2, 0)
        else:
            host_count = network.num_addresses
        total_hosts += host_count
    return total_hosts


def parse_targets(targets: list[str]) -> tuple[list[str], list[str]]:
    cidrs: list[str] = []
    hostnames: list[str] = []
    for target in targets:
        try:
            ipaddress.ip_network(target, strict=False)
            cidrs.append(target)
        except ValueError:
            hostnames.append(target)
    return cidrs, hostnames


def resolve_hostnames_to_ips(
    hostnames: list[str],
    dns_servers: list[str] | None,
    timeout: float,
) -> tuple[dict[str, list[str]], list[str]]:
    if not hostnames:
        return {}, []
    resolver = build_dns_resolver(dns_servers, timeout)
    ip_to_names: dict[str, list[str]] = {}
    unresolved: list[str] = []
    for hostname in hostnames:
        ips = _forward_dns(hostname, dns_servers, resolver)
        if not ips:
            unresolved.append(hostname)
            continue
        for ip in sorted(ips):
            ip_to_names.setdefault(ip, []).append(hostname)
    return ip_to_names, unresolved


def enqueue_targets(
    task_queue: queue.Queue,
    cidrs: list[str],
    ports: list[int],
    ip_to_names: dict[str, list[str]],
    worker_count: int,
) -> None:
    for target in iter_targets(cidrs, ports):
        task_queue.put(target)
    for target in iter_hostname_targets(ip_to_names, ports):
        task_queue.put(target)
    for _ in range(worker_count):
        task_queue.put(None)


def _thumbprint(cert_der: bytes | None, algo: str) -> str | None:
    if not cert_der:
        return None
    try:
        import hashlib

        return hashlib.new(algo, cert_der).hexdigest()
    except Exception:
        return None


def _format_serial_number(serial: int | None) -> str | None:
    if serial is None:
        return None
    hex_str = f"{serial:x}"
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    hex_str = hex_str.upper()
    return ":".join(hex_str[i : i + 2] for i in range(0, len(hex_str), 2))


def _parse_cert_details(cert_der: bytes | None) -> dict:
    if not cert_der:
        return {}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_der_x509_certificate(cert_der)
        signature_alg = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
        return {
            "serial_number": _format_serial_number(cert.serial_number),
            "signature_algorithm": signature_alg,
            "version": cert.version.name,
        }
    except Exception:
        return {}


def cert_to_result(
    ip: str,
    port: int,
    cert: dict,
    cert_der: bytes | None,
    scan_start: str,
) -> dict:
    subject = cert.get("subject", ())
    issuer = cert.get("issuer", ())

    common_name = ""
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                common_name = value
                break
        if common_name:
            break
    issuer_common_name = ""
    for rdn in issuer:
        for key, value in rdn:
            if key == "commonName":
                issuer_common_name = value
                break
        if issuer_common_name:
            break

    subject_str = "/".join(f"{key}={value}" for rdn in subject for key, value in rdn)
    issuer_str = "/".join(f"{key}={value}" for rdn in issuer for key, value in rdn)

    sans = [value for _, value in cert.get("subjectAltName", ())]
    parsed = _parse_cert_details(cert_der)
    
    return {
        "scan_date": scan_start,
        "ip": ip,
        "port": port,
        "common_name": common_name,
        "subject": subject_str,
        "issuer": issuer_str,
        "issuer_common_name": issuer_common_name,
        "serial_number": parsed.get("serial_number") or cert.get("serialNumber"),
        "thumbprint_sha1": _thumbprint(cert_der, "sha1"),
        "thumbprint_sha256": _thumbprint(cert_der, "sha256"),
        "signature_algorithm": parsed.get("signature_algorithm") or cert.get("signatureAlgorithm"),
        "version": parsed.get("version"),
        "valid_from": cert.get("notBefore"),
        "valid_to": cert.get("notAfter"),
        "subject_alternative_names": sans,
        "self_signed": subject == issuer,
        "scan_source": "Certographer",
    }


def scan_target(
    ip: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
    legacy_context: ssl.SSLContext | None,
    reverse_names: list[str],
    verified_names: list[str],
    scan_start: str,
    input_names: list[str],
    include_ip_results: bool,
) -> list[dict] | None:
    def _merge_names(*name_lists: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for names in name_lists:
            for name in names:
                normalized = _normalize_hostname(name)
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                merged.append(normalized)
        return merged
    def _decode_cert(cert_der: bytes | None) -> dict | None:
        if not cert_der:
            return None
        if not hasattr(ssl, "_ssl") or not hasattr(ssl._ssl, "_test_decode_cert"):
            return None
        pem = ssl.DER_cert_to_PEM_cert(cert_der)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                delete=False,
                prefix="cert_decode_",
            ) as tmp:
                tmp.write(pem)
                tmp.flush()
                tmp_path = tmp.name
            return ssl._ssl._test_decode_cert(tmp_path)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _fetch_cert(
        server_hostname: str | None, tls_context: ssl.SSLContext
    ) -> tuple[dict | None, bytes | None, str | None]:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with tls_context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cert_der = tls_sock.getpeercert(binary_form=True)
                if cert:
                    return cert, cert_der, tls_sock.version()
                return _decode_cert(cert_der), cert_der, tls_sock.version()

    def _fetch_for_ip() -> tuple[dict | None, bytes | None, str | None]:
        try:
            return _fetch_cert(ip, context)
        except ssl.SSLError:
            try:
                return _fetch_cert(None, context)
            except (OSError, ConnectionResetError, ssl.SSLError):
                if legacy_context is None:
                    return None, None, None
                try:
                    return _fetch_cert(ip, legacy_context)
                except ssl.SSLError:
                    try:
                        return _fetch_cert(None, legacy_context)
                    except (OSError, ConnectionResetError, ssl.SSLError):
                        return None, None, None
        except (OSError, ConnectionResetError):
            return None, None, None

    def _fetch_for_hostname(hostname: str) -> tuple[dict | None, bytes | None, str | None]:
        try:
            return _fetch_cert(hostname, context)
        except ssl.SSLError:
            if legacy_context is None:
                return None, None, None
            try:
                return _fetch_cert(hostname, legacy_context)
            except ssl.SSLError:
                return None, None, None
        except (OSError, ConnectionResetError):
            return None, None, None

    results: list[dict] = []

    candidate_names = _merge_names(input_names, verified_names, reverse_names)
    for hostname in candidate_names:
        cert, cert_der, tls_version = _fetch_for_hostname(hostname)
        if not cert:
            continue
        result = cert_to_result(ip, port, cert, cert_der, scan_start)
        result["tls_version"] = tls_version
        result["server_hostname"] = hostname
        result["reverse_dns"] = reverse_names
        result["reverse_dns_verified"] = verified_names
        results.append(result)

    if include_ip_results or not results:
        cert, cert_der, tls_version = _fetch_for_ip()
        if cert:
            result = cert_to_result(ip, port, cert, cert_der, scan_start)
            result["tls_version"] = tls_version
            result["server_hostname"] = ip
            result["reverse_dns"] = reverse_names
            result["reverse_dns_verified"] = verified_names
            results.append(result)

    if not results:
        return None
    return results


def worker(
    task_queue: queue.Queue,
    result_queue: queue.Queue,
    timeout: float,
    progress: Progress,
    dns_servers: list[str] | None,
    scan_start: str,
    stats: ScanStats,
    include_ip_results: bool,
    enable_reverse_dns: bool,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1

    legacy_context = None
    if hasattr(ssl, "TLSVersion"):
        legacy_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy_context.check_hostname = False
        legacy_context.verify_mode = ssl.CERT_NONE
        legacy_context.minimum_version = ssl.TLSVersion.TLSv1
        try:
            legacy_context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            legacy_context = None

    resolver = build_dns_resolver(dns_servers, timeout) if enable_reverse_dns else None

    while True:
        item = task_queue.get()
        if item is None:
            task_queue.task_done()
            break
        ip, port, input_names = item
        try:
            if enable_reverse_dns:
                reverse_names, verified_names = resolve_hostnames(ip, dns_servers, resolver)
            else:
                reverse_names, verified_names = [], []
            results = scan_target(
                ip,
                port,
                timeout,
                context,
                legacy_context,
                reverse_names,
                verified_names,
                scan_start,
                input_names,
                include_ip_results,
            )
            if results:
                for result in results:
                    stats.record(ip, result)
                    result_queue.put(result)
        except Exception:
            pass
        finally:
            progress.increment()
            task_queue.task_done()


def status_monitor(
    progress: Progress,
    workers: list[threading.Thread],
    stop_event: threading.Event,
) -> None:
    def _format_eta(seconds: float) -> str:
        if seconds <= 0:
            return "0s"
        seconds_int = int(seconds)
        hours, remainder = divmod(seconds_int, 3600)
        minutes, secs = divmod(remainder, 60)
        if hours:
            return f"{hours}h{minutes:02d}m{secs:02d}s"
        if minutes:
            return f"{minutes}m{secs:02d}s"
        return f"{secs}s"

    last_print = 0.0
    start_time = time.monotonic()
    while not stop_event.is_set():
        now = time.monotonic()
        if now - last_print < 0.2:
            time.sleep(0.05)
            continue
        processed, total = progress.snapshot()
        if total:
            percent = processed / total * 100
            elapsed = max(now - start_time, 0.001)
            rate = processed / elapsed if processed else 0.0
            remaining = ((total - processed) / rate) if rate else 0.0
            line = (
                f"Scanning: {processed}/{total} ({percent:5.1f}%) "
                f"ETA { _format_eta(remaining) }"
            )
        else:
            line = f"Scanning: {processed}"
        print(f"\r{line}", end="", file=os.sys.stderr)
        last_print = now
        if processed >= total and all(not w.is_alive() for w in workers):
            break
        time.sleep(0.05)
    processed, total = progress.snapshot()
    if total:
        if processed < total:
            processed = total
        line = f"Scanning: {processed}/{total} (100.0%)"
    else:
        line = f"Scanning: {processed}"
    print(f"\r{line}\n", end="", file=os.sys.stderr)


def stream_results(
    result_queue: queue.Queue,
    workers: list[threading.Thread],
    json_lines: bool,
    output_stream,
    progress: Progress,
) -> None:
    if json_lines:
        while True:
            try:
                result = result_queue.get(timeout=0.2)
            except queue.Empty:
                processed, total = progress.snapshot()
                if total and processed >= total and result_queue.empty():
                    break
                if not any(worker.is_alive() for worker in workers) and result_queue.empty():
                    break
                continue
            output_stream.write(json.dumps(result, separators=(",", ":")) + "\n")
            output_stream.flush()
            result_queue.task_done()
        return

    first = True
    output_stream.write("[")
    while True:
        try:
            result = result_queue.get(timeout=0.2)
        except queue.Empty:
            processed, total = progress.snapshot()
            if total and processed >= total and result_queue.empty():
                break
            if not any(worker.is_alive() for worker in workers) and result_queue.empty():
                break
            continue
        if not first:
            output_stream.write(",")
        output_stream.write(json.dumps(result, separators=(",", ":")))
        first = False
        result_queue.task_done()
    output_stream.write("]")
    output_stream.flush()


def main() -> None:
    args = parse_args()
    scan_start = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log_dir = "logs"
    if not os.path.isdir(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(
        log_dir, f"scan_{time.strftime('%Y%m%d_%H%M%S', time.gmtime())}.log"
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)sZ %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.FileHandler(log_path, encoding="utf-8")],
    )
    def _cleanup_old_logs(directory: str, max_age_days: int) -> int:
        cutoff = time.time() - (max_age_days * 24 * 60 * 60)
        removed = 0
        try:
            for name in os.listdir(directory):
                if not name.lower().endswith(".log"):
                    continue
                path = os.path.join(directory, name)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                        removed += 1
                except OSError:
                    logging.exception("Failed to remove old log: %s", path)
        except OSError:
            logging.exception("Failed to list log directory: %s", directory)
        return removed

    removed_logs = _cleanup_old_logs(log_dir, 30)
    if removed_logs:
        logging.info("Removed %s log file(s) older than 30 days", removed_logs)
    logging.info("Scan starting")
    logging.info("Args: %s", vars(args))
    if args.dns_server and dns is None:
        print(
            "Custom DNS servers require dnspython. Install requirements.txt first.",
            file=os.sys.stderr,
        )
        logging.error("Custom DNS servers requested but dnspython not installed.")
        return
    cidrs = list(args.cidr or [])
    target_cidrs: list[str] = []
    target_hostnames: list[str] = []
    if args.target:
        target_cidrs, target_hostnames = parse_targets(args.target)
        cidrs.extend(target_cidrs)
    if not cidrs and not target_hostnames:
        cidrs = list(DEFAULT_CIDRS)

    ports = args.port if args.port else list(DEFAULT_PORTS)
    logging.info("CIDRs: %s", cidrs)
    if target_hostnames:
        logging.info("Hostnames: %s", target_hostnames)
    logging.info("Ports: %s", ports)

    ip_to_names, unresolved = resolve_hostnames_to_ips(
        target_hostnames, args.dns_server, args.timeout
    )
    if unresolved:
        logging.warning("Unresolved hostnames: %s", unresolved)

    total_targets = count_targets(cidrs, ip_to_names, ports)
    total_hosts = count_hosts(cidrs) + len(ip_to_names)
    progress = Progress(total_targets)
    stats = ScanStats()
    logging.info("Total targets: %s", total_targets)
    logging.info("Total hosts: %s", total_hosts)
    logging.info("Workers: %s", args.workers)

    task_queue: queue.Queue = queue.Queue(maxsize=args.queue_size)
    result_queue: queue.Queue = queue.Queue()

    workers: list[threading.Thread] = []
    for _ in range(args.workers):
        thread = threading.Thread(
            target=worker,
            args=(
                task_queue,
                result_queue,
                args.timeout,
                progress,
                args.dns_server,
                scan_start,
                stats,
                args.include_ip_results,
                not args.no_reverse_dns,
            ),
            daemon=True,
        )
        thread.start()
        workers.append(thread)

    stop_event = threading.Event()
    monitor = threading.Thread(
        target=status_monitor,
        args=(progress, workers, stop_event),
        daemon=True,
    )
    monitor.start()

    producer = threading.Thread(
        target=enqueue_targets,
        args=(task_queue, cidrs, ports, ip_to_names, len(workers)),
        daemon=True,
    )
    producer.start()

    output_stream = None
    temp_output_path = None
    if args.output:
        output_dir = os.path.dirname(os.path.abspath(args.output)) or "."
        temp_file = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=output_dir,
            prefix=".scan_tmp_",
        )
        temp_output_path = temp_file.name
        output_stream = temp_file
    else:
        output_stream = os.sys.stdout

    try:
        stream_results(result_queue, workers, args.json_lines, output_stream, progress)
    finally:
        if args.output and output_stream is not None:
            output_stream.close()
            if temp_output_path is not None:
                os.replace(temp_output_path, args.output)

    producer.join()
    for thread in workers:
        thread.join()

    result_queue.join()
    task_queue.join()
    stop_event.set()
    monitor.join()
    unique_certs, hosts_with_certs, subject_names = stats.snapshot()
    logging.info(
        "Summary: unique_certs=%s hosts_scanned=%s hosts_with_certs=%s subject_names=%s",
        unique_certs,
        total_hosts,
        hosts_with_certs,
        subject_names,
    )
    logging.info("Scan complete")


if __name__ == "__main__":
    main()
