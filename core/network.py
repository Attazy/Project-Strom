import asyncio
import ipaddress
import socket
import time
from contextlib import suppress
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from utils.logger import setup_logger

logger = setup_logger('network')

# Conservative concurrency defaults so we do not overwhelm the target by accident.
DEFAULT_TIMEOUT = 2.0
DEFAULT_CONCURRENCY = 200
DEFAULT_RETRIES = 1


class _EventLoopRunner:
    """Utility wrapper to run async coroutines from sync code safely."""

    @staticmethod
    def run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


def resolve_targets(target: str) -> List[str]:
    """Expand a single target expression (CIDR, range, hostname) into concrete IPs."""
    target = target.strip()
    if not target:
        return []

    resolved: List[str] = []

    with suppress(ValueError):
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]

    if '-' in target and '/' not in target:
        base, _, range_part = target.partition('-')
        try:
            start_ip = ipaddress.ip_address(base)
            end_ip = ipaddress.ip_address(range_part)
        except ValueError:
            # Handle shorthand like 10.0.0.1-10
            prefix, _, last_octet = base.rpartition('.')
            with suppress(ValueError):
                start_ip = ipaddress.ip_address(base)
                end_ip = ipaddress.ip_address(f"{prefix}.{range_part}")
        else:
            pass

        try:
            current = int(start_ip)
            limit = int(end_ip)
            step = 1 if current <= limit else -1
            for value in range(current, limit + step, step):
                resolved.append(str(ipaddress.ip_address(value)))
            return resolved
        except (UnboundLocalError, ValueError):
            resolved.clear()

    with suppress(socket.gaierror):
        addr = socket.gethostbyname(target)
        return [addr]

    with suppress(ValueError):
        ip = ipaddress.ip_address(target)
        return [str(ip)]

    logger.warning(f"Unable to resolve target expression: {target}")
    return resolved


def normalize_ports(ports: Sequence[int]) -> List[int]:
    """Sanitize port collections and keep ordering stable."""
    cleaned = sorted({p for p in ports if isinstance(p, int) and 0 < p < 65536})
    return cleaned


async def _probe_connect(host: str, port: int, timeout: float) -> Tuple[int, Optional[float]]:
    start = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        with suppress(Exception):
            await writer.wait_closed()
        return port, time.perf_counter() - start
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, None


async def _connect_scan(host: str, ports: Sequence[int], timeout: float, concurrency: int, retries: int) -> Dict[int, float]:
    semaphore = asyncio.Semaphore(concurrency)
    results: Dict[int, float] = {}

    async def task(port: int):
        async with semaphore:
            attempt = 0
            latency: Optional[float] = None
            while attempt <= retries and latency is None:
                attempt += 1
                port, latency = await _probe_connect(host, port, timeout)
            if latency is not None:
                results[port] = latency

    await asyncio.gather(*(task(port) for port in ports))
    return results


def tcp_connect_scan(host: str,
                     ports: Sequence[int],
                     timeout: float = DEFAULT_TIMEOUT,
                     concurrency: int = DEFAULT_CONCURRENCY,
                     retries: int = DEFAULT_RETRIES) -> Dict[int, float]:
    """High-performance asynchronous TCP connect scan."""
    ports = normalize_ports(ports)
    if not ports:
        return {}
    logger.debug(f"Running TCP connect scan on {host} for {len(ports)} ports")
    return _EventLoopRunner.run(_connect_scan(host, ports, timeout, concurrency, retries))


def syn_scan(host: str, ports: Sequence[int], timeout: float = DEFAULT_TIMEOUT) -> Dict[int, float]:
    """Perform a SYN scan using scapy for stealth discovery."""
    try:
        from scapy.all import IP, TCP, sr1
    except ImportError as exc:
        logger.error("Scapy is required for SYN scanning: %s", exc)
        return {}

    ports = normalize_ports(ports)
    if not ports:
        return {}

    latencies: Dict[int, float] = {}
    for port in ports:
        pkt = IP(dst=host) / TCP(dport=port, flags='S')
        start = time.perf_counter()
        try:
            response = sr1(pkt, timeout=timeout, verbose=0)
        except PermissionError as exc:
            logger.warning("SYN scan unavailable without raw socket privileges: %s", exc)
            return {}
        except OSError as exc:
            logger.debug(f"SYN probe error on {host}:{port} -> {exc}")
            continue
        if response and response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK
                latencies[port] = time.perf_counter() - start
    return latencies


def udp_scan(host: str, ports: Sequence[int], timeout: float = DEFAULT_TIMEOUT) -> Dict[int, Optional[str]]:
    """Lightweight UDP scan with simple payload heuristics."""
    payload_map = {
        53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
        123: b"\x1b" + b"\0" * 47,
        161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x70\x0f\x9f\x36\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    }

    results: Dict[int, Optional[str]] = {}

    for port in normalize_ports(ports):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                payload = payload_map.get(port, b"\0")
                sock.sendto(payload, (host, port))
                data, _ = sock.recvfrom(1024)
                results[port] = data.hex()
        except socket.timeout:
            results[port] = None
        except OSError as exc:
            logger.debug(f"UDP probe error on {host}:{port} -> {exc}")
    return results


CLOUD_HINTS: Dict[str, Dict[str, Sequence[str]]] = {
    'AWS': {'prefixes': ('3.', '13.', '15.', '18.', '34.', '44.', '52.', '54.', '100.'), 'rdns': ('amazonaws.com', 'awsdns')},
    'Azure': {'prefixes': ('13.', '20.', '40.', '52.', '104.'), 'rdns': ('cloudapp.azure.com', 'microsoft.com', 'azure.com')},
    'GCP': {'prefixes': ('34.', '35.', '104.', '107.', '108.', '146.', '199.'), 'rdns': ('googleusercontent.com', 'googlecloud.com')},
    'OCI': {'prefixes': ('129.146.', '129.213.', '130.35.', '140.238.'), 'rdns': ('oraclecloud.com',)},
}


def detect_cloud_provider(ip: str) -> Dict[str, str]:
    """Heuristic cloud provider detection using IP prefixes and reverse DNS."""
    findings: Dict[str, str] = {}

    with suppress(ValueError):
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            findings['note'] = 'Private address space'
            return findings

    prefix_match = []
    for provider, hints in CLOUD_HINTS.items():
        if any(ip.startswith(prefix) for prefix in hints['prefixes']):
            prefix_match.append(provider)

    rdns_match: List[str] = []
    with suppress(socket.herror, socket.gaierror, UnicodeError):
        hostname = socket.gethostbyaddr(ip)[0]
        for provider, hints in CLOUD_HINTS.items():
            if any(token in hostname for token in hints['rdns']):
                rdns_match.append(provider)
        if hostname:
            findings['ptr'] = hostname

    if prefix_match:
        findings['prefix_hint'] = ', '.join(sorted(set(prefix_match)))
    if rdns_match:
        findings['rdns_hint'] = ', '.join(sorted(set(rdns_match)))

    if not findings:
        findings['note'] = 'Provider not confidently identified'

    return findings


def enrich_host_metadata(ip: str) -> Dict[str, str]:
    """Collect lightweight metadata for a host (reverse DNS, provider hints)."""
    metadata = detect_cloud_provider(ip)
    return metadata


def port_scan(target: str, ports: Iterable[int], timeout: float = DEFAULT_TIMEOUT) -> List[int]:
    """Legacy helper retained for backwards compatibility."""
    scan_result = tcp_connect_scan(target, ports, timeout=timeout)
    return sorted(scan_result.keys())

