import socket
import threading
import ipaddress
import queue
from typing import List, Dict, Optional
from tqdm import tqdm

_SCAPY_AVAILABLE = False
try:
    from scapy.all import IP, TCP, sr1, send, conf
    conf.verb = 0
    _SCAPY_AVAILABLE = True
except ImportError:
    pass


class NetworkScanner:
    """Multi-threaded network port scanner.

    Supports two scan strategies:
      syn     — stealth SYN scan via Scapy (requires root)
      connect — full TCP connect scan; no root needed, also grabs service banners
    """

    def __init__(
        self,
        target: str,
        ports: str = "1-1000",
        max_threads: int = 50,
        timeout: float = 1.0,
        scan_type: str = "syn",
    ):
        self.target = target
        self.ports_to_scan = self._parse_ports(ports)
        self.max_threads = max_threads
        self.timeout = timeout
        self.scan_type = scan_type
        self.open_ports: List[Dict] = []
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.scanned_ports = 0

    def _parse_ports(self, port_spec: str) -> List[int]:
        ports = []
        for part in port_spec.split(","):
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def _get_hosts(self) -> List[str]:
        try:
            network = ipaddress.ip_network(self.target, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return [self.target]

    def _syn_scan_port(self, host: str, port: int) -> bool:
        """Returns True if port is open (SYN/ACK received). Requires root."""
        syn = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(syn, timeout=self.timeout, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
            return True
        return False

    def _connect_scan_port(self, host: str, port: int) -> tuple:
        """Returns (is_open, banner_or_None). No root required."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                banner = None
                try:
                    sock.settimeout(self.timeout)
                    sock.sendall(b"\r\n")
                    raw = sock.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
                return True, banner
        except (ConnectionRefusedError, OSError):
            return False, None

    def _scan_worker(self, port_queue: queue.Queue, host: str, progress: tqdm, scan_type: str):
        while not self.stop_event.is_set():
            try:
                port = port_queue.get(timeout=0.1)
            except queue.Empty:
                break  # queue exhausted — exit cleanly (no deadlock)

            is_open = False
            banner: Optional[str] = None
            try:
                if scan_type == "connect":
                    is_open, banner = self._connect_scan_port(host, port)
                else:
                    is_open = self._syn_scan_port(host, port)

                if is_open:
                    with self.lock:
                        self.open_ports.append({"port": port, "banner": banner})
                    msg = f"Port {port}: OPEN"
                    if banner:
                        msg += f" | {banner[:80]}"
                    tqdm.write(msg)

            except Exception as e:
                err = str(e)
                if "Permission denied" in err or "Operation not permitted" in err:
                    tqdm.write(
                        "[!] Permission denied. SYN scan needs root. "
                        "Re-run with sudo, or use --scan-type connect."
                    )
                    self.stop_event.set()
                else:
                    tqdm.write(f"[!] Error on port {port}: {err}")
            finally:
                with self.lock:
                    self.scanned_ports += 1
                progress.update(1)
                port_queue.task_done()

    def scan(self) -> List[Dict]:
        """Run the scan and return list of per-host result dicts."""
        import os

        hosts = self._get_hosts()

        scan_type = self.scan_type
        if scan_type == "syn":
            if not _SCAPY_AVAILABLE:
                print("[!] Scapy not available. Falling back to connect scan.")
                scan_type = "connect"
            elif os.name != "nt" and os.geteuid() != 0:
                print("[!] WARNING: SYN scan usually requires root privileges.")
                print("[!] Tip: use --scan-type connect to scan without root.\n")

        all_results: List[Dict] = []

        for host in hosts:
            self.open_ports = []
            self.scanned_ports = 0
            self.stop_event.clear()

            port_queue: queue.Queue = queue.Queue()
            for port in self.ports_to_scan:
                port_queue.put(port)

            n_ports = len(self.ports_to_scan)
            print(f"\nScanning {host} ({n_ports} ports, {scan_type} scan) ...")

            with tqdm(total=n_ports, unit="port", desc=host) as progress:
                threads = [
                    threading.Thread(
                        target=self._scan_worker,
                        args=(port_queue, host, progress, scan_type),
                        daemon=True,
                    )
                    for _ in range(min(self.max_threads, n_ports))
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

            open_sorted = sorted(self.open_ports, key=lambda e: e["port"])
            print(f"\nHost {host}: {len(open_sorted)} open port(s)")
            if open_sorted:
                for entry in open_sorted:
                    line = f"  {entry['port']}/tcp OPEN"
                    if entry.get("banner"):
                        line += f"  {entry['banner'][:80]}"
                    print(line)

            all_results.append({"host": host, "open_ports": open_sorted})

        return all_results
