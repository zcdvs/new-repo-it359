"""
Fileless Malware Detection Script
IT 359 Final Project - Fileless Malware Research

This script detects potential fileless malware activity by monitoring
system behavior rather than scanning for file signatures.

It is designed to detect the behaviors used by the accompanying
fileless_simulation.ps1 script and C2 listener:
- Suspicious PowerShell command lines (e.g., -nop, -w hidden, -enc)
- PowerShell processes connecting to the C2 server/port

WARNING: This is for educational purposes only.
Only use in controlled lab environments.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import psutil

import json
import threading
import http.server
import socketserver
import requests
import urllib.parse

# Optional scapy for packet capture (used to extract HTTP response bodies)
try:
    from scapy.all import sniff, TCP, Raw, IP, conf  # type: ignore
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False

# Optional Windows-specific registry access
try:
    import winreg
except Exception:
    winreg = None

# Default values should match the C2 listener defaults.
# NOTE: In the recommended lab topology the C2 listener runs on a separate VM.
# For that reason, default host is '*' (any IP on the chosen port) rather than
# localhost, which would only detect a C2 running on the same machine.
DEFAULT_C2_HOST = os.getenv("IT359_C2_HOST", "*")
DEFAULT_C2_PORT = int(os.getenv("IT359_C2_PORT", "8080"))


SUSPICIOUS_POWERSHELL_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"-w\s*hidden", re.IGNORECASE),
    re.compile(r"-windowstyle\s*hidden", re.IGNORECASE),
    re.compile(r"-enc(odedcommand)?", re.IGNORECASE),
    re.compile(r"invoke-expression|iex", re.IGNORECASE),
    re.compile(r"fileless_simulation\.ps1", re.IGNORECASE),
    re.compile(r"-C2Server", re.IGNORECASE),
]

POWERSHELL_NAMES: Set[str] = {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}


def parse_c2_from_cmdline(cmdline: str) -> Tuple[Optional[str], Optional[int]]:
    """Best-effort extraction of -C2Server/-C2Port from the simulation command line."""

    if not cmdline:
        return None, None

    host: Optional[str] = None
    port: Optional[int] = None

    # Accept: -C2Server 1.2.3.4 or -C2Server "1.2.3.4"
    m_host = re.search(r"-C2Server\s+\"?([^\"\s]+)\"?", cmdline, re.IGNORECASE)
    if m_host:
        host = m_host.group(1).strip()

    m_port = re.search(r"-C2Port\s+(\d+)", cmdline, re.IGNORECASE)
    if m_port:
        try:
            port = int(m_port.group(1))
        except ValueError:
            port = None

    return host, port


@dataclass
class Detection:
    pid: int
    process_name: str
    severity: str
    reason: str
    cmdline: str


def is_powershell_process(proc: psutil.Process) -> bool:
    """Return True if the process looks like PowerShell or pwsh."""
    try:
        name = (proc.name() or "").lower()
        return name in POWERSHELL_NAMES
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def get_cmdline(proc: psutil.Process) -> str:
    try:
        return " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def detect_suspicious_cmdline(proc: psutil.Process) -> Optional[Detection]:
    if not is_powershell_process(proc):
        return None

    cmdline = get_cmdline(proc)
    if not cmdline:
        return None

    matched_patterns: List[str] = []
    for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
        if pattern.search(cmdline):
            matched_patterns.append(pattern.pattern)

    if matched_patterns:
        return Detection(
            pid=proc.pid,
            process_name=proc.name(),
            severity="HIGH",
            reason=f"Suspicious PowerShell command line (matched: {', '.join(matched_patterns)})",
            cmdline=cmdline,
        )

    return None


def detect_c2_connections(proc: psutil.Process, c2_host: str, c2_port: int) -> Optional[Detection]:
    """Detect if the process is connecting to the configured C2 host/port."""
    try:
        conns = proc.net_connections(kind="inet")  # type: ignore[arg-type]
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        # Common on Windows without elevated privileges.
        # Fallback: scan system-wide connections and filter by PID.
        try:
            conns = [c for c in psutil.net_connections(kind="inet") if c.pid == proc.pid]
        except Exception:
            return None

    cmdline = get_cmdline(proc)

    for conn in conns:
        if not conn.raddr:
            continue

        state = (conn.status or "").upper()
        if state and state in {"LISTEN", "CLOSED"}:
            continue

        r_ip, r_port = conn.raddr.ip, conn.raddr.port

        if r_port == c2_port:
            # treat IPv4/IPv6 loopback equivalently for localhost checks
            same_loopback = (c2_host in ("127.0.0.1", "::1") and r_ip in ("127.0.0.1", "::1"))
            if c2_host == "*" or r_ip == c2_host or same_loopback:
                severity = "HIGH" if is_powershell_process(proc) else "MEDIUM"
                return Detection(
                    pid=proc.pid,
                    process_name=proc.name(),
                    severity=severity,
                    reason=f"Process connected to C2 {r_ip}:{r_port}",
                    cmdline=cmdline,
                )
    # Final fallback: use netstat/ss parsing to find this PID connecting to the C2
    try:
        pids = find_pids_by_netstat(c2_host, c2_port)
        if proc.pid in pids:
            severity = "HIGH" if is_powershell_process(proc) else "MEDIUM"
            return Detection(
                pid=proc.pid,
                process_name=proc.name(),
                severity=severity,
                reason=f"Netstat indicates connection to C2 {c2_host}:{c2_port}",
                cmdline=cmdline,
            )
    except Exception:
        pass

    return None


def _parse_ip_port(addr: str) -> (Optional[str], Optional[int]):
    """Parse address like 127.0.0.1:8080 or [::1]:8080 into (ip, port)."""
    if not addr:
        return None, None
    addr = addr.strip()
    # Handle [::1]:8080
    if addr.startswith('[') and ']' in addr:
        ip = addr[1:addr.index(']')]
        rest = addr.split(']')[-1]
        if rest.startswith(':'):
            try:
                return ip, int(rest[1:])
            except Exception:
                return ip, None
        return ip, None
    # IPv4 or IPv6 without brackets
    parts = addr.rsplit(':', 1)
    if len(parts) == 2:
        ip, port = parts[0], parts[1]
        try:
            return ip, int(port)
        except Exception:
            return ip, None
    return addr, None


def find_pids_by_netstat(c2_host: str, c2_port: int) -> Set[int]:
    """Return a set of PIDs with connections to c2_host:c2_port using netstat/ss as a fallback.

    Works without psutil connection privileges in many environments.
    """
    pids: Set[int] = set()
    try:
        system = platform.system().lower()
        if system.startswith('win'):
            out = subprocess.check_output(["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                if parts[0] not in ("TCP", "UDP"):
                    continue
                # Windows: TCP LocalAddress ForeignAddress State PID
                if parts[0] == 'UDP':
                    if len(parts) < 4:
                        continue
                    foreign = parts[2]
                    pid = parts[-1]
                else:
                    if len(parts) < 5:
                        continue
                    foreign = parts[2]
                    pid = parts[-1]

                ip, port = _parse_ip_port(foreign)
                if port is None:
                    continue
                if port == c2_port and (c2_host == '*' or c2_host == ip or (c2_host == '127.0.0.1' and ip in ('127.0.0.1', '::1'))):
                    try:
                        pid_int = int(pid)
                        if pid_int > 0:
                            pids.add(pid_int)
                    except Exception:
                        continue
        else:
            # Try ss then netstat on Unix-like systems
            try:
                out = subprocess.check_output(["ss", "-ntp"], text=True, stderr=subprocess.DEVNULL)
            except Exception:
                out = subprocess.check_output(["netstat", "-ntp"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if f':{c2_port}' not in line:
                    continue
                # attempt to extract pid=NNN or last token with pid
                m = re.search(r'pid=(\d+)', line)
                if m:
                    try:
                        pid_int = int(m.group(1))
                        if pid_int > 0:
                            pids.add(pid_int)
                    except Exception:
                        pass
                else:
                    # fallback: look for a number in parentheses like users:("proc",pid,fd)
                    m2 = re.search(r'\b(\d{2,6})\b', line)
                    if m2:
                        try:
                            pid_int = int(m2.group(1))
                            if pid_int > 0:
                                pids.add(pid_int)
                        except Exception:
                            pass
    except Exception:
        # non-fatal fallback
        pass
    return pids


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP proxy handler that forwards requests to an upstream C2 and
    calls a callback when responses contain a 'command' field.

    Class attributes are set by the starter function `start_http_proxy`.
    """
    upstream_host: str = '127.0.0.1'
    upstream_port: int = 8081
    proxy_bind_host: str = '127.0.0.1'
    proxy_bind_port: int = 8080
    on_command_cb = None

    def log_message(self, format: str, *args) -> None:  # reduce noisy logs
        # Silence default http.server access logs; detector output is clearer.
        return

    def _handle(self):
        # Read request body if present
        try:
            length = int(self.headers.get('Content-Length', 0))
        except Exception:
            length = 0
        body = self.rfile.read(length) if length > 0 else None

        # Prepare headers for upstream
        headers = {k: v for k, v in self.headers.items()}
        headers['Host'] = f"{self.upstream_host}:{self.upstream_port}"

        # Build upstream URL
        url = urllib.parse.urlunparse(('http', f"{self.upstream_host}:{self.upstream_port}", self.path, '', '', ''))

        try:
            resp = requests.request(self.command, url, headers=headers, data=body, timeout=10)
        except Exception as exc:
            self.send_error(502, f"Bad gateway: {exc}")
            return

        # Relay response status and headers
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ("transfer-encoding", "connection"):
                continue
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(resp.content)
        except Exception:
            pass

        # Inspect JSON responses for 'command'
        try:
            data = resp.json()
        except Exception:
            data = None

        cmd = None
        if isinstance(data, dict):
            cmd = data.get('command')

        if cmd and callable(self.on_command_cb):
            client_ip, client_port = self.client_address
            # Attempt to map the client-side flow to a PID
            try:
                pid = find_pid_for_flow(client_ip, client_port, self.proxy_bind_host, self.proxy_bind_port)
            except Exception:
                pid = None
            try:
                self.on_command_cb(pid, cmd, data, (client_ip, client_port, self.upstream_host, self.upstream_port))
            except Exception:
                pass

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


def start_http_proxy(listen_host: str, listen_port: int, upstream_host: str, upstream_port: int, on_command_cb, debug: bool = False) -> None:
    """Start a simple threaded HTTP proxy that forwards to upstream C2.

    This server is intended for local lab use only. It should be started
    before the client begins making requests to the proxied host/port.
    """
    Handler = ProxyHTTPRequestHandler
    Handler.upstream_host = upstream_host
    Handler.upstream_port = upstream_port
    Handler.proxy_bind_host = listen_host
    Handler.proxy_bind_port = listen_port
    # Store the callback as a static function to avoid it becoming a bound
    # method on handler instances (which would receive `self` implicitly).
    Handler.on_command_cb = staticmethod(on_command_cb)

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = ThreadedHTTPServer((listen_host, listen_port), Handler)
    server.debug = debug

    try:
        print(f"[+] HTTP proxy listening on {listen_host}:{listen_port} forwarding to {upstream_host}:{upstream_port}")
        server.serve_forever()
    except Exception as exc:
        print(f"[!] Proxy server failed: {exc}")


def find_pid_for_flow(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[int]:
    """Attempt to map a TCP flow (src_ip:src_port -> dst_ip:dst_port) to a PID using psutil.net_connections.

    Returns PID if found, otherwise None.
    """
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                l = c.laddr
                r = c.raddr
            except Exception:
                continue
            if not l or not r:
                continue
            try:
                if l.ip == src_ip and l.port == src_port and r.ip == dst_ip and r.port == dst_port:
                    return c.pid
                if l.ip == dst_ip and l.port == dst_port and r.ip == src_ip and r.port == src_port:
                    return c.pid
            except Exception:
                continue
    except Exception:
        pass
    return None


def start_scapy_sniffer(c2_port: int, on_command_cb, iface: Optional[str] = None) -> None:
    """Start a scapy-based sniffer that extracts HTTP response bodies on the given TCP port.

    Calls on_command_cb(pid_or_none, command_str, parsed_json, flow_tuple)
    flow_tuple = (client_ip, client_port, server_ip, server_port)
    """
    if not HAS_SCAPY:
        print("[!] scapy not available; packet-capture disabled. Install scapy and Npcap, then run detector elevated.")
        return

    buffers: Dict[Tuple[str, int, str, int], bytes] = {}
    max_buf = 64 * 1024

    def _pkt_handler(pkt):
        try:
            if not pkt.haslayer(TCP):
                return
            if not pkt.haslayer(Raw):
                return
            raw = bytes(pkt[Raw].load)
            if not raw:
                return

            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]
            server_ip = ip_layer.src
            client_ip = ip_layer.dst
            server_port = int(tcp_layer.sport)
            client_port = int(tcp_layer.dport)

            flow_key = (server_ip, server_port, client_ip, client_port)
            buf = buffers.get(flow_key, b"") + raw

            # Trim leading noise until HTTP response is found
            idx = buf.find(b"HTTP/")
            if idx == -1:
                buffers[flow_key] = buf[-max_buf:]
                return
            if idx > 0:
                buf = buf[idx:]

            sep = buf.find(b"\r\n\r\n")
            if sep == -1:
                buffers[flow_key] = buf[-max_buf:]
                return

            headers = buf[:sep].decode('utf-8', errors='ignore')
            body = buf[sep + 4:]

            # Respect Content-Length if present
            m = re.search(r"content-length:\s*(\d+)", headers, re.IGNORECASE)
            if m:
                try:
                    length = int(m.group(1))
                except Exception:
                    length = None
                if length is not None and len(body) < length:
                    buffers[flow_key] = buf[-max_buf:]
                    return
                if length is not None:
                    body = body[:length]

            # Parse JSON body for command
            try:
                data = json.loads(body.decode('utf-8', errors='ignore'))
            except Exception:
                buffers[flow_key] = b""
                return
            if not isinstance(data, dict):
                buffers[flow_key] = b""
                return
            cmd = data.get('command')
            if not cmd:
                buffers[flow_key] = b""
                return

            # Try to map to PID (client side expected)
            pid = find_pid_for_flow(client_ip, client_port, server_ip, server_port)
            on_command_cb(pid, cmd, data, (client_ip, client_port, server_ip, server_port))
            buffers[flow_key] = b""
        except Exception:
            return

    # Prefer the loopback adapter on Windows when not specified.
    if iface is None and platform.system().lower().startswith('win'):
        try:
            for i in conf.ifaces.values():
                name = getattr(i, 'name', '') or str(i)
                if 'loopback' in name.lower():
                    iface = name
                    break
        except Exception:
            pass

    bpf = f"tcp port {c2_port}"
    try:
        sniff(filter=bpf, prn=_pkt_handler, store=False, iface=iface)
    except Exception as exc:
        msg = f"[!] Packet sniffer failed: {exc}. Ensure Npcap is installed and run detector with elevated privileges."
        if iface:
            msg += f" (iface={iface})"
        print(msg)


def detect_registry_persistence(seen: Dict[str, str]) -> None:
    """Detect Run key persistence for DemoApp (HKCU)."""
    if winreg is None:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\\Microsoft\\Windows\\CurrentVersion\\Run") as key:
            try:
                val, _ = winreg.QueryValueEx(key, 'DemoApp')
                if val and seen.get('registry') != val:
                    det = Detection(pid=0, process_name='registry', severity='MEDIUM', reason='Run key DemoApp present', cmdline=str(val))
                    print_detection(det)
                    seen['registry'] = val
            except FileNotFoundError:
                return
    except Exception:
        return


def detect_artifact_files(seen: Dict[str, str]) -> None:
    """Detect marker files the simulation may create in Live mode."""
    candidates = [r'C:\\temp\\execution_marker.txt', os.path.join(os.path.expanduser('~'), 'Desktop', 'HI.txt')]
    for path in candidates:
        try:
            if os.path.exists(path) and seen.get(path) != 'exists':
                det = Detection(pid=0, process_name='file', severity='LOW', reason=f'Artifact found: {path}', cmdline='')
                print_detection(det)
                seen[path] = 'exists'
        except Exception:
            continue

def score_process_behavior(proc: psutil.Process, c2_host: str, c2_port: int) -> Optional[Detection]:
    """Score process behavior instead of relying on one perfect indicator."""
    score = 0
    reasons: List[str] = []

    is_ps = is_powershell_process(proc)
    cmdline = get_cmdline(proc)

    if is_ps:
        score += 1
        reasons.append("PowerShell process observed")

    if cmdline:
        matched_patterns = []
        for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
            if pattern.search(cmdline):
                matched_patterns.append(pattern.pattern)

        if matched_patterns:
            score += 3
            reasons.append(f"suspicious command-line patterns: {', '.join(matched_patterns)}")

    # Network behavior
    try:
        conns = proc.net_connections(kind="inet")  # type: ignore[arg-type]
    except psutil.AccessDenied:
        try:
            conns = [c for c in psutil.net_connections(kind="inet") if c.pid == proc.pid]
        except Exception:
            conns = []
    except psutil.NoSuchProcess:
        return None

    outbound_count = 0
    c2_matches = []

    for conn in conns:
        if not conn.raddr:
            continue

        state = (conn.status or "").upper()
        if state in {"LISTEN", "CLOSED"}:
            continue

        r_ip = conn.raddr.ip
        r_port = conn.raddr.port
        outbound_count += 1

        if r_port == c2_port and (c2_host == "*" or r_ip == c2_host):
            c2_matches.append(f"{r_ip}:{r_port}")

    if is_ps and outbound_count > 0:
        score += 2
        reasons.append(f"PowerShell has outbound network activity ({outbound_count} connection(s))")

    if is_ps and c2_matches:
        score += 4
        reasons.append(f"PowerShell connected to configured C2 target(s): {', '.join(c2_matches)}")

    # Generic PowerShell command line plus network activity is suspicious in your lab.
    if is_ps and cmdline.lower().endswith("powershell.exe") and outbound_count > 0:
        score += 2
        reasons.append("generic PowerShell command line with outbound network behavior")

    if score >= 4:
        severity = "HIGH" if score >= 6 else "MEDIUM"
        return Detection(
            pid=proc.pid,
            process_name=proc.name(),
            severity=severity,
            reason=f"Behavior score {score}: " + "; ".join(reasons),
            cmdline=cmdline,
        )

    return None

def iter_processes() -> Iterable[psutil.Process]:
    """Safely iterate over processes."""
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            yield proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def print_detection(det: Detection) -> None:
    banner = "=" * 70
    print(banner)
    print(f"[DETECTION] Severity: {det.severity}")
    if det.pid:
        print(f"  PID: {det.pid}")
    print(f"  Process: {det.process_name}")
    print(f"  Reason: {det.reason}")
    if det.cmdline:
        print(f"  Cmdline: {det.cmdline}")
    print(banner)
    print()


def monitor(
    c2_host: str,
    c2_port: int,
    interval: float = 5.0,
    debug: bool = False,
    autodetect_c2: bool = True,
    pcap_iface: Optional[str] = None,
    enable_proxy: bool = False,
    proxy_listen_host: str = '127.0.0.1',
    proxy_listen_port: Optional[int] = None,
    proxy_upstream_host: str = '127.0.0.1',
    proxy_upstream_port: Optional[int] = None,
) -> None:
    """Continuously monitor for suspicious behavior.

    - Looks for suspicious PowerShell command lines
    - Looks for processes connecting to the C2 host/port
    """
    print("Fileless Malware Detector - IT 359 Final Project")
    print("=" * 60)
    print(f"[*] Monitoring for suspicious PowerShell activity...")
    print(f"[*] C2 target: {c2_host}:{c2_port} (host='*' means any IP on port {c2_port})")
    print(f"[*] Poll interval: {interval} seconds")
    if debug:
        print(f"[*] DEBUG MODE: ON (verbose output enabled)")
    print("[*] Press Ctrl+C to stop.\n")

    # seen_pid: track per-pid detection keys to avoid duplicate prints
    seen_pid: Dict[int, Set[str]] = {}
    # seen_global: track non-pid items like registry keys or files
    seen_global: Dict[str, str] = {}
    debug_count = 0

    # Beaconing detection state
    conn_history: Dict[int, List[float]] = {}
    netstat_history: Dict[int, List[float]] = {}
    prev_children: Dict[int, int] = {}
    prev_stats: Dict[int, Tuple[int, int, int, int]] = {}
    beacon_detected: Set[int] = set()
    BEACON_THRESHOLD = 2
    # Use a conservative expected interval (some clients beacon every 10s)
    expected_interval = max(interval, 10.0)
    BEACON_WINDOW_SECONDS = expected_interval * 3.0  # look for N hits within this window

    try:
        # Start packet-capture sniffer in background to extract C2 HTTP responses (commands)
        pcap_lock = threading.Lock()
        pcap_seen: Set[str] = set()

        def _on_pcap_command(pid: Optional[int], command: str, data: dict, flow: tuple) -> None:
            # Deduplicate
            key = f"pcap:{pid}:{command}"
            with pcap_lock:
                if key in pcap_seen:
                    return
                pcap_seen.add(key)

            # Map pid/name and cmdline where possible
            proc_name = str(pid or '')
            cmdline = ''
            if pid:
                try:
                    p = psutil.Process(pid)
                    proc_name = p.name()
                    cmdline = get_cmdline(p)
                except Exception:
                    pass

            det = Detection(
                pid=pid or 0,
                process_name=proc_name or 'unknown',
                severity='HIGH',
                reason=f'C2 command via packet capture: {command}',
                cmdline=cmdline,
            )
            print_detection(det)

        # Launch sniffer thread (non-blocking)
        sniffer_thread = threading.Thread(target=start_scapy_sniffer, args=(c2_port, _on_pcap_command, pcap_iface), daemon=True)
        sniffer_thread.start()

        # Optionally start HTTP proxy to intercept and forward C2 traffic
        if enable_proxy:
            proxy_listen_port = proxy_listen_port or c2_port
            proxy_upstream_port = proxy_upstream_port or (c2_port + 1)

            def _on_proxy_command(pid: Optional[int], command: str, data: dict, flow: tuple) -> None:
                key = f"proxy:{pid}:{command}"
                with pcap_lock:
                    if key in pcap_seen:
                        return
                    pcap_seen.add(key)

                proc_name = str(pid or '')
                cmdline = ''
                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                        cmdline = get_cmdline(p)
                    except Exception:
                        pass

                det = Detection(
                    pid=pid or 0,
                    process_name=proc_name or 'unknown',
                    severity='HIGH',
                    reason=f'C2 command via HTTP proxy: {command}',
                    cmdline=cmdline,
                )
                print_detection(det)

            proxy_thread = threading.Thread(
                target=start_http_proxy,
                args=(proxy_listen_host, proxy_listen_port, proxy_upstream_host, proxy_upstream_port, _on_proxy_command, debug),
                daemon=True,
            )
            proxy_thread.start()
            print(f"[!] Proxy enabled: ensure your C2 listener runs on {proxy_upstream_host}:{proxy_upstream_port} and clients point to {proxy_listen_host}:{proxy_listen_port}")

        while True:
            debug_count += 1
            powershell_procs = []
            
            for proc in iter_processes():
                # Ignore system/kernel pseudo-process entries (pid 0) to reduce noisy false positives
                try:
                    if proc.pid == 0:
                        continue
                except Exception:
                    continue

                cmdline = get_cmdline(proc)
                
                # Track PowerShell processes for debug output
                if is_powershell_process(proc):
                    powershell_procs.append((proc.pid, proc.name(), cmdline))
                
                # 1) Suspicious PowerShell command line
                det1 = detect_suspicious_cmdline(proc)
                if det1:
                    key = f"cmdline:{det1.cmdline[:200]}"
                    keys = seen_pid.setdefault(proc.pid, set())
                    if key not in keys:
                        print_detection(det1)
                        keys.add(key)
                    # do not `continue` here; continue checks for connections and behavior

                # 2) Connection to C2
                # If we're monitoring PowerShell and the simulation specifies a C2,
                # prefer that as a per-process target. This avoids requiring users to
                # hardcode IPs in the detector.
                host_eff = c2_host
                port_eff = c2_port
                if autodetect_c2 and is_powershell_process(proc):
                    h2, p2 = parse_c2_from_cmdline(cmdline)
                    if h2:
                        host_eff = h2
                    if p2:
                        port_eff = p2

                det2 = detect_c2_connections(proc, c2_host=host_eff, c2_port=port_eff)
                if det2:
                    # record a timestamp for beaconing heuristics
                    try:
                        ts = time.time()
                        conn_history.setdefault(proc.pid, []).append(ts)
                    except Exception:
                        ts = time.time()

                    # Only print if this specific connection detection key is new
                    conn_key = f"conn:{det2.reason}"
                    keys = seen_pid.setdefault(proc.pid, set())
                    if conn_key not in keys:
                        print_detection(det2)
                        keys.add(conn_key)

                    # check for beaconing behavior (N hits within window)
                    try:
                        hist = conn_history.get(proc.pid, [])
                        # drop old timestamps
                        hist = [t for t in hist if t >= ts - BEACON_WINDOW_SECONDS]
                        conn_history[proc.pid] = hist
                        if len(hist) >= BEACON_THRESHOLD and 'beacon' not in keys:
                            # compute average interval between hits
                            avg_interval = (hist[-1] - hist[0]) / max(1, len(hist) - 1)
                            det = Detection(
                                pid=proc.pid,
                                process_name=proc.name(),
                                severity='HIGH',
                                reason=f'Beaconing to C2 detected ({len(hist)} hits, avg interval {avg_interval:.1f}s)',
                                cmdline=cmdline,
                            )
                            print_detection(det)
                            keys.add('beacon')
                            beacon_detected.add(proc.pid)
                    except Exception:
                        pass

                    # child-process heuristic: if this PowerShell spawned children since last check
                    try:
                        children = proc.children(recursive=False)
                        cur_children = len(children)
                        prev = prev_children.get(proc.pid, 0)
                        child_key = 'child_spawn'
                        if cur_children > prev and child_key not in keys:
                            det = Detection(
                                pid=proc.pid,
                                process_name=proc.name(),
                                severity='MEDIUM',
                                reason=f'Possible remote command execution: new child processes observed ({cur_children} children)',
                                cmdline=cmdline,
                            )
                            print_detection(det)
                            keys.add(child_key)
                        prev_children[proc.pid] = cur_children
                    except Exception:
                        pass

                    continue

                # 3) Behavior score detection
                det3 = score_process_behavior(proc, c2_host=host_eff, c2_port=port_eff)
                if det3:
                    detection_key = f"behavior:{det3.reason[:200]}"
                    keys = seen_pid.setdefault(proc.pid, set())
                    if detection_key not in keys:
                        print_detection(det3)
                        keys.add(detection_key)
                    continue
            
            # Debug output: show PowerShell processes found
            if debug and debug_count % 3 == 0:  # Print every 3rd iteration to reduce spam
                if powershell_procs:
                    print(f"\n[DEBUG] Found {len(powershell_procs)} PowerShell process(es):")
                    for pid, name, cmd in powershell_procs:
                        print(f"  - PID {pid} ({name}): {cmd[:80]}..." if len(cmd) > 80 else f"  - PID {pid} ({name}): {cmd}")
                    print()

            # Fallback netstat-based detection for C2 connections (works without psutil net permissions)
            try:
                netstat_pids = find_pids_by_netstat(c2_host, c2_port)
                for pid in netstat_pids:
                    key = f'netstat:{c2_host}:{c2_port}'
                    ts = time.time()
                    netstat_history.setdefault(pid, []).append(ts)
                    keys = seen_pid.setdefault(pid, set())
                    if key not in keys:
                        try:
                            proc = psutil.Process(pid)
                            name = proc.name()
                            cmdline = get_cmdline(proc)
                        except Exception:
                            name = str(pid)
                            cmdline = ''
                        severity = 'HIGH' if name.lower() in POWERSHELL_NAMES else 'MEDIUM'
                        det = Detection(pid=pid, process_name=name, severity=severity, reason=f"Netstat: connection to C2 {c2_host}:{c2_port}", cmdline=cmdline)
                        print_detection(det)
                        keys.add(key)

                    # Beaconing check via repeated netstat sightings
                    try:
                        hist = netstat_history.get(pid, [])
                        hist = [t for t in hist if t >= ts - BEACON_WINDOW_SECONDS]
                        netstat_history[pid] = hist
                        if len(hist) >= BEACON_THRESHOLD and 'beacon' not in keys:
                            try:
                                proc = psutil.Process(pid)
                                name = proc.name()
                                cmdline = get_cmdline(proc)
                            except Exception:
                                name = str(pid)
                                cmdline = ''
                            avg_interval = (hist[-1] - hist[0]) / max(1, len(hist) - 1)
                            det = Detection(pid=pid, process_name=name, severity='HIGH', reason=f'Netstat beaconing: {len(hist)} sightings, avg interval {avg_interval:.1f}s', cmdline=cmdline)
                            print_detection(det)
                            keys.add('beacon')
                            beacon_detected.add(pid)
                    except Exception:
                        pass
            except Exception:
                pass

            # Registry persistence check (HKCU Run DemoApp)
            try:
                detect_registry_persistence(seen_global)
            except Exception:
                pass

            # Detect artifact files that may be written in Live mode
            try:
                detect_artifact_files(seen_global)
            except Exception:
                pass

            # Post-check: for any PID we've flagged as beaconing, look for runtime activity
            try:
                for pid in list(beacon_detected):
                    try:
                        p = psutil.Process(pid)
                    except Exception:
                        continue
                    try:
                        threads = p.num_threads()
                    except Exception:
                        threads = 0
                    try:
                        mem = p.memory_info().rss
                    except Exception:
                        mem = 0
                    try:
                        io = p.io_counters()
                        io_read = int(io.read_bytes)
                        io_write = int(io.write_bytes)
                    except Exception:
                        io_read = 0
                        io_write = 0

                    prev = prev_stats.get(pid)
                    keys = seen_pid.setdefault(pid, set())
                    if prev:
                        prev_threads, prev_mem, prev_read, prev_write = prev
                        # Heuristic: spike in threads or memory or IO suggests work (possible command execution)
                        if (threads > prev_threads + 2 or
                            mem > prev_mem + (1 << 20) or
                            (io_read - prev_read) > (1 << 16) or
                            (io_write - prev_write) > (1 << 16)):
                            try:
                                cmdline = get_cmdline(p)
                            except Exception:
                                cmdline = ''
                            post_key = 'postbeacon_activity'
                            if post_key not in keys:
                                det = Detection(pid=pid, process_name=p.name(), severity='MEDIUM', reason='Post-beacon activity: threads/memory/IO spike (possible command execution)', cmdline=cmdline)
                                print_detection(det)
                                keys.add(post_key)
                    prev_stats[pid] = (threads, mem, io_read, io_write)
            except Exception:
                pass

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Behavior-based fileless malware detector")
    parser.add_argument(
        "--c2-host",
        default=DEFAULT_C2_HOST,
        help=(
            "C2 host/IP to watch (use '*' for any IP). Default is '*' to support a separate C2 VM. "
            "You can also set IT359_C2_HOST env var."
        ),
    )
    parser.add_argument(
        "--c2-port",
        type=int,
        default=DEFAULT_C2_PORT,
        help="C2 port to watch (default: 8080; can also set IT359_C2_PORT env var)",
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to see all PowerShell processes")
    parser.add_argument(
        "--pcap-iface",
        default=None,
        help=(
            "Pcap interface name to sniff (optional). On Windows, the loopback adapter is auto-selected when available."
        ),
    )
    parser.add_argument(
        "--no-autodetect-c2",
        action="store_true",
        help="Disable per-process C2 host/port autodetection from PowerShell cmdline",
    )
    parser.add_argument("--enable-proxy", action="store_true", help="Enable local HTTP proxy to intercept/forward C2 traffic (run C2 on upstream port)")
    parser.add_argument("--proxy-listen-host", default="127.0.0.1", help="Proxy listen host (default: 127.0.0.1)")
    parser.add_argument("--proxy-listen-port", type=int, default=None, help="Proxy listen port (default: same as --c2-port)")
    parser.add_argument("--proxy-upstream-host", default="127.0.0.1", help="Upstream C2 host the proxy forwards to (default: 127.0.0.1)")
    parser.add_argument("--proxy-upstream-port", type=int, default=None, help="Upstream C2 port the proxy forwards to (default: c2-port+1)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic sanity check: psutil requires appropriate privileges for some info
    try:
        _ = psutil.pids()
    except Exception as exc:  # pragma: no cover - safety net
        print(f"[!] psutil error: {exc}")
        sys.exit(1)

    monitor(
        c2_host=args.c2_host,
        c2_port=args.c2_port,
        interval=args.interval,
        debug=args.debug,
        autodetect_c2=not args.no_autodetect_c2,
        pcap_iface=args.pcap_iface,
        enable_proxy=args.enable_proxy,
        proxy_listen_host=args.proxy_listen_host,
        proxy_listen_port=args.proxy_listen_port,
        proxy_upstream_host=args.proxy_upstream_host,
        proxy_upstream_port=args.proxy_upstream_port,
    )


if __name__ == "__main__":
    main()
