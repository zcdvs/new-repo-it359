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
from typing import Dict, Iterable, List, Optional, Set

import psutil

# Optional Windows-specific registry access
try:
    import winreg
except Exception:
    winreg = None

# Default values should match the C2 listener defaults
DEFAULT_C2_HOST = "127.0.0.1"
DEFAULT_C2_PORT = 8080


SUSPICIOUS_POWERSHELL_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"-w\s*hidden", re.IGNORECASE),
    re.compile(r"-windowstyle\s*hidden", re.IGNORECASE),
    re.compile(r"-enc(odedcommand)?", re.IGNORECASE),
    re.compile(r"invoke-expression|iex", re.IGNORECASE),
    re.compile(r"fileless_simulation\.ps1", re.IGNORECASE),
    re.compile(r"-C2Server", re.IGNORECASE),
]

POWERSHELL_NAMES: Set[str] = {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}


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
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    cmdline = get_cmdline(proc)
    for conn in conns:
        if not conn.raddr:
            continue
        r_ip, r_port = conn.raddr.ip, conn.raddr.port
        if r_port == c2_port and (c2_host == "*" or r_ip == c2_host):
            severity = "HIGH" if is_powershell_process(proc) else "MEDIUM"
            return Detection(
                pid=proc.pid,
                process_name=proc.name(),
                severity=severity,
                reason=f"Process connected to C2 {r_ip}:{r_port}",
                cmdline=cmdline,
            )

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
    print(f"  PID: {det.pid}")
    print(f"  Process: {det.process_name}")
    print(f"  Reason: {det.reason}")
    print(f"  Cmdline: {det.cmdline}")
    print(banner)
    print()


def monitor(c2_host: str, c2_port: int, interval: float = 5.0, debug: bool = False) -> None:
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

    seen: Dict[int, str] = {}
    debug_count = 0

    try:
        while True:
            debug_count += 1
            powershell_procs = []
            
            for proc in iter_processes():
                cmdline = get_cmdline(proc)
                
                # Track PowerShell processes for debug output
                if is_powershell_process(proc):
                    powershell_procs.append((proc.pid, proc.name(), cmdline))
                
                # 1) Suspicious PowerShell command line
                det1 = detect_suspicious_cmdline(proc)
                if det1:
                    # Only print if this is a new detection for this process
                    if seen.get(proc.pid) != cmdline:
                        print_detection(det1)
                        seen[proc.pid] = cmdline
                    continue

                # 2) Connection to C2
                det2 = detect_c2_connections(proc, c2_host=c2_host, c2_port=c2_port)
                if det2:
                    # Only print if this is a new detection for this process
                    if seen.get(proc.pid) != cmdline:
                        print_detection(det2)
                        seen[proc.pid] = cmdline
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
                    if seen.get(pid) != key:
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
                        seen[pid] = key
            except Exception:
                pass

            # Registry persistence check (HKCU Run DemoApp)
            try:
                detect_registry_persistence(seen)
            except Exception:
                pass

            # Detect artifact files that may be written in Live mode
            try:
                detect_artifact_files(seen)
            except Exception:
                pass

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Behavior-based fileless malware detector")
    parser.add_argument("--c2-host", default=DEFAULT_C2_HOST, help="C2 host/IP to watch (use '*' for any IP, default: 127.0.0.1)")
    parser.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT, help="C2 port to watch (default: 8080)")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to see all PowerShell processes")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic sanity check: psutil requires appropriate privileges for some info
    try:
        _ = psutil.pids()
    except Exception as exc:  # pragma: no cover - safety net
        print(f"[!] psutil error: {exc}")
        sys.exit(1)

    monitor(c2_host=args.c2_host, c2_port=args.c2_port, interval=args.interval, debug=args.debug)


if __name__ == "__main__":
    main()
