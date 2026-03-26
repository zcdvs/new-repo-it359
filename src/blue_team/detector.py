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
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

import psutil

# Default values should match the C2 listener defaults
DEFAULT_C2_HOST = "127.0.0.1"
DEFAULT_C2_PORT = 8080


SUSPICIOUS_POWERSHELL_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"-nop", re.IGNORECASE),
    re.compile(r"-noprofile", re.IGNORECASE),
    re.compile(r"-w\s*hidden", re.IGNORECASE),
    re.compile(r"-windowstyle\s*hidden", re.IGNORECASE),
    re.compile(r"-enc(odedcommand)?", re.IGNORECASE),
    re.compile(r"invoke-expression|iex", re.IGNORECASE),
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
        conns = proc.connections(kind="inet")  # type: ignore[arg-type]
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


def monitor(c2_host: str, c2_port: int, interval: float = 5.0) -> None:
    """Continuously monitor for suspicious behavior.

    - Looks for suspicious PowerShell command lines
    - Looks for processes connecting to the C2 host/port
    """
    print("Fileless Malware Detector - IT 359 Final Project")
    print("=" * 60)
    print(f"[*] Monitoring for suspicious PowerShell activity...")
    print(f"[*] C2 target: {c2_host}:{c2_port} (host='*' means any IP on port {c2_port})")
    print(f"[*] Poll interval: {interval} seconds")
    print("[*] Press Ctrl+C to stop.\n")

    seen: Dict[int, str] = {}

    try:
        while True:
            for proc in iter_processes():
                # Skip already seen benign processes (by PID and cmdline string)
                cmdline = get_cmdline(proc)
                key = (proc.pid, cmdline)
                cache_val = seen.get(proc.pid)
                if cache_val == cmdline:
                    continue

                # 1) Suspicious PowerShell command line
                det1 = detect_suspicious_cmdline(proc)
                if det1:
                    print_detection(det1)
                    seen[proc.pid] = det1.cmdline
                    continue

                # 2) Connection to C2
                det2 = detect_c2_connections(proc, c2_host=c2_host, c2_port=c2_port)
                if det2:
                    print_detection(det2)
                    seen[proc.pid] = det2.cmdline
                    continue

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Behavior-based fileless malware detector")
    parser.add_argument("--c2-host", default=DEFAULT_C2_HOST, help="C2 host/IP to watch (use '*' for any IP, default: 127.0.0.1)")
    parser.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT, help="C2 port to watch (default: 8080)")
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Basic sanity check: psutil requires appropriate privileges for some info
    try:
        _ = psutil.pids()
    except Exception as exc:  # pragma: no cover - safety net
        print(f"[!] psutil error: {exc}")
        sys.exit(1)

    monitor(c2_host=args.c2_host, c2_port=args.c2_port, interval=args.interval)


if __name__ == "__main__":
    main()
