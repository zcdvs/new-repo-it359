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
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import psutil

# Default values should match the C2 listener defaults.
# NOTE: In the recommended lab topology the C2 listener runs on a separate VM.
# For that reason, default host is '*' (any IP on the chosen port) rather than
# localhost, which would only detect a C2 running on the same machine.
DEFAULT_C2_HOST = os.getenv("IT359_C2_HOST", "*")
DEFAULT_C2_PORT = int(os.getenv("IT359_C2_PORT", "8080"))


SUSPICIOUS_POWERSHELL_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"-nop", re.IGNORECASE),
    re.compile(r"-noprofile", re.IGNORECASE),
    re.compile(r"-w\s*hidden", re.IGNORECASE),
    re.compile(r"-windowstyle\s*hidden", re.IGNORECASE),
    re.compile(r"-enc(odedcommand)?", re.IGNORECASE),
    re.compile(r"invoke-expression|iex", re.IGNORECASE),
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

        # Skip listeners/closed sockets; keep established-ish outbound states.
        state = (conn.status or "").upper()
        if state and state in {"LISTEN", "CLOSED"}:
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


def monitor(
    c2_host: str,
    c2_port: int,
    interval: float = 5.0,
    debug: bool = False,
    autodetect_c2: bool = True,
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
    parser.add_argument("--interval", type=float, default=5.0, help="Polling interval in seconds (default: 5.0)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to see all PowerShell processes")
    parser.add_argument(
        "--no-autodetect-c2",
        action="store_true",
        help="Disable per-process C2 host/port autodetection from PowerShell cmdline",
    )
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
    )


if __name__ == "__main__":
    main()
