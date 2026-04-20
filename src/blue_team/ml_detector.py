"""
Machine Learning-Based Fileless Malware Detector
IT 359 Final Project - Fileless Malware Research

This script uses an AI model (via the college's OpenWebUI /api/chat/completions
endpoint) to classify process behavior as benign or potentially malicious.

It builds on the same behavioral ideas as detector.py, but instead of
hard-coded rules, it sends process features to the AI model and
interprets the response.

WARNING: This is for educational purposes only.
Only use in controlled lab environments.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

import psutil
import requests

# Defaults should align with your lab environment
DEFAULT_C2_HOST = "127.0.0.1"
DEFAULT_C2_PORT = 8080

# OpenWebUI / Sushi AI defaults
DEFAULT_AI_BASE_URL = "http://sushi.it.ilstu.edu:8080"
DEFAULT_MODEL_NAME = "translategemma:latest"  # replace if your instructor suggests another


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
class ProcessFeatures:
    pid: int
    name: str
    cmdline: str
    is_powershell: bool
    suspicious_flags: List[str]
    c2_connections: int
    c2_host_matched: bool


@dataclass
class MLDecision:
    label: str  # "malicious" or "benign" (or similar)
    score: float
    reason: str


def is_powershell(name: str) -> bool:
    return name.lower() in POWERSHELL_NAMES


def safe_cmdline(proc: psutil.Process) -> str:
    try:
        return " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def extract_process_features(proc: psutil.Process, c2_host: str, c2_port: int) -> Optional[ProcessFeatures]:
    """Extract basic behavioral features for a single process."""
    try:
        name = proc.name() or ""
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None

    cmdline = safe_cmdline(proc)

    # Suspicious flags (PowerShell-focused)
    suspicious: List[str] = []
    for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
        if pattern.search(cmdline):
            suspicious.append(pattern.pattern)

    # Network connections to C2
    c2_conns = 0
    host_match = False
    try:
        for conn in proc.connections(kind="inet"):  # type: ignore[arg-type]
            if not conn.raddr:
                continue
            r_ip, r_port = conn.raddr.ip, conn.raddr.port
            if r_port == c2_port:
                c2_conns += 1
                if c2_host == "*" or r_ip == c2_host:
                    host_match = True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

    return ProcessFeatures(
        pid=proc.pid,
        name=name,
        cmdline=cmdline,
        is_powershell=is_powershell(name),
        suspicious_flags=suspicious,
        c2_connections=c2_conns,
        c2_host_matched=host_match,
    )


def build_prompt(features: ProcessFeatures) -> str:
    """Create a prompt describing the process in a security context.

    We ask the AI to respond strictly with JSON so we can parse it.
    """
    suspicious_str = ", ".join(features.suspicious_flags) if features.suspicious_flags else "none"

    description = f"""
You are a cybersecurity analysis assistant.
You are given information about a single process on a Windows machine.
The process may be part of a fileless malware simulation that uses
PowerShell to beacon to an HTTP C2 server, or it may be benign.

Your task: Classify the process as either malicious or benign based on
its behavior and explain your reasoning.

Here is the process information:
- PID: {features.pid}
- Name: {features.name}
- Is PowerShell: {features.is_powershell}
- Command line: {features.cmdline}
- Suspicious flags/patterns: {suspicious_str}
- Number of connections to C2 port: {features.c2_connections}
- Connected to configured C2 host: {features.c2_host_matched}

Respond ONLY with a JSON object with the following fields:
  - "label": "malicious" or "benign" (or similar short label)
  - "score": a number between 0.0 and 1.0 representing how confident you are it is malicious
  - "reason": a short natural language explanation

Example response:
{{"label": "malicious", "score": 0.92, "reason": "PowerShell with -nop and C2 connections"}}
""".strip()

    return description


def call_openwebui(base_url: str, api_key: str, model: str, prompt: str) -> str:
    """Call the OpenWebUI /api/chat/completions endpoint and return the content string.

    This follows the pattern from example-ai-api-usage.js.
    """
    url = base_url.rstrip("/") + "/api/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "user", "content": prompt},
        ],
        "stream": False,
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    content = ""
    if isinstance(data, dict) and "choices" in data and isinstance(data["choices"], list) and data["choices"]:
        content = data["choices"][0].get("message", {}).get("content", "")
    elif isinstance(data, dict) and "result" in data:
        content = str(data["result"])

    return content.strip()


def parse_ml_decision(raw_text: str) -> Optional[MLDecision]:
    """Try to parse an MLDecision from the model's textual response.

    We expect JSON, but we defensively strip any surrounding text.
    """
    if not raw_text:
        return None

    # Try to find first '{' and last '}' to extract JSON
    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    json_str = raw_text[start : end + 1]
    try:
        obj = json.loads(json_str)
    except json.JSONDecodeError:
        return None

    label = str(obj.get("label", "unknown"))
    try:
        score = float(obj.get("score", 0.0))
    except (TypeError, ValueError):
        score = 0.0
    reason = str(obj.get("reason", ""))

    return MLDecision(label=label, score=score, reason=reason)


def analyze_process_with_ai(
    features: ProcessFeatures,
    base_url: str,
    api_key: str,
    model: str,
) -> Optional[MLDecision]:
    prompt = build_prompt(features)
    try:
        raw = call_openwebui(base_url=base_url, api_key=api_key, model=model, prompt=prompt)
    except requests.RequestException as exc:
        print(f"[!] AI API request failed for PID {features.pid}: {exc}")
        return None

    decision = parse_ml_decision(raw)
    if decision is None:
        print(f"[!] Could not parse AI response for PID {features.pid}. Raw response:\n{raw[:300]}\n")
    return decision


def iter_processes() -> Iterable[psutil.Process]:
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            yield proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def print_detection(features: ProcessFeatures, decision: MLDecision) -> None:
    banner = "=" * 70
    print(banner)
    print("[ML DETECTION]")
    print(f"  PID: {features.pid}")
    print(f"  Process: {features.name}")
    print(f"  Label: {decision.label}")
    print(f"  Score: {decision.score:.2f}")
    print(f"  Reason: {decision.reason}")
    print(f"  Cmdline: {features.cmdline}")
    print(banner)
    print()


def monitor(
    c2_host: str,
    c2_port: int,
    interval: float,
    ai_base_url: str,
    ai_api_key: str,
    model_name: str,
    threshold: float,
    max_processes_per_cycle: int,
) -> None:
    print("ML-Based Fileless Malware Detector - IT 359 Final Project")
    print("=" * 60)
    print(f"[*] Using AI endpoint: {ai_base_url}")
    print(f"[*] Model: {model_name}")
    print(f"[*] C2 target: {c2_host}:{c2_port} (host='*' means any IP on port {c2_port})")
    print(f"[*] Malicious score threshold: {threshold}")
    print(f"[*] Max processes per cycle: {max_processes_per_cycle}")
    print(f"[*] Poll interval: {interval} seconds")
    print("[*] Press Ctrl+C to stop.\n")

    # Cache decisions per (pid, cmdline) so we don't re-query the AI frequently
    cache: Dict[Tuple[int, str], MLDecision] = {}

    try:
        while True:
            count = 0
            for proc in iter_processes():
                if count >= max_processes_per_cycle:
                    break

                features = extract_process_features(proc, c2_host=c2_host, c2_port=c2_port)
                if features is None:
                    continue

                key = (features.pid, features.cmdline)
                if key in cache:
                    decision = cache[key]
                else:
                    decision = analyze_process_with_ai(
                        features,
                        base_url=ai_base_url,
                        api_key=ai_api_key,
                        model=model_name,
                    )
                    if decision is None:
                        continue
                    cache[key] = decision

                if decision.score >= threshold or decision.label.lower() in {"malicious", "suspicious"}:
                    print_detection(features, decision)

                count += 1

            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] ML monitoring stopped by user.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ML/AI-based fileless malware detector (OpenWebUI)")
    parser.add_argument("--c2-host", default=DEFAULT_C2_HOST, help="C2 host/IP to watch (use '*' for any IP, default: 127.0.0.1)")
    parser.add_argument("--c2-port", type=int, default=DEFAULT_C2_PORT, help="C2 port to watch (default: 8080)")
    parser.add_argument("--interval", type=float, default=10.0, help="Polling interval in seconds (default: 10.0)")
    parser.add_argument("--threshold", type=float, default=0.7, help="Score threshold for malicious classification (default: 0.7)")
    parser.add_argument("--max-processes", type=int, default=10, help="Max processes to analyze per cycle (default: 10)")
    parser.add_argument("--ai-base-url", default=DEFAULT_AI_BASE_URL, help="Base URL of OpenWebUI server (default: http://sushi.it.ilstu.edu:8080)")
    parser.add_argument("--model", default=DEFAULT_MODEL_NAME, help="Model name to use (default: translategemma:latest)")
    parser.add_argument("--api-key-env", default="SUSHI_API_KEY", help="Env var name that stores the API key (default: SUSHI_API_KEY)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        print(f"[!] Missing API key: set environment variable {args.api_key_env} with your OpenWebUI API key.")
        sys.exit(1)

    # Basic sanity check that psutil works
    try:
        _ = psutil.pids()
    except Exception as exc:  # pragma: no cover - safety net
        print(f"[!] psutil error: {exc}")
        sys.exit(1)

    monitor(
        c2_host=args.c2_host,
        c2_port=args.c2_port,
        interval=args.interval,
        ai_base_url=args.ai_base_url,
        ai_api_key=api_key,
        model_name=args.model,
        threshold=args.threshold,
        max_processes_per_cycle=args.max_processes,
    )


if __name__ == "__main__":
    main()
