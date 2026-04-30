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

import json
import os
import socket
import time
from typing import Any, Dict, Iterable, List, Optional

import psutil
from google import genai

# The client gets the API key from the environment variable `GEMINI_API_KEY`.
client = genai.Client()


def iter_processes() -> List[Dict[str, Any]]:
    """Return a snapshot of running processes with common fields.

    Notes:
    - Cross-platform via psutil.
    - Some fields may be missing due to permissions; we default safely.
    """

    host = socket.gethostname()
    procs: List[Dict[str, Any]] = []

    for p in psutil.process_iter(
        attrs=["pid", "name", "username", "cmdline", "create_time"],
        ad_value=None,
    ):
        info = p.info
        cmdline = info.get("cmdline")
        if isinstance(cmdline, list):
            cmdline_str = " ".join([c for c in cmdline if c])
        else:
            cmdline_str = cmdline or ""

        procs.append(
            {
                "pid": info.get("pid"),
                "name": info.get("name") or "",
                "cmdline": cmdline_str,
                "user": info.get("username") or "",
                "host": host,
                "create_time": info.get("create_time"),
            }
        )

    return procs


def looks_suspicious(proc: Dict[str, Any]) -> bool:
    """Cheap local pre-filter to avoid sending every process to the model."""
    name = (proc.get("name") or "").lower()
    cmd = (proc.get("cmdline") or "").lower()

    keywords = [
        "powershell",
        "pwsh",
        "-enc",
        "encodedcommand",
        "invoke-expression",
        "iex",
        "wmi",
        "ciminstance",
        "frombase64string",
    ]

    return any(k in name or k in cmd for k in keywords)

def classify_process_behavior(features: dict) -> str:
    response = client.models.generate_content(
        model="gemini-3-flash-preview", contents=str(features)
    )
    return response.text

def identify_suspicious_processes(processes: list) -> list:
    suspicious_processes = []
    for proc in processes:
        features = {
            "pid": proc["pid"],
            "name": proc["name"],
            "cmdline": proc["cmdline"],
            "user": proc["user"],
            "host": proc["host"]
        }
        result = classify_process_behavior(features)
        if "malicious" in result.lower():
            suspicious_processes.append(proc)
    return suspicious_processes

def main():
    try:
        print("Initializing AI model...")
        response = client.models.generate_content(
            model="gemini-3-flash-preview", contents="Explain how AI works in a few words"
        )
        print(f"Response text: {response.text}")
        print("----------------------------------------------------------------")
        print("Monitoring running processes. Press Ctrl+C to stop.")

        poll_seconds = float(os.getenv("ML_DETECTOR_POLL_SECONDS", "2"))
        max_per_cycle = int(os.getenv("ML_DETECTOR_MAX_PER_CYCLE", "5"))

        known_pids: set[int] = set()
        while True:
            snapshot = iter_processes()

            # Track new processes since last poll (lightweight detection signal)
            new_procs = [p for p in snapshot if isinstance(p.get("pid"), int) and p["pid"] not in known_pids]
            for p in new_procs:
                known_pids.add(p["pid"])

            # Only send a small number of suspicious processes to the model each cycle
            candidates = [p for p in new_procs if looks_suspicious(p)]
            if not candidates:
                time.sleep(poll_seconds)
                continue

            to_check = candidates[:max_per_cycle]
            for proc in to_check:
                features = {
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "cmdline": proc.get("cmdline"),
                    "user": proc.get("user"),
                    "host": proc.get("host"),
                    "create_time": proc.get("create_time"),
                }
                result = classify_process_behavior(features)

                print("\n[AI] Process classification:")
                print(json.dumps(features, indent=2))
                print(result)

                if "malicious" in (result or "").lower():
                    with open("suspicious_processes.log", "a", encoding="utf-8") as log_file:
                        log_file.write(json.dumps({"features": features, "model_output": result}) + "\n")

            time.sleep(poll_seconds)
    except Exception as e:
        import traceback
        print(f"Error occurred: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()