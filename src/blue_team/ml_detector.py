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
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

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
    """Cheap local pre-filter to avoid sending every process to the model.

    Prefer high-signal command-line indicators over just process name.
    """
    name = (proc.get("name") or "").lower()
    cmd = (proc.get("cmdline") or "").lower()

    if "powershell" not in name and "pwsh" not in name:
        return False

    # High-signal flags / behaviors often seen in fileless tooling
    high_signal = [
        "-enc",
        "-encodedcommand",
        "encodedcommand",
        "-nop",
        "-noprofile",
        "-w hidden",
        "-windowstyle hidden",
        "invoke-expression",
    "iex",
        "frombase64string",
        "downloadstring",
        "downloaddata",
        "invoke-webrequest",
        "invoke-restmethod",
        "new-object net.webclient",
    ]

    return any(k in cmd for k in high_signal)


def local_risk_score(proc: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Return (score, reasons) based on local heuristics."""

    cmd = (proc.get("cmdline") or "")
    cmd_l = cmd.lower()
    score = 0
    reasons: List[str] = []

    indicators = [
        (r"\b-enc\b|\b-encodedcommand\b", 5, "encoded command"),
        (r"\b-nop\b|\b-noprofile\b", 2, "no profile"),
        (r"-w\s+hidden|-windowstyle\s+hidden", 2, "hidden window"),
        (r"frombase64string", 4, "base64 decode"),
        (r"invoke-expression|\biex\b", 3, "Invoke-Expression"),
        (r"downloadstring|downloaddata|new-object\s+net\.webclient", 4, "download cradle"),
        (r"invoke-webrequest|invoke-restmethod", 2, "HTTP client"),
    ]

    for pattern, pts, label in indicators:
        if re.search(pattern, cmd_l):
            score += pts
            reasons.append(label)

    # Very long command lines can be a weak signal (obfuscation / one-liners)
    if len(cmd) > 250:
        score += 1
        reasons.append("long cmdline")

    return score, reasons


def build_model_prompt(features: Dict[str, Any], score: int, reasons: List[str]) -> str:
    return (
        "You are a blue-team process-behavior classifier. "
        "Given process features, return STRICT JSON ONLY (no markdown) with keys: "
        "verdict (one of benign|suspicious|malicious), confidence (0-1), reasons (array of strings).\n"
        f"LocalHeuristicScore: {score}\n"
        f"LocalHeuristicReasons: {reasons}\n"
        f"ProcessFeatures: {json.dumps(features, ensure_ascii=False)}\n"
    )


def parse_model_json(text: str) -> Optional[Dict[str, Any]]:
    """Attempt to parse JSON even if the model prepends/appends extra text."""
    if not text:
        return None

    # First try: whole string
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass

    # Fallback: extract first {...} block
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    try:
        obj = json.loads(text[start : end + 1])
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def classify_process_behavior(prompt: str) -> str:
    """Send a single prompt to the model and return raw text."""
    model_name = os.getenv("ML_DETECTOR_MODEL", "gemini-3-flash-preview")
    response = client.models.generate_content(model=model_name, contents=prompt)
    return response.text

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
        max_per_cycle = int(os.getenv("ML_DETECTOR_MAX_PER_CYCLE", "3"))
        min_score_for_ai = int(os.getenv("ML_DETECTOR_MIN_SCORE", "5"))

        # Dedupe: remember which processes we've already scored (pid, create_time, cmdline hash)
        seen_keys: set[Tuple[int, Optional[float], int]] = set()
        known_pids: set[int] = set()

        while True:
            snapshot = iter_processes()

            # Track new processes since last poll (lightweight detection signal)
            new_procs = [p for p in snapshot if isinstance(p.get("pid"), int) and p["pid"] not in known_pids]
            for p in new_procs:
                known_pids.add(p["pid"])

            # Only consider candidates with a meaningful signal.
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

                score, reasons = local_risk_score(proc)
                features["local_score"] = score
                features["local_reasons"] = reasons

                pid = features.get("pid")
                create_time = features.get("create_time")
                cmd_hash = hash(features.get("cmdline") or "")
                proc_key = (int(pid) if isinstance(pid, int) else -1, float(create_time) if isinstance(create_time, (int, float)) else None, cmd_hash)
                if proc_key in seen_keys:
                    continue
                seen_keys.add(proc_key)

                # Only escalate to AI if score is high enough
                if score < min_score_for_ai:
                    continue

                prompt = build_model_prompt(features, score, reasons)
                result = classify_process_behavior(prompt)
                parsed = parse_model_json(result)

                print("\n[AI] Process classification:")
                print(json.dumps(features, indent=2))
                print(result)

                verdict = None
                confidence = None
                if parsed:
                    verdict = (parsed.get("verdict") or "").lower()
                    confidence = parsed.get("confidence")

                if verdict in {"suspicious", "malicious"}:
                    with open("suspicious_processes.log", "a", encoding="utf-8") as log_file:
                        log_file.write(
                            json.dumps(
                                {
                                    "features": features,
                                    "verdict": verdict,
                                    "confidence": confidence,
                                    "model_output": parsed or result,
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

            time.sleep(poll_seconds)
    except Exception as e:
        import traceback
        print(f"Error occurred: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()