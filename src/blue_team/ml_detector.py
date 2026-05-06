""" 
Machine Learning-Based Fileless Malware Detector
IT 359 Final Project - Fileless Malware Research

This script uses an AI model (via the Gemini API) to classify process behavior
as benign or potentially malicious.

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


# ---------------------------------------------------------------------------
# Process collection and low-cost local heuristics
# ---------------------------------------------------------------------------


def iter_processes() -> List[Dict[str, Any]]:
    """Return a snapshot of running processes with common fields.

    Notes:
    - Cross-platform via psutil.
    - Some fields may be missing due to permissions; we default safely.

    Returns:
        A list of dicts. Each dict attempts to include:
        - pid (int)
        - name (str)
        - cmdline (str)
        - user (str)
        - host (str)
        - create_time (float | None)
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

    This is intentionally conservative: it should reduce AI calls and noise.

    Current implementation focuses on PowerShell/pwsh plus common fileless
    indicators (encoded commands, hidden windows, download cradles, etc.).
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

    return any(k in cmd for k in map(str.lower, high_signal))


def is_powershell_family(proc: Dict[str, Any]) -> bool:
    """True for PowerShell-style processes.

    This is used for a broader "real-time monitor" mode where we may want to
    at least score/log PowerShell sessions even if their command line is bland.
    """

    name = (proc.get("name") or "").lower()
    return "powershell" in name or "pwsh" in name


def get_env_bool(name: str, default: bool) -> bool:
    """Parse environment variable booleans like 1/0, true/false, yes/no."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def local_risk_score(proc: Dict[str, Any]) -> Tuple[int, List[str]]:
    """Return (score, reasons) based on local heuristics.

    This is a lightweight scoring step used to decide whether a process is
    worth sending to the LLM.

    Returns:
        score: Integer risk score (higher = more suspicious)
        reasons: Human-readable list of why points were added
    """

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
        (r"frombase64string", 4, "base64 decode"),
        (r"(?<![a-zA-Z0-9])base64(?![a-zA-Z0-9])", 4, "base64 decode"),
        (r"(?<![a-zA-Z0-9])b64(?![a-zA-Z0-9])", 4, "base64 decode"),
        (r"(?<![a-zA-Z0-9])data:(?![a-zA-Z0-9])", 4, "data URI"),
        (r"(?<![a-zA-Z0-9])blob:(?![a-zA-Z0-9])", 4, "blob URI"),
        (r"(?<![a-zA-Z0-9])file:(?![a-zA-Z0-9])", 4, "file URI"),
        (r"(?<![a-zA-Z0-9])http(?![a-zA-Z0-9])", 2, "HTTP in cmdline"),
        (r"(?<![a-zA-Z0-9])Invoke-WebRequest(?![a-zA-Z0-9])", 3, "Invoke-WebRequest")
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


def count_remote_connections(pid: int) -> Tuple[int, List[str]]:
    """Return (count, remote_endpoints) for established/outbound connections.

    This is a portable-ish behavior signal for LiveMode beaconing.
    It won't catch everything, but it's often enough to detect HTTP beacons.
    """

    remotes: List[str] = []
    try:
        p = psutil.Process(pid)
        for c in p.net_connections(kind="inet"):
            if not c.raddr:
                continue
            # On Windows/macOS/Linux: raddr is typically an (ip, port) tuple
            ip = getattr(c.raddr, "ip", None) or (c.raddr[0] if isinstance(c.raddr, tuple) else None)
            port = getattr(c.raddr, "port", None) or (c.raddr[1] if isinstance(c.raddr, tuple) else None)
            state = (c.status or "").upper()
            if state in {"ESTABLISHED", "SYN_SENT"}:
                remotes.append(f"{ip}:{port}")
    except Exception:
        # AccessDenied is common without admin; treat as unknown rather than failing.
        return 0, []

    # Return unique endpoints but keep a stable list for logging.
    remotes_unique = sorted(set([r for r in remotes if r and "None" not in r]))
    return len(remotes_unique), remotes_unique


def build_model_prompt(features: Dict[str, Any], score: int, reasons: List[str]) -> str:
    """Build an instruction prompt that requests strict JSON from the model.

    Why JSON?
    - It reduces the need for brittle substring matching (e.g., "malicious").
    - It makes logging and downstream automation easier.
    """
    return (
        "You are a blue-team process-behavior classifier. "
        "Return STRICT JSON ONLY (no markdown, no prose, no code fences). "
        "The JSON object MUST have exactly these keys: "
        "verdict, confidence, reasons, process_id_explanation. "
        "\n"
        "- verdict: one of 'benign' | 'suspicious' | 'malicious'\n"
        "- confidence: integer 0-10\n"
        "- reasons: array of short strings explaining the verdict\n"
        "- process_id_explanation: a 1-3 sentence plain-English explanation of what the process ID (pid) represents for *this* process on the host, and why it helps investigation\n"
        "\n"
        f"LocalHeuristicScore: {score}\n"
        f"LocalHeuristicReasons: {reasons}\n"
        f"ProcessFeatures: {json.dumps(features, ensure_ascii=False)}\n"
    )


def parse_model_json(text: str) -> Optional[Dict[str, Any]]:
    """Attempt to parse JSON even if the model prepends/appends extra text.

    Models sometimes wrap JSON in prose. This helper tries:
    1) Parse the entire response as JSON.
    2) If that fails, extract the first {...} block and parse it.
    """
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
    """Send a single prompt to the model and return raw text.

    Configuration:
        ML_DETECTOR_MODEL: model name (default: gemma-4-31b-it)
    """
    model_name = os.getenv("ML_DETECTOR_MODEL", "gemma-4-31b-it")
    response = client.models.generate_content(model=model_name, contents=prompt)
    return response.text


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def main():
    print("Initializing AI model...")
    response = client.models.generate_content(
        model="gemma-4-31b-it", contents="Explain how AI works in a few words in simple terms, specifically focusing on cybersecurity."
    )
    print(f"Response text: {response.text}")
    print("----------------------------------------------------------------")
    print("Monitoring running processes. Press Ctrl+C to stop.")

        # Tuning knobs (environment variables)
        # - ML_DETECTOR_POLL_SECONDS: polling interval
        # - ML_DETECTOR_MAX_PER_CYCLE: max candidates sent to AI per poll
        # - ML_DETECTOR_MIN_SCORE: minimum local heuristic score before AI
        # - ML_DETECTOR_SCAN_MODE: "new" (default) or "all"
        #       new: only processes first observed after the detector starts
        #       all: re-check running processes each poll (with throttle)
        # - ML_DETECTOR_DEBUG: print why items are/aren't escalated
    poll_seconds = float(os.getenv("ML_DETECTOR_POLL_SECONDS", "5"))
    min_score_for_ai = int(os.getenv("ML_DETECTOR_MIN_SCORE", "2"))

    # For LiveMode beaconing, "all" is usually the right default because
    # the PowerShell host process may already exist before the detector starts.
    scan_mode = os.getenv("ML_DETECTOR_SCAN_MODE", "all").strip().lower()
    debug = get_env_bool("ML_DETECTOR_DEBUG", False)
    show_scores = get_env_bool("ML_DETECTOR_SHOW_SCORES", True)

    # In "all" mode, avoid hammering the same long-running process.
    # Re-check a (pid, cmdline) at most every N seconds.
    throttle_seconds = float(os.getenv("ML_DETECTOR_THROTTLE_SECONDS", "60"))
    last_checked: Dict[Tuple[int, int], float] = {}

    # Tracking set used to detect *new* processes between polls.
    known_pids: set[int] = set()

    while True:
        snapshot = iter_processes()

        # Per-cycle counters (for a concise "is it working?" summary)
        scanned_count = 0
        nonzero_score_count = 0
        escalated_to_ai_count = 0
        powershell_seen_count = 0

        # Choose candidates depending on scan mode.
        # - new: only look at newly observed PIDs
        # - all: look at all running processes each poll (throttled)
        if scan_mode == "all":
            procs = [p for p in snapshot if isinstance(p.get("pid"), int)]
        else:
            procs = [
                p
                for p in snapshot
                if isinstance(p.get("pid"), int) and p["pid"] not in known_pids
            ]
            for p in procs:
                known_pids.add(p["pid"])

        # Step 1: iterate candidates
        for proc in procs:
            scanned_count += 1
            features = {
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "cmdline": proc.get("cmdline"),
                "user": proc.get("user"),
                "host": proc.get("host"),
                "create_time": proc.get("create_time"),
            }

            # Step 2: local scoring (avoid AI unless there's enough signal)
            score, reasons = local_risk_score(proc)
            features["local_score"] = score
            features["local_reasons"] = reasons

            if score > 0:
                nonzero_score_count += 1

            # LiveMode behavior signal: PowerShell process making outbound connections.
            pid_val = features.get("pid")
            conn_count = 0
            remotes: List[str] = []
            if isinstance(pid_val, int) and pid_val > 0:
                conn_count, remotes = count_remote_connections(pid_val)
                if conn_count > 0:
                    # Weight network activity fairly high.
                    score += 4
                    reasons.append("outbound network connections")
                    features["local_score"] = score
                    features["local_reasons"] = reasons

            features["remote_connection_count"] = conn_count
            features["remote_endpoints"] = remotes

            # Optional: add a low-cost "suspicious cmdline" hint.
            # If this is false and the score is low, it's likely benign.
            features["cmdline_high_signal"] = looks_suspicious(proc)

            is_ps = is_powershell_family(proc)
            if is_ps:
                powershell_seen_count += 1

            if show_scores:
                # Reduce noise: only print per-process lines when there's any local signal.
                # Also print PowerShell-family processes so demos are easier to follow.
                if score > 0 or is_ps:
                    print(
                        f"[monitor] pid={features.get('pid')} name={features.get('name')} "
                        f"score={features.get('local_score')} reasons={features.get('local_reasons')} "
                        f"remotes={features.get('remote_connection_count', 0)}"
                    )

            pid = features.get("pid")
            create_time = features.get("create_time")
            cmd_hash = hash(features.get("cmdline") or "")
            proc_key = (
                int(pid) if isinstance(pid, int) else -1,
                float(create_time) if isinstance(create_time, (int, float)) else None,
                cmd_hash,
            )

            # Additional throttle for scan_mode=all
            pid_i = int(pid) if isinstance(pid, int) else -1
            cmd_hash2 = hash(features.get("cmdline") or "")
            throttle_key = (pid_i, cmd_hash2)
            now = time.time()
            last = last_checked.get(throttle_key)
            if scan_mode == "all" and last is not None and (now - last) < throttle_seconds:
                if debug:
                    print(
                        f"[debug] throttled pid={pid_i} ({int(now - last)}s since last check)"
                    )
                continue
            last_checked[throttle_key] = now

            # Step 4: AI escalation threshold
            if score < min_score_for_ai:
                if debug:
                    print(
                        f"[debug] skip-ai pid={features.get('pid')} name={features.get('name')} "
                        f"score={score} reasons={reasons} cmdline_high_signal={features.get('cmdline_high_signal')}"
                    )
                continue

            escalated_to_ai_count += 1
            prompt = build_model_prompt(features, score, reasons)
            result = classify_process_behavior(prompt)
            parsed = parse_model_json(result)

            # Step 5: output + optional logging of suspicious/malicious verdicts
            print("\n[AI] Process classification:")
            print(json.dumps(features, indent=2))
            print(result)

            verdict = None
            confidence = None
            pid_explanation = None
            if parsed:
                verdict = (parsed.get("verdict") or "").lower()
                confidence = parsed.get("confidence")
                pid_explanation = parsed.get("process_id_explanation")

            if pid_explanation:
                print(f"[AI] PID explanation: {pid_explanation}")

            if verdict in {"suspicious", "malicious"}:
                with open("suspicious_processes.log", "a", encoding="utf-8") as log_file:
                    log_file.write(
                        json.dumps(
                            {
                                "features": features,
                                "verdict": verdict,
                                "confidence": confidence,
                                "process_id_explanation": pid_explanation,
                                "model_output": parsed or result,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

        # Concise cycle summary so users can tell the tool is alive even when nothing is suspicious.
        # Only emit when per-process printing didn't produce much signal.
        if show_scores and (nonzero_score_count == 0 and escalated_to_ai_count == 0):
            print(
                f"[cycle] scanned={scanned_count} nonzero_scores={nonzero_score_count} "
                f"powershell_seen={powershell_seen_count} escalated_to_ai={escalated_to_ai_count} (no alerts)"
            )

        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()