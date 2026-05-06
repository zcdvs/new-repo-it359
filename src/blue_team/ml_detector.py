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


def trunc(s: str, max_len: int = 160) -> str:
    """Return a single-line truncated string for console-safe display."""
    s = (s or "").replace("\r", " ").replace("\n", " ").strip()
    return s if len(s) <= max_len else (s[: max_len - 1] + "…")


def fmt_ai_summary(
    *,
    pid: Any,
    name: Any,
    score: int,
    verdict: Optional[str],
    confidence: Any,
    reasons: Optional[List[str]],
    conn_count: int,
) -> str:
    verdict_s = verdict or "unknown"
    conf_s = "?" if confidence is None else str(confidence)
    top_reasons = ", ".join((reasons or [])[:3])
    return (
        f"\n[AI] pid={pid} name={name} score={score} remotes={conn_count} "
        f"verdict={verdict_s} confidence={conf_s} reasons=[{trunc(top_reasons, 140)}]\n"
    )


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
        "new-object net.webclient"
    ]

    return any(k in cmd for k in map(str.lower, high_signal))


def is_powershell_family(proc: Dict[str, Any]) -> bool:
    """True for PowerShell-style processes.

    This is used for a broader "real-time monitor" mode where we may want to
    at least score/log PowerShell sessions even if their command line is bland.
    """

    name = (proc.get("name") or "").lower()
    return "powershell" in name or "pwsh" in name


def maybe_read_powershell_history_lines(max_lines: int = 200) -> List[str]:
    """Best-effort read of PowerShell PSReadLine history (Windows).

    This is OPTIONAL and intended for lab demos when the cmdline doesn't include
    the actual interactive commands (e.g., user types `iex ...` inside a shell).

    Controlled by env var:
      ML_DETECTOR_READ_PS_HISTORY=1

    Returns:
      A list of recent history lines (lowercased, stripped). On failure returns [].
    """

    if os.name != "nt":
        return []

    if os.getenv("ML_DETECTOR_READ_PS_HISTORY", "0").strip().lower() not in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }:
        return []

    appdata = os.getenv("APPDATA") or ""
    if not appdata:
        return []

    # Typical path: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    hist_path = os.path.join(
        appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"
    )
    try:
        with open(hist_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip().lower() for ln in f.read().splitlines() if ln.strip()]
        return lines[-max_lines:]
    except Exception:
        return []


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
    (r"(?<![a-zA-Z0-9])invoke-webrequest(?![a-zA-Z0-9])", 3, "Invoke-WebRequest"),
    # If the script is launched with -File, the cmdline may not show IEX/etc.
    # Catch our lab simulation script/file name as a high-signal indicator.
    (r"fileless_simulation\.ps1", 6, "fileless simulation script"),
    # Catch key function names from the simulation even if invoked indirectly.
    (r"\b(send-beacon|invoke-memoryexecution|get-systemrecon|show-registrypersistence)\b", 4, "matches simulation technique name"),
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
            # Include additional states that frequently show up during short beacons.
            # TIME_WAIT/CLOSE_WAIT can still indicate recent outbound activity.
            if state in {"ESTABLISHED", "SYN_SENT", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "TIME_WAIT"}:
                remotes.append(f"{ip}:{port}")
    except Exception:
        # AccessDenied is common without admin on Windows; optionally fall back to a
        # system-wide scan and filter by pid.
        if os.getenv("ML_DETECTOR_CONN_FALLBACK", "1").strip().lower() not in {"1", "true", "yes", "y", "on"}:
            return 0, []
        try:
            for c in psutil.net_connections(kind="inet"):
                if getattr(c, "pid", None) != pid:
                    continue
                if not c.raddr:
                    continue
                ip = getattr(c.raddr, "ip", None) or (c.raddr[0] if isinstance(c.raddr, tuple) else None)
                port = getattr(c.raddr, "port", None) or (c.raddr[1] if isinstance(c.raddr, tuple) else None)
                state = (c.status or "").upper()
                if state in {"ESTABLISHED", "SYN_SENT", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "TIME_WAIT"}:
                    remotes.append(f"{ip}:{port}")
        except Exception:
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
    try:
        response = client.models.generate_content(model="gemma-4-31b-it", contents=prompt)
        return response.text or ""
    except Exception as e:
        # Keep the monitor running even if the model call fails.
        return json.dumps(
            {
                "verdict": "suspicious",
                "confidence": 0,
                "reasons": [f"model_call_failed: {type(e).__name__}: {e}"],
                "process_id_explanation": (
                    "PID is the operating system's identifier for a running process. "
                    "Use it to correlate this alert with Task Manager, process command line, and network connections."
                ),
            },
            ensure_ascii=False,
        )


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def main():
    print("Initializing AI model...")
    try:
        response = client.models.generate_content(
            model="gemma-4-31b-it",
            contents=(
                "Explain how AI works in a few words in simple terms, specifically focusing on cybersecurity."
            ),
        )
        print(f"Response text: {response.text}")
    except Exception as e:
        print(f"[warn] AI init failed ({type(e).__name__}): {e}")
        print("[warn] Continuing; AI classifications may fail until configured.")
    print("----------------------------------------------------------------")
    print("Monitoring running processes. Press Ctrl+C to stop.")

    # Tuning knobs (environment variables)
    # - ML_DETECTOR_POLL_SECONDS: polling interval
    # - ML_DETECTOR_MIN_SCORE: minimum local heuristic score before AI
    # - ML_DETECTOR_SCAN_MODE: "new" (default) or "all"
    #       new: only processes first observed after the detector starts
    #       all: re-check running processes each poll (with throttle)
    # - ML_DETECTOR_DEBUG: print why items are/aren't escalated
    poll_seconds = float(os.getenv("ML_DETECTOR_POLL_SECONDS", "5"))
    min_score_for_ai = int(os.getenv("ML_DETECTOR_MIN_SCORE", "2"))
    max_ai_per_cycle = int(os.getenv("ML_DETECTOR_MAX_AI_PER_CYCLE", "3"))

    # For LiveMode beaconing, "all" is usually the right default because
    # the PowerShell host process may already exist before the detector starts.
    scan_mode = os.getenv("ML_DETECTOR_SCAN_MODE", "all").strip().lower()
    debug = get_env_bool("ML_DETECTOR_DEBUG", False)
    show_scores = get_env_bool("ML_DETECTOR_SHOW_SCORES", True)

    # Output controls:
    # - ML_DETECTOR_AI_VERBOSE=1 -> print full features + raw model output
    # - ML_DETECTOR_AI_PRINT_PID_EXPLANATION=1 -> print PID explanation line
    # - ML_DETECTOR_MONITOR_PRINT_CMDLINE=1 -> include cmdline (truncated) in monitor lines
    ai_verbose = get_env_bool("ML_DETECTOR_AI_VERBOSE", False)
    ai_print_pid_expl = get_env_bool("ML_DETECTOR_AI_PRINT_PID_EXPLANATION", False)
    monitor_print_cmdline = get_env_bool("ML_DETECTOR_MONITOR_PRINT_CMDLINE", False)
    write_alert_log = get_env_bool("ML_DETECTOR_WRITE_ALERT_LOG", False)
    alert_log_path = os.getenv("ML_DETECTOR_ALERT_LOG_PATH", "suspicious_processes.log")

    # In "all" mode, avoid hammering the same long-running process.
    # Re-check a (pid, cmdline) at most every N seconds.
    throttle_seconds = float(os.getenv("ML_DETECTOR_THROTTLE_SECONDS", "60"))
    last_checked: Dict[Tuple[int, int], float] = {}

    # Tracking set used to detect *new* processes between polls.
    known_pids: set[int] = set()

    # Optional: read PowerShell history once per cycle (Windows) for interactive commands.
    # This is intentionally coarse and should only be used in controlled lab environments.
    ps_hist_indicators = {
        "invoke-expression",
        " iex ",
        "frombase64string",
        "invoke-webrequest",
        "invoke-restmethod",
        "downloadstring",
        "encodedcommand",
    }

    while True:
        ps_history_lines = maybe_read_powershell_history_lines()
        ps_hist_hit = any(
            any(ind in f" {ln} " for ind in ps_hist_indicators) for ln in ps_history_lines
        )
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

            # If enabled and we saw suspicious interactive history, boost PowerShell-family processes.
            if ps_hist_hit and is_powershell_family(proc):
                score += 3
                reasons.append("suspicious PowerShell history (interactive)")
                features["local_score"] = score
                features["local_reasons"] = reasons
                features["ps_history_signal"] = True
            else:
                features["ps_history_signal"] = False

            if score > 0:
                nonzero_score_count += 1

            # LiveMode behavior signal: PowerShell process making outbound connections.
            pid_val = features.get("pid")
            conn_count = 0
            remotes: List[str] = []
            if isinstance(pid_val, int) and pid_val > 0:
                # On Windows this can throw AccessDenied/NoSuchProcess mid-iteration.
                try:
                    conn_count, remotes = count_remote_connections(pid_val)
                except Exception:
                    conn_count, remotes = 0, []
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
                    cmd_part = ""
                    if monitor_print_cmdline:
                        cmd_part = f" cmdline={trunc(str(features.get('cmdline') or ''), 120)}"
                    print(
                        f"[monitor] pid={features.get('pid')} name={features.get('name')} "
                        f"score={features.get('local_score')} reasons={features.get('local_reasons')} "
                        f"remotes={features.get('remote_connection_count', 0)}" + cmd_part
                    )

            # Additional throttle for scan_mode=all
            pid = features.get("pid")
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
            if escalated_to_ai_count > max_ai_per_cycle:
                if debug:
                    print(f"[debug] max-ai-per-cycle reached ({max_ai_per_cycle}); skipping remaining")
                break
            prompt = build_model_prompt(features, score, reasons)
            result = classify_process_behavior(prompt)
            parsed = parse_model_json(result)

            verdict = None
            confidence = None
            pid_explanation = None
            model_reasons: Optional[List[str]] = None
            if parsed:
                verdict = (parsed.get("verdict") or "").lower()
                confidence = parsed.get("confidence")
                pid_explanation = parsed.get("process_id_explanation")
                if isinstance(parsed.get("reasons"), list):
                    model_reasons = [str(x) for x in parsed.get("reasons") if x is not None]

            # Step 5: compact output by default (verbose mode shows full dumps)
            print(
                fmt_ai_summary(
                    pid=features.get("pid"),
                    name=features.get("name"),
                    score=int(features.get("local_score") or score),
                    verdict=verdict,
                    confidence=confidence,
                    reasons=model_reasons,
                    conn_count=int(features.get("remote_connection_count") or 0),
                )
            )

            if ai_print_pid_expl and pid_explanation:
                print(f"[AI] PID explanation: {pid_explanation}")

            if ai_verbose:
                print("[AI] Features:")
                print(json.dumps(features, indent=2))
                print("[AI] Raw model output:")
                print(result)

            if write_alert_log and verdict in {"suspicious", "malicious"}:
                try:
                    with open(alert_log_path, "a", encoding="utf-8") as log_file:
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
                except Exception as e:
                    if debug:
                        print(f"[debug] failed writing alert log ({type(e).__name__}): {e}")

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