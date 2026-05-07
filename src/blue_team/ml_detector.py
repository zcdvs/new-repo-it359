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
from collections import deque
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any, Deque, Dict, List, Optional, Tuple
import logging
import platform

import psutil
from google import genai

# The client gets the API key from the environment variable `GEMINI_API_KEY`.
client = genai.Client()


@dataclass(frozen=True)
class DetectorConfig:
    poll_seconds: float
    debug: bool
    min_score_for_ai: int
    max_ai_per_cycle: int
    throttle_seconds: float
    write_alert_log: bool
    alert_log_path: str
    ai_verbose: bool
    ai_print_pid_expl: bool
    monitor_print_cmdline: bool
    allow_process_names: List[str]
    allow_cmdline_regex: List[re.Pattern[str]]
    deny_process_names: List[str]
    deny_cmdline_regex: List[re.Pattern[str]]
    json_log_path: str


def _split_csv(raw: str) -> List[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def _compile_regex_list(raw: str) -> List[re.Pattern[str]]:
    out: List[re.Pattern[str]] = []
    for pat in _split_csv(raw):
        try:
            out.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            # Ignore invalid patterns rather than crashing in production.
            continue
    return out


def get_config() -> DetectorConfig:
    poll_seconds = float(os.getenv("ML_DETECTOR_POLL_SECONDS", "10"))
    debug = get_env_bool("ML_DETECTOR_DEBUG", False)

    # Always-on monitor: we still use a local score to decide when to call the model.
    min_score_for_ai = int(os.getenv("ML_DETECTOR_MIN_SCORE", "2"))
    # PowerShell often runs in-process scriptblocks with a bland cmdline; allow a lower
    # threshold so your fileless demo can still escalate to AI.
    # (Used in main loop; not part of DetectorConfig to keep the struct stable.)
    max_ai_per_cycle = int(os.getenv("ML_DETECTOR_MAX_AI_PER_CYCLE", "4"))
    throttle_seconds = float(os.getenv("ML_DETECTOR_THROTTLE_SECONDS", "15"))

    ai_verbose = get_env_bool("ML_DETECTOR_AI_VERBOSE", False)
    ai_print_pid_expl = get_env_bool("ML_DETECTOR_AI_PRINT_PID_EXPLANATION", False)
    monitor_print_cmdline = get_env_bool("ML_DETECTOR_MONITOR_PRINT_CMDLINE", False)
    write_alert_log = get_env_bool("ML_DETECTOR_WRITE_ALERT_LOG", False)
    alert_log_path = os.getenv("ML_DETECTOR_ALERT_LOG_PATH", "suspicious_processes.log")

    allow_process_names = [x.lower() for x in _split_csv(os.getenv("ML_DETECTOR_ALLOW_PROCESS_NAMES", ""))]
    deny_process_names = [x.lower() for x in _split_csv(os.getenv("ML_DETECTOR_DENY_PROCESS_NAMES", ""))]
    allow_cmdline_regex = _compile_regex_list(os.getenv("ML_DETECTOR_ALLOW_CMDLINE_REGEX", ""))
    deny_cmdline_regex = _compile_regex_list(os.getenv("ML_DETECTOR_DENY_CMDLINE_REGEX", ""))

    json_log_path = os.getenv("ML_DETECTOR_JSON_LOG_PATH", "ml_detector.jsonl")

    return DetectorConfig(
        poll_seconds=poll_seconds,
        debug=debug,
        min_score_for_ai=min_score_for_ai,
    max_ai_per_cycle=max_ai_per_cycle,
    throttle_seconds=throttle_seconds,
        write_alert_log=write_alert_log,
        alert_log_path=alert_log_path,
        ai_verbose=ai_verbose,
        ai_print_pid_expl=ai_print_pid_expl,
        monitor_print_cmdline=monitor_print_cmdline,
        allow_process_names=allow_process_names,
        allow_cmdline_regex=allow_cmdline_regex,
        deny_process_names=deny_process_names,
        deny_cmdline_regex=deny_cmdline_regex,
        json_log_path=json_log_path,
    )


def setup_logger(cfg: DetectorConfig) -> logging.Logger:
    logger = logging.getLogger("ml_detector")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG if cfg.debug else logging.INFO)

    # JSONL log suitable for ingestion (Splunk/ELK/etc.)
    handler = RotatingFileHandler(
        cfg.json_log_path,
        maxBytes=int(os.getenv("ML_DETECTOR_JSON_LOG_MAX_BYTES", str(2 * 1024 * 1024))),
        backupCount=int(os.getenv("ML_DETECTOR_JSON_LOG_BACKUPS", "3")),
        encoding="utf-8",
    )
    handler.setLevel(logging.DEBUG if cfg.debug else logging.INFO)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def log_event(logger: logging.Logger, event: Dict[str, Any]) -> None:
    try:
        logger.info(json.dumps(event, ensure_ascii=False))
    except Exception:
        # Never crash the detector due to logging.
        pass


def is_allowed_by_policy(proc: Dict[str, Any], cfg: DetectorConfig) -> bool:
    name = (proc.get("name") or "").lower()
    cmd = (proc.get("cmdline") or "")

    if cfg.deny_process_names and name in cfg.deny_process_names:
        return False
    if any(p.search(cmd) for p in cfg.deny_cmdline_regex):
        return False

    # If allowlists are provided, require a match.
    if cfg.allow_process_names or cfg.allow_cmdline_regex:
        if name in cfg.allow_process_names:
            return True
        if any(p.search(cmd) for p in cfg.allow_cmdline_regex):
            return True
        return False

    return True


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


def fmt_alert_line(
    *,
    kind: str,
    pid: Any,
    name: Any,
    score: int,
    remotes: int,
    loopback: int = 0,
    beacon: int,
    reasons: List[str],
    cmdline: str = "",
    max_reasons: int = 3,
    max_cmd: int = 120,
) -> str:
    """Single-line console output to keep output readable."""
    rs = ",".join([trunc(str(r), 60) for r in (reasons or [])[:max_reasons]])
    cmd_part = f" cmd={trunc(cmdline, max_cmd)}" if cmdline else ""
    loop_part = f" loop={loopback}" if loopback else ""
    return (
        f"[{kind}] pid={pid} name={name} score={score} remotes={remotes}{loop_part} "
        f"beacon={beacon} reasons={rs}{cmd_part}"
    )


def fmt_ai_block(
    *,
    pid: Any,
    name: Any,
    score: int,
    verdict: Optional[str],
    confidence: Any,
    reasons: Optional[List[str]],
    remotes: int,
    loopback: int = 0,
    beacon: int,
    wrap: int,
) -> str:
    """Multi-line AI output meant for terminals that truncate long single lines."""

    verdict_s = verdict or "unknown"
    conf_s = "?" if confidence is None else str(confidence)
    rs = "; ".join([str(x) for x in (reasons or [])])
    rs = rs.replace("\r", " ").replace("\n", " ").strip()

    if wrap and wrap > 0:
        # simple wrapping without importing textwrap for minimal deps
        chunks = [rs[i : i + wrap] for i in range(0, len(rs), wrap)] or [""]
        reasons_lines = "\n".join([f"  - {c}" for c in chunks])
    else:
        reasons_lines = f"  - {rs}"

    loop_part = f" loop={loopback}" if loopback else ""
    return (
        "\n"
        f"[AI] pid={pid} name={name} score={score} remotes={remotes}{loop_part} beacon={beacon} verdict={verdict_s} confidence={conf_s}\n"
        f"[AI] reasons:\n{reasons_lines}\n"
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


def _is_loopback_ip(ip: Optional[str]) -> bool:
    if not ip:
        return False
    ip = ip.strip().lower()
    return ip.startswith("127.") or ip in {"::1", "localhost"}


def split_endpoints(remotes: List[str]) -> Tuple[List[str], List[str]]:
    """Split endpoints into (loopback, external)."""
    loopback: List[str] = []
    external: List[str] = []
    for ep in remotes or []:
        ip = ep.split(":")[0].strip() if ep else ""
        if _is_loopback_ip(ip):
            loopback.append(ep)
        else:
            external.append(ep)
    return sorted(set(loopback)), sorted(set(external))


def _interval_stats(ts: List[float]) -> Tuple[Optional[float], Optional[float]]:
    """Return (mean_interval, jitter) for a timestamp series.

    jitter is the mean absolute deviation from mean_interval.
    """

    if len(ts) < 3:
        return None, None
    intervals = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
    mean_i = sum(intervals) / len(intervals)
    mad = sum(abs(x - mean_i) for x in intervals) / len(intervals)
    return mean_i, mad


def compute_beacon_likeness(
    *,
    timestamps: List[float],
    remote_counts: List[int],
    remote_endpoints: List[List[str]],
) -> Tuple[int, List[str]]:
    """Return (beacon_likeness_score 0-10, reasons).

    Heuristics (intentionally simple / hacktool-ish):
    - Regular-ish periodic activity (low jitter): common for beacon loops.
    - Short reconnect patterns: remote_count toggles 0->>0 repeatedly.
    - Repeatedly contacting the same endpoint(s).
    """

    reasons: List[str] = []
    if len(timestamps) < 3:
        return 0, reasons

    mean_i, jitter = _interval_stats(timestamps)
    score = 0

    # 1) Periodicity signal
    if mean_i is not None and jitter is not None and mean_i > 0:
        # Relative jitter (lower is "more periodic")
        rel = jitter / mean_i
        # Typical beacon intervals are often 2s+; still allow small loops for demos.
        if mean_i >= 2 and rel <= 0.35:
            score += 5
            reasons.append(f"periodic callbacks (avg={mean_i:.1f}s jitter={rel:.2f})")
        elif mean_i >= 2 and rel <= 0.6:
            score += 3
            reasons.append(f"semi-periodic callbacks (avg={mean_i:.1f}s jitter={rel:.2f})")

    # 2) Connection toggling/reconnect behavior
    transitions = 0
    for i in range(1, len(remote_counts)):
        if (remote_counts[i - 1] == 0) != (remote_counts[i] == 0):
            transitions += 1
    if transitions >= 2:
        score += 2
        reasons.append("repeated connect/disconnect pattern")

    # 3) Same endpoint repetition (sticky destination)
    flat = [ep for eps in remote_endpoints for ep in eps]
    if flat:
        # Count duplicates
        uniq = set(flat)
        if len(uniq) == 1 and len(flat) >= 3:
            score += 3
            reasons.append("repeatedly contacts same remote endpoint")
        elif len(uniq) <= 2 and len(flat) >= 4:
            score += 2
            reasons.append("contacts small set of remote endpoints")

    # Clamp 0-10
    score = max(0, min(10, score))
    return score, reasons


def build_model_prompt(features: Dict[str, Any], score: int, reasons: List[str]) -> str:
    """Build an instruction prompt that requests strict JSON from the model.

    Why JSON?
    - It reduces the need for brittle substring matching (e.g., "malicious").
    - It makes logging and downstream automation easier.
    """
    # Production note: keep this prompt stable and explicit.
    # We want deterministic keys and minimal risk of the model returning prose.
    return (
        "You are a blue-team process-behavior classifier for endpoint telemetry. "
        "Classify the process as benign/suspicious/malicious using the provided features. "
        "You may use timing/periodicity features (beacon_likeness) to reason about C2-style beaconing, "
        "but do not over-weight networking alone. "
        "Return STRICT JSON ONLY (no markdown, no prose, no code fences). "
        "The JSON object MUST have exactly these keys: verdict, confidence, reasons, process_id_explanation. "
        "\n"
        "- verdict: one of 'benign' | 'suspicious' | 'malicious'\n"
        "- confidence: integer 0-10\n"
        "- reasons: array of short strings explaining the verdict\n"
        "- process_id_explanation: 1-3 sentences explaining what PID represents on this host and how to pivot\n"
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
    cfg = get_config()
    logger = setup_logger(cfg)

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
    print("Monitoring running processes (start this BEFORE running the fileless simulation). Ctrl+C to stop.")

    # Structured startup log for ops.
    log_event(
        logger,
        {
            "event": "startup",
            "ts": time.time(),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "config": {
                "poll_seconds": cfg.poll_seconds,
                "min_score_for_ai": cfg.min_score_for_ai,
                "max_ai_per_cycle": cfg.max_ai_per_cycle,
                "throttle_seconds": cfg.throttle_seconds,
                "json_log_path": cfg.json_log_path,
            },
        },
    )

    # Always-on behavior:
    # - we monitor continuously
    # - we call AI only for suspicious processes (local score or beacon-likeness)
    poll_seconds = cfg.poll_seconds
    min_score_for_ai = cfg.min_score_for_ai
    ps_min_score_for_ai = int(os.getenv("ML_DETECTOR_PS_MIN_SCORE", "1"))
    max_ai_per_cycle = cfg.max_ai_per_cycle
    debug = cfg.debug

    # Output controls:
    # - ML_DETECTOR_AI_VERBOSE=1 -> print full features + raw model output
    # - ML_DETECTOR_AI_PRINT_PID_EXPLANATION=1 -> print PID explanation line
    # - ML_DETECTOR_MONITOR_PRINT_CMDLINE=1 -> include cmdline (truncated) in monitor lines
    ai_verbose = cfg.ai_verbose
    ai_print_pid_expl = cfg.ai_print_pid_expl
    monitor_print_cmdline = cfg.monitor_print_cmdline
    write_alert_log = cfg.write_alert_log
    alert_log_path = cfg.alert_log_path

    # Reduce common benign noise on Windows (browsers/child content processes).
    # These can have loopback IPC connections and long cmdlines that otherwise cause
    # frequent AI escalations.
    suppress_ai_process_names = {
        x.strip().lower()
        for x in _split_csv(
            os.getenv(
                "ML_DETECTOR_SUPPRESS_AI_PROCESS_NAMES",
                "chrome.exe,msedge.exe,firefox.exe,brave.exe,opera.exe"
            )
        )
        if x.strip()
    }
    suppress_ai_requires_external = get_env_bool("ML_DETECTOR_SUPPRESS_AI_REQUIRES_EXTERNAL", True)

    # Console output tuning (defaults chosen to reduce benign noise):
    # - ML_DETECTOR_PRINT_MONITOR=1 enables per-process monitor lines.
    # - ML_DETECTOR_MONITOR_MIN_SCORE sets minimum local score to print.
    # - ML_DETECTOR_MONITOR_PRINT_POWERSHELL=1 prints PowerShell even at low score.
    # - ML_DETECTOR_MONITOR_PRINT_NETONLY=1 prints any process with conn_count>0 even if score is low.
    print_monitor = get_env_bool("ML_DETECTOR_PRINT_MONITOR", False)
    monitor_min_score = int(os.getenv("ML_DETECTOR_MONITOR_MIN_SCORE", "2"))
    monitor_print_powershell = get_env_bool("ML_DETECTOR_MONITOR_PRINT_POWERSHELL", True)
    monitor_print_netonly = get_env_bool("ML_DETECTOR_MONITOR_PRINT_NETONLY", False)

    # AI output formatting:
    # - ML_DETECTOR_AI_ONE_LINE=1 prints a single-line AI output.
    # - ML_DETECTOR_AI_WRAP sets wrap width for reasons in block output (0 disables wrapping).
    ai_one_line = get_env_bool("ML_DETECTOR_AI_ONE_LINE", False)
    ai_wrap = int(os.getenv("ML_DETECTOR_AI_WRAP", "120"))

    # Optional: print a single-line beacon alert when beacon-likeness is strong.
    # This helps demos when AI is throttled/off and monitor lines are disabled.
    print_beacon_alerts = get_env_bool("ML_DETECTOR_PRINT_BEACON_ALERTS", True)
    beacon_alert_min = int(os.getenv("ML_DETECTOR_BEACON_ALERT_MIN", "8"))

    # Beacon tuning (NO hardcoded IPs):
    # We detect beaconing based on timing/jitter + repeated endpoints + connect/disconnect.
    # To keep it usable in labs, we compute beacon-likeness for all processes by default,
    # but you can tune how strongly it affects risk scoring.
    beacon_only_powershell = get_env_bool("ML_DETECTOR_BEACON_ONLY_POWERSHELL", False)
    beacon_boost_ps_min = int(os.getenv("ML_DETECTOR_BEACON_BOOST_PS_MIN", "3"))
    beacon_boost_ps_strong = int(os.getenv("ML_DETECTOR_BEACON_BOOST_PS_STRONG", "6"))
    beacon_boost_other_min = int(os.getenv("ML_DETECTOR_BEACON_BOOST_OTHER_MIN", "8"))
    beacon_boost_other_strong = int(os.getenv("ML_DETECTOR_BEACON_BOOST_OTHER_STRONG", "9"))

    # Avoid hammering the same long-running process with AI.
    # Re-check a (pid, cmdline) at most every N seconds.
    throttle_seconds = cfg.throttle_seconds
    last_checked: Dict[Tuple[int, int], float] = {}
    # If the model call fails, apply a longer cooldown to avoid noisy retries.
    ai_error_cooldown_seconds = float(os.getenv("ML_DETECTOR_AI_ERROR_COOLDOWN_SECONDS", "180"))
    last_ai_error: Dict[Tuple[int, int], float] = {}

    # Per-PID time series used for beacon-likeness scoring.
    # Stores only recent samples to keep memory bounded.
    beacon_history_seconds = float(os.getenv("ML_DETECTOR_BEACON_WINDOW_SECONDS", "120"))
    beacon_min_samples = int(os.getenv("ML_DETECTOR_BEACON_MIN_SAMPLES", "4"))
    # pid -> deque of (timestamp, conn_count, remotes)
    beacon_hist: Dict[int, Deque[Tuple[float, int, List[str]]]] = {}

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

    cycle_no = 0
    while True:
        cycle_no += 1
        snapshot = iter_processes()
        procs = [p for p in snapshot if isinstance(p.get("pid"), int)]

        scanned_count = 0
        escalated_to_ai_count = 0
        powershell_seen_count = 0
        monitor_printed_count = 0
        suspicious_count = 0

        for proc in procs:
            scanned_count += 1

            if not is_allowed_by_policy(proc, cfg):
                if debug:
                    print(
                        f"[debug] policy-skip pid={proc.get('pid')} name={proc.get('name')}"
                    )
                continue

            features = {
                "pid": proc.get("pid"),
                "name": proc.get("name"),
                "cmdline": proc.get("cmdline"),
                "user": proc.get("user"),
                "host": proc.get("host"),
                "create_time": proc.get("create_time"),
            }

            # Always include stable environment fields for downstream correlation.
            features["platform"] = platform.system().lower()
            features["platform_release"] = platform.release()

            # Step 2: local scoring (avoid AI unless there's enough signal)
            score, reasons = local_risk_score(proc)
            features["local_score"] = score
            features["local_reasons"] = reasons

            # LiveMode behavior signal: outbound connections.
            pid_val = features.get("pid")
            conn_count = 0
            remotes: List[str] = []
            loopback_eps: List[str] = []
            external_eps: List[str] = []
            if isinstance(pid_val, int) and pid_val > 0:
                # On Windows this can throw AccessDenied/NoSuchProcess mid-iteration.
                try:
                    conn_count, remotes = count_remote_connections(pid_val)
                except Exception:
                    conn_count, remotes = 0, []

                loopback_eps, external_eps = split_endpoints(remotes)

                # Treat outbound networking as *some* signal, and stronger when PowerShell is involved.
                is_ps_for_net = is_powershell_family(proc)
                # IMPORTANT: loopback-only activity is common in browsers (IPC) and shouldn't
                # trigger escalation by itself.
                if len(external_eps) > 0:
                    score += 1
                    reasons.append("external outbound network activity")
                    if is_ps_for_net:
                        score += 2
                        reasons.append("PowerShell external outbound network activity")
                    features["local_score"] = score
                    features["local_reasons"] = reasons

                # Beacon-likeness (rate-based) — doesn't rely on a fixed C2 IP.
                # We score based on periodic connection behavior for processes
                # that exhibit outbound network activity.
                # IMPORTANT: only track samples when we actually saw a remote endpoint.
                # Otherwise, many long-running services look artificially "periodic" at poll rate.
                features["beacon_likeness"] = 0
                features["beacon_reasons"] = []
                allow_beacon_calc = (not beacon_only_powershell) or is_powershell_family(proc)
                # Only consider EXTERNAL endpoints for beaconing; loopback periodicity is normal IPC.
                if allow_beacon_calc and len(external_eps) > 0:
                    now_ts = time.time()
                    dq = beacon_hist.get(pid_val)
                    if dq is None:
                        dq = deque(maxlen=200)
                        beacon_hist[pid_val] = dq
                    dq.append((now_ts, int(len(external_eps)), list(external_eps)))

                    cutoff = now_ts - beacon_history_seconds
                    while dq and dq[0][0] < cutoff:
                        dq.popleft()

                    if len(dq) >= beacon_min_samples:
                        ts = [x[0] for x in dq]
                        counts = [x[1] for x in dq]
                        rem_series = [x[2] for x in dq]
                        bl_score, bl_reasons = compute_beacon_likeness(
                            timestamps=ts,
                            remote_counts=counts,
                            remote_endpoints=rem_series,
                        )
                        features["beacon_likeness"] = bl_score
                        features["beacon_reasons"] = bl_reasons

                        # Beacon-likeness should be a meaningful escalation signal.
                        # Keep thresholds configurable so you can reduce false positives without baselining IPs.
                        if is_powershell_family(proc):
                            if bl_score >= beacon_boost_ps_strong:
                                score += 3
                                reasons.append("beacon-like timing")
                            elif bl_score >= beacon_boost_ps_min:
                                score += 1
                                reasons.append("possible beacon timing")
                        else:
                            # Non-PS processes are more likely to be legitimate background updaters,
                            # so default thresholds are higher.
                            if bl_score >= beacon_boost_other_strong:
                                score += 3
                                reasons.append("beacon-like timing")
                            elif bl_score >= beacon_boost_other_min:
                                score += 1
                                reasons.append("possible beacon timing")
                        features["local_score"] = score
                        features["local_reasons"] = reasons

            features["remote_connection_count"] = conn_count
            features["remote_endpoints"] = remotes
            features["loopback_endpoints"] = loopback_eps
            features["external_endpoints"] = external_eps
            features["external_connection_count"] = len(external_eps)

            # Optional: add a low-cost "suspicious cmdline" hint.
            # If this is false and the score is low, it's likely benign.
            features["cmdline_high_signal"] = looks_suspicious(proc)

            is_ps = is_powershell_family(proc)
            if is_ps:
                powershell_seen_count += 1

            # Mark "suspicious" for cycle summary. This doesn't mean malicious—it just means
            # it had enough local/network signal to be worth looking at.
            if score >= monitor_min_score or int(features.get("beacon_likeness") or 0) >= 3:
                suspicious_count += 1

            # Optional per-process monitor lines (off by default to reduce benign noise).
            if print_monitor:
                should_print = False
                if score >= monitor_min_score:
                    should_print = True
                if monitor_print_powershell and is_ps:
                    should_print = True
                if monitor_print_netonly and int(features.get("remote_connection_count") or 0) > 0:
                    should_print = True

                if should_print:
                    monitor_printed_count += 1
                    cmdline = str(features.get("cmdline") or "") if monitor_print_cmdline else ""
                    print(
                        fmt_alert_line(
                            kind="MON",
                            pid=features.get("pid"),
                            name=features.get("name"),
                            score=int(features.get("local_score") or 0),
                            remotes=int(features.get("external_connection_count") or 0),
                            loopback=len(list(features.get("loopback_endpoints") or [])),
                            beacon=int(features.get("beacon_likeness") or 0),
                            reasons=[str(x) for x in (features.get("local_reasons") or [])],
                            cmdline=cmdline,
                        )
                    )

            # Additional throttle for scan_mode=all
            pid = features.get("pid")
            pid_i = int(pid) if isinstance(pid, int) else -1
            cmd_hash2 = hash(features.get("cmdline") or "")
            throttle_key = (pid_i, cmd_hash2)
            now = time.time()

            last_err = last_ai_error.get(throttle_key)
            if last_err is not None and (now - last_err) < ai_error_cooldown_seconds:
                if debug:
                    print(
                        f"[debug] ai-error-cooldown pid={pid_i} ({int(now - last_err)}s since last error)"
                    )
                continue

            last = last_checked.get(throttle_key)
            if last is not None and (now - last) < throttle_seconds:
                if debug:
                    print(
                        f"[debug] throttled pid={pid_i} ({int(now - last)}s since last check)"
                    )
                continue
            last_checked[throttle_key] = now

            # Step 4: AI escalation threshold
            # PowerShell heuristics: allow lower scores to escalate if there's any
            # networking or beacon-like timing, since scriptblock activity won't show
            # up in cmdline-based scoring.
            ai_threshold = min_score_for_ai
            if is_ps:
                if int(features.get("external_connection_count") or 0) > 0 or int(features.get("beacon_likeness") or 0) >= 3:
                    ai_threshold = min(ai_threshold, ps_min_score_for_ai)

            if score < ai_threshold:
                if debug:
                    print(
                        f"[debug] skip-ai pid={features.get('pid')} name={features.get('name')} "
                        f"score={score} threshold={ai_threshold} reasons={reasons} cmdline_high_signal={features.get('cmdline_high_signal')}"
                    )
                continue

            # Additional guardrail: suppress AI escalation for common noisy processes
            # unless there's external network activity or a stronger local score.
            proc_name_l = (str(features.get("name") or "")).lower()
            if proc_name_l in suppress_ai_process_names:
                has_external = int(features.get("external_connection_count") or 0) > 0
                if (not suppress_ai_requires_external) or has_external:
                    # allow through
                    pass
                else:
                    # Require more than the bare minimum score to avoid constant Firefox noise.
                    extra_min = int(os.getenv("ML_DETECTOR_SUPPRESS_AI_MIN_SCORE", "4"))
                    if score < extra_min:
                        if debug:
                            print(
                                f"[debug] suppress-ai pid={features.get('pid')} name={features.get('name')} score={score}"
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

            # If the AI call failed (we synthesize a JSON response with model_call_failed),
            # cool down retries for this (pid, cmdline).
            if model_reasons and any("model_call_failed" in r for r in model_reasons):
                last_ai_error[throttle_key] = time.time()

            # Step 5: Print only actionable items in quiet mode.
            final_score = int(features.get("local_score") or score)
            if ai_one_line:
                print(
                    fmt_alert_line(
                        kind="AI",
                        pid=features.get("pid"),
                        name=features.get("name"),
                        score=final_score,
                        remotes=int(features.get("external_connection_count") or 0),
                        loopback=len(list(features.get("loopback_endpoints") or [])),
                        beacon=int(features.get("beacon_likeness") or 0),
                        reasons=[str(x) for x in (model_reasons or [])],
                    )
                )
            else:
                print(
                    fmt_ai_block(
                        pid=features.get("pid"),
                        name=features.get("name"),
                        score=final_score,
                        verdict=verdict,
                        confidence=confidence,
                        reasons=model_reasons,
                        remotes=int(features.get("external_connection_count") or 0),
                        loopback=len(list(features.get("loopback_endpoints") or [])),
                        beacon=int(features.get("beacon_likeness") or 0),
                        wrap=ai_wrap,
                    )
                )

            # Structured alert event. This is the production-friendly output.
            log_event(
                logger,
                {
                    "event": "classification",
                    "ts": time.time(),
                    "pid": features.get("pid"),
                    "name": features.get("name"),
                    "score": final_score,
                    "verdict": verdict,
                    "confidence": confidence,
                    "local_reasons": features.get("local_reasons"),
                    "model_reasons": model_reasons,
                    "remote_connection_count": int(features.get("remote_connection_count") or 0),
                    "beacon_likeness": int(features.get("beacon_likeness") or 0),
                },
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

        # Cycle summary: one line per cycle so you can see it's alive.
        print(
            f"[cycle] scanned={scanned_count} ps_seen={powershell_seen_count} "
            f"susp={suspicious_count} mon={monitor_printed_count} ai={escalated_to_ai_count}"
        )
        log_event(
            logger,
            {
                "event": "cycle_summary",
                "ts": time.time(),
                "scanned": scanned_count,
                "ps_seen": powershell_seen_count,
                "ai": escalated_to_ai_count,
            },
        )

        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()