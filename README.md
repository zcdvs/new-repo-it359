# IT 359 Final Project - Spring 2026
## Fileless Malware: Attack Simulation & Detection

Our final project for IT 359 explores fileless malware—a type of malware that operates entirely within a computer's RAM, instead of writing files to the hard drive. This makes it significantly harder to detect using traditional antivirus solutions.

---

## Team Name
**Hack the Blocks**
   
## Team Members
- Zac Davis
- Caleb Clauson

---

## Purpose of the Project
The primary goal of this project is to explore the shift in the cybersecurity landscape from file-based threats to behavior-based threats. As modern operating systems become better at scanning files on disk, attackers have pivoted to memory-resident techniques that leave no traditional footprint.

This project provides hands-on experience with both offensive (Red Team) and defensive (Blue Team) security techniques.

---

## Project Structure

```
├── README.md
├── requirements.txt
├── src/
│   ├── red_team/              # Offensive tools
│   │   ├── fileless_simulation.ps1   # PowerShell malware simulation
│   │   └── c2_listener.py            # Python C2 server
│   └── blue_team/             # Defensive tools
│       ├── detector.py               # Behavior-based detection
│       └── ml_detector.py            # ML-based detection
└── docs/
    ├── project_overview.md
    └── setup_guide.md
```

---

## Red Team Components

### 1. Fileless Malware Simulation (PowerShell)
`src/red_team/fileless_simulation.ps1`

Demonstrates common fileless malware techniques:

| Technique | Description |
|-----------|-------------|
| In-Memory Reconnaissance | Gathers system info without writing to disk |
| HTTP Beaconing | Communicates with C2 server via HTTP |
| In-Memory Code Execution | Executes code from strings using ScriptBlocks |
| Environment Variable Abuse | Stores payloads in environment variables |
| Registry Persistence | Demonstrates registry-based persistence (educational) |
| WMI Event Subscription | Explains WMI-based persistence (educational) |

**Usage:**
```powershell
# Run with default settings
.\fileless_simulation.ps1

# Specify C2 server
.\fileless_simulation.ps1 -C2Server "192.168.1.100" -C2Port 8080
```

### 2. Command & Control (C2) Listener (Python)
`src/red_team/c2_listener.py`

A Python-based HTTP server that:
- Receives beacon data from infected hosts
- Logs reconnaissance information
- Can send commands back to compromised systems

---

## Blue Team Components

### 1. Behavior-Based Detector (Python)
`src/blue_team/detector.py`

Detects fileless malware through behavioral analysis:
- Process monitoring for suspicious PowerShell activity
- Network connection analysis for C2 beaconing
- Memory pattern detection

### 2. Machine Learning Detector (Python)
`src/blue_team/ml_detector.py`

Uses ML/AI to identify fileless malware:
- Feature extraction from system behavior
- Trained model to recognize malicious patterns
- Real-time threat detection capabilities

---

## Technologies Used

| Category | Technologies |
|----------|-------------|
| Red Team | PowerShell 5.1+, Python 3.8+ |
| Blue Team | Python 3.8+, scikit-learn, psutil |
| Communication | HTTP/HTTPS, Flask |
| ML/AI | scikit-learn, numpy, pandas, sushi |

---

## Setup & Installation

### Prerequisites
- Windows 10/11 (for PowerShell simulation)
- Python 3.8 or higher
- Virtual environment recommended

### Quick Start
```bash
# Clone the repository
git clone https://github.com/zcdvs/new-repo-it359.git
cd new-repo-it359

# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## ⚠️ Disclaimer

**This project is for EDUCATIONAL PURPOSES ONLY.**

- Only run these scripts in isolated lab environments
- Never use on systems without explicit authorization
- This project is part of an academic course (IT 359)
- The authors are not responsible for any misuse

---

## References

- [MITRE ATT&CK - Fileless Malware](https://attack.mitre.org/)
- [Microsoft Docs - PowerShell Security](https://docs.microsoft.com/en-us/powershell/)
- Additional references to be added as research progresses

---

## License

This project is created for academic purposes as part of IT 359 at Illinois State University, Spring 2026.

