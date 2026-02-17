# Setup Guide

## Prerequisites

### For Red Team Scripts
- Windows environment with PowerShell 5.1+ (for malware simulation)
- Python 3.8+ (for C2 listener)

### For Blue Team Scripts
- Python 3.8+
- Required Python packages (see requirements.txt)

## Environment Setup

### 1. Clone the Repository
```bash
git clone https://github.com/zcdvs/new-repo-it359.git
cd new-repo-it359
```

### 2. Create Python Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
.\venv\Scripts\activate   # On Windows
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

## Safety Notice
⚠️ **WARNING**: This project contains security research code. Only run these scripts in isolated, controlled lab environments. Never use on systems without proper authorization.

## Lab Environment Recommendations
- Use virtual machines for testing
- Isolate test networks from production systems
- Document all testing activities
