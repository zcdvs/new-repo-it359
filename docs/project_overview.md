# IT 359 Final Project - Fileless Malware Research

## Overview
This project explores fileless malware techniques and detection methods as part of the IT 359 Spring 2026 final project.

## Team: Hack the Blocks
- Zac Davis
- Caleb Clauson

## Project Components

### Red Team (Offensive)
- **PowerShell Script**: Simulates fileless malware by executing commands entirely in memory
- **Python C2 Listener**: Command and Control server running on the attacking machine to receive data via HTTP/HTTPS

### Blue Team (Defensive)
- **Detection Script**: Python-based threat detection
- **ML/AI Detection**: Machine learning model trained to identify fileless malware behavior

## Key Concepts

### What is Fileless Malware?
Fileless malware operates within a computer's RAM rather than writing files to the hard drive. This makes it harder to detect using traditional file-based antivirus scanning.

### Why Study This?
Modern operating systems have become better at scanning files on disk, causing attackers to pivot to memory-resident techniques that leave no traditional footprint on the filesystem.

## References
- [Add references here as research progresses]
