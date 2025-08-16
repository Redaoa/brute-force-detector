# SIEM-lite

A lightweight Security Information & Event Management (SIEM) system for students and researchers.
Runs as a single-file **Flask app** with no external JavaScript/CSS dependencies.  

## ✨ Features
- Parse real Linux logs (`/var/log/auth.log`, `/var/log/syslog`) or run in **simulation mode**.
- Detects:
  - SSH brute-force attempts
  - Invalid users
  - Password spraying
  - Sudo authentication failures
  - Basic nmap scans
- Stores events + alerts in SQLite (`sentinel.db`).
- Live web dashboard at `http://127.0.0.1:5000`.
- REST API (`/api/events`, `/api/alerts`, `/api/stats`, `/api/ingest`).

## 🚀 Quickstart
```bash
git clone https://github.com/YOUR_USERNAME/cyber-sentinel.git
cd cyber-sentinel
pip install -r requirements.txt
