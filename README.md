# SentinelShield: Web Application Firewall
**Project 5 - Cybersecurity Scholarship**

Built by Adebamigbe Dorcas Adeyemi | June 2026

---

## Overview

SentinelShield is an enterprise-style Web Application Firewall (WAF) that inspects HTTP requests, detects web attacks, enforces rate limiting, and generates comprehensive security logs and reports.

---

## What It Does

- **Detects SQL Injection** — Blocks database manipulation attacks
- **Detects XSS (Cross-Site Scripting)** — Stops JavaScript injection attacks
- **Detects Command Injection** — Prevents OS command execution
- **Detects LFI (Local File Inclusion)** — Blocks unauthorized file access
- **Detects Path Traversal** — Stops directory traversal attempts
- **Rate Limiting** — Prevents brute-force and DDoS attacks
- **Real-Time Logging** — Records all activity and alerts
- **Live Dashboard** — Statistics and threat visualization

---

## System Architecture

Three-module design for enterprise scalability:

1. **waf_engine.py** — Core WAF detection engine (reusable module)
2. **test_server.py** — Flask server using WAF protection
3. **waf_dashboard.py** — Real-time statistics dashboard

---

## Installation & Usage

### Prerequisites
- Python 3.6+
- Flask: `pip install flask --break-system-packages`
- Termux or Linux environment

### Quick Start

```bash
# Clone and enter directory
git clone https://github.com/dorcasjames/sentinelshield-waf.git
cd sentinelshield-waf

# Start test server
python3 test_server.py# sentinelshield-waf
