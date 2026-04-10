# Setup Notes

This repository contains a **guided lab setup** for ELEC0138 CW1 and CW2.  
It is **not a fully automated deployment**, because several steps require manual interaction in the browser or terminal.

## Important Notes

### 1. Network interface names may differ
The commands in `lab_setup_commands.sh` assume:
- `eth0` = internal network adapter (VirtualBox internal network `corpnet`)
- `eth1` = NAT / internet adapter

On some VMs, interface names may differ (e.g. `enp0s3`, `enp0s8`).  
Check using:

```bash
ip a
```

Then substitute the correct names wherever `eth0` / `eth1` appear in the setup script.

---

### 2. IP assignments are not persistent
The `ip addr add` commands in Sections 1 and 2 assign IPs only for the current session.  
After a reboot, re-run:

```bash
# Kali
sudo ip addr add 10.0.0.1/24 dev eth0

# Ubuntu
sudo ip addr add 10.0.0.2/24 dev eth0
```

To make assignments persistent, use netplan (Ubuntu) or `/etc/network/interfaces` (Kali).

---

### 3. DVWA must be initialised before attacks
Before running any CW1 or CW2 attack commands, ensure:
1. DVWA database has been created via `http://10.0.0.2/dvwa/setup.php` → "Create / Reset Database"
2. Security level is set to **Low** via DVWA Security tab
3. You are logged in as `admin / password` and have a valid `PHPSESSID` cookie

---

### 4. WAF must stay running during CW2 demos
`waf_proxy.py` is a foreground process. Keep the terminal open while running Hydra against the WAF.  
Use a second terminal window or a `tmux` session:

```bash
tmux new -s waf
python3 ~/waf_proxy.py
# Ctrl+B then D to detach; tmux attach -t waf to return
```

---

### 5. Reset WAF state between runs
The WAF keeps lockout and rate-limit state in memory. Between demo runs, reset via:

```bash
curl -X POST http://10.0.0.1:5000/waf/reset
```

Or use the **Reset Stats & State** button on the dashboard at `http://10.0.0.1:5000/waf/dashboard`.

---

### 6. Python dependencies
Install using the provided `requirement.txt`:

```bash
pip install -r requirement.txt --break-system-packages
```

Required packages: `Flask>=3.0`, `requests>=2.31`, `cryptography>=42.0`

---

### 7. Reading the encrypted audit log (Layer 6)
By default `LOG_ENCRYPT = True`, so `waf_audit.log` contains base64-encoded AES-256-GCM ciphertext — opening it in a text editor will show unreadable output. To print decrypted entries to the terminal:

```bash
python3 ~/waf_proxy.py --decrypt
```

The AES key is stored in `waf_audit.key` in the same directory. Keep this file secret and do not commit it to version control.

---

### 8. Enabling HTTPS/TLS mode (Layer 7)
By default `USE_TLS = False` and the WAF runs over plain HTTP on port 5000. To enable TLS:

1. Open `waf_proxy.py` and set `USE_TLS = True`
2. Restart the WAF — it will auto-generate `waf_cert.pem` and `waf_key.pem` on first run
3. Access the WAF at `https://10.0.0.1:5443` (accept the self-signed certificate warning in the browser)

To swap in a CA-signed certificate, replace `waf_cert.pem` and `waf_key.pem` with your own PEM files — no code changes required.
