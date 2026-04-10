#!/usr/bin/env python3
"""
Defence Prototype — Flask WAF Reverse Proxy

Architecture:
  Browser / demo client  --->  WAF proxy (this app)  --->  DVWA backend

Layers:
  Layer 1 — SQL injection filtering (regex IDS/IPS)
  Layer 2 — Account lockout with EXPONENTIAL BACKOFF
  Layer 3 — IP rate limiting (sliding window)
  Layer 4 — Audit logging + live dashboard
  Layer 5 — Privacy-preserving IP pseudonymisation (SHA-256)
  Layer 6 — AES-256-GCM log encryption at rest
  Layer 7 — HTTPS/TLS with auto-generated self-signed cert
"""

from flask import Flask, request, Response, render_template_string, redirect
import requests as req_lib
import re
import time
import os
import base64
import ipaddress
import hashlib
import datetime
from html import escape
from collections import defaultdict

# ── cryptography: AES-256-GCM log encryption ──────────────────────────────────
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── cryptography: self-signed TLS certificate generation ──────────────────────
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DVWA_TARGET         = "http://10.0.0.2"
WAF_HOST            = "0.0.0.0"
WAF_PORT            = 5000

LOCKOUT_THRESHOLD   = 5
LOCKOUT_DURATION    = 60           # seconds — base duration for first lockout
LOCKOUT_MAX_DURATION = 3600        # 1-hour cap on exponential backoff
RATE_LIMIT_MAX      = 20
RATE_LIMIT_WINDOW   = 30           # seconds
DEDUP_WINDOW        = 2.0          # seconds

LOG_FILE            = "waf_audit.log"
LOG_ENCRYPT         = True         # AES-256-GCM encryption for log file
LOG_KEY_FILE        = "waf_audit.key"

USE_TLS             = True        # Set True to run HTTPS on WAF_TLS_PORT
WAF_TLS_PORT        = 5443
TLS_CERT_FILE       = "waf_cert.pem"
TLS_KEY_FILE        = "waf_key.pem"

FAILURE_TEXT        = "Username and/or password incorrect."
SUCCESS_TEXT        = "Welcome to the password protected area"

# ─────────────────────────────────────────────
# LAYER 6 — AES-256-GCM LOG KEY MANAGEMENT
# ─────────────────────────────────────────────
def load_or_generate_log_key() -> bytes:
    """
    Load the 256-bit AES key from disk, or generate and save a new one.
    The key file must be protected (chmod 600) in production.
    """
    if os.path.exists(LOG_KEY_FILE):
        with open(LOG_KEY_FILE, "rb") as f:
            return base64.b64decode(f.read().strip())
    key = os.urandom(32)  # 256-bit key
    with open(LOG_KEY_FILE, "wb") as f:
        f.write(base64.b64encode(key))
    print(f"[INFO] AES-256 log key generated -> {LOG_KEY_FILE}  (keep this file secret!)")
    return key


LOG_KEY = load_or_generate_log_key()


def write_log_line(line: str):
    """
    Write one log line.  When LOG_ENCRYPT=True each line is encrypted with
    AES-256-GCM using a fresh 12-byte nonce, then base64-encoded before
    being appended to the log file.  Use --decrypt to read the log.
    """
    if LOG_ENCRYPT:
        aes   = AESGCM(LOG_KEY)
        nonce = os.urandom(12)                          # 96-bit nonce (NIST recommended)
        ct    = aes.encrypt(nonce, line.encode(), None) # None = no additional data
        encoded = base64.b64encode(nonce + ct).decode()
        with open(LOG_FILE, "a") as f:
            f.write(encoded + "\n")
    else:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def decrypt_log():
    """
    Decrypt and print the full log to stdout.
    Run with:  python3 waf_proxy.py --decrypt
    """
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        return
    aes = AESGCM(LOG_KEY)
    with open(LOG_FILE) as f:
        for i, raw_line in enumerate(f, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                raw   = base64.b64decode(raw_line)
                nonce = raw[:12]
                ct    = raw[12:]
                print(aes.decrypt(nonce, ct, None).decode())
            except Exception:
                # Line was written in plain-text mode — print as-is
                print(raw_line)

# ─────────────────────────────────────────────
# LAYER 7 — TLS CERTIFICATE GENERATION
# ─────────────────────────────────────────────
def generate_self_signed_cert(cert_path: str, key_path: str):
    """
    Generate a 2048-bit RSA self-signed certificate valid for 365 days,
    with a SAN for IP 10.0.0.1.  Saved as PEM files on disk.
    """
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(key_path, "wb") as f:
        f.write(priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         "WAF-ELEC0138"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   "AcmeCorp WAF"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(priv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
            ]),
            critical=False,
        )
        .sign(priv_key, hashes.SHA256())
    )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[INFO] Self-signed TLS cert generated -> {cert_path}  (expires 365 days)")


def ensure_tls_cert():
    if not (os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE)):
        generate_self_signed_cert(TLS_CERT_FILE, TLS_KEY_FILE)

# ─────────────────────────────────────────────
# IN-MEMORY STATE
# ─────────────────────────────────────────────
failed_attempts         = defaultdict(int)   # username -> failed count this cycle
lockout_until           = {}                 # username -> unix timestamp
lockout_count           = defaultdict(int)   # username -> total times locked out
ip_request_log          = defaultdict(list)  # ip -> list[timestamps]
recent_submission_cache = {}                 # fingerprint -> cached response

stats = {
    "requests_proxied": 0,
    "sqli_blocked":     0,
    "logins_failed":    0,
    "brute_blocked":    0,
    "rate_limited":     0,
    "logins_success":   0,
}

blocked_log = []

# ─────────────────────────────────────────────
# LAYER 5 — LOGGING / PRIVACY
# ─────────────────────────────────────────────
def pseudonymise_ip(ip: str) -> str:
    return "ip-" + hashlib.sha256(ip.encode()).hexdigest()[:12]


def log(level: str, message: str, ip: str = ""):
    ts          = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_msg    = message.replace(ip, pseudonymise_ip(ip)) if ip else message
    line_term   = f"[{ts}] [{level}] {message}"    # terminal (real IP)
    line_file   = f"[{ts}] [{level}] {safe_msg}"   # file (pseudonymised IP)

    print(line_term)
    write_log_line(line_file)                        # Layer 6: encrypted write


def add_blocked_event(event_type: str, ip: str, detail: str):
    blocked_log.append({
        "time":   datetime.datetime.now().strftime("%H:%M:%S"),
        "type":   event_type,
        "ip":     ip,
        "detail": detail[:120],
    })
    if len(blocked_log) > 100:
        blocked_log.pop(0)

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def cleanup_recent_cache():
    now     = time.time()
    expired = [k for k, v in recent_submission_cache.items() if now - v["ts"] > DEDUP_WINDOW]
    for k in expired:
        del recent_submission_cache[k]


def make_submission_fingerprint(ip, full_path, username, password, submit) -> str:
    raw = f"{ip}|{full_path}|{username}|{password}|{submit}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_cached_submission_response(fingerprint: str):
    cleanup_recent_cache()
    entry = recent_submission_cache.get(fingerprint)
    if not entry:
        return None
    return Response(entry["body"], status=entry["status"],
                    mimetype=entry["mimetype"], headers=entry["headers"])


def cache_submission_response(fingerprint: str, response: Response):
    headers = {k: v for k, v in response.headers.items()
               if k.lower() not in {"content-length", "transfer-encoding", "connection"}}
    recent_submission_cache[fingerprint] = {
        "ts":       time.time(),
        "body":     response.get_data(),
        "status":   response.status_code,
        "mimetype": response.mimetype,
        "headers":  headers,
    }


def normalize_dvwa_path(path: str) -> str:
    full_path = "/dvwa/" + path if path else "/dvwa/"
    if full_path in {"/dvwa", "/dvwa/"}:
        return "/dvwa/"
    if full_path.rstrip("/") == "/dvwa/vulnerabilities/brute":
        return "/dvwa/vulnerabilities/brute/"
    return full_path


def extract_login_fields(params: dict, form_data: dict):
    username = (form_data.get("username") or params.get("username") or "").strip()
    password =  form_data.get("password") or params.get("password") or ""
    submit   = (form_data.get("Login")    or params.get("Login")    or "").strip()
    return username, password, submit


def is_brute_path(full_path: str) -> bool:
    return full_path.rstrip("/") == "/dvwa/vulnerabilities/brute"


def is_brute_submission(full_path, params, form_data) -> bool:
    username, password, submit = extract_login_fields(params, form_data)
    return is_brute_path(full_path) and bool(username) and bool(password) and submit == "Login"

# ─────────────────────────────────────────────
# LAYER 1 — SQLi FILTERING
# ─────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"('|\"|"
    r"\b(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|SLEEP|BENCHMARK|"
    r"LOAD_FILE|OUTFILE|INFORMATION_SCHEMA|VERSION|DATABASE)\b|"
    r"--|#|/\*|\*/|"
    r";|\b0x[0-9a-fA-F]+)",
    re.IGNORECASE
)


def detect_sqli(value: str) -> bool:
    return bool(SQLI_PATTERNS.search(str(value)))


def scan_inputs(params: dict, form_data: dict):
    merged = {**params, **form_data}
    for key, value in merged.items():
        if isinstance(value, str) and detect_sqli(value):
            return True, f"{key}={value[:80]}"
    return False, ""

# ─────────────────────────────────────────────
# LAYER 3 — RATE LIMITING
# ─────────────────────────────────────────────
def is_rate_limited(ip: str) -> bool:
    now               = time.time()
    ip_request_log[ip] = [t for t in ip_request_log[ip] if now - t < RATE_LIMIT_WINDOW]
    ip_request_log[ip].append(now)
    return len(ip_request_log[ip]) > RATE_LIMIT_MAX

# ─────────────────────────────────────────────
# LAYER 2 — ACCOUNT LOCKOUT (EXPONENTIAL BACKOFF)
# ─────────────────────────────────────────────
def _lockout_duration_for(username: str) -> int:
    """
    Compute lockout duration with exponential backoff.
    lockout_count tracks how many times this account has been locked out.
    Duration doubles each time: 60s → 120s → 240s → 480s → … (cap: 3600s)
    """
    count = lockout_count[username]
    return int(min(LOCKOUT_DURATION * (2 ** (count - 1)), LOCKOUT_MAX_DURATION))


def check_lockout(username: str):
    now   = time.time()
    until = lockout_until.get(username)

    if until is None:
        return False, 0

    if now < until:
        return True, int(until - now)

    # Lockout expired — clear for next cycle; keep lockout_count for backoff
    del lockout_until[username]
    failed_attempts[username] = 0
    return False, 0


def record_login_failure(username: str, ip: str):
    failed_attempts[username] += 1
    stats["logins_failed"] += 1

    log(
        "WARN",
        f"LOGIN_FAIL username={username} ip={ip} "
        f"attempt={failed_attempts[username]}/{LOCKOUT_THRESHOLD}",
        ip,
    )

    if failed_attempts[username] >= LOCKOUT_THRESHOLD:
        lockout_count[username] += 1                         # increment before duration calc
        duration = _lockout_duration_for(username)
        lockout_until[username] = time.time() + duration
        failed_attempts[username] = 0                        # reset for next cycle
        stats["brute_blocked"] += 1

        log(
            "ALERT",
            f"ACCOUNT_LOCKED username={username} ip={ip} "
            f"duration={duration}s lockout_count={lockout_count[username]}",
            ip,
        )
        add_blocked_event(
            "BRUTE_FORCE",
            ip,
            f"Account '{username}' locked {duration}s (lockout #{lockout_count[username]})",
        )


def record_login_success(username: str, ip: str):
    failed_attempts[username]  = 0
    lockout_count[username]    = 0   # reset backoff on successful login
    if username in lockout_until:
        del lockout_until[username]

    stats["logins_success"] += 1
    log("INFO", f"LOGIN_OK username={username} ip={ip}", ip)

# ─────────────────────────────────────────────
# RESPONSE BUILDERS
# ─────────────────────────────────────────────
def build_generic_brute_failure(reason: str) -> Response:
    """
    Oracle hardening: all blocked login paths return the same page containing
    FAILURE_TEXT so Hydra's F= detection still works and attackers cannot
    distinguish lockout / rate-limit / SQLi block from a plain wrong password.
    """
    body = f"""
    <html>
      <head><title>Login</title></head>
      <body style="font-family:Arial,sans-serif;padding:24px">
        <h2>Login</h2>
        <p>{FAILURE_TEXT}</p>
        <p>Please try again later.</p>
      </body>
    </html>
    """
    resp = Response(body, status=200, mimetype="text/html")
    resp.headers["X-WAF-Decision"] = reason
    return resp


def build_block_page(title: str, detail: str, status_code: int) -> Response:
    body = f"""
    <html>
      <head><title>{escape(title)}</title></head>
      <body style="font-family:monospace;padding:24px">
        <h1 style="color:red">{escape(title)}</h1>
        <p>{escape(detail)}</p>
      </body>
    </html>
    """
    return Response(body, status=status_code, mimetype="text/html")

# ─────────────────────────────────────────────
# PROXY CORE
# ─────────────────────────────────────────────
STRIP_REQ_HEADERS = {
    "host", "content-length", "transfer-encoding",
    "connection", "keep-alive", "accept-encoding",
}

STRIP_RESP_HEADERS = {
    "content-length", "transfer-encoding", "connection", "content-encoding",
}


def forward_to_dvwa(target_url: str) -> Response:
    headers = {k: v for k, v in request.headers if k.lower() not in STRIP_REQ_HEADERS}
    headers["Accept-Encoding"] = "identity"

    try:
        upstream = req_lib.request(
            method=request.method,
            url=target_url,
            headers=headers,
            params=dict(request.args),
            data=dict(request.form),
            cookies=dict(request.cookies),
            allow_redirects=False,
            timeout=10,
        )
        resp_headers = [(k, v) for k, v in upstream.headers.items()
                        if k.lower() not in STRIP_RESP_HEADERS]
        return Response(upstream.content, status=upstream.status_code, headers=resp_headers)

    except Exception as e:
        log("ERROR", f"UPSTREAM_ERROR error={e}")
        return build_block_page("WAF — 502 Bad Gateway", "Upstream DVWA server unreachable.", 502)

# ─────────────────────────────────────────────
# MAIN ROUTE
# ─────────────────────────────────────────────
@app.route("/dvwa/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/dvwa/<path:path>",             methods=["GET", "POST"])
def proxy(path):
    ip            = request.remote_addr or "unknown"
    full_path     = normalize_dvwa_path(path)
    target_url    = f"{DVWA_TARGET}{full_path}"
    params        = dict(request.args)
    form_data     = dict(request.form)
    username, password, submit = extract_login_fields(params, form_data)
    brute_submission = is_brute_submission(full_path, params, form_data)

    submission_fp = None
    if brute_submission:
        submission_fp = make_submission_fingerprint(ip, full_path, username, password, submit)
        cached = get_cached_submission_response(submission_fp)
        if cached is not None:
            log("DEBUG", f"DUPLICATE_BRUTE_SUBMISSION username={username} ip={ip}", ip)
            return cached

    # Layer 3 — Rate limit
    if is_rate_limited(ip):
        stats["rate_limited"] += 1
        log("WARN", f"RATE_LIMITED ip={ip} path={full_path}", ip)
        add_blocked_event("RATE_LIMIT", ip, f"Exceeded {RATE_LIMIT_MAX} requests in {RATE_LIMIT_WINDOW}s")
        if brute_submission:
            response = build_generic_brute_failure("RATE_LIMIT")
            if submission_fp:
                cache_submission_response(submission_fp, response)
            return response
        return build_block_page(
            "WAF — 429 Too Many Requests",
            f"Rate limit exceeded: max {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW} seconds.",
            429,
        )

    # Layer 1 — SQLi filtering
    is_sqli, payload = scan_inputs(params, form_data)
    if is_sqli:
        stats["sqli_blocked"] += 1
        log("ALERT", f"SQLI_BLOCKED ip={ip} path={full_path} payload={payload!r}", ip)
        add_blocked_event("SQL_INJECTION", ip, payload)
        if brute_submission:
            response = build_generic_brute_failure("SQLI_BLOCK")
            if submission_fp:
                cache_submission_response(submission_fp, response)
            return response
        return build_block_page("WAF — 403 Forbidden", f"Suspicious input blocked: {payload}", 403)

    # Layer 2 — Lockout
    if brute_submission and username:
        locked, remaining = check_lockout(username)
        if locked:
            log("WARN", f"LOGIN_BLOCKED username={username} ip={ip} remaining={remaining}s", ip)
            add_blocked_event("LOCKOUT", ip, f"Blocked login for '{username}' ({remaining}s remaining)")
            response = build_generic_brute_failure("LOCKOUT")
            if submission_fp:
                cache_submission_response(submission_fp, response)
            return response

    # Forward to DVWA
    stats["requests_proxied"] += 1
    response = forward_to_dvwa(target_url)

    if brute_submission and username and password:
        body = response.get_data(as_text=True)
        if SUCCESS_TEXT in body:
            record_login_success(username, ip)
        elif FAILURE_TEXT in body:
            record_login_failure(username, ip)
        else:
            log("DEBUG",
                f"BRUTE_UNKNOWN username={username} ip={ip} "
                f"status={response.status_code} "
                f"location={response.headers.get('Location', '')}",
                ip)
        if submission_fp:
            cache_submission_response(submission_fp, response)

    return response

# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────
DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
  <title>WAF Dashboard </title>
  <meta http-equiv="refresh" content="5">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: "Courier New", monospace; background: #0d1117; color: #c9d1d9; padding: 24px; }
    h1   { color: #58a6ff; margin-bottom: 4px; font-size: 1.5em; }
    .sub { color: #8b949e; margin-bottom: 24px; font-size: 0.9em; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 28px; }
    .box  { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
    .num  { font-size: 2.2em; font-weight: bold; }
    .red  { color: #f85149; } .grn { color: #3fb950; } .blu { color: #58a6ff; }
    .ylw  { color: #d29922; }
    h2    { color: #f85149; margin: 18px 0 10px; font-size: 1em; letter-spacing: 1px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.83em; margin-bottom: 12px; }
    th    { background: #21262d; padding: 8px 10px; text-align: left; border-bottom: 1px solid #30363d; }
    td    { padding: 6px 10px; border-bottom: 1px solid #21262d; }
    .reset-btn { margin-top: 18px; background: #21262d; color: #c9d1d9; border: 1px solid #30363d;
                 padding: 8px 16px; cursor: pointer; border-radius: 6px; font-family: monospace; }
    .reset-btn:hover { background: #30363d; }
    .muted { color: #8b949e; }
    .badge-tls-on  { color: #3fb950; font-weight: bold; }
    .badge-tls-off { color: #8b949e; }
    .badge-enc-on  { color: #3fb950; font-weight: bold; }
  </style>
</head>
<body>
  <h1>&#x1F6E1; WAF Security Dashboard</h1>
  <div class="sub">
    Backend: {{ target }} |
    Lockout: {{ lockout_threshold }} failures / {{ lockout_duration }}s (base, exponential backoff) |
    Rate limit: {{ rate_limit_max }} req / {{ rate_limit_window }}s |
    TLS: <span class="{{ 'badge-tls-on' if tls_enabled else 'badge-tls-off' }}">{{ 'ON (:' + tls_port|string + ')' if tls_enabled else 'OFF' }}</span> |
    Log Enc: <span class="badge-enc-on">{{ 'AES-256-GCM' if log_encrypt else 'plaintext' }}</span> |
    Refresh: 5s
  </div>

  <div class="grid">
    <div class="box"><div class="num blu">{{ stats.requests_proxied }}</div><div>Requests Proxied</div></div>
    <div class="box"><div class="num red">{{ stats.sqli_blocked }}</div><div>SQLi Blocked</div></div>
    <div class="box"><div class="num red">{{ stats.brute_blocked }}</div><div>Lockout Events</div></div>
    <div class="box"><div class="num red">{{ stats.logins_failed }}</div><div>Failed Logins</div></div>
    <div class="box"><div class="num grn">{{ stats.logins_success }}</div><div>Successful Logins</div></div>
    <div class="box"><div class="num red">{{ stats.rate_limited }}</div><div>Rate Limited</div></div>
  </div>

  <h2>ACTIVE LOCKOUTS</h2>
  {% if active_lockouts %}
  <table>
    <tr><th>Username</th><th>Remaining</th><th>Total Duration</th><th>Lockout #</th><th>Next Duration</th></tr>
    {% for username, remaining, total, count in active_lockouts %}
    <tr>
      <td>{{ username }}</td>
      <td class="red">{{ remaining }}s</td>
      <td>{{ total }}s</td>
      <td class="ylw">{{ count }}</td>
      <td class="ylw">{{ [lockout_base * (2 ** count), lockout_max] | min }}s</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="muted">No accounts currently locked.</p>
  {% endif %}

  <h2>RECENT BLOCKED EVENTS</h2>
  {% if blocked_log %}
  <table>
    <tr><th>Time</th><th>Type</th><th>IP</th><th>Detail</th></tr>
    {% for e in blocked_log|reverse %}
    <tr><td>{{ e.time }}</td><td>{{ e.type }}</td><td>{{ e.ip }}</td><td>{{ e.detail }}</td></tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="muted">No blocked events yet.</p>
  {% endif %}

  <form method="POST" action="/waf/reset">
    <button class="reset-btn" type="submit">Reset Stats &amp; State</button>
  </form>
</body>
</html>
"""


@app.route("/waf/dashboard")
def dashboard():
    now = time.time()
    active_lockouts = []
    for username, until in lockout_until.items():
        remaining = int(until - now)
        if remaining > 0:
            count = lockout_count[username]
            total = int(min(LOCKOUT_DURATION * (2 ** (count - 1)), LOCKOUT_MAX_DURATION))
            active_lockouts.append((username, remaining, total, count))
    active_lockouts.sort(key=lambda x: x[0])

    return render_template_string(
        DASHBOARD,
        stats=stats,
        blocked_log=blocked_log,
        target=DVWA_TARGET,
        lockout_threshold=LOCKOUT_THRESHOLD,
        lockout_duration=LOCKOUT_DURATION,
        lockout_base=LOCKOUT_DURATION,
        lockout_max=LOCKOUT_MAX_DURATION,
        rate_limit_max=RATE_LIMIT_MAX,
        rate_limit_window=RATE_LIMIT_WINDOW,
        active_lockouts=active_lockouts,
        tls_enabled=USE_TLS,
        tls_port=WAF_TLS_PORT,
        log_encrypt=LOG_ENCRYPT,
    )


@app.route("/waf/reset", methods=["POST"])
def reset():
    for key in stats:
        stats[key] = 0
    blocked_log.clear()
    failed_attempts.clear()
    lockout_until.clear()
    lockout_count.clear()       # [v2] clear exponential backoff counters
    ip_request_log.clear()
    recent_submission_cache.clear()
    log("INFO", "WAF state reset via dashboard")
    return redirect("/waf/dashboard")


@app.route("/")
def root():
    return redirect("/dvwa/")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # ── Decrypt mode ──────────────────────────────────────────────────────────
    if "--decrypt" in sys.argv:
        print(f"[Decrypting {LOG_FILE} with key from {LOG_KEY_FILE}]\n")
        decrypt_log()
        sys.exit(0)

    # ── Startup logging ───────────────────────────────────────────────────────
    proto = "https" if USE_TLS else "http"
    port  = WAF_TLS_PORT if USE_TLS else WAF_PORT

    log("INFO", f"WAF proxy starting on {WAF_HOST}:{port} -> {DVWA_TARGET}")
    log("INFO",
        f"Config: lockout={LOCKOUT_THRESHOLD}/{LOCKOUT_DURATION}s (exp backoff, max={LOCKOUT_MAX_DURATION}s) | "
        f"rate_limit={RATE_LIMIT_MAX}/{RATE_LIMIT_WINDOW}s | dedup={DEDUP_WINDOW}s")
    log("INFO", f"Log encryption: {'AES-256-GCM (' + LOG_KEY_FILE + ')' if LOG_ENCRYPT else 'disabled (plaintext)'}")
    log("INFO", f"TLS: {'enabled, cert=' + TLS_CERT_FILE if USE_TLS else 'disabled (HTTP)'}")
    log("INFO", f"Dashboard: {proto}://10.0.0.1:{port}/waf/dashboard")

    # ── TLS setup ────────────────────────────────────────────────────────────
    if USE_TLS:
        ensure_tls_cert()
        ssl_context = (TLS_CERT_FILE, TLS_KEY_FILE)
    else:
        ssl_context = None

    app.run(host=WAF_HOST, port=port, debug=False, ssl_context=ssl_context)
