#!/usr/bin/env python3
"""
ELEC0138 CW2 — Flask WAF Reverse Proxy

Defensive Flask reverse proxy for a DVWA lab environment.

Architecture:
  Browser / demo client  --->  WAF proxy (this app)  --->  DVWA backend

Main functions:
  Layer 1 — SQL injection filtering
  Layer 2 — Account lockout on repeated failed brute-force logins
  Layer 3 — IP rate limiting
  Layer 4 — Audit logging + live dashboard
  Layer 5 — Privacy-preserving IP pseudonymisation in logs

Important implementation notes:
  - The backend DVWA application remains vulnerable.
  - The WAF sits in front of it and blocks malicious traffic.
  - For brute-force submissions that are blocked, the proxy returns a
    generic login-failure-style page to avoid obvious false positives.
  - Compression headers are handled carefully to avoid browser
    "content encoding" errors.
"""

from flask import Flask, request, Response, render_template_string, redirect
import requests as req_lib
import re
import time
import hashlib
from html import escape
from datetime import datetime
from collections import defaultdict

app = Flask(__name__)

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DVWA_TARGET = "http://10.0.0.2"
WAF_HOST = "0.0.0.0"
WAF_PORT = 5000

LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 60          # seconds
RATE_LIMIT_MAX = 20            # requests
RATE_LIMIT_WINDOW = 30         # seconds
DEDUP_WINDOW = 2.0             # seconds; ignore identical repeated brute submissions

LOG_FILE = "waf_audit.log"

FAILURE_TEXT = "Username and/or password incorrect."
SUCCESS_TEXT = "Welcome to the password protected area"

# ─────────────────────────────────────────────
# IN-MEMORY STATE
# ─────────────────────────────────────────────
failed_attempts = defaultdict(int)      # username -> count
lockout_until = {}                      # username -> unix timestamp
ip_request_log = defaultdict(list)      # ip -> list[timestamps]
recent_submission_cache = {}            # fingerprint -> cached response

stats = {
    "requests_proxied": 0,
    "sqli_blocked": 0,
    "logins_failed": 0,
    "brute_blocked": 0,
    "rate_limited": 0,
    "logins_success": 0,
}

blocked_log = []

# ─────────────────────────────────────────────
# LOGGING / PRIVACY
# ─────────────────────────────────────────────
def pseudonymise_ip(ip: str) -> str:
    return "ip-" + hashlib.sha256(ip.encode()).hexdigest()[:12]


def log(level: str, message: str, ip: str = ""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_message = message.replace(ip, pseudonymise_ip(ip)) if ip else message
    line_term = f"[{ts}] [{level}] {message}"
    line_file = f"[{ts}] [{level}] {safe_message}"

    print(line_term)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line_file + "\n")


def add_blocked_event(event_type: str, ip: str, detail: str):
    blocked_log.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": event_type,
        "ip": ip,
        "detail": detail[:120],
    })
    if len(blocked_log) > 100:
        blocked_log.pop(0)

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def cleanup_recent_cache():
    now = time.time()
    expired = [
        key for key, value in recent_submission_cache.items()
        if now - value["ts"] > DEDUP_WINDOW
    ]
    for key in expired:
        del recent_submission_cache[key]


def make_submission_fingerprint(ip: str, full_path: str, username: str, password: str, submit: str) -> str:
    raw = f"{ip}|{full_path}|{username}|{password}|{submit}"
    return hashlib.sha256(raw.encode()).hexdigest()


def get_cached_submission_response(fingerprint: str):
    cleanup_recent_cache()
    entry = recent_submission_cache.get(fingerprint)
    if not entry:
        return None

    return Response(
        entry["body"],
        status=entry["status"],
        mimetype=entry["mimetype"],
        headers=entry["headers"],
    )


def cache_submission_response(fingerprint: str, response: Response):
    headers = {}
    for k, v in response.headers.items():
        if k.lower() not in {"content-length", "transfer-encoding", "connection"}:
            headers[k] = v

    recent_submission_cache[fingerprint] = {
        "ts": time.time(),
        "body": response.get_data(),
        "status": response.status_code,
        "mimetype": response.mimetype,
        "headers": headers,
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
    password = form_data.get("password") or params.get("password") or ""
    submit = (form_data.get("Login") or params.get("Login") or "").strip()
    return username, password, submit


def is_brute_path(full_path: str) -> bool:
    return full_path.rstrip("/") == "/dvwa/vulnerabilities/brute"


def is_brute_submission(full_path: str, params: dict, form_data: dict) -> bool:
    username, password, submit = extract_login_fields(params, form_data)
    return is_brute_path(full_path) and bool(username) and bool(password) and submit == "Login"

# ─────────────────────────────────────────────
# SQLi FILTERING
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
    merged = {}
    merged.update(params)
    merged.update(form_data)

    for key, value in merged.items():
        if isinstance(value, str) and detect_sqli(value):
            return True, f"{key}={value[:80]}"
    return False, ""

# ─────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────
def is_rate_limited(ip: str) -> bool:
    now = time.time()
    ip_request_log[ip] = [t for t in ip_request_log[ip] if now - t < RATE_LIMIT_WINDOW]
    ip_request_log[ip].append(now)
    return len(ip_request_log[ip]) > RATE_LIMIT_MAX

# ─────────────────────────────────────────────
# ACCOUNT LOCKOUT
# ─────────────────────────────────────────────
def check_lockout(username: str):
    now = time.time()
    until = lockout_until.get(username)

    if until is None:
        return False, 0

    if now < until:
        return True, int(until - now)

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
        lockout_until[username] = time.time() + LOCKOUT_DURATION
        stats["brute_blocked"] += 1
        log(
            "ALERT",
            f"ACCOUNT_LOCKED username={username} ip={ip} duration={LOCKOUT_DURATION}s",
            ip,
        )
        add_blocked_event(
            "BRUTE_FORCE",
            ip,
            f"Account '{username}' locked after {LOCKOUT_THRESHOLD} failed logins",
        )


def record_login_success(username: str, ip: str):
    failed_attempts[username] = 0
    if username in lockout_until:
        del lockout_until[username]

    stats["logins_success"] += 1
    log("INFO", f"LOGIN_OK username={username} ip={ip}", ip)

# ─────────────────────────────────────────────
# RESPONSE BUILDERS
# ─────────────────────────────────────────────
def build_generic_brute_failure(reason: str) -> Response:
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
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "accept-encoding",   # important: prevent broken compression handling
}

STRIP_RESP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "content-encoding",  # important: avoid browser decoding errors
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

        response_headers = [
            (k, v)
            for k, v in upstream.headers.items()
            if k.lower() not in STRIP_RESP_HEADERS
        ]

        return Response(
            upstream.content,
            status=upstream.status_code,
            headers=response_headers,
        )

    except Exception as e:
        log("ERROR", f"UPSTREAM_ERROR error={e}")
        return build_block_page("WAF — 502 Bad Gateway", "Upstream DVWA server unreachable.", 502)

# ─────────────────────────────────────────────
# MAIN ROUTE
# ─────────────────────────────────────────────
@app.route("/dvwa/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/dvwa/<path:path>", methods=["GET", "POST"])
def proxy(path):
    ip = request.remote_addr or "unknown"
    full_path = normalize_dvwa_path(path)
    target_url = f"{DVWA_TARGET}{full_path}"

    params = dict(request.args)
    form_data = dict(request.form)

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

        return build_block_page(
            "WAF — 403 Forbidden",
            f"Suspicious input blocked: {payload}",
            403,
        )

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

    # Post-response brute-force outcome detection
    if brute_submission and username and password:
        body = response.get_data(as_text=True)

        if SUCCESS_TEXT in body:
            record_login_success(username, ip)

        elif FAILURE_TEXT in body:
            record_login_failure(username, ip)

        else:
            log(
                "DEBUG",
                f"BRUTE_UNKNOWN username={username} ip={ip} "
                f"status={response.status_code} "
                f"location={response.headers.get('Location', '')}",
                ip,
            )

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
  <title>WAF Dashboard — ELEC0138 CW2</title>
  <meta http-equiv="refresh" content="5">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "Courier New", monospace;
      background: #0d1117;
      color: #c9d1d9;
      padding: 24px;
    }
    h1 { color: #58a6ff; margin-bottom: 4px; font-size: 1.5em; }
    .sub { color: #8b949e; margin-bottom: 24px; font-size: 0.9em; }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      margin-bottom: 28px;
    }
    .box {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 16px;
      text-align: center;
    }
    .num { font-size: 2.2em; font-weight: bold; }
    .red { color: #f85149; }
    .grn { color: #3fb950; }
    .blu { color: #58a6ff; }
    h2 {
      color: #f85149;
      margin: 18px 0 10px;
      font-size: 1em;
      letter-spacing: 1px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.83em;
      margin-bottom: 12px;
    }
    th {
      background: #21262d;
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid #30363d;
    }
    td {
      padding: 6px 10px;
      border-bottom: 1px solid #21262d;
    }
    .reset-btn {
      margin-top: 18px;
      background: #21262d;
      color: #c9d1d9;
      border: 1px solid #30363d;
      padding: 8px 16px;
      cursor: pointer;
      border-radius: 6px;
      font-family: monospace;
    }
    .reset-btn:hover { background: #30363d; }
    .muted { color: #8b949e; }
  </style>
</head>
<body>
  <h1>&#x1F6E1; WAF Security Dashboard</h1>
  <div class="sub">
    Backend: {{ target }} |
    Lockout: {{ lockout_threshold }} failures / {{ lockout_duration }}s |
    Rate limit: {{ rate_limit_max }} req / {{ rate_limit_window }}s |
    Refresh: 5s
  </div>

  <div class="grid">
    <div class="box">
      <div class="num blu">{{ stats.requests_proxied }}</div>
      <div>Requests Proxied</div>
    </div>
    <div class="box">
      <div class="num red">{{ stats.sqli_blocked }}</div>
      <div>SQLi Blocked</div>
    </div>
    <div class="box">
      <div class="num red">{{ stats.brute_blocked }}</div>
      <div>Lockout Events</div>
    </div>
    <div class="box">
      <div class="num red">{{ stats.logins_failed }}</div>
      <div>Failed Logins</div>
    </div>
    <div class="box">
      <div class="num grn">{{ stats.logins_success }}</div>
      <div>Successful Logins</div>
    </div>
    <div class="box">
      <div class="num red">{{ stats.rate_limited }}</div>
      <div>Rate Limited</div>
    </div>
  </div>

  <h2>ACTIVE LOCKOUTS</h2>
  {% if active_lockouts %}
  <table>
    <tr><th>Username</th><th>Seconds Remaining</th></tr>
    {% for username, remaining in active_lockouts %}
    <tr><td>{{ username }}</td><td>{{ remaining }}</td></tr>
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
    <tr>
      <td>{{ e.time }}</td>
      <td>{{ e.type }}</td>
      <td>{{ e.ip }}</td>
      <td>{{ e.detail }}</td>
    </tr>
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
            active_lockouts.append((username, remaining))

    active_lockouts.sort(key=lambda x: x[0])

    return render_template_string(
        DASHBOARD,
        stats=stats,
        blocked_log=blocked_log,
        target=DVWA_TARGET,
        lockout_threshold=LOCKOUT_THRESHOLD,
        lockout_duration=LOCKOUT_DURATION,
        rate_limit_max=RATE_LIMIT_MAX,
        rate_limit_window=RATE_LIMIT_WINDOW,
        active_lockouts=active_lockouts,
    )


@app.route("/waf/reset", methods=["POST"])
def reset():
    for key in stats:
        stats[key] = 0

    blocked_log.clear()
    failed_attempts.clear()
    lockout_until.clear()
    ip_request_log.clear()
    recent_submission_cache.clear()

    log("INFO", "WAF state reset via dashboard")
    return redirect("/waf/dashboard")


@app.route("/")
def root():
    return redirect("/dvwa/")


if __name__ == "__main__":
    log("INFO", f"WAF proxy starting on {WAF_HOST}:{WAF_PORT} -> {DVWA_TARGET}")
    log(
        "INFO",
        f"Config: lockout={LOCKOUT_THRESHOLD}/{LOCKOUT_DURATION}s | "
        f"rate_limit={RATE_LIMIT_MAX}/{RATE_LIMIT_WINDOW}s | "
        f"dedup={DEDUP_WINDOW}s"
    )
    log("INFO", f"Dashboard: http://10.0.0.1:{WAF_PORT}/waf/dashboard")
    app.run(host=WAF_HOST, port=WAF_PORT, debug=False)
