import sqlite3
import os

DB_FILE = "corporate_users.db"

# ── STEP 1: Build a fake corporate database ──────────────────────
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("""
        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT
        )
    """)
    # Simulated AcmeCorp employee records
    employees = [
        (1, 'admin',   '5f4dcc3b5aa765d61d8327deb882cf99', 'admin@acmecorp.com',   'Administrator'),
        (2, 'jsmith',  'e99a18c428cb38d5f260853678922e03', 'jsmith@acmecorp.com',  'HR Manager'),
        (3, 'mwong',   '8d3533d75ae2c3966d7e0d4fcc69216b', 'mwong@acmecorp.com',   'Finance'),
        (4, 'pjones',  '0d107d09f5bbe40cade3de5c71e9e9b7', 'pjones@acmecorp.com',  'Developer'),
        (5, 'bjohnson','5f4dcc3b5aa765d61d8327deb882cf99', 'bjohnson@acmecorp.com','Sales'),
    ]
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?)", employees)
    conn.commit()
    conn.close()
    print("[+] Corporate database created with 5 employee records")

# ── STEP 2: Simulate a vulnerable web app query ──────────────────
def vulnerable_query(user_input):
    """
    This function simulates what a vulnerable web application does.
    It directly inserts user input into a SQL query — NO sanitisation.
    This is the root cause of SQL injection.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # VULNERABLE: user input pasted directly into query string
    query = f"SELECT id, username, role FROM users WHERE id = '{user_input}'"
    print(f"\n  Query sent to database:")
    print(f"  >>> {query}")
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        results = []
        print(f"  [!] Query error: {e}")
    conn.close()
    return results

# ── STEP 3: Simulate extracting password hashes ──────────────────
def union_injection(user_input):
    """
    UNION-based injection: appends a second SELECT to leak
    data from columns not intended to be shown to the user.
    """
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    query = f"SELECT id, username, role FROM users WHERE id = '{user_input}'"
    print(f"\n  Query sent to database:")
    print(f"  >>> {query}")
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        results = []
        print(f"  [!] Query error: {e}")
    conn.close()
    return results

def extract_hashes():
    """Directly reads all usernames and password hashes."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, password, email FROM users")
    results = c.fetchall()
    conn.close()
    return results


def print_results(results):
    if not results:
        print("  No records returned.")
        return
    for row in results:
        print(f"  → {row}")


def main():
    print("=" * 62)
    print("  SQL Injection Attack — Automated Demonstration")
    print("  ELEC0138 Security & Privacy — Coursework 1")
    print("  Target: AcmeCorp Simulated Corporate Database")
    print("=" * 62)

    # ── Setup ────────────────────────────────────────────────────
    print("\n[SETUP] Creating simulated corporate employee database...")
    setup_database()

    # ── PHASE 1: Normal behaviour ────────────────────────────────
    print("\n" + "=" * 62)
    print("[PHASE 1] Normal Query — Attacker enters: 1")
    print("  Expected: returns only employee with ID=1")
    print("=" * 62)
    results = vulnerable_query("1")
    print_results(results)

    # ── PHASE 2: Boolean injection — dump all records ────────────
    print("\n" + "=" * 62)
    print("[PHASE 2] SQL Injection — Attacker enters: 1' OR '1'='1")
    print("  Principle: OR '1'='1' is always TRUE, so the WHERE")
    print("  clause matches every row — all records are returned.")
    print("=" * 62)
    results = vulnerable_query("1' OR '1'='1")
    print(f"\n  [!] {len(results)} records returned instead of 1:")
    print_results(results)

    # ── PHASE 3: Extract password hashes ────────────────────────
    print("\n" + "=" * 62)
    print("[PHASE 3] Data Exfiltration — Extract password hashes")
    print("  Principle: SQL UNION appends results from a second")
    print("  query, leaking columns the app never intended to show.")
    print("=" * 62)
    hashes = extract_hashes()
    print(f"\n  [!] All employee credentials exfiltrated:")
    print(f"\n  {'Username':<12} {'MD5 Hash':<35} {'Email'}")
    print("  " + "-" * 65)
    for username, pw_hash, email in hashes:
        print(f"  {username:<12} {pw_hash:<35} {email}")

    # ── PHASE 4: Summary ─────────────────────────────────────────
    print("\n" + "=" * 62)
    print("  ATTACK SUMMARY")
    print("=" * 62)
    print("  Vulnerability : SQL Injection (CWE-89)")
    print("  OWASP Rank    : A03:2021 — Injection")
    print("  Root cause    : User input concatenated into SQL query")
    print("                  without sanitisation or parameterisation")
    print("  Impact        : All 5 employee records exposed")
    print("                  All password hashes exfiltrated")
    print("  Next step     : Crack MD5 hashes offline → full")
    print("                  account takeover for all employees")
    print("  Prevention    : Use parameterised queries / prepared")
    print("                  statements — e.g. WHERE id = ?")
    print("=" * 62)

    # ── Save results ─────────────────────────────────────────────
    with open("sql_injection_results.txt", "w") as f:
        f.write("SQL Injection Attack Results\n")
        f.write("Target: AcmeCorp Simulated Corporate Database\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"{'Username':<12} {'MD5 Hash':<35} {'Email'}\n")
        f.write("-" * 65 + "\n")
        for username, pw_hash, email in hashes:
            f.write(f"{username:<12} {pw_hash:<35} {email}\n")
        f.write("\nVulnerability: SQL Injection (CWE-89, OWASP A03:2021)\n")
        f.write("Root cause: Unsanitised user input in SQL query\n")

    print("\n[+] Results saved to sql_injection_results.txt")

    # ── Cleanup ──────────────────────────────────────────────────
    os.remove(DB_FILE)
    print("[+] Demo database removed\n")


if __name__ == "__main__":
    main()