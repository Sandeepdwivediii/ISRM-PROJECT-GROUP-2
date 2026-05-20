"""
================================================================================
  VULNERABLE STUDENT MANAGEMENT SYSTEM (SMS)
  Phase 2 – Intentionally Vulnerable Application for Security Research
  Course: Information Security & Risk Management

 

  Vulnerabilities Included (mapped to MITRE ATT&CK Phase 1):
  1.**  Brute Force / Credential Stuffing    – No account lockout, no CAPTCHA
  2.  SQL Injection                         – Raw f-string queries, no parameterization
  3.  Insecure File Upload                  – No file type validation
  4.  Broken Authentication                 – Weak passwords, plain-text storage
  5.**  Privilege Escalation (IDOR)           – URL parameter role=admin accepted
  6.**  Session Hijacking                     – No HttpOnly/Secure cookie flags
  7.  Sensitive Data Exposure               – Plain-text passwords in DB & responses
  8.**   Information Disclosure                – Verbose error messages with stack traces
  9.  Log Injection / No Logging Integrity  – User input written directly to logs
  10. Command Injection                     – OS commands built from user input
  11.** Path Traversal                        – File download path not sanitized
  12. Parameter Tampering                   – Hidden form fields accepted at face value
  13. XSS (stored)                          – Profile fields rendered without escaping
  14. Business Logic Flaw                   – Grade override without authorization
  15. DoS via Login Flooding                – No rate limiting on login endpoint
================================================================================
"""

import os
import sqlite3
import subprocess
import logging
from datetime import datetime
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, make_response, jsonify, g
)

# ── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

# VULN-06: Hardcoded, short, guessable secret key → weak session signing
app.secret_key = "sms123"

# VULN-09: Log file with no integrity protection; raw user data written to it
logging.basicConfig(
    filename="logs/sms.log",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s"
)

DATABASE = "sms.db"
UPLOAD_FOLDER = "uploads"


# ── Database Helpers ───────────────────────────────────────────────────────────
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Seed the database with intentionally weak data."""
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT UNIQUE NOT NULL,
                password  TEXT NOT NULL,          -- VULN-04: plain-text passwords
                role      TEXT DEFAULT 'student', -- student | faculty | admin
                email     TEXT,
                full_name TEXT
            );

            CREATE TABLE IF NOT EXISTS students (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                roll_no     TEXT UNIQUE,
                full_name   TEXT,
                dob         TEXT,
                address     TEXT,
                phone       TEXT,
                national_id TEXT,                 -- VULN-07: PII stored unencrypted
                gpa         REAL DEFAULT 0.0,
                financial_aid TEXT
            );

            CREATE TABLE IF NOT EXISTS grades (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER,
                course     TEXT,
                marks      INTEGER,
                grade      TEXT
            );

            CREATE TABLE IF NOT EXISTS files (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                uploader  TEXT,
                filename  TEXT,
                filepath  TEXT,
                upload_ts TEXT
            );

            -- Seed users (plain-text passwords – VULN-04)
            INSERT OR IGNORE INTO users (username, password, role, email, full_name)
            VALUES
                ('admin',        'admin123',   'admin',   'admin@university.edu',   'System Admin'),
                ('john.smith',   'password1',  'student', 'john@university.edu',    'John Smith'),
                ('jane.doe',     'jane2024',   'student', 'jane@university.edu',    'Jane Doe'),
                ('prof.kumar',   'faculty99',  'faculty', 'kumar@university.edu',   'Prof. Raj Kumar'),
                ('alice.wang',   'alice123',   'student', 'alice@university.edu',   'Alice Wang');

            -- Seed students
            INSERT OR IGNORE INTO students
                (user_id, roll_no, full_name, dob, address, phone, national_id, gpa, financial_aid)
            VALUES
                (2, 'CS2021001', 'John Smith',  '2002-04-15', '42 Elm Street, NY',   '9876543210', 'NID-JH-001', 3.7, 'Merit Scholarship $5000'),
                (3, 'CS2021002', 'Jane Doe',   '2003-07-22', '17 Oak Avenue, CA',   '9876543211', 'NID-JD-002', 3.2, 'Need-Based Aid $3000'),
                (5, 'CS2021003', 'Alice Wang', '2002-11-30', '8 Pine Road, TX',     '9876543212', 'NID-AW-003', 3.9, 'Research Grant $7000');

            -- Seed grades
            INSERT OR IGNORE INTO grades (student_id, course, marks, grade)
            VALUES
                (1, 'Data Structures',     88, 'A'),
                (1, 'Operating Systems',   72, 'B'),
                (2, 'Data Structures',     65, 'C'),
                (2, 'Database Systems',    78, 'B+'),
                (3, 'Algorithms',          95, 'A+');
        """)
        db.commit()


# ── Vulnerability Banner (printed in terminal) ─────────────────────────────────
VULN_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║   VULNERABLE SMS – PHASE 2  (Educational Use Only)              ║
║   Running at: http://127.0.0.1:5000                              ║
║                                                                  ║
║   Default Credentials:                                           ║
║     admin / admin123   (admin)                                   ║
║     john.smith / password1  (student)                            ║
║     prof.kumar / faculty99  (faculty)                            ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ── Home ───────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))


# ── Login  (VULN-01 Brute Force | VULN-02 SQL Injection | VULN-04 Broken Auth
#           | VULN-08 Verbose Errors | VULN-09 Log Injection | VULN-15 DoS) ──────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULN-09: Log injection – raw user-controlled input written to log file
        logging.info(f"LOGIN ATTEMPT | user={username} | ip={request.remote_addr}")

        # VULN-02: SQL Injection – raw string interpolation, no parameterization
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            db = get_db()
            user = db.execute(query).fetchone()
        except Exception as e:
            # VULN-08: Information Disclosure – full exception + raw query exposed
            return render_template("error.html", error=str(e), query=query), 500

        if user:
            # VULN-06: Session cookie has no HttpOnly/Secure flags (set below)
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            session["role"]     = user["role"]   # VULN-05: role stored client-side in session
            session["full_name"]= user["full_name"]
            logging.info(f"LOGIN SUCCESS | user={username} | role={user['role']}")
            return redirect(url_for("dashboard"))
        else:
            # VULN-08: Reveals whether the username exists (different messages)
            db2 = get_db()
            user_exists = db2.execute(
                f"SELECT id FROM users WHERE username='{username}'"
            ).fetchone()
            if user_exists:
                error = "Incorrect password for user: " + username
            else:
                error = f"No account found with username '{username}'"

    resp = make_response(render_template("login.html", error=error))
    # VULN-06: Session cookie missing HttpOnly and Secure flags → XSS can steal it
    resp.set_cookie("sms_session", session.get("username", ""), httponly=False, secure=False)
    return resp


# ── Logout ────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Dashboard ──────────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-05: role can be overridden via URL param → privilege escalation
    role = request.args.get("role", session.get("role", "student"))
    session["role"] = role  # persists the tampered role

    db = get_db()
    students = db.execute("SELECT * FROM students").fetchall()
    return render_template("dashboard.html",
                           user=session,
                           role=role,
                           students=students)


# ── Student Search  (VULN-02 SQL Injection) ────────────────────────────────────
@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect(url_for("login"))

    query_param = request.args.get("q", "")
    results = []
    raw_query = ""
    error = None

    if query_param:
        # VULN-02: SQL Injection – unsanitized input directly in query
        raw_query = (
            f"SELECT s.*, u.email, u.password FROM students s "
            f"JOIN users u ON s.user_id = u.id "
            f"WHERE s.full_name LIKE '%{query_param}%' "
            f"OR s.roll_no = '{query_param}'"
        )
        try:
            db = get_db()
            results = db.execute(raw_query).fetchall()
        except Exception as e:
            # VULN-08: Raw SQL error + query string returned to client
            error = f"DB Error: {e} | Query: {raw_query}"

    return render_template("search.html",
                           results=results,
                           query=query_param,
                           raw_query=raw_query,
                           error=error)


# ── Student Profile  (VULN-05 IDOR | VULN-07 Data Exposure | VULN-13 XSS) ──────
@app.route("/student/<int:student_id>")
def student_profile(student_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-05: IDOR – no check that the logged-in user owns this profile
    db = get_db()
    student = db.execute(
        "SELECT s.*, u.email, u.password, u.username FROM students s "
        "JOIN users u ON s.user_id = u.id WHERE s.id = ?", (student_id,)
    ).fetchone()

    grades = db.execute(
        "SELECT * FROM grades WHERE student_id = ?", (student_id,)
    ).fetchall()

    # VULN-07: Sensitive data (plain-text password, national_id, financial_aid) returned to any logged-in user
    return render_template("profile.html", student=student, grades=grades)


# ── Grade Override  (VULN-12 Parameter Tampering | VULN-14 Business Logic) ─────
@app.route("/grade/update", methods=["POST"])
def update_grade():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-12 & 14: No role check – any student can POST this form to change grades
    student_id = request.form.get("student_id")
    course     = request.form.get("course")
    new_marks  = request.form.get("marks")
    new_grade  = request.form.get("grade")

    db = get_db()
    db.execute(
        "UPDATE grades SET marks=?, grade=? WHERE student_id=? AND course=?",
        (new_marks, new_grade, student_id, course)
    )
    db.commit()
    logging.info(f"GRADE UPDATE | by={session.get('username')} | student={student_id} | course={course} | grade={new_grade}")
    return redirect(url_for("student_profile", student_id=student_id))


# ── File Upload  (VULN-03 Insecure Upload | VULN-07 No AV Scan) ───────────────
@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    message = None
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # VULN-03: No file type validation – .php, .py, .sh files accepted
            # VULN-03: No content inspection, no AV scanning
            filename = f.filename  # VULN-03: Original filename used directly (path traversal possible)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            f.save(filepath)

            db = get_db()
            db.execute(
                "INSERT INTO files (uploader, filename, filepath, upload_ts) VALUES (?,?,?,?)",
                (session["username"], filename, filepath, datetime.now().isoformat())
            )
            db.commit()
            # VULN-08: Full server path disclosed in success message
            message = f"File uploaded successfully: {os.path.abspath(filepath)}"
            logging.info(f"FILE UPLOAD | user={session['username']} | file={filename} | path={filepath}")

    db = get_db()
    files = db.execute("SELECT * FROM files").fetchall()
    return render_template("upload.html", message=message, files=files)


# ── File Download  (VULN-11 Path Traversal) ────────────────────────────────────
@app.route("/download")
def download_file():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-11: Path traversal – filename not sanitized, allows ../../etc/passwd
    filename = request.args.get("file", "")
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(filepath, "rb") as fh:
            content = fh.read()
        # VULN-08: File content (potentially sensitive) returned directly
        resp = make_response(content)
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp
    except Exception as e:
        # VULN-08: Full path + exception details disclosed
        return render_template("error.html",
                               error=f"Cannot read file '{filepath}': {e}",
                               query=filepath), 404


# ── System Diagnostics  (VULN-10 Command Injection) ───────────────────────────
@app.route("/admin/diagnostics", methods=["GET", "POST"])
def diagnostics():
    if "user_id" not in session:
        return redirect(url_for("login"))

    output = ""
    cmd = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        # VULN-10: Command injection – host value injected directly into shell command
        cmd = f"ping -c 2 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True,
                                             stderr=subprocess.STDOUT,
                                             timeout=5).decode()
        except Exception as e:
            # VULN-08: Stack trace / system output exposed
            output = f"Error: {e}"

    return render_template("diagnostics.html", output=output, cmd=cmd)


# ── Profile Update  (VULN-13 Stored XSS | VULN-12 Parameter Tampering) ─────────
@app.route("/profile/update", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-13: No HTML encoding – XSS payload stored in DB and rendered unescaped
    # VULN-12: user_id taken from form, not from session → IDOR
    user_id   = request.form.get("user_id")          # should use session["user_id"]
    full_name = request.form.get("full_name", "")    # XSS payload goes here
    address   = request.form.get("address", "")
    phone     = request.form.get("phone", "")

    db = get_db()
    db.execute(
        "UPDATE students SET full_name=?, address=?, phone=? WHERE user_id=?",
        (full_name, address, phone, user_id)
    )
    db.commit()
    student = db.execute("SELECT id FROM students WHERE user_id=?", (user_id,)).fetchone()
    if student:
        return redirect(url_for("student_profile", student_id=student["id"]))
    return redirect(url_for("dashboard"))


# ── Admin Panel  (VULN-05 Role Bypass) ────────────────────────────────────────
@app.route("/admin")
def admin_panel():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # VULN-2a: Role check uses session["role"] which can be poisoned via ?role=admin*******
    if session.get("role") != "admin":
        return render_template("error.html",
                               error="Access Denied – Admins only",
                               query=""), 403

    db = get_db()
    users    = db.execute("SELECT * FROM users").fetchall()     # VULN-07: includes plain-text passwords
    students = db.execute("SELECT * FROM students").fetchall()
    files    = db.execute("SELECT * FROM files").fetchall()
    logs     = _read_logs()
    return render_template("admin.html", users=users, students=students,
                           files=files, logs=logs)


# ── Log Viewer / Log Injection  (VULN-09) ──────────────────────────────────────
@app.route("/admin/logs")
def view_logs():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    logs = _read_logs()
    return render_template("logs.html", logs=logs)


@app.route("/admin/logs/inject", methods=["POST"])
def inject_log():
    """VULN-09: Endpoint that accepts arbitrary log injection (no sanitization)."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    fake_entry = request.form.get("log_entry", "")
    # VULN-09: Forged log entry written directly – attacker can fake timestamps & users
    logging.info(f"[INJECTED] {fake_entry}")
    return redirect(url_for("view_logs"))


@app.route("/admin/logs/clear", methods=["POST"])
def clear_logs():
    """VULN-09: Any admin (or role-tampered user) can wipe the entire log."""
    if session.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403
    with open("logs/sms.log", "w") as f:
        f.write("")
    return redirect(url_for("view_logs"))


def _read_logs():
    try:
        with open("logs/sms.log", "r") as f:
            return f.readlines()[-200:]
    except Exception:
        return []


# ── API: Bulk Data Export  (VULN-07 Sensitive Data Exposure | VULN-08) ─────────
@app.route("/api/students")
def api_students():
    """VULN-07: No auth check on API endpoint; returns all PII + passwords."""
    db = get_db()
    # VULN-07: password field included; VULN-08: no pagination or rate limit
    rows = db.execute(
        "SELECT s.*, u.username, u.password, u.email FROM students s "
        "JOIN users u ON s.user_id = u.id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── Error Handlers  (VULN-08 Verbose Errors) ──────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    # VULN-08: Full URL path revealed in error
    return render_template("error.html",
                           error=f"404 – Page not found: {request.url}",
                           query=request.url), 404


@app.errorhandler(500)
def server_error(e):
    # VULN-08: Full exception including stack trace returned
    import traceback
    return render_template("error.html",
                           error=str(e),
                           query=traceback.format_exc()), 500


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    try:
        print(VULN_BANNER)
    except UnicodeEncodeError:
        # Fallback for terminals that cannot render box-drawing characters.
        print(VULN_BANNER.encode("ascii", "replace").decode("ascii"))
    # VULN-08: Debug mode ON in production → full stack traces to browser
    app.run(debug=True, host="0.0.0.0", port=5000)
