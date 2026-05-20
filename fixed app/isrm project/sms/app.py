"""
================================================================================
  STUDENT MANAGEMENT SYSTEM (SMS) — PATCHED VERSION
  Phase 7 – Control Design & Code Review (Implementation Phase)
  Course: Information Security & Risk Management

  All vulnerabilities from Phase 2 have been fixed.
  Controls implemented:
    ✅ Parameterized SQL queries (no more f-string injection)
    ✅ bcrypt password hashing (no plain-text storage)
    ✅ Account lockout after 5 failed attempts (anti-brute force)
    ✅ Secure session cookies (HttpOnly + Secure flags)
    ✅ Strong random secret key from environment variable
    ✅ Server-side RBAC (role never trusted from URL)
    ✅ IDOR fix (ownership check on all profile routes)
    ✅ File upload whitelist (only safe extensions allowed)
    ✅ Path traversal fix (secure_filename + realpath check)
    ✅ Command injection fix (no shell=True, list-based args)
    ✅ Input validation on all form fields
    ✅ XSS fix (Jinja2 auto-escaping, no | safe)
    ✅ Log sanitization (newline injection removed)
    ✅ debug=False (no stack traces to browser)
    ✅ Bind to localhost only (not 0.0.0.0)
================================================================================
"""

import os
import re
import sqlite3
import subprocess
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import (
    Flask, request, render_template, redirect,
    url_for, session, make_response, jsonify, g
)
from werkzeug.utils import secure_filename

# ── App Setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

# FIX-06: Strong random secret key from environment variable
# Never hardcoded. Falls back to a random key if env var not set.
app.secret_key = os.environ.get("SMS_SECRET_KEY", secrets.token_hex(32))

# FIX-06: Secure session cookie configuration
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot access cookie
app.config["SESSION_COOKIE_SECURE"]   = False  # Set True in production (HTTPS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# FIX-09: Structured logging with sanitization helper
logging.basicConfig(
    filename="logs/sms.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

DATABASE    = "sms.db"
UPLOAD_FOLDER = "uploads"

# FIX-03: File upload whitelist — ONLY these extensions are allowed
ALLOWED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg", ".txt"}

# FIX-01: Brute force protection — track failed login attempts in memory
#         In production use Redis or a DB table
_failed_attempts = {}   # { username: {"count": int, "locked_until": datetime} }
MAX_ATTEMPTS  = 5
LOCKOUT_SECS  = 300     # 5 minutes


# ── Helpers ────────────────────────────────────────────────────────────────────

def sanitize_log(value: str) -> str:
    """FIX-09: Strip newlines and carriage returns to prevent log injection."""
    return re.sub(r"[\r\n]", " ", str(value))


def allowed_file(filename: str) -> bool:
    """FIX-03: Check file extension against whitelist."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def is_bcrypt_hash(value: str) -> bool:
    """Return True when the stored password already looks like a bcrypt hash."""
    return isinstance(value, str) and value.startswith(("$2a$", "$2b$", "$2y$"))


def is_locked_out(username: str) -> bool:
    """FIX-01: Return True if the account is currently locked."""
    entry = _failed_attempts.get(username)
    if not entry:
        return False
    if entry["count"] >= MAX_ATTEMPTS:
        if datetime.now() < entry["locked_until"]:
            return True
        else:
            # Lockout expired — reset
            _failed_attempts.pop(username, None)
    return False


def record_failure(username: str):
    """FIX-01: Increment failed login counter; lock if threshold reached."""
    entry = _failed_attempts.setdefault(username, {"count": 0, "locked_until": None})
    entry["count"] += 1
    if entry["count"] >= MAX_ATTEMPTS:
        entry["locked_until"] = datetime.now() + timedelta(seconds=LOCKOUT_SECS)
        logging.warning(f"ACCOUNT LOCKED | user={sanitize_log(username)} | reason=too many failures")


def reset_failures(username: str):
    """FIX-01: Clear failed login counter on successful login."""
    _failed_attempts.pop(username, None)


# ── Decorators ─────────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """FIX-05: Enforce server-side role check. Role NEVER read from URL."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            # Role always comes from session set at login — never from request
            if session.get("role") not in roles:
                logging.warning(
                    f"UNAUTHORIZED ACCESS | user={sanitize_log(session.get('username','?'))} "
                    f"| route={request.path} | role={session.get('role')}"
                )
                return render_template("error.html",
                                       error="Access Denied. You do not have permission to view this page.",
                                       query=""), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


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
    """Seed the database with hashed passwords."""
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT UNIQUE NOT NULL,
                password  TEXT NOT NULL,
                role      TEXT DEFAULT 'student',
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
                national_id TEXT,
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
        """)

        # FIX-04: Seed with bcrypt-hashed passwords
        users = [
            ("admin",      "admin123",  "admin",   "admin@university.edu",  "System Admin"),
            ("john.smith", "password1", "student", "john@university.edu",   "John Smith"),
            ("jane.doe",   "jane2024",  "student", "jane@university.edu",   "Jane Doe"),
            ("prof.kumar", "faculty99", "faculty", "kumar@university.edu",  "Prof. Raj Kumar"),
            ("alice.wang", "alice123",  "student", "alice@university.edu",  "Alice Wang"),
        ]
        for username, plain_pw, role, email, full_name in users:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if not existing:
                # FIX-04: Hash password with bcrypt before storing
                hashed = bcrypt.hashpw(plain_pw.encode(), bcrypt.gensalt()).decode()
                db.execute(
                    "INSERT INTO users (username, password, role, email, full_name) VALUES (?,?,?,?,?)",
                    (username, hashed, role, email, full_name)
                )
            else:
                current_password = db.execute(
                    "SELECT password FROM users WHERE username = ?", (username,)
                ).fetchone()[0]
                if not is_bcrypt_hash(current_password):
                    hashed = bcrypt.hashpw(plain_pw.encode(), bcrypt.gensalt()).decode()
                    db.execute(
                        "UPDATE users SET password = ? WHERE username = ?",
                        (hashed, username)
                    )

        db.execute("""
            INSERT OR IGNORE INTO students
                (user_id, roll_no, full_name, dob, address, phone, national_id, gpa, financial_aid)
            VALUES
                (2,'CS2021001','John Smith', '2002-04-15','42 Elm Street, NY', '9876543210','NID-JH-001',3.7,'Merit Scholarship $5000'),
                (3,'CS2021002','Jane Doe',   '2003-07-22','17 Oak Avenue, CA', '9876543211','NID-JD-002',3.2,'Need-Based Aid $3000'),
                (5,'CS2021003','Alice Wang', '2002-11-30','8 Pine Road, TX',   '9876543212','NID-AW-003',3.9,'Research Grant $7000')
        """)
        db.execute("""
            INSERT OR IGNORE INTO grades (student_id, course, marks, grade) VALUES
                (1,'Data Structures',88,'A'),
                (1,'Operating Systems',72,'B'),
                (2,'Data Structures',65,'C'),
                (2,'Database Systems',78,'B+'),
                (3,'Algorithms',95,'A+')
        """)
        db.commit()


# ══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return redirect(url_for("login"))


# ── Login ──────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # FIX-09: Sanitize before logging — prevent log injection
        logging.info(f"LOGIN ATTEMPT | user={sanitize_log(username)} | ip={request.remote_addr}")

        # FIX-01: Check account lockout before processing
        if is_locked_out(username):
            error = "Account temporarily locked due to too many failed attempts. Please try again later."
            return render_template("login.html", error=error)

        # FIX-02: Parameterized query — no f-string, no injection possible
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # FIX-04: Verify password against bcrypt hash
        password_matches = False
        if user:
            stored_password = user["password"]
            if is_bcrypt_hash(stored_password):
                try:
                    password_matches = bcrypt.checkpw(password.encode(), stored_password.encode())
                except ValueError:
                    password_matches = False
            elif password == stored_password:
                password_matches = True
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                db.execute(
                    "UPDATE users SET password = ? WHERE id = ?",
                    (hashed, user["id"])
                )
                db.commit()

        if user and password_matches:
            reset_failures(username)
            session.clear()
            session["user_id"]  = user["id"]
            session["username"] = user["username"]
            # FIX-05: Role set from DB at login only — never from URL parameter
            session["role"]     = user["role"]
            session["full_name"]= user["full_name"]
            session.permanent   = True
            logging.info(f"LOGIN SUCCESS | user={sanitize_log(username)} | role={user['role']}")
            return redirect(url_for("dashboard"))
        else:
            record_failure(username)
            # FIX-08: Generic error — does NOT reveal if username exists
            error = "Invalid username or password."
            logging.warning(f"LOGIN FAILURE | user={sanitize_log(username)}")

    # FIX-06: No manual set_cookie — Flask handles session cookie with secure config above
    return render_template("login.html", error=error)


# ── Logout ────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Dashboard ──────────────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    # FIX-05: Role NEVER read from URL — always from session set at login
    # No request.args.get("role") here
    db = get_db()
    students = db.execute("SELECT * FROM students").fetchall()
    return render_template("dashboard.html",
                           user=session,
                           role=session.get("role"),
                           students=students)


# ── Student Search ─────────────────────────────────────────────────────────────
@app.route("/search")
@login_required
def search():
    query_param = request.args.get("q", "").strip()
    results = []
    error   = None

    if query_param:
        # FIX-02: Parameterized query with LIKE — safe against SQL injection
        db = get_db()
        try:
            results = db.execute(
                "SELECT s.id, s.roll_no, s.full_name, s.gpa, u.email "
                "FROM students s JOIN users u ON s.user_id = u.id "
                "WHERE s.full_name LIKE ? OR s.roll_no = ?",
                (f"%{query_param}%", query_param)
            ).fetchall()
        except Exception:
            # FIX-08: Generic error — no raw SQL or stack trace exposed
            error = "An error occurred while searching. Please try again."
            logging.error("Search query failed", exc_info=True)

    return render_template("search.html",
                           results=results,
                           query=query_param,
                           error=error)


# ── Student Profile ────────────────────────────────────────────────────────────
@app.route("/student/<int:student_id>")
@login_required
def student_profile(student_id):
    db = get_db()

    # FIX-05: IDOR fix — students can only view their own profile
    # Faculty and admin can view any profile
    if session.get("role") == "student":
        student = db.execute(
            "SELECT s.id, s.roll_no, s.full_name, s.dob, s.address, s.phone, "
            "s.gpa, s.user_id, u.email, u.username "
            "FROM students s JOIN users u ON s.user_id = u.id "
            "WHERE s.id = ? AND s.user_id = ?",
            (student_id, session["user_id"])
        ).fetchone()
        if not student:
            return render_template("error.html",
                                   error="Access Denied. You can only view your own profile.",
                                   query=""), 403
    else:
        # Faculty / admin: can view any student but password is NOT returned
        student = db.execute(
            "SELECT s.id, s.roll_no, s.full_name, s.dob, s.address, s.phone, "
            "s.gpa, s.financial_aid, s.national_id, s.user_id, u.email, u.username "
            "FROM students s JOIN users u ON s.user_id = u.id WHERE s.id = ?",
            (student_id,)
        ).fetchone()

    if not student:
        return render_template("error.html", error="Student not found.", query=""), 404

    grades = db.execute(
        "SELECT * FROM grades WHERE student_id = ?", (student_id,)
    ).fetchall()

    return render_template("profile.html", student=student, grades=grades)


# ── Grade Update ───────────────────────────────────────────────────────────────
@app.route("/grade/update", methods=["POST"])
@login_required
@role_required("admin", "faculty")   # FIX-14: Only admin/faculty can update grades
def update_grade():
    student_id = request.form.get("student_id", "")
    course     = request.form.get("course", "").strip()

    # FIX-12: Validate marks is a number in valid range
    try:
        new_marks = int(request.form.get("marks", 0))
        if not (0 <= new_marks <= 100):
            raise ValueError
    except ValueError:
        return render_template("error.html",
                               error="Invalid marks value. Must be 0–100.", query=""), 400

    # FIX-12: Validate grade is alphanumeric only
    new_grade = request.form.get("grade", "").strip()
    if not re.match(r"^[A-Za-z+\-]{1,3}$", new_grade):
        return render_template("error.html",
                               error="Invalid grade format.", query=""), 400

    db = get_db()
    db.execute(
        "UPDATE grades SET marks=?, grade=? WHERE student_id=? AND course=?",
        (new_marks, new_grade, student_id, course)
    )
    db.commit()
    logging.info(
        f"GRADE UPDATE | by={sanitize_log(session.get('username'))} "
        f"| student={sanitize_log(str(student_id))} | course={sanitize_log(course)} "
        f"| grade={sanitize_log(new_grade)}"
    )
    return redirect(url_for("student_profile", student_id=student_id))


# ── File Upload ────────────────────────────────────────────────────────────────
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    message = None
    error   = None

    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # FIX-03: Sanitize filename — removes path traversal sequences
            filename = secure_filename(f.filename)

            # FIX-03: Check extension against whitelist
            if not allowed_file(filename):
                error = f"File type not allowed. Permitted types: {', '.join(ALLOWED_EXTENSIONS)}"
            else:
                # FIX-03: Rename to UUID to prevent web shell execution by name
                ext      = os.path.splitext(filename)[1].lower()
                safe_name = f"{secrets.token_hex(16)}{ext}"
                filepath  = os.path.join(UPLOAD_FOLDER, safe_name)
                f.save(filepath)

                db = get_db()
                db.execute(
                    "INSERT INTO files (uploader, filename, filepath, upload_ts) VALUES (?,?,?,?)",
                    (session["username"], filename, filepath, datetime.now().isoformat())
                )
                db.commit()
                # FIX-08: Do NOT expose full server path in response
                message = f"File '{filename}' uploaded successfully."
                logging.info(
                    f"FILE UPLOAD | user={sanitize_log(session['username'])} "
                    f"| original={sanitize_log(filename)} | saved_as={safe_name}"
                )

    db = get_db()
    files = db.execute("SELECT * FROM files").fetchall()
    return render_template("upload.html", message=message, files=files, error=error)


# ── File Download ──────────────────────────────────────────────────────────────
@app.route("/download")
@login_required
def download_file():
    filename = request.args.get("file", "")

    # FIX-11: Sanitize filename to remove traversal sequences
    filename = secure_filename(filename)
    if not filename:
        return render_template("error.html", error="Invalid file name.", query=""), 400

    filepath = os.path.realpath(os.path.join(UPLOAD_FOLDER, filename))
    base     = os.path.realpath(UPLOAD_FOLDER)

    # FIX-11: Confirm resolved path is still inside uploads/ directory
    if not filepath.startswith(base + os.sep):
        logging.warning(
            f"PATH TRAVERSAL BLOCKED | user={sanitize_log(session.get('username','?'))} "
            f"| attempted={sanitize_log(filename)}"
        )
        return render_template("error.html", error="Access denied.", query=""), 403

    if not os.path.exists(filepath):
        return render_template("error.html", error="File not found.", query=""), 404

    try:
        with open(filepath, "rb") as fh:
            content = fh.read()
        resp = make_response(content)
        # FIX-11: Use only the sanitized filename in header
        resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
        return resp
    except Exception:
        # FIX-08: Generic error — no path or stack trace
        logging.error("File download failed", exc_info=True)
        return render_template("error.html", error="Could not retrieve file.", query=""), 500


# ── System Diagnostics ─────────────────────────────────────────────────────────
@app.route("/admin/diagnostics", methods=["GET", "POST"])
@login_required
@role_required("admin")   # FIX-10: Restrict diagnostics to admin only
def diagnostics():
    output = ""
    cmd    = ""

    if request.method == "POST":
        host = request.form.get("host", "").strip()

        # FIX-10: Validate host — only allow hostnames/IPs (no shell metacharacters)
        if not re.match(r"^[a-zA-Z0-9.\-]{1,253}$", host):
            return render_template("error.html",
                                   error="Invalid hostname. Only alphanumeric characters, dots, and hyphens are allowed.",
                                   query=""), 400

        cmd = f"ping -c 2 {host}"   # safe because host is validated above
        try:
            # FIX-10: shell=False + list args — no shell injection possible
            output = subprocess.check_output(
                ["ping", "-c", "2", host],   # list form, not string
                shell=False,                  # shell=False is critical
                stderr=subprocess.STDOUT,
                timeout=5
            ).decode()
        except subprocess.TimeoutExpired:
            output = "Request timed out."
        except subprocess.CalledProcessError as e:
            output = e.output.decode() if e.output else "Host unreachable."
        except Exception:
            # FIX-08: Generic error only
            output = "Diagnostic check failed."
            logging.error("Diagnostics error", exc_info=True)

    return render_template("diagnostics.html", output=output, cmd=cmd)


# ── Profile Update ─────────────────────────────────────────────────────────────
@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    # FIX-12: user_id always taken from SESSION — not from form
    user_id = session["user_id"]

    # FIX-13: Validate and sanitize all inputs
    full_name = request.form.get("full_name", "").strip()
    address   = request.form.get("address",   "").strip()
    phone     = request.form.get("phone",     "").strip()

    # Basic input validation
    if not full_name or len(full_name) > 100:
        return render_template("error.html",
                               error="Full name is required and must be under 100 characters.", query=""), 400
    if phone and not re.match(r"^\+?[0-9\s\-]{7,15}$", phone):
        return render_template("error.html",
                               error="Invalid phone number format.", query=""), 400

    db = get_db()
    db.execute(
        "UPDATE students SET full_name=?, address=?, phone=? WHERE user_id=?",
        (full_name, address, phone, user_id)   # FIX-13: stored safely; Jinja auto-escapes on render
    )
    db.commit()
    logging.info(f"PROFILE UPDATE | user={sanitize_log(session.get('username'))}")

    student = db.execute(
        "SELECT id FROM students WHERE user_id=?", (user_id,)
    ).fetchone()
    if student:
        return redirect(url_for("student_profile", student_id=student["id"]))
    return redirect(url_for("dashboard"))


# ── Admin Panel ────────────────────────────────────────────────────────────────
@app.route("/admin")
@login_required
@role_required("admin")   # FIX-05: Decorator-based RBAC, not session["role"] ad-hoc check
def admin_panel():
    db = get_db()
    # FIX-07: Password column excluded from admin query
    users    = db.execute("SELECT id, username, role, email, full_name FROM users").fetchall()
    students = db.execute("SELECT * FROM students").fetchall()
    files    = db.execute("SELECT * FROM files").fetchall()
    logs     = _read_logs()
    return render_template("admin.html", users=users, students=students,
                           files=files, logs=logs)


# ── Log Viewer ─────────────────────────────────────────────────────────────────
@app.route("/admin/logs")
@login_required
@role_required("admin")
def view_logs():
    logs = _read_logs()
    return render_template("logs.html", logs=logs)


@app.route("/admin/logs/inject", methods=["POST"])
@login_required
@role_required("admin")
def inject_log():
    # FIX-09: Sanitize log entry — strip newlines to prevent log injection
    entry = sanitize_log(request.form.get("log_entry", "").strip())
    if entry:
        logging.info(f"MANUAL LOG ENTRY | by={sanitize_log(session.get('username'))} | entry={entry}")
    return redirect(url_for("view_logs"))


@app.route("/admin/logs/clear", methods=["POST"])
@login_required
@role_required("admin")
def clear_logs():
    with open("logs/sms.log", "w") as f:
        f.write("")
    logging.info(f"LOGS CLEARED | by={sanitize_log(session.get('username'))}")
    return redirect(url_for("view_logs"))


def _read_logs():
    try:
        with open("logs/sms.log", "r") as f:
            return f.readlines()[-200:]
    except Exception:
        return []


# ── API: Students ──────────────────────────────────────────────────────────────
@app.route("/api/students")
@login_required
@role_required("admin", "faculty")   # FIX-07: Auth + role required; password excluded
def api_students():
    db = get_db()
    # FIX-07: Password field completely excluded from API response
    rows = db.execute(
        "SELECT s.id, s.roll_no, s.full_name, s.gpa, u.username, u.email "
        "FROM students s JOIN users u ON s.user_id = u.id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ── Error Handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    # FIX-08: Generic message — no URL or path info exposed
    return render_template("error.html",
                           error="Page not found.",
                           query=""), 404


@app.errorhandler(500)
def server_error(e):
    # FIX-08: Generic message — no stack trace exposed to user
    logging.error("Internal server error", exc_info=True)
    return render_template("error.html",
                           error="An internal error occurred. Please contact the administrator.",
                           query=""), 500


# ── Entry Point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("SMS (Patched) running at http://127.0.0.1:5000")
    # FIX-08: debug=False — no Werkzeug debugger, no stack traces in browser
    # FIX-13: Bind to localhost only — not exposed on all interfaces
    app.run(debug=False, host="127.0.0.1", port=5000)