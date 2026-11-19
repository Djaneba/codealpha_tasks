# Secure Code Review Report: NoteKeeper (Python / Flask)

| | |
|---|---|
| **Project** | CodeAlpha Cyber Security Internship, Task 3: Secure Coding Review |
| **Application** | NoteKeeper v1.0, note-taking web app (Python 3, Flask 3, SQLite) |
| **Audited file** | `vulnerable_app/app.py` (168 lines) |
| **Remediated file** | `secure_app/app.py` + `secure_app/templates/` |
| **Reviewer** | Amadou Sanoko Djaneba, Cyber Security Intern |
| **Date** | November 2026 |
| **Standards** | OWASP Top 10 (2021), OWASP ASVS 4.0 (L1/L2), CWE |

---

## 1. Executive summary

NoteKeeper was reviewed using **manual line-by-line inspection**, **static analysis** (a custom AST-based SAST scanner, `tools/pysast.py`) and **dynamic verification**: every finding was confirmed with an automated proof-of-concept test.

The application is **critically insecure**. **17 vulnerabilities** were identified, including **3 critical flaws that each give an unauthenticated attacker full control of the server in a single HTTP request** (SQL injection, OS command injection and unsafe pickle deserialization).

| Severity | Count | Findings |
|---|:-:|---|
| 🔴 Critical | 3 | V-01, V-02, V-03 |
| 🟠 High | 8 | V-04, V-05, V-06, V-07, V-08, V-09, V-10, V-11 |
| 🟡 Medium | 4 | V-12, V-13, V-14, V-16 |
| 🔵 Low | 2 | V-15, V-17 |
| **Total** | **17** | |

**All 17 findings have been remediated** in `secure_app/`. The fixes are verified by 16 regression tests (`tests/test_secure_app.py`), and the SAST scanner reports **0 findings** on the remediated code (versus 21 on the original).

**Top 3 priorities:**

1. Never build SQL, shell commands or file paths from user input (V-01, V-02, V-04, V-05).
2. Enforce authentication and authorisation on the server for every object and route (V-06, V-07).
3. Remove secrets from code and disable debug features (V-10, V-11, V-12).

## 2. Scope and methodology

**In scope:** all routes of `vulnerable_app/app.py`: `/login`, `/logout`, `/notes`, `/note/<id>`, `/search`, `/tools/ping`, `/download`, `/upload`, `/import`, `/admin/users`, the error handler and the application configuration.
**Out of scope:** infrastructure, OS hardening, third-party library internals.

| Phase | Approach |
|---|---|
| 1. Reconnaissance | Mapped entry points (routes, parameters, cookies, files) and trust boundaries; identified data flows from `request.*` to sensitive *sinks* (SQL, shell, filesystem, HTML, redirects, deserialisers). |
| 2. Automated SAST | `tools/pysast.py`: custom scanner with 17 rules mapped to CWE/OWASP and intra-function taint tracking. Reports in `reports/`. (Bandit and Semgrep are recommended in CI; see §6.) |
| 3. Manual review | Line-by-line review against the OWASP ASVS checklist: authentication, session management, access control, input validation, output encoding, cryptography, error handling, configuration. |
| 4. Dynamic verification | Each finding was exploited with a safe proof-of-concept test (`tests/test_vulnerable_app.py`, 15 tests, all succeed against the original app; V-11 and V-17 were verified by inspection). |
| 5. Remediation & retest | Fixed code written in `secure_app/`, then verified with regression tests and a rescan. |

**Severity rating** (OWASP Risk Rating, likelihood × impact):

- **Critical:** remote, unauthenticated, trivial to exploit, full compromise (RCE, full DB access).
- **High:** significant data exposure or privilege escalation, or easily chained to critical.
- **Medium:** exploitation needs user interaction or specific conditions; limited impact.
- **Low:** defence-in-depth weakness or best-practice deviation.

**SAST vs. manual review.** The scanner flagged 12 of the 17 issues automatically. Manual review was required to find the **IDOR (V-06)**, the **stored XSS in `/notes` (line 101)**, the **missing CSRF protection (V-14)**, the **missing security headers (V-15)**, the **missing rate limiting (V-16)** and the **weak default passwords (V-17)**: business-logic and *absence-of-control* flaws that pattern-based tools cannot see. This shows why automated tools must be combined with human review.

## 3. Findings overview

| ID | Vulnerability | Severity | CWE | OWASP 2021 | Location |
|---|---|:-:|---|---|---|
| V-01 | SQL injection in login (authentication bypass) | 🔴 Critical | CWE-89 | A03 Injection | `app.py:73-74` |
| V-02 | OS command injection in network tool | 🔴 Critical | CWE-78 | A03 Injection | `app.py:128` |
| V-03 | Insecure deserialization (pickle) → RCE | 🔴 Critical | CWE-502 | A08 Integrity Failures | `app.py:146-148` |
| V-04 | Path traversal / arbitrary file read | 🟠 High | CWE-22 | A01 Broken Access Control | `app.py:133-135` |
| V-05 | Unrestricted file upload / arbitrary file write | 🟠 High | CWE-434, CWE-22 | A04 Insecure Design | `app.py:139-142` |
| V-06 | IDOR: read any user's notes | 🟠 High | CWE-639 | A01 Broken Access Control | `app.py:110` |
| V-07 | Admin access via client-controlled cookie; hash disclosure | 🟠 High | CWE-565, CWE-284 | A01 Broken Access Control | `app.py:154-156` |
| V-08 | Cross-Site Scripting (reflected + stored) | 🟠 High | CWE-79 | A03 Injection | `app.py:28, 80, 101, 113, 119` |
| V-09 | Unsalted MD5 password hashing | 🟠 High | CWE-916, CWE-328 | A02 Cryptographic Failures | `app.py:48, 72` |
| V-10 | Hard-coded secret key and credentials → session forgery | 🟠 High | CWE-798 | A07 Auth Failures | `app.py:21-22` |
| V-11 | Flask debug mode enabled on all interfaces | 🟠 High | CWE-489 | A05 Misconfiguration | `app.py:168` |
| V-12 | Stack traces returned to users | 🟡 Medium | CWE-209 | A05 Misconfiguration | `app.py:160-163` |
| V-13 | Open redirect after login | 🟡 Medium | CWE-601 | A01 Broken Access Control | `app.py:79` |
| V-14 | No CSRF protection on state-changing requests | 🟡 Medium | CWE-352 | A01 Broken Access Control | all POST routes |
| V-15 | Missing security headers, weak cookie flags, GET logout | 🔵 Low | CWE-693, CWE-1004 | A05 Misconfiguration | global |
| V-16 | No brute-force protection on login | 🟡 Medium | CWE-307 | A07 Auth Failures | `app.py:67-81` |
| V-17 | Weak default passwords seeded in code | 🔵 Low | CWE-521, CWE-1392 | A07 Auth Failures | `app.py:22, 46` |

## 4. Detailed findings

### V-01: SQL injection in login 🔴 Critical
**Location:** `vulnerable_app/app.py:73-74` · **CWE-89** · **OWASP A03:2021**

```python
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + pwd_hash + "'"
user = get_db().execute(query).fetchone()
```
**Description.** The username is concatenated directly into the SQL statement. A quote character ends the string literal and the rest of the input is interpreted as SQL.

**Proof of concept.** Username `admin' -- ` with any password produces `... WHERE username = 'admin' -- ' AND password = '...'`. The password check is commented out and the attacker is logged in as **admin** (`test_v01_sql_injection_login_bypass`). UNION-based payloads can also dump the whole database.

**Impact.** Complete authentication bypass, full read/write access to the database.

**Remediation.** Use parameterised queries everywhere: the driver sends data separately from the SQL code.
```python
user = get_db().execute(
    "SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)
).fetchone()
if user and check_password_hash(user["password_hash"], password): ...
```
Use an ORM (SQLAlchemy) with bound parameters, and a least-privilege DB account.

---

### V-02: OS command injection 🔴 Critical
**Location:** `app.py:128` · **CWE-78** · **OWASP A03:2021**

```python
output = subprocess.check_output("ping -c 1 " + host, shell=True, ...)
```
**Description.** `host` comes from the query string and is passed to `/bin/sh` (`shell=True`). Shell metacharacters (`;`, `&&`, `|`, `$( )`, backticks) chain arbitrary commands. The route also has **no authentication**.

**Proof of concept.** `GET /tools/ping?host=127.0.0.1; echo INJECTED_$((6*7))` returns `INJECTED_42`: the shell evaluated attacker-supplied code (`test_v02_command_injection`). An attacker could equally run `cat /etc/passwd`, download malware or open a reverse shell.

**Impact.** Remote code execution with the privileges of the web server, i.e. full server compromise.

**Remediation.** Avoid the shell; validate against a strict allow-list; pass arguments as a list; use `--` to stop option injection; require authentication; add a timeout.
```python
try:
    ipaddress.ip_address(host)
except ValueError:
    if not HOSTNAME_RE.match(host):
        abort(400, description="Invalid IP address or hostname.")
proc = subprocess.run(["ping", "-c", "1", "-W", "2", "--", host],
                      capture_output=True, text=True, timeout=5, check=False)
```
Better still, use a library (e.g. ICMP via `icmplib`) instead of spawning processes.

---

### V-03: Insecure deserialization (pickle) 🔴 Critical
**Location:** `app.py:146-148` · **CWE-502** · **OWASP A08:2021**

```python
data = base64.b64decode(request.form["data"])
notes_list = pickle.loads(data)
```
**Description.** `pickle` can serialise *instructions*: an object's `__reduce__` method tells the loader which function to call. Unpickling attacker-controlled bytes therefore executes attacker-chosen code. The route is also unauthenticated.

**Proof of concept.** A harmless payload whose `__reduce__` returns `(eval, ("['executed'] * 7",))` makes the server evaluate the expression and answer `Imported 7 notes` (`test_v03_insecure_deserialization_executes_code`). Replacing `eval` with `os.system` gives a shell.

**Impact.** Unauthenticated remote code execution.

**Remediation.** Never unpickle untrusted data. Use a data-only format (JSON) and validate its schema, types and sizes:
```python
items = json.loads(request.form.get("data", ""))
if not isinstance(items, list) or len(items) > MAX_IMPORT: abort(400)
for it in items:
    if not isinstance(it, dict) or not isinstance(it.get("title"), str) ...: abort(400)
```
If objects must be serialised, sign them (HMAC) and still prefer JSON / Pydantic / marshmallow.

---

### V-04: Path traversal (arbitrary file read) 🟠 High
**Location:** `app.py:133-135` · **CWE-22** · **OWASP A01:2021**

```python
filename = request.args.get("file", "")
return send_file(os.path.join(UPLOAD_DIR, filename))
```
**Description.** `../` sequences climb out of the upload folder, and `os.path.join` **discards the base directory entirely** when the second argument is an absolute path.

**Proof of concept.** `/download?file=../../../../../../etc/passwd` returns the system password file; `/download?file=/full/path/app.py` returns the application source code including the hard-coded secret key (`test_v04_path_traversal_reads_source_code`).

**Impact.** Disclosure of source code, secrets, configuration and the database file. Chained with V-10 (secret key) this gives admin sessions; chained with V-11 it can be used to compute the Werkzeug debugger PIN and obtain RCE.

**Remediation.**
```python
@app.route("/download/<path:filename>")
@login_required
def download(filename):
    safe = secure_filename(filename)
    if not safe or safe != filename:
        abort(404)
    return send_from_directory(app.config["UPLOAD_FOLDER"], safe, as_attachment=True)
```
`send_from_directory` uses `safe_join`, which refuses paths escaping the directory. Store files under random IDs and keep an ownership table.

---

### V-05: Unrestricted file upload 🟠 High
**Location:** `app.py:139-142` · **CWE-434 / CWE-22** · **OWASP A04:2021**

```python
f = request.files["file"]
f.save(os.path.join(UPLOAD_DIR, f.filename))
```
**Description.** The client-supplied filename is trusted (path traversal on write), any file type and size is accepted, existing files can be overwritten, and the route is unauthenticated. The filename is also reflected without encoding (XSS).

**Proof of concept.** Uploading a file named `../planted.py` writes it **outside** the upload directory (`test_v05_upload_overwrites_files_outside_upload_dir`). Overwriting `app.py` or a template leads to code execution; uploading `.html`/`.svg` enables stored XSS; huge uploads exhaust the disk.

**Remediation.** Authenticate; sanitise with `secure_filename`; allow-list extensions (and verify content/magic bytes); set `MAX_CONTENT_LENGTH`; store under a random server-generated name outside the web root; serve with `Content-Disposition: attachment`; scan with antivirus where relevant.
```python
name = secure_filename(f.filename)
ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
if ext not in ALLOWED_EXTENSIONS: abort(400)
f.save(os.path.join(app.config["UPLOAD_FOLDER"], f"{uuid.uuid4().hex}.{ext}"))
```

---

### V-06: Insecure Direct Object Reference (IDOR) 🟠 High
**Location:** `app.py:110` · **CWE-639** · **OWASP A01:2021** · *(found by manual review only)*

```python
note = get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
```
**Description.** The query is safely parameterised, but it **never checks ownership**. Any logged-in user can read any note by incrementing the ID.

**Proof of concept.** Logged in as `alice`, `GET /note/1` returns the admin's note *“Root VPN password: …”* (`test_v06_idor_read_other_users_note`).

**Remediation.** Enforce object-level authorisation in the query itself and return 404 (not 403) to avoid revealing which IDs exist:
```python
note = db.execute("SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?",
                  (note_id, current_user()["id"])).fetchone()
if note is None: abort(404)
```
Consider non-guessable identifiers (UUIDs) as defence-in-depth.

---

### V-07: Broken access control on admin page 🟠 High
**Location:** `app.py:154-156` · **CWE-565 / CWE-284** · **OWASP A01:2021**

```python
if request.cookies.get("role") == "admin" or session.get("role") == "admin":
    rows = get_db().execute("SELECT id, username, password, role FROM users").fetchall()
```
**Description.** Authorisation trusts a plain cookie fully controlled by the browser. The page also displays every user's password hash.

**Proof of concept.** Without logging in, setting the cookie `role=admin` grants access to `/admin/users` and exposes all MD5 hashes (`test_v07_admin_access_with_forged_cookie`).

**Remediation.** Derive the role server-side from the database on each request (decorator `@admin_required`), deny by default, log failures, and never expose password hashes:
```python
def admin_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        user = current_user()                    # loaded from DB via session user_id
        if user is None: return redirect(url_for("login"))
        if user["role"] != "admin": abort(403)
        return view(*a, **kw)
    return wrapper
```

---

### V-08: Cross-Site Scripting (reflected and stored) 🟠 High
**Location:** `app.py:28` (`{{ body|safe }}`), `80`, `101`, `113`, `119`, `142` · **CWE-79** · **OWASP A03:2021**

**Description.** HTML is assembled with f-strings/concatenation from user data and then rendered through a template with `|safe`, which **disables Jinja's auto-escaping**. Affected: the search term (reflected), the username in the login error (reflected), note titles/bodies (stored, lines 101 and 113), uploaded file names.

**Proof of concept.** `/search?q=<script>alert(1)</script>` is returned verbatim; a note body `<img src=x onerror=alert(document.cookie)>` executes for anyone who views it (`test_v08_reflected_and_stored_xss`).

**Impact.** Session hijacking, actions on behalf of the victim, phishing inside the trusted site, keylogging.

**Remediation.** Never build HTML by string concatenation. Use template files with Jinja auto-escaping (on by default for `.html`), never `|safe`/`Markup()` on user data, and add a strict **Content-Security-Policy** as a second layer:
```html
<p>Results for: {{ q }}</p>   {# rendered as &lt;script&gt;... #}
```

---

### V-09: Weak password storage (unsalted MD5) 🟠 High
**Location:** `app.py:48, 72` · **CWE-916 / CWE-328** · **OWASP A02:2021**

```python
hashlib.md5(password.encode()).hexdigest()
```
**Description.** MD5 is a fast, unsalted, broken hash. Modern GPUs compute billions of MD5 hashes per second, and identical passwords produce identical hashes (rainbow tables). `md5("admin123")` is in every public lookup database.

**Remediation.** Use a slow, salted, memory-hard KDF: **Argon2id**, **scrypt** or **bcrypt** (or PBKDF2 with ≥600,000 iterations):
```python
from werkzeug.security import generate_password_hash, check_password_hash
generate_password_hash(password)            # scrypt with a random salt (Werkzeug ≥ 3)
check_password_hash(stored_hash, password)  # constant-time comparison
```
Force a password reset for all users after migration.

---

### V-10: Hard-coded secret key and credentials 🟠 High
**Location:** `app.py:21-22` · **CWE-798** · **OWASP A07:2021**

```python
app.secret_key = "notekeeper-secret-123"
ADMIN_PASSWORD = "admin123"
```
**Description.** Flask signs session cookies with `secret_key`. Anyone who reads the source (GitHub, a leaked backup, or V-04) can **forge any session**.

**Proof of concept.** Signing `{"user_id": 1, "role": "admin"}` with the known key using Flask's own serializer grants admin access (`test_v10_session_forgery_with_hardcoded_secret`).

**Remediation.** Load secrets from environment variables or a secrets manager (Vault, AWS Secrets Manager); generate them with `secrets.token_hex(32)`; rotate the leaked key; add secret scanning (gitleaks, GitHub secret scanning) to CI.
```python
secret = os.environ.get("NOTEKEEPER_SECRET_KEY") or secrets.token_hex(32)
```

---

### V-11: Debug mode enabled in production 🟠 High
**Location:** `app.py:168` · **CWE-489** · **OWASP A05:2021**

```python
app.run(host="0.0.0.0", port=5000, debug=True)
```
**Description.** The Werkzeug interactive debugger provides a Python console in the browser. It is PIN-protected, but the PIN is derived from machine data that can be read through V-04. `0.0.0.0` exposes the development server on every interface.

**Remediation.** `debug=False` (enabled only via an explicit development environment variable), bind to `127.0.0.1`, and run behind a production WSGI server (gunicorn/uWSGI) and a TLS reverse proxy (nginx).

---

### V-12: Information disclosure through stack traces 🟡 Medium
**Location:** `app.py:160-163` · **CWE-209** · **OWASP A05:2021**

```python
@app.errorhandler(Exception)
def handle_error(e):
    return "<pre>" + traceback.format_exc() + "</pre>", 500
```
**Proof of concept.** Posting invalid base64 to `/import` returns the full Python traceback with file paths and code (`test_v12_stack_trace_disclosure`).

**Remediation.** Return a generic error page with the correct status code; log details server-side only (`log.exception(...)`).

---

### V-13: Open redirect 🟡 Medium
**Location:** `app.py:79` · **CWE-601** · **OWASP A01:2021**

```python
return redirect(request.args.get("next", "/notes"))
```
**Proof of concept.** `/login?next=https://evil.example/phish` sends the freshly logged-in user to an attacker's site, a perfect phishing pivot because the link starts with the legitimate domain (`test_v13_open_redirect`).

**Remediation.** Only accept relative, same-site paths:
```python
def is_safe_redirect(target):
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return False
    p = urlparse(target)
    return not p.scheme and not p.netloc
```

---

### V-14: Missing CSRF protection 🟡 Medium
**Location:** all `POST` routes (`/login`, `/notes`, `/upload`, `/import`) · **CWE-352** · **OWASP A01:2021** · *(manual review)*

**Description.** Nothing proves that a state-changing request was sent intentionally from the application's own pages. A malicious site can auto-submit a form to `/notes` or `/import` with the victim's cookies (`test_v14_no_csrf_protection`).

**Remediation.** Synchronizer token pattern (per-session random token in every form, verified with `secrets.compare_digest`), or Flask-WTF `CSRFProtect`; plus `SameSite=Lax` cookies. Logout changed from GET to POST.

---

### V-15: Missing security headers and weak cookie configuration 🔵 Low
**Location:** global configuration · **CWE-693 / CWE-1004 / CWE-614** · **OWASP A05:2021**

**Description.** No `Content-Security-Policy`, `X-Frame-Options` (clickjacking), `X-Content-Type-Options`, `Referrer-Policy` or HSTS; session cookie without `Secure`/`SameSite`; no session timeout; logout via GET (`test_v15_missing_security_headers`).

**Remediation.** Set headers in an `after_request` hook (or use Flask-Talisman); `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, `PERMANENT_SESSION_LIFETIME=30 min`; regenerate the session on login (`session.clear()`).

---

### V-16: No brute-force protection 🟡 Medium
**Location:** `app.py:67-81` · **CWE-307** · **OWASP A07:2021** · *(manual review)*

**Description.** Unlimited login attempts allow online password guessing and credential stuffing (`test_v16_no_bruteforce_protection`: 20 failures, then success). The error message also reflects the username.

**Remediation.** Throttle per IP + account (implemented: 5 failures / 15 min → HTTP 429), generic error messages, logging/alerting of failed logins; in production use Flask-Limiter with Redis, CAPTCHA after repeated failures, and MFA.

---

### V-17: Weak default credentials 🔵 Low
**Location:** `app.py:22, 46` · **CWE-521 / CWE-1392** · **OWASP A07:2021** · *(manual review)*

**Description.** Accounts are seeded with trivial passwords (`admin123`, `alice2024`) that appear in every wordlist.

**Remediation.** No default passwords: the admin password comes from an environment variable or is randomly generated at first start; enforce a password policy (≥12 characters, check against breached-password lists such as Have I Been Pwned *k-anonymity* API).

## 5. Attack chain example

An unauthenticated attacker can fully compromise the server in **two requests** without any password:

1. `GET /download?file=../app.py` (or an absolute path such as `/proc/self/cwd/app.py`) → source code + secret key (V-04, V-10)
2. `POST /import` with a malicious pickle → remote code execution (V-03)

…or simply `GET /tools/ping?host=x;<command>` (V-02). With the remediated version, every step of this chain fails (see `tests/test_secure_app.py`).

## 6. Secure coding best practices (recommendations)

**Input & output**

- Treat **all** input as untrusted: query string, form, JSON, headers, cookies, file names, and data read back from the DB.
- Validate with **allow-lists** (type, length, format, range); reject rather than “clean”.
- Use **parameterised queries** / ORM; never concatenate SQL, shell, LDAP or XPath.
- Encode output for its context; rely on template auto-escaping; never `|safe` user data.
- Avoid `shell=True`, `eval`, `exec`, `pickle`, `yaml.load` on untrusted data.

**Authentication & sessions**

- Hash passwords with Argon2id/scrypt/bcrypt; enforce MFA for admins.
- Regenerate the session on login; short timeouts; `Secure`, `HttpOnly`, `SameSite` cookies.
- Throttle login attempts; use generic error messages.

**Access control**

- Deny by default; check authorisation **server-side on every request and for every object**.
- Never trust client-side data (cookies, hidden fields, JWT claims you didn't verify) for authorisation.

**Configuration & secrets**

- No secrets in code or Git; use environment variables / a vault; rotate leaked keys.
- Debug off in production; generic error pages; security headers; TLS everywhere.
- Keep dependencies updated (`pip-audit`, Dependabot).

**Process (DevSecOps)**

- Add SAST to CI: `bandit -r .`, `semgrep --config p/python --config p/flask`, plus `tools/pysast.py --min-severity HIGH` as a gate.
- Secret scanning (gitleaks), dependency scanning (pip-audit), DAST (OWASP ZAP) on staging.
- Security unit tests for every fixed vulnerability (as in `tests/`), peer code review with an OWASP ASVS checklist, and developer security training.

## 7. Remediation verification

| Check | Original app | Remediated app |
|---|---|---|
| SAST findings (`tools/pysast.py`) | **21** (3 critical, 15 high, 2 medium, 1 low) | **0** |
| Exploit PoC tests that succeed | **15 / 15** | **0**: 16 regression tests confirm every attack is blocked and normal use still works |
| Unauthenticated RCE paths | 2 (V-02, V-03) | 0 |

Reproduce: `python3 -m unittest discover -s tests -v` and `python3 tools/pysast.py vulnerable_app/ secure_app/`.

## 8. Conclusion

NoteKeeper's original code shows the most common root causes of web vulnerabilities: **mixing code and data** (SQL, shell, HTML, pickle), **trusting the client** (cookies, file names, redirect targets), and **insecure defaults** (debug mode, hard-coded secrets, MD5). The remediated version applies defence-in-depth: input validation, safe APIs, server-side authorisation, strong cryptography, secure configuration and automated security tests. Integrating SAST, secret scanning and security tests into the development pipeline will prevent these classes of bugs from coming back.

---
*Appendix: raw scanner output in `reports/sast_vulnerable.txt` / `.json` and `reports/sast_secure.txt` / `.json`.*
