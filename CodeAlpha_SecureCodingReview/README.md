# CodeAlpha – Secure Coding Review

> **CodeAlpha Cyber Security Internship – Task 3**
> A complete security audit of a Python/Flask web application: manual code review, static analysis with a custom SAST tool, exploit verification, remediated code and a professional audit report.

![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![Flask](https://img.shields.io/badge/flask-3.x-black) ![Tests](https://img.shields.io/badge/tests-34%20passing-brightgreen) ![Findings](https://img.shields.io/badge/findings-17%20fixed-orange)

---

## Overview

| | |
|---|---|
| **Language** | Python 3 |
| **Application audited** | *NoteKeeper*, a Flask + SQLite note-taking app (login, notes, search, file upload/download, import, network tool, admin panel) |
| **Methods** | Manual line-by-line review (OWASP ASVS) · Static analysis (custom AST scanner) · Dynamic verification (proof-of-concept tests) |
| **Results** | **17 vulnerabilities**: 3 Critical · 8 High · 4 Medium · 2 Low, **all remediated and verified** |

📄 **Full report:** [`AUDIT_REPORT.md`](AUDIT_REPORT.md)

## Findings summary

| ID | Vulnerability | Severity | CWE |
|---|---|:-:|---|
| V-01 | SQL injection → authentication bypass | 🔴 Critical | CWE-89 |
| V-02 | OS command injection → RCE | 🔴 Critical | CWE-78 |
| V-03 | Insecure deserialization (pickle) → RCE | 🔴 Critical | CWE-502 |
| V-04 | Path traversal / arbitrary file read | 🟠 High | CWE-22 |
| V-05 | Unrestricted file upload | 🟠 High | CWE-434 |
| V-06 | IDOR: access to other users' notes | 🟠 High | CWE-639 |
| V-07 | Admin access via forged cookie | 🟠 High | CWE-565 |
| V-08 | Reflected & stored XSS | 🟠 High | CWE-79 |
| V-09 | Unsalted MD5 password hashing | 🟠 High | CWE-916 |
| V-10 | Hard-coded secret key → session forgery | 🟠 High | CWE-798 |
| V-11 | Debug mode in production | 🟠 High | CWE-489 |
| V-12 | Stack trace disclosure | 🟡 Medium | CWE-209 |
| V-13 | Open redirect | 🟡 Medium | CWE-601 |
| V-14 | Missing CSRF protection | 🟡 Medium | CWE-352 |
| V-16 | No brute-force protection | 🟡 Medium | CWE-307 |
| V-15 | Missing security headers / cookie flags | 🔵 Low | CWE-693 |
| V-17 | Weak default credentials | 🔵 Low | CWE-521 |

## Repository structure

```
CodeAlpha_SecureCodingReview/
├── AUDIT_REPORT.md            # professional audit report (findings, PoC, impact, remediation)
├── vulnerable_app/app.py      # ⚠️ original, intentionally vulnerable application (audit target)
├── secure_app/
│   ├── app.py                 # remediated application, every fix tagged [V-xx]
│   └── templates/             # auto-escaped Jinja templates with CSRF tokens
├── tools/pysast.py            # custom SAST scanner: 17 rules, CWE/OWASP mapping, taint tracking
├── tests/
│   ├── test_vulnerable_app.py # 15 exploit PoCs: prove each flaw is real
│   ├── test_secure_app.py     # 16 regression tests: prove each fix works
│   └── test_pysast.py         # scanner tests
├── reports/                   # SAST results (txt + json) before / after
└── requirements.txt
```

## Quick start

```bash
git clone https://github.com/Djaneba/CodeAlpha_SecureCodingReview.git
cd CodeAlpha_SecureCodingReview
pip install -r requirements.txt

# 1. Run the static analysis
python3 tools/pysast.py vulnerable_app/          # 21 findings
python3 tools/pysast.py secure_app/              # 0 findings

# 2. Prove the vulnerabilities and the fixes
python3 -m unittest discover -s tests -v         # 34 tests, all pass

# 3. Run the secure app
export NOTEKEEPER_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export NOTEKEEPER_ADMIN_PASSWORD='choose-a-long-passphrase'
export NOTEKEEPER_INSECURE_COOKIES=1             # local HTTP only; omit behind HTTPS
python3 secure_app/app.py                        # http://127.0.0.1:5000
```

## The custom SAST tool (`tools/pysast.py`)

A dependency-free static analyser that parses Python into an **AST** and tracks **tainted data** from `flask.request` to dangerous sinks.

```
$ python3 tools/pysast.py vulnerable_app/
[CRITICAL] PY001 SQL query built from dynamic string  (CWE-89, A03:2021 Injection)
           vulnerable_app/app.py:74  ->  user = get_db().execute(query).fetchone()
[CRITICAL] PY002 OS command execution through a shell  (CWE-78, A03:2021 Injection)
           vulnerable_app/app.py:128 ->  output = subprocess.check_output("ping -c 1 " + host, shell=True, ...)
[CRITICAL] PY003 Unsafe deserialization  (CWE-502, A08:2021 Software and Data Integrity Failures)
           vulnerable_app/app.py:148 ->  notes_list = pickle.loads(data)
...
Summary: CRITICAL=3, HIGH=15, MEDIUM=2, LOW=1
```

| Rules | Detects |
|---|---|
| PY001–PY004 | SQL injection, shell command injection, unsafe deserialization (pickle/yaml/marshal), eval/exec |
| PY005–PY007 | MD5/SHA1, hard-coded secrets, Flask debug mode |
| PY008, PY015 | XSS: `\|safe`, HTML built from user input |
| PY009, PY016 | Path traversal, unsafe file upload |
| PY010–PY014, PY017 | Open redirect, cookie-based authorisation, stack-trace disclosure, `verify=False`, `0.0.0.0` binding, `mktemp` |

Options: `--json report.json`, `--min-severity HIGH` (returns exit code 1 → usable as a CI gate). It recognises sanitisers (`secure_filename`, `int`, allow-list checks such as `is_safe_redirect`) to limit false positives.

**Lesson learned:** the scanner found 12 of the 17 issues. IDOR, missing CSRF, missing headers, missing rate limiting and weak default passwords were found by **manual review**: automated tools complement, but never replace, a human reviewer.

For production projects, also run industry tools:
```bash
pip install bandit semgrep pip-audit
bandit -r vulnerable_app/
semgrep --config p/python --config p/flask vulnerable_app/
pip-audit
```

## Key remediations

| Problem | Secure pattern applied |
|---|---|
| String-built SQL | Parameterised queries `execute("... WHERE u = ?", (u,))` |
| `shell=True` | Allow-list validation + `subprocess.run([...], shell=False)` |
| `pickle.loads` | JSON + schema validation |
| User-controlled paths | `secure_filename` + `send_from_directory` + random stored names |
| Missing authorisation | `@login_required`, `@admin_required`, ownership check in SQL |
| `\|safe` / f-string HTML | Jinja templates with auto-escaping + CSP |
| MD5 | scrypt via `werkzeug.security` |
| Hard-coded secrets / debug | Environment variables, debug off, `127.0.0.1` |
| CSRF / brute force / headers | Synchronizer tokens, 5 attempts / 15 min lockout, CSP, X-Frame-Options, secure cookies |

## ⚠️ Disclaimer

`vulnerable_app/` is **intentionally insecure** and exists only as an audit target for learning. Never deploy it or expose it to a network.

## Author

**Amadou Sanoko Djaneba** – Cyber Security Intern @ CodeAlpha
[GitHub](https://github.com/Djaneba)
