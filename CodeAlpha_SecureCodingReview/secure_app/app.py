"""
NoteKeeper - REMEDIATED version (CodeAlpha Task 3 - Secure Coding Review).

Every fix is tagged with the finding ID from ../AUDIT_REPORT.md, e.g. [V-01].

Run locally:
    export NOTEKEEPER_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    export NOTEKEEPER_ADMIN_PASSWORD='a-long-unique-passphrase'
    python3 secure_app/app.py
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import time
import uuid
from collections import defaultdict, deque
from functools import wraps
from urllib.parse import urlparse

from flask import (Flask, abort, flash, g, redirect, render_template, request, send_from_directory,
                   session, url_for)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log = logging.getLogger("notekeeper.security")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg"}
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
MAX_TITLE, MAX_BODY, MAX_IMPORT = 120, 5000, 100
LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW = 5, 15 * 60


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, root_path=BASE_DIR, template_folder="templates")

    # [V-10] secrets come from the environment, never from source code
    secret = os.environ.get("NOTEKEEPER_SECRET_KEY")
    if not secret:
        secret = secrets.token_hex(32)
        log.warning("NOTEKEEPER_SECRET_KEY not set: using a random key (sessions reset on restart)")

    app.config.update(
        SECRET_KEY=secret,
        DATABASE=os.path.join(BASE_DIR, "notekeeper.db"),
        UPLOAD_FOLDER=os.path.join(BASE_DIR, "uploads"),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,                 # [V-05] 2 MB upload limit
        # [V-15] hardened session cookie
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("NOTEKEEPER_INSECURE_COOKIES") != "1",
        PERMANENT_SESSION_LIFETIME=30 * 60,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    failed_logins: dict[str, deque] = defaultdict(deque)

    # ------------------------------------------------------------------ db
    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db(admin_password: str | None = None) -> None:
        db = sqlite3.connect(app.config["DATABASE"])
        db.executescript("""
            DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;
            CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                                password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user');
            CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
                                title TEXT NOT NULL, body TEXT NOT NULL);
        """)
        # [V-09] salted, slow password hashing (scrypt via Werkzeug)
        # [V-17] no default password: taken from env or randomly generated
        admin_pw = admin_password or os.environ.get("NOTEKEEPER_ADMIN_PASSWORD") or secrets.token_urlsafe(16)
        if not (admin_password or os.environ.get("NOTEKEEPER_ADMIN_PASSWORD")):
            print(f"[init] generated admin password: {admin_pw}")
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   ("admin", generate_password_hash(admin_pw), "admin"))
        db.commit()
        db.close()

    app.init_db = init_db  # exposed for the CLI and the tests

    def create_user(username: str, password: str, role: str = "user") -> int:
        db = get_db()
        cur = db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                         (username, generate_password_hash(password), role))
        db.commit()
        return cur.lastrowid

    app.create_user = create_user

    # ------------------------------------------------------------ helpers
    def current_user():
        uid = session.get("user_id")
        if uid is None:
            return None
        return get_db().execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if current_user() is None:
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapper

    def admin_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login"))
            if user["role"] != "admin":                       # [V-07] role from the DB only
                log.warning("Forbidden admin access by user_id=%s", user["id"])
                abort(403)
            return view(*args, **kwargs)
        return wrapper

    def is_safe_redirect(target: str | None) -> bool:      # [V-13]
        if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
            return False
        parsed = urlparse(target)
        return not parsed.scheme and not parsed.netloc

    def csrf_token() -> str:                                # [V-14]
        if "_csrf" not in session:
            session["_csrf"] = secrets.token_urlsafe(32)
        return session["_csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["current_user"] = current_user

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not secrets.compare_digest(sent, session.get("_csrf", "")) or not sent:
                log.warning("CSRF validation failed for %s from %s", request.path, request.remote_addr)
                abort(400, description="Invalid or missing CSRF token")

    @app.after_request
    def security_headers(resp):                             # [V-15]
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; "
                                                   "object-src 'none'; frame-ancestors 'none'; "
                                                   "base-uri 'self'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.errorhandler(Exception)
    def handle_error(e):                                    # [V-12] generic errors, details in logs
        if isinstance(e, HTTPException):
            return render_template("error.html", code=e.code, message=e.description), e.code
        log.exception("Unhandled error")
        return render_template("error.html", code=500, message="An internal error occurred."), 500

    # -------------------------------------------------------------- routes
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()[:64]
            password = request.form.get("password", "")
            key = f"{request.remote_addr}|{username.lower()}"
            attempts = failed_logins[key]
            now = time.time()
            while attempts and now - attempts[0] > LOGIN_WINDOW:
                attempts.popleft()
            if len(attempts) >= LOGIN_MAX_ATTEMPTS:             # [V-16] brute-force throttling
                log.warning("Login locked for %s", key)
                return render_template("login.html", error="Too many attempts. Try again later."), 429

            # [V-01] parameterised query - user input never becomes SQL code
            user = get_db().execute("SELECT id, username, password_hash, role FROM users WHERE username = ?",
                                    (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                attempts.clear()
                session.clear()                                 # prevent session fixation
                session.permanent = True
                session["user_id"] = user["id"]
                log.info("Successful login user_id=%s", user["id"])
                nxt = request.args.get("next")
                return redirect(nxt if is_safe_redirect(nxt) else url_for("notes"))
            attempts.append(now)
            log.warning("Failed login for username=%r from %s", username, request.remote_addr)
            # [V-08] generic, auto-escaped message (no reflection of the username)
            return render_template("login.html", error="Invalid username or password."), 401
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/notes", methods=["GET", "POST"])
    @login_required
    def notes():
        user = current_user()
        db = get_db()
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if not title or len(title) > MAX_TITLE or len(body) > MAX_BODY:
                abort(400, description=f"Title required (max {MAX_TITLE} chars), body max {MAX_BODY} chars.")
            db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", (user["id"], title, body))
            db.commit()
            return redirect(url_for("notes"))
        rows = db.execute("SELECT id, title, body FROM notes WHERE owner_id = ? ORDER BY id DESC",
                          (user["id"],)).fetchall()
        return render_template("notes.html", notes=rows)    # [V-08] auto-escaped

    @app.route("/note/<int:note_id>")
    @login_required
    def view_note(note_id: int):
        # [V-06] object-level authorisation: the note must belong to the current user
        note = get_db().execute("SELECT id, title, body FROM notes WHERE id = ? AND owner_id = ?",
                                (note_id, current_user()["id"])).fetchone()
        if note is None:
            abort(404)
        return render_template("note.html", note=note)

    @app.route("/search")
    @login_required
    def search():
        q = request.args.get("q", "")[:100]
        rows = []
        if q:
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            rows = get_db().execute(
                "SELECT id, title FROM notes WHERE owner_id = ? AND title LIKE ? ESCAPE '\\'",
                (current_user()["id"], like)).fetchall()
        return render_template("search.html", q=q, results=rows)   # [V-08]

    @app.route("/tools/ping")
    @login_required
    def ping():
        host = request.args.get("host", "").strip()
        if not host:
            return render_template("ping.html")
        # [V-02] strict allow-list validation + no shell + argument list
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not HOSTNAME_RE.match(host):
                abort(400, description="Invalid IP address or hostname.")
        try:
            proc = subprocess.run(["ping", "-c", "1", "-W", "2", "--", host], capture_output=True,
                                  text=True, timeout=5, check=False)
            output = proc.stdout or proc.stderr
        except (subprocess.TimeoutExpired, FileNotFoundError):
            output = "Ping failed or timed out."
        return render_template("ping.html", host=host, output=output)

    @app.route("/download/<path:filename>")
    @login_required
    def download(filename: str):
        # [V-04] sanitised name + send_from_directory (safe_join refuses ../ and absolute paths)
        safe = secure_filename(filename)
        if not safe or safe != filename:
            abort(404)
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe, as_attachment=True)

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "GET":
            return render_template("upload.html")
        f = request.files.get("file")
        if f is None or not f.filename:
            abort(400, description="No file provided.")
        name = secure_filename(f.filename)                   # [V-05]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext not in ALLOWED_EXTENSIONS:
            abort(400, description="File type not allowed.")
        stored = f"{uuid.uuid4().hex}.{ext}"                  # never trust or reuse the client name
        f.save(os.path.join(app.config["UPLOAD_FOLDER"], stored))
        flash(f"Uploaded as {stored}")
        return redirect(url_for("upload"))

    @app.route("/import", methods=["POST"])
    @login_required
    def import_notes():
        # [V-03] JSON (data only) instead of pickle (code), with schema validation
        try:
            items = json.loads(request.form.get("data", ""))
        except (ValueError, TypeError):
            abort(400, description="Invalid JSON.")
        if not isinstance(items, list) or len(items) > MAX_IMPORT:
            abort(400, description=f"Expected a list of at most {MAX_IMPORT} notes.")
        clean = []
        for it in items:
            if (not isinstance(it, dict) or not isinstance(it.get("title"), str)
                    or not isinstance(it.get("body", ""), str)
                    or not 0 < len(it["title"]) <= MAX_TITLE or len(it.get("body", "")) > MAX_BODY):
                abort(400, description="Each note needs a 'title' and an optional 'body' (strings).")
            clean.append((current_user()["id"], it["title"], it.get("body", "")))
        db = get_db()
        db.executemany("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", clean)
        db.commit()
        flash(f"Imported {len(clean)} notes")
        return redirect(url_for("notes"))

    @app.route("/admin/users")
    @admin_required
    def admin_users():
        # [V-07] password hashes are never displayed
        rows = get_db().execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
        return render_template("admin.html", users=rows)

    return app


if __name__ == "__main__":
    application = create_app()
    if not os.path.exists(application.config["DATABASE"]):
        application.init_db()
    # [V-11] debug disabled, loopback only; use a WSGI server (gunicorn) behind a TLS proxy in production
    application.run(host="127.0.0.1", port=5000,
                    debug=os.environ.get("FLASK_DEBUG") == "1" and os.environ.get("NOTEKEEPER_ENV") == "dev")
