"""
NoteKeeper - a small note-taking web application (Flask + SQLite).

!!! WARNING !!!
This is the ORIGINAL, INTENTIONALLY VULNERABLE version used as the target of
the CodeAlpha secure code review (Task 3). It contains real security flaws
for educational purposes. NEVER deploy it. See ../AUDIT_REPORT.md and the
remediated version in ../secure_app/.
"""
import hashlib
import os
import pickle
import base64
import sqlite3
import subprocess

from flask import (Flask, request, redirect, session, render_template_string,
                   send_file, g)

app = Flask(__name__)
app.secret_key = "notekeeper-secret-123"
ADMIN_PASSWORD = "admin123"
DB_PATH = os.path.join(os.path.dirname(__file__), "notekeeper.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")

PAGE = """<!doctype html><title>NoteKeeper</title>
<h1>NoteKeeper</h1>{% if user %}<p>Logged in as {{ user }} | <a href="/logout">logout</a></p>{% endif %}
{{ body|safe }}"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, body TEXT);
    """)
    for user, pwd, role in (("admin", ADMIN_PASSWORD, "admin"), ("alice", "alice2024", "user"),
                            ("bob", "bob2024", "user")):
        db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   (user, hashlib.md5(pwd.encode()).hexdigest(), role))
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (1, 'Admin secrets', 'Root VPN password: Sup3r!')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (2, 'Alice todo', 'Buy milk')")
    db.execute("INSERT INTO notes (owner_id, title, body) VALUES (3, 'Bob diary', 'Private thoughts')")
    db.commit()
    db.close()
    os.makedirs(UPLOAD_DIR, exist_ok=True)


def render(body):
    return render_template_string(PAGE, body=body, user=session.get("username"))


@app.route("/")
def index():
    return render('<a href="/login">Login</a> | <a href="/notes">My notes</a> | '
                  '<a href="/search">Search</a> | <a href="/tools/ping">Network tool</a>')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pwd_hash = hashlib.md5(password.encode()).hexdigest()
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + pwd_hash + "'"
        user = get_db().execute(query).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(request.args.get("next", "/notes"))
        return render("<p>Invalid credentials for user " + username + "</p>"), 401
    return render('<form method="post"><input name="username"><input name="password" type="password">'
                  '<button>Login</button></form>')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    if request.method == "POST":
        db.execute("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                   (session["user_id"], request.form["title"], request.form["body"]))
        db.commit()
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (session["user_id"],)).fetchall()
    items = "".join(f'<li><a href="/note/{r["id"]}">{r["title"]}</a>: {r["body"]}</li>' for r in rows)
    return render(f"<ul>{items}</ul><form method='post'><input name='title'><textarea name='body'></textarea>"
                  f"<button>Add</button></form>")


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    note = get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return render("Not found"), 404
    return render(f"<h2>{note['title']}</h2><p>{note['body']}</p>")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return render(f"<form><input name='q' value='{q}'><button>Search</button></form>"
                  f"<p>Results for: {q}</p>")


@app.route("/tools/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return render("<form><input name='host' placeholder='IP or hostname'><button>Ping</button></form>")
    output = subprocess.check_output("ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT, timeout=10)
    return render("<pre>" + output.decode(errors="replace") + "</pre>")


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return render("Uploaded " + f.filename)


@app.route("/import", methods=["POST"])
def import_notes():
    data = base64.b64decode(request.form["data"])
    notes_list = pickle.loads(data)
    return render(f"Imported {len(notes_list)} notes")


@app.route("/admin/users")
def admin_users():
    if request.cookies.get("role") == "admin" or session.get("role") == "admin":
        rows = get_db().execute("SELECT id, username, password, role FROM users").fetchall()
        return render("<br>".join(f"{r['id']} {r['username']} {r['password']} {r['role']}" for r in rows))
    return render("Forbidden"), 403


@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return "<pre>" + traceback.format_exc() + "</pre>", 500


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
