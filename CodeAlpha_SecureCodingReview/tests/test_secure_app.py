"""
Regression tests: each test proves that a finding from AUDIT_REPORT.md is
FIXED in secure_app/. A passing test here = the attack no longer works.

    python3 -m unittest discover -s tests -v
"""
import base64
import importlib.util
import json
import logging
import os
import pickle
import re
import shutil
import sqlite3
import tempfile
import unittest
from io import BytesIO

from flask.sessions import SecureCookieSessionInterface

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logging.getLogger("notekeeper.security").setLevel(logging.CRITICAL)


def load_secure():
    spec = importlib.util.spec_from_file_location("secure_app_mod", os.path.join(ROOT, "secure_app", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SecureAppTests(unittest.TestCase):
    ADMIN_PW = "Adm1n-Very-Long-Passphrase!"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        mod = load_secure()
        self.app = mod.create_app({"TESTING": True, "SESSION_COOKIE_SECURE": False,
                                   "DATABASE": os.path.join(self.tmp, "db.sqlite"),
                                   "UPLOAD_FOLDER": os.path.join(self.tmp, "uploads")})
        os.makedirs(self.app.config["UPLOAD_FOLDER"], exist_ok=True)
        self.app.init_db(self.ADMIN_PW)
        with self.app.app_context():
            self.app.create_user("alice", "alice-strong-pass-2024")
            self.app.create_user("bob", "bob-strong-pass-2024")
        db = sqlite3.connect(self.app.config["DATABASE"])
        db.execute("INSERT INTO notes (owner_id, title, body) VALUES (1, 'Admin secrets', 'Root VPN password')")
        db.commit()
        db.close()
        self.c = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers ---------------------------------------------------------------
    def token(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        m = re.search(r'name="csrf_token" value="([^"]+)"', html)
        return m.group(1) if m else ""

    def login(self, user, pwd, next_url=None):
        tok = self.token()
        url = "/login" + (f"?next={next_url}" if next_url else "")
        return self.c.post(url, data={"username": user, "password": pwd, "csrf_token": tok})

    # tests -----------------------------------------------------------------
    def test_v01_sql_injection_rejected(self):
        for payload in ("admin' -- ", "' OR '1'='1", "admin'/*"):
            self.assertEqual(self.login(payload, "x").status_code, 401)
        with self.c.session_transaction() as s:
            self.assertNotIn("user_id", s)

    def test_valid_login_works(self):
        r = self.login("alice", "alice-strong-pass-2024")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/notes"))

    def test_v02_command_injection_blocked(self):
        self.login("alice", "alice-strong-pass-2024")
        for host in ("127.0.0.1; id", "127.0.0.1 && cat /etc/passwd", "$(whoami)", "-oProxyCommand=x"):
            r = self.c.get("/tools/ping", query_string={"host": host})
            self.assertEqual(r.status_code, 400, host)

    def test_v03_pickle_payload_rejected(self):
        self.login("alice", "alice-strong-pass-2024")
        tok = self.token("/notes")
        payload = base64.b64encode(pickle.dumps(["x"])).decode()
        r = self.c.post("/import", data={"data": payload, "csrf_token": tok})
        self.assertEqual(r.status_code, 400)
        ok = self.c.post("/import", data={"data": json.dumps([{"title": "t", "body": "b"}]), "csrf_token": tok})
        self.assertEqual(ok.status_code, 302)

    def test_v04_path_traversal_blocked(self):
        self.login("alice", "alice-strong-pass-2024")
        for p in ("../app.py", "..%2Fapp.py", "%2Fetc%2Fpasswd"):
            r = self.c.get(f"/download/{p}", follow_redirects=True)
            self.assertEqual(r.status_code, 404, p)
            self.assertNotIn(b"root:", r.data)

    def test_v05_upload_hardened(self):
        self.login("alice", "alice-strong-pass-2024")
        tok = self.token("/upload")
        bad = self.c.post("/upload", data={"file": (BytesIO(b"x"), "../planted.py"), "csrf_token": tok},
                          content_type="multipart/form-data")
        self.assertEqual(bad.status_code, 400)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "planted.py")))
        good = self.c.post("/upload", data={"file": (BytesIO(b"hello"), "../../notes.txt"), "csrf_token": tok},
                           content_type="multipart/form-data")
        self.assertEqual(good.status_code, 302)
        stored = os.listdir(self.app.config["UPLOAD_FOLDER"])
        self.assertEqual(len(stored), 1)
        self.assertRegex(stored[0], r"^[0-9a-f]{32}\.txt$")

    def test_v06_idor_blocked(self):
        self.login("alice", "alice-strong-pass-2024")
        r = self.c.get("/note/1")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Root VPN password", r.data)

    def test_v07_cookie_role_ignored_and_user_forbidden(self):
        self.c.set_cookie("role", "admin")
        self.assertEqual(self.c.get("/admin/users").status_code, 302)       # not logged in
        self.login("alice", "alice-strong-pass-2024")
        self.assertEqual(self.c.get("/admin/users").status_code, 403)
        self.c = self.app.test_client()
        self.login("admin", self.ADMIN_PW)
        r = self.c.get("/admin/users")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"scrypt", r.data)                                   # no hashes shown

    def test_v08_xss_escaped(self):
        self.login("alice", "alice-strong-pass-2024")
        r = self.c.get("/search", query_string={"q": "<script>alert(1)</script>"})
        self.assertNotIn(b"<script>alert(1)</script>", r.data)
        self.assertIn(b"&lt;script&gt;", r.data)
        tok = self.token("/notes")
        self.c.post("/notes", data={"title": "x", "body": "<img src=x onerror=alert(1)>", "csrf_token": tok})
        page = self.c.get("/notes").data
        self.assertNotIn(b"<img src=x onerror", page)
        self.assertIn(b"&lt;img src=x onerror=alert(1)&gt;", page)

    def test_v09_strong_password_hashing(self):
        db = sqlite3.connect(self.app.config["DATABASE"])
        h = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
        db.close()
        self.assertTrue(h.startswith(("scrypt:", "pbkdf2:")))
        self.assertNotIn("alice-strong-pass-2024", h)

    def test_v10_forged_session_with_old_key_rejected(self):
        old = load_secure().create_app({"SECRET_KEY": "notekeeper-secret-123"})
        forged = SecureCookieSessionInterface().get_signing_serializer(old).dumps({"user_id": 1})
        self.c.set_cookie("session", forged)
        self.assertEqual(self.c.get("/admin/users").status_code, 302)
        self.assertNotEqual(self.app.config["SECRET_KEY"], "notekeeper-secret-123")

    def test_v12_generic_error_page(self):
        self.login("alice", "alice-strong-pass-2024")
        tok = self.token("/notes")
        r = self.c.post("/import", data={"data": "{broken", "csrf_token": tok})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn(b"Traceback", r.data)

    def test_v13_open_redirect_blocked(self):
        for target in ("https://evil.example/phish", "//evil.example", "/\\evil.example"):
            self.c = self.app.test_client()
            r = self.login("alice", "alice-strong-pass-2024", next_url=target)
            self.assertTrue(r.headers["Location"].endswith("/notes"), target)
        self.c = self.app.test_client()
        r = self.login("alice", "alice-strong-pass-2024", next_url="/search")
        self.assertTrue(r.headers["Location"].endswith("/search"))

    def test_v14_csrf_required(self):
        self.login("alice", "alice-strong-pass-2024")
        r = self.c.post("/notes", data={"title": "csrf", "body": "forged"})
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/notes", data={"title": "csrf", "body": "forged", "csrf_token": "wrong"})
        self.assertEqual(r.status_code, 400)

    def test_v15_security_headers_and_cookie_flags(self):
        r = self.c.get("/login")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_v16_bruteforce_lockout(self):
        for _ in range(5):
            self.assertEqual(self.login("alice", "guess").status_code, 401)
        self.assertEqual(self.login("alice", "alice-strong-pass-2024").status_code, 429)


if __name__ == "__main__":
    unittest.main(verbosity=2)
