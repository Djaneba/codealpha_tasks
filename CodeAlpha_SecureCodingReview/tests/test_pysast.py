"""Tests for the custom SAST scanner (tools/pysast.py)."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import pysast  # noqa: E402


class PySastTests(unittest.TestCase):
    def test_detects_all_rule_families_in_vulnerable_app(self):
        found = {f.rule for f in pysast.scan_file(os.path.join(ROOT, "vulnerable_app", "app.py"))}
        for rule in ("PY001", "PY002", "PY003", "PY005", "PY006", "PY007", "PY008",
                     "PY009", "PY010", "PY011", "PY012", "PY015", "PY016"):
            self.assertIn(rule, found)

    def test_secure_app_is_clean(self):
        self.assertEqual(pysast.scan_file(os.path.join(ROOT, "secure_app", "app.py")), [])

    def test_parameterised_query_not_flagged(self):
        import tempfile
        code = ("from flask import request\n"
                "def f(db):\n"
                "    u = request.args.get('u')\n"
                "    db.execute('SELECT * FROM t WHERE u = ?', (u,))\n"
                "    db.execute('SELECT * FROM t WHERE u = ' + u)\n")
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as fh:
            fh.write(code)
        try:
            res = pysast.scan_file(fh.name)
        finally:
            os.unlink(fh.name)
        self.assertEqual([(f.rule, f.line, f.severity) for f in res], [("PY001", 5, "CRITICAL")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
