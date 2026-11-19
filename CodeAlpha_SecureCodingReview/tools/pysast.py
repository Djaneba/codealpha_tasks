#!/usr/bin/env python3
"""
pysast - a lightweight static application security testing (SAST) tool for
Python / Flask code, written for the CodeAlpha secure code review (Task 3).

It walks the Python AST of every file and applies security rules mapped to
CWE and the OWASP Top 10 (2021). A simple intra-function taint tracker marks
variables that come from user input (request.args / form / files / cookies /
headers / json / data / values) and follows them through assignments, so that
dangerous *sinks* (SQL, shell, file system, redirect...) fed by user data are
reported with a higher confidence.

Usage:
    python3 tools/pysast.py vulnerable_app/            # human-readable report
    python3 tools/pysast.py secure_app/ --json out.json
    python3 tools/pysast.py app.py --min-severity HIGH  # CI gate (exit code 1)

This is a teaching tool, complementary to Bandit / Semgrep, not a replacement.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, asdict

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
USER_INPUT_ATTRS = {"args", "form", "files", "cookies", "headers", "json", "data", "values",
                    "get_json", "get_data"}
SANITIZERS = {"secure_filename", "int", "float", "bool", "escape", "quote", "quote_plus",
              "ip_address", "ip_network", "uuid4", "len"}
SECRET_NAME = re.compile(r"(secret|passw(or)?d|pwd|token|api_?key|private_?key|secret_?key)", re.I)


@dataclass
class Finding:
    rule: str
    title: str
    severity: str
    cwe: str
    owasp: str
    file: str
    line: int
    code: str
    detail: str


RULES = {
    "PY001": ("SQL query built from dynamic string", "CRITICAL", "CWE-89", "A03:2021 Injection"),
    "PY002": ("OS command execution through a shell", "CRITICAL", "CWE-78", "A03:2021 Injection"),
    "PY003": ("Unsafe deserialization", "CRITICAL", "CWE-502", "A08:2021 Software and Data Integrity Failures"),
    "PY004": ("Use of eval/exec", "HIGH", "CWE-95", "A03:2021 Injection"),
    "PY005": ("Weak hash algorithm (MD5/SHA1)", "HIGH", "CWE-328", "A02:2021 Cryptographic Failures"),
    "PY006": ("Hard-coded secret or credential", "HIGH", "CWE-798", "A07:2021 Identification and Authentication Failures"),
    "PY007": ("Flask debug mode enabled", "HIGH", "CWE-489", "A05:2021 Security Misconfiguration"),
    "PY008": ("Autoescaping disabled in template (|safe / Markup)", "HIGH", "CWE-79", "A03:2021 Injection"),
    "PY009": ("File path built from user input", "HIGH", "CWE-22", "A01:2021 Broken Access Control"),
    "PY010": ("Open redirect", "MEDIUM", "CWE-601", "A01:2021 Broken Access Control"),
    "PY011": ("Authorization decision based on client cookie", "HIGH", "CWE-565", "A01:2021 Broken Access Control"),
    "PY012": ("Stack trace returned to the client", "MEDIUM", "CWE-209", "A05:2021 Security Misconfiguration"),
    "PY013": ("TLS certificate verification disabled", "HIGH", "CWE-295", "A02:2021 Cryptographic Failures"),
    "PY014": ("Server bound to all interfaces", "LOW", "CWE-1327", "A05:2021 Security Misconfiguration"),
    "PY015": ("HTML built from user input without escaping", "HIGH", "CWE-79", "A03:2021 Injection"),
    "PY016": ("Uploaded file saved with client-supplied name", "HIGH", "CWE-434", "A04:2021 Insecure Design"),
    "PY017": ("Insecure temporary file", "MEDIUM", "CWE-377", "A05:2021 Security Misconfiguration"),
}


def dotted(node: ast.AST) -> str:
    """Return 'a.b.c' for Name/Attribute chains (calls are rendered as '()')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}()"
    return ""


def is_user_input(node: ast.AST) -> bool:
    """True if the expression reads directly from flask.request."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in USER_INPUT_ATTRS:
            if dotted(sub.value).endswith("request"):
                return True
        if isinstance(sub, ast.Attribute) and sub.attr == "filename":
            return True
    return False


def is_dynamic_string(node: ast.AST) -> bool:
    """String built at run time: concatenation, %-format, f-string or .format()."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


class Analyzer(ast.NodeVisitor):
    def __init__(self, path: str, source: str) -> None:
        self.path, self.lines = path, source.splitlines()
        self.findings: list[Finding] = []
        self.tainted: set[str] = set()       # names holding user input
        self.dyn_strings: set[str] = set()   # names holding dynamically built strings

    # -- helpers ----------------------------------------------------------- #
    def report(self, rule: str, node: ast.AST, detail: str, severity: str | None = None) -> None:
        title, sev, cwe, owasp = RULES[rule]
        line = getattr(node, "lineno", 0)
        code = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if any(f.rule == rule and f.line == line for f in self.findings):
            return
        self.findings.append(Finding(rule, title, severity or sev, cwe, owasp,
                                     self.path, line, code[:140], detail))

    def taint_of(self, node: ast.AST) -> bool:
        if is_user_input(node):
            return True
        return any(isinstance(n, ast.Name) and n.id in self.tainted for n in ast.walk(node))

    @staticmethod
    def is_sanitized(node: ast.AST) -> bool:
        """Value produced by a known sanitiser, e.g. secure_filename(x) or int(x)."""
        return isinstance(node, ast.Call) and dotted(node.func).split(".")[-1] in SANITIZERS

    @staticmethod
    def guarded(node: ast.AST) -> bool:
        """`x if is_safe_*(x) else default` - value validated by an allow-list check."""
        if isinstance(node, ast.IfExp):
            return any(isinstance(n, ast.Call) and re.search(r"safe|allowed|valid|whitelist",
                                                              dotted(n.func), re.I)
                       for n in ast.walk(node.test))
        return False

    @staticmethod
    def _strip_numeric(node: ast.AST) -> ast.AST:
        """Copy of node where len()/int()/float()/bool() calls are neutralised:
        their result is a number, which cannot carry an XSS payload."""
        class _T(ast.NodeTransformer):
            def visit_Call(self, n: ast.Call):
                if isinstance(n.func, ast.Name) and n.func.id in ("len", "int", "float", "bool"):
                    return ast.Constant(0)
                return self.generic_visit(n)
        import copy
        return _T().visit(copy.deepcopy(node))

    def dynamic(self, node: ast.AST) -> bool:
        return is_dynamic_string(node) or (isinstance(node, ast.Name) and node.id in self.dyn_strings)

    # -- scopes ------------------------------------------------------------ #
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved = (self.tainted, self.dyn_strings)
        self.tainted, self.dyn_strings = set(), set()
        # route parameters of a Flask view are user-controlled
        for deco in node.decorator_list:
            if isinstance(deco, ast.Call) and dotted(deco.func).endswith(".route"):
                self.tainted.update(a.arg for a in node.args.args)
        self.generic_visit(node)
        self.tainted, self.dyn_strings = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    # -- assignments ------------------------------------------------------- #
    def visit_Assign(self, node: ast.Assign) -> None:
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if self.is_sanitized(node.value):
            self.tainted.difference_update(names)
        elif self.taint_of(node.value):
            self.tainted.update(names)
        if is_dynamic_string(node.value):
            self.dyn_strings.update(names)
        # hard-coded secrets: SECRET = "..." / app.secret_key = "..."
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
            for t in node.targets:
                label = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
                if label and SECRET_NAME.search(label):
                    self.report("PY006", node, f"'{label}' is assigned a literal string; load it from "
                                               f"the environment or a secrets manager instead.")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if self.taint_of(node.iter) and isinstance(node.target, ast.Name):
            self.tainted.add(node.target.id)
        self.generic_visit(node)

    # -- string constants (templates) ---------------------------------------- #
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and re.search(r"\|\s*safe\b", node.value):
            self.report("PY008", node, "The Jinja '|safe' filter disables auto-escaping; any user data "
                                       "rendered through it leads to Cross-Site Scripting.")

    # -- return values ------------------------------------------------------- #
    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            for sub in ast.walk(node.value):
                if isinstance(sub, ast.Call) and dotted(sub.func) == "traceback.format_exc":
                    self.report("PY012", node, "Internal stack traces leak file paths, code and "
                                               "library versions to attackers.")
        self.generic_visit(node)

    # -- calls (sinks) ------------------------------------------------------- #
    def visit_Call(self, node: ast.Call) -> None:
        name = dotted(node.func)
        short = name.split(".")[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        args = node.args

        # SQL injection
        if short in ("execute", "executemany", "executescript", "raw") and args:
            q = args[0]
            if self.dynamic(q) or (self.taint_of(q) and not isinstance(q, ast.Constant)):
                sev = "CRITICAL" if self.taint_of(q) or (isinstance(q, ast.Name) and q.id in self.tainted) \
                    else "HIGH"
                self.report("PY001", node, "Query text is built by string operations; use parameterised "
                                           "queries (placeholders '?' / '%s') instead.", sev)

        # Command injection
        if name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
            self.report("PY002", node, "shell=True passes the command to /bin/sh; metacharacters in "
                                       "user input (; | && $()) execute arbitrary commands.",
                        "CRITICAL" if args and self.taint_of(args[0]) else "HIGH")
        if name in ("os.system", "os.popen", "commands.getoutput"):
            self.report("PY002", node, f"{name}() always runs through a shell.",
                        "CRITICAL" if args and self.taint_of(args[0]) else "HIGH")

        # Deserialization
        if name in ("pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads", "dill.loads",
                    "shelve.open", "jsonpickle.decode"):
            self.report("PY003", node, f"{name}() can execute arbitrary code when given attacker-"
                                       f"controlled data. Use JSON with schema validation.")
        if name == "yaml.load" and not any("Safe" in dotted(v) for v in kw.values()):
            self.report("PY003", node, "yaml.load without SafeLoader can instantiate arbitrary objects.")

        # eval / exec
        if name in ("eval", "exec"):
            self.report("PY004", node, f"{name}() executes arbitrary Python code.",
                        "CRITICAL" if args and self.taint_of(args[0]) else "HIGH")

        # weak hashes
        if name in ("hashlib.md5", "hashlib.sha1") or (name == "hashlib.new" and args and
                                                       isinstance(args[0], ast.Constant) and
                                                       str(args[0].value).lower() in ("md5", "sha1")):
            self.report("PY005", node, "MD5/SHA-1 are fast and broken; for passwords use a slow, salted "
                                       "KDF (scrypt, Argon2, bcrypt, PBKDF2).")

        # debug mode / bind address
        if short == "run":
            d = kw.get("debug")
            if isinstance(d, ast.Constant) and d.value is True:
                self.report("PY007", node, "The Werkzeug debugger allows remote code execution and leaks "
                                           "source code. Never enable it outside local development.")
            h = kw.get("host")
            if isinstance(h, ast.Constant) and h.value == "0.0.0.0":
                self.report("PY014", node, "Listening on 0.0.0.0 exposes the app on every network "
                                           "interface; put it behind a reverse proxy.")

        # path traversal
        if short in ("send_file", "open", "send_from_directory_unsafe") or name in ("os.path.join",):
            if any(self.taint_of(a) for a in args):
                self.report("PY009", node, "A file path is derived from user input; '../' or an absolute "
                                           "path escapes the intended directory. Use "
                                           "werkzeug.utils.secure_filename / safe_join and send_from_directory.")

        # file upload saved with client name
        if short == "save" and args and any(isinstance(n, ast.Attribute) and n.attr == "filename"
                                            for n in ast.walk(args[0])):
            if not any(isinstance(n, ast.Call) and dotted(n.func).endswith("secure_filename")
                       for n in ast.walk(args[0])):
                self.report("PY016", node, "The client controls file.filename ('../../app.py'); sanitise it "
                                           "with secure_filename, restrict extensions and size.")

        # open redirect
        if short == "redirect" and args and self.taint_of(args[0]) and not self.guarded(args[0]):
            self.report("PY010", node, "Redirect target comes from the request; attackers can send victims "
                                       "to a phishing site. Allow only relative, same-site paths.")

        # cookie-based authorisation
        if name.endswith("request.cookies.get") and args and isinstance(args[0], ast.Constant) and \
                re.search(r"role|admin|is_?staff|privilege|perm", str(args[0].value), re.I):
            self.report("PY011", node, "Cookies are fully controlled by the client; never trust them for "
                                       "authorisation. Use the server-side session / database.")

        # TLS verification
        if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self.report("PY013", node, "verify=False disables certificate validation (MITM).")

        # insecure temp file
        if name == "tempfile.mktemp":
            self.report("PY017", node, "mktemp is race-prone; use NamedTemporaryFile / mkstemp.")

        # HTML assembled from user input and passed to a renderer / response
        if short in ("render", "render_template_string", "make_response", "Response") and args:
            a0 = args[0]
            if self.dynamic(a0) and self.taint_of(self._strip_numeric(a0)):
                self.report("PY015", node, "User-controlled data is concatenated into HTML without "
                                           "escaping (XSS). Use templates with auto-escaping.")

        self.generic_visit(node)


def scan_file(path: str) -> list[Finding]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        print(f"[!] Skipping {path}: {exc}", file=sys.stderr)
        return []
    an = Analyzer(path, source)
    an.visit(tree)
    return sorted(an.findings, key=lambda f: f.line)


def iter_files(target: str):
    if os.path.isfile(target):
        yield target
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", ".venv", "venv", "node_modules"}]
        for f in sorted(files):
            if f.endswith(".py"):
                yield os.path.join(root, f)


COLOURS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lightweight Python/Flask SAST scanner (CodeAlpha Task 3)")
    ap.add_argument("targets", nargs="+", help="files or directories to scan")
    ap.add_argument("--json", metavar="FILE", help="write findings as JSON")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="LOW",
                    help="only report findings at or above this level; exit 1 if any")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    colour = sys.stdout.isatty() and not args.no_color
    floor = SEVERITIES.index(args.min_severity)

    findings: list[Finding] = []
    files = [f for t in args.targets for f in iter_files(t)]
    for f in files:
        findings += [x for x in scan_file(f) if SEVERITIES.index(x.severity) >= floor]
    findings.sort(key=lambda x: (-SEVERITIES.index(x.severity), x.file, x.line))

    print(f"pysast - scanned {len(files)} file(s), {len(findings)} finding(s)\n")
    for x in findings:
        sev = f"{COLOURS[x.severity]}{x.severity:<8}\033[0m" if colour else f"{x.severity:<8}"
        print(f"[{sev}] {x.rule} {x.title}  ({x.cwe}, {x.owasp})")
        print(f"           {x.file}:{x.line}  ->  {x.code}")
        print(f"           {x.detail}\n")
    counts = {s: sum(1 for x in findings if x.severity == s) for s in reversed(SEVERITIES)}
    print("Summary: " + ", ".join(f"{s}={n}" for s, n in counts.items()))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"files": files, "summary": counts, "findings": [asdict(x) for x in findings]},
                      fh, indent=2)
        print(f"JSON report written to {args.json}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
