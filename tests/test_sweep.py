"""End-to-end tests against throwaway git repos with planted FAKE secrets.

Fixture values are assembled from pieces at runtime so this file itself never contains a
token-shaped string (keeps secret-sweep, GitHub push protection, etc. from flagging it).
"""
import hashlib
import io
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secretsweep.cli import main                      # noqa: E402
from secretsweep.remediate import apply_plan, build_plan, write_purge_plan  # noqa: E402
from secretsweep.rules import scan_line              # noqa: E402
from secretsweep.scanner import RepoInfo, scan_repo  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def rand(n, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(secrets.choice(alphabet) for _ in range(n))


AWS = "AK" + "IA" + rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
GH = "gh" + "p_" + rand(36)
STRIPE = "sk" + "_live_" + rand(24)
EVM = "0x" + secrets.token_hex(32)
WIF = b58check(b"\x80" + secrets.token_bytes(32) + b"\x01")
SEED = "abandon ability able about above absent absorb abstract absurd abuse access accident"  # secretsweep:allow
GENERIC = "Zq8#" + rand(20)
DBPW = "S3cr" + rand(10)


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as fh:
        return fh.read()


def git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True)


def make_repo(root):
    os.makedirs(root)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "user.email", "test@example.invalid")
    git(root, "config", "user.name", "Test")
    files = {
        "app.py": f'"""App."""\nAWS_KEY = "{AWS}"\nstripe_key = \'{STRIPE}\'\nprint("hi")\n',
        "web/client.js": f'const config = {{ apiToken: "{GH}" }};\nmodule.exports = config;\n',
        "deploy/wallet.ts": f'export const PRIVATE_KEY = "{EVM}";\nconst mnemonic = "{SEED}";\n',
        "settings.yaml": f'db: "postgres://admin:{DBPW}@db.internal:5432/app"\n',
        ".env": f"API_SECRET={GENERIC}\n",
        "keys/server.pem": "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----\n",
        "README.md": "nothing to see\n",
    }
    for p, body in files.items():
        full = os.path.join(root, p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", newline="\n") as fh:
            fh.write(body)
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "initial")
    # A secret that only survives in history
    with open(os.path.join(root, "old.py"), "w", newline="\n") as fh:
        fh.write(f'btc = "{WIF}"\n')
    git(root, "add", "old.py")
    git(root, "commit", "-q", "-m", "add old")
    git(root, "rm", "-q", "old.py")
    git(root, "commit", "-q", "-m", "remove old")
    # Untracked + unignored sensitive file
    with open(os.path.join(root, ".env.local"), "w") as fh:
        fh.write("X=1\n")


class RuleTests(unittest.TestCase):
    def ids(self, line, path="x.py"):
        return {m.rule.id for m in scan_line(line, path)}

    def test_specific_rules(self):
        self.assertIn("aws-access-key-id", self.ids(f'k = "{AWS}"'))
        self.assertIn("github-token", self.ids(f"token: {GH}"))
        self.assertIn("stripe-live-key", self.ids(STRIPE))
        self.assertIn("evm-private-key", self.ids(f'PRIVATE_KEY="{EVM}"'))
        self.assertIn("bitcoin-wif", self.ids(WIF))
        self.assertIn("seed-phrase", self.ids(f'mnemonic = "{SEED}"'))

    def test_specific_beats_generic(self):
        self.assertEqual(self.ids(f'api_token = "{GH}"'), {"github-token"})

    def test_false_positives(self):
        self.assertFalse(self.ids('password = "your-password-here"'))
        self.assertFalse(self.ids('api_key = os.environ["API_KEY"]'))
        self.assertFalse(self.ids('token_url = "https://example.com/oauth/token"'))
        self.assertFalse(self.ids("tx = 0x" + "ab" * 32))           # bare hash, no key context
        self.assertFalse(self.ids("5" + "H" * 50))                   # base58-shaped but bad checksum
        self.assertFalse(self.ids(f'k = "{AWS}"  # secretsweep:allow'))
        self.assertFalse(self.ids('secretsweep = "secretsweep.cli:main"'))
        self.assertFalse(self.ids('url = f"postgres://admin:{password}@db:5432/app"'))


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = os.path.join(self.tmp.name, "user", "demo")
        make_repo(self.repo)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan(self):
        found = scan_repo(self.repo, RepoInfo("user/demo", "https://github.com/user/demo"), worktree=True)
        by_rule = {f.rule_id: f for f in found}
        for rid in ("aws-access-key-id", "stripe-live-key", "github-token", "evm-private-key", "seed-phrase",
                    "db-connection-string", "env-file", "env-file-secret", "private-key", "pem-key-file", "bitcoin-wif"):
            self.assertIn(rid, by_rule, rid)
        aws = by_rule["aws-access-key-id"]
        self.assertEqual((aws.head_locations[0].path, aws.head_locations[0].line), ("app.py", 2))
        self.assertTrue(aws.head_locations[0].url.endswith("/app.py#L2"))
        self.assertEqual(aws.first_seen.line, 2)
        btc = by_rule["bitcoin-wif"]
        self.assertFalse(btc.in_head)                       # history only
        self.assertEqual(btc.first_seen.path, "old.py")
        self.assertTrue(any(f.kind == "untracked" and f.masked == ".env.local" for f in found))
        for f in found:                                     # reports never carry raw values
            self.assertNotIn(f.masked, (AWS, GH, STRIPE, EVM, WIF, SEED, GENERIC, DBPW))

    def test_scan_local_cli_and_report(self):
        out_dir = os.path.join(self.tmp.name, "report")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["scan-local", os.path.join(self.tmp.name, "user"), "--out", out_dir, "--workers", "2"])
        self.assertEqual(code, 1)
        report = read(out_dir, "report.md")
        self.assertIn("AWS Access Key ID", report)
        for raw in (AWS, GH, STRIPE, EVM, WIF, GENERIC):
            self.assertNotIn(raw, report)
            self.assertNotIn(raw, buf.getvalue())

    def test_fix(self):
        plan = build_plan(self.repo)
        apply_plan(plan)
        app = read(self.repo, "app.py")
        self.assertNotIn(AWS, app)
        self.assertIn('os.environ["AWS_KEY"]', app)
        self.assertIn('os.environ["STRIPE_KEY"]', app)
        self.assertTrue(app.startswith('"""App."""\nimport os\n'))
        js = read(self.repo, "web", "client.js")
        self.assertIn("process.env.API_TOKEN", js)
        ts = read(self.repo, "deploy", "wallet.ts")
        self.assertIn("process.env.PRIVATE_KEY", ts)
        self.assertIn("process.env.MNEMONIC", ts)
        env = read(self.repo, ".env")
        self.assertIn(f"AWS_KEY={AWS}", env)
        self.assertIn(f'MNEMONIC="{SEED}"', env)
        self.assertIn("AWS_KEY=", read(self.repo, ".env.example"))
        gi = read(self.repo, ".gitignore")
        self.assertIn(".env", gi)
        self.assertIn("*.pem", gi)
        tracked = subprocess.run(["git", "-C", self.repo, "ls-files"], capture_output=True, text=True).stdout.split()
        self.assertNotIn(".env", tracked)
        self.assertNotIn("keys/server.pem", tracked)
        self.assertTrue(os.path.exists(os.path.join(self.repo, "keys", "server.pem")))   # untracked, not deleted
        self.assertEqual(plan.manual[0][0], "settings.yaml")                                # yaml needs a human
        # After fixing, nothing that would be committed contains the moved secrets.
        git(self.repo, "add", "-A")
        staged = subprocess.run(["git", "-C", self.repo, "diff", "--cached"], capture_output=True, text=True).stdout
        added = [ln for ln in staged.splitlines() if ln.startswith("+")]
        for raw in (AWS, GH, STRIPE, EVM, SEED, GENERIC):
            self.assertFalse(any(raw in ln for ln in added), raw[:4])

    def test_purge_plan(self):
        with self.assertRaises(ValueError):
            write_purge_plan(self.repo, os.path.join(self.repo, "purge.txt"))
        out = os.path.join(self.tmp.name, "purge.txt")
        n, paths = write_purge_plan(self.repo, out)
        body = read(out)
        self.assertIn(WIF + "==>", body)                     # history-only secret is purged too
        self.assertIn(AWS + "==>", body)
        self.assertIn(".env", paths)


class HookTests(unittest.TestCase):
    """Real `git commit` runs against an installed hook. Global git config is redirected to a temp file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved_env = {k: os.environ.get(k) for k in ("SECRETSWEEP_HOME", "GIT_CONFIG_GLOBAL")}
        os.environ["SECRETSWEEP_HOME"] = os.path.join(self.tmp.name, "home")
        os.environ["GIT_CONFIG_GLOBAL"] = os.path.join(self.tmp.name, "gitconfig")
        open(os.environ["GIT_CONFIG_GLOBAL"], "w").close()
        self.repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "test@example.invalid")
        git(self.repo, "config", "user.name", "Test")
        self.write("README.md", "hello\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "init")

    def tearDown(self):
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def write(self, name, body):
        full = os.path.join(self.repo, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", newline="\n") as fh:
            fh.write(body)

    def commit(self, *files, msg="change"):
        subprocess.run(["git", "-C", self.repo, "add", *files], check=True, capture_output=True)
        return subprocess.run(["git", "-C", self.repo, "commit", "-m", msg], capture_output=True, text=True)

    def test_blocks_then_allows_after_fix(self):
        from secretsweep.hooks import hook_status, install_repo
        install_repo(self.repo)
        self.assertEqual(hook_status(self.repo), "repo")
        self.write("app.py", f'KEY = "{AWS}"\n')
        res = self.commit("app.py")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("commit blocked", res.stdout + res.stderr)
        self.assertIn("app.py:1", res.stdout + res.stderr)
        self.assertNotIn(AWS, res.stdout + res.stderr)
        self.write("app.py", 'import os\nKEY = os.environ["KEY"]\n')
        self.assertEqual(self.commit("app.py").returncode, 0)

    def test_only_added_lines_count(self):
        from secretsweep.hooks import install_repo
        self.write("old.py", f'KEY = "{AWS}"\nx = 1\n')
        subprocess.run(["git", "-C", self.repo, "add", "old.py"], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-q", "--no-verify", "-m", "legacy"], check=True)
        install_repo(self.repo)
        self.write("old.py", f'KEY = "{AWS}"\nx = 2\n')
        self.assertEqual(self.commit("old.py").returncode, 0)     # untouched old secret doesn't block

    def test_blocks_env_file_and_warns_on_low(self):
        from secretsweep.hooks import install_repo
        install_repo(self.repo)
        self.write(".env", "DEBUG=1\n")
        res = self.commit(".env")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("git rm --cached", res.stdout + res.stderr)
        git(self.repo, "rm", "-q", "--cached", ".env")
        self.write("pay.js", f'const k = "{"sk" + "_test_" + rand(24)}";\n')
        res = self.commit("pay.js")
        self.assertEqual(res.returncode, 0)
        self.assertIn("warning", res.stdout + res.stderr)

    def test_existing_hook_is_chained_and_restored(self):
        from secretsweep.hooks import install_repo, uninstall_repo
        hook = os.path.join(self.repo, ".git", "hooks", "pre-commit")
        with open(hook, "w", newline="\n") as fh:
            fh.write('#!/bin/sh\ntouch "$(git rev-parse --show-toplevel)/.ran"\n')
        install_repo(self.repo)
        self.write("a.txt", "fine\n")
        self.assertEqual(self.commit("a.txt").returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.repo, ".ran")))
        uninstall_repo(self.repo)
        self.assertIn("touch", read(hook))

    def test_global_hook(self):
        from secretsweep.hooks import hook_status, install_global, uninstall_global
        install_global()
        self.assertEqual(hook_status(self.repo), "global")
        self.write("w.ts", f'const PRIVATE_KEY = "{EVM}";\n')
        self.assertNotEqual(self.commit("w.ts").returncode, 0)
        uninstall_global()
        self.assertEqual(hook_status(self.repo), "none")
        self.assertNotIn("hooksPath", read(os.environ["GIT_CONFIG_GLOBAL"]))

    def test_stdin_json_for_editor(self):
        import json
        run_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "run.py")
        res = subprocess.run([sys.executable, run_py, "check", "--stdin", "--path", "a.py", "--format", "json"],
                             input=f'x = 1\ntoken = "{GH}"\n'.encode(), capture_output=True)
        hit = json.loads(res.stdout)["findings"][0]
        self.assertEqual((hit["rule_id"], hit["line"], hit["col"]), ("github-token", 2, 9))
        self.assertNotIn(GH, res.stdout.decode())


if __name__ == "__main__":
    unittest.main()
