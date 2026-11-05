"""`secretsweep fix`: clean a local working copy.

1. gitignore .env (and any sensitive file types found)
2. untrack committed sensitive files (git rm --cached; the file stays on disk)
3. move hardcoded secrets into .env, add the key names to .env.example
4. rewrite Python / JS / TS source to read the value from the environment
5. optionally write a git-filter-repo plan to purge the secrets from history

Nothing is committed or pushed; review with `git diff` afterwards.
"""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from .rules import SKIP_CONTENT, Match, gitignore_pattern, mask, match_file_rule, scan_line
from .scanner import iter_history

PY_EXT = {".py", ".pyw"}
JS_EXT = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
ENV_BLOCK = [".env", ".env.*", "!.env.example", "!.env.sample", "!.env.template"]

_STRING = re.compile(r"""(?P<q>["'`])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")
_ASSIGN_NAME = re.compile(r"""["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(?:=|:|:=|=>)\s*$""")


@dataclass
class Plan:
    root: str
    gitignore_add: list[str] = field(default_factory=list)
    untrack: list[str] = field(default_factory=list)
    env_new: dict[str, str] = field(default_factory=dict)
    example_add: list[str] = field(default_factory=list)
    rewrites: dict[str, list[str]] = field(default_factory=dict)     # path -> new file lines
    rewrite_notes: list[tuple[str, int, str, str]] = field(default_factory=list)  # path, line, rule, env name
    manual: list[tuple[str, int, str, str, str]] = field(default_factory=list)    # path, line, rule, env, how-to
    rotate: dict[str, tuple[str, str]] = field(default_factory=dict)  # masked -> (rule name, how)

    @property
    def empty(self) -> bool:
        return not (self.gitignore_add or self.untrack or self.env_new or self.rewrites or self.manual)


def _git(root: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["git", "-C", root, "-c", "core.quotePath=false", *args], capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode(errors="replace").strip())
    return proc


def _is_ignored(root: str, path: str) -> bool:
    return _git(root, "check-ignore", "-q", "--no-index", "--", path, check=False).returncode == 0


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _env_name(raw: str) -> str:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").upper()
    return s if s and not s[0].isdigit() else "SECRET_" + s


def _read_env(path: str) -> dict[str, str]:
    out = {}
    if os.path.isfile(path):
        for ln in _read_bytes(path).decode("utf-8", "replace").splitlines():
            m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", ln)
            if m:
                out[m.group(1)] = m.group(2).strip().strip("'\"")
    return out


def _how_to(path: str, name: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    low = path.lower()
    if ".github/workflows/" in low:
        return f"store it as a repository secret and use ${{{{ secrets.{name} }}}}"
    if "docker-compose" in low or "compose." in low:
        return f"use ${{{name}}} and keep the value in .env"
    return {
        ".go": f'os.Getenv("{name}")', ".rb": f'ENV.fetch("{name}")', ".java": f'System.getenv("{name}")',
        ".kt": f'System.getenv("{name}")', ".php": f"getenv('{name}')", ".rs": f'std::env::var("{name}")',
        ".cs": f'Environment.GetEnvironmentVariable("{name}")', ".swift": f'ProcessInfo.processInfo.environment["{name}"]',
        ".sh": f'"${name}"', ".bash": f'"${name}"', ".zsh": f'"${name}"', ".ps1": f"$env:{name}",
        ".ipynb": f'os.environ["{name}"] (and clear the notebook outputs)',
        ".json": "move it out of this file into .env / your secret manager",
        ".yml": "move it out of this file into .env / your secret manager",
        ".yaml": "move it out of this file into .env / your secret manager",
    }.get(ext, f"read {name} from the environment instead of hardcoding it")


def _ensure_import_os(lines: list[str]) -> None:
    if any(re.match(r"\s*import\s+(?:.*,\s*)?os(?:\s|,|\.|$)", ln) for ln in lines):
        return
    i = 0
    while i < len(lines) and (lines[i].startswith("#") or not lines[i].strip()):
        i += 1
    if i < len(lines) and lines[i].lstrip()[:3] in ('"""', "'''"):
        q = lines[i].lstrip()[:3]
        if lines[i].count(q) < 2:
            i += 1
            while i < len(lines) and q not in lines[i]:
                i += 1
        i += 1
    while i < len(lines) and lines[i].startswith("from __future__"):
        i += 1
    nl = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    lines.insert(i, "import os" + nl)


def build_plan(root: str) -> Plan:
    root = _git(root, "rev-parse", "--show-toplevel").stdout.decode().strip()
    plan = Plan(root)
    env_path = os.path.join(root, ".env")
    env_all = _read_env(env_path)
    by_value = {v: k for k, v in env_all.items()}
    example = set(_read_env(os.path.join(root, ".env.example")))

    def claim(name: str, value: str) -> str:
        if value in by_value:
            return by_value[value]
        base, n = name, 2
        while name in env_all and env_all[name] != value:
            name, n = f"{base}_{n}", n + 1
        env_all[name] = value
        by_value[value] = name
        plan.env_new[name] = value
        return name

    want_ignore: list[str] = []
    if not (_is_ignored(root, ".env") and _is_ignored(root, ".env.local")):
        want_ignore += ENV_BLOCK

    tracked = [p for p in _git(root, "ls-files", "-z").stdout.decode("utf-8", "replace").split("\0") if p]
    for path in tracked:
        fr = match_file_rule(path)
        if fr:
            plan.untrack.append(path)
            pat = gitignore_pattern(fr, path)
            if not _is_ignored(root, path) and pat not in want_ignore:
                want_ignore.append(pat)
            plan.rotate[path] = (fr.name, fr.rotate or "rotate every credential this file contained")
            continue
        full = os.path.join(root, path)
        if SKIP_CONTENT.search(path) or not os.path.isfile(full) or os.path.getsize(full) > 2 * 1024 * 1024:
            continue
        data = _read_bytes(full)
        if b"\0" in data[:8000]:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        lines = (text if text is not None else data.decode("utf-8", "replace")).splitlines(keepends=True)
        ext = os.path.splitext(path)[1].lower()
        rewritable = text is not None and (ext in PY_EXT or ext in JS_EXT)
        changed = False
        for idx, line in enumerate(lines):
            matches = scan_line(line.rstrip("\r\n"), path)
            if not matches:
                continue
            new_line = line
            done_spans: list[tuple[int, int]] = []
            for m in sorted(matches, key=lambda m: -m.start):
                plan.rotate[mask(m.secret)] = (m.rule.name, m.rule.rotate or "rotate it with the issuer")
                lit = _enclosing_literal(line, m)
                name_src = m.var_name
                if lit:
                    nm = _ASSIGN_NAME.search(line[:lit[0]])
                    name_src = name_src or (nm.group(1) if nm else None)
                env_name = _env_name(name_src) if name_src else m.rule.env_name
                if lit and any(lit[0] == s for s, _ in done_spans):
                    continue
                if not (rewritable and lit and _safe_literal(line, lit, ext)):
                    plan.manual.append((path, idx + 1, m.rule.name, env_name, _how_to(path, env_name)))
                    continue
                ls, le, body = lit
                env_name = claim(env_name, body)
                accessor = f'os.environ["{env_name}"]' if ext in PY_EXT else f"process.env.{env_name}"
                new_line = new_line[:ls] + accessor + new_line[le:]
                done_spans.append((ls, le))
                plan.rewrite_notes.append((path, idx + 1, m.rule.name, env_name))
            if new_line != line:
                lines[idx] = new_line
                changed = True
        if changed:
            if ext in PY_EXT:
                _ensure_import_os(lines)
            plan.rewrites[path] = lines

    if plan.env_new and not _is_ignored(root, ".env") and ".env" not in want_ignore:
        want_ignore += ENV_BLOCK
    existing = set()
    gi = os.path.join(root, ".gitignore")
    if os.path.isfile(gi):
        existing = {ln.strip() for ln in _read_bytes(gi).decode("utf-8", "replace").splitlines()}
    plan.gitignore_add = [p for p in dict.fromkeys(want_ignore) if p not in existing]
    plan.example_add = [k for k in plan.env_new if k not in example]
    return plan


def _enclosing_literal(line: str, m: Match) -> Optional[tuple[int, int, str]]:
    for sm in _STRING.finditer(line):
        bs, be = sm.span("body")
        if bs <= m.start and m.end <= be:
            return sm.start(), sm.end(), sm.group("body")
    return None


def _safe_literal(line: str, lit: tuple[int, int, str], ext: str) -> bool:
    ls, _, body = lit
    if "\\" in body or "${" in body or "{" in body and line[ls] == "`":
        return False
    prefix = line[max(0, ls - 2):ls]
    if ext in PY_EXT and re.search(r"[fFbB][rR]?$|[rR][fFbB]$", prefix):
        return False                     # f-strings / bytes literals need a human
    return True


def _env_line(name: str, value: str) -> str:
    if re.search(r"[\s#'\"\\$]", value):
        value = '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return f"{name}={value}\n"


def print_plan(plan: Plan) -> None:
    print(f"\nRemediation plan for {plan.root}\n")
    if plan.gitignore_add:
        print("  .gitignore  + " + ", ".join(plan.gitignore_add))
    for p in plan.untrack:
        print(f"  untrack      {p}   (git rm --cached; file stays on disk)")
    for path, line, rule, name in plan.rewrite_notes:
        print(f"  rewrite      {path}:{line}  {rule} → {name} (value moved to .env)")
    if plan.example_add:
        print("  .env.example + " + ", ".join(plan.example_add))
    for path, line, rule, name, how in plan.manual:
        print(f"  MANUAL       {path}:{line}  {rule}: {how}")


def apply_plan(plan: Plan) -> None:
    root = plan.root
    if plan.gitignore_add:
        gi = os.path.join(root, ".gitignore")
        prefix = ""
        if os.path.isfile(gi):
            content = _read_bytes(gi)
            prefix = "" if not content or content.endswith(b"\n") else "\n"
        with open(gi, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(prefix + "\n# --- added by secret-sweep ---\n" + "\n".join(plan.gitignore_add) + "\n")
    if plan.untrack:
        _git(root, "rm", "--cached", "--quiet", "--", *plan.untrack)
    if plan.env_new:
        env_path = os.path.join(root, ".env")
        prefix = ""
        if os.path.isfile(env_path) and not _read_bytes(env_path).endswith(b"\n"):
            prefix = "\n"
        with open(env_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(prefix + "".join(_env_line(k, v) for k, v in plan.env_new.items()))
    if plan.example_add:
        ex = os.path.join(root, ".env.example")
        prefix = "" if not os.path.isfile(ex) or _read_bytes(ex).endswith(b"\n") else "\n"
        with open(ex, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(prefix + "".join(f"{k}=\n" for k in plan.example_add))
    for path, lines in plan.rewrites.items():
        with open(os.path.join(root, path), "w", encoding="utf-8", newline="") as fh:
            fh.write("".join(lines))


def write_purge_plan(root: str, out_file: str) -> tuple[int, list[str]]:
    """Collect every secret ever committed (raw values) into a git-filter-repo --replace-text file."""
    root_abs = os.path.abspath(root)
    out_abs = os.path.abspath(out_file)
    if os.path.commonpath([root_abs, out_abs]) == root_abs:
        raise ValueError("Write the purge file OUTSIDE the repository; it contains raw secret values.")
    secrets, paths = {}, []
    for _c, _a, _d, path, _ln, added in iter_history(root):
        if added is None:
            if match_file_rule(path) and path not in paths:
                paths.append(path)
            continue
        for m in scan_line(added, path):
            if not m.rule.per_file:
                secrets[m.secret] = None
    with open(out_abs, "w", encoding="utf-8", newline="\n") as fh:
        for s in secrets:
            fh.write(f"{s}==>***REMOVED-BY-SECRETSWEEP***\n")
    return len(secrets), paths


def print_next_steps(plan: Plan, purge: Optional[tuple[str, int, list[str]]]) -> None:
    print("\nNext steps")
    print("  1. ROTATE / REVOKE every exposed credential. Removing it from the code does not un-leak it:")
    for masked, (rule, how) in plan.rotate.items():
        print(f"       - {rule} {masked}: {how}")
    print("  2. Review the changes:   git status  &&  git diff")
    if plan.rewrites:
        print("     Your code now reads values from the environment. Load .env at startup, e.g.")
        print("       Python: pip install python-dotenv; from dotenv import load_dotenv; load_dotenv()")
        print("       Node:   node --env-file=.env app.js   (Node 20+), or npm i dotenv; import 'dotenv/config'")
    print("  3. Commit:  git add -A && git commit -m \"Remove hardcoded secrets\"")
    if purge:
        out_file, n, paths = purge
        print(f"  4. Purge history ({n} secret value(s), {len(paths)} sensitive path(s)). Install git-filter-repo, then in a")
        print("     FRESH clone (git clone --mirror <url>), run:")
        cmd = f'git filter-repo --sensitive-data-removal --replace-text "{out_file}"'
        cmd += "".join(f' --path "{p}"' for p in paths) + (" --invert-paths" if paths else "")
        print(f"       {cmd}")
        print("       (--sensitive-data-removal needs git-filter-repo 2.47+; drop it on older versions)")
        print("       git push --force --mirror origin")
        print("     Collaborators must re-clone. Ask GitHub Support to purge cached views and PR refs, and check forks.")
        print(f"     Then DELETE {out_file}: it contains the raw secrets.")
        if paths:
            print("     (Run --replace-text and --invert-paths as two separate passes if your filter-repo version complains.)")
    else:
        print("  4. Secrets also live in git history. Re-run with --purge-plan <file-outside-repo> for purge commands.")
