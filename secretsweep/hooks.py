"""Commit-time protection.

`check` scans only what is about to be committed (lines added in the index), so an old secret
elsewhere in the file never blocks an unrelated commit. `install_*` wire it in as a git
pre-commit hook. Git runs that hook for every commit from the terminal, VS Code, or any GUI.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Iterable, Optional

from .rules import SEVERITY_ORDER, fingerprint, gitignore_pattern, mask, match_file_rule, scan_line
from .scanner import content_fingerprint, load_ignore, parse_diff, path_ignored

MARK = "secret-sweep pre-commit hook"
PASSTHROUGH_MARK = "secret-sweep pass-through"
BACKUP_SUFFIX = ".pre-secretsweep"
CLIENT_HOOKS = ["applypatch-msg", "pre-applypatch", "post-applypatch", "prepare-commit-msg", "commit-msg",
                "post-commit", "pre-rebase", "post-checkout", "post-merge", "pre-push", "post-rewrite",
                "pre-merge-commit", "pre-auto-gc", "push-to-checkout", "reference-transaction"]


def sweep_home() -> str:
    return os.environ.get("SECRETSWEEP_HOME") or os.path.join(os.path.expanduser("~"), ".secretsweep")


def _git(cwd: str, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout.strip()


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


# --------------------------------------------------------------------------- check

@dataclass
class Hit:
    path: str
    line: Optional[int]
    col: Optional[int]
    end: Optional[int]
    rule_id: str
    rule_name: str
    severity: str
    masked: str
    env_name: str
    fingerprint: str
    kind: str            # "content" | "file"
    gitignore: str = ""


def scan_added(items: Iterable[tuple[str, Optional[int], Optional[str]]], globs: list[str], fps: set[str],
               file_rules: bool = True) -> list[Hit]:
    """items: (path, line_no, text). text None means "this path is being added/changed" (filename rules only)."""
    hits, seen = [], set()
    for path, line_no, text in items:
        if path_ignored(path, globs):
            continue
        if text is None:
            fr = match_file_rule(path) if file_rules else None
            fp = fingerprint("file\0" + path)
            if fr and fp not in fps and ("file", path) not in seen:
                seen.add(("file", path))
                hits.append(Hit(path, None, None, None, fr.id, fr.name, fr.severity, path, "", fp, "file",
                                gitignore_pattern(fr, path)))
            continue
        for m in scan_line(text, path):
            fp = content_fingerprint(m.rule, m.secret, path)
            if fp in fps or (fp, path, line_no) in seen:
                continue
            seen.add((fp, path, line_no))
            hits.append(Hit(path, line_no, m.start, m.end, m.rule.id, m.rule.name, m.rule.severity,
                            mask(m.secret) if not m.rule.per_file else m.secret[:40], m.rule.env_name, fp, "content"))
    return sorted(hits, key=lambda h: (SEVERITY_ORDER[h.severity], h.path, h.line or 0))


def staged_hits(repo: str) -> list[Hit]:
    root = _git(repo, "rev-parse", "--show-toplevel")
    globs, fps = load_ignore(root, rev="")
    proc = subprocess.Popen(
        ["git", "-C", root, "-c", "core.quotePath=false", "diff", "--cached", "-U0", "--no-color",
         "--no-ext-diff", "--no-textconv", "--diff-filter=ACMR"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        items = [(path, line_no, text) for _c, _a, _d, path, line_no, text in parse_diff(proc.stdout)]
    finally:
        proc.stdout.close()
        proc.wait()
    return scan_added(items, globs, fps)


def text_hits(text: str, path: str, repo: Optional[str] = None) -> list[Hit]:
    globs, fps = [], set()
    if repo:
        try:
            globs, fps = load_ignore(_git(repo, "rev-parse", "--show-toplevel"), rev="HEAD")
        except RuntimeError:
            pass
    return scan_added(((path, i, ln) for i, ln in enumerate(text.splitlines(), 1)), globs, fps, file_rules=False)


def print_blocked(hits: list[Hit]) -> None:
    out = sys.stdout
    out.write(f"\nsecret-sweep: commit blocked. {len(hits)} secret(s) found in your staged changes.\n\n")
    for h in hits:
        where = f"{h.path}:{h.line}" if h.line else h.path
        detail = "" if h.kind == "file" else f"  {h.masked}"
        out.write(f"  {h.severity.upper():8}  {h.rule_name}{detail}\n            {where}\n")
        if h.kind == "file":
            out.write(f"            fix: git rm --cached \"{h.path}\"  and add {h.gitignore} to .gitignore\n")
    out.write("\nHow to fix:\n"
              "  - Move the value into .env (gitignored) and read it from the environment.\n"
              "    `secretsweep fix .` does this for you, then `git add` the result.\n"
              "  - False positive? Add a `secretsweep:allow` comment on that line, or add\n"
              "    `fp:<fingerprint>` to .secretsweepignore. Fingerprints: "
              + ", ".join(sorted({h.fingerprint for h in hits})) + "\n"
              "  - Bypass once (not recommended): git commit --no-verify\n\n")
    out.flush()


def hits_json(hits: list[Hit]) -> str:
    return json.dumps({"findings": [asdict(h) for h in hits]})


# --------------------------------------------------------------------------- install

def _install_lib() -> str:
    """Copy this package to ~/.secretsweep/lib so hooks keep working if the original folder moves."""
    lib = os.path.join(sweep_home(), "lib")
    src = os.path.dirname(os.path.abspath(__file__))
    dst = os.path.join(lib, "secretsweep")
    if not _same(src, dst):
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    run_py = os.path.join(lib, "run.py")
    with open(run_py, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("import os, sys\nsys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
                 "from secretsweep.__main__ import run\nrun()\n")
    return run_py.replace("\\", "/")


def _hook_body(run_py: str, chain: str) -> str:
    py = sys.executable.replace("\\", "/")
    return f"""#!/bin/sh
# {MARK}: blocks commits that add secrets.
# Bypass once: git commit --no-verify    Remove: secretsweep uninstall-hook
SWEEP_RUN="{run_py}"
run_sweep() {{
  [ "$SECRETSWEEP_CHECKED" = "1" ] && return 0
  for py in "{py}" python3 python py; do
    if [ -f "$py" ] || command -v "$py" >/dev/null 2>&1; then
      "$py" "$SWEEP_RUN" check
      return $?
    fi
  done
  echo "secret-sweep: Python not found, so staged changes could not be checked. Commit blocked." >&2
  echo "Install Python, or bypass once with: git commit --no-verify" >&2
  return 1
}}
run_sweep || exit 1
export SECRETSWEEP_CHECKED=1
{chain}
exit 0
"""


def _write_exec(path: str, body: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _global_hooks_dir() -> str:
    return os.path.join(sweep_home(), "hooks")


def global_installed() -> bool:
    cur = _git(".", "config", "--global", "--get", "core.hooksPath", check=False)
    return bool(cur) and _same(os.path.expanduser(cur), _global_hooks_dir())


def _repo_dirs(repo: str) -> tuple[str, str]:
    root = _git(repo, "rev-parse", "--show-toplevel")
    common = _git(root, "rev-parse", "--git-common-dir")
    common = common if os.path.isabs(common) else os.path.join(root, common)
    return root, os.path.join(common, "hooks")


def install_repo(repo: str) -> str:
    root, hooks_dir = _repo_dirs(repo)
    local_hp = _git(root, "config", "--local", "--get", "core.hooksPath", check=False)
    if local_hp:
        return (f"{root}: skipped, this repo routes hooks through core.hooksPath={local_hp} (husky or similar).\n"
                f"    Add this line to that pre-commit hook instead:  \"{sys.executable}\" \"{_install_lib()}\" check")
    os.makedirs(hooks_dir, exist_ok=True)
    hook = os.path.join(hooks_dir, "pre-commit")
    backup = hook + BACKUP_SUFFIX
    note = ""
    if os.path.isfile(hook):
        with open(hook, encoding="utf-8", errors="replace") as fh:
            ours = MARK in fh.read()
        if not ours:
            if os.path.exists(backup):
                return f"{root}: skipped, both pre-commit and pre-commit{BACKUP_SUFFIX} exist; merge them by hand."
            os.replace(hook, backup)
            note = f" (your existing pre-commit hook still runs, after the check)"
    chain = (f'HOOK_DIR="$(dirname "$0")"\n'
             f'if [ -f "$HOOK_DIR/pre-commit{BACKUP_SUFFIX}" ]; then exec "$HOOK_DIR/pre-commit{BACKUP_SUFFIX}" "$@"; fi')
    _write_exec(hook, _hook_body(_install_lib(), chain))
    cur = _git(root, "config", "--global", "--get", "core.hooksPath", check=False)
    if cur and not global_installed():
        note += f"\n    warning: global core.hooksPath={cur} overrides repo hooks, so git will not run this one."
    return f"{root}: protected{note}"


def uninstall_repo(repo: str) -> str:
    root, hooks_dir = _repo_dirs(repo)
    hook = os.path.join(hooks_dir, "pre-commit")
    if not os.path.isfile(hook):
        return f"{root}: no hook installed"
    with open(hook, encoding="utf-8", errors="replace") as fh:
        if MARK not in fh.read():
            return f"{root}: pre-commit hook is not secret-sweep's; left alone"
    os.remove(hook)
    if os.path.isfile(hook + BACKUP_SUFFIX):
        os.replace(hook + BACKUP_SUFFIX, hook)
        return f"{root}: removed; your previous pre-commit hook was restored"
    return f"{root}: removed"


def install_global() -> str:
    gdir = _global_hooks_dir()
    cur = _git(".", "config", "--global", "--get", "core.hooksPath", check=False)
    if cur and not global_installed():
        raise RuntimeError(f"global core.hooksPath is already set to {cur}. Install per repo instead "
                           f"(secretsweep install-hook <folder>), or unset it first.")
    os.makedirs(gdir, exist_ok=True)
    local = 'LOCAL="$(git rev-parse --git-common-dir)/hooks/{name}"\nif [ -f "$LOCAL" ]; then exec "$LOCAL" "$@"; fi'
    _write_exec(os.path.join(gdir, "pre-commit"), _hook_body(_install_lib(), local.format(name="pre-commit")))
    for name in CLIENT_HOOKS:
        # core.hooksPath replaces .git/hooks for every hook type, so forward the rest to the repo's own.
        _write_exec(os.path.join(gdir, name), f"#!/bin/sh\n# {PASSTHROUGH_MARK}\n{local.format(name=name)}\nexit 0\n")
    _git(".", "config", "--global", "core.hooksPath", gdir.replace("\\", "/"))
    return (f"Every repository on this machine is now protected (global core.hooksPath -> {gdir}).\n"
            "Existing per-repo hooks keep running. Repos with their own core.hooksPath (e.g. husky) are not covered.")


def uninstall_global() -> str:
    if not global_installed():
        return "Global hook is not installed."
    _git(".", "config", "--global", "--unset", "core.hooksPath")
    shutil.rmtree(_global_hooks_dir(), ignore_errors=True)
    return "Global hook removed; git uses each repo's own .git/hooks again."


def hook_status(repo: str) -> str:
    try:
        _root, hooks_dir = _repo_dirs(repo)
    except RuntimeError:
        return "not-a-repo"
    if global_installed():
        return "global"
    hook = os.path.join(hooks_dir, "pre-commit")
    if os.path.isfile(hook):
        with open(hook, encoding="utf-8", errors="replace") as fh:
            if MARK in fh.read():
                return "repo"
    return "none"
