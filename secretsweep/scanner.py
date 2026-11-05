"""Scan a git repository's HEAD tree and full history, merging hits into one finding per unique secret."""
from __future__ import annotations

import fnmatch
import re
import subprocess
from dataclasses import dataclass, field
from typing import Iterator, Optional
from urllib.parse import quote

from .rules import (SEVERITY_ORDER, SKIP_CONTENT, FileRule, Rule, fingerprint, gitignore_pattern, mask,
                    match_file_rule, scan_line)

MAX_BLOB_BYTES = 2 * 1024 * 1024


@dataclass
class Location:
    path: str
    line: Optional[int]
    commit: Optional[str]
    author: Optional[str] = None
    date: Optional[str] = None
    url: Optional[str] = None


@dataclass
class Finding:
    repo: str
    rule_id: str
    rule_name: str
    severity: str
    category: str
    kind: str                       # "content" | "file" | "untracked"
    fingerprint: str
    masked: str
    env_name: str
    rotate: str
    gitignore: str = ""
    head_locations: list[Location] = field(default_factory=list)
    first_seen: Optional[Location] = None
    commit_count: int = 0

    @property
    def in_head(self) -> bool:
        return bool(self.head_locations)

    @property
    def status(self) -> str:
        if self.kind == "untracked":
            return "untracked, not gitignored"
        return "LIVE in HEAD" if self.in_head else "history only"

    @property
    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), not self.in_head, self.repo, self.rule_id)


@dataclass
class RepoInfo:
    full_name: str
    html_url: Optional[str] = None
    private: bool = False
    local_path: Optional[str] = None


# --------------------------------------------------------------------------- git plumbing

def git(git_dir: str, *args: str, check: bool = True) -> bytes:
    proc = subprocess.run(["git", "-C", git_dir, "-c", "core.quotePath=false", *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def head_commit(git_dir: str) -> Optional[str]:
    out = git(git_dir, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", check=False).strip()
    return out.decode() or None


def iter_head_blobs(git_dir: str) -> Iterator[tuple[str, Optional[bytes]]]:
    """Yield (path, content) for every file at HEAD. content is None when the blob is skipped (too big/excluded)."""
    listing = git(git_dir, "ls-tree", "-r", "-z", "-l", "HEAD")
    entries = []
    for rec in listing.split(b"\0"):
        if not rec:
            continue
        meta, path = rec.split(b"\t", 1)
        mode, typ, sha, size = meta.split()
        if typ != b"blob" or mode == b"120000":   # skip submodules and symlinks
            continue
        entries.append((path.decode("utf-8", "replace"), sha.decode(), int(size) if size != b"-" else 0))
    batch = subprocess.Popen(["git", "-C", git_dir, "cat-file", "--batch"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for path, sha, size in entries:
            if size > MAX_BLOB_BYTES or SKIP_CONTENT.search(path):
                yield path, None
                continue
            batch.stdin.write(sha.encode() + b"\n")
            batch.stdin.flush()
            header = batch.stdout.readline().split()
            n = int(header[2])
            data = batch.stdout.read(n)
            batch.stdout.read(1)
            yield path, data
    finally:
        batch.stdin.close()
        batch.stdout.close()
        batch.wait()


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _diff_path(raw: str) -> Optional[str]:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1].encode("latin-1", "replace").decode("unicode_escape").encode("latin-1", "replace").decode("utf-8", "replace")
    if raw == "/dev/null":
        return None
    return raw[2:] if raw[:2] in ("a/", "b/") else raw


def iter_history(git_dir: str) -> Iterator[tuple[str, str, str, str, Optional[int], Optional[str]]]:
    """Walk every commit on every ref, oldest first.

    Yields (commit, author, date, path, line_no, added_line). added_line is None for a
    "file touched" event (used for sensitive-filename detection, including binaries).
    """
    proc = subprocess.Popen(
        ["git", "-C", git_dir, "-c", "core.quotePath=false", "log", "--all", "--reverse", "-p", "-U0",
         "--no-color", "--no-ext-diff", "--no-textconv", "--format=\x01%H\x02%an\x02%aI"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        yield from parse_diff(proc.stdout)
    finally:
        proc.stdout.close()
        proc.wait()


def parse_diff(stream) -> Iterator[tuple[str, str, str, str, Optional[int], Optional[str]]]:
    commit = author = date = ""
    path: Optional[str] = None
    line_no = 0
    skip = False
    for raw in stream:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("\x01"):
            commit, author, date = (line[1:].split("\x02") + ["", ""])[:3]
            path = None
        elif line.startswith("+++ "):
            path = _diff_path(line[4:])
            skip = path is None or bool(SKIP_CONTENT.search(path))
            if path:
                yield commit, author, date, path, None, None
        elif line.startswith("Binary files "):
            m = re.search(r" and (.+) differ$", line)
            p = _diff_path(m.group(1)) if m else None
            if p:
                yield commit, author, date, p, None, None
        elif line.startswith("@@"):
            m = _HUNK.match(line)
            line_no = int(m.group(1)) if m else 0
        elif line.startswith("+") and path and not skip:
            yield commit, author, date, path, line_no, line[1:]
            line_no += 1


def load_ignore(git_dir: str, rev: str = "HEAD") -> tuple[list[str], set[str]]:
    """.secretsweepignore at `rev` ("" = the index): one path glob per line, or `fp:<fingerprint>` to allow one secret."""
    data = git(git_dir, "show", f"{rev}:.secretsweepignore", check=False)
    globs, fps = [], set()
    for ln in data.decode("utf-8", "replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("fp:"):
            fps.add(ln[3:].strip())
        else:
            globs.append(ln)
    return globs, fps


# --------------------------------------------------------------------------- scanning

def path_ignored(path: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(path.rsplit("/", 1)[-1], g) for g in globs)


def content_fingerprint(rule: Rule, secret: str, path: str) -> str:
    return fingerprint(path + "\0" + secret if rule.per_file else secret)


class _Collector:
    def __init__(self, repo: RepoInfo, ignore_globs: list[str], ignore_fps: set[str]):
        self.repo = repo
        self.globs = ignore_globs
        self.fps = ignore_fps
        self.findings: dict[tuple[str, str], Finding] = {}
        self.commits: dict[tuple[str, str], set[str]] = {}

    def ignored(self, path: str) -> bool:
        return path_ignored(path, self.globs)

    def _url(self, commit: Optional[str], path: str, line: Optional[int]) -> Optional[str]:
        if not (self.repo.html_url and commit):
            return None
        return f"{self.repo.html_url}/blob/{commit}/{quote(path)}" + (f"#L{line}" if line else "")

    def _get(self, key, make) -> Optional[Finding]:
        if key[1] in self.fps:
            return None
        if key not in self.findings:
            self.findings[key] = make()
        return self.findings[key]

    def _content(self, rule: Rule, secret: str, path: str) -> tuple[tuple[str, str], callable]:
        fp = content_fingerprint(rule, secret, path)
        return (rule.id, fp), lambda: Finding(
            self.repo.full_name, rule.id, rule.name, rule.severity, rule.category, "content", fp,
            mask(secret) if not rule.per_file else secret[:40], rule.env_name, rule.rotate)

    def _file(self, fr: FileRule, path: str, kind: str = "file") -> tuple[tuple[str, str], callable]:
        fp = fingerprint("file\0" + path)
        sev = "medium" if kind == "untracked" else fr.severity
        return (fr.id + ("-untracked" if kind == "untracked" else ""), fp), lambda: Finding(
            self.repo.full_name, fr.id, fr.name.replace("Committed ", "") if kind == "untracked" else fr.name, sev, fr.category, kind, fp, path, "",
            fr.rotate or "Rotate every credential this file contained.", gitignore_pattern(fr, path))

    def add_head(self, path: str, line: Optional[int], commit: str, key_make):
        key, make = key_make
        f = self._get(key, make)
        if f:
            f.head_locations.append(Location(path, line, commit, url=self._url(commit, path, line)))

    def add_history(self, path, line, commit, author, date, key_make):
        key, make = key_make
        f = self._get(key, make)
        if not f:
            return
        if f.first_seen is None:
            f.first_seen = Location(path, line, commit, author, date, self._url(commit, path, line))
        self.commits.setdefault(key, set()).add(commit)

    def result(self) -> list[Finding]:
        for key, commits in self.commits.items():
            self.findings[key].commit_count = len(commits)
        return sorted(self.findings.values(), key=lambda f: f.sort_key)


def scan_repo(git_dir: str, repo: RepoInfo, history: bool = True, worktree: bool = False) -> list[Finding]:
    """Scan one repository. `git_dir` may be a bare clone or a normal working copy."""
    head = head_commit(git_dir)
    if head is None:
        return []                                       # empty repository
    globs, fps = load_ignore(git_dir)
    col = _Collector(repo, globs, fps)

    for path, data in iter_head_blobs(git_dir):
        if col.ignored(path):
            continue
        fr = match_file_rule(path)
        if fr:
            col.add_head(path, None, head, col._file(fr, path))
        if data is None or b"\0" in data[:8000]:
            continue
        text = data.decode("utf-8", "replace")
        for i, ln in enumerate(text.splitlines(), 1):
            for m in scan_line(ln, path):
                col.add_head(path, i, head, col._content(m.rule, m.secret, path))

    if history:
        for commit, author, date, path, line_no, added in iter_history(git_dir):
            if col.ignored(path):
                continue
            if added is None:
                fr = match_file_rule(path)
                if fr:
                    col.add_history(path, None, commit, author, date, col._file(fr, path))
                continue
            for m in scan_line(added, path):
                col.add_history(path, line_no, commit, author, date, col._content(m.rule, m.secret, path))

    if worktree:
        # Sensitive files sitting in the working tree that are neither tracked nor gitignored:
        # not leaked yet, but one `git add .` away from it.
        out = git(git_dir, "ls-files", "--others", "--exclude-standard", "-z", check=False)
        for p in out.decode("utf-8", "replace").split("\0"):
            fr = match_file_rule(p) if p else None
            if fr and not col.ignored(p):
                col.add_head(p, None, None, col._file(fr, p, kind="untracked"))

    return col.result()
