"""Command-line entry point."""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import __version__
from .github import GitHubError, get_repo, list_repos, resolve_token, sync_clone
from .hooks import (hits_json, hook_status, install_global, install_repo, print_blocked, staged_hits, text_hits,
                    uninstall_global, uninstall_repo)
from .remediate import apply_plan, build_plan, print_next_steps, print_plan, write_purge_plan
from .report import print_console, write_reports
from .rules import FILE_RULES, RULES, SEVERITY_ORDER
from .scanner import RepoInfo, git, scan_repo

DEFAULT_CACHE = os.path.join(os.path.expanduser("~"), ".secretsweep", "cache")
_GH_URL = re.compile(r"^(?:https?://|git@)?(?:www\.)?github\.com[/:]([\w.-]+)(?:/([\w.-]+?))?(?:\.git)?/?(?:[#?].*)?$")
_OWNER_REPO = re.compile(r"^([\w.-]+)/([\w.-]+?)(?:\.git)?$")
_OWNER = re.compile(r"^[\w.-]+$")


def _filter(findings, min_sev):
    limit = SEVERITY_ORDER[min_sev]
    return [f for f in findings if SEVERITY_ORDER[f.severity] <= limit]


def _run_parallel(jobs, workers, fn):
    """Run fn(job) for each (label, job) across a thread pool, printing progress as repos finish."""
    findings, errors = [], {}
    total = len(jobs)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(fn, job): label for label, job in jobs}
        for done, fut in enumerate(as_completed(futs), 1):
            label = futs[fut]
            try:
                res, secs = fut.result()
                findings.extend(res)
                print(f"  [{done:>{len(str(total))}}/{total}] {label}: "
                      f"{len(res) or 'no'} finding{'s' if len(res) != 1 else ''} ({secs:.1f}s)", flush=True)
            except Exception as e:  # one broken repo must not stop the sweep
                errors[label] = str(e)
                print(f"  [{done}/{total}] {label}: ERROR {str(e).splitlines()[0] if str(e) else e}", flush=True)
    return findings, errors


def _find_local_repos(base: str, depth: int = 3) -> list[str]:
    found = []
    base = os.path.abspath(base)
    for cur, dirs, _files in os.walk(base):
        if os.path.exists(os.path.join(cur, ".git")):
            found.append(cur)
            dirs[:] = []
            continue
        if cur[len(base):].count(os.sep) >= depth:
            dirs[:] = []
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "venv", ".venv")]
    return sorted(found)


def _github_url(path: str):
    url = git(path, "remote", "get-url", "origin", check=False).decode().strip()
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?/?$", url)
    return f"https://github.com/{m.group(1)}" if m else None


def _resolve(targets, args):
    """Turn each target into scan jobs.

    A target is a local folder (one repo, or a folder of repos), a GitHub user/org (every repo
    they own), `owner/repo`, or a github.com URL to either.
    """
    jobs, errors, clones, token, token_done = {}, {}, {}, None, False
    for t in targets:
        if os.path.isdir(t):
            base = os.path.abspath(t)
            repos = _find_local_repos(base)
            if not repos:
                errors[t] = "no git repositories found here"
            for p in repos:
                label = os.path.relpath(p, os.path.dirname(base)).replace(os.sep, "/")
                jobs[label] = ("local", p)
                clones[label] = p
            continue
        if not token_done:
            token, token_done = resolve_token(args.token), True
            print("GitHub: " + ("authenticated (private repos included where you have access)"
                                if token else "unauthenticated, public repos only (set GITHUB_TOKEN for private)"))
        m = _GH_URL.match(t)
        owner, name = (m.group(1), m.group(2)) if m else (None, None)
        if not m:
            mr = _OWNER_REPO.match(t)
            owner, name = (mr.group(1), mr.group(2)) if mr else (t if _OWNER.match(t) else None, None)
        if not owner:
            errors[t] = "not a folder, GitHub user, owner/repo, or github.com URL"
            continue
        try:
            if name:
                repos = [get_repo(f"{owner}/{name}", token)]
            else:
                repos = list_repos(owner, token, args.include_forks, not args.skip_archived)
                print(f"  {owner}: {len(repos)} repo(s)")
        except GitHubError as e:
            errors[t] = str(e)
            continue
        if args.only:
            wanted = {r.strip().lower() for r in args.only.split(",")}
            repos = [r for r in repos if r["name"].lower() in wanted]
        for r in repos:
            jobs[r["full_name"]] = ("remote", r)
    return list(jobs.items()), errors, clones, token


def cmd_scan(args) -> int:
    jobs, errors, clones, token = _resolve(args.targets, args)
    for t, e in errors.items():
        print(f"  {t}: {e}", file=sys.stderr)
    if not jobs:
        print("Nothing to scan.")
        return 2 if errors else 0
    print(f"Scanning {len(jobs)} repo(s) with {min(args.workers, len(jobs))} worker(s)"
          f"{'' if args.no_history else ', including full git history'}…")

    def work(job):
        t0 = time.time()
        kind, obj = job
        if kind == "local":
            label = next(k for k, v in clones.items() if v == obj)
            info = RepoInfo(label, _github_url(obj), local_path=obj)
            return scan_repo(obj, info, history=not args.no_history, worktree=True), time.time() - t0
        dest = os.path.join(args.cache, obj["owner"]["login"], obj["name"] + ".git")
        sync_clone(obj["clone_url"], dest, token)
        info = RepoInfo(obj["full_name"], obj["html_url"], obj.get("private", False))
        return scan_repo(dest, info, history=not args.no_history), time.time() - t0

    findings, scan_errors = _run_parallel(jobs, min(args.workers, len(jobs)), work)
    errors.update(scan_errors)
    label = args.targets[0] if len(args.targets) == 1 else "multi"
    label = os.path.basename(os.path.abspath(label)) if os.path.isdir(label) else label
    meta = {"owner": label, "targets": args.targets, "repo_count": len(jobs), "history": not args.no_history,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tool": f"secret-sweep {__version__}", "clones": clones}

    findings = _filter(findings, args.min_severity)
    print_console(findings, errors, meta["repo_count"])
    safe = re.sub(r"[^\w.-]+", "_", label).strip("_") or "scan"
    out = args.out or os.path.join("reports", f"{safe}-{time.strftime('%Y%m%d-%H%M%S')}")
    json_path, md_path = write_reports(findings, errors, meta, out)
    print(f"\nReport: {os.path.abspath(md_path)}\nJSON:   {os.path.abspath(json_path)}")
    if any(f.in_head for f in findings):
        print("\nTo fix a repo, run against your local working copy:  secretsweep fix <path-to-repo>")
    fail = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] <= fail for f in findings) else 0


def cmd_check(args) -> int:
    try:
        if args.stdin:
            text = sys.stdin.buffer.read().decode("utf-8", "replace")
            hits = text_hits(text, args.as_path or "stdin", repo=args.repo)
        else:
            hits = staged_hits(args.repo)
    except RuntimeError as e:
        print(f"secret-sweep: {e}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(hits_json(hits))
        return 0 if args.stdin else int(bool(hits))
    limit = SEVERITY_ORDER[args.block_on]
    blocking = [h for h in hits if SEVERITY_ORDER[h.severity] <= limit]
    if blocking:
        print_blocked(hits)
        return 1
    for h in hits:
        print(f"secret-sweep: warning, {h.rule_name} ({h.severity}) at {h.path}:{h.line}. Allowed, below --block-on.")
    return 0


def cmd_install_hook(args) -> int:
    try:
        if args.global_:
            print(install_global())
            return 0
        repos = _find_local_repos(args.path)
        if not repos:
            print(f"No git repositories found under {args.path}", file=sys.stderr)
            return 2
        for r in repos:
            print(install_repo(r))
        print("\nCommits that add secrets will now be rejected (terminal, VS Code, and any git GUI).")
        return 0
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def cmd_uninstall_hook(args) -> int:
    if args.global_:
        print(uninstall_global())
        return 0
    for r in _find_local_repos(args.path):
        print(uninstall_repo(r))
    return 0


def cmd_hook_status(args) -> int:
    print(hook_status(args.path))
    return 0


def cmd_fix(args) -> int:
    try:
        plan = build_plan(args.path)
    except RuntimeError as e:
        print(f"error: {args.path} is not a git working copy ({e})", file=sys.stderr)
        return 2
    purge = None
    if args.purge_plan:
        try:
            n, paths = write_purge_plan(plan.root, args.purge_plan)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        purge = (os.path.abspath(args.purge_plan), n, paths)
        print(f"Wrote history purge list ({n} value(s)) to {purge[0]}  ← contains raw secrets, delete after use")
    if plan.empty:
        print(f"\nNothing to change in the working tree of {plan.root}.")
        if purge:
            print_next_steps(plan, purge)
        return 0
    print_plan(plan)
    if args.dry_run:
        print("\n(dry run: nothing changed)")
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            print("\nRefusing to modify files without confirmation; re-run with --yes.", file=sys.stderr)
            return 2
        if input("\nApply these changes? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted; nothing changed.")
            return 1
    apply_plan(plan)
    print("\nApplied. Nothing was committed or pushed.")
    print_next_steps(plan, purge)
    return 0


def cmd_rules(_args) -> int:
    for r in RULES:
        print(f"  {r.severity:8} {r.id:28} {r.name}")
    for r in FILE_RULES:
        print(f"  {r.severity:8} {r.id:28} {r.name} (filename)")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="secretsweep", description="Find, block, and remove leaked secrets in git repositories.")
    p.add_argument("--version", action="version", version=f"secret-sweep {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def scan_opts(sp):
        sp.add_argument("--workers", type=int, default=min(16, (os.cpu_count() or 4) * 2), help="repos scanned in parallel")
        sp.add_argument("--no-history", action="store_true", help="only scan the current tree, not every commit")
        sp.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low", help="hide findings below this level")
        sp.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="low", help="exit 1 if findings at/above this level")
        sp.add_argument("--out", help="report directory (default: ./reports/<target>-<timestamp>)")
        sp.add_argument("--token", help="GitHub token (default: $GITHUB_TOKEN, $GH_TOKEN, or `gh auth token`)")
        sp.add_argument("--include-forks", action="store_true")
        sp.add_argument("--skip-archived", action="store_true")
        sp.add_argument("--only", help="comma-separated repo names to limit a user/org sweep to")
        sp.add_argument("--cache", default=DEFAULT_CACHE, help=f"where bare clones are kept (default: {DEFAULT_CACHE})")
        sp.set_defaults(fn=cmd_scan)

    s = sub.add_parser("scan", help="scan repos: a GitHub user/org, owner/repo, a github.com URL, or a local folder",
                       description="TARGET may be: a GitHub user or org (every repo they own), owner/repo, "
                                   "a github.com URL, a local repo, or a local folder containing many repos. "
                                   "Mix as many as you like.")
    s.add_argument("targets", nargs="+", metavar="TARGET")
    scan_opts(s)

    sl = sub.add_parser("scan-local", help="alias for `scan <folder>`")
    sl.add_argument("targets", nargs="+", metavar="PATH")
    scan_opts(sl)

    c = sub.add_parser("check", help="scan staged changes (what the pre-commit hook runs); exit 1 to block")
    c.add_argument("repo", nargs="?", default=".")
    c.add_argument("--block-on", choices=list(SEVERITY_ORDER), default="medium",
                   help="lowest severity that blocks the commit (default: medium; low findings only warn)")
    c.add_argument("--stdin", action="store_true", help="scan text from stdin instead (editor integrations)")
    c.add_argument("--path", dest="as_path", help="file path to report for --stdin text")
    c.add_argument("--format", choices=["text", "json"], default="text")
    c.set_defaults(fn=cmd_check)

    ih = sub.add_parser("install-hook", help="block commits containing secrets: one repo, every repo in a folder, or --global")
    ih.add_argument("path", nargs="?", default=".", help="a repo, or a folder of repos (default: current folder)")
    ih.add_argument("--global", dest="global_", action="store_true", help="protect every repo on this machine")
    ih.set_defaults(fn=cmd_install_hook)

    uh = sub.add_parser("uninstall-hook", help="remove the pre-commit hook")
    uh.add_argument("path", nargs="?", default=".")
    uh.add_argument("--global", dest="global_", action="store_true")
    uh.set_defaults(fn=cmd_uninstall_hook)

    hs = sub.add_parser("hook-status", help="print none | repo | global | not-a-repo")
    hs.add_argument("path", nargs="?", default=".")
    hs.set_defaults(fn=cmd_hook_status)

    f = sub.add_parser("fix", help="remediate a local working copy (.gitignore, untrack, move secrets to .env)")
    f.add_argument("path")
    f.add_argument("--dry-run", action="store_true", help="show the plan without changing anything")
    f.add_argument("--yes", "-y", action="store_true", help="apply without asking")
    f.add_argument("--purge-plan", metavar="FILE", help="also write a git-filter-repo replacements file (outside the repo)")
    f.set_defaults(fn=cmd_fix)

    r = sub.add_parser("rules", help="list detection rules")
    r.set_defaults(fn=cmd_rules)

    args = p.parse_args(argv)
    if getattr(args, "workers", 1) < 1:
        p.error("--workers must be at least 1")
    return args.fn(args)
