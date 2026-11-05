"""Console, JSON and Markdown reports. Reports never contain raw secret values, only masked previews."""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from dataclasses import asdict

from .rules import SEVERITY_ORDER
from .scanner import Finding

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
_DIM, _BOLD, _RESET = "\033[2m", "\033[1m", "\033[0m"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")   # enables ANSI escape handling in the Windows console
    return True


def remediation_steps(f: Finding, local_hint: str = "<path-to-your-clone>") -> list[str]:
    steps = []
    if f.category == "crypto":
        steps.append(f"**Treat the wallet as compromised.** {f.rotate}")
    elif f.kind == "untracked":
        steps.append(f"Not committed yet. Add `{f.gitignore or '/' + f.masked}` to `.gitignore` before your next commit.")
        return steps
    else:
        steps.append(f"Revoke / rotate it: {f.rotate}" if f.rotate else "Revoke / rotate it with the issuer.")
    if f.in_head:
        if f.kind == "file":
            steps.append(f"Untrack the file and gitignore it (`{f.gitignore}`): `secretsweep fix {local_hint}` does this.")
        elif f.rule_id == "env-file-secret":
            steps.append("This lives in a committed env file: `secretsweep fix` untracks it and gitignores `.env`.")
        else:
            steps.append(f"Move the value into `.env` as `{f.env_name}` and read it from the environment: "
                         f"`secretsweep fix {local_hint}` does this and gitignores `.env`.")
    steps.append("Purge it from git history (it stays retrievable from old commits even after deletion): "
                 f"`secretsweep fix {local_hint} --purge-plan <file-outside-repo>` writes a git-filter-repo plan.")
    return steps


def print_console(findings: list[Finding], errors: dict[str, str], repo_count: int) -> None:
    color = _use_color()
    c = (lambda code, s: f"{code}{s}{_RESET}") if color else (lambda code, s: s)
    by_repo: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda f: f.sort_key):
        by_repo.setdefault(f.repo, []).append(f)
    for repo, items in sorted(by_repo.items()):
        print("\n" + c(_BOLD, f"■ {repo}") + c(_DIM, f"  ({len(items)} finding{'s' if len(items) != 1 else ''})"))
        for f in items:
            sev = c(_COLORS.get(f.severity, ""), f" {f.severity.upper():8} ")
            print(f"  {sev} {f.rule_name}  {c(_DIM, f.masked)}  [{f.status}]")
            for loc in f.head_locations[:5]:
                where = f"{loc.path}:{loc.line}" if loc.line else loc.path
                print(f"      → {where}" + (c(_DIM, f"  {loc.url}") if loc.url else ""))
            if len(f.head_locations) > 5:
                print(c(_DIM, f"      … and {len(f.head_locations) - 5} more locations"))
            if f.first_seen:
                fs = f.first_seen
                where = f"{fs.path}:{fs.line}" if fs.line else fs.path
                print(c(_DIM, f"      first committed {fs.commit[:10]} by {fs.author} on {(fs.date or '')[:10]} "
                              f"({where}); in {f.commit_count} commit(s)"))
    counts = Counter(f.severity for f in findings)
    print("\n" + c(_BOLD, "Summary: ") + f"{len(findings)} finding(s) across {len(by_repo)} of {repo_count} repo(s)  "
          + "  ".join(f"{s}: {counts[s]}" for s in SEVERITY_ORDER if counts[s]))
    if errors:
        print(c(_COLORS["medium"], f"{len(errors)} repo(s) could not be scanned:"))
        for repo, err in errors.items():
            print(f"  - {repo}: {err.splitlines()[0] if err else 'error'}")


def write_reports(findings: list[Finding], errors: dict[str, str], meta: dict, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    findings = sorted(findings, key=lambda f: f.sort_key)

    json_path = os.path.join(out_dir, "findings.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "errors": errors,
                   "findings": [{**asdict(f), "in_head": f.in_head, "status": f.status} for f in findings]}, fh, indent=2)

    md_path = os.path.join(out_dir, "report.md")
    counts = Counter(f.severity for f in findings)
    lines = [f"# Secret sweep: {meta.get('owner', 'local')}", "",
             f"Scanned **{meta.get('repo_count', 0)}** repositories on {meta.get('scanned_at', '')}"
             f" (history: {'yes' if meta.get('history') else 'no'}).", "",
             "| Severity | Count |", "|---|---|"]
    lines += [f"| {s} | {counts[s]} |" for s in SEVERITY_ORDER if counts[s]] or ["| none | 0 |"]
    lines += ["", "> Values are masked. Every secret listed here should be considered exposed: "
              "**rotate first**, then clean the repo and its history.", ""]
    by_repo: dict[str, list[Finding]] = {}
    for f in findings:
        by_repo.setdefault(f.repo, []).append(f)
    clones = meta.get("clones", {})
    for repo, items in by_repo.items():
        lines += [f"## {repo}", ""]
        for i, f in enumerate(items, 1):
            lines.append(f"### {i}. {f.rule_name} `{f.masked}`")
            lines.append(f"**{f.severity.upper()}** · {f.status} · fingerprint `{f.fingerprint}`")
            lines.append("")
            for loc in f.head_locations:
                where = f"{loc.path}:{loc.line}" if loc.line else loc.path
                lines.append(f"- {'[' + where + '](' + loc.url + ')' if loc.url else '`' + where + '`'}")
            if f.first_seen:
                fs = f.first_seen
                where = f"{fs.path}:{fs.line}" if fs.line else fs.path
                link = f"[{fs.commit[:10]}]({fs.url})" if fs.url else f"`{fs.commit[:10]}`"
                lines.append(f"- First committed in {link} by {fs.author} on {(fs.date or '')[:10]} "
                             f"(`{where}`), present in {f.commit_count} commit(s)")
            lines += ["", "**Remediation**", ""]
            lines += [f"{n}. {s}" for n, s in enumerate(remediation_steps(f, clones.get(repo, "<path-to-your-clone>")), 1)]
            lines.append("")
    if errors:
        lines += ["## Repositories that could not be scanned", ""]
        lines += [f"- {r}: {e.splitlines()[0] if e else 'error'}" for r, e in errors.items()]
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return json_path, md_path
