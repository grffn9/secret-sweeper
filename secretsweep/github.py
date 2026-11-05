"""List every repository owned by a GitHub user/org and keep bare clones of them in a local cache."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from typing import Optional

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


def resolve_token(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    if shutil.which("gh"):
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    return None


def _get(url: str, token: Optional[str]):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "secret-sweep",
        **({"Authorization": f"Bearer {token}"} if token else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp), resp.headers.get("Link", "")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise GitHubError(f"Not found: {url}") from None
        if e.code in (401, 403):
            remaining = e.headers.get("X-RateLimit-Remaining")
            hint = ("rate limit hit; set GITHUB_TOKEN to raise it" if remaining == "0"
                    else "token rejected or lacks access")
            raise GitHubError(f"GitHub API {e.code} for {url} ({hint})") from None
        raise GitHubError(f"GitHub API {e.code} for {url}") from None


def _paginate(url: str, token: Optional[str]) -> list[dict]:
    items = []
    while url:
        page, link = _get(url, token)
        items.extend(page)
        url = None
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part[part.find("<") + 1:part.find(">")]
    return items


def list_repos(owner: str, token: Optional[str], include_forks: bool = False,
               include_archived: bool = True) -> list[dict]:
    """All repos owned by `owner`. Private repos are included when the token belongs to that user (or an org member)."""
    me = None
    if token:
        try:
            me = _get(f"{API}/user", token)[0]["login"]
        except GitHubError:
            me = None
    profile = _get(f"{API}/users/{owner}", token)[0]
    if profile.get("type") == "Organization":
        repos = _paginate(f"{API}/orgs/{owner}/repos?type=all&per_page=100", token)
    elif me and me.lower() == owner.lower():
        repos = _paginate(f"{API}/user/repos?affiliation=owner&per_page=100", token)
    else:
        repos = _paginate(f"{API}/users/{owner}/repos?type=owner&per_page=100", token)
    return [r for r in repos
            if (include_forks or not r.get("fork")) and (include_archived or not r.get("archived"))]


def get_repo(full_name: str, token: Optional[str]) -> dict:
    return _get(f"{API}/repos/{full_name}", token)[0]


def _git_env(token: Optional[str]) -> dict:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if token:
        # Pass auth as an extra HTTP header via env-config so the token never lands in
        # .git/config, the process list, or the remote URL.
        n = int(env.get("GIT_CONFIG_COUNT", "0") or 0)
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env[f"GIT_CONFIG_KEY_{n}"] = "http.https://github.com/.extraheader"
        env[f"GIT_CONFIG_VALUE_{n}"] = f"AUTHORIZATION: basic {basic}"
        env["GIT_CONFIG_COUNT"] = str(n + 1)
    return env


def sync_clone(clone_url: str, dest: str, token: Optional[str]) -> str:
    """Bare-clone the repo into `dest`, or fetch updates if it is already cached. Returns `dest`."""
    env = _git_env(token)
    base = ["git", "-c", "credential.helper=", "-c", "core.askPass="]
    if os.path.isdir(dest):
        cmd = base + ["-C", dest, "fetch", "--quiet", "--prune", "--force", "origin",
                      "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"]
    else:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        cmd = base + ["clone", "--bare", "--quiet", clone_url, dest]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        if not os.path.isdir(os.path.join(dest, "objects")):
            shutil.rmtree(dest, ignore_errors=True)
        raise RuntimeError(proc.stderr.strip() or f"git exited {proc.returncode}")
    return dest
