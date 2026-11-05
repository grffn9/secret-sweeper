# secret-sweep

Find leaked secrets in one repo or in **every repository a GitHub user (or org) owns**, see exactly
where each one is (file, line, commit, author, link), clean them up, and **block new ones at commit time**.

- **Any scope:** a single repo, a whole GitHub account, a local folder of repos, or a mix, scanned in parallel.
- **Full history:** scans every commit on every branch, not just the current files. A key you
  deleted last year is still public if it's in history.
- **Blocks commits:** a git pre-commit hook rejects any commit that adds a secret. It works from VS
  Code, the terminal, and any git GUI. An optional VS Code extension also underlines secrets as you type.
- **Remediation built in:** `fix` gitignores `.env`, untracks committed secret files, moves
  hardcoded keys into `.env`, and rewrites Python/JS/TS code to read them from the environment.
- **Safe by default:** reports show masked values only. Nothing is ever committed or pushed for you.
- **No dependencies:** Python 3.9+ and git.

## Quick start

`run.py` works from anywhere. Or `pip install -e .` once and use `secretsweep` instead of `python run.py`.

```bash
# --- scan ---
python run.py scan octocat                          # every repo a GitHub user/org owns
python run.py scan octocat/Hello-World              # one GitHub repo (or paste its URL)
python run.py scan C:\code\my-app                   # one local repo
python run.py scan C:\code                          # every repo in a local folder
python run.py scan alice bob/api C:\code\my-app     # mix any of the above

# private repos: use a token with read access
$env:GITHUB_TOKEN="ghp_yourtoken"                   # cmd.exe: set GITHUB_TOKEN=...

# --- block commits that contain secrets ---
python run.py install-hook C:\code\my-app           # one repo
python run.py install-hook C:\code                  # every repo in a folder
python run.py install-hook --global                 # every repo on this machine, including future clones

# --- clean up a repo (your working copy): shows a plan, asks before changing anything ---
python run.py fix C:\code\my-app
```

A target that exists as a local folder is scanned locally. To force GitHub, use the URL form
(`github.com/name`).

## What you get

Console output grouped by repo, plus `reports/<owner>-<timestamp>/report.md` and `findings.json`:

```
■ me/shop-api  (12 findings)
   CRITICAL  AWS Access Key ID  AKIA…KJI  [LIVE in HEAD]
      → app.py:2   https://github.com/me/shop-api/blob/<sha>/app.py#L2
      first committed 356ee25b15 by Jane on 2025-03-14 (app.py:2); in 4 commit(s)
   CRITICAL  Bitcoin Private Key (WIF)  L4yM…NCP  [history only]
      first committed dfc9cb13b2 by Jane on 2024-11-02 (old.py:1); in 1 commit(s)
```

Status meanings:
| Status | Meaning |
|---|---|
| **LIVE in HEAD** | In the current code. Rotate it, then run `fix`. |
| **history only** | Deleted from the code but still in old commits. Rotate it, then purge history. |
| **untracked, not gitignored** | (Local repos only.) Not leaked yet, but one `git add .` away. |

The exit code is 1 when anything is found (`--fail-on high` to tune), so it also works in CI.

## What it detects

Run `python -m secretsweep rules` for the full list.

- **Cloud / infra:** AWS keys, Google API keys and service-account JSON, Azure storage keys, DigitalOcean
- **Code hosting / registries:** GitHub (classic + fine-grained), GitLab, npm, PyPI tokens
- **AI:** OpenAI, Anthropic, Hugging Face
- **Payments / comms:** Stripe, Square, Shopify, Slack tokens and webhooks, Discord, Telegram, Twilio, SendGrid, Mailgun
- **Crypto wallets:** EVM private keys, Bitcoin WIF keys (checksum-verified), BIP32 xprv keys, seed/mnemonic
  phrases, Solana keypair arrays, encrypted Ethereum keystores, `wallet.dat`
- **Credentials:** PEM/SSH/PGP private keys, database URLs with passwords, JWTs, hardcoded
  `password = "..."` / `api_key = "..."` assignments (entropy-filtered)
- **Files that shouldn't be committed:** `.env*`, `id_rsa`, `*.pem/*.key/*.p12`, `.npmrc`, `.pypirc`,
  `.git-credentials`, `*.tfstate`, `*.kdbx`, and more

## Blocking commits

The pre-commit hook runs `secretsweep check`, which scans **only the lines being added** in the
staged changes. An old secret elsewhere in a file never blocks an unrelated commit (`scan` is what
finds those). A blocked commit looks like this in the terminal, and in VS Code's commit error dialog:

```
secret-sweep: commit blocked. 2 secret(s) found in your staged changes.

  CRITICAL  Stripe Live Secret Key  sk_l…7dc
            billing.py:1
  HIGH      Committed .env file
            .env
            fix: git rm --cached ".env"  and add .env to .gitignore
```

| Install | Command | Notes |
|---|---|---|
| One repo | `install-hook <repo>` | Writes `.git/hooks/pre-commit`. An existing hook is kept and still runs after the check. |
| A folder of repos | `install-hook <folder>` | Same as above, for every repo found up to 3 levels deep. |
| Every repo on the machine | `install-hook --global` | Sets git's global `core.hooksPath`, so new clones are covered too. Each repo's own hooks still run. |
| Teams using [pre-commit](https://pre-commit.com) | add this repo to `.pre-commit-config.yaml` | `.pre-commit-hooks.yaml` is included (hook id `secret-sweep`). |

- Remove with `uninstall-hook <repo>` or `uninstall-hook --global`. `hook-status <repo>` shows the current state.
- `check --block-on high` blocks only high and critical. The default is medium; low findings (e.g. Stripe
  *test* keys) print a warning but let the commit through.
- Repos that set their own `core.hooksPath` (husky, etc.) are skipped. `install-hook` prints the line
  to add to their hook instead.
- The hook runs a copy of the scanner in `~/.secretsweep/lib`, so it keeps working if you move this folder.
- Bypass once with `git commit --no-verify`.

### VS Code extension

`vscode-extension/` contains a small extension (the scanner is bundled; it needs Python only):

```bash
python vscode-extension/build_vsix.py
code --install-extension vscode-extension/dist/secret-sweep-0.1.0.vsix
```

- When you open a repo without protection, it offers to install the hook for that repo or for all repos.
- Underlines secrets as you type, with a fix hint.
- The status bar shows whether commits are protected.
- Command palette, under "Secret Sweep": scan this repo, scan a GitHub user/org/repo, fix this repo,
  install or remove protection.

## Remediation: `fix`

Run `fix` on **your local working copy** of a repo (not the scan cache):

```bash
python -m secretsweep fix ./my-app --dry-run      # show the plan only
python -m secretsweep fix ./my-app                # asks [y/N] before changing anything
python -m secretsweep fix ./my-app --purge-plan ../my-app-purge.txt   # also prepare a history purge
```

What it does:
1. Adds `.env`, `.env.*` (keeping `.env.example`) and any sensitive file types it found to `.gitignore`.
2. `git rm --cached` committed secret files (`.env`, `*.pem`, wallets…). They stay on your disk.
3. Moves hardcoded secrets into `.env` and adds the key names (no values) to `.env.example`.
4. Rewrites the code: `AWS_KEY = "AKIA…"` becomes `AWS_KEY = os.environ["AWS_KEY"]` (Python) or
   `process.env.AWS_KEY` (JS/TS). Other languages and config files (YAML, JSON, Go, Ruby…) are listed
   as **MANUAL** with the exact replacement to use.
5. Prints next steps: rotation links for each secret, how to load `.env` (`python-dotenv`,
   `node --env-file=.env`), and the commit command.

`--purge-plan FILE` collects every secret ever committed into a
[git-filter-repo](https://github.com/newren/git-filter-repo) `--replace-text` file and prints the
exact rewrite and force-push commands. The file holds raw secrets, so it must sit outside the repo
and should be deleted afterwards. The tool never rewrites history or force-pushes for you.

### Order matters

1. **Rotate/revoke first.** Once a secret has been pushed, assume someone has it. Bots scrape GitHub
   within minutes. Removing it from the code does not un-leak it.
   **Crypto keys and seed phrases can't be rotated:** move the funds to a new wallet immediately.
2. Run `fix`, review `git diff`, commit.
3. Purge history if the repo is public or the secret was valuable, then ask collaborators to re-clone.

## Options

| Flag | Applies to | Meaning |
|---|---|---|
| `--workers N` | scan | Repos scanned in parallel (default: 2× CPU cores, max 16) |
| `--no-history` | scan | Scan only the current files (faster, misses deleted secrets) |
| `--only a,b` | scan | Limit a user/org sweep to these repo names |
| `--include-forks` / `--skip-archived` | scan | Forks are skipped and archived repos included by default |
| `--min-severity` / `--fail-on` | scan | Filter output / set exit-code threshold |
| `--block-on LEVEL` | check | Lowest severity that blocks a commit (default: medium) |
| `--cache DIR` | scan | Bare clones are cached here (`~/.secretsweep/cache`), so later runs only fetch new commits |
| `--token` | scan | GitHub token (also read from `GITHUB_TOKEN`, `GH_TOKEN`, or `gh auth token`) |

The token is passed to git as an HTTP header through the environment. It is never written to
`.git/config`, a remote URL, or the reports.

## Suppressing false positives

- Inline: add `secretsweep:allow` (or `gitleaks:allow`) as a comment on the line.
- Per repo: commit a `.secretsweepignore` with path globs (`tests/fixtures/*`) or specific
  findings by fingerprint (`fp:68c6ab3eba220da7`, shown in the report).

## Limitations

- Pattern-based: it can't tell whether a key is still active. Check with the provider.
- Merge-commit-only changes and files over 2 MB are not scanned. Lines are scanned up to 4,000 characters.
- Scans GitHub. For other hosts, clone the repos into one folder and use `scan-local`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests build throwaway repos with randomly generated fake secrets and check detection, history
tracking, masking, and the full `fix` flow.
