# Secret Sweep for VS Code

- **Blocks commits that add secrets.** On first open of a repo it offers to install a git
  pre-commit hook for this repo or for every repo on the machine. Because it's a real git hook,
  it also blocks commits from the terminal and other git clients, not just VS Code.
- **Highlights secrets as you type:** API keys, tokens, private keys, wallet keys and seed phrases
  get a red squiggle with a fix hint.
- **Commands** (Ctrl+Shift+P, then "Secret Sweep"): scan this repo including history, scan a whole
  GitHub user/org or one repo, fix this repo (moves secrets to `.env`), install or remove protection.

The status bar shows whether commits in the current repo are protected.

Requires Python 3.9+ on PATH (or set `secretSweep.pythonPath`). The scanner is bundled; no other installs.
