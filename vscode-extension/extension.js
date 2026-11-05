'use strict';
// Secret Sweep for VS Code. The blocking itself is a git pre-commit hook, so it also applies to
// commits made from the terminal or any other git client. This extension adds inline warnings,
// one-click hook setup, and shortcuts for the scan / fix commands.
const vscode = require('vscode');
const cp = require('child_process');
const os = require('os');
const path = require('path');

const SEVERITY = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
};
const MAX_LINT_CHARS = 1_000_000;

let ctx;
let diagnostics;
let statusItem;
let pythonErrorShown = false;
const lintTimers = new Map();

function cfg() {
  return vscode.workspace.getConfiguration('secretSweep');
}

function pythonCmd() {
  return cfg().get('pythonPath') || (process.platform === 'win32' ? 'python' : 'python3');
}

function toolScript() {
  return cfg().get('toolPath') || path.join(ctx.extensionPath, 'tool', 'run.py');
}

function runTool(args, { input, cwd } = {}) {
  return new Promise((resolve) => {
    let out = '';
    let err = '';
    let child;
    try {
      child = cp.spawn(pythonCmd(), [toolScript(), ...args], { cwd, windowsHide: true });
    } catch (e) {
      resolve({ code: -1, out, err: String(e) });
      return;
    }
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => resolve({ code: -1, out, err: String(e) }));
    child.on('close', (code) => resolve({ code, out, err }));
    child.stdin.on('error', () => {});
    child.stdin.end(input === undefined ? '' : input);
  });
}

function toolFailed(res) {
  if (res.code !== -1 || pythonErrorShown) return;
  pythonErrorShown = true;
  vscode.window
    .showErrorMessage(`Secret Sweep could not run Python (${pythonCmd()}). Install Python 3.9+ or set secretSweep.pythonPath.`,
      'Open Settings')
    .then((pick) => pick && vscode.commands.executeCommand('workbench.action.openSettings', 'secretSweep.pythonPath'));
}

// ------------------------------------------------------------------ inline warnings

async function lint(doc) {
  if (!cfg().get('highlightSecrets')) return;
  if (!['file', 'untitled'].includes(doc.uri.scheme)) return;
  const text = doc.getText();
  if (text.length > MAX_LINT_CHARS) return;
  const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
  const rel = folder
    ? path.relative(folder.uri.fsPath, doc.uri.fsPath).split(path.sep).join('/')
    : path.basename(doc.uri.fsPath || 'untitled');
  const args = ['check', '--stdin', '--path', rel, '--format', 'json'];
  if (folder) args.push(folder.uri.fsPath);
  const res = await runTool(args, { input: text, cwd: folder ? folder.uri.fsPath : undefined });
  if (res.code !== 0) return toolFailed(res);
  let data;
  try {
    data = JSON.parse(res.out);
  } catch {
    return;
  }
  const found = [];
  for (const h of data.findings) {
    const line = (h.line || 1) - 1;
    if (line >= doc.lineCount) continue;
    const range = new vscode.Range(line, h.col || 0, line, h.end || doc.lineAt(line).text.length);
    const d = new vscode.Diagnostic(range,
      `${h.rule_name} (${h.severity}). Move it to .env and read it from the environment; ` +
      `commits adding it will be blocked. Run "Secret Sweep: Fix this repo" to do it automatically.`,
      SEVERITY[h.severity] ?? vscode.DiagnosticSeverity.Warning);
    d.source = 'secret-sweep';
    d.code = h.rule_id;
    found.push(d);
  }
  diagnostics.set(doc.uri, found);
}

function lintSoon(doc, delay = 600) {
  const key = doc.uri.toString();
  clearTimeout(lintTimers.get(key));
  lintTimers.set(key, setTimeout(() => {
    lintTimers.delete(key);
    lint(doc);
  }, delay));
}

// ------------------------------------------------------------------ hook management

async function pickFolder() {
  const folders = vscode.workspace.workspaceFolders || [];
  if (folders.length === 0) {
    vscode.window.showWarningMessage('Secret Sweep: open a folder first.');
    return undefined;
  }
  return folders.length === 1 ? folders[0] : vscode.window.showWorkspaceFolderPick();
}

async function runHookCommand(args) {
  const res = await runTool(args);
  if (res.code === -1) return toolFailed(res);
  const msg = (res.code === 0 ? res.out : res.err || res.out).trim().split('\n')[0];
  (res.code === 0 ? vscode.window.showInformationMessage : vscode.window.showErrorMessage)(`Secret Sweep: ${msg}`);
  refreshStatus();
}

async function refreshStatus() {
  const folder = (vscode.workspace.workspaceFolders || [])[0];
  if (!folder) return statusItem.hide();
  const res = await runTool(['hook-status', folder.uri.fsPath]);
  const status = res.out.trim();
  if (res.code !== 0 || status === 'not-a-repo') return statusItem.hide();
  const on = status === 'repo' || status === 'global';
  statusItem.text = on ? '$(shield) Secrets blocked' : '$(unlock) Commits unprotected';
  statusItem.tooltip = on
    ? `Secret Sweep pre-commit hook active (${status === 'global' ? 'all repos' : 'this repo'})`
    : 'Click to block commits that contain secrets';
  statusItem.command = on ? 'secretSweep.scanRepo' : 'secretSweep.installHook';
  statusItem.show();
  return status;
}

async function offerHook(folder) {
  if (!cfg().get('offerHookInstall')) return;
  const key = `dismissed:${folder.uri.fsPath}`;
  if (ctx.globalState.get(key)) return;
  const res = await runTool(['hook-status', folder.uri.fsPath]);
  if (res.code !== 0 || res.out.trim() !== 'none') return toolFailed(res);
  const pick = await vscode.window.showInformationMessage(
    `Secret Sweep: block commits that contain API keys or wallet keys in "${folder.name}"?`,
    'This repo', 'All repos on this machine', "Don't ask again");
  if (pick === 'This repo') await runHookCommand(['install-hook', folder.uri.fsPath]);
  else if (pick === 'All repos on this machine') await runHookCommand(['install-hook', '--global']);
  else if (pick === "Don't ask again") await ctx.globalState.update(key, true);
}

// ------------------------------------------------------------------ terminal commands

function inTerminal(args, cwd) {
  const term = vscode.window.createTerminal({
    name: 'Secret Sweep',
    shellPath: pythonCmd(),
    shellArgs: [toolScript(), ...args],
    cwd: cwd || os.homedir(),
  });
  term.show();
}

function reportDir() {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  return path.join(ctx.globalStorageUri.fsPath, 'reports', stamp);
}

// ------------------------------------------------------------------ activation

function activate(context) {
  ctx = context;
  diagnostics = vscode.languages.createDiagnosticCollection('secret-sweep');
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  context.subscriptions.push(diagnostics, statusItem);

  const reg = (id, fn) => context.subscriptions.push(vscode.commands.registerCommand(id, fn));
  reg('secretSweep.installHook', async () => {
    const f = await pickFolder();
    if (f) await runHookCommand(['install-hook', f.uri.fsPath]);
  });
  reg('secretSweep.installHookGlobal', () => runHookCommand(['install-hook', '--global']));
  reg('secretSweep.uninstallHook', async () => {
    const f = await pickFolder();
    if (f) await runHookCommand(['uninstall-hook', f.uri.fsPath]);
  });
  reg('secretSweep.uninstallHookGlobal', () => runHookCommand(['uninstall-hook', '--global']));
  reg('secretSweep.scanRepo', async () => {
    const f = await pickFolder();
    if (f) inTerminal(['scan', f.uri.fsPath, '--out', reportDir()], f.uri.fsPath);
  });
  reg('secretSweep.scanGitHub', async () => {
    const target = await vscode.window.showInputBox({
      prompt: 'GitHub user or org (scans every repo they own), owner/repo, or a github.com URL',
      placeHolder: 'octocat   or   octocat/Hello-World',
      ignoreFocusOut: true,
    });
    if (target && target.trim()) inTerminal(['scan', ...target.trim().split(/\s+/), '--out', reportDir()]);
  });
  reg('secretSweep.fixRepo', async () => {
    const f = await pickFolder();
    if (f) inTerminal(['fix', f.uri.fsPath], f.uri.fsPath);
  });

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((d) => lintSoon(d, 50)),
    vscode.workspace.onDidChangeTextDocument((e) => lintSoon(e.document)),
    vscode.workspace.onDidSaveTextDocument((d) => lintSoon(d, 0)),
    vscode.workspace.onDidCloseTextDocument((d) => diagnostics.delete(d.uri)),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('secretSweep.highlightSecrets') && !cfg().get('highlightSecrets')) diagnostics.clear();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => refreshStatus()),
  );
  vscode.workspace.textDocuments.forEach((d) => lintSoon(d, 50));

  refreshStatus().then((status) => {
    if (status === 'none') (vscode.workspace.workspaceFolders || []).forEach(offerHook);
  });
}

function deactivate() {
  lintTimers.forEach((t) => clearTimeout(t));
}

module.exports = { activate, deactivate };
