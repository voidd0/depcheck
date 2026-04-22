#!/usr/bin/env node
// depcheck — dep scanner: vulns + unused/missing + Python. Free forever from vøiddo.
// https://voiddo.com/tools/depcheck/

const {
  scanPackageJson,
  readLockfile,
  walkLockfilePackages,
  checkVulnerabilities,
  formatReport,
  findUnusedAndMissingJs,
  findUnusedAndMissingPy,
  KNOWN_VULNS,
} = require('../src/scanner');
const { maybeShowPromo, getHelpFooter } = require('../src/promo');

const pkg = require('../package.json');
const args = process.argv.slice(2);

const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

function showHelp() {
  console.log(`
${YELLOW}depcheck${RESET} ${DIM}v${pkg.version}${RESET}
${DIM}dependency scanner: known vulns + unused/missing — free forever from vøiddo${RESET}

${CYAN}Usage:${RESET}
  depcheck [command] [path] [options]

${CYAN}Commands:${RESET}
  check, c          Scan package.json (+ lockfile) for known vulnerabilities (default)
  unused, u         Find declared dependencies that aren't imported anywhere
  missing, m        Find imported modules that aren't declared in package.json
  all, a            All of the above, rolled up
  python, py        Same check but for Python requirements.txt / pyproject.toml
  list, l           Dump known CVE database entries

${CYAN}Options:${RESET}
  -p, --path <dir>        Project root to scan (default: cwd)
  --package <name>        Restrict vuln check to a single package
  --critical              Only show critical-severity issues
  --fail-on <severity>    Exit non-zero if any issue ≥ severity (critical|high|medium|low)
  --json                  Emit JSON envelope
  --no-lock               Do not walk package-lock.json (direct deps only)
  -h, --help              Show this help
  --version               Show version

${CYAN}Examples:${RESET}
  depcheck                                ${DIM}# scan cwd for vulns${RESET}
  depcheck check --package lodash         ${DIM}# focused scan${RESET}
  depcheck check --fail-on high           ${DIM}# CI gate${RESET}
  depcheck unused                         ${DIM}# find unused dev/prod deps${RESET}
  depcheck missing                        ${DIM}# imports that lack a declaration${RESET}
  depcheck all --json | jq .summary       ${DIM}# full report${RESET}
  depcheck python                         ${DIM}# Python unused/missing via requirements.txt${RESET}
  depcheck list --json | jq length        ${DIM}# CVE DB size${RESET}

${DIM}docs: https://voiddo.com/tools/depcheck/${RESET}${getHelpFooter()}
`);
}

function parseArgs() {
  const opts = {
    command: 'check',
    targetPath: '.',
    package: null,
    critical: false,
    failOn: null,
    json: false,
    noLock: false,
    help: false,
    version: false,
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') { opts.help = true; continue; }
    if (arg === '--version') { opts.version = true; continue; }
    if (arg === '--package') { opts.package = args[++i]; continue; }
    if (arg === '--critical') { opts.critical = true; continue; }
    if (arg === '--fail-on') { opts.failOn = args[++i]; continue; }
    if (arg === '--json') { opts.json = true; continue; }
    if (arg === '--no-lock') { opts.noLock = true; continue; }
    if (arg === '-p' || arg === '--path') { opts.targetPath = args[++i]; continue; }
    if (!arg.startsWith('-')) {
      const cmd = arg.toLowerCase();
      const cmds = ['check', 'c', 'unused', 'u', 'missing', 'm', 'all', 'a', 'python', 'py', 'list', 'l'];
      if (cmds.includes(cmd) && opts.command === 'check') {
        opts.command = cmd;
      } else {
        opts.targetPath = arg;
      }
    }
  }
  return opts;
}

function severityAtLeast(issueSev, threshold) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  const a = order[issueSev];
  const b = order[threshold];
  if (a === undefined || b === undefined) return false;
  return a <= b;
}

function runCheck(opts) {
  const deps = scanPackageJson(opts.targetPath);
  if (deps.error) {
    if (opts.json) process.stdout.write(JSON.stringify({ command: 'check', ok: false, error: deps.error }) + '\n');
    else console.error(`${RED}${deps.error}${RESET}`);
    return 1;
  }

  const lock = opts.noLock ? null : readLockfile(opts.targetPath);
  const entries = lock ? walkLockfilePackages(lock) : null;

  const vulns = entries
    ? checkVulnerabilities(entries, { critical: opts.critical, package: opts.package })
    : checkVulnerabilities(deps, { critical: opts.critical, package: opts.package });

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      command: 'check',
      ok: vulns.length === 0,
      project: deps.name,
      lockfileUsed: !!lock,
      scanned: entries ? entries.length : Object.keys(deps.dependencies).length + Object.keys(deps.devDependencies).length,
      vulnerabilities: vulns,
    }, null, 2) + '\n');
  } else {
    if (!opts.critical) {
      console.log();
      console.log(`  ${YELLOW}depcheck${RESET} ${DIM}— voiddo.com/tools/depcheck${RESET}`);
      console.log(`  ${DIM}${'─'.repeat(28)}${RESET}`);
      console.log(`  Project:  ${deps.name}`);
      console.log(`  Source:   ${lock ? 'package-lock.json (transitive)' : 'package.json (direct only)'}`);
      console.log(`  Scanned:  ${entries ? entries.length : Object.keys(deps.dependencies).length + Object.keys(deps.devDependencies).length} package(s)`);
    }
    process.stdout.write(formatReport(vulns));
  }

  if (opts.failOn) {
    for (const v of vulns) {
      if (severityAtLeast(v.severity, opts.failOn)) return 1;
    }
    return 0;
  }
  return vulns.length > 0 ? 1 : 0;
}

function runUnusedMissingJs(opts, mode) {
  const result = findUnusedAndMissingJs(opts.targetPath);
  if (result.error) {
    if (opts.json) process.stdout.write(JSON.stringify({ command: mode, ok: false, error: result.error }) + '\n');
    else console.error(`${RED}${result.error}${RESET}`);
    return 1;
  }

  if (opts.json) {
    const payload = { command: mode, ok: true, ...result };
    if (mode === 'unused') delete payload.missing;
    if (mode === 'missing') delete payload.unused;
    process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
  } else {
    console.log();
    console.log(`  ${YELLOW}depcheck ${mode}${RESET} ${DIM}— voiddo.com/tools/depcheck${RESET}`);
    console.log(`  ${DIM}${'─'.repeat(28)}${RESET}`);
    console.log(`  Declared: ${result.declared}   Imported: ${result.imported}   Files: ${result.files}`);
    console.log();

    if (mode !== 'missing') {
      console.log(`  ${CYAN}UNUSED DEPS${RESET} ${DIM}(declared but never imported)${RESET}`);
      console.log(`  ${DIM}${'─'.repeat(11)}${RESET}`);
      if (result.unused.length === 0) {
        console.log(`  ${GREEN}✓${RESET} none`);
      } else {
        for (const n of result.unused) console.log(`  ${YELLOW}-${RESET} ${n}`);
      }
      console.log();
    }

    if (mode !== 'unused') {
      console.log(`  ${CYAN}MISSING DEPS${RESET} ${DIM}(imported but not declared)${RESET}`);
      console.log(`  ${DIM}${'─'.repeat(12)}${RESET}`);
      if (result.missing.length === 0) {
        console.log(`  ${GREEN}✓${RESET} none`);
      } else {
        for (const n of result.missing) console.log(`  ${RED}+${RESET} ${n}`);
      }
      console.log();
    }
  }

  const hasIssues = (mode === 'unused' && result.unused.length > 0)
    || (mode === 'missing' && result.missing.length > 0);
  return hasIssues && opts.failOn ? 1 : 0;
}

function runAll(opts) {
  const deps = scanPackageJson(opts.targetPath);
  if (deps.error) {
    if (opts.json) process.stdout.write(JSON.stringify({ command: 'all', ok: false, error: deps.error }) + '\n');
    else console.error(`${RED}${deps.error}${RESET}`);
    return 1;
  }

  const lock = opts.noLock ? null : readLockfile(opts.targetPath);
  const entries = lock ? walkLockfilePackages(lock) : null;
  const vulns = entries
    ? checkVulnerabilities(entries, { critical: opts.critical, package: opts.package })
    : checkVulnerabilities(deps, { critical: opts.critical, package: opts.package });

  const um = findUnusedAndMissingJs(opts.targetPath);

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      command: 'all',
      project: deps.name,
      vulnerabilities: vulns,
      unused: um.unused || [],
      missing: um.missing || [],
      summary: {
        vulns: vulns.length,
        unused: (um.unused || []).length,
        missing: (um.missing || []).length,
      },
    }, null, 2) + '\n');
  } else {
    console.log();
    console.log(`  ${YELLOW}depcheck — full scan${RESET} ${DIM}(${deps.name})${RESET}`);
    console.log(`  ${DIM}${'─'.repeat(20)}${RESET}`);
    process.stdout.write(formatReport(vulns));
    console.log(`  ${CYAN}UNUSED (${um.unused.length}):${RESET} ${um.unused.length ? um.unused.join(', ') : '—'}`);
    console.log(`  ${CYAN}MISSING (${um.missing.length}):${RESET} ${um.missing.length ? um.missing.join(', ') : '—'}`);
    console.log();
  }
  return vulns.length > 0 ? 1 : 0;
}

function runPython(opts) {
  const result = findUnusedAndMissingPy(opts.targetPath);
  if (result.error) {
    if (opts.json) process.stdout.write(JSON.stringify({ command: 'python', ok: false, error: result.error }) + '\n');
    else console.error(`${RED}${result.error}${RESET}`);
    return 1;
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify({ command: 'python', ok: true, ...result }, null, 2) + '\n');
  } else {
    console.log();
    console.log(`  ${YELLOW}depcheck python${RESET} ${DIM}— voiddo.com/tools/depcheck${RESET}`);
    console.log(`  ${DIM}${'─'.repeat(28)}${RESET}`);
    console.log(`  Declared: ${result.declared}   Imported: ${result.imported}   Files: ${result.files}`);
    console.log();
    console.log(`  ${CYAN}UNUSED${RESET} ${DIM}(${result.unused.length})${RESET}`);
    for (const n of result.unused.slice(0, 30)) console.log(`  ${YELLOW}-${RESET} ${n}`);
    if (result.unused.length > 30) console.log(`  ${DIM}... and ${result.unused.length - 30} more${RESET}`);
    console.log();
    console.log(`  ${CYAN}MISSING${RESET} ${DIM}(${result.missing.length})${RESET}`);
    for (const n of result.missing.slice(0, 30)) console.log(`  ${RED}+${RESET} ${n}`);
    if (result.missing.length > 30) console.log(`  ${DIM}... and ${result.missing.length - 30} more${RESET}`);
    console.log();
  }
  return 0;
}

function runList(opts) {
  const rows = Object.entries(KNOWN_VULNS).map(([name, v]) => ({ name, ...v }));
  if (opts.json) {
    process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
    return 0;
  }
  console.log();
  console.log(`  ${YELLOW}depcheck — known CVE database${RESET} ${DIM}(${rows.length} entries)${RESET}`);
  console.log(`  ${DIM}${'─'.repeat(28)}${RESET}`);
  for (const r of rows) {
    const colors = { critical: RED, high: YELLOW, medium: CYAN, low: DIM };
    const c = colors[r.severity] || RESET;
    console.log(`  ${c}${r.severity.padEnd(9)}${RESET} ${r.name.padEnd(22)} ${DIM}< ${r.below.padEnd(9)} ${r.cve.padEnd(18)} — ${r.desc}${RESET}`);
  }
  console.log();
  return 0;
}

function main() {
  const opts = parseArgs();
  if (opts.help) { showHelp(); return 0; }
  if (opts.version) { console.log(pkg.version); return 0; }

  let code = 0;
  switch (opts.command) {
    case 'check':
    case 'c':
      code = runCheck(opts); break;
    case 'unused':
    case 'u':
      code = runUnusedMissingJs(opts, 'unused'); break;
    case 'missing':
    case 'm':
      code = runUnusedMissingJs(opts, 'missing'); break;
    case 'all':
    case 'a':
      code = runAll(opts); break;
    case 'python':
    case 'py':
      code = runPython(opts); break;
    case 'list':
    case 'l':
      code = runList(opts); break;
    default:
      if (opts.json) process.stdout.write(JSON.stringify({ ok: false, error: `unknown command "${opts.command}"` }) + '\n');
      else console.error(`${RED}unknown command "${opts.command}"${RESET}`);
      code = 1;
  }

  maybeShowPromo();
  return code;
}

process.exit(main() || 0);
