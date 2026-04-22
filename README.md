# depcheck

**Dependency scanner for humans.** Find known CVEs, unused packages wasting install time, and missing imports that'll crash production — all offline, no network, no API keys.

Free forever gift from [vøiddo](https://voiddo.com).

```
$ depcheck all

  depcheck — full scan (my-app)
  ────────────────────

  Found 2 vulnerabilities:

  ✗ lodash@4.17.15
    Severity: HIGH
    CVE:      CVE-2021-23337
    Issue:    Command Injection
    Fix:      upgrade to >=4.17.21

  ✗ minimist@1.2.0
    Severity: CRITICAL
    CVE:      CVE-2021-44906
    Issue:    Prototype Pollution
    Fix:      upgrade to >=1.2.6

  UNUSED (2): commander, chalk
  MISSING (1): moment
```

## Why depcheck

`npm audit` requires a network call, needs a lockfile, and (when it works) throws a wall of JSON at you. `depcheck` (the classic one) only checks unused. `pip-audit` only checks Python vulns. You end up running three tools and still don't know if you have unused Express deps dragging install time.

This depcheck is one binary that does the three things that matter:
1. **Offline CVE scan** — 47 curated entries through 2025 (Express, Axios, WS, `follow-redirects`, supply-chain sabotage like `node-ipc` / `colors` / `faker`).
2. **Unused / missing** — static import analysis across `.js/.mjs/.cjs/.jsx/.ts/.tsx`.
3. **Python support** — same game for `requirements.txt` / `pyproject.toml` + `.py` sources.

No network calls. No API keys. No npm registry lookup. Runs in CI, Docker builds, even `offline` containers.

## Install

```bash
npm install -g @v0idd0/depcheck
```

Ad-hoc via `npx`:

```bash
npx -y @v0idd0/depcheck check --fail-on high
```

## Quickstart

```bash
# Vuln scan (default, walks package-lock.json for transitives)
depcheck

# Focused check
depcheck check --package axios
depcheck check --critical

# CI gate: fail on any high or worse
depcheck check --fail-on high

# Unused / missing static analysis
depcheck unused
depcheck missing

# All three reports together
depcheck all

# Python (requirements.txt or pyproject.toml)
depcheck python

# Dump the curated CVE database
depcheck list
depcheck list --json | jq length

# Machine-readable envelope for CI
depcheck check --json | jq .vulnerabilities
```

## Commands

| Command | Aliases | Description |
|---------|---------|-------------|
| `check`   | `c` | Scan for known CVEs in `package.json` / `package-lock.json` (default) |
| `unused`  | `u` | Find declared deps that aren't imported anywhere |
| `missing` | `m` | Find imports that aren't declared |
| `all`     | `a` | Roll up: vulns + unused + missing |
| `python`  | `py`| Same unused/missing analysis for Python |
| `list`    | `l` | Dump the curated CVE database (47 entries) |

## Options

| Flag | Description |
|------|-------------|
| `-p, --path <dir>` | Project root (default: cwd) |
| `--package <name>` | Restrict vuln check to a single package |
| `--critical` | Only show `critical`-severity issues |
| `--fail-on <sev>` | Exit non-zero if any issue ≥ severity (critical/high/medium/low) |
| `--json` | JSON envelope output |
| `--no-lock` | Skip `package-lock.json`, direct deps only |
| `-h, --help` | Show help |
| `--version` | Show version |

## What's in the CVE database

47 entries hand-curated from the npm ecosystem, 2017–2025:

- **Prototype pollution**: minimist, async, y18n, set-value, ansi, json5, postcss, highlight.js, xml2js
- **ReDoS**: node-fetch, glob-parent, trim-newlines, path-parse, hosted-git-info, normalize-url, debug, marked, semver, moment, fast-xml-parser
- **Command / code injection**: lodash, ejs, pug, handlebars, simple-git, yaml
- **Auth / HTTP issues**: axios (XSRF), jsonwebtoken, cookie, express (open redirect), body-parser, serve-static, send, ws
- **Supply-chain sabotage**: `node-ipc` (wiped RU/BY disks), `colors` (intentionally broken), `faker` (renamed to `@faker-js/faker`)
- **2024 freshness**: puppeteer, esbuild, webpack, cookie, `follow-redirects`, `serve-static`

Run `depcheck list` to see everything. The DB ships in the package — no network call at runtime.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean (no vulns / `--fail-on` threshold not met) |
| `1`  | Vulnerabilities found, file missing, or unknown command |

## Programmatic use

```js
const {
  scanPackageJson, readLockfile, walkLockfilePackages,
  checkVulnerabilities, findUnusedAndMissingJs, findUnusedAndMissingPy,
  extractJsImports, extractPyImports, KNOWN_VULNS,
} = require('@v0idd0/depcheck/src/scanner');

// Direct CVE scan
const deps = scanPackageJson('./my-project');
const vulns = checkVulnerabilities(deps);

// Transitive scan
const lock = readLockfile('./my-project');
const entries = walkLockfilePackages(lock);
const allVulns = checkVulnerabilities(entries);

// Unused / missing
const { unused, missing } = findUnusedAndMissingJs('./my-project');

// Parse imports
const imports = extractJsImports(`const x = require('foo');`);
// Set { 'foo' }
```

## From the same studio

vøiddo builds sharp, free-forever CLIs for devs who are tired of paywalls:

- [`@v0idd0/jsonyo`](https://voiddo.com/tools/jsonyo/) — JSON that yells at you
- [`@v0idd0/tokcount`](https://voiddo.com/tools/tokcount/) — token counter for 60+ LLMs
- [`@v0idd0/ctxstuff`](https://voiddo.com/tools/ctxstuff/) — stuff a repo into an LLM context
- [`@v0idd0/promptdiff`](https://voiddo.com/tools/promptdiff/) — diff two prompts
- [`@v0idd0/httpwut`](https://voiddo.com/tools/httpwut/) — HTTP debugger
- [`@v0idd0/gitstats`](https://voiddo.com/tools/gitstats/) — local git analytics
- [`@v0idd0/licenseme`](https://voiddo.com/tools/licenseme/) — LICENSE generator + detector
- [`@v0idd0/envguard`](https://voiddo.com/tools/envguard/) — .env validator + secret scanner

Full catalog: [voiddo.com/tools](https://voiddo.com/tools/).

## License

MIT © [vøiddo](https://voiddo.com) — free forever, no asterisks.

## Links

- Docs: https://voiddo.com/tools/depcheck/
- Source: https://github.com/voidd0/depcheck
- npm: https://npmjs.com/package/@v0idd0/depcheck
- Studio: https://voiddo.com
- Issues: https://github.com/voidd0/depcheck/issues
- Support: support@voiddo.com
