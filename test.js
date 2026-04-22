// depcheck — tests. free forever from vøiddo. https://voiddo.com/tools/depcheck/

const {
  scanPackageJson,
  checkVulnerabilities,
  formatReport,
  extractJsImports,
  extractPyImports,
  compareVersions,
  findUnusedAndMissingJs,
  readLockfile,
  walkLockfilePackages,
  KNOWN_VULNS,
} = require('./src/scanner');
const fs = require('fs');
const path = require('path');
const os = require('os');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log('\x1b[32m✓ ' + name + '\x1b[0m');
    passed++;
  } catch (e) {
    console.log('\x1b[31m✗ ' + name + '\x1b[0m');
    console.log('  ' + e.message);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

// Test scanPackageJson
test('scanPackageJson returns object with dependencies', () => {
  const result = scanPackageJson('.');
  assert(typeof result === 'object', 'Should return object');
  assert('dependencies' in result || 'devDependencies' in result || 'name' in result, 'Should have deps or name');
});

test('scanPackageJson returns error for missing file', () => {
  const result = scanPackageJson('/nonexistent/path');
  assert(result.error, 'Should return error for missing file');
});

// Test checkVulnerabilities
test('checkVulnerabilities finds vulnerable lodash', () => {
  const deps = {
    dependencies: { 'lodash': '^4.17.15' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length > 0, 'Should find vulnerability');
  assert(vulns[0].name === 'lodash', 'Should be lodash');
});

test('checkVulnerabilities finds vulnerable minimist', () => {
  const deps = {
    dependencies: { 'minimist': '1.2.0' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length > 0, 'Should find vulnerability');
  assert(vulns[0].severity === 'critical', 'Should be critical');
});

test('checkVulnerabilities ignores safe versions', () => {
  const deps = {
    dependencies: { 'lodash': '^4.17.21' },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps);
  assert(vulns.length === 0, 'Should not find vulnerabilities for safe version');
});

test('checkVulnerabilities respects critical filter', () => {
  const deps = {
    dependencies: {
      'lodash': '4.17.15',
      'minimist': '1.2.0'
    },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps, { critical: true });
  assert(vulns.length === 1, 'Should only find critical');
  assert(vulns[0].name === 'minimist', 'Should be minimist');
});

test('checkVulnerabilities respects package filter', () => {
  const deps = {
    dependencies: {
      'lodash': '4.17.15',
      'minimist': '1.2.0'
    },
    devDependencies: {}
  };
  const vulns = checkVulnerabilities(deps, { package: 'lodash' });
  assert(vulns.length === 1, 'Should only find lodash');
  assert(vulns[0].name === 'lodash', 'Should be lodash');
});

// Test formatReport
test('formatReport returns string', () => {
  const vulns = [{ name: 'test', version: '1.0.0', severity: 'high', cve: 'CVE-2021-0000', desc: 'Test', fix: '2.0.0' }];
  const report = formatReport(vulns);
  assert(typeof report === 'string', 'Should return string');
  assert(report.includes('test'), 'Should include package name');
});

test('formatReport returns valid JSON with --json flag', () => {
  const vulns = [{ name: 'test', version: '1.0.0', severity: 'high', cve: 'CVE-2021-0000', desc: 'Test', fix: '2.0.0' }];
  const report = formatReport(vulns, { json: true });
  const parsed = JSON.parse(report);
  assert(Array.isArray(parsed), 'Should be valid JSON array');
  assert(parsed[0].name === 'test', 'Should contain vulnerability data');
});

test('formatReport shows success message when no vulnerabilities', () => {
  const report = formatReport([]);
  assert(report.includes('No known vulnerabilities'), 'Should show success message');
});

// New: JS import extraction
test('extractJsImports finds require calls', () => {
  const src = `const foo = require('lodash');\nrequire('./local.js');\nimport axios from 'axios';`;
  const out = extractJsImports(src);
  assert(out.has('lodash'), 'should find lodash');
  assert(out.has('axios'), 'should find axios');
  assert(!out.has('./local.js'), 'should skip local imports');
});

test('extractJsImports handles scoped packages', () => {
  const src = `import { x } from '@v0idd0/jsonyo/utils';`;
  const out = extractJsImports(src);
  assert(out.has('@v0idd0/jsonyo'), 'should keep scope');
});

test('extractJsImports skips node:* builtins', () => {
  const src = `import fs from 'node:fs';`;
  const out = extractJsImports(src);
  assert(!out.has('node:fs') && !out.has('fs'), 'should skip node:* specifiers');
});

// Python import extraction
test('extractPyImports finds from/import', () => {
  const src = `import requests\nfrom django.db import models\nimport os, sys`;
  const out = extractPyImports(src);
  assert(out.has('requests'), 'requests');
  assert(out.has('django'), 'django');
  assert(out.has('os'), 'os');
  assert(out.has('sys'), 'sys');
});

// compareVersions
test('compareVersions -1, 0, 1', () => {
  assert(compareVersions('1.0.0', '2.0.0') === -1);
  assert(compareVersions('2.0.0', '2.0.0') === 0);
  assert(compareVersions('3.0.0', '2.0.0') === 1);
});

// findUnusedAndMissingJs on a tiny fake project
test('findUnusedAndMissingJs detects unused + missing', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'depcheck-'));
  fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify({
    name: 'fake', dependencies: { axios: '^1.0.0', unused: '^1.0.0' }
  }));
  fs.writeFileSync(path.join(tmp, 'app.js'), `const axios = require('axios');\nconst moment = require('moment');`);
  const r = findUnusedAndMissingJs(tmp);
  assert(r.unused.includes('unused'), 'unused should flag "unused"');
  assert(r.missing.includes('moment'), 'missing should flag "moment"');
  fs.rmSync(tmp, { recursive: true, force: true });
});

// KNOWN_VULNS size
test('KNOWN_VULNS has >40 entries', () => {
  const size = Object.keys(KNOWN_VULNS).length;
  assert(size >= 40, `expected >=40, got ${size}`);
});

// checkVulnerabilities accepts lockfile-style array
test('checkVulnerabilities accepts array of {name, version}', () => {
  const vulns = checkVulnerabilities([
    { name: 'lodash', version: '4.17.15' },
    { name: 'ejs', version: '3.0.0' },
  ]);
  assert(vulns.length >= 2, 'should find vulns in array form');
});

console.log('\n' + passed + '/' + (passed + failed) + ' tests passed\n');

if (failed > 0) process.exit(1);
