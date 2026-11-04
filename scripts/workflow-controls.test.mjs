import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const workflowDir = join(root, '.github', 'workflows');
const read = (name) => readFileSync(join(workflowDir, name), 'utf8');

test('every third-party action is pinned to a full commit', () => {
  const violations = [];
  for (const name of readdirSync(workflowDir).filter((entry) => /\.ya?ml$/.test(entry))) {
    for (const match of read(name).matchAll(/^\s*-?\s*uses:\s*([^\s#]+)/gm)) {
      const reference = match[1];
      if (reference.startsWith('./')) continue;
      if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/.test(reference)) {
        violations.push(`${name}: ${reference}`);
      }
    }
  }
  assert.deepEqual(violations, []);
});

test('source-running jobs have read-only repository authority', () => {
  const browser = read('browser-gate.yml');
  const ci = read('ci.yml');
  const pages = read('pages.yml');
  const pagesPreamble = pages.slice(0, pages.indexOf('\njobs:'));
  const deployJob = pages.slice(pages.indexOf('\n  deploy:'));

  assert.match(browser, /permissions:\n {2}contents: read/);
  assert.match(ci, /permissions:\n {2}contents: read/);
  assert.match(pagesPreamble, /permissions:\n {2}contents: read/);
  assert.doesNotMatch(pagesPreamble, /pages:\s*write|id-token:\s*write/);
  assert.match(deployJob, /permissions:\n {6}pages: write\n {6}id-token: write/);
  assert.doesNotMatch(deployJob, /actions\/checkout|npm\s/);
});

test('Pages never deploys from pull requests or cancels main publication', () => {
  const pages = read('pages.yml');
  const trigger = pages.slice(0, pages.indexOf('\npermissions:'));
  assert.doesNotMatch(trigger, /pull_request/);
  assert.match(pages, /concurrency:[\s\S]*cancel-in-progress: false/);
});

test('CI tests supported Node majors from the exact lockfile', () => {
  const ci = read('ci.yml');
  const browser = read('browser-gate.yml');
  assert.match(ci, /node:\s*\[22, 24, 26\]/);
  for (const source of [ci, browser]) {
    assert.match(source, /npm ci/);
    assert.match(source, /npm audit --audit-level=high/);
    assert.doesNotMatch(source, /npm install(?:\s|$)/);
  }
});

test('pull requests and Pages call the same complete browser gate', () => {
  const ci = read('ci.yml');
  const pages = read('pages.yml');
  const browser = read('browser-gate.yml');
  assert.match(ci, /uses: \.\/\.github\/workflows\/browser-gate\.yml/);
  assert.match(pages, /uses: \.\/\.github\/workflows\/browser-gate\.yml/);
  assert.match(browser, /run: npm run test:e2e/);
  assert.match(browser, /run: npm run test:mutations/);
  assert.match(browser, /mutation-evidence\.json/);
  assert.match(browser, /if: inputs\.upload_pages_artifact/);
});

test('Dependabot leaves majors open and fails closed', () => {
  const ci = read('ci.yml');
  assert.match(ci, /update-type == 'version-update:semver-major'/);
  assert.match(ci, /update-type == 'version-update:semver-minor'/);
  assert.match(ci, /update-type == 'version-update:semver-patch'/);
  assert.match(ci, /if \[ "\$merged" != true \]; then[\s\S]*exit 1/);
  // `gh workflow run` must start its own line so the fleet's dispatch census
  // can see it, and must still fail the job rather than warn.
  assert.match(ci, /\n\s*gh workflow run pages\.yml[^\n]*\\\n\s*\|\| \{[^}]*exit 1; \}/);

  // The paragraph saying WHY that dispatch exists has to travel with it: a
  // merge made with GITHUB_TOKEN raises no push event, so the dispatch is the
  // only thing that ships a self-merged bump. Splitting pages.yml into
  // ci.yml + browser-gate.yml moved the line and left the paragraph behind.
  const dispatchAt = ci.indexOf('gh workflow run pages.yml');
  const preceding = ci.slice(0, dispatchAt).split('\n');
  preceding.pop();
  const commentRun = [];
  while (preceding.length > 0 && /^\s*#/.test(preceding[preceding.length - 1])) commentRun.unshift(preceding.pop());
  const block = commentRun.join('\n');
  assert.match(block, /raises no push event/, 'the rationale must sit directly above the dispatch');
  assert.match(block, /is the same gate-then-deploy pipeline/, 'including its closing claim');
  assert.doesNotMatch(ci, /::warning::|exit 0/);
});
