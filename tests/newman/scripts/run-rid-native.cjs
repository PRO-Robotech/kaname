// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// This client runs a generated, reviewed RID collection against a live fixture.
// Only the sanitized actual execution census goes to stdout; no reporters,
// response bodies, request headers, environment exports or arbitrary errors.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const digest = (b) => crypto.createHash('sha256').update(b).digest('hex');
const fail = (kind) => {
  process.stdout.write(JSON.stringify({schemaVersion: 1, ok: false, kind}) + '\n');
  process.exitCode = 1;
};
// Canonical v1 records: kind TAB relative ASCII path TAB octal mode TAB
// digest/resolved-relative-target/- LF; byte-sort complete records. Bounded
// traversal includes all install/dependency files, directories and internal links.
function toolTree(root) {
  root = fs.realpathSync(root);
  let count = 0, bytes = 0, files = 0;
  const entries = [], regular = new Set();
  const safe = (s) => s.length <= 4096 && /^[\x20-\x7e]+$/.test(s);
  function visit(dir, depth) {
    if (depth > 128) throw new Error('tree-depth');
    const handle = fs.opendirSync(dir);
    try {
      let entry;
      while ((entry = handle.readSync()) !== null) {
        if (++count > 32768) throw new Error('tree-count');
        const absolute = path.join(dir, entry.name), relative = path.relative(root, absolute);
        if (!safe(relative)) throw new Error('tree-path');
        const stat = fs.lstatSync(absolute), mode = (stat.mode & 0o777).toString(8).padStart(3, '0');
        let kind, value;
        if (stat.isSymbolicLink()) {
          value = path.relative(root, fs.realpathSync(absolute));
          if (value === '..' || value.startsWith('../') || path.isAbsolute(value) || !safe(value)) throw new Error('tree-link');
          kind = 'S';
        } else if (stat.isDirectory()) { kind = 'D'; value = '-'; }
        else if (stat.isFile()) {
          if (stat.size > 32 * 1048576 || (bytes += stat.size) > 256 * 1048576) throw new Error('tree-bytes');
          const fd = fs.openSync(absolute, 'r');
          const hash = crypto.createHash('sha256'), buffer = Buffer.alloc(65536);
          let seen = 0;
          try { let got; while ((got = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
            seen += got; if (seen > 32 * 1048576) throw new Error('tree-file'); hash.update(buffer.subarray(0, got));
          }} finally { fs.closeSync(fd); }
          if (seen !== stat.size) throw new Error('tree-drift');
          kind = 'F'; value = hash.digest('hex'); files++; regular.add(absolute);
        } else throw new Error('tree-special');
        entries.push(kind + '\t' + relative + '\t' + mode + '\t' + value + '\n');
        if (kind === 'D') visit(absolute, depth + 1);
      }
    } finally { handle.closeSync(); }
  }
  visit(root, 0);
  if (!files) throw new Error('tree-empty');
  entries.sort();
  return {sha256: digest(Buffer.from(entries.join(''))), files, bytes, regular, root};
}
function assertCache(tree) {
  const runner = fs.realpathSync(__filename);
  for (const file of Object.keys(require.cache)) {
    const actual = fs.realpathSync(file);
    if (actual !== runner && !tree.regular.has(actual)) throw new Error('unattested-require-cache');
  }
}
const expiredKeyCase = 'registry-installation-rid01-EXPIRED-KEY-REFUSAL';
const rid01Cases = new Set(['CLEAN-BEFORE','CLEAN-INSTALLED','S1-EXACT-IDENTITIES','RENEWAL-BEFORE',
  'EXPIRED-ACCESS-TOKEN','RENEWAL-AFTER','EXPIRED-KEY-REFUSAL','VALID-KEY-TWIN']
  .map(x => 'registry-installation-rid01-' + x));
function clientSecretNames(stem, caseId, variables) {
  if (!caseId.startsWith(stem + '-') || caseId.length === stem.length + 1 ||
      !variables || typeof variables !== 'object' || Array.isArray(variables)) throw new Error('invalid-secret-policy');
  const names = ['jwtRIDOperator'];
  if (stem === 'registry-installation-rid10') names.push('jwtRIDCreator');
  if (stem === 'registry-installation-rid01') {
    if (!rid01Cases.has(caseId)) throw new Error('invalid-secret-policy');
    if (caseId === 'registry-installation-rid01-EXPIRED-ACCESS-TOKEN') names.push('jwtRIDExpiredCreator');
    if (caseId === 'registry-installation-rid01-RENEWAL-AFTER') names.push('jwtRIDCreator');
    if (caseId === expiredKeyCase) names.push('rid01ClientAssertion');
  }
  if (Object.keys(variables).some(k => ((k.startsWith('jwtRID') || k === 'rid01ClientAssertion') && !names.includes(k)) ||
      (k === 'rid01IssuanceOrigin' && caseId !== expiredKeyCase)) ||
      names.some(k => typeof variables[k] !== 'string' || !variables[k] || Buffer.byteLength(variables[k],'utf8') > 16384)) {
    throw new Error('invalid-secret-policy');
  }
  return names;
}
function ownedOrigin(raw) {
  if (typeof raw !== 'string') throw new Error('invalid-origin');
  const u = new URL(raw);
  if (u.protocol !== 'https:' || !['localhost','127.0.0.1'].includes(u.hostname) ||
      u.username || u.password || u.pathname !== '/' || u.search || u.hash || !u.port ||
      (raw !== u.origin && raw !== u.origin + '/')) throw new Error('invalid-origin');
  return u;
}
function requestPolicy(caseId, publicRaw, policy, variables) {
  const publicURL = ownedOrigin(publicRaw);
  if (caseId !== expiredKeyCase) {
    if (policy != null || Object.hasOwn(variables,'rid01IssuanceOrigin')) throw new Error('unexpected-policy');
    return {publicOrigin:publicURL.origin, token:null};
  }
  if (!['9098','9198'].includes(publicURL.port)) throw new Error('invalid-public-policy');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy) ||
      Object.keys(policy).sort().join(',') !== 'caseId,method,origin,path,requestName' ||
      policy.caseId !== caseId || policy.requestName !== caseId + ' :: expired-standing-key-token-refusal' ||
      policy.method !== 'POST' || policy.path !== '/iam/v1/token') throw new Error('invalid-token-policy');
  const tokenURL = ownedOrigin(policy.origin);
  if (policy.origin !== tokenURL.origin || tokenURL.hostname !== publicURL.hostname ||
      tokenURL.port !== (publicURL.port === '9098' ? '9096' : '9196') ||
      variables.rid01IssuanceOrigin !== tokenURL.origin) throw new Error('invalid-token-origin');
  return {publicOrigin:publicURL.origin, token:{...policy}};
}
// Shared by BEFORE-network admission and actual-execution receipt validation.
function allowedRequest(policy, names, name, method, rawURL) {
  try {
    if (!names.includes(name)) return false;
    const u = new URL(rawURL);
    if (u.username || u.password || u.hash) return false;
    if (policy.token && name === policy.token.requestName) {
      return method === policy.token.method && rawURL === policy.token.origin + policy.token.path;
    }
    return u.origin === policy.publicOrigin;
  } catch (_) { return false; }
}
// beforeRequest fires synchronously before runtime creates its HTTP requester.
// A mere exitCode or async stdout write would leave the outgoing request alive.
function stopBeforeNetwork() {
  try { fs.writeSync(1, '{"schemaVersion":1,"ok":false,"kind":"request-policy-denied-before-network"}\n'); }
  finally { process.exit(1); }
}
async function main() {
  // Await parent admission before ANY early validation/exit or HTTP request.
  let chunks = [], length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > 1048576) { fail('bounded-input-exceeded'); return; }
    chunks.push(chunk);
  }
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  chunks = null;
  const [collectionPath, packagePath, caPath, certPath, keyPath, caseId] = process.argv.slice(2);
  if (!collectionPath || !packagePath || !caPath || !certPath || !keyPath ||
      !/^registry-installation-rid(?:0[1-9]|1[012])-[A-Z0-9-]+$/.test(caseId || '')) {
    fail('invalid-static-run-input'); return;
  }
  const stem = caseId.match(/^registry-installation-rid\d\d/)[0];
  if (!path.isAbsolute(collectionPath) ||
      path.basename(collectionPath) !== stem + '.postman_collection.json' ||
      !path.isAbsolute(packagePath) || !path.isAbsolute(caPath) ||
      !path.isAbsolute(certPath) || !path.isAbsolute(keyPath)) {
    fail('invalid-source-paths'); return;
  }
  const beforeTree = toolTree(packagePath);
  const nodeSHA256 = digest(fs.readFileSync(process.execPath));
  const runnerSHA256 = digest(fs.readFileSync(__filename));
  const expected = input.expectedIdentities;
  if (!expected || Object.keys(expected).sort().join(',') !== 'collectionSHA256,nodeSHA256,runnerSHA256,testExecutableSHA256,toolTreeSHA256' ||
      Object.values(expected).some((s) => !/^[a-f0-9]{64}$/.test(s)) ||
      expected.nodeSHA256 !== nodeSHA256 || expected.runnerSHA256 !== runnerSHA256 ||
      expected.toolTreeSHA256 !== beforeTree.sha256 || expected.testExecutableSHA256 !== input.testExecutableSHA256) {
    fail('external-tool-identities-mismatch'); return;
  }
  const packageBytes = fs.readFileSync(path.join(packagePath, 'package.json'));
  const pkg = JSON.parse(packageBytes);
  if (pkg.name !== 'newman' || pkg.version !== '6.2.2') {
    fail('unexpected-newman-version'); return;
  }
  const collectionBytes = fs.readFileSync(collectionPath);
  if (digest(collectionBytes) !== expected.collectionSHA256) { fail('external-collection-identity-mismatch'); return; }
  const collection = JSON.parse(collectionBytes);
  const folders = collection.item.filter((x) => x.name.startsWith(caseId + ' — '));
  if (folders.length !== 1) { fail('case-folder-missing-or-ambiguous'); return; }
  const folder = folders[0];
  const leafItems = [];
  const visit = (items) => items.forEach((x) => {
    if (x.request) leafItems.push(x);
    else visit(x.item || []);
  });
  visit(folder.item || []);
  const names = leafItems.map((x) => x.name);
  const allLeaves = [];
  const allVisit = (items) => items.forEach((x) => {
    if (x.request) allLeaves.push(x); else allVisit(x.item || []);
  });
  allVisit(collection.item || []);
  const allNames = allLeaves.map((x) => x.name);
  if (!names.length || new Set(names).size !== names.length ||
      new Set(allNames).size !== allNames.length) {
    fail('empty-or-ambiguous-declared-request-census'); return;
  }
  let origin, policy;
  try {
    clientSecretNames(stem, caseId, input.variables);
    origin = ownedOrigin(input.ownRestBaseUrl);
    policy = requestPolicy(caseId, input.ownRestBaseUrl, input.requestPolicy, input.variables);
    if (policy.token && !names.includes(policy.token.requestName)) throw new Error('missing-token-leaf');
  } catch (_) { fail('invalid-owned-request-or-secret-policy'); return; }
  const reserved = new Set(['ownRestBaseUrl', 'baseUrl', '__proto__', 'prototype', 'constructor']);
  if (Array.isArray(input.variables) ||
      Object.keys(input.variables).some((key) => reserved.has(key)) ||
      !/^[A-Za-z0-9-]{16,80}$/.test(input.runId || '') ||
      !/^[a-f0-9]{64}$/.test(input.testExecutableSHA256 || '')) {
    fail('invalid-owned-producer-input'); return;
  }
  const variables = Object.entries(input.variables).map(([key,value]) => ({
    key, value: typeof value === 'string' ? value : JSON.stringify(value),
    type: 'text', enabled: true,
  }));
  variables.push({key: 'ownRestBaseUrl', value: origin.origin, enabled: true});
  // The shared generator still emits baseUrl placeholders before its own-front
  // pre-request routing. A distinct sentinel proves requests use the named front.
  variables.push({key: 'baseUrl', value: 'https://unused.invalid', enabled: true});
  const newman = require(packagePath);
  assertCache(beforeTree);
  const options = {
    collection, folder: folder.name,
    environment: {name: 'private-live-rid-input', values: variables},
    reporters: [], insecure: false, sslExtraCaCerts: caPath,
    sslClientCert: certPath, sslClientKey: keyPath,
    ignoreRedirects: true, timeout: 90000, timeoutRequest: 5000,
    timeoutScript: 3000, iterationCount: 1, bail: false,
  };
  newman.run(options, (error, summary) => {
    try {
      if (!summary || !summary.run) { fail('newman-no-actual-summary'); return; }
      const observed = new Set(), executions = [];
      let requests = 0, unanswered = 0, assertions = 0, failed = 0, skipped = 0;
      let wrongOrigin = 0, unexpectedItems = 0;
      for (const ex of summary.run.executions || []) {
        const name = ex.item && ex.item.name;
        const known = names.includes(name);
        if (known) observed.add(name); else unexpectedItems++;
        if (ex.request) requests++;
        if (!ex.response || ex.requestError) unanswered++;
        let sameOrigin = false;
        if (ex.request && ex.request.url) {
          sameOrigin = allowedRequest(policy, names, name, ex.request.method, ex.request.url.toString());
        }
        if (!sameOrigin) wrongOrigin++;
        const results = (ex.assertions || []).map((a, index) => {
          assertions++;
          if (a.error) failed++;
          if (a.skipped) skipped++;
          // Assertion text/error messages can embed an unexpected body or token.
          return {assertion: 'assertion-' + index, skipped: !!a.skipped,
                  ...(a.error ? {error: {name: 'AssertionError',
                                        message: 'withheld; inspect exact reviewed case and step'}} : {})};
        });
        executions.push({
          item: {name: known ? name : '[unexpected-item]'},
          nativeCursor: ex.cursor ? {
            position: ex.cursor.position, length: ex.cursor.length,
            iteration: ex.cursor.iteration,
          } : null,
          sourceLeafIndex: known ? allNames.indexOf(name) : null,
          request: ex.request ? {method: ex.request.method,
                                url: {raw: '[runtime URL withheld]'}} : null,
          response: ex.response ? {code: ex.response.code} : null,
          ...(ex.requestError ? {requestError: {code: 'TRANSPORT_ERROR'}} : {}),
          assertions: results, actualExpectedOrigin: sameOrigin,
        });
      }
      const missing = names.filter((x) => !observed.has(x));
      const failureCount = (summary.run.failures || []).length;
      const stats = summary.run.stats || {};
      const emptyAssertionRequests = executions.filter((x) => !x.assertions.length).length;
      const ok = !error && requests > 0 && !unanswered && assertions > 0 &&
        !failed && !skipped && !failureCount && !wrongOrigin && !unexpectedItems &&
        !missing.length && !emptyAssertionRequests &&
        (!stats.requests || (stats.requests.failed || 0) === 0) &&
        (!stats.assertions || (stats.assertions.failed || 0) === 0);
      if (!fs.readFileSync(collectionPath).equals(collectionBytes) ||
          !fs.readFileSync(path.join(packagePath, 'package.json')).equals(packageBytes)) {
        fail('source-or-tool-input-changed-during-run'); return;
      }
      const afterTree = toolTree(packagePath);
      assertCache(afterTree);
      if (afterTree.sha256 !== beforeTree.sha256 || digest(fs.readFileSync(process.execPath)) !== nodeSHA256 ||
          digest(fs.readFileSync(__filename)) !== runnerSHA256) { fail('toolchain-changed-during-run'); return; }
      const receipt = {
        schemaVersion: 1, ok, caseId, selectedFolder: folder.name,
        producer: {runId: input.runId, testExecutableSHA256: input.testExecutableSHA256},
        collectionSHA256: digest(collectionBytes), newmanVersion: pkg.version,
        newmanPackageSHA256: digest(packageBytes), nodeSHA256, runnerSHA256,
        toolTreeSHA256: beforeTree.sha256,
        toolTree: {algorithm: 'rid-tool-tree-v1', beforeSHA256: beforeTree.sha256, afterSHA256: afterTree.sha256,
                   files: beforeTree.files, bytes: beforeTree.bytes, requireCacheAttested: true},
        caSHA256: digest(fs.readFileSync(caPath)), actualOrigin: origin.origin,
        counts: {declaredRequests: names.length, uniqueRequests: observed.size,
                 requests, unanswered, assertions, failed, skipped, failureCount,
                 wrongOrigin, unexpectedItems, missing, emptyAssertionRequests},
        // Preserve only the immutable on-disk definition, never summary.environment.
        collection: JSON.parse(collectionBytes.toString('utf8')),
        run: {stats: {requests: {total: requests, failed: unanswered},
                      assertions: {total: assertions, failed, skipped}},
              executions},
      };
      process.stdout.write(JSON.stringify(receipt) + '\n');
      process.exitCode = ok ? 0 : 1;
    } catch (_) { fail('sanitized-result-processing-failed'); }
  }).on('beforeRequest', (error, args) => {
    let allowed = false;
    try {
      allowed = !error && args && args.item && args.request && args.request.url &&
        allowedRequest(policy, names, args.item.name, args.request.method, args.request.url.toString());
    } catch (_) { /* Never emit an SDK URL/error/header/body. */ }
    if (!allowed) stopBeforeNetwork();
  });
}
module.exports = {clientSecretNames, ownedOrigin, requestPolicy, allowedRequest};
if (require.main === module) main().catch(() => fail('client-precondition-or-execution-failed'));
