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
const rid03Actors = Object.freeze({
  "registry-installation-rid03-S1-GRANT-ACT": "I",
  "registry-installation-rid03-S1-GRANT-VERIFY": "O",
  "registry-installation-rid03-S1-ROLE-DENIED-ACT": "I",
  "registry-installation-rid03-S1-ROLE-DENIED-VERIFY": "O",
  "registry-installation-rid03-S1-ROLE-TWIN-ACT": "I",
  "registry-installation-rid03-S1-ROLE-TWIN-VERIFY": "O",
  "registry-installation-rid03-S1-TARGET-DENIED-ACT": "I",
  "registry-installation-rid03-S1-TARGET-DENIED-VERIFY": "O",
  "registry-installation-rid03-S1-TARGET-TWIN-ACT": "I",
  "registry-installation-rid03-S1-TARGET-TWIN-VERIFY": "O",
  "registry-installation-rid03-S1-SUBJECT-DENIED-ACT": "I",
  "registry-installation-rid03-S1-SUBJECT-DENIED-VERIFY": "O",
  "registry-installation-rid03-S1-SUBJECT-TWIN-ACT": "I",
  "registry-installation-rid03-S1-SUBJECT-TWIN-VERIFY": "O",
  "registry-installation-rid03-S1-ISSUER-GD-DENIED-ACT": "I",
  "registry-installation-rid03-S1-ISSUER-GD-DENIED-VERIFY": "O",
  "registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT": "C",
  "registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY": "O",
  "registry-installation-rid03-S1-AUTHENTICATED-DENIED-ACT": "I",
  "registry-installation-rid03-S1-AUTHENTICATED-DENIED-VERIFY": "O",
  "registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT": "I",
  "registry-installation-rid03-S1-ANONYMOUS-TWIN-VERIFY": "O",
  "registry-installation-rid03-S2-GRANT-ACT": "I",
  "registry-installation-rid03-S2-GRANT-VERIFY": "O",
  "registry-installation-rid03-S2-ROLE-DENIED-ACT": "I",
  "registry-installation-rid03-S2-ROLE-DENIED-VERIFY": "O",
  "registry-installation-rid03-S2-ROLE-TWIN-ACT": "I",
  "registry-installation-rid03-S2-ROLE-TWIN-VERIFY": "O",
  "registry-installation-rid03-S2-TARGET-DENIED-ACT": "I",
  "registry-installation-rid03-S2-TARGET-DENIED-VERIFY": "O",
  "registry-installation-rid03-S2-TARGET-TWIN-ACT": "I",
  "registry-installation-rid03-S2-TARGET-TWIN-VERIFY": "O",
  "registry-installation-rid03-S2-SUBJECT-DENIED-ACT": "I",
  "registry-installation-rid03-S2-SUBJECT-DENIED-VERIFY": "O",
  "registry-installation-rid03-S2-SUBJECT-TWIN-ACT": "I",
  "registry-installation-rid03-S2-SUBJECT-TWIN-VERIFY": "O",
  "registry-installation-rid03-S2-ISSUER-GD-DENIED-ACT": "I",
  "registry-installation-rid03-S2-ISSUER-GD-DENIED-VERIFY": "O",
  "registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT": "C",
  "registry-installation-rid03-S2-CREATOR-GD-TWIN-VERIFY": "O",
  "registry-installation-rid03-S2-AUTHENTICATED-DENIED-ACT": "I",
  "registry-installation-rid03-S2-AUTHENTICATED-DENIED-VERIFY": "O",
  "registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT": "I",
  "registry-installation-rid03-S2-ANONYMOUS-TWIN-VERIFY": "O"
});
const rid04Actors=Object.freeze({
  "registry-installation-rid04-S1-BEFORE-RETIREMENT": "O",
  "registry-installation-rid04-S1-RETIRED-DENIED-ACT": "I",
  "registry-installation-rid04-S1-RETIRED-DENIED-VERIFY": "O",
  "registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT": "O",
  "registry-installation-rid04-S1-RESTORED-GRANT-ACT": "I",
  "registry-installation-rid04-S1-RESTORED-GRANT-VERIFY": "O",
  "registry-installation-rid04-S1-RESTORED-REAPPLY": "O",
  "registry-installation-rid04-S2-BEFORE-RETIREMENT": "O",
  "registry-installation-rid04-S2-RETIRED-DENIED-ACT": "I",
  "registry-installation-rid04-S2-RETIRED-DENIED-VERIFY": "O",
  "registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT": "O",
  "registry-installation-rid04-S2-RESTORED-GRANT-ACT": "I",
  "registry-installation-rid04-S2-RESTORED-GRANT-VERIFY": "O",
  "registry-installation-rid04-S2-RESTORED-REAPPLY": "O"
});
const rid05Actors=Object.freeze({
  "registry-installation-rid05-S1-KEYS-AND-REFERENCES-CLEAN": "O",
  "registry-installation-rid05-S1-DELETED-C-SNAPSHOT": "O",
  "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED": "A",
  "registry-installation-rid05-S1-DELETED-C-GRANT-ACT": "I",
  "registry-installation-rid05-S1-DELETED-C-GRANT-VERIFY": "O",
  "registry-installation-rid05-S1-SAME-NAME-C2-SNAPSHOT": "O",
  "registry-installation-rid05-S1-C2-NO-REVIVAL-ACT": "I",
  "registry-installation-rid05-S1-C2-NO-REVIVAL-VERIFY": "O",
  "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT": "O",
  "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY": "O",
  "registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT": "O",
  "registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
  "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT": "I",
  "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY": "O",
  "registry-installation-rid05-S1-RECOVERY-REAPPLY": "O",
  "registry-installation-rid05-S2-KEYS-AND-REFERENCES-CLEAN": "O",
  "registry-installation-rid05-S2-DELETED-C-SNAPSHOT": "O",
  "registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED": "A",
  "registry-installation-rid05-S2-DELETED-C-GRANT-ACT": "I",
  "registry-installation-rid05-S2-DELETED-C-GRANT-VERIFY": "O",
  "registry-installation-rid05-S2-SAME-NAME-C2-SNAPSHOT": "O",
  "registry-installation-rid05-S2-C2-NO-REVIVAL-ACT": "I",
  "registry-installation-rid05-S2-C2-NO-REVIVAL-VERIFY": "O",
  "registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT": "O",
  "registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-VERIFY": "O",
  "registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT": "O",
  "registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
  "registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT": "I",
  "registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-VERIFY": "O",
  "registry-installation-rid05-S2-RECOVERY-REAPPLY": "O"
});
function issuanceCase(caseId){
 if(caseId===expiredKeyCase)return {variable:'rid01IssuanceOrigin',leaf:'expired-standing-key-token-refusal'};
 if(caseId==='registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED'||caseId==='registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED')return {variable:'rid05IssuanceOrigin',leaf:'old-standing-key-token-refusal'};
 return null;
}
const rid06Actors=Object.freeze({
  "registry-installation-rid06-S1-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S1-REVOKE-ACT": "O",
  "registry-installation-rid06-S1-AFTER-REVOKE": "O",
  "registry-installation-rid06-S1-SEQUENTIAL-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S1-SEQUENTIAL-AFTER-OVERLAP": "O",
  "registry-installation-rid06-S1-AFTER-SEQUENTIAL-REFUSAL": "O",
  "registry-installation-rid06-S1-NO-REVOKE-BEFORE": "O",
  "registry-installation-rid06-S1-NO-REVOKE-TWIN": "O",
  "registry-installation-rid06-S1-RECOVERY-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S1-RECOVERY-AFTER-REVOKE": "O",
  "registry-installation-rid06-S1-EXPLICIT-CREATE-ACT": "C",
  "registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY": "O",
  "registry-installation-rid06-S1-RECOVERY-REAPPLY": "O",
  "registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT": "I",
  "registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY": "O",
  "registry-installation-rid06-S2-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S2-REVOKE-ACT": "O",
  "registry-installation-rid06-S2-AFTER-REVOKE": "O",
  "registry-installation-rid06-S2-SEQUENTIAL-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S2-SEQUENTIAL-AFTER-OVERLAP": "O",
  "registry-installation-rid06-S2-AFTER-SEQUENTIAL-REFUSAL": "O",
  "registry-installation-rid06-S2-NO-REVOKE-BEFORE": "O",
  "registry-installation-rid06-S2-NO-REVOKE-TWIN": "O",
  "registry-installation-rid06-S2-RECOVERY-BEFORE-REVOKE": "O",
  "registry-installation-rid06-S2-RECOVERY-AFTER-REVOKE": "O",
  "registry-installation-rid06-S2-EXPLICIT-CREATE-ACT": "C",
  "registry-installation-rid06-S2-EXPLICIT-CREATE-VERIFY": "O",
  "registry-installation-rid06-S2-RECOVERY-REAPPLY": "O",
  "registry-installation-rid06-S2-EXPLICIT-RECOVERY-ACT": "I",
  "registry-installation-rid06-S2-EXPLICIT-RECOVERY-VERIFY": "O"
});
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
  if (stem === 'registry-installation-rid03') {
    if (!Object.hasOwn(rid03Actors, caseId)) throw new Error('invalid-secret-policy');
    if (rid03Actors[caseId] === 'I') names.push('jwtRIDIssuer');
    if (rid03Actors[caseId] === 'C') names.push('jwtRIDCreator');
  }
  if (stem === 'registry-installation-rid04') {
    if (!Object.hasOwn(rid04Actors,caseId)) throw new Error('invalid-secret-policy');
    if (rid04Actors[caseId] === 'I') names.push('jwtRIDIssuer');
  }
  if(stem==='registry-installation-rid05'){
    if(!Object.hasOwn(rid05Actors,caseId))throw new Error('invalid-secret-policy');
    if(rid05Actors[caseId]==='I')names.push('jwtRIDIssuer');
    if(rid05Actors[caseId]==='A')names.push('rid05ClientAssertion');
  }
  if(stem==='registry-installation-rid06'){
    if(!Object.hasOwn(rid06Actors,caseId))throw new Error('invalid-secret-policy');
    if(rid06Actors[caseId]==='I')names.push('jwtRIDIssuer');
    if(rid06Actors[caseId]==='C')names.push('jwtRIDCreator');
  }
  if (Object.keys(variables).some(k => ((k.startsWith('jwtRID') || k === 'rid01ClientAssertion' || k==='rid05ClientAssertion') && !names.includes(k)) ||
      (k === 'rid01IssuanceOrigin' && caseId !== expiredKeyCase) || (k==='rid05IssuanceOrigin' && !(issuanceCase(caseId)&&issuanceCase(caseId).variable===k))) ||
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
  const spec=issuanceCase(caseId);
  if((Object.hasOwn(variables,'rid01IssuanceOrigin')&&(!spec||spec.variable!=='rid01IssuanceOrigin')) || (Object.hasOwn(variables,'rid05IssuanceOrigin')&&(!spec||spec.variable!=='rid05IssuanceOrigin')))throw new Error('unexpected-policy');
  if (!spec) {
    if (policy != null || Object.hasOwn(variables,'rid01IssuanceOrigin') || Object.hasOwn(variables,'rid05IssuanceOrigin')) throw new Error('unexpected-policy');
    return {publicOrigin:publicURL.origin, token:null};
  }
  if (!['9098','9198'].includes(publicURL.port)) throw new Error('invalid-public-policy');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy) ||
      Object.keys(policy).sort().join(',') !== 'caseId,method,origin,path,requestName' ||
      policy.caseId !== caseId || policy.requestName !== caseId + ' :: '+spec.leaf ||
      policy.method !== 'POST' || policy.path !== '/iam/v1/token') throw new Error('invalid-token-policy');
  const tokenURL = ownedOrigin(policy.origin);
  if (policy.origin !== tokenURL.origin || tokenURL.hostname !== publicURL.hostname ||
      tokenURL.port !== (publicURL.port === '9098' ? '9096' : '9196') ||
      variables[spec.variable] !== tokenURL.origin) throw new Error('invalid-token-origin');
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
const permitFrame = 'RID_NEWMAN_PERMIT_V1\n';
function validatePermitFrame(raw, ended) {
  if (!ended || raw !== permitFrame) throw new Error('invalid-node-permit');
}
async function validatedInputACK(caseId, runId) {
  if (!fs.fstatSync(3).isFIFO() || !fs.fstatSync(4).isFIFO()) throw new Error('missing-node-protocol-pipes');
  const ack = JSON.stringify({version:1,pid:process.pid,caseId,runId}) + '\n';
  if (Buffer.byteLength(ack) > 512) throw new Error('oversized-node-ack');
  fs.writeSync(3,ack); fs.closeSync(3);
  await new Promise((resolve,reject)=>{
    let raw='',ended=false;
    const stream=fs.createReadStream(null,{fd:4,autoClose:true});
    const rejectBound = () => { try { fs.writeSync(1, '{"schemaVersion":1,"ok":false,"kind":"node-permit-rejected"}\n'); } finally { process.exit(1); } };
    const timer=setTimeout(rejectBound,15000);
    stream.on('data',chunk=>{raw+=chunk.toString('utf8');if(Buffer.byteLength(raw)>64){clearTimeout(timer);rejectBound();}});
    stream.on('end',()=>{ended=true;clearTimeout(timer);try{validatePermitFrame(raw,ended);resolve();}catch(_){reject(new Error('invalid-node-permit'));}});
    stream.on('error',()=>{clearTimeout(timer);reject(new Error('node-permit-unavailable'));});
  });
}
const rid03ObservedCases = new Set([
 'registry-installation-rid03-S1-GRANT-ACT','registry-installation-rid03-S1-ROLE-TWIN-ACT','registry-installation-rid03-S1-TARGET-TWIN-ACT','registry-installation-rid03-S1-SUBJECT-TWIN-ACT','registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT',
 'registry-installation-rid03-S2-GRANT-ACT','registry-installation-rid03-S2-ROLE-TWIN-ACT','registry-installation-rid03-S2-TARGET-TWIN-ACT','registry-installation-rid03-S2-SUBJECT-TWIN-ACT','registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT',
]);
function rid03GetObservation(caseId, executions, starts, ends) {
 if (!rid03ObservedCases.has(caseId)) {
  if (starts.length || ends.length) throw new Error('invalid-act-get-observation');
  return null;
 }
 const name=caseId+' :: actual-action-resource-Get';
 const rows=executions.filter(x=>x.item && x.item.name===name);
 if(rows.length!==1 || starts.length!==1 || ends.length!==1) throw new Error('invalid-act-get-observation');
 const ex=rows[0];
 if(!ex.request || ex.request.method!=='GET' || !ex.response || ex.response.code!==200 || ex.requestError ||
    !(ex.assertions||[]).length || ex.assertions.some(x=>x.error||x.skipped)) throw new Error('invalid-act-get-observation');
 const j=ex.response.json(), target=j.target && j.target.resources && j.target.resources.resources;
 const id=/^[A-Za-z0-9_-]{1,128}$/;
 if(!Array.isArray(target)||target.length!==1 || ![j.id,j.delegationId,j.subjectId,j.roleId,j.scopeId,target[0].id].every(x=>typeof x==='string'&&id.test(x)) ||
    !['service_account','system_class'].includes(j.subjectType) || j.scopeType!=='iam.account' || target[0].type!=='registry.registries') throw new Error('invalid-act-get-observation');
 const url=new URL(ex.request.url.toString());
 const mat=Date.parse(j.materializedAt),created=Date.parse(j.createdAt),start=starts[0],end=ends[0];
 if(url.pathname!=='/iam/v1/accessBindings/'+j.id || url.search || url.hash ||
    typeof j.materializedAt!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(j.materializedAt) ||
    typeof j.createdAt!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(j.createdAt) ||
    ![mat,created,start,end].every(Number.isFinite) || mat<created || mat>end || end<start || end-start>5000) throw new Error('invalid-act-get-observation');
 return {version:1,caseId,requestName:name,method:'GET',path:url.pathname,resourceId:j.id,materializedAt:j.materializedAt,createdAt:j.createdAt,
         delegationId:j.delegationId,subjectType:j.subjectType,subjectId:j.subjectId,roleId:j.roleId,scopeType:j.scopeType,scopeId:j.scopeId,
         targetType:target[0].type,targetId:target[0].id,startedAt:new Date(start).toISOString(),completedAt:new Date(end).toISOString()};
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
  try { await validatedInputACK(caseId,input.runId); } catch (_) { fail('node-permit-rejected'); return; }
  const options = {
    collection, folder: folder.name,
    environment: {name: 'private-live-rid-input', values: variables},
    reporters: [], insecure: false, sslExtraCaCerts: caPath,
    sslClientCert: certPath, sslClientKey: keyPath,
    ignoreRedirects: true, timeout: 90000, timeoutRequest: 5000,
    timeoutScript: 3000, iterationCount: 1, bail: false,
  };
  const rid03Starts=[],rid03Ends=[];
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
      const actGet=rid03GetObservation(caseId,summary.run.executions||[],rid03Starts,rid03Ends);
      const receipt = {
        ...(actGet ? {rid03ActGet:actGet} : {}),
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
    if(rid03ObservedCases.has(caseId) && args.item.name===caseId+' :: actual-action-resource-Get')rid03Starts.push(Date.now());
  }).on('request', (error,args)=>{
    if(rid03ObservedCases.has(caseId) && args && args.item && args.item.name===caseId+' :: actual-action-resource-Get')rid03Ends.push(Date.now());
  });
}
module.exports = {clientSecretNames, ownedOrigin, requestPolicy, allowedRequest, validatePermitFrame, rid03GetObservation};
if (require.main === module) main().catch(() => fail('client-precondition-or-execution-failed'));
