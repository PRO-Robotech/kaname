// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// Pure security-policy source tests; importing the runner cannot start its CLI.
const test = require('node:test');
const assert = require('node:assert/strict');
const {clientSecretNames, requestPolicy, allowedRequest} = require('./run-rid-native.cjs');
const id = 'registry-installation-rid01-EXPIRED-KEY-REFUSAL';
const leaf = id + ' :: expired-standing-key-token-refusal';
const normal = id + ' :: same-ordinary-O';
const raw = {caseId:id,requestName:leaf,method:'POST',path:'/iam/v1/token',origin:'https://localhost:9096'};
const variables = {jwtRIDOperator:'O',rid01ClientAssertion:'assertion',rid01IssuanceOrigin:raw.origin};
for (const [name,caseId,vars,want] of [
 ['operator-default','registry-installation-rid08-EMPTY-N0',{jwtRIDOperator:'O'},true],
 ['RID10-owner-regression','registry-installation-rid10-FAULT-PARTIAL',{jwtRIDOperator:'O',jwtRIDCreator:'C'},true],
 ['RID10-missing-owner','registry-installation-rid10-FAULT-PARTIAL',{jwtRIDOperator:'O'},false],
 ['expired-C-exact','registry-installation-rid01-EXPIRED-ACCESS-TOKEN',{jwtRIDOperator:'O',jwtRIDExpiredCreator:'oldC'},true],
 ['renewed-C-exact','registry-installation-rid01-RENEWAL-AFTER',{jwtRIDOperator:'O',jwtRIDCreator:'C'},true],
 ['assertion-exact',id,variables,true],
 ['assertion-missing',id,{jwtRIDOperator:'O'},false],
 ['assertion-out-of-phase','registry-installation-rid01-CLEAN-BEFORE',{jwtRIDOperator:'O',rid01ClientAssertion:'x'},false],
 ['old-C-out-of-phase','registry-installation-rid01-RENEWAL-AFTER',{jwtRIDOperator:'O',jwtRIDCreator:'C',jwtRIDExpiredCreator:'x'},false],
 ['unknown-actor',id,{...variables,jwtRIDOther:'x'},false],
 ['oversized-assertion',id,{...variables,rid01ClientAssertion:'x'.repeat(16385)},false],
 ['wrong-assertion-type',id,{...variables,rid01ClientAssertion:1},false],
]) test('secret/'+name,()=>{const stem=caseId.match(/^registry-installation-rid\d\d/)[0];if(want)assert.ok(clientSecretNames(stem,caseId,vars));else assert.throws(()=>clientSecretNames(stem,caseId,vars));});
for (const [name,publicURL,p,vars,want] of [
 ['primary-pair','https://localhost:9098',raw,variables,true],
 ['second-pair','https://127.0.0.1:9198',{...raw,origin:'https://127.0.0.1:9196'},{...variables,rid01IssuanceOrigin:'https://127.0.0.1:9196'},true],
 ['missing-policy','https://localhost:9098',null,variables,false],
 ['extra-key','https://localhost:9098',{...raw,extra:'x'},variables,false],
 ['wrong-phase','https://localhost:9098',{...raw,caseId:'registry-installation-rid01-VALID-KEY-TWIN'},variables,false],
 ['wrong-leaf','https://localhost:9098',{...raw,requestName:normal},variables,false],
 ['wrong-method','https://localhost:9098',{...raw,method:'GET'},variables,false],
 ['wrong-path','https://localhost:9098',{...raw,path:'/iam/v1/me'},variables,false],
 ['wrong-pair','https://localhost:9198',raw,variables,false],
 ['credentials','https://localhost:9098',{...raw,origin:'https://x:y@localhost:9096'},variables,false],
 ['query','https://localhost:9098',{...raw,origin:'https://localhost:9096?q=1'},variables,false],
 ['fragment','https://localhost:9098',{...raw,origin:'https://localhost:9096#x'},variables,false],
 ['nonloopback','https://example.com:9098',raw,variables,false],
 ['admin-public','https://localhost:9097',raw,variables,false],
 ['variable-forgery','https://localhost:9098',raw,{...variables,rid01IssuanceOrigin:'https://localhost:9097'},false],
]) test('policy/'+name,()=>{if(want)assert.ok(requestPolicy(id,publicURL,p,vars));else assert.throws(()=>requestPolicy(id,publicURL,p,vars));});
const policy = requestPolicy(id,'https://localhost:9098',raw,variables);
for (const [name,item,method,url,want] of [
 ['token-exact',leaf,'POST','https://localhost:9096/iam/v1/token',true],
 ['normal-public',normal,'GET','https://localhost:9098/iam/v1/accounts?pageSize=2',true],
 ['token-no-public-fallback',leaf,'POST','https://localhost:9098/iam/v1/token',false],
 ['wrong-leaf-issuance',normal,'POST','https://localhost:9096/iam/v1/token',false],
 ['wrong-method',leaf,'GET','https://localhost:9096/iam/v1/token',false],
 ['wrong-path',leaf,'POST','https://localhost:9096/iam/v1/me',false],
 ['token-query',leaf,'POST','https://localhost:9096/iam/v1/token?x=1',false],
 ['token-empty-query',leaf,'POST','https://localhost:9096/iam/v1/token?',false],
 ['token-fragment',leaf,'POST','https://localhost:9096/iam/v1/token#x',false],
 ['credentials',leaf,'POST','https://x:y@localhost:9096/iam/v1/token',false],
 ['wrong-port',leaf,'POST','https://localhost:9097/iam/v1/token',false],
 ['unknown-leaf','unknown','GET','https://localhost:9098/iam/v1/me',false],
]) test('request/'+name,()=>assert.equal(allowedRequest(policy,[leaf,normal],item,method,url),want));
test('default-no-issuance',()=>{const p=requestPolicy('registry-installation-rid10-FAULT-PARTIAL','https://localhost:9098',null,{});assert.equal(allowedRequest(p,[normal],normal,'GET','https://localhost:9098/iam/v1/me'),true);assert.equal(allowedRequest(p,[normal],normal,'POST','https://localhost:9096/iam/v1/token'),false);});

for (const [name,publicURL,token,want] of [
 ['default-dynamic-port','https://localhost:43217',false,true],
 ['token-dynamic-port-rejected','https://localhost:43217',true,false],
 ['origin-without-port-rejected','https://localhost',false,false],
 ['explicit-default443-rejected','https://localhost:443',false,false],
 ['port-leading-zero-rejected','https://localhost:043217',false,false],
 ['port-overflow-rejected','https://localhost:65536',false,false],
]) test('dynamic-origin/'+name,()=>{
 const caseID=token?id:'registry-installation-rid08-EMPTY-N0';
 const run=()=>requestPolicy(caseID,publicURL,token?raw:null,token?variables:{});
 if(want){const p=run();assert.equal(allowedRequest(p,[normal],normal,'GET',publicURL+'/iam/v1/me'),true);assert.equal(allowedRequest(p,[normal],normal,'GET','https://localhost:43218/iam/v1/me'),false);}
 else assert.throws(run);
});

// RID03 source census and closed actor policy; prior policy controls unchanged.
const rid03LiteralCases=[
  "registry-installation-rid03-S1-GRANT-ACT",
  "registry-installation-rid03-S1-GRANT-VERIFY",
  "registry-installation-rid03-S1-ROLE-DENIED-ACT",
  "registry-installation-rid03-S1-ROLE-DENIED-VERIFY",
  "registry-installation-rid03-S1-ROLE-TWIN-ACT",
  "registry-installation-rid03-S1-ROLE-TWIN-VERIFY",
  "registry-installation-rid03-S1-TARGET-DENIED-ACT",
  "registry-installation-rid03-S1-TARGET-DENIED-VERIFY",
  "registry-installation-rid03-S1-TARGET-TWIN-ACT",
  "registry-installation-rid03-S1-TARGET-TWIN-VERIFY",
  "registry-installation-rid03-S1-SUBJECT-DENIED-ACT",
  "registry-installation-rid03-S1-SUBJECT-DENIED-VERIFY",
  "registry-installation-rid03-S1-SUBJECT-TWIN-ACT",
  "registry-installation-rid03-S1-SUBJECT-TWIN-VERIFY",
  "registry-installation-rid03-S1-ISSUER-GD-DENIED-ACT",
  "registry-installation-rid03-S1-ISSUER-GD-DENIED-VERIFY",
  "registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT",
  "registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY",
  "registry-installation-rid03-S1-AUTHENTICATED-DENIED-ACT",
  "registry-installation-rid03-S1-AUTHENTICATED-DENIED-VERIFY",
  "registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT",
  "registry-installation-rid03-S1-ANONYMOUS-TWIN-VERIFY",
  "registry-installation-rid03-S2-GRANT-ACT",
  "registry-installation-rid03-S2-GRANT-VERIFY",
  "registry-installation-rid03-S2-ROLE-DENIED-ACT",
  "registry-installation-rid03-S2-ROLE-DENIED-VERIFY",
  "registry-installation-rid03-S2-ROLE-TWIN-ACT",
  "registry-installation-rid03-S2-ROLE-TWIN-VERIFY",
  "registry-installation-rid03-S2-TARGET-DENIED-ACT",
  "registry-installation-rid03-S2-TARGET-DENIED-VERIFY",
  "registry-installation-rid03-S2-TARGET-TWIN-ACT",
  "registry-installation-rid03-S2-TARGET-TWIN-VERIFY",
  "registry-installation-rid03-S2-SUBJECT-DENIED-ACT",
  "registry-installation-rid03-S2-SUBJECT-DENIED-VERIFY",
  "registry-installation-rid03-S2-SUBJECT-TWIN-ACT",
  "registry-installation-rid03-S2-SUBJECT-TWIN-VERIFY",
  "registry-installation-rid03-S2-ISSUER-GD-DENIED-ACT",
  "registry-installation-rid03-S2-ISSUER-GD-DENIED-VERIFY",
  "registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT",
  "registry-installation-rid03-S2-CREATOR-GD-TWIN-VERIFY",
  "registry-installation-rid03-S2-AUTHENTICATED-DENIED-ACT",
  "registry-installation-rid03-S2-AUTHENTICATED-DENIED-VERIFY",
  "registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT",
  "registry-installation-rid03-S2-ANONYMOUS-TWIN-VERIFY"
];
for (const caseId of rid03LiteralCases) test('secret/RID03-literal/'+caseId,()=>{
 const vars={jwtRIDOperator:'O'};
 const want=['jwtRIDOperator'];
 if(caseId.endsWith('-ACT')){const actor=caseId.includes('-CREATOR-GD-TWIN-')?'jwtRIDCreator':'jwtRIDIssuer';vars[actor]='actual-dummy';want.push(actor);}
 assert.deepEqual(clientSecretNames('registry-installation-rid03',caseId,vars),want);
});
for(const [name,caseId,vars] of [
 ['I-missing','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O'}],
 ['I-empty','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:''}],
 ['I-type','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:1}],
 ['I-oversize','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'x'.repeat(16385)}],
 ['C-on-I-ACT','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',jwtRIDCreator:'C'}],
 ['I-on-C-ACT','registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['I-on-VERIFY','registry-installation-rid03-S1-GRANT-VERIFY',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['C-on-VERIFY','registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY',{jwtRIDOperator:'O',jwtRIDCreator:'C'}],
 ['I-outside-RID03','registry-installation-rid08-EMPTY-N0',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['unknown-phase','registry-installation-rid03-S1-GRANT-AFTER',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['unknown-mode','registry-installation-rid03-S3-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['assertion-on-I-ACT','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',rid01ClientAssertion:'assertion'}],
])test('secret/RID03-negative/'+name,()=>assert.throws(()=>clientSecretNames(caseId.match(/^registry-installation-rid\d\d/)[0],caseId,vars)));
