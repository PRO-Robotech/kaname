// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {clientSecretNames,requestPolicy,allowedRequest}=require('./run-rid-native.cjs');
const literals={
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
};
for(const [id,actor] of Object.entries(literals)) test('RID05-literal/'+id,()=>{
 const vars={jwtRIDOperator:'O'},want=['jwtRIDOperator'];if(actor==='I'){vars.jwtRIDIssuer='I';want.push('jwtRIDIssuer');}if(actor==='A'){vars.rid05ClientAssertion='original-C-signature';want.push('rid05ClientAssertion');}
 assert.deepEqual(clientSecretNames('registry-installation-rid05',id,vars),want);
 if(actor!=='A')assert.deepEqual(requestPolicy(id,'https://localhost:22222',null,vars),{publicOrigin:'https://localhost:22222',token:null});
});
for(const [name,id,vars] of [
 ['unknown-phase','registry-installation-rid05-S1-OTHER',{jwtRIDOperator:'O'}],
 ['missing-I','registry-installation-rid05-S1-DELETED-C-GRANT-ACT',{jwtRIDOperator:'O'}],
 ['VERIFY-I','registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['C2-bearer','registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',jwtRIDCreator:'C2'}],
 ['old-C-bearer','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O',rid05ClientAssertion:'A',jwtRIDExpiredCreator:'C'}],
 ['missing-assertion','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O'}],
 ['empty-assertion','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O',rid05ClientAssertion:''}],
 ['type-assertion','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O',rid05ClientAssertion:1}],
 ['oversize-assertion','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O',rid05ClientAssertion:'x'.repeat(16385)}],
 ['READ-assertion','registry-installation-rid05-S1-DELETED-C-SNAPSHOT',{jwtRIDOperator:'O',rid05ClientAssertion:'A'}],
 ['other-assertion','registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED',{jwtRIDOperator:'O',rid05ClientAssertion:'A',rid01ClientAssertion:'A'}],
 ['READ-origin','registry-installation-rid05-S1-DELETED-C-SNAPSHOT',{jwtRIDOperator:'O',rid05IssuanceOrigin:'https://localhost:9096'}],
 ])test('RID05-secret-reject/'+name,()=>assert.throws(()=>clientSecretNames('registry-installation-rid05',id,vars)));
function base(mode='S1') {const id='registry-installation-rid05-'+mode+'-OLD-C-TOKEN-REFUSED',pub='https://localhost:'+(mode==='S1'?'9098':'9198'),origin='https://localhost:'+(mode==='S1'?'9096':'9196');return {id,pub,vars:{rid05IssuanceOrigin:origin},p:{caseId:id,requestName:id+' :: old-standing-key-token-refusal',method:'POST',path:'/iam/v1/token',origin}};}
for(const mode of ['S1','S2'])test('RID05-owned-token/'+mode,()=>{const {id,pub,vars,p}=base(mode),policy=requestPolicy(id,pub,p,vars),names=[p.requestName,'public-census'];assert.equal(allowedRequest(policy,names,p.requestName,'POST',p.origin+p.path),true);assert.equal(allowedRequest(policy,names,p.requestName,'POST',pub+p.path),false);assert.equal(allowedRequest(policy,names,'public-census','GET',pub+'/iam/v1/me'),true);assert.equal(allowedRequest(policy,names,'public-census','POST',p.origin+p.path),false);});
for(const name of ['wrong-phase','wrong-leaf','wrong-method','wrong-path','wrong-port','wrong-host','query','credentials','dynamic-public-token','other-variable','missing-variable','missing-policy','extra-policy-key'])test('RID05-origin-reject/'+name,()=>{let {id,pub,vars,p}=base();switch(name){case 'wrong-phase':id='registry-installation-rid05-S1-DELETED-C-SNAPSHOT';break;case 'wrong-leaf':p.requestName+='-other';break;case 'wrong-method':p.method='GET';break;case 'wrong-path':p.path+='/other';break;case 'wrong-port':p.origin='https://localhost:9097';vars.rid05IssuanceOrigin=p.origin;break;case 'wrong-host':p.origin='https://127.0.0.1:9096';vars.rid05IssuanceOrigin=p.origin;break;case 'query':p.origin+='?x=1';break;case 'credentials':p.origin='https://x@localhost:9096';break;case 'dynamic-public-token':pub='https://localhost:22222';break;case 'other-variable':vars.rid01IssuanceOrigin=p.origin;break;case 'missing-variable':delete vars.rid05IssuanceOrigin;break;case 'missing-policy':p=null;break;case 'extra-policy-key':p.extra=true;break;}assert.throws(()=>requestPolicy(id,pub,p,vars));});
for(const [name,method,url,nameOverride] of [
 ['wrong-method','GET','https://localhost:9096/iam/v1/token'],
 ['extra-query','POST','https://localhost:9096/iam/v1/token?x=1'],
 ['wrong-path','POST','https://localhost:9096/iam/v1/token/other'],
 ['credentials','POST','https://x@localhost:9096/iam/v1/token'],
 ['fragment','POST','https://localhost:9096/iam/v1/token#x'],
 ['wrong-leaf','POST','https://localhost:9096/iam/v1/token','public-census'],
 ])test('RID05-before-network-reject/'+name,()=>{const {id,pub,vars,p}=base();assert.equal(allowedRequest(requestPolicy(id,pub,p,vars),[p.requestName,'public-census'],nameOverride||p.requestName,method,url),false);});
for(const [name,stem,id,vars] of [
 ['03-assertion','registry-installation-rid03','registry-installation-rid03-S1-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',rid05ClientAssertion:'A'}],
 ['04-origin','registry-installation-rid04','registry-installation-rid04-S1-BEFORE-RETIREMENT',{jwtRIDOperator:'O',rid05IssuanceOrigin:'https://localhost:9096'}],
 ])test('RID05-isolation/'+name,()=>assert.throws(()=>clientSecretNames(stem,id,vars)));
