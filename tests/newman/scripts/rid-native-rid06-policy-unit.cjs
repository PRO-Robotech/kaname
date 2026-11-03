// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {clientSecretNames,requestPolicy,allowedRequest}=require('./run-rid-native.cjs');
const literalActors={
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
};
for(const [id,actor]of Object.entries(literalActors))test('RID06-literal/'+id,()=>{const v={jwtRIDOperator:'O'},want=['jwtRIDOperator'];if(actor==='I'){v.jwtRIDIssuer='I';want.push('jwtRIDIssuer');}if(actor==='C'){v.jwtRIDCreator='C';want.push('jwtRIDCreator');}assert.deepEqual(clientSecretNames('registry-installation-rid06',id,v),want);const p=requestPolicy(id,'https://localhost:22222',null,v);assert.equal(allowedRequest(p,['action'],'action','POST','https://localhost:22222/iam/v1/grantDelegations'),true);assert.equal(allowedRequest(p,['action'],'action','POST','https://localhost:9096/iam/v1/token'),false);});
for(const [name,id,v]of [
['unknown-phase','registry-installation-rid06-S1-OTHER',{jwtRIDOperator:'O'}],
['missing-C','registry-installation-rid06-S1-EXPLICIT-CREATE-ACT',{jwtRIDOperator:'O'}],
['missing-I','registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT',{jwtRIDOperator:'O'}],
['empty-C','registry-installation-rid06-S1-EXPLICIT-CREATE-ACT',{jwtRIDOperator:'O',jwtRIDCreator:''}],
['type-I','registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:1}],
['oversize-I','registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'x'.repeat(16385)}],
['VERIFY-C','registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY',{jwtRIDOperator:'O',jwtRIDCreator:'C'}],
['VERIFY-I','registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
['READ-I','registry-installation-rid06-S1-NO-REVOKE-TWIN',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
['revoke-I','registry-installation-rid06-S1-REVOKE-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
['mixed-C-I','registry-installation-rid06-S1-EXPLICIT-CREATE-ACT',{jwtRIDOperator:'O',jwtRIDCreator:'C',jwtRIDIssuer:'I'}],
['assertion01','registry-installation-rid06-S1-REVOKE-ACT',{jwtRIDOperator:'O',rid01ClientAssertion:'A'}],
['assertion05','registry-installation-rid06-S1-REVOKE-ACT',{jwtRIDOperator:'O',rid05ClientAssertion:'A'}],
['issuance01','registry-installation-rid06-S1-REVOKE-ACT',{jwtRIDOperator:'O',rid01IssuanceOrigin:'https://localhost:9096'}],
['issuance05','registry-installation-rid06-S1-REVOKE-ACT',{jwtRIDOperator:'O',rid05IssuanceOrigin:'https://localhost:9096'}],
])test('RID06-secret-reject/'+name,()=>assert.throws(()=>clientSecretNames('registry-installation-rid06',id,v)));
for(const name of ['policy-object','old-origin','deletion-origin','nonHTTPS','remote-host','implicit-port'])test('RID06-origin-reject/'+name,()=>{const id='registry-installation-rid06-S1-REVOKE-ACT';let origin='https://localhost:22222',p=null,v={};if(name==='policy-object')p={caseId:id,requestName:id+' :: actual-revoke',method:'POST',path:'/iam/v1/token',origin:'https://localhost:9096'};if(name==='old-origin')v.rid01IssuanceOrigin='https://localhost:9096';if(name==='deletion-origin')v.rid05IssuanceOrigin='https://localhost:9096';if(name==='nonHTTPS')origin='http://localhost:22222';if(name==='remote-host')origin='https://example.invalid:22222';if(name==='implicit-port')origin='https://localhost';assert.throws(()=>requestPolicy(id,origin,p,v));});
