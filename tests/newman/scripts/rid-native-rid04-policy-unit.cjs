// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {clientSecretNames,requestPolicy}=require('./run-rid-native.cjs');
const literalIDs=[
  "registry-installation-rid04-S1-BEFORE-RETIREMENT",
  "registry-installation-rid04-S1-RETIRED-DENIED-ACT",
  "registry-installation-rid04-S1-RETIRED-DENIED-VERIFY",
  "registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT",
  "registry-installation-rid04-S1-RESTORED-GRANT-ACT",
  "registry-installation-rid04-S1-RESTORED-GRANT-VERIFY",
  "registry-installation-rid04-S1-RESTORED-REAPPLY",
  "registry-installation-rid04-S2-BEFORE-RETIREMENT",
  "registry-installation-rid04-S2-RETIRED-DENIED-ACT",
  "registry-installation-rid04-S2-RETIRED-DENIED-VERIFY",
  "registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT",
  "registry-installation-rid04-S2-RESTORED-GRANT-ACT",
  "registry-installation-rid04-S2-RESTORED-GRANT-VERIFY",
  "registry-installation-rid04-S2-RESTORED-REAPPLY"
];
for(const id of literalIDs){test('RID04-literal/'+id,()=>{
 const vars={jwtRIDOperator:'O'};
 const want=['jwtRIDOperator'];
 if(id.endsWith('-ACT')){vars.jwtRIDIssuer='I';want.push('jwtRIDIssuer');}
 assert.deepEqual(clientSecretNames('registry-installation-rid04',id,vars),want);
 assert.deepEqual(requestPolicy(id,'https://localhost:22222',null,vars),{publicOrigin:'https://localhost:22222',token:null});
});}
for(const [name,id,vars] of [
 ['unknown-phase','registry-installation-rid04-S1-OTHER',{jwtRIDOperator:'O'}],
 ['missing-I','registry-installation-rid04-S1-RETIRED-DENIED-ACT',{jwtRIDOperator:'O'}],
 ['empty-I','registry-installation-rid04-S1-RESTORED-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:''}],
 ['invalid-I-type','registry-installation-rid04-S1-RESTORED-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:1}],
 ['oversize-I','registry-installation-rid04-S1-RESTORED-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'x'.repeat(16385)}],
 ['VERIFY-I-forbidden','registry-installation-rid04-S1-RESTORED-GRANT-VERIFY',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['READ-I-forbidden','registry-installation-rid04-S1-BEFORE-RETIREMENT',{jwtRIDOperator:'O',jwtRIDIssuer:'I'}],
 ['C-forbidden','registry-installation-rid04-S1-RESTORED-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',jwtRIDCreator:'C'}],
 ['assertion-forbidden','registry-installation-rid04-S1-RESTORED-GRANT-ACT',{jwtRIDOperator:'O',jwtRIDIssuer:'I',rid01ClientAssertion:'assertion'}],
 ['issuance-origin-forbidden','registry-installation-rid04-S1-BEFORE-RETIREMENT',{jwtRIDOperator:'O',rid01IssuanceOrigin:'https://localhost:9096'}],
])test('RID04-reject/'+name,()=>assert.throws(()=>clientSecretNames('registry-installation-rid04',id,vars)));
