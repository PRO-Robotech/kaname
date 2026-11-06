// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// Root must regenerate ONLY RID05 after integrating the Python change. These
// controls deliberately consume that actual generated collection; they neither
// regenerate it nor test a separately copied fragment of its scripts.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {clientSecretNames,requestPolicy,allowedRequest}=require('./run-rid-native.cjs');
const collection=JSON.parse(fs.readFileSync(path.join(__dirname,'../collections/registry-installation-rid05.postman_collection.json'),'utf8'));
const literalIDs=[
  "registry-installation-rid05-S1-KEYS-AND-REFERENCES-CLEAN",
  "registry-installation-rid05-S1-DELETED-C-SNAPSHOT",
  "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED",
  "registry-installation-rid05-S1-DELETED-C-GRANT-ACT",
  "registry-installation-rid05-S1-DELETED-C-GRANT-VERIFY",
  "registry-installation-rid05-S1-SAME-NAME-C2-SNAPSHOT",
  "registry-installation-rid05-S1-C2-NO-REVIVAL-ACT",
  "registry-installation-rid05-S1-C2-NO-REVIVAL-VERIFY",
  "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT",
  "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY",
  "registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT",
  "registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-VERIFY",
  "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT",
  "registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY",
  "registry-installation-rid05-S1-RECOVERY-REAPPLY",
  "registry-installation-rid05-S2-KEYS-AND-REFERENCES-CLEAN",
  "registry-installation-rid05-S2-DELETED-C-SNAPSHOT",
  "registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED",
  "registry-installation-rid05-S2-DELETED-C-GRANT-ACT",
  "registry-installation-rid05-S2-DELETED-C-GRANT-VERIFY",
  "registry-installation-rid05-S2-SAME-NAME-C2-SNAPSHOT",
  "registry-installation-rid05-S2-C2-NO-REVIVAL-ACT",
  "registry-installation-rid05-S2-C2-NO-REVIVAL-VERIFY",
  "registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT",
  "registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-VERIFY",
  "registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT",
  "registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-VERIFY",
  "registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT",
  "registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-VERIFY",
  "registry-installation-rid05-S2-RECOVERY-REAPPLY"
];
function leaves(node){return(node.item||[]).flatMap(x=>x.item?leaves(x):[x]);}
function caseFolder(id){const matches=(collection.item||[]).filter(x=>x.name===id||x.name.startsWith(id+' — '));assert.equal(matches.length,1,'exact actual generated literal folder required');return matches[0];}
function source(item,listen){return(item.event||[]).filter(e=>e.listen===listen).flatMap(e=>e.script.exec||[]).join('\n');}
function leaf(id,name){const item=leaves(caseFolder(id)).find(x=>x.name===id+' :: '+name);assert.ok(item,'exact actual generated leaf required');return item;}
for(const id of literalIDs)test('RID05-rendered-scripts/'+id,()=>{const folder=caseFolder(id);assert.ok(leaves(folder).length>=15);for(const item of [folder,...leaves(folder)])for(const event of item.event||[])new vm.Script('(function(){\n'+(event.script.exec||[]).join('\n')+'\n})',{filename:'reviewed-rendered-case-script'});});
function expectation(value){const chain={};for(const k of ['to','be','and'])Object.defineProperty(chain,k,{get:()=>chain});chain.eql=want=>assert.deepEqual(value,want);chain.below=want=>assert.ok(value<want);return chain;}
expectation.fail=()=>assert.fail('actual rendered script reported a fixture precondition failure');
function evaluate(code,variables,response={}){
 const env=new Map(Object.entries(variables)),failures=[],next=[];let skipped=false;
 const headers=new Map();
 const request={url:'https://unowned.invalid/placeholder',headers:{upsert:({key,value})=>headers.set(key,value)},body:{raw:'{}',update(value){this.raw=value;}}};
 const pm={environment:{get:k=>env.get(k),set:(k,v)=>env.set(k,v)},variables:{get:k=>env.get(k),replaceIn:s=>s.replace(/{{([^}]+)}}/g,(_,k)=>String(env.get(k)||''))},request,response:{code:200,json:()=>response,text:()=>JSON.stringify(response)},info:{requestName:'actual-test-item'},expect:expectation,test:(name,fn)=>{try{fn();}catch(_){failures.push(name);}},execution:{setNextRequest:n=>next.push(n),skipRequest:()=>{skipped=true;}}};
 new vm.Script('(function(){\n'+code+'\n})();',{filename:'actual-rendered-case-script'}).runInNewContext({pm,Date,JSON,Number,Object});
 return{request,headers,env,failures,skipped,next};
}
const issuerACTs=[
 'registry-installation-rid05-S1-DELETED-C-GRANT-ACT','registry-installation-rid05-S2-DELETED-C-GRANT-ACT',
 'registry-installation-rid05-S1-C2-NO-REVIVAL-ACT','registry-installation-rid05-S2-C2-NO-REVIVAL-ACT',
 'registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT','registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT'];
for(const id of issuerACTs)test('RID05-actual-action-pre/'+id,()=>{
 const item=leaf(id,'actual-action'),request={subjectType:'service_account',subjectId:'U',roleId:'pull',scopeType:'iam.account',scopeId:'A',target:{resources:[{type:'registry.registries',id:'R'}]}};
 const out=evaluate(source(item,'prerequest'),{jwtRIDIssuer:'I',ownRestBaseUrl:'https://localhost:9098',rid05Expected:JSON.stringify({oldCreatorId:'C',request})});assert.deepEqual(out.failures,[]);assert.equal(out.skipped,false);assert.equal(out.headers.get('Authorization'),'Bearer I');assert.equal(out.request.url,'https://localhost:9098/iam/v1/accessBindings');assert.deepEqual(JSON.parse(out.request.body.raw),request);
 const vars={jwtRIDOperator:'O',jwtRIDIssuer:'I'};assert.deepEqual(clientSecretNames('registry-installation-rid05',id,vars),['jwtRIDOperator','jwtRIDIssuer']);assert.equal(allowedRequest(requestPolicy(id,'https://localhost:9098',null,vars),[item.name],item.name,'POST',out.request.url),true);
});
for(const name of ['full-script-extra-paren','forged-front-origin','wrong-request-leaf','unused-C-secret'])test('RID05-actual-action-reject/'+name,()=>{
 const id=issuerACTs[0],item=leaf(id,'actual-action'),code=source(item,'prerequest'),vars={jwtRIDOperator:'O',jwtRIDIssuer:'I'};
 if(name==='full-script-extra-paren'){const broken=code.replace("JSON.parse(pm.environment.get('rid05Expected')).request));","JSON.parse(pm.environment.get('rid05Expected')).request)));");assert.notEqual(broken,code);assert.throws(()=>new vm.Script('(function(){\n'+broken+'\n})'));return;}
 if(name==='unused-C-secret'){assert.throws(()=>clientSecretNames('registry-installation-rid05',id,{...vars,jwtRIDCreator:'C'}));return;}
 const origin=name==='forged-front-origin'?'https://localhost:9096':'https://localhost:9098';const out=evaluate(code,{jwtRIDIssuer:'I',ownRestBaseUrl:origin,rid05Expected:JSON.stringify({oldCreatorId:'C',request:{accountId:'A'}})});assert.equal(allowedRequest(requestPolicy(id,'https://localhost:9098',null,vars),[item.name],name==='wrong-request-leaf'?item.name+'-other':item.name,'POST',out.request.url),false);
});
function wireFixture(id){const failed=id.includes('-ACTIVE-DELEGATE-DELETE-ACT'),metadata={'@type':'type.googleapis.com/kaname.cloud.iam.v1.DeleteServiceAccountMetadata',serviceAccountId:'C',accountId:'SYS'},fixed={id:'',description:'Delete service account C',createdAt:null,createdBy:'O',modifiedAt:null,done:true,metadata,principalType:'user',principalId:'O',principalDisplayName:'O'};
 if(failed)fixed.error={code:9,message:'service account C holds an active grant delegation D; revoke it first',details:[]};else fixed.response={'@type':'type.googleapis.com/google.protobuf.Empty',value:{}};
 const contract={caseId:id,resourceId:'C',accountId:'SYS',operatorId:'O',notBefore:'2026-11-03T12:00:00Z',notAfter:'2026-11-03T12:02:00Z',operation:fixed};
 const actual=JSON.parse(JSON.stringify(fixed));actual.id='actual-post-handle';actual.createdAt='2026-11-03T12:00:01Z';actual.modifiedAt='2026-11-03T12:00:02Z';
 return{e:{caseId:id,oldCreatorId:'C',systemId:'SYS',operatorId:'O',denied:failed,blockingDelegationId:'D',deleteContract:contract,snapshot:{projection:{serviceAccounts:[{id:'C',accountId:'SYS'}]}}},actual};
}
for(const id of ['registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT','registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT','registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT','registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT'])test('RID05-actual-delete-poll/'+id,()=>{const {e,actual}=wireFixture(id);const out=evaluate(source(leaf(id,'actual-owner-Operation-Get'),'test'),{rid05Expected:JSON.stringify(e),rid05ActionOperationId:actual.id,rid05ActionDeadline:String(Date.now()+30000),rid05Polls:'0'},actual);assert.deepEqual(out.failures,[]);assert.equal(out.next.length,0);});
for(const name of ['missing-value','wrong-value','extra-value-field','wrong-type','wrong-metadata-type','wrong-resource','wrong-account','wrong-principal','wrong-createdBy','wrong-post-ID','before-clock','future-clock','reversed-clock','extra-operation-field','wrong-case','missing-contract'])test('RID05-actual-delete-poll-reject/'+name,()=>{
 const id='registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT',{e,actual}=wireFixture(id);switch(name){case'missing-value':delete actual.response.value;break;case'wrong-value':actual.response.value=null;break;case'extra-value-field':actual.response.value={unexpected:true};break;case'wrong-type':actual.response['@type']='type.googleapis.com/other.Empty';break;case'wrong-metadata-type':actual.metadata['@type']='type.googleapis.com/other.DeleteServiceAccountMetadata';break;case'wrong-resource':actual.metadata.serviceAccountId='C2';break;case'wrong-account':actual.metadata.accountId='OTHER';break;case'wrong-principal':actual.principalId='C';break;case'wrong-createdBy':actual.createdBy='C';break;case'wrong-post-ID':actual.id='other-handle';break;case'before-clock':actual.createdAt='2000-01-01T00:00:00Z';break;case'future-clock':actual.modifiedAt='2099-01-01T00:00:00Z';break;case'reversed-clock':actual.modifiedAt='2026-11-03T12:00:00Z';break;case'extra-operation-field':actual.future=true;break;case'wrong-case':e.deleteContract.caseId='registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT';break;case'missing-contract':delete e.deleteContract;break;}
 const out=evaluate(source(leaf(id,'actual-owner-Operation-Get'),'test'),{rid05Expected:JSON.stringify(e),rid05ActionOperationId:'actual-post-handle',rid05ActionDeadline:String(Date.now()+30000),rid05Polls:'0'},actual);assert.ok(out.failures.length>0);
});

// Missing credentials remain an explicit fixture failure; this is never counted
// as actual HTTP execution or as a successful denial of the requested actor.
test('RID05-actual-action-reject/missing-I-credential',()=>{
 const id=issuerACTs[0],item=leaf(id,'actual-action');
 const out=evaluate(source(item,'prerequest'),{ownRestBaseUrl:'https://localhost:9098',rid05Expected:JSON.stringify({oldCreatorId:'C',request:{accountId:'A'}})});
 assert.deepEqual(out.failures,['[УСЛОВИЕ НЕ СОЗДАНО] harness config: jwtRIDIssuer is set (subject under test)']);assert.equal(out.skipped,true);assert.equal(out.headers.has('Authorization'),false);
});
for(const id of ['registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT','registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT','registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT','registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT'])test('RID05-delete-outcome-generator-contract/'+id,()=>{
 const code=source(leaf(id,'actual-owner-Operation-Get'),'test');
 assert.ok(code.includes('pm.expect(op.error).to.eql(c.operation.error);'),'actual generated outcome must compare the BEFORE-derived canonical contract');
 assert.equal(code.includes('delete operation succeeded (no operation.error)'),false,'no success-only fallback on a closed failed/successful Delete contract');
});
for(const name of ['missing-error','wrong-code','wrong-message','wrong-details','success-substitution'])test('RID05-actual-delete-guard-reject/'+name,()=>{
 const id='registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT',{e,actual}=wireFixture(id);
 switch(name){case'missing-error':delete actual.error;break;case'wrong-code':actual.error.code=7;break;case'wrong-message':actual.error.message='permission denied';break;case'wrong-details':actual.error.details=[{unexpected:true}];break;case'success-substitution':delete actual.error;actual.response={'@type':'type.googleapis.com/google.protobuf.Empty',value:{}};break;}
 const out=evaluate(source(leaf(id,'actual-owner-Operation-Get'),'test'),{rid05Expected:JSON.stringify(e),rid05ActionOperationId:actual.id,rid05ActionDeadline:String(Date.now()+30000),rid05Polls:'0'},actual);assert.ok(out.failures.includes('exact normal asynchronous Delete outcome'));
});
