// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// Root regenerates RID06 after source review. Consume actual rendered scripts,
// including the normal auth/own-front guards; never generate a separate fragment.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const collection=JSON.parse(fs.readFileSync(path.join(__dirname,'../collections/registry-installation-rid06.postman_collection.json'),'utf8'));
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
function leaves(node){return(node.item||[]).flatMap(x=>x.item?leaves(x):[x]);}
function folder(id){const xs=(collection.item||[]).filter(x=>x.name===id||x.name.startsWith(id+' — '));assert.equal(xs.length,1);return xs[0];}
function leaf(id,name){const xs=leaves(folder(id)).filter(x=>x.name===id+' :: '+name);assert.equal(xs.length,1);return xs[0];}
function source(item,listen){return(item.event||[]).filter(e=>e.listen===listen).flatMap(e=>e.script.exec||[]).join('\n');}
for(const id of Object.keys(literalActors))test('RID06-rendered-scripts/'+id,()=>{const f=folder(id);assert.ok(leaves(f).length>=2);for(const item of[f,...leaves(f)])for(const event of item.event||[])new vm.Script('(function(){\n'+event.script.exec.join('\n')+'\n})');});
function expectation(value){const chain={};for(const k of['to','be','and'])Object.defineProperty(chain,k,{get:()=>chain});chain.eql=want=>assert.deepEqual(structuredClone(value),structuredClone(want));chain.below=want=>assert.ok(value<want);chain.above=want=>assert.ok(value>want);chain.a=kind=>{assert.equal(typeof value,kind);return chain;};Object.defineProperty(chain,'not',{get:()=>({get empty(){assert.ok(value!==''&&value!==null&&value!==undefined);return chain;}})});return chain;}
expectation.fail=()=>assert.fail('actual rendered script reported a fixture precondition failure');
function evaluate(code,variables,response={}){
 const env=new Map(Object.entries(variables)),headers=new Map(),failures=[],next=[];let skipped=false;
 const request={url:'https://unowned.invalid/placeholder',headers:{upsert:({key,value})=>headers.set(key,value)},body:{raw:'{}',update(value){this.raw=value;}}};
 const pm={environment:{get:k=>env.get(k),set:(k,v)=>env.set(k,v)},variables:{get:k=>env.get(k),has:k=>env.has(k),replaceIn:s=>s.replace(/{{([^}]+)}}/g,(match,k)=>env.has(k)?String(env.get(k)):match)},request,response:{code:200,json:()=>response,text:()=>JSON.stringify(response)},info:{requestName:'actual-test-item'},expect:expectation,test:(name,fn)=>{try{fn();}catch(_){failures.push(name);}},execution:{setNextRequest:n=>next.push(n),skipRequest:()=>{skipped=true;}}};
 new vm.Script('(function(){\n'+code+'\n})();').runInNewContext({pm,Date,JSON,Number,Object,Set});return{request,env,headers,failures,next,skipped};
}
function fixture(id){const mode=id.includes('-S2-')?'S2':'S1',critical=id.endsWith('-REVOKE-ACT'),creator=id.endsWith('-EXPLICIT-CREATE-ACT'),recovered=id.endsWith('-EXPLICIT-RECOVERY-ACT'),accounts=(mode==='S2'?['A','A2','A3','SYS']:['A','SYS']).map(id=>({id})),status=critical?'ACTIVE':'REVOKED';
 const delegations=accounts.filter(a=>a.id!=='SYS').map((a,i)=>({id:i?'GD'+i:'GD',accountId:a.id,delegate:{id:'I'},delegatedBy:{type:'service_account',id:'C'},status:i?'ACTIVE':status}));if(recovered)delegations.push({id:'NEWGD',accountId:'A',delegate:{id:'I'},status:'ACTIVE'});
 return{caseId:id,mode,phase:'ACT',oldStatus:status,oldDelegationId:'GD',oldGrantId:'G',operatorId:'O',creatorId:'C',issuerId:'I',actor:creator?'C':critical?'O':'I',systemId:'SYS',tenantId:'A',installationDelegationId:recovered?'NEWGD':'GD',path:critical?'/iam/v1/grantDelegations/GD:revoke':creator?'/iam/v1/grantDelegations':'/iam/v1/accessBindings',request:critical?{}:{accountId:'A',fixture:'same-before-body'},actionDeadline:critical?new Date(Date.now()+10000).toISOString():undefined,snapshot:{projection:{accounts,serviceAccounts:[{id:'C',enabled:true},{id:'I',enabled:true}],groups:[{id:'GROUP',accountId:'SYS',name:'module-relation-writers'}],roles:[{id:'ROLE'}],bindings:[{id:'G',status,delegationId:'GD',revocationReason:'REVOCATION_REASON_DELEGATION_REVOKED'}],delegations,catalog:{},members:{GROUP:[]}}}};
}
const actionIDs=Object.keys(literalActors).filter(id=>id.endsWith('-ACT'));
for(const id of actionIDs)test('RID06-actual-action-pre/'+id,()=>{
 const e=fixture(id),actor=literalActors[id],variable=actor==='O'?'jwtRIDOperator':actor==='C'?'jwtRIDCreator':'jwtRIDIssuer',critical=id.endsWith('-REVOKE-ACT');
 const out=evaluate(source(leaf(id,critical?'actual-revoke':'actual-action'),'prerequest'),{[variable]:actor,ownRestBaseUrl:'https://localhost:9098',rid06Expected:JSON.stringify(e)});
 assert.deepEqual(out.failures,[]);assert.equal(out.skipped,false);assert.equal(out.headers.get('Authorization'),'Bearer '+actor);assert.equal(out.request.url.replace(/{{([^}]+)}}/g,(_,k)=>String(out.env.get(k))),'https://localhost:9098'+e.path);assert.deepEqual(JSON.parse(out.request.body.raw),e.request);if(critical)assert.equal(Number(out.env.get('rid06ActionDeadline')),Date.parse(e.actionDeadline));
});
for(const id of actionIDs)test('RID06-actual-action-missing-credential/'+id,()=>{
 const actor=literalActors[id],variable=actor==='O'?'jwtRIDOperator':actor==='C'?'jwtRIDCreator':'jwtRIDIssuer',out=evaluate(source(leaf(id,id.endsWith('-REVOKE-ACT')?'actual-revoke':'actual-action'),'prerequest'),{ownRestBaseUrl:'https://localhost:9098',rid06Expected:JSON.stringify(fixture(id))});
 assert.deepEqual(out.failures,['[УСЛОВИЕ НЕ СОЗДАНО] harness config: '+variable+' is set (subject under test)']);assert.equal(out.skipped,true);assert.equal(out.headers.has('Authorization'),false);
});
for(const mode of['S1','S2'])test('RID06-actual-revoke-poll/'+mode,()=>{
 const id='registry-installation-rid06-'+mode+'-REVOKE-ACT',e=fixture(id),op={id:'OP',done:true,metadata:{grantDelegationId:'GD',accountId:'A'},response:{id:'GD',accountId:'A',status:'REVOKED'}},code=source(leaf(id,'actual-owner-Operation-Get'),'test');
 assert.ok(code.includes('pm.expect(op.error||null).to.eql(null)'));const out=evaluate(code,{rid06Expected:JSON.stringify(e),rid06ActionOperationId:'OP',rid06ActionDeadline:String(Date.now()+10000),rid06Polls:'0'},op);assert.deepEqual(out.failures,[]);assert.equal(out.next.length,0);
});
for(const name of['wrong-handle','wrong-metadata','wrong-account','wrong-resource','not-revoked','failed-operation','expired-deadline'])test('RID06-actual-revoke-poll-reject/'+name,()=>{
 const id='registry-installation-rid06-S1-REVOKE-ACT',e=fixture(id),op={id:'OP',done:true,metadata:{grantDelegationId:'GD',accountId:'A'},response:{id:'GD',accountId:'A',status:'REVOKED'}};
 switch(name){case'wrong-handle':op.id='OTHER';break;case'wrong-metadata':op.metadata.grantDelegationId='OTHER';break;case'wrong-account':op.metadata.accountId='OTHER';break;case'wrong-resource':op.response.id='OTHER';break;case'not-revoked':op.response.status='ACTIVE';break;case'failed-operation':op.error={code:9};break;}
 const out=evaluate(source(leaf(id,'actual-owner-Operation-Get'),'test'),{rid06Expected:JSON.stringify(e),rid06ActionOperationId:'OP',rid06ActionDeadline:String(Date.now()+(name==='expired-deadline'?-1000:10000)),rid06Polls:'0'},op);assert.ok(out.failures.length>0);
});

// Chai data equality must not reject an otherwise identical JSON record solely
// because a literal belongs to the rendered script's VM realm. structuredClone
// keeps data types and own-property presence; no JSON stringify normalization.
test('RID06-sandbox-eql/cross-realm-record',()=>{
 const actual={type:'service_account',id:'C'},expected=new vm.Script("({type:'service_account',id:'C'})").runInNewContext();
 assert.throws(()=>assert.deepEqual(actual,expected),'before-fix strict prototype comparator must reproduce the realm mismatch');
 expectation(actual).eql(expected);assert.deepEqual(actual,{type:'service_account',id:'C'});
});
for(const name of ['wrong-type','extra-field','missing-field','nested-mismatch','undefined-presence'])test('RID06-sandbox-eql-reject/'+name,()=>{
 const actual={type:'service_account',id:'C',nested:{value:7}},expressions={
  'wrong-type':"({type:'service_account',id:'C',nested:{value:'7'}})",
  'extra-field':"({type:'service_account',id:'C',nested:{value:7},extra:true})",
  'missing-field':"({type:'service_account',nested:{value:7}})",
  'nested-mismatch':"({type:'service_account',id:'C',nested:{value:8}})",
  'undefined-presence':"({type:'service_account',id:'C',nested:{value:7},extra:undefined})"
 };
 const expected=new vm.Script(expressions[name]).runInNewContext();assert.throws(()=>expectation(actual).eql(expected));
});
