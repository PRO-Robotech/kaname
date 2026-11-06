// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// Исполняем только фактически сгенерированные скрипты; коллекции и код предмета не переписываем.
const test = require('node:test'), assert = require('node:assert/strict');
const vm = require('node:vm'), fs = require('node:fs'), path = require('node:path');
const RID05 = [
  'registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT',
  'registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT',
  'registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT',
  'registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT',
];
const RID10 = [
  {id:'registry-installation-rid10-FAULT-PARTIAL', operations:2, failed:true},
  {id:'registry-installation-rid10-FAULT-RECOVERED', operations:5, failed:true},
  {id:'registry-installation-rid10-FAULT-TWIN', operations:3, failed:false},
  {id:'registry-installation-rid10-RETIREMENT-PARTIAL', operations:1, failed:false},
  {id:'registry-installation-rid10-RETIREMENT-RECOVERED', operations:4, failed:false},
  {id:'registry-installation-rid10-RETIREMENT-TWIN', operations:3, failed:false},
];
const collections = new Map(['05','10'].map(rid => [rid, JSON.parse(fs.readFileSync(
  path.join(__dirname,'../collections/registry-installation-rid'+rid+'.postman_collection.json'),'utf8'))]));
const clone = value => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
function subject(rid,id) {
  const folders = collections.get(rid).item.filter(f => f.name === id || f.name.startsWith(id+' — '));
  assert.equal(folders.length,1,'нужна ровно одна actual папка');
  const leaves = node => (node.item||[]).flatMap(it => it.item ? leaves(it) : [it]);
  const suffix = rid === '05' ? 'actual-owner-Operation-Get' : 'every-primary-normal-GD-Operation-Get';
  const items = leaves(folders[0]).filter(it => it.name === id+' :: '+suffix);
  assert.equal(items.length,1,'нужен ровно один actual leaf');
  const request=items[0].request, url=typeof request.url==='string'?request.url:request.url.raw;
  assert.equal(request.method,'GET');assert.ok(url.endsWith('/operations/{{'+(rid==='05'?'rid05ActionOperationId':'rid10OperationId')+'}}'));
  return {name:items[0].name, code:items[0].event.filter(e => e.listen === 'test').flatMap(e => e.script.exec).join('\n')};
}
function expectation(value) {
  const chain = {}; let negative = false;
  for (const key of ['to','be','and','have']) Object.defineProperty(chain,key,{get:()=>chain});
  Object.defineProperty(chain,'not',{get:()=>{negative=!negative;return chain;}});
  chain.eql = wanted => negative ? assert.notDeepEqual(clone(value),clone(wanted)) : assert.deepEqual(clone(value),clone(wanted));
  chain.below = wanted => assert.ok(negative ? !(value < wanted) : value < wanted);
  chain.an = wanted => assert.equal(typeof value,wanted);
  chain.include = wanted => assert.equal(value.includes(wanted),!negative);
  chain.property = wanted => assert.equal(Object.prototype.hasOwnProperty.call(value,wanted),!negative);
  return chain;
}
const EPOCH = Date.parse('2026-11-03T12:00:01Z');
function clock() {
  let elapsed = 0;
  class FixtureDate extends Date { static now() { const now=EPOCH+elapsed;elapsed+=10;return now; } }
  return {Date:FixtureDate, elapsed:()=>elapsed};
}
function run(code,state,response) {
  const failures=[], called=[], next=[], start=state.clock.elapsed();
  const pm = {
    environment:{get:k=>state.env.get(k),set:(k,v)=>state.env.set(k,v),unset:k=>state.env.delete(k)},
    response:{code:200,json:()=>clone(response),text:()=>JSON.stringify(response)},
    info:{requestName:state.item.name},expect:expectation,
    test:(name,fn)=>{called.push(name);try{fn();}catch(error){failures.push({name,error});}},
    execution:{setNextRequest:name=>next.push({name,operationId:state.env.get(state.idVar),elapsed:state.clock.elapsed()-start})},
  };
  // Движущиеся часы завершают реальный busy-wait без ожидания физических часов; VM имеет жёсткий предел.
  new vm.Script('(function(){\n'+code+'\n})();',{filename:state.item.name}).runInNewContext(
    {pm,Date:state.clock.Date,JSON,Number,Object},{timeout:1000});
  return {failures,called,next,elapsed:state.clock.elapsed()-start};
}
function green(out) { assert.deepEqual(out.failures,[]); }
function red(out,oracle) { assert.ok(out.failures.some(f=>f.name===oracle),'ожидаем ошибку именно предметного pm.test'); }
const OUT05 = 'exact normal asynchronous Delete outcome';
const OUT10 = 'actual creator-owned Operation.Get equals full primary row/Any/status projection';
function fixture05(id) {
  const failed=id.includes('-ACTIVE-DELEGATE-DELETE-ACT');
  const fixed={id:'',description:'Delete service account C',createdAt:null,createdBy:'O',modifiedAt:null,done:true,
    metadata:{'@type':'type.googleapis.com/kaname.cloud.iam.v1.DeleteServiceAccountMetadata',serviceAccountId:'C',accountId:'SYS'},
    principalType:'user',principalId:'O',principalDisplayName:'O'};
  if(failed) fixed.error={code:9,message:'service account C holds an active grant delegation D; revoke it first',details:[]};
  else fixed.response={'@type':'type.googleapis.com/google.protobuf.Empty',value:{}};
  const expected={caseId:id,oldCreatorId:'C',operatorId:'O',snapshot:{projection:{serviceAccounts:[{id:'C',accountId:'SYS'}]}},
    deleteContract:{caseId:id,resourceId:'C',accountId:'SYS',operatorId:'O',notBefore:'2026-11-03T12:00:00Z',notAfter:'2026-11-03T12:02:00Z',operation:fixed}};
  const terminal={...clone(fixed),id:'actual-post-handle',createdAt:'2026-11-03T12:00:01Z',modifiedAt:'2026-11-03T12:00:02Z'};
  return {item:subject('05',id),clock:clock(),idVar:'rid05ActionOperationId',terminal,
    env:new Map(Object.entries({rid05Expected:JSON.stringify(expected),rid05ActionOperationId:terminal.id,rid05ActionDeadline:String(EPOCH+30000),rid05Polls:'0'}))};
}
function pending05(state) { return {id:state.terminal.id,done:false}; }
function probe05Pending(id,code) {
  const s=fixture05(id), out=run(code,s,pending05(s));green(out);
  assert.deepEqual(out.next.map(n=>n.name),[s.item.name]);assert.equal(out.next[0].operationId,s.terminal.id);
  assert.ok(out.next[0].elapsed>=100,'повтор обязан идти после паузы');assert.equal(s.env.get('rid05Polls'),'1');
  assert.equal(out.called.includes(OUT05),false,'terminal oracle не исполняется на pending');return s;
}
function probe05Boundary(id,code,kind) {
  const s=fixture05(id), pending=pending05(s);
  if(kind==='wrong-ID') pending.id='foreign';
  if(kind==='at-deadline') s.env.set('rid05ActionDeadline',String(EPOCH));
  if(kind==='expired') s.env.set('rid05ActionDeadline',String(EPOCH-1));
  if(kind==='4999'||kind==='5000') s.env.set('rid05Polls',kind);
  const out=run(code,s,pending);red(out,OUT05);assert.deepEqual(out.next,[]);
}
function fixture10(row,prefix='op') {
  const operations=Array.from({length:row.operations},(_,i)=>({id:prefix+'-'+i,description:'Create grant delegation '+i,
    createdAt:'2026-11-03T12:00:01Z',createdBy:'C',modifiedAt:'2026-11-03T12:00:02Z',done:true,
    principalType:'service_account',principalId:'C',principalDisplayName:'C',
    metadata:{'@type':'type.googleapis.com/kaname.cloud.iam.v1.CreateGrantDelegationMetadata',grantDelegationId:'GD-'+i,accountId:'A'},
    response:{'@type':'type.googleapis.com/kaname.cloud.iam.v1.GrantDelegation',id:'GD-'+i,accountId:'A',status:'ACTIVE'}}));
  if(row.failed){delete operations[0].response;operations[0].error={code:13,message:'internal error',details:[]};}
  const expected={creatorId:'C',failedOperationId:row.failed?operations[0].id:'',snapshot:{operations}};
  return {item:subject('10',row.id),clock:clock(),idVar:'rid10OperationId',expected,operations,
    env:new Map(Object.entries({rid10Expected:JSON.stringify(expected),rid10OperationIndex:'0',rid10OperationId:operations[0].id,rid10OperationsSeen:'[]'}))};
}
function store10(s) { s.env.set('rid10Expected',JSON.stringify(s.expected)); }
function probe10Pending(row,code,s=fixture10(row)) {
  const index=s.env.get('rid10OperationIndex'), id=s.env.get('rid10OperationId'), seen=s.env.get('rid10OperationsSeen');
  const out=run(code,s,{id,done:false});green(out);
  assert.deepEqual(out.next.map(n=>[n.name,n.operationId]),[[s.item.name,id]]);assert.ok(out.next[0].elapsed>=500,'нет межопросной паузы');
  assert.equal(s.env.get('rid10OperationIndex'),index);assert.equal(s.env.get('rid10OperationId'),id);assert.equal(s.env.get('rid10OperationsSeen'),seen);
  assert.equal(out.called.includes(OUT10),false);return s;
}
function probe10Cap(row,code) {
  const s=fixture10(row), id=s.operations[0].id;s.env.set('rid10OperationPollId',id);s.env.set('rid10OperationPollCount','49');
  probe10Pending(row,code,s);assert.equal(s.env.get('rid10OperationPollCount'),'50');
  const out=run(code,s,{id,done:false});red(out,OUT10);assert.equal(out.next.some(n=>n.operationId===id),false);
}
function probe10Foreign(row,code,kind) {
  const s=fixture10(row), id=s.operations[0].id,pending={id,done:false};
  if(kind==='got') pending.id='foreign';else{s.expected.snapshot.operations[0].id='foreign';store10(s);}
  red(run(code,s,pending),OUT10);
}
function probe10NewID(row,code) {
  // Одиночная retirement-partial не получает выдуманной второй операции: следующий запуск имеет новый один ID.
  const s=fixture10(row,'next-run');s.env.set('rid10OperationPollId','previous-run');s.env.set('rid10OperationPollCount','49');
  probe10Pending(row,code,s);assert.equal(s.env.get('rid10OperationPollCount'),'1');
}
function replaceOnce(code,from,to) { assert.equal(code.split(from).length-1,1,'mutant должен менять один реальный фрагмент');return code.replace(from,to); }
function killed(code,from,to,probe) {
  const mutant=replaceOnce(code,from,to);
  // Ошибки синтаксиса и исполнения не являются доказательством: нужен отказ поведенческого oracle.
  assert.throws(()=>probe(mutant),error=>error.name==='AssertionError');
}
for(const id of RID05) {
  test('operation-await/RID05/pending-terminal/'+id,()=>{
    const s=probe05Pending(id,subject('05',id).code), out=run(s.item.code,s,s.terminal);green(out);
    assert.ok(out.called.includes(OUT05));assert.deepEqual(out.next,[]);
  });
  test('operation-await/RID05/boundaries/'+id,()=>{
    const code=subject('05',id).code;
    for(const kind of ['wrong-ID','at-deadline','expired','4999','5000']) probe05Boundary(id,code,kind);
    const s=fixture05(id);s.env.set('rid05Polls','4998');const out=run(code,s,pending05(s));green(out);
    assert.equal(s.env.get('rid05Polls'),'4999');assert.equal(out.next.length,1);
  });
  test('operation-await/RID05/mutants/'+id,()=>{
    const code=subject('05',id).code, pending=c=>probe05Pending(id,c);
    killed(code,'pm.execution.setNextRequest(pm.info.requestName);','void 0;',pending);
    killed(code,'while(Date.now()-_rid05PollStarted<_rid05Pause)void 0;','void 0;',pending);
    killed(code,"op.id===pm.environment.get('rid05ActionOperationId') && ",'',c=>probe05Boundary(id,c,'wrong-ID'));
    killed(code,"Number(pm.environment.get('rid05Polls'))<5000 && ",'',c=>probe05Boundary(id,c,'4999'));
    killed(code," && Date.now()<Number(pm.environment.get('rid05ActionDeadline'))",'',c=>probe05Boundary(id,c,'expired'));
    killed(code,"pm.environment.set('rid05Polls',String(Number(pm.environment.get('rid05Polls'))+1));","pm.environment.set('rid05Polls','0');",pending);
  });
}
for(const row of RID10) {
  test('operation-await/RID10/pending-terminal-reset/'+row.id,()=>{
    const s=probe10Pending(row,subject('10',row.id).code);assert.equal(s.env.get('rid10OperationPollCount'),'1');
    probe10Pending(row,s.item.code,s);assert.equal(s.env.get('rid10OperationPollCount'),'2');
    for(let i=0;i<s.operations.length;i++) {
      const out=run(s.item.code,s,s.operations[i]);green(out);assert.ok(out.called.includes(OUT10));
      assert.deepEqual(JSON.parse(s.env.get('rid10OperationsSeen')),s.operations.slice(0,i+1).map(op=>op.id));
      if(i+1<s.operations.length) {
        assert.equal(s.env.get('rid10OperationIndex'),String(i+1));assert.equal(s.env.get('rid10OperationId'),s.operations[i+1].id);
        assert.deepEqual(out.next.map(n=>[n.name,n.operationId]),[[s.item.name,s.operations[i+1].id]]);
        s.env.set('rid10OperationPollId',s.operations[i].id);s.env.set('rid10OperationPollCount','49');
        probe10Pending(row,s.item.code,s);assert.equal(s.env.get('rid10OperationPollCount'),'1');
      }else{assert.deepEqual(out.next,[]);assert.ok(out.called.includes('EVERY independently inventoried normal GD Operation was really Get once'));}
    }
    probe10NewID(row,s.item.code);
  });
  test('operation-await/RID10/boundaries/'+row.id,()=>{
    const code=subject('10',row.id).code;probe10Cap(row,code);probe10Foreign(row,code,'got');probe10Foreign(row,code,'expected');
    for(const kind of ['full-row','owner',...(row.failed?['code13']:[])]) {
      const s=fixture10(row),got=clone(s.operations[0]);
      if(kind==='full-row') got.description='foreign description';
      if(kind==='owner'){got.principalId='foreign';s.expected.snapshot.operations[0].principalId='foreign';store10(s);}
      if(kind==='code13'){got.error.code=7;s.expected.snapshot.operations[0].error.code=7;store10(s);}
      red(run(code,s,got),OUT10);
    }
  });
  test('operation-await/RID10/mutants/'+row.id,()=>{
    const code=subject('10',row.id).code,pending=c=>probe10Pending(row,c);
    killed(code,'  pm.execution.setNextRequest(pm.info.requestName);\n  return;','  void 0;\n  return;',pending);
    killed(code,'while (Date.now() - _rid10PollStarted < 500) void 0;','void 0;',pending);
    killed(code,"  return;\n}\npm.environment.unset('rid10OperationPollId');","}\npm.environment.unset('rid10OperationPollId');",pending);
    killed(code,"if (pm.environment.get('rid10OperationPollId') !== operationId)",'if (true)',c=>probe10Cap(row,c));
    killed(code,'got.id === operationId && ','',c=>probe10Foreign(row,c,'got'));
    killed(code,'expected.id === operationId && ','',c=>probe10Foreign(row,c,'expected'));
    killed(code,' && polls < 50','',c=>probe10Cap(row,c));
    killed(code,"if (pm.environment.get('rid10OperationPollId') !== operationId)","if (pm.environment.get('rid10OperationPollId') === operationId)",c=>probe10NewID(row,c));
    killed(code,'  return;\n}',"  pm.environment.set('rid10OperationIndex','999');\n  return;\n}",pending);
  });
}
