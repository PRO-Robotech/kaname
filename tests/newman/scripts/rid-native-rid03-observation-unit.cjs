// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
'use strict';
// Pure receipt-schema controls. No Newman/API/process is launched.
const test=require('node:test'), assert=require('node:assert/strict');
const {rid03GetObservation}=require('./run-rid-native.cjs');
const caseId='registry-installation-rid03-S1-GRANT-ACT';
const at=Date.parse('2026-11-03T12:00:01.100Z');
function fixture(){
 const body={id:'binding',delegationId:'delegation',subjectType:'service_account',subjectId:'grantee',roleId:'role',scopeType:'iam.account',scopeId:'account',target:{resources:{resources:[{type:'registry.registries',id:'target'}]}},createdAt:'2026-11-03T12:00:00Z',materializedAt:'2026-11-03T12:00:01Z'};
 const ex={item:{name:caseId+' :: actual-action-resource-Get'},request:{method:'GET',url:{toString:()=> 'https://localhost:9098/iam/v1/accessBindings/binding'}},response:{code:200,json:()=>body},assertions:[{assertion:'checked'}]};
 return {body,rows:[ex],starts:[at],ends:[at+100]};
}
for(const [name,change]of [
 ['missing',x=>{x.rows=[];}],
 ['duplicate',x=>{x.rows.push(x.rows[0]);}],
 ['extra-observation-clock',x=>{x.starts.push(at);}],
 ['far-future-timestamp',x=>{x.body.materializedAt='2099-11-03T12:00:01Z';}],
 ['missing-materialization',x=>{x.body.materializedAt=null;}],
 ['wrong-resource-path',x=>{x.body.id='other';}],
 ['wrong-method',x=>{x.rows[0].request.method='POST';}],
 ['wrong-identity-kind',x=>{x.body.subjectType='user';}],
 ['secret-shaped-ID',x=>{x.body.subjectId='eyJ.header.signature';}],
 ['unknown-extra-target',x=>{x.body.target.resources.resources.push({type:'registry.registries',id:'extra'});}],
 ['wrong-status',x=>{x.rows[0].response.code=404;}],
 ['failed-assertion',x=>{x.rows[0].assertions[0].error={message:'withheld'};}],
 ['outside-request-window',x=>{x.ends=[at+6000];}],
])test('RID03-observation/'+name,()=>{const x=fixture();change(x);assert.throws(()=>rid03GetObservation(caseId,x.rows,x.starts,x.ends));});
test('RID03-observation/exact-positive',()=>{const x=fixture(),o=rid03GetObservation(caseId,x.rows,x.starts,x.ends);assert.equal(o.resourceId,'binding');assert.equal(o.materializedAt,x.body.materializedAt);assert.equal(Object.keys(o).length,18);assert.equal('body'in o,false);});
test('RID03-observation/wrong-phase',()=>{const x=fixture();assert.throws(()=>rid03GetObservation('registry-installation-rid03-S1-GRANT-VERIFY',x.rows,x.starts,x.ends));});
test('RID03-observation/default-no-metadata',()=>assert.equal(rid03GetObservation('registry-installation-rid10-FAULT-PARTIAL',[],[],[]),null));
