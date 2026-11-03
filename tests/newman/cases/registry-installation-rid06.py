# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID06 actual public Revoke/explicit Create/I grant in existing8 native worlds.
The critical Revoke phase has only actual POST+owner poll inside the unchanged
before-pair pause; full read census is outside that critical section.
"""
from rid_midrun_public import midrun_read_steps
HOME='kaname'
CASES=[]
_CONFIG=r"""const e=JSON.parse(pm.environment.get('rid06Expected')||'null');
const keys=['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid=e&&e.caseId===__CASE__&&e.mode===__MODE__&&e.phase===__PHASE__&&e.oldStatus===__STATUS__&&e.oldDelegationId&&e.oldGrantId&&e.operatorId&&e.creatorId&&e.issuerId&&e.systemId&&e.tenantId&&e.installationDelegationId&&e.snapshot&&e.snapshot.projection&&keys.every(k=>Array.isArray(e.snapshot.projection[k]))&&e.snapshot.projection.catalog&&e.snapshot.projection.members;
if(!valid){__MISSING__}else{
 const p=e.snapshot.projection;
 pm.test('RID06 full independent primary identities/history and exact pair counts',()=>{
  keys.forEach(k=>{pm.expect(p[k].length).to.be.above(0);pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length);});
  pm.expect(p.accounts.length).to.eql(__ACCOUNTS__);pm.expect(Object.keys(p.members).sort()).to.eql(p.groups.map(g=>g.id).sort());pm.expect(p.groups.filter(g=>g.accountId===e.systemId&&g.name==='module-relation-writers').length).to.eql(1);
  pm.expect(p.serviceAccounts.find(x=>x.id===e.creatorId).enabled).to.eql(true);pm.expect(p.serviceAccounts.find(x=>x.id===e.issuerId).enabled).to.eql(true);
  const oldGD=p.delegations.find(x=>x.id===e.oldDelegationId),oldG=p.bindings.find(x=>x.id===e.oldGrantId);
  pm.expect(oldGD.status).to.eql(__STATUS__);pm.expect(oldGD.delegatedBy).to.eql({type:'service_account',id:e.creatorId});pm.expect(oldG.status).to.eql(__STATUS__);pm.expect(oldG.delegationId).to.eql(oldGD.id);
  if(__STATUS__==='REVOKED')pm.expect(oldG.revocationReason).to.eql('REVOCATION_REASON_DELEGATION_REVOKED');
  const installed=p.delegations.filter(x=>x.delegate.id===e.issuerId);pm.expect(installed.length).to.eql(__GDCOUNT__);pm.expect(installed.filter(x=>x.accountId===e.tenantId&&x.status==='ACTIVE').length).to.eql(__TENANTACTIVE__);
  if(e.phase==='VERIFY'){pm.expect(e.operation.done).to.eql(true);pm.environment.set('rid06PrimaryOperationId',e.operation.id);}
 });
 keys.forEach(k=>{pm.environment.set('rid10Seen_'+k,'[]');pm.environment.set('rid10Listed_'+k,'{}');pm.environment.set('rid10Tokens_'+k,'[""]');pm.environment.set('rid10Page_'+k,'');pm.environment.set('rid10AccountIndex_'+k,'0');pm.environment.set('rid10Account_'+k,p.accounts[0].id);pm.environment.set('rid10GetIndex_'+k,'0');pm.environment.set('rid10GetId_'+k,p[k][0].id);pm.environment.set('rid10Got_'+k,'[]');});
 pm.environment.set('rid10GroupIndex','0');pm.environment.set('rid10GroupId',p.groups[0].id);pm.environment.set('rid10MembersSeen','{}');pm.environment.set('rid10MembersTokens','[""]');pm.environment.set('rid10MembersPage','');
}""".strip()
_POST=r"""
const op=pm.response.json();
pm.test('actual mutation returns one Operation handle',()=>pm.expect(op.id).to.be.a('string').and.not.empty);
pm.environment.set('rid06ActionOperationId',op.id);
""".strip()
_POLL=r"""
const e=JSON.parse(pm.environment.get('rid06Expected')),op=pm.response.json();
pm.test('same real Operation bounded polling',()=>{
 pm.expect(op.id).to.eql(pm.environment.get('rid06ActionOperationId'));
 pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid06ActionDeadline')));pm.expect(Number(pm.environment.get('rid06Polls'))).to.be.below(5000);
});
pm.environment.set('rid06Polls',String(Number(pm.environment.get('rid06Polls'))+1));
if(!op.done){pm.execution.setNextRequest(pm.info.requestName);}else{
 pm.test('done success exact requested response identity',()=>{
  pm.expect(op.error||null).to.eql(null);pm.expect(op.response.id).to.be.a('string').and.not.empty;
  if(e.path==='/iam/v1/accessBindings'){
   pm.expect(op.metadata.accessBindingId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.tenantId);pm.expect(op.response.delegationId).to.eql(e.installationDelegationId);
  }else{pm.expect(op.metadata.grantDelegationId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.request.accountId);}
 });
 pm.environment.set('rid06ActionResponse',JSON.stringify(op.response));pm.environment.set('rid06ActionResourceId',op.response.id);
}
""".strip()
_REVOKE_POLL=r"""const e=JSON.parse(pm.environment.get('rid06Expected')),op=pm.response.json();
pm.test('actual O-owned Revoke poll is same handle and within clipped deadline',()=>{pm.expect(op.id).to.eql(pm.environment.get('rid06ActionOperationId'));pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid06ActionDeadline')));pm.expect(Number(pm.environment.get('rid06Polls'))).to.be.below(5000);});
pm.environment.set('rid06Polls',String(Number(pm.environment.get('rid06Polls'))+1));
if(!op.done)pm.execution.setNextRequest(pm.info.requestName);else{pm.test('real committed Revoke exact ID/account/status, no replacement',()=>{pm.expect(op.error||null).to.eql(null);pm.expect(op.metadata.grantDelegationId).to.eql(e.oldDelegationId);pm.expect(op.metadata.accountId).to.eql(e.tenantId);pm.expect(op.response.id).to.eql(e.oldDelegationId);pm.expect(op.response.status).to.eql('REVOKED');pm.expect(op.response.accountId).to.eql(e.tenantId);});}
""".strip()
_PHASES=[('registry-installation-rid06-S1-BEFORE-REVOKE', 'S1', 'BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S1-REVOKE-ACT', 'S1', 'REVOKE-ACT', 'O', 'ACT', 'ACTIVE', False), ('registry-installation-rid06-S1-AFTER-REVOKE', 'S1', 'AFTER-REVOKE', 'O', 'VERIFY', 'REVOKED', False), ('registry-installation-rid06-S1-SEQUENTIAL-BEFORE-REVOKE', 'S1', 'SEQUENTIAL-BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S1-SEQUENTIAL-AFTER-OVERLAP', 'S1', 'SEQUENTIAL-AFTER-OVERLAP', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S1-AFTER-SEQUENTIAL-REFUSAL', 'S1', 'AFTER-SEQUENTIAL-REFUSAL', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S1-NO-REVOKE-BEFORE', 'S1', 'NO-REVOKE-BEFORE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S1-NO-REVOKE-TWIN', 'S1', 'NO-REVOKE-TWIN', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S1-RECOVERY-BEFORE-REVOKE', 'S1', 'RECOVERY-BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S1-RECOVERY-AFTER-REVOKE', 'S1', 'RECOVERY-AFTER-REVOKE', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S1-EXPLICIT-CREATE-ACT', 'S1', 'EXPLICIT-CREATE-ACT', 'C', 'ACT', 'REVOKED', False), ('registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY', 'S1', 'EXPLICIT-CREATE-VERIFY', 'O', 'VERIFY', 'REVOKED', True), ('registry-installation-rid06-S1-RECOVERY-REAPPLY', 'S1', 'RECOVERY-REAPPLY', 'O', 'READ', 'REVOKED', True), ('registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT', 'S1', 'EXPLICIT-RECOVERY-ACT', 'I', 'ACT', 'REVOKED', True), ('registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY', 'S1', 'EXPLICIT-RECOVERY-VERIFY', 'O', 'VERIFY', 'REVOKED', True), ('registry-installation-rid06-S2-BEFORE-REVOKE', 'S2', 'BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S2-REVOKE-ACT', 'S2', 'REVOKE-ACT', 'O', 'ACT', 'ACTIVE', False), ('registry-installation-rid06-S2-AFTER-REVOKE', 'S2', 'AFTER-REVOKE', 'O', 'VERIFY', 'REVOKED', False), ('registry-installation-rid06-S2-SEQUENTIAL-BEFORE-REVOKE', 'S2', 'SEQUENTIAL-BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S2-SEQUENTIAL-AFTER-OVERLAP', 'S2', 'SEQUENTIAL-AFTER-OVERLAP', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S2-AFTER-SEQUENTIAL-REFUSAL', 'S2', 'AFTER-SEQUENTIAL-REFUSAL', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S2-NO-REVOKE-BEFORE', 'S2', 'NO-REVOKE-BEFORE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S2-NO-REVOKE-TWIN', 'S2', 'NO-REVOKE-TWIN', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S2-RECOVERY-BEFORE-REVOKE', 'S2', 'RECOVERY-BEFORE-REVOKE', 'O', 'READ', 'ACTIVE', False), ('registry-installation-rid06-S2-RECOVERY-AFTER-REVOKE', 'S2', 'RECOVERY-AFTER-REVOKE', 'O', 'READ', 'REVOKED', False), ('registry-installation-rid06-S2-EXPLICIT-CREATE-ACT', 'S2', 'EXPLICIT-CREATE-ACT', 'C', 'ACT', 'REVOKED', False), ('registry-installation-rid06-S2-EXPLICIT-CREATE-VERIFY', 'S2', 'EXPLICIT-CREATE-VERIFY', 'O', 'VERIFY', 'REVOKED', True), ('registry-installation-rid06-S2-RECOVERY-REAPPLY', 'S2', 'RECOVERY-REAPPLY', 'O', 'READ', 'REVOKED', True), ('registry-installation-rid06-S2-EXPLICIT-RECOVERY-ACT', 'S2', 'EXPLICIT-RECOVERY-ACT', 'I', 'ACT', 'REVOKED', True), ('registry-installation-rid06-S2-EXPLICIT-RECOVERY-VERIFY', 'S2', 'EXPLICIT-RECOVERY-VERIFY', 'O', 'VERIFY', 'REVOKED', True)]
for case_id,mode,suffix,actor,phase,status,recovered in _PHASES:
 config=_CONFIG
 for k,v in {'__CASE__':js_str(case_id),'__MODE__':js_str(mode),'__PHASE__':js_str(phase),'__STATUS__':js_str(status),'__ACCOUNTS__':'2' if mode=='S1' else '4','__GDCOUNT__':str((1 if mode=='S1' else 3)+int(recovered)),'__TENANTACTIVE__':'1' if status=='ACTIVE' or recovered else '0','__MISSING__':'\n'.join(precondition_not_met('RID06 closed full primary premise','Missing/incompatible RID06 fixture; no public verdict',indent=' '))}.items():config=config.replace(k,v)
 critical=suffix=='REVOKE-ACT'
 steps=[] if critical else [Step(name='same-ordinary-O',method='GET',path='/iam/v1/me',auth='jwtRIDOperator',pre_script=config.splitlines(),test_script=[*assert_status(200),"const e=JSON.parse(pm.environment.get('rid06Expected'));pm.test('verified independent O',()=>{pm.expect(pm.response.json().subject).to.eql('user:'+e.operatorId);pm.expect(pm.response.json().userId).to.eql(e.operatorId);});"])]
 if not critical:steps+=midrun_read_steps(Step,assert_status,js_str,expected_var='rid06Expected')
 if phase=='ACT':
  credential='jwtRIDOperator' if critical else 'jwtRIDCreator' if actor=='C' else 'jwtRIDIssuer'
  if not critical:steps.append(Step(name='actual-caller',method='GET',path='/iam/v1/me',auth=credential,test_script=[*assert_status(200),"const e=JSON.parse(pm.environment.get('rid06Expected'));pm.test('same actual caller',()=>pm.expect(pm.response.json().subject).to.eql('service_account:'+e.actor));"]))
  pre=config.splitlines() if critical else []
  pre += ["const actionExpected=JSON.parse(pm.environment.get('rid06Expected'));pm.environment.set('rid06OldGD',actionExpected.oldDelegationId);pm.request.body.update(JSON.stringify(actionExpected.request));pm.environment.set('rid06Polls','0');pm.environment.set('rid06ActionDeadline',String(actionExpected.actionDeadline?Date.parse(actionExpected.actionDeadline):Date.now()+30000));"]
  steps.append(Step(name='actual-revoke' if critical else 'actual-action',method='POST',path='/iam/v1/grantDelegations/{{rid06OldGD}}:revoke' if critical else '/iam/v1/grantDelegations' if actor=='C' else '/iam/v1/accessBindings',auth=credential,body={},pre_script=pre,test_script=[*assert_status(200),*_POST.splitlines()]))
  steps.append(Step(name='actual-owner-Operation-Get',method='GET',path='/operations/{{rid06ActionOperationId}}',auth=credential,test_script=[*assert_status(200),*(_REVOKE_POLL if critical else _POLL).splitlines()]))
 if phase=='VERIFY':
  if suffix=='AFTER-REVOKE':steps.append(Step(name='primary-owned-Operation-Get',method='GET',path='/operations/{{rid06PrimaryOperationId}}',auth='jwtRIDOperator',test_script=[*assert_status(200),"pm.test('full actual O-owned Operation equals independent primary',()=>pm.expect(pm.response.json()).to.eql(JSON.parse(pm.environment.get('rid06Expected')).operation));"]))
  else:steps.append(Step(name='primary-hidden-Operation-Get',method='GET',path='/operations/{{rid06PrimaryOperationId}}',auth='jwtRIDOperator',test_script=[*assert_status(404),"const e=JSON.parse(pm.environment.get('rid06Expected'));pm.test('independent O is not caller Operation owner, no leak',()=>pm.expect(pm.response.json()).to.eql({code:5,message:'operation '+e.operation.id+' not found',details:[]}));"]))
 CASES.append(Case(id=case_id,title='RID06 public '+mode+' '+suffix,classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES=address_own_front(CASES,'RID06 ordinary isolated public HTTPS; critical original pause is never extended')
