# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID05 same8nativeworlds: deleted originalC, distinct nativeC2, honest Delete executor.
All standalone API requests are real HTTPS; no startup/admin RPC substitution.
Opaque original-C assertion gets only its exact parent-owned issuance leaf.
"""
from rid_midrun_public import midrun_read_steps
HOME='kaname'
CASES=[]
_CONFIG=r"""const e=JSON.parse(pm.environment.get('rid05Expected')||'null');
const keys=['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid=e && e.caseId===__CASE__ && e.mode===__MODE__ && e.phase===__PHASE__ &&
 e.operatorId && e.creatorId && e.oldCreatorId===e.creatorId && e.issuerId && e.systemId && e.tenantId && e.installationDelegationId &&
 e.oldGrantId && e.oldDelegationId && e.creatorPresent===__PRESENT__ && e.oldGrantStatus===__OLDSTATUS__ && e.snapshot && e.snapshot.projection &&
 keys.every(k=>Array.isArray(e.snapshot.projection[k])) && e.snapshot.projection.catalog && e.snapshot.projection.members;
if(!valid){
__MISSING__
}else{
 const p=e.snapshot.projection;
 pm.test('RID05 complete primary identities and undeletable historical creator',()=>{
  keys.forEach(k=>{pm.expect(p[k].length).to.be.above(0);pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length);});
  pm.expect(p.accounts.length).to.eql(__ACCOUNTS__);pm.expect(Object.keys(p.members).sort()).to.eql(p.groups.map(x=>x.id).sort());
  pm.expect(p.groups.filter(g=>g.accountId===e.systemId && g.name==='module-relation-writers').length).to.eql(1);
  const issuer=p.serviceAccounts.find(x=>x.id===e.issuerId);pm.expect(issuer.enabled).to.eql(true);pm.expect(issuer.accountId).to.eql(e.systemId);
  pm.expect(p.serviceAccounts.some(x=>x.id===e.oldCreatorId)).to.eql(__PRESENT__);
  if(__C2__){const c2=p.serviceAccounts.find(x=>x.id===e.replacementCreatorId);pm.expect(c2).to.be.an('object');pm.expect(c2.id).not.to.eql(e.oldCreatorId);pm.expect(c2.name).to.eql('rid-native-standing-creator');pm.expect(c2.accountId).to.eql(e.systemId);}
  else pm.expect(e.replacementCreatorId||'').to.eql('');
  const old=p.bindings.find(g=>g.id===e.oldGrantId);pm.expect(old.status).to.eql(__OLDSTATUS__);pm.expect(old.delegationId).to.eql(e.oldDelegationId);
  const oldGD=p.delegations.find(g=>g.id===e.oldDelegationId);pm.expect(oldGD.status).to.eql(__OLDSTATUS__);pm.expect(oldGD.delegatedBy).to.eql({type:'service_account',id:e.oldCreatorId});
  const installed=p.delegations.filter(g=>g.delegate.id===e.issuerId);pm.expect(installed.length).to.eql(__GDCOUNT__);
  installed.forEach(g=>{pm.expect(g.module).to.eql('registry');pm.expect(g.delegatedBy.id).to.eql(g.status==='REVOKED'?e.oldCreatorId:(__RECOVERY__?e.replacementCreatorId:e.oldCreatorId));});
  p.bindings.filter(g=>g.status==='ACTIVE').forEach(g=>{pm.expect(g.subjectType==='service_account' && g.subjectId===e.oldCreatorId).to.eql(false);(g.subjects||[]).forEach(x=>pm.expect(['service_account','SUBJECT_TYPE_SERVICE_ACCOUNT'].includes(x.type)&&x.id===e.oldCreatorId).to.eql(false));});
  Object.values(p.members).flat().forEach(m=>pm.expect(m.memberType==='service_account'&&m.memberId===e.oldCreatorId).to.eql(false));
  const refs=p.delegations.filter(g=>g.status==='ACTIVE'&&g.delegate.id===e.oldCreatorId);
  if(__BLOCKING__){pm.expect(refs.map(g=>g.id)).to.eql([e.blockingDelegationId]);}else pm.expect(refs).to.eql([]);
  if(e.phase==='VERIFY'&&__DELETE__){pm.expect(e.operation.done).to.eql(true);pm.environment.set('rid05PrimaryOperationId',e.operation.id);}
  else if(e.phase==='VERIFY'&&!e.denied){pm.expect(e.operation.done).to.eql(true);pm.expect(e.resource.status).to.eql('ACTIVE');pm.expect(e.resource.delegationId).to.eql(e.installationDelegationId);pm.expect(p.bindings.find(g=>g.id===e.resource.id)).to.eql(e.resource);pm.environment.set('rid05PrimaryOperationId',e.operation.id);}
  else{pm.expect(e.operation||null).to.eql(null);pm.expect(e.resource||null).to.eql(null);}
 });
 keys.forEach(k=>{pm.environment.set('rid10Seen_'+k,'[]');pm.environment.set('rid10Listed_'+k,'{}');pm.environment.set('rid10Tokens_'+k,'[""]');pm.environment.set('rid10Page_'+k,'');pm.environment.set('rid10AccountIndex_'+k,'0');pm.environment.set('rid10Account_'+k,p.accounts[0].id);pm.environment.set('rid10GetIndex_'+k,'0');pm.environment.set('rid10GetId_'+k,p[k][0].id);pm.environment.set('rid10Got_'+k,'[]');});
 pm.environment.set('rid10GroupIndex','0');pm.environment.set('rid10GroupId',p.groups[0].id);pm.environment.set('rid10MembersSeen','{}');pm.environment.set('rid10MembersTokens','[""]');pm.environment.set('rid10MembersPage','');
}""".strip()
_POST=r"""
const op=pm.response.json();
pm.test('actual mutation returns one Operation handle',()=>pm.expect(op.id).to.be.a('string').and.not.empty);
pm.environment.set('rid05ActionOperationId',op.id);
""".strip()
_POLL=r"""
const e=JSON.parse(pm.environment.get('rid05Expected')),op=pm.response.json();
pm.test('same real Operation bounded polling',()=>{
 pm.expect(op.id).to.eql(pm.environment.get('rid05ActionOperationId'));
 pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid05ActionDeadline')));pm.expect(Number(pm.environment.get('rid05Polls'))).to.be.below(5000);
});
pm.environment.set('rid05Polls',String(Number(pm.environment.get('rid05Polls'))+1));
if(!op.done){pm.execution.setNextRequest(pm.info.requestName);}else{
 pm.test('done success exact requested response identity',()=>{
  pm.expect(op.error||null).to.eql(null);pm.expect(op.response.id).to.be.a('string').and.not.empty;
  if(e.path==='/iam/v1/accessBindings'){
   pm.expect(op.metadata.accessBindingId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.tenantId);pm.expect(op.response.delegationId).to.eql(e.installationDelegationId);
  }else{pm.expect(op.metadata.grantDelegationId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.request.accountId);}
 });
 pm.environment.set('rid05ActionResponse',JSON.stringify(op.response));pm.environment.set('rid05ActionResourceId',op.response.id);
}
""".strip()
_DELETE_POLL=r"""const e=JSON.parse(pm.environment.get('rid05Expected')),op=pm.response.json();
pm.test('same actual O-owned Delete Operation and deadline',()=>{pm.expect(op.id).to.eql(pm.environment.get('rid05ActionOperationId'));pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid05ActionDeadline')));pm.expect(Number(pm.environment.get('rid05Polls'))).to.be.below(5000);});
pm.environment.set('rid05Polls',String(Number(pm.environment.get('rid05Polls'))+1));
if(!op.done)pm.execution.setNextRequest(pm.info.requestName);else{
 pm.test('exact normal asynchronous Delete outcome',()=>{
  const c=e.deleteContract,creator=e.snapshot.projection.serviceAccounts.find(sa=>sa.id===e.oldCreatorId);
  pm.expect(!!c&&c.caseId===e.caseId&&c.resourceId===e.oldCreatorId&&creator&&c.accountId===creator.accountId&&c.operatorId===e.operatorId).to.eql(true);
  pm.expect(op.done).to.eql(true);
  // The full canonical typed skeleton is derived BEFORE this mutation. Only
  // allocated Operation ID and its two clocks are dynamic, and each is checked.
  pm.expect(Object.keys(op).sort()).to.eql(Object.keys(c.operation).sort());
  Object.keys(c.operation).filter(k=>!['id','createdAt','modifiedAt'].includes(k)).forEach(k=>pm.expect(op[k]).to.eql(c.operation[k]));
  const created=Date.parse(op.createdAt),modified=Date.parse(op.modifiedAt),lower=Date.parse(c.notBefore),upper=Date.parse(c.notAfter);
  pm.expect(Number.isFinite(created)&&Number.isFinite(modified)&&Number.isFinite(lower)&&Number.isFinite(upper)&&created>=lower&&created<=modified&&modified<=upper).to.eql(true);
 });
}""".strip()
_PHASES=[
 ('registry-installation-rid05-S1-KEYS-AND-REFERENCES-CLEAN', 'S1', 'KEYS-AND-REFERENCES-CLEAN', 'KEYS-AND-REFERENCES-CLEAN', 'READ', False, False, False, False, True),
 ('registry-installation-rid05-S1-DELETED-C-SNAPSHOT', 'S1', 'DELETED-C-SNAPSHOT', 'DELETED-C-SNAPSHOT', 'READ', False, False, False, False, False),
 ('registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED', 'S1', 'OLD-C-TOKEN-REFUSED', 'OLD-C-TOKEN-REFUSED', 'READ', False, True, False, False, False),
 ('registry-installation-rid05-S1-DELETED-C-GRANT-ACT', 'S1', 'DELETED-C-GRANT-ACT', 'DELETED-C-GRANT', 'ACT', False, False, False, False, False),
 ('registry-installation-rid05-S1-DELETED-C-GRANT-VERIFY', 'S1', 'DELETED-C-GRANT-VERIFY', 'DELETED-C-GRANT', 'VERIFY', False, False, False, False, False),
 ('registry-installation-rid05-S1-SAME-NAME-C2-SNAPSHOT', 'S1', 'SAME-NAME-C2-SNAPSHOT', 'SAME-NAME-C2-SNAPSHOT', 'READ', False, False, False, True, False),
 ('registry-installation-rid05-S1-C2-NO-REVIVAL-ACT', 'S1', 'C2-NO-REVIVAL-ACT', 'C2-NO-REVIVAL', 'ACT', False, False, False, True, False),
 ('registry-installation-rid05-S1-C2-NO-REVIVAL-VERIFY', 'S1', 'C2-NO-REVIVAL-VERIFY', 'C2-NO-REVIVAL', 'VERIFY', False, False, False, True, False),
 ('registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT', 'S1', 'ACTIVE-DELEGATE-DELETE-ACT', 'ACTIVE-DELEGATE-DELETE', 'ACT', True, False, False, False, True),
 ('registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY', 'S1', 'ACTIVE-DELEGATE-DELETE-VERIFY', 'ACTIVE-DELEGATE-DELETE', 'VERIFY', True, False, False, False, True),
 ('registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT', 'S1', 'REVOKE-ONLY-DELETE-TWIN-ACT', 'REVOKE-ONLY-DELETE-TWIN', 'ACT', True, False, False, False, True),
 ('registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-VERIFY', 'S1', 'REVOKE-ONLY-DELETE-TWIN-VERIFY', 'REVOKE-ONLY-DELETE-TWIN', 'VERIFY', True, False, False, False, False),
 ('registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT', 'S1', 'EXPLICIT-C2-RECOVERY-ACT', 'EXPLICIT-C2-RECOVERY', 'ACT', False, False, True, True, False),
 ('registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY', 'S1', 'EXPLICIT-C2-RECOVERY-VERIFY', 'EXPLICIT-C2-RECOVERY', 'VERIFY', False, False, True, True, False),
 ('registry-installation-rid05-S1-RECOVERY-REAPPLY', 'S1', 'RECOVERY-REAPPLY', 'RECOVERY-REAPPLY', 'READ', False, False, True, True, False),
 ('registry-installation-rid05-S2-KEYS-AND-REFERENCES-CLEAN', 'S2', 'KEYS-AND-REFERENCES-CLEAN', 'KEYS-AND-REFERENCES-CLEAN', 'READ', False, False, False, False, True),
 ('registry-installation-rid05-S2-DELETED-C-SNAPSHOT', 'S2', 'DELETED-C-SNAPSHOT', 'DELETED-C-SNAPSHOT', 'READ', False, False, False, False, False),
 ('registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED', 'S2', 'OLD-C-TOKEN-REFUSED', 'OLD-C-TOKEN-REFUSED', 'READ', False, True, False, False, False),
 ('registry-installation-rid05-S2-DELETED-C-GRANT-ACT', 'S2', 'DELETED-C-GRANT-ACT', 'DELETED-C-GRANT', 'ACT', False, False, False, False, False),
 ('registry-installation-rid05-S2-DELETED-C-GRANT-VERIFY', 'S2', 'DELETED-C-GRANT-VERIFY', 'DELETED-C-GRANT', 'VERIFY', False, False, False, False, False),
 ('registry-installation-rid05-S2-SAME-NAME-C2-SNAPSHOT', 'S2', 'SAME-NAME-C2-SNAPSHOT', 'SAME-NAME-C2-SNAPSHOT', 'READ', False, False, False, True, False),
 ('registry-installation-rid05-S2-C2-NO-REVIVAL-ACT', 'S2', 'C2-NO-REVIVAL-ACT', 'C2-NO-REVIVAL', 'ACT', False, False, False, True, False),
 ('registry-installation-rid05-S2-C2-NO-REVIVAL-VERIFY', 'S2', 'C2-NO-REVIVAL-VERIFY', 'C2-NO-REVIVAL', 'VERIFY', False, False, False, True, False),
 ('registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT', 'S2', 'ACTIVE-DELEGATE-DELETE-ACT', 'ACTIVE-DELEGATE-DELETE', 'ACT', True, False, False, False, True),
 ('registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-VERIFY', 'S2', 'ACTIVE-DELEGATE-DELETE-VERIFY', 'ACTIVE-DELEGATE-DELETE', 'VERIFY', True, False, False, False, True),
 ('registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT', 'S2', 'REVOKE-ONLY-DELETE-TWIN-ACT', 'REVOKE-ONLY-DELETE-TWIN', 'ACT', True, False, False, False, True),
 ('registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-VERIFY', 'S2', 'REVOKE-ONLY-DELETE-TWIN-VERIFY', 'REVOKE-ONLY-DELETE-TWIN', 'VERIFY', True, False, False, False, False),
 ('registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT', 'S2', 'EXPLICIT-C2-RECOVERY-ACT', 'EXPLICIT-C2-RECOVERY', 'ACT', False, False, True, True, False),
 ('registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-VERIFY', 'S2', 'EXPLICIT-C2-RECOVERY-VERIFY', 'EXPLICIT-C2-RECOVERY', 'VERIFY', False, False, True, True, False),
 ('registry-installation-rid05-S2-RECOVERY-REAPPLY', 'S2', 'RECOVERY-REAPPLY', 'RECOVERY-REAPPLY', 'READ', False, False, True, True, False),
]
for case_id,mode,suffix,scenario,phase,delete,token,recovery,c2,present in _PHASES:
 denied=scenario in ('DELETED-C-GRANT','C2-NO-REVIVAL','ACTIVE-DELEGATE-DELETE')
 config=_CONFIG
 for key,value in {'__CASE__':js_str(case_id),'__MODE__':js_str(mode),'__PHASE__':js_str(phase),'__PRESENT__':'true' if present else 'false','__OLDSTATUS__':js_str('REVOKED' if recovery else 'ACTIVE'),'__C2__':'true' if c2 else 'false','__RECOVERY__':'true' if recovery else 'false','__BLOCKING__':'true' if scenario=='ACTIVE-DELEGATE-DELETE' else 'false','__DELETE__':'true' if delete else 'false','__ACCOUNTS__':'4' if mode=='S2' else '2','__GDCOUNT__':str((3 if mode=='S2' else 1)*(2 if recovery else 1)),
 '__MISSING__':'\n'.join(precondition_not_met('RID05 closed literal primary identity','Missing/incompatible RID05 fixture; no public verdict',indent='  '))}.items():config=config.replace(key,value)
 steps=[Step(name='same-ordinary-O',method='GET',path='/iam/v1/me',auth='jwtRIDOperator',pre_script=config.splitlines(),test_script=[*assert_status(200),"const e=JSON.parse(pm.environment.get('rid05Expected')),j=pm.response.json();pm.test('same verified independent O',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
 steps+=midrun_read_steps(Step,assert_status,js_str,expected_var='rid05Expected')
 if not present:
  steps.append(Step(name='deleted-original-C-Get',method='GET',path='/iam/v1/serviceAccounts/{{rid05OldCreator}}',auth='jwtRIDOperator',pre_script=["pm.environment.set('rid05OldCreator',JSON.parse(pm.environment.get('rid05Expected')).oldCreatorId);"],test_script=[*assert_status(404),"pm.test('oldC exact absent identity, never C2 substitution',()=>{const j=pm.response.json();pm.expect(j.code).to.eql(5);pm.expect(j.id).to.eql(undefined);});"]))
 if suffix=='KEYS-AND-REFERENCES-CLEAN':
  steps.append(Step(name='all-original-C-key-pages-empty',method='GET',path='/iam/v1/serviceAccounts/{{rid05OldCreator}}/keys?pageSize=2',auth='jwtRIDOperator',pre_script=["pm.environment.set('rid05OldCreator',JSON.parse(pm.environment.get('rid05Expected')).oldCreatorId);"],test_script=[*assert_status(200),"pm.test('primary0 allkeyinventory: no fabricated Get for empty keys',()=>{const j=pm.response.json();pm.expect(j.keys).to.eql([]);pm.expect(j.nextPageToken||'').to.eql('');});"]))
 if token:
  steps.append(Step(name='old-standing-key-token-refusal',method='POST',path='/iam/v1/token',auth='anonymous',follow_redirects=False,cookie_jar=False,form=[('grant_type','client_credentials'),('client_assertion_type','urn:ietf:params:oauth:client-assertion-type:jwt-bearer'),('client_assertion','{{rid05ClientAssertion}}'),('audience','https://kaname.local')],pre_script=["const e=JSON.parse(pm.environment.get('rid05Expected'));pm.test('fresh originalC signature before real authn request',()=>pm.expect(Date.now()).to.be.below(Date.parse(e.assertionExpiresAt)));pm.request.url=pm.environment.get('rid05IssuanceOrigin')+'/iam/v1/token';"],test_script=[*assert_status(401),"pm.test('revoked/deleted original standing credential refused, no sole-cause claim',()=>pm.expect(pm.response.json().error).to.eql('invalid_client'));"]))
 if phase=='ACT':
  if not delete:steps.append(Step(name='actual-I',method='GET',path='/iam/v1/me',auth='jwtRIDIssuer',test_script=[*assert_status(200),"const e=JSON.parse(pm.environment.get('rid05Expected'));pm.test('genuine same issuer',()=>pm.expect(pm.response.json().subject).to.eql('service_account:'+e.issuerId));"]))
  outcome=[*assert_status(403),"pm.test('synchronous oldcreator/no-revival grant refusal',()=>{const j=pm.response.json();pm.expect(j.code).to.eql(7);pm.expect(j.message).to.eql('permission denied');pm.expect(j.id).to.eql(undefined);});"] if denied and not delete else [*assert_status(200),*_POST.splitlines()]
  path='/iam/v1/serviceAccounts/{{rid05DeleteCreator}}' if delete else '/iam/v1/accessBindings'
  pre=["const e=JSON.parse(pm.environment.get('rid05Expected'));pm.environment.set('rid05DeleteCreator',e.oldCreatorId);pm.environment.set('rid05ActionDeadline',String(Date.now()+30000));pm.environment.set('rid05Polls','0');"]
  if not delete:pre.append("pm.request.body.update(JSON.stringify(JSON.parse(pm.environment.get('rid05Expected')).request));")
  if delete:steps.append(Step(name='actual-delete',method='DELETE',path=path,auth='jwtRIDOperator',pre_script=pre,test_script=outcome))
  else:steps.append(Step(name='actual-action',method='POST',path=path,auth='jwtRIDIssuer',body={},pre_script=pre,test_script=outcome))
  if delete or not denied:steps.append(Step(name='actual-owner-Operation-Get',method='GET',path='/operations/{{rid05ActionOperationId}}',auth='jwtRIDOperator' if delete else 'jwtRIDIssuer',test_script=[*assert_status(200),*(_DELETE_POLL if delete else _POLL).splitlines()]))
 elif phase=='VERIFY' and (delete or not denied):
  if delete:steps.append(Step(name='independent-primary-owned-Operation-Get',method='GET',path='/operations/{{rid05PrimaryOperationId}}',auth='jwtRIDOperator',test_script=[*assert_status(200),"pm.test('full actual O-owned Operation equals independent primary',()=>pm.expect(pm.response.json()).to.eql(JSON.parse(pm.environment.get('rid05Expected')).operation));"]))
  else:steps.append(Step(name='independent-primary-hidden-Operation-Get',method='GET',path='/operations/{{rid05PrimaryOperationId}}',auth='jwtRIDOperator',test_script=[*assert_status(404),"const e=JSON.parse(pm.environment.get('rid05Expected'));pm.test('O is not I Operation owner',()=>pm.expect(pm.response.json()).to.eql({code:5,message:'operation '+e.operation.id+' not found',details:[]}));"]))
 CASES.append(Case(id=case_id,title='RID05 public '+mode+' '+suffix,classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES=address_own_front(CASES,'RID05 ordinary isolated public HTTPS; tokenleaf uses only parent-scoped owned issuance')
