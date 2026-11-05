# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID04: same-world current-creator retirement/refusal/explicit recovery.

Only I ACT POST mutates public state. Fullserve/RevokeAdmin/GrantAdmin remain
native integration boundaries. EVERY Get/List in O-only VERIFY uses independent
post-ACT primary input. No RID03 ACT Get metadata or response self-oracle.
"""
HOME = 'kaname'
CASES = []
_CONFIG = r"""const e=JSON.parse(pm.environment.get('rid04Expected')||'null');
const keys=['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid=e && e.caseId===__CASE__ && e.mode===__MODE__ && e.phase===__PHASE__ &&
 e.operatorId && e.creatorId && e.issuerId && e.systemId && e.tenantId && e.installationDelegationId &&
 e.oldGrantId && e.actor===e.issuerId && e.creatorAuthority===__AUTHORITY__ && e.snapshot && e.snapshot.projection &&
 keys.every(k=>Array.isArray(e.snapshot.projection[k])) && e.snapshot.projection.catalog && e.snapshot.projection.members &&
 (e.phase==='READ' || (e.scenario===__SCENARIO__ && e.denied===__DENIED__ && e.request && e.path==='/iam/v1/accessBindings'));
if(!valid){
__MISSING__
}else{
 const p=e.snapshot.projection;
 pm.test('RID04 full same-world primary identities/history and current-authority premise',()=>{
  keys.forEach(k=>{pm.expect(p[k].length).to.be.above(0);pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length);});
  pm.expect(p.accounts.length).to.eql(__ACCOUNTS__);
  pm.expect(Object.keys(p.members).sort()).to.eql(p.groups.map(x=>x.id).sort());
  pm.expect(p.groups.filter(g=>g.accountId===e.systemId && g.name==='module-relation-writers').length).to.eql(1);
  const issuer=p.serviceAccounts.find(x=>x.id===e.issuerId);pm.expect(issuer.enabled).to.eql(true);pm.expect(issuer.accountId).to.eql(e.systemId);
  const creator=p.serviceAccounts.find(x=>x.id===e.creatorId);pm.expect(creator.enabled).to.eql(true);pm.expect(creator.accountId).to.eql(e.systemId);pm.expect(e.issuerId).not.to.eql(e.creatorId);
  const installed=p.delegations.filter(g=>g.delegate.id===e.issuerId);pm.expect(installed.length).to.eql(__N__);
  installed.forEach(g=>{pm.expect(g.status).to.eql('ACTIVE');pm.expect(g.module).to.eql('registry');pm.expect(g.delegatedBy).to.eql({type:'service_account',id:e.creatorId});});
  pm.expect(installed.map(g=>g.id)).to.include(e.installationDelegationId);
  const old=p.bindings.find(g=>g.id===e.oldGrantId);pm.expect(old.status).to.eql('ACTIVE');pm.expect(old.delegationId).to.eql(e.installationDelegationId);pm.expect(old.materializedAt).to.be.a('string').and.not.empty;
  if(e.phase==='VERIFY' && !e.denied){
   pm.expect(e.operation.done).to.eql(true);pm.expect(e.operation.error||null).to.eql(null);
   pm.expect(e.resource.status).to.eql('ACTIVE');pm.expect(e.resource.delegationId).to.eql(e.installationDelegationId);
   pm.expect(p.bindings.find(g=>g.id===e.resource.id)).to.eql(e.resource);
   pm.environment.set('rid04PrimaryOperationId',e.operation.id);
  }else{pm.expect(e.operation||null).to.eql(null);pm.expect(e.resource||null).to.eql(null);}
 });
 keys.forEach(k=>{
  pm.environment.set('rid10Seen_'+k,'[]');pm.environment.set('rid10Listed_'+k,'{}');pm.environment.set('rid10Tokens_'+k,'[""]');pm.environment.set('rid10Page_'+k,'');
  pm.environment.set('rid10AccountIndex_'+k,'0');pm.environment.set('rid10Account_'+k,p.accounts[0].id);
  pm.environment.set('rid10GetIndex_'+k,'0');pm.environment.set('rid10GetId_'+k,p[k][0].id);pm.environment.set('rid10Got_'+k,'[]');
 });
 pm.environment.set('rid10GroupIndex','0');pm.environment.set('rid10GroupId',p.groups[0].id);
 pm.environment.set('rid10MembersSeen','{}');pm.environment.set('rid10MembersTokens','[""]');pm.environment.set('rid10MembersPage','');
}""".strip()
_POST = r"""
const op=pm.response.json();
pm.test('actual mutation returns one Operation handle',()=>pm.expect(op.id).to.be.a('string').and.not.empty);
pm.environment.set('rid04ActionOperationId',op.id);
""".strip()
_POLL = r"""
const e=JSON.parse(pm.environment.get('rid04Expected')),op=pm.response.json();
pm.test('same real Operation bounded polling',()=>{
 pm.expect(op.id).to.eql(pm.environment.get('rid04ActionOperationId'));
 pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid04ActionDeadline')));pm.expect(Number(pm.environment.get('rid04Polls'))).to.be.below(5000);
});
pm.environment.set('rid04Polls',String(Number(pm.environment.get('rid04Polls'))+1));
if(!op.done){pm.execution.setNextRequest(pm.info.requestName);}else{
 pm.test('done success exact requested response identity',()=>{
  pm.expect(op.error||null).to.eql(null);pm.expect(op.response.id).to.be.a('string').and.not.empty;
  if(e.path==='/iam/v1/accessBindings'){
   pm.expect(op.metadata.accessBindingId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.tenantId);pm.expect(op.response.delegationId).to.eql(e.installationDelegationId);
  }else{pm.expect(op.metadata.grantDelegationId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.request.accountId);}
 });
 pm.environment.set('rid04ActionResponse',JSON.stringify(op.response));pm.environment.set('rid04ActionResourceId',op.response.id);
}
""".strip()
_PHASES = [
    ('registry-installation-rid04-S1-BEFORE-RETIREMENT', 'S1', 'BEFORE-RETIREMENT', '', 'READ'),
    ('registry-installation-rid04-S1-RETIRED-DENIED-ACT', 'S1', 'RETIRED-DENIED-ACT', 'RETIRED-DENIED', 'ACT'),
    ('registry-installation-rid04-S1-RETIRED-DENIED-VERIFY', 'S1', 'RETIRED-DENIED-VERIFY', 'RETIRED-DENIED', 'VERIFY'),
    ('registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT', 'S1', 'REFUSED-APPLY-SNAPSHOT', '', 'READ'),
    ('registry-installation-rid04-S1-RESTORED-GRANT-ACT', 'S1', 'RESTORED-GRANT-ACT', 'RESTORED-GRANT', 'ACT'),
    ('registry-installation-rid04-S1-RESTORED-GRANT-VERIFY', 'S1', 'RESTORED-GRANT-VERIFY', 'RESTORED-GRANT', 'VERIFY'),
    ('registry-installation-rid04-S1-RESTORED-REAPPLY', 'S1', 'RESTORED-REAPPLY', '', 'READ'),
    ('registry-installation-rid04-S2-BEFORE-RETIREMENT', 'S2', 'BEFORE-RETIREMENT', '', 'READ'),
    ('registry-installation-rid04-S2-RETIRED-DENIED-ACT', 'S2', 'RETIRED-DENIED-ACT', 'RETIRED-DENIED', 'ACT'),
    ('registry-installation-rid04-S2-RETIRED-DENIED-VERIFY', 'S2', 'RETIRED-DENIED-VERIFY', 'RETIRED-DENIED', 'VERIFY'),
    ('registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT', 'S2', 'REFUSED-APPLY-SNAPSHOT', '', 'READ'),
    ('registry-installation-rid04-S2-RESTORED-GRANT-ACT', 'S2', 'RESTORED-GRANT-ACT', 'RESTORED-GRANT', 'ACT'),
    ('registry-installation-rid04-S2-RESTORED-GRANT-VERIFY', 'S2', 'RESTORED-GRANT-VERIFY', 'RESTORED-GRANT', 'VERIFY'),
    ('registry-installation-rid04-S2-RESTORED-REAPPLY', 'S2', 'RESTORED-REAPPLY', '', 'READ'),
]
for case_id, mode, suffix, scenario, phase in _PHASES:
    denied = scenario == 'RETIRED-DENIED'
    authority = suffix == 'BEFORE-RETIREMENT' or suffix.startswith('RESTORED-')
    config = _CONFIG
    for key,value in {
        '__CASE__':js_str(case_id),'__MODE__':js_str(mode),'__PHASE__':js_str(phase),
        '__SCENARIO__':js_str(scenario),'__DENIED__':'true' if denied else 'false',
        '__AUTHORITY__':'true' if authority else 'false','__N__':'3' if mode=='S2' else '1',
        '__ACCOUNTS__':'4' if mode=='S2' else '2',
        '__MISSING__':'\n'.join(precondition_not_met('RID04 complete primary and exact literal stage',
            'Missing/incompatible independent RID04 fixture; no public verdict',indent='  ')),
    }.items(): config=config.replace(key,value)
    steps=[Step(name='same-ordinary-O',method='GET',path='/iam/v1/me',auth='jwtRIDOperator',
        pre_script=config.splitlines(),test_script=[*assert_status(200),
        "const e=JSON.parse(pm.environment.get('rid04Expected')),j=pm.response.json();",
        "pm.test('independent ordinary verified O survives retirement',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
    steps+=midrun_read_steps(Step,assert_status,js_str,expected_var='rid04Expected')
    if phase=='ACT':
        steps.append(Step(name='actual-I',method='GET',path='/iam/v1/me',auth='jwtRIDIssuer',
            test_script=[*assert_status(200),"const e=JSON.parse(pm.environment.get('rid04Expected'));",
                "pm.test('genuine renewed I, not C/O substitute',()=>pm.expect(pm.response.json().subject).to.eql('service_account:'+e.issuerId));"]))
        result=[*assert_status(403),"pm.test('retired current creator causes synchronous permission refusal',()=>{const j=pm.response.json();pm.expect(j.code).to.eql(7);pm.expect(j.message).to.eql('permission denied');pm.expect(j.id).to.eql(undefined);});"] if denied else [*assert_status(200),*_POST.splitlines()]
        steps.append(Step(name='actual-action',method='POST',path='/iam/v1/accessBindings',auth='jwtRIDIssuer',body={},
            pre_script=["const e=JSON.parse(pm.environment.get('rid04Expected'));pm.request.body.update(JSON.stringify(e.request));pm.environment.set('rid04ActionDeadline',String(Date.now()+30000));pm.environment.set('rid04Polls','0');"],test_script=result))
        if not denied:
            steps.append(Step(name='actual-owner-Operation-Get',method='GET',path='/operations/{{rid04ActionOperationId}}',auth='jwtRIDIssuer',test_script=[*assert_status(200),*_POLL.splitlines()]))
    elif phase=='VERIFY' and not denied:
        steps.append(Step(name='independent-primary-Operation-Get',method='GET',path='/operations/{{rid04PrimaryOperationId}}',auth='jwtRIDOperator',test_script=[*assert_status(404),
            "pm.test('O exact owner-hidden Operation refusal without leak',()=>{const j=pm.response.json();pm.expect(j).to.eql({code:5,message:'operation '+JSON.parse(pm.environment.get('rid04Expected')).operation.id+' not found',details:[]});});"]))
    CASES.append(Case(id=case_id,title='RID04 public '+mode+' '+suffix,classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES=address_own_front(CASES,'RID04 same isolated standalone public HTTPS origin')
