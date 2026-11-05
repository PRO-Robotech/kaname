# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real I/C ACT, parent primary delta, then O-only VERIFY in the SAME world.

ACT returned IDs only connect its own Operation/Get requests. VERIFY receives
independent primary IDs, never report bodies. Common census is reused unchanged.
"""
HOME = 'kaname'
CASES = []
_CONFIG = r"""
const e=JSON.parse(pm.environment.get('rid03Expected')||'null');
const keys=['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid=e && e.caseId===__CASE__ && e.mode===__MODE__ && e.scenario===__SCENARIO__ && e.phase===__PHASE__ &&
 e.operatorId && e.creatorId && e.issuerId && e.systemId && e.tenantId && e.installationDelegationId &&
 e.actor===__ACTOR__ && e.denied===__DENIED__ && e.path===__PATH__ && e.request && e.snapshot && e.snapshot.projection &&
 keys.every(k=>Array.isArray(e.snapshot.projection[k])) && e.snapshot.projection.catalog && e.snapshot.projection.members;
if(!valid){
__MISSING__
}else{
 const p=e.snapshot.projection;
 pm.test('complete literal same-world primary premise',()=>{
  keys.forEach(k=>{pm.expect(p[k].length).to.be.above(0);pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length);});
  pm.expect(Object.keys(p.members).sort()).to.eql(p.groups.map(x=>x.id).sort());
  pm.expect(p.groups.filter(g=>g.accountId===e.systemId && g.name==='module-relation-writers').length).to.eql(1);
  const issuer=p.serviceAccounts.find(x=>x.id===e.issuerId);pm.expect(issuer.name).to.eql('rid-public-issuer');pm.expect(issuer.enabled).to.eql(true);pm.expect(issuer.accountId).to.eql(e.systemId);
  pm.expect(p.serviceAccounts.map(x=>x.id)).to.include(e.creatorId);pm.expect(e.creatorId).not.to.eql(e.issuerId);
  const installed=p.delegations.filter(g=>g.delegate.id===e.issuerId);pm.expect(installed.length).to.eql(__N__);
  installed.forEach(g=>{pm.expect(g.status).to.eql('ACTIVE');pm.expect(g.module).to.eql('registry');pm.expect(g.delegatedBy).to.eql({type:'service_account',id:e.creatorId});});
  pm.expect(installed.map(g=>g.id)).to.include(e.installationDelegationId);
  if(e.phase==='VERIFY' && !e.denied){
   pm.expect(e.operation).to.be.an('object');pm.expect(e.operation.done).to.eql(true);pm.expect(e.operation.error||null).to.eql(null);
   pm.expect(e.resource.status).to.eql('ACTIVE');
   pm.expect((e.path==='/iam/v1/accessBindings'?p.bindings:p.delegations).find(x=>x.id===e.resource.id)).to.eql(e.resource);
   if(e.path==='/iam/v1/accessBindings')pm.expect(e.resource.delegationId).to.eql(e.installationDelegationId);
   pm.environment.set('rid03PrimaryOperationId',e.operation.id);
  }else{pm.expect(e.operation||null).to.eql(null);pm.expect(e.resource||null).to.eql(null);}
 });
 keys.forEach(k=>{
  pm.environment.set('rid10Seen_'+k,'[]');pm.environment.set('rid10Listed_'+k,'{}');pm.environment.set('rid10Tokens_'+k,'[""]');pm.environment.set('rid10Page_'+k,'');
  pm.environment.set('rid10AccountIndex_'+k,'0');pm.environment.set('rid10Account_'+k,p.accounts[0].id);
  pm.environment.set('rid10GetIndex_'+k,'0');pm.environment.set('rid10GetId_'+k,p[k][0].id);pm.environment.set('rid10Got_'+k,'[]');
 });
 pm.environment.set('rid10GroupIndex','0');pm.environment.set('rid10GroupId',p.groups[0].id);
 pm.environment.set('rid10MembersSeen','{}');pm.environment.set('rid10MembersTokens','[""]');pm.environment.set('rid10MembersPage','');
 pm.environment.set('rid03ActionDeadline',String(Date.now()+30000));pm.environment.set('rid03Polls','0');
}
""".strip()
_POST = r"""
const op=pm.response.json();
pm.test('actual mutation returns one Operation handle',()=>pm.expect(op.id).to.be.a('string').and.not.empty);
pm.environment.set('rid03ActionOperationId',op.id);
""".strip()
_POLL = r"""
const e=JSON.parse(pm.environment.get('rid03Expected')),op=pm.response.json();
pm.test('same real Operation bounded polling',()=>{
 pm.expect(op.id).to.eql(pm.environment.get('rid03ActionOperationId'));
 pm.expect(Date.now()).to.be.below(Number(pm.environment.get('rid03ActionDeadline')));pm.expect(Number(pm.environment.get('rid03Polls'))).to.be.below(5000);
});
pm.environment.set('rid03Polls',String(Number(pm.environment.get('rid03Polls'))+1));
if(!op.done){pm.execution.setNextRequest(pm.info.requestName);}else{
 pm.test('done success exact requested response identity',()=>{
  pm.expect(op.error||null).to.eql(null);pm.expect(op.response.id).to.be.a('string').and.not.empty;
  if(e.path==='/iam/v1/accessBindings'){
   pm.expect(op.metadata.accessBindingId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.tenantId);pm.expect(op.response.delegationId).to.eql(e.installationDelegationId);
  }else{pm.expect(op.metadata.grantDelegationId).to.eql(op.response.id);pm.expect(op.metadata.accountId).to.eql(e.request.accountId);}
 });
 pm.environment.set('rid03ActionResponse',JSON.stringify(op.response));pm.environment.set('rid03ActionResourceId',op.response.id);
}
""".strip()
_GET = r"""
const e=JSON.parse(pm.environment.get('rid03Expected')),j=pm.response.json();
const response=JSON.parse(pm.environment.get('rid03ActionResponse'));
const expected={...response};delete expected['@type'];

pm.test('own Operation/Get full equality active exact delegation',()=>{
 if(e.path==='/iam/v1/accessBindings'){
  pm.expect(Object.keys(j).sort()).to.eql(Object.keys(expected).sort());
  Object.keys(expected).filter(k=>k!=='materializedAt').forEach(k=>pm.expect(j[k]).to.eql(expected[k]));
 }else pm.expect(j).to.eql(expected);
 pm.expect(j.status).to.eql('ACTIVE');pm.expect(j.id).to.eql(pm.environment.get('rid03ActionResourceId'));
 if(e.path==='/iam/v1/accessBindings'){
  pm.expect(j.delegationId).to.eql(e.installationDelegationId);pm.expect(j.subjectType).to.eql(e.request.subjectType);pm.expect(j.subjectId).to.eql(e.request.subjectId);pm.expect(j.roleId).to.eql(e.request.roleId);
  pm.expect(j.scopeType).to.eql(e.request.scopeType);pm.expect(j.scopeId).to.eql(e.request.scopeId);
 }else{pm.expect(j.accountId).to.eql(e.request.accountId);pm.expect(j.delegate).to.eql(e.request.delegate);pm.expect(j.delegatedBy).to.eql({type:'service_account',id:e.creatorId});}
});
if(e.path==='/iam/v1/accessBindings'){
 pm.test('single actual Get enrichment is nonempty bounded data; independent primary acceptance follows',()=>{
  pm.expect(j.materializedAt).to.be.a('string').and.not.empty;
  pm.expect(Date.parse(j.materializedAt)).to.be.at.least(Date.parse(j.createdAt));
  pm.expect(Date.parse(j.materializedAt)).to.be.at.most(Date.now());
  if(response.materializedAt)pm.expect(Date.parse(response.materializedAt)).to.be.at.most(Date.parse(j.materializedAt));
 });
}

""".strip()

# Frozen explicit literal census: 22 phases in each of the existing two modes.
_PHASES = [
    ('registry-installation-rid03-S1-GRANT-ACT', 'S1', 'GRANT', 'ACT'),
    ('registry-installation-rid03-S1-GRANT-VERIFY', 'S1', 'GRANT', 'VERIFY'),
    ('registry-installation-rid03-S1-ROLE-DENIED-ACT', 'S1', 'ROLE-DENIED', 'ACT'),
    ('registry-installation-rid03-S1-ROLE-DENIED-VERIFY', 'S1', 'ROLE-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S1-ROLE-TWIN-ACT', 'S1', 'ROLE-TWIN', 'ACT'),
    ('registry-installation-rid03-S1-ROLE-TWIN-VERIFY', 'S1', 'ROLE-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S1-TARGET-DENIED-ACT', 'S1', 'TARGET-DENIED', 'ACT'),
    ('registry-installation-rid03-S1-TARGET-DENIED-VERIFY', 'S1', 'TARGET-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S1-TARGET-TWIN-ACT', 'S1', 'TARGET-TWIN', 'ACT'),
    ('registry-installation-rid03-S1-TARGET-TWIN-VERIFY', 'S1', 'TARGET-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S1-SUBJECT-DENIED-ACT', 'S1', 'SUBJECT-DENIED', 'ACT'),
    ('registry-installation-rid03-S1-SUBJECT-DENIED-VERIFY', 'S1', 'SUBJECT-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S1-SUBJECT-TWIN-ACT', 'S1', 'SUBJECT-TWIN', 'ACT'),
    ('registry-installation-rid03-S1-SUBJECT-TWIN-VERIFY', 'S1', 'SUBJECT-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S1-ISSUER-GD-DENIED-ACT', 'S1', 'ISSUER-GD-DENIED', 'ACT'),
    ('registry-installation-rid03-S1-ISSUER-GD-DENIED-VERIFY', 'S1', 'ISSUER-GD-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S1-CREATOR-GD-TWIN-ACT', 'S1', 'CREATOR-GD-TWIN', 'ACT'),
    ('registry-installation-rid03-S1-CREATOR-GD-TWIN-VERIFY', 'S1', 'CREATOR-GD-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S1-AUTHENTICATED-DENIED-ACT', 'S1', 'AUTHENTICATED-DENIED', 'ACT'),
    ('registry-installation-rid03-S1-AUTHENTICATED-DENIED-VERIFY', 'S1', 'AUTHENTICATED-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S1-ANONYMOUS-TWIN-ACT', 'S1', 'ANONYMOUS-TWIN', 'ACT'),
    ('registry-installation-rid03-S1-ANONYMOUS-TWIN-VERIFY', 'S1', 'ANONYMOUS-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S2-GRANT-ACT', 'S2', 'GRANT', 'ACT'),
    ('registry-installation-rid03-S2-GRANT-VERIFY', 'S2', 'GRANT', 'VERIFY'),
    ('registry-installation-rid03-S2-ROLE-DENIED-ACT', 'S2', 'ROLE-DENIED', 'ACT'),
    ('registry-installation-rid03-S2-ROLE-DENIED-VERIFY', 'S2', 'ROLE-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S2-ROLE-TWIN-ACT', 'S2', 'ROLE-TWIN', 'ACT'),
    ('registry-installation-rid03-S2-ROLE-TWIN-VERIFY', 'S2', 'ROLE-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S2-TARGET-DENIED-ACT', 'S2', 'TARGET-DENIED', 'ACT'),
    ('registry-installation-rid03-S2-TARGET-DENIED-VERIFY', 'S2', 'TARGET-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S2-TARGET-TWIN-ACT', 'S2', 'TARGET-TWIN', 'ACT'),
    ('registry-installation-rid03-S2-TARGET-TWIN-VERIFY', 'S2', 'TARGET-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S2-SUBJECT-DENIED-ACT', 'S2', 'SUBJECT-DENIED', 'ACT'),
    ('registry-installation-rid03-S2-SUBJECT-DENIED-VERIFY', 'S2', 'SUBJECT-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S2-SUBJECT-TWIN-ACT', 'S2', 'SUBJECT-TWIN', 'ACT'),
    ('registry-installation-rid03-S2-SUBJECT-TWIN-VERIFY', 'S2', 'SUBJECT-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S2-ISSUER-GD-DENIED-ACT', 'S2', 'ISSUER-GD-DENIED', 'ACT'),
    ('registry-installation-rid03-S2-ISSUER-GD-DENIED-VERIFY', 'S2', 'ISSUER-GD-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S2-CREATOR-GD-TWIN-ACT', 'S2', 'CREATOR-GD-TWIN', 'ACT'),
    ('registry-installation-rid03-S2-CREATOR-GD-TWIN-VERIFY', 'S2', 'CREATOR-GD-TWIN', 'VERIFY'),
    ('registry-installation-rid03-S2-AUTHENTICATED-DENIED-ACT', 'S2', 'AUTHENTICATED-DENIED', 'ACT'),
    ('registry-installation-rid03-S2-AUTHENTICATED-DENIED-VERIFY', 'S2', 'AUTHENTICATED-DENIED', 'VERIFY'),
    ('registry-installation-rid03-S2-ANONYMOUS-TWIN-ACT', 'S2', 'ANONYMOUS-TWIN', 'ACT'),
    ('registry-installation-rid03-S2-ANONYMOUS-TWIN-VERIFY', 'S2', 'ANONYMOUS-TWIN', 'VERIFY'),
]

for case_id, mode, scenario, phase in _PHASES:
    denied = scenario.endswith('-DENIED')
    creator = scenario == 'CREATOR-GD-TWIN'
    route = '/iam/v1/grantDelegations' if '-GD-' in scenario else '/iam/v1/accessBindings'
    auth = 'jwtRIDCreator' if creator else 'jwtRIDIssuer'
    config = _CONFIG
    for key, value in {
        '__CASE__': js_str(case_id), '__MODE__': js_str(mode), '__SCENARIO__': js_str(scenario),
        '__PHASE__': js_str(phase), '__ACTOR__': 'e.creatorId' if creator else 'e.issuerId',
        '__DENIED__': 'true' if denied else 'false', '__PATH__': js_str(route), '__N__': '3' if mode == 'S2' else '1',
        '__MISSING__': '\n'.join(precondition_not_met('RID03 complete primary and exact literal action',
            'Missing or incompatible RID03 primary input; no public verdict', indent='  ')),
    }.items():
        config = config.replace(key, value)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me', auth='jwtRIDOperator',
        pre_script=config.splitlines(), test_script=[*assert_status(200),
        "const e=JSON.parse(pm.environment.get('rid03Expected')),j=pm.response.json();",
        "pm.test('actual independent ordinary O',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
    steps += midrun_read_steps(Step, assert_status, js_str, expected_var='rid03Expected')
    if phase == 'ACT':
        steps.append(Step(name='actual-action-actor', method='GET', path='/iam/v1/me', auth=auth,
            test_script=[*assert_status(200), "const e=JSON.parse(pm.environment.get('rid03Expected'));",
            "pm.test('actual declared service-account actor',()=>pm.expect(pm.response.json().subject).to.eql('service_account:'+e.actor));"]))
        test = [*assert_status(403),
            "pm.test('synchronous axis refusal code7 permission denied',()=>{const j=pm.response.json();pm.expect(j.code).to.eql(7);pm.expect(j.message).to.eql('permission denied');pm.expect(j.id).to.eql(undefined);});"] if denied else [*assert_status(200), *_POST.splitlines()]
        steps.append(Step(name='actual-action', method='POST', path=route, auth=auth, body={},
            pre_script=["const e=JSON.parse(pm.environment.get('rid03Expected'));pm.request.body.update(JSON.stringify(e.request));pm.environment.set('rid03ActionDeadline',String(Date.now()+30000));pm.environment.set('rid03Polls','0');"],
            test_script=test))
        if not denied:
            steps.append(Step(name='actual-action-Operation-Get', method='GET', path='/operations/{{rid03ActionOperationId}}',
                auth=auth, test_script=[*assert_status(200), *_POLL.splitlines()]))
            steps.append(Step(name='actual-action-resource-Get', method='GET', path=route+'/{{rid03ActionResourceId}}',
                auth='jwtRIDOperator', test_script=[*assert_status(200), *_GET.splitlines()]))
    elif not denied:
        steps.append(Step(name='independent-primary-Operation-Get', method='GET', path='/operations/{{rid03PrimaryOperationId}}',
            auth='jwtRIDOperator', test_script=[*assert_status(404),
            "pm.test('O is not the I/C Operation owner: exact hidden Operation refusal',()=>{const j=pm.response.json();pm.expect(j).to.eql({code:5,message:'operation '+JSON.parse(pm.environment.get('rid03Expected')).operation.id+' not found',details:[]});});"]))
    CASES.append(Case(id=case_id, title='RID03 public '+mode+' '+scenario+' '+phase,
                     classes=['CONF','CRUD'], priority='P0', steps=steps))
CASES = address_own_front(CASES, 'RID03 same isolated standalone Kaname public HTTPS origin')
