# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Eight actual RID01 phases, owned once by the existing four native scenarios.

Depends on frozen RID12R1 common expected_var API and root's case-scoped
RID01 FD5 secret/issuance-origin extension. No token is issued in JavaScript
except the mandatory actual expired-standing-key refusal request.
"""
import json

HOME = 'kaname'
CASES = []
_CONFIG = r"""
const e = JSON.parse(pm.environment.get('rid01Expected') || 'null');
const keys = ['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid = e && e.caseId === __CASE__ && e.phase === __PHASE__ &&
 e.operatorId && e.creatorId && e.systemId && e.tenantId && Array.isArray(e.modules) && e.issuers && e.snapshot && e.snapshot.projection &&
 keys.every(k => Array.isArray(e.snapshot.projection[k])) && e.snapshot.projection.catalog &&
 Array.isArray(e.snapshot.projection.catalog.modules) && Array.isArray(e.snapshot.projection.catalog.closedVerbs) &&
 Array.isArray(e.snapshot.projection.catalog.retiredResources) && e.snapshot.projection.catalog.wildcardPolicy &&
 e.snapshot.projection.members && typeof e.snapshot.projection.members === 'object' && !Array.isArray(e.snapshot.projection.members) &&
 Object.keys(e.snapshot.projection.members).length === e.snapshot.projection.groups.length &&
 e.snapshot.projection.groups.every(g => Array.isArray(e.snapshot.projection.members[g.id]));
if (!valid) {
__MISSING__
} else {
 const p = e.snapshot.projection;
 pm.test('literal complete RID01 primary inventory and exact independently resolved issuers', () => {
  pm.expect(p.accounts.length).to.eql(2);
  pm.expect(p.accounts.filter(x=>x.id!==e.systemId).map(x=>x.id)).to.eql([e.tenantId]);
  pm.expect(p.accounts.find(x=>x.id===e.tenantId).ownerUserId).to.eql(e.operatorId);
  pm.expect(e.creatorId).not.to.eql(e.tenantId);
  pm.expect(e.creatorId).not.to.eql(e.systemId);
  pm.expect(e.modules).to.eql(__MODULES__);
  pm.expect(p.serviceAccounts.length).to.eql(3+e.modules.length);
  pm.expect(p.delegations.length).to.eql(e.modules.length);
  pm.expect(p.serviceAccounts.map(x=>x.id)).to.include(e.creatorId);
  p.serviceAccounts.forEach(x=>pm.expect(x.accountId).to.eql(e.systemId));
  pm.expect(p.groups.length).to.be.above(0);
  pm.expect(p.groups.filter(x=>x.accountId===e.systemId && x.name==='module-relation-writers').length).to.eql(1);
  keys.forEach(k=>pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length));
  pm.expect(Object.keys(e.issuers).sort()).to.eql([...e.modules].sort());
  e.modules.forEach(module=>{
   const issuer=p.serviceAccounts.filter(x=>x.accountId===e.systemId && x.name==='svc-'+module);
   pm.expect(issuer.map(x=>x.id)).to.eql([e.issuers[module]]);
   pm.expect(issuer[0].enabled).to.eql(true);
   pm.expect(e.issuers[module]).not.to.eql(e.creatorId);
   pm.expect(e.issuers[module]).not.to.eql(e.tenantId);
   const roles=p.roles.filter(x=>x.name===module+'.reader');
   pm.expect(roles.length).to.eql(1);pm.expect(roles[0].clusterId).to.eql('cluster_root');
   const rows=p.delegations.filter(x=>x.module===module);
   pm.expect(rows.length).to.eql(1);
   const gd=rows[0];pm.expect(gd.accountId).to.eql(e.tenantId);pm.expect(gd.status).to.eql('ACTIVE');
   pm.expect(gd.delegate).to.eql({type:'SUBJECT_TYPE_SERVICE_ACCOUNT',id:e.issuers[module]});
   pm.expect(gd.delegatedBy).to.eql({type:'service_account',id:e.creatorId});
   pm.expect(gd.roleIds).to.eql([roles[0].id]);pm.expect(gd.targetTypes).to.eql([module+'.objects']);
   pm.expect(gd.subjectTypes).to.eql(['SUBJECT_TYPE_SERVICE_ACCOUNT']);
   pm.expect(gd.revokedAt).to.eql(null);pm.expect(gd.revokedBy).to.eql(null);
  });
  if(['EXPIRED-ACCESS-TOKEN','RENEWAL-AFTER','EXPIRED-KEY-REFUSAL'].includes(e.phase)){
   pm.expect(e.previousProjection).to.be.an('object');
   keys.forEach(k=>pm.expect(p[k]).to.eql(e.previousProjection[k]));
   pm.expect(p.catalog).to.eql(e.previousProjection.catalog);pm.expect(p.members).to.eql(e.previousProjection.members);
  }
 });
 keys.forEach(k=>{
  pm.environment.set('rid10Seen_'+k,'[]'); pm.environment.set('rid10Listed_'+k,'{}');
  pm.environment.set('rid10Tokens_'+k,'[""]'); pm.environment.set('rid10Page_'+k,'');
  pm.environment.set('rid10AccountIndex_'+k,'0'); pm.environment.set('rid10Account_'+k,p.accounts[0].id);
  pm.environment.set('rid10GetIndex_'+k,'0'); pm.environment.set('rid10GetId_'+k,p[k].length?p[k][0].id:'');
  pm.environment.set('rid10Got_'+k,'[]');
 });
 pm.environment.set('rid10GroupIndex','0'); pm.environment.set('rid10GroupId',p.groups.length?p.groups[0].id:'');
 pm.environment.set('rid10MembersSeen','{}'); pm.environment.set('rid10MembersTokens','[""]'); pm.environment.set('rid10MembersPage','');
}
""".strip()


_PHASES = [
    ('registry-installation-rid01-CLEAN-BEFORE', 'CLEAN-BEFORE'),
    ('registry-installation-rid01-CLEAN-INSTALLED', 'CLEAN-INSTALLED'),
    ('registry-installation-rid01-S1-EXACT-IDENTITIES', 'S1-EXACT-IDENTITIES'),
    ('registry-installation-rid01-RENEWAL-BEFORE', 'RENEWAL-BEFORE'),
    ('registry-installation-rid01-EXPIRED-ACCESS-TOKEN', 'EXPIRED-ACCESS-TOKEN'),
    ('registry-installation-rid01-RENEWAL-AFTER', 'RENEWAL-AFTER'),
    ('registry-installation-rid01-EXPIRED-KEY-REFUSAL', 'EXPIRED-KEY-REFUSAL'),
    ('registry-installation-rid01-VALID-KEY-TWIN', 'VALID-KEY-TWIN'),
]

for case_id, phase in _PHASES:
    modules = [] if phase == 'CLEAN-BEFORE' else ['ridfirst', 'ridsecond'] if phase == 'CLEAN-INSTALLED' else ['ridfirst']
    config = _CONFIG
    for key, value in {
        '__CASE__': js_str(case_id), '__PHASE__': js_str(phase), '__MODULES__': json.dumps(modules),
        '__MISSING__': '\n'.join(precondition_not_met('RID01 exact same-world full primary snapshot',
          'Missing/incompatible complete RID01 inventory; no public verdict', indent='  ')),
    }.items():
        config = config.replace(key, value)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me', auth='jwtRIDOperator',
                  pre_script=config.splitlines(), test_script=[*assert_status(200),
                  "const e = JSON.parse(pm.environment.get('rid01Expected'));",
                  "const j = pm.response.json();",
                  "pm.test('actual independent ordinary O',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
    if phase == 'EXPIRED-ACCESS-TOKEN':
        steps.append(Step(name='actual-expired-C-bearer-refusal', method='GET', path='/iam/v1/me', auth='jwtRIDExpiredCreator',
                          test_script=[*assert_status(401),
                          "pm.test('actual expired C bearer was presented unchanged',()=>pm.expect(pm.environment.get('jwtRIDExpiredCreator')).to.be.a('string').and.not.empty);"]))
    if phase == 'RENEWAL-AFTER':
        steps.append(Step(name='actual-renewed-C-bearer-identity', method='GET', path='/iam/v1/me', auth='jwtRIDCreator',
                          test_script=[*assert_status(200),
                          "const e=JSON.parse(pm.environment.get('rid01Expected')); const j=pm.response.json();",
                          "pm.test('renewed C authenticates as exact original creator',()=>{pm.expect(j.subject).to.eql('service_account:'+e.creatorId);pm.expect(j.userId||'').to.eql('');});"]))
    if phase == 'EXPIRED-KEY-REFUSAL':
        steps.append(Step(name='expired-standing-key-token-refusal', method='POST', path='/iam/v1/token', auth='anonymous',
                          follow_redirects=False, cookie_jar=False,
                          form=[('grant_type','client_credentials'),
                                ('client_assertion_type','urn:ietf:params:oauth:client-assertion-type:jwt-bearer'),
                                ('client_assertion','{{rid01ClientAssertion}}'), ('audience','https://kaname.local')],
                          pre_script=["const e=JSON.parse(pm.environment.get('rid01Expected'));",
                              "pm.test('fresh live assertion isolates expired stored key refusal',()=>pm.expect(Date.now()).to.be.below(Date.parse(e.assertionExpiresAt)));",
                              "pm.request.url=pm.environment.get('rid01IssuanceOrigin')+'/iam/v1/token';"],
                          test_script=[*assert_status(401),
                              "pm.test('ordinary OAuth expired-key refusal',()=>pm.expect(pm.response.json().error).to.eql('invalid_client'));"]))
    reads = midrun_read_steps(Step, assert_status, js_str, expected_var='rid01Expected')
    if phase == 'CLEAN-BEFORE':
        # Known empty: List every account and assert primary GD0; no fake Get.
        reads = [step for step in reads if step.name != 'every-Get-delegations']
    steps += reads
    CASES.append(Case(id=case_id,title='RID01 public '+phase,classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES = address_own_front(CASES, 'RID01 observes the same isolated standalone Kaname public origin')
