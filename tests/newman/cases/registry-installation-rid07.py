# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""32 O-only public phases in the 16 existing RID07 worlds.

Depends on RID12 R1's frozen shared optional expected_var API, SHA256
7761859f66733af35308ade3809a680c9bade7695efb904d453d6fabc3aeb942.
No setup, credential issuance, Operation Get or HTTP mutation is added.
"""
from rid_midrun_public import midrun_read_steps

HOME = 'kaname'
CASES = []
_CONFIG = r"""
const e = JSON.parse(pm.environment.get('rid07Expected') || 'null');
const keys = ['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid = e && e.caseId === __CASE__ && e.axis === __AXIS__ && e.mode === __MODE__ && e.twin === __TWIN__ && e.phase === __PHASE__ &&
 e.operatorId && e.creatorId && e.systemId && e.tenantId && e.issuerId && e.pairCreatorId &&
 e.oldPairId && e.activePairId && e.oldGrantId && e.activeGrantId && e.pullRoleId && e.pushRoleId &&
 (e.phase === 'before' ? e.previousProjection === null : e.previousProjection && keys.every(k=>Array.isArray(e.previousProjection[k]))) &&
 e.snapshot && e.snapshot.projection &&
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
 pm.test('literal complete RID07 primary inventory and unchanged full pair/grant history', () => {
  pm.expect(p.accounts.length).to.eql(__N__+1);
  const normal=p.accounts.filter(x=>x.id!==e.systemId);
  pm.expect(normal.length).to.eql(__N__);
  pm.expect(normal.map(x=>x.id)).to.include(e.tenantId);
  normal.forEach(x=>pm.expect(x.ownerUserId).to.eql(e.operatorId));
  if(__N__===3){pm.expect(normal.map(x=>x.id)).to.include(e.tenantNamedSystem);pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);}
  else pm.expect(e.tenantNamedSystem).to.eql('');
  pm.expect(p.serviceAccounts.length).to.eql(__SA__);
  pm.expect(p.delegations.length).to.eql(__N__+1);
  pm.expect(p.groups.length).to.be.above(0);
  pm.expect(p.groups.filter(x=>x.accountId===e.systemId && x.name==='module-relation-writers').length).to.eql(1);
  keys.forEach(k=>pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length));
  const issuer=p.serviceAccounts.filter(x=>x.accountId===e.systemId && x.name==='rid-public-issuer');
  pm.expect(issuer.map(x=>x.id)).to.eql([e.issuerId]);
  pm.expect(e.issuerId).not.to.eql(e.creatorId);
  pm.expect(issuer[0].enabled).to.eql(true);
  const other=p.serviceAccounts.filter(x=>x.accountId===e.systemId && x.name==='rid07-other-creator');
  if(e.axis==='DELEGATEDBY'){
    pm.expect(other.length).to.eql(1);
    pm.expect(other[0].id).not.to.eql(e.creatorId);
    pm.expect(e.pairCreatorId).to.eql(e.twin?e.creatorId:other[0].id);
  }else{pm.expect(other).to.eql([]);pm.expect(e.pairCreatorId).to.eql(e.creatorId);}
  pm.expect(p.roles.filter(x=>x.name==='registry.puller').map(x=>x.id)).to.eql([e.pullRoleId]);
  pm.expect(p.roles.filter(x=>x.name==='registry.pusher').map(x=>x.id)).to.eql([e.pushRoleId]);
  const old=p.delegations.find(x=>x.id===e.oldPairId);
  const active=p.delegations.find(x=>x.id===e.activePairId);
  pm.expect(old).to.be.an('object');pm.expect(active).to.be.an('object');
  pm.expect(old.accountId).to.eql(e.tenantId);pm.expect(active.accountId).to.eql(e.tenantId);
  pm.expect(old.status).to.eql('REVOKED');pm.expect(old.revokedAt).to.be.a('string').and.not.empty;
  pm.expect(old.revokedBy).to.be.an('object');
  pm.expect(active.status).to.eql('ACTIVE');
  const activeRows=p.delegations.filter(x=>x.status==='ACTIVE');
  pm.expect(activeRows.length).to.eql(__N__);
  pm.expect(activeRows.map(x=>x.accountId).sort()).to.eql(normal.map(x=>x.id).sort());
  p.delegations.forEach(x=>{
   pm.expect(x.module).to.eql('registry');
   pm.expect(normal.map(a=>a.id)).to.include(x.accountId);
   pm.expect(x.delegate).to.eql({type:'SUBJECT_TYPE_SERVICE_ACCOUNT',id:e.issuerId});
   const conflict=x.id===e.activePairId && !e.twin;
   pm.expect(x.delegatedBy).to.eql({type:'service_account',id:x.id===e.activePairId?e.pairCreatorId:e.creatorId});
   pm.expect(x.roleIds).to.eql([conflict&&e.axis==='ROLEIDS'?e.pushRoleId:e.pullRoleId]);
   pm.expect(x.targetTypes).to.eql([conflict&&e.axis==='TARGETTYPES'?'registry.repositories':'registry.registries']);
   pm.expect(x.subjectTypes).to.eql([conflict&&e.axis==='SUBJECTTYPES'?'SUBJECT_TYPE_USER':'SUBJECT_TYPE_SERVICE_ACCOUNT']);
   if(x.status==='ACTIVE'){pm.expect(x.revokedAt).to.eql(null);pm.expect(x.revokedBy).to.eql(null);}
  });
  const oldG=p.bindings.find(x=>x.id===e.oldGrantId), activeG=p.bindings.find(x=>x.id===e.activeGrantId);
  pm.expect(oldG).to.be.an('object');pm.expect(activeG).to.be.an('object');
  pm.expect(oldG.status).to.eql('REVOKED');pm.expect(oldG.delegationId).to.eql(e.oldPairId);
  pm.expect(activeG.status).to.eql('ACTIVE');pm.expect(activeG.delegationId).to.eql(e.activePairId);
  pm.expect(activeG.materializedAt).to.be.a('string').and.not.empty;
  if(e.phase==='after'){
   keys.forEach(k=>pm.expect(p[k]).to.eql(e.previousProjection[k]));
   pm.expect(p.catalog).to.eql(e.previousProjection.catalog);
   pm.expect(p.members).to.eql(e.previousProjection.members);
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

# Approved literal phase inventory; native axis mapping is explicit in Go.
_PHASES = [
    ('registry-installation-rid07-ROLEIDS-S1-NEGATIVE-BEFORE', 'ROLEIDS', 'S1', False, 'before'),
    ('registry-installation-rid07-ROLEIDS-S1-NEGATIVE-AFTER', 'ROLEIDS', 'S1', False, 'after'),
    ('registry-installation-rid07-ROLEIDS-S1-TWIN-BEFORE', 'ROLEIDS', 'S1', True, 'before'),
    ('registry-installation-rid07-ROLEIDS-S1-TWIN-AFTER', 'ROLEIDS', 'S1', True, 'after'),
    ('registry-installation-rid07-ROLEIDS-S2-NEGATIVE-BEFORE', 'ROLEIDS', 'S2', False, 'before'),
    ('registry-installation-rid07-ROLEIDS-S2-NEGATIVE-AFTER', 'ROLEIDS', 'S2', False, 'after'),
    ('registry-installation-rid07-ROLEIDS-S2-TWIN-BEFORE', 'ROLEIDS', 'S2', True, 'before'),
    ('registry-installation-rid07-ROLEIDS-S2-TWIN-AFTER', 'ROLEIDS', 'S2', True, 'after'),
    ('registry-installation-rid07-TARGETTYPES-S1-NEGATIVE-BEFORE', 'TARGETTYPES', 'S1', False, 'before'),
    ('registry-installation-rid07-TARGETTYPES-S1-NEGATIVE-AFTER', 'TARGETTYPES', 'S1', False, 'after'),
    ('registry-installation-rid07-TARGETTYPES-S1-TWIN-BEFORE', 'TARGETTYPES', 'S1', True, 'before'),
    ('registry-installation-rid07-TARGETTYPES-S1-TWIN-AFTER', 'TARGETTYPES', 'S1', True, 'after'),
    ('registry-installation-rid07-TARGETTYPES-S2-NEGATIVE-BEFORE', 'TARGETTYPES', 'S2', False, 'before'),
    ('registry-installation-rid07-TARGETTYPES-S2-NEGATIVE-AFTER', 'TARGETTYPES', 'S2', False, 'after'),
    ('registry-installation-rid07-TARGETTYPES-S2-TWIN-BEFORE', 'TARGETTYPES', 'S2', True, 'before'),
    ('registry-installation-rid07-TARGETTYPES-S2-TWIN-AFTER', 'TARGETTYPES', 'S2', True, 'after'),
    ('registry-installation-rid07-SUBJECTTYPES-S1-NEGATIVE-BEFORE', 'SUBJECTTYPES', 'S1', False, 'before'),
    ('registry-installation-rid07-SUBJECTTYPES-S1-NEGATIVE-AFTER', 'SUBJECTTYPES', 'S1', False, 'after'),
    ('registry-installation-rid07-SUBJECTTYPES-S1-TWIN-BEFORE', 'SUBJECTTYPES', 'S1', True, 'before'),
    ('registry-installation-rid07-SUBJECTTYPES-S1-TWIN-AFTER', 'SUBJECTTYPES', 'S1', True, 'after'),
    ('registry-installation-rid07-SUBJECTTYPES-S2-NEGATIVE-BEFORE', 'SUBJECTTYPES', 'S2', False, 'before'),
    ('registry-installation-rid07-SUBJECTTYPES-S2-NEGATIVE-AFTER', 'SUBJECTTYPES', 'S2', False, 'after'),
    ('registry-installation-rid07-SUBJECTTYPES-S2-TWIN-BEFORE', 'SUBJECTTYPES', 'S2', True, 'before'),
    ('registry-installation-rid07-SUBJECTTYPES-S2-TWIN-AFTER', 'SUBJECTTYPES', 'S2', True, 'after'),
    ('registry-installation-rid07-DELEGATEDBY-S1-NEGATIVE-BEFORE', 'DELEGATEDBY', 'S1', False, 'before'),
    ('registry-installation-rid07-DELEGATEDBY-S1-NEGATIVE-AFTER', 'DELEGATEDBY', 'S1', False, 'after'),
    ('registry-installation-rid07-DELEGATEDBY-S1-TWIN-BEFORE', 'DELEGATEDBY', 'S1', True, 'before'),
    ('registry-installation-rid07-DELEGATEDBY-S1-TWIN-AFTER', 'DELEGATEDBY', 'S1', True, 'after'),
    ('registry-installation-rid07-DELEGATEDBY-S2-NEGATIVE-BEFORE', 'DELEGATEDBY', 'S2', False, 'before'),
    ('registry-installation-rid07-DELEGATEDBY-S2-NEGATIVE-AFTER', 'DELEGATEDBY', 'S2', False, 'after'),
    ('registry-installation-rid07-DELEGATEDBY-S2-TWIN-BEFORE', 'DELEGATEDBY', 'S2', True, 'before'),
    ('registry-installation-rid07-DELEGATEDBY-S2-TWIN-AFTER', 'DELEGATEDBY', 'S2', True, 'after'),
]

for case_id, axis, mode, twin, phase in _PHASES:
    config = _CONFIG
    for key, value in {
        '__CASE__': js_str(case_id), '__AXIS__': js_str(axis), '__MODE__': js_str(mode),
        '__TWIN__': str(twin).lower(), '__PHASE__': js_str(phase),
        '__N__': '1' if mode == 'S1' else '3', '__SA__': '8' if axis == 'DELEGATEDBY' else '7',
        '__MISSING__': '\n'.join(precondition_not_met('RID07 exact same-world full primary snapshot',
          'Missing/incompatible complete RID07 inventory; no public verdict', indent='  ')),
    }.items():
        config = config.replace(key, value)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me', auth='jwtRIDOperator',
                  pre_script=config.splitlines(), test_script=[*assert_status(200),
                  "const e = JSON.parse(pm.environment.get('rid07Expected'));",
                  "const j = pm.response.json();",
                  "pm.test('actual independent ordinary O',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
    # Every entity is independently known nonempty in these base-ready worlds.
    # Every leaf really performs HTTP: no runtime skip or fabricated empty Get.
    steps += midrun_read_steps(Step, assert_status, js_str, expected_var='rid07Expected')
    CASES.append(Case(id=case_id,title='RID07 public '+axis+' '+mode+' '+('TWIN' if twin else 'NEGATIVE')+' '+phase,
                      classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES = address_own_front(CASES, 'RID07 observes the same isolated standalone Kaname public origin')
