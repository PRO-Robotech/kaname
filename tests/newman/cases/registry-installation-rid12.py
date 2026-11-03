# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""65 literal, read-only phases in the 32 existing RID12 native worlds."""
from rid_midrun_public import midrun_read_steps

HOME = 'kaname'
CASES = []
_CONFIG = r"""
const e = JSON.parse(pm.environment.get('rid12Expected') || 'null');
const keys = ['accounts','serviceAccounts','groups','roles','bindings','delegations'];
const valid = e && e.caseId === __CASE__ && e.name === __NAME__ && e.kind === __KIND__ && e.phase === __PHASE__ &&
 e.operatorId && e.creatorId && e.systemId && e.tenantNamedSystem && e.snapshot && e.snapshot.projection &&
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
 pm.test('literal complete RID12 same-world primary inventory, S2 N3', () => {
  pm.expect(p.accounts.length).to.eql(4);
  pm.expect(p.accounts.filter(x=>x.id!==e.systemId).length).to.eql(3);
  pm.expect(p.accounts.filter(x=>x.id!==e.systemId).map(x=>x.id)).to.include(e.tenantNamedSystem);
  pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);
  pm.expect(p.serviceAccounts.length).to.eql(__SA__);
  pm.expect(p.delegations.length).to.eql(__GD__);
  pm.expect(p.groups.length).to.be.above(0);
  pm.expect(p.groups.filter(x=>x.accountId===e.systemId && x.name==='module-relation-writers').length).to.eql(1);
  p.serviceAccounts.forEach(x=>pm.expect(x.accountId).to.eql(e.systemId));
  keys.forEach(k=>pm.expect(new Set(p[k].map(x=>x.id)).size).to.eql(p[k].length));
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

# Closed literal 65-phase inventory; native hook positions own execution.
_PHASES = [
    ('registry-installation-rid12-UNKNOWN-FIELD-NEGATIVE-BEFORE', 'unknown-field', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-UNKNOWN-FIELD-NEGATIVE-AFTER', 'unknown-field', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-UNKNOWN-FIELD-TWIN-BEFORE', 'unknown-field', 'TWIN', 'before'),
    ('registry-installation-rid12-UNKNOWN-FIELD-TWIN-AFTER', 'unknown-field', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-EMPTY-ROLEIDS-NEGATIVE-BEFORE', 'empty-roleIds', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-EMPTY-ROLEIDS-NEGATIVE-AFTER', 'empty-roleIds', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-EMPTY-ROLEIDS-TWIN-BEFORE', 'empty-roleIds', 'TWIN', 'before'),
    ('registry-installation-rid12-EMPTY-ROLEIDS-TWIN-AFTER', 'empty-roleIds', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-DUPLICATE-ROLEIDS-NEGATIVE-BEFORE', 'duplicate-roleIds', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-DUPLICATE-ROLEIDS-NEGATIVE-AFTER', 'duplicate-roleIds', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-DUPLICATE-ROLEIDS-TWIN-BEFORE', 'duplicate-roleIds', 'TWIN', 'before'),
    ('registry-installation-rid12-DUPLICATE-ROLEIDS-TWIN-AFTER', 'duplicate-roleIds', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-EMPTY-TARGETTYPES-NEGATIVE-BEFORE', 'empty-targetTypes', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-EMPTY-TARGETTYPES-NEGATIVE-AFTER', 'empty-targetTypes', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-EMPTY-TARGETTYPES-TWIN-BEFORE', 'empty-targetTypes', 'TWIN', 'before'),
    ('registry-installation-rid12-EMPTY-TARGETTYPES-TWIN-AFTER', 'empty-targetTypes', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-DUPLICATE-TARGETTYPES-NEGATIVE-BEFORE', 'duplicate-targetTypes', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-DUPLICATE-TARGETTYPES-NEGATIVE-AFTER', 'duplicate-targetTypes', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-DUPLICATE-TARGETTYPES-TWIN-BEFORE', 'duplicate-targetTypes', 'TWIN', 'before'),
    ('registry-installation-rid12-DUPLICATE-TARGETTYPES-TWIN-AFTER', 'duplicate-targetTypes', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-EMPTY-SUBJECTTYPES-NEGATIVE-BEFORE', 'empty-subjectTypes', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-EMPTY-SUBJECTTYPES-NEGATIVE-AFTER', 'empty-subjectTypes', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-EMPTY-SUBJECTTYPES-TWIN-BEFORE', 'empty-subjectTypes', 'TWIN', 'before'),
    ('registry-installation-rid12-EMPTY-SUBJECTTYPES-TWIN-AFTER', 'empty-subjectTypes', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-DUPLICATE-SUBJECTTYPES-NEGATIVE-BEFORE', 'duplicate-subjectTypes', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-DUPLICATE-SUBJECTTYPES-NEGATIVE-AFTER', 'duplicate-subjectTypes', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-DUPLICATE-SUBJECTTYPES-TWIN-BEFORE', 'duplicate-subjectTypes', 'TWIN', 'before'),
    ('registry-installation-rid12-DUPLICATE-SUBJECTTYPES-TWIN-AFTER', 'duplicate-subjectTypes', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-ROLES17-NEGATIVE-BEFORE', 'roles17', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-ROLES17-NEGATIVE-AFTER', 'roles17', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-ROLES17-TWIN-BEFORE', 'roles17', 'TWIN', 'before'),
    ('registry-installation-rid12-ROLES17-TWIN-AFTER', 'roles17', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-TYPES17-NEGATIVE-BEFORE', 'types17', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-TYPES17-NEGATIVE-AFTER', 'types17', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-TYPES17-TWIN-BEFORE', 'types17', 'TWIN', 'before'),
    ('registry-installation-rid12-TYPES17-TWIN-AFTER', 'types17', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-SUBJECTS5-NEGATIVE-BEFORE', 'subjects5', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-SUBJECTS5-NEGATIVE-AFTER', 'subjects5', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-SUBJECTS5-TWIN-BEFORE', 'subjects5', 'TWIN', 'before'),
    ('registry-installation-rid12-SUBJECTS5-TWIN-AFTER', 'subjects5', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-SUBJECT-UNSPECIFIED-NEGATIVE-BEFORE', 'subject-unspecified', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-SUBJECT-UNSPECIFIED-NEGATIVE-AFTER', 'subject-unspecified', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-SUBJECT-UNSPECIFIED-TWIN-BEFORE', 'subject-unspecified', 'TWIN', 'before'),
    ('registry-installation-rid12-SUBJECT-UNSPECIFIED-TWIN-AFTER', 'subject-unspecified', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-SUBJECT-UNKNOWN-NEGATIVE-BEFORE', 'subject-unknown', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-SUBJECT-UNKNOWN-NEGATIVE-AFTER', 'subject-unknown', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-SUBJECT-UNKNOWN-TWIN-BEFORE', 'subject-unknown', 'TWIN', 'before'),
    ('registry-installation-rid12-SUBJECT-UNKNOWN-TWIN-AFTER', 'subject-unknown', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-IAM-ROLE-NEGATIVE-BEFORE', 'iam-role', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-IAM-ROLE-NEGATIVE-AFTER', 'iam-role', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-IAM-ROLE-TWIN-BEFORE', 'iam-role', 'TWIN', 'before'),
    ('registry-installation-rid12-IAM-ROLE-TWIN-AFTER', 'iam-role', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-IAM-TYPE-NEGATIVE-BEFORE', 'iam-type', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-IAM-TYPE-NEGATIVE-AFTER', 'iam-type', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-IAM-TYPE-TWIN-BEFORE', 'iam-type', 'TWIN', 'before'),
    ('registry-installation-rid12-IAM-TYPE-TWIN-AFTER', 'iam-type', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-IAM-MODULE-NEGATIVE-BEFORE', 'iam-module', 'NEGATIVE', 'before'),
    ('registry-installation-rid12-IAM-MODULE-NEGATIVE-AFTER', 'iam-module', 'NEGATIVE', 'after-negative'),
    ('registry-installation-rid12-IAM-MODULE-TWIN-BEFORE', 'iam-module', 'TWIN', 'before'),
    ('registry-installation-rid12-IAM-MODULE-TWIN-AFTER', 'iam-module', 'TWIN', 'after-positive'),
    ('registry-installation-rid12-ABSENT-NO-GD-BEFORE', 'absent', 'NO-GD', 'before'),
    ('registry-installation-rid12-ABSENT-NO-GD-AFTER', 'absent', 'NO-GD', 'after-positive'),
    ('registry-installation-rid12-EMPTY-NO-GD-BEFORE', 'empty', 'NO-GD', 'before'),
    ('registry-installation-rid12-EMPTY-NO-GD-AFTER', 'empty', 'NO-GD', 'after-positive'),
    ('registry-installation-rid12-ROLES17-TWIN-AFTER-REORDER', 'roles17', 'TWIN', 'after-reorder'),
]

for case_id, name, kind, phase in _PHASES:
    delivered = phase != 'before' and kind != 'NEGATIVE'
    config = _CONFIG
    for key, value in {
        '__CASE__': js_str(case_id), '__NAME__': js_str(name), '__KIND__': js_str(kind), '__PHASE__': js_str(phase),
        '__SA__': '5' if delivered else '3', '__GD__': '6' if delivered and kind == 'TWIN' else '0',
        '__MISSING__': '\n'.join(precondition_not_met('RID12 exact same-world full primary snapshot',
          'Missing/incompatible complete RID12 inventory; no public verdict', indent='  ')),
    }.items():
        config = config.replace(key, value)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me', auth='jwtRIDOperator',
                  pre_script=config.splitlines(), test_script=[*assert_status(200),
                  "const e = JSON.parse(pm.environment.get('rid12Expected'));",
                  "const j = pm.response.json();",
                  "pm.test('actual independent ordinary O',()=>{pm.expect(j.subject).to.eql('user:'+e.operatorId);pm.expect(j.userId).to.eql(e.operatorId);});"])]
    reads = midrun_read_steps(Step, assert_status, js_str, expected_var='rid12Expected')
    # A closed GD0 phase has no Get item at generation time. Its real List
    # leaves still traverse every account and prove exact empty primary census.
    # All 16 nonempty phases retain EVERY primary GD Get and List/Get equality.
    if not (delivered and kind == 'TWIN'):
        reads = [step for step in reads if step.name != 'every-Get-delegations']
    steps += reads
    CASES.append(Case(id=case_id,title='RID12 public '+name+' '+kind+' '+phase,
                      classes=['CONF','CRUD'],priority='P0',steps=steps))
CASES = address_own_front(CASES, 'RID12 observes the same isolated standalone Kaname public origin')
