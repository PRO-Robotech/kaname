# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Six mandatory RID10 phases in the four existing generic Kaname worlds.

Snapshot reads use O. Only /me ownership proof and stored C-owned Operation.Get
use the lawfully authenticated C bearer (separate root FD5 extension required).
Node remains restricted to the existing owned public origin, with no issuance.
"""

HOME = 'kaname'
CASES = []
_CONFIG = r"""
const e = JSON.parse(pm.environment.get('rid10Expected') || 'null');
const keys = ['accounts', 'serviceAccounts', 'groups', 'roles', 'bindings', 'delegations'];
const complete = s => s && Array.isArray(s.operations) && s.operations.length > 0 &&
  s.projection && keys.every(k => Array.isArray(s.projection[k])) &&
  s.projection.members && typeof s.projection.members === 'object' &&
  !Array.isArray(s.projection.members) && s.projection.catalog &&
  Array.isArray(s.projection.catalog.modules) && Array.isArray(s.projection.catalog.closedVerbs) &&
  Array.isArray(s.projection.catalog.retiredResources) && s.projection.catalog.wildcardPolicy &&
  Object.keys(s.projection.members).length === s.projection.groups.length &&
  s.projection.groups.every(g => Array.isArray(s.projection.members[g.id]));
const valid = e && e.caseId === __CASE__ && e.mode === __MODE__ && e.phase === __PHASE__ &&
  e.operatorId && e.creatorId && e.systemId && e.issuerId && e.tenantNamedSystem &&
  e.firstAccountId && e.firstGDId && e.oldGId && complete(e.snapshot) &&
  (__RECOVERED__ ? complete(e.previousSnapshot) : e.previousSnapshot === null) &&
  pm.environment.get('jwtRIDCreator');
if (!valid) {
__MISSING__
} else {
  const p = e.snapshot.projection;
  pm.test('complete primary phase with literal N3 and exact independent counts', () => {
    pm.expect(p.accounts.length).to.eql(4);
    pm.expect(p.serviceAccounts.length).to.eql(6);
    pm.expect(p.serviceAccounts.filter(x => x.accountId === e.systemId).length).to.eql(5);
    pm.expect(p.delegations.length).to.eql(__GD__);
    pm.expect(e.snapshot.operations.length).to.eql(__OPS__);
    keys.forEach(k => pm.expect(new Set(p[k].map(x => x.id)).size).to.eql(p[k].length));
    pm.expect(new Set(e.snapshot.operations.map(x => x.id)).size).to.eql(__OPS__);
    pm.expect(p.groups.length).to.be.above(0);
    pm.expect(p.roles.length).to.be.above(0);
    pm.expect(p.bindings.length).to.be.above(0);
    const normal = p.accounts.filter(x => x.id !== e.systemId).map(x => x.id).sort();
    pm.expect(normal.length).to.eql(3);
    pm.expect(normal).to.include(e.tenantNamedSystem);
    pm.expect(normal[0]).to.eql(e.firstAccountId);
    pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);
    p.accounts.filter(x => x.id !== e.systemId).forEach(x => pm.expect(x.ownerUserId).to.eql(e.operatorId));
    const issuer = p.serviceAccounts.filter(x => x.accountId === e.systemId && x.name === 'rid-public-issuer');
    pm.expect(issuer.map(x => x.id)).to.eql([e.issuerId]);
    pm.expect(issuer[0].enabled).to.eql(true);
    pm.expect(e.issuerId).not.to.eql(e.creatorId);
    pm.expect(p.serviceAccounts.filter(x => x.accountId === e.systemId && x.name === 'kacho-registry').length).to.eql(1);
    const grantees = p.serviceAccounts.filter(x => x.accountId !== e.systemId);
    pm.expect(grantees.length).to.eql(1);
    pm.expect(grantees[0].accountId).to.eql(e.firstAccountId);
    pm.expect(grantees[0].name).to.eql('rid10-first-grantee');
    const roles = p.roles.filter(x => x.name === 'registry.puller');
    pm.expect(roles.length).to.eql(1);
    const first = p.delegations.find(x => x.id === e.firstGDId);
    pm.expect(first).to.be.an('object');
    pm.expect(first.accountId).to.eql(e.firstAccountId);
    p.delegations.forEach(x => {
      pm.expect(normal).to.include(x.accountId);
      pm.expect(x.module).to.eql('registry');
      pm.expect(x.status).to.eql('ACTIVE');
      pm.expect(x.roleIds).to.eql([roles[0].id]);
      pm.expect(x.targetTypes).to.eql(['registry.registries']);
      pm.expect(x.subjectTypes).to.eql(['SUBJECT_TYPE_SERVICE_ACCOUNT']);
      pm.expect(x.delegate).to.eql({type:'SUBJECT_TYPE_SERVICE_ACCOUNT',id:e.issuerId});
      pm.expect(x.delegatedBy).to.eql({type:'service_account',id:e.creatorId});
      pm.expect(x.revokedAt).to.eql(null);
      pm.expect(x.revokedBy).to.eql(null);
    });
    pm.expect(new Set(p.delegations.map(x => x.accountId)).size).to.eql(__GD__);
    pm.expect(p.delegations.filter(x => x.accountId === e.systemId)).to.eql([]);
    const old = p.bindings.find(x => x.id === e.oldGId);
    pm.expect(old).to.be.an('object');
    pm.expect(old.status).to.eql('ACTIVE');
    pm.expect(old.delegationId).to.eql(e.firstGDId);
    pm.expect(old.roleId).to.eql(roles[0].id);
    pm.expect(old.scopeType).to.eql('iam.account');
    pm.expect(old.scopeId).to.eql(e.firstAccountId);
    pm.expect(old.subjects).to.eql([{type:'SUBJECT_TYPE_SERVICE_ACCOUNT',id:grantees[0].id}]);
    pm.expect(old.target).to.eql({resources:{resources:[{type:'registry.registries',id:'rid-native-registry'}]}});
    pm.expect(old.materializedAt).to.be.a('string').and.not.empty;
    pm.expect(old.revokedAt).to.eql(null);
    const failed = e.snapshot.operations.filter(x => x.error);
    pm.expect(failed.length).to.eql(__FAILED__);
    if (__FAILED__) {
      pm.expect(failed[0].id).to.eql(e.failedOperationId);
      pm.expect(failed[0].done).to.eql(true);
      pm.expect(failed[0].error.code).to.eql(13);
      pm.expect(failed[0].error.message).to.eql('internal error');
      pm.expect(failed[0].metadata.accountId).to.eql(normal[1]);
      pm.expect(failed[0]).not.to.have.property('response');
    } else {
      pm.expect(e.failedOperationId).to.eql('');
    }
    e.snapshot.operations.forEach(x => {
      pm.expect(x.done).to.eql(true);
      pm.expect(x.principalType).to.eql('service_account');
      pm.expect(x.principalId).to.eql(e.creatorId);
      pm.expect(normal).to.include(x.metadata.accountId);
      if (!x.error) {
        const gd = p.delegations.find(y => y.id === x.metadata.grantDelegationId);
        pm.expect(gd).to.be.an('object');
        const response = {...x.response}; delete response['@type'];
        pm.expect(response).to.eql(gd);
      }
    });
    if (__RECOVERED__) {
      const previous = e.previousSnapshot;
      previous.projection.delegations.forEach(x => pm.expect(p.delegations.find(y => y.id === x.id)).to.eql(x));
      pm.expect(p.bindings.find(x => x.id === e.oldGId)).to.eql(previous.projection.bindings.find(x => x.id === e.oldGId));
      previous.operations.forEach(x => pm.expect(e.snapshot.operations.find(y => y.id === x.id)).to.eql(x));
      pm.expect(e.snapshot.operations.length).to.eql(previous.operations.length + 3);
    }
  });
  keys.forEach(k => {
    pm.environment.set('rid10Seen_' + k, '[]');
    pm.environment.set('rid10Listed_' + k, '{}');
    pm.environment.set('rid10Tokens_' + k, '[""]');
    pm.environment.set('rid10Page_' + k, '');
    pm.environment.set('rid10AccountIndex_' + k, '0');
    pm.environment.set('rid10Account_' + k, p.accounts[0].id);
    pm.environment.set('rid10GetIndex_' + k, '0');
    pm.environment.set('rid10GetId_' + k, p[k].length ? p[k][0].id : '');
    pm.environment.set('rid10Got_' + k, '[]');
  });
  pm.environment.set('rid10GroupIndex', '0');
  pm.environment.set('rid10GroupId', p.groups[0].id);
  pm.environment.set('rid10MembersSeen', '{}');
  pm.environment.set('rid10MembersTokens', '[""]');
  pm.environment.set('rid10MembersPage', '');
  pm.environment.set('rid10OperationIndex', '0');
  pm.environment.set('rid10OperationId', e.snapshot.operations[0].id);
  pm.environment.set('rid10OperationsSeen', '[]');
}
""".strip()
_ME_O = [*assert_status(200),
         "const e = JSON.parse(pm.environment.get('rid10Expected'));",
         "const j = pm.response.json();",
         "pm.test('actual ordinary O is independently authenticated', () => { pm.expect(j.subject).to.eql('user:' + e.operatorId); pm.expect(j.userId).to.eql(e.operatorId); });"]
_ME_C = [*assert_status(200),
         "const e = JSON.parse(pm.environment.get('rid10Expected'));",
         "const j = pm.response.json();",
         "pm.test('actual lawful C owns the observed Operations, independently of admin authority', () => { pm.expect(j.subject).to.eql('service_account:' + e.creatorId); pm.expect(j.userId || '').to.eql(''); });"]
_OPERATIONS = [*assert_status(200), *r"""
const e = JSON.parse(pm.environment.get('rid10Expected'));
const index = Number(pm.environment.get('rid10OperationIndex'));
const expected = e.snapshot.operations[index];
const got = pm.response.json();
// Счётчик привязан к текущему ID: переход к следующей строке не подменяет опрос этой операции.
const operationId = pm.environment.get('rid10OperationId');
if (pm.environment.get('rid10OperationPollId') !== operationId) {
  pm.environment.set('rid10OperationPollId', operationId);
  pm.environment.set('rid10OperationPollCount', '0');
}
const polls = Number(pm.environment.get('rid10OperationPollCount'));
if (!got.done && expected && got.id === operationId && expected.id === operationId && polls < __POLL_CAP__) {
  pm.environment.set('rid10OperationPollCount', String(polls + 1));
  const _rid10PollStarted = Date.now(); while (Date.now() - _rid10PollStarted < 500) void 0;
  pm.execution.setNextRequest(pm.info.requestName);
  return;
}
pm.environment.unset('rid10OperationPollId');
pm.environment.unset('rid10OperationPollCount');
const seen = JSON.parse(pm.environment.get('rid10OperationsSeen'));
pm.test('actual creator-owned Operation.Get equals full primary row/Any/status projection', () => {
  pm.expect(expected).to.be.an('object');
  pm.expect(got).to.eql(expected);
  pm.expect(got.done).to.eql(true);
  pm.expect(got.principalType).to.eql('service_account');
  pm.expect(got.principalId).to.eql(e.creatorId);
  pm.expect(seen).not.to.include(got.id);
  if (got.id === e.failedOperationId) {
    pm.expect(got.error.code).to.eql(13);
    pm.expect(got.error.message).to.eql('internal error');
    pm.expect(got).not.to.have.property('response');
  }
});
seen.push(got.id);
pm.environment.set('rid10OperationsSeen', JSON.stringify(seen));
if (index + 1 < e.snapshot.operations.length) {
  pm.environment.set('rid10OperationIndex', String(index + 1));
  pm.environment.set('rid10OperationId', e.snapshot.operations[index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('EVERY independently inventoried normal GD Operation was really Get once', () =>
    pm.expect([...seen].sort()).to.eql(e.snapshot.operations.map(x => x.id).sort()));
}
""".replace("__POLL_CAP__", str(POLL_CAP)).strip().splitlines()]

# Six literal phases, no additional before/Newman case and no convenience subset.
for case_id, mode, phase, gd, ops, failed in [
    ('registry-installation-rid10-FAULT-PARTIAL', 'fault', 'partial', 1, 2, 1),
    ('registry-installation-rid10-FAULT-RECOVERED', 'fault', 'recovered', 3, 5, 1),
    ('registry-installation-rid10-FAULT-TWIN', 'fault', 'twin', 3, 3, 0),
    ('registry-installation-rid10-RETIREMENT-PARTIAL', 'retirement', 'partial', 1, 1, 0),
    ('registry-installation-rid10-RETIREMENT-RECOVERED', 'retirement', 'recovered', 3, 4, 0),
    ('registry-installation-rid10-RETIREMENT-TWIN', 'retirement', 'twin', 3, 3, 0),
]:
    replacements = {
        '__CASE__': js_str(case_id), '__MODE__': js_str(mode), '__PHASE__': js_str(phase),
        '__GD__': str(gd), '__OPS__': str(ops), '__FAILED__': str(failed),
        '__RECOVERED__': str(phase == 'recovered').lower(),
        '__MISSING__': '\n'.join(precondition_not_met(
            'RID10 complete same-world primary producer and audited lawful C bearer',
            'Missing/incompatible primary RID10 inventory or owner credential; no public verdict is possible', indent='  ')),
    }
    config = _CONFIG
    for a, b in replacements.items():
        config = config.replace(a, b)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me', auth='jwtRIDOperator',
                  pre_script=config.splitlines(), test_script=_ME_O),
             Step(name='lawful-C-Operation-owner', method='GET', path='/iam/v1/me',
                  auth='jwtRIDCreator', test_script=_ME_C)]
    steps += midrun_read_steps(Step, assert_status, js_str)
    steps.append(Step(name='every-primary-normal-GD-Operation-Get', method='GET',
                      path='/operations/{{rid10OperationId}}', auth='jwtRIDCreator', test_script=_OPERATIONS))
    CASES.append(Case(id=case_id, title='RID10 public ' + mode + ' ' + phase,
                      classes=['CONF', 'CRUD'], priority='P0', steps=steps))
CASES = address_own_front(CASES, 'RID10 observes the same isolated standalone Kaname public origin')
