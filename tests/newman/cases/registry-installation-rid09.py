# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID09: 32 literal read-only phases in the 16 existing S2/N3 worlds.

All expected payloads are from the parent primary RO/RR snapshot, never from
native REST observations. No token/setup mutation occurs in these cases.
"""
HOME = "kaname"
CASES = []

_CONFIG = r"""
const e = JSON.parse(pm.environment.get('rid09Expected') || 'null');
const keys = ['accounts', 'serviceAccounts', 'groups', 'roles', 'bindings', 'delegations'];
const complete = p => p && keys.every(k => Array.isArray(p[k])) &&
  p.members && typeof p.members === 'object' && !Array.isArray(p.members) &&
  p.catalog && Array.isArray(p.catalog.modules) && Array.isArray(p.catalog.closedVerbs) &&
  Array.isArray(p.catalog.retiredResources) && p.catalog.wildcardPolicy &&
  Object.keys(p.members).length === p.groups.length &&
  p.groups.every(g => Array.isArray(p.members[g.id]));
const valid = e && e.caseId === __CASE__ && e.phase === __PHASE__ &&
  e.axis === __AXIS__ && e.reverse === __REVERSE__ && e.twin === __TWIN__ && e.n === 3 &&
  e.operatorId && e.creatorId && e.systemId && e.tenantNamedSystem && complete(e.projection) &&
  (__BEFORE__ ? e.previousProjection === null : complete(e.previousProjection));
if (!valid) {
__MISSING__
} else {
  const p = e.projection;
  pm.test('exact live phase and complete primary inventories with independent N and delta', () => {
    pm.expect(p.accounts.length).to.eql(4);
    pm.expect(p.serviceAccounts.length).to.eql(__SA__);
    pm.expect(p.delegations.length).to.eql(__GD__);
    pm.expect(p.groups.length).to.be.above(0);
    pm.expect(p.roles.length).to.be.above(0);
    pm.expect(p.bindings.length).to.be.above(0);
    keys.forEach(k => pm.expect(new Set(p[k].map(x => x.id)).size).to.eql(p[k].length));
    pm.expect(p.accounts.map(x => x.id)).to.include(e.systemId).and.include(e.tenantNamedSystem);
    pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);
    p.accounts.filter(x => x.id !== e.systemId).forEach(x => pm.expect(x.ownerUserId).to.eql(e.operatorId));
    pm.expect(p.serviceAccounts.map(x => x.id)).to.include(e.creatorId);
    p.serviceAccounts.forEach(x => pm.expect(x.accountId).to.eql(e.systemId));
    pm.expect(Object.keys(p.members).sort()).to.eql(p.groups.map(x => x.id).sort());
    p.groups.forEach(g => pm.expect(p.members[g.id]).to.be.an('array'));
    ['ridfirst', 'ridsecond'].forEach(module => {
      const mods = p.catalog.modules.filter(x => x.module === module);
      const roles = p.roles.filter(x => x.name === module + '.reader');
      const groups = p.groups.filter(x => x.name === module + '-readers');
      const issuers = p.serviceAccounts.filter(x => x.name === 'svc-' + module);
      [mods, roles, groups, issuers].forEach(rows => pm.expect(rows.length).to.eql(__DELIVERED__ ? 1 : 0));
      if (__DELIVERED__) {
        pm.expect(issuers[0].enabled).to.eql(true);
        pm.expect(issuers[0].id).not.to.eql(e.creatorId);
        pm.expect(mods[0].resources.map(x => x.resource)).to.eql(['objects']);
        pm.expect([...mods[0].resources[0].verbs].sort()).to.eql(['get', 'list']);
        pm.expect(roles[0].definitionTier).to.eql({tierType:'iam.cluster', tierId:'cluster_root'});
        pm.expect(roles[0].rules.length).to.eql(1);
        pm.expect(roles[0].rules[0].module).to.eql(module);
        pm.expect(roles[0].rules[0].resources).to.eql(['objects']);
        pm.expect([...roles[0].rules[0].verbs].sort()).to.eql(['get', 'list']);
        const writers = p.groups.filter(x => x.accountId === e.systemId && x.name === 'module-relation-writers');
        pm.expect(writers.length).to.eql(1);
        pm.expect(p.members[writers[0].id].filter(x => x.memberType === 'service_account' && x.memberId === issuers[0].id).length).to.eql(1);
        const bindings = p.bindings.filter(x => x.roleId === roles[0].id && x.subjectId === groups[0].id);
        pm.expect(bindings.length).to.eql(1);
        pm.expect(bindings[0].scopeType).to.eql('iam.cluster');
        pm.expect(bindings[0].scopeId).to.eql('cluster_root');
        pm.expect(bindings[0].subjects).to.eql([{type:'SUBJECT_TYPE_GROUP',id:groups[0].id}]);
        pm.expect(bindings[0].target).to.eql({allInScope:{}});
        pm.expect(bindings[0].system).to.eql(true);
        pm.expect(bindings[0].deletionProtection).to.eql(true);
        p.accounts.filter(x => x.id !== e.systemId).forEach(account => {
          const rows = p.delegations.filter(x => x.accountId === account.id && x.module === module);
          pm.expect(rows.length).to.eql(1);
          pm.expect(rows[0].roleIds).to.eql([roles[0].id]);
          pm.expect(rows[0].targetTypes).to.eql([module + '.objects']);
          pm.expect(rows[0].subjectTypes).to.eql(['SUBJECT_TYPE_SERVICE_ACCOUNT']);
          pm.expect(rows[0].delegate).to.eql({type:'SUBJECT_TYPE_SERVICE_ACCOUNT',id:issuers[0].id});
          pm.expect(rows[0].delegatedBy).to.eql({type:'service_account',id:e.creatorId});
          pm.expect(rows[0].status).to.eql('ACTIVE');
          pm.expect(rows[0].revokedAt).to.eql(null);
          pm.expect(rows[0].revokedBy).to.eql(null);
        });
      }
    });
    pm.expect(p.delegations.filter(x => x.accountId === e.systemId)).to.eql([]);
    if (!__BEFORE__ && !__DELIVERED__) {
      pm.expect(p).to.eql(e.previousProjection);
    }
    if (__DELIVERED__) {
      pm.expect(p.accounts).to.eql(e.previousProjection.accounts);
      pm.expect(p.serviceAccounts.length).to.eql(e.previousProjection.serviceAccounts.length + 2);
      e.previousProjection.serviceAccounts.forEach(old =>
        pm.expect(p.serviceAccounts.find(x => x.id === old.id)).to.eql(old));
      pm.expect(p.roles.length).to.eql(e.previousProjection.roles.length + 2);
      pm.expect(p.groups.length).to.eql(e.previousProjection.groups.length + 2);
      pm.expect(p.bindings.length).to.eql(e.previousProjection.bindings.length + 2);
      const count = m => Object.values(m).reduce((n, rows) => n + rows.length, 0);
      pm.expect(count(p.members)).to.eql(count(e.previousProjection.members) + 2);
    }
  });
  keys.forEach(k => {
    pm.environment.set('rid09Seen_' + k, '[]');
    pm.environment.set('rid09Listed_' + k, '{}');
    pm.environment.set('rid09Tokens_' + k, '[""]');
    pm.environment.set('rid09Page_' + k, '');
    pm.environment.set('rid09AccountIndex_' + k, '0');
    pm.environment.set('rid09Account_' + k, p.accounts[0].id);
    pm.environment.set('rid09GetIndex_' + k, '0');
    pm.environment.set('rid09GetId_' + k, p[k].length ? p[k][0].id : '');
    pm.environment.set('rid09Got_' + k, '[]');
  });
  pm.environment.set('rid09GroupIndex', '0');
  pm.environment.set('rid09GroupId', p.groups[0].id);
  pm.environment.set('rid09MembersSeen', '{}');
  pm.environment.set('rid09MembersTokens', '[""]');
  pm.environment.set('rid09MembersPage', '');
}
""".strip()

_ME = [*assert_status(200), *"""
const e = JSON.parse(pm.environment.get('rid09Expected'));
const j = pm.response.json();
pm.test('actual same ordinary O authenticated identity', () => {
  pm.expect(j.subject).to.eql('user:' + e.operatorId);
  pm.expect(j.userId).to.eql(e.operatorId);
});
""".strip().splitlines()]

# This builder is local to this slice. Generator-injected Step/assert_status are
# passed from the same case module; there is no imagined imported helper API.
def _entity_steps(entity, route, response_key, scoped=False, get=True):
    replacements = {'__ENTITY__': js_str(entity), '__RESPONSE__': js_str(response_key),
                    '__SCOPED__': 'true' if scoped else 'false'}
    script = r"""
const k = __ENTITY__, responseKey = __RESPONSE__;
const p = JSON.parse(pm.environment.get('rid09Expected')).projection;
const j = pm.response.json();
const rows = j[responseKey];
const seen = JSON.parse(pm.environment.get('rid09Seen_' + k));
const listed = JSON.parse(pm.environment.get('rid09Listed_' + k));
const account = pm.environment.get('rid09Account_' + k);
pm.test('complete primary-backed pageSize2 page ' + k, () => {
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach(x => {
  pm.test('full primary object and unique List identity ' + k, () => {
    const expected = p[k].find(y => y.id === x.id);
    pm.expect(expected).to.be.an('object');
    pm.expect(seen).not.to.include(x.id);
    if (__SCOPED__) pm.expect(x.accountId).to.eql(account);
    pm.expect(x).to.eql(expected);
  });
  seen.push(x.id); listed[x.id] = x;
});
pm.environment.set('rid09Seen_' + k, JSON.stringify(seen));
pm.environment.set('rid09Listed_' + k, JSON.stringify(listed));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid09Tokens_' + k));
  pm.test('fresh noncyclic continuation ' + k, () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid09Tokens_' + k, JSON.stringify(tokens));
  pm.environment.set('rid09Page_' + k, j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete independently expected membership for scope ' + k, () => {
    const expected = p[k].filter(x => !__SCOPED__ || x.accountId === account).map(x => x.id).sort();
    const actual = seen.filter(id => !__SCOPED__ || listed[id].accountId === account).sort();
    pm.expect(actual).to.eql(expected);
  });
  const index = Number(pm.environment.get('rid09AccountIndex_' + k)) + 1;
  if (__SCOPED__ && index < p.accounts.length) {
    pm.environment.set('rid09AccountIndex_' + k, String(index));
    pm.environment.set('rid09Account_' + k, p.accounts[index].id);
    pm.environment.set('rid09Page_' + k, '');
    pm.environment.set('rid09Tokens_' + k, '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('ALL primary List identities across all scopes ' + k, () =>
      pm.expect([...seen].sort()).to.eql(p[k].map(x => x.id).sort()));
  }
}
""".strip()
    detail = r"""
const k = __ENTITY__;
const p = JSON.parse(pm.environment.get('rid09Expected')).projection;
const index = Number(pm.environment.get('rid09GetIndex_' + k));
const listed = JSON.parse(pm.environment.get('rid09Listed_' + k));
const seen = JSON.parse(pm.environment.get('rid09Got_' + k));
const got = pm.response.json();
pm.test('full primary fields plus complete List/Get equality ' + k, () => {
  pm.expect(p[k][index]).to.be.an('object');
  pm.expect(got).to.eql(p[k][index]);
  pm.expect(listed[got.id]).to.be.an('object');
  pm.expect(got).to.eql(listed[got.id]);
  pm.expect(seen).not.to.include(got.id);
});
seen.push(got.id);
pm.environment.set('rid09Got_' + k, JSON.stringify(seen));
if (index + 1 < p[k].length) {
  pm.environment.set('rid09GetIndex_' + k, String(index + 1));
  pm.environment.set('rid09GetId_' + k, p[k][index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('EVERY primary/List object has exactly one Get ' + k, () => {
    pm.expect([...seen].sort()).to.eql(p[k].map(x => x.id).sort());
    pm.expect([...seen].sort()).to.eql(JSON.parse(pm.environment.get('rid09Seen_' + k)).sort());
  });
}
""".strip()
    for a, b in replacements.items():
        script = script.replace(a, b)
        detail = detail.replace(a, b)
    path = route + '?pageSize=2&pageToken={{rid09Page_' + entity + '}}'
    if scoped:
        path += '&accountId={{rid09Account_' + entity + '}}'
    if entity == 'bindings':
        path += '&includeRevoked=true'
    steps = [Step(name='complete-pages-' + entity, method='GET', path=path,
                  auth='jwtRIDOperator', test_script=[*assert_status(200), *script.splitlines()])]
    if get:
        steps.append(Step(name='every-Get-' + entity, method='GET',
                          path=route + '/{{rid09GetId_' + entity + '}}', auth='jwtRIDOperator',
                          test_script=[*assert_status(200), *detail.splitlines()]))
    return steps

_CATALOG = [*assert_status(200), *"""
const p = JSON.parse(pm.environment.get('rid09Expected')).projection;
pm.test('ENTIRE public permission catalog including retired/common/wildcard fields equals primary', () =>
  pm.expect(pm.response.json()).to.eql(p.catalog));
""".strip().splitlines()]
_MEMBERS = [*assert_status(200), *r"""
const p = JSON.parse(pm.environment.get('rid09Expected')).projection;
const group = pm.environment.get('rid09GroupId');
const j = pm.response.json(), rows = j.members;
const allSeen = JSON.parse(pm.environment.get('rid09MembersSeen'));
const seen = allSeen[group] || [];
const key = x => x.memberType + '/' + x.memberId;
pm.test('real group membership pageSize2 from a primary group', () => {
  pm.expect(p.groups.map(x => x.id)).to.include(group);
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach(x => {
  pm.test('exact member type/ID/addedAt and no duplicate join', () => {
    const expected = p.members[group].find(y => key(y) === key(x));
    pm.expect(expected).to.be.an('object');
    pm.expect(x).to.eql(expected);
    pm.expect(seen).not.to.include(key(x));
  }); seen.push(key(x));
});
allSeen[group] = seen;
pm.environment.set('rid09MembersSeen', JSON.stringify(allSeen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid09MembersTokens'));
  pm.test('fresh noncyclic member page token', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid09MembersTokens', JSON.stringify(tokens));
  pm.environment.set('rid09MembersPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete primary joins for this group including empty groups', () =>
    pm.expect([...seen].sort()).to.eql(p.members[group].map(key).sort()));
  const index = Number(pm.environment.get('rid09GroupIndex')) + 1;
  if (index < p.groups.length) {
    pm.environment.set('rid09GroupIndex', String(index));
    pm.environment.set('rid09GroupId', p.groups[index].id);
    pm.environment.set('rid09MembersPage', '');
    pm.environment.set('rid09MembersTokens', '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('EVERY primary/List/Get group has complete public member pages', () =>
      pm.expect(Object.keys(allSeen).sort()).to.eql(p.groups.map(x => x.id).sort()));
  }
}
""".strip().splitlines()]

# The 32 approved IDs remain literal source declarations, independent of reports.
for case_id, axis, reverse, twin, before in [
    ('registry-installation-rid09-ROLEIDS-M1-M2-NEGATIVE-BEFORE', 'roleIds', False, False, True),
    ('registry-installation-rid09-ROLEIDS-M1-M2-NEGATIVE-AFTER', 'roleIds', False, False, False),
    ('registry-installation-rid09-ROLEIDS-M1-M2-TWIN-BEFORE', 'roleIds', False, True, True),
    ('registry-installation-rid09-ROLEIDS-M1-M2-TWIN-AFTER', 'roleIds', False, True, False),
    ('registry-installation-rid09-ROLEIDS-M2-M1-NEGATIVE-BEFORE', 'roleIds', True, False, True),
    ('registry-installation-rid09-ROLEIDS-M2-M1-NEGATIVE-AFTER', 'roleIds', True, False, False),
    ('registry-installation-rid09-ROLEIDS-M2-M1-TWIN-BEFORE', 'roleIds', True, True, True),
    ('registry-installation-rid09-ROLEIDS-M2-M1-TWIN-AFTER', 'roleIds', True, True, False),
    ('registry-installation-rid09-TARGETTYPES-M1-M2-NEGATIVE-BEFORE', 'targetTypes', False, False, True),
    ('registry-installation-rid09-TARGETTYPES-M1-M2-NEGATIVE-AFTER', 'targetTypes', False, False, False),
    ('registry-installation-rid09-TARGETTYPES-M1-M2-TWIN-BEFORE', 'targetTypes', False, True, True),
    ('registry-installation-rid09-TARGETTYPES-M1-M2-TWIN-AFTER', 'targetTypes', False, True, False),
    ('registry-installation-rid09-TARGETTYPES-M2-M1-NEGATIVE-BEFORE', 'targetTypes', True, False, True),
    ('registry-installation-rid09-TARGETTYPES-M2-M1-NEGATIVE-AFTER', 'targetTypes', True, False, False),
    ('registry-installation-rid09-TARGETTYPES-M2-M1-TWIN-BEFORE', 'targetTypes', True, True, True),
    ('registry-installation-rid09-TARGETTYPES-M2-M1-TWIN-AFTER', 'targetTypes', True, True, False),
    ('registry-installation-rid09-SUBJECTTYPES-M1-M2-NEGATIVE-BEFORE', 'subjectTypes', False, False, True),
    ('registry-installation-rid09-SUBJECTTYPES-M1-M2-NEGATIVE-AFTER', 'subjectTypes', False, False, False),
    ('registry-installation-rid09-SUBJECTTYPES-M1-M2-TWIN-BEFORE', 'subjectTypes', False, True, True),
    ('registry-installation-rid09-SUBJECTTYPES-M1-M2-TWIN-AFTER', 'subjectTypes', False, True, False),
    ('registry-installation-rid09-SUBJECTTYPES-M2-M1-NEGATIVE-BEFORE', 'subjectTypes', True, False, True),
    ('registry-installation-rid09-SUBJECTTYPES-M2-M1-NEGATIVE-AFTER', 'subjectTypes', True, False, False),
    ('registry-installation-rid09-SUBJECTTYPES-M2-M1-TWIN-BEFORE', 'subjectTypes', True, True, True),
    ('registry-installation-rid09-SUBJECTTYPES-M2-M1-TWIN-AFTER', 'subjectTypes', True, True, False),
    ('registry-installation-rid09-DELEGATE-M1-M2-NEGATIVE-BEFORE', 'delegate', False, False, True),
    ('registry-installation-rid09-DELEGATE-M1-M2-NEGATIVE-AFTER', 'delegate', False, False, False),
    ('registry-installation-rid09-DELEGATE-M1-M2-TWIN-BEFORE', 'delegate', False, True, True),
    ('registry-installation-rid09-DELEGATE-M1-M2-TWIN-AFTER', 'delegate', False, True, False),
    ('registry-installation-rid09-DELEGATE-M2-M1-NEGATIVE-BEFORE', 'delegate', True, False, True),
    ('registry-installation-rid09-DELEGATE-M2-M1-NEGATIVE-AFTER', 'delegate', True, False, False),
    ('registry-installation-rid09-DELEGATE-M2-M1-TWIN-BEFORE', 'delegate', True, True, True),
    ('registry-installation-rid09-DELEGATE-M2-M1-TWIN-AFTER', 'delegate', True, True, False),

]:
    delivered = twin and not before
    phase = 'before' if before else ('after-positive' if twin else 'after-negative')
    replacements = {
        '__CASE__': js_str(case_id), '__PHASE__': js_str(phase), '__AXIS__': js_str(axis),
        '__REVERSE__': str(reverse).lower(), '__TWIN__': str(twin).lower(),
        '__BEFORE__': str(before).lower(), '__DELIVERED__': str(delivered).lower(),
        '__SA__': '5' if delivered else '3', '__GD__': '6' if delivered else '0',
        '__MISSING__': '\n'.join(precondition_not_met(
            'RID09 complete live same-world primary producer and literal phase',
            'Missing/partial/incompatible primary RID09 inventory; no public verdict is possible', indent='  ')),
    }
    config = _CONFIG
    for a, b in replacements.items():
        config = config.replace(a, b)
    steps = [Step(name='same-ordinary-O', method='GET', path='/iam/v1/me',
                  auth='jwtRIDOperator', pre_script=config.splitlines(), test_script=_ME),
             Step(name='complete-permission-catalog', method='GET', path='/iam/v1/permissionCatalog',
                  auth='jwtRIDOperator', test_script=_CATALOG)]
    steps += _entity_steps('accounts', '/iam/v1/accounts', 'accounts')
    steps += _entity_steps('serviceAccounts', '/iam/v1/serviceAccounts', 'serviceAccounts', scoped=True)
    steps += _entity_steps('groups', '/iam/v1/groups', 'groups', scoped=True)
    steps.append(Step(name='complete-all-group-member-pages', method='GET',
                      path='/iam/v1/groups/{{rid09GroupId}}:listMembers?pageSize=2&pageToken={{rid09MembersPage}}',
                      auth='jwtRIDOperator', test_script=_MEMBERS))
    steps += _entity_steps('roles', '/iam/v1/roles', 'roles')
    steps += _entity_steps('bindings', '/iam/v1/accessBindings', 'accessBindings')
    steps += _entity_steps('delegations', '/iam/v1/grantDelegations', 'grantDelegations', scoped=True, get=delivered)
    CASES.append(Case(id=case_id, title='RID09 entire public projection ' + case_id,
                      classes=['CONF', 'CRUD'], priority='P0', steps=steps))
CASES = address_own_front(CASES, 'RID09 observes the same isolated standalone Kaname public front')
