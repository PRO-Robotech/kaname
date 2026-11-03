# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID10-only read-only page/Get builders; caller supplies real generator symbols.

Adapted from frozen RID09 source; that approved source is never modified or
imported/executed as a side effect. No network/setup actions live in this module.
"""
def _entity_steps(Step, assert_status, js_str, entity, route, response_key, scoped=False, get=True):
    replacements = {'__ENTITY__': js_str(entity), '__RESPONSE__': js_str(response_key),
                    '__SCOPED__': 'true' if scoped else 'false'}
    script = r"""
const k = __ENTITY__, responseKey = __RESPONSE__;
const p = JSON.parse(pm.environment.get('rid10Expected')).snapshot.projection;
const j = pm.response.json();
const rows = j[responseKey];
const seen = JSON.parse(pm.environment.get('rid10Seen_' + k));
const listed = JSON.parse(pm.environment.get('rid10Listed_' + k));
const account = pm.environment.get('rid10Account_' + k);
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
pm.environment.set('rid10Seen_' + k, JSON.stringify(seen));
pm.environment.set('rid10Listed_' + k, JSON.stringify(listed));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid10Tokens_' + k));
  pm.test('fresh noncyclic continuation ' + k, () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid10Tokens_' + k, JSON.stringify(tokens));
  pm.environment.set('rid10Page_' + k, j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete independently expected membership for scope ' + k, () => {
    const expected = p[k].filter(x => !__SCOPED__ || x.accountId === account).map(x => x.id).sort();
    const actual = seen.filter(id => !__SCOPED__ || listed[id].accountId === account).sort();
    pm.expect(actual).to.eql(expected);
  });
  const index = Number(pm.environment.get('rid10AccountIndex_' + k)) + 1;
  if (__SCOPED__ && index < p.accounts.length) {
    pm.environment.set('rid10AccountIndex_' + k, String(index));
    pm.environment.set('rid10Account_' + k, p.accounts[index].id);
    pm.environment.set('rid10Page_' + k, '');
    pm.environment.set('rid10Tokens_' + k, '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('ALL primary List identities across all scopes ' + k, () =>
      pm.expect([...seen].sort()).to.eql(p[k].map(x => x.id).sort()));
  }
}
""".strip()
    detail = r"""
const k = __ENTITY__;
const p = JSON.parse(pm.environment.get('rid10Expected')).snapshot.projection;
const index = Number(pm.environment.get('rid10GetIndex_' + k));
const listed = JSON.parse(pm.environment.get('rid10Listed_' + k));
const seen = JSON.parse(pm.environment.get('rid10Got_' + k));
const got = pm.response.json();
pm.test('full primary fields plus complete List/Get equality ' + k, () => {
  pm.expect(p[k][index]).to.be.an('object');
  pm.expect(got).to.eql(p[k][index]);
  pm.expect(listed[got.id]).to.be.an('object');
  pm.expect(got).to.eql(listed[got.id]);
  pm.expect(seen).not.to.include(got.id);
});
seen.push(got.id);
pm.environment.set('rid10Got_' + k, JSON.stringify(seen));
if (index + 1 < p[k].length) {
  pm.environment.set('rid10GetIndex_' + k, String(index + 1));
  pm.environment.set('rid10GetId_' + k, p[k][index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('EVERY primary/List object has exactly one Get ' + k, () => {
    pm.expect([...seen].sort()).to.eql(p[k].map(x => x.id).sort());
    pm.expect([...seen].sort()).to.eql(JSON.parse(pm.environment.get('rid10Seen_' + k)).sort());
  });
}
""".strip()
    for a, b in replacements.items():
        script = script.replace(a, b)
        detail = detail.replace(a, b)
    path = route + '?pageSize=2&pageToken={{rid10Page_' + entity + '}}'
    if scoped:
        path += '&accountId={{rid10Account_' + entity + '}}'
    if entity == 'bindings':
        path += '&includeRevoked=true'
    steps = [Step(name='complete-pages-' + entity, method='GET', path=path,
                  auth='jwtRIDOperator', test_script=[*assert_status(200), *script.splitlines()])]
    if get:
        steps.append(Step(name='every-Get-' + entity, method='GET',
                          path=route + '/{{rid10GetId_' + entity + '}}', auth='jwtRIDOperator',
                          test_script=[*assert_status(200), *detail.splitlines()]))
    return steps

_MEMBERS = r"""
const p = JSON.parse(pm.environment.get('rid10Expected')).snapshot.projection;
const group = pm.environment.get('rid10GroupId');
const j = pm.response.json(), rows = j.members;
const allSeen = JSON.parse(pm.environment.get('rid10MembersSeen'));
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
pm.environment.set('rid10MembersSeen', JSON.stringify(allSeen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid10MembersTokens'));
  pm.test('fresh noncyclic member page token', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid10MembersTokens', JSON.stringify(tokens));
  pm.environment.set('rid10MembersPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete primary joins for this group including empty groups', () =>
    pm.expect([...seen].sort()).to.eql(p.members[group].map(key).sort()));
  const index = Number(pm.environment.get('rid10GroupIndex')) + 1;
  if (index < p.groups.length) {
    pm.environment.set('rid10GroupIndex', String(index));
    pm.environment.set('rid10GroupId', p.groups[index].id);
    pm.environment.set('rid10MembersPage', '');
    pm.environment.set('rid10MembersTokens', '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('EVERY primary/List/Get group has complete public member pages', () =>
      pm.expect(Object.keys(allSeen).sort()).to.eql(p.groups.map(x => x.id).sort()));
  }
}
""".strip().splitlines()

def midrun_read_steps(Step, assert_status, js_str):
    catalog = [*assert_status(200),
               "const e = JSON.parse(pm.environment.get('rid10Expected'));",
               "pm.test('entire primary permissionCatalog', () => pm.expect(pm.response.json()).to.eql(e.snapshot.projection.catalog));"]
    steps = [Step(name='complete-permission-catalog', method='GET', path='/iam/v1/permissionCatalog',
                  auth='jwtRIDOperator', test_script=catalog)]
    for entity, route, response_key, scoped in [
        ('accounts', '/iam/v1/accounts', 'accounts', False),
        ('serviceAccounts', '/iam/v1/serviceAccounts', 'serviceAccounts', True),
        ('groups', '/iam/v1/groups', 'groups', True),
        ('roles', '/iam/v1/roles', 'roles', False),
        ('bindings', '/iam/v1/accessBindings', 'accessBindings', False),
        ('delegations', '/iam/v1/grantDelegations', 'grantDelegations', True),
    ]:
        steps += _entity_steps(Step, assert_status, js_str, entity, route, response_key, scoped=scoped)
    steps.append(Step(name='complete-all-group-member-pages', method='GET',
                      path='/iam/v1/groups/{{rid10GroupId}}:listMembers?pageSize=2&pageToken={{rid10MembersPage}}',
                      auth='jwtRIDOperator', test_script=[*assert_status(200), *_MEMBERS]))
    return steps
