# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID02 read-only public consequences in the SAME two native worlds.

Producer: full startup world + independent primary RO projections. Secrets are
passed to the owned Newman child on stdin, never in a collection or argv.
Four literal phases surround actual full-serve axis reorder in S1/S2.
Expected N=1/3 is fixed independently; SYS is always excluded.
"""
HOME = "kaname"
CASES = []

_ME = [
    *assert_status(200),
    "const j = pm.response.json();",
    "const e = JSON.parse(pm.environment.get('rid02Expected'));",
    "pm.test('same independently authenticated O', () => {",
    "  pm.expect(j.subject).to.eql('user:' + e.operatorId);",
    "  pm.expect(j.userId).to.eql(e.operatorId);",
    "});",
]
_CONFIG = """
const e = JSON.parse(pm.environment.get('rid02Expected') || 'null');
const expectedPhase = __PHASE__;
const valid = e && e.phase === expectedPhase &&
  Array.isArray(e.accounts) && Array.isArray(e.delegatedAccounts) &&
  Array.isArray(e.serviceAccounts) && Array.isArray(e.delegations) &&
  Array.isArray(e.previousDelegations) && e.operatorId && e.creatorId && e.systemId;
if (!valid) {
__MISSING__
} else {
  pm.test('RID02 exact phase and complete primary producer', () => {
    pm.expect(e.accounts.length).to.eql(__ACCOUNTS__);
    pm.expect(new Set(e.accounts).size).to.eql(e.accounts.length);
    pm.expect(e.accounts).to.include(e.systemId);
    pm.expect(e.serviceAccounts.length).to.eql(4);
    pm.expect(e.delegatedAccounts.length).to.eql(__N__);
    pm.expect(new Set(e.delegatedAccounts).size).to.eql(__N__);
    pm.expect(e.delegatedAccounts).not.to.include(e.systemId);
    pm.expect(e.delegations.length).to.eql(__PAIRS__);
    pm.expect(e.previousDelegations.length).to.eql(__PREVIOUS__);
    pm.expect(e.mode).to.eql(__MODE__);
    pm.expect(e.issuerId).to.be.a('string').and.not.empty;
    pm.expect(e.issuerId).not.to.eql(e.creatorId);
    pm.expect(e.serviceAccounts.map(x => x.id)).to.include(e.creatorId).and.include(e.issuerId);
    pm.expect(e.serviceAccounts.filter(x => x.name === 'svc-ridbounds').map(x => x.id)).to.eql([e.issuerId]);
    if (__N__ === 3) {
      pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);
      pm.expect(e.delegatedAccounts).to.include(e.tenantNamedSystem);
    }
  });
  pm.environment.set('rid02AccountsSeen', '[]');
  pm.environment.set('rid02AccountTokens', '[""]');
  pm.environment.set('rid02AccountsPage', '');
  pm.environment.set('rid02SASeen', '[]');
  pm.environment.set('rid02SAList', '{}');
  pm.environment.set('rid02SAGetSeen', '[]');
  pm.environment.set('rid02SADetailIndex', '0');
  pm.environment.set('rid02SAId', e.serviceAccounts[0].id);
  pm.environment.set('rid02SATokens', '[""]');
  pm.environment.set('rid02SAPage', '');
  pm.environment.set('rid02GDSeen', '[]');
  pm.environment.set('rid02GDList', '{}');
  pm.environment.set('rid02GDGetSeen', '[]');
  pm.environment.set('rid02GDTokens', '[""]');
  pm.environment.set('rid02GDPage', '');
  pm.environment.set('rid02AccountIndex', '0');
  pm.environment.set('rid02Account', e.accounts[0]);
  pm.environment.set('rid02DetailIndex', '0');
  pm.environment.set('rid02GDId', e.delegations.length ? e.delegations[0].id : '');
}
""".strip().splitlines()
_ACCOUNTS = """
const e = JSON.parse(pm.environment.get('rid02Expected'));
const j = pm.response.json();
const rows = j.accounts || [];
const seen = JSON.parse(pm.environment.get('rid02AccountsSeen'));
pm.test('complete canonical account page of size2', () => {
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach((x) => {
  pm.test('account identity is present in primary and not duplicated', () => {
    pm.expect(e.accounts).to.include(x.id);
    pm.expect(seen).not.to.include(x.id);
  });
  seen.push(x.id);
});
pm.environment.set('rid02AccountsSeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid02AccountTokens'));
  pm.test('account page token is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid02AccountTokens', JSON.stringify(tokens));
  pm.environment.set('rid02AccountsPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('public canonical account IDs equal the complete independent primary census', () =>
    pm.expect([...seen].sort()).to.eql([...e.accounts].sort()));
}
""".strip().splitlines()
_SA_FIELDS = """
function checkSA(x, expected) {
  pm.expect(expected).to.be.an('object');
  ['id', 'accountId', 'name', 'createdAt'].forEach(k => pm.expect(x[k]).to.eql(expected[k]));
  pm.expect(x.description || '').to.eql(expected.description);
  pm.expect(x.labels || {}).to.eql(expected.labels);
  pm.expect(x.enabled || false).to.eql(expected.enabled);
  pm.expect(Object.keys(x).sort()).to.satisfy(keys => keys.every(k =>
    ['id', 'accountId', 'name', 'description', 'labels', 'enabled', 'createdAt'].includes(k)));
}
""".strip().splitlines()
_SA = """
const j = pm.response.json();
const e = JSON.parse(pm.environment.get('rid02Expected'));
const seen = JSON.parse(pm.environment.get('rid02SASeen'));
const listed = JSON.parse(pm.environment.get('rid02SAList'));
const rows = j.serviceAccounts || [];
pm.test('SYS SA page answered with at most pageSize2', () => {
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach((x) => {
  const expected = e.serviceAccounts.find((y) => y.id === x.id);
  pm.test('exact primary complete SA identity/status/description/labels/timestamp', () => {
    pm.expect(expected).to.be.an('object');
    pm.expect(seen).not.to.include(x.id);
    checkSA(x, expected);
  });
  seen.push(x.id);
});
rows.forEach((x) => { listed[x.id] = x; });
pm.environment.set('rid02SAList', JSON.stringify(listed));
pm.environment.set('rid02SASeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid02SATokens'));
  pm.test('SA next page is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid02SATokens', JSON.stringify(tokens));
  pm.environment.set('rid02SAPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete SYS SA membership equals primary and includes C plus declared I', () =>
    pm.expect([...seen].sort()).to.eql(e.serviceAccounts.map((x) => x.id).sort()));
}
""".strip().splitlines()
_SA_DETAIL = """
const e = JSON.parse(pm.environment.get('rid02Expected'));
const index = Number(pm.environment.get('rid02SADetailIndex'));
const expected = e.serviceAccounts[index];
const got = pm.response.json();
const listed = JSON.parse(pm.environment.get('rid02SAList'));
const seen = JSON.parse(pm.environment.get('rid02SAGetSeen'));
pm.test('SA Get exact independent primary identity name account timestamp and complete List object', () => {
  pm.expect(expected).to.be.an('object');
  pm.expect(seen).not.to.include(got.id);
  checkSA(got, expected);
  pm.expect(got.accountId).to.eql(e.systemId);
  pm.expect(listed[got.id]).to.be.an('object');
  pm.expect(got).to.eql(listed[got.id]);
});
seen.push(got.id);
pm.environment.set('rid02SAGetSeen', JSON.stringify(seen));
if (index + 1 < e.serviceAccounts.length) {
  pm.environment.set('rid02SADetailIndex', String(index + 1));
  pm.environment.set('rid02SAId', e.serviceAccounts[index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('ALL four SA Get IDs equal complete primary and List membership', () => {
    pm.expect(seen.length).to.eql(4);
    pm.expect([...seen].sort()).to.eql(e.serviceAccounts.map((x) => x.id).sort());
    pm.expect([...seen].sort()).to.eql(JSON.parse(pm.environment.get('rid02SASeen')).sort());
  });
}
""".strip().splitlines()
_GD_FIELDS = """
function checkGD(x, expected) {
  pm.expect(expected).to.be.an('object');
  ['id', 'accountId', 'module', 'status', 'createdAt'].forEach((k) =>
    pm.expect(x[k]).to.eql(expected[k]));
  pm.expect(x.delegate).to.eql(expected.delegate);
  pm.expect(x.delegatedBy).to.eql(expected.delegatedBy);
  ['roleIds', 'targetTypes', 'subjectTypes'].forEach((k) =>
    pm.expect([...(x[k] || [])].sort()).to.eql([...expected[k]].sort()));
  pm.expect(x.revokedAt === undefined || x.revokedAt === null).to.eql(true);
  pm.expect(x.revokedBy === undefined || x.revokedBy === null).to.eql(true);
  pm.expect(Object.keys(x)).to.satisfy(keys => keys.every(k =>
    ['id', 'accountId', 'module', 'status', 'createdAt', 'delegate', 'delegatedBy',
     'roleIds', 'targetTypes', 'subjectTypes', 'revokedAt', 'revokedBy'].includes(k)));
}
""".strip().splitlines()
_GD = [
    *_GD_FIELDS,
    *"""
const j = pm.response.json();
const e = JSON.parse(pm.environment.get('rid02Expected'));
const seen = JSON.parse(pm.environment.get('rid02GDSeen'));
const account = pm.environment.get('rid02Account');
const listed = JSON.parse(pm.environment.get('rid02GDList'));
const rows = j.grantDelegations || [];
pm.test('account GD page answered with at most pageSize2', () => {
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach((x) => {
  pm.test('exact primary GD, canonical SYS exclusion and no duplicate', () => {
    pm.expect(e.delegatedAccounts).to.include(account);
    pm.expect(x.accountId).to.eql(account);
    pm.expect(seen).not.to.include(x.id);
    checkGD(x, e.delegations.find((y) => y.id === x.id));
  });
  seen.push(x.id);
  listed[x.id] = x;
});
pm.environment.set('rid02GDList', JSON.stringify(listed));
pm.environment.set('rid02GDSeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid02GDTokens'));
  pm.test('GD next page is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid02GDTokens', JSON.stringify(tokens));
  pm.environment.set('rid02GDPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  const index = Number(pm.environment.get('rid02AccountIndex')) + 1;
  if (index < e.accounts.length) {
    pm.environment.set('rid02AccountIndex', String(index));
    pm.environment.set('rid02Account', e.accounts[index]);
    pm.environment.set('rid02GDPage', '');
    pm.environment.set('rid02GDTokens', '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('complete public N/IDs equal independent primary expectation', () => {
      pm.expect([...seen].sort()).to.eql(e.delegations.map((x) => x.id).sort());
      e.delegatedAccounts.forEach((a) => {
        const pairs = e.delegations.filter((x) => x.accountId === a);
        pm.expect(pairs.map((x) => x.module)).to.eql(['ridbounds']);
        pairs.forEach(x => pm.expect(x.delegate.id).to.eql(e.issuerId));
      });
      e.previousDelegations.forEach((old) => {
        const current = e.delegations.find((x) => x.id === old.id);
        pm.expect(current).to.eql(old);
      });
    });
  }
}
""".strip().splitlines(),
]
_DETAIL = [
    *_GD_FIELDS,
    *"""
const e = JSON.parse(pm.environment.get('rid02Expected'));
const index = Number(pm.environment.get('rid02DetailIndex'));
const got = pm.response.json();
const seen = JSON.parse(pm.environment.get('rid02GDGetSeen'));
const listed = JSON.parse(pm.environment.get('rid02GDList'));
pm.test('public Get preserves primary full fields and complete List object', () => {
  checkGD(got, e.delegations[index]);
  pm.expect(listed[got.id]).to.be.an('object');
  pm.expect(got).to.eql(listed[got.id]);
  pm.expect(seen).not.to.include(got.id);
});
seen.push(got.id);
pm.environment.set('rid02GDGetSeen', JSON.stringify(seen));
if (index + 1 < e.delegations.length) {
  pm.environment.set('rid02DetailIndex', String(index + 1));
  pm.environment.set('rid02GDId', e.delegations[index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('every primary and List GD has one public Get', () => {
    pm.expect([...seen].sort()).to.eql(e.delegations.map(x => x.id).sort());
    pm.expect([...seen].sort()).to.eql(JSON.parse(pm.environment.get('rid02GDSeen')).sort());
  });
}
""".strip().splitlines(),
]

# Literal mandatory phases; existing RID08 source remains untouched.
for case_id, mode, phase, n, accounts, previous in [
    ("registry-installation-rid02-S1-BEFORE-REORDER", "S1", "BEFORE-REORDER", 1, 2, 0),
    ("registry-installation-rid02-S1-AFTER-REORDER", "S1", "AFTER-REORDER", 1, 2, 1),
    ("registry-installation-rid02-S2-BEFORE-REORDER", "S2", "BEFORE-REORDER", 3, 4, 0),
    ("registry-installation-rid02-S2-AFTER-REORDER", "S2", "AFTER-REORDER", 3, 4, 3),
]:
    replacements = {
        "__PHASE__": js_str(phase), "__MODE__": js_str(mode), "__N__": str(n),
        "__ACCOUNTS__": str(accounts), "__PAIRS__": str(n), "__PREVIOUS__": str(previous),
        "__MISSING__": "\n".join(precondition_not_met(
            "RID02 same-world primary producer and exact phase",
            "Missing/incompatible live RID02 fixture; no public verdict is possible", indent="  ")),
    }
    config = "\n".join(_CONFIG)
    for key, value in replacements.items():
        config = config.replace(key, value)
    steps = [
        Step(name="same-ordinary-O", method="GET", path="/iam/v1/me", auth="jwtRIDOperator",
             pre_script=config.splitlines(), test_script=_ME),
        Step(name="complete-all-account-pages", method="GET",
             path="/iam/v1/accounts?pageSize=2&pageToken={{rid02AccountsPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_ACCOUNTS]),
        Step(name="complete-SYS-SA-pages", method="GET",
             path="/iam/v1/serviceAccounts?accountId={{ridSystemId}}&pageSize=2&pageToken={{rid02SAPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_SA_FIELDS, *_SA]),
        Step(name="each-SYS-SA-public-Get", method="GET",
             path="/iam/v1/serviceAccounts/{{rid02SAId}}", auth="jwtRIDOperator",
             test_script=[*assert_status(200), *_SA_FIELDS, *_SA_DETAIL]),
        Step(name="complete-all-account-GD-pages", method="GET",
             path="/iam/v1/grantDelegations?accountId={{rid02Account}}&pageSize=2&pageToken={{rid02GDPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_GD]),
        Step(name="each-GD-public-Get", method="GET",
             path="/iam/v1/grantDelegations/{{rid02GDId}}", auth="jwtRIDOperator",
             test_script=[*assert_status(200), *_DETAIL]),
    ]
    CASES.append(Case(id=case_id, title="RID02 public " + mode + " " + phase,
                      classes=["CONF", "CRUD"], priority="P0", steps=steps))
CASES = address_own_front(CASES, "RID02 uses the same isolated standalone Kaname public front")
