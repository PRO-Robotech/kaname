# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RID08 public consequences in the SAME live native fixture.

Producer: full startup world + independent primary RO projections. Secrets are
passed to the owned Newman child on stdin, never in a collection or argv.
Each phase is a separate mandatory folder; its expected N is fixed below.
The native coordinator must execute ALL six phases, not choose a convenient one.
"""
HOME = "kaname"
CASES = []

_ME = [
    *assert_status(200),
    "const j = pm.response.json();",
    "const e = JSON.parse(pm.environment.get('rid08Expected'));",
    "pm.test('same independently authenticated O', () => {",
    "  pm.expect(j.subject).to.eql('user:' + e.operatorId);",
    "  pm.expect(j.userId).to.eql(e.operatorId);",
    "});",
]
_CONFIG = """
const e = JSON.parse(pm.environment.get('rid08Expected') || 'null');
const expectedPhase = __PHASE__;
const valid = e && e.phase === expectedPhase &&
  Array.isArray(e.accounts) && Array.isArray(e.delegatedAccounts) &&
  Array.isArray(e.serviceAccounts) && Array.isArray(e.delegations) &&
  Array.isArray(e.previousDelegations) && e.operatorId && e.creatorId && e.systemId;
if (!valid) {
__MISSING__
} else {
  pm.test('RID08 exact phase and complete primary producer', () => {
    pm.expect(e.accounts.length).to.eql(__ACCOUNTS__);
    pm.expect(new Set(e.accounts).size).to.eql(e.accounts.length);
    pm.expect(e.accounts).to.include(e.systemId);
    pm.expect(e.serviceAccounts.length).to.eql(5);
    pm.expect(e.delegatedAccounts.length).to.eql(__N__);
    pm.expect(new Set(e.delegatedAccounts).size).to.eql(__N__);
    pm.expect(e.delegatedAccounts).not.to.include(e.systemId);
    pm.expect(e.delegations.length).to.eql(__PAIRS__);
    pm.expect(e.previousDelegations.length).to.eql(__PREVIOUS__);
    if (__N__ > 0) {
      pm.expect(e.tenantNamedSystem).not.to.eql(e.systemId);
      pm.expect(e.delegatedAccounts).to.include(e.tenantNamedSystem);
    }
    if (expectedPhase === 'first-n3') {
      pm.expect(e.accounts).to.include(e.futureAccountId);
      pm.expect(e.delegatedAccounts).not.to.include(e.futureAccountId);
    }
    if (expectedPhase === 'repeat-n4') {
      pm.expect(e.delegatedAccounts).to.include(e.futureAccountId);
    }
  });
  pm.environment.set('rid08AccountsSeen', '[]');
  pm.environment.set('rid08AccountTokens', '[""]');
  pm.environment.set('rid08AccountsPage', '');
  pm.environment.set('rid08SASeen', '[]');
  pm.environment.set('rid08SAList', '{}');
  pm.environment.set('rid08SAGetSeen', '[]');
  pm.environment.set('rid08SADetailIndex', '0');
  pm.environment.set('rid08SAId', e.serviceAccounts[0].id);
  pm.environment.set('rid08SATokens', '[""]');
  pm.environment.set('rid08SAPage', '');
  pm.environment.set('rid08GDSeen', '[]');
  pm.environment.set('rid08GDTokens', '[""]');
  pm.environment.set('rid08GDPage', '');
  pm.environment.set('rid08AccountIndex', '0');
  pm.environment.set('rid08Account', e.accounts[0]);
  pm.environment.set('rid08DetailIndex', '0');
  pm.environment.set('rid08GDId', e.delegations.length ? e.delegations[0].id : '');
}
""".strip().splitlines()
_ACCOUNTS = """
const e = JSON.parse(pm.environment.get('rid08Expected'));
const j = pm.response.json();
const rows = j.accounts || [];
const seen = JSON.parse(pm.environment.get('rid08AccountsSeen'));
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
pm.environment.set('rid08AccountsSeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid08AccountTokens'));
  pm.test('account page token is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid08AccountTokens', JSON.stringify(tokens));
  pm.environment.set('rid08AccountsPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('public canonical account IDs equal the complete independent primary census', () =>
    pm.expect([...seen].sort()).to.eql([...e.accounts].sort()));
}
""".strip().splitlines()
_SA = """
const j = pm.response.json();
const e = JSON.parse(pm.environment.get('rid08Expected'));
const seen = JSON.parse(pm.environment.get('rid08SASeen'));
const listed = JSON.parse(pm.environment.get('rid08SAList'));
const rows = j.serviceAccounts || [];
pm.test('SYS SA page answered with at most pageSize2', () => {
  pm.expect(rows).to.be.an('array');
  pm.expect(rows.length).to.be.at.most(2);
});
rows.forEach((x) => {
  const expected = e.serviceAccounts.find((y) => y.id === x.id);
  pm.test('exact primary SA identity/name/account/timestamp', () => {
    pm.expect(expected).to.be.an('object');
    pm.expect(seen).not.to.include(x.id);
    pm.expect(x.accountId).to.eql(e.systemId);
    pm.expect(x.name).to.eql(expected.name);
    pm.expect(x.createdAt).to.eql(expected.createdAt);
  });
  seen.push(x.id);
});
rows.forEach((x) => { listed[x.id] = x; });
pm.environment.set('rid08SAList', JSON.stringify(listed));
pm.environment.set('rid08SASeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid08SATokens'));
  pm.test('SA next page is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid08SATokens', JSON.stringify(tokens));
  pm.environment.set('rid08SAPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('complete SYS SA membership equals primary and includes C plus both I', () =>
    pm.expect([...seen].sort()).to.eql(e.serviceAccounts.map((x) => x.id).sort()));
}
""".strip().splitlines()
_SA_DETAIL = """
const e = JSON.parse(pm.environment.get('rid08Expected'));
const index = Number(pm.environment.get('rid08SADetailIndex'));
const expected = e.serviceAccounts[index];
const got = pm.response.json();
const listed = JSON.parse(pm.environment.get('rid08SAList'));
const seen = JSON.parse(pm.environment.get('rid08SAGetSeen'));
pm.test('SA Get exact independent primary identity name account timestamp and complete List object', () => {
  pm.expect(expected).to.be.an('object');
  pm.expect(seen).not.to.include(got.id);
  ['id', 'name', 'accountId', 'createdAt'].forEach((k) => pm.expect(got[k]).to.eql(expected[k]));
  pm.expect(got.accountId).to.eql(e.systemId);
  pm.expect(listed[got.id]).to.be.an('object');
  pm.expect(got).to.eql(listed[got.id]);
});
seen.push(got.id);
pm.environment.set('rid08SAGetSeen', JSON.stringify(seen));
if (index + 1 < e.serviceAccounts.length) {
  pm.environment.set('rid08SADetailIndex', String(index + 1));
  pm.environment.set('rid08SAId', e.serviceAccounts[index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  pm.test('ALL five SA Get IDs equal complete primary and List membership', () => {
    pm.expect(seen.length).to.eql(5);
    pm.expect([...seen].sort()).to.eql(e.serviceAccounts.map((x) => x.id).sort());
    pm.expect([...seen].sort()).to.eql(JSON.parse(pm.environment.get('rid08SASeen')).sort());
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
    pm.expect(x[k]).to.eql(expected[k]));
  pm.expect(x.revokedAt || null).to.eql(null);
  pm.expect(x.revokedBy || null).to.eql(null);
}
""".strip().splitlines()
_GD = [
    *_GD_FIELDS,
    *"""
const j = pm.response.json();
const e = JSON.parse(pm.environment.get('rid08Expected'));
const seen = JSON.parse(pm.environment.get('rid08GDSeen'));
const account = pm.environment.get('rid08Account');
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
});
pm.environment.set('rid08GDSeen', JSON.stringify(seen));
if (j.nextPageToken) {
  const tokens = JSON.parse(pm.environment.get('rid08GDTokens'));
  pm.test('GD next page is fresh', () => pm.expect(tokens).not.to.include(j.nextPageToken));
  tokens.push(j.nextPageToken);
  pm.environment.set('rid08GDTokens', JSON.stringify(tokens));
  pm.environment.set('rid08GDPage', j.nextPageToken);
  pm.execution.setNextRequest(pm.info.requestName);
} else {
  const index = Number(pm.environment.get('rid08AccountIndex')) + 1;
  if (index < e.accounts.length) {
    pm.environment.set('rid08AccountIndex', String(index));
    pm.environment.set('rid08Account', e.accounts[index]);
    pm.environment.set('rid08GDPage', '');
    pm.environment.set('rid08GDTokens', '[""]');
    pm.execution.setNextRequest(pm.info.requestName);
  } else {
    pm.test('complete public N/IDs equal independent primary expectation', () => {
      pm.expect([...seen].sort()).to.eql(e.delegations.map((x) => x.id).sort());
      e.delegatedAccounts.forEach((a) => {
        const pairs = e.delegations.filter((x) => x.accountId === a);
        pm.expect(pairs.map((x) => x.module).sort()).to.eql(['ridfirst', 'ridsecond']);
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
const e = JSON.parse(pm.environment.get('rid08Expected'));
const index = Number(pm.environment.get('rid08DetailIndex'));
pm.test('public Get preserves exact ID/axes/creator/time', () =>
  checkGD(pm.response.json(), e.delegations[index]));
if (index + 1 < e.delegations.length) {
  pm.environment.set('rid08DetailIndex', String(index + 1));
  pm.environment.set('rid08GDId', e.delegations[index + 1].id);
  pm.execution.setNextRequest(pm.info.requestName);
}
""".strip().splitlines(),
]

# Every generated Case ID is listed literally in docs/CASES-INDEX.md.
for case_id, phase, n, accounts, previous in [
    ("registry-installation-rid08-FIRST-N3", "first-n3", 3, 5, 0),
    ("registry-installation-rid08-REPEAT-N4", "repeat-n4", 4, 5, 6),
    ("registry-installation-rid08-EMPTY-N0", "empty-n0", 0, 1, 0),
    ("registry-installation-rid08-LATE-FAULT-N0", "late-fault-n0", 0, 4, 0),
    ("registry-installation-rid08-FAULT-TWIN-N3", "fault-twin-n3", 3, 4, 0),
    ("registry-installation-rid08-RETRY-N3", "retry-n3", 3, 4, 6),
]:
    replacements = {
        "__PHASE__": js_str(phase), "__N__": str(n), "__ACCOUNTS__": str(accounts),
        "__PAIRS__": str(2*n), "__PREVIOUS__": str(previous),
        "__MISSING__": "\n".join(precondition_not_met(
            "RID08 live primary producer and exact phase",
            "Missing/incompatible live RID08 fixture; no public verdict is possible", indent="  ")),
    }
    config = "\n".join(_CONFIG)
    for key, value in replacements.items():
        config = config.replace(key, value)
    steps = [
        Step(name="same-ordinary-O", method="GET", path="/iam/v1/me", auth="jwtRIDOperator",
             pre_script=config.splitlines(), test_script=_ME),
        Step(name="complete-all-account-pages", method="GET",
             path="/iam/v1/accounts?pageSize=2&pageToken={{rid08AccountsPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_ACCOUNTS]),
        Step(name="complete-SYS-SA-pages", method="GET",
             path="/iam/v1/serviceAccounts?accountId={{ridSystemId}}&pageSize=2&pageToken={{rid08SAPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_SA]),
        Step(name="each-SYS-SA-public-Get", method="GET",
             path="/iam/v1/serviceAccounts/{{rid08SAId}}", auth="jwtRIDOperator",
             test_script=[*assert_status(200), *_SA_DETAIL]),
        Step(name="complete-all-account-GD-pages", method="GET",
             path="/iam/v1/grantDelegations?accountId={{rid08Account}}&pageSize=2&pageToken={{rid08GDPage}}",
             auth="jwtRIDOperator", test_script=[*assert_status(200), *_GD]),
    ]
    if n:
        steps.append(Step(name="each-GD-public-Get", method="GET",
                          path="/iam/v1/grantDelegations/{{rid08GDId}}", auth="jwtRIDOperator",
                          test_script=[*assert_status(200), *_DETAIL]))
    else:
        steps.append(Step(name="same-O-after-zero-public-census", method="GET",
                          path="/iam/v1/me", auth="jwtRIDOperator", test_script=_ME))
    if phase == "empty-n0":
        steps.append(Step(name="deleted-A-remains-absent", method="GET",
                          path="/iam/v1/accounts/{{ridDeletedAccountId}}", auth="jwtRIDOperator",
                          test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND")]))
    CASES.append(Case(id=case_id, title="RID08 public " + phase,
                      classes=["CONF", "CRUD"], priority="P0", steps=steps))
CASES = address_own_front(CASES, "RID08 uses the same isolated standalone Kaname public front")
