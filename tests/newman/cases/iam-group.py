# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для GroupService + member management.

Covered RPCs:
  Create, Get, List, Update, Delete,
  AddMember, RemoveMember, ListMembers, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId (admin of accountAId)
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated, no account membership
    jwtInvitee        — JWT for user with binding on accountBId
    accountAId        — pre-seeded account for group scope
    accountBId        — cross-account (for isolation probes)
    userAAAId         — User.id of jwtAccountAdminA principal
    userNOBId         — User.id of jwtNoBindings principal
    userINVId         — User.id of jwtInvitee principal

  No additional env vars needed. The suite creates a FRESH group per runId
  ("grp-{{runId}}") in accountAId via jwtAccountAdminA. This avoids cross-test
  pollution while reusing seeded users for AddMember/RemoveMember.

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kacho-iam).

Gotchas:
  - AddMember with non-existent user/SA → FailedPrecondition (9) via
    group_members_member_exists_trg DB trigger (NOT a software refcheck).
  - Membership set-verbs are IDEMPOTENT, and that is the CONTRACT, not an
    accident: group_service.proto states it on both RPCs ("Идемпотентно:
    повторное добавление того же member'а — no-op" / "удаление
    несуществующего членства — no-op"), the use-cases implement it
    (add_member.go INSERT … ON CONFLICT DO NOTHING; remove_member.go treats 0
    rows affected as success), and it is the platform-wide semantics for
    collection membership (nlb TargetGroup.AddTargets, vpc
    Network/Subnet.AddCidrBlocks, iam access_binding_subjects — all ON CONFLICT
    DO NOTHING; data-integrity.md's attach template is idempotent by
    construction: "свободно ИЛИ уже наш"). So:
      * AddMember of an existing member  → Operation done, NO error, and the
        member appears EXACTLY ONCE (asserted, not assumed).
      * RemoveMember of a non-member     → Operation done, NO error, and the
        membership set is unchanged (asserted).
    A retried mutation is not an error; the failure modes worth reporting are
    "the row is missing" / "the row is duplicated", both of which these cases
    check through ListMembers instead of through an error code.
  - ListMembers is a custom method: `GET /iam/v1/groups/{group_id}:listMembers`
    (group_service.proto). It is NOT `/groups/{id}/members` — that path is not
    in the generated REST route table, so it resolves to no FQN and fail-closes
    on a permission-catalog miss (403 with an EMPTY `action`), which silently
    satisfies any assertion that only looks at the status code.
  - Group.List is scope-filtered: non-member gets 200 + empty list (like SA.List).
  - GroupService has no plain account-unscoped List; always ?accountId=<id>.

Case IDs follow the IAM-GRP-<RPC>-<CLASS>[-detail] scheme.

Acceptance scenarios:
  CreateGroup → id starts with `grp`.
  AddMember happy + idempotent (дубль → no-op, ровно одна строка членства).
  AddMember с несущ. user → FailedPrecondition (DB-триггер).
  RemoveMember + idempotent remove-of-non-member (набор членов не меняется).
  DeleteGroup с AccessBinding → FailedPrecondition (FK RESTRICT).

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  GroupService RPCs are correctly implemented in kacho-iam. Do not weaken
  assertions — fix the implementation instead.
"""

CASES = []

# Garbage id for negative probes.
GARBAGE_GRP = "grp00000000000notfnd"


# ---------------------------------------------------------------------------
# Helpers: IAM operation envelope assert (prefix `iop`)
# ---------------------------------------------------------------------------

def assert_iam_operation_envelope():
    return [
        "pm.test('IAM Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


# ---------------------------------------------------------------------------
# Helper: a 403 must be the deny we are actually testing, not a catalog miss.
#
# The api-gateway fail-closes with 403 AUTHZ_DENIED when the requested method
# has no permission-catalog entry — which is also what a MISROUTED path
# produces, because an unresolved path yields no FQN to look up. Both denials
# are `{"code":7}`, so a negative that asserts only the status code passes on
# either, and a wrong path turns the whole case into a tautology.
#
# The two are distinguishable in the body: a real per-object deny carries the
# resolved permission and scope in ErrorInfo.metadata (`action`, `resource`),
# whereas the catalog miss carries an EMPTY action (the descriptor is built
# before the entry is known). Asserting the action/resource pins the deny to
# the RPC and object under test.
# ---------------------------------------------------------------------------

def assert_scoped_authz_deny(action: str, resource_expr: str):
    """resource_expr is a JS expression (not a literal) — `{{var}}` is not
    interpolated inside test scripts, so a variable-bearing scope must be read
    with pm.environment.get()."""
    return [
        "pm.test('403 PermissionDenied (code 7)', () => {",
        "  pm.expect(pm.response.code).to.eql(403);",
        "  pm.expect(pm.response.json().code, pm.response.text()).to.eql(7);",
        "});",
        f"pm.test('deny is the scoped authz deny on {action}, not a permission-catalog miss', () => {{",
        "  const j = pm.response.json();",
        "  const info = (j.details || []).find(d => (d['@type'] || '').includes('ErrorInfo'));",
        "  pm.expect(info, 'ErrorInfo detail: ' + JSON.stringify(j)).to.be.an('object');",
        "  pm.expect(info.reason, JSON.stringify(j)).to.eql('AUTHZ_DENIED');",
        "  const md = info.metadata || {};",
        f"  pm.expect(md.action, 'empty action means the catalog had no entry for the method (misrouted path?): ' + JSON.stringify(j)).to.eql('{action}');",
        f"  pm.expect(md.resource, JSON.stringify(j)).to.eql({resource_expr});",
        "});",
    ]


# Permission + FGA object type of GroupService/ListMembers (permission_catalog.json).
LM_ACTION = "iam.group_memberses.listMembers"


# ---------------------------------------------------------------------------
# Helper: poll an Operation to done and assert it carries NO error.
#
# gen.py has poll_operation_until_done() (fixed `opId`) and assert_op_error()
# (asserts an error). The idempotent membership verbs need the third
# combination: a named op var, polled to done, asserted SUCCESSFUL.
#
# The busy-wait before setNextRequest is mandatory (testing.md): newman runs the
# test script synchronously and dispatches setNextRequest before any setTimeout
# callback, so without it the loop retries back-to-back and covers milliseconds
# instead of seconds.
# ---------------------------------------------------------------------------

def poll_until_done_no_error(why: str, cap: int = 50):
    delay = max(100, min(500, 30000 // cap))
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_okPollStarted') !== pm.info.requestName) {",
        "  pm.environment.set('_okPollCount', '0');",
        "  pm.environment.set('_okPollStarted', pm.info.requestName);",
        "}",
        "const pc = parseInt(pm.environment.get('_okPollCount') || '0', 10);",
        f"if (!j.done && pc < {cap}) {{",
        "  pm.environment.set('_okPollCount', String(pc + 1));",
        f"  const _ipd = Date.now(); while (Date.now() - _ipd < {delay}) void 0;",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_okPollCount');",
        "pm.environment.unset('_okPollStarted');",
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        f"pm.test('operation carries no error — {why}', () => {{",
        "  pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([undefined, null, 0]);",
        "});",
    ]


# ---------------------------------------------------------------------------
# IAM-GRP-CR-CRUD-OK — Create group → Operation done → Get confirms
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-CR-CRUD-OK",
    title="Create group in accountAId → Operation(iop) done → Get confirms id prefix `grp`",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "grp-{{runId}}", "description": "newman group create probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.groupId", "crudGroupId"),
            ],
        ),
        Step(
            name="poll-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('crudGroupId')) {",
                "  pm.environment.set('crudGroupId', j.response.id);",
                "}",
            ],
        ),
        # budget=60 (24s @ 400ms): `iam.group` maps to the LEAF FGA object_type
        # `iam_group` (authzmap fga_types), NOT a bare hierarchy ancestor like
        # `iam.project`→`project`. Under the flat Contract-A model a leaf type has NO
        # `<rel> from account` ACCESS cascade, so the account-admin's per-object v_get on
        # a freshly-created group is MATERIALIZED per-object (sync post-commit reconciler
        # + at-least-once event-drain fallback) — it is NOT resolved instantly by hierarchy
        # cascade the way a project GET is. A denied read hides existence as 404
        # ("iam_group not found"), so poll past BOTH the 403/404 window until the per-object
        # v_get converges. The default 6s budget under-covers the cluster-materialization
        # tail (cf. iam-acb poll budget 30→80 for the same reason); 24s is the observed
        # ceiling. Guaranteed to converge (materialization is at-least-once) — never masked:
        # on budget exhaustion the 200-assert still fails a genuine non-materialization.
        retry_until_authorized(Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Group.id prefix grp', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with grp').to.match(/^grp[a-z0-9]+$/);",
                "});",
                "pm.test('Group.accountId matches accountAId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('Group.name contains runId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.name, 'name must contain runId').to.include(pm.environment.get('runId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ), budget=60),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-CR-NEG-NAME-INVALID — invalid name (UPPERCASE) → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-CR-NEG-NAME-INVALID",
    title="Create group with invalid name (UPPERCASE) → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-invalid",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "BAD-GROUP-{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-CR-NEG-ACCOUNT-MISSING — non-existent accountId → async FailedPrecondition
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-CR-NEG-ACCOUNT-MISSING",
    title="Create group with non-existent accountId → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-account",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "acc00000000000notfnd", "name": "grpbadacc{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                # 403 is also acceptable — the authz middleware checks FGA for the
                # account scope before creating the Operation. A non-existent accountId has
                # no FGA tuples, so FGA denies with PERMISSION_DENIED(7)/403.
                # Accepted outcomes: 200 (async Op created), 400 (sync validation), 403 (FGA deny).
                "pm.test('sync 200 or 400 or 403', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 403]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 400) {",
                "  pm.test('sync code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else if (pm.response.code === 200) {",
                "  pm.environment.set('badAccGrpOpId', j.id || '');",
                "} else {",
                "  pm.environment.set('badAccGrpOpId', '');",
                "}",
            ],
        ),
        Step(
            name="poll-bad-account",
            method="GET",
            path="/operations/{{badAccGrpOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('badAccGrpOpId')) {",
                "  pm.execution.skipRequest();",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('badAccGrpOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 9 or 3 (FAILED_PRECONDITION — account FK)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([3, 9]);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-CR-AUTHZ-ANON-DENY — anonymous Create → 401 Unauthenticated
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-CR-AUTHZ-ANON-DENY",
    title="Create group as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "anongrp{{runId}}"},
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-CR-AUTHZ-NONADMIN-DENY — jwtNoBindings has no editor on accountA → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-CR-AUTHZ-NONADMIN-DENY",
    title="Create group as jwtNoBindings (no editor on accountAId) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-nonadmin",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "nonadmingrp{{runId}}"},
            auth="jwtNoBindings",
            test_script=[
                "pm.test('NONADMIN: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONADMIN: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-GT-CRUD-OK — Get the crud group → 200 + correct fields
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-GT-CRUD-OK",
    title="Get crudGroupId → 200 + id prefix grp, accountId matches",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-ok",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Group.id prefix grp', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with grp').to.match(/^grp[a-z0-9]+$/);",
                "});",
                "pm.test('Group.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('crudGroupId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-GT-NEG-NOTFOUND — Get non-existent group → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-GT-NEG-NOTFOUND",
    title="Get non-existent group id → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path=f"/iam/v1/groups/{GARBAGE_GRP}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 or 7', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-GT-AUTHZ-FOREIGN-DENY — jwtNoBindings gets group in accountA → 404
# (BUG-2: read-deny on verb-bearing IAM Get hides existence; was 403).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-GT-AUTHZ-FOREIGN-DENY",
    title="Get crudGroupId as jwtNoBindings (no v_get on accountA) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}",
            auth="jwtNoBindings",
            test_script=[
                "pm.test('FOREIGN: status 404 (hide existence, was 403)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
                "pm.test('FOREIGN: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {}).toLowerCase()).to.not.include('deny_reasons'));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-CRUD-OK — List groups ?accountId=accountAId → 200, contains crudGroupId
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-CRUD-OK",
    title="List groups ?accountId=accountAId → 200, groups array contains crudGroupId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-ok",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('groups array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.groups, 'groups field').to.be.an('array');",
                "});",
                "pm.test('crudGroupId present in list', () => {",
                "  const j = pm.response.json();",
                "  const gid = pm.environment.get('crudGroupId');",
                "  if (gid) {",
                "    pm.expect((j.groups || []).some(g => g.id === gid), 'crudGroupId in list').to.be.true;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-AUTHZ-ANON-DENY — anonymous List → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-AUTHZ-ANON-DENY",
    title="List groups as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-AUTHZ-SCOPE-FILTER — non-member gets 200 + empty list (scope-filter)
# Group.List is a scope-filter RPC like SA.List: non-member → 200+empty, not 403.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-AUTHZ-SCOPE-FILTER",
    title="List groups ?accountId=accountAId as jwtNoBindings → 200 + empty list (scope-filter)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-nonmember",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('scope-filter: groups array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.groups, 'groups field').to.be.an('array');",
                "});",
                "pm.test('scope-filter: non-member sees empty group list', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.groups || []).length, 'empty list for non-member').to.eql(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-BVA-PAGESIZE-0 — pageSize=0 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-BVA-PAGESIZE-0",
    title="List groups pageSize=0 → 200 (default applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}&pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-BVA-PAGESIZE-1",
    title="List groups pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}&pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.groups||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-BVA-PAGESIZE-MAX — pageSize=1000 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-BVA-PAGESIZE-MAX",
    title="List groups pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LS-BVA-PAGESIZE-OVER — pageSize=1001 → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LS-BVA-PAGESIZE-OVER",
    title="List groups pageSize=1001 (over-max) → 400 InvalidArgument",
    classes=["BVA", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/groups?accountId={{accountAId}}&pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-UP-CRUD-OK — Update group description (mask=description) → Operation done, Get confirms
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-UP-CRUD-OK",
    title="Update crudGroupId description (updateMask=description) → Operation done, Get confirms",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update",
            method="PATCH",
            path="/iam/v1/groups/{{crudGroupId}}",
            body={"description": "updated-{{runId}}", "updateMask": "description"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="get-confirms-update",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Group.description updated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description must include updated-').to.include('updated-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-UP-NEG-NOTFOUND — Update non-existent group → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-UP-NEG-NOTFOUND",
    title="Update non-existent group → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-notfound",
            method="PATCH",
            path=f"/iam/v1/groups/{GARBAGE_GRP}",
            body={"description": "ghost", "updateMask": "description"},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 or 7', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-UP-AUTHZ-DELEGATED-ADMIN-ALLOW — jwtInvitee who is group admin can update
# TODO authz-matrix: This requires an AccessBinding giving jwtInvitee editor on the
# group or on accountBId. The crud-fixture only seeds invitee binding on accountBId.
# Until we have a seeded invitee-admin-on-group fixture, we probe with jwtInvitee
# updating their scoped group in accountBId instead.
# Companion case: IAM-GRP-UP-AUTHZ-DELEGATED-ADMIN-ALLOW.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-UP-AUTHZ-NONADMIN-DENY",
    title="Update crudGroupId as jwtNoBindings (no editor on accountA) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-nonadmin",
            method="PATCH",
            path="/iam/v1/groups/{{crudGroupId}}",
            body={"description": "nonadmin", "updateMask": "description"},
            auth="jwtNoBindings",
            test_script=[
                "pm.test('NONADMIN: 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONADMIN: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-AM-CRUD-OK — AddMember userNOBId to crudGroupId → Operation done
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-AM-CRUD-OK",
    title="AddMember (user/userNOBId) to crudGroupId → Operation done",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="add-member",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-AM-IDEMPOTENT-DUP — AddMember of a member the group already has.
#
# CONTRACT: idempotent no-op. group_service.proto/AddMember says so verbatim
# ("Идемпотентно: повторное добавление того же member'а — no-op"), add_member.go
# implements it (INSERT … ON CONFLICT DO NOTHING), and it is the platform-wide
# semantics for collection membership (nlb AddTargets, vpc AddCidrBlocks, iam
# access_binding_subjects). A retried Add is not an error.
#
# What idempotency can actually break is the ROW COUNT, so that is what is
# asserted: the Operation succeeds AND the member is present exactly once. An
# error-code assertion could never have caught a duplicate row.
#
# Depends on IAM-GRP-AM-CRUD-OK having added userNOBId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-AM-IDEMPOTENT-DUP",
    title="AddMember of an existing member (userNOBId) → Operation done, no error, member still present exactly once",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="add-dup",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "dupAddMemberOpId"),
            ],
        ),
        Step(
            name="poll-dup-add",
            method="GET",
            path="/operations/{{dupAddMemberOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *poll_until_done_no_error("re-adding an existing member is a no-op, not an error"),
            ],
        ),
        Step(
            name="dup-add-leaves-one-row",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}:listMembers",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('member present exactly once after the duplicate Add', () => {",
                "  const ms = pm.response.json().members || [];",
                "  const mine = ms.filter(m => m.memberId === pm.environment.get('userNOBId'));",
                "  pm.expect(mine.length, JSON.stringify(ms)).to.eql(1);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-AM-NEG-MEMBER-MISSING — AddMember with non-existent user_id → FailedPrecondition
# group_members_member_exists_trg fires → FailedPrecondition (9).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-AM-NEG-MEMBER-MISSING",
    title="AddMember non-existent user → Operation.error FAILED_PRECONDITION (9) from DB trigger",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="add-bad-member",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "usr0000000000000ghst"},
            auth="jwtAccountAdminA",
            test_script=[
                # May be sync 400 (soft validation before Operation) or 200 (Operation).
                "pm.test('sync 200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 400) {",
                "  pm.test('sync code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else {",
                "  pm.environment.set('opId', j.id || '');",
                "}",
            ],
        ),
        assert_op_error(9, "FAILED_PRECONDITION", msg_substr="not found"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-AM-AUTHZ-NONADMIN-DENY — jwtNoBindings cannot AddMember → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-AM-AUTHZ-NONADMIN-DENY",
    title="AddMember to crudGroupId as jwtNoBindings → 403 or 404 (no editor binding)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="add-nonadmin",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userINVId}}"},
            auth="jwtNoBindings",
            test_script=[
                "pm.test('NONADMIN: 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONADMIN: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-RM-CRUD-OK — RemoveMember (userNOBId) → Operation done
# Depends on IAM-GRP-AM-CRUD-OK having added userNOBId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-RM-CRUD-OK",
    title="RemoveMember (user/userNOBId) from crudGroupId → Operation done",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="remove-member",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:removeMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-RM-IDEMPOTENT-NOT-MEMBER — RemoveMember of a subject that is not a member.
#
# CONTRACT: idempotent no-op. group_service.proto/RemoveMember says so verbatim
# ("Идемпотентно: удаление несуществующего членства — no-op") and
# remove_member.go implements it (0 rows affected is success). Symmetric with
# AddMember, and with the platform's other detach/remove verbs — a retried
# teardown must not fail, or every compensating path has to special-case it.
#
# The real risk of a no-op remove is COLLATERAL: that it removes something else,
# or that a genuine membership silently disappears. That is what is asserted —
# the Operation succeeds, userINVId is (still) absent, and the group's other
# membership is untouched.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-RM-IDEMPOTENT-NOT-MEMBER",
    title="RemoveMember of a non-member (userINVId) → Operation done, no error, membership set unchanged",
    classes=["CRUD"],
    priority="P1",
    steps=[
        # Re-seed one known member so "unchanged" has something to be measured
        # against (IAM-GRP-RM-CRUD-OK emptied the group just above).
        Step(
            name="seed-member-before-noop-remove",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="remove-not-member",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:removeMember",
            body={"memberType": "user", "memberId": "{{userINVId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "rmNotMemberOpId"),
            ],
        ),
        Step(
            name="poll-rm-not-member",
            method="GET",
            path="/operations/{{rmNotMemberOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *poll_until_done_no_error("removing a non-member is a no-op, not an error"),
            ],
        ),
        Step(
            name="noop-remove-changed-nothing",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}:listMembers",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('the non-member is still absent', () => {",
                "  const ms = pm.response.json().members || [];",
                "  const inv = ms.filter(m => m.memberId === pm.environment.get('userINVId'));",
                "  pm.expect(inv.length, JSON.stringify(ms)).to.eql(0);",
                "});",
                "pm.test('the genuine member was NOT collaterally removed', () => {",
                "  const ms = pm.response.json().members || [];",
                "  const nob = ms.filter(m => m.memberId === pm.environment.get('userNOBId'));",
                "  pm.expect(nob.length, JSON.stringify(ms)).to.eql(1);",
                "});",
            ],
        ),
        # Restore the pre-case state (group empty) so later cases keep their
        # own preconditions.
        Step(
            name="restore-empty-group",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:removeMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-RM-AUTHZ-NONADMIN-DENY — RemoveMember as jwtNoBindings → 403 or 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-RM-AUTHZ-NONADMIN-DENY",
    title="RemoveMember from crudGroupId as jwtNoBindings → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="remove-nonadmin",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:removeMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtNoBindings",
            test_script=[
                "pm.test('NONADMIN: 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONADMIN: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LM-CRUD-OK — ListMembers of crudGroupId → 200, and the member is IN it.
#
# Self-seeded (testing.md): IAM-GRP-RM-CRUD-OK emptied the group a few cases
# earlier, so the case adds its own member instead of reading whatever previous
# cases happened to leave behind. "members is an array" is satisfied by an empty
# array — the content assertion is what makes this a read test.
#
# Path: the custom-method form from group_service.proto. The former
# `/groups/{id}/members` is not a generated route, so this case used to fail-close
# on a permission-catalog miss.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-CRUD-OK",
    title="ListMembers of crudGroupId → 200, self-seeded member present exactly once",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="seed-member-for-list",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="list-members",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}:listMembers",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('members array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.members, 'members field').to.be.an('array');",
                "});",
                "pm.test('the seeded member is present exactly once, typed', () => {",
                "  const ms = pm.response.json().members || [];",
                "  const mine = ms.filter(m => m.memberId === pm.environment.get('userNOBId'));",
                "  pm.expect(mine.length, JSON.stringify(ms)).to.eql(1);",
                "  pm.expect(mine[0].memberType, JSON.stringify(mine[0])).to.eql('user');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LM-NEG-NOTFOUND — ListMembers of a well-formed but non-existent group.
#
# Authz-first (testing.md): the gateway resolves the scope to
# `iam_group:<garbage>` and Checks it BEFORE the backend, so a group that does
# not exist has no authorization path and the answer is 403 — for THIS group and
# THIS permission. ListMembers is not a hide-existence read (that fallback covers
# `/Get` + `v_get`), so the 403 is not rewritten to 404.
#
# The assertion pins the deny to its subject: previously this case passed on the
# permission-catalog miss caused by a misrouted path, i.e. on a denial that had
# nothing to do with the group being absent.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-NEG-NOTFOUND",
    title="ListMembers of non-existent group → 403 on iam_group:<absent> (authz-first, no path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-members-notfound",
            method="GET",
            path=f"/iam/v1/groups/{GARBAGE_GRP}:listMembers",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_scoped_authz_deny(LM_ACTION, f"'iam_group:{GARBAGE_GRP}'"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LM-AUTHZ-FOREIGN-DENY — jwtNoBindings cannot ListMembers of accountA group.
#
# The deny under test is "this subject has no v_list path to THIS group". The
# same request under jwtAccountAdminA is a 200 two cases up, so the assertion
# below isolates the subject as the only difference — and pins the denial to
# `iam_group:<crudGroupId>` + the ListMembers permission, so a route/catalog
# regression (which denies every subject, for an unrelated reason) fails the
# case instead of satisfying it.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-AUTHZ-FOREIGN-DENY",
    title="ListMembers of crudGroupId as jwtNoBindings (no v_list on group) → 403 on iam_group:<crudGroupId>",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-members-foreign",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}:listMembers",
            auth="jwtNoBindings",
            test_script=[
                *assert_scoped_authz_deny(
                    LM_ACTION, "'iam_group:' + pm.environment.get('crudGroupId')"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-DL-CRUD-OK — Delete the crud group (no active AccessBindings) → Operation done
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-DL-CRUD-OK",
    title="Delete crudGroupId (no AccessBindings) → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/groups/{{crudGroupId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the group is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/groups/{{crudGroupId}}", "Group"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-DL-NEG-NOTFOUND — Delete non-existent group → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-DL-NEG-NOTFOUND",
    title="Delete non-existent group → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path=f"/iam/v1/groups/{GARBAGE_GRP}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 or 7', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-DL-AUTHZ-ANON-DENY — Delete as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-DL-AUTHZ-ANON-DENY",
    title="Delete group as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-anon",
            method="DELETE",
            # crudGroupId was deleted above; use GARBAGE_GRP for anon-deny probe.
            path=f"/iam/v1/groups/{GARBAGE_GRP}",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LSOP-CRUD-OK — ListOperations for a group → 200, operations array
# Create a fresh group for this probe (crudGroupId was deleted above).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LSOP-CRUD-OK",
    title="ListOperations for a group → 200, operations array present",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-for-lsop",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "lsopgrp{{runId}}", "description": "lsop probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.groupId", "lsopGroupId"),
            ],
        ),
        Step(
            name="poll-create-lsop",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('lsopGroupId')) {",
                "  pm.environment.set('lsopGroupId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/groups/{{lsopGroupId}}/operations",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('operations array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.operations, 'operations field').to.be.an('array');",
                "});",
            ],
        ),
    ],
))
