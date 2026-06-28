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
  - AddMember duplicate (same member_type+member_id in same group) → AlreadyExists (6).
  - RemoveMember of non-member → NotFound (5) or FailedPrecondition (9).
  - Group.List is scope-filtered: non-member gets 200 + empty list (like SA.List).
  - GroupService has no plain account-unscoped List; always ?accountId=<id>.

Case IDs follow the IAM-GRP-<RPC>-<CLASS>[-detail] scheme.

Acceptance scenarios:
  CreateGroup → id starts with `grp`.
  AddMember happy + idempotent (дубль → AlreadyExists or no-op).
  AddMember с несущ. user → FailedPrecondition (DB-триггер).
  RemoveMember + no-member guard.
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
                "  postman.setNextRequest(pm.info.requestName);",
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
        Step(
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
        ),
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
                "  postman.setNextRequest(null);",
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
# IAM-GRP-AM-NEG-DUP — AddMember duplicate → AlreadyExists (6)
# Same (member_type, member_id) in same group → UNIQUE violation → AlreadyExists.
# Depends on IAM-GRP-AM-CRUD-OK having added userNOBId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-AM-NEG-DUP",
    title="AddMember duplicate (userNOBId already in group) → async AlreadyExists (6)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="add-dup",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userNOBId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('sync 200 or 400/409', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 409]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 200) {",
                "  pm.environment.set('dupAddMemberOpId', j.id || '');",
                "} else {",
                "  // sync rejection: 6 (ALREADY_EXISTS) or 3 (INVALID_ARGUMENT)",
                "  pm.test('sync code 3 or 6', () => pm.expect(j.code).to.be.oneOf([3, 6]));",
                "}",
            ],
        ),
        Step(
            name="poll-dup-add",
            method="GET",
            path="/operations/{{dupAddMemberOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('dupAddMemberOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('dupAddMemberOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 6 (ALREADY_EXISTS — duplicate member)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(6);",
                "  });",
                "}",
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
# IAM-GRP-RM-NEG-NOT-MEMBER — RemoveMember of non-member → NotFound or FailedPrecondition
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-RM-NEG-NOT-MEMBER",
    title="RemoveMember non-member (userINVId not in group) → 404 NotFound or 9 FailedPrecondition",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="remove-not-member",
            method="POST",
            path="/iam/v1/groups/{{crudGroupId}}:removeMember",
            body={"memberType": "user", "memberId": "{{userINVId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('sync 200 or 4xx', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 404]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 200) {",
                "  pm.environment.set('rmNotMemberOpId', j.id || '');",
                "} else {",
                "  pm.test('sync code 3, 5, or 9', () => pm.expect(j.code).to.be.oneOf([3, 5, 9]));",
                "}",
            ],
        ),
        Step(
            name="poll-rm-not-member",
            method="GET",
            path="/operations/{{rmNotMemberOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('rmNotMemberOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('rmNotMemberOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 5 or 9 (NOT_FOUND or FAILED_PRECONDITION)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([5, 9]);",
                "  });",
                "}",
            ],
        ),
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
# IAM-GRP-LM-CRUD-OK — ListMembers of crudGroupId → 200, members array
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-CRUD-OK",
    title="ListMembers of crudGroupId → 200, members array present",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-members",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}/members",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('members array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.members, 'members field').to.be.an('array');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LM-NEG-NOTFOUND — ListMembers of non-existent group → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-NEG-NOTFOUND",
    title="ListMembers of non-existent group → 404 NotFound or 403",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-members-notfound",
            method="GET",
            path=f"/iam/v1/groups/{GARBAGE_GRP}/members",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-GRP-LM-AUTHZ-FOREIGN-DENY — jwtNoBindings cannot ListMembers of accountA group → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-GRP-LM-AUTHZ-FOREIGN-DENY",
    title="ListMembers of crudGroupId as jwtNoBindings (no viewer on group) → 403",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-members-foreign",
            method="GET",
            path="/iam/v1/groups/{{crudGroupId}}/members",
            auth="jwtNoBindings",
            test_script=[
                "pm.test('FOREIGN: 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
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
                "  postman.setNextRequest(pm.info.requestName);",
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
