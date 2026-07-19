# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для ServiceAccountService.

Covered RPCs:
  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId (admin of accountAId)
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated, no account membership
    accountAId        — pre-seeded account for SA scope
    accountBId        — cross-account (for isolation probes)
    userAAAId         — User.id of jwtAccountAdminA principal

  No additional env vars are needed. The suite creates a FRESH ServiceAccount
  per runId ("sva-{{runId}}") in accountAId using jwtAccountAdminA.

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kacho-iam).

Gotchas:
  - ServiceAccount.List is a scope-filter RPC (like User.List): non-member
    caller gets 200 + empty `serviceAccounts` list, NOT 403. This is by design
    (authz-deny.py `sa-list-account-*` matrix).
  - `account_id` is immutable on Update → InvalidArgument (3) if in updateMask.
  - Duplicate SA name per account → AlreadyExists (6) async (UNIQUE constraint
    `service_accounts_account_id_name_key`).
  - SA Create requires a valid accountId (FK → FailedPrecondition if missing).

Case IDs follow the IAM-SVA-<RPC>-<CLASS>[-detail] scheme.

Acceptance scenarios:
  Create-happy → id starts with `sva`.
  Duplicate name per account → AlreadyExists (async).
  Delete с AccessBinding → FailedPrecondition (atomic CAS).

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  ServiceAccountService RPCs are correctly implemented. Do not weaken
  assertions — fix the implementation instead.
"""

CASES = []

# Garbage id for negative probes.
GARBAGE_SVA = "sva00000000000notfnd"


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
# IAM-SVA-CR-CRUD-OK — Create SA → Operation done → Get confirms
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-CRUD-OK",
    title="Create service account in accountAId → Operation(iop) done → Get confirms id prefix `sva`",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "sva-{{runId}}", "description": "newman SA create probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.serviceAccountId", "crudSvaId"),
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
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('crudSvaId')) {",
                "  pm.environment.set('crudSvaId', j.response.id);",
                "}",
            ],
        ),
        retry_until_authorized(Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('SA.id prefix sva', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with sva').to.match(/^sva[a-z0-9]+$/);",
                "});",
                "pm.test('SA.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('crudSvaId'));",
                "});",
                "pm.test('SA.accountId matches accountAId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('SA.name contains runId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.name, 'name must contain runId').to.include(pm.environment.get('runId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        )),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-CR-NEG-NAME-INVALID — invalid name (UPPERCASE) → 400 InvalidArgument
# SA names must match the same regex as other resources (lowercase-start).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-NEG-NAME-INVALID",
    title="Create SA with invalid name (UPPERCASE) → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-invalid",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "BAD-SA-{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-CR-NEG-NAME-DUP — duplicate SA name per account → Operation.error AlreadyExists
# Depends on IAM-SVA-CR-CRUD-OK having created "sva-{{runId}}".
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-NEG-NAME-DUP",
    title="Create SA with duplicate name per account → Operation.error ALREADY_EXISTS (6)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-dup",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "sva-{{runId}}", "description": "dup-name"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        assert_op_error(6, "ALREADY_EXISTS", msg_substr="already exists"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-CR-NEG-PROJECT-MISSING — non-existent accountId → async FailedPrecondition
# (Coverage list uses "PROJECT-MISSING" but this service is account-scoped on IAM.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-NEG-PROJECT-MISSING",
    title="Create SA with non-existent accountId → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-account",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "acc00000000000notfnd", "name": "svabadacc{{runId}}"},
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
                "  pm.environment.set('badAccSvaOpId', j.id || '');",
                "} else {",
                "  pm.environment.set('badAccSvaOpId', '');",
                "}",
            ],
        ),
        Step(
            name="poll-bad-account",
            method="GET",
            path="/operations/{{badAccSvaOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('badAccSvaOpId')) {",
                "  pm.execution.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('badAccSvaOpId')) {",
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
# IAM-SVA-CR-AUTHZ-ANON-DENY — anonymous Create → 401 Unauthenticated
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-AUTHZ-ANON-DENY",
    title="Create SA as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "anonsva{{runId}}"},
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
# IAM-SVA-CR-AUTHZ-NONADMIN-DENY — jwtNoBindings has no editor on accountA → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-CR-AUTHZ-NONADMIN-DENY",
    title="Create SA as jwtNoBindings (no editor on accountAId) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-nonadmin",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "nonadminsva{{runId}}"},
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
# IAM-SVA-GT-CRUD-OK — Get the crud SA → 200 + correct fields
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-GT-CRUD-OK",
    title="Get crudSvaId → 200 + id prefix sva, accountId matches",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-ok",
            method="GET",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('SA.id prefix sva', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with sva').to.match(/^sva[a-z0-9]+$/);",
                "});",
                "pm.test('SA.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('crudSvaId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-GT-NEG-NOTFOUND — Get non-existent SA → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-GT-NEG-NOTFOUND",
    title="Get non-existent SA id → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}",
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
# IAM-SVA-GT-AUTHZ-FOREIGN-DENY — jwtNoBindings gets SA in accountA → 404
# (BUG-2: read-deny on verb-bearing IAM Get hides existence; was 403).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-GT-AUTHZ-FOREIGN-DENY",
    title="Get crudSvaId as jwtNoBindings (no v_get on accountA SA) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
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
# IAM-SVA-LS-CRUD-OK — List SAs ?accountId=accountAId → 200, contains crudSvaId
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-CRUD-OK",
    title="List serviceAccounts ?accountId=accountAId → 200, serviceAccounts contains crudSvaId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-ok",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('serviceAccounts array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.serviceAccounts, 'serviceAccounts field').to.be.an('array');",
                "});",
                "pm.test('crudSvaId present in list', () => {",
                "  const j = pm.response.json();",
                "  const sid = pm.environment.get('crudSvaId');",
                "  if (sid) {",
                "    pm.expect((j.serviceAccounts || []).some(s => s.id === sid), 'crudSvaId in list').to.be.true;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-LS-AUTHZ-ANON-DENY — anonymous List → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-AUTHZ-ANON-DENY",
    title="List serviceAccounts as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}",
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
# IAM-SVA-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY — non-member gets 200 + empty (scope-filter)
# SA.List is a scope-filter RPC. jwtNoBindings is not a member of
# accountAId → returns 200 + empty serviceAccounts, not 403.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY",
    title="List serviceAccounts ?accountId=A as jwtNoBindings → 200 + empty list (scope-filter)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-nonmember",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('scope-filter: serviceAccounts array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.serviceAccounts, 'serviceAccounts field').to.be.an('array');",
                "});",
                "pm.test('scope-filter: non-member sees empty SA list (not 403)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.serviceAccounts || []).length, 'empty list for non-member').to.eql(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-LS-BVA-PAGESIZE-0 — pageSize=0 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-BVA-PAGESIZE-0",
    title="List serviceAccounts pageSize=0 → 200 (default applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}&pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-BVA-PAGESIZE-1",
    title="List serviceAccounts pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}&pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.serviceAccounts||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-LS-BVA-PAGESIZE-MAX — pageSize=1000 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-BVA-PAGESIZE-MAX",
    title="List serviceAccounts pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-LS-BVA-PAGESIZE-OVER — pageSize=1001 → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LS-BVA-PAGESIZE-OVER",
    title="List serviceAccounts pageSize=1001 (over-max) → 400 InvalidArgument",
    classes=["BVA", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}&pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-UP-CRUD-OK — Update SA description (mask=description) → Operation done, Get confirms
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-UP-CRUD-OK",
    title="Update crudSvaId description (updateMask=description) → Operation done, Get confirms",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update",
            method="PATCH",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
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
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('SA.description updated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description must include updated-').to.include('updated-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-UP-NEG-NOTFOUND — Update non-existent SA → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-UP-NEG-NOTFOUND",
    title="Update non-existent SA → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-notfound",
            method="PATCH",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}",
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
# IAM-SVA-UP-NEG-IMMUTABLE-PROJECT — account_id in updateMask → sync InvalidArgument
# `account_id` is hard-immutable on ServiceAccount.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-UP-NEG-IMMUTABLE-PROJECT",
    title="Update SA with account_id in updateMask → 400 InvalidArgument (immutable field)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="update-immutable",
            method="PATCH",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            body={"accountId": "{{accountAId}}", "updateMask": "account_id"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('error mentions immutable or account_id', () => {",
                "  const j = pm.response.json();",
                "  const msg = (j.message || '').toLowerCase();",
                "  pm.expect(msg).to.satisfy(m => m.includes('immutable') || m.includes('account_id') || m.includes('account'), 'message: ' + msg);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-UP-AUTHZ-NONADMIN-DENY — jwtNoBindings cannot Update accountA's SA → 403 or 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-UP-AUTHZ-NONADMIN-DENY",
    title="Update crudSvaId as jwtNoBindings (no editor on accountA) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-nonadmin",
            method="PATCH",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
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
# IAM-SVA-DL-CRUD-OK — Delete the crud SA (no active AccessBindings) → Operation done
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DL-CRUD-OK",
    title="Delete crudSvaId (no AccessBindings) → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the service account is actually gone (async delete +
        # FGA tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/serviceAccounts/{{crudSvaId}}", "ServiceAccount"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-DL-NEG-NOTFOUND — Delete non-existent SA → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DL-NEG-NOTFOUND",
    title="Delete non-existent SA → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}",
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
# IAM-SVA-DL-AUTHZ-ANON-DENY — Delete as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DL-AUTHZ-ANON-DENY",
    title="Delete SA as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-anon",
            method="DELETE",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}",
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
# IAM-SVA-LSOP-CRUD-OK — ListOperations for an SA → 200, operations array
# Create a fresh SA since crudSvaId was deleted above.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LSOP-CRUD-OK",
    title="ListOperations for a service account → 200, operations array present",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-for-lsop",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "svalsop{{runId}}", "description": "lsop probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.serviceAccountId", "lsopSvaId"),
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
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('lsopSvaId')) {",
                "  pm.environment.set('lsopSvaId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/serviceAccounts/{{lsopSvaId}}/operations",
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


# ---------------------------------------------------------------------------
# IAM-SVA-LSOP-NEG-NOTFOUND — ListOperations for non-existent SA → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-LSOP-NEG-NOTFOUND",
    title="ListOperations for non-existent SA → 404 NotFound or 403",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-ops-notfound",
            method="GET",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}/operations",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))
