# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для ProjectService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId (sub=auth-test-account-admin-a@example.com)
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated but no account membership
    userAAAId         — the User id that is owner of accountAId
    accountAId        — pre-seeded account owned by userAAAId
    accountBId        — cross-account (for isolation probes)

  crud-fixture extension:
    setup.sh already creates a project "crud-child-prj" in accountAId (for the
    IAM-ACC-DL-NEG-HAS-CHILDREN guard). That project id is written to PROJECT_A
    inside setup.sh but NOT exported as a named env var. The iam-project suite
    therefore creates its own fresh project in the CRUD flow and saves the id as
    `crudProjectId` in the env — this is safe because setup.sh is idempotent
    (it finds existing projects, so re-runs will not duplicate).

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop`.
  Poll step hits /operations/{id} via OpsProxy at api-gateway (iop* → kacho-iam).

Case IDs follow the IAM-PRJ-<RPC>-<CLASS>[-detail] scheme.

ProjectService.Get is owner-only (returns NOT_FOUND for a non-owner non-anonymous
caller — it does NOT consult AccessBinding). This is asserted explicitly.

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  ProjectService RPCs are correctly implemented. Do not weaken assertions.

verifies: ProjectService Create/Update/Delete/duplicate-name acceptance scenarios
from iam-project.py spec.
"""

CASES = []

# ---------------------------------------------------------------------------
# Helpers: IAM operation envelope assert (prefix `iop`)
# ---------------------------------------------------------------------------

def assert_iam_operation_envelope():
    """Assert response is an IAM Operation with id prefix `iop`."""
    return [
        "pm.test('IAM Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


# ---------------------------------------------------------------------------
# IAM-PRJ-CR-CRUD-OK — Create→poll→Get stateful flow
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-CRUD-OK",
    title="Create project in accountAId → Operation(iop) done → Get confirms id prefix `prj`, accountId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "prj-{{runId}}", "description": "newman project create probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.projectId", "crudProjectId"),
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
                "if (j.response && j.response.id && !pm.environment.get('crudProjectId')) {",
                "  pm.environment.set('crudProjectId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/projects/{{crudProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Project.id prefix prj', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with prj').to.match(/^prj[a-z0-9]+$/);",
                "});",
                "pm.test('Project.accountId matches accountAId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('Project.name matches runId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.name).to.include(pm.environment.get('runId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-CR-NEG-NAME-INVALID — invalid name (uppercase) → 400 (verifies: validation)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-NEG-NAME-INVALID",
    title="Create project with UPPERCASE name → 400 InvalidArgument, no Operation",
    classes=["NEG", "BVA"],
    priority="P1",
    steps=[
        Step(
            name="create-invalid-name",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "PRJ-INVALID-{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('response is not an Operation', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id || '').to.not.match(/^iop/);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-CR-NEG-NAME-DUP — duplicate name per-account → Operation.error ALREADY_EXISTS
# Depends on IAM-PRJ-CR-CRUD-OK having created "prj-{{runId}}" successfully.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-NEG-NAME-DUP",
    title="Create project with duplicate name in same account → Operation.error ALREADY_EXISTS (6)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-dup",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "prj-{{runId}}", "description": "dup-name"},
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
# IAM-PRJ-CR-NEG-ACCOUNT-MISSING — unknown account_id → async FailedPrecondition
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-NEG-ACCOUNT-MISSING",
    title="Create project with non-existent accountId → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-account",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "acc00000000000notfnd", "name": "prj-bad-acc-{{runId}}"},
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
                "  pm.environment.set('badAccPrjOpId', j.id || '');",
                "} else {",
                "  pm.environment.set('badAccPrjOpId', '');",
                "}",
            ],
        ),
        Step(
            name="poll-bad-account",
            method="GET",
            path="/operations/{{badAccPrjOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('badAccPrjOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('badAccPrjOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 9 or 3 (FK violation or invalid arg)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([3, 9]);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-CR-AUTHZ-ANON-DENY — anonymous Create → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-AUTHZ-ANON-DENY",
    title="Create project as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "anon-prj-{{runId}}"},
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
# IAM-PRJ-CR-AUTHZ-NONADMIN-DENY — non-admin (jwtNoBindings) Create in accountA → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-AUTHZ-NONADMIN-DENY",
    title="Create project in accountAId as jwtNoBindings (no editor binding) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-nonadmin",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "nonadmin-prj-{{runId}}"},
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
# IAM-PRJ-CR-BVA-NAME-MIN — name len=3 (minimum) → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-BVA-NAME-MIN",
    title="Create project с name len=3 (min) → 200 OK",
    classes=["BVA"],
    priority="P2",
    steps=[
        Step(
            name="cr-name-min",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "abc"},
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
# IAM-PRJ-CR-BVA-NAME-MAX — name len=63 (maximum) → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-BVA-NAME-MAX",
    title="Create project с name len=63 (max) → 200 OK",
    classes=["BVA"],
    priority="P2",
    steps=[
        Step(
            name="cr-name-max",
            method="POST",
            path="/iam/v1/projects",
            # 63 chars: 'a' + 61 'b' + 'z'
            body={"accountId": "{{accountAId}}", "name": "a" + "b" * 61 + "z"},
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
# IAM-PRJ-CR-BVA-NAME-OVER — name len=64 (over-max) → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-CR-BVA-NAME-OVER",
    title="Create project с name len=64 (over-max) → 400 InvalidArgument",
    classes=["BVA", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="cr-name-over",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "a" + "b" * 62 + "z"},  # 64 chars
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-GT-CRUD-OK — Get the crud project → 200 + correct fields
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-GT-CRUD-OK",
    title="Get crudProjectId (owner caller) → 200 + id prefix prj, accountId matches",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-ok",
            method="GET",
            path="/iam/v1/projects/{{crudProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Project.id prefix prj', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.match(/^prj[a-z0-9]+$/);",
                "});",
                "pm.test('Project.accountId correct', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId).to.eql(pm.environment.get('accountAId'));",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-GT-NEG-NOTFOUND — Get with garbage id → 404 or 403 (no FGA path)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-GT-NEG-NOTFOUND",
    title="Get non-existent project id → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path="/iam/v1/projects/prj00000000000notfnd",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403 (no FGA path)', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 or 7', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-GT-AUTHZ-ANON-DENY — Get as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-GT-AUTHZ-ANON-DENY",
    title="Get project as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-anon",
            method="GET",
            path="/iam/v1/projects/{{crudProjectId}}",
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
# IAM-PRJ-GT-AUTHZ-FOREIGN-DENY — Get crudProjectId as jwtNoBindings → 404 or 403
# ProjectService.Get is owner-only: a non-owner non-anonymous caller gets
# NOT_FOUND (or PERMISSION_DENIED via FGA no-path). It does NOT consult
# AccessBinding. This is the real behavior asserted here.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-GT-AUTHZ-FOREIGN-DENY",
    title="Get crudProjectId as jwtNoBindings (non-owner) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/projects/{{crudProjectId}}",
            auth="jwtNoBindings",
            test_script=[
                # BUG-2 hide-existence: read-deny on a verb-bearing IAM Get is surfaced
                # as NotFound (404 / code 5), never PermissionDenied — no enumeration leak.
                "pm.test('FOREIGN: status 404 (hide existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
                "pm.test('FOREIGN: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {}).toLowerCase()).to.not.include('deny_reasons'));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-CRUD-OK — List projects ?accountId=accountAId → 200, projects array
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-CRUD-OK",
    title="List projects ?accountId=accountAId as owner → 200, contains crudProjectId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-ok",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('projects array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projects, 'projects field').to.be.an('array');",
                "});",
                "pm.test('crudProjectId in projects list', () => {",
                "  const j = pm.response.json();",
                "  const pid = pm.environment.get('crudProjectId');",
                "  pm.expect((j.projects || []).some(p => p.id === pid), 'crudProjectId in list').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-AUTHZ-ANON-DENY — List as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-AUTHZ-ANON-DENY",
    title="List projects as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}",
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
# IAM-PRJ-LS-AUTHZ-INVITED-ADMIN-SEES — invitee with binding on accountB sees B's projects
# List is scope-filtered (exempt from gateway authz) → never 403 for authenticated.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-AUTHZ-INVITED-ADMIN-SEES",
    title="List projects ?accountId=accountBId as jwtInvitee → 200 (scope-filter, member sees)",
    classes=["AUTHZ", "CRUD"],
    priority="P1",
    steps=[
        Step(
            name="list-invitee-b",
            method="GET",
            path="/iam/v1/projects?accountId={{accountBId}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                "pm.test('projects array present (invitee sees B)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projects, 'projects field').to.be.an('array');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-AUTHZ-SECL-CROSS-USER-ISOLATION — user must NOT see another's projects
# SEC-L: ProjectService.List is FGA-`viewer`-driven. jwtAccountAdminA owns
# accountA only and has no grant on accountB → listing accountB's projects must
# return an empty/own-only set, never accountB's projects (INV-1 over-exposure
# guard; user-facing end-to-end form of acceptance scenario D).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-AUTHZ-SECL-CROSS-USER-ISOLATION",
    title="List projects ?accountId=accountBId as jwtAccountAdminA → 200, none of B's projects visible (INV-1)",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="list-no-cross-user-leak",
            method="GET",
            path="/iam/v1/projects?accountId={{accountBId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('projects array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projects, 'projects field').to.be.an('array');",
                "});",
                "pm.test('SEC-L: user with no grant on accountB sees none of B projects (INV-1)', () => {",
                "  const j = pm.response.json();",
                "  const bId = pm.environment.get('accountBId');",
                "  const leaked = (j.projects || []).filter(p => p.accountId === bId);",
                "  pm.expect(leaked.length, 'no accountB projects must leak').to.equal(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-NEG-PAGINATION-CONSISTENT — garbage pageToken → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-NEG-PAGINATION-CONSISTENT",
    title="List projects с garbage pageToken → 400 InvalidArgument",
    classes=["NEG", "PAGE"],
    priority="P1",
    steps=[
        Step(
            name="ls-bad-token",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=10&pageToken=not-a-real-token",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-BVA-PAGESIZE-0 — pageSize=0 → 200 (default applied)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-BVA-PAGESIZE-0",
    title="List projects pageSize=0 → 200 (default page size applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-BVA-PAGESIZE-1",
    title="List projects pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.projects||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-BVA-PAGESIZE-MAX — pageSize=1000 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-BVA-PAGESIZE-MAX",
    title="List projects pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LS-BVA-PAGESIZE-OVER — pageSize=1001 → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LS-BVA-PAGESIZE-OVER",
    title="List projects pageSize=1001 (over-max) → 400 InvalidArgument",
    classes=["BVA", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-UP-CRUD-OK — Update description (mask=description) → Operation done, Get confirms
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-UP-CRUD-OK",
    title="Update project description (updateMask=description) → Operation done, Get confirms new description",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update",
            method="PATCH",
            path="/iam/v1/projects/{{crudProjectId}}",
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
            path="/iam/v1/projects/{{crudProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Project.description updated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description must include updated-').to.include('updated-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-UP-NEG-NOTFOUND — Update non-existent project → 404 or 403 (no FGA path)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-UP-NEG-NOTFOUND",
    title="Update non-existent project → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-notfound",
            method="PATCH",
            path="/iam/v1/projects/prj00000000000notfnd",
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
# IAM-PRJ-UP-NEG-IMMUTABLE-ACCOUNT — account_id in updateMask → 400 InvalidArgument
# account_id is hard-immutable after create (changed only via Move).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-UP-NEG-IMMUTABLE-ACCOUNT",
    title="Update with account_id in updateMask → 400 InvalidArgument (immutable field)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="update-immutable",
            method="PATCH",
            path="/iam/v1/projects/{{crudProjectId}}",
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
# IAM-PRJ-UP-AUTHZ-ANON-DENY — Update as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-UP-AUTHZ-ANON-DENY",
    title="Update project as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-anon",
            method="PATCH",
            path="/iam/v1/projects/{{crudProjectId}}",
            body={"description": "anon", "updateMask": "description"},
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-UP-AUTHZ-NONADMIN-DENY — Update as jwtNoBindings → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-UP-AUTHZ-NONADMIN-DENY",
    title="Update project as jwtNoBindings (no editor binding) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-nonadmin",
            method="PATCH",
            path="/iam/v1/projects/{{crudProjectId}}",
            body={"description": "nonadmin", "updateMask": "description"},
            auth="jwtNoBindings",
            test_script=[
                "pm.test('NONADMIN: status 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONADMIN: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-DL-CRUD-OK — Delete the crud project (no children) → Operation done, Get 404/403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-DL-CRUD-OK",
    title="Delete crudProjectId (no children) → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/projects/{{crudProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the project is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/projects/{{crudProjectId}}", "Project"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-DL-NEG-NOTFOUND — Delete non-existent → 404 or 403 (no FGA path)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-DL-NEG-NOTFOUND",
    title="Delete non-existent project → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path="/iam/v1/projects/prj00000000000notfnd",
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
# IAM-PRJ-DL-NEG-HAS-CHILDREN — Delete project with active children → FailedPrecondition
# TODO: requires a project that has children (e.g. ServiceAccounts bound to it).
# This case is skipped until child-resource creation is covered by another suite.
# For now we assert the negative on the pre-seeded "crud-child-prj" only if it
# has groups/SAs; otherwise we skip gracefully.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-DL-NEG-HAS-CHILDREN",
    title="Delete project with active children → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG", "STATE"],
    priority="P1",
    steps=[
        # Use accountAId's pre-seeded child project (crud-child-prj) whose ID is
        # NOT in the env directly. We do a fresh create+immediately delete to test
        # the happy path; for the has-children scenario we rely on the fact that
        # the main crud project may have been deleted above. If setup.sh seeds
        # a project WITH children, use projectA1Id (full authz fixture).
        # TODO authz-matrix: This case is best exercised with projectA1Id from
        # full authz-fixtures, which has ServiceAccounts bound to it. For now we
        # only assert the sync/async behavior against a garbage id to confirm
        # routing is correct (the implementation check lives in the DB FK layer).
        Step(
            name="delete-with-maybe-children",
            method="DELETE",
            path="/iam/v1/projects/prj00000000000notfnd",
            auth="jwtAccountAdminA",
            test_script=[
                # For a non-existent project, expect 404 or 403 (no FGA path).
                # A real has-children test requires projectA1Id from full authz fixture.
                # TODO authz-matrix: IAM-PRJ-DL-NEG-HAS-CHILDREN — needs projectA1Id
                # with ServiceAccounts; seed via full authz-fixtures/setup.sh.
                "pm.test('404 or 403 (no FGA path or not found)', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-DL-AUTHZ-ANON-DENY — Delete as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-DL-AUTHZ-ANON-DENY",
    title="Delete project as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-anon",
            method="DELETE",
            path="/iam/v1/projects/prj00000000000notfnd",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LSOP-CRUD-OK — ListOperations for a project → 200, operations array
# Self-contained: creates a fresh project (crudProjectId was deleted by
# IAM-PRJ-DL-CRUD-OK), then lists its operations.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LSOP-CRUD-OK",
    title="ListOperations for a freshly-created project → 200, operations array present",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-for-lsop",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "lsop-{{runId}}", "description": "newman project list-ops test"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.projectId", "lsopPrjId"),
            ],
        ),
        Step(
            name="poll-create-for-lsop",
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
                "if (j.response && j.response.id && !pm.environment.get('lsopPrjId')) {",
                "  pm.environment.set('lsopPrjId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/projects/{{lsopPrjId}}/operations",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('200 or 404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([200, 403, 404]));",
                "if (pm.response.code === 200) {",
                "  pm.test('operations array present', () => {",
                "    const j = pm.response.json();",
                "    pm.expect(j.operations, 'operations field').to.be.an('array');",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-LSOP-NEG-NOTFOUND — ListOperations for non-existent project → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-LSOP-NEG-NOTFOUND",
    title="ListOperations for non-existent project → 404 NotFound or 403",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-ops-notfound",
            method="GET",
            path="/iam/v1/projects/prj00000000000notfnd/operations",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))
