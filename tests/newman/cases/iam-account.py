# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для AccountService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  This suite requires a seeded owner user + JWT. It reuses the authz-fixtures
  env vars produced by `tests/authz-fixtures/setup.sh`:
    jwtAccountAdminA  — JWT for userAAAId (sub=auth-test-account-admin-a@example.com)
    userAAAId         — the User id that will be set as owner_user_id
    accountAId        — pre-seeded account owned by userAAAId (for Get/Update/Delete/authz)
    accountBId        — cross-account (for negative isolation probes)
    jwtAccountAdminB  — JWT for accountBId owner (for isolation probes)
    jwtNoBindings     — authenticated but no account membership (for non-owner-deny probes)

  For the stateful Create→poll→Get→Update→Delete flow the suite creates a
  FRESH account per runId (name "crud-{{runId}}"), owned by userAAAId using
  jwtAccountAdminA. This avoids cross-test pollution while reusing the seeded user.

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop` (IAM operations
  are distinct from api-gateway OperationService; the poll step hits `/operations/{id}`
  via the OpsProxy at api-gateway which routes `iop*` to kacho-iam).

Case IDs follow the IAM-ACC-<RPC>-<CLASS>[-detail] scheme.

Authz cases:
  Cases that require specific JWT fixtures (jwtAccountAdminA etc.) are included
  since authz-fixtures already provides them. Anonymous (no Authorization header)
  cases use auth="anonymous" per Step.auth convention from authz-deny.py.

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  AccountService RPCs are correctly implemented in kacho-iam. Do not weaken
  assertions to make them pass — fix the implementation instead.

verifies: AccountService Create/Get/Update/Delete acceptance scenarios from
iam-account.py spec.
"""

CASES = []

# ---------------------------------------------------------------------------
# Helpers: operation envelope assert for IAM (prefix `iop`, not `epd`)
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


def poll_iam_op():
    """Poll /operations/{opId} until done, up to 8 retries. IAM ops use iop* prefix."""
    return poll_operation_until_done()


# ---------------------------------------------------------------------------
# IAM-ACC-CR-CRUD-OK — stateful Create→poll→Get flow
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-CRUD-OK",
    title="Create account → Operation(iop) done → Get confirms id prefix `acc`, name",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Step 1: Create account owned by the pre-seeded userAAAId.
        # jwtAccountAdminA (sub=auth-test-account-admin-a@example.com) is the calling
        # principal; RequireOwnerMatchesPrincipal enforces owner_user_id == principal's
        # resolved user id (userAAAId). Both are set by authz-fixtures.
        Step(
            name="create",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "crud-{{runId}}", "description": "newman account create probe", "ownerUserId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "crudAccountId"),
            ],
        ),
        # Step 2: Poll Operation until done.
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
                # Extract accountId from operation response if not yet saved from metadata above.
                "if (j.response && j.response.id && !pm.environment.get('crudAccountId')) {",
                "  pm.environment.set('crudAccountId', j.response.id);",
                "}",
            ],
        ),
        # Step 3: Get confirms the created Account.
        Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/accounts/{{crudAccountId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Account.id prefix acc', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with acc').to.match(/^acc[a-z0-9]+$/);",
                "});",
                "pm.test('Account.name matches runId', () => {",
                "  const j = pm.response.json();",
                "  const runId = pm.environment.get('runId');",
                "  pm.expect(j.name, 'name must contain runId').to.include(runId);",
                "});",
                "pm.test('Account.ownerUserId matches seeded user', () => {",
                "  const j = pm.response.json();",
                "  const expected = pm.environment.get('userAAAId');",
                "  pm.expect(j.ownerUserId, 'ownerUserId must match userAAAId').to.eql(expected);",
                "});",
                "pm.test('Account.description matches', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description').to.include('account create probe');",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-NEG-NAME-INVALID — uppercase name → sync InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-NEG-NAME-INVALID",
    title="Create with invalid name (UPPERCASE) → 400 InvalidArgument, no Operation",
    classes=["NEG", "BVA"],
    priority="P1",
    steps=[
        Step(
            name="create-invalid",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "ACME-{{runId}}", "ownerUserId": "{{userAAAId}}"},
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
# IAM-ACC-CR-NEG-NAME-DUP — duplicate name → Operation.error ALREADY_EXISTS
# Depends on IAM-ACC-CR-CRUD-OK having created "crud-{{runId}}" successfully.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-NEG-NAME-DUP",
    title="Create duplicate name → Operation.error.code = ALREADY_EXISTS (6)",
    classes=["NEG"],
    priority="P1",
    steps=[
        # Post a second Create with the same name. Sync response is 200 (Operation accepted).
        Step(
            name="create-dup",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "crud-{{runId}}", "description": "dup-name", "ownerUserId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                # save to opId (overwriting the CRUD-OK op) so assert_op_error
                # polls the correct duplicate-create operation, not the first successful one.
                *save_from_response("j.id", "opId"),
            ],
        ),
        # Poll and assert error.code == 6 (ALREADY_EXISTS).
        assert_op_error(6, "ALREADY_EXISTS", msg_substr="already exists"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-NEG-OWNER-MISSING — unknown owner_user_id → async FailedPrecondition
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-NEG-OWNER-MISSING",
    title="Create with non-existent owner_user_id → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        # The JWT sub must match ownerUserId for RequireOwnerMatchesPrincipal.
        # We use jwtAccountAdminA whose resolved id is userAAAId, but pass a
        # garbage owner_user_id that differs from userAAAId.
        # NOTE: RequireOwnerMatchesPrincipal fires SYNC (before Operation) and
        # returns InvalidArgument (3) when owner_user_id != principal. The FK
        # violation "user not found" fires ASYNC (9). Both are valid negative
        # signals; we assert whichever fires.
        Step(
            name="create-bad-owner",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "badowner-{{runId}}", "description": "bad owner", "ownerUserId": "usr00000000000000bad"},
            auth="jwtAccountAdminA",
            test_script=[
                # Sync: could be 400 (owner mismatch / invalid id format) or 200 (Operation).
                "pm.test('sync response 200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));",
                "const j = pm.response.json();",
                # If 400, must be INVALID_ARGUMENT or FAILED_PRECONDITION.
                "if (pm.response.code === 400) {",
                "  pm.test('sync error code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else {",
                "  // 200 = Operation accepted; save id for the poll step below.",
                "  pm.environment.set('badOwnerOpId', j.id || '');",
                "}",
            ],
        ),
        # Poll only if an Operation was returned.
        Step(
            name="poll-bad-owner",
            method="GET",
            path="/operations/{{badOwnerOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "// If sync returned 400, no operation was created — skip poll step.",
                "if (!pm.environment.get('badOwnerOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('badOwnerOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('operation error code 9 or 3 (FAILED_PRECONDITION or INVALID_ARGUMENT)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([3, 9]);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-AUTHZ-ANON-DENY — anonymous caller → 401 Unauthenticated
# Account.Create is <exempt> from gateway authz but still blocked by the IAM
# anti-anonymous interceptor → 401 UNAUTHENTICATED (16).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-AUTHZ-ANON-DENY",
    title="Create account as anonymous → 401 Unauthenticated (IAM anti-anon interceptor)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "anon-{{runId}}", "ownerUserId": "usr00000000000000bad"},
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
# IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY — ownerUserId != principal → 403 or 400
# RequireOwnerMatchesPrincipal: owner_user_id MUST equal the calling principal.
# jwtNoBindings' resolved user id is userNOBId, not userAAAId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY",
    title="Create with ownerUserId != principal → 400 InvalidArgument (RequireOwnerMatchesPrincipal)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-hijack",
            method="POST",
            path="/iam/v1/accounts",
            # jwtNoBindings principal resolves to userNOBId, but ownerUserId is userAAAId → mismatch.
            body={"name": "hijack-{{runId}}", "ownerUserId": "{{userAAAId}}"},
            auth="jwtNoBindings",
            test_script=[
                # RequireOwnerMatchesPrincipal fires sync → 400 INVALID_ARGUMENT or 403 PERMISSION_DENIED.
                "pm.test('HIJACK: 400 or 403', () => pm.expect(pm.response.code).to.be.oneOf([400, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('HIJACK: grpc code 3 or 7', () => pm.expect(j && j.code).to.be.oneOf([3, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-BVA-NAME-MIN — name len=3 (minimum) → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-BVA-NAME-MIN",
    title="Create с name len=3 (min, 'abc') → 200 OK",
    classes=["BVA"],
    priority="P2",
    steps=[
        Step(
            name="cr-name-min",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "ab{{runId}}"[:3] if False else "abc", "ownerUserId": "{{userAAAId}}"},
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
# IAM-ACC-CR-BVA-NAME-MAX — name len=63 (maximum) → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-BVA-NAME-MAX",
    title="Create с name len=63 (max) → 200 OK",
    classes=["BVA"],
    priority="P2",
    steps=[
        Step(
            name="cr-name-max",
            method="POST",
            path="/iam/v1/accounts",
            # 63 chars: 'a' + 61 lowercase alphanumeric + 'z'
            body={"name": "a" + "b" * 61 + "z", "ownerUserId": "{{userAAAId}}"},
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
# IAM-ACC-CR-BVA-NAME-OVER — name len=64 (over-max) → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-BVA-NAME-OVER",
    title="Create с name len=64 (over-max) → 400 InvalidArgument",
    classes=["BVA", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="cr-name-over",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "a" + "b" * 62 + "z", "ownerUserId": "{{userAAAId}}"},  # 64 chars
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-SEC-INJECTION — SQL/XSS/cmd injection in name → handled, no 500
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-SEC-INJECTION",
    title="Security: SQL injection in name → handled (4xx), no 500/leak",
    classes=["SEC", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="sec-sqli",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "test' OR 1=1--", "ownerUserId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('not 500', () => pm.expect(pm.response.code).to.not.eql(500));",
                "pm.test('handled 2xx/4xx', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 413]));",
                "const body = JSON.stringify(pm.response.json() || {}).toLowerCase();",
                "pm.test('no panic/sqlstate/stacktrace leak', () => {",
                "  pm.expect(body).to.not.include('panic');",
                "  pm.expect(body).to.not.include('sqlstate');",
                "  pm.expect(body).to.not.include('goroutine');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-GT-CRUD-OK — Get pre-seeded accountAId → 200 + correct fields
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-GT-CRUD-OK",
    title="Get pre-seeded accountAId → 200 + id prefix acc, ownerUserId matches",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-ok",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Account.id prefix acc', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with acc').to.match(/^acc[a-z0-9]+$/);",
                "});",
                "pm.test('Account.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('Account.ownerUserId present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.ownerUserId, 'ownerUserId must be non-empty').to.be.a('string').with.length.greaterThan(0);",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-GT-NEG-NOTFOUND — Get with garbage id → 404 NotFound
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-GT-NEG-NOTFOUND",
    title="Get non-existent account id → 404 NotFound",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path="/iam/v1/accounts/acc00000000000notfnd",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                *assert_grpc_code(5, "NOT_FOUND"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-GT-NEG-ID-MALFORMED — Get with syntactically invalid id → 400
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-GT-NEG-ID-MALFORMED",
    title="Get with malformed account_id (wrong prefix) → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P2",
    steps=[
        Step(
            name="get-malformed",
            method="GET",
            # account_id constraint: <=20 chars; "not-an-acc-id-xxx-xxxx-very-long" exceeds length
            path="/iam/v1/accounts/not-an-account-id-at-all-toolong",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('400 or 404', () => pm.expect(pm.response.code).to.be.oneOf([400, 404]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-GT-AUTHZ-ANON-DENY — anonymous Get → 401 Unauthenticated
# Get is authz-gated (required_relation: viewer on account).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-GT-AUTHZ-ANON-DENY",
    title="Get account as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-anon",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
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
# IAM-ACC-GT-AUTHZ-FOREIGN-DENY — cross-account Get → 404 hide-existence
# jwtNoBindings has no v_get relation on accountAId → read-deny is surfaced as
# NotFound (BUG-2: was 403 PERMISSION_DENIED; gateway now hides existence for
# verb-bearing IAM reads, no enumeration leak).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-GT-AUTHZ-FOREIGN-DENY",
    title="Get accountAId as jwtNoBindings (no v_get) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
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
# IAM-ACC-LS-CRUD-OK — List accounts → 200, scope-filter returns caller's accounts
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-CRUD-OK",
    title="List accounts as jwtAccountAdminA → 200, accounts array present",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-ok",
            method="GET",
            path="/iam/v1/accounts",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('accounts array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accounts, 'accounts field').to.be.an('array');",
                "});",
                "pm.test('accounts contains accountAId', () => {",
                "  const j = pm.response.json();",
                "  const aId = pm.environment.get('accountAId');",
                "  pm.expect((j.accounts || []).some(a => a.id === aId), 'accountAId present in list').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-AUTHZ-ANON-DENY — List as anonymous → 401
# List is <exempt> from gateway authz but IAM anti-anon interceptor blocks anon.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-AUTHZ-ANON-DENY",
    title="List accounts as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/accounts",
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
# IAM-ACC-LS-AUTHZ-SCOPE-INVITED-ADMIN-SEES — invitee sees account-B in List
# jwtInvitee has admin binding on account-B → invitee's List must include accountBId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-AUTHZ-SCOPE-INVITED-ADMIN-SEES",
    title="List as jwtInvitee → 200, accountBId visible (scope-filter includes member accounts)",
    classes=["AUTHZ", "CRUD"],
    priority="P1",
    steps=[
        Step(
            name="list-invitee",
            method="GET",
            path="/iam/v1/accounts",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                "pm.test('accounts array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accounts, 'accounts field').to.be.an('array');",
                "});",
                "pm.test('invitee sees accountBId (member account)', () => {",
                "  const j = pm.response.json();",
                "  const bId = pm.environment.get('accountBId');",
                "  pm.expect((j.accounts || []).some(a => a.id === bId), 'accountBId in list for invitee').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-AUTHZ-SECL-CROSS-USER-ISOLATION — user must NOT see another's account
# SEC-L: AccountService.List is FGA-`viewer`-driven. A user with neither
# ownership nor a grant on accountB must NEVER see it (INV-1 over-exposure
# guard). jwtAccountAdminA owns accountA only; accountB is owned by a different
# user. This is the user-facing end-to-end form of acceptance scenario D.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-AUTHZ-SECL-CROSS-USER-ISOLATION",
    title="List as jwtAccountAdminA → 200, accountBId NOT visible (cross-user isolation, INV-1)",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="list-no-cross-user-leak",
            method="GET",
            path="/iam/v1/accounts",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('accounts array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accounts, 'accounts field').to.be.an('array');",
                "});",
                "pm.test('SEC-L: owner sees own accountAId', () => {",
                "  const j = pm.response.json();",
                "  const aId = pm.environment.get('accountAId');",
                "  pm.expect((j.accounts || []).some(a => a.id === aId), 'accountAId present').to.be.true;",
                "});",
                "pm.test('SEC-L: must NOT see another user accountBId (INV-1)', () => {",
                "  const j = pm.response.json();",
                "  const bId = pm.environment.get('accountBId');",
                "  pm.expect((j.accounts || []).some(a => a.id === bId), 'accountBId must be hidden').to.be.false;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-BVA-PAGESIZE-0 — pageSize=0 → 200 (default applied)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-BVA-PAGESIZE-0",
    title="List pageSize=0 → 200 (default page size applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/accounts?pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-BVA-PAGESIZE-1",
    title="List pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/accounts?pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.accounts||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-BVA-PAGESIZE-MAX — pageSize=1000 (boundary max) → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-BVA-PAGESIZE-MAX",
    title="List pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/accounts?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-BVA-PAGESIZE-OVER — pageSize=1001 (over-max) → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-BVA-PAGESIZE-OVER",
    title="List pageSize=1001 (over-max) → 400 InvalidArgument",
    classes=["BVA", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/accounts?pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LS-NEG-PAGETOKEN-GARBAGE — garbage page_token → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-NEG-PAGETOKEN-GARBAGE",
    title="List с garbage page_token → 400 InvalidArgument",
    classes=["NEG", "PAGE"],
    priority="P1",
    steps=[
        Step(
            name="ls-bad-token",
            method="GET",
            path="/iam/v1/accounts?pageSize=10&pageToken=not-a-real-token",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-UP-CRUD-OK — Update name (mask=name) → Operation done, Get confirms
# Uses crudAccountId saved by IAM-ACC-CR-CRUD-OK.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-CRUD-OK",
    title="Update account name (updateMask=name) → Operation done, Get confirms new name",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update",
            method="PATCH",
            path="/iam/v1/accounts/{{crudAccountId}}",
            body={"name": "upd-{{runId}}", "updateMask": "name"},
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
            path="/iam/v1/accounts/{{crudAccountId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Account.name updated', () => {",
                "  const j = pm.response.json();",
                "  const runId = pm.environment.get('runId');",
                "  pm.expect(j.name, 'name must contain upd- and runId').to.include('upd-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-UP-NEG-NOTFOUND — Update non-existent account → async NotFound or sync 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-NEG-NOTFOUND",
    title="Update non-existent account → 404 NotFound",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-notfound",
            method="PATCH",
            path="/iam/v1/accounts/acc00000000000notfnd",
            body={"name": "ghost-{{runId}}", "updateMask": "name"},
            auth="jwtAccountAdminA",
            test_script=[
                # authz check fires first; for a garbage id that never existed,
                # FGA has no parent-tuple → 403 PERMISSION_DENIED (no path).
                # If authz is bypassed, the handler returns 404.
                "pm.test('404 or 403 (no FGA path)', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 (NOT_FOUND) or 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-UP-NEG-IMMUTABLE-OWNER — owner_user_id in update_mask → sync InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-NEG-IMMUTABLE-OWNER",
    title="Update with owner_user_id in updateMask → 400 InvalidArgument (immutable field)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="update-immutable",
            method="PATCH",
            path="/iam/v1/accounts/{{accountAId}}",
            body={"ownerUserId": "{{userAAAId}}", "updateMask": "owner_user_id"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('error mentions immutable or owner_user_id', () => {",
                "  const j = pm.response.json();",
                "  const msg = (j.message || '').toLowerCase();",
                "  pm.expect(msg).to.satisfy(m => m.includes('immutable') || m.includes('owner_user_id'), 'message: ' + msg);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-UP-NEG-MASK-UNKNOWN — unknown field in update_mask → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-NEG-MASK-UNKNOWN",
    title="Update с unknown field in updateMask → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P2",
    steps=[
        Step(
            name="update-unknown-mask",
            method="PATCH",
            path="/iam/v1/accounts/{{accountAId}}",
            body={"updateMask": "nonexistent_field"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-UP-AUTHZ-ANON-DENY — Update as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-AUTHZ-ANON-DENY",
    title="Update account as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-anon",
            method="PATCH",
            path="/iam/v1/accounts/{{accountAId}}",
            body={"name": "anon-{{runId}}", "updateMask": "name"},
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
# IAM-ACC-UP-AUTHZ-NONADMIN-DENY — Update accountA as jwtNoBindings (no editor) → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-UP-AUTHZ-NONADMIN-DENY",
    title="Update accountAId as jwtNoBindings (no editor binding) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-nonadmin",
            method="PATCH",
            path="/iam/v1/accounts/{{accountAId}}",
            body={"name": "nonadmin-{{runId}}", "updateMask": "name"},
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
# IAM-ACC-DL-CRUD-OK — Delete the crud account created in IAM-ACC-CR-CRUD-OK
# Depends on: crudAccountId env var saved in IAM-ACC-CR-CRUD-OK.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-DL-CRUD-OK",
    title="Delete crud account (no children) → Operation done, Get returns 404",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/accounts/{{crudAccountId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the account is actually gone (async delete + FGA
        # owner-tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/accounts/{{crudAccountId}}", "Account"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-DL-NEG-NOTFOUND — Delete non-existent account → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-DL-NEG-NOTFOUND",
    title="Delete non-existent account → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path="/iam/v1/accounts/acc00000000000notfnd",
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
# IAM-ACC-DL-NEG-HAS-CHILDREN — Delete account with active Project → FailedPrecondition
# Uses accountAId which already has projects (seeded by authz-fixtures).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-DL-NEG-HAS-CHILDREN",
    title="Delete account with active projects → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG", "STATE"],
    priority="P1",
    steps=[
        Step(
            name="delete-with-children",
            method="DELETE",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        assert_op_error(9, "FAILED_PRECONDITION", msg_substr="cannot be deleted"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-DL-AUTHZ-ANON-DENY — Delete as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-DL-AUTHZ-ANON-DENY",
    title="Delete account as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-anon",
            method="DELETE",
            path="/iam/v1/accounts/{{accountAId}}",
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
# IAM-ACC-DL-AUTHZ-NONOWNER-DENY — Delete accountA as jwtAccountAdminB (cross-account) → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-DL-AUTHZ-NONOWNER-DENY",
    title="Delete accountAId as jwtAccountAdminB (no editor on A) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-cross",
            method="DELETE",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtAccountAdminB",
            test_script=[
                "pm.test('CROSS: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('CROSS: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LSOP-CRUD-OK — ListOperations returns the account's recorded ops
#
# Self-contained (crudAccountId from IAM-ACC-CR-CRUD-OK is deleted by
# IAM-ACC-DL-CRUD-OK before this runs): create a fresh account, poll its Create
# Operation to done, then GET .../operations and assert the array is NON-EMPTY
# and contains an `iop`-prefixed op. This distinguishes the fixed handler from
# the prior bug, where AccountService.ListOperations was registered (proto +
# api-gateway route) but UNIMPLEMENTED in the Account handler → gRPC Unimplemented
# → REST 501 (assert_status(200) RED) — or, had it returned a no-op stub, an
# empty operations array. The non-empty assertion is the regression guard.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LSOP-CRUD-OK",
    title="ListOperations for a freshly-created account → 200, operations array non-empty",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-for-lsop",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "lsop-{{runId}}", "description": "newman account list-ops test", "ownerUserId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "lsopAccId"),
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
                "if (j.response && j.response.id && !pm.environment.get('lsopAccId')) {",
                "  pm.environment.set('lsopAccId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/accounts/{{lsopAccId}}/operations",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('operations array present and non-empty', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.operations, 'operations field').to.be.an('array');",
                "  pm.expect(j.operations.length, 'at least the Create op recorded').to.be.above(0);",
                "  pm.expect(j.operations[0].id, 'op id prefix iop').to.match(/^iop[a-z0-9]+$/);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LSOP-NEG-NOTFOUND — ListOperations for non-existent account → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LSOP-NEG-NOTFOUND",
    title="ListOperations for non-existent account → 404 NotFound or 403",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-ops-notfound",
            method="GET",
            path="/iam/v1/accounts/acc00000000000notfnd/operations",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-LSOP-AUTHZ-ANON-DENY — ListOperations as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LSOP-AUTHZ-ANON-DENY",
    title="ListOperations for accountAId as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-ops-anon",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/operations",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('ANON: grpc code 16', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
            ],
        ),
    ],
))
