# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для RoleService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId (admin of accountAId)
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated, no account membership
    accountAId        — pre-seeded account for custom role scope
    accountBId        — cross-account (for isolation probes)

  System roles are seeded with deterministic ids: `rol` + substr(md5(<name>),1,17).
  See authz-deny.py constants (ROLE_ADMIN, ROLE_VIEW).

  Custom roles are account-scoped (account_id NOT NULL, is_system=false).
  Name unique per-account (partial UNIQUE `roles_custom_unique`).

  No additional env vars are needed beyond what crud-fixture provides.
  The suite creates/deletes fresh custom roles per runId to avoid pollution.

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kacho-iam).

Case IDs follow the IAM-ROL-<RPC>-<CLASS>[-detail] scheme.

Authz semantics:
  - RoleService.List (GET /iam/v1/roles) — catalog-read: every authenticated
    user can list roles (system + their account's custom). Returns ALLOW for
    all authenticated subjects.
  - RoleService.Get — catalog-read: same as List.
  - RoleService.Create/Update/Delete — cluster-role-mutate (for system roles)
    or account-editor-mutate (for custom roles). Creating a custom role in
    account-A requires editor on account-A.
  - Deleting a system role → FailedPrecondition "System role cannot be deleted".
  - Deleting a custom role that is in use (has AccessBindings) → FailedPrecondition.

System role ids used in this suite (deterministic catalog):
  ROLE_VIEW = "rol1bda80f2be4d3658e"   # md5('view')[:17]

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  RoleService RPCs are correctly implemented. Do not weaken assertions.

verifies: RoleService Create / Get / Delete acceptance scenarios from
iam-role.py spec (custom-role CRUD, system-role read-only, FailedPrecondition
on deleting a system role).
"""

CASES = []

# System role ids — deterministic catalog (`rol` + md5(<name>)[:17]).
# Matches authz-deny.py constants exactly.
ROLE_VIEW  = "rol1bda80f2be4d3658e"   # md5('view')[:17]
ROLE_ADMIN = "rol21232f297a57a5a74"   # md5('admin')[:17]

# A non-existent role id for negative probes.
GARBAGE_ROLE = "rol00000000000notfnd"


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
# IAM-ROL-CR-CRUD-OK — Create custom role → Operation done → Get confirms
#
# Role.Get/List enforce per-object via ListObjects(v_list, iam_role). Because
# `v_list` has NO tier→v_* bridge in the FGA model, a role's own
# creator/account-admin (jwtAccountAdminA) did not resolve it on the role they just
# created → own Get returned 404. Role.Get/List enforcement uses
# the `viewer` TIER relation (cascades from account-tier, consistent with
# account/project List); the owner now resolves their own role → get-confirms 200.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-CRUD-OK",
    title="Create custom role in accountAId → Operation(iop) done → Get confirms id prefix `rol`, isSystem=false",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "custom_reader_{{runId}}",
                "description": "newman custom-role create probe",
                "rules": [
                    {"module": "iam", "resources": ["user"], "verbs": ["read"]},
                    {"module": "vpc", "resources": ["network"], "verbs": ["read"]},
                ],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "crudRoleId"),
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
                "if (j.response && j.response.id && !pm.environment.get('crudRoleId')) {",
                "  pm.environment.set('crudRoleId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/roles/{{crudRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Role.id prefix rol', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with rol').to.match(/^rol[a-z0-9]+$/);",
                "});",
                "pm.test('Role.isSystem=false (custom role)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.isSystem, 'custom role: isSystem must be false').to.eql(false);",
                "});",
                "pm.test('Role.accountId matches accountAId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId).to.eql(pm.environment.get('accountAId'));",
                "});",
                # RBAC contract: authored field is `rules`;
                # the compiled `permissions` form is output-only and is ALWAYS
                # empty on the public surface (internal compiled representation).
                "pm.test('Role.rules length=2', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.rules || []).length).to.eql(2);",
                "});",
                # Each rule carries a SCALAR `module` (string) — there is no
                # array `modules` field on the public surface.
                "pm.test('Role.rules[].module is a scalar string, no modules array', () => {",
                "  const j = pm.response.json();",
                "  (j.rules || []).forEach((r) => {",
                "    pm.expect(r.module, 'rule.module must be a string').to.be.a('string');",
                "    pm.expect(r.modules, 'array modules must be absent').to.not.exist;",
                "  });",
                "  pm.expect((j.rules || []).map((r) => r.module)).to.have.members(['iam', 'vpc']);",
                "});",
                "pm.test('Role.permissions empty on public surface (compiled/output-only)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.permissions || []).length).to.eql(0);",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-NAME-INVALID — invalid role name (hyphen / uppercase) → 400
# Role name must match ^[a-z][a-z0-9_]{0,40}$ (hyphen is invalid for roles
# per authz-deny.py ESC-3 note; underscore is valid).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-NAME-INVALID",
    title="Create custom role with hyphen in name (invalid: ^[a-z][a-z0-9_]{0,40}$) → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-name",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "bad-role-name-{{runId}}", "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-RULE-INVALID — invalid rule (malformed module token) → 400 InvalidArgument
# RBAC rules model: the authored field is `rules`, an array of
# Rule objects. `module` is a required SCALAR string; resources/verbs are required
# string arrays; tokens must match the segment regex (lowercase identifiers, no
# spaces/uppercase). A bad module token like "VPC UPPER!" fails Rule.Validate
# SYNCHRONOUSLY (before the Operation is created) → sync 400 INVALID_ARGUMENT
# ("invalid token"). (Was: invalid permission string format; permissions are no
# longer accepted on input.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-RULE-INVALID",
    title="Create custom role with an invalid rule (malformed module token) → 400 InvalidArgument (sync rule validation)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-rule",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "badrole_{{runId}}",
                "rules": [{"module": "VPC UPPER!", "resources": ["subnet"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                # Rule validation is SYNC (before the Operation envelope) → 400.
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-MODULE-UNKNOWN — unknown module (grammar-valid, not in the closed
# platform set) → 400 InvalidArgument.
# `module:"banana"` matches the module-token grammar (^[a-z][a-z0-9-]*$) but is NOT
# a member of the closed set {iam,vpc,compute,loadbalancer}, so domain.IsKnownModule
# rejects it on the request-path (sync, before the Operation) with the stable text
# "unknown module 'banana'". A member like `vpc` is accepted (positive counter-
# example covered by the CRUD happy case).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-MODULE-UNKNOWN",
    title="Create custom role with an unknown module token (banana) → 400 InvalidArgument (closed-set reject)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-unknown-module",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "unkmodrole_{{runId}}",
                "rules": [{"module": "banana", "resources": ["subnet"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('message: unknown module', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.contain('unknown module');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-PERMISSIONS-REJECTED — body carries the output-only `permissions`
# field → 400 InvalidArgument "Illegal argument permissions (compiled/output-only)".
# `permissions` is the
# COMPILED form and is output-only. Create/Update reject any non-empty
# `permissions` on input SYNCHRONOUSLY (before the Operation is created).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-PERMISSIONS-REJECTED",
    title="Create custom role with output-only `permissions` field populated → 400 INVALID_ARGUMENT (compiled/output-only)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="create-with-permissions",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "permrole_{{runId}}",
                "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}],
                "permissions": ["iam.user.*.read"],
            },
            auth="jwtAccountAdminA",
            test_script=[
                # `permissions` is compiled/output-only → rejected SYNC (before Operation).
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('message: permissions is compiled/output-only', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.contain('compiled/output-only');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-AUTHZ-FOREIGN-ACCOUNT-DENY — Create a custom role scoped to a
# foreign / non-existent account → sync 403 PERMISSION_DENIED, before any
# existence-check.
#
# `accountId` IS the authz scope of RoleService.Create (account-editor-mutate;
# see the suite header "Creating a custom role in account-A requires editor on
# account-A"). The authz interceptor runs InternalIAMService.Check on
# `iam.role.create` @ `account:<accountId>` BEFORE the use-case body. The body
# here is `acc00000000000notfnd` — well-formed (`acc`+17 chars, so it passes the
# sync ValidateResourceID guard, NOT a malformed-id 400) but a foreign /
# non-existent account over which jwtAccountAdminA (admin of accountA only) holds
# no relation. Check therefore DENIES → sync 403 PERMISSION_DENIED (code 7), and
# the request never reaches the use-case, never enqueues an Operation, never
# touches the roles_account_fk INSERT. This is the secure contract: the API does
# not leak the existence of a foreign/non-existent account behind a
# FailedPrecondition — authority is denied first.
#
# Why the prior "non-existent account → async FAILED_PRECONDITION (FK 23503)"
# expectation was wrong here: the roles_account_fk existence-check lives in the
# async doCreate INSERT, reachable ONLY after the authz Check passes. But the
# Check scope IS the account in the body, so a caller can never be authorized
# over an account that does not exist (no FGA hierarchy tuple resolves to a
# phantom `account:notfnd`). The FK-existence path is thus not reachable through
# the public API for a non-existent account — the 403 supersedes it. Test design:
# error-guessing (foreign vs own scope) + decision-table (caller × account-scope).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-AUTHZ-FOREIGN-ACCOUNT-DENY",
    title="Create custom role scoped to a foreign/non-existent account as jwtAccountAdminA → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-foreign-account",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "acc00000000000notfnd", "name": "badaccrole_{{runId}}", "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('FOREIGN-ACCOUNT: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN-ACCOUNT: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-AUTHZ-ANON-DENY — Create as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-AUTHZ-ANON-DENY",
    title="Create role as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "anonrole_{{runId}}", "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}]},
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
# IAM-ROL-CR-AUTHZ-NONADMIN-DENY — Create as jwtNoBindings (no editor on accountA) → 403
# cluster-role-mutate / account-editor-mutate: NOB has no binding on accountA.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-AUTHZ-NONADMIN-DENY",
    title="Create custom role as jwtNoBindings (no editor on accountAId) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-nonadmin",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "nonadminrole_{{runId}}", "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}]},
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
# IAM-ROL-GT-CRUD-OK — Get a system role by id → 200 + isSystem=true
# catalog-read: every authenticated user can Get a system role.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-GT-CRUD-OK",
    title="Get system role ROLE_VIEW → 200, isSystem=true, id matches",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-system",
            method="GET",
            path=f"/iam/v1/roles/{ROLE_VIEW}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Role.id matches ROLE_VIEW', () => {",
                f"  const j = pm.response.json();",
                f"  pm.expect(j.id).to.eql('{ROLE_VIEW}');",
                "});",
                "pm.test('Role.isSystem=true', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.isSystem, 'system role: isSystem must be true').to.eql(true);",
                "});",
                "pm.test('Role.accountId absent/null (system role has no account)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId || '', 'system role has no accountId').to.eql('');",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-GT-NEG-NOTFOUND — Get non-existent role → 404 NotFound
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-GT-NEG-NOTFOUND",
    title="Get non-existent role id → 404 NotFound",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path=f"/iam/v1/roles/{GARBAGE_ROLE}",
            auth="jwtAccountAdminA",
            test_script=[
                # Garbage role id: no FGA tuple → 403; or 404 if repo check runs first.
                "pm.test('404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 or 7', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-GT-NEG-FOREIGN-CUSTOM-404 — Get a foreign account's CUSTOM role,
# ungranted → 404 NotFound (no existence leak).
#
# crudRoleId is accountA's custom role (created by IAM-ROL-CR-CRUD-OK, isSystem=false).
# jwtAccountAdminB is admin of accountB and has NO v_list grant on accountA's role.
# RoleService.Get enforces custom roles per-object via the same FGA v_list set as List,
# so an ungranted custom role → NOT_FOUND (NOT 403 — must not confirm existence), and
# rules[] is NOT leaked (read==enforce parity with List, which already hides it).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-GT-NEG-FOREIGN-CUSTOM-404",
    title="Get accountA custom role (crudRoleId) as jwtAccountAdminB (ungranted) → 404 NotFound, no rules[] leak",
    classes=["NEG", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="get-foreign-custom-ungranted",
            method="GET",
            path="/iam/v1/roles/{{crudRoleId}}",
            auth="jwtAccountAdminB",
            test_script=[
                # read==enforce + no existence leak: an ungranted custom role MUST be
                # NOT_FOUND (gRPC code 5), NEVER 403 (which would confirm it exists).
                "pm.test('404 NotFound (no existence leak, NOT 403)', () => {",
                "  pm.expect(pm.response.code, 'ungranted custom Get must be 404, not 403').to.eql(404);",
                "});",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('gRPC code 5 (NOT_FOUND)', () => pm.expect(j && j.code).to.eql(5));",
                # no-leak: the error body must NOT carry the foreign role's policy (rules[]).
                "pm.test('no rules[] leak in error body', () => {",
                "  pm.expect(j && j.rules, 'error body must not expose the foreign policy rules[]').to.be.oneOf([undefined, null]);",
                "  pm.expect(j && j.isSystem, 'error body must not expose role fields').to.be.oneOf([undefined, null]);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-SYSTEM-ONLY-NO-ACCOUNT — List without accountId → system roles only
# catalog-read: every authenticated user can list. At least 12 system roles from migration.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-SYSTEM-ONLY-NO-ACCOUNT",
    title="List roles (no accountId) → 200, ≥12 system roles returned (catalog-read)",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-system",
            method="GET",
            path="/iam/v1/roles",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('roles array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.roles, 'roles field').to.be.an('array');",
                "});",
                # At least 12 system roles seeded by migration 0001/0008.
                "pm.test('at least 12 system roles in catalog', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.roles || []).length, 'at least 12 system roles').to.be.at.least(12);",
                "});",
                "pm.test('ROLE_VIEW present in catalog', () => {",
                "  const j = pm.response.json();",
                f"  pm.expect((j.roles || []).some(r => r.id === '{ROLE_VIEW}'), 'ROLE_VIEW in catalog').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-SYSTEM-PLUS-CUSTOM-WITH-ACCOUNT — List ?accountId=accountAId →
# system roles + accountA's custom roles (incl. crudRoleId).
#
# Contract: the accountId query param scopes the result to system + THAT account's
# custom roles; without accountId only system roles (cluster catalog).
# RoleService.List is scope-filtered per-object. crudRoleId is created by
# IAM-ROL-CR-CRUD-OK.
#
# The handler honours account_id and the pg repo scopes to
# `(is_system OR account_id = $acc)`; the per-object FGA filter resolves via the
# `viewer` TIER relation so the account-admin sees their own custom role (proven by
# IAM-ROL-CR-CRUD-OK get-confirms, which Gets crudRoleId directly → 200 using the
# SAME resolver).
#
# PAGINATION (test-only): the catalog floor is 56 system roles (seeded, created_at =
# migration time → they sort FIRST under `ORDER BY created_at ASC, id ASC`).
# crudRoleId is a custom role created during the run (created_at = NOW() → sorts LAST).
# With the default page size of 50 the response is the first 50 system roles and
# crudRoleId lands on page 2+, so the unpaginated list never contained it even though
# the role IS visible (read==enforce holds: Get with the same resolver returns 200).
# This is a page-boundary defect in the CASE, not a product List/Get divergence.
# Requesting pageSize=1000 (contract max, accountA has < 1000 roles) returns all of
# accountA's roles on one page.
# verifies: account-scoped Role.List returns system roles + the account's own custom
# role, scope-filtered per-object via the viewer tier (read==enforce parity with Get).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-SYSTEM-PLUS-CUSTOM-WITH-ACCOUNT",
    title="List roles ?accountId=accountAId → 200, contains system roles + crudRoleId",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="list-with-account",
            # pageSize=1000 (contract max): the catalog floor is 56 system roles which
            # sort first (created_at = migration time); crudRoleId is a run-created
            # custom role (created_at = NOW()) and lands past the default-50 boundary.
            # A single max-size page returns all of accountA's roles deterministically
            # so the account's own custom role is present (it has always been visible —
            # read==enforce — this just defeats the page boundary).
            method="GET",
            path="/iam/v1/roles?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('roles array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.roles, 'roles field').to.be.an('array');",
                "});",
                # crudRoleId is set by IAM-ROL-CR-CRUD-OK (create→poll succeed; the
                # role exists). Assert unconditionally — the account-scoped List MUST
                # return the account's own custom role: the
                # per-object filter uses the `viewer` tier (cascades from account-tier),
                # so the account-admin resolves their own role. pageSize=1000 ensures
                # the role is on the (single) page despite the 56-system-role floor.
                "pm.test('crudRoleId in roles list', () => {",
                "  const j = pm.response.json();",
                "  const rid = pm.environment.get('crudRoleId');",
                "  pm.expect(rid, 'crudRoleId captured by IAM-ROL-CR-CRUD-OK').to.be.a('string').and.not.empty;",
                "  pm.expect((j.roles || []).some(r => r.id === rid), 'crudRoleId present').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-NEG-NO-FOREIGN-CUSTOM — List with cross-account accountId → custom roles filtered out
# jwtAccountAdminA listing ?accountId=accountBId should NOT see accountB's custom roles.
# System roles are visible (catalog-read). Custom roles of B are scoped to B.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-NEG-NO-FOREIGN-CUSTOM",
    title="List roles ?accountId=accountBId as jwtAccountAdminA → system roles only, not accountB custom",
    classes=["NEG", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-foreign-account",
            method="GET",
            path="/iam/v1/roles?accountId={{accountBId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # jwtAccountAdminA cannot see accountB's custom roles (scoped to B).
                # System roles are still returned (catalog-read).
                *assert_status(200),
                "pm.test('roles array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.roles, 'roles field').to.be.an('array');",
                "});",
                "pm.test('crudRoleId (accountA custom) NOT in accountB list', () => {",
                "  const j = pm.response.json();",
                "  const rid = pm.environment.get('crudRoleId');",
                "  if (rid) {",
                "    pm.expect((j.roles || []).some(r => r.id === rid), 'accountA custom role leaked into B list').to.be.false;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-AUTHZ-ANON — List as anonymous → 401
# catalog-read is still blocked by IAM anti-anon interceptor for anonymous.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-AUTHZ-ANON",
    title="List roles as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/roles",
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
# IAM-ROL-LS-BVA-PAGESIZE-0 — pageSize=0 → 200 (default applied)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-BVA-PAGESIZE-0",
    title="List roles pageSize=0 → 200 (default page size applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/roles?pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-BVA-PAGESIZE-1",
    title="List roles pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/roles?pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.roles||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-BVA-PAGESIZE-MAX — pageSize=1000 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-BVA-PAGESIZE-MAX",
    title="List roles pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/roles?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LS-BVA-PAGESIZE-OVER — pageSize=1001 (over-max) → 400 InvalidArgument
#
# BVA upper boundary (max+1). Convention (corevalidate.PageSize): page_size > 1000 →
# InvalidArgument, NOT a silent clamp ("Не silent fallback — это нарушение контракта"
# — corelib comment). The reference impl kacho-vpc rejects via validate.PageSize.
#
# IAM List RPCs do not silently clamp page_size>1000 — the pg repos' effectivePageSize
# rejects with ErrInvalidArg → INVALID_ARGUMENT (400), parity with kacho-vpc
# corevalidate.PageSize.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LS-BVA-PAGESIZE-OVER",
    title="List roles pageSize=1001 (over-max) → 400 InvalidArgument",
    classes=["BVA", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/roles?pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-UP-CRUD-OK — Update custom role description → Operation done, Get confirms
#
# Same resolver as IAM-ROL-CR-CRUD-OK — an account-admin could not Get the role
# they own when per-object Get-enforce had no tier→v_list bridge. Role.Get/List
# enforcement uses the `viewer` tier (cascades from account-tier) → get-confirms-update
# is 200.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-UP-CRUD-OK",
    title="Update crudRoleId description (updateMask=description) → Operation done, Get confirms",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update",
            method="PATCH",
            path="/iam/v1/roles/{{crudRoleId}}",
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
            path="/iam/v1/roles/{{crudRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Role.description updated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description must include updated-').to.include('updated-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-UP-NEG-SYSTEM-IMMUTABLE — Update system role → FailedPrecondition
# System roles are immutable (name, is_system are hard-immutable).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-UP-NEG-SYSTEM-IMMUTABLE",
    title="Update system role ROLE_VIEW → 400 InvalidArgument or async FAILED_PRECONDITION (system immutable)",
    classes=["NEG", "STATE"],
    priority="P1",
    steps=[
        Step(
            name="update-system",
            method="PATCH",
            path=f"/iam/v1/roles/{ROLE_VIEW}",
            body={"description": "trying to update system role", "updateMask": "description"},
            auth="jwtAccountAdminA",
            test_script=[
                # Could be sync 400 (system role detected before Operation)
                # or async FailedPrecondition (Operation.error.code=9).
                # Or could be sync 403 if authz is enforced (cluster-role-mutate).
                "pm.test('400 or 403 or 200 (then async fail)', () => pm.expect(pm.response.code).to.be.oneOf([400, 403, 200]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 400) {",
                "  pm.test('sync code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else if (pm.response.code === 403) {",
                "  pm.test('403 code 7', () => pm.expect(j.code).to.eql(7));",
                "} else {",
                "  pm.environment.set('sysMutOpId', j.id || '');",
                "}",
            ],
        ),
        Step(
            name="poll-system-update",
            method="GET",
            path="/operations/{{sysMutOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('sysMutOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('sysMutOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 3 or 9 (system immutable)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([3, 9]);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-UP-NEG-NOTFOUND — Update non-existent role → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-UP-NEG-NOTFOUND",
    title="Update non-existent role → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-notfound",
            method="PATCH",
            path=f"/iam/v1/roles/{GARBAGE_ROLE}",
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
# IAM-ROL-UP-AUTHZ-NONADMIN-DENY — Update custom role as jwtNoBindings → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-UP-AUTHZ-NONADMIN-DENY",
    title="Update crudRoleId as jwtNoBindings (no editor on accountA) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="update-nonadmin",
            method="PATCH",
            path="/iam/v1/roles/{{crudRoleId}}",
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
# IAM-ROL-DL-CRUD-OK — Delete the crud custom role (not in use) → Operation done, Get 404/403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-DL-CRUD-OK",
    title="Delete crudRoleId (custom, not in use) → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/roles/{{crudRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the role is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/roles/{{crudRoleId}}", "Role"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-DL-NEG-SYSTEM — Delete system role → Operation.error FAILED_PRECONDITION
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-DL-NEG-SYSTEM",
    title="Delete system role ROLE_VIEW → Operation.error FAILED_PRECONDITION (9) 'System role cannot be deleted'",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-system",
            method="DELETE",
            path=f"/iam/v1/roles/{ROLE_VIEW}",
            auth="jwtAccountAdminA",
            test_script=[
                # Could be sync 403 (cluster-role-mutate authz) or 200 (Operation then async fail).
                "pm.test('sync 200 or 403 (cluster-role-mutate)', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 403) {",
                "  pm.test('403 code 7 (PERMISSION_DENIED)', () => pm.expect(j.code).to.eql(7));",
                "} else {",
                "  pm.environment.set('opId', j.id || '');",
                "}",
            ],
        ),
        Step(
            name="poll-system-delete",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "// If sync returned 403, no operation was created — skip poll.",
                "if (!pm.environment.get('opId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('opId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 9 (FAILED_PRECONDITION — system role)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(9);",
                "  });",
                "  pm.test('error message contains system role', () => {",
                "    pm.expect((j.error && j.error.message || '').toLowerCase()).to.satisfy(",
                "      m => m.includes('system') || m.includes('cannot'), 'message: ' + (j.error && j.error.message));",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-DL-NEG-IN-USE — Delete a CUSTOM role carrying an AccessBinding →
# async FAILED_PRECONDITION "role is in use by access bindings" (FK 23503
# RESTRICT). AccessBindingService.Delete is a HARD delete (the row is
# purged, not soft-revoked) — so after deleting (purging) the binding the FK
# child is gone and the same Role.Delete succeeds, then Get → NotFound. Full
# self-contained flow: create role → bind it → delete role (fail) → delete
# (purge) binding → delete role (ok) → get (404).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-DL-NEG-IN-USE",
    title="Delete custom role with a binding → async FAILED_PRECONDITION (role is in use); purge binding → delete OK → Get 404",
    classes=["NEG", "STATE", "CRUD"],
    priority="P0",
    steps=[
        # 1. create a fresh custom role to bind.
        Step(
            name="a16-create-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "inuse_{{runId}}",
                "rules": [{"module": "iam", "resources": ["user"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "a16RoleId"),
            ],
        ),
        poll_operation_until_done(),
        # 2. bind the role on account-A (creates the FK child that blocks delete).
        Step(
            name="a16-create-binding",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": "{{a16RoleId}}",
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "a16AcbId"),
            ],
        ),
        poll_operation_until_done(),
        # 3. delete the role while it carries the binding → async FAILED_PRECONDITION.
        Step(
            name="a16-delete-in-use",
            method="DELETE",
            path="/iam/v1/roles/{{a16RoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        Step(
            name="a16-poll-delete-in-use",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) { pm.environment.set('_pollCount', String(pc + 1)); postman.setNextRequest(pm.info.requestName); return; }",
                "pm.environment.unset('_pollCount'); pm.environment.unset('_pollStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('error FAILED_PRECONDITION (code 9)', () => pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(9));",
                "pm.test('message: role is in use by access bindings', () => {",
                "  pm.expect((j.error && j.error.message || '').toLowerCase(), JSON.stringify(j)).to.contain('role is in use by access bindings');",
                "});",
            ],
        ),
        # 4. role still exists (delete was refused).
        Step(
            name="a16-role-still-present",
            method="GET",
            path="/iam/v1/roles/{{a16RoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('role still present after refused delete', () => pm.expect(pm.response.json().id).to.eql(pm.environment.get('a16RoleId')));",
            ],
        ),
        # 5. delete (purge) the binding — AccessBindingService.Delete is a HARD
        #    delete, so the FK child row is removed (not soft-revoked).
        Step(
            name="a16-purge-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{a16AcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # 6. delete the role again → now succeeds.
        Step(
            name="a16-delete-ok",
            method="DELETE",
            path="/iam/v1/roles/{{a16RoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        Step(
            name="a16-poll-delete-ok",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) { pm.environment.set('_pollCount', String(pc + 1)); postman.setNextRequest(pm.info.requestName); return; }",
                "pm.environment.unset('_pollCount'); pm.environment.unset('_pollStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('delete succeeded after revoke (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
            ],
        ),
        # 7. role is gone → Get 404.
        Step(
            name="a16-get-after-delete",
            method="GET",
            path="/iam/v1/roles/{{a16RoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('Get after delete → 404 or 403', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-DL-AUTHZ-NONADMIN-DENY — Delete crudRoleId as jwtNoBindings → 403 or 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-DL-AUTHZ-NONADMIN-DENY",
    title="Delete crudRoleId as jwtNoBindings (no editor on accountA) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-nonadmin",
            method="DELETE",
            # crudRoleId was deleted by IAM-ROL-DL-CRUD-OK above. Use GARBAGE_ROLE
            # for the non-admin deny probe (FGA: no path → 403).
            path=f"/iam/v1/roles/{GARBAGE_ROLE}",
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
# IAM-ROL-LSOP-CRUD-OK — ListOperations for a role → 200, operations array
# Create a fresh custom role to list its operations.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LSOP-CRUD-OK",
    title="ListOperations for a custom role → 200, returns the create Operation (not an empty no-op list)",
    classes=["CRUD"],
    priority="P1",
    steps=[
        # Create a temp role to have its operations listed.
        Step(
            name="create-for-lsop",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "lsop_role_{{runId}}", "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}]},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.id", "lsopOpId"),
                *save_from_response("j.metadata && j.metadata.roleId", "lsopRoleId"),
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
                "if (j.response && j.response.id && !pm.environment.get('lsopRoleId')) {",
                "  pm.environment.set('lsopRoleId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/roles/{{lsopRoleId}}/operations",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('operations array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.operations, 'operations field').to.be.an('array');",
                "});",
                # Regression guard: the handler was a no-op returning [] even when
                # operations existed. The create-Operation for this role MUST appear.
                "pm.test('create Operation present (not the empty no-op list)', () => {",
                "  const j = pm.response.json();",
                "  const want = pm.environment.get('lsopOpId');",
                "  pm.expect((j.operations || []).length, 'at least the create op').to.be.at.least(1);",
                "  pm.expect((j.operations || []).some(o => o.id === want), 'create op id in list').to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-LSOP-NEG-PAGE-TOKEN-GARBAGE — ListOperations bad pageToken → 400
# Opaque cursor token; garbage must yield InvalidArgument (never INTERNAL/200).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-LSOP-NEG-PAGE-TOKEN-GARBAGE",
    title="ListOperations with garbage pageToken → 400 InvalidArgument",
    classes=["NEG", "PAGE", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="lsop-bad-token",
            method="GET",
            path=f"/iam/v1/roles/{ROLE_VIEW}/operations?pageSize=10&pageToken=not-a-real-token",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ===========================================================================
# RBAC rules model — rule-validation negatives (validation is SYNC, before the
# Operation → 400 INVALID_ARGUMENT).
# ===========================================================================

# verb-`*` in a custom role is ALLOWED ("all verbs of the type").
CASES.append(Case(
    id="IAM-ROL-CR-RULES-VERB-STAR-OK",
    title="Create custom role with verbs:['*'] → Operation done; Get shows rules[0].verbs==['*'], permissions empty",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-verb-star",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "verbstar_{{runId}}",
                "rules": [{"module": "compute", "resources": ["instance"], "verbs": ["*"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "verbStarRoleId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="get-verb-star",
            method="GET",
            path="/iam/v1/roles/{{verbStarRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('rules[0].verbs == [*] (verb-* preserved as authority)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.rules && j.rules[0] && j.rules[0].verbs, JSON.stringify(j)).to.eql(['*']);",
                "});",
                "pm.test('permissions empty on public surface (compiled internal)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.permissions || []).length, JSON.stringify(j)).to.eql(0);",
                "});",
            ],
        ),
    ],
))


# module-`*` / resource-`*` in a custom role → 400 (wildcard is system-only).
CASES.append(Case(
    id="IAM-ROL-CR-RULES-MODULE-STAR-DENY",
    title="Create custom role with module:'*' → 400 INVALID_ARGUMENT (wildcard system-only)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-module-star",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "modstar_{{runId}}",
                "rules": [{"module": "*", "resources": ["instance"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('message: wildcard system-only', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.contain('system-only');",
                "});",
            ],
        ),
    ],
))

CASES.append(Case(
    id="IAM-ROL-CR-RULES-RESOURCE-STAR-DENY",
    title="Create custom role with resources:['*'] → 400 INVALID_ARGUMENT (wildcard system-only)",
    classes=["NEG", "VAL"],
    priority="P2",
    steps=[
        Step(
            name="create-resource-star",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "resstar_{{runId}}",
                "rules": [{"module": "compute", "resources": ["*"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# Unified label-scope: matchLabels on an iam content type (iam.role) is now ACCEPTED
# (feed-gate reversed — iam.role/user/serviceAccount/group/accessBinding are
# label-selectable, materialized iam-direct same-DB from own-table labels).
# verifies: a matchLabels rule on an iam content type (iam.role) is accepted on Create.
CASES.append(Case(
    id="IAM-ROL-CR-RULES-FEEDGATE-IAMROLE-OK",
    title="Create custom role with matchLabels on iam content type (iam.role) → Operation succeeds (feed-gate reversed)",
    classes=["CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-feedgate-iamrole",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "feedgate_iamrole_{{runId}}",
                "rules": [{"module": "iam", "resources": ["role"], "verbs": ["get"],
                           "matchLabels": {"tier": "gold"}}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "feedgateIamRoleOpId"),
            ],
        ),
        Step(
            name="poll-feedgate-iamrole",
            method="GET",
            path="/operations/{{feedgateIamRoleOpId}}",
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
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation no error (feed-gate reversed — iam.role is label-selectable)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
            ],
        ),
    ],
))

CASES.append(Case(
    id="IAM-ROL-CR-RULES-FEEDGATE-IAMPROJECT-OK",
    title="Create label-only custom role (single matchLabels rule on iam.project) → Operation succeeds, Get returns rules[]",
    classes=["CRUD"],
    priority="P1",
    steps=[
        # Label-only: the role's ONLY rule is ARM_LABELS, so it
        # compiles to an EMPTY permission set. It MUST still be
        # accepted — the operation must finish WITHOUT error (not merely done),
        # and Get must return the authored rules[] with an empty permissions[].
        Step(
            name="create-label-only",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "feedok_{{runId}}",
                "rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"],
                           "matchLabels": {"tier": "gold"}}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # The operation must have SUCCEEDED (response present, no error) — a
        # label-only role that was falsely rejected would finish done WITH an error.
        assert_op_success(),
        Step(
            name="get-label-only",
            method="GET",
            path="/iam/v1/roles/{{lastOpResponseRoleId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "// the create Operation's response is the Role — pull its id.",
                "const r = JSON.parse(pm.environment.get('lastOpResponse') || '{}');",
                "pm.environment.set('lastOpResponseRoleId', r.id || '');",
            ],
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('role carries the authored rules[]', () => pm.expect((j.rules||[]).length, JSON.stringify(j)).to.eql(1));",
                "pm.test('rule is the matchLabels arm', () => pm.expect(j.rules[0].matchLabels && j.rules[0].matchLabels.tier, JSON.stringify(j)).to.eql('gold'));",
                "pm.test('label-only role has empty compiled permissions[]', () => pm.expect((j.permissions||[]).length, JSON.stringify(j)).to.eql(0));",
            ],
        ),
    ],
))


# Cardinality / XOR — resourceNames AND matchLabels in one rule → 400.
CASES.append(Case(
    id="IAM-ROL-CR-RULES-XOR-DENY",
    title="Create custom role with both resourceNames and matchLabels in one rule → 400 (mutually exclusive)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-xor",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "xorrule_{{runId}}",
                "rules": [{"module": "vpc", "resources": ["subnet"], "verbs": ["get"],
                           "resourceNames": ["sub5"], "matchLabels": {"env": "prod"}}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('message: mutually exclusive', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.contain('mutually exclusive');",
                "});",
            ],
        ),
    ],
))

# Empty rules[] → 400 (must be non-empty).
CASES.append(Case(
    id="IAM-ROL-CR-RULES-EMPTY-DENY",
    title="Create custom role with empty rules[] → 400 INVALID_ARGUMENT (must be non-empty)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-empty-rules",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "emptyrules_{{runId}}", "rules": []},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# Compiled-cap — rules compiling to >1024 permissions → 400 (not silent
# truncation). One module per rule, and the module must be a member
# of the closed set {iam,vpc,compute,loadbalancer} (Rule.Validate runs BEFORE the
# compiler, so an unknown module would 400 with the wrong text). Five single-module
# rules each over 16 resources x 16 verbs = 256 compiled; 4 distinct known modules
# + a 2nd `iam` rule with a DISJOINT resource set (so permissions stay distinct,
# not deduped) → 5 x 256 = 1280 > 1024. Each list ≤16 so the shape validation
# passes and the cap (not a cardinality error) is what trips.
def _over_cap_rules():
    verbs = [f"v{chr(97 + i)}" for i in range(16)]
    res_a = [f"r{chr(97 + i)}" for i in range(16)]
    res_b = [f"s{chr(97 + i)}" for i in range(16)]
    return [
        {"module": "iam", "resources": res_a, "verbs": verbs},
        {"module": "vpc", "resources": res_a, "verbs": verbs},
        {"module": "compute", "resources": res_a, "verbs": verbs},
        {"module": "loadbalancer", "resources": res_a, "verbs": verbs},
        {"module": "iam", "resources": res_b, "verbs": verbs},  # disjoint resources → distinct perms
    ]


CASES.append(Case(
    id="IAM-ROL-CR-RULES-CAP-OVER-DENY",
    title="Create custom role whose rules compile to >1024 permissions → 400 (compiled permissions exceed 1024)",
    classes=["NEG", "VAL", "BVA"],
    priority="P1",
    steps=[
        Step(
            name="create-over-cap",
            method="POST",
            path="/iam/v1/roles",
            body={"accountId": "{{accountAId}}", "name": "overcap_{{runId}}", "rules": _over_cap_rules()},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('message: compiled permissions exceed 1024', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.contain('exceed 1024');",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# RBAC rules model: rules[] is the only writable policy surface; the compiled
# `permissions` field is OUTPUT-only (empty/absent on the public Get/List
# projection) and is REJECTED if supplied to Create. Black-box through
# api-gateway. Do not weaken assertions.
# ===========================================================================


# ---------------------------------------------------------------------------
# IAM-ROLE-F52-RULES-PUBLIC — resolve a SYSTEM role via Role.List, then
# Role.Get on it → non-empty `rules`, empty/absent `permissions` on the public
# surface (rules[] is the policy contract; permissions is compiled/internal).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROLE-F52-RULES-PUBLIC",
    title="Role.Get on a system role → non-empty rules[], empty/absent permissions (rules is the public policy surface)",
    classes=["CONF", "CLEANCUT"],
    priority="P0",
    steps=[
        # resolve a system role id from the catalog
        Step(
            name="list-roles-resolve-system",
            method="GET",
            path="/iam/v1/roles",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('roles catalog returned', () => pm.expect(pm.response.json().roles).to.be.an('array'));",
                f"pm.test('system role ROLE_VIEW resolvable in catalog', () => {{",
                "  const j = pm.response.json();",
                f"  const r = (j.roles || []).find(x => x.id === '{ROLE_VIEW}' && x.isSystem === true);",
                "  pm.expect(r, JSON.stringify(j)).to.exist;",
                "  pm.environment.set('f52SysRoleId', r.id);",
                "});",
            ],
        ),
        Step(
            name="get-system-role-rules-public",
            method="GET",
            path="/iam/v1/roles/{{f52SysRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('system Role.Get carries non-empty rules[]', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.rules, JSON.stringify(j)).to.be.an('array');",
                "  pm.expect(j.rules.length, 'rules[] must be non-empty (public policy surface)').to.be.greaterThan(0);",
                "});",
                "pm.test('permissions empty/absent on public surface (compiled/output-only)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.permissions || []).length, JSON.stringify(j)).to.eql(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROLE-F52-PERMS-REJECTED — Role.Create with a non-empty `permissions`
# array in the body → 400 INVALID_ARGUMENT (permissions is compiled/output-only;
# rules[] is the only writable policy surface).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROLE-F52-PERMS-REJECTED",
    title="Role.Create with non-empty permissions[] in the body → 400 INVALID_ARGUMENT (permissions write-rejected)",
    classes=["NEG", "VAL", "CLEANCUT"],
    priority="P0",
    steps=[
        # permissions is write-rejected; rules is the only writable surface
        Step(
            name="create-role-with-permissions",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "f52permrole_{{runId}}",
                "rules": [{"module": "iam", "resources": ["user"], "verbs": ["read"]}],
                "permissions": ["iam.user.*.read"],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-PROJECT-SCOPED — a custom role can be created PROJECT-scoped via the
# public API (CreateRoleRequest.project_id), so the project-anchor materialization
# path is reachable from the public surface.
#
# Flow: create a fresh project under accountA → create a role with `projectId`
# (no accountId) → poll → Get confirms the role carries projectId (not
# accountId) and isSystem=false. The end-to-end project-anchor Check is
# covered by the project-anchor case in iam-invite-grant-fga.py.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-PROJECT-SCOPED",
    title="Create PROJECT-scoped custom role (CreateRoleRequest.project_id) → Operation done → Get confirms projectId set, accountId empty, isSystem=false",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # 1. fresh project under accountA to scope the role to.
        Step(
            name="create-project-212",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "{{accountAId}}", "name": "prj212-{{runId}}", "description": "newman project-scoped role host"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.projectId", "projectId212"),
            ],
        ),
        poll_operation_until_done("jwtAccountAdminA"),
        # carry the project id forward (poll may have surfaced it in response.id).
        Step(
            name="stash-project-212",
            method="GET",
            path="/iam/v1/projects/{{projectId212}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('project id prefix prj', () => pm.expect(pm.response.json().id).to.match(/^prj[a-z0-9]+$/));",
            ],
        ),
        # 2. create a PROJECT-scoped role — projectId set, NO accountId.
        Step(
            name="create-project-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                "projectId": "{{projectId212}}",
                "name": "prj_role_{{runId}}",
                "description": "newman project-scoped custom role",
                "rules": [
                    {"module": "iam", "resources": ["project"], "verbs": ["get", "list"]},
                ],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "prjRoleId212"),
            ],
        ),
        poll_operation_until_done("jwtAccountAdminA"),
        Step(
            name="get-confirms-project-scope",
            method="GET",
            path="/iam/v1/roles/{{prjRoleId212}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Role.id prefix rol', () => pm.expect(pm.response.json().id).to.match(/^rol[a-z0-9]+$/));",
                "pm.test('Role.isSystem=false', () => pm.expect(pm.response.json().isSystem).to.eql(false));",
                "pm.test('Role.projectId matches the project (project-scoped)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.projectId, JSON.stringify(j)).to.eql(pm.environment.get('projectId212'));",
                "});",
                "pm.test('Role.accountId empty for a project-scoped role', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accountId || '', JSON.stringify(j)).to.eql('');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-BOTH-SCOPES — scope XOR: account_id AND project_id both set →
# 400 INVALID_ARGUMENT (a custom role is account- XOR project-scoped). No role.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-BOTH-SCOPES",
    title="Create role with BOTH accountId and projectId → 400 INVALID_ARGUMENT (scope XOR)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="create-both-scopes",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "projectId": "prj0000000000000abcd",
                "name": "bothscope_{{runId}}",
                "rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ROL-CR-NEG-NO-SCOPE — scope XOR: neither accountId nor projectId →
# 400 INVALID_ARGUMENT (a custom role must carry exactly one scope). No role.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-CR-NEG-NO-SCOPE",
    title="Create role with NEITHER accountId nor projectId → 400 INVALID_ARGUMENT (scope required)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="create-no-scope",
            method="POST",
            path="/iam/v1/roles",
            body={
                "name": "noscope_{{runId}}",
                "rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# Role own-resource `labels`.
#
# Role.labels (own-resource tenant-facing метки) делают Role label-selectable
# наравне с account/project; их НЕ путать с Rule.matchLabels (object-selector
# внутри грант-правила). labels — mutable через update_mask=labels.
#
# verifies: own-resource labels round-trip via update_mask=labels (happy), and
# invalid labels → INVALID_ARGUMENT.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ROL-UP-T33-LABELS-OK",
    title="Update crudRoleId labels (updateMask=labels) → Operation done, Get confirms own-resource labels",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update-labels",
            method="PATCH",
            path="/iam/v1/roles/{{crudRoleId}}",
            body={"labels": {"team": "payments", "tier": "gold"}, "updateMask": "labels"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="get-confirms-labels",
            method="GET",
            path="/iam/v1/roles/{{crudRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('Role.labels persisted (own-resource)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.labels, 'labels map present').to.be.an('object');",
                "  pm.expect(j.labels.team, JSON.stringify(j.labels)).to.eql('payments');",
                "  pm.expect(j.labels.tier).to.eql('gold');",
                "});",
            ],
        ),
        Step(
            name="list-roles-visible",
            method="GET",
            path="/iam/v1/roles?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('account-admin lists own custom role (viewer-tier, List unaffected)', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.roles || []).map(r => r.id);",
                "  pm.expect(ids, JSON.stringify(ids)).to.include(pm.environment.get('crudRoleId'));",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ROL-CR-T33-NEG-BADLABELS",
    title="Create role with invalid labels (uppercase/special) → 400 INVALID_ARGUMENT (request-layer annotation parity)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-labels",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "badlbl_{{runId}}",
                "rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"]}],
                "labels": {"Team": "PROD!"},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))
