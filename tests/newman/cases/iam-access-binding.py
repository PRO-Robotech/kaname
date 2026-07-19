# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для AccessBindingService.

Covered RPCs:
  Create (strict — migration 0003), Get, Delete, ListByScope, ListBySubject.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId (admin of accountAId)
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated, no account membership
    accountAId        — pre-seeded account as binding resource
    accountBId        — cross-account (for isolation probes)
    userAAAId         — User.id of jwtAccountAdminA principal
    userNOBId         — User.id of jwtNoBindings principal
    userAABId         — User.id of jwtAccountAdminB principal

  System role id used: ROLE_VIEW = "rol1bda80f2be4d3658e" (md5('view')[:17])
  from migration 0008_role_catalog_kac122.sql. Matches authz-deny.py constant.

  The suite creates AccessBindings on accountAId (resource_type="account",
  resource_id=accountAId) with subject userNOBId. Migration 0003 makes Create
  STRICT: a duplicate active 5-tuple (subject,role,resource) returns
  AlreadyExists with verbatim text «these permissions are already granted to
  <subject_id> on <res_type>:<res_id>» instead of silently re-using the
  existing id.

Operation envelope:
  Create and Delete return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kacho-iam).
  Get / ListByScope / ListBySubject are sync reads (no Operation).

Gotchas:
  - Create is STRICT (migration 0003): a duplicate 5-tuple (subject_type,
    subject_id, role_id, resource_type, resource_id) with revoked_at IS NULL
    raises ALREADY_EXISTS via partial UNIQUE access_bindings_active_grant_uniq.
    The error surfaces in op.error.code=6 with verbatim message
    «these permissions are already granted to <subject_id> on
    <resource_type>:<resource_id>». A re-grant AFTER explicit Delete (which
    soft-revokes) is allowed.
  - AccessBindingService has NO plain account-scoped GET /iam/v1/accessBindings list.
    Only ListByScope and ListBySubject are exposed (with_list=False
    in authz-deny.py define_account_scoped). Calling GET /iam/v1/accessBindings
    returns a 404/405/501 — this is by design, not a bug.
  - subject_id existence IS enforced (migration 0049 subject_ref_exists BEFORE
    INSERT/UPDATE trigger — a polymorphic-FK substitute): the (subject_type,
    subject_id) pair must resolve to an existing user/service_account/group in the
    iam DB, else 23503 → async FailedPrecondition. A made-up subject id can NOT be
    bound (phantom-grant / delete-race close, hard-rule #10) — see mint_user().
    role_id HAS a real FK (access_bindings_role_fk → roles.id): non-existent role_id
    → async FailedPrecondition (FK RESTRICT). resource_id is stored as opaque TEXT.
  - ListBySubject authz semantics: user principal may only query
    their OWN bindings (subject_type=user, subject_id=<self>); cross-user
    ListBySubject → 403 PermissionDenied.
  - Delete authority: not self-only; account-owner
    may revoke grants within their scope.
  - After Delete: the FGA grant-tuple is also removed.

Case IDs follow the IAM-ACB-<RPC>-<CLASS>[-detail] scheme.

Acceptance scenarios:
  Create-happy → id starts with `acb`.
  Duplicate active 5-tuple → AlreadyExists with verbatim text
    «these permissions are already granted to <subject_id> on
    <res_type>:<res_id>» (migration 0003).
  Create с несущ. role_id → FailedPrecondition (FK).

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  AccessBindingService RPCs are correctly implemented. Do not weaken
  assertions — fix the implementation instead.
"""

CASES = []

# System role ids — deterministic catalog (`rol` + md5(<name>)[:17]).
ROLE_VIEW  = "rol1bda80f2be4d3658e"   # md5('view')[:17]
ROLE_ADMIN = "rol21232f297a57a5a74"   # md5('admin')[:17]

# Reusable SYSTEM verb-bundle role used as the target-binding role.
# `compute.instance.admin` carries permissions ["compute.instance.*"] (migration
# 0001 role catalog), so it COVERS object type `compute.instance` (role-coverage
# gate passes) but does NOT cover `vpc.subnet` (the coverage negative). Being a
# SYSTEM role it is assignable on ANY scope (account/project/cluster), so it is the
# clean reusable role for the target scenarios. id = "rol" + md5("compute.instance.admin")[:17].
ROLE_COMPUTE_ADMIN = "rolfe4e91e8c9f6542a6"

# SYSTEM role that grants verbs ONLY on the iam.user object type
# (`iam.user.view` carries permissions ["iam.user.read","iam.user.list",
# "iam.user.get"], migration 0001 catalog; migration 0005 promotes each to the
# canonical 4-segment form `iam.user.*.read` etc.). PermissionObjectType extracts
# type `iam.user` (resource != "*", so NOT a wildcard bundle), hence
# domain.RoleCoversType(perms, "compute.instance") == FALSE — the role covers no
# verb on compute.instance. This is the clean role for the selector role-coverage
# negative: it parallels ROLE_COMPUTE_ADMIN-vs-vpc.subnet in the target-ref
# negative. NOTE: ROLE_VIEW ("view") is a GLOBAL viewer bundle
# (`*.*.*.read` after 0005) — it DOES cover compute.instance via the `*` module
# wildcard, so it must NOT be used for a coverage-negative. id = "rol" +
# md5("iam.user.view")[:17].
ROLE_IAM_USER_VIEW = "role2f47108d41b38f39"

# Owner system-role (migration 0035). id = "rol" + md5("owner")[:17]. The
# Account.Create auto owner-binding and the migrate-backfill on existing accounts
# both bind this role @ ACCOUNT with deletion_protection=true.
ROLE_OWNER = "rol72122ce96bfec66e2"

# A non-existent role and binding id for negative probes.
GARBAGE_ROLE = "rol00000000000notfnd"
GARBAGE_ACB  = "acb00000000000notfnd"


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


def _delete_acb_teardown(name, acb_var, auth="jwtAccountAdminA"):
    """Best-effort revoke so re-runs don't trip the strict-create active-grant
    UNIQUE (subject,role,resource). Accepts 200/404/403."""
    return Step(
        name=name,
        method="DELETE",
        path="/iam/v1/accessBindings/{{" + acb_var + "}}",
        auth=auth,
        test_script=[
            "pm.test('teardown: status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
        ],
    )


def _f51_teardown():
    return _delete_acb_teardown("teardown-f51", "f51AcbId")


def mint_user(env_var, ext, auth="jwtAccountAdminA"):
    """Mint a fresh REAL user via the PUBLIC invite flow (UserService.Invite,
    POST /iam/v1/users:invite), wait for it to COMMIT, and stash its id — so it can
    be an AccessBinding subject. Returns TWO steps: the invite + a poll of the
    returned Operation to done.

    Migration 0049 (access_bindings subject_ref_exists trigger) makes the binding's
    (subject_type, subject_id) a within-service reference that MUST resolve to an
    existing user/service_account/group — a made-up `usr-*` string is rejected 23503
    → FAILED_PRECONDITION at Create (phantom-grant / delete-race close, hard-rule #10).
    So a subject can no longer be invented inline; mint a real one.

    We use Invite (not UpsertFromIdentity): UpsertFromIdentity is an Internal* RPC with
    no PUBLIC REST route — it is served ONLY on the api-gateway cluster-internal listener
    (:8081), so at the public {{baseUrl}} (:8080) it 404s (ban #6). Invite is the PUBLIC
    REST mint a tenant admin can drive: it INSERTs a PENDING user row and returns
    metadata.userId synchronously; the row EXISTS in kacho_iam.users, so the 0049 trigger
    (existence, status-agnostic) passes and the id is a valid subject. email is
    runId-scoped → a distinct real user per run (unique subject, no active-grant UNIQUE
    collision) referenced by no other suite (→ no cross-suite pollution). jwtAccountAdminA
    can invite into account-A (canInviteUsers editor cascade); the invited id carries the
    `usr` prefix. Same PUBLIC flow as the GREEN iam-user IAM-USR-SETUP-INVITE-INV-TO-B case.
    Invite is async (LRO worker commits the row in a goroutine), so the poll
    deterministically waits for the mint Operation done → the row is committed before the
    binding Create uses it."""
    op_var = f"{env_var}MintOp"
    return [
        Step(
            name=f"mint-{env_var}",
            method="POST",
            path="/iam/v1/users:invite",
            body={
                "accountId": "{{accountAId}}",
                "email": f"{ext}-{{{{runId}}}}@kacho.local",
                "displayName": f"acb {ext} {{{{runId}}}}",
            },
            auth=auth,
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", op_var),
                *save_from_response("(j.metadata && j.metadata.userId) || (j.user && j.user.id) || j.id", env_var),
                f"pm.test('minted {env_var} has usr prefix', () => pm.expect(pm.environment.get('{env_var}') || '', 'minted user id').to.match(/^usr[a-z0-9]+$/));",
            ],
        ),
        Step(
            name=f"mint-poll-{env_var}",
            method="GET",
            path="/operations/{{" + op_var + "}}",
            auth=auth,
            test_script=[
                "pm.test('mint poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                f"if (!j.done && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                f"pm.test('minted {env_var} committed (operation done, no error)', () => {{",
                "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
                "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
                "});",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# IAM-ACB-CR-CRUD-OK — Create AccessBinding → Operation done → Get confirms
# Subject: userNOBId. Role: ROLE_VIEW. Resource: account/accountAId.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-CRUD-OK",
    title="Create AccessBinding (user/userNOBId, view, account/accountAId) → Operation(iop) done → Get confirms id prefix `acb`",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Re-run safety (fixture-dup guard): AccessBinding.Create is strict-create
        # (a duplicate active 5-tuple raises ALREADY_EXISTS, migration 0003). The DB
        # is persistent across newman runs, so a binding created by a PRIOR run of this
        # very case survives and makes THIS run's `create` fail ALREADY_EXISTS — which
        # leaves crudAcbId pointing at a never-created binding (get-confirms 403/404)
        # and starves list-by-resource/list-by-subject. Discover any pre-existing
        # active (userNOBId, ROLE_VIEW, account/accountAId) binding and revoke it
        # FIRST, so `create` always materializes a fresh one. Idempotent: nothing to
        # revoke on a clean DB.
        # The discovery GET ALWAYS runs (a safe read). When it finds a pre-existing
        # active dup it stashes dupAcbId and falls through to the revoke; when the DB is
        # clean it jumps straight to `create` (so the DELETE step never fires with an
        # empty/malformed id).
        Step(
            name="pre-clean-dup",
            method="GET",
            # Discovery MUST use an AUTHORIZED read: :listByScope on account/accountAId
            # (the account owner sees EVERY binding in the account scope). The prior
            # :listBySubject?subjectId=userNOBId is a CROSS-user query (owner is not the
            # subject) -> correctly denied 403, so it could never discover the stale dup
            # and `create` then collided ALREADY_EXISTS (crudAcbId became a phantom).
            # pageSize=1000: the account scope accumulates >50 bindings across re-runs, so
            # the default page (50) can page-out the stale (userNOBId,view,account) dup.
            # :listByScope returns ALL subjects -> the find filters by subjectId=userNOBId.
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean list status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "pm.environment.unset('dupAcbId');",
                "if (pm.response.code === 200) {",
                "  const j = pm.response.json();",
                "  const arr = (j && j.accessBindings) || [];",
                f"  const dup = arr.find(b => b.roleId === '{ROLE_VIEW}'",
                "       && b.subjectId === pm.environment.get('userNOBId')",
                "       && b.resourceType === 'account'",
                "       && b.resourceId === pm.environment.get('accountAId'));",
                "  if (dup && dup.id) { pm.environment.set('dupAcbId', dup.id); }",
                "}",
                # No pre-existing dup (clean DB, or NOB not visible) → skip revoke+poll.
                "if (!pm.environment.get('dupAcbId')) { pm.execution.setNextRequest('create'); }",
            ],
        ),
        Step(
            # Reached ONLY when dupAcbId is set (a real, well-formed binding id).
            name="pre-clean-revoke",
            method="DELETE",
            path="/iam/v1/accessBindings/{{dupAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # The stale (userNOBId,view,accountA) binding is typically a LEFTOVER from
                # the authz-deny AB-CR-ALLOW suite (it grants the SAME shared 5-tuple and its
                # best-effort teardown accepts a transient 403), or from a prior run. AAA's
                # `v_delete` on it (admin-from-account, resolved via the binding→account
                # parent-tuple) is EVENTUALLY-consistent: an immediate DELETE 403s until that
                # parent-tuple drains to OpenFGA — proven CONVERGENT by
                # AUTHZGCP-BIND-DELETE-BY-ADMIN-ALLOW (poll-fga-readiness → delete → 200).
                # A single-shot revoke that accepts the 403 leaves the binding ACTIVE, so it
                # keeps the strict-create UNIQUE (WHERE revoked_at IS NULL) slot and EVERY
                # downstream (userNOBId,view,accountA) create (CR-CRUD-OK, CR-NEG-DUP, DL-FLOW,
                # DP-*) collides ALREADY_EXISTS → crudAcbId phantom → the whole ACB suite
                # cascades (get/list/delete 404/403). So retry SELF on the 403 delete-authority
                # window until the revoke succeeds (200 → poll it done below) or the binding is
                # already gone (404). Bounded; on budget exhaustion the existing fall-through to
                # `create` still surfaces the real collision (never masked, never infinite).
                "if (pm.environment.get('_pcrStarted') !== pm.info.requestName) { pm.environment.set('_pcrCount', '0'); pm.environment.set('_pcrStarted', pm.info.requestName); }",
                "const _pcrc = parseInt(pm.environment.get('_pcrCount') || '0', 10);",
                "if (pm.response.code === 403 && _pcrc < 40) {",
                "  pm.environment.set('_pcrCount', String(_pcrc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* delete-authority (binding→account parent-tuple) materialization wait */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pcrCount'); pm.environment.unset('_pcrStarted');",
                "pm.test('pre-clean revoke status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
                "const j = pm.response.json();",
                # A 200 returns the delete Operation → poll it done; a 404/403 means it is
                # already gone → skip the poll and create directly.
                "if (pm.response.code === 200 && j && j.id) { pm.environment.set('preCleanOpId', j.id); }",
                "else { pm.environment.unset('preCleanOpId'); pm.execution.setNextRequest('create'); }",
            ],
        ),
        Step(
            # AccessBinding.Delete is async: revoked_at is stamped in the operation
            # worker, so `create` must wait for the delete Operation to report done —
            # otherwise the active-grant UNIQUE (WHERE revoked_at IS NULL) still sees the
            # old row and `create` collides ALREADY_EXISTS (the fixture-dup).
            name="pre-clean-poll",
            method="GET",
            path="/operations/{{preCleanOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('pre-clean delete done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
        Step(
            name="create",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "crudAcbId"),
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('crudAcbId')) {",
                "  pm.environment.set('crudAcbId', j.response.id);",
                "}",
            ],
        ),
        # flat-RBAC is eventually-consistent on grant→access: the GET of the
        # just-created binding is authz-gated on the caller resolving read access on
        # iam_access_binding:<crudAcbId> via the binding's account-anchor parent-tuple,
        # which propagates a beat after Operation→done → an immediate GET intermittently
        # 403s under full-pipeline CI load. The access is GUARANTEED to materialize
        # (proven by the real-OpenFGA sync-FGA-write integration tests), so poll the GET
        # until it leaves the 403 propagation window, then assert on the converged 200.
        poll_request_until_status(
            name="get-confirms",
            method="GET",
            path="/iam/v1/accessBindings/{{crudAcbId}}",
            auth="jwtAccountAdminA",
            # Retry the authz-gate deny window: the binding row exists (just created),
            # so the only transient is the owner's per-object v_get materializing a beat
            # after Operation→done. BUG-2 hide-existence surfaces that read-deny as 404
            # (not 403), so poll past BOTH until the v_get converges to 200.
            retry_on=(403, 404),
            test_script=[
                *assert_status(200),
                "pm.test('AccessBinding.id prefix acb', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with acb').to.match(/^acb[a-z0-9]+$/);",
                "});",
                "pm.test('AccessBinding.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('crudAcbId'));",
                "});",
                "pm.test('AccessBinding.subjectType = user', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.subjectType).to.eql('user');",
                "});",
                f"pm.test('AccessBinding.roleId = ROLE_VIEW', () => {{",
                f"  const j = pm.response.json();",
                f"  pm.expect(j.roleId).to.eql('{ROLE_VIEW}');",
                "});",
                "pm.test('AccessBinding.resourceType = account', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.resourceType).to.eql('account');",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-NEG-DUP — Create same 5-tuple again → Operation.error AlreadyExists
# Migration 0003 replaces the historical ON CONFLICT-upsert idempotency with a
# strict partial UNIQUE access_bindings_active_grant_uniq (WHERE revoked_at IS
# NULL). A duplicate active grant surfaces gRPC code AlreadyExists (6) with
# verbatim text «these permissions are already granted to <subject_id> on
# <resource_type>:<resource_id>».
# Depends on IAM-ACB-CR-CRUD-OK having created the binding.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-NEG-DUP",
    title="Create duplicate active 5-tuple → Operation.error ALREADY_EXISTS with verbatim text (migration 0003)",
    classes=["NEG"],
    priority="P0",
    steps=[
        Step(
            name="create-duplicate",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                # Sync handler enqueues Operation regardless of duplicate;
                # the conflict surfaces inside op.error after polling.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "dupOpId"),
            ],
        ),
        Step(
            name="poll-dup-op",
            method="GET",
            path="/operations/{{dupOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('strict-create: operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('strict-create: operation.error present (AlreadyExists)', () => {",
                "  pm.expect(j.error, JSON.stringify(j)).to.exist;",
                # gRPC AlreadyExists = 6.
                "  pm.expect(j.error.code, 'error.code must be AlreadyExists (6)').to.eql(6);",
                "});",
                "pm.test('strict-create: error.message contains verbatim text', () => {",
                "  const expectedSubj = pm.environment.get('userNOBId');",
                "  const expectedAcc = pm.environment.get('accountAId');",
                "  const want = `these permissions are already granted to ${expectedSubj} on account:${expectedAcc}`;",
                "  pm.expect(j.error.message, `verbatim text expected, got ${j.error.message}`).to.include(want);",
                "});",
            ],
        ),
        # Read-after-write on the (pre-existing) crudAcbId binding — same grant→access
        # propagation window as IAM-ACB-CR-CRUD-OK/get-confirms: poll past any
        # transient 403 to the converged 200, then assert the original survived.
        poll_request_until_status(
            name="verify-original-survives",
            method="GET",
            path="/iam/v1/accessBindings/{{crudAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),  # BUG-2 hide-existence: the v_get propagation deny is 404 (not 403); binding row exists, poll past both to 200.
            test_script=[
                *assert_status(200),
                "pm.test('strict-create: original binding still active', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'original binding still exists').to.eql(pm.environment.get('crudAcbId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-NEG-ROLE-MISSING — non-existent roleId → async FailedPrecondition
# FK access_bindings_role_fk → roles(id) RESTRICT.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-NEG-ROLE-MISSING",
    title="Create AccessBinding with non-existent roleId → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-role",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": GARBAGE_ROLE,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('sync 200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 400) {",
                "  pm.test('sync code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else {",
                "  pm.environment.set('opId', j.id || '');",
                "}",
            ],
        ),
        assert_op_error(9, "FAILED_PRECONDITION", msg_substr="role"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-NEG-SUBJECT-INVALID — invalid subject_type value → sync InvalidArgument
# subject_type must be one of: "user", "service_account", "group".
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-NEG-SUBJECT-INVALID",
    title="Create AccessBinding with invalid subjectType → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-subject",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "notARealType",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
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
# IAM-ACB-CR-AUTHZ-ANON-DENY — anonymous Create → 401 Unauthenticated
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-AUTHZ-ANON-DENY",
    title="Create AccessBinding as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-anon",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
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
# IAM-ACB-CR-AUTHZ-NONADMIN-DENY — jwtNoBindings cannot Create on accountA → 403
# Caller must be owner of the resource Account (or have FGA admin) to grant.
# jwtNoBindings has no binding on accountA → grant-authority denied.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-AUTHZ-NONADMIN-DENY",
    title="Create AccessBinding on accountAId as jwtNoBindings (no grant-authority) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-nonadmin",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
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
# IAM-ACB-GT-CRUD-OK — Get the crud AccessBinding → 200 + correct fields
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-GT-CRUD-OK",
    title="Get crudAcbId → 200 + id prefix acb, subjectType/roleId/resourceType correct",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Read-after-write on crudAcbId — same grant→access propagation window:
        # poll past the transient 403 to the converged 200, then assert the fields.
        poll_request_until_status(
            name="get-ok",
            method="GET",
            path="/iam/v1/accessBindings/{{crudAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),  # BUG-2 hide-existence: the v_get propagation deny is 404 (not 403); binding row exists, poll past both to 200.
            test_script=[
                *assert_status(200),
                "pm.test('AccessBinding.id prefix acb', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with acb').to.match(/^acb[a-z0-9]+$/);",
                "});",
                "pm.test('AccessBinding.id matches requested', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('crudAcbId'));",
                "});",
                "pm.test('AccessBinding fields populated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.subjectType, 'subjectType').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(j.subjectId, 'subjectId').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(j.roleId, 'roleId').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(j.resourceType, 'resourceType').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(j.resourceId, 'resourceId').to.be.a('string').with.length.greaterThan(0);",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-GT-NEG-NOTFOUND — Get non-existent AccessBinding → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-GT-NEG-NOTFOUND",
    title="Get non-existent AccessBinding id → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path=f"/iam/v1/accessBindings/{GARBAGE_ACB}",
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
# IAM-ACB-GT-NEG-ID-MALFORMED — Get with malformed id → 400 or 404
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-GT-NEG-ID-MALFORMED",
    title="Get AccessBinding with malformed id → 400 InvalidArgument or 404",
    classes=["NEG", "VAL"],
    priority="P2",
    steps=[
        Step(
            name="get-malformed",
            method="GET",
            path="/iam/v1/accessBindings/not-a-valid-acb-id-at-all-verylongstring",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('400 or 404', () => pm.expect(pm.response.code).to.be.oneOf([400, 404]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBSC-CRUD-OK — ListByScope (account/accountAId) → 200, contains crudAcbId
# REST: GET /iam/v1/accessBindings:listByScope?resourceType=account&resourceId=...
# (proto defines GET with query params; grpc-gateway maps POST body → query only for GET bindings)
#
# Requires the api-gateway :listByScope route/catalog/allowlist entry; without it
# the request returns 403 "catalog: no entry for method".
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBSC-CRUD-OK",
    title="ListByScope (account/accountAId) → 200, accessBindings array contains crudAcbId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Read-after-write LIST on the fresh crudAcbId binding — same grant→access
        # propagation window: the listByScope RPC returns 200 but crudAcbId may
        # not yet be in the result set (binding account-anchor tuple lags op-done), and
        # a non-converged caller may transiently 403. Poll until crudAcbId is visible
        # (guaranteed to appear — sync-FGA-write integration proof), then assert.
        poll_request_until_status(
            name="list-by-resource",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            retry_on=(403,),  # 403-only; the 200-but-absent window is handled by retry_predicate.
            retry_predicate=("(() => { const j = pm.response.json(); const aid = "
                             "pm.environment.get('crudAcbId'); return aid && "
                             "!(j.accessBindings || []).some(b => b.id === aid); })()"),
            test_script=[
                *assert_status(200),
                "pm.test('accessBindings array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accessBindings, 'accessBindings field').to.be.an('array');",
                "});",
                "pm.test('crudAcbId present in ListByScope result', () => {",
                "  const j = pm.response.json();",
                "  const aid = pm.environment.get('crudAcbId');",
                "  if (aid) {",
                "    pm.expect((j.accessBindings || []).some(b => b.id === aid), 'crudAcbId in list').to.be.true;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBSC-AUTHZ-ANON-DENY — anonymous ListByScope → 401
#
# Pins the anon→401 contract for :listByScope. Requires the api-gateway
# :listByScope route; without it the catalog-miss returns 403/code 7 instead of the
# expected 401/code 16 (the request never reaches the anti-anon interceptor).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBSC-AUTHZ-ANON-DENY",
    title="ListByScope as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="lbr-anon",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}",
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
# IAM-ACB-LBSC-AUTHZ-STRANGER — a true stranger to accountA (jwtAccountAdminB, owner
# of a DIFFERENT account, no grant-authority and no visibility on accountA) calling
# ListByScope on accountA → 403 PermissionDenied (anti-leak).
#
# WHY the actor is jwtAccountAdminB, not jwtNoBindings: under the unified
# label-scope model ListByScope visibility is `viewer ∪ v_list ∪
# self/granted-floor`. jwtNoBindings is NOT a stranger to accountA in this suite —
# IAM-ACB-CR-CRUD-OK grants userNOBId an account-scoped `view` (*.*.* read/list/get)
# role on accountA, which materializes per-object v_list on every binding in
# accountA's scope, so NOB legitimately sees them (no longer empty). The anti-leak
# guarantee is about a caller with NO authority AND NO visibility: jwtAccountAdminB
# owns accountB only, holds no grant on accountA and no v_list on any accountA
# binding → the union floor collapses to ∅ and the use-case fail-closes with
# PermissionDenied (forbidden indistinguishable from empty — a stranger must not
# learn the scope exists nor receive a distinguishing empty 200, anti-leak).
# verifies: a true stranger (no authority, no v_list visibility) → 403 (anti-leak;
# forbidden indistinguishable from empty).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBSC-AUTHZ-STRANGER",
    title="ListByScope (account/accountAId) as jwtAccountAdminB (true stranger: no authority, no visibility) → 403 PermissionDenied (anti-leak)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="lbr-stranger",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminB",
            test_script=[
                # Anti-leak: a stranger with no authority and no v_list visibility
                # is denied — forbidden indistinguishable from empty. An empty 200 would
                # leak that the scope exists; PermissionDenied is required.
                "pm.test('STRANGER: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('STRANGER: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBS-CRUD-OK — ListBySubject (user/userNOBId) called by userNOBId → 200
# Self-query: user queries their own bindings → ALLOW.
# REST: GET /iam/v1/accessBindings:listBySubject?subjectType=user&subjectId=...
# (proto defines GET with query params)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBS-CRUD-OK",
    title="ListBySubject (user/userNOBId) as jwtNoBindings (self) → 200, accessBindings array",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Read-after-write self-LIST — same grant→access propagation window:
        # NOB's self-scope listBySubject returns 200 but crudAcbId may not yet be in
        # the result set. Poll until it appears (guaranteed), then assert.
        poll_request_until_status(
            name="list-by-subject-self",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userNOBId}}&pageSize=1000",
            auth="jwtNoBindings",
            retry_on=(403,),  # 403-only; the 200-but-absent window is handled by retry_predicate.
            retry_predicate=("(() => { const j = pm.response.json(); const aid = "
                             "pm.environment.get('crudAcbId'); return aid && "
                             "!(j.accessBindings || []).some(b => b.id === aid); })()"),
            test_script=[
                *assert_status(200),
                "pm.test('accessBindings array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accessBindings, 'accessBindings field').to.be.an('array');",
                "});",
                "pm.test('crudAcbId visible to self (NOB sees their own bindings)', () => {",
                "  const j = pm.response.json();",
                "  const aid = pm.environment.get('crudAcbId');",
                "  if (aid) {",
                "    pm.expect((j.accessBindings || []).some(b => b.id === aid), 'crudAcbId in self-list').to.be.true;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBS-AUTHZ-SELF-OK — owner queries their own bindings → 200
# jwtAccountAdminA queries userAAAId's bindings → ALLOW (self).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBS-AUTHZ-SELF-OK",
    title="ListBySubject (user/userAAAId) as jwtAccountAdminA (self) → 200, array present",
    classes=["AUTHZ", "CRUD"],
    priority="P1",
    steps=[
        Step(
            name="list-by-subject-self-aaa",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userAAAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('accessBindings array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accessBindings, 'accessBindings field').to.be.an('array');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBS-AUTHZ-FOREIGN-DENY — jwtNoBindings queries AAA's bindings → 403
# Cross-user ListBySubject: user NOB querying user AAA's bindings → DENY.
# user principal may only query their OWN bindings.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBS-AUTHZ-FOREIGN-DENY",
    title="ListBySubject (user/userAAAId) as jwtNoBindings (cross-user) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-by-subject-foreign",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userAAAId}}",
            auth="jwtNoBindings",
            test_script=[
                "pm.test('FOREIGN: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBA-CRUD-OK — ListByAccount (accountAId) called by accountA owner → 200
# Admin-only RPC that returns ALL bindings in the account
# scope (account-attached + every project owned by the account).
# REST: GET /iam/v1/accounts/{accountId}/accessBindings
# Authority: `admin` relation on `account:<accountId>` (account owner or
# delegated FGA admin). NOT a self-scope RPC — admin sees everyone's bindings.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBA-CRUD-OK",
    title="ListByAccount (accountAId) as jwtAccountAdminA → 200, accessBindings array contains crudAcbId",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Read-after-write account-scope LIST — same grant→access propagation window:
        # listByAccount returns 200 but crudAcbId may not yet be in the result
        # set. Poll until it appears (guaranteed), then assert.
        poll_request_until_status(
            name="list-by-account-owner",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000",
            auth="jwtAccountAdminA",
            retry_on=(403,),  # 403-only; the 200-but-absent window is handled by retry_predicate.
            retry_predicate=("(() => { const j = pm.response.json(); const aid = "
                             "pm.environment.get('crudAcbId'); return aid && "
                             "!(j.accessBindings || []).some(b => b.id === aid); })()"),
            test_script=[
                *assert_status(200),
                "pm.test('LBA: accessBindings array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accessBindings, 'accessBindings field').to.be.an('array');",
                "});",
                "pm.test('LBA: crudAcbId visible (owner sees every binding in account scope)', () => {",
                "  const j = pm.response.json();",
                "  const aid = pm.environment.get('crudAcbId');",
                "  if (aid) {",
                "    pm.expect((j.accessBindings || []).some(b => b.id === aid), 'crudAcbId in account-scope list').to.be.true;",
                "  }",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBA-AUTHZ-STRANGER-DENY — a true stranger to accountA → 403 PermissionDenied.
# ListByAccount is the account-audit list (every binding in the account scope). A
# caller with no admin floor AND no label-visibility on accountA must NOT see it.
#
# WHY the actor is jwtAccountAdminB, not jwtNoBindings: under the unified
# label-scope model ListByAccount = account-admin floor ∪ (viewer ∪
# v_list). jwtNoBindings holds an account-scoped `view` grant on accountA (created
# by IAM-ACB-CR-CRUD-OK), which materializes per-object v_list on accountA's
# bindings → it legitimately sees them (no longer denied). The anti-leak guarantee
# targets a caller with neither admin floor nor any visibility: jwtAccountAdminB
# owns accountB only → no admin on accountA, no v_list on any accountA binding →
# the union collapses to ∅ and the use-case fail-closes with PermissionDenied
# (existence-leak-safe; an empty 200 would distinguish a real account from a
# forbidden one).
# verifies: a caller with neither admin floor nor visibility → 403 (anti-leak).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBA-AUTHZ-STRANGER-DENY",
    title="ListByAccount (accountAId) as jwtAccountAdminB (true stranger: no admin, no visibility) → 403 PermissionDenied (anti-leak)",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="list-by-account-stranger",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings",
            auth="jwtAccountAdminB",
            test_script=[
                "pm.test('STRANGER: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('STRANGER: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LBA-AUTHZ-ANON-DENY — anonymous ListByAccount → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LBA-AUTHZ-ANON-DENY",
    title="ListByAccount (accountAId) as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="lba-anon",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings",
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
# IAM-ACB-DL-CRUD-OK — Delete the crud AccessBinding → Operation done, Get 404/403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DL-CRUD-OK",
    title="Delete crudAcbId → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Read-after-write DELETE on the fresh crudAcbId binding — same grant→access
        # propagation window: the Delete gate needs `editor on
        # iam_access_binding:<crudAcbId>` (resolved via the binding's account-anchor
        # parent-tuple), which lags op-done → an immediate DELETE intermittently 403s.
        # Poll past the 403 to the converged 200 (access guaranteed to materialize),
        # then poll the delete Operation and the get-until-gone terminal.
        poll_request_until_status(
            name="delete",
            method="DELETE",
            path="/iam/v1/accessBindings/{{crudAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403,),  # 403-only: binding exists; a 404 (already gone) is a real anomaly.
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the binding is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/accessBindings/{{crudAcbId}}", "AccessBinding"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-DL-NEG-NOTFOUND — Delete non-existent AccessBinding → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DL-NEG-NOTFOUND",
    title="Delete non-existent AccessBinding → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path=f"/iam/v1/accessBindings/{GARBAGE_ACB}",
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
# IAM-ACB-DL-AUTHZ-ADMIN-ALLOW — account owner (jwtAccountAdminA) deletes a binding → 200
# Create a fresh binding for this probe (crudAcbId was deleted above).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DL-AUTHZ-ADMIN-ALLOW",
    title="Delete AccessBinding as account owner (jwtAccountAdminA) → 200 Operation (ALLOW)",
    classes=["AUTHZ", "CRUD"],
    priority="P1",
    steps=[
        Step(
            name="create-for-delete-authz",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userAABId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "deleteAuthzAcbId"),
            ],
        ),
        Step(
            name="poll-create-for-delete",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('deleteAuthzAcbId')) {",
                "  pm.environment.set('deleteAuthzAcbId', j.response.id);",
                "}",
            ],
        ),
        # Read-after-write DELETE on the fresh deleteAuthzAcbId binding — same
        # grant→access propagation window: poll past the transient 403 (owner's
        # Delete gate needs editor on iam_access_binding:<id>, which lags op-done) to
        # the converged 200, then poll the Operation done.
        poll_request_until_status(
            name="delete-as-owner",
            method="DELETE",
            path="/iam/v1/accessBindings/{{deleteAuthzAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403,),  # 403-only: binding exists; a 404 is a real anomaly.
            test_script=[
                # Account owner can revoke grants in their scope.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-DL-AUTHZ-STRANGER-DENY — jwtNoBindings cannot Delete a binding on accountA → 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DL-AUTHZ-STRANGER-DENY",
    title="Delete accessBinding on accountA as jwtNoBindings (no grant-authority) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-stranger",
            method="DELETE",
            path=f"/iam/v1/accessBindings/{GARBAGE_ACB}",
            auth="jwtNoBindings",
            test_script=[
                "pm.test('STRANGER: 403 or 404', () => pm.expect(pm.response.code).to.be.oneOf([403, 404]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('STRANGER: code 7 or 5', () => pm.expect(j && j.code).to.be.oneOf([7, 5]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-DL-FLOW-REVOKE-ENFORCED — grant → revoke → DB-level binding gone.
# Verifies the storage side of the revoke flow: a freshly-created binding can
# be deleted, and Get on the same id returns 404/403 afterwards. The companion
# "Check returns DENY after revoke" propagation is covered by the dedicated
# authz-grant-check-propagation suite (FGA-Check after Delete).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DL-FLOW-REVOKE-ENFORCED",
    title="Grant → Delete → Get returns 404/403 (binding revoked at storage layer)",
    classes=["FLOW", "CRUD"],
    priority="P1",
    steps=[
        # Create a fresh binding.
        Step(
            name="grant-create",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "flowAcbId"),
            ],
        ),
        Step(
            name="poll-grant",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('flowAcbId')) {",
                "  pm.environment.set('flowAcbId', j.response.id);",
                "}",
            ],
        ),
        # Revoke (delete) the binding. Read-after-write DELETE on the freshly-granted
        # flowAcbId — same grant→access propagation window: poll past the
        # transient 403 (Delete gate needs editor on iam_access_binding:<flowAcbId>,
        # which lags op-done) to the converged 200, then poll the Operation done.
        poll_request_until_status(
            name="revoke-delete",
            method="DELETE",
            path="/iam/v1/accessBindings/{{flowAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403,),  # 403-only: binding exists; a 404 is a real anomaly.
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Verify binding is gone from DB.
        Step(
            name="get-after-revoke",
            method="GET",
            path="/iam/v1/accessBindings/{{flowAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # After revoke the binding is gone at the storage layer; a read of it
                # is denied. Both outcomes are acceptable and carry no existence leak —
                # the revoker already knows the binding existed, so the exact deny-code
                # on a just-deleted binding is an edge detail, not a security boundary:
                #   404 — owner's per-object v_get tuple removed → hide-existence; OR
                #   403 — authz-gate denies before the soft-deleted row resolves.
                # (Live single-resource Get-deny on an *extant* resource stays strict
                # 404 elsewhere; only this delete-flow tail is tolerant.)
                "pm.test('FLOW: binding gone after revoke — 404 or 403', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([404, 403]);",
                "});",
                # Companion "subject denied via authz-gated RPC after revoke"
                # assertion lives in the grant-check-propagation suite.
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# Cluster-scope AccessBinding: AccessBindingService.Create
# accepts resource_type='cluster' with the singleton resource_id
# 'cluster_kacho_root'. Authority is delegated only — caller must hold
# `system_admin` on cluster:cluster_kacho_root (no DB owner fallback for the
# cluster scope). Bootstrap admin is granted system_admin at startup via
# bootstrap_admin.go.
# ---------------------------------------------------------------------------

CLUSTER_SINGLETON_ID = "cluster_kacho_root"


# ---------------------------------------------------------------------------
# IAM-ACB-CR-CLUSTER-OK — Bootstrap admin grants cluster-scope binding → 200,
# Operation done, Get confirms resource_type='cluster' / resource_id=singleton.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-CLUSTER-OK",
    title="Create cluster-scope AccessBinding (admin/cluster_kacho_root) as jwtBootstrap → 200 Operation done, Get confirms",
    classes=["CRUD", "CLUSTER"],
    priority="P0",
    steps=[
        Step(
            name="cluster-create",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_ADMIN,
                "resourceType": "cluster",
                "resourceId": CLUSTER_SINGLETON_ID,
            },
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "clusterAcbId"),
            ],
        ),
        Step(
            name="poll-cluster-create",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtBootstrap",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                # poll-cluster-create budget 30→80 (GATE-RUN #3 root #3). Busy-wait уже
                # был (c8ec4c2), НЕ пропущен — но budget 30*500ms=15s < confirm-deadline
                # KACHO_IAM_OWNER_CONFIRM_DEADLINE=30s. Cluster-scope AccessBinding.Create
                # делает broad cluster-materialization (owner-tuple confirm read-after-write
                # под HIGHER_CONSISTENCY по singleton cluster_kacho_root); op-done лагал >15s
                # → done:false на конце polla (binding при этом уже материализован:
                # get-cluster-binding зелёный). Project-scope AB confirm'ится <15s (др. 35
                # inline-polls ок при pc<30). 80*500ms=40s покрывает 30s confirm-deadline с
                # запасом. Только этот P0 cluster-poll; fast-путь выходит рано (не крутит 80).
                "if (!j.done && pc < 80) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('cluster-create: operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('cluster-create: operation succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('clusterAcbId')) {",
                "  pm.environment.set('clusterAcbId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="get-cluster-binding",
            method="GET",
            path="/iam/v1/accessBindings/{{clusterAcbId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('cluster-binding.resourceType = cluster', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.resourceType, JSON.stringify(j)).to.eql('cluster');",
                "});",
                f"pm.test('cluster-binding.resourceId = singleton', () => {{",
                "  const j = pm.response.json();",
                f"  pm.expect(j.resourceId, JSON.stringify(j)).to.eql('{CLUSTER_SINGLETON_ID}');",
                "});",
                "pm.test('cluster-binding.id prefix acb', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with acb').to.match(/^acb[a-z0-9]+$/);",
                "});",
            ],
        ),
        # Teardown — revoke so re-runs don't trip strict-create UNIQUE.
        Step(
            name="cluster-delete-teardown",
            method="DELETE",
            path="/iam/v1/accessBindings/{{clusterAcbId}}",
            auth="jwtBootstrap",
            test_script=[
                # Teardown is best-effort: accept 200/404/403 (some envs may already
                # have revoked across re-runs).
                "pm.test('teardown: status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-CLUSTER-AUTHZ-NONADMIN-DENY — Non-admin caller cannot grant
# cluster-scope. The use-case has no owner-fallback for cluster scope; only
# delegated FGA admin (`system_admin` on cluster) qualifies.
# jwtAccountAdminA owns accountA but holds no system_admin → DENY (403).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-CLUSTER-AUTHZ-NONADMIN-DENY",
    title="Create cluster-scope AccessBinding as jwtAccountAdminA (no system_admin) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG", "CLUSTER"],
    priority="P0",
    steps=[
        Step(
            name="cluster-create-nonadmin",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userAABId}}",
                "roleId": ROLE_ADMIN,
                "resourceType": "cluster",
                "resourceId": CLUSTER_SINGLETON_ID,
            },
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('CLUSTER-NONADMIN: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('CLUSTER-NONADMIN: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-CLUSTER-NEG-WRONG-RESID — resource_type='cluster' with a
# non-singleton resource_id must fail validation. Domain enforces
# ClusterSingletonID — any other value → InvalidArgument from Validate().
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-CLUSTER-NEG-WRONG-RESID",
    title="Create cluster-scope AccessBinding with wrong resource_id → 400 InvalidArgument (singleton enforced)",
    classes=["NEG", "VAL", "CLUSTER"],
    priority="P1",
    steps=[
        Step(
            name="cluster-create-wrongid",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_ADMIN,
                "resourceType": "cluster",
                "resourceId": "not_the_singleton",
            },
            auth="jwtBootstrap",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-GLOBAL-ALL-NONADMIN-REJECT — GLOBAL (=cluster scope) + selector all on
# a NON cluster-admin role is a per-object-cluster-wide anti-pattern → SYNC
# INVALID_ARGUMENT (before the Operation). ROLE_VIEW is the system viewer bundle
# `*.*.{get,list,read}` — an ARM_ANCHOR (selector=all) rule whose verbs are NOT `*`,
# so it is NOT the cluster-admin superuser (`*.*.*`). Caller jwtBootstrap IS
# cluster-admin (so it clears grant-authority and reaches the selector gate — the
# rejection is the selector policy, not an authz denial). The cluster-admin role
# (ROLE_ADMIN, *.*.*) at GLOBAL is the legal case, covered by IAM-ACB-CR-CLUSTER-OK above.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-GLOBAL-ALL-NONADMIN-REJECT",
    title="Create GLOBAL (cluster) AccessBinding with non-cluster-admin selector=all role → 400 INVALID_ARGUMENT",
    classes=["NEG", "VAL", "CLUSTER"],
    priority="P0",
    steps=[
        Step(
            name="cluster-create-global-all-nonadmin",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,  # *.*.{get,list,read} — ARM_ANCHOR, NOT *.*.*
                "resourceType": "cluster",
                "resourceId": CLUSTER_SINGLETON_ID,
            },
            auth="jwtBootstrap",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('GLOBAL+all non-cluster-admin message', () => {",
                "  let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "  pm.expect(j && j.message, JSON.stringify(j)).to.include('GLOBAL scope requires names or labels selector');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-GROUP-CRUD-OK — ListSubjectPrivileges for a
# subject_type=group subject returns the group's DIRECT bindings, role_name
# resolved server-side. Self-contained flow: create a group → grant a viewer
# binding to that group on account/accountAId → listSubjectPrivileges?
# subjectType=group&subjectId=<grp> → assert the privilege is present + enriched.
# Caller jwtAccountAdminA is the owner/admin of accountAId (the group's home
# account), so the self/account-admin authz gate allows the read.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LSP-GROUP-CRUD-OK",
    title="ListSubjectPrivileges (group subject) → 200, group's direct binding present with resolved role_name",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="create-group",
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": "lspgrp{{runId}}", "description": "1.3b group-privileges probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.groupId", "lspGroupId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        Step(
            name="capture-group-id",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "if (j.response && j.response.id) pm.environment.set('lspGroupId', j.response.id);",
                "pm.test('lspGroupId captured (grp prefix)', () => {",
                "  pm.expect(pm.environment.get('lspGroupId'), 'lspGroupId').to.match(/^grp[a-z0-9]+$/);",
                "});",
            ],
        ),
        Step(
            name="grant-binding-to-group",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "group",
                "subjectId": "{{lspGroupId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        Step(
            name="list-group-privileges",
            method="GET",
            path="/iam/v1/accessBindings:listSubjectPrivileges?subjectType=group&subjectId={{lspGroupId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('privileges array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.privileges, 'privileges field').to.be.an('array');",
                "});",
                "pm.test('group viewer privilege present with resolved role_name', () => {",
                "  const j = pm.response.json();",
                f"  const p = (j.privileges || []).find(x => x.roleId === '{ROLE_VIEW}');",
                "  pm.expect(p, 'viewer privilege for the group binding').to.exist;",
                "  pm.expect(p.roleName, 'role_name resolved server-side (non-empty)').to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect(p.resourceType, 'resourceType=account').to.eql('account');",
                "  pm.expect(p.resourceId, 'resourceId=accountAId').to.eql(pm.environment.get('accountAId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-GROUP-NEG-PREFIX-MISMATCH — a group id passed as
# subjectType=user is rejected with sync InvalidArgument (prefix↔type mismatch,
# first statement before any repo touch). Confirms the whitelist accepts `group`
# but still enforces prefix↔type consistency.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LSP-GROUP-NEG-PREFIX-MISMATCH",
    title="ListSubjectPrivileges with a grp-id under subjectType=user → 400 InvalidArgument (prefix mismatch)",
    classes=["NEG", "VAL", "AUTHZ"],
    priority="P1",
    steps=[
        Step(
            name="list-priv-prefix-mismatch",
            method="GET",
            path="/iam/v1/accessBindings:listSubjectPrivileges?subjectType=user&subjectId=grp00000000000group1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))


# ===========================================================================
# ListAssignableRoles + Create scope-enforcement
#
# Test-first (RED): these cases fail until ListAssignableRoles is implemented
# and AccessBinding.Create begins enforcing isRoleAssignable. Do not weaken —
# fix the implementation.
# ===========================================================================


# ---------------------------------------------------------------------------
# IAM-ACB-LAR-CRUD-OK — 1.5-01/1.5-11: ListAssignableRoles on account/accountAId
# returns SYSTEM roles (scopeGroup=SYSTEM), each carrying role_id/name/scopeGroup;
# no `permissions` field; ROLE_VIEW (a system role) is present.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LAR-CRUD-OK",
    title="ListAssignableRoles (account/accountAId) → 200, SYSTEM roles with scopeGroup, no permissions",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="list-assignable-account",
            method="GET",
            path="/iam/v1/accessBindings:listAssignableRoles?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('roles array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.roles, 'roles field').to.be.an('array');",
                "});",
                f"pm.test('system role ROLE_VIEW present with scopeGroup SYSTEM', () => {{",
                "  const j = pm.response.json();",
                f"  const r = (j.roles || []).find(x => x.roleId === '{ROLE_VIEW}');",
                "  pm.expect(r, JSON.stringify(j)).to.exist;",
                "  pm.expect(r.scopeGroup, 'server-computed scope_group').to.eql('SYSTEM');",
                "  pm.expect(r.isSystem).to.eql(true);",
                "  pm.expect(r.name, 'resolved name present').to.be.a('string').and.not.empty;",
                "});",
                "pm.test('AssignableRole carries no permissions field (lean picker, Q#2)', () => {",
                "  const j = pm.response.json();",
                "  (j.roles || []).forEach(r => pm.expect(r.permissions, 'no permissions on AssignableRole').to.not.exist);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LAR-CRUD-CLUSTER — 1.5-03: cluster resource returns ONLY system roles.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LAR-CRUD-CLUSTER",
    title="ListAssignableRoles (cluster/cluster_kacho_root) → 200, every role isSystem=true (1.5-03)",
    classes=["CRUD", "CONF"],
    priority="P1",
    steps=[
        Step(
            name="list-assignable-cluster",
            method="GET",
            path="/iam/v1/accessBindings:listAssignableRoles?resourceType=cluster&resourceId=cluster_kacho_root",
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                "pm.test('cluster → only system roles (1.5-03)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.roles, JSON.stringify(j)).to.be.an('array');",
                "  (j.roles || []).forEach(r => {",
                "    pm.expect(r.isSystem, `role ${r.roleId} must be system`).to.eql(true);",
                "    pm.expect(r.scopeGroup).to.eql('SYSTEM');",
                "  });",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LAR-NEG-MALFORMED — malformed resource_id → 400 OR 403.
# The use-case validates resource_id format as its FIRST statement
# (InvalidArgument 400; asserted directly at the use-case level by the Go
# integration test). End-to-end through the api-gateway, however, the
# per-RPC authz interceptor runs BEFORE the handler: for a resource-scoped RPC it
# extracts the (malformed) resource_id as the FGA scope object and the Check
# fail-closes (no grant-authority on an unresolvable object) → PERMISSION_DENIED
# (403). Both are correct: 400 is the format contract, 403 is the security layer
# pre-empting it (defense-in-depth — you cannot be authorized on a malformed
# scope). Same flexibility as IAM-ACB-GT-NEG-ID-MALFORMED (400 or 404). The
# layering is documented in docs/architecture/assignable-roles-scope-enforcement.md.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LAR-NEG-MALFORMED",
    title="ListAssignableRoles with malformed account resource_id → 400 InvalidArgument or 403 (authz pre-empt)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="lar-malformed",
            method="GET",
            path="/iam/v1/accessBindings:listAssignableRoles?resourceType=account&resourceId=not-a-valid-id",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('malformed resource_id → 400 (format) or 403 (authz pre-empt)', () => pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([400, 403]));",
                "pm.test('grpc code INVALID_ARGUMENT (3) or PERMISSION_DENIED (7)', () => pm.expect(pm.response.json().code).to.be.oneOf([3, 7]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LAR-NEG-AUTHZ — 1.5-08: caller without grant-authority on accountAId
# (jwtAccountAdminB owns accountBId, not accountAId) → 403.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-LAR-NEG-AUTHZ",
    title="ListAssignableRoles on accountAId by accountB-admin (no grant-authority) → 403 (1.5-08)",
    classes=["NEG", "AUTHZ"],
    priority="P1",
    steps=[
        Step(
            name="lar-authz-deny",
            method="GET",
            path="/iam/v1/accessBindings:listAssignableRoles?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminB",
            test_script=[
                "pm.test('no grant-authority → 403', () => pm.expect(pm.response.code, pm.response.text()).to.equal(403));",
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-CR-NEG-MISSCOPED — 1.5-12 parity: a foreign-account custom role (minted
# in accountBId by accountB-admin) bound on accountAId by accountA-admin →
# Operation.error FAILED_PRECONDITION (9), binding NOT created. List⇔Create parity:
# the same role is NOT in ListAssignableRoles(account/accountAId).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-CR-NEG-MISSCOPED",
    title="Create with foreign-account custom role on accountAId → Operation.error FAILED_PRECONDITION (1.5-12)",
    classes=["NEG", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="mint-foreign-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountBId}}",
                "name": "misscoped_{{runId}}",
                "rules": [{"module": "iam", "resources": ["users"], "verbs": ["read"]}],
            },
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "misOpId"),
                *save_from_response("j.metadata && j.metadata.roleId", "misRoleId"),
            ],
        ),
        Step(
            name="poll-mint-role",
            method="GET",
            path="/operations/{{misOpId}}",
            auth="jwtAccountAdminB",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('foreign role minted', () => pm.expect(j.done && !j.error, JSON.stringify(j)).to.eql(true));",
                "if (j.response && j.response.id) { pm.environment.set('misRoleId', j.response.id); }",
            ],
        ),
        Step(
            name="lar-excludes-foreign",
            method="GET",
            path="/iam/v1/accessBindings:listAssignableRoles?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('foreign role NOT in ListAssignableRoles (parity)', () => {",
                "  const j = pm.response.json();",
                "  const rid = pm.environment.get('misRoleId');",
                "  pm.expect((j.roles || []).some(r => r.roleId === rid), 'foreign role must be absent').to.be.false;",
                "});",
            ],
        ),
        Step(
            name="create-misscoped",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": "{{misRoleId}}",
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "misBindOpId"),
            ],
        ),
        Step(
            name="poll-misscoped-op",
            method="GET",
            path="/operations/{{misBindOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('mis-scoped Create: operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('mis-scoped Create: Operation.error FAILED_PRECONDITION (9)', () => {",
                "  pm.expect(j.error, JSON.stringify(j)).to.exist;",
                "  pm.expect(j.error.code, 'error.code must be FAILED_PRECONDITION (9)').to.eql(9);",
                "  pm.expect(j.error.message, j.error.message).to.include('not assignable');",
                "});",
            ],
        ),
    ],
))


# ===========================================================================
# RBAC rules model: the resource-scoped AccessBinding.target surface is REMOVED:
#
#   POST /iam/v1/accessBindings/{id}:addTargetResources      → 404 (route gone)
#   POST /iam/v1/accessBindings/{id}:removeTargetResources   → 404
#   POST /iam/v1/accessBindings/{id}:replaceTargetSelector   → 404
#   GET  /iam/v1/accessBindings:listGrantableResources       → 404
#   GET  /iam/v1/accessBindings:listByResource               → 404 (renamed
#                                                               → :listByScope)
#
# AccessBinding.target / .targetRef are gone from Get/List responses, and
# CreateAccessBindingRequest no longer reads target/selector/targetRef — a body
# carrying those keys has them ignored as unknown fields; the binding is created
# from subjects[]/roleId/scope (scopeRef | resourceType+resourceId) only.
#
# Black-box through api-gateway. These cases pin the removed-route 404s, the
# unknown-field-ignored Create, and the rename that supersede the deleted
# resource-scoped surface. Do not weaken assertions.
# ===========================================================================


# ---------------------------------------------------------------------------
# IAM-ACB-F50-ROUTES-REMOVED — the four resource-scoped REST verbs and the
# legacy :listByResource name are gone, while the renamed :listByScope serves the
# same scope-list semantics (200 for a scope the caller can read).
#
# A removed RPC is REJECTED before routing by the api-gateway authz-interceptor's
# permission-catalog gate (fail-closed, defense-in-depth): the F clean-cut dropped
# the RPC from the proto, the REST route-table, the allowlist AND the permission
# catalog (verified: kacho-api-gateway internal/middleware/embed/permission_catalog
# .json + rest_route_table_gen.go + allowlist/list.go carry NO entry for any of the
# five removed methods, only the renamed :listByScope). The authz interceptor runs
# the catalog lookup FIRST, finds no entry → denies with PERMISSION_DENIED (gRPC
# code 7 / HTTP 403) carrying a `google.rpc.PreconditionFailure` violation of type
# `authz.catalog` ("catalog: no entry for method"). The request never reaches the
# grpc-gateway mux, so a 501/UNIMPLEMENTED is never produced — the catalog-miss
# fail-closed 403 is the canonical "this method is not callable" outcome for a
# fully-removed RPC (a removed-but-still-catalogued route would instead be 501;
# absence from the catalog is the stronger removal proof). NOTE: a prior revision
# expected 501/code 12 — that was a test-design error about WHICH layer answers an
# absent method first (catalog-gate, not the mux), never a product defect. The
# product is correct fail-closed; corrected here to 403 / code 7 / authz.catalog.
#
# The trailing list-by-scope-ok sub-step uses the renamed :listByScope route:
# the catalog + route-table carry :listByScope, so a scope the caller can read
# returns 200.
# ---------------------------------------------------------------------------


def assert_route_removed(label):
    # A fully-removed RPC has NO permission-catalog entry, so the api-gateway authz
    # interceptor fail-closes BEFORE routing: PERMISSION_DENIED (HTTP 403 / gRPC
    # code 7) with an `authz.catalog` PreconditionFailure ("catalog: no entry for
    # method"). One thought per pm.test(): status, code, then the catalog-miss
    # signature that proves the denial is the missing-catalog path (not a generic
    # authz deny on an existing method).
    return [
        f"pm.test('{label} route removed → 403 (catalog-miss fail-closed, not callable)', () => pm.expect(pm.response.code, pm.response.text()).to.eql(403));",
        "let _rj; try { _rj = pm.response.json(); } catch(e) { _rj = null; }",
        f"pm.test('{label} route removed → grpc code 7 (PERMISSION_DENIED)', () => pm.expect(_rj && _rj.code, JSON.stringify(_rj)).to.eql(7));",
        f"pm.test('{label} route removed → authz.catalog miss in details', () => {{",
        "  const det = (_rj && _rj.details) || [];",
        "  const blob = JSON.stringify(det);",
        "  pm.expect(blob, blob).to.include('catalog');",
        "});",
    ]


CASES.append(Case(
    id="IAM-ACB-F50-ROUTES-REMOVED",
    title="removed verbs (:add/removeTargetResources, :replaceTargetSelector, :listGrantableResources) + legacy :listByResource → 403 catalog-miss (fail-closed, not callable); :listByScope → 200",
    classes=["NEG", "CONF", "CLEANCUT"],
    priority="P0",
    steps=[
        # verifies (listGrantableResources route removed)
        Step(
            name="list-grantable-removed",
            method="GET",
            path="/iam/v1/accessBindings:listGrantableResources?scopeType=account&scopeId={{accountAId}}&objectType=iam.project",
            auth="jwtAccountAdminA",
            test_script=assert_route_removed("listGrantableResources"),
        ),
        # verifies (addTargetResources route removed)
        Step(
            name="add-target-removed",
            method="POST",
            path="/iam/v1/accessBindings/{{crudAcbId}}:addTargetResources",
            body={"target": {"resources": {"resources": [{"type": "compute.instance", "id": "inst-x"}]}}},
            auth="jwtAccountAdminA",
            test_script=assert_route_removed("addTargetResources"),
        ),
        # verifies (replaceTargetSelector route removed)
        Step(
            name="replace-selector-removed",
            method="POST",
            path="/iam/v1/accessBindings/{{crudAcbId}}:replaceTargetSelector",
            body={"selector": {"types": ["compute.instance"], "matchLabels": {"env": "prod"}}},
            auth="jwtAccountAdminA",
            test_script=assert_route_removed("replaceTargetSelector"),
        ),
        # verifies (removeTargetResources route removed)
        Step(
            name="remove-target-removed",
            method="POST",
            path="/iam/v1/accessBindings/{{crudAcbId}}:removeTargetResources",
            body={"target": {"resources": {"resources": [{"type": "compute.instance", "id": "inst-x"}]}}},
            auth="jwtAccountAdminA",
            test_script=assert_route_removed("removeTargetResources"),
        ),
        # verifies (legacy :listByResource name removed)
        Step(
            name="list-by-resource-legacy-removed",
            method="GET",
            path="/iam/v1/accessBindings:listByResource?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=assert_route_removed("legacy :listByResource"),
        ),
        # verifies (renamed :listByScope serves the same semantics → 200)
        Step(
            name="list-by-scope-ok",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('listByScope (renamed) returns the accessBindings array', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.accessBindings, JSON.stringify(j)).to.be.an('array');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-F51-TARGET-IGNORED — Create with a body that ALSO carries the
# removed `target` / `selector` keys (now unknown fields) → binding is created
# from subjects/roleId/scope only (200, iop Operation done); Get(binding) carries
# NO `target` and NO `selector`/`targetRef` field.
# Self-contained: synthetic runId-suffixed subject + teardown so re-runs don't
# trip the strict-create active-grant UNIQUE.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-F51-TARGET-IGNORED",
    title="Create with unknown target/selector keys → created from subjects/roleId/scope only; Get has no target/selector/targetRef",
    classes=["CRUD", "CONF", "CLEANCUT"],
    priority="P0",
    steps=[
        # verifies (unknown target/selector keys ignored on Create)
        # subject must be a REAL user (migration 0049 subject_ref_exists) — mint one.
        *mint_user("f51UserId", "usr-f51"),
        Step(
            name="create-with-unknown-target-keys",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{f51UserId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
                # Removed surface — these keys are now UNKNOWN and must be ignored.
                "target": {"resources": {"resources": [
                    {"type": "compute.instance", "id": "inst-f51-{{runId}}"},
                ]}},
                "selector": {"types": ["compute.instance"], "matchLabels": {"env": "prod"}},
                "targetRef": {"byName": {"resources": [
                    {"type": "compute.instance", "id": "inst-f51-{{runId}}"},
                ]}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "f51OpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "f51AcbId"),
            ],
        ),
        Step(
            name="poll-f51-op",
            method="GET",
            path="/operations/{{f51OpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('Create with unknown target/selector keys: operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('Create succeeded (no error — unknown fields ignored)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('f51AcbId')) {",
                "  pm.environment.set('f51AcbId', j.response.id);",
                "}",
            ],
        ),
        # Read-after-write on the freshly-created binding OBJECT — same grant→access
        # propagation window as IAM-ACB-CR-CRUD-OK/get-confirms: the owner's
        # per-object viewer access on the new iam_access_binding materializes a beat
        # after Operation→done, so an IMMEDIATE single-shot GET flakes 403 under
        # full-pipeline CI load. Poll past the transient 403 to the converged 200,
        # then run the surface assertions on the TERMINAL response (a genuine
        # never-converging deny still fails at the cap — not masked).
        poll_request_until_status(
            name="get-f51-no-target",
            method="GET",
            path="/iam/v1/accessBindings/{{f51AcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),  # BUG-2 hide-existence: the v_get propagation deny is 404 (not 403); binding row exists, poll past both to 200.
            test_script=[
                *assert_status(200),
                "pm.test('binding created from subjects/roleId/scope', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.subjectType).to.eql('user');",
                f"  pm.expect(j.roleId).to.eql('{ROLE_VIEW}');",
                "  pm.expect(j.resourceType).to.eql('account');",
                "  pm.expect(j.resourceId).to.eql(pm.environment.get('accountAId'));",
                "});",
                "pm.test('response has NO target field (removed surface)', () => {",
                "  pm.expect(pm.response.json().target, JSON.stringify(pm.response.json())).to.be.undefined;",
                "});",
                "pm.test('response has NO selector field (removed surface)', () => {",
                "  pm.expect(pm.response.json().selector, JSON.stringify(pm.response.json())).to.be.undefined;",
                "});",
                "pm.test('response has NO targetRef field (removed surface)', () => {",
                "  pm.expect(pm.response.json().targetRef, JSON.stringify(pm.response.json())).to.be.undefined;",
                "});",
            ],
        ),
        _f51_teardown(),
    ],
))





# ---------------------------------------------------------------------------
# Deletion protection.
#
#   IAM-ACB-DP-NEG-DELETE-PROTECTED — Create a binding with
#     deletionProtection=true, then Delete → Operation.error FAILED_PRECONDITION
#     (code 9), verbatim "deletion_protection enabled".
#   IAM-ACB-DP-CRUD-CLEAR-THEN-DELETE — Create protected → Update(update_mask=
#     ["deletionProtection"], false) clears it → Delete succeeds.
#
# Both create on account/accountAId with subject userNOBId, role ROLE_VIEW, by
# the account admin (jwtAccountAdminA passes requireGrantAuthority).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-DP-NEG-DELETE-PROTECTED",
    title="Delete a deletion_protection=true binding → FAILED_PRECONDITION",
    classes=["NEG"],
    priority="P0",
    steps=[
        Step(
            name="create-protected",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
                "deletionProtection": True,
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "dpAcbId"),
            ],
        ),
        poll_operation_until_done(),
        # The protected flag is visible on read. Read-after-write on the fresh binding
        # OBJECT — owner per-object access materializes a beat after Operation→done;
        # poll past the transient 403/404 to the converged 200 (the read-deny
        # surfaces as hide-existence 404 NOT_FOUND, not 403, during the window — both
        # are retried; never-converge still fails at the cap).
        poll_request_until_status(
            name="get-shows-protected",
            method="GET",
            path="/iam/v1/accessBindings/{{dpAcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),
            test_script=[
                *assert_status(200),
                "pm.test('deletionProtection=true on read', () => pm.expect(pm.response.json().deletionProtection).to.eql(true));",
            ],
        ),
        # Delete is rejected SYNC (FAILED_PRECONDITION) — the protected guard
        # returns the gRPC error directly, not inside an Operation.
        Step(
            name="delete-blocked",
            method="DELETE",
            path="/iam/v1/accessBindings/{{dpAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('Delete blocked → 400 FAILED_PRECONDITION', () => pm.expect(pm.response.code).to.be.oneOf([400, 409]));",
                "const j = pm.response.json();",
                "pm.test('error text mentions deletion_protection', () => pm.expect(JSON.stringify(j).toLowerCase()).to.include('deletion_protection'));",
            ],
        ),
        # Teardown: clear protection then delete so re-runs are clean.
        Step(
            name="teardown-clear",
            method="PATCH",
            path="/iam/v1/accessBindings/{{dpAcbId}}",
            body={"updateMask": "deletionProtection", "deletionProtection": False},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('clear status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
                "const j = pm.response.json(); if (j && j.id) pm.environment.set('opId', j.id);",
            ],
        ),
        _delete_acb_teardown("teardown-dp-neg", "dpAcbId"),
    ],
))


CASES.append(Case(
    id="IAM-ACB-DP-CRUD-CLEAR-THEN-DELETE",
    title="Update clears deletion_protection → Delete then succeeds",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="create-protected",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
                "deletionProtection": True,
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "dp2AcbId"),
            ],
        ),
        poll_operation_until_done(),
        # Update(update_mask=["deletionProtection"], false) → Operation done.
        # AccessBindingService.Update gates on `v_update` on the iam_access_binding
        # object (Design-B verb-bearing). The admin's v_update on the FRESH binding
        # forward-materializes a beat after create→Operation-done (the owner/admin
        # `*.*` content-mat propagation window — same lag the sibling
        # get-shows-* steps poll past). A single-shot PATCH here therefore flakes
        # with a transient 403 under full-pipeline load; poll the SAME PATCH past the
        # 403 propagation window to the converged 200 (a genuine never-converge deny
        # still surfaces at the cap — not masked). retry_on 403-only: the binding row
        # exists (404 would be a real anomaly).
        poll_request_until_status(
            name="update-clear",
            method="PATCH",
            path="/iam/v1/accessBindings/{{dp2AcbId}}",
            body={"updateMask": "deletionProtection", "deletionProtection": False},
            auth="jwtAccountAdminA",
            retry_on=(403,),
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Read-after-write on the binding OBJECT (post-clear); poll past any transient
        # 403 propagation window to the converged 200 before asserting.
        poll_request_until_status(
            name="get-shows-cleared",
            method="GET",
            path="/iam/v1/accessBindings/{{dp2AcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),
            test_script=[
                *assert_status(200),
                "pm.test('deletionProtection=false after clear', () => pm.expect(pm.response.json().deletionProtection).to.eql(false));",
            ],
        ),
        # Now Delete succeeds (returns an Operation that completes without error).
        # Delete gates on `v_delete` on the iam_access_binding; same forward-mat
        # propagation window as update-clear → poll the DELETE past a transient 403.
        poll_request_until_status(
            name="delete-ok",
            method="DELETE",
            path="/iam/v1/accessBindings/{{dp2AcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403,),
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
# IAM-ACB-OWNER-P8-NOACCESS-LOSS — owner-binding present + deletion-protected.
#
# Black-box no-access-loss invariant: every account has an ACTIVE owner-role
# binding for its owner (created by Account.Create auto-bind, and by the
# migrate-backfill on accounts that pre-dated it). It is deletion_protected, so a
# Delete on it is refused FAILED_PRECONDITION until the protection is cleared via
# Update. This is the tenant-observable guarantee — no operator loses owner access
# in the contract window.
#
#   happy:    listBySubject(user, owner) on accountAId → an owner-role binding
#             with deletionProtection=true is present.
#   negative: Delete that owner-binding → SYNC FAILED_PRECONDITION (the protected
#             guard returns the gRPC error directly, not an Operation), verbatim
#             mentions deletion_protection.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-OWNER-P8-NOACCESS-LOSS",
    title="owner-binding present + deletion-protected on an account (no-access-loss)",
    classes=["CONF", "IDM", "NEG"],
    priority="P1",
    steps=[
        # happy: the owner (jwtAccountAdminA / userAAAId) holds an ACTIVE owner-role
        # binding on accountAId. ListBySubject(user, self) returns the owner's
        # bindings; one of them is role=owner on resource account/accountAId with
        # deletionProtection=true.
        Step(
            name="listbysubject-finds-owner-binding",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userAAAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('an owner-role binding on accountAId is present and deletion-protected (no-access-loss)', () => {",
                "  const j = pm.response.json();",
                "  const list = j.accessBindings || j.bindings || [];",
                "  const owner = list.find(b =>",
                "    b.roleId === '" + ROLE_OWNER + "' &&",
                "    b.resourceType === 'account' &&",
                "    b.resourceId === pm.environment.get('accountAId'));",
                "  pm.expect(owner, 'owner-binding present on accountAId').to.not.be.undefined;",
                "  pm.expect(owner.deletionProtection, 'owner-binding deletion_protected').to.eql(true);",
                "  pm.environment.set('ownerAcbId', owner.id);",
                "});",
            ],
        ),
        # negative: Delete the deletion-protected owner-binding is rejected SYNC
        # (FAILED_PRECONDITION) — the protected guard returns the gRPC error
        # directly, not inside an Operation.
        Step(
            name="delete-owner-binding-refused",
            method="DELETE",
            path="/iam/v1/accessBindings/{{ownerAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('Delete owner-binding blocked → 400/409 FAILED_PRECONDITION', () => pm.expect(pm.response.code).to.be.oneOf([400, 409]));",
                "pm.test('error text mentions deletion_protection', () => pm.expect(JSON.stringify(pm.response.json()).toLowerCase()).to.include('deletion_protection'));",
            ],
        ),
        Step(
            name="owner-binding-still-present",
            method="GET",
            path="/iam/v1/accessBindings/{{ownerAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('owner-binding survives the refused Delete (deletion_protection)', () => {",
                "  pm.expect(pm.response.json().deletionProtection).to.eql(true);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# AccessBinding own-resource `labels`.
#
# AccessBinding.labels (own-resource tenant-facing метки самого binding) делают
# binding label-selectable (catalog-видимость через viewer ∪ v_list). Mutable
# set расширен до {deletionProtection, labels} — любой иной mask путь
# (roleId/subject/scope/resource*) → INVALID_ARGUMENT.
#
# Uses a DISTINCT 5-tuple (ROLE_ADMIN on account/accountAId) so the strict active-
# grant UNIQUE (migration 0003) does not collide with the ROLE_VIEW CRUD binding.
#
# verifies: Create+Update own-resource labels (updateMask=labels) round-trip;
#   a roleId in update_mask → INVALID_ARGUMENT (immutable set not weakened).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACB-T33-LABELS-OK",
    title="Create AccessBinding with labels + Update labels (updateMask=labels) → Operation done, Get confirms",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Pre-clean: revoke any stale active (userNOBId, ROLE_ADMIN, account/accountAId)
        # binding so the strict active-grant UNIQUE (migration 0003) does not collide
        # with t33-create. Discovery MUST use an authorized read: ListByAccount on
        # accountAId as the account owner (jwtAccountAdminA) returns EVERY binding in the
        # account scope (owner/admin floor) — unlike :listBySubject?subjectId=userNOBId,
        # which is a cross-user query (the owner is NOT the subject) and is correctly
        # denied 403 (only a subject may list their own bindings). The discovery read
        # ALWAYS runs; when no stale ROLE_ADMIN binding exists it jumps straight to
        # t33-create-with-labels so the DELETE step never fires with an empty id.
        Step(
            name="t33-pre-clean-list",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean list status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "pm.environment.unset('t33StaleAcbId');",
                "if (pm.response.code === 200) {",
                "  const j = pm.response.json();",
                "  const rows = (j.accessBindings || j.bindings || []);",
                "  const m = rows.find(b => b.roleId === '" + ROLE_ADMIN + "' && b.resourceType === 'account' && b.resourceId === pm.environment.get('accountAId') && (!b.status || b.status === 'ACTIVE' || b.status === 'STATUS_UNSPECIFIED'));",
                "  if (m && m.id) { pm.environment.set('t33StaleAcbId', m.id); }",
                "}",
                # No stale binding (clean DB) → skip the revoke and go straight to create.
                "if (!pm.environment.get('t33StaleAcbId')) { pm.execution.setNextRequest('t33-create-with-labels'); }",
            ],
        ),
        Step(
            # Reached ONLY when t33StaleAcbId is set (a real, well-formed binding id).
            name="t33-pre-clean-delete",
            method="DELETE",
            path="/iam/v1/accessBindings/{{t33StaleAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean delete accepted or already gone', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
                "const j = pm.response.json();",
                # A 200 returns the delete Operation → poll it done before create (the
                # active-grant UNIQUE keys on revoked_at IS NULL, set in the worker); a
                # 404 means it is already gone → skip the poll and create directly.
                "if (pm.response.code === 200 && j && j.id) { pm.environment.set('t33PreCleanOpId', j.id); }",
                "else { pm.environment.unset('t33PreCleanOpId'); pm.execution.setNextRequest('t33-create-with-labels'); }",
            ],
        ),
        Step(
            name="t33-pre-clean-poll",
            method="GET",
            path="/operations/{{t33PreCleanOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('pre-clean delete done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
        Step(
            name="t33-create-with-labels",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_ADMIN,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
                "labels": {"stage": "prod"},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "t33AcbId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="t33-capture-id",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (j.response && j.response.id && !pm.environment.get('t33AcbId')) {",
                "  pm.environment.set('t33AcbId', j.response.id);",
                "}",
            ],
        ),
        # AccessBindingService.Update gates on `v_update` on the iam_access_binding
        # object (Design-B verb-bearing). The admin's v_update on the FRESH binding
        # forward-materializes a beat after create→Operation-done (the owner/admin
        # `*.*` content-mat propagation window — same lag the sibling
        # deletion-protection update-clear step polls past). A single-shot PATCH here
        # therefore flakes with a transient 403 under full-pipeline load; poll the SAME
        # PATCH past the 403 propagation window to the converged 200 (a genuine
        # never-converge deny still surfaces at the cap — not masked). retry_on 403-only:
        # the binding row exists (404 would be a real anomaly).
        poll_request_until_status(
            name="t33-update-labels",
            method="PATCH",
            path="/iam/v1/accessBindings/{{t33AcbId}}",
            body={"labels": {"stage": "staging", "team": "payments"}, "updateMask": "labels"},
            auth="jwtAccountAdminA",
            retry_on=(403,),
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        poll_request_until_status(
            name="t33-get-confirms-labels",
            method="GET",
            path="/iam/v1/accessBindings/{{t33AcbId}}",
            auth="jwtAccountAdminA",
            retry_on=(403, 404),
            test_script=[
                *assert_status(200),
                "pm.test('AccessBinding.labels updated (own-resource)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.labels, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(j.labels.stage).to.eql('staging');",
                "  pm.expect(j.labels.team).to.eql('payments');",
                "});",
            ],
        ),
        # Teardown: revoke the binding so reruns start clean.
        Step(
            name="t33-teardown",
            method="DELETE",
            path="/iam/v1/accessBindings/{{t33AcbId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('t33AcbId')) { pm.execution.setNextRequest(null); }",
            ],
            test_script=[
                "pm.test('teardown delete accepted', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACB-UP-T33-NEG-ROLEID-IMMUTABLE",
    title="Update AccessBinding with roleId in update_mask → 400 INVALID_ARGUMENT (immutable set not weakened)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        # Caller = owner: the owner attempts Update(acb-X) with
        # update_mask=["roleId"] and must reach the IAM update_mask validation →
        # INVALID_ARGUMENT "role_id is immutable after AccessBinding.Create". The
        # api-gateway gates `v_update` on the iam_access_binding object FIRST (Design-B
        # verb-bearing), and the owner's v_update is materialized SYNCHRONOUSLY only on
        # a binding the owner itself created (AccessBinding.Create → ReconcileObject of
        # the new object). The owner does NOT hold v_update on an arbitrary pre-existing
        # binding in the account (it gets v_get/viewer there, but not v_update), so a
        # PATCH against a foreign binding stays 403 forever — the gate denies before the
        # request reaches the validation. Therefore this case creates its OWN fresh
        # binding (distinct 5-tuple userINVId/ROLE_VIEW so the strict active-grant UNIQUE
        # — migration 0003 — does not collide with the userNOBId CRUD binding), then runs
        # the immutable-roleId PATCH on THAT binding, where v_update is materialized.

        # Pre-clean: revoke any stale active (userINVId, ROLE_VIEW, account/accountAId)
        # binding so the strict active-grant UNIQUE does not collide with imm-create.
        # ListByAccount as the owner returns every binding in the account scope.
        Step(
            name="t33imm-pre-clean-list",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean list status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "pm.environment.unset('t33immStaleAcbId');",
                "if (pm.response.code === 200) {",
                "  const j = pm.response.json();",
                "  const rows = (j.accessBindings || j.bindings || []);",
                "  const m = rows.find(b => b.roleId === '" + ROLE_VIEW + "' && b.resourceType === 'account' && b.resourceId === pm.environment.get('accountAId') && b.subjectId === pm.environment.get('userINVId') && (!b.status || b.status === 'ACTIVE' || b.status === 'STATUS_UNSPECIFIED'));",
                "  if (m && m.id) { pm.environment.set('t33immStaleAcbId', m.id); }",
                "}",
                "if (!pm.environment.get('t33immStaleAcbId')) { pm.execution.setNextRequest('t33imm-create'); }",
            ],
        ),
        Step(
            name="t33imm-pre-clean-delete",
            method="DELETE",
            path="/iam/v1/accessBindings/{{t33immStaleAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean delete accepted or already gone', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 200 && j && j.id) { pm.environment.set('t33immPreCleanOpId', j.id); }",
                "else { pm.environment.unset('t33immPreCleanOpId'); pm.execution.setNextRequest('t33imm-create'); }",
            ],
        ),
        Step(
            name="t33imm-pre-clean-poll",
            method="GET",
            path="/operations/{{t33immPreCleanOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('pre-clean delete done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
        Step(
            name="t33imm-create",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userINVId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "t33immAcbId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="t33imm-capture-id",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (j.response && j.response.id && !pm.environment.get('t33immAcbId')) {",
                "  pm.environment.set('t33immAcbId', j.response.id);",
                "}",
            ],
        ),
        # The owner's v_update on the fresh binding forward-materializes a beat after
        # create→Operation-done (propagation window) — same lag the sibling
        # deletion-protection update-clear step polls past. Poll the SAME PATCH past the
        # transient 403 until the request lands in IAM, then assert the TERMINAL is the
        # validation error: 400 / code 3 with the role_id-immutable text (the immutable
        # reject is the real, stable terminal; the gate convergence is timing, not a
        # hole). retry_on 403-only: the binding row exists (404 would be a real anomaly).
        poll_request_until_status(
            name="t33-update-immutable-field",
            method="PATCH",
            path="/iam/v1/accessBindings/{{t33immAcbId}}",
            body={"roleId": ROLE_ADMIN, "updateMask": "roleId"},
            auth="jwtAccountAdminA",
            retry_on=(403,),
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('error text mentions role_id immutable', () => pm.expect(JSON.stringify(pm.response.json()).toLowerCase()).to.include('immutable'));",
            ],
        ),
        # Teardown: revoke the fresh binding so reruns start clean.
        Step(
            name="t33imm-teardown",
            method="DELETE",
            path="/iam/v1/accessBindings/{{t33immAcbId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('t33immAcbId')) { pm.execution.setNextRequest(null); }",
            ],
            test_script=[
                "pm.test('teardown delete accepted', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
            ],
        ),
    ],
))
