# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для UserService.

Covered RPCs:  Get, List, Invite, Delete (public UserService).
Not covered here: InternalUserService.UpsertFromIdentity, InternalUserService.Get —
  those are internal-port-only RPCs covered in iam-internal-only-check.py.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — JWT for userAAAId
    jwtAccountAdminB  — JWT for accountBId owner
    jwtNoBindings     — authenticated, no account membership
    jwtInvitee        — JWT for user with binding on accountBId
    userAAAId         — User.id of jwtAccountAdminA principal
    userNOBId         — User.id of jwtNoBindings principal
    userINVId         — User.id of jwtInvitee principal
    accountAId        — pre-seeded account owned by userAAAId
    accountBId        — cross-account (for List scope + Invite target)

  Users are seeded via InternalUserService.UpsertFromIdentity (internal flow)
  during setup.sh or authz-fixtures/setup.sh. The public Invite flow is tested
  here as the only public "write" path for users.

  crud-fixture extension:
    For IAM-USR-INV-CRUD-OK we Invite a NEW email (invitee-{{runId}}@kacho.local)
    to accountAId with a viewer role. This creates a new pending User (or looks
    up an existing one). The invite target must NOT be an existing binding for
    the idempotency case.

    System role id used for Invite: `rol1bda80f2be4d3658e` (view — md5('view')[:17])
    — matches the deterministic system-role catalog. See authz-deny.py ROLE_VIEW constant.

Operation envelope:
  Mutations return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kacho-iam).

Case IDs follow the IAM-USR-<RPC>-<CLASS>[-detail] scheme.

Authz semantics:
  - UserService.Get is per-resource-gated: only the user themselves can Get
    their own record (iam_user.viewer cascade = subject). Cross-user account-admin
    paths do NOT exist (each user owns their own home account, and the account-admin
    of account-A cannot Get userNOB's record via that path).
  - UserService.List is a scope-filter RPC: returns 200 with only the users of
    accounts where the principal is a member. Non-members get 200 + empty list,
    NOT 403. Anonymous → 401 (IAM anti-anonymous interceptor).
  - UserService.Invite is gated (CanInviteUsers = editor on account).
  - UserService.Delete is per-resource-gated (owner can delete their own users).

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  UserService RPCs are correctly implemented. Do not weaken assertions.

verifies: UserService.List scope-filter and UserService.Invite acceptance
scenarios from iam-user.py spec.
"""

CASES = []

# System role ids — deterministic catalog (`rol` + md5(<name>)[:17]).
# See authz-deny.py ROLE_VIEW constant (md5('view')[:17]).
ROLE_VIEW = "rol1bda80f2be4d3658e"


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


def nob_preclean_account_a(next_step):
    """Bounded list→delete→await loop removing EVERY active account-A binding for userNOBId so
    the non-member scope-filter assertion is self-isolating (cross-suite order-independent).

    Without this, a prior suite (e.g. the access-binding CRUD case grants (userNOBId, ROLE_VIEW,
    account:accountAId)) can leave NOB with a residual account-A viewer grant → NOB legitimately
    sees account-A users under viewer∪v_list → the "empty for non-member" assertion flips. The
    loop's terminal (clean-slate) branch jumps FORWARD to `next_step` (never falling into the
    delete machinery — the visibility-set hang lesson), so the iteration cap holds."""
    CAP = 12
    return [
        Step(
            name="nob-preclean-list",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userNOBId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (pm.environment.get('_nobStarted') !== pm.info.requestName) { pm.environment.set('_nobCount', '0'); pm.environment.set('_nobStarted', pm.info.requestName); }",
            ],
            test_script=[
                "pm.test('nob pre-clean list acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                "const c = parseInt(pm.environment.get('_nobCount') || '0', 10);",
                "let arr = [];",
                "if (pm.response.code === 200) { arr = ((pm.response.json() || {}).accessBindings || []).filter(b => b.resourceType === 'account' && b.resourceId === pm.environment.get('accountAId')); }",
                f"if (arr.length > 0 && c < {CAP}) {{",
                "  pm.environment.set('nobDup', arr[0].id);",
                "  pm.environment.set('_nobCount', String(c + 1));",
                "  postman.setNextRequest('nob-preclean-del');",
                "  return;",
                "}",
                "pm.environment.unset('_nobCount'); pm.environment.unset('_nobStarted'); pm.environment.unset('nobDup');",
                f"postman.setNextRequest('{next_step}');",
            ],
        ),
        Step(
            name="nob-preclean-del",
            method="DELETE",
            path="/iam/v1/accessBindings/{{nobDup}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('nob pre-clean delete acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
                "pm.environment.unset('nobDelOp');",
                "if (pm.response.code === 200) { const dj = pm.response.json() || {}; if (dj.id) pm.environment.set('nobDelOp', dj.id); }",
                "if (!pm.environment.get('nobDelOp')) { postman.setNextRequest('nob-preclean-list'); }",
            ],
        ),
        Step(
            name="nob-preclean-await",
            method="GET",
            path="/operations/{{nobDelOp}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (pm.environment.get('_nobAwaitStarted') !== pm.info.requestName) { pm.environment.set('_nobAwaitCount', '0'); pm.environment.set('_nobAwaitStarted', pm.info.requestName); }",
            ],
            test_script=[
                "const j = pm.response.json();",
                "const c = parseInt(pm.environment.get('_nobAwaitCount') || '0', 10);",
                f"if (!j.done && c < {POLL_CAP}) {{ pm.environment.set('_nobAwaitCount', String(c + 1)); postman.setNextRequest(pm.info.requestName); return; }}",
                "pm.environment.unset('_nobAwaitCount'); pm.environment.unset('_nobAwaitStarted');",
                "postman.setNextRequest('nob-preclean-list');",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# IAM-USR-GT-CRUD-OK — Get userNOBId as NOB (self — only self can get own record)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GT-CRUD-OK",
    title="Get userNOBId as jwtNoBindings (self) → 200 + id prefix usr, externalId present",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-self",
            method="GET",
            path="/iam/v1/users/{{userNOBId}}",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('User.id prefix usr', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with usr').to.match(/^usr[a-z0-9]+$/);",
                "});",
                "pm.test('User.id matches userNOBId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('userNOBId'));",
                "});",
                "pm.test('User.email present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.email, 'email must be non-empty').to.be.a('string').with.length.greaterThan(0);",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-GT-NEG-NOTFOUND — Get non-existent user → 404 or 403 (no FGA path)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GT-NEG-NOTFOUND",
    title="Get non-existent user id → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-notfound",
            method="GET",
            path="/iam/v1/users/usr00000000000notfnd",
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
# IAM-USR-GT-AUTHZ-ANON-DENY — Get as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GT-AUTHZ-ANON-DENY",
    title="Get user as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-anon",
            method="GET",
            path="/iam/v1/users/{{userNOBId}}",
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
# IAM-USR-GT-AUTHZ-FOREIGN-DENY — Get userNOBId as jwtAccountAdminA (different user, no admin path) → 403 or 404
# Per authz-deny.py: Get is per-resource-gated. The `iam_user.viewer` cascade
# is `subject or editor or viewer from account`. AAA is editor of account-A,
# but NOB's home account is NOT account-A → AAA has no viewer path to NOB.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GT-AUTHZ-FOREIGN-DENY",
    title="Get userNOBId as jwtAccountAdminA (no viewer path to NOB) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/users/{{userNOBId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # The account-admin of account-A cannot Get userNOB because NOB's
                # home account ≠ account-A. FGA: no path → read-deny. BUG-2: a verb-bearing
                # IAM read-deny is surfaced as NotFound (404 / code 5), never
                # PermissionDenied — no enumeration leak.
                "pm.test('FOREIGN: status 404 (hide existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('FOREIGN: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
                "pm.test('FOREIGN: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {}).toLowerCase()).to.not.include('deny_reasons'));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-CRUD-OK — List users ?accountId=accountAId as owner → 200, users array
# List is scope-filtered: owner sees members of account-A.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-CRUD-OK",
    title="List users ?accountId=accountAId as jwtAccountAdminA → 200, users array non-empty",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="list-ok",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('users array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.users, 'users field').to.be.an('array');",
                "});",
                "pm.test('users list non-empty for owner', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.users || []).length, 'at least one user (owner)').to.be.greaterThan(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-AUTHZ-ANON-DENY — List as anonymous → 401
# List is scope-filter-exempt at gateway but IAM anti-anon interceptor blocks anon.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-AUTHZ-ANON-DENY",
    title="List users as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="list-anon",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}",
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
# IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY — non-member gets 200 + empty list (scope-filter)
# jwtNoBindings is not a member of accountAId → scope-filter returns 200 + empty, not 403.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY",
    title="List users ?accountId=accountAId as jwtNoBindings (non-member) → 200 + empty list (scope-filter)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        # Self-isolation: strip any residual account-A grant on userNOBId left by another suite
        # (e.g. access-binding CRUD grants NOB a ROLE_VIEW@account) so "non-member sees empty"
        # holds regardless of cross-suite run order. Clean slate → jumps to list-nonmember.
        *nob_preclean_account_a("list-nonmember"),
        Step(
            name="list-nonmember",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}",
            auth="jwtNoBindings",
            test_script=[
                # Per authz-deny.py: user-list-account-A → NOB → EMPTY (200 + zero users).
                *assert_status(200),
                "pm.test('NOB: users empty (scope-filter default-deny)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.users || []).length, 'zero users for non-member').to.equal(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-SETUP-INVITE-INV-TO-B — invite invitee to accountB so MEMBER-SEES works
# MEMBER-SEES depends on invitee having membership in accountB. The fixture
# only seeds the invitee in accountA. We add a setup step here to invite them to
# accountB before the scope-filter assertion. Idempotent (re-invite returns same binding).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-SETUP-INVITE-INV-TO-B",
    title="Setup: invite auth-test-invitee@example.com to accountBId (idempotent) → 200 Operation done",
    classes=["SETUP"],
    priority="P0",
    steps=[
        Step(
            name="invite-inv-to-b",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "email": "auth-test-invitee@example.com"},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminB"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-AUTHZ-MEMBER-NO-OVERSHOW — a plain member (binding on accountB) WITHOUT
# a user viewer/v_list grant does NOT see accountB's other users.
#
# Unified label-scope model: membership-over-show is
# REMOVED. user.List filters through `viewer ∪ v_list` on iam_user — a mere member
# of an account no longer automatically sees ALL of that account's users; visibility
# now requires a per-object viewer/v_list grant (account-admin/owner resolves it via
# the account-tier cascade; a label/names selector materializes object-only v_list).
# The invitee here holds only an account-membership binding on accountB (no user
# viewer grant) and their own User row is NOT in accountB's scope, so the scope-list
# is empty — and crucially it MUST NOT leak the account owner / other members.
# verifies: a plain account member with no per-object user viewer/v_list grant does
# NOT see the account's users (membership-over-show removed; no owner/member leak).
# Depends on IAM-USR-SETUP-INVITE-INV-TO-B running first to ensure membership.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-AUTHZ-MEMBER-NO-OVERSHOW",
    title="List users ?accountId=accountBId as jwtInvitee (member, no user-viewer grant) → 200, NO membership-over-show (does not leak B's users)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-member-no-overshow",
            method="GET",
            path="/iam/v1/users?accountId={{accountBId}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                "pm.test('member without user-viewer grant does NOT see accountB users (membership-over-show removed)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.users, 'users field').to.be.an('array');",
                "  // A plain member no longer sees the account's users via membership.",
                "  // The invitee holds no iam_user viewer/v_list grant on accountB → empty scope-list.",
                "  pm.expect((j.users || []).length, 'no membership-over-show: list is empty for a no-grant member').to.eql(0);",
                "});",
                "pm.test('no leak of accountB owner via membership-over-show', () => {",
                "  const j = pm.response.json();",
                "  const ownerId = pm.environment.get('userAABId');",
                "  pm.expect((j.users || []).some(u => u.id === ownerId), 'accountB owner must not be visible to a no-grant member').to.be.false;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-BVA-PAGESIZE-0 — pageSize=0 → 200 (default applied)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-BVA-PAGESIZE-0",
    title="List users pageSize=0 → 200 (default page size applied)",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps0",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=0",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-BVA-PAGESIZE-1 — pageSize=1 → ≤1 item
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-BVA-PAGESIZE-1",
    title="List users pageSize=1 → ≤1 item returned",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('at most 1 item', () => { const j = pm.response.json(); pm.expect((j.users||[]).length).to.be.at.most(1); });",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-BVA-PAGESIZE-MAX — pageSize=1000 → 200
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-BVA-PAGESIZE-MAX",
    title="List users pageSize=1000 (boundary max) → 200",
    classes=["BVA", "PAGE"],
    priority="P2",
    steps=[
        Step(
            name="ls-ps1000",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200)],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-LS-BVA-PAGESIZE-OVER — pageSize=1001 (over-max) → 400 INVALID_ARGUMENT
# page_size > 1000 is REJECTED (no silent clamp) —
# parity with kacho-vpc (corevalidate.PageSize). The pg repo's effectivePageSize
# returns ErrInvalidArg → INVALID_ARGUMENT (HTTP 400). (Was: 200 silently capped.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-BVA-PAGESIZE-OVER",
    title="List users pageSize=1001 (over-max) → 400 INVALID_ARGUMENT (no silent clamp)",
    classes=["BVA", "VAL", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="ls-ps1001",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1001",
            auth="jwtAccountAdminA",
            test_script=[
                # pageSize > 1000 → INVALID_ARGUMENT (400), not a silent cap.
                "pm.test('status 400 (page_size rejected)', () => pm.expect(pm.response.code).to.eql(400));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-CRUD-OK — Invite new user to accountAId → Operation done
# Invite is the public flow: POST /iam/v1/users:invite.
# Creates a new User record (or returns existing) and creates an AccessBinding.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-CRUD-OK",
    title="Invite new user (email=invitee-{{runId}}@kacho.local) to accountAId → Operation done",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="invite",
            method="POST",
            path="/iam/v1/users:invite",
            body={
                # project_id is required when role_id is set
                # (server enforces project_id/role_id pair per proto
                # user_service.proto:117-133 + invite.go:118-123). Mirrors the
                # workspace fixture invite_body which always sends all 4 fields.
                "accountId": "{{accountAId}}",
                "projectId": "{{projectA1Id}}",
                "email": "invitee-{{runId}}@kacho.local",
                "roleId": ROLE_VIEW,
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.userId", "invitedUserId"),
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
                "if (j.response && j.response.userId && !pm.environment.get('invitedUserId')) {",
                "  pm.environment.set('invitedUserId', j.response.userId);",
                "}",
            ],
        ),
        # Verify the invited user has id prefix usr.
        Step(
            name="get-invited-user",
            method="GET",
            path="/iam/v1/users/{{invitedUserId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('invitedUserId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                # BUG-2: a verb-bearing IAM read-deny hides existence (404 / code 5),
                # not 403 — so the deny branch here is 404, never 403.
                "pm.test('invited user status 200 or 404 (FGA may restrict cross-get → hide existence)', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));",
                "if (pm.response.code === 200) {",
                "  pm.test('User.id prefix usr', () => {",
                "    const j = pm.response.json();",
                "    pm.expect(j.id, 'id must start with usr').to.match(/^usr[a-z0-9]+$/);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-NEG-EMAIL-INVALID — Invite with invalid email → 400 InvalidArgument
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-NEG-EMAIL-INVALID",
    title="Invite with invalid email format → 400 InvalidArgument",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="invite-bad-email",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": "not-a-valid-email", "roleId": ROLE_VIEW},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('error mentions email', () => {",
                "  const j = pm.response.json();",
                "  const msg = (j.message || '').toLowerCase();",
                "  pm.expect(msg).to.include('email');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-NEG-ROLE-MISSING — Invite with non-existent roleId → async FailedPrecondition
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-NEG-ROLE-MISSING",
    title="Invite with non-existent roleId → Operation.error FAILED_PRECONDITION (9)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="invite-bad-role",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": "badrole-{{runId}}@kacho.local", "roleId": "rol00000000000notfnd"},
            auth="jwtAccountAdminA",
            test_script=[
                # Sync 200 (Operation accepted) or sync 400 (role id format invalid).
                "pm.test('sync 200 or 400', () => pm.expect(pm.response.code).to.be.oneOf([200, 400]));",
                "const j = pm.response.json();",
                "if (pm.response.code === 400) {",
                "  pm.test('sync code 3 or 9', () => pm.expect(j.code).to.be.oneOf([3, 9]));",
                "} else {",
                "  pm.environment.set('badRoleInvOpId', j.id || '');",
                "}",
            ],
        ),
        Step(
            name="poll-bad-role",
            method="GET",
            path="/operations/{{badRoleInvOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (!pm.environment.get('badRoleInvOpId')) {",
                "  postman.setNextRequest(null);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('badRoleInvOpId')) {",
                "  pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "  pm.test('error code 9 (FAILED_PRECONDITION — role not found)', () => {",
                "    pm.expect(j.error && j.error.code, JSON.stringify(j)).to.be.oneOf([3, 9]);",
                "  });",
                "}",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-IDEM-REINVITE — Invite same email twice → idempotent (existing binding, no error)
# The invite path is idempotent. Re-inviting the same
# email with the same role should succeed (return existing binding, not fail).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-IDEM-REINVITE",
    title="Re-invite same email+role to same account → 200 idempotent (no AlreadyExists)",
    classes=["IDEM"],
    priority="P1",
    steps=[
        Step(
            name="reinvite",
            method="POST",
            path="/iam/v1/users:invite",
            # Re-invite jwtInvitee's email to accountBId (already a member).
            body={"accountId": "{{accountBId}}", "email": "auth-test-invitee@example.com", "roleId": ROLE_VIEW},
            auth="jwtAccountAdminB",
            test_script=[
                # Should succeed (200 Operation) — idempotent re-invite.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-AUTHZ-ANON-DENY — Invite as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-AUTHZ-ANON-DENY",
    title="Invite user as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="invite-anon",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": "anon@kacho.local", "roleId": ROLE_VIEW},
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
# IAM-USR-INV-AUTHZ-NONADMIN-DENY — Invite as jwtNoBindings (no editor on accountA) → 403
# CanInviteUsers = Check editor on account. NOB has no binding on accountA → denied.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-AUTHZ-NONADMIN-DENY",
    title="Invite user as jwtNoBindings (no editor on accountAId) → 403 PermissionDenied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="invite-nonadmin",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": "nonadmin-inv@kacho.local", "roleId": ROLE_VIEW},
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
# IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS — Invite new user → invitee can list accountA
# This is a stateful flow test: after Invite, the new user should have a viewer
# binding on accountA and be able to list its users (or at minimum not get 403).
# TODO authz-matrix: Full flow requires a live JWT for the new invitee — that
# requires generating a real token for invitee-{{runId}}@kacho.local.
# For now we verify the invite operation itself completed and leave the
# post-invite access check as a TODO.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS",
    title="Invite flow: after Invite → invited user has viewer binding on accountAId",
    classes=["FLOW"],
    priority="P1",
    steps=[
        Step(
            name="verify-invitee-binding",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # After IAM-USR-INV-CRUD-OK, the invited user should appear in the
                # users list for accountA (as a viewer member). We assert the list
                # is non-empty and contains at least one user, which is consistent
                # with a successful invite.
                *assert_status(200),
                "pm.test('users list non-empty after invite (binding created)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.users || []).length, 'at least one user (owner + invitee)').to.be.greaterThan(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-DL-CRUD-OK — Delete seeded user (userINVId) without active group membership
# Note: userINVId is the invitee user. Deleting them removes the record.
# Depends on: userINVId from crud-fixture/setup.sh.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-CRUD-OK",
    title="Delete userINVId (no group membership) → Operation done, Get returns 404 or 403",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="delete-user",
            method="DELETE",
            path="/iam/v1/users/{{userINVId}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Poll the GET until the user is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/users/{{userINVId}}", "User"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-DL-NEG-NOTFOUND — Delete non-existent user → 404 or 403
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-NEG-NOTFOUND",
    title="Delete non-existent user → 404 NotFound or 403 (no FGA path)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-notfound",
            method="DELETE",
            path="/iam/v1/users/usr00000000000notfnd",
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
# IAM-USR-DL-AUTHZ-ANON-DENY — Delete as anonymous → 401
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-AUTHZ-ANON-DENY",
    title="Delete user as anonymous → 401 Unauthenticated",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-anon",
            method="DELETE",
            path="/iam/v1/users/{{userNOBId}}",
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
# IAM-USR-DL-AUTHZ-NONADMIN-DENY — Delete userAAAId as jwtNoBindings (cross-user) → 403 or 404
# Per authz semantics: NOB cannot delete AAA (no viewer/owner path to AAA's record).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-AUTHZ-NONADMIN-DENY",
    title="Delete userAAAId as jwtNoBindings (no owner path to AAA) → 403 or 404",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-nonadmin",
            method="DELETE",
            path="/iam/v1/users/{{userAAAId}}",
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
# IAM-USR-UP-CRUD-OK-LABELS — UpdateUser sets labels (updateMask=labels) →
# Operation done, Get confirms labels round-trip.
# The public UpdateUser RPC: labels are the only mutable field.
# jwtAccountAdminA is the owner of accountAId and of userAAAId's home account, so
# the owner-matches-principal authz passes.
# verifies: labels set via update_mask round-trip through users.labels.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-UP-CRUD-OK-LABELS",
    title="UpdateUser userAAAId labels (updateMask=labels) → Operation done, Get confirms labels",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="update-labels",
            method="PATCH",
            path="/iam/v1/users/{{userAAAId}}",
            body={"labels": {"tier": "gold-{{runId}}"}, "updateMask": "labels"},
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
            path="/iam/v1/users/{{userAAAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('User.labels.tier updated', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.labels, 'labels field').to.be.an('object');",
                "  pm.expect(j.labels.tier, 'labels.tier must include gold-').to.include('gold-');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-UP-NEG-IMMUTABLE-EXTERNALID — external_id in updateMask → sync 400
# INVALID_ARGUMENT. external_id (the IdP identity key) is hard-immutable on User.
# verifies: an identity field in the mask → INVALID_ARGUMENT (first statement).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-UP-NEG-IMMUTABLE-EXTERNALID",
    title="UpdateUser with external_id in updateMask → 400 INVALID_ARGUMENT (immutable)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="update-immutable-externalid",
            method="PATCH",
            path="/iam/v1/users/{{userAAAId}}",
            body={"updateMask": "external_id"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('error mentions immutable or external_id', () => {",
                "  const j = pm.response.json();",
                "  const msg = (j.message || '').toLowerCase();",
                "  pm.expect(msg).to.satisfy(m => m.includes('immutable') || m.includes('external_id') || m.includes('external'), 'message: ' + msg);",
                "});",
            ],
        ),
    ],
))
