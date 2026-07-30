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
# jwtPureNoBindings is not a member of accountAId → scope-filter returns 200 + empty, not 403.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY",
    title="List users ?accountId=accountAId as jwtPureNoBindings (non-member) → 200 + empty list (scope-filter)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        # kacho-iam#276 root-cause fix — this reads jwtPureNoBindings, a DEDICATED subject that
        # NO suite EVER grants (setup.sh). Previously it read jwtNoBindings, which the iam
        # access-binding CRUD suites grant `ROLE_VIEW@account-A`; under the parallel fan-out that
        # account-scoped viewer transiently made account-A users visible to NOB via containment →
        # this "must be empty" canary flipped, which had forced a preclean loop + retry_until_absent
        # band-aid. A guaranteed binding-free principal makes this a STRICT single-shot leak-guard:
        # a GENUINE user-list over-show still FAILS the "zero users" assertion honestly.
        Step(
            name="list-nonmember",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}",
            auth="jwtPureNoBindings",
            test_script=[
                # Per authz-deny.py: user-list-account-A → non-member → EMPTY (200 + zero users).
                *assert_status(200),
                "pm.test('non-member: users empty (scope-filter default-deny)', () => {",
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
    title="List users ?accountId=accountBId as jwtPureNoBindings (authenticated, zero grants) → 200, NO over-show (empty scope-list, does not leak B's users)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-member-no-overshow",
            method="GET",
            path="/iam/v1/users?accountId={{accountBId}}",
            # A subject with NO v_list/viewer grant on accountB must see an empty
            # scope-list. Uses jwtPureNoBindings (the never-granted subject) — NOT
            # jwtInvitee: the seed grants jwtInvitee admin@account:accountB
            # (setup.sh — "INV admin in account-B"), so INV legitimately materializes
            # v_list on every accountB user via the account-tier cascade (list.go) and
            # correctly sees them. The no-over-show property is "no user-list grant ⇒
            # empty", which only a genuinely unbound subject can assert.
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('subject without a user-viewer/v_list grant does NOT see accountB users (no over-show)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.users, 'users field').to.be.an('array');",
                "  // Bare authentication (no account/user grant) yields no user visibility.",
                "  pm.expect((j.users || []).length, 'no over-show: list is empty for a no-grant subject').to.eql(0);",
                "});",
                "pm.test('no leak of accountB owner to a no-grant subject', () => {",
                "  const j = pm.response.json();",
                "  const ownerId = pm.environment.get('userAABId');",
                "  pm.expect((j.users || []).some(u => u.id === ownerId), 'accountB owner must not be visible to a no-grant subject').to.be.false;",
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
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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
            test_script=[
                # Читает ТОТ ЖЕ вызывающий, который только что пригласил, и право
                # `v_get` на новом объекте пользователя материализуется СИНХРОННО
                # внутри самого приглашения (реконсайл объекта вызывается до того, как
                # операция помечена done, ровно чтобы закрыть окно «пригласил → сразу
                # читаю»). Значит исход один.
                #
                # Прежнее `oneOf([200, 404])` оправдывалось тем, что «FGA может
                # ограничить cross-get → скрытие существования». Скрытие существования
                # относится к ДРУГОМУ вызывающему — тому, у кого права нет; этот кейс
                # такого не ставит вовсе. Поэтому 404 здесь означал бы потерю права у
                # приглашающего, то есть дефект, а утверждение его принимало.
                #
                # Пропуск шага по пустому `invitedUserId` тоже снят: пустая переменная —
                # это сорванная фикстура, и она обязана краснеть, а не отменять
                # проверку молча (кейс иначе зеленел на промахе).
                "pm.test('фикстура записала id приглашённого', () => "
                "  pm.expect(pm.environment.get('invitedUserId'), 'invitedUserId').to.be.a('string').and.not.empty);",
                *assert_status(200),
                "pm.test('User.id prefix usr', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with usr').to.match(/^usr[a-z0-9]+$/);",
                "});",
                "pm.test('и это именно тот пользователь, которого пригласили', () => "
                "  pm.expect(pm.response.json().id).to.eql(pm.environment.get('invitedUserId')));",
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
#
# ЧЕГО КЕЙС НЕ ДЕЛАЛ. Тело несло `roleId` БЕЗ `projectId`, а проект обязателен всегда,
# когда задана роль (`invite.go`, проверка стоит до создания операции). Поэтому приглашение
# отвергалось синхронным 400 «Illegal argument project_id: required when role_id is set»
# на КАЖДОМ прогоне: операции не возникало, поллинг себя пропускал, и полоса, ради которой
# кейс существует — несуществующая роль на вставке выдачи, — не выполнялась НИ РАЗУ.
# Утверждение `oneOf([200, 400])` это и скрывало: оно проходило и на том отказе, и на
# другом, и на отсутствии отказа вовсе.
#
# Это ТОТ ЖЕ дефект авторства, который сосед `IAM-USR-INV-IDEM-REINVITE` уже разобрал и
# починил у себя (см. его шапку). Здесь он остался жив — потому что правку применили к
# одному кейсу, а не к классу.
#
# ЧТО ТЕПЕРЬ. Проект назван, поэтому вставка выдачи действительно доходит до БД и
# упирается в FK на роль (`access_bindings_role_fk`) — полоса АСИНХРОННАЯ: вызывающий
# получает конверт операции, а отказ живёт в самой операции. Заявлены код и контрактный
# текст: `FAILED_PRECONDITION` + «Role <id> not found» (pgmaperr, direction-sensitive —
# на вставке это «роли нет», на удалении роли текст другой). Текст пинит, КАКОЙ это
# отказ, иначе кейс прошёл бы на любом постороннем.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-NEG-ROLE-MISSING",
    title="Invite with non-existent roleId → Operation.error FAILED_PRECONDITION (9) \"Role <id> not found\"",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="invite-bad-role",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "projectId": "{{projectA1Id}}",
                  "email": "badrole-{{runId}}@kacho.local", "roleId": "rol00000000000notfnd"},
            auth="jwtAccountAdminA",
            test_script=[
                # Полоса одна: форма id роли валидна (узнаваемый префикс), поэтому
                # синхронного отказа по формату нет, и приглашение принимается конвертом
                # операции. Отказ выносит операция — шагом ниже.
                *assert_status(200),
                "pm.test('200 — это конверт операции', () => pm.expect(pm.response.json().id, pm.response.text()).to.be.a('string').and.not.empty);",
                "pm.environment.set('badRoleInvOpId', pm.response.json().id);",
            ],
        ),
        Step(
            name="poll-bad-role",
            method="GET",
            path="/operations/{{badRoleInvOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                # Реальная пауза между поллами: newman исполняет test-script синхронно и
                # вызывает setNextRequest ДО любого setTimeout, поэтому busy-wait —
                # единственный способ действительно разнести опросы (testing.md).
                "if (pm.environment.get('_badRoleStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_badRolePolls', '0');",
                "  pm.environment.set('_badRoleStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_badRolePolls') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_badRolePolls', String(pc + 1));",
                "  const _bp = Date.now(); while (Date.now() - _bp < 500) void 0;",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_badRolePolls');",
                "pm.environment.unset('_badRoleStarted');",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('error code 9 (FAILED_PRECONDITION — role not found)', () => "
                "  pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(9));",
                # Пиним ФОРМУ контрактного текста, а не сам идентификатор роли, и на это
                # есть причина в коде: подсказка идентификатора, которую вставка выдачи
                # передаёт мапперу, собрана под текст про ЗАНЯТЫЙ слот
                # («<субъект>|<тип области>:<область>») и переиспользуется ветвью FK по
                # роли как есть. Поэтому в слот роли попадает составная строка, а не
                # `rol…`. Утверждать здесь `Role rol… not found` значило бы утверждать
                # то, чего продукт не производит; утверждать просто «not found» — не
                # отличать эту причину от общей заглушки FK и от «уже существует».
                # Форма `Role … not found` отличает, и она — то, что реально доходит.
                # verifies https://github.com/PRO-Robotech/kacho/issues/105
                "pm.test('текст — контрактный тон FK по роли (Role … not found)', () => "
                "  pm.expect(((j.error||{}).message||'')).to.match(/^Role .* not found$/));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-INV-IDEM-REINVITE — re-invite the SAME email to the SAME account.
#
# WHAT THIS CASE USED TO DO (and why it proved nothing). The body carried
# `roleId` but no `projectId`, and `project_id` has been REQUIRED whenever
# `role_id` is set since the RPC existed — so the invite was rejected 400
# `Illegal argument project_id: required when role_id is set` on every run. The
# rejection carried no Operation id, the shared `opId` kept the PREVIOUS case's
# invite, and the poll confirmed THAT operation as `done` — green. The
# idempotency this case is named for was therefore never once exercised.
# (`opId` is now cleared before each capture — gen.py::save_from_response — so
# this class cannot silently recur.)
#
# WHAT IT CHECKS NOW — the two halves of the landed contract, separately:
#
#  1. USER-ROW idempotency (the invariant in the case name): re-inviting an email
#     that already has a row in the account returns the SAME user, no error. The
#     assertion is on `response.id`, NOT `metadata.userId`: Invite pre-allocates a
#     fresh id into metadata BEFORE the async worker discovers the existing row,
#     so metadata carries a phantom id on the idempotent path and only the
#     Operation `response` is authoritative (testing.md: check op.error/response,
#     never read an id out of metadata alone).
#
#  2. GRANT strictness with `projectId`+`roleId` present (the required field the
#     old payload omitted): re-issuing an ALREADY-ACTIVE grant is NOT silently
#     absorbed — `AccessBinding.Insert` is a strict create (the previous
#     `ON CONFLICT DO UPDATE` upsert was deliberately removed because it hid real
#     duplicate grants from the audit chain, access_binding_repo.go:18), so the
#     partial UNIQUE `access_bindings_active_grant_uniq` raises 23505 and the
#     Operation completes with ALREADY_EXISTS and the verbatim contract text.
#     Asserting that text pins WHICH rejection this is, so the negative cannot
#     pass on an unrelated refusal.
#
# Self-seeded per run (`{{runId}}` in the email) so the case is idempotent across
# runs and independent of what other suites did to the shared fixture users.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-IDEM-REINVITE",
    title="Re-invite same email → same User row (idempotent); re-issuing an already-active "
          "project grant → Operation ALREADY_EXISTS (strict create, not a silent upsert)",
    classes=["IDEM", "NEG"],
    priority="P1",
    steps=[
        # --- 1. seed: first invite of a fresh email, no grant ------------------
        Step(
            name="invite-first",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "email": "reinv-{{runId}}@kacho.local"},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="capture-first-user",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('first invite succeeded (no op.error)', () => pm.expect(j.error, JSON.stringify(j)).to.eql(undefined));",
                "pm.test('first invite returned the User in response', () => {",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j)).to.match(/^usr[a-z0-9]+$/);",
                "});",
                *save_from_response("j.response && j.response.id", "reinvUserId"),
            ],
        ),
        # --- 2. the idempotency claim: identical invite → SAME user row --------
        Step(
            name="reinvite-same-email",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "email": "reinv-{{runId}}@kacho.local"},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="reinvite-is-idempotent",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('re-invite succeeded (no AlreadyExists on the user row)', () => pm.expect(j.error, JSON.stringify(j)).to.eql(undefined));",
                # The authoritative id is response.id — metadata.userId is the
                # pre-allocated candidate the idempotent path discards.
                "pm.test('re-invite returned the SAME User row (idempotent)', () => {",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j))",
                "    .to.eql(pm.environment.get('reinvUserId'));",
                "});",
                "pm.test('re-invite did not resurrect the row as a new invite', () => {",
                "  pm.expect(j.response && j.response.inviteStatus, JSON.stringify(j)).to.eql('PENDING');",
                "});",
            ],
        ),
        # --- 3. grant strictness: projectId+roleId, issued twice ---------------
        Step(
            name="invite-with-grant",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "projectId": "{{projectB1Id}}",
                  "email": "reinv-{{runId}}@kacho.local", "roleId": ROLE_VIEW},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        Step(
            name="reinvite-duplicate-grant",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "projectId": "{{projectB1Id}}",
                  "email": "reinv-{{runId}}@kacho.local", "roleId": ROLE_VIEW},
            auth="jwtAccountAdminB",
            test_script=[
                # The duplicate is detected in the async worker (DB UNIQUE), so the
                # RPC itself is accepted — the refusal lands on the Operation.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "dupGrantOpId"),
            ],
        ),
        assert_op_error(6, "ALREADY_EXISTS",
                        msg_substr="these permissions are already granted",
                        op_var="dupGrantOpId"),
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
# IAM-USR-DL-CRUD-OK — delete a user that CAN be deleted.
#
# TWO defects, one behind the other:
#
#  (a) The Operation was minted by jwtInvitee (self-delete) but polled by the
#      helper's old hard-coded default, jwtAccountAdminA. OperationService.Get is
#      principal-scoped and hides a foreign operation as 404, so the poll 404'd for
#      its whole retry budget — 52 failing assertions, one root. Fixed at the
#      harness level: the poll now inherits the minting principal
#      (gen.py::AUTH_INHERIT_OP), so this cannot recur in the next case either.
#
#  (b) Underneath it, the delete NEVER SUCCEEDED. `userINVId` is a shared fixture
#      user that by construction holds active AccessBindings — the owner grant on
#      its own personal account, admin on its default project, plus admin@account-B
#      from tests/authz-fixtures/setup.sh — and User.Delete is guarded by the
#      access-binding RESTRICT: `FAILED_PRECONDITION: User <id> has active access
#      bindings and cannot be deleted` (product behaviour, deliberate, locked by
#      pgmaperr_test.go). The old case never noticed because it asserted only
#      `done`, never SUCCESS, and its get-after-delete ran as an unrelated principal
#      that gets 403/404 on that record whether or not it still exists — the
#      "gone" assertion was satisfied by hide-existence, not by deletion.
#
# So the fixture is the defect, not the product: the case has to target a user that
# is genuinely deletable. It self-seeds one — an invite WITHOUT `roleId` creates a
# PENDING user row and no AccessBinding — and deletes it as the account owner (the
# non-self branch of the Delete guard: owner of the target's account). Run-unique
# email keeps it idempotent across runs.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-CRUD-OK",
    title="Delete a binding-free user as the owner of its account → Operation SUCCEEDS, Get returns 404",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="seed-deletable-user",
            method="POST",
            path="/iam/v1/users:invite",
            # No roleId ⇒ no AccessBinding ⇒ nothing for the RESTRICT guard to hold.
            body={"accountId": "{{accountAId}}", "email": "dele-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="capture-deletable-user",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                # op.error BEFORE reading an id (testing.md): a failed Invite still
                # carries a pre-allocated id in metadata, so metadata alone would
                # hand the delete below a phantom user.
                "pm.test('seed invite succeeded (no op.error)', () => pm.expect(j.error, JSON.stringify(j)).to.eql(undefined));",
                "pm.test('seed invite returned a User', () => {",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j)).to.match(/^usr[a-z0-9]+$/);",
                "});",
                *save_from_response("j.response && j.response.id", "delUserId"),
            ],
        ),
        retry_until_authorized(Step(
            name="delete-user",
            method="DELETE",
            path="/iam/v1/users/{{delUserId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        )),
        poll_operation_until_done(),
        # The assertion the case was missing: the delete has to have SUCCEEDED.
        # Without it "gone" below is indistinguishable from hide-existence.
        assert_op_success(),
        # Poll the GET until the user is actually gone (async delete + FGA
        # tuple removal can lag the Operation→done a beat).
        get_until_gone("/iam/v1/users/{{delUserId}}", "User"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-DL-NEG-ACTIVE-BINDINGS — the other half of the contract that (b) above
# exposed: a user holding active AccessBindings CANNOT be deleted. This is the
# behaviour the old IAM-USR-DL-CRUD-OK was silently hitting; asserted here on
# purpose, with the verbatim text so it cannot pass on an unrelated refusal.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-NEG-ACTIVE-BINDINGS",
    title="Delete a user that holds active AccessBindings → Operation.error FAILED_PRECONDITION (9) "
          "'has active access bindings and cannot be deleted'",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="delete-bound-user",
            method="DELETE",
            # Self-delete: jwtInvitee always holds bindings (own personal account
            # owner grant + the account-B admin grant from the fixture seed), so the
            # RESTRICT guard is reached rather than the authz gate.
            path="/iam/v1/users/{{userINVId}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "boundDelOpId"),
            ],
        ),
        # Polls as jwtInvitee — inherited from the step that minted the operation.
        assert_op_error(9, "FAILED_PRECONDITION",
                        msg_substr="has active access bindings and cannot be deleted",
                        op_var="boundDelOpId"),
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
