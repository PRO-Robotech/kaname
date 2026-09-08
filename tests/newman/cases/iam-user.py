# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для UserService.

Covered RPCs:  Get, List, Invite, Delete + глаголы-действия :block / :unblock /
  :removeFromAccount (public UserService).
Not covered here: InternalUserService.UpsertFromIdentity, InternalUserService.Get —
  those are internal-port-only RPCs covered in iam-internal-only-check.py.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — служебная учётка, admin @ accountAId (НЕ предъявитель userAAAId)
    jwtAccountAdminB  — служебная учётка, admin @ accountBId
    jwtNoBindings     — authenticated, no account membership
    jwtInvitee        — служебная учётка с выдачей на accountBId
    userAAAId         — ЦЕЛЬ ПРИВЯЗКИ: строка пользователя, владеющая accountAId
    userNOBId         — ЦЕЛЬ ПРИВЯЗКИ: пользователь без выдач
    userINVId         — ЦЕЛЬ ПРИВЯЗКИ: приглашаемый пользователь
    accountAId        — pre-seeded account owned by userAAAId
    accountBId        — cross-account (for List scope + Invite target)

  ПОЧЕМУ `user*Id` НЕ ПРЕДЪЯВИТЕЛИ. Это ЦЕЛИ ПРИВЯЗКИ — строки пользователей,
  заведённые, чтобы разрешился триггер существования субъекта. Ни один выдаваемый
  предъявитель ими не аутентифицируется, и не может: машинный харнесс получает
  `client_credentials`, то есть служебную учётку. Привязать роль к `{{user*Id}}` и
  читать `{{jwt*}}` значит завести канал, который не разрешится ни при каком
  бюджете, а выглядеть это будет таймаутом шестью шагами позже. Набор объявлен
  ДАННЫМИ (`tests/authz-fixtures/principal_pairings.py`, `BINDING_TARGET_ONLY_IDS`)
  и сверяется гейтом `scripts/case_header_principal_claim_test.py`.

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

    IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS дополнительно требует:
      jwtBootstrap      — предъявитель пробы модели прав (InternalIAMService.Check);
      internalBaseUrl   — адрес cluster-internal REST-листенера (инжектится
                          прогонщиком через --env-var; без него шаг ОТКАЗЫВАЕТ и
                          пропускается, а не уезжает молча на публичный порт);
      projectA1Id       — область, которую называет само приглашение;
      projectB1Id       — проект ЧУЖОГО аккаунта, отрицательный контроль пробы.

Operation envelope:
  Mutations return `operation.Operation` with id prefix `iop`.
  Poll hits /operations/{id} via OpsProxy (iop* → kaname).

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


# Шаги создания РАСХОДУЕМОГО PENDING-приглашения в accountA со своим адресом.
# Общие для всех кейсов, которым нужно своё приглашение, поэтому собираются
# функцией: копия в каждом кейсе разъехалась бы.
#
# Приглашение всегда СВОЁ: переиспользовать `invitedUserId` из
# IAM-USR-INV-CRUD-OK нельзя — порядок кейсов не контракт, а чужая фикстура.
#
# Определение стоит ЗДЕСЬ, а не рядом с первым потребителем: потребителей теперь
# двое — кейсы `:block`/`:unblock` ниже и IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS
# выше, — а python читает файл сверху вниз.
#
# `with_grant` — НЕСУЩИЙ параметр, а не удобство вызывающего. Пара «проект +
# роль» заводит членство И ЖИВУЮ ВЫДАЧУ на него, а членство, несущее живую
# выдачу, НЕ СНИМАЕТСЯ: отложенный триггер `membership_carrying_rights_is_kept`
# (миграция 472002) отвергает снятие НА КОММИТЕ, потому что порядок «сперва
# права, потом участие» — конструкция базы, а не дисциплина вызывающего (#1127).
#
# Поэтому кейсу, чей предмет — само ИСКЛЮЧЕНИЕ, нужна жертва БЕЗ выдачи: иначе
# он падает на страже, к его предмету отношения не имеющем, и называет виновником
# невиновного. Тот же приём и по той же причине стоит у IAM-USR-DL-CRUD-OK — там
# строку личности держит RESTRICT по тем же самым выдачам.
#
# Умолчание оставлено ПРЕЖНИМ (`True`) намеренно: прочие потребители приглашают
# РАДИ доступа, и снятие роли сменило бы предмет их кейсов. Сам страж при этом
# покрытия не теряет — он утверждается через край отдельным кейсом
# IAM-USR-EXCL-NEG-LIVE-GRANT, где живая выдача и есть предмет.
def _invite_probe(var: str, email_tag: str, with_grant: bool = True):
    body = {
        "accountId": "{{accountAId}}",
        "email": f"{email_tag}-{{{{runId}}}}@kacho.local",
    }
    if with_grant:
        # `role_id` обязателен ТОГДА И ТОЛЬКО ТОГДА, когда назван `project_id`
        # (см. InviteUserInput): половина пары — синхронный INVALID_ARGUMENT.
        body["projectId"] = "{{projectA1Id}}"
        body["roleId"] = ROLE_VIEW
    return [
        Step(
            name=f"invite-{email_tag}",
            method="POST",
            path="/iam/v1/users:invite",
            body=body,
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered(f"invite-{email_tag}"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.userId", var),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        # Приглашение обязано РЕАЛЬНО состояться: отказ, снятый с несозданной
        # строки, доказывает только то, что строки нет. Kachō кладёт
        # предвыделенный id в metadata даже у операции, завершившейся ошибкой,
        # поэтому без этой проверки дальше поехал бы фантом.
        assert_op_success(auth="jwtAccountAdminA"),
    ]


# Адрес пробы модели прав. `/iam/v1/internal/*` обслуживает ТОЛЬКО
# cluster-internal REST-листенер, поэтому шаг переписывает адрес на
# {{internalBaseUrl}} санкционированной формой require_env_url: утвердить (назвав
# переменную) и пропустить запрос. Без переписывания шаг ушёл бы на публичный порт
# и получил маршрутный 404, неотличимый от отказа модели.
CHECK_PATH = "/iam/v1/internal/iam:check"


def _internal_check_url():
    return require_env_url(
        "internalBaseUrl", CHECK_PATH,
        "internal-only Check probe — /iam/v1/internal/* is served ONLY by the "
        "cluster-internal REST listener")


# ---------------------------------------------------------------------------
# IAM-USR-GT-CRUD-OK — Get userNOBId as NOB (self — only self can get own record)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GT-CRUD-OK",
    title="Get ceremonyUserId as jwtHumanCeremony (self) → 200 + id prefix usr, externalId present",
    classes=["CRUD"],
    priority="P0",
    steps=[
        Step(
            name="get-self",
            method="GET",
            path="/iam/v1/users/{{ceremonyUserId}}",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('User.id prefix usr', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, 'id must start with usr').to.match(/^usr[a-z0-9]+$/);",
                "});",
                "pm.test('User.id matches ceremonyUserId', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('ceremonyUserId'));",
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
# IAM-USR-INV-NEG-ROLE-MISSING — Invite с несуществующим roleId → СИНХРОННЫЙ
# FailedPrecondition «Role <id> not found».
#
# ЧЕГО КЕЙС НЕ ДЕЛАЛ (первая редакция). Тело несло `roleId` БЕЗ `projectId`, а проект
# обязателен всегда, когда задана роль. Приглашение отвергалось синхронным 400 «Illegal
# argument project_id: required when role_id is set» на КАЖДОМ прогоне, и полоса, ради
# которой кейс существует, не выполнялась НИ РАЗУ. Утверждение `oneOf([200, 400])` это
# и скрывало.
#
# ПОЧЕМУ ОН ОСТАВАЛСЯ КРАСНЫМ ПОСЛЕ ТОЙ ПРАВКИ. Проект назвали — и предсказали, что
# вставка выдачи дойдёт до БД и упрётся в FK на роль, то есть полоса АСИНХРОННАЯ (конверт
# операции, отказ внутри неё). На момент правки (30.07, 03:26) это было верно. В 20:00
# того же дня продукт это изменил: проверка «роль назначаема на область» встала у КАЖДОГО
# писателя привязок, и на пути приглашения она стоит ДО создания операции. Полоса стала
# СИНХРОННОЙ, а кейс остался прежним — форма ответа сменилась, проверка нет.
#
# Цена была не в одном утверждении. `invite-bad-role` получал 400 вместо 200, поэтому
# `badRoleInvOpId` не захватывался, и следующий шаг тридцать раз опрашивал
# `/operations/{{badRoleInvOpId}}` по НЕРАЗРЕШЁННОЙ подстановке. Один устаревший
# прогноз полосы давал ~36 упавших утверждений.
#
# ЧТО ПРОВЕРЯЕТСЯ ТЕПЕРЬ — ровно то, что продукт производит, и строже прежнего:
# синхронный 400, `code` 9 (FAILED_PRECONDITION) и ТОЧНЫЙ контрактный текст. Прежняя
# редакция пинила лишь ФОРМУ текста (`/^Role .* not found$/`), потому что на полосе FK в
# слот роли попадала составная строка, а не `rol…`. Синхронная проверка сообщает
# НАСТОЯЩИЙ идентификатор роли, поэтому здесь утверждается сам текст целиком — это
# отличает отказ по роли и от общей заглушки FK, и от «уже существует», и от отказа по
# любому другому полю.
#
# Полоса FK остаётся DB-уровневым backstop'ом (ban #10) для гонки «роль удалили между
# проверкой и вставкой» — она недетерминируема из newman и здесь не утверждается.
#
# ЗДЕСЬ СТОЯЛА ПОМЕТКА `# verifies …/issues/105`, И ОНА ПЕРЕЖИЛА СВОЙ ПРЕДМЕТ.
# Пометка означает «кейс ожидаемо КРАСНЫЙ, пока дефект открыт» (ban #13) и выкупает его
# из «всё обязано быть зелёным». Дефект закрыт (`kacho#105`, COMPLETED 2026-08-07):
# подсказка мапперу ошибок на вставке выдачи теперь разбирается, и в слот роли попадает
# сама роль — ветвь FK по роли в `internal/repo/kaname/pg/pgmaperr.go`, регрессия на ТЕКСТ
# в `pgmaperr_binding_hint_test.go`. Пометка при этом стояла в одном абзаце с текстом,
# который сам называл утверждение суженным до идентификатора, — то есть противоречила
# соседней строке.
#
# ЧТО ЗАЩИЩАЕТ КЕЙС, и почему он остаётся после снятия пометки: приглашение с валидной по
# ФОРМЕ, но несуществующей ролью отвергается СИНХРОННО, кодом FAILED_PRECONDITION, с
# контрактным текстом, называющим САМУ РОЛЬ, и без конверта операции. Четыре утверждения
# ниже различают четыре разных регресса: возврат полосы в асинхронную (появится операция),
# подмену кода, возврат составной подсказки в слот роли и отказ по любому другому полю.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-NEG-ROLE-MISSING",
    title="Invite with non-existent roleId → sync FAILED_PRECONDITION (9) \"Role <id> not found\"",
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
                # 400, а не 200: форма id роли валидна (узнаваемый префикс), поэтому
                # отказа по ФОРМАТУ нет — отказ выносит проверка назначаемости роли,
                # и она стоит до создания операции. Конверта операции здесь не будет.
                *assert_status(400),
                "const j = pm.response.json();",
                "pm.test('code 9 (FAILED_PRECONDITION — роли нет)', () => "
                "  pm.expect(j.code, pm.response.text()).to.eql(9));",
                "pm.test('контрактный текст называет саму роль', () => "
                "  pm.expect(j.message, pm.response.text())"
                "    .to.eql('Role rol00000000000notfnd not found'));",
                # Отказ синхронный ⇒ операции не возникает. Утверждается явно: иначе
                # возврат к асинхронной полосе прошёл бы незамеченным, а вместе с ним
                # вернулся бы и поллинг по неразрешённой подстановке.
                "pm.test('операции не создано (полоса синхронная)', () => "
                "  pm.expect(j.id, pm.response.text()).to.be.undefined);",
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
# IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS — приглашение ДАЁТ ПРИГЛАШЁННОМУ ДОСТУП на
# том объёме, который названо в приглашении.
#
# ЧТО ЗДЕСЬ БЫЛО И ПОЧЕМУ ЭТО НЕ МОГЛО УПАСТЬ. Кейс утверждал ровно одно: список
# пользователей аккаунта A НЕПУСТ. Он непуст всегда — в нём как минимум владелец
# аккаунта, — то есть утверждение было тождественно истинным и оставалось зелёным
# при приглашении, не создавшем ни строки, ни выдачи. Заголовок при этом обещал
# «приглашённый получает доступ», а шапка объявляла проверку доступа отложенной.
# Заголовок называл и не тот объём: тело приглашения адресует ПРОЕКТ
# (`projectId` обязателен, когда задан `roleId`), поэтому выдача создаётся на
# `project:{{projectA1Id}}`, а не на аккаунте.
#
# ПОЧЕМУ ДОСТУП ПРОВЕРЯЕТСЯ ПРОБОЙ МОДЕЛИ, А НЕ ЗАПРОСОМ ОТ ПРИГЛАШЁННОГО. Токена
# приглашённого не существует и получить его харнесс не может: машинный посев
# получает только `client_credentials`, то есть служебную учётку (шапка
# tests/authz-fixtures/mint_rs256.py), а приглашение по построению адресовано
# человеку, который ЕЩЁ НЕ ВХОДИЛ. Прежняя шапка называла это «TODO: нужен живой
# JWT» — но ждать тут нечего, предмет недостижим. Наблюдаемая величина, которая
# ЕСТЬ, — вердикт самой модели прав: `InternalIAMService.Check` спрашивает про
# ЛЮБОЙ субъект, не предъявляя его. Та же проба и тем же способом используется в
# cases/iam-invite-grant-fga.py и cases/iam-rbac-scope-grant.py.
#
# ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — `v_get`, А НЕ ЯРУС. Край разрешает чтение по
# verb-bearing отношению (`get` → `v_get`), поэтому «доступ» — это именно `v_get` на
# названном объекте. Ярус `viewer` тут был бы слабее и пропустил бы ровно тот
# дефект, который назван в самом продукте: выдача, эмитировавшая ТОЛЬКО ярус,
# оставляет приглашённого без `v_get`, то есть с отказом на GET подаренного проекта
# (services/iam/internal/apps/kaname/api/user/invite.go, порт ObjectReconciler).
# Роль `view` несёт `read/list/get` на `*.*`, а выдача создаётся без пообъектного
# сужения (`allInScope`), поэтому глаголы материализуются и НА САМОМ объекте
# области (reconcile.desiredRuleMembers → scopeSelfMember).
#
# ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ — ОБЯЗАТЕЛЕН И ОДНОКРАТЕН. Без него «разрешено» неотличимо
# от пробы, которая отвечает «да» на что угодно. Поэтому тот же субъект спрашивается
# про проект ЧУЖОГО аккаунта (`projectB1Id`), где ему не выдавали ничего, и там
# ответ обязан быть «не разрешено». Отказ НЕ поллится (повтор на отрицании прятал бы
# настоящую утечку) — это единственный выстрел.
#
# ОГРАНИЧЕННЫЙ ПОВТОР — только на положительной половине и только на окне
# материализации: сама выдача пишется в транзакции приглашения, а её видимость в
# хранилище прав доезжает форвардом/дренажем. Бюджет конечен, после него исполняется
# настоящее утверждение — не сошлось значит красное.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-INV-FLOW-INVITEE-GETS-ACCESS",
    title="Invite flow: the invited user really HOLDS v_get on the invited project, and holds "
          "nothing on a foreign-account project (Check probe, positive + paired negative)",
    classes=["FLOW", "AUTHZ"],
    priority="P1",
    steps=[
        # Своё приглашение со своим адресом (общая фикстура не задействована).
        *_invite_probe("inviteAccessUserId", "accessprobe"),
        # ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА — приглашённый держит v_get на подаренном проекте.
        poll_request_until_status(
            name="invitee-holds-v-get-on-invited-project",
            method="POST",
            path=CHECK_PATH,
            auth="jwtBootstrap",
            body={
                "subjectId": "user:{{inviteAccessUserId}}",
                "relation": "v_get",
                "object": "project:{{projectA1Id}}",
            },
            expect_code=200,
            pre_script=_internal_check_url(),
            # Проба всегда отвечает 200; «ещё не сошлось» — это ТЕЛО ответа.
            retry_predicate="(() => { let j; try { j = pm.response.json(); } "
                            "catch (e) { return false; } return j.allowed !== true; })()",
            test_script=[
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('фикстура записала id приглашённого', () => "
                "  pm.expect(pm.environment.get('inviteAccessUserId'), 'inviteAccessUserId')"
                "   .to.be.a('string').and.not.empty);",
                "pm.test('приглашение материализовало v_get на подаренном проекте', () => {",
                "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                "  pm.expect(j && j.allowed, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),
        # ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ — та же проба, тот же субъект, чужой проект.
        Step(
            name="invitee-holds-nothing-on-foreign-project",
            method="POST",
            path=CHECK_PATH,
            auth="jwtBootstrap",
            body={
                "subjectId": "user:{{inviteAccessUserId}}",
                "relation": "v_get",
                "object": "project:{{projectB1Id}}",
            },
            pre_script=_internal_check_url(),
            test_script=[
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('на проекте чужого аккаунта доступа НЕТ (проба различает)', () => {",
                "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                "  pm.expect(j && j.allowed, JSON.stringify(j)).to.not.eql(true);",
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
# PENDING user row and no AccessBinding. Run-unique email keeps it idempotent
# across runs.
#
# ЗДЕСЬ УДАЛЯЛ РАСПОРЯДИТЕЛЬ АККАУНТА, И ТАКОЙ ПОЛОСЫ БОЛЬШЕ НЕТ (#1131). Абзац
# выше называл её «non-self branch of the Delete guard: owner of the target's
# account» — на дереве этой ветви не осталось: строка `iam_user` ГЛОБАЛЬНА, одна
# на все аккаунты человека, поэтому её снятие из аккаунта A стирает человека и в
# аккаунте B. Снятие переведено на `iam_user.identity_remover`, у которого
# источников уровня аккаунта НЕТ ВОВСЕ: круг — сам человек либо надзор облака.
# Ни делегированный распорядитель, ни ВЛАДЕЛЕЦ аккаунта туда не входят, так что
# смена предъявителя на владельца прежнюю редакцию не спасла бы.
#
# ПОЧЕМУ ЭТО НЕ ОСЛАБЛЕНИЕ. Утверждения не тронуты: операция обязана ЗАВЕРШИТЬСЯ
# УСПЕХОМ, и человека после этого не должно быть. Сменился предъявитель — с того,
# кто права лишён, на того, кто им располагает; иначе кейс проверял бы отказ
# модели, а не удаление. Отказ распорядителю аккаунта не потерян и утверждается
# отдельно — `IAM-USR-RMID-NEG-ACCOUNT-ADMIN::identity-delete-denied`.
#
# ЧТЕНИЕ ПОСЛЕ УДАЛЕНИЯ — ТЕМ ЖЕ ПРЕДЪЯВИТЕЛЕМ, и это чинит вторую половину
# дефекта (b), названного выше. Прежде «gone» снимал посторонний принципал, у
# которого 403/404 приходит независимо от того, существует ли строка, — то есть
# утверждение удовлетворялось скрытием существования, а не удалением. У надзора
# облака путь к строке есть всегда, поэтому его `404` означает ровно то, что
# кейс обещает: строки нет.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-DL-CRUD-OK",
    title="Delete a binding-free user as the cloud administrator → Operation SUCCEEDS, Get returns 404",
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
            auth="jwtBootstrap",
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
        get_until_gone("/iam/v1/users/{{delUserId}}", "User", auth="jwtBootstrap"),
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
            # Self-delete: the ceremony human always holds bindings — the ceremony seed
            # creates an account HE owns (`ceremonyAccountId`, stage 8б) before any
            # collection runs — so the RESTRICT guard is reached rather than the authz
            # gate. Deliberately not left to accumulate from other collections: that
            # would make the precondition depend on collection order.
            path="/iam/v1/users/{{ceremonyUserId}}",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "boundDelOpId"),
            ],
        ),
        # Polls as jwtHumanCeremony — inherited from the step that minted the operation.
        # Текст владельца ЦЕЛИКОМ: «has active access bindings and cannot be deleted»
        # несут отказы User, Group и ServiceAccount, и утверждение об общей части не
        # различало, ЧЕЙ отказ пришёл (#1748).
        assert_op_error(9, "FAILED_PRECONDITION",
                        msg_text="User {{ceremonyUserId}} has active access bindings "
                                 "and cannot be deleted",
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
#
# ДЕЙСТВУЮЩЕЕ ЛИЦО — АДМИНИСТРАТОР ОБЛАКА, и это изменение #1102, а не выбор
# удобной учётки. Строка `iam_user` — ГЛОБАЛЬНАЯ личность, одна на все аккаунты
# человека, поэтому её метки решают состав селекторных выдач в КАЖДОМ его
# аккаунте. Правка записи перестала быть правом уровня аккаунта: край гейтит её
# отношением `record_writer`, у которого нет ни пообъектной выдачи, ни
# администратора аккаунта, ни его владельца.
#
# Прежде здесь стоял `jwtAccountAdminA`, и кейс пиннил ровно то поведение,
# которое директива владельца запрещает. Он не удалён, а ПЕРЕНАЦЕЛЕН: путь
# правки обязан остаться проверенным — иначе «отказано всем» стало бы
# неотличимо от «работает у того, кому положено». Отказ распорядителю аккаунта
# утверждается отдельно — IAM-USR-GOV-NEG-ACCOUNT-ADMIN ниже.
#
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
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtBootstrap"),
        Step(
            name="get-confirms-labels",
            method="GET",
            path="/iam/v1/users/{{userAAAId}}",
            auth="jwtBootstrap",
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
            auth="jwtBootstrap",
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


# ---------------------------------------------------------------------------
# Административный запрет участию — `:block` / `:unblock`.
#
# ЧТО ЗДЕСЬ ЕСТЬ И ЧЕГО НЕТ, СКАЗАНО ПРЯМО.
#
# Через край закреплены: маршрут целиком (allowlist → каталог → scope-extractor →
# обработчик → use-case), отказ на неподтверждённом приглашении, отсутствующий id,
# анонимный вызов и кросс-аккаунтный отказ.
#
# Положительного пути (действующее членство → запрет → снятие) здесь НЕТ, и это
# открытый долг с числом: 1 сценарий. Причина не «сложно», а конкретная: ему нужно
# РАСХОДУЕМОЕ действующее членство внутри аккаунта, которым мы администрируем, а
# фикстура такого не сеет — каждому принципалу провизионируется его собственный
# домашний аккаунт, поэтому в accountA/accountB нет ни одного чужого действующего
# членства. Заблокировать принципала фикстуры нельзя: его токен перестанет
# работать, снять запрет он себе не сможет (самостоятельного пути нет
# by construction), и остаток прогона поедет на сломанной фикстуре. Наблюдаемый
# исход поэтому закреплён на настоящей базе и настоящих читателях выдачи
# (services/iam/internal/apps/kaname/api/audit/user_block_integration_test.go), а
# здесь — то, что через край проверяемо без порчи общего состояния.
#
# ПОЧЕМУ ОТКАЗ НА PENDING — НЕ СЛАБАЯ ПРОБА, А РАЗЛИЧАЮЩАЯ. Ответ
# FAILED_PRECONDITION не может прийти ни от промаха маршрута (404 без деталей), ни
# от промаха каталога (403 fail-closed с пустым action), ни от authz-отказа. Его
# может произвести ТОЛЬКО use-case, дошедший до синхронной проверки состояния, —
# то есть зелёный тут означает, что вся цепочка живая.
#
# Приглашение создаётся своё, со своим адресом: переиспользовать
# `invitedUserId` из IAM-USR-INV-CRUD-OK нельзя — порядок кейсов не контракт, а
# чужая фикстура, на которую наш отказ не должен опираться.
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# IAM-USR-BLK-NEG-PENDING — `:block` на неподтверждённом приглашении.
# verifies: маршрут действия живой целиком, и состояние решает синхронно.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-BLK-NEG-PENDING",
    title="Block a PENDING invitation → 400 FAILED_PRECONDITION \"is not active\" (route proven live)",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        *_invite_probe("blkPendingId", "blockprobe"),
        retry_until_authorized(Step(
            name="block-pending",
            method="POST",
            path="/iam/v1/users/{{blkPendingId}}:block",
            body={},
            # ЗДЕСЬ СТОЯЛ РАСПОРЯДИТЕЛЬ АККАУНТА, И ОН БОЛЬШЕ НЕ ДЕРЖИТ ЭТОГО
            # ПРАВА (#1102). Запрет пишется в состояние ГЛОБАЛЬНОЙ строки и
            # останавливает выдачу удостоверений человеку ВЕЗДЕ, поэтому
            # `iam_user.identity_suspender` источников уровня аккаунта не имеет:
            # круг — надзор облака, и только он.
            #
            # ПОЧЕМУ ЭТО НЕ ОСЛАБЛЕНИЕ, А ВОССТАНОВЛЕНИЕ ПРЕДМЕТА. Кейс утверждает,
            # что решает СОСТОЯНИЕ: `400`+`code=9`+«is not active». Отказ модели
            # (`403`+`code=7`) до состояния не доходит вовсе, то есть на прежнем
            # предъявителе кейс перестал проверять то, ради чего написан. Отказ
            # распорядителю аккаунта при этом НЕ потерян и утверждается по-прежнему —
            # `IAM-USR-GOV-NEG-ACCOUNT-ADMIN::identity-block-denied`, тем же
            # предъявителем `jwtAccountAdminAStepUp`.
            #
            # Порог повышения (`required_acr_min=2`) этому предъявителю не помеха и
            # не подделка: `grpcsrv.EvaluateStepUp` ПЕРВОЙ ветвью освобождает
            # машинного принципала до всякого сравнения acr, а `jwtBootstrap` —
            # служебная учётка кластерного администратора.
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("block-pending"),
                # 400/9 — единственный исход, который НЕЛЬЗЯ получить ни промахом
                # маршрута, ни промахом каталога, ни authz-отказом.
                #
                # Статус 400, а НЕ 412: край своего отображения ошибок не несёт
                # (mux собран без WithErrorHandler), поэтому статус выбирает
                # runtime.HTTPStatusFromCode, а она FAILED_PRECONDITION отдаёт
                # как 400 — намеренно, о чём говорит её собственный комментарий
                # в этой же ветке. 412 не производится краем ни для одного кода.
                # Различает валидацию и состояние здесь ПАРА (статус + code=9):
                # 400 сам по себе приходит и от INVALID_ARGUMENT.
                # Таблица целиком — api-conventions.md §«gRPC-код → HTTP-статус».
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                "pm.test('reason is the state, named in words', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('is not active');",
                "});",
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
        # Состояние не изменилось: отказ, у которого остался эффект, — не отказ.
        Step(
            name="pending-still-pending",
            method="GET",
            path="/iam/v1/users/{{blkPendingId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("pending-still-pending"),
                *assert_status(200),
                "pm.test('invite is still PENDING', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.inviteStatus, JSON.stringify(j)).to.eql('PENDING');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-UBK-NEG-PENDING — та же проба для обратного направления.
# Симметрия проверяется, а не предполагается: асимметрия между запретом и
# снятием — это дверь, которую оператор находит запертой в худший момент.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-UBK-NEG-PENDING",
    title="Unblock a PENDING invitation → 400 FAILED_PRECONDITION (activation is a different path)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        *_invite_probe("ubkPendingId", "unblockprobe"),
        retry_until_authorized(Step(
            name="unblock-pending",
            method="POST",
            path="/iam/v1/users/{{ubkPendingId}}:unblock",
            body={},
            # Надзор облака — по той же причине, что у парного кейса выше
            # (`identity_suspender` без источников уровня аккаунта, #1102); здесь
            # она не пересказывается, иначе заведутся два места об одном предмете.
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("unblock-pending"),
                # 400, не 412 — см. парный кейс выше и таблицу отображения в
                # api-conventions.md §«gRPC-код → HTTP-статус». Пара (статус,
                # code=9) — то, что отличает состояние от валидации.
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                "pm.test('reason is the state, named in words', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message || '', JSON.stringify(j)).to.include('is not active');",
                "});",
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-BLK-NEG-NOTFOUND — `:block` по корректному по форме, но отсутствующему id.
# Авторизация идёт до backend-валидации, поэтому 403 здесь так же защитим, как
# 404; чего быть не может — это 200.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-BLK-NEG-NOTFOUND",
    title="Block a well-formed but absent user id → 404 or scoped 403, never 200",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="block-absent",
            method="POST",
            path="/iam/v1/users/usr00000000000notfnd:block",
            body={},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("block-absent"),
                "pm.test('404 or 403, never 200', () => pm.expect(pm.response.code).to.be.oneOf([404, 403]));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('code 5 (NOT_FOUND) or 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code).to.be.oneOf([5, 7]));",
                # Голое «404 или 403» было бы тавтологией: оно держится и когда путь
                # написан с опечаткой, и когда записи в каталоге нет вовсе. Поэтому
                # при 403 требуется РАЗРЕШЁННОЕ действие в деталях: у промаха
                # каталога оно пустое (дескриптор строится раньше, чем известна
                # запись), у настоящего per-object отказа — названо.
                "pm.test('a 403 here is the per-object deny, not a permission-catalog miss', () => {",
                "  if (pm.response.code !== 403) { pm.expect(true).to.be.true; return; }",
                "  const det = (j && j.details) || [];",
                "  const info = det.find(d => (d['@type'] || '').includes('ErrorInfo')) || {};",
                "  const md = info.metadata || {};",
                "  pm.expect(md.action, 'empty action means the catalog had no entry for the method (misrouted path?): '"
                " + JSON.stringify(j)).to.eql('iam.users.block');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-BLK-AUTHZ-ANON-DENY — `:block` без аутентификации.
# Анонимность не может быть личностью: приостановить участие человека по
# распоряжению, за которое некого назвать, не должен уметь никто.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-BLK-AUTHZ-ANON-DENY",
    title="Block as anonymous → 401/403, never 200",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="block-anon",
            method="POST",
            path="/iam/v1/users/{{userAAAId}}:block",
            body={},
            auth=None,
            test_script=[
                *assert_answered("block-anon"),
                "pm.test('401 or 403, never 200', () => pm.expect(pm.response.code).to.be.oneOf([401, 403]));",
            ],
        ),
        Step(
            name="unblock-anon",
            method="POST",
            path="/iam/v1/users/{{userAAAId}}:unblock",
            body={},
            auth=None,
            test_script=[
                *assert_answered("unblock-anon"),
                "pm.test('401 or 403, never 200', () => pm.expect(pm.response.code).to.be.oneOf([401, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-BLK-NEG-CROSS-ACCOUNT — администратор аккаунта B запрещает участие в
# аккаунте A.
#
# Самый ценный негатив для нового объектного действия и вся причина, по которой у
# RPC есть scope-extractor: без него любой аутентифицированный, кто может назвать
# id, вышибал бы члена соседнего тенанта. Отказ в обслуживании соседу — низкая
# планка для атакующего и высокая для заметности: жертва видит, что человек
# перестал входить, и в своём аккаунте объяснения не находит.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-BLK-NEG-CROSS-ACCOUNT",
    title="Account B admin blocking an account A membership → scoped deny, victim untouched",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        *_invite_probe("crossVictimId", "crossprobe"),
        Step(
            name="cross-account-block-denied",
            method="POST",
            path="/iam/v1/users/{{crossVictimId}}:block",
            body={},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_answered("cross-account-block-denied"),
                *assert_scoped_authz_deny(
                    "iam.users.block",
                    "'iam_user:' + pm.environment.get('crossVictimId')",
                ),
            ],
        ),
        # И жертва не тронута — отказ, у которого остался эффект, не отказ. Это то
        # утверждение, которое отличает «отказали» от «отказали в квитанции».
        Step(
            name="victim-untouched",
            method="GET",
            path="/iam/v1/users/{{crossVictimId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-untouched"),
                *assert_status(200),
                "pm.test('the neighbour could not touch it: state unchanged', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.inviteStatus, JSON.stringify(j)).to.eql('PENDING');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-GOV-NEG-ACCOUNT-ADMIN — пригласивший распоряжается ПРАВАМИ, но не
# СТРОКОЙ ЛИЧНОСТИ (#1102, вторая половина директивы владельца 2026-08-23).
#
# Директива дословно: «тот кто пригласил может только удалить/добавить права».
#
# ПОЧЕМУ ПОЛОЖИТЕЛЬНОЕ ИДЁТ ПЕРВЫМ, А НЕ ДЛЯ ПОЛНОТЫ. Отказ, снятый в одиночку,
# зеленеет одинаково и на верном дереве, и на дереве, где у распорядителя аккаунта
# отняли всё. Поэтому кейс начинается с того, что директива ему ОСТАВЛЯЕТ:
# приглашение с ролью — это выдача прав, создаваемая атомарно со строкой
# приглашения, то есть ровно «добавить права» в своём аккаунте. Шаг несёт
# `assert_op_success`, поэтому «права выданы» утверждается ИСХОДОМ операции, а не
# фактом вызова.
#
# ЧТО ИМЕННО ОТКАЗЫВАЕТСЯ. Правка записи и запрет личности. Обе — распоряжение
# ГЛОБАЛЬНОЙ строкой: у человека она одна на все его аккаунты, поэтому метки
# решают состав селекторных выдач в каждом из них, а состояние решает вход на
# платформу целиком. Распорядитель ОДНОГО аккаунта, получив это право, решал бы
# за аккаунты, к которым отношения не имеет.
#
# ЖЕРТВА НЕ ТРОНУТА — отдельным шагом. Отказ, у которого остался эффект, не
# отказ; и тот же шаг несёт второй положительный контроль: ЧИТАТЬ своих людей
# распорядитель аккаунта по-прежнему вправе (`v_get` источники уровня аккаунта
# сохраняет намеренно). Если бы сужение задело чтение, кейс покраснел бы здесь.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-GOV-NEG-ACCOUNT-ADMIN",
    title="Пригласивший добавляет права в своём аккаунте — успех; правит запись "
          "человека и запрещает его — отказ",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        # ПОЛОЖИТЕЛЬНОЕ: «добавить права» — приглашение с ролью.
        *_invite_probe("govVictimId", "govprobe"),
        # ОТРИЦАНИЕ 1 — правка записи.
        Step(
            name="record-edit-denied",
            method="PATCH",
            path="/iam/v1/users/{{govVictimId}}",
            body={"labels": {"tier": "gold-{{runId}}"}, "updateMask": "labels"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("record-edit-denied"),
                *assert_scoped_authz_deny(
                    "iam.users.update",
                    "'iam_user:' + pm.environment.get('govVictimId')",
                ),
            ],
        ),
        # ОТРИЦАНИЕ 2 — запрет личности. Ступень доверия здесь ни при чём:
        # предъявитель несёт её (`jwtAccountAdminAStepUp`), поэтому отказ приходит
        # от модели прав, а не от порога acr — иначе кейс утверждал бы о пороге.
        Step(
            name="identity-block-denied",
            method="POST",
            path="/iam/v1/users/{{govVictimId}}:block",
            body={},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("identity-block-denied"),
                *assert_scoped_authz_deny(
                    "iam.users.block",
                    "'iam_user:' + pm.environment.get('govVictimId')",
                ),
            ],
        ),
        # ЖЕРТВА НЕ ТРОНУТА + чтение своих людей осталось.
        Step(
            name="victim-untouched-and-still-readable",
            method="GET",
            path="/iam/v1/users/{{govVictimId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-untouched-and-still-readable"),
                *assert_status(200),
                "pm.test('читать своих людей распорядитель аккаунта по-прежнему вправе', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('govVictimId'));",
                "});",
                "pm.test('состояние не изменилось: запрет не доехал', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.inviteStatus, JSON.stringify(j)).to.eql('PENDING');",
                "});",
                "pm.test('метки не изменились: правка не доехала', () => {",
                "  const j = pm.response.json();",
                "  const labels = j.labels || {};",
                "  pm.expect(labels.tier, JSON.stringify(j)).to.be.undefined;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-EXCL-CRUD-OK — распорядитель аккаунта ВЫВОДИТ человека из своего
# аккаунта, и человек при этом остаётся человеком (#1127).
#
# ПРЕДМЕТ. Вторая строка таблицы областей директивы владельца (2026-08-23): кто
# участвует в МОЁМ аккаунте — дело аккаунта. До этого изменения действия не было
# вовсе, и «исключить» выражалось снятием выдач: членство оставалось, человек
# оставался в списке людей аккаунта, а предел приёма продолжал его считать.
#
# ПАРА, А НЕ ОДИН ШАГ. Кейс утверждает ОБА конца: человека в аккаунте больше нет
# (список аккаунта его не показывает) И человек по-прежнему существует как
# личность (надзор облака читает его строку). Первое без второго зеленело бы и на
# дереве, где исключение стирает личность целиком, — то есть на дефекте, который
# #1131 закрывает соседним изменением.
#
# СПИСОК — ИМЕННО ТОТ ПРЕДИКАТ, который менялся: `UserService.List` сужается
# ЧЛЕНСТВАМИ, поэтому «его нет в списке аккаунта» есть наблюдаемое следствие
# снятой строки членства, а не пересказ того же вызова.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-EXCL-CRUD-OK",
    title="Пригласивший исключает человека из своего аккаунта: списка аккаунта он "
          "больше не в нём, а личность цела",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        # Свой расходуемый приглашённый: чужая фикстура сделала бы порядок кейсов
        # контрактом.
        #
        # БЕЗ ВЫДАЧИ, и это предмет, а не мелочь фикстуры. Предмет кейса —
        # ИСКЛЮЧЕНИЕ; приглашение с ролью завело бы вдобавок живую выдачу, а
        # членство, её несущее, страж `membership_carrying_rights_is_kept`
        # (миграция 472002) снять не даёт — кейс падал бы на порядке «сперва
        # права, потом участие», к его предмету отношения не имеющем. Сам
        # порядок утверждается там, где он и есть предмет:
        # IAM-USR-EXCL-NEG-LIVE-GRANT.
        *_invite_probe("exclVictimId", "exclprobe", with_grant=False),
        # ПРЕДПОСЫЛКА: он ДЕЙСТВИТЕЛЬНО в списке аккаунта. Без неё «его нет»
        # ниже истинно и на дереве, где список сломан целиком.
        Step(
            name="victim-is-listed-before",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-is-listed-before"),
                *assert_status(200),
                "pm.test('ПРЕДПОСЫЛКА: приглашённый есть в списке аккаунта', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.include(pm.environment.get('exclVictimId'));",
                "});",
            ],
        ),
        # ДЕЙСТВИЕ. Ступень доверия несётся предъявителем: порог acr=2 у этого RPC
        # тот же, что у приглашения и у отзыва выдачи, и кейс утверждает решение
        # МОДЕЛИ, а не порог.
        Step(
            name="exclude-from-account",
            method="POST",
            path="/iam/v1/users/{{exclVictimId}}:removeFromAccount",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("exclude-from-account"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        # Исход операции, а не факт вызова: предвыделенный id приезжает в
        # metadata и у операции, завершившейся ошибкой.
        assert_op_success(auth="jwtAccountAdminA"),
        # ПОЛОВИНА ПЕРВАЯ — его нет в аккаунте.
        Step(
            name="victim-is-not-listed-after",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-is-not-listed-after"),
                *assert_status(200),
                "pm.test('исключённого в списке аккаунта больше нет', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.not.include(pm.environment.get('exclVictimId'));",
                "});",
                "pm.test('КОНТРОЛЬ: список не опустел — снято одно членство, а не все', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.users || []).length, JSON.stringify(j)).to.be.above(0);",
                "});",
            ],
        ),
        # ПОЛОВИНА ВТОРАЯ — личность цела. Спрашивает НАДЗОР ОБЛАКА: у
        # распорядителя аккаунта после исключения нет пути к этой строке, и это
        # правильно, но тогда его отказ ничего не сказал бы о существовании.
        Step(
            name="identity-survived",
            method="GET",
            path="/iam/v1/users/{{exclVictimId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("identity-survived"),
                *assert_status(200),
                "pm.test('человек остался человеком: исключение сняло членство, не личность', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('exclVictimId'));",
                "});",
            ],
        ),
        # ИДЕМПОТЕНТНОСТЬ. Аргумент — ОТСУТСТВИЕ членства, а не переход:
        # направление, делающее систему строже, не может падать на повторе.
        Step(
            name="exclude-again-is-idempotent",
            method="POST",
            path="/iam/v1/users/{{exclVictimId}}:removeFromAccount",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("exclude-again-is-idempotent"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-EXCL-NEG-CROSS-ACCOUNT — исключать можно ИЗ СВОЕГО аккаунта, и область
# решения не выходит за его границу (#1127).
#
# Отрицание к кейсу выше и его необходимая половина: право, проверенное только
# положительно, зеленеет и на отношении, разрешающем всё.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-EXCL-NEG-CROSS-ACCOUNT",
    title="Распорядитель аккаунта A исключает из аккаунта B — отказ",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(
            name="cross-account-exclusion-denied",
            method="POST",
            path="/iam/v1/users/{{userINVId}}:removeFromAccount",
            body={"accountId": "{{accountBId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("cross-account-exclusion-denied"),
                *assert_scoped_authz_deny(
                    "iam.users.removeFromAccount",
                    "'account:' + pm.environment.get('accountBId')",
                ),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-EXCL-NEG-LIVE-GRANT — членство, несущее ЖИВУЮ ВЫДАЧУ, не снимается:
# порядок «сперва права, потом участие» (#1127, миграция 472002).
#
# ПОЧЕМУ ЭТОТ КЕЙС ЗАВЕДЁН. До него это поведение через край не проверялось
# НИЧЕМ. Оно закрыто пробой репозитория
# (`TestIntegration_MembershipCarryingRightsIsRefusedWithContractTone`), но она
# судит СНЯТИЕ СТРОКИ, а не то, что видит вызывающий: между стражем и ответом
# лежат два слоя, каждый со своим способом разъехаться молча, —
# отображение 23000 → FAILED_PRECONDITION с контракт-тоном
# (`repo/kaname/pg/pgmaperr.go`) и доставка отказа ИСХОДОМ ОПЕРАЦИИ, а не
# синхронным кодом (страж отложенный, он срабатывает на КОММИТЕ). Проба
# репозитория остаётся зелёной при любом расхождении в обоих.
#
# ПОЧЕМУ ОН ПОЯВЛЯЕТСЯ ВМЕСТЕ С ПРАВКОЙ ФИКСТУР. Положительные плечи
# IAM-USR-EXCL-CRUD-OK и IAM-USR-RMID-NEG-ACCOUNT-ADMIN переведены на жертву БЕЗ
# выдачи — иначе они падают на страже, к их предмету отношения не имеющем.
# Перенос без этого кейса просто СНЯЛ БЫ покрытие: страж перестал бы
# срабатывать хоть где-нибудь на пути через край.
#
# ПАРА НА ОДНОЙ ПЕРЕМЕННОЙ. Плечи различаются РОВНО ОДНИМ — наличием живой
# выдачи; аккаунт, предъявитель, глагол и предикат наблюдения у них общие.
# Поэтому «отказано» здесь не может пройти на дереве, где исключение сломано
# для всех: второе плечо тем же вызовом проходит. Обратное тоже верно — успех
# второго плеча не зачитывается за работоспособность стража, его утверждает
# первое.
#
# УЧАСТИЕ СОХРАНЕНО — ОТДЕЛЬНОЕ УТВЕРЖДЕНИЕ. Отказ, у которого остался эффект,
# отказом не является; страж отложенный, поэтому строка членства успевает быть
# удалённой ВНУТРИ транзакции и возвращается только откатом. Наблюдается тем же
# предикатом, что и в положительном кейсе: `UserService.List` сужается
# ЧЛЕНСТВАМИ, значит «он всё ещё в списке аккаунта» есть следствие уцелевшей
# строки, а не пересказ того же вызова.
#
# ОТКАЗ НАЗЫВАЕТ ИМЕННО ЭТОГО ЧЕЛОВЕКА И ИМЕННО ЭТОТ АККАУНТ. Страж — триггер:
# он срабатывает на коммите, и назвать пару в тексте можно только тем, что
# писатель оставил в подсказке (`userWriter.RemoveMembership` →
# `splitBindingHint`). Утверждение формы текста этого не ловит: пустая подсказка
# даёт ЗАКОННЫЙ обобщённый текст той же ветви, и он прошёл бы. Поэтому пара
# идентификаторов сверяется с переменными окружения.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-EXCL-NEG-LIVE-GRANT",
    title="Исключение из аккаунта человека с живой выдачей — отказ FAILED_PRECONDITION (9) "
          "с контракт-тоном, участие сохранено; без выдачи то же исключение проходит",
    classes=["NEG", "CRUD"],
    priority="P0",
    steps=[
        # ── ПЛЕЧО ОТКАЗА: жертва С живой выдачей ─────────────────────────────
        # `with_grant=True` (умолчание) — приглашение с парой «проект + роль»
        # заводит членство И выдачу на проект аккаунта A, то есть ровно то
        # состояние, которое страж охраняет.
        *_invite_probe("holdVictimId", "holdprobe"),
        # ПРЕДПОСЫЛКА: он ДЕЙСТВИТЕЛЬНО в аккаунте. Без неё «участие сохранено»
        # ниже истинно и на дереве, где приглашение членства не завело вовсе.
        Step(
            name="granted-victim-is-listed-before",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("granted-victim-is-listed-before"),
                *assert_status(200),
                "pm.test('ПРЕДПОСЫЛКА: приглашённый с выдачей есть в списке аккаунта', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.include(pm.environment.get('holdVictimId'));",
                "});",
            ],
        ),
        Step(
            name="exclude-while-grant-is-live",
            method="POST",
            path="/iam/v1/users/{{holdVictimId}}:removeFromAccount",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("exclude-while-grant-is-live"),
                # Отказ приходит ИСХОДОМ ОПЕРАЦИИ, а не синхронным кодом: страж
                # отложенный и срабатывает на коммите — то есть уже внутри
                # асинхронного шага. Синхронный ответ здесь обязан быть 200 с
                # конвертом операции, и это утверждается, чтобы «отказ» не
                # зачёлся за отказ КРАЯ.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        # ПАРА: код, машинный признак полосы И текст.
        #
        # ТЕКСТ ПРИБИТ ЦЕЛИКОМ, а не подстрокой, и причина прежняя: обобщённая
        # ветвь той же карты («user still has active access bindings in this
        # account…») подстроку содержит, поэтому подстрока прошла бы на
        # потерянной подсказке.
        #
        # ХВОСТ ПЕРЕЧНЯ — ЧАСТЬ ОБЕЩАНИЯ, А НЕ УКРАШЕНИЕ. Контракт
        # RemoveFromAccount обещает отказ «with the grants named»; до #1686 у
        # обещания не было исполнителя, и текст обрывался на аккаунте. Регексп
        # поэтому ТРЕБУЕТ хотя бы одного названного идентификатора выдачи:
        # снимут перечень — кейс покраснеет, и это ровно тот исход, ради
        # которого он пишется.
        #
        # ВЕЛИЧИНА ПЕРЕЧНЯ НЕ ПРИБИВАЕТСЯ ЧИСЛОМ (`\d+`, не `1`). Сколько выдач
        # заводит приглашение — свойство ФИКСТУРЫ, а не предмета: предмет в том,
        # что выдачи НАЗВАНЫ. Прибей единицу — и кейс станет краснеть на правке
        # фикстуры, к его утверждению отношения не имеющей.
        #
        # ПРИЗНАК — ТО, НА ЧЁМ КЛЮЧУЕТСЯ КЛИЕНТ. Тон message остаётся контрактом
        # и меняется осознанно; `reason` от языка и тона не зависит вовсе,
        # поэтому пара «код + признак» есть машинная половина утверждения, а
        # регексп — человеческая.
        assert_op_error(
            9, "FAILED_PRECONDITION",
            reason="MEMBERSHIP_CARRIES_RIGHTS",
            msg_regex=r"^User usr[a-z0-9]+ still has active access bindings in "
                      r"Account acc[a-z0-9]+ and cannot be removed from it: "
                      r"acb[a-z0-9]+(, acb[a-z0-9]+)* \(\d+ total\); "
                      r"revoke them before removing the membership$",
        ),
        # Пара идентификаторов — ТА САМАЯ. Операция уже `done` (шаг выше довёл
        # её поллингом), поэтому чтение одиночное.
        Step(
            name="refusal-names-this-user-and-this-account",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("refusal-names-this-user-and-this-account"),
                *assert_status(200),
                "pm.test('отказ называет ЭТОГО человека и ЭТОТ аккаунт', () => {",
                "  const j = pm.response.json();",
                "  const m = (j.error && j.error.message) || '';",
                "  pm.expect(m, JSON.stringify(j)).to.include(pm.environment.get('holdVictimId'));",
                "  pm.expect(m, JSON.stringify(j)).to.include(pm.environment.get('accountAId'));",
                "});",
                # ПРОЗА И МАШИННАЯ ПОЛОВИНА ГОВОРЯТ ОБ ОДНОМ. Перечень уезжает
                # дважды — текстом и в `metadata` признака, — то есть это два
                # места об одном предмете, и разойтись они могут молча: клиент,
                # читающий признак, получил бы один набор, читающий текст —
                # другой, и ни одна проба по отдельности этого не увидела бы.
                #
                # Утверждение НЕ ЗНАЕТ фикстуры: оно не называет ни одного
                # идентификатора и не считает их. Спрашивается ровно
                # согласованность — каждый названный машинно обязан стоять и в
                # тексте, — поэтому оно переживает любую правку приглашения.
                "pm.test('машинный перечень выдач и текст называют одни и те же выдачи', () => {",
                "  const j = pm.response.json();",
                "  const m = (j.error && j.error.message) || '';",
                "  const ds = (j.error && j.error.details) || [];",
                "  const ei = ds.find(d => d && d.reason === 'MEMBERSHIP_CARRIES_RIGHTS');",
                "  pm.expect(ei, 'признак полосы обязан быть в деталях: ' + JSON.stringify(j)).to.be.an('object');",
                "  const ids = ((ei.metadata || {}).blocking_binding_ids || '').split(',').filter(Boolean);",
                "  pm.expect(ids, 'перечень мешающих выдач пуст — обещание контракта без исполнителя: ' + JSON.stringify(j)).to.not.be.empty;",
                "  ids.forEach(id => pm.expect(m, 'машинно назван ' + id + ', а в тексте его нет: ' + JSON.stringify(j)).to.include(id));",
                "  const cnt = parseInt((ei.metadata || {}).blocking_binding_count || '0', 10);",
                "  pm.expect(cnt, 'величина перечня обязана быть не меньше числа названных: ' + JSON.stringify(j)).to.be.at.least(ids.length);",
                "});",
            ],
        ),
        # УЧАСТИЕ СОХРАНЕНО: отказ, у которого остался эффект, не отказ.
        Step(
            name="membership-survived-the-refusal",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("membership-survived-the-refusal"),
                *assert_status(200),
                "pm.test('отвергнутое исключение участия не сняло', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.include(pm.environment.get('holdVictimId'));",
                "});",
            ],
        ),
        # ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: та же полоса, жертва БЕЗ выдачи ──────────
        # Тот же аккаунт, тот же предъявитель, тот же глагол. Единственное
        # отличие — отсутствие живой выдачи, и его достаточно, чтобы исключение
        # прошло. Без этого плеча отказ выше был бы неотличим от дерева, где
        # исключение не работает ни для кого.
        *_invite_probe("freeVictimId", "freeprobe", with_grant=False),
        Step(
            name="exclude-without-a-grant",
            method="POST",
            path="/iam/v1/users/{{freeVictimId}}:removeFromAccount",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("exclude-without-a-grant"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),
        Step(
            name="ungranted-victim-is-not-listed-after",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("ungranted-victim-is-not-listed-after"),
                *assert_status(200),
                "pm.test('КОНТРОЛЬ: без выдачи исключение состоялось', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.not.include(pm.environment.get('freeVictimId'));",
                "});",
                "pm.test('КОНТРОЛЬ: снято одно членство, а не все — держатель выдачи на месте', () => {",
                "  const j = pm.response.json();",
                "  const ids = (j.users || []).map(u => u.id);",
                "  pm.expect(ids, JSON.stringify(j)).to.include(pm.environment.get('holdVictimId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-RMID-NEG-ACCOUNT-ADMIN — распорядитель аккаунта НЕ стирает строку
# личности, а выводит человека из своего аккаунта (#1131).
#
# ПРЕДМЕТ. Строка `iam_user` — ГЛОБАЛЬНАЯ личность: одна на все аккаунты
# человека. Удаление её из аккаунта A стирает человека и в аккаунте B — он теряет
# личность целиком, а не участие в одном тенанте. Это строго тяжелее запрета,
# который #1102 из рук аккаунта уже забрал: запрет обратим, удаление нет.
#
# ПОЛОЖИТЕЛЬНОЕ ИДЁТ ВТОРЫМ И ЗАМЫКАЕТ ПАРУ: тот же распорядитель тем же
# предъявителем делает то, что директива ему ОСТАВЛЯЕТ, — исключает человека из
# своего аккаунта. Без этой половины «отказано» было бы неотличимо от дерева, где
# у распорядителя аккаунта отняли всё.
#
# ЗАГОЛОВОК НАЗЫВАЕТ ОБА ИСХОДА, И ЭТО НЕСУЩЕЕ, А НЕ СТИЛЬ (#1178). Гейт смешанного
# исхода (`tools/mixedoutcomeaudit/`) читает направление кейса ПО ЗАГОЛОВКУ, и кейс,
# объявивший себя отрицательным токеном `-NEG-`, обязан читаться хоть одним словом
# направления: пока не читается, пустая корзина REJECT означает «не умею прочитать»,
# а не «чисто». Прежний заголовок («не стирает … ему остаётся») не называл НИ ОДНОГО
# исхода и ронял задание конвейера. Перепись, по которой правился именно заголовок, а
# не словарь: в этом файле 24 объявленно отрицательных кейса, 23 из них читаются
# словом В ЗАГОЛОВКЕ (коды 400/401/403/404, `deny`, «отказ», «запрещ», «не получ»), и
# ни один — токеном идентификатора; этот был единственным исключением. Оборот «не
# стирает» при этом сохранён: он и есть предмет кейса.
#
# ЧИТАЕТСЯ КАК BOTH — и это верно по существу: кейс обещает ОБА исхода (отказ на
# снятие личности, успех на исключение из аккаунта). Приписать ему чистый REJECT
# значило бы объявить его положительное плечо нарушением собственной метки.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-RMID-NEG-ACCOUNT-ADMIN",
    title="Пригласивший не стирает строку личности — отказ; исключение из своего "
          "аккаунта проходит",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        # БЕЗ ВЫДАЧИ: положительное плечо ниже ИСКЛЮЧАЕТ этого человека из
        # аккаунта, а членство с живой выдачей не снимается (страж
        # `membership_carrying_rights_is_kept`, миграция 472002). Отрицательное
        # плечо от роли не зависит вовсе — оно про право снять ЛИЧНОСТЬ.
        *_invite_probe("rmidVictimId", "rmidprobe", with_grant=False),
        # ОТРИЦАНИЕ — снятие ЛИЧНОСТИ.
        Step(
            name="identity-delete-denied",
            method="DELETE",
            path="/iam/v1/users/{{rmidVictimId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("identity-delete-denied"),
                *assert_scoped_authz_deny(
                    "iam.users.delete",
                    "'iam_user:' + pm.environment.get('rmidVictimId')",
                ),
            ],
        ),
        # ЖЕРТВА НЕ ТРОНУТА: отказ, у которого остался эффект, не отказ.
        Step(
            name="victim-still-exists",
            method="GET",
            path="/iam/v1/users/{{rmidVictimId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-still-exists"),
                *assert_status(200),
                "pm.test('строка личности на месте: удаление не доехало', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('rmidVictimId'));",
                "});",
            ],
        ),
        # ПОЛОЖИТЕЛЬНОЕ — то, что директива распорядителю ОСТАВЛЯЕТ.
        Step(
            name="exclusion-is-what-he-keeps",
            method="POST",
            path="/iam/v1/users/{{rmidVictimId}}:removeFromAccount",
            body={"accountId": "{{accountAId}}"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("exclusion-is-what-he-keeps"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# IAM-ID-1-01 / -02 / -06 — один человек есть ОДНА строка, в скольких бы
# аккаунтах он ни состоял (задачи kacho#470 / #981).
#
# ПОЧЕМУ ЭТОТ КЕЙС СУЩЕСТВУЕТ. До отрыва приглашение известной почты во второй
# аккаунт заводило ВТОРУЮ строку: второй идентификатор, второй набор прав, и
# активировать из них можно было только одну — вторая оставалась неактивируемой
# навсегда, а выданное на неё право осиротевшим. Снаружи это выглядело
# исправным: обе операции завершались успехом.
#
# ЧЕМ ЧЛЕНСТВО НАБЛЮДАЕТСЯ ЧЕРЕЗ КРАЙ, ПОКА У НЕГО НЕТ СВОЕГО РЕСУРСА. Публичного
# списка членств ещё нет (он приезжает вместе с переездом глагола приглашения).
# Но список пользователей сужается ИМЕННО ЧЛЕНСТВАМИ, поэтому «человек состоит в
# обоих аккаунтах» наблюдаемо так: ОДИН И ТОТ ЖЕ идентификатор приходит в списке
# аккаунта A и в списке аккаунта B. Двум строкам это дало бы два разных
# идентификатора, и утверждение равенства покраснело бы.
#
# ОТРИЦАНИЕ — СОСТАВОМ, А НЕ ФАКТОМ ВЫЗОВА. Отдельно утверждается, что строк с
# этой почтой в списке аккаунта РОВНО ОДНА: без этого «идентификаторы совпали»
# прошло бы и на дереве, которое завело вторую строку и вернуло первую.
#
# ПОВТОР СТОИТ ТОЛЬКО НА ПОЛОЖИТЕЛЬНЫХ ПЛЕЧАХ. Список — первый доступ к своему
# свежему ресурсу, и окно материализации прав к нему относится; отрицание
# («второй строки нет») повтором НЕ оборачивается — там повтор пережидал бы ровно
# то, ради чего кейс написан.
_DUAL_EMAIL = "dual-{{runId}}@kacho.local"

CASES.append(Case(
    id="IAM-USR-IDENTITY-GLOBAL-TWO-ACCOUNTS",
    title="Один человек, приглашённый в ДВА аккаунта, — одна строка и один "
          "идентификатор; он виден в списках обоих аккаунтов",
    classes=["CRUD", "IDEM", "NEG"],
    priority="P0",
    steps=[
        # ── 1. приглашение в аккаунт A ───────────────────────────────────────
        Step(
            name="dual-invite-account-a",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": _DUAL_EMAIL},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="dual-capture-user-from-a",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('[dual] приглашение в A завершилось без отказа', () => "
                "pm.expect(j.error, JSON.stringify(j)).to.eql(undefined));",
                "pm.test('[dual] ответ несёт строку человека', () => {",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j)).to.match(/^usr[a-z0-9]+$/);",
                "});",
                *save_from_response("j.response && j.response.id", "dualUserFromA"),
            ],
        ),
        # ── 2. та же почта в аккаунт B, ДРУГИМ администратором ───────────────
        Step(
            name="dual-invite-account-b",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountBId}}", "email": _DUAL_EMAIL},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="dual-second-account-reuses-the-same-row",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('[dual] приглашение во ВТОРОЙ аккаунт завершилось без отказа', () => "
                "pm.expect(j.error, JSON.stringify(j)).to.eql(undefined));",
                "const fromA = pm.environment.get('dualUserFromA');",
                # Страж фикстуры: без первого идентификатора сравнение ниже
                # выродилось бы в сравнение с undefined и зеленело бы всегда.
                "pm.test('[dual] фикстура принесла идентификатор из первого приглашения', () => "
                "pm.expect(Boolean(fromA), 'dualUserFromA пуст').to.eql(true));",
                "pm.test('[dual] IAM-ID-1-01: идентификатор человека ТОТ ЖЕ в обоих аккаунтах', () => {",
                "  pm.expect(j.response && j.response.id, 'второе приглашение вернуло ДРУГУЮ строку: "
                "человек задвоился, и активировать можно будет только одну из них. Ответ: ' "
                "+ JSON.stringify(j)).to.eql(fromA);",
                "});",
            ],
        ),
        # ── 3. он виден в списке аккаунта A ──────────────────────────────────
        poll_request_until_status(
            name="dual-visible-in-account-a",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            retry_predicate="!(pm.response.json().users || []).some("
                            "r => r.id === pm.environment.get('dualUserFromA'))",
            test_script=[
                *assert_status(200),
                "const rows = pm.response.json().users || [];",
                "const want = pm.environment.get('dualUserFromA');",
                "pm.test('[dual] человек виден в списке аккаунта A', () => "
                "pm.expect(rows.some(r => r.id === want), JSON.stringify(rows.map(r => r.id)))"
                ".to.eql(true));",
                # ОТРИЦАНИЕ СОСТАВОМ — без повтора. Строка с этой почтой обязана
                # быть ровно одна: две означали бы, что отрыв не состоялся, а
                # равенство идентификаторов выше это скрыло бы.
                "pm.test('[dual] IAM-ID-1-06: строк с этой почтой ровно одна', () => {",
                "  const same = rows.filter(r => (r.email || '').toLowerCase() "
                "=== pm.environment.get('dualEmailLower'));",
                "  pm.expect(same.map(r => r.id), 'строк с почтой приглашённого больше одной: "
                "глобальный ключ идентичности не держит').to.have.lengthOf(1);",
                "});",
            ],
            pre_script=[
                "pm.environment.set('dualEmailLower', "
                "('dual-' + pm.environment.get('runId') + '@kacho.local').toLowerCase());",
            ],
        ),
        # ── 4. и в списке аккаунта B — то есть членств ДВА ───────────────────
        poll_request_until_status(
            name="dual-visible-in-account-b",
            method="GET",
            path="/iam/v1/users?accountId={{accountBId}}&pageSize=1000",
            auth="jwtAccountAdminB",
            retry_predicate="!(pm.response.json().users || []).some("
                            "r => r.id === pm.environment.get('dualUserFromA'))",
            test_script=[
                *assert_status(200),
                "const rows = pm.response.json().users || [];",
                "const want = pm.environment.get('dualUserFromA');",
                "pm.test('[dual] IAM-ID-1-01: ТОТ ЖЕ человек виден и в списке аккаунта B — "
                "значит членств у него два', () => "
                "pm.expect(rows.some(r => r.id === want), JSON.stringify(rows.map(r => r.id)))"
                ".to.eql(true));",
            ],
        ),
        # ── 5. уборка за собой ───────────────────────────────────────────────
        Step(
            name="dual-cleanup",
            method="DELETE",
            path="/iam/v1/users/{{dualUserFromA}}",
            # Снятие строки личности — не право аккаунта (#1131,
            # `iam_user.identity_remover`). Уборка за собой обязана идти тем, кто
            # это право держит, иначе она молча не убирает: отказ пришёл бы на
            # шаг, чей предмет — вовсе не модель прав.
            auth="jwtBootstrap",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-TOK-ACTAS-* — «действовать ОТ ИМЕНИ человека» и «править его запись» —
# РАЗНЫЕ права (задача kacho#1086).
#
# ПРЕДМЕТ. Персональный токен делает предъявителя САМИМ ЧЕЛОВЕКОМ: всюду, где
# действует он, и во всех аккаунтах, где он состоит. Пока выпуск гейтился тем же
# отношением, что и правка записи, право выступать от чужого имени приезжало
# всякому держателю обычной выдачи внутри аккаунта — в том числе тому, кто
# человека всего лишь пригласил.
#
# ПОЧЕМУ ПАРА, А НЕ ОДНО ОТРИЦАНИЕ. Запрет, снятый в одиночку, зеленеет и на
# сломанной чеканке: «никто не может» неотличимо от «никому и не положено».
# Поэтому рядом — положительная половина: сам человек выпускает и отзывает свой
# токен. Ей нужен предъявитель, принадлежащий ЧЕЛОВЕКУ, поэтому она идёт волной
# церемонии (`tests/authz-fixtures/ceremony_credentials.py`) — как и остальные
# кейсы этого файла, которым нужен `jwtHumanCeremony*`.
#
# ЧТО ЭТИ КЕЙСЫ НЕ УТВЕРЖДАЮТ. Правку ЗАПИСИ приглашённого (имя, метки,
# состояние) администратор аккаунта по-прежнему держит — это отдельный предмет с
# отдельным размером, и здесь он не трогается. Утверждать здесь «правка тоже
# отказана» значило бы описывать дерево, которого нет.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-TOK-ACTAS-NEG-INVITER",
    title="Пригласивший добавляет права приглашённому — успех; выпустить и отозвать "
          "его персональный токен — отказ (действие от имени ≠ правка записи)",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        # ПОЛОЖИТЕЛЬНАЯ ПОЛОВИНА — способность, которая обязана УЦЕЛЕТЬ.
        # Приглашение с ролью и есть «добавить права»: тот же администратор
        # аккаунта, та же ручка, что и в соседних кейсах файла. Без этого шага
        # отказы ниже неотличимы от «у этого предъявителя вообще нет доступа».
        *_invite_probe("actAsInvitedUserId", "actas-invitee"),
        Step(
            name="inviter-issues-token-for-the-invited-person",
            method="POST",
            path="/iam/v1/users/{{actAsInvitedUserId}}/tokens",
            auth="jwtAccountAdminAStepUp",
            body={
                "userId": "{{actAsInvitedUserId}}",
                "createdByUserId": "{{actAsInvitedUserId}}",
                "description": "actas probe {{runId}}",
                "name": "actas-{{runId}}",
            },
            test_script=[
                *assert_answered("UserTokenService.Issue от пригласившего"),
                "pm.test('пригласивший НЕ выпускает персональный токен приглашённого: "
                "удостоверение действует всюду, где действует человек, включая аккаунты, "
                "к которым пригласивший отношения не имеет', "
                "() => pm.expect(pm.response.code, pm.response.text()).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('отказ назван кодом PERMISSION_DENIED, а не подменён иным исходом', "
                "() => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
        Step(
            name="inviter-revokes-token-of-the-invited-person",
            method="DELETE",
            # Идентификатор токена намеренно вымышленный: решение принимает КРАЙ,
            # по объекту личности из адреса, ДО того как сервис увидит запрос.
            # Настоящий токен здесь пришлось бы сперва выпустить — тем самым
            # действием, которое кейс объявляет невозможным.
            path="/iam/v1/users/{{actAsInvitedUserId}}/tokens/uoc00000000000000act",
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("UserTokenService.Revoke от пригласившего"),
                "pm.test('пригласивший НЕ отзывает персональный токен приглашённого — "
                "это та же полоса, что и выпуск', "
                "() => pm.expect(pm.response.code, pm.response.text()).to.equal(403));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('отказ назван кодом PERMISSION_DENIED', "
                "() => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-USR-TOK-ACTAS-POS-SELF",
    title="Сам человек выпускает и отзывает СВОЙ персональный токен "
          "(положительная половина запрета выше)",
    classes=["AUTHZ", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="self-issues-own-token",
            method="POST",
            path="/iam/v1/users/{{ceremonyUserId}}/tokens",
            auth="jwtHumanCeremonyStepUp",
            body={
                "userId": "{{ceremonyUserId}}",
                "createdByUserId": "{{ceremonyUserId}}",
                "description": "actas self probe {{runId}}",
                "name": "actas-self-{{runId}}",
            },
            test_script=[
                *assert_answered("UserTokenService.Issue самому себе"),
                "pm.test('человек выпускает СВОЙ токен: удостоверение принадлежит ему, "
                "и запрет на чужой выпуск не имеет права отнимать собственный', "
                "() => pm.expect(pm.response.code, pm.response.text()).to.equal(200));",
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                # Идентификатор берётся из metadata, где он предвыделен ДО
                # асинхронного исхода, — поэтому ниже стоит проверка самого исхода,
                # а не только `done`.
                *save_from_response("j.metadata && j.metadata.keyId", "actAsSelfTokenId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        Step(
            name="self-revokes-own-token",
            method="DELETE",
            path="/iam/v1/users/{{ceremonyUserId}}/tokens/{{actAsSelfTokenId}}",
            auth="jwtHumanCeremonyStepUp",
            test_script=[
                *assert_answered("UserTokenService.Revoke своего токена"),
                "pm.test('человек отзывает СВОЙ токен', "
                "() => pm.expect(pm.response.code, pm.response.text()).to.equal(200));",
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
    ],
))


# ---------------------------------------------------------------------------
# IAM-USR-TOK-READ-* — ВИДЕТЬ перечень удостоверений человека вправе он сам, а не
# распорядитель его аккаунта (задача kacho#1133).
#
# ПРЕДМЕТ. Третья сторона той же директивы владельца (2026-08-23), что закрыли
# #1086 (выпуск и отзыв) и #1102 (правка строки личности): «тот кто пригласил
# может только удалить/добавить права». Перечень персональных токенов — не право
# на аккаунт, а СВЕДЕНИЯ О ЛИЧНОСТИ: сколько удостоверений живо, когда выпущены,
# когда истекают, чем названы. Раскрытие сведений — тоже действие за человека.
#
# Личность здесь ГЛОБАЛЬНА: одна строка на все аккаунты человека, а звено
# «личность → аккаунт» вердикт берёт из членства, которых у него может быть
# несколько. Значит право уровня ОДНОГО аккаунта раскрывало бы удостоверения
# человека целиком — включая те, которыми он действует там, куда держатель этого
# права не вхож.
#
# ЧТО ЗДЕСЬ ЧЕМУ КОНТРОЛЬ, СКАЗАНО ПРЯМО. Отрицание, снятое в одиночку, зеленеет
# и на сломанном чтении: «никто не видит» неотличимо от «никому и не положено».
# Поэтому:
#   * IAM-USR-TOK-READ-POS-SELF — положительная половина обоих отрицаний: чтение
#     ПРОДОЛЖАЕТ работать у того, кому оно принадлежит, и возвращает именно тот
#     токен, который человек только что выпустил;
#   * у каждого отрицания СВОЙ контроль внутри кейса — шаг, доказывающий, что
#     отказанный предъявитель имеет к этому человеку и этому аккаунту настоящий
#     доступ. Без него «403» неотличимо от «у него вообще ничего нет».
#
# ПОЧЕМУ У ЦЕЛИ ОТРИЦАНИЙ НЕТ СВОИХ ТОКЕНОВ, И ПОЧЕМУ ЭТО НИЧЕГО НЕ ОСЛАБЛЯЕТ.
# Цель — свежеприглашённый человек, у которого предъявителя нет by construction:
# приглашение это не учётные данные. Решение о доступе принимает КРАЙ, по объекту
# личности из адреса, ДО того как служба увидит запрос, — поэтому наличие или
# отсутствие строк в перечне на исход не влияет. Ровно тем же рассуждением
# пользуется соседний IAM-USR-TOK-ACTAS-NEG-INVITER с вымышленным токеном.
#
# ЧЕГО ЭТИ КЕЙСЫ НЕ УТВЕРЖДАЮТ. Чтение ЗАПИСИ приглашённого (`UserService.Get`) и
# перечень людей аккаунта распорядитель по-прежнему держит — видеть своих людей
# законное дело аккаунта. Это не забыто, а намеренно: контроль первого отрицания
# на этом и стоит.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-USR-TOK-READ-POS-SELF",
    title="Человек видит СВОЙ перечень персональных токенов и находит в нём только что "
          "выпущенный (положительная половина запретов ниже)",
    classes=["AUTHZ", "CRUD"],
    priority="P0",
    steps=[
        Step(
            name="read-self-issues-own-token",
            method="POST",
            path="/iam/v1/users/{{ceremonyUserId}}/tokens",
            auth="jwtHumanCeremonyStepUp",
            body={
                "userId": "{{ceremonyUserId}}",
                "createdByUserId": "{{ceremonyUserId}}",
                "description": "read probe {{runId}}",
                "name": "read-self-{{runId}}",
            },
            test_script=[
                *assert_answered("UserTokenService.Issue самому себе (фикстура чтения)"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                # Идентификатор берётся из metadata, где он предвыделен ДО
                # асинхронного исхода, — поэтому следующим шагом стоит проверка
                # самого исхода, а не только `done`.
                *save_from_response("j.metadata && j.metadata.keyId", "readSelfTokenId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Первое чтение СВОЕГО свежего ресурса — законное место ограниченного
        # ожидания: строка токена коммитится своей операцией, и её появление
        # гарантировано. На отрицания ниже ожидание НЕ ставится: там оно было бы
        # маскировкой отказа.
        poll_request_until_status(
            name="read-self-lists-own-tokens",
            method="GET",
            path="/iam/v1/users/{{ceremonyUserId}}/tokens?pageSize=1000",
            auth="jwtHumanCeremony",
            retry_predicate="(() => { const j = pm.response.json();"
                            " const id = pm.environment.get('readSelfTokenId');"
                            " return !!id && !(j.tokens || []).some(t => t.id === id); })()",
            test_script=[
                *assert_answered("UserTokenService.List своего перечня"),
                *assert_status(200),
                "pm.test('человек ВИДИТ свой перечень удостоверений: сужение чтения не имеет "
                "права отнимать у владельца обзор собственных ключей — идентификатор выданного "
                "существует ровно один раз, в ответе на выпуск, и без перечня отзыв стал бы "
                "недостижим', () => {",
                "  const j = pm.response.json();",
                "  const id = pm.environment.get('readSelfTokenId');",
                "  pm.expect(id, 'фикстура не захватила идентификатор выпущенного токена')"
                ".to.be.a('string').with.length.greaterThan(0);",
                "  pm.expect((j.tokens || []).map(t => t.id), JSON.stringify(j)).to.include(id);",
                "});",
                "pm.test('перечень отдаёт только метаданные — приватной части в нём нет', () => {",
                "  const raw = pm.response.text();",
                "  pm.expect(raw).to.not.include('PRIVATE KEY');",
                "  pm.expect(raw).to.not.include('privateKeyPem');",
                "});",
            ],
        ),
        Step(
            name="read-self-revokes-own-token",
            method="DELETE",
            path="/iam/v1/users/{{ceremonyUserId}}/tokens/{{readSelfTokenId}}",
            auth="jwtHumanCeremonyStepUp",
            test_script=[
                *assert_answered("UserTokenService.Revoke своего токена (уборка за собой)"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
    ],
))


CASES.append(Case(
    id="IAM-USR-TOK-READ-NEG-ACCOUNT-ADMIN",
    title="Распорядитель аккаунта видит своих людей, но перечень персональных токенов "
          "приглашённого им человека НЕ получает",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        *_invite_probe("readInvitedUserId", "read-invitee"),
        # КОНТРОЛЬ. Доказывает сразу два условия, без которых отказ ниже ничего не
        # значит: предъявитель распорядителя жив, и человек, чей перечень у него
        # запрашивается, ДЕЙСТВИТЕЛЬНО состоит в аккаунте, которым тот
        # распоряжается. Именно это членство и давало прежде право читать его
        # удостоверения — через каскад распорядителя аккаунта.
        poll_request_until_status(
            name="read-admin-sees-the-person-in-his-account",
            method="GET",
            path="/iam/v1/users?accountId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            retry_predicate="(() => { const j = pm.response.json();"
                            " const id = pm.environment.get('readInvitedUserId');"
                            " return !!id && !(j.users || []).some(u => u.id === id); })()",
            test_script=[
                *assert_answered("UserService.List людей своего аккаунта"),
                *assert_status(200),
                "pm.test('КОНТРОЛЬ: распорядитель ВИДИТ этого человека среди людей своего "
                "аккаунта — значит отказ ниже про перечень удостоверений, а не про отсутствие "
                "доступа вообще', () => {",
                "  const j = pm.response.json();",
                "  const id = pm.environment.get('readInvitedUserId');",
                "  pm.expect((j.users || []).map(u => u.id), JSON.stringify(j)).to.include(id);",
                "});",
            ],
        ),
        Step(
            name="read-admin-lists-tokens-of-the-invited-person",
            method="GET",
            path="/iam/v1/users/{{readInvitedUserId}}/tokens",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("UserTokenService.List от распорядителя аккаунта"),
                # Утверждается ПАРА, а не один статус: HTTP-код — механическое
                # следствие отображения края, смысл несёт код модели. Полоса здесь
                # ОДНА и она выводится, а не угадывается: скрытие существования край
                # применяет к чтению по идентификатору (`/Get` + `v_get`), а этот RPC
                # ни тем, ни другим не является и явного признака в каталоге не несёт,
                # — значит отказ приходит как PERMISSION_DENIED. Толерантность
                # `403|404` здесь перечисляла бы исход без производителя.
                "pm.test('распорядитель аккаунта НЕ получает перечень персональных удостоверений "
                "приглашённого: удостоверение действует всюду, где действует человек, включая "
                "аккаунты, к которым распорядитель отношения не имеет, а сколько их и когда они "
                "истекают — сведения о личности, а не право на аккаунт', "
                # `.to.eql`, а не `.to.equal`: генератор ЧИТАЕТ объявленный исход шага
                # именно в этой форме и по нему решает, оборачивать ли шаг ожиданием
                # видимости. Объявленный 403 отключает ожидание by construction —
                # ретрай на отрицании был бы маскировкой отказа, а не терпимостью к
                # окну.
                "() => pm.expect(pm.response.code, pm.response.text()).to.eql(403));",
                *assert_grpc_code(7, "PERMISSION_DENIED"),
                "pm.test('в ответе нет ни одного удостоверения — отказ не отдал перечень частично', "
                "() => {",
                "  let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "  pm.expect(j && j.tokens, JSON.stringify(j)).to.be.oneOf([undefined, null]);",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-USR-TOK-READ-NEG-TENANT",
    title="Другой арендатор того же аккаунта перечень персональных токенов человека "
          "НЕ получает",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        *_invite_probe("readTenantTargetUserId", "read-tenant-target"),
        # КОНТРОЛЬ. Предъявитель арендатора жив и имеет настоящий доступ ВНУТРИ
        # того же аккаунта — он редактор проекта A1. Без этого шага отказ ниже
        # неотличим от «этому предъявителю вообще ничего не выдано», а такое
        # отрицание зеленеет на любом сломанном доступе.
        Step(
            name="read-tenant-control-reads-his-project",
            method="GET",
            path="/iam/v1/projects/{{projectA1Id}}",
            auth="jwtInvitee",
            test_script=[
                *assert_answered("ProjectService.Get проекта, где арендатор — редактор"),
                *assert_status(200),
                "pm.test('КОНТРОЛЬ: арендатор имеет настоящий доступ внутри этого аккаунта — "
                "значит отказ ниже про сведения о чужой личности, а не про пустую выдачу', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id).to.eql(pm.environment.get('projectA1Id'));",
                "});",
            ],
        ),
        Step(
            name="read-tenant-lists-tokens-of-another-person",
            method="GET",
            path="/iam/v1/users/{{readTenantTargetUserId}}/tokens",
            auth="jwtInvitee",
            test_script=[
                *assert_answered("UserTokenService.List от другого арендатора аккаунта"),
                "pm.test('арендатор НЕ получает перечень удостоверений другого человека того же "
                "аккаунта: круг читателей — сам человек и надзор облака, и соседство по аккаунту "
                "в него не входит', "
                # `.to.eql` — по той же причине, что у соседнего кейса: объявленный
                # исход отключает ожидание видимости, и отрицание остаётся
                # одноразовым.
                "() => pm.expect(pm.response.code, pm.response.text()).to.eql(403));",
                *assert_grpc_code(7, "PERMISSION_DENIED"),
            ],
        ),
    ],
))
