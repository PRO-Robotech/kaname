# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для ServiceAccountService.

Covered RPCs:
  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — служебная учётка, admin @ accountAId (НЕ предъявитель userAAAId)
    jwtAccountAdminB  — служебная учётка, admin @ accountBId
    jwtNoBindings     — authenticated, no account membership
    accountAId        — pre-seeded account for SA scope
    accountBId        — cross-account (for isolation probes)
    userAAAId         — ЦЕЛЬ ПРИВЯЗКИ: строка пользователя, владеющая accountAId

  ПОЧЕМУ `user*Id` НЕ ПРЕДЪЯВИТЕЛИ. Это ЦЕЛИ ПРИВЯЗКИ — строки пользователей,
  заведённые, чтобы разрешился триггер существования субъекта. Ни один выдаваемый
  предъявитель ими не аутентифицируется, и не может: машинный харнесс получает
  `client_credentials`, то есть служебную учётку. Привязать роль к `{{user*Id}}` и
  читать `{{jwt*}}` значит завести канал, который не разрешится ни при каком
  бюджете, а выглядеть это будет таймаутом шестью шагами позже. Набор объявлен
  ДАННЫМИ (`tests/authz-fixtures/principal_pairings.py`, `BINDING_TARGET_ONLY_IDS`)
  и сверяется гейтом `scripts/case_header_principal_claim_test.py`.

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


def _revoke_key_steps(name, key_var):
    """Revoke one issued SA key and ASSERT the revocation landed.

    Two steps, not one: the mutation returns an Operation, and an Operation that
    finished WITH an error is indistinguishable from success at the HTTP layer.
    The id is read from a variable the issuing step captured out of the operation
    metadata; an empty variable is a broken case, so the guard says so instead of
    firing a DELETE at an unresolved template."""
    return [
        Step(
            name=name,
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{disSvaId}}/keys/{{" + key_var + "}}",
            auth="jwtAccountAdminAStepUp",
            pre_script=[
                f"if (!pm.environment.get('{key_var}')) {{",
                f"  pm.test('{name}: {key_var} captured by the issuing step', "
                f"() => pm.expect.fail('{key_var} is empty — the Issue operation did "
                f"not name its key, so there is nothing to revoke and the teardown "
                f"below would fail on RESTRICT'));",
                "  pm.execution.skipRequest();",
                "}",
            ],
            test_script=[
                *assert_answered(name),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),
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
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
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
        # Текст владельца ЦЕЛИКОМ: «already exists» несут пять разных отказов iam,
        # и утверждение об общей части проходило на отказе о ЧУЖОМ ресурсе (#1748).
        assert_op_error(6, "ALREADY_EXISTS",
                        msg_text="ServiceAccount with name sva-{{runId}} already exists"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-CR-NEG-PROJECT-MISSING — аккаунт без пути прав → отказ на краю
# (Coverage list uses "PROJECT-MISSING" but this service is account-scoped on IAM.)
# ---------------------------------------------------------------------------

# Создание под аккаунтом, к которому у вызывающего нет пути прав, решается НА КРАЮ и
# отказом — до того как сервис вообще набирается.
#
# Запись каталога прав для этого метода несёт `required_relation: editor` +
# `scope_extractor {object_type: account, from_request_field: account_id}`. Идентификатор
# `acc00000000000notfnd` формой валиден (узнаваемый префикс), поэтому синхронного 400 по
# формату нет — край выполняет вопрос к модели. Объекта аккаунта не существовало никогда,
# значит тупла у него нет ни у кого, значит `no path`, значит терминальный 403. Каскад
# верхних уровней здесь не при чём: вызывающий — обычный владелец своего аккаунта, не
# администратор облака.
#
# Отсюда следует, чего кейс НЕ проверяет и не может: полосу FK на вставке (async
# `FAILED_PRECONDITION`), которую обещал его прежний заголовок. Сервис на этом пути
# недостижим. Прежнее `oneOf([200, 400, 403])` принимало три исхода, из которых
# реализуем один, — то есть не могло упасть ни на смене полосы, ни на приёме запроса.
#
# Ценность кейса — в другом, и она настоящая: отказ обязан быть терминальным (403, код 7)
# и НЕ должен сообщать, существует ли названный аккаунт. Иначе отличие «нет доступа» от
# «нет объекта» становится оракулом существования аккаунтов чужих тенантов.
CASES.append(Case(
    id="IAM-SVA-CR-NEG-PROJECT-MISSING",
    title="Create service account under an account with no authorization path → 403 PERMISSION_DENIED at the edge (anti-oracle)",
    classes=["NEG", "AUTHZ"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-account",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "acc00000000000notfnd", "name": "svabadacc{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
                "pm.test('отказ называет действие, а не судьбу объекта', () => "
                "  pm.expect(pm.response.json().message||'').to.include('iam.service_accounts.create'));",
                # Анти-оракул: по тексту отказа нельзя отличить «аккаунта нет» от
                # «доступа нет».
                "pm.test('отказ не сообщает, существует ли аккаунт', () => {",
                "  const m = (pm.response.json().message || '').toLowerCase();",
                "  pm.expect(m).to.not.contain('not found');",
                "  pm.expect(m).to.not.contain('does not exist');",
                "});",
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
    title="Get crudSvaId as jwtPureNoBindings (no v_get on accountA SA) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/serviceAccounts/{{crudSvaId}}",
            # jwtNoBindings is NOT a no-grant subject any more: the iam suites
            # themselves grant userNOBId `view` on account-A (iam-flat-authz-vbc
            # create-derive) and on account-B (the authz-deny AB-CR ALLOW rows),
            # and those bindings stay ACTIVE in the DB across runs. A probe that
            # asserts "this subject sees nothing" was therefore asserting it
            # against a subject that is genuinely authorised — a fixture artifact,
            # not a product leak. jwtPureNoBindings is the DEDICATED never-granted
            # subject seeded for exactly this (tests/authz-fixtures/setup.sh; it is
            # never a grant TARGET anywhere in the tree).
            auth="jwtPureNoBindings",
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
            # pageSize=1000 — условие осмысленности утверждения «свой свежий SA виден».
            # Список курсорный, (created_at, id) ASC, страница по умолчанию 50; сервисный
            # аккаунт, созданный ЭТИМ прогоном, сортируется последним и уезжает за первую
            # страницу, как только их в аккаунте больше 50. Измерено на стенде 2026-07-29:
            # 71 SA в account-A, дефолтная страница вернула 50 старейших + nextPageToken.
            # Не лаг материализации (ретрай не помогает) и не дефект продукта — курсорная
            # ASC-семантика заявлена контрактом. Тот же класс, что IAM-PRJ-LS-CRUD-OK и
            # (ранее) IAM-ROL-LS-SYSTEM-PLUS-CUSTOM-WITH-ACCOUNT.
            # Негативы ниже (LS-AUTHZ-ANON-DENY / LS-AUTHZ-SCOPE-NONMEMBER-EMPTY) страницу
            # НЕ расширяют: они утверждают 401 и пустой список, размер страницы им безразличен.
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}&pageSize=1000",
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
    title="List serviceAccounts ?accountId=A as jwtPureNoBindings → 200 + empty list (scope-filter)",
    classes=["AUTHZ", "SCOPE"],
    priority="P1",
    steps=[
        Step(
            name="list-nonmember",
            method="GET",
            path="/iam/v1/serviceAccounts?accountId={{accountAId}}",
            # jwtNoBindings is NOT a no-grant subject any more: the iam suites
            # themselves grant userNOBId `view` on account-A (iam-flat-authz-vbc
            # create-derive) and on account-B (the authz-deny AB-CR ALLOW rows),
            # and those bindings stay ACTIVE in the DB across runs. A probe that
            # asserts "this subject sees nothing" was therefore asserting it
            # against a subject that is genuinely authorised — a fixture artifact,
            # not a product leak. jwtPureNoBindings is the DEDICATED never-granted
            # subject seeded for exactly this (tests/authz-fixtures/setup.sh; it is
            # never a grant TARGET anywhere in the tree).
            auth="jwtPureNoBindings",
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
            # The mask alone carries the assertion: the immutable-switch is keyed on
            # the mask path, and `accountId` is not a field of
            # UpdateServiceAccountRequest — sending it would be a discarded key.
            body={"updateMask": "account_id"},
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
                "  const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
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


# ---------------------------------------------------------------------------
# IAM-SVA-DIS-CRUD-OK — the whole loop, black box: an enabled service account is
# issued a credential; :disable; the SAME request is refused; :enable; it works.
#
# This is the case that proves the WRITER and the READER met. `enabled` was read
# by the token hook, by key issuance and by the docker-token validator long
# before anything could set it, so every one of those refusals was unreachable
# in practice. What is asserted here is not that a field changed — it is that
# the platform's answer to "may this machine identity be handed a credential"
# changed, and changed back.
#
# The credential-issuance RPC and both actions carry catalog
# `required_acr_min=2`, so every mutating step presents the step-up'd token.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DIS-CRUD-OK",
    title="Enabled SA is issued a key → :disable → key issuance REFUSED → :enable → issued again",
    classes=["CRUD", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="create-sa",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "svadis{{runId}}",
                  "description": "newman disable/enable loop probe"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("create-sa"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.serviceAccountId", "disSvaId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),

        Step(
            name="get-confirms-enabled",
            method="GET",
            path="/iam/v1/serviceAccounts/{{disSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("get-confirms-enabled"),
                *assert_status(200),
                # The starting state is asserted, not assumed. Without this the
                # later `enabled === false` proves only "false at the end", which
                # a field that was never true also satisfies.
                "pm.test('a fresh service account starts enabled', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.enabled, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),

        # ── 1. Enabled: a credential IS issued. The control case, and it must come
        #      first: `enabled` is false in every zero value, so a gate reading an
        #      unloaded field refuses EVERY account — and a case that only checked
        #      the refusal would report green while machine access was dead.
        retry_until_authorized(Step(
            name="issue-key-while-enabled",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}/keys",
            body={"description": "newman key before disable"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("issue-key-while-enabled"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        Step(
            name="assert-op-success-key-while-enabled",
            method="GET", path="/operations/{{opId}}", auth="jwtAccountAdminA",
            op_var="opId",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation succeeded (response, no error)', () => pm.expect(Boolean(j.response) && !j.error, JSON.stringify(j)).to.eql(true));",
                "pm.test('issue metadata names the key it minted', () => {",
                "  pm.expect(j.metadata && j.metadata.keyId, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "});",
                "if (j.metadata && j.metadata.keyId) { pm.environment.set('disKeyBeforeId', j.metadata.keyId); }",
            ],
        ),

        # ── 2. Disable — an ACTION with no field mask to forget.
        retry_until_authorized(Step(
            name="disable",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}:disable",
            body={},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("disable"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),

        Step(
            name="get-confirms-disabled",
            method="GET",
            path="/iam/v1/serviceAccounts/{{disSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("get-confirms-disabled"),
                *assert_status(200),
                "pm.test('SA.enabled is false — the state an operator set is a state they can SEE', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.enabled, JSON.stringify(j)).to.eql(false);",
                "});",
            ],
        ),

        # ── 3. Disabled: the SAME request is refused. Synchronous, because the
        #      request is well-formed and the answer is known now.
        Step(
            name="issue-key-while-disabled",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}/keys",
            body={"description": "newman key while disabled"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("issue-key-while-disabled"),
                *assert_status(400),
                *assert_grpc_code(9, "FAILED_PRECONDITION"),
                "pm.test('message names the reason (contract tone)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j)).to.include('is disabled and cannot be issued a key');",
                "});",
            ],
        ),

        # ── 4. Disabling again is a success: the state is the subject, not the
        #      transition. The safe direction must never fail on retry.
        Step(
            name="disable-again-idempotent",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}:disable",
            body={},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("disable-again-idempotent"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),

        # ── 5. Enable — and the platform answers yes again.
        Step(
            name="enable",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}:enable",
            body={},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("enable"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),

        retry_until_authorized(Step(
            name="issue-key-after-enable",
            method="POST",
            path="/iam/v1/serviceAccounts/{{disSvaId}}/keys",
            body={"description": "newman key after enable"},
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_answered("issue-key-after-enable"),
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        # Both issued keys are captured from the operation metadata, because the
        # teardown below CANNOT succeed while they live: the OAuth-client row that
        # backs a key references the service account `ON DELETE RESTRICT`, so the
        # platform refuses to delete a machine identity whose credentials are still
        # valid. That refusal is the product being right — deleting the identity while
        # its credentials keep working is exactly what RESTRICT is there to prevent.
        # The case used to issue two keys and then delete the account, so the teardown
        # came back as an async code-9 and the leaked account stayed in the listing.
        Step(
            name="assert-op-success-key-after-enable",
            method="GET", path="/operations/{{opId}}", auth="jwtAccountAdminA",
            op_var="opId",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('operation succeeded (response, no error)', () => pm.expect(Boolean(j.response) && !j.error, JSON.stringify(j)).to.eql(true));",
                "pm.test('issue metadata names the key it minted', () => {",
                "  pm.expect(j.metadata && j.metadata.keyId, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "});",
                "if (j.metadata && j.metadata.keyId) { pm.environment.set('disKeyAfterId', j.metadata.keyId); }",
            ],
        ),

        Step(
            name="get-confirms-enabled-again",
            method="GET",
            path="/iam/v1/serviceAccounts/{{disSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("get-confirms-enabled-again"),
                *assert_status(200),
                "pm.test('and the state an operator can SEE came back too', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.enabled, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),

        # Cleanup: the suite's own fixture does not outlive it (a leaked SA grows
        # the account listing and moves other cases' list contracts).
        #
        # The credentials go FIRST, and they are asserted rather than merely attempted:
        # revocation is the documented way past the RESTRICT above, so a revoke that
        # silently failed would resurface one step later as the same opaque teardown
        # error this ordering exists to remove.
        *_revoke_key_steps("revoke-key-before", "disKeyBeforeId"),
        *_revoke_key_steps("revoke-key-after", "disKeyAfterId"),
        Step(
            name="cleanup-delete-sa",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{disSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("cleanup-delete-sa"),
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        # The cleanup is asserted, not merely attempted: a Delete that fails
        # asynchronously is invisible, and the comment above would then be
        # claiming a teardown that did not happen while the account listing grows
        # every run.
        assert_op_success(auth="jwtAccountAdminA"),
    ],
))


# ---------------------------------------------------------------------------
# NOT COVERED HERE — the step-up floor on :disable / :enable.
#
# This is an OPEN DEBT with a number attached (1 invariant, 2 RPCs), not an
# invariant this suite quietly reports green.
#
# A case was written asserting "disable without a step-up'd session → 403" and
# removed on review, because on this stand it could not fail for the reason its
# title claimed. Three independent reasons, any one sufficient:
#
#   1. the floor runs on ONE arm of the edge — the asymmetric-JWT path. The
#      fixture tokens here are symmetric dev-secret JWTs and take the other
#      path, which never consults the claim at all. Both fixture identities then
#      carry the same subject, the same tuples and the same verdict;
#   2. where the floor DOES run, its answer is 401, not 403 — so the assertion
#      could not be satisfied by a step-up denial on any stand;
#   3. what does produce 403 here is the ordinary per-object deny during the
#      owner-tuple materialization window — which the very next step of the same
#      case required to have CLOSED. Green would have meant "the grant had not
#      propagated yet", i.e. the opposite of what was claimed.
#
# What DOES pin the classification, decisively and in the differential sense, is
# the Go gate over the permission catalog
# (gateway/internal/middleware/permission_catalog_acr_invariant_test.go): both
# RPCs are named in the sensitive set, the set is asserted in BOTH directions,
# and lowering either one to the routine floor fails it. That covers the
# DECLARATION.
#
# What remains uncovered is the ENFORCEMENT of that declaration end-to-end, and
# it needs a stand where the floor is live (production-mode / asymmetric tokens)
# plus a fixture that can present both an elevated and a non-elevated session.
# Until such a wave exists, this invariant is not black-box tested. Said plainly
# rather than papered over with a probe that always passes.

# ---------------------------------------------------------------------------
# IAM-SVA-DIS-NEG-NOTFOUND — :disable on a well-formed but absent id.
# Authz-first: the gateway's scope extractor cannot resolve the target, so a
# 403 is as defensible as a 404 here. Never 200.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DIS-NEG-NOTFOUND",
    title="Disable a well-formed but absent service account → scoped authz deny on the action",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="disable-absent",
            method="POST",
            path=f"/iam/v1/serviceAccounts/{GARBAGE_SVA}:disable",
            body={},
            auth="jwtAccountAdminAStepUp",
            # A bare `oneOf([403, 404])` here would be a tautology: it also holds
            # when the route template is misspelled (404), when the catalog entry
            # is missing (403 fail-closed) and when the FQN never reached the
            # allowlist (403). Every one of those means the RPC does not work,
            # and the probe would have called them all a pass.
            #
            # The discriminator is the RESOLVED ACTION in the error detail: a real
            # per-object deny names the permission it denied, while a catalog miss
            # carries an empty one (the descriptor is built before the entry is
            # known). Pinning the object too — the extractor reads the id straight
            # off the path, so it is deterministic.
            test_script=[
                *assert_answered("disable-absent"),
                *assert_scoped_authz_deny(
                    "iam.service_accounts.disable",
                    f"'iam_service_account:{GARBAGE_SVA}'",
                ),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-SVA-DIS-NEG-CROSS-ACCOUNT — the admin of account B cannot disable a service
# account of account A.
#
# The single most valuable negative for a new object-scoped action, and the whole
# reason the RPC carries a scope extractor: without one, any authenticated caller
# who can name an id could take another tenant's machine identity out of service.
# Denial-of-service against a neighbour is a low bar to clear and a high one to
# notice — the victim sees their automation stop authenticating, with nothing in
# their own account to explain it.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-SVA-DIS-NEG-CROSS-ACCOUNT",
    title="Account B admin disabling an account A service account → scoped deny, never 200",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="create-victim-sa",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={"accountId": "{{accountAId}}", "name": "svavict{{runId}}",
                  "description": "newman cross-account probe target"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("create-victim-sa"),
                *assert_status(200),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.serviceAccountId", "victimSvaId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        # The victim must really exist before the deny means anything: a deny on a
        # resource that was never created proves only that nothing is there.
        assert_op_success(auth="jwtAccountAdminA"),
        Step(
            name="cross-account-disable-denied",
            method="POST",
            path="/iam/v1/serviceAccounts/{{victimSvaId}}:disable",
            body={},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_answered("cross-account-disable-denied"),
                *assert_scoped_authz_deny(
                    "iam.service_accounts.disable",
                    "'iam_service_account:' + pm.environment.get('victimSvaId')",
                ),
            ],
        ),
        # And the victim is untouched — a deny that still had an effect is not a
        # deny. This is the assertion that separates "refused" from "refused the
        # caller a receipt".
        Step(
            name="victim-still-enabled",
            method="GET",
            path="/iam/v1/serviceAccounts/{{victimSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("victim-still-enabled"),
                *assert_status(200),
                "pm.test('the neighbour could not touch it: enabled is still true', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.enabled, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),
        Step(
            name="cleanup-victim-sa",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{victimSvaId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_answered("cleanup-victim-sa"),
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(auth="jwtAccountAdminA"),
        assert_op_success(auth="jwtAccountAdminA"),
    ],
))
