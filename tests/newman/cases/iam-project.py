# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set для ProjectService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  Reuses vars from crud-fixture/setup.sh (superset: authz-fixtures/setup.sh):
    jwtAccountAdminA  — служебная учётка, admin @ accountAId (НЕ предъявитель userAAAId)
    jwtAccountAdminB  — служебная учётка, admin @ accountBId
    jwtNoBindings     — authenticated but no account membership
    userAAAId         — the User id that is owner of accountAId
    accountAId        — pre-seeded account owned by userAAAId
    accountBId        — cross-account (for isolation probes)

  ПОЧЕМУ `user*Id` НЕ ПРЕДЪЯВИТЕЛИ. Это ЦЕЛИ ПРИВЯЗКИ — строки пользователей,
  заведённые, чтобы разрешился триггер существования субъекта. Ни один выдаваемый
  предъявитель ими не аутентифицируется, и не может: машинный харнесс получает
  `client_credentials`, то есть служебную учётку. Привязать роль к `{{user*Id}}` и
  читать `{{jwt*}}` значит завести канал, который не разрешится ни при каком
  бюджете, а выглядеть это будет таймаутом шестью шагами позже. Набор объявлен
  ДАННЫМИ (`tests/authz-fixtures/principal_pairings.py`, `BINDING_TARGET_ONLY_IDS`)
  и сверяется гейтом `scripts/case_header_principal_claim_test.py`.

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

Удаление НЕПУСТОГО проекта (IAM-PRJ-DL-NEG-HAS-CHILDREN) держится внешним ключом
`roles_project_fk` (запрет удаления родителя): единственный живой ребёнок проекта в
kacho_iam сегодня — ПРОЕКТНАЯ пользовательская роль. Кейс заводит и снимает его сам
через публичный API, поэтому общая фикстура не задействована и после прогона ничего
не остаётся.

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
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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
        retry_until_authorized(Step(
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
        )),
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
        # Текст владельца ЦЕЛИКОМ: «already exists» несут пять разных отказов iam,
        # и утверждение об общей части проходило на отказе о ЧУЖОМ ресурсе (#1748).
        assert_op_error(6, "ALREADY_EXISTS",
                        msg_text="Project with name prj-{{runId}} already exists"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-PRJ-CR-NEG-ACCOUNT-MISSING — аккаунт без пути прав → отказ на краю
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
    id="IAM-PRJ-CR-NEG-ACCOUNT-MISSING",
    title="Create project under an account with no authorization path → 403 PERMISSION_DENIED at the edge (anti-oracle)",
    classes=["NEG", "AUTHZ"],
    priority="P1",
    steps=[
        Step(
            name="create-bad-account",
            method="POST",
            path="/iam/v1/projects",
            body={"accountId": "acc00000000000notfnd", "name": "prj-bad-acc-{{runId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(7, "PERMISSION_DENIED"),
                "pm.test('отказ называет действие, а не судьбу объекта', () => "
                "  pm.expect(pm.response.json().message||'').to.include('iam.projects.create'));",
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
    title="Get crudProjectId as jwtPureNoBindings (non-owner) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-foreign",
            method="GET",
            path="/iam/v1/projects/{{crudProjectId}}",
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
            # pageSize=1000 — НЕ косметика, а условие осмысленности утверждения ниже.
            #
            # Список курсорный и отсортирован по (created_at, id) ASC, а страница по
            # умолчанию — 50. Проект, созданный ЭТИМ прогоном, имеет created_at=NOW() и
            # поэтому сортируется ПОСЛЕДНИМ: как только в аккаунте накапливается больше
            # 50 проектов, он закономерно уезжает на вторую страницу, и проверка
            # «свой свежий проект виден в списке» падает на СТАРНИЦЕ, а не на видимости.
            # Измерено на стенде 2026-07-29: в account-A 55 проектов, страница по
            # умолчанию вернула 50 старейших + nextPageToken, свежий проект — на 2-й.
            # Это не read-your-writes лаг (ретрай бы не помог) и не дефект продукта:
            # курсорная семантика ASC — заявленный контракт.
            # Тот же класс уже чинили ровно так же для
            # IAM-ROL-LS-SYSTEM-PLUS-CUSTOM-WITH-ACCOUNT (56 системных ролей вытесняли
            # созданную прогоном роль за страницу) — см. комментарий #193 в
            # scripts/assert-suites-green.sh.
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1000",
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
            # The mask alone carries the assertion: the immutable-switch is keyed on
            # the mask path, and `accountId` is not a field of UpdateProjectRequest —
            # sending it would be a key the edge discards.
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
# IAM-PRJ-DL-NEG-HAS-CHILDREN — удаление проекта, У КОТОРОГО ЕСТЬ РЕБЁНОК.
#
# ЧТО ЗДЕСЬ БЫЛО И ПОЧЕМУ ЭТО НЕ МОГЛО УПАСТЬ. Кейс обещал заголовком отказ по
# состоянию (FAILED_PRECONDITION на проекте с живыми детьми), а утверждал
# `oneOf([404, 403])` по МУСОРНОМУ идентификатору `prj00000000000notfnd`. У такого
# утверждения нет производителя заявленного исхода вовсе: несуществующий проект
# отвечает промахом или отказом в правах, то есть проба зеленела ровно тогда, когда
# защиты от удаления непустого проекта не существовало бы в продукте. Соседний кейс
# IAM-PRJ-DL-NEG-NOTFOUND утверждает то же самое и по тому же входу — то есть слот
# был занят дублем под чужим заголовком.
#
# ЧЕМ ЗАМЕНЕНО — НАСТОЯЩИЙ РЕБЁНОК, СОЗДАННЫЙ ПУБЛИЧНЫМ API. Единственный живой
# ребёнок проекта в kacho_iam на сегодня — ПРОЕКТНАЯ пользовательская роль
# (`roles.project_id`, внешний ключ с запретом удаления родителя). Он заводится через
# публичный `POST /iam/v1/roles` с `projectId` (та же форма, что у
# IAM-ROL-CR-PROJECT-SCOPED в cases/iam-role.py), поэтому фикстура кейса
# САМОДОСТАТОЧНА: свой проект, свой ребёнок, своя уборка — ни один общий
# идентификатор фикстуры не задействован и после кейса не остаётся.
#
# ПОЧЕМУ ТЕКСТ ИМЕННО ОБЩИЙ. Запрет удаления поднимает 23503 на внешнем ключе
# `roles_project_fk`, а он в поимённом разборе маппера НЕ назван (в отличие от
# ключей аккаунта), поэтому до клиента доходит общий текст ветви «внешний ключ без
# собственного сообщения» с кодом 9. Пиним ДОСТАВЛЕННЫЙ текст, а не желаемый: тон
# сообщений — часть контракта (api-conventions.md §Error-format), и утверждение про
# «Project … contains …» краснело бы на исправном продукте.
#
# ОБЩИЙ ТЕКСТ ТЕПЕРЬ РАЗВЕДЁН ПО ПОЛОСАМ, И ЗДЕСЬ — «ЕЩЁ ИСПОЛЬЗУЕТСЯ». Прежде обе
# стороны ссылочного отказа приходили ОДНИМ текстом («referenced resource not found or
# still in use»), то есть отказ не восстанавливал следующий шаг: «нет ссылаемого»
# лечится СОЗДАНИЕМ, «ещё используется» — ОСВОБОЖДЕНИЕМ, и выбрать вызывающий не мог.
# Стороны разведены, и различие живёт в `google.rpc.ErrorInfo.reason`, потому что код у
# них общий, а разбор прозы вызывающему запрещён конвенцией. Утверждается ПАРА — код и
# признак (api-conventions.md §by-lane code-split). Соседний кейс
# cases/iam-group.py::IAM-GRP-AM-NEG-MEMBER-MISSING пинит ВТОРУЮ полосу того же отказа
# (REFERENCE_MISSING) — вместе они и есть доказательство, что полосы различимы, а не
# переименованы.
#
# ПОЧЕМУ ОТРИЦАНИЕ ИДЁТ В ПАРЕ С ПОЛОЖИТЕЛЬНЫМ. Одинокий отказ неотличим от
# «удаление проекта сломано вообще» (testing.md §«Отрицание годится только в паре с
# положительным»). Поэтому после снятия ребёнка ТОТ ЖЕ запрос обязан пройти: ребёнок
# удаляется, и удаление проекта завершается операцией БЕЗ ошибки. Красным станет и
# пропавший запрет (первое утверждение), и запрет, ставший вечным (второе).
#
# ТОЛЕРАНТНОСТЬ «СНАЧАЛА ПРАВА» ЗДЕСЬ НЕ ПРИМЕНЯЕТСЯ. Она законна для НЕДОСТУПНОГО
# объекта, а этот проект вызывающий только что создал сам, поэтому 403 на нём
# означал бы потерю права создателем — дефект, а не законный исход. Краткое окно
# материализации закрывается ограниченным повтором (retry_until_authorized) на
# ПЕРВОМ обращении к своему свежему проекту; набор глаголов объекта пишется целиком
# (data-integrity.md: sync-FGA-write атомарен per-object), поэтому видимый `v_get`
# влечёт видимый `v_delete`.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-PRJ-DL-NEG-HAS-CHILDREN",
    title="Delete a project that still has a child (project-scoped custom Role) → Operation.error "
          "FAILED_PRECONDITION (9); after the child is removed the SAME delete succeeds",
    classes=["NEG", "STATE"],
    priority="P1",
    steps=[
        # 1. свой проект-носитель ребёнка (общая фикстура не трогается).
        Step(
            name="create-child-host-project",
            method="POST",
            path="/iam/v1/projects",
            body={
                "accountId": "{{accountAId}}",
                "name": "prjchild-{{runId}}",
                "description": "newman has-children delete guard host",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.projectId", "childHostProjectId"),
            ],
        ),
        # Операция обязана РЕАЛЬНО завершиться успехом: предвыделенный id лежит в
        # metadata даже у операции с ошибкой, и без этой проверки дальше поехал бы
        # фантомный проект, а отказ на нём читался бы как сработавший запрет.
        poll_operation_until_done(),
        assert_op_success(),
        # Первое обращение к своему свежему проекту — под ограниченным повтором на
        # окне материализации набора глаголов создателя.
        retry_until_authorized(Step(
            name="get-child-host-project",
            method="GET",
            path="/iam/v1/projects/{{childHostProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('фикстура записала id проекта-носителя', () => "
                "  pm.expect(pm.environment.get('childHostProjectId'), 'childHostProjectId')"
                "   .to.be.a('string').and.not.empty);",
                "pm.test('и это именно он', () => pm.expect(pm.response.json().id)"
                ".to.eql(pm.environment.get('childHostProjectId')));",
            ],
        )),
        # 2. РЕБЁНОК — проектная пользовательская роль (roles.project_id → FK RESTRICT).
        Step(
            name="create-project-scoped-child-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                "projectId": "{{childHostProjectId}}",
                "name": "prj_child_{{runId}}",
                "description": "newman child of the project under delete-guard test",
                "rules": [
                    {"module": "iam", "resources": ["project"], "verbs": ["get", "list"]},
                ],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "childRoleId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # Ребёнок обязан СУЩЕСТВОВАТЬ и принадлежать этому проекту — иначе отказ ниже
        # доказывал бы не запрет удаления непустого проекта, а что-то другое.
        retry_until_authorized(Step(
            name="get-child-role",
            method="GET",
            path="/iam/v1/roles/{{childRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ребёнок привязан именно к этому проекту', () => "
                "  pm.expect(pm.response.json().projectId, pm.response.text())"
                "   .to.eql(pm.environment.get('childHostProjectId')));",
            ],
        )),
        # 3. ОТРИЦАНИЕ — удаление проекта с живым ребёнком отвергается ПО СОСТОЯНИЮ.
        Step(
            name="delete-project-with-child",
            method="DELETE",
            path="/iam/v1/projects/{{childHostProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                # Полоса одна и она АСИНХРОННАЯ: запрет живёт на внешнем ключе внутри
                # DELETE, а DELETE исполняет worker. Синхронного 400 здесь не бывает —
                # сервис возвращает конверт операции, а отказ приезжает в ней.
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        assert_op_error(9, "FAILED_PRECONDITION",
                        msg_substr="resource is still referenced by other resources",
                        reason="REFERENCE_IN_USE"),
        # Проект обязан ОСТАТЬСЯ: отказ, после которого ресурс всё равно исчез, —
        # это не сработавший запрет, а потерянная строка.
        Step(
            name="project-survived-refused-delete",
            method="GET",
            path="/iam/v1/projects/{{childHostProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('проект на месте после отвергнутого удаления', () => "
                "  pm.expect(pm.response.json().id).to.eql(pm.environment.get('childHostProjectId')));",
            ],
        ),
        # 4. ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (он же уборка) — снимаем ребёнка, и ТОТ ЖЕ запрос
        # проходит. Без этой половины отказ выше был бы зелёным и на полностью
        # сломанном удалении проектов.
        Step(
            name="delete-child-role",
            method="DELETE",
            path="/iam/v1/roles/{{childRoleId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        Step(
            name="delete-project-after-child-gone",
            method="DELETE",
            path="/iam/v1/projects/{{childHostProjectId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        # И проект действительно ИСЧЕЗ: операция без ошибки — утверждение о самой
        # операции, а не о строке. Иначе положительный контроль зеленел бы на
        # удалении, которое ничего не удаляет.
        get_until_gone("/iam/v1/projects/{{childHostProjectId}}", "Project"),
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
                "  const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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
                # Создатель проекта видит операции проекта детерминированно: право
                # `v_list` на объекте проекта материализуется СИНХРОННО в том же
                # запросе, что создал проект (реконсайл объекта вызывается внутри
                # создания, до того как операция помечена done) — именно чтобы закрыть
                # окно «создал → сразу читаю». Поэтому отказных исходов здесь нет, а
                # прежнее `oneOf([200, 403, 404])` делало кейс с именем `CRUD-OK`
                # неспособным упасть: и потеря права, и исчезновение проекта проходили
                # бы как «ожидаемый исход».
                *assert_status(200),
                "pm.test('operations array present', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.operations, 'operations field').to.be.an('array');",
                "});",
                # Ради этого кейс и существует: среди операций проекта обязана быть его
                # собственная операция создания. Пустой массив «формально массив» —
                # утверждение без содержания.
                "pm.test('и содержит хотя бы одну операцию — создание самого проекта', () => {",
                "  const j = pm.response.json();",
                "  pm.expect((j.operations || []).length, JSON.stringify(j)).to.be.greaterThan(0);",
                "});",
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
