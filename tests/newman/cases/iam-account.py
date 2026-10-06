# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для AccountService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  This suite requires a seeded owner user + JWT. It reuses the authz-fixtures
  env vars produced by `PRO-Robotech/kacho:tests/authz-fixtures/setup.sh`:
    jwtAccountAdminA  — service-account bearer, admin @ accountAId (READ/UPDATE/DELETE
                        of the PRE-SEEDED account and every non-creating probe)
    userAAAId         — the User who owns the pre-seeded accountAId
    accountAId        — pre-seeded account owned by userAAAId (for Get/Update/Delete/authz)
    accountBId        — cross-account (for negative isolation probes)
    jwtAccountAdminB  — bearer for accountBId (for isolation probes)
    jwtNoBindings     — authenticated but no account membership (for non-owner-deny probes)

  ПОЧЕМУ СОЗДАНИЕ АККАУНТА ИДЁТ ПОД ДРУГИМ ПРЕДЪЯВИТЕЛЕМ — И ЭТО НЕ ОСЛАБЛЕНИЕ.
  Аккаунт принадлежит ПОЛЬЗОВАТЕЛЮ by construction: `owner_user_id` ссылается на
  `users(id)`, а владелец выводится из принципала, а не из тела. Поэтому вызов от
  служебной учётки отвергается синхронно, первым стейтментом, с именем поля —
  и это правильное поведение продукта, а не дефект (см. account/create.go).
  Все предъявители матричного посева машинные, значит ими аккаунт не создать.
  Условие «предъявитель принадлежит человеку» создаёт ВОЛНА ЦЕРЕМОНИИ
  (посев `tests/authz-fixtures/seed_ceremony.py --wave` на автономном стенде,
  задание `stand-ceremony`; локально — `scripts/run-ceremony.sh`):
    jwtHumanCeremony  — предъявитель ЧЕЛОВЕКА, добытый настоящим входом паролем
    ceremonyUserId    — идентификатор этого человека в iam (ожидаемый владелец)

  ЧТО ИМЕННО ПЕРЕПРИВЯЗАНО. Шаги, СОЗДАЮЩИЕ аккаунт, и всё, что работает с
  созданным аккаунтом (poll/get/update/delete его самого и его дочернего проекта),
  идут под ЧЕЛОВЕКОМ — иначе владельцем стал бы тот, кто владеть не может. Человек
  у каждого заводящего кейса СВОЙ (`ceremony_credentials.ADMISSION_SLOTS`): заведение
  списывается с темпа личности, и складывать заведения разных кейсов в одного
  человека значит воспроизводить сценарий, который продукт отвергает.
  Шаги, чей предмет — ЛИЧНОСТЬ вызывающего (аноним, чужой принципал, кросс-аккаунт),
  предъявителя НЕ меняют: там машинность или анонимность и есть проверяемое свойство.

  ПОБОЧНОЕ СЛЕДСТВИЕ, КОТОРОЕ РАНЬШЕ БЫЛО НЕ ВИДНО. Пока создание отвергалось,
  негативные кейсы этого набора зеленели, НЕ ДОЙДЯ до своего предмета: отказ
  приходил про род принципала, а утверждение проверяло только код 400. Под
  человеческим предъявителем те же кейсы наконец способны упасть — ради этого
  перепривязаны и они, а не только положительные.

  For the stateful Create→poll→Get→Update→Delete flow the suite creates a
  FRESH account per runId (name "crud-{{runId}}"), owned by the ceremony human.
  This avoids cross-test pollution while reusing the seeded read fixtures.

Operation envelope:
  All mutations return `operation.Operation` with id prefix `iop` (IAM operations
  are distinct from api-gateway OperationService; the poll step hits `/operations/{id}`
  via the OpsProxy at api-gateway which routes `iop*` to kaname).

Case IDs follow the IAM-ACC-<RPC>-<CLASS>[-detail] scheme.

Authz cases:
  Cases that require specific JWT fixtures (jwtAccountAdminA etc.) are included
  since authz-fixtures already provides them. Anonymous (no Authorization header)
  cases use auth="anonymous" per Step.auth convention from authz-deny.py.

Test-first note (strict TDD):
  These cases are written RED-first. They will fail until the corresponding
  AccountService RPCs are correctly implemented in kaname. Do not weaken
  assertions to make them pass — fix the implementation instead.

verifies: AccountService Create/Get/Update/Delete acceptance scenarios from
iam-account.py spec.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`: домены
# выводятся из REST-путей этого же модуля, и объявление обязано с ними сходиться.
HOME = "kaname"

CASES = []

# ПОДНЯТЫЙ УРОВЕНЬ ВХОДА — ТОТ ЖЕ ЧЕЛОВЕК, ДРУГОЙ УРОВЕНЬ АУТЕНТИФИКАЦИИ.
# Необратимое удаление объявлено чувствительным (`required_acr_min = "2"` у
# `AccountService/Delete` и `ProjectService/Delete`). Служебная учётка от этого порога
# ОСВОБОЖДЕНА, поэтому, пока удаление шло машинным предъявителем, порог не проверялся
# ни разу — он впервые начал действовать вместе с человеческим вызывающим.
# Какие шаги требуют поднятого уровня, берётся у КАТАЛОГА
# (`gateway/internal/middleware/embed/permission_catalog.json`), а не по догадке.
#
# ЧЕЛОВЕК У КАЖДОГО ЗАВОДЯЩЕГО КЕЙСА СВОЙ. Заведение аккаунта списывается с ТЕМПА
# личности (#618, умолчание — три в час на внешний идентификатор входа), а посев уже
# занимает у человека церемонии два места. Пока все заведения волны шли под ним, их
# набиралось десять при потолке три: первое проходило, остальные получали
# `RESOURCE_EXHAUSTED`, и падение доставалось шагам, шедшим следом за несозданным
# аккаунтом. Отказ ВЕРЕН — человек заводит СЕБЕ аккаунт, а не восемь подряд; неверна
# была форма пробы. Слоты объявлены в `ceremony_credentials.ADMISSION_SLOTS`, выдаёт
# их волна церемонии, каждая личность заводит РОВНО ОДИН аккаунт.
#
# Пара на слот: обычный вход заводит, читает и правит; поднятый — убирает за собой.
_HUMAN_CRUD = "jwtHumanAccCrud"
_HUMAN_CRUD_STEPUP = "jwtHumanAccCrudStepUp"
_HUMAN_CRUD_USER_ID = "humanAccCrudUserId"

_HUMAN_BVA_MIN = "jwtHumanAccBvaMin"
_HUMAN_BVA_MIN_STEPUP = "jwtHumanAccBvaMinStepUp"

_HUMAN_BVA_MAX = "jwtHumanAccBvaMax"
_HUMAN_BVA_MAX_STEPUP = "jwtHumanAccBvaMaxStepUp"

_HUMAN_LSOP = "jwtHumanAccLsop"
_HUMAN_LSOP_STEPUP = "jwtHumanAccLsopStepUp"

# Кейсы, чей предмет — синхронный ОТКАЗ заведения (форма имени, поле в теле, род
# принципала), остаются на человеке церемонии: отвергнутое заведение не списывает
# ничего — транзакция не доходит до фиксации. Здесь же остаётся кейс занятого имени:
# его заведение принимается синхронно, но отменяется уникальностью имени, поэтому
# строки за ним нет и списания тоже.
_HUMAN = "jwtHumanCeremony"

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


def list_accounts_walk(name, auth, assertions, cap=25):
    """Пройти `GET /iam/v1/accounts` ПО КУРСОРУ и утверждать на НАКОПЛЕННОМ множестве.

    ЗАЧЕМ ОБХОД, А НЕ ОДНА СТРАНИЦА. Список читает страницу из своей БД курсором
    `(created_at, id)` и проверяет права на идентификаторы ЭТОЙ страницы — то есть
    «страница → проверка страницы», а не «перечисли вселенную → отфильтруй». Значит
    страница, все строки которой вызывающему недоступны, законно приходит ПУСТОЙ и с
    непустым `nextPageToken`; следовать курсору обязан клиент.

    Замер на стенде (2026-08-04): в таблице 265 аккаунтов, вызывающему доступен один и
    он не попадает в первые 50 по порядку курсора — `GET /iam/v1/accounts` без
    `pageSize` вернул `{accounts: [], nextPageToken: "…"}`. Кейс, читавший одну
    страницу, объявлял это «своего аккаунта не видно».

    ЧЕМ ЭТО ХУЖЕ ПРОСТО КРАСНОГО. Парное ОТРИЦАНИЕ («чужой аккаунт не виден») на пустой
    странице проходит ВАКУУМНО: не увидеть нечего, когда не прочитано ничего. Поэтому
    поднять `pageSize` было бы не исправлением, а отсрочкой — на 1001-м аккаунте
    вернулось бы то же самое, причём молча и со стороны отрицания.

    Поэтому: обход до ИСЧЕРПАНИЯ курсора + отдельное утверждение, что курсор исчерпан, —
    иначе «нет в списке» неотличимо от «не дочитали до конца». Обход ограничен `cap`
    страницами: разбежавшийся курсор обязан упасть, а не крутиться.

    Обход НЕ несёт межзапросной паузы намеренно: это ПРОХОД по страницам, а не опрос
    одного и того же состояния в ожидании сходимости — каждая итерация запрашивает
    строго другую страницу и продвигается (та же оговорка, что у обхода выдач в
    cases/iam-authz-grant-check-propagation.py).
    """
    # Модули кейсов ничего не импортируют — помощники им пробрасываются, поэтому
    # имя переменной чистится без regexp.
    v = "".join(c for c in name if c.isalnum())
    tok, page, acc, started = f"_{v}Tok", f"_{v}Page", f"_{v}Acc", f"_{v}Started"
    return Step(
        name=name,
        method="GET",
        # Декларативная база; пре-скрипт пересобирает URL, добавляя курсор на продолжении.
        path="/iam/v1/accounts?pageSize=1000",
        auth=auth,
        pre_script=[
            f"if (pm.environment.get('{started}') !== pm.info.requestName) {{",
            f"  pm.environment.set('{tok}', '');",
            f"  pm.environment.set('{page}', '0');",
            f"  pm.environment.set('{acc}', '[]');",
            f"  pm.environment.set('{started}', pm.info.requestName);",
            "}",
            # Адрес — собственного фронта (kaname#398): модуль переадресован
            # целиком (`address_own_front` в конце), и обход не возвращает шаг на край.
            "const _b = pm.environment.get('ownRestBaseUrl') || pm.variables.get('ownRestBaseUrl') || '';",
            f"const _t = pm.environment.get('{tok}') || '';",
            "pm.request.url = _b + '/iam/v1/accounts?pageSize=1000'"
            "  + (_t ? '&pageToken=' + encodeURIComponent(_t) : '');",
        ],
        test_script=[
            "pm.test('page status 200', () => pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
            "const j = pm.response.json();",
            "pm.test('accounts array present on every page', () => pm.expect(j.accounts, JSON.stringify(j)).to.be.an('array'));",
            f"const _seen = JSON.parse(pm.environment.get('{acc}') || '[]').concat(((j.accounts) || []).map(a => a.id));",
            f"pm.environment.set('{acc}', JSON.stringify(_seen));",
            f"const _pg = parseInt(pm.environment.get('{page}') || '0', 10);",
            f"if (j.nextPageToken && _pg < {cap}) {{",
            f"  pm.environment.set('{tok}', j.nextPageToken);",
            f"  pm.environment.set('{page}', String(_pg + 1));",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{tok}'); pm.environment.unset('{page}'); pm.environment.unset('{started}');",
            # Без этого утверждения «нет в списке» означало бы «не дочитали».
            f"pm.test('cursor exhausted within {cap} pages (else \"absent\" == \"unread\")',"
            " () => pm.expect(j.nextPageToken || '', 'pages walked: ' + _pg).to.eql(''));",
            "const accounts = _seen;",
            *assertions,
        ],
    )


# ---------------------------------------------------------------------------
# IAM-ACC-CR-CRUD-OK — stateful Create→poll→Get flow
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-CRUD-OK",
    title="Create account → Operation(iop) done → Get confirms id prefix `acc`, name",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # Step 1: Create the account as the CEREMONY HUMAN.
        # `owner_user_id` is derived from the authenticated principal and references
        # `users(id)`, so the caller must be a user — a service-account bearer is
        # refused synchronously. The slot human is produced by the ceremony wave.
        Step(
            name="create",
            method="POST",
            path="/iam/v1/accounts",
            # IAM-1 F1: ownerUserId° is derived-from-caller — NOT sent in the body.
            body={"name": "crud-{{runId}}", "description": "newman account create probe"},
            auth=_HUMAN_CRUD,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "crudAccountId"),
                # IAM-1 F2: Account.Create co-creates a "default" Project (id in
                # metadata.defaultProjectId). Capture it so the Delete case can remove
                # the child first — projects_account_fk is ON DELETE RESTRICT, so
                # Account.Delete fails FailedPrecondition while the default project exists.
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "crudDefaultProjectId"),
            ],
        ),
        # Step 2: Poll Operation until done.
        Step(
            name="poll-op",
            method="GET",
            path="/operations/{{opId}}",
            # OperationService.Get is principal-scoped and hides a foreign operation
            # behind 404 — the poll must run as whoever MINTED the operation.
            auth=_HUMAN_CRUD,
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
                # Extract accountId from operation response if not yet saved from metadata above.
                "if (j.response && j.response.id && !pm.environment.get('crudAccountId')) {",
                "  pm.environment.set('crudAccountId', j.response.id);",
                "}",
            ],
        ),
        # Step 3: Get confirms the created Account.
        retry_until_authorized(Step(
            name="get-confirms",
            method="GET",
            path="/iam/v1/accounts/{{crudAccountId}}",
            auth=_HUMAN_CRUD,
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
                # Владелец выводится из ПРИНЦИПАЛА, а не из тела, поэтому ожидаемое
                # значение — человек церемонии, создавший аккаунт. Сверка с пустой
                # переменной запрещена: она превратила бы утверждение в тождество.
                "pm.test('Account.ownerUserId == the human who created it', () => {",
                "  const j = pm.response.json();",
                f"  const expected = pm.environment.get('{_HUMAN_CRUD_USER_ID}');",
                f"  pm.expect(expected, '{_HUMAN_CRUD_USER_ID} must be seeded by the ceremony wave')"
                ".to.be.a('string').and.to.match(/^usr[a-z0-9]+$/);",
                "  pm.expect(j.ownerUserId, 'ownerUserId must be the creating human').to.eql(expected);",
                "});",
                "pm.test('Account.description matches', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.description, 'description').to.include('account create probe');",
                "});",
                *assert_created_at_seconds("pm.response.json().createdAt"),
            ],
        )),
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
            body={"name": "ACME-{{runId}}"},
            # Предмет кейса — ИМЯ. Под машинным предъявителем запрос отвергался
            # раньше валидации имени (род принципала), и кейс зеленел, ни разу не
            # дойдя до того, что проверяет. Человеческий предъявитель доводит до имени.
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                # Отказ обязан быть ПРО ИМЯ. Без этого утверждения любой другой
                # синхронный 400 (напр. про род принципала) прошёл бы как успех,
                # и кейс снова стал бы неспособным упасть.
                "pm.test('rejection names the invalid field (name)', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument name'));",
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
            body={"name": "crud-{{runId}}", "description": "dup-name"},
            # Тот же человек, что создал оригинал: иначе отказ придёт про род
            # принципала, а не про занятое имя, и Operation вообще не заведётся.
            auth=_HUMAN,
            test_script=[
                *assert_status(200),
                # save to opId (overwriting the CRUD-OK op) so assert_op_error
                # polls the correct duplicate-create operation, not the first successful one.
                *save_from_response("j.id", "opId"),
            ],
        ),
        # Poll and assert error.code == 6 (ALREADY_EXISTS).
        # Текст владельца ЦЕЛИКОМ: «already exists» несут пять разных отказов iam,
        # и утверждение об общей части проходило на отказе о ЧУЖОМ ресурсе (#1748).
        assert_op_error(6, "ALREADY_EXISTS",
                        msg_text="Account with name crud-{{runId}} already exists"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACC-CR-NEG-OWNER-MISSING — REPURPOSED for IAM-1 F1 (redesign-2026):
#   owner_user_id° is OUTPUT-ONLY derived-from-caller. The AS-IS "owner required /
#   unknown owner → error" path is REMOVED — supplying ANY ownerUserId in the Create
#   body is now a sync INVALID_ARGUMENT (before the Operation is minted). See
#   cases/iam-account-redesign.py::IAM-ACC-RD-CR-OWNER-* for the full F1 coverage.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-NEG-OWNER-MISSING",
    title="IAM-1-02: Account.Create с ownerUserId в теле → sync 400 INVALID_ARGUMENT 'Illegal argument "
          "ownerUserId (derived from caller)' (owner° output-only — old required/unknown-owner путь удалён)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-owner-in-body",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "badowner-{{runId}}", "description": "owner-in-body reject", "ownerUserId": "usr00000000000000bad"},
            # Вызывающий обязан быть тем, кто ИНАЧЕ создал бы аккаунт: только тогда
            # снятие проверки поля сделало бы кейс красным. Под машинным предъявителем
            # отказ пришёл бы про род принципала и кейс остался бы зелёным навсегда.
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('derived-from-caller reject text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument ownerUserId (derived from caller)'));",
                "pm.test('no Operation minted', () => pm.expect((pm.response.json().id)||'').to.not.match(/^iop/));",
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
            body={"name": "anon-{{runId}}"},
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
# IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY — REPURPOSED for IAM-1 F1 (redesign-2026):
#   the AS-IS anti-hijack branch (RequireOwnerMatchesPrincipal → 403/400 when
#   owner != principal) is GONE. ownerUserId is output-only by construction, so a
#   mismatched value in the body is simply rejected as INVALID_ARGUMENT (there is
#   nothing to "hijack" — the owner is always the authenticated caller).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY",
    title="IAM-1-02: Account.Create с ownerUserId != caller (человек церемонии шлёт чужой userAAAId) → sync 400 "
          "INVALID_ARGUMENT 'Illegal argument ownerUserId (derived from caller)' (не authz-403 — "
          "anti-hijack-branch удалён, поле output-only)",
    classes=["NEG"],
    priority="P1",
    steps=[
        Step(
            name="create-owner-mismatch",
            method="POST",
            path="/iam/v1/accounts",
            # Тело называет ЧУЖОГО владельца (userAAAId), вызывающий — человек церемонии.
            body={"name": "hijack-{{runId}}", "ownerUserId": "{{userAAAId}}"},
            # ЗАЧЕМ ИМЕННО ЧЕЛОВЕК, А НЕ ПРЕЖНИЙ БЕЗПРАВНЫЙ ПРЕДЪЯВИТЕЛЬ. Кейс сторожит
            # УДАЛЁННУЮ anti-hijack-ветку: если проверку поля однажды снимут, владелец
            # выведется из вызывающего и запрос ПРОЙДЁТ — кейс обязан на этом покраснеть.
            # Под машинным предъявителем он покраснеть не мог: отказ всё равно пришёл бы,
            # только про род принципала. Матрицу «чужие принципалы» держит authz-deny.py.
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('derived-from-caller reject text', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument ownerUserId (derived from caller)'));",
            ],
        ),
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
            body={"name": "a" + "b" * 62 + "z"},  # 64 chars
            # Предмет — ДЛИНА имени. Под машинным предъявителем 400 приходил про род
            # принципала, то есть кейс не проверял границу и не мог упасть.
            auth=_HUMAN,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('rejection names the over-long field (name)', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument name'));",
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
            body={"name": "test' OR 1=1--"},
            # Предмет — обработка инъекции в ИМЕНИ. Под машинным предъявителем запрос
            # отвергался про род принципала, и до имени инъекция не доходила вовсе.
            auth=_HUMAN,
            test_script=[
                "pm.test('not 500', () => pm.expect(pm.response.code).to.not.eql(500));",
                # Строка инъекции не может удовлетворить форму имени продукта, поэтому
                # исход ровно один. Прежнее `oneOf([200,400,413])` принимало и успех, и
                # отказ — то есть не утверждало ничего о том, что инъекция отвергнута.
                *assert_status(400),
                "pm.test('rejection names the field, not the storage layer', () => pm.expect(pm.response.json().message||'', JSON.stringify(pm.response.json())).to.include('Illegal argument name'));",
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
            # jwtNoBindings is used DOUBLY in the seed (also a grant-TARGET for the
            # grant/revoke suites), so under the shared wave it can carry a live
            # v_get on accountAId → 200 (over-visibility that is a SEED artifact, not
            # a product leak). Use the DEDICATED never-granted jwtPureNoBindings so
            # the foreign-deny is a true no-access probe.
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
# IAM-ACC-LS-CRUD-OK — List accounts → 200, scope-filter returns caller's accounts
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="IAM-ACC-LS-CRUD-OK",
    title="List accounts as jwtAccountAdminA → 200, accounts array present",
    classes=["CRUD"],
    priority="P0",
    steps=[
        list_accounts_walk("list-ok", "jwtAccountAdminA", [
            "pm.test('accounts contains accountAId (cursor walked to exhaustion)', () => {",
            "  const aId = pm.environment.get('accountAId');",
            "  pm.expect(aId, 'accountAId must be seeded').to.be.a('string').and.to.match(/^acc[a-z0-9]+$/);",
            "  pm.expect(accounts.indexOf(aId) !== -1, 'seen ids: ' + accounts.length).to.be.true;",
            "});",
        ]),
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
        list_accounts_walk("list-invitee", "jwtInvitee", [
            "pm.test('invitee sees accountBId (member account)', () => {",
            "  const bId = pm.environment.get('accountBId');",
            "  pm.expect(bId, 'accountBId must be seeded').to.be.a('string').and.to.match(/^acc[a-z0-9]+$/);",
            "  pm.expect(accounts.indexOf(bId) !== -1, 'seen ids: ' + accounts.length).to.be.true;",
            "});",
        ]),
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
        # ОТРИЦАНИЕ ЗДЕСЬ ДЕЙСТВИТЕЛЬНО ТОЛЬКО ПРИ ИСЧЕРПАННОМ КУРСОРЕ. «Чужого аккаунта
        # не видно» на ОДНОЙ странице — вакуумная истина, если страница пуста: именно так
        # это отрицание и зеленело, пока парный положительный краснел. Обход до конца
        # делает обе половины осмысленными одновременно.
        list_accounts_walk("list-no-cross-user-leak", "jwtAccountAdminA", [
            "pm.test('SEC-L: owner sees own accountAId', () => {",
            "  const aId = pm.environment.get('accountAId');",
            "  pm.expect(aId, 'accountAId must be seeded').to.be.a('string').and.to.match(/^acc[a-z0-9]+$/);",
            "  pm.expect(accounts.indexOf(aId) !== -1, 'seen ids: ' + accounts.length).to.be.true;",
            "});",
            "pm.test('SEC-L: must NOT see another user accountBId (INV-1)', () => {",
            "  const bId = pm.environment.get('accountBId');",
            "  pm.expect(bId, 'accountBId must be seeded').to.be.a('string').and.to.match(/^acc[a-z0-9]+$/);",
            "  pm.expect(accounts.indexOf(bId) !== -1, 'seen ids: ' + accounts.length).to.be.false;",
            "});",
        ]),
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
            # Аккаунт принадлежит человеку полосы CRUD — правит его владелец.
            auth=_HUMAN_CRUD,
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
            auth=_HUMAN_CRUD,
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
            # The mask alone carries the assertion: the immutable-switch is keyed on
            # the mask path, and `ownerUserId` is not a field of UpdateAccountRequest —
            # sending it would be a key the edge discards.
            body={"updateMask": "owner_user_id"},
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
    title="Delete crud account → remove F2 default project first (RESTRICT FK), then Operation done, Get returns 404",
    classes=["CRUD"],
    priority="P0",
    steps=[
        # IAM-1 F2: the account carries a co-created "default" Project. Account.Delete
        # is fail-closed while children exist (projects_account_fk ON DELETE RESTRICT →
        # FailedPrecondition; TestAccount_08_Delete_WithProjects). Remove the default
        # project first so the account is genuinely child-free.
        Step(
            name="delete-default-project",
            method="DELETE",
            path="/iam/v1/projects/{{crudDefaultProjectId}}",
            # Дочерний проект создан сагой аккаунта, владелец тот же человек.
            # Удаление проекта чувствительно (acr>=2) → поднятый вход.
            auth=_HUMAN_CRUD_STEPUP,
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # ПЕРВАЯ ПОЛОВИНА ПАРЫ — БЕЗ НЕЁ ВТОРАЯ НЕ УТВЕРЖДАЕТ НИЧЕГО.
        #
        # `AccountService/Get` СКРЫВАЕТ СУЩЕСТВОВАНИЕ: при отказе в доступе край
        # отдаёт не 403, а `404 "Account <id> not found"` — байт-в-байт тот же
        # ответ, что и настоящий промах (`HidesExistenceOnDeny`: `/Get` +
        # `v_get` + пообъектная область; сам ответ собран так, чтобы отличить
        # «нет доступа» от «не существует» было нельзя — иначе это оракул
        # существования). Значит «ресурса больше нет» и «этот предъявитель его
        # никогда не видел» — ОДИН И ТОТ ЖЕ ответ, и утверждение о снятии,
        # заданное предъявителю без доступа, зеленеет при любом поведении
        # продукта: удаление могло не сработать вовсе.
        #
        # Поэтому шаг ниже читает аккаунт ТЕМ ЖЕ предъявителем, что и шаг после
        # удаления, и требует 200 с тем самым `id`. Пара «200 до → 404 после»
        # различает два состояния; каждая половина по отдельности — нет.
        #
        # Предъявитель — ВЛАДЕЛЕЦ (`_HUMAN_CRUD`, обычный вход): аккаунт заведён
        # им, право на своей области у него структурное, и читать его он вправе
        # без поднятого входа (`required_acr_min = 1` у `/Get`; поднятый вход
        # нужен удалению, а не чтению). Обе половины идут под ОДНИМ бэрером —
        # иначе между ними менялся бы не только предмет, но и субъект.
        Step(
            name="account-visible-before-delete",
            method="GET",
            path="/iam/v1/accounts/{{crudAccountId}}",
            auth=_HUMAN_CRUD,
            test_script=[
                *assert_status(200),
                "pm.test('владелец ВИДИТ аккаунт до снятия (иначе 404 после ничего не значит)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('crudAccountId'));",
                "});",
            ],
        ),
        Step(
            name="delete",
            method="DELETE",
            path="/iam/v1/accounts/{{crudAccountId}}",
            # Удаление аккаунта якорится на ВЛАДЕЛЬЦЕ (структурный источник прав
            # на своей области), поэтому снести его обязан тот, кто создал — и
            # необратимое удаление требует поднятого уровня входа (acr>=2).
            auth=_HUMAN_CRUD_STEPUP,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # ВТОРАЯ ПОЛОВИНА ПАРЫ. Опрос до терминального «нет» (асинхронное удаление
        # и снятие кортежа владения отстают от `Operation→done` на такт).
        #
        # `auth` НАЗВАН ЯВНО и совпадает с предъявителем шага-пары выше. Умолчание
        # helper'а (`jwtAccountAdminA`) здесь неверно by construction: это машинный
        # предъявитель ЧУЖОГО, посеянного аккаунта, доступа к `crudAccountId` у него
        # не было никогда — и скрытие существования вернуло бы ему 404 на ЖИВОМ
        # аккаунте. Держится это не комментарием: `assert_gone_principal` в gen.py
        # роняет генерацию, если предъявитель шага «ушёл» не показал 200 на том же
        # адресе раньше в том же кейсе.
        get_until_gone("/iam/v1/accounts/{{crudAccountId}}", "Account", auth=_HUMAN_CRUD),
    ],
))


# ---------------------------------------------------------------------------
# ПОЧЕМУ ГРАНИЧНЫЕ КЕЙСЫ ИМЕНИ СТОЯТ ЗДЕСЬ, А НЕ В РАЗДЕЛЕ CREATE
# ---------------------------------------------------------------------------
# Аккаунт занимает слот потолка ОБЪЁМА своей личности (`iam.account`, умолчание 5
# на внешний идентификатор входа), и одновременно живые аккаунты ОДНОЙ личности
# складываются в один потолок.
#
# `IAM-ACC-CR-CRUD-OK` заводит аккаунт, который живёт до `IAM-ACC-DL-CRUD-OK` —
# это НАМЕРЕННАЯ форма полосы CRUD, и сводить её нельзя без потери предмета.
# Пока граничные кейсы стояли в разделе создания И ВСЯ ВОЛНА ШЛА ПОД ОДНИМ
# ЧЕЛОВЕКОМ, их недолговечные аккаунты ложились ПОВЕРХ долгоживущего: пик
# доходил до 4 при потолке 5, то есть запас был в одну единицу. Следствие
# наблюдалось: следующее создание где угодно в волне упиралось в потолок, и
# отказ доставался не тому кейсу, который его вызвал, — читался он как каскад
# отказов в правах, потому что квоту в тексте никто с волной не связывал.
#
# СЕГОДНЯ У КАЖДОГО ЗАВОДЯЩЕГО КЕЙСА ЛИЧНОСТЬ СВОЯ, и складываться этим
# аккаунтам больше не с чем: пик каждой личности равен 2 при потолке 5. Переезд
# кейсов при этом остаётся верным и по второй причине — потолок ТЕМПА (три
# заведения в час), которому уборка не возвращает ничего.
#
# ДЕРЖИТСЯ ГЕЙТОМ, А НЕ ЭТИМ КОММЕНТАРИЕМ:
# `deploy/scripts/assert-identity-account-peak-under-ceiling.py` считает пик
# КАЖДОЙ личности по сгенерированным коллекциям в порядке волны и падает, когда
# запас меньше двух; полосу ТЕМПА держит его сосед
# `deploy/scripts/assert-identity-admission-rate-headroom.py`.
# Сами кейсы от переезда не изменились ни на строку: их предмет — длина имени,
# а не соседство с полосой CRUD.

# ---------------------------------------------------------------------------
# IAM-ACC-CR-BVA-NAME-MIN / -MAX — граничная длина имени → 200
#
# ИМЯ АККАУНТА ГЛОБАЛЬНО УНИКАЛЬНО (`accounts_name_unique UNIQUE (name)`), поэтому
# литеральное имя проходит РОВНО ОДИН РАЗ и коллизится на каждом следующем прогоне.
# Пока создание отвергалось раньше вставки, эта мина была не видна: кейс падал по
# другой причине. Под человеческим предъявителем он бы прошёл один раз и залип.
#
# Поэтому имя СОБИРАЕТСЯ из runId в пре-скрипте, а длина ПРОВЕРЯЕТСЯ утверждением:
# без этой проверки правка энтропии молча сдвинула бы длину, и граничный кейс
# перестал бы быть граничным, оставаясь зелёным. За собой оба кейса убирают —
# иначе аккаунты копятся и списочные контракты поедут.
# ---------------------------------------------------------------------------

def _bva_name_script(var: str, length: int) -> list:
    """Собрать имя ровно `length` символов с энтропией прогона и проверить длину."""
    return [
        "const _rid = String(pm.environment.get('runId') || '').toLowerCase().replace(/[^a-z0-9]/g, '');",
        # Первый символ обязан быть буквой (^[a-z]), остальные — [-a-z0-9].
        "const _A = 'abcdefghijklmnopqrstuvwxyz';",
        "const _B = 'abcdefghijklmnopqrstuvwxyz0123456789';",
        "let _h = 0; for (const _c of _rid) { _h = (_h * 33 + _c.charCodeAt(0)) >>> 0; }",
        f"const _len = {length};",
        "let _n = _A[_h % 26];",
        "const _tail = _rid.slice(-(_len - 1));",
        "for (let _i = 1; _i < _len - _tail.length; _i++) { _n += _B[(_h >>> (_i % 24)) % 36]; }",
        "_n += _tail;",
        "_n = _n.slice(0, _len);",
        f"pm.environment.set('{var}', _n);",
        # Фикстура не снисходительнее продукта: если имя не той длины или не той
        # формы, граничного кейса больше нет — и об этом обязано быть сказано ЗДЕСЬ.
        #
        # ФОРМА: утвердить (назвав переменную), ЗАТЕМ снять шаг. Эталон —
        # gen.py::require_env_url, правило объявлено в exec-coverage.py (STATIC BANS).
        # Прежняя редакция утверждала ВНЕ ветки и шаг всё равно отправляла: сломанная
        # фикстура уезжала на сервер, ответ приходил, и падение читалось как дефект
        # продукта на границе имени — тогда как граничного случая в запросе уже не было.
        # Отправленный шаг со сломанной фикстурой хуже неотправленного: он даёт
        # утверждению предмет, которого тот не описывает.
        # Форма — та же, что у продукта (`pkg/validate/nameform`). Она здесь
        # ВЫПИСАНА, а не импортирована: сценарий исполняется движком коллекции,
        # у которого доступа к дереву нет. Расхождение с продуктом не тихое —
        # утверждение ниже называет переменную и роняет ФИКСТУРУ, а не кейс.
        "const _bvaOk = _rid.length > 0 && _n.length === _len "
        "&& /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/.test(_n);",
        "if (!_bvaOk) {",
        f"  pm.test('fixture: runId is seeded (name entropy source for {var})', "
        "() => pm.expect(_rid.length, 'runId').to.be.above(0));",
        f"  pm.test('fixture: BVA name is exactly {length} chars', "
        "() => pm.expect(_n.length, _n).to.eql(_len));",
        f"  pm.test('fixture: BVA name matches the product name form ({var})', "
        "() => pm.expect(_n).to.match(/^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/));",
        "  pm.execution.skipRequest();",
        "}",
    ]


CASES.append(Case(
    id="IAM-ACC-CR-BVA-NAME-MIN",
    # Контрактный минимум длины имени — ОДИН символ (RFC 1123), а не три: прежняя
    # форма iam была уже канона, и #1279 её сняла. Здесь длина остаётся 3, и это
    # решение, а не недосмотр: имя аккаунта уникально на ВЕСЬ кластер
    # (`accounts_name_unique`), а односимвольных имён всего 26 — параллельные
    # прогоны и соседние арендаторы столкнулись бы на них детерминированно, и
    # кейс падал бы `409` по чужой причине.
    #
    # Единица как ГРАНИЦА утверждается там, где уникальность не мешает: доменный
    # тип (`internal/domain/resource_name_canon_test.go`), путь создания каждого
    # ресурса (`name_canon_test.go` рядом с каждым use-case) и ограничение живой
    # базы (`pkg/nameformdb`, образец «один символ»).
    title="Create с name len=3 → 200 OK",
    classes=["BVA"],
    priority="P2",
    steps=[
        Step(
            name="cr-name-min",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "{{bvaMinName}}"},
            auth=_HUMAN_BVA_MIN,
            pre_script=_bva_name_script("bvaMinName", 3),
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "bvaMinAccId"),
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "bvaMinPrjId"),
            ],
        ),
        poll_operation_until_done(),
        # Уборка: сперва дочерний проект (FK RESTRICT), затем аккаунт.
        *reliable_delete("teardown-bva-min-project", "/iam/v1/projects/{{bvaMinPrjId}}",
                         auth=_HUMAN_BVA_MIN_STEPUP, op_key="bvaMinPrj"),
        *reliable_delete("teardown-bva-min-account", "/iam/v1/accounts/{{bvaMinAccId}}",
                         auth=_HUMAN_BVA_MIN_STEPUP, op_key="bvaMinAcc"),
    ],
))


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
            body={"name": "{{bvaMaxName}}"},
            auth=_HUMAN_BVA_MAX,
            pre_script=_bva_name_script("bvaMaxName", 63),
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "bvaMaxAccId"),
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "bvaMaxPrjId"),
            ],
        ),
        poll_operation_until_done(),
        *reliable_delete("teardown-bva-max-project", "/iam/v1/projects/{{bvaMaxPrjId}}",
                         auth=_HUMAN_BVA_MAX_STEPUP, op_key="bvaMaxPrj"),
        *reliable_delete("teardown-bva-max-account", "/iam/v1/accounts/{{bvaMaxAccId}}",
                         auth=_HUMAN_BVA_MAX_STEPUP, op_key="bvaMaxAcc"),
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
        # Текст владельца ЦЕЛИКОМ: «cannot be deleted» несут ОДИННАДЦАТЬ разных
        # отказов iam, и утверждение об общей части не различало, какая именно
        # помеха удержала удаление (#1748).
        assert_op_error(9, "FAILED_PRECONDITION",
                        msg_text="Account {{accountAId}} contains projects and cannot be deleted"),
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
            body={"name": "lsop-{{runId}}", "description": "newman account list-ops test"},
            auth=_HUMAN_LSOP,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "lsopAccId"),
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "lsopPrjId"),
            ],
        ),
        Step(
            name="poll-create-for-lsop",
            method="GET",
            path="/operations/{{opId}}",
            auth=_HUMAN_LSOP,
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
                "if (j.response && j.response.id && !pm.environment.get('lsopAccId')) {",
                "  pm.environment.set('lsopAccId', j.response.id);",
                "}",
            ],
        ),
        Step(
            name="list-ops",
            method="GET",
            path="/iam/v1/accounts/{{lsopAccId}}/operations",
            auth=_HUMAN_LSOP,
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
        # Уборка: аккаунт этого кейса больше никем не удаляется, а накопление
        # аккаунтов между прогонами двигает списочные контракты соседних кейсов.
        *reliable_delete("teardown-lsop-project", "/iam/v1/projects/{{lsopPrjId}}",
                         auth=_HUMAN_LSOP_STEPUP, op_key="lsopPrj"),
        *reliable_delete("teardown-lsop-account", "/iam/v1/accounts/{{lsopAccId}}",
                         auth=_HUMAN_LSOP_STEPUP, op_key="lsopAcc"),
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


# ===========================================================================
# IAM-ACC-ID-* — ИДЕНТИФИКАТОР АККАУНТА МОЖНО УКАЗАТЬ ПРИ СОЗДАНИИ (kaname#549)
#
# Приёмка `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
# сценарии уровня E. Номер сценария — в идентификаторе кейса (`IAM-ACC-ID-<NN>`).
#
# ЛЮДИ — СЛОТЫ ВОЛНЫ ЦЕРЕМОНИИ (§6.2): арендаторы `AidTen*` без прав на кластере и
# администраторы облака `AidAdm*`, которым посев выдал `system_admin` и утвердил
# выдачу чтением посеянного служебного аккаунта. Один заводящий сценарий — один
# человек и не больше двух успешных заведений сверх регистрации.
#
# ИДЕНТИФИКАТОРЫ X, X2, Y, Z, N — СВЕЖИЕ НА КАЖДЫЙ ПРОГОН: выданный идентификатор
# повторно не выдаётся (Р5), и литерал сгорел бы после первого прогона. Они
# выводятся из `runId` в алфавит генератора; фикстура, не давшая формы генератора,
# роняет себя и запрос не отправляет.
#
# УБОРКА — только того, что заведено положительным шагом, и только по
# идентификатору, который кейс сам назначил либо прочёл из исхода успешной
# операции. Идентификатор из метаданных ОТВЕРГНУТОЙ операции не убирается
# никогда: после реализации он равен занятому чужому (посеянному, личному).
# ===========================================================================

_AID_TEN = {n: (f"jwtHumanAidTen{n}", f"jwtHumanAidTen{n}StepUp", f"humanAidTen{n}UserId")
            for n in ("01", "21", "23", "25", "Shared")}
_AID_ADM = {n: (f"jwtHumanAidAdm{n}", f"jwtHumanAidAdm{n}StepUp", f"humanAidAdm{n}UserId")
            for n in ("03", "04", "12", "13", "16", "19", "22", "Shared")}
_AID_SEEDED = "acc1a18042d81fb438d6"
_AID_FORM = "/^acc[0-9abcdefghjkmnpqrstvwxyz]{17}$/"
_AID_NAME_RESERVED = ("Illegal argument name: the account id form is reserved for the "
                      "account's own id")


def _aid_ids(**salts) -> list:
    """Пред-скрипт: свежие идентификаторы формы генератора из `runId` и соли."""
    out = [
        "const _rid = String(pm.environment.get('runId') || '');",
        "const _AL = '0123456789abcdefghjkmnpqrstvwxyz';",
        "const _aidId = (salt) => {",
        "  let a = 2166136261 >>> 0, b = 5381 >>> 0;",
        "  for (const c of _rid + ':' + salt) {",
        "    a = Math.imul(a ^ c.charCodeAt(0), 16777619) >>> 0;",
        "    b = ((b * 33) ^ c.charCodeAt(0)) >>> 0;",
        "  }",
        "  let s = 'acc';",
        "  for (let i = 0; i < 17; i++) {",
        "    a ^= a << 13; a >>>= 0; a ^= a >>> 17; a ^= a << 5; a >>>= 0;",
        "    b = (Math.imul(b, 1103515245) + 12345) >>> 0;",
        "    s += _AL[((a ^ b) >>> 0) % 32];",
        "  }",
        "  return s;",
        "};",
        "let _aidOk = _rid.length > 0;",
    ]
    for var, salt in salts.items():
        out += [
            f"if (!pm.environment.get({js_str(var)})) pm.environment.set({js_str(var)}, _aidId({js_str(salt)}));",
            f"_aidOk = _aidOk && {_AID_FORM}.test(pm.environment.get({js_str(var)}) || '');",
        ]
    out += [
        "if (!_aidOk) {",
        "  pm.test('fixture: runId is seeded and every derived id has the generator form', "
        "() => pm.expect(_aidOk, 'runId / derived ids').to.eql(true));",
        "  pm.execution.skipRequest();",
        "}",
    ]
    return out


def _aid_reset(*names) -> list:
    """Пред-скрипт первого шага: идентификаторы прогона чеканятся заново на кейс."""
    return [f"pm.environment.unset({js_str(n)});" for n in names]


def _aid_create(name, body, auth, acc_var=None, prj_var=None, pre=(), extra=()):
    """Синхронный приём создания: Operation; захват проекта и (провизорно) аккаунта."""
    script = [*assert_status(200), *assert_iam_operation_envelope(),
              *save_from_response("j.id", "opId")]
    if acc_var:
        script += save_from_response("j.metadata && j.metadata.accountId", acc_var)
    if prj_var:
        script += save_from_response("j.metadata && j.metadata.defaultProjectId", prj_var)
    return Step(name=name, method="POST", path="/iam/v1/accounts", body=body, auth=auth,
                pre_script=list(pre), test_script=[*script, *extra])


def _aid_metadata_is(var) -> list:
    return [f"pm.test({js_str(f'metadata.accountId is the supplied id ({var})')}, () => "
            f"pm.expect((pm.response.json().metadata || {{}}).accountId, JSON.stringify(pm.response.json()))"
            f".to.eql(pm.environment.get({js_str(var)})));"]


def _aid_op_response(name, auth, checks) -> Step:
    """Завершённая операция `opId`: `response` без `error`, и проверки ответа."""
    return Step(name=name, method="GET", path="/operations/{{opId}}", auth=auth, op_var="opId",
                test_script=[
                    *assert_status(200),
                    "const j = pm.response.json();",
                    "pm.test('operation done with response, no error', () => "
                    "pm.expect(j.done === true && Boolean(j.response) && !j.error, JSON.stringify(j)).to.eql(true));",
                    "const r = j.response || {};",
                    *checks,
                ])


def _aid_sync_refusal(name, body, auth, http, code, message, field=None, pre=()) -> Step:
    script = [*assert_status(http), *assert_grpc_code(code, {3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED"}[code]),
              *assert_refusal_message(message),
              "pm.test('the answer is a status, not an Operation', () => "
              "pm.expect(String(pm.response.json().id || ''), pm.response.text()).to.not.match(/^iop/));"]
    if field:
        script.append(
            "pm.test('BadRequest.fieldViolations[0].field is the id field', () => {"
            " const det = (pm.response.json().details || []).find(d => (d['@type'] || '').includes('BadRequest'));"
            " pm.expect(det, pm.response.text()).to.be.an('object');"
            f" pm.expect(((det.fieldViolations || [])[0] || {{}}).field).to.eql({js_str(field)}); }});")
    return Step(name=name, method="POST", path="/iam/v1/accounts", body=body, auth=auth,
                pre_script=list(pre), test_script=script)


def _aid_get_account(name, var, auth, checks, fresh=True) -> Step:
    step = Step(name=name, method="GET", path="/iam/v1/accounts/{{" + var + "}}", auth=auth,
                test_script=[*assert_status(200), "const j = pm.response.json();", *checks])
    return retry_until_authorized(step) if fresh else step


def _aid_get_absent(name, var, auth) -> Step:
    return Step(name=name, method="GET", path="/iam/v1/accounts/{{" + var + "}}", auth=auth,
                test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"),
                             *assert_refusal_message("Account {{" + var + "}} not found")])


def _aid_teardown(tag, acc_var, prj_var, stepup) -> list:
    return [
        *reliable_delete(f"teardown-{tag}-project", "/iam/v1/projects/{{" + prj_var + "}}",
                         auth=stepup, op_key=f"{tag}Prj"),
        *reliable_delete(f"teardown-{tag}-account", "/iam/v1/accounts/{{" + acc_var + "}}",
                         auth=stepup, op_key=f"{tag}Acc"),
    ]


# ── без поля — генератор ───────────────────────────────────────────────────

_t1, _t1s, _t1u = _AID_TEN["01"]
CASES.append(Case(
    id="IAM-ACC-ID-01",
    title="AID-01: без id идентификатор чеканит генератор; пустой id неотличим от отсутствия",
    classes=["CRUD"],
    priority="P0",
    steps=[
        _aid_create("create-without-id", {"name": "aid01-{{runId}}"}, _t1, "aid01Acc", "aid01Prj",
                    extra=["pm.test('metadata.accountId has the generator form', () => "
                           f"pm.expect((pm.response.json().metadata || {{}}).accountId).to.match({_AID_FORM}));"]),
        poll_operation_until_done(),
        _aid_op_response("op-response", _t1, [
            "pm.test('response.id equals metadata.accountId', () => pm.expect(r.id).to.eql(pm.environment.get('aid01Acc')));",
            f"pm.test('ownerUserId is the creating human', () => pm.expect(r.ownerUserId).to.eql(pm.environment.get({js_str(_t1u)})));",
        ]),
        _aid_get_account("get-created", "aid01Acc", _t1, [
            "pm.test('same account', () => pm.expect(j.id).to.eql(pm.environment.get('aid01Acc')));"]),
        _aid_create("create-empty-id", {"name": "aid01b-{{runId}}", "id": ""}, _t1, "aid01bAcc", "aid01bPrj",
                    extra=["pm.test('empty id: metadata.accountId has the generator form', () => "
                           f"pm.expect((pm.response.json().metadata || {{}}).accountId).to.match({_AID_FORM}));"]),
        poll_operation_until_done(),
        _aid_op_response("op-response-empty-id", _t1, [
            "pm.test('response.id equals metadata.accountId', () => pm.expect(r.id).to.eql(pm.environment.get('aid01bAcc')));"]),
        *_aid_teardown("aid01", "aid01Acc", "aid01Prj", _t1s),
        *_aid_teardown("aid01b", "aid01bAcc", "aid01bPrj", _t1s),
    ],
))

# ── указанный идентификатор записан ровно он ───────────────────────────────

_a3, _a3s, _a3u = _AID_ADM["03"]
CASES.append(Case(
    id="IAM-ACC-ID-03",
    title="AID-03: администратор облака с корректным id получает аккаунт ровно с ним",
    classes=["CRUD"],
    priority="P0",
    steps=[
        _aid_create("create-with-id", {"id": "{{aid03X}}", "name": "aid03-{{runId}}"}, _a3,
                    "aid03Acc", "aid03Prj", pre=[*_aid_reset("aid03X"), *_aid_ids(aid03X="aid03")],
                    extra=_aid_metadata_is("aid03X")),
        poll_operation_until_done(),
        _aid_op_response("op-response", _a3, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid03X')));",
            "pm.test('response.name', () => pm.expect(r.name).to.eql('aid03-' + pm.environment.get('runId')));",
            f"pm.test('ownerUserId is the admin', () => pm.expect(r.ownerUserId).to.eql(pm.environment.get({js_str(_a3u)})));",
        ]),
        _aid_get_account("get-x", "aid03X", _a3, [
            "pm.test('id = X', () => pm.expect(j.id).to.eql(pm.environment.get('aid03X')));"]),
        retry_until_authorized(Step(
            name="default-project-belongs-to-x", method="GET", path="/iam/v1/projects/{{aid03Prj}}", auth=_a3,
            test_script=[*assert_status(200),
                         "pm.test('project.accountId = X', () => pm.expect(pm.response.json().accountId)"
                         ".to.eql(pm.environment.get('aid03X')));"])),
        *_aid_teardown("aid03", "aid03Acc", "aid03Prj", _a3s),
    ],
))

_a4, _a4s, _a4u = _AID_ADM["04"]
CASES.append(Case(
    id="IAM-ACC-ID-04",
    title="AID-04: без имени имя аккаунта равно указанному идентификатору",
    classes=["CRUD"],
    priority="P1",
    steps=[
        _aid_create("create-id-only", {"id": "{{aid04X}}"}, _a4, "aid04Acc", "aid04Prj",
                    pre=[*_aid_reset("aid04X"), *_aid_ids(aid04X="aid04")], extra=_aid_metadata_is("aid04X")),
        poll_operation_until_done(),
        _aid_op_response("op-response", _a4, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid04X')));",
            "pm.test('response.name = X', () => pm.expect(r.name).to.eql(pm.environment.get('aid04X')));",
            "pm.test('description names X', () => pm.expect(j.description).to.eql('Create account ' + pm.environment.get('aid04X')));",
        ]),
        *_aid_teardown("aid04", "aid04Acc", "aid04Prj", _a4s),
    ],
))

# ── форма ──────────────────────────────────────────────────────────────────

_as, _ass, _asu = _AID_ADM["Shared"]
_hs, _hss, _hsu = _AID_TEN["Shared"]
_AID05_VALUES = (
    ("upper", "acc7M3K9Q2X5V8B4N6T1"),
    ("letter-u", "acc7m3k9q2x5v8b4n6tu"),
    ("letter-i", "acc7m3k9q2x5v8b4n6ti"),
    ("len-19", "acc7m3k9q2x5v8b4n6t"),
    ("len-21", "acc7m3k9q2x5v8b4n6t12"),
    ("foreign-prefix", "prj7m3k9q2x5v8b4n6t1"),
    ("hyphen-form", "acc-7m3k9q2x5v8b4n6t1"),
    ("leading-space", " acc7m3k9q2x5v8b4n6t1"),
    ("cyrillic-a", "acc7m3k9q2x5v8b4n6tа"),
)
CASES.append(Case(
    id="IAM-ACC-ID-05",
    title="AID-05: негодная форма id отвергается синхронно, до операции (девять значений, по одному факту)",
    classes=["NEG", "BVA"],
    priority="P0",
    steps=[_aid_sync_refusal(f"create-{tag}", {"id": value, "name": "aid05-{{runId}}"}, _as, 400, 3,
                             "invalid account id '" + value + "'", field="id")
           for tag, value in _AID05_VALUES],
))

CASES.append(Case(
    id="IAM-ACC-ID-07",
    title="AID-07: форма проверяется раньше права — не администратор получает тот же отказ формы",
    classes=["NEG"],
    priority="P1",
    steps=[_aid_sync_refusal("create-bad-form", {"id": "acc7M3K9Q2X5V8B4N6T1", "name": "aid07-{{runId}}"},
                             _hs, 400, 3, "invalid account id 'acc7M3K9Q2X5V8B4N6T1'", field="id")],
))

# ── право ──────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="IAM-ACC-ID-08",
    title="AID-08: не администратор облака с корректной формой получает отказ права; аккаунта нет",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        _aid_sync_refusal("create-not-admin", {"id": "{{aid08X}}", "name": "aid08-{{runId}}"}, _hs, 403, 7,
                          "permission denied", pre=[*_aid_reset("aid08X"), *_aid_ids(aid08X="aid08")]),
        _aid_get_absent("admin-sees-no-account", "aid08X", _as),
    ],
))


def _aid09_step(name, var_expr_pre, body_id, store):
    return Step(name=name, method="POST", path="/iam/v1/accounts", auth=_hs,
                body={"id": body_id, "name": "aid09-{{runId}}"}, pre_script=list(var_expr_pre),
                test_script=[*assert_status(403), *assert_grpc_code(7, "PERMISSION_DENIED"),
                             *assert_refusal_message("permission denied"),
                             f"pm.environment.set({js_str(store)}, pm.response.text());"])


CASES.append(Case(
    id="IAM-ACC-ID-09",
    title="AID-09: отказ права побайтово один для невыданного, посеянного и личного идентификатора",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        Step(name="own-personal-account", method="GET", path="/iam/v1/accounts?pageSize=1000", auth=_hs,
             test_script=[*assert_status(200),
                          "const own = (pm.response.json().accounts || []).filter(a => a.ownerUserId === "
                          f"pm.environment.get({js_str(_hsu)}));",
                          "pm.test('fixture: exactly one own (personal) account', () => pm.expect(own.length).to.eql(1));",
                          "pm.environment.set('aid09P', own.length === 1 ? own[0].id : '');"]),
        _aid09_step("create-never-issued", [*_aid_reset("aid09X"), *_aid_ids(aid09X="aid09")], "{{aid09X}}", "aid09BodyX"),
        _aid09_step("create-seeded", [], _AID_SEEDED, "aid09BodySeeded"),
        Step(name="create-own-personal", method="POST", path="/iam/v1/accounts", auth=_hs,
             body={"id": "{{aid09P}}", "name": "aid09-{{runId}}"},
             test_script=[*assert_status(403), *assert_grpc_code(7, "PERMISSION_DENIED"),
                          "pm.test('three refusals are byte-equal', () => {",
                          "  pm.expect(pm.environment.get('aid09BodyX')).to.eql(pm.response.text());",
                          "  pm.expect(pm.environment.get('aid09BodySeeded')).to.eql(pm.response.text());",
                          "});"]),
    ],
))

CASES.append(Case(
    id="IAM-ACC-ID-10",
    title="AID-10: служебная учётка, держащая system_admin, аккаунт не заводит ни с id, ни без",
    classes=["NEG"],
    priority="P1",
    steps=[
        _aid_sync_refusal(
            "machine-with-id", {"id": "{{aid10X}}", "name": "aid10-{{runId}}"}, "jwtBootstrap", 400, 3,
            "Illegal argument ownerUserId (an Account is owned by a user; principal type is service_account)",
            pre=[*_aid_reset("aid10X"), *_aid_ids(aid10X="aid10")]),
        _aid_sync_refusal(
            "machine-without-id", {"name": "aid10b-{{runId}}"}, "jwtBootstrap", 400, 3,
            "Illegal argument ownerUserId (an Account is owned by a user; principal type is service_account)"),
    ],
))

# ── занятый и выданный идентификатор ───────────────────────────────────────

_a12, _a12s, _ = _AID_ADM["12"]
CASES.append(Case(
    id="IAM-ACC-ID-12",
    title="AID-12: занятый живой id — ALREADY_EXISTS в исходе операции, при имени и без",
    classes=["NEG"],
    priority="P0",
    steps=[
        _aid_create("world-i-create", {"id": "{{aid12X}}", "name": "aid12-{{runId}}"}, _a12, None, "aid12Prj",
                    pre=[*_aid_reset("aid12X", "aid12X2"), *_aid_ids(aid12X="aid12", aid12X2="aid12x2")],
                    extra=_aid_metadata_is("aid12X")),
        poll_operation_until_done(),
        _aid_op_response("world-i-created", _a12, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid12X')));"]),
        _aid_create("world-i-again", {"id": "{{aid12X}}", "name": "aid12b-{{runId}}"}, _a12,
                    extra=_aid_metadata_is("aid12X")),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account {{aid12X}} already exists"),
        _aid_create("world-ii-create", {"id": "{{aid12X2}}"}, _a12, None, "aid12Prj2",
                    extra=_aid_metadata_is("aid12X2")),
        poll_operation_until_done(),
        _aid_op_response("world-ii-created", _a12, [
            "pm.test('response.name = X2', () => pm.expect(r.name).to.eql(pm.environment.get('aid12X2')));"]),
        _aid_create("world-ii-again", {"id": "{{aid12X2}}"}, _a12, extra=_aid_metadata_is("aid12X2")),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account {{aid12X2}} already exists"),
        _aid_get_account("x-unchanged", "aid12X", _a12, [
            "pm.test('name unchanged', () => pm.expect(j.name).to.eql('aid12-' + pm.environment.get('runId')));"]),
        _aid_get_account("x2-unchanged", "aid12X2", _a12, [
            "pm.test('name = X2', () => pm.expect(j.name).to.eql(pm.environment.get('aid12X2')));"]),
        *_aid_teardown("aid12", "aid12X", "aid12Prj", _a12s),
        *_aid_teardown("aid12b", "aid12X2", "aid12Prj2", _a12s),
    ],
))

_a13, _a13s, _ = _AID_ADM["13"]
CASES.append(Case(
    id="IAM-ACC-ID-13",
    title="AID-13: повтор того же запроса не создаёт второго и не возвращает существующего",
    classes=["IDM", "NEG"],
    priority="P1",
    steps=[
        _aid_create("first", {"id": "{{aid13X}}", "name": "aid13-{{runId}}", "labels": {"k": "v1"}}, _a13,
                    None, "aid13Prj", pre=[*_aid_reset("aid13X"), *_aid_ids(aid13X="aid13")],
                    extra=[*_aid_metadata_is("aid13X"), "pm.environment.set('aid13FirstOp', pm.response.json().id || '');"]),
        poll_operation_until_done(),
        _aid_get_account("first-state", "aid13X", _a13, [
            "pm.environment.set('aid13CreatedAt', j.createdAt || '');",
            "pm.test('labels', () => pm.expect(j.labels).to.eql({k: 'v1'}));"]),
        _aid_create("repeat", {"id": "{{aid13X}}", "name": "aid13-{{runId}}", "labels": {"k": "v1"}}, _a13),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account {{aid13X}} already exists"),
        Step(name="first-op-still-succeeded", method="GET", path="/operations/{{aid13FirstOp}}", auth=_a13,
             test_script=[*assert_status(200), "const j = pm.response.json();",
                          "pm.test('first op done with response.id = X', () => pm.expect(j.done && j.response && "
                          "j.response.id, JSON.stringify(j)).to.eql(pm.environment.get('aid13X')));"]),
        _aid_get_account("account-unchanged", "aid13X", _a13, [
            "pm.test('labels unchanged', () => pm.expect(j.labels).to.eql({k: 'v1'}));",
            "pm.test('createdAt unchanged', () => pm.expect(j.createdAt).to.eql(pm.environment.get('aid13CreatedAt')));"],
            fresh=False),
        *_aid_teardown("aid13", "aid13X", "aid13Prj", _a13s),
    ],
))

CASES.append(Case(
    id="IAM-ACC-ID-15",
    title="AID-15: посеянный служебный идентификатор не выдаётся",
    classes=["NEG"],
    priority="P0",
    steps=[
        # Имя посеянного аккаунта читается ДО попытки и сверяется ПОСЛЕ: литерал
        # посевной идентичности в дерево не пишется (перепись приёмки
        # seed-identity-names-its-own-service считает его остатком).
        Step(name="seeded-before", method="GET", path=f"/iam/v1/accounts/{_AID_SEEDED}", auth=_as,
             test_script=[*assert_status(200),
                          "pm.test('fixture: seeded account has a name', () => "
                          "pm.expect(pm.response.json().name || '').to.not.eql(''));",
                          "pm.environment.set('aid15SeededName', pm.response.json().name || '');"]),
        _aid_create("create-seeded-id", {"id": _AID_SEEDED, "name": "aid15-{{runId}}"}, _as),
        assert_op_error(6, "ALREADY_EXISTS", msg_text=f"Account {_AID_SEEDED} already exists"),
        Step(name="seeded-unchanged", method="GET", path=f"/iam/v1/accounts/{_AID_SEEDED}", auth=_as,
             test_script=[*assert_status(200),
                          "pm.test('seeded account keeps its name', () => pm.expect(pm.response.json().name)"
                          ".to.eql(pm.environment.get('aid15SeededName')));"]),
    ],
))

_a16, _a16s, _ = _AID_ADM["16"]
CASES.append(Case(
    id="IAM-ACC-ID-16",
    title="AID-16: идентификатор удалённого аккаунта не выдаётся повторно",
    classes=["NEG"],
    priority="P0",
    steps=[
        _aid_create("create-x", {"id": "{{aid16X}}", "name": "aid16-{{runId}}"}, _a16, None, "aid16Prj",
                    pre=[*_aid_reset("aid16X", "aid16Y"), *_aid_ids(aid16X="aid16", aid16Y="aid16y")],
                    extra=_aid_metadata_is("aid16X")),
        poll_operation_until_done(),
        _aid_op_response("x-created", _a16, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid16X')));"]),
        *reliable_delete("delete-x-project", "/iam/v1/projects/{{aid16Prj}}", auth=_a16s, op_key="aid16Prj",
                         terminal_codes=(200,), require_operation=True),
        *reliable_delete("delete-x", "/iam/v1/accounts/{{aid16X}}", auth=_a16s, op_key="aid16Acc",
                         terminal_codes=(200,), require_operation=True),
        _aid_get_absent("x-is-gone", "aid16X", _a16),
        _aid_create("create-x-again", {"id": "{{aid16X}}", "name": "aid16b-{{runId}}"}, _a16,
                    extra=_aid_metadata_is("aid16X")),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account {{aid16X}} already exists"),
        _aid_get_absent("x-still-gone", "aid16X", _a16),
        _aid_create("twin-fresh-y", {"id": "{{aid16Y}}", "name": "aid16y-{{runId}}"}, _a16, None, "aid16PrjY",
                    extra=_aid_metadata_is("aid16Y")),
        poll_operation_until_done(),
        _aid_op_response("y-created", _a16, [
            "pm.test('response.id = Y', () => pm.expect(r.id).to.eql(pm.environment.get('aid16Y')));"]),
        *_aid_teardown("aid16y", "aid16Y", "aid16PrjY", _a16s),
    ],
))

# ── сокрытие существования и лента ─────────────────────────────────────────

_a19, _a19s, _ = _AID_ADM["19"]
_AID19_MASK = ("const _mask = (t, id) => String(t).split(id).join('<ID>');")
CASES.append(Case(
    id="IAM-ACC-ID-19",
    title="AID-19: посторонний не отличает идентификатор, заданный администратором, от невыданного",
    classes=["AUTHZ", "NEG"],
    priority="P0",
    steps=[
        _aid_create("admin-creates-x", {"id": "{{aid19X}}", "name": "aid19-{{runId}}"}, _a19, None, "aid19Prj",
                    pre=[*_aid_reset("aid19X", "aid19Y"), *_aid_ids(aid19X="aid19", aid19Y="aid19y")],
                    extra=_aid_metadata_is("aid19X")),
        poll_operation_until_done(),
        _aid_op_response("x-created", _a19, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid19X')));"]),
        _aid_get_account("twin-admin-reads-x", "aid19X", _a19, [
            "pm.test('id = X', () => pm.expect(j.id).to.eql(pm.environment.get('aid19X')));"]),
        Step(name="stranger-get-x", method="GET", path="/iam/v1/accounts/{{aid19X}}", auth=_hs,
             test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"),
                          *assert_refusal_message("Account {{aid19X}} not found"),
                          "pm.environment.set('aid19GetX', pm.response.text());"]),
        Step(name="stranger-get-y", method="GET", path="/iam/v1/accounts/{{aid19Y}}", auth=_hs,
             test_script=[*assert_status(404), *assert_grpc_code(5, "NOT_FOUND"),
                          *assert_refusal_message("Account {{aid19Y}} not found"), _AID19_MASK,
                          "pm.test('get bodies equal after masking the id', () => pm.expect(_mask(pm.environment.get('aid19GetX'), "
                          "pm.environment.get('aid19X'))).to.eql(_mask(pm.response.text(), pm.environment.get('aid19Y'))));"]),
        Step(name="stranger-ledger-x", method="GET", path="/iam/v1/accounts/{{aid19X}}/operations:all", auth=_hs,
             test_script=["pm.environment.set('aid19OpsX', JSON.stringify({s: pm.response.code, "
                          "c: (() => { try { return pm.response.json().code; } catch (e) { return null; } })(), t: pm.response.text()}));",
                          "pm.test('stranger is refused the ledger of X', () => pm.expect(pm.response.code).to.not.eql(200));"]),
        Step(name="stranger-ledger-y", method="GET", path="/iam/v1/accounts/{{aid19Y}}/operations:all", auth=_hs,
             test_script=[_AID19_MASK,
                          "const x = JSON.parse(pm.environment.get('aid19OpsX') || '{}');",
                          "let c = null; try { c = pm.response.json().code; } catch (e) { c = null; }",
                          "pm.test('ledger answers the same (status, code) pair', () => pm.expect([pm.response.code, c]).to.eql([x.s, x.c]));",
                          "pm.test('ledger bodies equal after masking the id', () => pm.expect(_mask(x.t, pm.environment.get('aid19X')))"
                          ".to.eql(_mask(pm.response.text(), pm.environment.get('aid19Y'))));"]),
        *_aid_teardown("aid19", "aid19X", "aid19Prj", _a19s),
    ],
))

_AID20_COUNT = ("const _ops = (pm.response.json().operations || []);"
                " pm.test('fixture: the ledger is read whole (one page)', () => "
                "pm.expect(pm.response.json().nextPageToken || '').to.eql(''));")
CASES.append(Case(
    id="IAM-ACC-ID-20",
    title="AID-20: неудавшаяся попытка с id P видна в ленте аккаунта P (названный остаток Р9)",
    classes=["AUTHZ"],
    priority="P2",
    steps=[
        Step(name="own-personal-account", method="GET", path="/iam/v1/accounts?pageSize=1000", auth=_hs,
             test_script=[*assert_status(200),
                          "const own = (pm.response.json().accounts || []).filter(a => a.ownerUserId === "
                          f"pm.environment.get({js_str(_hsu)}));",
                          "pm.test('fixture: exactly one own (personal) account', () => pm.expect(own.length).to.eql(1));",
                          "pm.environment.set('aid20P', own.length === 1 ? own[0].id : '');",
                          "if (own.length === 1) pm.environment.set('aid20Before', JSON.stringify("
                          "{name: own[0].name, labels: own[0].labels || {}, createdAt: own[0].createdAt}));"]),
        Step(name="ledger-before", method="GET", path="/iam/v1/accounts/{{aid20P}}/operations:all?pageSize=1000", auth=_hs,
             test_script=[*assert_status(200), _AID20_COUNT,
                          "pm.test('no ALREADY_EXISTS operation before', () => pm.expect(_ops.filter(o => o.error && o.error.code === 6).length).to.eql(0));",
                          "pm.environment.set('aid20Count', String(_ops.length));"]),
        _aid_create("admin-tries-p", {"id": "{{aid20P}}", "name": "aid20-{{runId}}"}, _as,
                    extra=[*_aid_metadata_is("aid20P"), "pm.environment.set('aid20Op', pm.response.json().id || '');"]),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account {{aid20P}} already exists"),
        Step(name="ledger-after", method="GET", path="/iam/v1/accounts/{{aid20P}}/operations:all?pageSize=1000", auth=_hs,
             test_script=[*assert_status(200), _AID20_COUNT,
                          "pm.test('exactly one operation more', () => pm.expect(_ops.length).to.eql(parseInt(pm.environment.get('aid20Count'), 10) + 1));",
                          "const it = _ops.find(o => o.id === pm.environment.get('aid20Op')) || {};",
                          "pm.test('it is the admin attempt, done with ALREADY_EXISTS on P', () => {",
                          "  pm.expect(it.done, JSON.stringify(it)).to.eql(true);",
                          "  pm.expect(it.error && it.error.code).to.eql(6);",
                          "  pm.expect((it.metadata || {}).accountId).to.eql(pm.environment.get('aid20P'));",
                          "});"]),
        Step(name="p-unchanged", method="GET", path="/iam/v1/accounts/{{aid20P}}", auth=_hs,
             test_script=[*assert_status(200), "const j = pm.response.json();",
                          "const b = JSON.parse(pm.environment.get('aid20Before') || '{}');",
                          "pm.test('name, labels, createdAt unchanged', () => pm.expect({name: j.name, labels: j.labels || {}, "
                          "createdAt: j.createdAt}).to.eql(b));"]),
    ],
))

# ── имя формы идентификатора ───────────────────────────────────────────────

_t21, _t21s, _ = _AID_TEN["21"]
CASES.append(Case(
    id="IAM-ACC-ID-21",
    title="AID-21: арендатор не может назвать аккаунт именем формы идентификатора",
    classes=["NEG"],
    priority="P0",
    steps=[
        _aid_sync_refusal("create-name-id-form", {"name": "{{aid21N}}"}, _t21, 400, 3, _AID_NAME_RESERVED,
                          pre=[*_aid_reset("aid21N", "aid21Twin"), *_aid_ids(aid21N="aid21"),
                               "pm.environment.set('aid21Twin', (pm.environment.get('aid21N') || '').slice(0, 19) + 'u');"]),
        _aid_create("twin-last-char-u", {"name": "{{aid21Twin}}"}, _t21, "aid21Acc", "aid21Prj"),
        poll_operation_until_done(),
        _aid_op_response("twin-created", _t21, [
            "pm.test('response.name is the sent name', () => pm.expect(r.name).to.eql(pm.environment.get('aid21Twin')));"]),
        *_aid_teardown("aid21", "aid21Acc", "aid21Prj", _t21s),
    ],
))

_a22, _a22s, _ = _AID_ADM["22"]
CASES.append(Case(
    id="IAM-ACC-ID-22",
    title="AID-22: имя, равное собственному id, допустимо; равное другому — нет",
    classes=["NEG"],
    priority="P1",
    steps=[
        _aid_create("name-equals-own-id", {"id": "{{aid22X}}", "name": "{{aid22X}}"}, _a22, None, "aid22Prj",
                    pre=[*_aid_reset("aid22X", "aid22Z", "aid22X2"),
                         *_aid_ids(aid22X="aid22", aid22Z="aid22z", aid22X2="aid22x2")],
                    extra=_aid_metadata_is("aid22X")),
        poll_operation_until_done(),
        _aid_op_response("own-name-created", _a22, [
            "pm.test('response.id = X', () => pm.expect(r.id).to.eql(pm.environment.get('aid22X')));",
            "pm.test('response.name = X', () => pm.expect(r.name).to.eql(pm.environment.get('aid22X')));"]),
        _aid_sync_refusal("name-is-another-id", {"id": "{{aid22Z}}", "name": "{{aid22X2}}"}, _a22, 400, 3,
                          _AID_NAME_RESERVED),
        _aid_get_absent("z-is-absent", "aid22Z", _a22),
        *_aid_teardown("aid22", "aid22X", "aid22Prj", _a22s),
    ],
))

_t23, _t23s, _ = _AID_TEN["23"]
CASES.append(Case(
    id="IAM-ACC-ID-23",
    title="AID-23: правка имени подчиняется правилу формы идентификатора, правка меток — нет",
    classes=["NEG"],
    priority="P1",
    steps=[
        _aid_create("create-q", {"name": "aid23-{{runId}}"}, _t23, "aid23Q", "aid23PrjQ",
                    pre=[*_aid_reset("aid23N"), *_aid_ids(aid23N="aid23")]),
        poll_operation_until_done(),
        _aid_create("create-r-unnamed", {}, _t23, "aid23R", "aid23PrjR"),
        poll_operation_until_done(),
        Step(name="rename-q-to-id-form", method="PATCH", path="/iam/v1/accounts/{{aid23Q}}", auth=_t23,
             body={"name": "{{aid23N}}", "updateMask": "name"},
             test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT"),
                          *assert_refusal_message(_AID_NAME_RESERVED)]),
        _aid_get_account("q-name-unchanged", "aid23Q", _t23, [
            "pm.test('name of Q unchanged', () => pm.expect(j.name).to.eql('aid23-' + pm.environment.get('runId')));"]),
        Step(name="twin1-rename-q-to-own-id", method="PATCH", path="/iam/v1/accounts/{{aid23Q}}", auth=_t23,
             body={"name": "{{aid23Q}}", "updateMask": "name"},
             test_script=[*assert_status(200), *assert_iam_operation_envelope(), *save_from_response("j.id", "opId")]),
        assert_op_success(),
        _aid_get_account("q-named-q", "aid23Q", _t23, [
            "pm.test('name of Q is Q', () => pm.expect(j.name).to.eql(pm.environment.get('aid23Q')));"], fresh=False),
        Step(name="twin2-relabel-r", method="PATCH", path="/iam/v1/accounts/{{aid23R}}", auth=_t23,
             body={"labels": {"k": "v"}, "updateMask": "labels"},
             test_script=[*assert_status(200), *assert_iam_operation_envelope(), *save_from_response("j.id", "opId")]),
        assert_op_success(),
        _aid_get_account("r-keeps-its-name", "aid23R", _t23, [
            "pm.test('name of R is still R', () => pm.expect(j.name).to.eql(pm.environment.get('aid23R')));",
            "pm.test('labels applied', () => pm.expect(j.labels).to.eql({k: 'v'}));"], fresh=False),
        *_aid_teardown("aid23q", "aid23Q", "aid23PrjQ", _t23s),
        *_aid_teardown("aid23r", "aid23R", "aid23PrjR", _t23s),
    ],
))

_t25, _t25s, _ = _AID_TEN["25"]
CASES.append(Case(
    id="IAM-ACC-ID-25",
    title="AID-25: конфликт обычного имени отвечает прежним текстом",
    classes=["NEG"],
    priority="P1",
    steps=[
        _aid_create("create-name", {"name": "aid25-{{runId}}"}, _t25, "aid25Acc", "aid25Prj"),
        poll_operation_until_done(),
        _aid_create("create-same-name", {"name": "aid25-{{runId}}"}, _t25),
        assert_op_error(6, "ALREADY_EXISTS", msg_text="Account with name aid25-{{runId}} already exists"),
        _aid_create("twin-fresh-name", {"name": "aid25b-{{runId}}"}, _t25, "aid25bAcc", "aid25bPrj"),
        poll_operation_until_done(),
        _aid_op_response("twin-created", _t25, [
            "pm.test('response.name', () => pm.expect(r.name).to.eql('aid25b-' + pm.environment.get('runId')));"]),
        *_aid_teardown("aid25", "aid25Acc", "aid25Prj", _t25s),
        *_aid_teardown("aid25b", "aid25bAcc", "aid25bPrj", _t25s),
    ],
))


# ---------------------------------------------------------------------------
# Ф4-29, Ф4-30 — пространство имён личных аккаунтов зарезервировано
# (приёмка `registration-and-its-three-consequences.md`, Р9 п. 3; kaname#256)
# ---------------------------------------------------------------------------
#
# Префикс `personal-cloud-` — знак личного аккаунта, который заводит СИСТЕМА
# как следствие регистрации. Арендатор глаголами `Create` и `Update` в это
# пространство не входит: синхронный отказ до операции, `INVALID_ARGUMENT`,
# текст Р9 п. 3 побайтово. Каждое утверждение отказа стоит рядом с близнецом,
# отличающимся ОДНИМ фактом — дефисом на границе префикса: без близнеца отказ
# зеленел бы и на продукте, отвергающем любое имя.
#
# Человек — свой слот (`AccRsv`): положительный близнец Ф4-29 заводит аккаунт, а
# заведение списывается с темпа личности. Тот же аккаунт служит «Дано» Ф4-30.
# Второй положительный близнец Ф4-30 — правка прочих полей САМОГО личного
# аккаунта: это личный аккаунт человека церемонии (`ceremonyAccountId`, его
# завела регистрация), метка ставится и снимается тем же кейсом.
_HUMAN_RSV = "jwtHumanAccRsv"
_HUMAN_RSV_STEPUP = "jwtHumanAccRsvStepUp"
_RSV_REFUSAL = "Illegal argument name: prefix 'personal-cloud-' is reserved for personal accounts"


def _rsv_tail_script() -> list:
    """Хвост имён кейса из `runId`: строчные латиница и цифры, не длиннее 12.

    Фикстура не снисходительнее продукта: пустой хвост — не «имя без хвоста», а
    несозданное условие, и шаг снимается, назвав переменную.
    """
    return [
        "const _rid = String(pm.environment.get('runId') || '').toLowerCase().replace(/[^a-z0-9]/g, '');",
        "const _t = _rid.slice(-12);",
        "pm.environment.set('rsvTail', _t);",
        "pm.environment.set('rsvTailUpper', _t.toUpperCase() + 'X');",
        "if (_t.length === 0) {",
        "  pm.test('fixture: runId is seeded (name entropy source for rsvTail)', "
        "() => pm.expect(_t.length, 'runId').to.be.above(0));",
        "  pm.execution.skipRequest();",
        "}",
    ]


def _rsv_refused() -> list:
    return [
        *assert_status(400),
        *assert_grpc_code(3, "INVALID_ARGUMENT"),
        *assert_refusal_message(_RSV_REFUSAL),
        "pm.test('синхронный отказ: операции нет', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, JSON.stringify(j)).to.be.undefined;",
        "});",
    ]


CASES.append(Case(
    id="IAM-ACC-F4-29-RESERVED-PREFIX-ON-CREATE",
    title="Ф4-29: Create с именем из пространства личных аккаунтов → 400 резерва; "
          "близнец без дефиса на границе → аккаунт заведён",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="f429-create-reserved",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "personal-cloud-{{rsvTail}}"},
            auth=_HUMAN_RSV,
            pre_script=_rsv_tail_script(),
            test_script=_rsv_refused(),
        ),
        Step(
            name="f429-reserved-account-absent",
            method="GET",
            path="/iam/v1/accounts?pageSize=1000",
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                "pm.test('аккаунта с отвергнутым именем нет', () => {",
                "  const want = 'personal-cloud-' + pm.environment.get('rsvTail');",
                "  const names = (pm.response.json().accounts || []).map(a => a.name);",
                "  pm.expect(names, JSON.stringify(names)).to.not.include(want);",
                "});",
            ],
        ),
        # Порядок проверок: имя негодной ФОРМЫ с тем же префиксом получает прежний
        # отказ формы, а не отказ резерва.
        Step(
            name="f429-bad-form-keeps-the-form-refusal",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "personal-cloud-{{rsvTailUpper}}"},
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('отказ формы, а не резерва', () => {",
                "  const m = pm.response.json().message || '';",
                "  pm.expect(m, m).to.match(/^Illegal argument name: must match /);",
                "  pm.expect(m, m).to.not.include('is reserved for personal accounts');",
                "});",
            ],
        ),
        # Положительный близнец — одно различие: нет дефиса на границе префикса.
        Step(
            name="f429-twin-create",
            method="POST",
            path="/iam/v1/accounts",
            body={"name": "personal-cloud{{rsvTail}}"},
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accountId", "rsvAccId"),
                *save_from_response("j.metadata && j.metadata.defaultProjectId", "rsvPrjId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="f429-twin-created",
            method="GET",
            path="/iam/v1/accounts/{{rsvAccId}}",
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                "pm.test('аккаунт заведён с именем близнеца', () => {",
                "  pm.expect(pm.response.json().name).to.eql('personal-cloud' + pm.environment.get('rsvTail'));",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-ACC-F4-30-RESERVED-PREFIX-ON-RENAME",
    title="Ф4-30: переименование в пространство личных аккаунтов → 400 резерва, имя прежнее; "
          "близнецы — переименование без дефиса, правка меток и повтор имени личного аккаунта",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        # «Дано» — аккаунт вызывающего, заведённый близнецом Ф4-29.
        Step(
            name="f430-rename-reserved",
            method="PATCH",
            path="/iam/v1/accounts/{{rsvAccId}}",
            body={"name": "personal-cloud-{{rsvTail}}", "updateMask": "name"},
            auth=_HUMAN_RSV,
            # Аккаунта нет — его не завёл близнец Ф4-29: находка о продукте или о
            # кейсе, а не о харнессе, поэтому без метки третьего исхода.
            pre_script=[
                "if (!pm.environment.get('rsvAccId')) {",
                *report_then_skip("«Дано» Ф4-30: аккаунт вызывающего заведён близнецом Ф4-29",
                                  "rsvAccId пуст — близнец Ф4-29 аккаунта не завёл", indent="  "),
                "}",
            ],
            test_script=_rsv_refused(),
        ),
        Step(
            name="f430-name-unchanged",
            method="GET",
            path="/iam/v1/accounts/{{rsvAccId}}",
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                "pm.test('имя аккаунта осталось прежним', () => {",
                "  pm.expect(pm.response.json().name).to.eql('personal-cloud' + pm.environment.get('rsvTail'));",
                "});",
            ],
        ),
        # Первый положительный близнец — одно различие: нет дефиса на границе.
        Step(
            name="f430-twin-rename",
            method="PATCH",
            path="/iam/v1/accounts/{{rsvAccId}}",
            body={"name": "personal-cloudz{{rsvTail}}", "updateMask": "name"},
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="f430-twin-renamed",
            method="GET",
            path="/iam/v1/accounts/{{rsvAccId}}",
            auth=_HUMAN_RSV,
            test_script=[
                *assert_status(200),
                "pm.test('имя сменилось', () => {",
                "  pm.expect(pm.response.json().name).to.eql('personal-cloudz' + pm.environment.get('rsvTail'));",
                "});",
            ],
        ),
        # Второй положительный близнец — правка прочих полей САМОГО личного
        # аккаунта, чьё имя несёт префикс, и повтор его текущего имени.
        Step(
            name="f430-personal-account-read",
            method="GET",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            auth=_HUMAN,
            pre_script=[
                "if (!pm.environment.get('ceremonyAccountId')) {",
                *precondition_not_met("«Дано» Ф4-30: личный аккаунт человека церемонии",
                                      "ceremonyAccountId пуст — волна церемонии его не записала",
                                      indent="  "),
                "}",
            ],
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('fixture: это личный аккаунт — имя несёт префикс', () => "
                "pm.expect(j.name, j.name).to.match(/^personal-cloud-/));",
                "pm.test('fixture: меток у личного аккаунта нет — кейс вернёт их пустыми', () => "
                "pm.expect(Object.keys(j.labels || {}), JSON.stringify(j.labels)).to.be.empty);",
                "pm.environment.set('rsvPersonalName', j.name);",
            ],
        ),
        Step(
            name="f430-personal-account-labels",
            method="PATCH",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            body={"labels": {"f430": "{{rsvTail}}"}, "updateMask": "labels"},
            auth=_HUMAN,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="f430-personal-account-same-name",
            method="PATCH",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            body={"name": "{{rsvPersonalName}}", "updateMask": "name"},
            auth=_HUMAN,
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="f430-personal-account-after",
            method="GET",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            auth=_HUMAN,
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('метка поставлена, имя прежнее', () => {",
                "  pm.expect(j.name).to.eql(pm.environment.get('rsvPersonalName'));",
                "  pm.expect((j.labels || {}).f430).to.eql(pm.environment.get('rsvTail'));",
                "});",
            ],
        ),
        Step(
            name="f430-personal-account-labels-restore",
            method="PATCH",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            body={"labels": {}, "updateMask": "labels"},
            auth=_HUMAN,
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "opId"),
            ],
        ),
        poll_operation_until_done(),
        # Уборка: сперва дочерний проект (FK RESTRICT), затем аккаунт.
        *reliable_delete("teardown-rsv-project", "/iam/v1/projects/{{rsvPrjId}}",
                         auth=_HUMAN_RSV_STEPUP, op_key="rsvPrj"),
        *reliable_delete("teardown-rsv-account", "/iam/v1/accounts/{{rsvAccId}}",
                         auth=_HUMAN_RSV_STEPUP, op_key="rsvAcc"),
    ],
))


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а; kaname#398):
# предъявители людей куёт своя церемония службы на автономном стенде
# (`tests/authz-fixtures/seed_ceremony.py --wave`), и краю платформы здесь
# отвечать не на что.
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "волны церемонии нет поверхности, которую она судит")
