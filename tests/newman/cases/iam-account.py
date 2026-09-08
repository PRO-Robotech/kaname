# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для AccountService.

Covered RPCs:  Create, Get, List, Update, Delete, ListOperations.

CRUD fixture dependency:
  This suite requires a seeded owner user + JWT. It reuses the authz-fixtures
  env vars produced by `tests/authz-fixtures/setup.sh`:
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
  (`scripts/run-ceremony.sh` + `tests/authz-fixtures/prodseed_ceremony.py`):
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
            "const _b = pm.environment.get('baseUrl') || pm.variables.get('baseUrl') || '';",
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
