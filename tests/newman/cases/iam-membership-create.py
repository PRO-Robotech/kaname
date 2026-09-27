# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set создания членства (kaname#181; IAM-ID-1 §4 S3.2, сценарии -01/-02/-05).

Covered RPCs:
  MembershipService.Create (POST /iam/v1/memberships)

Что здесь проверяется по существу
---------------------------------
  * ИСХОД, а не вызов: членство, заведённое новым глаголом, ВИДИМО списком
    названного аккаунта, и повтор той же пары ПРЕЖНИМ глаголом (`UserService.Invite`,
    живёт рядом до стадии S4) строку не удваивает — идентификатор членства ТОТ ЖЕ;
  * `response` операции — `Membership`, а не `User`: состояние, аккаунт, человек;
  * разграничение переехало вместе с полем: чужой аккаунт — отказ ПРАВ, authz-first
    (дверь службы отвечает раньше use-case'а), и он неотличим от отказа по
    несуществующему аккаунту; пустой аккаунт — тоже отказ прав, потому что вызов
    без объекта fail-closed by construction (обе двери: край и собственная дверь
    службы);
  * у КАЖДОГО отрицания положительный контроль — тот же вызывающий в своём аккаунте.

Утверждается ПАРА: HTTP-статус и код `rpc.Status` в теле. HTTP один и тот же у
разных линий отказа (400 у формы и у предусловия), различает их код.

ГДЕ ПРОИЗВОДИТСЯ «400 С ИМЕНЕМ ПОЛЯ» на пустом аккаунте — и почему здесь его НЕТ.
Сервис отвергает пустой `account_id` синхронно, первым стейтментом, текстом
`Illegal argument account_id: required` — это утверждает проба use-case'а
(`internal/apps/kaname/api/user/create_membership_test.go`). Через ЛЮБУЮ дверь
до сервиса такой вызов не доходит: `account_id` есть объект, про который гейт
спрашивает модель прав, пустой объект — вызов без области, и гейт отвечает
отказом прав ДО сервиса (`corelib/authz/catalogderive`, `buildExtractor`, пустой
идентификатор уходит в Check и отвергается). Кейс утверждает то, что производит
дверь службы, — 403/7, — а не то, что производил бы use-case за снятой дверью.

ГДЕ ГОНЯЕТСЯ (e2e-flow.md §7а; kaname#416). Производитель каждого утверждения —
служба, поэтому шаги идут на её СОБСТВЕННЫЙ публичный фронт (`ownRestBaseUrl`,
`address_own_front` в конце модуля), и гоняет модуль задание `stand` процесса
`e2e-newman.yml` — автономный стенд без края платформы. Ключи окружения
(`jwtAccountAdminA/B`, `accountAId/BId`, `runId`) пишет посев этого стенда
(`tests/authz-fixtures/seed_own_stand.py --minted-keys`).

CRUD fixture dependency:
  jwtAccountAdminA / accountAId — распорядитель аккаунта A: СЛУЖЕБНАЯ учётка, а не
      человек; порог повышения (`required_acr_min=2`) машинного принципала не
      касается (`grpcsrv.EvaluateStepUp`, первая ветвь), поэтому создавать членство
      он вправе. Следствие для утверждений: `invitedBy` у членства, заведённого
      машиной, ПУСТ by design (`users.invited_by` — внешний ключ в `users`,
      служебная учётка человеком не является), и здесь он НЕ утверждается.
  jwtAccountAdminB / accountBId — то же для аккаунта B.

verifies: IAM-ID-1-01 (одна строка, два членства — через два аккаунта),
          IAM-ID-1-02 (известная почта во второй аккаунт), IAM-ID-1-05 (повтор идемпотентен).
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`.
HOME = "kaname"

CASES = []

# Well-formed идентификатор аккаунта, который не резолвится НИ ВО ЧТО.
ABSENT_ACCOUNT = "acc00000000000000000"


def _q(text):
    """Строковый литерал JavaScript."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _grpc_code(code, label):
    """Утверждается ПАРА: HTTP-статус проверяется отдельно, здесь — код rpc.Status."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


def _save_body(var):
    return [f"pm.environment.set({_q(var)}, pm.response.text());"]


def _same_body_modulo_scope(var, saved_scope_js, this_scope_js, label):
    """Тела двух отказов равны после подстановки `<ACCT>` вместо ЭХА собственного
    ввода (`account:<id>` в деталях отказа края) — приём тот же, что у чтений
    (`iam-membership-read.py`), и по той же причине: побайтового равенства тел,
    называющих область запроса, не бывает by construction."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const norm = (t, id) => (id ? t.split(id).join('<ACCT>') : t);",
        f"  const saved = norm(pm.environment.get({_q(var)}) || '', {saved_scope_js});",
        f"  const here = norm(pm.response.text(), {this_scope_js});",
        "  pm.expect(here, 'saved=' + saved + ' | here=' + here).to.eql(saved);",
        "});",
    ]


CODE_PERMISSION_DENIED = 7

MBR_EMAIL = "mbr-create-{{runId}}@kacho.local"


def _create_step(name, auth, account_var, email, op_var):
    """POST /iam/v1/memberships → 200 Operation; идентификатор операции — в op_var."""
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/memberships",
        body={"accountId": "{{" + account_var + "}}", "email": email},
        auth=auth,
        test_script=[
            *assert_status(200),
            *assert_operation_envelope(),
            "pm.test('metadata операции — CreateMembershipMetadata: аккаунт и человек названы до исполнения', () => {",
            "  const j = pm.response.json();",
            "  pm.expect(j.metadata && j.metadata.accountId, JSON.stringify(j)).to.eql(pm.environment.get(" + _q(account_var) + "));",
            "  pm.expect(j.metadata && j.metadata.userId, JSON.stringify(j)).to.match(/^usr[a-z0-9]+$/);",
            "});",
            *save_from_response("j.id", op_var),
        ],
    )


def _poll(auth, op_var):
    """Опрос операции по СВОЕЙ переменной (а не общей `opId`): в кейсе их несколько."""
    return Step(
        name="poll-" + op_var,
        method="GET",
        path="/operations/{{" + op_var + "}}",
        auth=auth,
        op_var=op_var,
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
            "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
            "if (!j.done && pc < 60) {",
            "  pm.environment.set('_pollCount', String(pc + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* пауза между поллами */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.environment.unset('_pollStarted');",
            "pm.test('ПРЕДМЕТ КЕЙСА СОЗДАН — операция завершилась без отказа', () => {",
            "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
            "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
            "});",
        ],
    )


# ---------------------------------------------------------------------------
# IAM-ID1-MBR-CREATE-OK — новый глагол заводит членство, видимое списком аккаунта;
# повтор прежним глаголом той же пары строку не удваивает (IAM-ID-1-05,
# предикат снятия kaname#181 п. 3).
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID1-MBR-CREATE-OK",
    title="POST /iam/v1/memberships заводит членство (response — Membership, PENDING), List аккаунта его видит; повтор через users:invite не удваивает",
    classes=["CRUD", "HAPPY", "IDEM"],
    priority="P0",
    steps=[
        _create_step("create-membership", "jwtAccountAdminA", "accountAId", MBR_EMAIL, "mbrCreateOp"),
        _poll("jwtAccountAdminA", "mbrCreateOp"),
        Step(
            name="read-create-response",
            method="GET",
            path="/operations/{{mbrCreateOp}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "pm.test('response операции — Membership названного аккаунта в состоянии PENDING', () => {",
                "  const m = j.response;",
                "  pm.expect(m, JSON.stringify(j)).to.be.an('object');",
                "  pm.expect(m.id, JSON.stringify(m)).to.match(/^mbr-[0-9a-z]{17}$/);",
                "  pm.expect(m.accountId, JSON.stringify(m)).to.eql(pm.environment.get('accountAId'));",
                "  pm.expect(m.userId, JSON.stringify(m)).to.match(/^usr[a-z0-9]+$/);",
                "  pm.expect(m.state, JSON.stringify(m)).to.eql('PENDING');",
                "  pm.expect(m.createdAt, JSON.stringify(m)).to.match(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/);",
                "});",
                "pm.test('у НЕИЗВЕСТНОЙ почты строку завела эта операция — metadata.userId и response.userId совпадают', () => {",
                "  pm.expect(j.response && j.response.userId, JSON.stringify(j)).to.eql(j.metadata && j.metadata.userId);",
                "});",
                *save_from_response("j.response.id", "mbrCreatedId"),
                *save_from_response("j.response.userId", "mbrCreatedUserId"),
            ],
        ),
        Step(
            name="list-shows-the-membership",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{mbrCreatedUserId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ИСХОД: членство ВИДИМО списком названного аккаунта — ровно одна запись с тем же id', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(j.memberships[0].id, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedId'));",
                "  pm.expect(j.memberships[0].state, JSON.stringify(j)).to.eql('PENDING');",
                "});",
            ],
        ),
        # Прежний глагол на ту же пару — до стадии S4 он живёт рядом.
        Step(
            name="repeat-via-users-invite",
            method="POST",
            path="/iam/v1/users:invite",
            body={"accountId": "{{accountAId}}", "email": MBR_EMAIL},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                *save_from_response("j.id", "mbrInviteOp"),
            ],
        ),
        _poll("jwtAccountAdminA", "mbrInviteOp"),
        Step(
            name="invite-returned-the-same-person",
            method="GET",
            path="/operations/{{mbrInviteOp}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('прежний глагол вернул ТУ ЖЕ строку человека', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedUserId'));",
                "});",
            ],
        ),
        Step(
            name="list-still-one-row",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{mbrCreatedUserId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('два глагола на одну пару — ОДНО членство, идентификатор переиспользован', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(j.memberships[0].id, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedId'));",
                "});",
            ],
        ),
        # Повтор НОВЫМ глаголом — зеркало предыдущего порядка (IAM-ID-1-05).
        _create_step("repeat-via-memberships", "jwtAccountAdminA", "accountAId", MBR_EMAIL, "mbrRepeatOp"),
        _poll("jwtAccountAdminA", "mbrRepeatOp"),
        Step(
            name="repeat-answers-the-same-membership",
            method="GET",
            path="/operations/{{mbrRepeatOp}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('повтор новым глаголом отвечает ТЕМ ЖЕ членством — ни второй строки, ни второго id', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.response && j.response.id, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedId'));",
                "  pm.expect(j.response && j.response.userId, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedUserId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID1-MBR-CREATE-SECOND-ACCOUNT — та же почта во ВТОРОЙ аккаунт (IAM-ID-1-01/-02):
# второй строки человека не заводится, членство во втором аккаунте появляется.
# Зависит от первого кейса того же набора: человек уже приглашён в A.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID1-MBR-CREATE-SECOND-ACCOUNT",
    title="Та же почта в аккаунт B новым глаголом → та же строка человека (metadata.userId = известная), второе членство в B; в A членство цело",
    classes=["CRUD", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="create-membership-in-b",
            method="POST",
            path="/iam/v1/memberships",
            body={"accountId": "{{accountBId}}", "email": MBR_EMAIL},
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                "pm.test('ИЗВЕСТНАЯ почта: metadata.userId называет её строку, а не свежего кандидата', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata && j.metadata.userId, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedUserId'));",
                "});",
                *save_from_response("j.id", "mbrSecondOp"),
            ],
        ),
        _poll("jwtAccountAdminB", "mbrSecondOp"),
        Step(
            name="second-membership-response",
            method="GET",
            path="/operations/{{mbrSecondOp}}",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "pm.test('ответ — членство в B ТОГО ЖЕ человека; строка одна на оба аккаунта', () => {",
                "  const j = pm.response.json();",
                "  const m = j.response;",
                "  pm.expect(m.accountId, JSON.stringify(m)).to.eql(pm.environment.get('accountBId'));",
                "  pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('mbrCreatedUserId'));",
                "  pm.expect(m.id, JSON.stringify(m)).to.not.eql(pm.environment.get('mbrCreatedId'));",
                "});",
            ],
        ),
        Step(
            name="membership-in-a-is-intact",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{mbrCreatedUserId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('членство в A не тронуто вторым приглашением', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  pm.expect(j.memberships[0].id, JSON.stringify(j)).to.eql(pm.environment.get('mbrCreatedId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID1-MBR-CREATE-NEG-AUTHZ — разграничение переехало вместе с полем: чужой
# аккаунт, несуществующий аккаунт и ПУСТОЙ аккаунт отвечают отказом ПРАВ, authz-first;
# чужой и несуществующий — неотличимо. Положительный контроль — свой аккаунт.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID1-MBR-CREATE-NEG-AUTHZ",
    title="Create в чужой аккаунт → 403 authz-first; несуществующий — тот же ответ; пустой accountId — отказ прав (вызов без объекта fail-closed); свой — 200",
    classes=["NEG", "AUTHZ", "ORACLE"],
    priority="P0",
    steps=[
        Step(
            name="create-in-foreign-account",
            method="POST",
            path="/iam/v1/memberships",
            body={"accountId": "{{accountBId}}", "email": "mbr-neg-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_grpc_code(CODE_PERMISSION_DENIED, "код — PERMISSION_DENIED: отказ прав, а не формы"),
                "pm.test('отказ не называет ни отношения, ни причины отказа модели', () => {",
                "  const t = pm.response.text().toLowerCase();",
                "  pm.expect(t).to.not.include('editor');",
                "  pm.expect(t).to.not.include('lacks relation');",
                "});",
                "pm.test('операции НЕ чеканится: тела операции в отказе нет', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata, JSON.stringify(j)).to.not.exist;",
                "  pm.expect(j.done, JSON.stringify(j)).to.not.exist;",
                "});",
                *_save_body("mbrForeignBody"),
            ],
        ),
        Step(
            name="create-in-absent-account",
            method="POST",
            path="/iam/v1/memberships",
            body={"accountId": ABSENT_ACCOUNT, "email": "mbr-neg-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_same_body_modulo_scope(
                    "mbrForeignBody",
                    "pm.environment.get('accountBId')",
                    _q(ABSENT_ACCOUNT),
                    "АНТИ-ОРАКУЛ: чужой аккаунт и несуществующий отвечают ОДИНАКОВО после "
                    "нормализации эха собственного ввода",
                ),
            ],
        ),
        Step(
            name="create-without-account",
            method="POST",
            path="/iam/v1/memberships",
            body={"email": "mbr-neg-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_grpc_code(CODE_PERMISSION_DENIED,
                            "пустой accountId — вызов БЕЗ ОБЪЕКТА: гейт отвергает его до сервиса, "
                            "fail-closed; сервисный 400 с именем поля за дверью недостижим by construction"),
                "pm.test('операции НЕ чеканится', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata, JSON.stringify(j)).to.not.exist;",
                "});",
            ],
        ),
        Step(
            name="control-own-account-is-admitted",
            method="POST",
            path="/iam/v1/memberships",
            body={"accountId": "{{accountAId}}", "email": "mbr-neg-{{runId}}@kacho.local"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_operation_envelope(),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же вызывающий в СВОЁМ аккаунте принят — "
                "отказы выше суть свойство прав, а не сломанного пути', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/);",
                "});",
                *save_from_response("j.id", "mbrControlOp"),
            ],
        ),
        _poll("jwtAccountAdminA", "mbrControlOp"),
    ],
))


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а; см. шапку).
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "ресурса нет адреса на автономном стенде, и кейс "
                                 "проверял бы край платформы вместо предмета")
