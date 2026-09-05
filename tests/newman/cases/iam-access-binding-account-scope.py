# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: «выдачи субъекта в названном аккаунте» одним вызовом (задача #1737).

Предмет — поле `accountId` у `GET /iam/v1/accessBindings`: сужение страницы до
области ОДНОГО аккаунта, то есть выдачи на самом аккаунте ПЛЮС выдачи на каждом
его проекте. Композируется с `filter` (один предикат) и с `includeRevoked`.

Приёмка: services/iam/docs/engineering/acceptance/subject-grants-within-an-account.md
(§5 сценарии IAM-AB-SIA-NN, §8 предикат готовности).

ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ И ЧЕГО НЕ ВИДЯТ ПРОБЫ GO. Пробы уровня use-case знают
дублёра, пробы репозитория — SQL; ни те, ни другие не проходят через КРАЙ.
Поле новое, а край перекодирует ответ своими стабами и неизвестное ему поле
запроса отбрасывает молча (`api-conventions.md` §«Поле контракта не выходит
наружу, пока КРАЙ не пересобран»). Единственный способ увидеть это — послать
запрос через :8080.

РАЗЛИЧАЮЩИЙ КЕЙС — IAM-AB-SIA-06 ниже. Остальные положительные зеленели бы и на
реализации, которая поле принимает и выбрасывает: они спрашивают про строки,
которые видны и без сужения. Различает пара «accountId против scopeId»: у
выдачи на ПРОЕКТЕ аккаунта `scopeId=<аккаунт>` не матчит вовсе, поэтому ответы
двух запросов обязаны РАЗЛИЧАТЬСЯ, и различие производится только фан-аутом.

Техники (testing-product-coach): ECP (область: сам аккаунт | его проект | чужой
аккаунт), BVA (пустая строка — законный вход; негодная форма — отказ), decision
table (accountId × filter × includeRevoked), error-guessing (id чужого типа),
anti-oracle (чужой и несуществующий аккаунт отвечают одинаково).

Дисциплина (testing.md): read-your-writes → `retry_until_present` (общий
слой) на ПЕРВОЕ списочное чтение своей свежей выдачи; отрицательные кейсы НЕ оборачиваются
повтором (повтор там маскирует настоящий отказ); каждый кейс сеет своё и за
собой убирает; имена run-unique через {{runId}}.
"""

CASES = []

# Системная роль только для чтения — годится и на аккаунте, и на проекте.
SYS_VIEW = "rol1bda80f2be4d3658e"


def assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def _grant(name, scope_type, scope_id, save_var):
    """Выдать субъекту {{userNOBId}} роль просмотра в названной области."""
    return [
        Step(name=name, method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "user", "subjectId": "{{userNOBId}}",
                   "roleId": SYS_VIEW, "scopeType": scope_type, "scopeId": scope_id,
                   "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *assert_iam_op(),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", save_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _cleanup(save_var, name="cleanup-binding"):
    # Уборка best-effort: отказ теардауна не есть дефект кейса под проверкой.
    return [Step(name=name, method="DELETE", path="/iam/v1/accessBindings/{{" + save_var + "}}",
                 auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
            poll_operation_until_done(required=False)]


def _ids_js(var):
    """JS-выражение: массив id выдач из тела ответа в переменную `var`."""
    return f"const {var} = (pm.response.json().accessBindings || []).map(b => b.id);"




# ===========================================================================
# IAM-AB-SIA-01 — фан-аут покрывает аккаунт И его проекты
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-01-FANOUT-OK",
    title="IAM-AB-SIA-01: List ?accountId=<A> отдаёт выдачу на самом аккаунте A И выдачу на его "
          "проекте — охват ListByAccount одним вызовом канонического чтения",
    classes=["CRUD", "CONF"],
    priority="P0",
    steps=[
        *_grant("grant-on-account", "iam.account", "{{accountAId}}", "siaAcbAcct"),
        *_grant("grant-on-project", "iam.project", "{{projectA1Id}}", "siaAcbProj"),
        retry_until_present(Step(
            name="list-account-scope",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('строка на самом аккаунте видна', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaAcbAcct')));",
                "pm.test('строка на ПРОЕКТЕ аккаунта видна — это и есть фан-аут', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaAcbProj')));",
            ],
        # Ждём ОБЕ строки, а не одну: шаг утверждает присутствие и той и другой,
        # и ожидание у́же утверждения даёт падение на второй, пока она ещё
        # материализуется. До сведения обёрток эта форма была недоступна —
        # кейс-локальная копия принимала ровно одно имя.
        ), ["siaAcbAcct", "siaAcbProj"]),
        *_cleanup("siaAcbAcct", name="cleanup-binding-acct"),
        *_cleanup("siaAcbProj", name="cleanup-binding-proj"),
    ],
))


# ===========================================================================
# IAM-AB-SIA-06 — РАЗЛИЧАЮЩИЙ: поле применено, а не принято и выброшено
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-06-DISCRIMINATING-OK",
    title="IAM-AB-SIA-06: ?accountId=<A> и ?filter=scope=\"iam.account\"&scopeId=<A> отвечают РАЗНЫМ "
          "составом — выдача на ПРОЕКТЕ аккаунта проходит только через accountId (фан-аут), "
          "и это единственный кейс, отличающий работающее поле от прочитанного и не применённого",
    classes=["CONF"],
    priority="P0",
    steps=[
        *_grant("disc-grant-project", "iam.project", "{{projectA1Id}}", "siaDiscProj"),
        # Сначала дожидаемся видимости свежей строки — ТОЛЬКО здесь, на первом
        # доступе к своему. Ниже повтора нет: там утверждается ОТСУТСТВИЕ, и
        # повтор на нём маскировал бы настоящий дефект.
        retry_until_present(Step(
            name="disc-list-by-account",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('accountId ВИДИТ выдачу на проекте аккаунта', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaDiscProj')));",
            ],
        ), "siaDiscProj"),
        Step(
            name="disc-list-by-scope-id",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&filter=scope%3D%22iam.account%22",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                # scopeId сверяется с resource_id строки, поэтому выдача на
                # ПРОЕКТЕ под `scope="iam.account"` не матчит вовсе. Ответы двух
                # запросов обязаны различаться — иначе поле ничего не сделало.
                "pm.test('scope=iam.account НЕ видит выдачу на проекте — ответы различаются', () =>",
                "  pm.expect(ids, pm.response.text()).to.not.include(pm.environment.get('siaDiscProj')));",
            ],
        ),
        *_cleanup("siaDiscProj"),
    ],
))


# ===========================================================================
# IAM-AB-SIA-02 — композиция с фильтром субъекта
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-02-COMPOSES-WITH-SUBJECT-OK",
    title="IAM-AB-SIA-02: ?accountId=<A>&filter=subject=\"<userNOB>\" — предикаты конъюнктивны: "
          "своя выдача субъекта видна, а выдач других субъектов того же аккаунта в ответе нет",
    classes=["CONF"],
    priority="P1",
    steps=[
        *_grant("comp-grant", "iam.account", "{{accountAId}}", "siaCompAcb"),
        retry_until_present(Step(
            name="comp-list",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}"
                 "&filter=subject%3D%22{{userNOBId}}%22",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('своя выдача субъекта видна', () => {",
                "  const ids = (pm.response.json().accessBindings || []).map(b => b.id);",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaCompAcb'));",
                "});",
                "pm.test('каждая строка принадлежит названному субъекту', () => {",
                "  const rows = pm.response.json().accessBindings || [];",
                "  const want = pm.environment.get('userNOBId');",
                "  rows.forEach(b => pm.expect(b.subjectId, JSON.stringify(b)).to.eql(want));",
                "});",
            ],
        ), "siaCompAcb"),
        *_cleanup("siaCompAcb"),
    ],
))


# ===========================================================================
# IAM-AB-SIA-03 — композиция с includeRevoked (обе стороны)
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-03-COMPOSES-WITH-INCLUDE-REVOKED-OK",
    title="IAM-AB-SIA-03: отозванная выдача видна под ?accountId=<A>&includeRevoked=true и СКРЫТА "
          "без флага — утверждается ПАРА (одно «видна» зеленело бы на реализации, не скрывающей "
          "отозванные никогда). Первое покрытие includeRevoked чёрным ящиком вообще",
    classes=["CONF", "NEG"],
    priority="P1",
    steps=[
        *_grant("rev-grant", "iam.account", "{{accountAId}}", "siaRevAcb"),
        retry_until_present(Step(
            name="rev-visible-before",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('живая выдача видна до отзыва (положительный контроль)', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaRevAcb')));",
            ],
        ), "siaRevAcb"),
        Step(name="rev-revoke", method="POST",
             path="/iam/v1/accessBindings/{{siaRevAcb}}:revoke", body={},
             auth="jwtAccountAdminAStepUp",
             test_script=[*assert_status(200), *assert_iam_op(),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(auth="jwtAccountAdminAStepUp"),
        assert_op_success(auth="jwtAccountAdminAStepUp"),
        Step(
            name="rev-hidden-by-default",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('без флага отозванная строка скрыта', () =>",
                "  pm.expect(ids, pm.response.text()).to.not.include(pm.environment.get('siaRevAcb')));",
            ],
        ),
        Step(
            name="rev-shown-with-flag",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=1000&accountId={{accountAId}}&includeRevoked=true",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('с флагом отозванная строка возвращается — сужение по аккаунту её не теряет', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('siaRevAcb')));",
            ],
        ),
        # Отозванная строка удаляется жёстко, чтобы прогон был идемпотентным.
        *_cleanup("siaRevAcb"),
    ],
))


# ===========================================================================
# IAM-AB-SIA-13 — пустая строка означает «не сужать»
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-13-EMPTY-IS-LEGAL-OK",
    title="IAM-AB-SIA-13: ?accountId= (пусто) → 200, а НЕ 400: пустое значение означает «не сужать», "
          "а не «аккаунт с пустым id»",
    classes=["BVA"],
    priority="P1",
    steps=[
        Step(
            name="sia-empty-account-id",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=100&accountId=",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ответ несёт массив выдач', () =>",
                "  pm.expect(pm.response.json().accessBindings === undefined "
                "|| Array.isArray(pm.response.json().accessBindings), pm.response.text()).to.eql(true));",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-AB-SIA-10/11 — анти-оракул: чужой и несуществующий аккаунт неотличимы
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-10-11-ANTI-ORACLE-OK",
    title="IAM-AB-SIA-10/11: ?accountId=<чужой> и ?accountId=<несуществующий, годной формы> отвечают "
          "200 с пустым перечнем и ТЕЛА совпадают — различимый ответ здесь есть оракул существования "
          "аккаунта (утверждается равенство тел, а не только кодов)",
    classes=["NEG", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="sia-foreign-account",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=100&accountId={{accountBId}}",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('чужой аккаунт → пустой перечень, НЕ 403 и НЕ 404', () => {",
                "  const rows = pm.response.json().accessBindings || [];",
                "  pm.expect(rows.length, pm.response.text()).to.eql(0);",
                "});",
                "pm.environment.set('siaForeignBody', JSON.stringify(pm.response.json()));",
            ],
        ),
        Step(
            name="sia-absent-account",
            method="GET",
            # Форма годна (префикс acc + крокфордово тело), аккаунта нет.
            path="/iam/v1/accessBindings?pageSize=100&accountId=acc00000000000absnt1",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('тела совпадают: существование аккаунта по ответу не читается', () =>",
                "  pm.expect(JSON.stringify(pm.response.json()), pm.response.text())",
                "    .to.eql(pm.environment.get('siaForeignBody')));",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-AB-SIA-12 / 16 — отказ формы, тем же производителем и тем же телом
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-12-MALFORMED-NEG",
    title="IAM-AB-SIA-12: ?accountId=not-an-id → 400 INVALID_ARGUMENT, тело плоское "
          "\"invalid account id 'not-an-id'\" — производитель ВЛАДЕЛЕЦ; у ListByAccount на том же "
          "поле производитель ДРУГОЙ (край), и текст его",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="sia-malformed-account-id",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=100&accountId=not-an-id",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('контракт-тон сообщения', () =>",
                "  pm.expect(pm.response.json().message, pm.response.text())",
                "    .to.eql(\"invalid account id 'not-an-id'\"));",
            ],
        ),
        # ТОТ ЖЕ ВХОД У СНИМАЕМОГО ГЛАГОЛА ДАЁТ ДРУГОЕ ТЕЛО, И ЭТО ФАКТ, А НЕ
        # ПОСЛАБЛЕНИЕ. Здесь стояло требование побайтового равенства двух тел; оно
        # опиралось на утверждение приёмки «производитель ОДИН на поле» — и
        # утверждение неверно. Производителя ДВА, потому что поле у двух глаголов
        # играет РАЗНЫЕ роли:
        #
        #   у `List` `accountId` — ФИЛЬТР: единого объекта для проверки у края нет
        #   (`scope_filtered`), запрос доезжает до владельца, и отказ его —
        #   `invalid account id '<X>'` (шаг выше);
        #
        #   у `ListByAccount` `account_id` — ЦЕЛЬ АВТОРИЗАЦИИ (`scope_extractor`),
        #   и край обязан судить её форму ДО модели прав, иначе отказ «пути нет»
        #   замаскирует 400 под 403. Отвечает КРАЙ, своим нейтральным именем
        #   ресурса: `invalid resource id '<X>'`.
        #
        # Утверждение осталось РАВЕНСТВОМ и осталось строгим — сменился не его вид,
        # а названный производитель. Ослабления до `oneOf` здесь нет: два текста
        # закреплены порознь, и смена любого красит прогон.
        #
        # Нейтральное имя ресурса у края — предмет ОТДЕЛЬНОЙ задачи #1932 (полос у
        # класса 210 из 346, 25 типов, все семь сервисов). Появится словарь имён —
        # этот шаг покраснеет и позовёт к себе.
        #
        # В дереве то же самое утверждает
        # `gateway/internal/middleware/authz_account_id_refusal_parity_test.go`:
        # он гонит настоящий страж края с настоящими записями каталога обоих
        # глаголов и не требует поднятого стенда.
        Step(
            name="sia-malformed-parity-with-list-by-account",
            method="GET",
            path="/iam/v1/accounts/not-an-id/accessBindings?pageSize=100",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('у цели авторизации отказ формы производит край, и текст его', () =>",
                "  pm.expect(pm.response.json().message, pm.response.text())",
                "    .to.eql(\"invalid resource id 'not-an-id'\"));",
            ],
        ),
    ],
))


CASES.append(Case(
    id="IAM-AB-SIA-16-WRONG-PREFIX-NEG",
    title="IAM-AB-SIA-16: ?accountId=<id проекта> — крокфордова форма годна, префикс не тот → "
          "400 INVALID_ARGUMENT (полоса СТРОГАЯ, паритет с ListByAccount на этом же поле)",
    classes=["NEG", "VAL"],
    priority="P1",
    steps=[
        Step(
            name="sia-wrong-prefix",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=100&accountId={{projectA1Id}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('сообщение называет ресурс, за который поле отвечает', () =>",
                "  pm.expect(pm.response.json().message, pm.response.text())",
                "    .to.include('invalid account id'));",
            ],
        ),
    ],
))


# ===========================================================================
# IAM-AB-SIA-14 — формат ДО замыкания на пустом гранте
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-SIA-14-FORMAT-BEFORE-EMPTY-GRANT-NEG",
    title="IAM-AB-SIA-14: вызывающий БЕЗ единой выдачи, ?accountId=<годный>&pageToken=<мусор> → 400, "
          "а не 200 с пустой страницей — порядок «формат → допуск → репозиторий» не зависит от того, "
          "что вызывающему выдано",
    classes=["NEG", "PAGE"],
    priority="P0",
    steps=[
        Step(
            name="sia-garbage-token-empty-grant",
            method="GET",
            path="/iam/v1/accessBindings?accountId={{accountAId}}&pageToken=%25%25%25not-base64%25%25%25",
            auth="jwtPureNoBindings",
            test_script=[*assert_status(400), *assert_grpc_code(3, "INVALID_ARGUMENT")],
        ),
        Step(
            name="sia-malformed-account-empty-grant",
            method="GET",
            path="/iam/v1/accessBindings?accountId=not-an-id",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(3, "INVALID_ARGUMENT"),
                "pm.test('пустой грант не превращает 400 в 200 []', () =>",
                "  pm.expect(pm.response.json().message, pm.response.text())",
                "    .to.eql(\"invalid account id 'not-an-id'\"));",
            ],
        ),
        # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же вызывающий с законным входом получает
        # 200. Без него оба отрицания выше зеленели бы на реализации, которая
        # отвергает у этого субъекта всё подряд.
        Step(
            name="sia-legal-input-empty-grant-passes",
            method="GET",
            path="/iam/v1/accessBindings?pageSize=100&accountId={{accountAId}}",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('законный вход при пустом гранте проходит', () => {",
                "  const rows = pm.response.json().accessBindings || [];",
                "  pm.expect(rows.length, pm.response.text()).to.eql(0);",
                "});",
            ],
        ),
    ],
))
