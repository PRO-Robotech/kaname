# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set чтения ПРИВИЛЕГИЙ названного субъекта чёрным ящиком (задача #1438).

Covered RPC:
  AccessBindingService.ListSubjectPrivileges
  (GET /iam/v1/accessBindings:listSubjectPrivileges?subjectType=&subjectId=)

Почему набор заведён
--------------------
Глагол отдаёт ПЕРЕЧЕНЬ ВЫДАЧ названного субъекта. На этой поверхности только что
закрыли два предмета: расхождение допуска между полосами (#1352) и отдачу перечня
целиком допущенному по ОДНОМУ аккаунту (#1354). Оба закрыты пробами уровня кода —
через край не проверялся НИ ОДИН. Единственный потребитель глагола — консоль,
то есть поведение, которое видит арендатор, держалось проверками того слоя, куда
арендатор не ходит. Обойдут сужение на крае (каталог разрешений, извлечение
области, порядок проверок) — код-пробы этого не заметят by construction.

Что здесь проверяется по существу
---------------------------------
Не «отвечает ли чтение», а то, что ДОПУСК И ПОЛНОТА ОТВЕТА — разные вещи:

  * СОБСТВЕННОЕ чтение отдаёт все выдачи субъекта, включая те, чья ОБЛАСТЬ лежит
    в чужом аккаунте (ответ не шире того, что вызывающему и так принадлежит);
  * РАСПОРЯДИТЕЛЬ домашнего аккаунта субъекта допущен — и его страница СУЖЕНА
    построчно: выдача в его аккаунте видна, выдача в чужом не видна вовсе, то
    есть состав чужих арендаторов по ответу не картируется;
  * ПОСТОРОННИЙ получает отказ, и отказ этот НИЧЕГО не сообщает о существовании
    субъекта: «есть, но не ваш» и «нет вовсе» отвечают побайтово одинаково.

ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ У КАЖДОГО ОТРИЦАНИЯ — И ОН ВНУТРИ КЕЙСА, А НЕ В СОСЕДНЕМ.
Утверждение «строки про аккаунт B не пришло» истинно и у поверхности, которая не
отдаёт ничего; утверждение «посторонний отвергнут» истинно и у поверхности,
которая отвергает всех. Поэтому:

  * узость страницы распорядителя сверяется с ГРУНТОМ, снятым в ТОМ ЖЕ кейсе
    собственным чтением того же субъекта: сперва доказывается, что строка про
    аккаунт B существует и через этот самый глагол на этом самом крае достаётся,
    и только потом — что распорядителю она не приходит. Плюс строка про его
    СОБСТВЕННЫЙ аккаунт прийти обязана, иначе «сузилось» неотличимо от «не
    материализовалось»;
  * рядом с каждым отказом стоит шаг, где ТОТ ЖЕ субъект читается ЗАКОННЫМ
    вызывающим и отвечает 200: отказ тогда говорит об авторитете, а не о мёртвом
    предъявителе, недоехавшей фикстуре или снятом маршруте.

Утверждается ПАРА — HTTP-статус И `code` из тела `google.rpc.Status`. Порознь
первый не отличает валидацию от состояния (400 приходит и от INVALID_ARGUMENT, и
от FAILED_PRECONDITION), а второй не заметит смены отображения на крае.

Толерантных `oneOf` здесь НЕТ НИ ОДНОГО, и это свойство поверхности, а не
строгость ради строгости. Запись каталога у этого глагола — `scope_filtered`:
край пообъектной проверки за него не делает и пропускает всякого
аутентифицированного, поэтому знаменитая полоса «authz-first» (403 раньше
валидации) здесь не производится вовсе. Полный порядок сервиса — тип субъекта →
префикс идентификатора → формат страницы → допуск → существование, — и он
однозначен на каждом входе набора.

CRUD fixture dependency (всё сеют общие фикстуры, ни одной своей записи набор не
создаёт и потому за собой не убирает — убирать нечего):
  svaInviteeId / jwtInvitee — служебная учётка, ДОМАШНИЙ аккаунт которой — A, а
      выдачи лежат в ДВУХ аккаунтах: `edit` на проекте A1 (внутри A) и `admin` на
      АККАУНТЕ B (снаружи). Ровно та форма, ради которой сужение и заведено:
      допуск решается по домашнему аккаунту, а строки называют область каждой
      выдачи. Пара «идентификатор ↔ предъявитель» объявлена в
      `tests/authz-fixtures/principal_pairings.py` и там же проверяется.
  jwtAccountAdminA / accountAId — распорядитель аккаунта A (служебная учётка).
      Допущен к субъекту, чей домашний аккаунт — A; страница ему СУЖАЕТСЯ.
  jwtAccountAdminB / accountBId — распорядитель аккаунта B. Держит `admin` ровно
      там, где у субъекта ЕСТЬ выдача, — и всё равно отвергнут, потому что допуск
      решается по ДОМАШНЕМУ аккаунту субъекта, а не по тому, где у субъекта
      случилась выдача.
  jwtPureNoBindings — аутентифицирован, прав нет нигде; выделенный субъект
      leak-guard'ов (#276), никогда не грантится.
  projectA1Id / projectB1Id — области, по которым видно, что сузилось.

verifies: PRO-Robotech/kacho#1438 (и через него — #1352, #1354).
"""

CASES = []

# Well-formed идентификатор служебной учётки, который не резолвится НИ ВО ЧТО.
# Форма — та, что производит продукт: слитная, префикс `sva` + 17 знаков, всего 20
# (`domain.ShortIDLen`), поэтому проверка формы его ПРОПУСКАЕТ и он доезжает до
# резолва. Идентификатор покороче/подлиннее упирался бы в 400 и об анти-оракуле не
# утверждал бы ничего.
ABSENT_SERVICE_ACCOUNT = "sva00000000000000000"

# gRPC-коды в теле ответа края.
CODE_INVALID_ARGUMENT = 3
CODE_PERMISSION_DENIED = 7

LSP = "/iam/v1/accessBindings:listSubjectPrivileges"


def _q(text):
    """Строковый литерал JavaScript. Экранируется всё, что рвёт литерал."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _rows_js():
    """Строки ответа — массивом, с диагностикой на неразобранном теле."""
    return [
        "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
        "  const rows = j.privileges;",
        "  pm.expect(rows, JSON.stringify(j)).to.be.an('array');",
    ]


def _has_scope(var_name, scope_type, label):
    """Строка с ОБЛАСТЬЮ, названной парой (scopeType, scopeId) — ПРИСУТСТВУЕТ."""
    return [
        f"pm.test({_q(label)}, () => {{",
        *_rows_js(),
        f"  const want = pm.environment.get({_q(var_name)});",
        f"  const hit = rows.filter(r => r.scopeType === {_q(scope_type)} && r.scopeId === want);",
        "  pm.expect(hit.length, 'ищем ' + want + ' среди ' + JSON.stringify(rows)).to.be.above(0);",
        "});",
    ]


def _row_shape(var_name, scope_type, label):
    """Форма ИМЕННО ТОЙ строки, про которую кейс делает утверждение.

    Утверждать форму `rows.forEach(…)` здесь НЕЛЬЗЯ, и это не осторожность, а
    свойство фикстуры: тот же субъект — предмет набора `rbac-visibility-set`,
    который заводит и сносит на нём выдачи со свежими ролями. Его остаток
    (снятая роль ⇒ пустое `roleName`, снятая выдача ⇒ `REVOKED`) — законное
    состояние, к предмету ЭТОГО кейса отношения не имеющее. Универсальное
    утверждение падало бы на нём, называя виновником нас, а зелёным было бы
    ровно тогда, когда сосед ничего не оставил, — то есть зависело бы от
    порядка прогонов, а не от продукта.
    """
    return [
        f"pm.test({_q(label)}, () => {{",
        *_rows_js(),
        f"  const want = pm.environment.get({_q(var_name)});",
        f"  const r = rows.find(x => x.scopeType === {_q(scope_type)} && x.scopeId === want);",
        "  pm.expect(r, 'строки ' + want + ' нет: ' + JSON.stringify(rows)).to.be.an('object');",
        "  pm.expect(r.bindingId, JSON.stringify(r)).to.match(/^acb[0-9a-z]{17}$/);",
        "  pm.expect(r.roleId, JSON.stringify(r)).to.match(/^rol[0-9a-z]{17}$/);",
        # Обогащение и есть то, чем этот глагол отличается от соседнего
        # `:listBySubject`: имя роли резолвится сервером через JOIN внутри БД,
        # а не добирается клиентом. Пустое имя означает повисшую роль.
        "  pm.expect(r.roleName, 'roleName пуст ⇒ роль повисла: ' + JSON.stringify(r))",
        "    .to.be.a('string').and.not.eql('');",
        "  pm.expect(r.derivation, JSON.stringify(r)).to.eql('DIRECT');",
        "  pm.expect(r.status, JSON.stringify(r)).to.eql('ACTIVE');",
        # Устаревшая пара объявлена «заполняется на КАЖДОМ чтении» — это
        # утверждение контракта, а не наблюдение.
        "  pm.expect(r.resourceId, 'легаси-зеркало разошлось: ' + JSON.stringify(r)).to.eql(r.scopeId);",
        "  pm.expect(r.resourceType, JSON.stringify(r)).to.eql(want.slice(0, 3) === 'acc' ? 'account' : 'project');",
        "  pm.expect(r.createdAt, JSON.stringify(r)).to.match(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/);",
        "});",
    ]


def _lacks_scope(var_name, label):
    """Ни одной строки с этой ОБЛАСТЬЮ — и идентификатора нет НИГДЕ в теле.

    Два утверждения, а не одно: отбор по полю ловит строку, а сканирование текста
    ловит то же имя, доехавшее ЛЮБЫМ другим полем — легаси-зеркалом
    `resourceId`, ссылкой на группу, курсором. Проекция несёт область ДВАЖДЫ
    (`scopeId` и устаревший `resourceId`), поэтому проба, читающая одно поле,
    прошла бы при живой утечке через соседнее.
    """
    return [
        f"pm.test({_q(label)}, () => {{",
        *_rows_js(),
        f"  const foreign = pm.environment.get({_q(var_name)});",
        "  pm.expect(foreign, 'фикстура обязана назвать чужую область').to.be.a('string').and.not.eql('');",
        "  const byField = rows.filter(r => r.scopeId === foreign || r.resourceId === foreign);",
        "  pm.expect(byField.length, 'чужая область строкой: ' + JSON.stringify(byField)).to.eql(0);",
        "  pm.expect(pm.response.text().indexOf(foreign), 'чужая область где-либо в теле').to.eql(-1);",
        "});",
    ]


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-SELF-OK — ПОЛОСА 1: сам субъект читает свои привилегии и получает
# их НЕСУЖЁННЫМИ, включая выдачу, чья область лежит в чужом аккаунте.
#
# Это и главный положительный кейс полосы, и — по существу — объявление грунта,
# который следующий кейс снимает заново у себя: без доказанного «строка про
# аккаунт B по этому глаголу достаётся» всё утверждение о сужении вакуумно.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-SELF-OK",
    title=("ПОЛОСА СВОЕГО: субъект читает свои привилегии → 200, обе выдачи на месте — "
           "и внутри домашнего аккаунта, и в чужом (собственное чтение НЕ сужается)"),
    classes=["CRUD", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="self-reads-own-privileges",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                "pm.test('перечень непуст — иначе всё ниже утверждало бы о пустом ответе', () => {",
                *_rows_js(),
                "  pm.expect(rows.length, JSON.stringify(rows)).to.be.at.least(2);",
                "});",
                *_has_scope("projectA1Id", "iam.project",
                           "выдача ВНУТРИ домашнего аккаунта (проект A1) видна"),
                *_has_scope("accountBId", "iam.account",
                           "выдача СНАРУЖИ домашнего аккаунта (аккаунт B) тоже видна — "
                           "собственное чтение не сужается"),
                # Форма — по КАЖДОЙ из двух названных строк отдельно: имя роли,
                # разрешённое сервером, происхождение, состояние, легаси-зеркало,
                # усечение отметки времени до секунд.
                *_row_shape("projectA1Id", "iam.project",
                            "форма строки о проекте A1: обогащена, DIRECT, ACTIVE, зеркало сходится"),
                *_row_shape("accountBId", "iam.account",
                            "форма строки об аккаунте B: обогащена, DIRECT, ACTIVE, зеркало сходится"),
                # Область названа канонической точечной формой у КАЖДОЙ строки —
                # утверждение о словаре, а не о конкретной выдаче, поэтому оно
                # законно накрывает и чужой остаток: словарь один на всех.
                "pm.test('scopeType КАЖДОЙ строки — из канонического точечного словаря', () => {",
                *_rows_js(),
                "  rows.forEach(r => {",
                "    pm.expect(r.scopeType, JSON.stringify(r)).to.match(/^iam\\.(cluster|account|project)$/);",
                "  });",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-ADMIN-NARROWED — ПОЛОСА 2: распорядитель ДОМАШНЕГО аккаунта
# субъекта допущен, но его страница СУЖЕНА границами этого аккаунта (#1354).
#
# ГРУНТ СНИМАЕТСЯ В ЭТОМ ЖЕ КЕЙСЕ, а не берётся из соседнего: кейс, чей
# положительный контроль лежит в другом файле, зеленеет, когда тот файл не
# исполнялся. Шаг 1 доказывает, что чужая строка через ЭТОТ глагол на ЭТОМ крае
# достаётся; шаг 2 — что распорядителю она не приходит.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-ADMIN-NARROWED",
    title=("ПОЛОСА РАСПОРЯДИТЕЛЯ: допущен по домашнему аккаунту субъекта, но страница СУЖЕНА — "
           "выдача в его аккаунте видна, выдача в чужом не приходит ни одним полем"),
    classes=["NEG", "CONF"],
    priority="P0",
    steps=[
        Step(
            name="ground-truth-both-scopes-exist",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(200),
                # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию следующего шага: обе строки
                # существуют и достаются этим глаголом. Без него «строки про B не
                # пришло» было бы истинно и на субъекте, у которого её нет вовсе.
                *_has_scope("accountBId", "iam.account",
                           "ГРУНТ: выдача в аккаунте B существует и через этот глагол достаётся"),
                *_has_scope("projectA1Id", "iam.project",
                           "ГРУНТ: выдача в проекте A1 существует и через этот глагол достаётся"),
                # Запоминается ИДЕНТИФИКАТОР чужой строки, а не их число. Число
                # сравнивать нельзя: перечень выдач субъекта может пополниться
                # между двумя шагами, и тогда «страница короче» ложно покраснеет
                # либо ложно позеленеет, не сказав ничего о сужении. Тождество
                # строки от постороннего пополнения не зависит вовсе.
                "pm.test('грунт запомнен — идентификатор ВЫДАЧИ, лежащей в чужом аккаунте', () => {",
                *_rows_js(),
                "  const b = pm.environment.get('accountBId');",
                "  const foreign = rows.find(r => r.scopeId === b);",
                "  pm.expect(foreign, 'строки про аккаунт B нет: ' + JSON.stringify(rows)).to.be.an('object');",
                "  pm.expect(foreign.bindingId, JSON.stringify(foreign)).to.match(/^acb[0-9a-z]{17}$/);",
                "  pm.environment.set('lspForeignBindingId', foreign.bindingId);",
                "});",
            ],
        ),
        Step(
            name="account-admin-sees-only-own-account",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtAccountAdminA",
            test_script=[
                # Допуск есть: домашний аккаунт субъекта — A, и вызывающий им
                # распоряжается. Отказ здесь означал бы расхождение полос (#1352),
                # а не сужение.
                *assert_status(200),
                *_has_scope("projectA1Id", "iam.project",
                           "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: своя выдача распорядителю видна — "
                           "иначе «сузилось» неотличимо от «не материализовалось»"),
                *_lacks_scope("accountBId",
                              "СУЖЕНИЕ: выдача в аккаунте B не приходит ни строкой, ни где-либо в теле"),
                *_lacks_scope("projectB1Id",
                              "СУЖЕНИЕ: проект аккаунта B в теле не назван — состав чужих "
                              "арендаторов по ответу не картируется"),
                # Связка с грунтом — по ТОЖДЕСТВУ строки: именно ТА выдача, что
                # предыдущий шаг увидел и назвал по идентификатору, распорядителю
                # не пришла. Утверждение, которого ни один шаг по отдельности
                # сделать не может: «строки про B не видно» истинно и у пустого
                # ответа, а «строка B существует» ничего не говорит о сужении.
                "pm.test('СНЯТА ИМЕННО ТА строка, которую грунт назвал по идентификатору', () => {",
                *_rows_js(),
                "  const gone = pm.environment.get('lspForeignBindingId');",
                "  pm.expect(gone, 'грунт не снят предыдущим шагом').to.be.a('string').and.not.eql('');",
                "  pm.expect(rows.filter(r => r.bindingId === gone).length,",
                "    'чужая выдача ' + gone + ' на странице: ' + JSON.stringify(rows)).to.eql(0);",
                "  pm.expect(pm.response.text().indexOf(gone), 'её идентификатор где-либо в теле').to.eql(-1);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-STRANGER-DENY — ПОЛОСА 3: не допущенный вовсе получает отказ.
#
# Две разные посторонности, и вторая содержательнее первой: распорядитель
# аккаунта B держит `admin` РОВНО ТАМ, где у субъекта есть выдача, — и всё равно
# отвергнут. Значит допуск решается по ДОМАШНЕМУ аккаунту субъекта, а не по тому,
# где субъекту случилось что-то выдать.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-STRANGER-DENY",
    title=("ПОЛОСА ПОСТОРОННЕГО: без прав → 403/PERMISSION_DENIED; распорядитель ЧУЖОГО аккаунта "
           "отвергнут, даже держа admin там, где у субъекта есть выдача"),
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="control-subject-is-readable-by-someone",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtAccountAdminA",
            test_script=[
                # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ко ВСЕМ отказам ниже: субъект существует,
                # маршрут на крае жив, глагол отвечает. Без него три 403 подряд
                # истинны и у снятого маршрута, и у мёртвой фикстуры.
                *assert_status(200),
                "pm.test('контроль: законный вызывающий получает перечень', () => {",
                *_rows_js(),
                "  pm.expect(rows.length, JSON.stringify(rows)).to.be.above(0);",
                "});",
            ],
        ),
        Step(
            name="caller-without-any-grant-denied",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(CODE_PERMISSION_DENIED, "PERMISSION_DENIED"),
            ],
        ),
        Step(
            name="admin-of-the-other-account-denied",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtAccountAdminB",
            test_script=[
                # Содержательная половина полосы: у этого вызывающего `admin` на
                # аккаунте B, а у субъекта в аккаунте B — выдача. Допуск он всё
                # равно не проходит, потому что решается он по домашнему аккаунту
                # СУБЪЕКТА (A). Пройди он — распорядитель B читал бы через этот
                # глагол выдачи чужого сотрудника целиком.
                *assert_status(403),
                *assert_grpc_code(CODE_PERMISSION_DENIED, "PERMISSION_DENIED"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-DENY-NO-ORACLE — тело отказа не называет НИЧЕГО сверх эха
# названного самим вызывающим, и «есть, но не ваш» неотличимо от «нет вовсе».
#
# Это вторая половина предиката задачи: полосы допуска можно закрыть верно и всё
# равно отдать оракул перечисления — по одному лишь РАЗЛИЧИЮ ответов посторонний
# отделяет существующий идентификатор от несуществующего и картирует кластер.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-DENY-NO-ORACLE",
    title=("ОТКАЗ НЕ ОРАКУЛ: существующий чужой субъект и не резолвящийся идентификатор отвечают "
           "постороннему ПОБАЙТОВО одинаково, и тело не называет ни одного идентификатора"),
    classes=["NEG", "SEC"],
    priority="P1",
    steps=[
        Step(
            name="oracle-control-subject-really-exists",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtAccountAdminA",
            test_script=[
                # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ, без которого весь кейс вакуумен: если бы
                # субъект не существовал, «оба отказа одинаковы» держалось бы
                # тривиально — сравнивались бы два «нет вовсе».
                *assert_status(200),
                "pm.test('контроль: субъект СУЩЕСТВУЕТ — значит дальше сравниваются РАЗНЫЕ положения', () => {",
                *_rows_js(),
                "  pm.expect(rows.length, JSON.stringify(rows)).to.be.above(0);",
                "});",
            ],
        ),
        Step(
            name="stranger-on-existing-subject",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(CODE_PERMISSION_DENIED, "PERMISSION_DENIED"),
                "pm.environment.set('lspDenyExistingBody', pm.response.text());",
            ],
        ),
        Step(
            name="stranger-on-absent-subject",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={ABSENT_SERVICE_ACCOUNT}",
            auth="jwtPureNoBindings",
            test_script=[
                *assert_status(403),
                *assert_grpc_code(CODE_PERMISSION_DENIED, "PERMISSION_DENIED"),
                # ПОБАЙТОВО, без нормализации — и это не строгость сверх нужного,
                # а свойство ответа: тело отказа эха ввода не несёт (см. следующее
                # утверждение), поэтому нормализовать в нём нечего. Там, где эхо
                # есть, соседний набор нормализует его явно и говорит, что именно.
                "pm.test('тела ОБОИХ отказов совпадают дословно — существование не сообщается', () => {",
                "  const saved = pm.environment.get('lspDenyExistingBody');",
                "  pm.expect(saved, 'предыдущий шаг не сохранил тело').to.be.a('string').and.not.eql('');",
                "  pm.expect(pm.response.text()).to.eql(saved);",
                "});",
                # Прямая формулировка предиката задачи: сверх эха названного самим
                # вызывающим отказ не называет ничего. Здесь эха нет вовсе, то есть
                # держится самая сильная форма — не назван НИ ОДИН идентификатор,
                # включая тот, что вызывающий прислал сам.
                "pm.test('тело отказа не называет ни одного идентификатора — ни чужого, ни своего эха', () => {",
                "  const body = pm.response.text();",
                "  [['svaInviteeId', pm.environment.get('svaInviteeId')],",
                "   ['accountAId', pm.environment.get('accountAId')],",
                "   ['accountBId', pm.environment.get('accountBId')],",
                "   ['projectA1Id', pm.environment.get('projectA1Id')]]",
                "    .forEach(([nm, v]) => {",
                "      pm.expect(v, 'фикстура ' + nm + ' пуста — сверять было бы не с чем')",
                "        .to.be.a('string').and.not.eql('');",
                "      pm.expect(body.indexOf(v), nm + ' назван в теле отказа: ' + body).to.eql(-1);",
                "    });",
                f"  pm.expect(body.indexOf({_q(ABSENT_SERVICE_ACCOUNT)}), 'эхо присланного id: ' + body).to.eql(-1);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-VAL — форма запроса судится СИНХРОННО и до всякого решения о
# личности: тип субъекта из закрытого словаря, префикс идентификатора под тип.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-VAL",
    title=("ВАЛИДАЦИЯ: тип субъекта вне словаря и несоответствие префикс↔тип → 400/INVALID_ARGUMENT "
           "с текстом владельца; законный вход тем же вызывающим → 200"),
    classes=["VAL", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="val-control-legal-input",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}",
            auth="jwtInvitee",
            test_script=[
                # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же вызывающий, тот же глагол, законный
                # вход — 200. Без него «негодное отвергнуто» истинно и у
                # поверхности, отвергающей всё.
                *assert_status(200),
            ],
        ),
        Step(
            name="val-subject-type-outside-the-vocabulary",
            method="GET",
            path=f"{LSP}?subjectType=robot&subjectId={{{{svaInviteeId}}}}",
            auth="jwtInvitee",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(CODE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
                # Текст владельца дословно: он называет ПОЛЕ и перечисляет
                # допустимое, то есть говорит вызывающему, что делать дальше.
                *assert_refusal_message_contains(
                    "Illegal argument subject_type (allowed: user|service_account|group)"),
            ],
        ),
        Step(
            name="val-prefix-does-not-match-the-declared-type",
            method="GET",
            path=f"{LSP}?subjectType=user&subjectId={{{{svaInviteeId}}}}",
            auth="jwtInvitee",
            test_script=[
                # Идентификатор служебной учётки, объявленный человеком. Форма сама
                # по себе безупречна — негодна ПАРА, и отвергается она до репозитория.
                *assert_status(400),
                *assert_grpc_code(CODE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
                *assert_refusal_message_contains("invalid user id '{{svaInviteeId}}'"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ACB-LSP-PAGE-BEFORE-IDENTITY — один и тот же негодный курсор отвечает
# ОДИНАКОВО допущенному и не допущенному.
#
# Предмет — ПОРЯДОК, и снаружи он проверяется только так. «Правильно ли составлен
# запрос» имеет один ответ для всех, и зависеть от того, что вызывающему выдано,
# он не вправе: иначе по коду ответа на заведомо негодный курсор посторонний
# читает, есть ли у него доступ к субъекту, — тот же оракул, только через форму.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ACB-LSP-PAGE-BEFORE-IDENTITY",
    title=("ПОРЯДОК: негодный курсор и запредельный размер страницы → 400/INVALID_ARGUMENT "
           "ОДИНАКОВО допущенному и постороннему — форма судится раньше прав"),
    classes=["VAL", "BVA", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="page-control-legal-cursor-request",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}&pageSize=1000",
            auth="jwtInvitee",
            test_script=[
                # ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ и верхняя граница разом: 1000 — предел
                # контракта, он обязан ПРИНИМАТЬСЯ.
                *assert_status(200),
            ],
        ),
        Step(
            name="page-size-above-the-contract-max",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}&pageSize=1001",
            auth="jwtInvitee",
            test_script=[
                # 1001 — первый шаг за предел; отвергается, а НЕ подрезается молча.
                *assert_status(400),
                *assert_grpc_code(CODE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
            ],
        ),
        Step(
            name="garbage-cursor-for-the-admitted-caller",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}&pageToken=not-a-cursor",
            auth="jwtInvitee",
            test_script=[
                *assert_status(400),
                *assert_grpc_code(CODE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
            ],
        ),
        Step(
            name="same-garbage-cursor-for-the-stranger",
            method="GET",
            path=f"{LSP}?subjectType=service_account&subjectId={{{{svaInviteeId}}}}&pageToken=not-a-cursor",
            auth="jwtPureNoBindings",
            test_script=[
                # ТОТ ЖЕ негодный курсор, вызывающий БЕЗ прав на субъекта. Ответ
                # обязан быть тем же: 400, а не 403. Приди сюда 403 — форма
                # судилась бы ПОСЛЕ прав, и вызывающий отличал бы «мне не видно
                # этого субъекта» от «мой курсор негоден» по ответу на ввод,
                # негодный для всех.
                *assert_status(400),
                *assert_grpc_code(CODE_INVALID_ARGUMENT, "INVALID_ARGUMENT"),
            ],
        ),
    ],
))
