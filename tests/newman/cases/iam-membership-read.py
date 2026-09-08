# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set чтения принадлежности человека аккаунту (IAM-ID-2, стадия S1).

Covered RPCs:
  MembershipService.List (GET /iam/v1/accounts/{accountId}/memberships)
  MembershipService.Get  (GET /iam/v1/accounts/{accountId}/memberships/{membershipId})

Что здесь проверяется по существу
---------------------------------
Не «работает ли чтение», а то, что оно НЕ РАЗЛИЧАЕТ положения, различать
которые не вправе. Аккаунт приходит входом и стоит в условии отбора, поэтому:

  * чужой аккаунт и НЕСУЩЕСТВУЮЩИЙ аккаунт отвечают ОДИНАКОВО — тела совпадают
    дословно после нормализации ЭХА собственного ввода вызывающего и различаются
    ровно им (см. `_same_body_modulo_scope`);
  * членство чужого аккаунта и членство, которого нет нигде, отвечают
    одинаково — тела различаются ровно подставленным идентификатором;
  * человек, состоящий ТОЛЬКО в чужом аккаунте, человек, не состоящий нигде, и
    строка, не резолвящаяся ни во что, дают один и тот же пустой перечень.

У КАЖДОГО отрицания стоит положительный контроль. Без него «ответы совпали»
истинно и у поверхности, которая не отвечает никому, а «негодное отвергнуто» —
у поверхности, которая отвергает всё.

Неразличимость утверждается СРАВНЕНИЕМ ТЕЛ, а не только совпадением кодов: проба,
сверяющая один код, зеленеет на любом расхождении текста.

Что нормализуется и почему это НЕ ослабление. Отказ края несёт область запроса
дословно — `account:<id>` в `violations[].subject` и в `metadata.resource`. Это эхо
того, что вызывающий прислал САМ, и оракулом быть не может: два вызова несут два
разных адреса, потому что он их и назвал. Побайтовое равенство таких тел невыполнимо
by construction, поэтому сверяется равенство ПОСЛЕ подстановки `<ACCT>` вместо эха —
и отдельным утверждением проверяется, что иных вхождений идентификатора в теле НЕТ.
Замер, из которого это выведено: два тела отказа, отрендеренных одним и тем же кодом
края на двух разных адресах, различаются РОВНО двумя вхождениями идентификатора;
сообщение, тип нарушения, описание, субъект, действие и `reason` совпадают дословно.

CRUD fixture dependency:
  jwtAccountAdminA / accountAId — распорядитель аккаунта A. ЭТО СЛУЖЕБНАЯ УЧЁТКА,
      а НЕ человек `userAAAId`: в боевой посадке машинный посев чеканит только
      `client_credentials`, то есть служебные учётки
      (`tests/authz-fixtures/prodseed_matrix.py` → `subject()` = «Create an SA»).
  userAAAId / userAABId / userNOBId — РЕАЛЬНЫЕ строки людей, но ТОЛЬКО ЦЕЛИ
      ПРИВЯЗКИ: ни одному из них посев не выдаёт предъявителя и выдать не может
      (`tests/authz-fixtures/principal_pairings.py`, врезка «NOT EVERY EMITTED ID
      BELONGS HERE»). Связывать любой из них с каким-либо `jwt*` — объявленный
      дефект фикстуры, а не пробел в перечне.
  jwtAccountAdminB / accountBId — то же для аккаунта B (тоже служебная учётка)
  jwtNoBindings                 — аутентифицирован, прав нигде нет
  jwtHumanCeremonyStepUp / ceremonyUserId / ceremonyAccountId — ЧЕЛОВЕК и аккаунт,
      которым он владеет. Единственный человеческий вызывающий набора; условие
      создаётся волной церемонии (`scripts/run-ceremony.sh`, WAVE 4), а сама
      коллекция попадает в неё ВЫВОДОМ ИЗ ДЕРЕВА — по тому, что шаг называет
      предъявителя из `CEREMONY_ONLY_ENV` (`tests/authz-fixtures/ceremony_credentials.py`).

verifies: IAM-ID-2-01, -02, -03, -04, -05, -12, -13.
"""

CASES = []

# Well-formed идентификаторы, которые не резолвятся НИ ВО ЧТО. Форма — та, что
# производит продукт: аккаунт слитной формой, членство дефисной.
ABSENT_ACCOUNT = "acc00000000000000000"
ABSENT_MEMBERSHIP = "mbr-00000000000000000"
ABSENT_USER = "usr00000000000000000"


def _q(text):
    """Строковый литерал JavaScript. Экранируется всё, что рвёт литерал."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _save_body(var):
    """Сохранить ТЕЛО ответа целиком — предмет сверки на байт-идентичность."""
    return [f"pm.environment.set({_q(var)}, pm.response.text());"]


def _same_body_as(var, label):
    return [
        f"pm.test({_q(label)}, () => {{",
        f"  pm.expect(pm.response.text()).to.eql(pm.environment.get({_q(var)}));",
        "});",
    ]


def _same_body_modulo_scope(var, saved_scope_js, this_scope_js, label):
    """Сверка тел ПО СУЩЕСТВУ: нормализуется ЭХО СОБСТВЕННОГО ВВОДА вызывающего.

    Отказ края несёт область запроса дословно — `account:<id>` в `violations[].subject`
    и в `metadata.resource`. Это ЭХО ТОГО, ЧТО ВЫЗЫВАЮЩИЙ ПРИСЛАЛ САМ, и оракулом оно
    быть не может: два вызова несут два разных адреса, потому что их назвал он.
    Требовать от таких тел побайтового совпадения значит требовать невыполнимого от
    любого ответа, который область запроса называет.

    Поэтому оба тела приводятся к общему виду подстановкой `<ACCT>` вместо ЭХА — и
    дальше сравниваются ДОСЛОВНО. Утверждение остаётся различающим: расхождение в коде,
    в сообщении, в описании отказа, в типе нарушения, в наборе полей или лишнее
    вхождение идентификатора помимо эха роняет его по-прежнему. Приём не новый и не
    выдуман здесь — им же сверяется пара одиночного чтения ниже
    (`IAM-ID2-ORACLE-GET-404`: «тела различаются РОВНО подставленным идентификатором»).
    """
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const norm = (t, id) => (id ? t.split(id).join('<ACCT>') : t);",
        f"  const saved = norm(pm.environment.get({_q(var)}) || '', {saved_scope_js});",
        f"  const here = norm(pm.response.text(), {this_scope_js});",
        "  pm.expect(here, 'saved=' + saved + ' | here=' + here).to.eql(saved);",
        "});",
    ]


def _grpc_code(code, label):
    """Утверждается ПАРА: HTTP-статус проверяется отдельно, здесь — код rpc.Status."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


# gRPC-коды в теле ответа края.
CODE_INVALID_ARGUMENT = 3
CODE_NOT_FOUND = 5
CODE_PERMISSION_DENIED = 7


# ---------------------------------------------------------------------------
# IAM-ID2-LIST-CRUD-OK (IAM-ID-2-01) — распорядитель читает членство сотрудника
# в СВОЁМ аккаунте, и обе проекции отдают одно и то же.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-LIST-CRUD-OK",
    title="List memberships of own account filtered by userId → 200, ровно одна запись; Get по её id отдаёт те же поля",
    classes=["CRUD", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="list-own-account-by-user",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{userAAAId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('перечень содержит ровно одну запись', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "});",
                "pm.test('поля записи заполнены и относятся к НАЗВАННОМУ аккаунту', () => {",
                "  const m = pm.response.json().memberships[0];",
                "  pm.expect(m.accountId, JSON.stringify(m)).to.eql(pm.environment.get('accountAId'));",
                "  pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('userAAAId'));",
                "  pm.expect(m.state, JSON.stringify(m)).to.eql('ACTIVE');",
                "  pm.expect(m.id, JSON.stringify(m)).to.match(/^mbr-[0-9a-z]{17}$/);",
                "});",
                "pm.test('createdAt усечён до секунд — микросекунды хранилища на провод не текут', () => {",
                "  const m = pm.response.json().memberships[0];",
                "  pm.expect(m.createdAt, JSON.stringify(m)).to.match(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/);",
                "});",
                *save_from_response("j.memberships[0].id", "mbrOwnAId"),
                *_save_body("mbrListOwnBody"),
            ],
        ),
        Step(
            name="get-same-membership-by-id",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships/{{mbrOwnAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ПРОЕКЦИИ НЕ РАСХОДЯТСЯ: одиночное чтение отдаёт те же поля, что и список', () => {",
                "  const g = pm.response.json();",
                "  const l = JSON.parse(pm.environment.get('mbrListOwnBody')).memberships[0];",
                "  ['id','accountId','accountName','userId','state','invitedBy','createdAt','updatedAt']",
                "    .forEach(f => pm.expect(g[f], 'поле ' + f + ': ' + JSON.stringify(g)).to.eql(l[f]));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-INVITED-PENDING-OK (IAM-ID-2-02) — приглашённый виден распорядителю
# как приглашённый, и состояние РАЗЛИЧАЕТ, а не отдаёт константу.
#
# Приглашение сеется САМИМ кейсом с `{{runId}}` в почте: общая фикстура
# рассказала бы про состояние, которого никто не назначал этому кейсу, и
# сорвалась бы вместе с чужим прогоном.
#
# ПРИГЛАШАЕТ ЧЕЛОВЕК, И ЭТО ТРЕБОВАНИЕ К ФОРМЕ ЗАПРОСА, А НЕ УДОБСТВО.
# `users.invited_by` — внешний ключ в `users(id)`, поэтому НАЗВАТЬ там можно
# только человека. Служебная учётка — законный приглашающий, но человеком она не
# является, и продукт ОСОЗНАННО оставляет колонку пустой, унося актора на
# `Operation` (`services/iam/internal/apps/kaname/api/user/invite.go`, врезка у
# `invitedBy`). Значит под машинным вызывающим утверждение «след приглашения
# назван» непроверяемо by construction: оно спрашивает про поле, которого при
# таком вызывающем не бывает.
#
# Прежняя редакция шла под `jwtAccountAdminA`, считая его человеком `userAAAId`.
# Посылка ложна (см. фикстурную шапку модуля), и красным это становилось ровно на
# одном утверждении — `invitedBy`, — то есть выглядело дефектом продукта.
# Отходных путей здесь ровно два, и маска в них не входит: волна, создающая
# условие, либо открытый долг с числом. Условие СОЗДАНО: человек церемонии
# существует, владеет своим аккаунтом (`owner` → `admin` → `editor` → `viewer` по
# модели, `proto/kaname/cloud/iam/v1/fga_model.fga` §type account) и несёт
# поднятый уровень входа, которого требует запись каталога у `UserService/Invite`
# (`required_acr_min: "2"`).
#
# Положительный контроль состояния остаётся на аккаунте A: он утверждает, что
# поле РАЗЛИЧАЕТ, и для этого ему довольно любого членства в состоянии «активно».
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-INVITED-PENDING-OK",
    title="Приглашённый ЧЕЛОВЕКОМ в его аккаунт виден как PENDING с непустым invitedBy; активный сосед — ACTIVE",
    classes=["CRUD", "STATE"],
    priority="P0",
    steps=[
        Step(
            name="invite-fresh-person",
            method="POST",
            path="/iam/v1/users:invite",
            body={
                "accountId": "{{ceremonyAccountId}}",
                "email": "mbr-pending-{{runId}}@kacho.local",
                "displayName": "membership pending {{runId}}",
            },
            auth="jwtHumanCeremonyStepUp",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "mbrInvOp"),
                *save_from_response("(j.metadata && j.metadata.userId) || j.id", "mbrInvUserId"),
                "pm.test('приглашение вернуло идентификатор человека', () => "
                "pm.expect(pm.environment.get('mbrInvUserId') || '', 'invited user id').to.match(/^usr[a-z0-9]+$/));",
            ],
        ),
        Step(
            name="invite-poll",
            method="GET",
            path="/operations/{{mbrInvOp}}",
            auth="jwtHumanCeremonyStepUp",
            op_var="mbrInvOp",
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
        ),
        Step(
            name="read-invited-membership",
            method="GET",
            path='/iam/v1/accounts/{{ceremonyAccountId}}/memberships?filter=userId%3D%22{{mbrInvUserId}}%22',
            # ЧТЕНИЕ идёт ОБЫЧНЫМ входом того же человека, а не поднятым.
            # `MembershipService/List` объявлен в каталоге без порога
            # (`required_acr_min: "1"`), и шаг, идущий поднятым по маршруту, где
            # порога нет, перестаёт проверять, что его здесь нет: он зеленел бы и
            # тогда, когда порог завели бы молча. Поднятый вход нужен ровно двум
            # шагам выше — `UserService/Invite` несёт `required_acr_min: "2"`.
            # Личность та же: `jwtHumanCeremony` и `jwtHumanCeremonyStepUp` —
            # один человек `ceremonyUserId`, различающийся только уровнем входа
            # (`tests/authz-fixtures/prodseed_ceremony.py`, `lvl1`/`lvl2`),
            # поэтому допуск `viewer` @ `account` у шага не меняется.
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('приглашённый виден как PENDING, и след приглашения называет ПРИГЛАСИВШЕГО ЧЕЛОВЕКА', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "  const m = j.memberships[0];",
                "  pm.expect(m.accountId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(m.state, JSON.stringify(m)).to.eql('PENDING');",
                "  pm.expect(m.invitedBy, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyUserId'));",
                "  pm.expect(m.createdAt, JSON.stringify(m)).to.match(/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/);",
                "});",
            ],
        ),
        Step(
            name="control-active-neighbour-differs",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{userAAAId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: у активного члена состояние ДРУГОЕ — "
                "поле различает, а не отдаёт константу. Аккаунт здесь ДРУГОЙ намеренно: "
                "контролируется свойство ПОЛЯ, а не соседство строк, и любого членства в "
                "состоянии «активно» для этого довольно', () => {",
                "  const m = pm.response.json().memberships[0];",
                "  pm.expect(m.state, JSON.stringify(m)).to.eql('ACTIVE');",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-NEG-FOREIGN-ACCOUNT (IAM-ID-2-03) — чужой аккаунт и аккаунт, которого
# НЕТ, отвечают ОДИНАКОВО: тела совпадают дословно после нормализации эха
# собственного ввода вызывающего и различаются ровно им.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-NEG-FOREIGN-ACCOUNT",
    title="List по чужому аккаунту → 403; ответ неотличим от ответа по несуществующему аккаунту",
    classes=["NEG", "AUTHZ", "ORACLE"],
    priority="P0",
    steps=[
        Step(
            name="list-foreign-account",
            method="GET",
            path="/iam/v1/accounts/{{accountBId}}/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_grpc_code(CODE_PERMISSION_DENIED, "код — PERMISSION_DENIED, а не скрывающий NOT_FOUND"),
                "pm.test('отказ НЕ называет ни отношения, ни причины отказа модели — "
                "край подменяет её неразглашающим описанием', () => {",
                "  const raw = pm.response.text();",
                "  const t = raw.toLowerCase();",
                "  pm.expect(t, raw).to.not.include('viewer');",
                "  pm.expect(t, raw).to.not.include('lacks relation');",
                "  pm.expect(t, raw).to.not.include('direct relations');",
                "  pm.expect(t, raw).to.not.include('deny_reasons');",
                "});",
                "pm.test('идентификатор аккаунта встречается ТОЛЬКО как ЭХО области, которую вызывающий "
                "назвал сам — ни одного вхождения помимо неё', () => {",
                "  const t = pm.response.text();",
                "  const id = pm.environment.get('accountBId');",
                "  const all = t.split(id).length - 1;",
                "  const echoed = t.split('account:' + id).length - 1;",
                "  pm.expect(all, 'вхождений ' + all + ', из них эхо области ' + echoed + ': ' + t)",
                "    .to.eql(echoed);",
                "});",
                "pm.test('ответ не содержит ни одного поля, производного от содержимого чужого аккаунта', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.not.exist;",
                "  pm.expect(j.nextPageToken, JSON.stringify(j)).to.not.exist;",
                "});",
                *_save_body("mbrForeignAcctBody"),
            ],
        ),
        Step(
            name="list-absent-account",
            method="GET",
            path=f"/iam/v1/accounts/{ABSENT_ACCOUNT}/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_same_body_modulo_scope(
                    "mbrForeignAcctBody",
                    "pm.environment.get('accountBId')",
                    _q(ABSENT_ACCOUNT),
                    "АНТИ-ОРАКУЛ: чужой аккаунт и несуществующий отвечают ОДИНАКОВО — тела "
                    "совпадают дословно после нормализации эха собственного ввода, и "
                    "различаются РОВНО им; модель прав не знает понятия «существует»",
                ),
            ],
        ),
        Step(
            name="control-owner-of-b-sees-b",
            method="GET",
            path="/iam/v1/accounts/{{accountBId}}/memberships",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: распорядитель B видит членства B — "
                "отказ выше был свойством прав, а не сломанного пути', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.length.greaterThan(0);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-NEG-FORM (IAM-ID-2-04) — у каждой половины СВОЙ производитель отказа.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-NEG-FORM",
    title="Негодная форма отвергается синхронно: идентификатор членства и терм фильтра — сервисом, идентификатор аккаунта — краем",
    classes=["NEG", "VAL"],
    priority="P0",
    steps=[
        Step(
            name="malformed-membership-id",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships/not-an-id",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "код — INVALID_ARGUMENT"),
                "pm.test('текст — контракт-тон владельца и называет негодный вход', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j)).to.eql(\"invalid membership id 'not-an-id'\");",
                "});",
            ],
        ),
        Step(
            name="filter-term-outside-whitelist",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=email%3D%22p%40example.test%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "код — INVALID_ARGUMENT"),
                "pm.test('отказ называет ПОЛЕ, а не отвечает полной страницей', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j)).to.include('email');",
                "});",
            ],
        ),
        Step(
            name="filter-operator-outside-declared",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%20CONTAINS%20%22usr%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "код — INVALID_ARGUMENT"),
                "pm.test('подстрочный поиск ОТВЕРГАЕТСЯ явно и называет поле, а не сводится молча к равенству', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j)).to.include('userId');",
                "});",
            ],
        ),
        Step(
            name="control-wellformed-absent-membership-is-404",
            method="GET",
            path=f"/iam/v1/accounts/{{{{accountAId}}}}/memberships/{ABSENT_MEMBERSHIP}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                *_grpc_code(CODE_NOT_FOUND,
                            "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: форма и существование — РАЗНЫЕ полосы"),
            ],
        ),
        Step(
            name="malformed-account-id-rights-holder",
            method="GET",
            path="/iam/v1/accounts/not-an-account/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "негодный accountId — отказ КРАЯ, до модели прав"),
                *_save_body("mbrMalformedAcctBody"),
            ],
        ),
        Step(
            name="malformed-account-id-no-rights",
            method="GET",
            path="/iam/v1/accounts/not-an-account/memberships",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(400),
                *_same_body_as(
                    "mbrMalformedAcctBody",
                    "исход НЕ является функцией прав: у вызывающего без единой выдачи ответ тот же, "
                    "потому что права не спрашиваются вовсе",
                ),
            ],
        ),
        Step(
            name="control-wellformed-absent-account-reaches-the-model",
            method="GET",
            path=f"/iam/v1/accounts/{ABSENT_ACCOUNT}/memberships",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(403),
                *_grpc_code(CODE_PERMISSION_DENIED,
                            "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: well-formed accountId рубеж формы ПРОХОДИТ — "
                            "иначе отрицание зеленело бы на крае, отвергающем ВСЯКИЙ accountId"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-NEG-PAGINATION (IAM-ID-2-05) — формат проверяется у того, кто до него
# доходит; у того, кто не доходит, исход ОДИН И ТОТ ЖЕ при любом вводе.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-NEG-PAGINATION",
    title="pageSize вне [0..1000] и негодный pageToken → 400 у держателя права; у вызывающего без права — 403 при ЛЮБОМ вводе",
    classes=["NEG", "BVA", "PAGINATION"],
    priority="P0",
    steps=[
        Step(
            name="page-size-over-cap",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageSize=5000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "pageSize ОТВЕРГАЕТСЯ, а не подрезается"),
            ],
        ),
        Step(
            name="garbage-page-token",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageToken=not-a-cursor",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "негодный курсор отвергается, а не игнорируется"),
            ],
        ),
        Step(
            name="control-lawful-page-passes",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageSize=10",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: законная страница проходит ПО ТОМУ ЖЕ ПУТИ — "
                "иначе отрицания зеленеют на поверхности, отвергающей всё', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.length.greaterThan(0);",
                "});",
            ],
        ),
        Step(
            name="no-rights-lawful-pagination",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageSize=10",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(403),
                *_grpc_code(CODE_PERMISSION_DENIED, "край отвечает РАНЬШЕ сервиса"),
                *_save_body("mbrNoRightsBody"),
            ],
        ),
        Step(
            name="no-rights-unlawful-page-size",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageSize=5000",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(403),
                *_same_body_as(
                    "mbrNoRightsBody",
                    "исход НЕ является функцией того, годен ли ввод: до проверки формата "
                    "такой вызов не доходит вовсе",
                ),
            ],
        ),
        Step(
            name="no-rights-garbage-token",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships?pageToken=not-a-cursor",
            auth="jwtNoBindings",
            test_script=[
                *assert_status(403),
                *_same_body_as("mbrNoRightsBody", "то же и на негодном курсоре"),
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-ORACLE-EMPTY (IAM-ID-2-12) — три РАЗНЫХ положения, один ответ.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-ORACLE-EMPTY",
    title="Человек из чужого аккаунта, человек ниоткуда и нерезолвимая строка дают ОДИН И ТОТ ЖЕ пустой перечень",
    classes=["NEG", "ORACLE"],
    priority="P0",
    steps=[
        Step(
            name="filter-person-of-foreign-account",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{userAABId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('перечень пуст', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships === undefined || j.memberships.length === 0, JSON.stringify(j)).to.eql(true);",
                "});",
                *_save_body("mbrEmptyBody"),
            ],
        ),
        Step(
            name="filter-person-without-membership",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{userNOBId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *_same_body_as("mbrEmptyBody",
                               "человек, не состоящий нигде, неотличим от человека чужого аккаунта"),
            ],
        ),
        Step(
            name="filter-unresolvable-person",
            method="GET",
            path=f'/iam/v1/accounts/{{{{accountAId}}}}/memberships?filter=userId%3D%22{ABSENT_USER}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *_same_body_as("mbrEmptyBody",
                               "строка, не резолвящаяся ни во что, неотличима от обоих: "
                               "отказ по отсутствию отличал бы «такого человека нет» от «есть, но не у вас»"),
            ],
        ),
        Step(
            name="control-person-of-this-account-answers",
            method="GET",
            path='/iam/v1/accounts/{{accountAId}}/memberships?filter=userId%3D%22{{userAAAId}}%22',
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: чтение отвечает содержательно, а не молчит всем', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-ORACLE-GET-404 (IAM-ID-2-13) — чужое членство по идентификатору
# неотличимо от несуществующего.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-ORACLE-GET-404",
    title="Членство чужого аккаунта и членство, которого нет нигде, дают один и тот же 404; тела различаются лишь подставленным id",
    classes=["NEG", "ORACLE"],
    priority="P0",
    steps=[
        Step(
            name="learn-a-membership-of-account-b",
            method="GET",
            path="/iam/v1/accounts/{{accountBId}}/memberships?pageSize=1",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "pm.test('ПРЕДМЕТ КЕЙСА СУЩЕСТВУЕТ: у аккаунта B есть членство', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').with.lengthOf(1);",
                "});",
                *save_from_response("j.memberships[0].id", "mbrOfBId"),
            ],
        ),
        Step(
            name="read-foreign-membership-through-account-a",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/memberships/{{mbrOfBId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                *_grpc_code(CODE_NOT_FOUND, "код — NOT_FOUND"),
                "pm.test('текст — контракт-тон владельца, и подставлен ЗАПРОШЕННЫЙ идентификатор', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.message, JSON.stringify(j))",
                "    .to.eql('Membership ' + pm.environment.get('mbrOfBId') + ' not found');",
                "});",
                *_save_body("mbrForeignGetBody"),
            ],
        ),
        Step(
            name="read-absent-membership-through-account-a",
            method="GET",
            path=f"/iam/v1/accounts/{{{{accountAId}}}}/memberships/{ABSENT_MEMBERSHIP}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(404),
                "pm.test('тела различаются РОВНО подставленным идентификатором и ничем иным', () => {",
                "  const foreign = pm.environment.get('mbrForeignGetBody')",
                "    .split(pm.environment.get('mbrOfBId')).join('<ID>');",
                f"  const absent = pm.response.text().split({_q(ABSENT_MEMBERSHIP)}).join('<ID>');",
                "  pm.expect(absent).to.eql(foreign);",
                "});",
            ],
        ),
        Step(
            name="control-owner-of-b-reads-the-same-row",
            method="GET",
            path="/iam/v1/accounts/{{accountBId}}/memberships/{{mbrOfBId}}",
            auth="jwtAccountAdminB",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: строка СУЩЕСТВУЕТ — значит её недоступность выше "
                "была сужением отбора, а не отсутствием данных', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('mbrOfBId'));",
                "  pm.expect(j.accountId, JSON.stringify(j)).to.eql(pm.environment.get('accountBId'));",
                "});",
            ],
        ),
    ],
))
