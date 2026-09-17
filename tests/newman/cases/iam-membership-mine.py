# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set СВОЕГО списка членств (IAM-ID-2, стадия S2; kaname#206).

Covered RPCs:
  MembershipService.ListMine (GET /iam/v1/me/memberships)

Что здесь проверяется по существу
---------------------------------
Чтение отвечает ПРО ВЫЗЫВАЮЩЕГО и ни про кого больше: человек берётся из
аутентификации, а поля «за кого спрашиваю» у запроса нет. Поэтому три вещи:

  * ПОЛНОТА — в перечне все аккаунты, где человек числится, включая тот, куда
    его ПОЗВАЛИ; «куда позвали» читается по следу приглашения (`invitedBy`,
    `createdAt`), а не по состоянию: у позванного `invitedBy` непуст и называет
    пригласившего, у владельца собственного аккаунта — пуст. Пара доказывает,
    что поле различает, а не отдаёт константу, и что своё чтение отвечает на
    ДРУГОЙ вопрос, чем снимок прав `WhoAmI` (тот аккаунт называет — и не
    различает, по какой ветви);
  * СУЖЕНИЕ — `?userId=` и `?filter=userId=…` ответа не меняют: у пути нет
    такого поля в контракте, край неизвестный параметр отбрасывает, а перечень
    остаётся перечнем вызывающего (IAM-ID-2-09);
  * ФОРМА — размер страницы вне предела и негодный курсор отвергаются, законный
    обход не теряет и не повторяет строк; без личности — 401, а не пустая
    страница (IAM-ID-2-10, -11).

ДВА ЧЕЛОВЕКА, И ЭТО ТРЕБОВАНИЕ ПРЕДМЕТА, А НЕ УДОБСТВО. След приглашения
называет ПРИГЛАСИВШЕГО ЧЕЛОВЕКА (`users.invited_by` — внешний ключ в
`users(id)`; служебная учётка человеком не является, и продукт осознанно
оставляет колонку пустой). Значит «позванный видит, кто и когда» проверяется
только парой людей: главный человек церемонии приглашает ВТОРОГО в свой
аккаунт, второй читает свой список. Второй — `jwtHumanCeremonyNoBindings`:
человек без единой выдачи, и приглашение БЕЗ проекта и роли выдачи не создаёт
(Р3 приёмки: членство ≠ право), поэтому фикстура соседних наборов не задета;
по окончании кейс СНИМАЕТ членство и оставляет фикстуру как нашёл.

CRUD fixture dependency:
  jwtHumanCeremony / jwtHumanCeremonyStepUp / ceremonyUserId / ceremonyAccountId
      — человек и аккаунт, которым он владеет; поднятый вход нужен приглашению
        (`MembershipService/Create` несёт `required_acr_min: "2"`).
  jwtHumanCeremonyNoBindings / ceremonyNoBindingsUserId — второй человек, без
      выдач (`PRO-Robotech/kacho:tests/authz-fixtures/prodseed_ceremony.py`, стадия 8в).
  jwtAccountAdminA / jwtAccountAdminAStepUp / accountAId / ceremonyEmail —
      служебная учётка-распорядитель A приглашает главного человека в A, чтобы у
      того стало ДВА членства и обход страницами имел предмет.

Чего набор НЕ утверждает — сказано вслух: состояние `PENDING` в своём списке
(недостижимо by construction — приглашённому нечем аутентифицироваться, а вход
активирует все его членства разом; IAM-ID-2-16 в части своего списка не имеет
производителя на стенде) и позитивный контроль «имя аккаунта задано» — имя
аккаунта церемонии стенд не объявляет; оба покрыты интеграционной пробой
`membership_mine_integration_test.go`.

verifies: IAM-ID-2-07, -08, -09, -10, -11, -17 (в части своего списка), -18.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а). Как и у соседнего
# набора чтения членств, шаги идут через край: человеческих предъявителей
# производит волна церемонии платформы, а 401 без личности утверждается на
# публичном слушателе — единственной поверхности этого чтения (§2.5).
HOME = "kaname"

CASES = []


def _q(text):
    """Строковый литерал JavaScript. Экранируется всё, что рвёт литерал."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _grpc_code(code, label):
    """Утверждается ПАРА: HTTP-статус проверяется отдельно, здесь — код rpc.Status."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.code, JSON.stringify(j)).to.eql({code});",
        "});",
    ]


CODE_INVALID_ARGUMENT = 3
CODE_UNAUTHENTICATED = 16

TS_RE = r"/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/"


def _poll(op_var, auth):
    """Опрос операции с НАСТОЯЩЕЙ паузой между поллами; предмет кейса создан,
    только если операция завершилась без отказа."""
    return Step(
        name=f"poll-{op_var}",
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


def _remove_from_account(name, user_var, account_var, auth_step_up, auth_poll, op_var):
    """Снять членство — оставить фикстуру как нашли. Исход утверждается: уборка,
    которая не удалась, оставила бы соседям чужое членство."""
    return [
        Step(
            name=name,
            method="POST",
            path="/iam/v1/users/{{" + user_var + "}}:removeFromAccount",
            body={"accountId": "{{" + account_var + "}}"},
            auth=auth_step_up,
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", op_var),
            ],
        ),
        _poll(op_var, auth_poll),
    ]


# ---------------------------------------------------------------------------
# IAM-ID2-MINE-INVITED-OK (IAM-ID-2-08, -07 в части следа, -18, -17) — позванный
# видит аккаунт, куда его позвали, и видит КТО и КОГДА; владелец того же аккаунта
# видит его в своём списке БЕЗ следа приглашения; снимок прав называет аккаунт
# обоим и не различает их; права членство не даёт; после исключения аккаунт из
# своего списка уходит.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-MINE-INVITED-OK",
    title="Позванный человек читает свой список: аккаунт приглашения с invitedBy = пригласивший; владелец — тот же аккаунт без следа",
    classes=["CRUD", "HAPPY", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="second-person-learns-own-email",
            method="GET",
            path="/iam/v1/me",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                *save_from_response("j.email", "mineNobEmail"),
                "pm.test('ПРЕДПОСЫЛКА: у второго человека есть адрес, которым его можно позвать', () => "
                "pm.expect(pm.environment.get('mineNobEmail') || '', 'email').to.match(/@/));",
            ],
        ),
        Step(
            name="owner-invites-second-person-without-role",
            method="POST",
            path="/iam/v1/memberships",
            # БЕЗ проекта и роли: выдачи приглашение не создаёт (Р3), и второй
            # человек остаётся человеком без выдач для соседних наборов.
            body={"accountId": "{{ceremonyAccountId}}", "email": "{{mineNobEmail}}"},
            auth="jwtHumanCeremonyStepUp",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "mineInvOp"),
                "pm.test('metadata называет ВТОРОГО человека — почта платформе известна, строка одна', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.metadata && j.metadata.userId, JSON.stringify(j)).to.eql(pm.environment.get('ceremonyNoBindingsUserId'));",
                "});",
            ],
        ),
        _poll("mineInvOp", "jwtHumanCeremonyStepUp"),
        Step(
            name="second-person-reads-own-memberships",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('перечень содержит аккаунт, куда позвали, — своим чтением, а не чужим', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array');",
                "  const m = j.memberships.find(x => x.accountId === pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(m, 'аккаунт приглашения в своём списке: ' + JSON.stringify(j)).to.exist;",
                "  pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyNoBindingsUserId'));",
                "  pm.expect(m.id, JSON.stringify(m)).to.match(/^mbr-[0-9a-z]{17}$/);",
                "});",
                "pm.test('видит КТО и КОГДА: invitedBy называет пригласившего человека, createdAt заполнен и усечён до секунд', () => {",
                "  const m = pm.response.json().memberships.find(x => x.accountId === pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(m.invitedBy, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyUserId'));",
                f"  pm.expect(m.createdAt, JSON.stringify(m)).to.match({TS_RE});",
                "});",
                "pm.test('state заполнен у КАЖДОЙ записи — проекции не расходятся; какое именно значение, кейс не утверждает', () => {",
                "  pm.response.json().memberships.forEach(m => pm.expect(m.state, JSON.stringify(m)).to.be.a('string').that.is.not.empty);",
                "});",
                "pm.test('accountName — строка: пустое означает «имя не задано», а не «аккаунта нет»', () => {",
                "  pm.response.json().memberships.forEach(m => pm.expect(m.accountName, JSON.stringify(m)).to.be.a('string'));",
                "});",
                "pm.test('в перечне НЕТ ни одной строки другого человека', () => {",
                "  pm.response.json().memberships.forEach(m => pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyNoBindingsUserId')));",
                "});",
            ],
        ),
        Step(
            name="control-owner-reads-same-account-without-invite-trace",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ следа: у владельца ТОТ ЖЕ аккаунт стоит с ПУСТЫМ invitedBy — поле различает, а не отдаёт константу', () => {",
                "  const j = pm.response.json();",
                "  const m = j.memberships.find(x => x.accountId === pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(m, 'собственный аккаунт в своём списке владельца: ' + JSON.stringify(j)).to.exist;",
                "  pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyUserId'));",
                "  pm.expect(m.invitedBy, JSON.stringify(m)).to.eql('');",
                "});",
            ],
        ),
        Step(
            name="snapshot-names-the-account-but-does-not-tell-the-branch",
            method="GET",
            path="/iam/v1/me",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('снимок прав аккаунт НАЗЫВАЕТ (вход сделал членство активным) — но ни кто позвал, ни когда, в нём нет', () => {",
                "  const j = pm.response.json();",
                "  const a = (j.accounts || []).find(x => x.accountId === pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(a, JSON.stringify(j)).to.exist;",
                "  pm.expect(a, JSON.stringify(a)).to.not.have.property('invitedBy');",
                "});",
            ],
        ),
        Step(
            name="membership-alone-grants-no-right-on-the-account",
            method="GET",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                "pm.test('приглашение БЕЗ роли доступа не даёт: чтение аккаунта отвергнуто (403 гейтом края либо 404 сокрытием)', () => "
                "pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([403, 404]));",
            ],
        ),
        Step(
            name="control-owner-reads-the-account",
            method="GET",
            path="/iam/v1/accounts/{{ceremonyAccountId}}",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ отказа: владельцу тот же аккаунт отдаётся — отказ выше был свойством прав, а не поверхности', () => {",
                "  pm.expect(pm.response.json().id).to.eql(pm.environment.get('ceremonyAccountId'));",
                "});",
            ],
        ),
        *_remove_from_account("cleanup-remove-second-person", "ceremonyNoBindingsUserId", "ceremonyAccountId",
                              "jwtHumanCeremonyStepUp", "jwtHumanCeremonyStepUp", "mineRmOp"),
        Step(
            name="excluded-person-no-longer-lists-the-account",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="jwtHumanCeremonyNoBindings",
            test_script=[
                *assert_status(200),
                "pm.test('ИСКЛЮЧЁН — строки нет: аккаунт из своего списка ушёл (IAM-ID-2-17 в части своего списка)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships.map(m => m.accountId), JSON.stringify(j)).to.not.include(pm.environment.get('ceremonyAccountId'));",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-MINE-PAGINATION (IAM-ID-2-11, -07 в части полноты, -09) — главный человек
# состоит в двух аккаунтах: своём и A, куда его позвала служебная учётка. Обход
# страницами не теряет и не повторяет; негодная форма отвергается; посторонние
# параметры ответа не меняют.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-MINE-PAGINATION",
    title="Свой список: pageSize вне предела и негодный pageToken → 400; обход по одной строке полон; ?userId= ответа не меняет",
    classes=["VAL", "NEG", "BVA", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="account-a-admin-invites-the-person",
            method="POST",
            path="/iam/v1/memberships",
            body={"accountId": "{{accountAId}}", "email": "{{ceremonyEmail}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "mineAInvOp"),
            ],
        ),
        _poll("mineAInvOp", "jwtAccountAdminA"),
        Step(
            name="page-size-out-of-range",
            method="GET",
            path="/iam/v1/me/memberships?pageSize=5000",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "код — INVALID_ARGUMENT: значение вне [0..1000] отвергается, а не подрезается"),
            ],
        ),
        Step(
            name="page-token-garbage",
            method="GET",
            path="/iam/v1/me/memberships?pageToken=not-a-cursor",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(400),
                *_grpc_code(CODE_INVALID_ARGUMENT, "код — INVALID_ARGUMENT: негодный курсор отвергается, а не игнорируется"),
            ],
        ),
        Step(
            name="full-list-is-complete",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛНОТА: в перечне и свой аккаунт, и A, куда позвали; состав сверяется по множеству', () => {",
                "  const ids = pm.response.json().memberships.map(m => m.accountId);",
                "  pm.expect(ids, JSON.stringify(ids)).to.include(pm.environment.get('ceremonyAccountId'));",
                "  pm.expect(ids, JSON.stringify(ids)).to.include(pm.environment.get('accountAId'));",
                "});",
                "pm.environment.set('mineFullIds', JSON.stringify(pm.response.json().memberships.map(m => m.id).sort()));",
            ],
        ),
        Step(
            name="page-of-one-carries-a-token",
            method="GET",
            path="/iam/v1/me/memberships?pageSize=1",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ курсора: страница из одной строки отдаёт непустой nextPageToken', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.have.lengthOf(1);",
                "  pm.expect(j.nextPageToken, JSON.stringify(j)).to.be.a('string').that.is.not.empty;",
                "});",
                *save_from_response("j.nextPageToken", "mineTok"),
                *save_from_response("j.memberships[0].id", "mineFirstId"),
            ],
        ),
        Step(
            name="walk-collects-every-row-exactly-once",
            method="GET",
            path="/iam/v1/me/memberships?pageSize=1&pageToken={{mineTok}}",
            auth="jwtHumanCeremony",
            # Обход: страница за страницей, по одной строке, пока токен непуст.
            # Собранные идентификаторы сверяются с полным перечнем — каждая строка
            # ровно один раз.
            pre_script=[
                "if (pm.environment.get('_mineWalkStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_mineWalkStarted', pm.info.requestName);",
                "  pm.environment.set('mineSeen', JSON.stringify([pm.environment.get('mineFirstId')]));",
                "  pm.environment.set('_mineWalkHops', '0');",
                "}",
            ],
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "const seen = JSON.parse(pm.environment.get('mineSeen') || '[]');",
                "pm.test('страница из одной строки, и строка ещё не встречалась', () => {",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.have.lengthOf(1);",
                "  pm.expect(seen, 'повтор строки ' + j.memberships[0].id).to.not.include(j.memberships[0].id);",
                "});",
                "seen.push(j.memberships[0].id);",
                "pm.environment.set('mineSeen', JSON.stringify(seen));",
                "const hops = parseInt(pm.environment.get('_mineWalkHops') || '0', 10);",
                "if (j.nextPageToken && hops < 50) {",
                "  pm.environment.set('mineTok', j.nextPageToken);",
                "  pm.environment.set('_mineWalkHops', String(hops + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_mineWalkStarted');",
                "pm.environment.unset('_mineWalkHops');",
                "pm.test('обход собрал КАЖДУЮ строку полного перечня ровно один раз', () => {",
                "  pm.expect(j.nextPageToken, 'обход оборван по пределу хопов').to.eql('');",
                "  pm.expect(JSON.stringify(seen.slice().sort())).to.eql(pm.environment.get('mineFullIds'));",
                "});",
            ],
        ),
        Step(
            name="foreign-subject-parameters-change-nothing",
            method="GET",
            path='/iam/v1/me/memberships?userId={{ceremonyNoBindingsUserId}}&filter=userId%3D%22{{ceremonyNoBindingsUserId}}%22',
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ответ НЕ зависит от «за кого спрашиваю»: перечень тот же, что без параметров — членства вызывающего, и только его (IAM-ID-2-09)', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(JSON.stringify(j.memberships.map(m => m.id).sort())).to.eql(pm.environment.get('mineFullIds'));",
                "  j.memberships.forEach(m => pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyUserId')));",
                "});",
            ],
        ),
        *_remove_from_account("cleanup-remove-person-from-a", "ceremonyUserId", "accountAId",
                              "jwtAccountAdminAStepUp", "jwtAccountAdminA", "mineARmOp"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-ID2-MINE-NEG-ANON (IAM-ID-2-10) — без личности отказ, а не пустая
# страница; положительный контроль — тот же вызов с личностью отвечает перечнем.
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-ID2-MINE-NEG-ANON",
    title="GET /iam/v1/me/memberships без Bearer → 401 UNAUTHENTICATED; с личностью — 200 и перечень вызывающего",
    classes=["NEG", "AUTHZ"],
    priority="P0",
    steps=[
        Step(
            name="own-memberships-anonymous",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="anonymous",
            test_script=[
                "pm.test('ANON: status 401 — не 200 с пустым перечнем', () => pm.expect(pm.response.code, pm.response.text()).to.equal(401));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"pm.test('ANON: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal({CODE_UNAUTHENTICATED}));",
            ],
        ),
        Step(
            name="control-with-principal-answers",
            method="GET",
            path="/iam/v1/me/memberships",
            auth="jwtHumanCeremony",
            test_script=[
                *assert_status(200),
                "pm.test('ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: с личностью — перечень членств вызывающего, непустой', () => {",
                "  const j = pm.response.json();",
                "  pm.expect(j.memberships, JSON.stringify(j)).to.be.an('array').that.is.not.empty;",
                "  j.memberships.forEach(m => pm.expect(m.userId, JSON.stringify(m)).to.eql(pm.environment.get('ceremonyUserId')));",
                "});",
            ],
        ),
    ],
))
