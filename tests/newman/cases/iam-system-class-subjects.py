# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: «аноним» и «вошедший» — системный класс субъекта привязки прав.

Приёмка: docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
редакция 6 (отпечаток 14fba0c20aca16483e41774ae1715ab0a6c6a017cb6b07d452fac3c637c5056c),
задача PRO-Robotech/kaname#829. Кейсы — по DoD приёмки, второй эшелон через собственный
публичный REST-фронт службы: S1 — SC-01…09, 14, 17, 40; L6 — SC-15; S2 — SC-19, 20, 21, 22,
24, 27, 28; S4 — краевая половина SC-53 (перечень кластерных администраторов, который
читает страница `/system/cluster/admins`; консольную половину держит проба браузера
`PRO-Robotech/kacho#3238`). Каждый ID несёт пару «статус + code». Сценарии только
integration (SC-12, 13, 23, 25, 26, 29, 37, 42, 43, 44) — с причиной в приёмке, здесь
их нет.

SC-10, 11, 16, 18 этим набором НЕ исполняются (редакция 6, DoD S1): их «Дано» — объект
сети, зарегистрированный его владельцем, а владельца сети на автономном стенде службы без
платформы нет by construction. На стадии S1 их держат integration-пробы
`internal/apps/kaname/api/access_binding/system_class_s1_integration_test.go`; сквозной
эшелон с теми же утверждениями — на стенде платформы, PRO-Robotech/kacho#3256.

SC-15 (отказ подстановке говорящим) исполняется этим набором с полосы L6 —
PRO-Robotech/kaname#832 (решение диспетчера Д1): вопрос `Check` от `user:*` → `400`,
code 3, текст дословно; близнец — тот же вопрос от человека `usr-B` отвечается по
выдачам. Переход до L6 (вопрос от подстановки как от анонима) снят тем же изменением,
что посадил отказ, и краем не утверждается.

КАК ПОСТРОЕН КАЖДЫЙ КЕЙС. Отрицание идёт в паре с положительным близнецом: сначала
та же выдача ЧЕЛОВЕКУ (`userNOBId`) либо выдача классу SC-01, затем предмет. Близнец
ловит сломанный посев: без него «400» на классе неотличимо от «400» на всём.

ФИКСТУРА (tests/authz-fixtures/seed_own_stand.py) против принципалов приёмки:
jwtAccountAdminA — распорядитель аккаунта A (`usr-A`; на стенде — учётка с ролью admin
на аккаунте A); userNOBId — человек без выдач (`usr-B`, только как цель выдачи и вопроса);
jwtNoBindings — предъявитель без права выдавать; jwtAccountAdminB — вызывающий ДРУГОГО
арендатора без прав в аккаунте A (`usr-C` как вызывающий, SC-17); jwtBootstrap — кластерный администратор
(`usr-K`: вопросы `Check`, перечни SC-17 и SC-53, тело К SC-28);
existingProjectId — проект аккаунта A; svaAId / jwtSAA — учётка аккаунта A. Роль только
чтения — системная `vpc.network.view` (`rolfe683216e63311d3f`, правила `[get, list]`),
роль правки — `vpc.network.admin` (`rol8ed48ecc3878c2e73`), роль кластерного
администратора — `rol21232f297a57a5a74`. Объект — сеть `enp00000000000000001` (obj-1)
правильной формы, цель выдачи — тип `vpc.network`, в вопросах к модели — тип `vpc_network`.

Test-design: ECP (виды субъекта; имена класса; вызывающие перечня), BVA (пустое имя),
decision table (класс × роль × цель × уровень области × вызывающий), error guessing
(дубль, подстановка говорящим), state transition (выдача → отзыв).
"""

HOME = "kaname"

CASES = []

POLL_CAP = 30

ROLE_READ = "rolfe683216e63311d3f"   # vpc.network.view — [get, list]
OBJ_ID = "enp00000000000000001"      # vpc.network правильной формы
SYSTEM_GRANT = "acbc5d32d66fc8dc4952"
ROLE_EDIT = "rol8ed48ecc3878c2e73"   # vpc.network.admin — [get, list, update]
ROLE_CLUSTER_ADMIN = "rol21232f297a57a5a74"
GLOBAL_RULE_TEXT = "GLOBAL scope requires names or labels selector for non-cluster-admin roles"

_OWN_WHY = ("собственный публичный REST-фронт службы: предмет — выдача классу и вопрос "
            "о доступе службы, а не край платформы")


def _klass(name):
    return {"type": "SUBJECT_TYPE_SYSTEM_CLASS", "id": name}


def _user(var):
    return {"type": "SUBJECT_TYPE_USER", "id": "{{" + var + "}}"}


def _target(obj=OBJ_ID):
    return {"resources": {"resources": [{"type": "vpc.network", "id": obj}]}}


def _body(subjects, role=ROLE_READ, target=None, scope_type="iam.project", scope_id="{{existingProjectId}}"):
    return {"subjects": subjects, "roleId": role, "scopeType": scope_type, "scopeId": scope_id,
            "target": target if target is not None else _target()}


def _poll(op_var, auth, name, capture=None, extra=()):
    cap = []
    if capture:
        cap = [f"if (j.done && !j.error && j.response && j.response.id) pm.environment.set({js_str(capture)}, j.response.id);"]
    return Step(
        name=name, method="GET", path="/operations/{{" + op_var + "}}", auth=auth,
        pre_script=[f"if (!pm.environment.get({js_str(op_var)})) {{ pm.execution.skipRequest(); }}"],
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code, pm.response.text()).to.eql(200));",
            "const j = pm.response.json();",
            "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
            "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
            f"if (!j.done && pc < {POLL_CAP}) {{",
            "  pm.environment.set('_pollCount', String(pc + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount'); pm.environment.unset('_pollStarted');",
            *cap,
            *extra,
        ],
    )


def _done_ok():
    return [
        "pm.test('operation done без error', () => {",
        "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
        "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
        "});",
    ]


def create_ok(name, body, id_var, auth="jwtAccountAdminA"):
    """Выдача заводится: 200 + Operation, опрос до done без error, id выдачи."""
    op_var = js_name(f"{id_var}OpId", where=f"iam-system-class-subjects/create_ok/{id_var}")
    return [
        Step(name=name, method="POST", path="/iam/v1/accessBindings", body=body, auth=auth,
             test_script=[*assert_status(200), *save_from_response("j.id", op_var)]),
        _poll(op_var, auth, f"{name}-poll", capture=id_var, extra=_done_ok()),
    ]


def create_refused(name, body, status, code, text, auth="jwtAccountAdminA", field=None):
    """Синхронный отказ: статус, code и ДОСЛОВНЫЙ текст; Operation не создана."""
    script = [
        *assert_status(status),
        "const j = pm.response.json();",
        f"pm.test({js_str(f'code {code}')}, () => pm.expect(j.code, JSON.stringify(j)).to.eql({code}));",
        "pm.test('Operation не создана', () => pm.expect(j.done, JSON.stringify(j)).to.not.exist);",
    ]
    if text is not None:
        script.append(f"pm.test('текст отказа дословно', () => pm.expect(j.message).to.eql({js_str(text)}));")
    if field:
        script += [
            "pm.test('нарушение названного поля', () => {",
            "  const f = (j.details || []).flatMap(d => (d.fieldViolations || []).map(v => v.field));",
            f"  pm.expect(f, JSON.stringify(j)).to.include({js_str(field)});",
            "});",
        ]
    return Step(name=name, method="POST", path="/iam/v1/accessBindings", body=body, auth=auth, test_script=script)


def revoke(id_var, auth="jwtAccountAdminA"):
    op_var = js_name(f"{id_var}DelOpId", where=f"iam-system-class-subjects/revoke/{id_var}")
    return [
        Step(name=f"cleanup-{id_var}", method="DELETE", path="/iam/v1/accessBindings/{{" + id_var + "}}", auth=auth,
             pre_script=[f"if (!pm.environment.get({js_str(id_var)})) {{ pm.execution.skipRequest(); }}"],
             test_script=[
                 "pm.test('уборка: снята (200) либо уже нет (404)', () => pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([200, 404]));",
                 "if (pm.response.code === 200) {",
                 *["  " + s for s in save_from_response("j.id", op_var)],
                 "}",
             ]),
        _poll(op_var, auth, f"cleanup-{id_var}-poll", extra=[
            f"pm.environment.unset({js_str(id_var)});",
            "pm.test('отзыв завершён', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        ]),
    ]


def check(name, subject, obj=OBJ_ID, verb="get", allowed=None, refused=None):
    """`AuthorizeService.Check` от кластерного администратора."""
    body = {"subject": subject, "resource": {"type": "vpc_network", "id": obj}, "action": f"vpc.networks.{verb}"}
    script = []
    if refused is not None:
        script = [
            *assert_status(400),
            "const j = pm.response.json();",
            "pm.test('code 3', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
            f"pm.test('текст отказа дословно', () => pm.expect(j.message).to.eql({js_str(refused)}));",
        ]
    else:
        script = [
            *assert_status(200),
            "const j = pm.response.json();",
            f"pm.test({js_str('allowed = ' + str(allowed).lower())}, () => pm.expect(j.allowed, JSON.stringify(j)).to.eql({str(allowed).lower()}));",
        ]
    return Step(name=name, method="POST", path="/iam/v1/authorize:check", body=body, auth="jwtBootstrap",
                test_script=script)


def _case(cid, title, classes, steps):
    CASES.append(Case(id=cid, title=title, classes=classes, priority="P0", steps=steps))


# ── S1 ──────────────────────────────────────────────────────────────────────

_case("SC01-CLASS-GRANT-CREATED", "SC-01: выдача классу authenticated заводится как выдача человеку; Get отдаёт класс",
      ["CRUD", "CONF"], [
          *create_ok("sc01-twin-user", _body([_user("userNOBId")]), "sc01UserAcbId"),
          *create_ok("sc01-class", _body([_klass("authenticated")]), "sc01AcbId"),
          Step(name="sc01-get", method="GET", path="/iam/v1/accessBindings/{{sc01AcbId}}", auth="jwtAccountAdminA",
               test_script=[
                   *assert_status(200),
                   "const j = pm.response.json();",
                   "pm.test('subjects — класс authenticated', () => pm.expect(j.subjects, JSON.stringify(j)).to.eql([{type: 'SUBJECT_TYPE_SYSTEM_CLASS', id: 'authenticated'}]));",
                   "pm.test('устаревшая пара', () => { pm.expect(j.subjectType).to.eql('system_class'); pm.expect(j.subjectId).to.eql('authenticated'); });",
                   "pm.test('system=false', () => pm.expect(j.system || false).to.eql(false));",
                   "pm.test('createdAt усечён до секунды', () => pm.expect(j.createdAt).to.match(/T\\d{2}:\\d{2}:\\d{2}Z$/));",
               ]),
          *revoke("sc01AcbId"), *revoke("sc01UserAcbId"),
      ])

for _cid, _name, _text in [
    ("SC02-UNKNOWN-CLASS-NAME", "everyone",
     'Illegal argument subject id "everyone" for subject type system_class (allowed: anonymous|authenticated)'),
    ("SC03-EMPTY-CLASS-NAME", "", "Illegal argument subject id (must be non-empty)"),
]:
    _case(_cid, f"{_cid}: имя класса {_name!r} → 400 INVALID_ARGUMENT; близнец SC-01", ["VAL", "NEG"], [
        *create_ok(f"{_cid.lower()}-twin", _body([_klass("authenticated")]), f"{_cid.lower().replace('-', '')}TwinId"),
        create_refused(f"{_cid.lower()}-refused", _body([_klass(_name)], role="rol1bda80f2be4d3658e"), 400, 3, _text),
        *revoke(f"{_cid.lower().replace('-', '')}TwinId"),
    ])

_case("SC04-CLASS-AND-USER", "SC-04: класс и человек в одной выдаче, порядок запроса", ["CRUD", "CONF"], [
    *create_ok("sc04-create", _body([_klass("authenticated"), _user("userNOBId")]), "sc04AcbId"),
    Step(name="sc04-get", method="GET", path="/iam/v1/accessBindings/{{sc04AcbId}}", auth="jwtAccountAdminA",
         test_script=[
             *assert_status(200),
             "const j = pm.response.json();",
             "pm.test('оба субъекта по порядку', () => pm.expect(j.subjects, JSON.stringify(j)).to.eql("
             "[{type: 'SUBJECT_TYPE_SYSTEM_CLASS', id: 'authenticated'}, {type: 'SUBJECT_TYPE_USER', id: pm.environment.get('userNOBId')}]));",
         ]),
    *revoke("sc04AcbId"),
])

_case("SC05-DUPLICATE-CLASS", "SC-05: повтор класса в одной выдаче → 400; близнец SC-04", ["VAL", "NEG"], [
    *create_ok("sc05-twin", _body([_klass("authenticated"), _user("userNOBId")]), "sc05TwinId"),
    create_refused("sc05-refused", _body([_klass("authenticated"), _klass("authenticated")], role="rol1bda80f2be4d3658e"), 400, 3,
                   "Illegal argument subjects: duplicate subject system_class/authenticated"),
    *revoke("sc05TwinId"),
])

_case("SC06-SECOND-ACTIVE-ALREADY-EXISTS", "SC-06: вторая такая же активная выдача → done с ALREADY_EXISTS", ["IDM", "NEG"], [
    *create_ok("sc06-first", _body([_klass("authenticated")]), "sc06AcbId"),
    Step(name="sc06-second", method="POST", path="/iam/v1/accessBindings", body=_body([_klass("authenticated")]),
         auth="jwtAccountAdminA", test_script=[*assert_status(200), *save_from_response("j.id", "sc06DupOpId")]),
    _poll("sc06DupOpId", "jwtAccountAdminA", "sc06-second-poll", extra=[
        "pm.test('done с error ALREADY_EXISTS (6)', () => { pm.expect(j.done).to.eql(true); pm.expect(j.error && j.error.code, JSON.stringify(j)).to.eql(6); });",
    ]),
    *revoke("sc06AcbId"),
])

_case("SC07-LEGACY-PAIR-ACCEPTS-CLASS", "SC-07: устаревшая пара system_class/anonymous принята; user/* — прежний отказ",
      ["CRUD", "VAL", "NEG"], [
          *create_ok("sc07-legacy", {"subjectType": "system_class", "subjectId": "anonymous", "roleId": ROLE_READ,
                                     "scopeType": "iam.project", "scopeId": "{{existingProjectId}}", "target": _target()},
                     "sc07AcbId"),
          Step(name="sc07-get", method="GET", path="/iam/v1/accessBindings/{{sc07AcbId}}", auth="jwtAccountAdminA",
               test_script=[*assert_status(200),
                            "const j = pm.response.json();",
                            "pm.test('subjects — класс anonymous', () => pm.expect(j.subjects, JSON.stringify(j)).to.eql([{type: 'SUBJECT_TYPE_SYSTEM_CLASS', id: 'anonymous'}]));"]),
          Step(name="sc07-wildcard-refused", method="POST", path="/iam/v1/accessBindings",
               body={"subjectType": "user", "subjectId": "*", "roleId": ROLE_READ, "scopeType": "iam.project",
                     "scopeId": "{{existingProjectId}}", "target": _target()},
               auth="jwtAccountAdminA", test_script=[
                   *assert_status(400), "const j = pm.response.json();",
                   "pm.test('code 3', () => pm.expect(j.code).to.eql(3));",
                   "pm.test('прежний текст', () => pm.expect(j.message).to.eql('Illegal argument subject_id \"*\" on a non-system access binding'));"]),
          *revoke("sc07AcbId"),
      ])

_case("SC08-CLASS-NOT-GROUP-MEMBER", "SC-08: класс не становится членом группы (member_type); близнец — человек",
      ["VAL", "NEG"], [
          Step(name="sc08-group", method="POST", path="/iam/v1/groups", auth="jwtAccountAdminA",
               body={"accountId": "{{accountAId}}", "name": "sc08-grp-{{runId}}"},
               test_script=[*assert_status(200), *save_from_response("j.id", "sc08GrpOpId")]),
          _poll("sc08GrpOpId", "jwtAccountAdminA", "sc08-group-poll", capture="sc08GrpId", extra=_done_ok()),
          Step(name="sc08-twin-user", method="POST", path="/iam/v1/groups/{{sc08GrpId}}:addMember", auth="jwtAccountAdminA",
               body={"memberType": "user", "memberId": "{{groupMemberAUserId}}"},
               test_script=[*assert_status(200), *save_from_response("j.id", "sc08AddOpId")]),
          _poll("sc08AddOpId", "jwtAccountAdminA", "sc08-twin-poll", extra=_done_ok()),
          Step(name="sc08-class-refused", method="POST", path="/iam/v1/groups/{{sc08GrpId}}:addMember", auth="jwtAccountAdminA",
               body={"memberType": "system_class", "memberId": "authenticated"},
               test_script=[*assert_status(400), "const j = pm.response.json();",
                            "pm.test('code 3', () => pm.expect(j.code).to.eql(3));",
                            "pm.test('поле member_type', () => { const f = (j.details || []).flatMap(d => (d.fieldViolations || []).map(v => v.field)); pm.expect(f, JSON.stringify(j)).to.include('member_type'); });"]),
          Step(name="sc08-cleanup-member", method="POST", path="/iam/v1/groups/{{sc08GrpId}}:removeMember", auth="jwtAccountAdminA",
               body={"memberType": "user", "memberId": "{{groupMemberAUserId}}"},
               test_script=["pm.test('уборка члена', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));"]),
          Step(name="sc08-cleanup-group", method="DELETE", path="/iam/v1/groups/{{sc08GrpId}}", auth="jwtAccountAdminA",
               test_script=["pm.test('уборка группы', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));"]),
      ])

_case("SC09-CLASS-NOT-CLUSTER-ADMIN", "SC-09: subjectType 4 у кластерного администратора → 400 subject_type",
      ["VAL", "NEG"], [
          Step(name="sc09-class-refused", method="POST", path="/iam/v1/cluster/admins", auth="jwtBootstrap",
               body={"subjectType": 4, "subjectId": "authenticated"},
               test_script=[*assert_status(400), "const j = pm.response.json();",
                            "pm.test('code 3', () => pm.expect(j.code).to.eql(3));",
                            "pm.test('поле subject_type и описание', () => { const v = (j.details || []).flatMap(d => d.fieldViolations || []); "
                            "pm.expect(v.map(x => x.field), JSON.stringify(j)).to.include('subject_type'); "
                            "pm.expect(v.map(x => x.description)).to.include(\"must be 'user' or 'service_account'\"); });"]),
      ])

_case("SC14-AUTHENTICATED-NOT-A-SPEAKER", "SC-14: system_class:authenticated говорящим → 400; близнец — аноним отвечается",
      ["VAL", "NEG"], [
          check("sc14-twin-anonymous", "system_class:anonymous", allowed=False),
          check("sc14-refused", "system_class:authenticated",
                refused="Illegal argument subject: system class authenticated is not a speaker"),
      ])

_case("SC15-WILDCARD-NOT-A-SPEAKER", "SC-15: подстановка user:* говорящим → 400; близнец — человек usr-B отвечается",
      ["VAL", "NEG"], [
          check("sc15-twin-user", "user:{{userNOBId}}", allowed=False),
          check("sc15-refused", "user:*", refused="Illegal argument subject: wildcard is not a speaker"),
      ])

def _list_by_class(name, auth, klass, want_js=None, wait_for=None):
    """`ListBySubject` по субъекту-классу. `want_js` — JS-массив ожидаемых id в порядке
    `(createdAt, id)`; None — пустая страница без `nextPageToken`.

    `wait_for` — первое чтение СВОЕЙ свежей выдачи (testing.md#ryw-retry-first-own-read):
    ограниченный опрос, пока в странице не появится названный id. На отрицании (пустая
    страница) опроса нет никогда (testing.md#ryw-retry-never-on-negatives).
    """
    wait = []
    if wait_for:
        wait = [
            "const _ids = ((pm.response.code === 200 && pm.response.json().accessBindings) || []).map(b => b.id);",
            "if (pm.environment.get('_lsStarted') !== pm.info.requestName) { pm.environment.set('_lsCount', '0'); pm.environment.set('_lsStarted', pm.info.requestName); }",
            "const _lc = parseInt(pm.environment.get('_lsCount') || '0', 10);",
            f"if (!_ids.includes(pm.environment.get({js_str(wait_for)})) && _lc < 50) {{",
            "  pm.environment.set('_lsCount', String(_lc + 1));",
            "  const _w = Date.now(); while (Date.now() - _w < 200) void 0;",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_lsCount'); pm.environment.unset('_lsStarted');",
        ]
    script = [*wait, *assert_status(200), "const j = pm.response.json();",
              "const ids = (j.accessBindings || []).map(b => b.id);"]
    if want_js is None:
        script += [
            "pm.test('страница пуста', () => pm.expect(ids, JSON.stringify(j)).to.eql([]));",
            "pm.test('nextPageToken пуст', () => pm.expect(j.nextPageToken || '', JSON.stringify(j)).to.eql(''));",
        ]
    else:
        script.append(f"pm.test('ровно ожидаемые выдачи в порядке (createdAt, id)', () => pm.expect(ids, JSON.stringify(j)).to.eql({want_js}));")
    return Step(name=name, method="GET", auth=auth,
                path=f"/iam/v1/accessBindings:listBySubject?subjectType=system_class&subjectId={klass}",
                test_script=script)


_case("SC17-LIST-BY-CLASS", "SC-17: перечень выдач классу сужен по праву на область; чужой арендатор — пустая страница; кластерный администратор — без сужения",
      ["FILTER", "AUTHZ"], [
          *create_ok("sc17-auth", _body([_klass("authenticated")]), "sc17AuthId"),
          *create_ok("sc17-anon", _body([_klass("anonymous")]), "sc17AnonId"),
          _list_by_class("sc17-own-anonymous", "jwtAccountAdminA", "anonymous",
                         want_js="[pm.environment.get('sc17AnonId')]", wait_for="sc17AnonId"),
          # Отрицательный близнец: тот же вызов от вызывающего ДРУГОГО арендатора без
          # прав в аккаунте A — один изменённый факт (вызывающий).
          _list_by_class("sc17-other-tenant-anonymous", "jwtAccountAdminB", "anonymous"),
          _list_by_class("sc17-cluster-admin-authenticated", "jwtBootstrap", "authenticated",
                         want_js=f"[{js_str(SYSTEM_GRANT)}, pm.environment.get('sc17AuthId')]", wait_for="sc17AuthId"),
          # Близнец «И»: тот же вызов от распорядителя аккаунта A — системной выдачи на
          # кластере нет, права на область кластера у него нет.
          _list_by_class("sc17-own-authenticated", "jwtAccountAdminA", "authenticated",
                         want_js="[pm.environment.get('sc17AuthId')]", wait_for="sc17AuthId"),
          *revoke("sc17AuthId"), *revoke("sc17AnonId"),
      ])

_case("SC40-SYSTEM-GRANT-MOVED", "SC-40: системная выдача чтения справочников — system_class/authenticated", ["CONF", "STATE"], [
    Step(name="sc40-get", method="GET", path=f"/iam/v1/accessBindings/{SYSTEM_GRANT}", auth="jwtBootstrap",
         test_script=[*assert_status(200), "const j = pm.response.json();",
                      "pm.test('класс authenticated', () => { pm.expect(j.subjects, JSON.stringify(j)).to.eql([{type: 'SUBJECT_TYPE_SYSTEM_CLASS', id: 'authenticated'}]); "
                      "pm.expect(j.subjectType).to.eql('system_class'); pm.expect(j.subjectId).to.eql('authenticated'); });",
                      "pm.test('прочее прежнее', () => { pm.expect(j.grantedRelation).to.eql('viewer'); pm.expect(j.system).to.eql(true); "
                      "pm.expect(j.deletionProtection).to.eql(true); pm.expect(j.scopeType).to.eql('iam.cluster'); pm.expect(j.id).to.eql('" + SYSTEM_GRANT + "'); });"]),
])

# ── S2 ──────────────────────────────────────────────────────────────────────

_ALL = {"allInScope": {}}

_case("SC19-AUTHENTICATED-ALL-IN-SCOPE-REFUSED", "SC-19: authenticated + allInScope на проекте и аккаунте → 400 target; близнец SC-01",
      ["VAL", "NEG"], [
          *create_ok("sc19-twin", _body([_klass("authenticated")]), "sc19TwinId"),
          create_refused("sc19-project", _body([_klass("authenticated")], role="rol1bda80f2be4d3658e", target=_ALL), 400, 3,
                         "Illegal argument target: a grant to system class authenticated outside the cluster names its objects (allInScope is not accepted)",
                         field="target"),
          create_refused("sc19-account", _body([_klass("authenticated")], role="rol1bda80f2be4d3658e", target=_ALL,
                                               scope_type="iam.account", scope_id="{{accountAId}}"), 400, 3,
                         "Illegal argument target: a grant to system class authenticated outside the cluster names its objects (allInScope is not accepted)",
                         field="target"),
          *revoke("sc19TwinId"),
      ])

_case("SC20-NO-AUTHORITY-NO-CLASS-GRANT", "SC-20: без права выдать — 403 тем же текстом, что человеку", ["AUTHZ", "NEG"], [
    Step(name="sc20-twin-user-refused", method="POST", path="/iam/v1/accessBindings", auth="jwtNoBindings",
         body=_body([_user("userNOBId")]),
         test_script=[*assert_status(403), "pm.environment.set('sc20UserRefusal', pm.response.json().message);"]),
    Step(name="sc20-class-refused", method="POST", path="/iam/v1/accessBindings", auth="jwtNoBindings",
         body=_body([_klass("authenticated")]),
         test_script=[*assert_status(403), "const j = pm.response.json();",
                      "pm.test('code 7', () => pm.expect(j.code).to.eql(7));",
                      "pm.test('тот же текст, что у выдачи человеку', () => pm.expect(j.message).to.eql(pm.environment.get('sc20UserRefusal')));",
                      "pm.environment.unset('sc20UserRefusal');"]),
])

_case("SC21-WRITE-ROLE-REFUSED", "SC-21: роль с пишущим глаголом классу → 400 FAILED_PRECONDITION", ["VAL", "NEG"], [
    *create_ok("sc21-twin", _body([_klass("authenticated")]), "sc21TwinId"),
    create_refused("sc21-refused", _body([_klass("authenticated")], role=ROLE_EDIT), 400, 9,
                   f"Role {ROLE_EDIT} grants verbs beyond get and list; a system class subject accepts read-only roles"),
    *revoke("sc21TwinId"),
])

_case("SC22-BOUND-ROLE-REFUSES-WRITE-VERB", "SC-22: роль, выданная классу, не получает пишущего глагола правкой", ["STATE", "NEG"], [
    Step(name="sc22-role", method="POST", path="/iam/v1/roles", auth="jwtAccountAdminA",
         body={"name": "sc22_read_{{runId}}", "definitionTier": {"tierType": "iam.account", "tierId": "{{accountAId}}"},
               "rules": [{"module": "vpc", "resources": ["network"], "verbs": ["get", "list"]}]},
         test_script=[*assert_status(200), *save_from_response("j.id", "sc22RoleOpId")]),
    _poll("sc22RoleOpId", "jwtAccountAdminA", "sc22-role-poll", capture="sc22RoleId", extra=_done_ok()),
    *create_ok("sc22-given", _body([_klass("authenticated")], role="{{sc22RoleId}}"), "sc22AcbId"),
    Step(name="sc22-refused", method="PATCH", path="/iam/v1/roles/{{sc22RoleId}}", auth="jwtAccountAdminA",
         body={"updateMask": "rules", "rules": [{"module": "vpc", "resources": ["network"], "verbs": ["get", "list", "update"]}]},
         test_script=[*assert_status(400), "const j = pm.response.json();",
                      "pm.test('code 9', () => pm.expect(j.code).to.eql(9));",
                      "pm.test('текст дословно', () => pm.expect(j.message).to.eql('Role ' + pm.environment.get('sc22RoleId') + ' is bound to a system class subject; it accepts read verbs only'));"]),
    *revoke("sc22AcbId"),
    Step(name="sc22-cleanup-role", method="DELETE", path="/iam/v1/roles/{{sc22RoleId}}", auth="jwtAccountAdminA",
         test_script=["pm.test('уборка роли', () => pm.expect(pm.response.code).to.be.oneOf([200, 404]));"]),
])

_case("SC24-ANONYMOUS-ALL-IN-SCOPE-REFUSED", "SC-24: анониму allInScope → 400 target; близнец SC-07", ["VAL", "NEG"], [
    *create_ok("sc24-twin", _body([_klass("anonymous")]), "sc24TwinId"),
    create_refused("sc24-refused", _body([_klass("anonymous")], role="rol1bda80f2be4d3658e", target=_ALL), 400, 3,
                   "Illegal argument target: a grant to system class anonymous names its objects (allInScope is not accepted)",
                   field="target"),
    *revoke("sc24TwinId"),
])

_SVA_A = {"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{svaAId}}"}

_case("SC27-SERVICE-ACCOUNT-GRANTS-TO-CLASS", "SC-27: учётка с admin на проекте выдаёт классу; grantedByUserId пуст; близнец без admin — 403", ["AUTHZ", "CRUD", "NEG"], [
    # Близнец (SC-20): посев выдач учётке A не заводит, и без admin на проекте
    # она выдать классу не вправе. Отличие от предмета — один факт: выдача admin.
    Step(name="sc27-twin-no-admin-refused", method="POST", path="/iam/v1/accessBindings", auth="jwtSAA",
         body=_body([_klass("authenticated")]),
         test_script=[*assert_status(403), "const j = pm.response.json();",
                      "pm.test('code 7', () => pm.expect(j.code, JSON.stringify(j)).to.eql(7));",
                      "pm.test('Operation не создана', () => pm.expect(j.done, JSON.stringify(j)).to.not.exist);"]),
    # Дано SC-27: у sva-A есть admin на prj-A — выдаёт распорядитель аккаунта A.
    *create_ok("sc27-given-admin", _body([_SVA_A], role=ROLE_CLUSTER_ADMIN, target=_ALL), "sc27AdminAcbId"),
    *create_ok("sc27-class-by-sva", _body([_klass("authenticated")]), "sc27AcbId", auth="jwtSAA"),
    Step(name="sc27-get", method="GET", path="/iam/v1/accessBindings/{{sc27AcbId}}", auth="jwtAccountAdminA",
         test_script=[*assert_status(200), "const j = pm.response.json();",
                      "pm.test('grantedByUserId пуст', () => pm.expect(j.grantedByUserId || '').to.eql(''));"]),
    *revoke("sc27AcbId"), *revoke("sc27AdminAcbId"),
])

_K_CLUSTER = dict(target=_ALL, scope_type="iam.cluster", scope_id="cluster_root")

_case("SC28-CLUSTER-CLASS-GRANT-UNREACHABLE",
      "SC-28: выдача классу на кластере глаголом создания недостижима — отказ в праве, отказ правила ствола, близнец с человеком, контроль живости пути",
      ["AUTHZ", "NEG", "STATE"], [
          # Тело К от распорядителя аккаунта A: право судится раньше ворот роли.
          Step(name="sc28-owner-refused", method="POST", path="/iam/v1/accessBindings", auth="jwtAccountAdminA",
               body=_body([_klass("authenticated")], **_K_CLUSTER),
               test_script=[*assert_status(403), "const j = pm.response.json();",
                            "pm.test('code 7', () => pm.expect(j.code, JSON.stringify(j)).to.eql(7));",
                            f"pm.test('текст не называет роль', () => pm.expect(j.message || '').to.not.include({js_str(ROLE_READ)}));",
                            "pm.test('Operation не создана', () => pm.expect(j.done, JSON.stringify(j)).to.not.exist);"]),
          # Близнец: тело К от кластерного администратора — отказ правила ствола дословно.
          create_refused("sc28-cluster-admin-refused", _body([_klass("authenticated")], **_K_CLUSTER),
                         400, 3, GLOBAL_RULE_TEXT, auth="jwtBootstrap"),
          # Близнец правила ствола: тело К с субъектом-человеком — тот же отказ тем же
          # текстом; класс не получает ни особого отказа, ни особого допуска.
          create_refused("sc28-user-same-rule", _body([_user("userNOBId")], **_K_CLUSTER),
                         400, 3, GLOBAL_RULE_TEXT, auth="jwtBootstrap"),
          # Контроль живости пути (не близнец): роль кластерного администратора человеку
          # на кластере с allInScope принимается — отказы выше по роли, а не по пути.
          *create_ok("sc28-path-alive", _body([_user("userNOBId")], role=ROLE_CLUSTER_ADMIN, **_K_CLUSTER),
                     "sc28CtlId", auth="jwtBootstrap"),
          *revoke("sc28CtlId", auth="jwtBootstrap"),
      ])

# ── S4, краевая половина ────────────────────────────────────────────────────

_case("SC53-CLUSTER-ADMINS-NO-CLASS-ROW",
      "SC-53: перечень кластерных администраторов (страница /system/cluster/admins) без строки класса и без системной выдачи",
      ["CONF", "NEG"], [
          Step(name="sc53-whoami", method="GET", path="/iam/v1/me", auth="jwtBootstrap",
               test_script=[*assert_status(200), "const j = pm.response.json();",
                            "pm.test('кластерный администратор назван субъектом', () => pm.expect(j.subject, JSON.stringify(j)).to.match(/^(user|service_account):/));",
                            "pm.environment.set('sc53AdminId', String(j.subject || '').split(':')[1] || '');"]),
          Step(name="sc53-list", method="GET", path="/iam/v1/cluster/admins", auth="jwtBootstrap",
               test_script=[*assert_status(200), "const j = pm.response.json();",
                            "const rows = j.admins || [];",
                            # Положительный контроль: перечень непуст и содержит вызывающего —
                            # отсутствие строки класса не выводится из пустого перечня.
                            "pm.test('перечень содержит вызывающего администратора', () => pm.expect(rows.map(a => a.subjectId), JSON.stringify(j)).to.include(pm.environment.get('sc53AdminId')));",
                            "pm.test('виды строк — только USER и SERVICE_ACCOUNT', () => pm.expect(rows.filter(a => !['USER', 'SERVICE_ACCOUNT'].includes(a.subjectType)), JSON.stringify(j)).to.eql([]));",
                            "pm.test('строки с субъектом-классом нет', () => pm.expect(rows.filter(a => ['authenticated', 'anonymous'].includes(a.subjectId)), JSON.stringify(j)).to.eql([]));",
                            f"pm.test({js_str('системной выдачи ' + SYSTEM_GRANT + ' нет')}, () => pm.expect(pm.response.text()).to.not.include({js_str(SYSTEM_GRANT)}));",
                            "pm.environment.unset('sc53AdminId');"]),
      ])


CASES = address_own_front(CASES, _OWN_WHY)
