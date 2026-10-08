# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set публичного близнеца `ClusterService` — администраторы кластера на
публичной поверхности (kaname#661; приёмка ADM-CA,
`docs/engineering/acceptance/cluster-admins-on-the-public-surface.md`, §5 S1 п.8).

Covered RPCs (публичный фронт службы):
  ClusterService.Get         (GET    /iam/v1/cluster)
  ClusterService.ListAdmins  (GET    /iam/v1/cluster/admins)
  ClusterService.GrantAdmin  (POST   /iam/v1/cluster/admins)
  ClusterService.RevokeAdmin (DELETE /iam/v1/cluster/admins/{subject_id})

Что здесь проверяется по существу
---------------------------------
Близнец исполняет ТЕ ЖЕ сценарии, что внутренняя служба, и закрыт тем же правом
`system_admin` на синглтоне кластера с тем же порогом уверенности (чтение «1»,
назначение и снятие «2»). Каждый отказ стоит в паре с близнецом, отличающимся
одним фактом: кортежем права (CAP-07), уровнем того же человека (CAP-08),
наличием удостоверения (CAP-09), фронтом, на котором стоит путь (CAP-21).

ПРОИЗВОДИТЕЛЬ УТВЕРЖДЕНИЙ — СЛУЖБА. Все шаги идут на собственный публичный
фронт (`ownRestBaseUrl`), CAP-21 — ещё и на собственный внутренний
(`ownInternalRestBaseUrl`). Края платформы здесь нет: порог на крае и его отказ
`401` с `WWW-Authenticate` — предмет набора края (CAP-25, `kacho#3093`); на
публичном слушателе службы порог предъявленного удостоверения судит её
политика вызывающего по своей копии каталога и отвечает `403`.

Аудит с публичной поверхности не наблюдаем: утверждения о строках аудита
(CAP-04, 05, 06, 17, 19) — в интеграционных пробах службы
(`internal/apps/kaname/api/cluster/public_twin_integration_test.go`).

ЧЕГО НАБОР НЕ УТВЕРЖДАЕТ — СКАЗАНО ВСЛУХ. Внутренние ноги CAP-20 (чтение и
снятие внутренним путём) и близнец CAP-21 «внутренний путь на внутреннем фронте
отвечает 200» на автономном стенде не исполнимы by construction: внутренние
глаголы администраторов кластера фронтируются краем
(`authzguard.GatewayFrontedInternalRPCs`), а внутренний фронт службы идёт к
своему слушателю СВОИМ удостоверением и кругом края не становится. Поэтому
CAP-21 утверждает здесь, что внутренний путь на внутреннем фронте ОБСЛУЖЕН
владельцем (ответ — не промах маршрутизатора), а «назначено одним путём — видно
другим» держит интеграционная проба `TestClusterPublic_CAP20_OneWritePathBothTransports`.

CRUD fixture dependency (посев `tests/authz-fixtures/seed_ceremony.py --wave`):
  jwtBootstrap                         — `m-admin`, машинный `system_admin` (машинный посев);
  jwtHumanCapAdmin / …StepUp / humanCapAdminUserId / ceremonyCapAdminEmail /
  ceremonyCapAdminAccountId            — `h-admin/1`, `h-admin/2`: один человек с выдачей;
  jwtHumanCapPlainStepUp               — `h-plain/2`: человек без выдач, уровень «2»;
  ceremonyCapTargetUserId / …Email / …DisplayName — `target` с непустым именем;
  ceremonyCapSvaTargetId               — `sva-target`, включённая служебная учётка;
  ceremonyCapBlockedUserId             — человек, которого CAP-12 блокирует и разблокирует.

Каждый кейс оставляет `target` и `sva-target` без выдачи, как нашёл: набор
назначает и снимает, и выдача, пережившая кейс, сделала бы вердикт соседа
функцией порядка.

verifies: CAP-01…CAP-14, CAP-17, CAP-20, CAP-21.
"""

HOME = "kaname"

CASES = []

M = "jwtBootstrap"
HA1 = "jwtHumanCapAdmin"
HA2 = "jwtHumanCapAdminStepUp"
HP2 = "jwtHumanCapPlainStepUp"
ANON = "anonymous"

CODE_INVALID_ARGUMENT = 3
CODE_NOT_FOUND = 5
CODE_PERMISSION_DENIED = 7
CODE_FAILED_PRECONDITION = 9
CODE_UNAUTHENTICATED = 16

ADMINS = "/iam/v1/cluster/admins"
TARGET = "{{ceremonyCapTargetUserId}}"
SVA_TARGET = "{{ceremonyCapSvaTargetId}}"
GHOST_USER = "usrzzzzzzzzzzzzzzzzz"
GHOST_SVA = "svazzzzzzzzzzzzzzzzz"
TS_RE = r"/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/"
CAG_RE = r"/^cag_[0-9a-hjkmnp-tv-z]{17}$/"

_INTERNAL_WHY = ("собственный внутренний REST-фронт службы; без него CAP-21 не различает, "
                 "на каком фронте стоит путь")


def _q(text):
    """Строковый литерал JavaScript."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'").replace("\n", " ") + "'"


def _pair(status, code, label):
    """Утверждается ПАРА: HTTP-статус и код `google.rpc.Status`."""
    return [
        *assert_status(status),
        f"pm.test({_q(label + ': grpc code ' + str(code))}, () => {{",
        "  let j; try { j = pm.response.json(); } catch (e) { j = null; }",
        f"  pm.expect(j && j.code, pm.response.text()).to.eql({code});",
        "});",
    ]


def _message(text_js, label):
    """Сообщение отказа ДОСЛОВНО — тон отказа часть контракта."""
    return [
        f"pm.test({_q(label + ': сообщение дословно')}, () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect(j.message, JSON.stringify(j)).to.eql({text_js});",
        "});",
    ]


def _field_violation(field, label, description=None):
    lines = [
        f"pm.test({_q(label + ': нарушение поля ' + field)}, () => {{",
        "  const j = pm.response.json();",
        "  const br = (j.details || []).find(d => (d['@type'] || '').endsWith('google.rpc.BadRequest'));",
        "  pm.expect(br, JSON.stringify(j)).to.exist;",
        f"  const fv = (br.fieldViolations || []).find(v => v.field === {_q(field)});",
        "  pm.expect(fv, JSON.stringify(j)).to.exist;",
    ]
    if description is not None:
        lines.append(f"  pm.expect(fv.description, JSON.stringify(fv)).to.eql({_q(description)});")
    lines.append("});")
    return lines


def _op_ok(label):
    """Мутация близнеца — `Operation` `iop…`, завершённая без отказа тем же ответом."""
    return [
        *assert_status(200),
        f"pm.test({_q(label + ': Operation iop… done без error')}, () => {{",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, JSON.stringify(j)).to.match(/^iop/);",
        "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
        "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
        "});",
    ]


def _grant(name, auth, subject_id, subject_type="USER", tests=()):
    return Step(
        name=name, method="POST", path=ADMINS,
        body={"subjectType": subject_type, "subjectId": subject_id},
        auth=auth, test_script=[*tests],
    )


def _revoke(name, auth, subject_id, query="", tests=()):
    return Step(
        name=name, method="DELETE", path=ADMINS + "/" + subject_id + query,
        auth=auth, test_script=[*tests],
    )


def _list(name, auth, tests=()):
    return Step(name=name, method="GET", path=ADMINS, auth=auth,
                test_script=[*assert_status(200), *tests])


def _entries_for(var_js, label, count):
    """Ровно `count` записей перечня с subjectId = значение переменной окружения."""
    return [
        f"pm.test({_q(label)}, () => {{",
        "  const j = pm.response.json();",
        "  pm.expect(j.admins, JSON.stringify(j)).to.be.an('array');",
        f"  const want = {var_js};",
        "  pm.expect(want, 'ключ посева').to.be.a('string').and.not.empty;",
        f"  pm.expect(j.admins.filter(a => a.subjectId === want).length, JSON.stringify(j)).to.eql({count});",
        "});",
    ]


def _env(name):
    return f"pm.environment.get({_q(name)})"


def _poll(op_var, auth):
    """Опрос операции с НАСТОЯЩЕЙ паузой между поллами; предмет создан, только
    если операция завершилась без отказа."""
    return Step(
        name=f"poll-{op_var}", method="GET", path="/operations/{{" + op_var + "}}",
        auth=auth, op_var=op_var,
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
            "pm.test('ПРЕДМЕТ КЕЙСА — операция завершилась без отказа', () => {",
            "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
            "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
            "});",
        ],
    )


def _cleanup_target(tag, auth=HA2):
    """Уборка: `target` уходит из кейса без выдачи. Исход утверждается."""
    return _revoke(f"{tag}-cleanup-revoke-target", auth, TARGET,
                   tests=_op_ok(f"{tag} уборка: target снят"))


# ---------------------------------------------------------------------------
# Класс A
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="CAP-01-LIST-ADMINS",
    title="m-admin читает перечень: запись машинного администратора, поля заполнены",
    classes=["CRUD", "HAPPY"], priority="P0",
    steps=[
        Step(name="cap01-whoami-m-admin", method="GET", path="/iam/v1/me", auth=M,
             test_script=[
                 *assert_status(200),
                 "pm.test('m-admin — служебная учётка', () => {",
                 "  const j = pm.response.json();",
                 "  pm.expect(j.subject, JSON.stringify(j)).to.match(/^service_account:sva/);",
                 "  pm.environment.set('capMachineAdminId', j.subject.split(':')[1]);",
                 "});",
             ]),
        _list("cap01-list", M, [
            "pm.test('admins содержит машинного администратора как SERVICE_ACCOUNT', () => {",
            "  const j = pm.response.json();",
            f"  const e = (j.admins || []).find(a => a.subjectId === {_env('capMachineAdminId')});",
            "  pm.expect(e, JSON.stringify(j)).to.exist;",
            "  pm.expect(e.subjectType, JSON.stringify(e)).to.eql('SERVICE_ACCOUNT');",
            "});",
            "pm.test('у каждой записи заполнены clusterAdminGrantId (cag_<17>), subjectId, grantedAt', () => {",
            "  pm.response.json().admins.forEach(a => {",
            f"    pm.expect(a.clusterAdminGrantId, JSON.stringify(a)).to.match({CAG_RE});",
            "    pm.expect(a.subjectId, JSON.stringify(a)).to.be.a('string').and.not.empty;",
            f"    pm.expect(a.grantedAt, JSON.stringify(a)).to.match({TS_RE});",
            "  });",
            "});",
        ]),
    ],
))

CASES.append(Case(
    id="CAP-02-GET-CLUSTER",
    title="m-admin читает кластер: id cluster_root, createdAt — целые секунды",
    classes=["CRUD", "HAPPY"], priority="P1",
    steps=[
        Step(name="cap02-get", method="GET", path="/iam/v1/cluster", auth=M,
             test_script=[
                 *assert_status(200),
                 "pm.test('id = cluster_root, createdAt усечён до секунд', () => {",
                 "  const j = pm.response.json();",
                 "  pm.expect(j.id, JSON.stringify(j)).to.eql('cluster_root');",
                 f"  pm.expect(j.createdAt, JSON.stringify(j)).to.match({TS_RE});",
                 "});",
             ]),
    ],
))

CASES.append(Case(
    id="CAP-03-GRANT-HUMAN",
    title="h-admin/2 назначает target: Operation done, ответ — выдача, перечень несёт имя и почту",
    classes=["CRUD", "HAPPY"], priority="P0",
    steps=[
        _grant("cap03-grant", HA2, TARGET, tests=[
            *_op_ok("CAP-03"),
            *save_from_response("j.id", "cap03OpId"),
            *save_from_response("j.metadata && j.metadata.clusterAdminGrantId", "capTargetGrantId"),
            "pm.test('metadata и response называют выдачу target', () => {",
            "  const j = pm.response.json();",
            f"  pm.expect(j.metadata.subjectId, JSON.stringify(j)).to.eql({_env('ceremonyCapTargetUserId')});",
            "  pm.expect(j.metadata.clusterAdminGrantId, JSON.stringify(j)).to.be.a('string').and.not.empty;",
            "  pm.expect(j.response.id, JSON.stringify(j)).to.eql(j.metadata.clusterAdminGrantId);",
            "  pm.expect(j.response.subjectType, JSON.stringify(j)).to.eql('USER');",
            f"  pm.expect(j.response.grantedByUserId, JSON.stringify(j)).to.eql({_env('humanCapAdminUserId')});",
            "});",
        ]),
        _poll("cap03OpId", HA2),
        _list("cap03-list", HA1, [
            *_entries_for(_env("ceremonyCapTargetUserId"), "в перечне ровно одна запись target", 1),
            "pm.test('subjectEmail — адрес target, subjectDisplayName непуст и равен имени, grantedByEmail — адрес h-admin', () => {",
            f"  const e = pm.response.json().admins.find(a => a.subjectId === {_env('ceremonyCapTargetUserId')});",
            f"  pm.expect(e.subjectEmail, JSON.stringify(e)).to.eql({_env('ceremonyCapTargetEmail')});",
            "  pm.expect(e.subjectDisplayName, JSON.stringify(e)).to.be.a('string').and.not.empty;",
            f"  pm.expect(e.subjectDisplayName, JSON.stringify(e)).to.eql({_env('ceremonyCapTargetDisplayName')});",
            f"  pm.expect(e.grantedByEmail, JSON.stringify(e)).to.eql({_env('ceremonyCapAdminEmail')});",
            "});",
        ]),
    ],
))

CASES.append(Case(
    id="CAP-04-REGRANT-IDEMPOTENT",
    title="Повтор назначения target — тот же clusterAdminGrantId, запись одна",
    classes=["IDM"], priority="P1",
    steps=[
        _grant("cap04-regrant", HA2, TARGET, tests=[
            *_op_ok("CAP-04"),
            "pm.test('тот же clusterAdminGrantId, что в CAP-03', () => {",
            "  const j = pm.response.json();",
            f"  pm.expect(j.metadata.clusterAdminGrantId, JSON.stringify(j)).to.eql({_env('capTargetGrantId')});",
            "});",
        ]),
        _list("cap04-list", HA1, _entries_for(_env("ceremonyCapTargetUserId"), "в перечне ровно одна запись target", 1)),
    ],
))

CASES.append(Case(
    id="CAP-05-REVOKE",
    title="h-admin/2 снимает target: Operation done, метаданные называют выдачу, перечень её не содержит",
    classes=["CRUD", "HAPPY"], priority="P0",
    steps=[
        _revoke("cap05-revoke", HA2, TARGET, tests=[
            *_op_ok("CAP-05"),
            "pm.test('metadata: выдача CAP-03 и subjectId target', () => {",
            "  const j = pm.response.json();",
            f"  pm.expect(j.metadata.clusterAdminGrantId, JSON.stringify(j)).to.eql({_env('capTargetGrantId')});",
            f"  pm.expect(j.metadata.subjectId, JSON.stringify(j)).to.eql({_env('ceremonyCapTargetUserId')});",
            "});",
        ]),
        _list("cap05-list", HA1, _entries_for(_env("ceremonyCapTargetUserId"), "перечень записи target не содержит", 0)),
    ],
))

CASES.append(Case(
    id="CAP-06-REGRANT-AFTER-REVOKE",
    title="Повторное назначение после снятия — тот же clusterAdminGrantId, выдача активна",
    classes=["IDM"], priority="P1",
    steps=[
        _grant("cap06-regrant", HA2, TARGET, tests=[
            *_op_ok("CAP-06"),
            "pm.test('тот же clusterAdminGrantId', () => {",
            "  const j = pm.response.json();",
            f"  pm.expect(j.metadata.clusterAdminGrantId, JSON.stringify(j)).to.eql({_env('capTargetGrantId')});",
            "});",
        ]),
        _list("cap06-list", HA1, _entries_for(_env("ceremonyCapTargetUserId"), "выдача target активна", 1)),
        _cleanup_target("cap06"),
    ],
))

# ---------------------------------------------------------------------------
# Класс B
# ---------------------------------------------------------------------------

_DENY_PLAIN = "CAP-07 h-plain/2"
CASES.append(Case(
    id="CAP-07-NO-GRANT-NO-ACCESS",
    title="h-plain/2 без кортежа на cluster — 403 на четырёх глаголах; h-admin/2 тем же уровнем — проходит",
    classes=["AUTHZ", "NEG"], priority="P0",
    steps=[
        Step(name="cap07-plain-get", method="GET", path="/iam/v1/cluster", auth=HP2,
             test_script=_pair(403, CODE_PERMISSION_DENIED, _DENY_PLAIN + " Get")),
        Step(name="cap07-plain-list", method="GET", path=ADMINS, auth=HP2,
             test_script=_pair(403, CODE_PERMISSION_DENIED, _DENY_PLAIN + " ListAdmins")),
        _grant("cap07-plain-grant", HP2, TARGET, tests=_pair(403, CODE_PERMISSION_DENIED, _DENY_PLAIN + " GrantAdmin")),
        _revoke("cap07-plain-revoke", HP2, TARGET, tests=_pair(403, CODE_PERMISSION_DENIED, _DENY_PLAIN + " RevokeAdmin")),
        _list("cap07-list-after-denied-grant", HA2,
              _entries_for(_env("ceremonyCapTargetUserId"), "отказанное назначение выдачи не создало", 0)),
        Step(name="cap07-twin-get", method="GET", path="/iam/v1/cluster", auth=HA2,
             test_script=[*assert_status(200)]),
        _grant("cap07-twin-grant", HA2, TARGET, tests=_op_ok("CAP-07 близнец GrantAdmin")),
        _revoke("cap07-twin-revoke", HA2, TARGET, tests=_op_ok("CAP-07 близнец RevokeAdmin")),
    ],
))

_DENY_L1 = "CAP-08 h-admin/1"
CASES.append(Case(
    id="CAP-08-ASSURANCE-FLOOR",
    title="Порог назначения и снятия «2», чтения «1»: h-admin/1 — 403 на мутациях, 200 на чтениях; h-admin/2 — проходит",
    classes=["AUTHZ", "NEG"], priority="P0",
    steps=[
        _grant("cap08-l1-grant", HA1, TARGET, tests=[
            *_pair(403, CODE_PERMISSION_DENIED, _DENY_L1 + " GrantAdmin"),
            *_message(_q("permission denied"), _DENY_L1 + " GrantAdmin"),
        ]),
        _list("cap08-l1-list", HA1,
              _entries_for(_env("ceremonyCapTargetUserId"), "назначение уровнем «1» выдачи не создало; чтение уровнем «1» — 200", 0)),
        Step(name="cap08-l1-get", method="GET", path="/iam/v1/cluster", auth=HA1,
             test_script=[*assert_status(200)]),
        _grant("cap08-l2-grant", HA2, TARGET, tests=_op_ok("CAP-08 близнец GrantAdmin")),
        _revoke("cap08-l1-revoke", HA1, TARGET, tests=[
            *_pair(403, CODE_PERMISSION_DENIED, _DENY_L1 + " RevokeAdmin"),
            *_message(_q("permission denied"), _DENY_L1 + " RevokeAdmin"),
        ]),
        _list("cap08-list-after-denied-revoke", HA1,
              _entries_for(_env("ceremonyCapTargetUserId"), "снятие уровнем «1» выдачу не тронуло", 1)),
        _revoke("cap08-l2-revoke", HA2, TARGET, tests=_op_ok("CAP-08 близнец RevokeAdmin")),
    ],
))

_ANON = "CAP-09 anon"
CASES.append(Case(
    id="CAP-09-ANONYMOUS",
    title="Без Authorization — 401 на четырёх глаголах; m-admin — проходит",
    classes=["AUTHZ", "NEG"], priority="P0",
    steps=[
        Step(name="cap09-anon-get", method="GET", path="/iam/v1/cluster", auth=ANON,
             test_script=_pair(401, CODE_UNAUTHENTICATED, _ANON + " Get")),
        Step(name="cap09-anon-list", method="GET", path=ADMINS, auth=ANON,
             test_script=_pair(401, CODE_UNAUTHENTICATED, _ANON + " ListAdmins")),
        _grant("cap09-anon-grant", ANON, TARGET, tests=_pair(401, CODE_UNAUTHENTICATED, _ANON + " GrantAdmin")),
        _revoke("cap09-anon-revoke", ANON, TARGET, tests=_pair(401, CODE_UNAUTHENTICATED, _ANON + " RevokeAdmin")),
        Step(name="cap09-twin-get", method="GET", path="/iam/v1/cluster", auth=M,
             test_script=[*assert_status(200)]),
        _list("cap09-twin-list", M, _entries_for(_env("ceremonyCapTargetUserId"), "анонимное назначение выдачи не создало", 0)),
        _grant("cap09-twin-grant", M, TARGET, tests=_op_ok("CAP-09 близнец GrantAdmin")),
        _revoke("cap09-twin-revoke", M, TARGET, tests=_op_ok("CAP-09 близнец RevokeAdmin")),
    ],
))

CASES.append(Case(
    id="CAP-10-MALFORMED-INPUT",
    title="Негодный вход назначения — 400/3 с нарушением поля subject_id; годный — успех",
    classes=["VAL", "NEG"], priority="P1",
    steps=[
        _grant("cap10-kind-mismatch", M, TARGET, subject_type="SERVICE_ACCOUNT", tests=[
            *_pair(400, CODE_INVALID_ARGUMENT, "CAP-10 (а)"),
            *_field_violation("subject_id", "CAP-10 (а)"),
        ]),
        Step(name="cap10-missing-id", method="POST", path=ADMINS, auth=M,
             body={"subjectType": "USER"},
             test_script=[
                 *_pair(400, CODE_INVALID_ARGUMENT, "CAP-10 (б)"),
                 *_field_violation("subject_id", "CAP-10 (б)", "required"),
             ]),
        _grant("cap10-underscore", M, "usr_aaaaaaaaaaaaaaaaa", tests=[
            *_pair(400, CODE_INVALID_ARGUMENT, "CAP-10 (в)"),
            *_field_violation("subject_id", "CAP-10 (в)"),
        ]),
        _list("cap10-list", M, _entries_for(_env("ceremonyCapTargetUserId"), "ни одной выдачи от негодного входа", 0)),
        _grant("cap10-twin", M, TARGET, tests=_op_ok("CAP-10 близнец")),
        _cleanup_target("cap10", auth=M),
    ],
))

CASES.append(Case(
    id="CAP-11-ABSENT-HUMAN",
    title="Назначение несуществующего человека годной формы — 400/3 `User <id> not found`",
    classes=["NEG"], priority="P1",
    steps=[
        _grant("cap11-ghost", M, GHOST_USER, tests=[
            *_pair(400, CODE_INVALID_ARGUMENT, "CAP-11"),
            *_message(_q(f"User {GHOST_USER} not found"), "CAP-11"),
        ]),
        _grant("cap11-twin", M, TARGET, tests=_op_ok("CAP-11 близнец")),
        _cleanup_target("cap11", auth=M),
    ],
))

CASES.append(Case(
    id="CAP-12-SUBJECT-BARRED",
    title="Назначение заблокированному, неподтверждённому и выключенной учётке — 400/9 с причиной; активным — успех",
    classes=["NEG", "STATE"], priority="P1",
    steps=[
        Step(name="cap12-block", method="POST",
             path="/iam/v1/users/{{ceremonyCapBlockedUserId}}:block", body={}, auth=HA2,
             test_script=[*assert_status(200), *save_from_response("j.id", "cap12BlockOpId")]),
        _poll("cap12BlockOpId", HA2),
        _grant("cap12-grant-blocked", M, "{{ceremonyCapBlockedUserId}}", tests=[
            *_pair(400, CODE_FAILED_PRECONDITION, "CAP-12 blocked"),
            *_message("'User ' + " + _env("ceremonyCapBlockedUserId") + " + ' is blocked'", "CAP-12 blocked"),
        ]),
        Step(name="cap12-invite-pending", method="POST", path="/iam/v1/users:invite",
             pre_script=[
                 "const __dom = (pm.environment.get('ceremonyCapTargetEmail') || '').split('@')[1] || '';",
                 "pm.environment.set('capPendingEmail', 'cap-pending-' + pm.variables.get('runId') + '@' + __dom);",
             ],
             body={"accountId": "{{ceremonyCapAdminAccountId}}", "email": "{{capPendingEmail}}"},
             auth=HA2,
             test_script=[
                 *assert_status(200),
                 *save_from_response("j.id", "cap12InviteOpId"),
                 *save_from_response("j.metadata && j.metadata.userId", "capPendingUserId"),
             ]),
        _poll("cap12InviteOpId", HA2),
        _grant("cap12-grant-pending", M, "{{capPendingUserId}}", tests=[
            *_pair(400, CODE_FAILED_PRECONDITION, "CAP-12 pending"),
            *_message("'User ' + " + _env("capPendingUserId") + " + ' is not active'", "CAP-12 pending"),
        ]),
        Step(name="cap12-sa-create", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{ceremonyCapAdminAccountId}}", "name": "cap-sva-off-{{runId}}"},
             auth=HA2,
             test_script=[
                 *assert_status(200),
                 *save_from_response("j.id", "cap12SaOpId"),
                 *save_from_response("j.metadata && j.metadata.serviceAccountId", "capSvaOffId"),
             ]),
        _poll("cap12SaOpId", HA2),
        Step(name="cap12-sa-disable", method="POST",
             path="/iam/v1/serviceAccounts/{{capSvaOffId}}:disable", body={}, auth=HA2,
             test_script=[*assert_status(200), *save_from_response("j.id", "cap12DisableOpId")]),
        _poll("cap12DisableOpId", HA2),
        _grant("cap12-grant-sva-off", M, "{{capSvaOffId}}", subject_type="SERVICE_ACCOUNT", tests=[
            *_pair(400, CODE_FAILED_PRECONDITION, "CAP-12 sva-off"),
            *_message("'ServiceAccount ' + " + _env("capSvaOffId") + " + ' is disabled'", "CAP-12 sva-off"),
        ]),
        _list("cap12-list", M, [
            "pm.test('ни одной выдачи barred-субъектам', () => {",
            "  const ids = pm.response.json().admins.map(a => a.subjectId);",
            "  ['ceremonyCapBlockedUserId', 'capPendingUserId', 'capSvaOffId'].forEach(k =>",
            "    pm.expect(ids, k).to.not.include(pm.environment.get(k)));",
            "});",
        ]),
        _grant("cap12-twin-target", M, TARGET, tests=_op_ok("CAP-12 близнец target")),
        _grant("cap12-twin-sva", M, SVA_TARGET, subject_type="SERVICE_ACCOUNT",
               tests=_op_ok("CAP-12 близнец sva-target")),
        _cleanup_target("cap12", auth=M),
        _revoke("cap12-cleanup-revoke-sva", M, SVA_TARGET, query="?subjectType=SERVICE_ACCOUNT",
                tests=_op_ok("CAP-12 уборка: sva-target снят")),
        Step(name="cap12-cleanup-unblock", method="POST",
             path="/iam/v1/users/{{ceremonyCapBlockedUserId}}:unblock", body={}, auth=HA2,
             test_script=[*assert_status(200), *save_from_response("j.id", "cap12UnblockOpId")]),
        _poll("cap12UnblockOpId", HA2),
        Step(name="cap12-cleanup-delete-pending", method="DELETE",
             path="/iam/v1/users/{{capPendingUserId}}", auth=HA2,
             test_script=[*assert_status(200), *save_from_response("j.id", "cap12DelUserOpId")]),
        _poll("cap12DelUserOpId", HA2),
        Step(name="cap12-cleanup-delete-sva-off", method="DELETE",
             path="/iam/v1/serviceAccounts/{{capSvaOffId}}", auth=HA2,
             test_script=[*assert_status(200), *save_from_response("j.id", "cap12DelSaOpId")]),
        _poll("cap12DelSaOpId", HA2),
    ],
))

CASES.append(Case(
    id="CAP-13-REVOKE-NON-ADMIN",
    title="Снятие того, кто администратором не является, — 404/5 с текстом; снятие активной выдачи — успех",
    classes=["NEG"], priority="P1",
    steps=[
        _revoke("cap13-revoke-non-admin", M, TARGET, tests=[
            *_pair(404, CODE_NOT_FOUND, "CAP-13"),
            *_message("'User ' + " + _env("ceremonyCapTargetUserId") + " + ' is not an active cluster admin'", "CAP-13"),
        ]),
        _grant("cap13-twin-grant", M, TARGET, tests=_op_ok("CAP-13 близнец: назначение")),
        _revoke("cap13-twin-revoke", M, TARGET, tests=_op_ok("CAP-13 близнец: снятие активной выдачи")),
    ],
))

CASES.append(Case(
    id="CAP-14-NO-SELF-REVOKE",
    title="h-admin/2 не снимает себя — 400/9 `cannot revoke own cluster admin grant`; снимает target — успех",
    classes=["NEG", "STATE"], priority="P0",
    steps=[
        _grant("cap14-grant-target", HA2, TARGET, tests=_op_ok("CAP-14 первый шаг")),
        _revoke("cap14-self", HA2, "{{humanCapAdminUserId}}", tests=[
            *_pair(400, CODE_FAILED_PRECONDITION, "CAP-14"),
            *_message(_q("cannot revoke own cluster admin grant"), "CAP-14"),
        ]),
        _revoke("cap14-twin-revoke-target", HA2, TARGET, tests=_op_ok("CAP-14 близнец")),
        _list("cap14-list", HA2, [
            *_entries_for(_env("ceremonyCapTargetUserId"), "записи target нет", 0),
            *_entries_for(_env("humanCapAdminUserId"), "запись h-admin на месте", 1),
        ]),
    ],
))

CASES.append(Case(
    id="CAP-17-MACHINE-SUBJECT",
    title="Служебная учётка назначается и снимается тем же путём; без рода снятие — 400/3; несуществующая — 400/3",
    classes=["CRUD", "NEG"], priority="P1",
    steps=[
        _grant("cap17-grant-sva", M, SVA_TARGET, subject_type="SERVICE_ACCOUNT",
               tests=_op_ok("CAP-17 назначение")),
        _list("cap17-list-has", M, [
            *_entries_for(_env("ceremonyCapSvaTargetId"), "запись sva-target в перечне", 1),
            "pm.test('род записи — SERVICE_ACCOUNT', () => {",
            f"  const e = pm.response.json().admins.find(a => a.subjectId === {_env('ceremonyCapSvaTargetId')});",
            "  pm.expect(e.subjectType, JSON.stringify(e)).to.eql('SERVICE_ACCOUNT');",
            "});",
        ]),
        _revoke("cap17-revoke-without-kind", M, SVA_TARGET, tests=[
            *_pair(400, CODE_INVALID_ARGUMENT, "CAP-17 без subjectType"),
            *_field_violation("subject_id", "CAP-17 без subjectType"),
        ]),
        _revoke("cap17-revoke-sva", M, SVA_TARGET, query="?subjectType=SERVICE_ACCOUNT",
                tests=_op_ok("CAP-17 снятие")),
        _list("cap17-list-gone", M, _entries_for(_env("ceremonyCapSvaTargetId"), "после снятия записи нет", 0)),
        _grant("cap17-ghost-sva", M, GHOST_SVA, subject_type="SERVICE_ACCOUNT", tests=[
            *_pair(400, CODE_INVALID_ARGUMENT, "CAP-17 несуществующая"),
            *_message(_q(f"ServiceAccount {GHOST_SVA} not found"), "CAP-17 несуществующая"),
        ]),
    ],
))

# ---------------------------------------------------------------------------
# Класс C
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="CAP-20-ONE-WRITE-PATH",
    title="Назначенное публичным путём видно публичным перечнем; повторное назначение после снятия — тот же id",
    classes=["CRUD", "IDM"], priority="P1",
    steps=[
        _grant("cap20-grant", M, TARGET, tests=[
            *_op_ok("CAP-20 назначение"),
            *save_from_response("j.metadata && j.metadata.clusterAdminGrantId", "cap20GrantId"),
        ]),
        _list("cap20-list", M, _entries_for(_env("ceremonyCapTargetUserId"), "запись target видна", 1)),
        _revoke("cap20-revoke", M, TARGET, tests=_op_ok("CAP-20 снятие")),
        _list("cap20-list-gone", M, _entries_for(_env("ceremonyCapTargetUserId"), "после снятия записи нет", 0)),
        _grant("cap20-regrant", M, TARGET, tests=[
            *_op_ok("CAP-20 повторное назначение"),
            "pm.test('тот же clusterAdminGrantId', () => {",
            "  const j = pm.response.json();",
            f"  pm.expect(j.metadata.clusterAdminGrantId, JSON.stringify(j)).to.eql({_env('cap20GrantId')});",
            "});",
        ]),
        _cleanup_target("cap20", auth=M),
    ],
))


def _routing_miss(label):
    """Промах маршрутизатора фронта: 404, JSON, `code = 5`, `message = "Not Found"`."""
    return [
        *assert_status(404),
        f"pm.test({_q(label + ': промах маршрутизатора, а не ответ владельца')}, () => {{",
        "  pm.expect(pm.response.headers.get('Content-Type') || '', 'Content-Type').to.include('application/json');",
        "  const j = pm.response.json();",
        "  pm.expect(j.code, JSON.stringify(j)).to.eql(5);",
        "  pm.expect(j.message, JSON.stringify(j)).to.eql('Not Found');",
        "});",
    ]


CASES.append(Case(
    id="CAP-21-FRONT-SEPARATION",
    title="Внутренний путь на публичном фронте и публичный на внутреннем — промах маршрутизатора; на своих фронтах — обслужены",
    classes=["SEC", "NEG"], priority="P0",
    steps=[
        Step(name="cap21-internal-path-on-public", method="GET",
             path="/iam/v1/internal/cluster/admins", auth=M,
             test_script=_routing_miss("CAP-21 внутренний путь на публичном фронте")),
        Step(name="cap21-public-path-on-internal", method="GET", path=ADMINS, auth=M,
             pre_script=require_env_url("ownInternalRestBaseUrl", ADMINS, _INTERNAL_WHY),
             test_script=_routing_miss("CAP-21 публичный путь на внутреннем фронте")),
        _list("cap21-twin-public-on-public", M),
        Step(name="cap21-twin-internal-on-internal", method="GET",
             path="/iam/v1/internal/cluster/admins", auth=M,
             pre_script=require_env_url("ownInternalRestBaseUrl", "/iam/v1/internal/cluster/admins",
                                        _INTERNAL_WHY),
             test_script=[
                 # Внутренний путь на СВОЁМ фронте обслужен владельцем: ответ не
                 # промах маршрутизатора. Исход владельца на автономном стенде —
                 # отказ круга вызывающих (глагол фронтируется краем), см. шапку.
                 "pm.test('CAP-21 близнец: внутренний путь на внутреннем фронте обслужен, не промах маршрутизатора', () => {",
                 "  let j; try { j = pm.response.json(); } catch (e) { j = {}; }",
                 "  pm.expect(pm.response.code === 404 && j.message === 'Not Found', pm.response.text()).to.eql(false);",
                 "});",
             ]),
    ],
))


# Все шаги, кроме адресованных кейсом (внутренний фронт CAP-21), — на
# собственный публичный фронт службы (e2e-flow.md §7а).
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы — поверхность "
                                 "публичного близнеца ClusterService")
