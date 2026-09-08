# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set для read-authz v_get (iam) — black-box через api-gateway.

Проверяет фикс «granted-non-owner GET account → 404»: ресурс-чтение
(Account/Project/User/Group/ServiceAccount .Get) на flat-модели
авторизуется verb-bearing relation `v_get` на объекте ресурса, а НЕ legacy
owner-only software-gate (authzguard.IsSelf). До фикса use-case переспрашивал
свой owner-only gate и оверрайдил ALLOW gateway-а → invitee, которому явно
выдали `iam.account.get`, получал 404 на GET account.

Контракт (hide-existence на read-deny):
  ALLOW  cluster-admin (short-circuit, любой объект)
    OR   subject держит v_get на объекте ресурса (owner-binding ИЛИ явный грант)
  иначе  read-deny → NotFound (404, code 5), БЕЗ deny_reasons — hide existence.

  gateway-Check режет read-RPC до iam и раньше возвращал 403
  PERMISSION_DENIED с verbose deny_reasons. iam read_authz.go отдает NotFound, но
  до него запрос не доходил. Теперь gateway маппит read-deny verb-bearing IAM Get
  → NotFound (как уже делал RoleService.Get). Несуществующий и existing-denied id
  → ОДИНАКОВЫЙ 404 (no enumeration leak). Мутации (Create/Update/Delete) остаются
  403/правильный код.

Happy (IAM-RDAUTHZ-ACC-GT-GRANTED-NONOWNER-OK):
  accountAdminA выдает invitee роль ROLE_VIEW (`*.* read/list/get` → v_get) на
  account:accountAId. invitee — НЕ owner accountA. После grant→FGA propagation
  GET /iam/v1/accounts/{accountAId} как jwtHumanCeremony → 200 (был 404).

Negative (IAM-RDAUTHZ-ACC-GT-NONGRANTED-DENY):
  jwtPureNoBindings (никакого v_get на accountA) GET accountA → 404 NOT_FOUND (code 5,
  hide existence, без deny_reasons). Single-shot — поллить нельзя, иначе маскирует
  утечку.

No-leak (IAM-RDAUTHZ-ACC-GT-NONEXISTENT-EQ-DENIED):
  GET well-formed-но-несуществующего account id как jwtPureNoBindings → тот же 404
  code 5, что и existing-denied → existing-denied неотличим от nonexistent.

Fixture (crud-fixture/setup.sh):
  jwtAccountAdminA — owner+grant-authority на accountAId.
  accountAId       — scope гранта (ACCOUNT tier), owned by accountAdminA.
  jwtHumanCeremony / ceremonyUserId — НЕ-owner subject, которому выдается v_get.
  jwtPureNoBindings — выделенный НИКОГДА-не-гранченый subject (negative). jwtNoBindings
                     им не является: сюиты грантят userNOBId view на оба аккаунта.

Test-first (strict TDD): кейс написан RED-first против
owner-only use-case-gate — был красным (404), зеленый после v_get-фикса.
Детерминированный двойник — internal/apps/kaname/api/readauthz/
get_vget_fga_integration_test.go (real-OpenFGA).
"""

CASES = []

# ROLE_VIEW — system viewer bundle (`*.* read/list/get`), assignable на любой
# scope; bind на account:<id> материализует v_get на account:<id> для subject.
ROLE_VIEW = "rol1bda80f2be4d3658e"  # md5('view')[:17]


def _revoke_teardown(name, acb_var):
    """RELIABLE revoke — общий помощник gen.py.

    Прежняя редакция принимала 403 («отказано в правах») как успешную уборку и
    ехала дальше. Отзыв при этом НЕ происходил: грант оставался ACTIVE в ОБЩЕМ
    аккаунте после конца прогона, и следующий прогон видел субъекта, у которого
    «нет ни одной выдачи», но которому тем не менее разрешено. Реализация была
    исправлена в соседнем файле (iam-rbac-subjects), а здесь класс остался жив —
    ровно потому, что помощник скопирован, а не общий. Теперь он один.
    """
    return reliable_delete(name, "/iam/v1/accessBindings/{{" + acb_var + "}}")


# ---------------------------------------------------------------------------
# IAM-RDAUTHZ-ACC-GT-GRANTED-NONOWNER-OK — happy: granted-non-owner reads account
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-RDAUTHZ-ACC-GT-GRANTED-NONOWNER-OK",
    title="GET account as a non-owner granted iam.account.get (v_get) → 200 (was 404)",
    classes=["AUTHZ", "CRUD"],
    priority="P0",
    steps=[
        # Pre-clean любой прежний active (ceremonyUserId, ROLE_VIEW, account/accountAId)
        # binding, чтобы strict-create всегда поднял свежий (DB persists между прогонами).
        Step(
            name="pre-clean-list",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                # РАЗВЕДКА ИДЁТ АВТОРИЗОВАННЫМ ЧТЕНИЕМ, И ИСХОД У НЕГО ОДИН — 200.
                #
                # Прежде здесь стоял `:listBySubject` для ЧУЖОГО субъекта. Это не
                # «известный продуктовый предел», как утверждал прежний текст, и не
                # kacho-iam#276 (тот про другое — про материализацию дочерних туплов у
                # не-владельца с глобальной ролью просмотра). Это был ОБЪЯВЛЕННЫЙ контракт
                # метода: строгий список только про себя, административного обхода нет.
                # Значит для админа исход был ровно один — отказ, — предочистка не
                # выполнялась НИКОГДА, а утверждение `oneOf([200, 403])` это скрывало,
                # принимая и недостижимый успех.
                #
                # Контракт с тех пор изменён (#1352): чтение допускает и распорядителя
                # домашнего аккаунта субъекта, сужая ответ границами этого аккаунта.
                # Замена ниже от этого не устарела — предочистке нужны ВСЕ субъекты
                # области, а на этот вопрос отвечает перечисление по области.
                #
                # Рабочая замена уже была в дереве, в соседнем наборе: перечисление по
                # ОБЛАСТИ аккаунта (владелец аккаунта видит выдачи ВСЕХ субъектов), а
                # нужный субъект выбирается фильтром. Его шапка прямо говорит, что
                # `listBySubject` «корректно отдаёт 403 и давал ЛОЖНУЮ чистоту слота».
                # Здесь та же замена — и предочистка наконец работает.
                *assert_status(200),
                "pm.environment.unset('rdAuthzDupAcbId');",
                "const arr = (pm.response.json() || {}).accessBindings || [];",
                f"const dup = arr.find(b => b.subjectId === pm.environment.get('ceremonyUserId')",
                f"       && b.roleId === '{ROLE_VIEW}' && b.scopeType === 'iam.account'",
                "       && b.scopeId === pm.environment.get('accountAId'));",
                "if (dup && dup.id) pm.environment.set('rdAuthzDupAcbId', dup.id);",
                "if (!pm.environment.get('rdAuthzDupAcbId')) { pm.execution.setNextRequest('grant-view'); }",
            ],
        ),
        poll_request_until_status(
            retry_on=(403,),
            
            name="del-dup",
            method="DELETE",
            path="/iam/v1/accessBindings/{{rdAuthzDupAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean: слот освобождён (200) или его и не было (404) — устойчивый 403 значит, что прежняя выдача ОСТАЛАСЬ активной и strict-create упрётся в UNIQUE', () => pm.expect(pm.response.code, JSON.stringify(pm.response.json() || {})).to.be.oneOf([200, 404]));",
                # Delete async — дождаться revoked_at до strict-create, иначе race с
                # active-grant partial UNIQUE → AlreadyExists.
                "pm.environment.unset('rdAuthzDelOpId');",
                "if (pm.response.code === 200) {",
                "  const dj = pm.response.json() || {};",
                "  if (dj.id) pm.environment.set('rdAuthzDelOpId', dj.id);",
                "}",
                "if (!pm.environment.get('rdAuthzDelOpId')) { pm.execution.setNextRequest('grant-view'); }",
            ],
        ),
        Step(
            name="await-del-dup",
            method="GET",
            path="/operations/{{rdAuthzDelOpId}}",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (pm.environment.get('_rdAuthzDelStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_rdAuthzDelCount', '0');",
                "  pm.environment.set('_rdAuthzDelStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "pm.test('await-del-dup 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_rdAuthzDelCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_rdAuthzDelCount', String(pc + 1));",
                "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_rdAuthzDelCount');",
                "pm.environment.unset('_rdAuthzDelStarted');",
                "pm.test('dup-revoke done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
        # Grant: bind ROLE_VIEW(invitee) на account:accountAId. accountAdminA держит
        # grant-authority (owner). Материализует v_get на account:accountAId для invitee.
        Step(
            name="grant-view",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                # Wire form of the enum, not the console's internal lowercase label:
                # the edge refuses an enum value outside the dictionary, and this is a
                # PRECONDITION step — a 400 here would fail the case for a reason that
                # has nothing to do with what it asserts.
                "subjects": [{"type": "SUBJECT_TYPE_USER", "id": "{{ceremonyUserId}}"}],
                "roleId": ROLE_VIEW,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                "pm.test('IAM Operation envelope', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "rdAuthzAcbId"),
            ],
        ),
        poll_operation_until_done(),
        Step(
            name="grant-op-success",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('grant Operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                # Свежий grant: либо без error, либо AlreadyExists (6), если ПАРАЛЛЕЛЬНАЯ
                # суита выдала тот же 5-tuple между предочисткой и этим созданием.
                # (Прежняя причина — «предочистка не смогла снести, listBySubject 403 для
                # чужого субъекта» — больше не действует: разведка идёт авторизованным
                # перечислением по области аккаунта и реально сносит остаток.)
                # ОБА доказывают, что v_get-грант существует → GET ниже даст 200. Жесткий
                # fail — реальная ошибка гранта (НЕ 6).
                "pm.test('grant materialized (done w/o hard error)', () => {",
                "  const code = j.error && j.error.code;",
                "  pm.expect([undefined, null, 0, 6], 'grant must not hard-fail: ' + JSON.stringify(j.error)).to.include(code);",
                "});",
            ],
        ),
        # THE ASSERTION: granted-non-owner reads the account. v_get propagation —
        # poll 403→200 (grant→FGA gate visibility window). Терминальный 200 = фикс.
        poll_request_until_status(
            name="get-account-as-granted-invitee",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtHumanCeremony",
            expect_code=200,
            retry_on=(403, 404),
            test_script=[
                "const j = pm.response.json();",
                "pm.test('GRANTED-NONOWNER: GET account 200 (was 404 owner-only gate)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                "pm.test('account id matches scope', () => pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('accountAId')));",
                "pm.test('owner is NOT the granted invitee (true non-owner read)', () => pm.expect(j.ownerUserId).to.not.eql(pm.environment.get('ceremonyUserId')));",
            ],
        ),
        *_revoke_teardown("teardown-grant", "rdAuthzAcbId"),
    ],
))


# ---------------------------------------------------------------------------
# IAM-RDAUTHZ-ACC-GT-NONGRANTED-DENY — negative: no v_get → 404 hide-existence
# (BUG-2: was 403 PERMISSION_DENIED + verbose deny_reasons leak).
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="IAM-RDAUTHZ-ACC-GT-NONGRANTED-DENY",
    title="GET account as jwtPureNoBindings (no v_get grant) → 404 NOT_FOUND (hide existence)",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        # Single-shot — must-DENY никогда не поллим (поллинг замаскировал бы leak).
        Step(
            name="get-account-non-granted",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtPureNoBindings",
            test_script=[
                "pm.test('NON-GRANTED: status 404 (hide existence, was 403)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NON-GRANTED: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
                # No enumeration leak: body must not carry deny_reasons / authz details.
                "pm.test('NON-GRANTED: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {}).toLowerCase()).to.not.include('deny_reasons'));",
                "pm.test('NON-GRANTED: no authz violation details leak', () => pm.expect(JSON.stringify(j || {}).toLowerCase()).to.not.include('preconditionfailure'));",
                # Stash for the indistinguishability comparison below.
                "pm.environment.set('rdAuthzDeniedCode', String((j && j.code) !== undefined ? j.code : ''));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# IAM-RDAUTHZ-ACC-GT-NONEXISTENT-EQ-DENIED — no-leak: a well-formed-but-nonexistent
# account id returns the SAME 404/code-5 as an existing-but-denied id → an attacker
# cannot tell "exists but forbidden" from "does not exist" (no enumeration leak).
# ---------------------------------------------------------------------------
# Well-formed account id (prefix `acc` + 17-char crockford-base32) that is not seeded.
_NONEXISTENT_ACCOUNT_ID = "acc00000000bug2miss"
CASES.append(Case(
    id="IAM-RDAUTHZ-ACC-GT-NONEXISTENT-EQ-DENIED",
    title="GET well-formed nonexistent account → same 404/code-5 as existing-denied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="get-account-nonexistent",
            method="GET",
            path="/iam/v1/accounts/" + _NONEXISTENT_ACCOUNT_ID,
            auth="jwtPureNoBindings",
            test_script=[
                "pm.test('NONEXISTENT: status 404', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
                "pm.test('NONEXISTENT: grpc code 5 (NOT_FOUND)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
                # Indistinguishable from existing-but-denied (set by the case above).
                "pm.test('NONEXISTENT == existing-denied (no enumeration leak)', () => pm.expect(String(j && j.code)).to.eql('5'));",
            ],
        ),
    ],
))
