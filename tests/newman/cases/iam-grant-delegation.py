# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: делегирование права выдавать на собственном фронте службы (GD-E1…GD-E5).

ПРЕДМЕТ. Приёмка `docs/engineering/acceptance/delegated-grants-stay-within-the-delegation.md`
(редакция 3, отпечаток 7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6;
задача PRO-Robotech/kaname#986, полоса красных проб PRO-Robotech/kaname#1009), S2:
GD-E1…GD-E5. Интеграционные пробы GD-01…GD-70 —
`internal/apps/kaname/api/access_binding/grant_delegation_*_integration_test.go`;
здесь — то, что видит потребитель края: пара «HTTP-статус, `code` тела».

ПОСЕВ НАБОРА (§S2 приёмки) — ДЕЛО ПРОИЗВОДИТЕЛЯ ПОСЕВА, А НЕ КЕЙСА. Кейс сам
заводит то, что заводится краем: учётки-субъекты выдач, делегирование, выдачи.
Трёх условий край не создаёт by construction:

  * объект типа registry, зарегистрированный в проекте аккаунта A, —
    регистрирует его только модуль-владелец по внутреннему ребру
    `InternalIAMService.RegisterResource` (ban #6, REST у него нет);
  * роли модуля registry (`registry.puller`, `registry.pusher`, `registry.admin`) —
    их доставляет манифест svc-registry (§7 приёмки, SRI-92 потребителя), путь
    старта службы, а не глагол края;
  * учётка-делегат в ОТДЕЛЬНОМ аккаунте и её предъявитель — слот посева, а не
    учётка, заведённая кейсом: ключ и обмен — полоса посева.

Их имена — переменные окружения `gdRegistryId`, `gdRegistryProjectId`,
`gdRegistryRolesDelivered`, `gdDelegateSaId`, `jwtGDDelegate`. Пустая переменная —
отказ с меткой «условие не создано» и именем переменной (`precondition_not_met`),
а не красный: вердикт о продукте без созданного условия невозможен.

Идентификатор роли модуля — выведенный (`'rol' || substr(md5(имя), 1, 17)`, та же
формула, что у посева ролей), поэтому вычисляется в скрипте, а не переписывается.

ЧТО УТВЕРЖДАЕТСЯ. E1 — делегирование заводится, читается полем за полем и
отзывается. E2 — близнец E1 (вызывающий — делегат): 403/7. E3 — делегат выдаёт
по делегированию, выдача несёт `delegationId`. E4 — близнец E3 (роль вне
делегирования): 403/7. E5 — отзыв и удаление делегатом проходят слушатель
(держатель GD-30, GD-41 a): своя выдача против чужой, защита от удаления,
правка за дверью.

Дисциплина (testing.md): каждый кейс сеет своё и за собой убирает (уборка
best-effort, отказ теардауна — не дефект предмета); имена — через {{runId}}.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а).
HOME = "kaname"

CASES = []

OWNER = "jwtAccountAdminA"
OWNER_STEP_UP = "jwtAccountAdminAStepUp"
DELEGATE = "jwtGDDelegate"

_SEED_VARS = [
    ("gdRegistryId", "реестр (registry.registries), зарегистрированный модулем в проекте аккаунта A"),
    ("gdRegistryProjectId", "проект аккаунта A, в котором зарегистрирован реестр"),
    ("gdRegistryRolesDelivered", "манифест registry с ролями puller/pusher/admin доставлен службе"),
    ("gdDelegateSaId", "учётка-делегат в отдельном аккаунте"),
    (DELEGATE, "предъявитель учётки-делегата"),
]


def _seeded():
    """Pre-request первого шага кейса: условия посева созданы; id ролей модуля."""
    missing = " || ".join(f"!pm.environment.get({js_str(v)})" for v, _ in _SEED_VARS)
    names = ", ".join(v for v, _ in _SEED_VARS)
    lines = [
        "// Идентификаторы ролей модуля registry — выведенные (формула посева ролей).",
        "['puller', 'pusher', 'admin'].forEach((r) => pm.environment.set(",
        "  'gdRole' + r.charAt(0).toUpperCase() + r.slice(1) + 'Id',",
        "  'rol' + CryptoJS.MD5('registry.' + r).toString().substring(0, 17)));",
        f"if ({missing}) {{",
        *precondition_not_met(
            "посев набора делегирования создан (§S2 приёмки)",
            f"не задана одна из переменных {names}: реестр, роли модуля registry и учётку-делегата "
            "заводит производитель посева, а не край — кейс не исполняется",
            indent="  "),
        "}",
    ]
    return lines


def _d1_body():
    return {
        "accountId": "{{accountAId}}",
        "delegate": {"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{gdDelegateSaId}}"},
        "roleIds": ["{{gdRolePullerId}}", "{{gdRolePusherId}}", "{{gdRoleAdminId}}"],
        "targetTypes": ["registry.registries", "registry.repositories"],
        "subjectTypes": ["SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS"],
    }


def _create_d1(prefix, var, first=True):
    """Заведение D1 владельцем до `done` без ошибки; id — в `var`."""
    return [
        Step(name=f"{prefix}-create-delegation", method="POST", path="/iam/v1/grantDelegations",
             body=_d1_body(), auth=OWNER_STEP_UP,
             pre_script=_seeded() if first else [],
             test_script=[*assert_status(200),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.grantDelegationId", var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _revoke_delegation(prefix, var, required=True):
    test = [*save_from_response("j.id", "opId")]
    if required:
        test = [*assert_status(200), *test]
    return [
        Step(name=f"{prefix}-revoke-delegation", method="POST",
             path="/iam/v1/grantDelegations/{{" + var + "}}:revoke", body={}, auth=OWNER_STEP_UP,
             test_script=test),
        poll_operation_until_done(required=required),
    ]


def _subject_sa(prefix, var):
    """Учётка-субъект выдачи в аккаунте A, заведённая кейсом."""
    return [
        Step(name=f"{prefix}-subject", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": prefix + "-{{runId}}", "description": "GD-E: субъект выдачи"},
             auth=OWNER,
             test_script=[*assert_status(200),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _cleanup_sa(prefix, var):
    return [
        Step(name=f"{prefix}-cleanup-subject", method="DELETE",
             path="/iam/v1/serviceAccounts/{{" + var + "}}", auth=OWNER,
             test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(required=False),
    ]


def _v_body(subject_var, role_var="gdRolePusherId", protection=False):
    """Тело выдачи V (§4.1): область — проект реестра, роль pusher, цель — реестр."""
    body = {
        "subjects": [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{" + subject_var + "}}"}],
        "roleId": "{{" + role_var + "}}",
        "scopeType": "iam.project",
        "scopeId": "{{gdRegistryProjectId}}",
        "target": {"resources": {"resources": [{"type": "registry.registries", "id": "{{gdRegistryId}}"}]}},
    }
    if protection:
        body["deletionProtection"] = True
    return body


def _grant(prefix, subject_var, out_var, auth=DELEGATE, protection=False, role_var="gdRolePusherId"):
    return [
        Step(name=f"{prefix}-grant", method="POST", path="/iam/v1/accessBindings",
             body=_v_body(subject_var, role_var, protection), auth=auth,
             test_script=[*assert_status(200),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", out_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _denied(case):
    return [
        *assert_status(403),
        *assert_grpc_code(7, "PERMISSION_DENIED"),
        *assert_refusal_message("permission denied", f"{case}: текст отказа — permission denied"),
    ]


# ===========================================================================
# GD-E1 — делегирование заводится и отзывается через край
# ===========================================================================

CASES.append(Case(
    id="IAM-GD-E1-DELEGATION-CREATE-GET-REVOKE-OK",
    title="GD-E1: владелец заводит делегирование, читает его полем за полем и отзывает — 200 на каждом шаге",
    classes=["CRUD", "CONF"],
    priority="P1",
    steps=[
        *_create_d1("gde1", "gdE1Id"),
        retry_until_present(Step(
            name="gde1-get", method="GET", path="/iam/v1/grantDelegations/{{gdE1Id}}", auth=OWNER,
            test_script=[
                *assert_status(200),
                "const j = pm.response.json();",
                "const sorted = (a) => JSON.stringify(a) === JSON.stringify([...a].sort());",
                "pm.test('GD-E1: id gdl…', () => pm.expect(j.id, pm.response.text()).to.eql(pm.environment.get('gdE1Id')));",
                "pm.test('GD-E1: accountId', () => pm.expect(j.accountId).to.eql(pm.environment.get('accountAId')));",
                "pm.test('GD-E1: delegate', () => pm.expect(j.delegate).to.eql("
                "{type: 'SUBJECT_TYPE_SERVICE_ACCOUNT', id: pm.environment.get('gdDelegateSaId')}));",
                "pm.test('GD-E1: roleIds — три роли по возрастанию', () => {",
                "  pm.expect([...j.roleIds].sort()).to.eql([pm.environment.get('gdRolePullerId'),",
                "    pm.environment.get('gdRolePusherId'), pm.environment.get('gdRoleAdminId')].sort());",
                "  pm.expect(sorted(j.roleIds), JSON.stringify(j.roleIds)).to.eql(true);",
                "});",
                "pm.test('GD-E1: targetTypes', () => pm.expect(j.targetTypes).to.eql(['registry.registries', 'registry.repositories']));",
                "pm.test('GD-E1: subjectTypes', () => pm.expect(j.subjectTypes).to.eql("
                "['SUBJECT_TYPE_SERVICE_ACCOUNT', 'SUBJECT_TYPE_SYSTEM_CLASS']));",
                "pm.test('GD-E1: module', () => pm.expect(j.module).to.eql('registry'));",
                "pm.test('GD-E1: status ACTIVE', () => pm.expect(j.status).to.eql('ACTIVE'));",
                "pm.test('GD-E1: createdAt усечён до секунды', () => pm.expect(j.createdAt).to.match(/T\\d{2}:\\d{2}:\\d{2}Z$/));",
            ],
        ), "gdE1Id"),
        *_revoke_delegation("gde1", "gdE1Id"),
        Step(name="gde1-get-revoked", method="GET", path="/iam/v1/grantDelegations/{{gdE1Id}}", auth=OWNER,
             test_script=[
                 *assert_status(200),
                 "pm.test('GD-E1: после отзыва status REVOKED', () =>",
                 "  pm.expect(pm.response.json().status, pm.response.text()).to.eql('REVOKED'));",
             ]),
    ],
))


# ===========================================================================
# GD-E2 — близнец E1: делегат не заводит делегирований
# ===========================================================================

CASES.append(Case(
    id="IAM-GD-E2-DELEGATE-CANNOT-DELEGATE-DENIED",
    title="GD-E2 (близнец E1, вызывающий — делегат): тот же запрос заведения — 403, code 7, permission denied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        Step(name="gde2-create-as-delegate", method="POST", path="/iam/v1/grantDelegations",
             body=_d1_body(), auth=DELEGATE, pre_script=_seeded(),
             test_script=_denied("GD-E2")),
    ],
))


# ===========================================================================
# GD-E3 — выдача делегатом через край
# ===========================================================================

CASES.append(Case(
    id="IAM-GD-E3-DELEGATE-GRANT-CARRIES-DELEGATION-OK",
    title="GD-E3: делегат выдаёт pusher на реестр учётке аккаунта — 200, операция без ошибки, выдача несёт delegationId",
    classes=["CRUD", "CONF"],
    priority="P1",
    steps=[
        *_create_d1("gde3", "gdE3Id"),
        *_subject_sa("gde3s", "gdE3Sa"),
        *_grant("gde3", "gdE3Sa", "gdE3Acb"),
        retry_until_present(Step(
            name="gde3-get-binding", method="GET", path="/iam/v1/accessBindings/{{gdE3Acb}}", auth=OWNER,
            test_script=[
                *assert_status(200),
                "pm.test('GD-E3: delegationId — делегирование E3', () =>",
                "  pm.expect(pm.response.json().delegationId, pm.response.text()).to.eql(pm.environment.get('gdE3Id')));",
                "pm.test('GD-E3: status ACTIVE', () => pm.expect(pm.response.json().status).to.eql('ACTIVE'));",
            ],
        ), "gdE3Acb"),
        *_revoke_delegation("gde3-cleanup", "gdE3Id", required=False),
        *_cleanup_sa("gde3s", "gdE3Sa"),
    ],
))


# ===========================================================================
# GD-E4 — близнец E3: роль вне делегирования
# ===========================================================================

CASES.append(Case(
    id="IAM-GD-E4-DELEGATE-ROLE-OUTSIDE-DENIED",
    title="GD-E4 (близнец E3, роль вне делегирования): каноническая admin на аккаунт — 403, code 7, permission denied",
    classes=["AUTHZ", "NEG"],
    priority="P1",
    steps=[
        *_create_d1("gde4", "gdE4Id"),
        *_subject_sa("gde4s", "gdE4Sa"),
        Step(name="gde4-grant-admin", method="POST", path="/iam/v1/accessBindings",
             body={
                 "subjects": [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{gdE4Sa}}"}],
                 "roleId": "rol21232f297a57a5a74",
                 "scopeType": "iam.account",
                 "scopeId": "{{accountAId}}",
                 "target": {"resources": {"resources": [{"type": "registry.registries", "id": "{{gdRegistryId}}"}]}},
             },
             auth=DELEGATE, test_script=_denied("GD-E4")),
        *_revoke_delegation("gde4-cleanup", "gdE4Id", required=False),
        *_cleanup_sa("gde4s", "gdE4Sa"),
    ],
))


# ===========================================================================
# GD-E5 — отзыв и удаление делегатом проходят слушатель
# ===========================================================================

CASES.append(Case(
    id="IAM-GD-E5-DELEGATE-REVOKE-DELETE-PASS-THE-LISTENER",
    title="GD-E5: делегат отзывает и удаляет своё (200), чужое — 403/7, защищённое — 400/9, правка — за дверью 403/7",
    classes=["AUTHZ", "STATE", "NEG"],
    priority="P1",
    steps=[
        *_create_d1("gde5", "gdE5Id"),
        *_subject_sa("gde5s1", "gdE5Sa1"),
        *_subject_sa("gde5s2", "gdE5Sa2"),
        *_subject_sa("gde5s3", "gdE5Sa3"),
        *_subject_sa("gde5s4", "gdE5Sa4"),
        *_grant("gde5-bd", "gdE5Sa1", "gdE5Bd"),
        *_grant("gde5-bd2", "gdE5Sa2", "gdE5Bd2"),
        *_grant("gde5-bp", "gdE5Sa3", "gdE5Bp", protection=True),
        *_grant("gde5-bo", "gdE5Sa4", "gdE5Bo", auth=OWNER_STEP_UP, role_var="gdRolePullerId"),
        # a — своя выдача: отзыв.
        Step(name="gde5-a-revoke-own", method="POST", path="/iam/v1/accessBindings/{{gdE5Bd}}:revoke",
             body={}, auth=DELEGATE,
             test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        assert_op_success(),
        Step(name="gde5-a-get", method="GET", path="/iam/v1/accessBindings/{{gdE5Bd}}", auth=OWNER,
             test_script=[*assert_status(200),
                          "pm.test('GD-E5 a: status REVOKED', () =>",
                          "  pm.expect(pm.response.json().status, pm.response.text()).to.eql('REVOKED'));"]),
        # b — чужая выдача (владельца, без делегирования).
        Step(name="gde5-b-revoke-foreign", method="POST", path="/iam/v1/accessBindings/{{gdE5Bo}}:revoke",
             body={}, auth=DELEGATE, test_script=_denied("GD-E5 b")),
        # c — своя выдача: удаление.
        Step(name="gde5-c-delete-own", method="DELETE", path="/iam/v1/accessBindings/{{gdE5Bd2}}",
             auth=DELEGATE, test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
        poll_operation_until_done(),
        assert_op_success(),
        # d — защищённая выдача: отзыв доходит до обработчика и упирается в защиту.
        Step(name="gde5-d-revoke-protected", method="POST", path="/iam/v1/accessBindings/{{gdE5Bp}}:revoke",
             body={}, auth=DELEGATE,
             test_script=[*assert_status(400), *assert_grpc_code(9, "FAILED_PRECONDITION"),
                          *assert_refusal_message(
                              "access binding {{gdE5Bp}} has deletion_protection enabled; clear it via Update before revoke",
                              "GD-E5 d: текст защиты от удаления")]),
        # e — тот же объект, другой глагол: правка остаётся за дверью (v_update).
        Step(name="gde5-e-update-protected", method="PATCH", path="/iam/v1/accessBindings/{{gdE5Bp}}",
             body={"updateMask": "deletionProtection", "deletionProtection": False}, auth=DELEGATE,
             test_script=_denied("GD-E5 e")),
        Step(name="gde5-e-get", method="GET", path="/iam/v1/accessBindings/{{gdE5Bp}}", auth=OWNER,
             test_script=[*assert_status(200),
                          "pm.test('GD-E5 e: deletionProtection осталась', () =>",
                          "  pm.expect(pm.response.json().deletionProtection, pm.response.text()).to.eql(true));",
                          "pm.test('GD-E5 e: status ACTIVE', () => pm.expect(pm.response.json().status).to.eql('ACTIVE'));"]),
        # Уборка: отзыв делегирования снимает выданное по нему, Bo — владельцем.
        Step(name="gde5-cleanup-bo", method="DELETE", path="/iam/v1/accessBindings/{{gdE5Bo}}",
             auth=OWNER_STEP_UP, test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(required=False),
        *_revoke_delegation("gde5-cleanup", "gdE5Id", required=False),
        *_cleanup_sa("gde5s1", "gdE5Sa1"),
        *_cleanup_sa("gde5s2", "gdE5Sa2"),
        *_cleanup_sa("gde5s3", "gdE5Sa3"),
        *_cleanup_sa("gde5s4", "gdE5Sa4"),
    ],
))


# kaname#1011: отдельное обычное делегирование допускает GROUP. Исходные оси D1 и
# GD-E1..E5 не меняются. Оба двойника используют одинаковые роль/цель/область и вызывающего;
# различается только состав группы. Делегат принадлежит A, поскольку
# публичный контракт AddMember требует одного аккаунта у участника и группы.
def _group_self_grant_twin(contains_delegate):
    prefix = "gdgroupdeny" if contains_delegate else "gdgroupallow"
    delegation_var, group_var, binding_var = prefix + "Delegation", prefix + "Group", prefix + "Binding"
    member = {"memberType": "service_account", "memberId": "{{gdGroupDelegateSaId}}"}
    first = [*_seeded(),
             "if (!pm.environment.get('gdGroupDelegateSaId') || !pm.environment.get('jwtGDGroupDelegate')) {",
             *precondition_not_met("group delegation fixture", "normal group-test delegate and credential missing", indent="  "),
             "}"]
    steps = [
        Step(name=prefix + "-create-delegation", method="POST", path="/iam/v1/grantDelegations",
             body={"accountId": "{{accountAId}}",
                   "delegate": {"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{gdGroupDelegateSaId}}"},
                   "roleIds": ["{{gdRolePusherId}}"], "targetTypes": ["registry.registries"],
                   "subjectTypes": ["SUBJECT_TYPE_GROUP"]}, auth=OWNER_STEP_UP, pre_script=first,
             test_script=[*assert_status(200), *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.grantDelegationId", delegation_var)]),
        poll_operation_until_done(), assert_op_success(),
        Step(name=prefix + "-create-group", method="POST", path="/iam/v1/groups",
             body={"accountId": "{{accountAId}}", "name": prefix + "-{{runId}}",
                   "description": "Independent delegation membership twin"}, auth=OWNER,
             test_script=[*assert_status(200), *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.groupId", group_var)]),
        poll_operation_until_done(), assert_op_success(),
    ]
    if contains_delegate:
        steps += [Step(name=prefix + "-add-delegate", method="POST",
                       path="/iam/v1/groups/{{" + group_var + "}}:addMember", body=member, auth=OWNER_STEP_UP,
                       test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
                  poll_operation_until_done(), assert_op_success()]
    expected_members = ("[{memberType:'service_account',memberId:pm.environment.get('gdGroupDelegateSaId')}]"
                        if contains_delegate else "[]")
    steps += [Step(name=prefix + "-verify-membership", method="GET",
                   path="/iam/v1/groups/{{" + group_var + "}}:listMembers?pageSize=1000", auth=OWNER,
                   test_script=[*assert_status(200),
                                "pm.test('membership Given is complete', () => { const j=pm.response.json();",
                                "  pm.expect(j.nextPageToken || '').to.eql('');",
                                "  pm.expect((j.members || []).map(m=>({memberType:m.memberType,memberId:m.memberId}))).to.eql(" + expected_members + "); });"])]
    grant_body = _v_body(group_var)
    grant_body["subjects"][0]["type"] = "SUBJECT_TYPE_GROUP"
    if contains_delegate:
        steps += [Step(name=prefix + "-grant-group", method="POST", path="/iam/v1/accessBindings",
                       body=grant_body, auth="jwtGDGroupDelegate",
                       test_script=[*_denied("kaname#1011 group contains delegate"),
                                    "pm.test('synchronous refusal is not an operation', () => pm.expect(pm.response.json()).not.to.have.property('id'));"])]
    else:
        steps += [Step(name=prefix + "-grant-group", method="POST", path="/iam/v1/accessBindings",
                       body=grant_body, auth="jwtGDGroupDelegate",
                       test_script=[*assert_status(200), *save_from_response("j.id", "opId"),
                                    *save_from_response("j.metadata && j.metadata.accessBindingId", binding_var)]),
                  poll_operation_until_done(), assert_op_success(),
                  Step(name=prefix + "-verify-delegated-binding", method="GET",
                       path="/iam/v1/accessBindings/{{" + binding_var + "}}", auth=OWNER,
                       test_script=[*assert_status(200),
                                    "pm.test('group grant used the intended delegation', () => { const j=pm.response.json();",
                                    "  pm.expect(j.delegationId).to.eql(pm.environment.get('" + delegation_var + "'));",
                                    "  pm.expect(j.status).to.eql('ACTIVE');",
                                    "  pm.expect(j.subjects).to.eql([{type:'SUBJECT_TYPE_GROUP',id:pm.environment.get('" + group_var + "')}]); });"])]
    steps += [*_revoke_delegation(prefix + "-cleanup", delegation_var), assert_op_success()]
    if not contains_delegate:
        steps += [Step(name=prefix + "-cleanup-binding", method="DELETE",
                       path="/iam/v1/accessBindings/{{" + binding_var + "}}", auth=OWNER_STEP_UP,
                       test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
                  poll_operation_until_done(), assert_op_success()]
    if contains_delegate:
        steps += [Step(name=prefix + "-remove-delegate", method="POST",
                       path="/iam/v1/groups/{{" + group_var + "}}:removeMember", body=member, auth=OWNER_STEP_UP,
                       test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
                  poll_operation_until_done(), assert_op_success()]
    steps += [Step(name=prefix + "-cleanup-group", method="DELETE", path="/iam/v1/groups/{{" + group_var + "}}",
                   auth=OWNER_STEP_UP, test_script=[*assert_status(200), *save_from_response("j.id", "opId")]),
              poll_operation_until_done(), assert_op_success()]
    return Case(id=("IAM-GD-1011-GROUP-CONTAINS-DELEGATE-DENIED" if contains_delegate
                    else "IAM-GD-1011-GROUP-WITHOUT-DELEGATE-ALLOWED"),
                title=("kaname#1011: группа содержит делегата — 403/7 до операции" if contains_delegate
                       else "kaname#1011: та же групповая ось без делегата — успешная операция с delegationId"),
                classes=["AUTHZ", "CONF"], priority="P1", steps=steps)


CASES.extend([_group_self_grant_twin(True), _group_self_grant_twin(False)])


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а): служба
# kaname наружу краем платформы не публикуется (Р-В5 приёмки), делегат ходит к ней
# напрямую.
# #1032: настоящий собственный край. Check всегда предъявляется самим S/S2/M.
_GDU_U = "jwtHumanCeremonyStepUp"
_GDU_E = "jwtHumanEscStepUp"
_GDU_C = "jwtHumanAidAdmSharedStepUp"
_GDU_D = "jwtGDDelegate"
_GDU_SA = "SUBJECT_TYPE_SERVICE_ACCOUNT"
_GDU_GROUP = "SUBJECT_TYPE_GROUP"


def _gdu_var(name):
    return "{{" + name + "}}"


def _gdu_ready():
    return [
        "const needed = ['gduGivenReady','gduAccountId','gduProjectId','gduRegistryId','gduRepositoryId','gduSId','jwtGDUS','gduS2Id','jwtGDUS2','gduMId','jwtGDUM','gduGroupId','gdDelegateSaId','jwtGDDelegate','gdRolePullerId','gdRolePusherId','gdRoleAdminId','gduAccountAdminRoleId','jwtHumanCeremony','jwtHumanCeremonyStepUp','ceremonyUserId','jwtHumanEscStepUp','humanEscUserId','jwtHumanAidAdmSharedStepUp','humanAidAdmSharedUserId'];",
        "const missing = needed.filter(k => !pm.environment.get(k));",
        "if (missing.length || pm.environment.get('gduGivenReady') !== 'true') { throw new Error('precondition_not_met: GDU own fixture: ' + missing.join(',')); }",
        "pm.test('Дано: отдельные S/S2/M/D', () => pm.expect(new Set(['gduSId','gduS2Id','gduMId','gdDelegateSaId'].map(k => pm.environment.get(k))).size).to.eql(4));",
    ]


def _gdu_check(name, subject="S", target="X", relation="get", allowed=False, wait=False):
    id_key, token = {"S": ("gduSId", "jwtGDUS"), "S2": ("gduS2Id", "jwtGDUS2"), "M": ("gduMId", "jwtGDUM")}[subject]
    typ, resource, key = ("registry_registry", "registries", "gduRegistryId") if target == "X" else ("registry_repository", "repositories", "gduRepositoryId")
    checks = [*assert_status(200),
        "pm.test('собственный точный effective verdict', () => pm.expect(pm.response.json().allowed).to.eql(" + str(allowed).lower() + "));"]
    if wait:
        # Только явно вызванная выдача/отзыв имеет окно согласования.
        checks = [
            "const key = 'gduWait:' + pm.info.requestName;",
            "const n = Number(pm.environment.get(key) || 0);",
            "const settled = pm.response.code === 200 && pm.response.json().allowed === " + str(allowed).lower() + ";",
            "if (!settled && n < 80) { pm.environment.set(key, String(n + 1)); setTimeout(() => {}, 250); pm.execution.setNextRequest(pm.info.requestName); return; }",
            "pm.environment.unset(key);", *checks]
    return Step(name=name, method="POST", path="/iam/v1/authorize:check", auth=token,
        body={"subject": "service_account:" + _gdu_var(id_key), "resource": {"type": typ, "id": _gdu_var(key)},
              "action": "registry." + resource + "." + relation, "requiredRelation": "v_" + relation}, test_script=checks)


def _gdu_mutate(name, path, body, capture=None, auth=_GDU_U, method="POST", response=None):
    tests = [*assert_status(200), *save_from_response("j.id", "opId")]
    if capture:
        tests.extend(save_from_response("j.metadata && j.metadata." + capture[0], capture[1]))
    result = [Step(name=name, method=method, path=path, body=body, auth=auth, test_script=tests),
              poll_operation_until_done(), assert_op_success()]
    if response:
        result.append(Step(name=name + "-response", method="GET", path="/operations/{{opId}}", auth=auth,
            test_script=[*assert_status(200),
                "pm.test('Operation.response присутствует', () => pm.expect(pm.response.json().response).to.be.an('object'));",
                "const result = Object.assign({}, pm.response.json().response); delete result['@type'];",
                "pm.environment.set(" + js_str(response) + ", JSON.stringify(result));"]))
    return result


def _gdu_binding(axis="old"):
    # Одинаковое тело плюс сравнение подставленных байтов запроса до/после.
    subject, role, typ, target = "gduSId", "gdRolePullerId", "registry.registries", "gduRegistryId"
    if axis == "role":
        role = "gdRolePusherId"
    elif axis == "target":
        subject, typ, target = "gduS2Id", "registry.repositories", "gduRepositoryId"
    elif axis == "subject":
        subject = "gduGroupId"
    body = {"subjects": [{"type": _GDU_GROUP if axis == "subject" else _GDU_SA, "id": _gdu_var(subject)}],
            "roleId": _gdu_var(role), "scopeType": "iam.project", "scopeId": "{{gduProjectId}}",
            "target": {"resources": {"resources": [{"type": typ, "id": _gdu_var(target)}]}}}
    if axis == "old":
        body["deletionProtection"] = True
    return body


def _gdu_grant(name, axis="old", denied=False, compare=False):
    body = _gdu_binding(axis)
    before = ["const bytes = pm.variables.replaceIn(pm.request.body.raw);",
        "pm.environment.set('gduExactGrant', bytes);"] if denied else []
    if compare:
        before = ["pm.test('та же выдача побайтово', () => pm.expect(pm.variables.replaceIn(pm.request.body.raw)).to.eql(pm.environment.get('gduExactGrant')));"]
    if denied:
        return [Step(name=name, method="POST", path="/iam/v1/accessBindings", auth=_GDU_D, body=body,
                     pre_script=before, test_script=[*_denied(name),
                         "pm.test('отказ синхронный без операции', () => pm.expect(pm.response.json().id).to.eql(undefined));"])]
    result = _gdu_mutate(name, "/iam/v1/accessBindings", body,
        capture=("accessBindingId", "gduB0" if axis == "old" else "gduNewBinding"), auth=_GDU_D)
    result[0].pre_script.extend(before)
    key = "gduB0" if axis == "old" else "gduNewBinding"
    result.append(Step(name=name + "-attribution", method="GET", path="/iam/v1/accessBindings/" + _gdu_var(key), auth=_GDU_U,
        test_script=[*assert_status(200),
            "pm.test('выдача принадлежит тому же d', () => pm.expect(pm.response.json().delegationId).to.eql(pm.environment.get('gduId')));",
            "pm.test('выдача ACTIVE', () => pm.expect(pm.response.json().status).to.eql('ACTIVE'));"]))
    return result


def _gdu_snapshot(name, capture=False, delegation=False):
    tests = [*assert_status(200)]
    slot = "gduBefore" if delegation else "gduB0Before"
    if capture:
        tests.append("pm.environment.set(" + js_str(slot) + ", JSON.stringify(pm.response.json()));")
    else:
        tests.append("pm.test('полный прежний ресурс без изменений', () => pm.expect(pm.response.json()).to.deep.eql(JSON.parse(pm.environment.get(" + js_str(slot) + "))));")
    return Step(name=name, method="GET",
        path="/iam/v1/grantDelegations/{{gduId}}" if delegation else "/iam/v1/accessBindings/{{gduB0}}",
        auth=_GDU_U, test_script=tests)


def _gdu_inventory(name, capture=False):
    return Step(name=name, method="GET", path="/iam/v1/accessBindings?filter=scopeId%3D%22{{gduProjectId}}%22&includeRevoked=true&pageSize=1000", auth=_GDU_U,
        test_script=[*assert_status(200),
            "const j = pm.response.json();",
            "pm.test('снимок полон', () => pm.expect(j.nextPageToken || '').to.eql(''));",
            # У независимой owner-выдачи проекта materializedAt меняется при
            # доставке дочерних объектов. Полная B0 сравнивается отдельно.
            "const rows = (j.accessBindings || []).map(b => { const row=Object.assign({},b); delete row.materializedAt; return row; }).sort((a,b) => a.id.localeCompare(b.id));",
            "pm.environment.set('gduInventory', JSON.stringify(rows));" if capture else
            "pm.test('Update не выдаёт и не отзывает', () => pm.expect(rows).to.deep.eql(JSON.parse(pm.environment.get('gduInventory'))));"])


def _gdu_invariant(name):
    return [_gdu_snapshot(name + "-B0"), _gdu_check(name + "-S-B0-effective", allowed=True), _gdu_inventory(name + "-bindings")]


def _gdu_readback(name, response="gduResponse", creator="ceremonyUserId"):
    return [Step(name=name + "-Get", method="GET", path="/iam/v1/grantDelegations/{{gduId}}", auth=_GDU_U,
        test_script=[*assert_status(200),
            "const j = pm.response.json();",
            "pm.test('Get = Operation.response', () => pm.expect(j).to.deep.eql(JSON.parse(pm.environment.get(" + js_str(response) + "))));",
            "pm.test('тот же ID и первоначальный автор', () => { pm.expect(j.id).to.eql(pm.environment.get('gduId')); pm.expect(j.delegatedBy).to.deep.eql({type:'user', id:pm.environment.get(" + js_str(creator) + ")}); });",
            "pm.test('наборы нормализованы', () => ['roleIds','targetTypes','subjectTypes'].forEach(k => pm.expect(j[k]).to.deep.eql([...j[k]].sort())));",
            "pm.environment.set('gduCurrent', JSON.stringify(j));"]),
        Step(name=name + "-List", method="GET", path="/iam/v1/grantDelegations?accountId={{gduAccountId}}&pageSize=1000", auth=_GDU_U,
            test_script=[*assert_status(200),
                "const j = pm.response.json();",
                "pm.test('List полный и содержит ровно тот d', () => { pm.expect(j.nextPageToken || '').to.eql(''); const rows=(j.grantDelegations || []).filter(d => d.id === pm.environment.get('gduId')); pm.expect(rows).to.deep.eql([JSON.parse(pm.environment.get('gduCurrent'))]); });"])]


def _gdu_patch(name, body, auth=_GDU_U, creator="ceremonyUserId"):
    result = _gdu_mutate(name, "/iam/v1/grantDelegations/{{gduId}}", body, auth=auth, method="PATCH", response="gduResponse")
    result[0].pre_script.extend([
        "const before = JSON.parse(pm.environment.get('gduCurrent'));",
        "const requested = JSON.parse(pm.variables.replaceIn(pm.request.body.raw));",
        "const selected = (requested.updateMask || 'roleIds,targetTypes,subjectTypes').split(',');",
        "for (const k of selected) before[k] = [...requested[k]].sort();",
        "pm.environment.set('gduExpected', JSON.stringify(before));"])
    result[0].test_script.append(
        "pm.test('Update metadata связывает d и A', () => { const m=pm.response.json().metadata || {}; pm.expect(m.grantDelegationId).to.eql(pm.environment.get('gduId')); pm.expect(m.accountId).to.eql(pm.environment.get('gduAccountId')); });")
    result.extend(_gdu_readback(name, creator=creator))
    result.append(Step(name=name + "-exact-after", method="GET", path="/iam/v1/grantDelegations/{{gduId}}", auth=_GDU_U,
        test_script=[*assert_status(200),
            "pm.test('ровно выбранные полные наборы; неизменяемые поля прежние', () => pm.expect(pm.response.json()).to.deep.eql(JSON.parse(pm.environment.get('gduExpected'))));"]))
    result.extend(_gdu_invariant(name))
    return result


def _gdu_axes(axis):
    if axis == "role":
        return {"updateMask": "roleIds", "roleIds": ["{{gdRolePusherId}}", "{{gdRolePullerId}}"]}
    if axis == "target":
        return {"updateMask": "targetTypes", "targetTypes": ["registry.repositories", "registry.registries"]}
    return {"updateMask": "subjectTypes", "subjectTypes": [_GDU_GROUP, _GDU_SA]}


def _gdu_given(name, creator=_GDU_U, creator_id="ceremonyUserId"):
    steps = [Step(name=name + "-owner", method="GET", path="/iam/v1/accounts/{{gduAccountId}}", auth=_GDU_U,
        pre_script=_gdu_ready(), test_script=[*assert_status(200),
            "pm.test('U — владелец строки аккаунта', () => pm.expect(pm.response.json().ownerUserId).to.eql(pm.environment.get('ceremonyUserId')));"]),
        Step(name=name + "-group", method="GET", path="/iam/v1/groups/{{gduGroupId}}:listMembers", auth=_GDU_U,
            test_script=[*assert_status(200),
                "pm.test('G содержит ровно M', () => { const j=pm.response.json(); pm.expect(j.nextPageToken || '').to.eql(''); pm.expect((j.members || []).map(m => ({memberType:m.memberType,memberId:m.memberId}))).to.deep.eql([{memberType:'service_account',memberId:pm.environment.get('gduMId')}]); });"])]
    for subject in ("S", "S2", "M"):
        for target, relation in (("X", "get"), ("Y", "get"), ("Y", "update")):
            steps.append(_gdu_check(name + "-clean-" + subject + target + relation, subject, target, relation))
    steps.extend(_gdu_mutate(name + "-D0", "/iam/v1/grantDelegations",
        {"accountId": "{{gduAccountId}}", "delegate": {"type": _GDU_SA, "id": "{{gdDelegateSaId}}"},
         "roleIds": ["{{gdRolePullerId}}"], "targetTypes": ["registry.registries"], "subjectTypes": [_GDU_SA]},
        capture=("grantDelegationId", "gduId"), auth=creator, response="gduResponse"))
    steps.extend(_gdu_readback(name + "-D0", creator=creator_id))
    steps.extend(_gdu_grant(name + "-B0"))
    steps.extend([_gdu_check(name + "-B0-ready", allowed=True, wait=True),
                  _gdu_snapshot(name + "-B0-save", capture=True),
                  _gdu_snapshot(name + "-D0-save", capture=True, delegation=True),
                  _gdu_inventory(name + "-inventory-save", capture=True)])
    return steps


def _gdu_cleanup(name):
    return [*_gdu_mutate(name + "-Revoke", "/iam/v1/grantDelegations/{{gduId}}:revoke", {}),
            Step(name=name + "-D-REVOKED", method="GET", path="/iam/v1/grantDelegations/{{gduId}}", auth=_GDU_U,
                test_script=[*assert_status(200),
                    "pm.test('d REVOKED с отметкой времени', () => { const j=pm.response.json(); pm.expect(j.status).to.eql('REVOKED'); pm.expect(j.revokedAt).to.be.a('string').and.not.empty; });"]),
            Step(name=name + "-B0-REVOKED", method="GET", path="/iam/v1/accessBindings/{{gduB0}}", auth=_GDU_U,
                test_script=[*assert_status(200),
                    "pm.test('защищённая B0 отозвана по делегированию и сохранена', () => { const j=pm.response.json(); pm.expect(j.status).to.eql('REVOKED'); pm.expect(j.revocationReason).to.eql('REVOCATION_REASON_DELEGATION_REVOKED'); pm.expect(j.revokedAt).to.be.a('string').and.not.empty; pm.expect(j.deletionProtection).to.eql(true); pm.expect(j.delegationId).to.eql(pm.environment.get('gduId')); });"]),
            _gdu_check(name + "-S-revoked", wait=True),
            _gdu_check(name + "-S-update-revoked", target="Y", relation="update", wait=True),
            _gdu_check(name + "-S2-revoked", subject="S2", target="Y", wait=True),
            _gdu_check(name + "-M-revoked", subject="M", wait=True)]


def _gdu_distinct(name, axis, allowed=False, wait=False):
    subject, target, relation = {"role": ("S", "Y", "update"), "target": ("S2", "Y", "get"), "subject": ("M", "X", "get")}[axis]
    return _gdu_check(name, subject, target, relation, allowed, wait)


def _gdu_expand(axis, case_id):
    return Case(id=case_id, title="#1032: расширение " + axis + ", та же выдача и собственный effective false/false/true", classes=["CRUD", "CONF", "NEG"], priority="P1",
        steps=[*_gdu_given(case_id), _gdu_distinct(case_id + "-before", axis),
            *_gdu_grant(case_id + "-grant-denied", axis, denied=True),
            *_gdu_patch(case_id + "-PATCH", _gdu_axes(axis)),
            _gdu_distinct(case_id + "-after-PATCH-before-grant", axis),
            *_gdu_grant(case_id + "-same-grant", axis, compare=True),
            _gdu_distinct(case_id + "-after-grant", axis, allowed=True, wait=True),
            _gdu_snapshot(case_id + "-B0-after-grant"), _gdu_check(case_id + "-B0-still-allowed", allowed=True),
            *_gdu_cleanup(case_id)])


for _axis, _id in (("role", "IAM-GDU-EXPAND-ROLE-ALLOWED"), ("target", "IAM-GDU-EXPAND-TARGET-ALLOWED"),
                    ("subject", "IAM-GDU-EXPAND-SUBJECT-ALLOWED")):
    CASES.append(_gdu_expand(_axis, _id))


def _gdu_error(name, body, code, text, auth=_GDU_U, field=None, http=400, challenge=None):
    tests = [*assert_status(http), *assert_grpc_code(code, {3: "INVALID_ARGUMENT", 7: "PERMISSION_DENIED", 9: "FAILED_PRECONDITION", 16: "UNAUTHENTICATED"}[code]),
             *assert_refusal_message(text, name + ": точный текст"),
             "pm.test('нет операции при синхронном отказе', () => pm.expect(pm.response.json().id).to.eql(undefined));"]
    if field:
        tests.append("pm.test('точный BadRequest', () => { const j=pm.response.json(); const ds=j.details || (j.error && j.error.details) || []; const b=ds.filter(d => /google.rpc.BadRequest$/.test(d['@type'] || '')); pm.expect(ds).to.have.length(1); pm.expect(b).to.have.length(1); pm.expect(b[0].fieldViolations).to.deep.eql([{field:" + js_str(field) + ",description:" + js_str(text) + ",reason:'',localizedMessage:null}]); });")
    if challenge:
        tests.append("pm.test('точный WWW-Authenticate challenge', () => pm.expect(pm.response.headers.get('WWW-Authenticate')).to.eql(" + js_str(challenge) + "));")
    return Step(name=name, method="PATCH", path="/iam/v1/grantDelegations/{{gduId}}", auth=auth, body=body, test_script=tests)

# Отказы имеют принимаемый близнец на той же строке и контроль всех осей/B0.
for _id, _axis, _bad, _code, _text, _field in (
        ("IAM-GDU-NARROW-ROLE-DENIED", "role", {"updateMask": "roleIds", "roleIds": ["{{gdRolePusherId}}"]}, 9,
         "grant delegation {{gduId}}: role_ids may only expand", None),
        ("IAM-GDU-CROSS-MODULE-TARGET-DENIED", "target", {"updateMask": "targetTypes", "targetTypes": ["registry.registries", "vpc.addressPool"]}, 9,
         "role_ids and target_types must belong to one module; found registry, vpc", None),
        ("IAM-GDU-EMPTY-SUBJECT-DENIED", "subject", {"updateMask": "subjectTypes", "subjectTypes": []}, 3,
         "subject_types: required", "subject_types")):
    _steps = _gdu_given(_id)
    if _axis == "role":
        _steps.extend(_gdu_patch(_id + "-expanded-control", _gdu_axes("role")))
    if _axis == "target":
        _steps.append(Step(name=_id + "-live-other-module", method="GET", path="/iam/v1/permissionCatalog", auth=_GDU_U,
            test_script=[*assert_status(200), "pm.test('vpc.addressPool живой, не неизвестный тип', () => pm.expect((pm.response.json().modules || []).some(m => m.module === 'vpc' && (m.resources || []).some(r => r.resource === 'addressPool'))).to.eql(true));"]))
    _steps.extend([_gdu_snapshot(_id + "-before-refusal", capture=True, delegation=True),
        _gdu_error(_id + "-refused", _bad, _code, _text, field=_field),
        _gdu_snapshot(_id + "-atomic-D", delegation=True), *_gdu_invariant(_id + "-atomic-I"),
        *_gdu_patch(_id + "-corrected-twin", _gdu_axes(_axis)), *_gdu_cleanup(_id)])
    CASES.append(Case(id=_id, title="#1032: точный отказ и исправленный близнец " + _axis, classes=["NEG", "VAL"], priority="P1", steps=_steps))


def _gdu_e_authority(name, allowed):
    return Step(name=name, method="POST", path="/iam/v1/authorize:check", auth=_GDU_E,
        body={"subject": "user:{{humanEscUserId}}", "resource": {"type": "account", "id": "{{gduAccountId}}"},
              "action": "iam.accounts.get", "requiredRelation": "admin"},
        test_script=[
            "const key='gduActorReady:' + pm.info.requestName, n=Number(pm.environment.get(key) || 0);",
            "const ready=pm.response.code === 200 && pm.response.json().allowed === " + str(allowed).lower() + ";",
            "if (!ready && n < 80) { pm.environment.set(key,String(n+1)); setTimeout(() => {},250); pm.execution.setNextRequest(pm.info.requestName); return; }",
            "pm.environment.unset(key);", *assert_status(200),
            "pm.test('самостоятельный account-admin E', () => pm.expect(pm.response.json().allowed).to.eql(" + str(allowed).lower() + "));"])


def _gdu_e_snapshot(name, capture=False):
    # Полный исходный список E может содержать штатные выдачи другого аккаунта.
    # Ничего не отбрасываем: после уборки сравниваем каждый объект целиком.
    tests = [*assert_status(200),
        "const j=pm.response.json(), bindings=j.accessBindings || [];",
        "pm.test('полный список E без скрытой страницы и чужих субъектов', () => {",
        "  pm.expect(j.accessBindings).to.be.an('array'); pm.expect(j.incompleteMembershipGroupIds || []).to.deep.eql([]);",
        "  pm.expect(j.nextPageToken || '').to.eql(''); pm.expect(bindings).to.be.an('array');",
        "  const ids=bindings.map(b => b.id); ids.forEach(id => pm.expect(id).to.be.a('string').and.not.empty);",
        "  pm.expect(new Set(ids).size).to.eql(bindings.length);",
        "  bindings.forEach(b => pm.expect((b.subjects || []).some(s => s.type === 'SUBJECT_TYPE_USER' && s.id === pm.environment.get('humanEscUserId'))).to.eql(true)); });",
        "const snapshot=bindings.slice().sort((a,b) => a.id.localeCompare(b.id));"]
    if capture:
        tests.extend([
            "pm.test('E не имеет выдач на GDU-аккаунте или глобальной области', () => {",
            "  bindings.forEach(b => { pm.expect(b.scopeType).to.be.oneOf(['iam.account','iam.project']);",
            "    pm.expect(b.scopeId).not.to.eql(pm.environment.get('gduAccountId')); }); });",
            "pm.environment.set('gduEBindingsBaseline', JSON.stringify(snapshot));"])
    else:
        tests.append("pm.test('полный исходный список E восстановлен без добавлений, удалений и изменений', () => { const baseline=pm.environment.get('gduEBindingsBaseline'); pm.expect(baseline).to.be.a('string').and.not.empty; pm.expect(snapshot).to.deep.eql(JSON.parse(baseline)); });")
    return Step(name=name, method="GET", path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{humanEscUserId}}&pageSize=1000",
        auth=_GDU_E, test_script=tests)


_owner_id = "IAM-GDU-OWNER-UPDATE-ALLOWED"
# E — настоящий человек без cloud-admin, временный account-admin. Выдача
# отзывается после кейса, чтобы не менять Given соседних проверок Esc.
_owner_steps = [Step(name=_owner_id + "-E-identity", method="GET", path="/iam/v1/me", auth=_GDU_E,
    pre_script=_gdu_ready(), test_script=[*assert_status(200),
        "pm.test('E настоящий человек без cloud-admin', () => { const j=pm.response.json(); pm.expect(j.subject).to.eql('user:' + pm.environment.get('humanEscUserId')); pm.expect(j.systemAdmin || false).to.eql(false); });"]),
    Step(name=_owner_id + "-C-identity", method="GET", path="/iam/v1/me", auth=_GDU_C,
        test_script=[*assert_status(200), "pm.test('C настоящий cloud-admin', () => { const j=pm.response.json(); pm.expect(j.subject).to.eql('user:' + pm.environment.get('humanAidAdmSharedUserId')); pm.expect(j.systemAdmin).to.eql(true); });"]),
    _gdu_e_snapshot(_owner_id + "-E-initial-bindings", capture=True),
    _gdu_e_authority(_owner_id + "-E-initially-denied", False),
    *_gdu_mutate(_owner_id + "-grant-E-admin", "/iam/v1/accessBindings",
        {"subjects": [{"type": "SUBJECT_TYPE_USER", "id": "{{humanEscUserId}}"}], "roleId": "{{gduAccountAdminRoleId}}",
         "scopeType": "iam.account", "scopeId": "{{gduAccountId}}", "target": {"allInScope": {}}}, capture=("accessBindingId", "gduEAdminBinding")),
    _gdu_e_authority(_owner_id + "-E-admin-ready", True),
    *_gdu_given(_owner_id),
    *_gdu_patch(_owner_id + "-U", _gdu_axes("role")),
    *_gdu_patch(_owner_id + "-E", _gdu_axes("target"), auth=_GDU_E),
    *_gdu_patch(_owner_id + "-C", _gdu_axes("subject"), auth=_GDU_C),
    *_gdu_cleanup(_owner_id),
    *_gdu_given(_owner_id + "-creator-E", creator=_GDU_E, creator_id="humanEscUserId"),
    *_gdu_patch(_owner_id + "-U-keeps-creator-E", _gdu_axes("role"), creator="humanEscUserId"),
    *_gdu_patch(_owner_id + "-C-keeps-creator-E", _gdu_axes("target"), auth=_GDU_C, creator="humanEscUserId"),
    *_gdu_cleanup(_owner_id + "-creator-E"),
    *_gdu_mutate(_owner_id + "-revoke-E-admin", "/iam/v1/accessBindings/{{gduEAdminBinding}}:revoke", {}),
    _gdu_e_authority(_owner_id + "-E-admin-removed", False),
    *_gdu_mutate(_owner_id + "-delete-own-E-fixture", "/iam/v1/accessBindings/{{gduEAdminBinding}}", None, method="DELETE"),
    _gdu_e_snapshot(_owner_id + "-E-bindings-restored")]
CASES.append(Case(id=_owner_id, title="#1032: настоящий U, отдельные E/C, первоначальный автор неизменен", classes=["CRUD", "CONF"], priority="P1", steps=_owner_steps))


for _id, _auth, _http, _code, _message, _challenge in (
        ("IAM-GDU-DELEGATE-UPDATE-DENIED", _GDU_D, 403, 7, "permission denied", None),
        ("IAM-GDU-ANONYMOUS-DENIED", "anonymous", 401, 16,
         "no credential presented; authenticate with authorization: Bearer <token>", None),
        ("IAM-GDU-ACR1-DENIED", "jwtHumanCeremony", 401, 16,
         "authentication level is insufficient: step up with a second factor, or present a credential of another kind",
         'Bearer error="insufficient_user_authentication", error_description="Required ACR 2 for this resource; presented ACR 1", acr_values="2"'),
        ("IAM-GDU-MACHINE-AUTHORITY-DENIED", "jwtGDUS2", 403, 7, "permission denied", None)):
    _steps = _gdu_given(_id)
    if _id == "IAM-GDU-MACHINE-AUTHORITY-DENIED":
        _steps.append(Step(name=_id + "-verified-machine", method="GET", path="/iam/v1/me", auth="jwtGDUS2",
            test_script=[*assert_status(200), "pm.test('проверенный машинный субъект, не облачный админ', () => { const j=pm.response.json(); pm.expect(j.subject).to.eql('service_account:' + pm.environment.get('gduS2Id')); pm.expect(j.systemAdmin || false).to.eql(false); });"]))
    _steps.extend([_gdu_error(_id + "-PATCH", _gdu_axes("role"), _code, _message, auth=_auth, http=_http, challenge=_challenge),
        _gdu_snapshot(_id + "-unchanged-D", delegation=True), *_gdu_invariant(_id + "-I"),
        *_gdu_patch(_id + "-owner-positive-twin", _gdu_axes("role")), *_gdu_cleanup(_id)])
    CASES.append(Case(id=_id, title="#1032: публичная дверь и принимаемый близнец " + _id, classes=["NEG", "CONF"], priority="P1", steps=_steps))


_repeat = "IAM-GDU-REPEAT-UNCHANGED"
CASES.append(Case(id=_repeat, title="#1032: успешный повтор полного набора — no-op, B0 и доступ прежние", classes=["CRUD", "CONF"], priority="P1", steps=[
    *_gdu_given(_repeat), *_gdu_patch(_repeat + "-first", _gdu_axes("role")),
    _gdu_snapshot(_repeat + "-save-expanded", capture=True, delegation=True),
    *_gdu_patch(_repeat + "-repeat", {"updateMask": "roleIds", "roleIds": ["{{gdRolePullerId}}", "{{gdRolePusherId}}"]}),
    _gdu_snapshot(_repeat + "-exact-noop", delegation=True),
    *_gdu_cleanup(_repeat)]))

_revoked = "IAM-GDU-REVOKED-UPDATE-DENIED"
CASES.append(Case(id=_revoked, title="#1032: ACTIVE-близнец и REVOKED, включая no-op, без оживления", classes=["NEG", "CONF"], priority="P1", steps=[
    *_gdu_given(_revoked), *_gdu_patch(_revoked + "-ACTIVE", _gdu_axes("role")),
    *_gdu_cleanup(_revoked), _gdu_snapshot(_revoked + "-save-D", capture=True, delegation=True),
    _gdu_snapshot(_revoked + "-save-B0", capture=True), _gdu_inventory(_revoked + "-save-bindings", capture=True),
    _gdu_error(_revoked + "-expansion", _gdu_axes("target"), 9, "grant delegation {{gduId}} is already revoked"),
    _gdu_error(_revoked + "-noop", _gdu_axes("role"), 9, "grant delegation {{gduId}} is already revoked"),
    _gdu_snapshot(_revoked + "-unchanged-D", delegation=True), _gdu_snapshot(_revoked + "-unchanged-B0"),
    _gdu_inventory(_revoked + "-unchanged-bindings"),
    _gdu_check(_revoked + "-S-denied"), _gdu_check(_revoked + "-S2-denied", subject="S2", target="Y"),
    _gdu_check(_revoked + "-M-denied", subject="M")]))


CASES = address_own_front(CASES, "собственный публичный REST-фронт службы — единственная поверхность, "
                                 "на которой делегат вызывает службу (Р-В5 приёмки)")
