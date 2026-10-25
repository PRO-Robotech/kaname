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


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а): служба
# kaname наружу краем платформы не публикуется (Р-В5 приёмки), делегат ходит к ней
# напрямую.
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы — единственная поверхность, "
                                 "на которой делегат вызывает службу (Р-В5 приёмки)")
