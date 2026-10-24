# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: причина отзыва выдачи на крае (`AccessBinding.revocationReason`).

ПРЕДМЕТ. Приёмка `docs/engineering/acceptance/unregistration-revokes-its-grants.md`
(редакция 2, отпечаток 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4;
задача PRO-Robotech/kaname#963), S2: URG-E1, URG-E2.

Снятие регистрации объекта — метод `Internal*` только внутреннего слушателя
(ban #6), у края его нет, поэтому отзыв ПО СНЯТИЮ судится интеграцией
(`testing-newman.md#edge-internal-consequence`). Край судит то, что через него
проходит: поле причины в теле ответа. Причину на крае кладёт отзыв глаголом —
тот же путь проекции (`toproto`), что у любой причины.

ЧТО УТВЕРЖДАЕТСЯ — ПАРА. E1: после отзыва `revocationReason =
REVOCATION_REASON_REVOKE` в `GET` и в `List` с `includeRevoked=true`. E2 —
близнец, один факт: отзыва не было, и ключа `revocationReason` в теле нет —
поле с присутствием (optional), незаданное, кодек фронта не выводит, хотя прочие
незаданные поля печатает (EmitUnpopulated). Без близнеца E1 зеленел бы на реализации,
которая пишет причину всем строкам подряд.

Дисциплина (testing.md): чтение своей свежей строки — `retry_until_present`;
каждый кейс сеет роль и выдачу сам и за собой убирает; имена run-unique через
{{runId}}.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а).
HOME = "kaname"

CASES = []


def _assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def _seed(prefix, role_var, binding_var):
    """Роль аккаунта и выдача её субъекту {{userNOBId}} на аккаунте, цель — вся область."""
    return [
        Step(name=f"{prefix}-role", method="POST", path="/iam/v1/roles",
             body={"name": prefix + "{{runId}}", "accountId": "{{accountAId}}",
                   "description": "URG-E: причина отзыва на крае",
                   "rules": [{"module": "iam", "resources": ["project"], "verbs": ["get"]}]},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *_assert_iam_op(),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var)]),
        poll_operation_until_done(),
        assert_op_success(),
        Step(name=f"{prefix}-grant", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "user", "subjectId": "{{userNOBId}}",
                   "roleId": "{{" + role_var + "}}", "scopeType": "iam.account", "scopeId": "{{accountAId}}",
                   "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *_assert_iam_op(),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", binding_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _cleanup(prefix, role_var, binding_var):
    # Уборка best-effort: отказ теардауна не есть дефект кейса под проверкой.
    return [
        Step(name=f"{prefix}-cleanup-binding", method="DELETE",
             path="/iam/v1/accessBindings/{{" + binding_var + "}}", auth="jwtAccountAdminA",
             test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(required=False),
        Step(name=f"{prefix}-cleanup-role", method="DELETE",
             path="/iam/v1/roles/{{" + role_var + "}}", auth="jwtAccountAdminA",
             test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(required=False),
    ]


# ===========================================================================
# URG-E1 — причина отзыва видна на крае
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-URG-E1-REVOCATION-REASON-VISIBLE-OK",
    title="URG-E1: после отзыва глаголом GET и List(includeRevoked=true) несут "
          "revocationReason = REVOCATION_REASON_REVOKE",
    classes=["CONF"],
    priority="P1",
    steps=[
        *_seed("urgea", "urgE1Role", "urgE1Acb"),
        Step(name="urge1-revoke", method="POST",
             path="/iam/v1/accessBindings/{{urgE1Acb}}:revoke", body={},
             auth="jwtAccountAdminAStepUp",
             test_script=[*assert_status(200), *_assert_iam_op(),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(auth="jwtAccountAdminAStepUp"),
        assert_op_success(auth="jwtAccountAdminAStepUp"),
        retry_until_present(Step(
            name="urge1-get",
            method="GET",
            path="/iam/v1/accessBindings/{{urgE1Acb}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('URG-E1: статус REVOKED', () =>",
                "  pm.expect(pm.response.json().status, pm.response.text()).to.eql('REVOKED'));",
                "pm.test('URG-E1: revocationReason = REVOCATION_REASON_REVOKE', () =>",
                "  pm.expect(pm.response.json().revocationReason, pm.response.text()).to.eql('REVOCATION_REASON_REVOKE'));",
            ],
        ), "urgE1Acb"),
        Step(
            name="urge1-list-include-revoked",
            method="GET",
            path="/iam/v1/accessBindings?filter=subject%3D%22{{userNOBId}}%22&includeRevoked=true&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "const mine = (pm.response.json().accessBindings || []).find(b => b.id === pm.environment.get('urgE1Acb'));",
                "pm.test('URG-E1: List с includeRevoked содержит выдачу', () => pm.expect(mine, pm.response.text()).to.be.an('object'));",
                "pm.test('URG-E1: List несёт ту же причину', () =>",
                "  pm.expect(mine && mine.revocationReason, pm.response.text()).to.eql('REVOCATION_REASON_REVOKE'));",
            ],
        ),
        *_cleanup("urge1", "urgE1Role", "urgE1Acb"),
    ],
))


# ===========================================================================
# URG-E2 — близнец E1: у действующей выдачи причины нет
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-URG-E2-ACTIVE-HAS-NO-REASON-OK",
    title="URG-E2 (близнец E1, отзыва не было): действующая выдача — status ACTIVE, "
          "ключа revocationReason в теле нет",
    classes=["CONF"],
    priority="P1",
    steps=[
        *_seed("urgeb", "urgE2Role", "urgE2Acb"),
        retry_until_present(Step(
            name="urge2-get",
            method="GET",
            path="/iam/v1/accessBindings/{{urgE2Acb}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                "pm.test('URG-E2: статус ACTIVE', () =>",
                "  pm.expect(pm.response.json().status, pm.response.text()).to.eql('ACTIVE'));",
                "pm.test('URG-E2: ключа revocationReason нет', () =>",
                "  pm.expect(pm.response.json(), pm.response.text()).to.not.have.property('revocationReason'));",
            ],
        ), "urgE2Acb"),
        *_cleanup("urge2", "urgE2Role", "urgE2Acb"),
    ],
))


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а; kaname#398):
# предъявители людей куёт своя церемония службы на автономном стенде
# (`tests/authz-fixtures/seed_ceremony.py --wave`), и краю платформы здесь
# отвечать не на что.
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "волны церемонии нет поверхности, которую она судит")
