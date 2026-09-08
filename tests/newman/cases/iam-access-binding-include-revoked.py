# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Case-set: флаг `includeRevoked` — на КАЖДОЙ поверхности, которая его принимает.

ПРЕДМЕТ. `include_revoked` — не ключ фильтра, а отдельное поле запроса
(`api-conventions.md`), и принимают его ТРИ разных чтения. Поле, которое одна
поверхность читает, а соседняя молча выбрасывает, — «принято-и-проигнорировано»
на уровне подсистемы, и увидеть это можно только вызовом: край перекодирует
ответ своими стабами, а неизвестное ему поле запроса отбрасывает без слова.

ПЕРЕЧЕНЬ ПОВЕРХНОСТЕЙ ВЫВЕДЕН ИЗ КОНТРАКТА, А НЕ ВЫПИСАН ПО ПАМЯТИ:

    grep -c 'bool include_revoked' proto/kaname/cloud/iam/v1/access_binding_service.proto   → 3

    ListAccessBindingsRequest          → GET /iam/v1/accessBindings
    ListAccessBindingsByAccountRequest → GET /iam/v1/accounts/{account_id}/accessBindings
    ListAccessBindingsByRoleRequest    → GET /iam/v1/accessBindings:listByRole

Первую из трёх покрывает IAM-AB-SIA-03 (`iam-access-binding-account-scope.py`).
Здесь — две оставшиеся, и до этого набора у них не было чёрного ящика ВОВСЕ:
`listByRole` не встречался в кейсах iam ни разу, а у `accounts/{id}/accessBindings`
существовал единственный отрицательный кейс на негодную форму id.

ЧТО УТВЕРЖДАЕТСЯ — ПАРА НА КАЖДОЙ ПОВЕРХНОСТИ, А НЕ ОДНА СТОРОНА. «С флагом
отозванная видна» зеленело бы на реализации, которая не скрывает отозванные
НИКОГДА; «без флага не видна» зеленело бы на пустом ответе. Поэтому у каждой
поверхности три шага подряд по ОДНОЙ И ТОЙ ЖЕ строке: живая видна (положительный
контроль — доказывает, что чтение вообще что-то возвращает и что строка попадает
в его выборку) · после отзыва без флага скрыта · после отзыва с флагом
возвращается.

ПОЧЕМУ У `listByRole` СВОЯ РОЛЬ, А НЕ СИСТЕМНАЯ. Роль run-unique, поэтому
выборка чтения состоит из строк ЭТОГО кейса: утверждение о присутствии не
зависит от того, сколько выдач на системную роль накопил прогон, и страница не
может увести искомую строку за свой предел.

Дисциплина (testing.md): read-your-writes → `retry_until_present` (общий слой) на
ПЕРВОЕ списочное чтение своей свежей строки; шаги, утверждающие ОТСУТСТВИЕ, НЕ
оборачиваются повтором — повтор там пережидал бы ровно тот отказ, ради которого
шаг написан; каждый кейс сеет своё и за собой убирает; имена run-unique через
{{runId}}.
"""

CASES = []

# Системная роль просмотра — та же, что у соседнего набора: предмет кейса не
# роль, а флаг, поэтому у поверхности `accounts/{id}/accessBindings` берётся
# готовая.
SYS_VIEW = "rol1bda80f2be4d3658e"


def _assert_iam_op():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def _ids_js(var):
    """JS-выражение: массив id выдач из тела ответа в переменную `var`."""
    return f"const {var} = (pm.response.json().accessBindings || []).map(b => b.id);"


def _grant(name, role_id, scope_type, scope_id, save_var):
    """Выдать субъекту {{userNOBId}} названную роль в названной области."""
    return [
        Step(name=name, method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "user", "subjectId": "{{userNOBId}}",
                   "roleId": role_id, "scopeType": scope_type, "scopeId": scope_id,
                   "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *_assert_iam_op(),
                          *save_from_response("j.id", "opId"),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", save_var)]),
        poll_operation_until_done(),
        assert_op_success(),
    ]


def _revoke(name, save_var):
    """Отзыв — мягкий: строка ОСТАЁТСЯ со статусом REVOKED, и это ровно то, что
    делает флаг наблюдаемым. Отзыв требует поднятого уровня аутентификации."""
    return [
        Step(name=name, method="POST",
             path="/iam/v1/accessBindings/{{" + save_var + "}}:revoke", body={},
             auth="jwtAccountAdminAStepUp",
             test_script=[*assert_status(200), *_assert_iam_op(),
                          *save_from_response("j.id", "opId")]),
        poll_operation_until_done(auth="jwtAccountAdminAStepUp"),
        assert_op_success(auth="jwtAccountAdminAStepUp"),
    ]


def _cleanup_binding(save_var, name="cleanup-binding"):
    # Уборка best-effort: отказ теардауна не есть дефект кейса под проверкой.
    return [Step(name=name, method="DELETE",
                 path="/iam/v1/accessBindings/{{" + save_var + "}}",
                 auth="jwtAccountAdminA",
                 test_script=[*save_from_response("j.id", "opId")]),
            poll_operation_until_done(required=False)]


# ===========================================================================
# IAM-AB-REV-01 — ListByAccount: GET /iam/v1/accounts/{id}/accessBindings
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-REV-01-BY-ACCOUNT-INCLUDE-REVOKED-OK",
    title="IAM-AB-REV-01: accounts/{id}/accessBindings — отозванная строка СКРЫТА без флага и "
          "возвращается под ?includeRevoked=true; живая видна до отзыва (положительный контроль). "
          "Первое покрытие этой поверхности чёрным ящиком вообще",
    classes=["CONF", "NEG"],
    priority="P1",
    steps=[
        *_grant("bya-grant", SYS_VIEW, "iam.account", "{{accountAId}}", "revByAcctAcb"),
        retry_until_present(Step(
            name="bya-visible-before",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('живая выдача видна до отзыва (положительный контроль)', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('revByAcctAcb')));",
            ],
        ), "revByAcctAcb"),
        *_revoke("bya-revoke", "revByAcctAcb"),
        Step(
            name="bya-hidden-by-default",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('без флага отозванная строка скрыта', () =>",
                "  pm.expect(ids, pm.response.text()).to.not.include(pm.environment.get('revByAcctAcb')));",
            ],
        ),
        Step(
            name="bya-shown-with-flag",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}/accessBindings?pageSize=1000&includeRevoked=true",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('с флагом отозванная строка возвращается — поле читается и этой поверхностью', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('revByAcctAcb')));",
                # Строка возвращается СО СВОИМ статусом, а не молча: иначе вызывающий
                # не отличит её от живой и прочитает отозванный доступ как
                # действующий.
                "pm.test('возвращённая строка НАЗЫВАЕТ себя отозванной', () => {",
                "  const b = (pm.response.json().accessBindings || [])",
                "    .find(x => x.id === pm.environment.get('revByAcctAcb'));",
                "  pm.expect(b, pm.response.text()).to.be.an('object');",
                "  pm.expect(b.status, JSON.stringify(b)).to.eql('REVOKED');",
                "});",
            ],
        ),
        *_cleanup_binding("revByAcctAcb", name="cleanup-bya-binding"),
    ],
))


# ===========================================================================
# IAM-AB-REV-02 — ListByRole: GET /iam/v1/accessBindings:listByRole
# ===========================================================================

CASES.append(Case(
    id="IAM-AB-REV-02-BY-ROLE-INCLUDE-REVOKED-OK",
    title="IAM-AB-REV-02: accessBindings:listByRole — отозванная строка СКРЫТА без флага и "
          "возвращается под ?includeRevoked=true; живая видна до отзыва (положительный контроль). "
          "Роль run-unique, поэтому выборка состоит из строк этого кейса",
    classes=["CONF", "NEG"],
    priority="P1",
    steps=[
        Step(
            name="byr-create-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "abrev{{runId}}",
                "description": "newman IAM-AB-REV-02 probe role",
                "rules": [{"module": "compute", "resources": ["instance"],
                           "verbs": ["get", "list"]}],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200), *_assert_iam_op(),
                *save_from_response("j.id", "opId"),
                *save_from_response("j.metadata && j.metadata.roleId", "revByRoleId"),
            ],
        ),
        poll_operation_until_done(),
        assert_op_success(),
        *_grant("byr-grant", "{{revByRoleId}}", "iam.account", "{{accountAId}}", "revByRoleAcb"),
        retry_until_present(Step(
            name="byr-visible-before",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId={{revByRoleId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('живая выдача видна до отзыва (положительный контроль)', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('revByRoleAcb')));",
            ],
        ), "revByRoleAcb"),
        *_revoke("byr-revoke", "revByRoleAcb"),
        Step(
            name="byr-hidden-by-default",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId={{revByRoleId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('без флага отозванная строка скрыта', () =>",
                "  pm.expect(ids, pm.response.text()).to.not.include(pm.environment.get('revByRoleAcb')));",
            ],
        ),
        Step(
            name="byr-shown-with-flag",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId={{revByRoleId}}&pageSize=1000&includeRevoked=true",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                _ids_js("ids"),
                "pm.test('с флагом отозванная строка возвращается — поле читается и этой поверхностью', () =>",
                "  pm.expect(ids, pm.response.text()).to.include(pm.environment.get('revByRoleAcb')));",
                "pm.test('возвращённая строка НАЗЫВАЕТ себя отозванной', () => {",
                "  const b = (pm.response.json().accessBindings || [])",
                "    .find(x => x.id === pm.environment.get('revByRoleAcb'));",
                "  pm.expect(b, pm.response.text()).to.be.an('object');",
                "  pm.expect(b.status, JSON.stringify(b)).to.eql('REVOKED');",
                "});",
            ],
        ),
        *_cleanup_binding("revByRoleAcb", name="cleanup-byr-binding"),
        Step(name="cleanup-byr-role", method="DELETE", path="/iam/v1/roles/{{revByRoleId}}",
             auth="jwtAccountAdminA", test_script=[*save_from_response("j.id", "opId")]),
        poll_operation_until_done(required=False),
    ],
))
