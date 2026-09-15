# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RBAC rules model — black-box matchLabels suite.

Verifies, end-to-end through api-gateway → IAM, the BLACK-BOX-REACHABLE half of the
ARM_LABELS (matchLabels) contract:

  HAPPY    — a RoleService.Create with an ARM_LABELS rule on a FED type
             (compute.instance) is ACCEPTED (Operation done, no error). The rule
             carries matchLabels, NOT resourceNames; it is reconciler-driven.
  HAPPY    — the SAME shape on an iam content type (iam.role) is ALSO ACCEPTED:
             under the unified label-scope model every iam content type
             (user/serviceAccount/group/role/accessBinding) is label-selectable
             (feed-gate reversed — these types materialize iam-direct same-DB from
             own-table labels, no resource_mirror feed required).

WHY the matched-object Check is NOT here: for the FED (compute) type the per-object
materialization (label match → per-object FGA tuple) requires resource_mirror to be
fed by the owner service over the INTERNAL `*→iam` RegisterResource edge (vpc/compute
/nlb fgaproxy, :9091) — that edge is NOT exposed on the public REST gateway, so a
single-service newman suite cannot seed a matched mirror object. The matched/non-
matched Check SEMANTICS are proven at the FGA-native tuple layer by the real-OpenFGA
integration test (access_binding.TestIntegration_ScopeGrant_C22_MatchLabels_PerObjectCheck)
and end-to-end (mirror-fed) by the cross-repo e2e (kacho-test) once vpc/compute create
a matching resource. This suite asserts the role-side contract that IS black-box-
reachable through the gateway.

Fixture dependency (tests/authz-fixtures): jwtAccountAdminA, accountAId.

ПОВЕРХНОСТЬ — СОБСТВЕННЫЙ ПУБЛИЧНЫЙ REST-ФРОНТ СЛУЖБЫ (`{{ownRestBaseUrl}}`),
а не край платформы (e2e-flow.md §7а): все шаги переадресованы
`address_own_front`, предъявителя и аккаунт пишет посев автономного стенда
(`tests/authz-fixtures/seed_own_stand.py`). Производитель каждого утверждения —
сама служба: код 200 и конверт операции — use-case создания роли, `done` без
`error` — её исполнитель; ни область, ни идентификатор объекта в запросе не
извлекаются краем, поэтому таблица §7а «что производит край» сюда не доходит.
Утверждения не менялись; изменён глагол второго кейса — причина у самого тела.
"""

# ДОМ МОДУЛЯ — репозиторий его ПРЕДМЕТА (e2e-flow.md §7а, решение владельца
# 2026-09-12). Сверяется с деревом гейтом `scripts/case_home_test.py`: домены
# выводятся из REST-путей этого же модуля, и объявление обязано с ними сходиться.
HOME = "kaname"

CASES = []

POLL_CAP = 30


def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
    """Self-polling Step body that waits for an IAM Operation to be done."""
    capture = ""
    if out_id_var:
        capture = (f"if (j.response && j.response.id && !pm.environment.get('{out_id_var}')) "
                   f"{{ pm.environment.set('{out_id_var}', j.response.id); }}")
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_pollCount', String(pc + 1));",
        "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        capture,
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
    ]


# ─────────────────────────────────────────────────────────────────────────────
# RBACLBL-FED-ACCEPTED — matchLabels rule on a fed type (compute.instance) is
# accepted at RoleService.Create (Operation completes, no error). The arm is
# ARM_LABELS (matchLabels present, resourceNames absent) — reconciler-driven.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="RBACLBL-FED-ACCEPTED",
    title="ARM_LABELS rule on fed type compute.instance → Role.Create accepted (C-22 role-side)",
    classes=["RBAC", "RULES", "LABELS", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="create-label-role-fed",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "rbac_lbl_fed_{{runId}}",
                "description": "newman ARM_LABELS fed-type probe role",
                # Пара «чтение + запись», и ОБА глагола объявлены типом, поэтому оба
                # действительно материализуются. Стояло `create`: на `compute_instance`
                # он не даёт пообъектного кортежа вовсе (создание авторизуется ярусом
                # записи на родителе), то есть правило с меткой заявляло два глагола, а
                # проверять по метке было нечего у одного из них.
                "rules": [{
                    "module": "compute", "resources": ["instance"],
                    "verbs": ["get", "update"],
                    "matchLabels": {"env": "prod"},
                }],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_opLblFed"),
            ],
        ),
        Step(
            name="poll-label-role-fed",
            method="GET",
            path="/operations/{{_opLblFed}}",
            auth="jwtAccountAdminA",
            test_script=poll_op_done("_opLblFed", out_id_var="lblFedRoleId"),
        ),
        # УБОРКА. Роль заводится этим кейсом под `{{runId}}` и прежде не
        # сносилась вовсе: повторный прогон с тем же посевом получал
        # ALREADY_EXISTS на создании и читал его отказом приёма правила.
        # Идентификатор берётся из ЗАВЕРШЁННОЙ операции (`response.id`), а не из
        # предвыделенных метаданных — у упавшей операции он указывал бы на фантом.
        *reliable_delete("teardown-label-role-fed", "/iam/v1/roles/{{lblFedRoleId}}",
                         auth="jwtAccountAdminA", op_key="lblFed",
                         terminal_codes=(200,), require_operation=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# RBACLBL-IAMTYPE-ACCEPTED — matchLabels rule on an iam content type (iam.role) is
# ACCEPTED at Create. The unified label-scope model makes every iam content type
# label-selectable (feed-gate reversed): iam.role/user/serviceAccount/group/
# accessBinding materialize iam-direct same-DB from own-table labels, so a
# matchLabels rule on them is a valid, reconciler-driven grant (no longer an
# eternal-PENDING dead-end).
# verifies: a matchLabels rule on an iam content type is accepted at Role.Create.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="RBACLBL-IAMTYPE-ACCEPTED",
    title="ARM_LABELS rule on iam content type iam.role → Role.Create accepted (feed-gate reversed)",
    classes=["RBAC", "RULES", "LABELS", "HAPPY"],
    priority="P0",
    steps=[
        Step(
            name="create-label-role-iamtype",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": "rbac_lbl_iamtype_{{runId}}",
                "description": "newman ARM_LABELS iam-content-type probe role",
                # ГЛАГОЛ — ЖИВОЙ ГЛАГОЛ ТИПА, А НЕ ЛЮБОЙ. Здесь стоял `get`: его
                # сняли с `iam.role` вместе с отношением без читателя (kacho#1922,
                # миграция 20260914120000_role_read_relation_leaves_the_catalog),
                # и операция отвечала «verbs: get is not a live verb of resource
                # role» (code 9, REFERENCE_MISSING). Кейс этого не видел: его не
                # гонял ни один конвейер службы, пока он стучался к краю. Предмет
                # кейса — приём matchLabels на типе iam, а не выбор глагола; живые
                # глаголы типа — `list`, `update`, `delete` (витрина каталога на
                # стенде), и `list` — тот, которым поимённо читается роль.
                "rules": [{
                    "module": "iam", "resources": ["role"],
                    "verbs": ["list"],
                    "matchLabels": {"env": "prod"},
                }],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_opLblIamType"),
            ],
        ),
        Step(
            name="poll-label-role-iamtype",
            method="GET",
            path="/operations/{{_opLblIamType}}",
            auth="jwtAccountAdminA",
            test_script=poll_op_done("_opLblIamType", out_id_var="lblIamTypeRoleId"),
        ),
        # УБОРКА. Роль заводится этим кейсом под `{{runId}}` и прежде не
        # сносилась вовсе: повторный прогон с тем же посевом получал
        # ALREADY_EXISTS на создании и читал его отказом приёма правила.
        # Идентификатор берётся из ЗАВЕРШЁННОЙ операции (`response.id`), а не из
        # предвыделенных метаданных — у упавшей операции он указывал бы на фантом.
        *reliable_delete("teardown-label-role-iamtype", "/iam/v1/roles/{{lblIamTypeRoleId}}",
                         auth="jwtAccountAdminA", op_key="lblIamType",
                         terminal_codes=(200,), require_operation=True),
    ],
))


# Все шаги — на собственный публичный фронт службы (e2e-flow.md §7а; см. шапку).
CASES = address_own_front(CASES, "собственный публичный REST-фронт службы; без него у "
                                 "ресурса нет адреса на автономном стенде, и кейс "
                                 "проверял бы край платформы вместо предмета")
