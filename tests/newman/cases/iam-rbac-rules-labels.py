# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

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
"""

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
        "  postman.setNextRequest(pm.info.requestName);",
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
                "rules": [{
                    "module": "compute", "resources": ["instance"],
                    "verbs": ["get", "create"],
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
            test_script=poll_op_done("_opLblFed"),
        ),
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
                "rules": [{
                    "module": "iam", "resources": ["role"],
                    "verbs": ["get"],
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
            test_script=poll_op_done("_opLblIamType"),
        ),
    ],
))
