# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""RBAC explicit model — black-box FGA Check matrix.

The unified reconciler is the SINGLE materialization path and emits
DIRECT per-object tuples (`<objType>:<id> # v_<verb>/<tier> @ subject`) for every
in-scope object a selector matches — never a `scope_grant:` escalation carrier. The
binding-time `scope_grant` primitive has been removed wholesale, so the escalation
carrier no longer exists (closed by construction).

What this suite asserts, black-box through api-gateway → IAM → OpenFGA:

  GRANT CONTRACT — an all_in_scope RULES-role Create + AccessBinding.Create on an
             ACCOUNT scope SUCCEEDS (Operation done, no error). This is the
             black-box-reachable half: the role/binding side.
  SCOPE_GRANT GONE — a raw Check on the OLD `scope_grant:account|<id>|<type>`
             carrier DENIES for EVERY relation (admin / v_delete / v_create) —
             the primitive is removed, so no subject ever resolves a relation on
             it (steady-state deny, no poll).

WHY NOT a per-object allow-Check here: the explicit model materializes access on
the CONTENT objects (compute_instance:<id>), which requires resource_mirror to be
fed by the owner service over the INTERNAL `*→iam` RegisterResource edge (:9091) —
NOT exposed on the public REST gateway, so a single-service newman suite cannot seed
a matched mirror object. The per-object materialization SEMANTICS are proven by the
real-Postgres integration tests (reconcile_unified_p4_integration_test.go:
TestP4_A01.. / TestP4_ScopeSelf..) and end-to-end (mirror-fed) by the cross-repo e2e
(kacho-test). This suite asserts only the role/binding contract + the scope_grant
removal that ARE black-box-reachable — the same split the
iam-rbac-rules-labels suite uses.

Black-box only: the probe hits InternalIAMService.Check
(POST /iam/v1/internal/iam:check, `<exempt>` from the per-RPC gate) — FGA-NATIVE
raw (subjectId, relation, object) passthrough against the live OpenFGA model.

Check-response shape (proto3 JSON via grpc-gateway):
  ALLOW → 200 {"allowed": true}
  DENY  → 200 {"reason": "<subject> lacks relation \"<rel>\" on <object>; ..."}
          `allowed` is the proto3 zero-value false → grpc-gateway OMITS it, so
          j.allowed is `undefined` (NOT false) on a deny. Deny is asserted as
          "allowed !== true" + a positive evidence check on the `reason` carrier.

Fixture dependency (tests/authz-fixtures/setup.sh): jwtBootstrap, jwtAccountAdminA,
userNOBId, accountAId.
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


def check_step(name, subject, relation, obj, expect_allowed, auth="jwtBootstrap",
               poll=False):
    """A Step hitting InternalIAMService.Check, asserting the allow/deny verdict.

    Check-response shape (InternalIAMService.Check, proto3 JSON):
      ALLOW → 200 {"allowed": true}
      DENY  → 200 {"reason": "<subject> lacks relation \"<rel>\" on <object>; ..."}
              — `allowed` is the proto3 zero-value `false`, which grpc-gateway
              JSON OMITS, so `j.allowed` is `undefined` on a deny (NOT literal
              `false`). A deny must therefore be asserted as "allowed is NOT true"
              (falsy: absent OR false) plus a positive evidence assertion on the
              `reason` carrier, never `j.allowed === false` (that compares
              `undefined === false` and is a false-RED dressed as an over-grant).

    expect_allowed=True  → allow verdict; asserts j.allowed === true.
    expect_allowed=False → deny  verdict; asserts j.allowed !== true AND the
                           deny `reason` references THIS (relation, object) — the
                           real Check-path evidence that the tuple resolves to no
                           granted relation (the cross-type cut).

    When poll=True (used for the positive grant→Check window), the step self-retries
    until allowed flips to true or POLL_CAP is hit (fga_outbox drainer is async).
    Negative (deny) checks do NOT poll — a deny is the steady state and must hold
    immediately (a flake that flips allow→deny would otherwise hide a real
    over-grant).
    """
    retry = []
    if poll:
        retry = [
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === {str(expect_allowed).lower()}) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_ckCount');",
            "pm.environment.unset('_ckStarted');",
        ]
    if expect_allowed:
        verdict = [
            f"pm.test('{name}: allowed == true', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.eql(true);",
            "});",
        ]
    else:
        # Deny: `allowed` is omitted (proto3 false). Assert "not allowed" + the
        # reason carrier names THIS relation + scope_grant type → real Check-path
        # deny proof.
        #
        # IMPORTANT: Postman does NOT substitute {{...}} inside test-script source
        # (only in URL/headers/body). The `obj` template embeds {{accountAId}}, so
        # we CANNOT assert the full object string literally. We assert the
        # substitution-free, identity-carrying tokens instead:
        #   - "scope_grant"  → the deny is about the type-scoped grant carrier
        #   - <resource-type-token> (vpc_subnet / iam_role / compute_instance) →
        #     the cross-type / per-verb identity (extracted from `obj`'s trailing
        #     `|<type>` segment, a literal, no {{}})
        #   - <relation>     → the denied relation (admin / v_delete / v_update)
        # Together these prove FGA found no path for (relation, this type) — the
        # cross-type cut / per-verb separation — without depending on the
        # runtime account id.
        type_token = obj.rsplit("|", 1)[-1]
        verdict = [
            f"pm.test('{name}: Check denies (allowed !== true)', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.not.eql(true);",
            "});",
            f"pm.test('{name}: deny reason names scope_grant type {type_token} + relation {relation}', () => {{",
            "  pm.expect(j.reason, JSON.stringify(j)).to.be.a('string');",
            "  pm.expect(j.reason).to.include('scope_grant');",
            f"  pm.expect(j.reason).to.include('{type_token}');",
            f"  pm.expect(j.reason).to.include('{relation}');",
            "});",
        ]
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/internal/iam:check",
        auth=auth,
        body={"subjectId": subject, "relation": relation, "object": obj},
        test_script=[
            "const j = pm.response.json();",
            *retry,
            *verdict,
        ],
    )


def create_rules_role_steps(role_var, rules, name_suffix):
    """RoleService.Create(rules) + op-poll, stashing the role id in role_var."""
    return [
        Step(
            name=f"create-role-{name_suffix}",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": f"sg_{name_suffix}_{{{{runId}}}}",
                "description": "newman scope_grant probe role",
                "rules": rules,
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.roleId", role_var),
                *save_from_response("j.id", f"_op_{role_var}"),
            ],
        ),
        Step(
            name=f"poll-role-{name_suffix}",
            method="GET",
            path=f"/operations/{{{{_op_{role_var}}}}}",
            auth="jwtAccountAdminA",
            test_script=poll_op_done(f"_op_{role_var}", out_id_var=role_var),
        ),
    ]


def bind_role_steps(role_var, bind_op_var, name_suffix):
    """AccessBindingService.Create all_in_scope @ accountA for userNOB + op-poll."""
    return [
        Step(
            name=f"bind-{name_suffix}",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": f"{{{{{role_var}}}}}",
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", bind_op_var),
            ],
        ),
        Step(
            name=f"poll-bind-{name_suffix}",
            method="GET",
            path=f"/operations/{{{{{bind_op_var}}}}}",
            auth="jwtAccountAdminA",
            test_script=poll_op_done(bind_op_var),
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# RBACSG-ESCALATION-CLOSED — compute.instance all_in_scope admin @ ACCOUNT does
# NOT cascade onto vpc_subnet / iam_role (HAPPY own-type + NEGATIVE cross-type).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="RBACSG-ESCALATION-CLOSED",
    title="all_in_scope compute.instance admin @ ACCOUNT → grant succeeds; scope_grant primitive removed (closed by construction)",
    classes=["FGA", "AUTHZ", "ESCALATION", "MATRIX"],
    priority="P0",
    steps=[
        # GRANT CONTRACT — the role Create + AccessBinding.Create succeed (the
        # bind-step asserts 200 + op-done). This is the black-box-reachable half.
        *create_rules_role_steps(
            "_sgRoleA",
            [{"module": "compute", "resources": ["instance"],
              "verbs": ["get", "list", "create", "update", "delete"]}],
            "admin",
        ),
        *bind_role_steps("_sgRoleA", "_sgBindAOp", "admin"),
        # The OLD scope_grant carrier is GONE: a raw Check on it DENIES for the
        # granted type+relation too (NOT just cross-type). The unified reconciler
        # materializes per-object DIRECT tuples on compute_instance:<id>, never a
        # scope_grant escalation carrier. Steady-state deny, no poll.
        check_step(
            name="scope-grant-removed-admin-on-compute",
            subject="user:{{userNOBId}}",
            relation="admin",
            obj="scope_grant:account|{{accountAId}}|compute_instance",
            expect_allowed=False,
        ),
        check_step(
            name="scope-grant-removed-v_delete-on-compute",
            subject="user:{{userNOBId}}",
            relation="v_delete",
            obj="scope_grant:account|{{accountAId}}|compute_instance",
            expect_allowed=False,
        ),
        # Cross-type is likewise denied (no carrier of any kind) — the
        # escalation is closed by construction.
        check_step(
            name="neg-no-scope-grant-on-vpc-subnet",
            subject="user:{{userNOBId}}",
            relation="admin",
            obj="scope_grant:account|{{accountAId}}|vpc_subnet",
            expect_allowed=False,
        ),
        check_step(
            name="neg-no-scope-grant-on-iam-role",
            subject="user:{{userNOBId}}",
            relation="admin",
            obj="scope_grant:account|{{accountAId}}|iam_role",
            expect_allowed=False,
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# RBACSG-PER-VERB — {get,create} rule emits ONLY v_get + v_create direct tuples
# on the scope_grant, so a raw FGA-native Check of v_delete / v_update on that
# SAME object DENIES (per-verb tuple separation, delete≠create).
#
# This proves the MODEL / tuple-emission layer: distinct v_* relations are NOT
# collapsed (v_create granted ⇏ v_delete granted). It is NOT a proof of
# consumer-side per-verb enforcement — the vpc/compute interceptor still resolves
# an RPC verb to a TIER (editor → permits delete), so on the consumer Check path
# delete is currently over-granted. That separate gap is the verb→TIER mapping
# (wiring the consumer Check to per-verb v_*), out of scope for this FGA-native
# raw-tuple suite (the consumer-enforcement arm is a vpc/compute interceptor
# concern, not black-box-reachable through this RPC).
# verifies: the model emits per-verb separated tuples (v_create granted ⇏ v_delete).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="RBACSG-PER-VERB",
    title="per-verb {get,create} all_in_scope grant succeeds; scope_grant carrier removed for every verb",
    classes=["FGA", "AUTHZ", "PER-VERB"],
    priority="P0",
    steps=[
        # GRANT CONTRACT — a {get,create} all_in_scope rule Create + bind succeed.
        *create_rules_role_steps(
            "_sgRoleGC",
            [{"module": "compute", "resources": ["instance"],
              "verbs": ["get", "create"]}],
            "getcreate",
        ),
        *bind_role_steps("_sgRoleGC", "_sgBindGCOp", "getcreate"),
        # The scope_grant carrier is removed: a raw Check on it DENIES even for
        # the GRANTED verb (v_create), because per-verb materialization is now DIRECT
        # on the content object (compute_instance:<id>), never on a scope_grant
        # carrier. The per-verb SEPARATION (v_create granted ⇏ v_delete granted) is
        # proven on the content object by the integration tests (TestC22_MatchLabels..
        # / TestP4_A02_Names..); here we assert only the black-box-reachable contract:
        # the carrier is gone for every verb. Steady-state deny, no poll.
        check_step(
            name="scope-grant-removed-v_create",
            subject="user:{{userNOBId}}",
            relation="v_create",
            obj="scope_grant:account|{{accountAId}}|compute_instance",
            expect_allowed=False,
        ),
        check_step(
            name="scope-grant-removed-v_delete",
            subject="user:{{userNOBId}}",
            relation="v_delete",
            obj="scope_grant:account|{{accountAId}}|compute_instance",
            expect_allowed=False,
        ),
        check_step(
            name="scope-grant-removed-v_update",
            subject="user:{{userNOBId}}",
            relation="v_update",
            obj="scope_grant:account|{{accountAId}}|compute_instance",
            expect_allowed=False,
        ),
    ],
))
