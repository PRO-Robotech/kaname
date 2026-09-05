# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

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


def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are served
    ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design (ban #6).
    gen.py emits {{baseUrl}}<path>; without this override the FGA-Check probe hits the
    public port → the edge's routing error {"code":5,"message":"Not Found"} → the first
    pm.response.json() parses but carries no result.
    Mirrors label-revoke-iam.py::_internal_url_override. internalBaseUrl is injected at
    runtime by the newman harness (--env-var); a MISSING value is a broken harness, not a legal mode, so the
    guard ASSERTS it (RED, naming the variable) before skipping — see
    gen.py::require_env_url."""
    return require_env_url(
        "internalBaseUrl", path,
        "internal-only Check probe — /iam/v1/internal/* is served ONLY by the "
        "cluster-internal REST listener")


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
            "  const _ipd2 = Date.now(); while (Date.now() - _ipd2 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
            "  pm.execution.setNextRequest(pm.info.requestName);",
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
        pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
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
    """AccessBindingService.Create all_in_scope @ accountA for userNOB + op-poll.

    The binding id is captured (not just the operation id) so revoke_binding_steps can
    take it back — see there for why leaving it behind is a cross-suite leak.
    """
    acb_var = f"{bind_op_var}Acb"
    return [
        Step(
            name=f"bind-{name_suffix}",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": f"{{{{{role_var}}}}}",
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", bind_op_var),
                *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var),
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


def revoke_binding_steps(bind_op_var, name_suffix):
    """Take the grant back — this case grants a SHARED fixture subject on the SHARED account.

    `userNOBId` is the platform's designated NO-GRANT subject: the vpc AUTHZ-*-LS-*-NOB and
    iam IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY leak-guards all assert "NOB sees nothing".
    Every run of this suite bound a compute.instance role to NOB on {{accountAId}} and never
    revoked it, so NOB became legitimately authorized and stayed that way — permanently, and
    for every OTHER suite. (kacho-iam#276 is that pollution. The runner's shared exemption
    list, which used to absorb it, was REMOVED whole — producing it is now simply red.)

    Same discipline as the binding teardown in iam-rbac-subjects: 403 is a propagation window,
    NOT a terminal state — retry past it, and let a persistent denial fail honestly rather than
    silently leave the grant standing. The custom ROLE this case creates is left in place: a
    role with no binding grants nothing, and role ids are runId-scoped.
    """
    # Значение вызывающего становится ЧАСТЬЮ ИМЕНИ переменной прогона, а имя не
    # экранируется: оно либо годно, либо порождаемый скрипт не разбирается — и
    # newman запишет это в testScripts, отчитавшись НУЛЁМ упавших утверждений.
    # То же имя уезжает и в АДРЕС (`{{…}}`), который JavaScript'ом не является
    # вовсе, — экранировать одну сторону значит развести писателя и читателя
    # молча. Поэтому исход — проверка годности при генерации (#1220).
    acb_var = js_name(f"{bind_op_var}Acb",
                      where="iam/iam-rbac-scope-grant/revoke_binding_steps/bind_op_var")
    return [
        poll_request_until_status(
            name=f"revoke-{name_suffix}",
            method="DELETE",
            path="/iam/v1/accessBindings/{{" + acb_var + "}}",
            auth="jwtAccountAdminA",
            expect_code=200,
            retry_on=(403,),
            test_script=[
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"pm.environment.unset('_{acb_var}RevOp');",
                "pm.test('teardown: NOB grant revoked (200) or already gone (404) — a persistent 403 leaves the "
                "no-grant leak-guard subject authorized for every later suite', "
                "() => pm.expect(pm.response.code, JSON.stringify(j)).to.be.oneOf([200, 404]));",
                f"if (pm.response.code === 200 && j && j.id) pm.environment.set('_{acb_var}RevOp', j.id);",
            ],
        ),
        Step(
            name=f"revoke-await-{name_suffix}",
            method="GET",
            path="/operations/{{_" + acb_var + "RevOp}}",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{acb_var}RevStarted') !== pm.info.requestName) {{ pm.environment.set('_{acb_var}RevCount', '0'); pm.environment.set('_{acb_var}RevStarted', pm.info.requestName); }}",
            ],
            test_script=[
                f"if (!pm.environment.get('_{acb_var}RevOp')) {{ return; }}",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"const c = parseInt(pm.environment.get('_{acb_var}RevCount') || '0', 10);",
                f"if (j && !j.done && c < {POLL_CAP}) {{",
                f"  pm.environment.set('_{acb_var}RevCount', String(c + 1));",
                "  const _rd = Date.now(); while (Date.now() - _rd < 500) void 0;",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                f"pm.environment.unset('_{acb_var}RevCount'); pm.environment.unset('_{acb_var}RevStarted');",
                "pm.test('teardown: revoke operation committed', () => pm.expect(j && j.done, JSON.stringify(j)).to.eql(true));",
            ],
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
        # `create` из набора СНЯТ: на `compute_instance` он инертен вдвойне —
        # пообъектного `v_create` тип не объявляет (создание авторизуется ярусом
        # записи на родителе), а ярус здесь и так `admin` от `delete`. То есть
        # глагол не менял ни одного кортежа и держался только по инерции набора.
        *create_rules_role_steps(
            "_sgRoleA",
            [{"module": "compute", "resources": ["instance"],
              "verbs": ["get", "list", "update", "delete"]}],
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
        # Give the grant back: userNOB is the shared no-grant leak-guard subject and this
        # binding lives in the SHARED account (see revoke_binding_steps).
        *revoke_binding_steps("_sgBindAOp", "admin"),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# RBACSG-PER-VERB — a {get,update} rule materializes per-verb tuples DIRECTLY on
# the content object, never on a scope_grant carrier, so a raw FGA-native Check on
# that carrier DENIES for every verb — including the granted ones.
#
# The rule pairs one READ verb with one WRITE verb, and both are verbs the TYPE
# declares, so both actually materialize. It used to pair get with `create`, which
# on `compute_instance` materializes NO per-object tuple at all — that relation is
# declared only by `registry_registry` (creating a thing is not an operation on the
# thing; the question is asked of the parent). A verb that emits nothing made the
# case's own name ("per-verb") describe one verb while claiming two. The carrier
# contract asserted below does not depend on which verbs those are, which is exactly
# why the wrong pair could sit here unnoticed.
#
# This proves the MODEL / tuple-emission layer: distinct v_* relations are NOT
# collapsed (a granted verb ⇏ v_delete granted). It is NOT a proof of
# consumer-side per-verb enforcement — the vpc/compute interceptor still resolves
# an RPC verb to a TIER (editor → permits delete), so on the consumer Check path
# delete is currently over-granted. That separate gap is the verb→TIER mapping
# (wiring the consumer Check to per-verb v_*), out of scope for this FGA-native
# raw-tuple suite (the consumer-enforcement arm is a vpc/compute interceptor
# concern, not black-box-reachable through this RPC).
# verifies: the model emits per-verb separated tuples (a granted verb ⇏ v_delete).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="RBACSG-PER-VERB",
    title="per-verb {get,update} all_in_scope grant succeeds; scope_grant carrier removed for every verb",
    classes=["FGA", "AUTHZ", "PER-VERB"],
    priority="P0",
    steps=[
        # GRANT CONTRACT — a {get,update} all_in_scope rule Create + bind succeed.
        *create_rules_role_steps(
            "_sgRoleGC",
            [{"module": "compute", "resources": ["instance"],
              "verbs": ["get", "update"]}],
            "getcreate",
        ),
        *bind_role_steps("_sgRoleGC", "_sgBindGCOp", "getcreate"),
        # The scope_grant carrier is removed: a raw Check on it DENIES for every
        # relation, because per-verb materialization is now DIRECT
        # on the content object (compute_instance:<id>), never on a scope_grant
        # carrier. The per-verb SEPARATION (a granted verb ⇏ v_delete granted) is
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
        *revoke_binding_steps("_sgBindGCOp", "getcreate"),
    ],
))
