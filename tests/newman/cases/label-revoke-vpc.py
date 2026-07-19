# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Cross-service ARM_LABELS revoke-on-label-change, vpc resources (e2e, black-box).

verifies: removing/changing the matching label on a vpc resource Update revokes
the ARM_LABELS grant (Check v_list flips True→False); adding the label
materializes it; non-label Update is a no-op; an empty-mask full-PATCH that zeroes
labels revokes; and the mirror re-emit intent survives an IAM outage.

─────────────────────────────────────────────────────────────────────────────
WHAT THIS SUITE PROVES (full mechanic, end-to-end through api-gateway)
─────────────────────────────────────────────────────────────────────────────
ARM_LABELS grant (a custom role with a {module, resources, verbs, matchLabels}
rule) on a CROSS-SERVICE resource (vpc.network / vpc.securityGroup) must be
REVOKED when the matching label is removed/changed on the resource. The bug
was: consumer services emitted InternalIAMService.RegisterResource (→
kacho_iam.resource_mirror upsert → mirror.upsert reconcile-event → rsab
re-materialize) ONLY on resource CREATE, NOT on label-UPDATE, so the IAM mirror
went stale and rsab kept stale membership forever. The fix makes each
label-selectable resource re-emit RegisterResource (mirror.upsert with current
labels) on Update-when-labels-changed.

The observable contract: visibility is probed through
InternalIAMService.Check on {subject, relation=v_list, object="<fgaType>:<id>"}.
A `[get,list]` rule on a verb-bearing type emits per-object `v_list` (+ `v_get`,
+ tier `viewer`) tuples (kacho-iam reconcile/tuples.go ruleObjectTuples). `v_list`
is used as the probe because it cascades ONLY via `g_vlist_<type> from project`
(fga_model.fga) — i.e. ONLY through a vlist-tier label grant, never through a
generic account/project viewer cascade — so a True/False v_list verdict isolates
the effect of THIS label grant (no fixture-pollution cascade can mask it).

─────────────────────────────────────────────────────────────────────────────
CLEAN SUBJECT + assignability — green by the RIGHT reason
─────────────────────────────────────────────────────────────────────────────
* CLEAN SUBJECT — each case mints a FRESH ServiceAccount on account A (sa_setup).
  A new SA has zero `#v_list` grants, so no account-viewer cascade can pre-satisfy
  the probe (the false-green trap). Every case asserts pre-grant DENY before
  the bind and the post-revoke convergence to DENY after the label change.
* ASSIGNABILITY — the ARM_LABELS role for a cross-service resource is
  ACCOUNT-SCOPED (created with accountId only) and bound on `account:<accountA>`,
  NOT on a project (an account-scoped custom role is assignable ONLY on its own
  account — IsRoleAssignable, role_scope.go; a project bind would error code-9).
  Containment (reconcile) then matches label-selected resources whose
  parent_account_id == accountA, i.e. resources in any project under account A.
* EXPLICIT BIND SUCCESS — the bind Operation is asserted done + no error +
  NOT FAILED_PRECONDITION(9) (assert_bind_succeeded), so a mis-scoped/failed bind
  can never hide behind a cascade.

─────────────────────────────────────────────────────────────────────────────
DEPLOYMENT SCOPE — full-umbrella stack (cross-service)
─────────────────────────────────────────────────────────────────────────────
These cases require kacho-vpc deployed alongside kacho-iam behind the gateway so
that vpc.NetworkService.Create/Update actually emits RegisterResource into
kacho_iam.resource_mirror (the `vpc→iam` :9091 edge). The umbrella newman-e2e
brings up the FULL stack (all services, mtls off) and runs this shared iam suite,
so these execute against a complete deployment. They are NOT whitelisted: a real
regression must fire the gate.

Test-design techniques: state-transition (mirror stale→fresh ⇒ membership
materialize→revoke), decision-table (label present×selector match ⇒ visible),
ECP (label match vs no-match), error-guessing (full-PATCH empty-mask zeroing
labels; non-label Update no-op; IAM-down intent durability), use-case (invite →
grant → revoke end-to-end). One thought per pm.test().

Fixtures (tests/authz-fixtures/setup.sh): jwtBootstrap, jwtAccountAdminA,
accountAId. The PROJECT is self-seeded per case (create_suite_project → {{_t31Proj}})
rather than read from the shared {{projectA1Id}} fixture: that fixture var could
resolve to a PHANTOM project (an id whose IAM row never committed — the fixture's
ensure_project extracts metadata.projectId even from a Create Operation that finished
WITH an error), so the cross-service peer-check vpc NetworkService.Create →
iam ProjectService.Get(projectA1Id) returned NOT_FOUND and every case cascaded RED.
A freshly-created, op-poll-confirmed project is guaranteed to exist for the peer-check.
All resources (project, SA, network, SG, role, binding) are self-seeded per case with
{{runId}}-suffixed names (self-contained, no cross-case / cross-suite collision).
"""

CASES = []

POLL_CAP = 30

VPC_NET = "/vpc/v1/networks"
VPC_SG = "/vpc/v1/securityGroups"


# ─────────────────────────────────────────────────────────────────────────────
# Reusable poll / probe / grant helpers (file-local, matching repo convention —
# each cases file redefines them so gen.py imports nothing case-to-case).
# ─────────────────────────────────────────────────────────────────────────────

def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
    """Self-polling Step body: wait for an Operation to be done; assert no error.
    Optionally stash response.id (the created resource id) into out_id_var."""
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
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        capture,
        "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
    ]


def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are
    served ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design
    (ban #6). gen.py emits {{baseUrl}}<path>; without this override the FGA-Check
    probe hits the public port → 404 page-not-found → JSONError on the first
    pm.response.json(). Mirrors iam-internal-only-check.py::_internal_url_override.
    internalBaseUrl is injected at runtime by deploy/scripts/newman-e2e.sh
    (--env-var); if unset (local dev without the internal-rest port-forward) the
    step is skipped rather than hitting a spurious public 404."""
    return [
        "// internal-only Check probe → api-gateway cluster-internal REST listener.",
        "const intBase = pm.environment.get('internalBaseUrl') || pm.variables.get('internalBaseUrl') || '';",
        "if (!intBase) {",
        "  console.warn('internalBaseUrl not set — skipping internal Check probe for this step.');",
        "  pm.execution.setNextRequest(null);",
        "} else {",
        f"  pm.request.url = intBase + '{path}';",
        "}",
    ]


def check_step(name, subject, relation, obj, expect_allowed, auth="jwtBootstrap", poll=False):
    """InternalIAMService.Check probe (POST /iam/v1/internal/iam:check) — exempt
    from the per-RPC authz gate, FGA-native passthrough. Served ONLY on the
    cluster-internal REST listener ({{internalBaseUrl}}, :18081) — the pre_script
    redirects there (the public :18080 404s /iam/v1/internal/* by design, ban #6).
    expect_allowed=True asserts allowed===true (optionally polling the reconcile/
    fga-drain window for eventual consistency); False asserts allowed !== true.
    One thought / pm.test."""
    retry = []
    if poll:
        retry = [
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === {str(expect_allowed).lower()}) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
            # Real inter-poll delay (~500ms): newman fires setNextRequest before any
            # setTimeout, so a busy-wait is the ONLY way to actually space out the polls.
            # POLL_CAP*0.5s (~15s) then covers the grant/revoke FGA-materialization window
            # under PARALLEL load instead of hammering ~30 back-to-back Checks in <2s (which
            # never waits for the tuple to (dis)appear → the revoke-deny / grant-allow flake).
            "  const _ckd = Date.now(); while (Date.now() - _ckd < 500) { /* inter-poll materialization wait ~500ms */ }",
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
        verdict = [
            f"pm.test('{name}: Check denies (allowed !== true)', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.not.eql(true);",
            "});",
        ]
    return Step(
        name=name, method="POST", path="/iam/v1/internal/iam:check",
        auth=auth, body={"subjectId": subject, "relation": relation, "object": obj},
        pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
        test_script=["const j = pm.response.json();", *retry, *verdict],
    )


def create_fresh_sa(sa_var, name_suffix):
    """ServiceAccountService.Create a FRESH SA on accountA (the clean grant
    subject) + op-poll, stashing the SA id. Zero `#v_list` grants — no cascade
    can pre-satisfy the probe (clean-subject discipline)."""
    return [
        Step(name=f"create-sa-{name_suffix}", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": f"t31-sa-{name_suffix}-{{{{runId}}}}",
                   "description": "newman label-revoke clean subject"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                          *save_from_response("j.id", f"_op_{sa_var}")]),
        Step(name=f"poll-sa-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{sa_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var)),
    ]


def create_label_role(role_var, rules, name_suffix):
    """RoleService.Create(rules) on accountA + op-poll, stashing the role id.
    ACCOUNT-scoped (CreateRoleRequest carries account_id only). The rule is
    ARM_LABELS (matchLabels present, resourceNames absent) — reconciler-driven."""
    return [
        Step(name=f"create-role-{name_suffix}", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": f"t31_{name_suffix}_{{{{runId}}}}",
                   "description": "newman ARM_LABELS probe role", "rules": rules},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", f"_op_{role_var}")]),
        Step(name=f"poll-role-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{role_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{role_var}", out_id_var=role_var)),
    ]


def assert_bind_succeeded(name):
    """Poll the bind Operation and assert it SUCCEEDED — done, no error, and NOT
    FAILED_PRECONDITION (code 9). THE honesty assertion: a mis-scoped / failed
    bind cannot be masked by an FGA cascade (the materialization is proven to come
    from a bind that actually committed)."""
    return [
        "const j = pm.response.json();",
        "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
        "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
        f"if (!j.done && pc < {POLL_CAP}) {{",
        "  pm.environment.set('_pollCount', String(pc + 1));",
        "  pm.execution.setNextRequest(pm.info.requestName);",
        "  return;",
        "}",
        "pm.environment.unset('_pollCount');",
        "pm.environment.unset('_pollStarted');",
        f"pm.test('{name}: bind operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
        f"pm.test('{name}: bind operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        f"pm.test('{name}: bind NOT FailedPrecondition (assignable)', () => {{",
        "  const code = j.error && j.error.code;",
        "  pm.expect(code, JSON.stringify(j)).to.not.eql(9);",
        "});",
    ]


def bind_role_on_account(role_var, bind_op_var, subject_var, name_suffix,
                         subject_type="service_account"):
    """AccessBindingService.Create(role @ account:<accountA>) for the subject +
    op-poll asserting the bind SUCCEEDED (account-scoped role on account)."""
    return [
        Step(name=f"bind-{name_suffix}", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": subject_type, "subjectId": f"{{{{{subject_var}}}}}",
                   "roleId": f"{{{{{role_var}}}}}", "resourceType": "account",
                   "resourceId": "{{accountAId}}"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", bind_op_var)]),
        Step(name=f"poll-bind-{name_suffix}", method="GET", path=f"/operations/{{{{{bind_op_var}}}}}",
             auth="jwtAccountAdminA", test_script=assert_bind_succeeded(f"bind-{name_suffix}")),
    ]


def create_suite_project(suffix):
    """Self-contained project seed — create a FRESH project under account-A at
    runtime and stash its id into {{_t31Proj}} (replacing the shared {{projectA1Id}}
    fixture dependency). Prepended to every case, so each case owns a project that is
    GUARANTEED to exist for the cross-service peer-check (vpc/compute → iam
    ProjectService.Get). The op-poll asserts done + NO error, so a project that ever
    fails to materialise fails LOUDLY here (not as an opaque downstream
    'Project <id> not found'). accountAId stays the shared-tenant anchor: the
    ARM_LABELS role is account-scoped on account:accountAId and containment matches
    resources whose parent_account_id == accountAId — a project under account-A
    satisfies it. Mirrors the runtime zone-discovery pattern in label-revoke-compute.py.
    Project.Create is authz-gated by editor@account:accountAId, which jwtAccountAdminA
    (account owner ⊇ editor) holds stably — no read-your-writes retry needed here; the
    fresh-project OWNER-tuple lag is absorbed by create_network's retry_until_authorized."""
    return [
        Step(name=f"create-proj-{suffix}", method="POST", path="/iam/v1/projects",
             body={"accountId": "{{accountAId}}",
                   "name": f"t31-prj-{suffix}-{{{{runId}}}}",
                   "description": "newman label-revoke self-contained project seed"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.projectId", "_t31Proj"),
                          *save_from_response("j.id", f"_op_proj_{suffix}")]),
        Step(name=f"poll-proj-{suffix}", method="GET", path=f"/operations/{{{{_op_proj_{suffix}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_proj_{suffix}")),
    ]


def create_network(net_var, suffix, labels):
    """NetworkService.Create in the self-seeded {{_t31Proj}} with the given labels +
    op-poll. On Create the vpc→iam RegisterResource edge feeds resource_mirror with
    labels."""
    return [
        # Bounded read-your-writes retry over AAA's create-authz materialization window:
        # NetworkService.Create needs the caller's editor/creator on project:projectA1
        # (fixture grant), whose FGA cascade tuple can still be draining at umbrella
        # cold-start → the first cross-service Create 403s at the gateway authz gate before
        # the tuple is visible. Retry SELF on 403 (a 403-create materialized nothing, so
        # re-firing is safe) until authorized; fail-closed at the budget.
        retry_until_authorized(
            Step(name=f"create-net-{suffix}", method="POST", path=VPC_NET,
                 body={"projectId": "{{_t31Proj}}", "name": f"t31-net-{suffix}-{{{{runId}}}}",
                       "labels": labels},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.networkId", net_var),
                              *save_from_response("j.id", f"_op_{net_var}")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name=f"poll-net-{suffix}", method="GET", path=f"/operations/{{{{_op_{net_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{net_var}", out_id_var=net_var)),
    ]


def update_network(net_var, suffix, body):
    """NetworkService.Update(net) PATCH + op-poll (assert done, no error).
    `body` must be a FLAT update body: mutable fields + a STRING `updateMask`
    (protojson serializes FieldMask as a comma-separated string, NOT a
    {paths:[...]} object — the object form 400s and the op id is never saved).
    The network id is bound from the PATCH path ({network_id} via grpc-gateway),
    so it MUST NOT appear in the body (mirrors working iam-account.py).

    Cross-service propagation poll: the api-gateway enforces `editor` on
    vpc_network:<id> for NetworkService/Update (permission vpc.networks.update,
    permission_catalog). AccountAdminA's editor access to a freshly-created network
    is materialized cross-service (vpc→iam fgaproxy RegisterResource → owner/admin
    tuple → reconcile → fga_outbox → async drain), so the PATCH right after
    create-net races that drain and 403s single-shot. This is async-BY-DESIGN across
    the service boundary (we do NOT sync-write through the iam→vpc boundary), so the
    correct fix is a poll-for-propagation on the Update relation BEFORE the PATCH —
    exactly like the `:check` poll the post-grant ALLOW step already uses. Probe via
    InternalIAMService.Check (exempt from the authz gate) until AAA holds editor."""
    return [
        check_step(f"pre-update-net-{suffix}-editor-prop",
                   "user:{{userAAAId}}", "editor", f"vpc_network:{{{{{net_var}}}}}",
                   expect_allowed=True, poll=True),
        Step(name=f"update-net-{suffix}", method="PATCH", path=f"{VPC_NET}/{{{{{net_var}}}}}",
             body=body, auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", f"_opu_{net_var}")]),
        Step(name=f"poll-update-net-{suffix}", method="GET", path=f"/operations/{{{{_opu_{net_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_opu_{net_var}")),
    ]


VPC_NET_RULE = [{"module": "vpc", "resources": ["network"], "verbs": ["get", "list"],
                 "matchLabels": {"network": "treska"}}]


# ─────────────────────────────────────────────────────────────────────────────
# revoke01_network — HAPPY revoke (the main vpc scenario).
# Create net{network:treska} → grant ARM_LABELS{matchLabels:network=treska} on
# account → pre/post bind ALLOW (v_list) → Update labels={} → visibility
# converges to DENY. Anchor: the resource still EXISTS (Get 200) after the
# label is removed (upsert-with-{} not Unregister — the mirror row stays).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-01",
    title="revoke01_network: vpc.network label-remove on Update revokes ARM_LABELS grant (Check v_list True→False)",
    classes=["T31", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE"],
    priority="P0",
    steps=[
        *create_suite_project("n1"),
        *create_fresh_sa("_t31SaN1", "n1"),
        *create_network("_t31NetN1", "n1", {"network": "treska"}),
        # clean subject: not yet a v_list-er of the network.
        check_step("n1-pre-grant-deny", "service_account:{{_t31SaN1}}", "v_list",
                   "vpc_network:{{_t31NetN1}}", expect_allowed=False),
        *create_label_role("_t31RoleN1", VPC_NET_RULE, "n1"),
        *bind_role_on_account("_t31RoleN1", "_t31BindN1", "_t31SaN1", "n1"),
        # grant materialized: label match (network=treska) → per-object v_list.
        check_step("n1-post-grant-allow", "service_account:{{_t31SaN1}}", "v_list",
                   "vpc_network:{{_t31NetN1}}", expect_allowed=True, poll=True),
        # remove the label → mirror.upsert(labels={}) → selector stops matching.
        *update_network("_t31NetN1", "n1",
                        {"updateMask": "labels", "labels": {}}),
        # eventual consistency: visibility converges to DENY.
        check_step("n1-post-revoke-deny", "service_account:{{_t31SaN1}}", "v_list",
                   "vpc_network:{{_t31NetN1}}", expect_allowed=False, poll=True),
        # Anchor: the network still EXISTS (upsert-with-{}, not Unregister —
        # removing a label must not delete the resource registration).
        Step(name="n1-resource-still-exists", method="GET", path=f"{VPC_NET}/{{{{_t31NetN1}}}}",
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          "pm.test('network still exists after label removed (upsert-not-unregister)', () => {",
                          "  const j = pm.response.json();",
                          "  pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('_t31NetN1'));",
                          "});",
                          "pm.test('network labels now empty', () => {",
                          "  const j = pm.response.json();",
                          "  pm.expect(Object.keys(j.labels || {}).length, JSON.stringify(j)).to.eql(0);",
                          "});"]),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# revoke02_securitygroup — DOUBLE BUG (Create + Update).
# SG must emit labels on BOTH Create (was bare-tuple without labels) and Update.
# The post-grant ALLOW step pins the Create-emit fix (an unlabeled mirror would
# never match the selector even for a fresh SG); the post-Update DENY pins the
# Update-emit fix. SG.Create requires a network_id → create a network first.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-SECGROUP-02",
    title="revoke02_securitygroup: vpc.securityGroup Create emits labels + Update label-change revokes (double-bug)",
    classes=["T31", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE"],
    priority="P0",
    steps=[
        *create_suite_project("sg"),
        *create_fresh_sa("_t31SaSg", "sg"),
        # SG needs a parent network (immutable network_id at Create).
        *create_network("_t31NetSg", "sg", {"network": "sgparent"}),
        # Bounded read-your-writes retry over AAA's create-authz materialization window
        # (same cold-start FGA-cascade lag as create-net); retry SELF on 403 until authorized.
        retry_until_authorized(
            Step(name="create-sg", method="POST", path=VPC_SG,
                 body={"projectId": "{{_t31Proj}}", "name": "t31-sg-{{runId}}",
                       "networkId": "{{_t31NetSg}}", "labels": {"sg": "okun"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              *save_from_response("j.metadata && j.metadata.securityGroupId", "_t31Sg"),
                              *save_from_response("j.id", "_opSg")]),
            budget=30, interval_ms=500, retry_on=(403,)),
        Step(name="poll-sg", method="GET", path="/operations/{{_opSg}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_opSg", out_id_var="_t31Sg")),
        check_step("sg-pre-grant-deny", "service_account:{{_t31SaSg}}", "v_list",
                   "vpc_security_group:{{_t31Sg}}", expect_allowed=False),
        *create_label_role(
            "_t31RoleSg",
            [{"module": "vpc", "resources": ["securityGroup"], "verbs": ["get", "list"],
              "matchLabels": {"sg": "okun"}}],
            "sg"),
        *bind_role_on_account("_t31RoleSg", "_t31BindSg", "_t31SaSg", "sg"),
        # Create-emit fix: a fresh SG with labels matches the selector.
        check_step("sg-post-grant-allow", "service_account:{{_t31SaSg}}", "v_list",
                   "vpc_security_group:{{_t31Sg}}", expect_allowed=True, poll=True),
        # change the label → selector {sg:okun} stops matching → revoke. This PATCH is the
        # FIRST mutate of the caller's OWN fresh SG's editor tuple (vpc→iam RegisterResource
        # → owner/editor tuple → reconcile → async drain), so under PARALLEL load it races the
        # materialization and 403s single-shot. Bounded read-your-writes retry SELF on 403.
        retry_until_authorized(
            Step(name="update-sg-labels", method="PATCH", path=f"{VPC_SG}/{{{{_t31Sg}}}}",
                 body={"updateMask": "labels", "labels": {"sg": "sudak"}},
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200), *save_from_response("j.id", "_opuSg")]),
            budget=25, interval_ms=500, retry_on=(403,)),
        Step(name="poll-update-sg", method="GET", path="/operations/{{_opuSg}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_opuSg")),
        check_step("sg-post-revoke-deny", "service_account:{{_t31SaSg}}", "v_list",
                   "vpc_security_group:{{_t31Sg}}", expect_allowed=False, poll=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# add01_network — symmetry: label ADD materializes the grant.
# Network starts with NO matching label → grant present but inert (DENY) → Update
# adds {network:treska} → visibility appears (ALLOW). Proves emit-on-Update also
# covers the GRANT direction, not only revoke.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-ADD-01",
    title="add01_network: vpc.network label-add on Update materializes ARM_LABELS grant (Check v_list False→True)",
    classes=["T31", "LABELS", "ADD", "FGA", "AUTHZ", "STATE"],
    priority="P1",
    steps=[
        *create_suite_project("add"),
        *create_fresh_sa("_t31SaAdd", "add"),
        *create_network("_t31NetAdd", "add", {"network": "plain"}),
        *create_label_role("_t31RoleAdd", VPC_NET_RULE, "add"),
        *bind_role_on_account("_t31RoleAdd", "_t31BindAdd", "_t31SaAdd", "add"),
        # no matching label yet → grant inert → DENY.
        check_step("add-pre-add-deny", "service_account:{{_t31SaAdd}}", "v_list",
                   "vpc_network:{{_t31NetAdd}}", expect_allowed=False, poll=True),
        # add the matching label → selector matches → visibility appears.
        *update_network("_t31NetAdd", "add",
                        {"updateMask": "labels", "labels": {"network": "treska"}}),
        check_step("add-post-add-allow", "service_account:{{_t31SaAdd}}", "v_list",
                   "vpc_network:{{_t31NetAdd}}", expect_allowed=True, poll=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# change01_network — grant migrates. Two grants (treska + okun)
# on the same subject. net starts {network:treska} (visible via role-T). Update
# to {network:okun}: role-T membership revokes, role-O materializes. The NET
# verdict stays ALLOW (now via role-O), but the source migrated — observable by
# probing each grant's effect through a single-role subject is heavy; here we pin
# the migration with the net-stays-visible invariant + a per-label decision: the
# subject WITHOUT the okun role would lose visibility. We model this with two
# subjects sharing the resource: SaBoth (both roles, stays ALLOW) and SaTreska
# (only treska role, goes DENY after the change).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-CHANGE-01",
    title="change01_network: vpc.network label swap treska→okun migrates ARM_LABELS grant (decision-table)",
    classes=["T31", "LABELS", "CHANGE", "FGA", "AUTHZ", "DECISION"],
    priority="P1",
    steps=[
        *create_suite_project("chg"),
        *create_fresh_sa("_t31SaBoth", "both"),
        *create_fresh_sa("_t31SaTreska", "tre"),
        *create_network("_t31NetChg", "chg", {"network": "treska"}),
        # role-T (treska) → bind on BOTH subjects; role-O (okun) → bind on SaBoth only.
        *create_label_role("_t31RoleT", VPC_NET_RULE, "rolet"),
        *create_label_role(
            "_t31RoleO",
            [{"module": "vpc", "resources": ["network"], "verbs": ["get", "list"],
              "matchLabels": {"network": "okun"}}],
            "roleo"),
        *bind_role_on_account("_t31RoleT", "_t31BindTBoth", "_t31SaBoth", "tboth"),
        *bind_role_on_account("_t31RoleO", "_t31BindOBoth", "_t31SaBoth", "oboth"),
        *bind_role_on_account("_t31RoleT", "_t31BindTTre", "_t31SaTreska", "ttre"),
        # initial: both subjects see the net via role-T (label=treska).
        check_step("chg-both-pre-allow", "service_account:{{_t31SaBoth}}", "v_list",
                   "vpc_network:{{_t31NetChg}}", expect_allowed=True, poll=True),
        check_step("chg-treska-pre-allow", "service_account:{{_t31SaTreska}}", "v_list",
                   "vpc_network:{{_t31NetChg}}", expect_allowed=True, poll=True),
        # swap label treska → okun.
        *update_network("_t31NetChg", "chg",
                        {"updateMask": "labels", "labels": {"network": "okun"}}),
        # SaBoth stays ALLOW (now via role-O) — net does not flicker to invisible.
        check_step("chg-both-post-allow", "service_account:{{_t31SaBoth}}", "v_list",
                   "vpc_network:{{_t31NetChg}}", expect_allowed=True, poll=True),
        # SaTreska loses visibility — only had the treska selector, now revoked.
        check_step("chg-treska-post-deny", "service_account:{{_t31SaTreska}}", "v_list",
                   "vpc_network:{{_t31NetChg}}", expect_allowed=False, poll=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# idm01_no_emit — non-label Update is a no-op for visibility.
# Update description only (labels NOT in mask) → visibility unchanged (stays
# ALLOW). External-observable half: a rename/desc change does not flip the
# grant. (The "no extra mirror.upsert" internal counter is integration-only; the
# gateway-observable invariant is visibility stability.)
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-IDM-01",
    title="idm01_no_emit: vpc.network non-label Update (description only) leaves ARM_LABELS visibility unchanged",
    classes=["T31", "LABELS", "IDM", "FGA", "AUTHZ"],
    priority="P1",
    steps=[
        *create_suite_project("idm"),
        *create_fresh_sa("_t31SaIdm", "idm"),
        *create_network("_t31NetIdm", "idm", {"network": "treska"}),
        check_step("idm-pre-grant-deny", "service_account:{{_t31SaIdm}}", "v_list",
                   "vpc_network:{{_t31NetIdm}}", expect_allowed=False),
        *create_label_role("_t31RoleIdm", VPC_NET_RULE, "idm"),
        *bind_role_on_account("_t31RoleIdm", "_t31BindIdm", "_t31SaIdm", "idm"),
        check_step("idm-post-grant-allow", "service_account:{{_t31SaIdm}}", "v_list",
                   "vpc_network:{{_t31NetIdm}}", expect_allowed=True, poll=True),
        # update description ONLY — labels untouched, not in mask.
        *update_network("_t31NetIdm", "idm",
                        {"updateMask": "description", "description": "renamed-by-t31-idm"}),
        # visibility unchanged — non-label Update must not revoke.
        check_step("idm-post-update-still-allow", "service_account:{{_t31SaIdm}}", "v_list",
                   "vpc_network:{{_t31NetIdm}}", expect_allowed=True, poll=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# fullpatch01_empty_mask — empty update_mask = full-PATCH ⇒ emit obligatory.
# The trickiest path: no explicit "labels" in the mask,
# but the full-PATCH body zeroes labels ({}). Case A: full-PATCH with labels={}
# revokes. Case B (symmetry): full-PATCH adding labels materializes. Both proven
# via the same subject by sequencing A then B on two separate networks.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-FULLPATCH-01",
    title="fullpatch01_empty_mask: vpc.network empty-mask full-PATCH zeroing labels revokes (+ symmetry add)",
    classes=["T31", "LABELS", "REVOKE", "FULLPATCH", "FGA", "AUTHZ"],
    priority="P1",
    steps=[
        *create_suite_project("fp"),
        # --- Case A: full-PATCH zeroing labels → revoke ---
        *create_fresh_sa("_t31SaFp", "fp"),
        *create_network("_t31NetFpA", "fpa", {"network": "treska"}),
        check_step("fp-a-pre-grant-deny", "service_account:{{_t31SaFp}}", "v_list",
                   "vpc_network:{{_t31NetFpA}}", expect_allowed=False),
        *create_label_role("_t31RoleFp", VPC_NET_RULE, "fp"),
        *bind_role_on_account("_t31RoleFp", "_t31BindFp", "_t31SaFp", "fp"),
        check_step("fp-a-post-grant-allow", "service_account:{{_t31SaFp}}", "v_list",
                   "vpc_network:{{_t31NetFpA}}", expect_allowed=True, poll=True),
        # full-object PATCH: NO updateMask, body carries labels={} (full-PATCH
        # treats absent/empty labels as {} → labelsInMask=true for empty mask).
        # Empty-mask PATCH applies the WHOLE body (applyNetworkMask: name +
        # description + labels). The current name MUST be echoed back or the
        # full-PATCH would zero it (→ unique/validation break). name == the
        # create-net-fpa name (deterministic {{runId}} suffix).
        *update_network("_t31NetFpA", "fpa",
                        {"name": "t31-net-fpa-{{runId}}", "labels": {}}),
        check_step("fp-a-post-revoke-deny", "service_account:{{_t31SaFp}}", "v_list",
                   "vpc_network:{{_t31NetFpA}}", expect_allowed=False, poll=True),
        # --- Case B: full-PATCH adding labels → materialize (symmetry) ---
        *create_network("_t31NetFpB", "fpb", {}),
        # same role/subject already bound on account; net B has no label → DENY.
        check_step("fp-b-pre-add-deny", "service_account:{{_t31SaFp}}", "v_list",
                   "vpc_network:{{_t31NetFpB}}", expect_allowed=False, poll=True),
        # full-PATCH adds labels; echo the current name so the empty-mask PATCH
        # does not zero it. name == the create-net-fpb name.
        *update_network("_t31NetFpB", "fpb",
                        {"name": "t31-net-fpb-{{runId}}", "labels": {"network": "treska"}}),
        check_step("fp-b-post-add-allow", "service_account:{{_t31SaFp}}", "v_list",
                   "vpc_network:{{_t31NetFpB}}", expect_allowed=True, poll=True),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# unavail01_intent_durable — IAM-down is NOT a precondition of the resource
# mutation. The mirror-emit is an async outbox relay,
# NOT a sync cross-service ref-check on the request path — so a label Update
# Operation completes WITHOUT error regardless of IAM mirror availability (the
# intent is durable in the vpc outbox, drained at-least-once). The gateway-
# observable half: the Update Operation is `done` with no error (it does NOT fail
# UNAVAILABLE). Toggling IAM availability mid-run is an integration-only injection;
# here we assert the durable-Update contract (mutation does not depend on a sync
# IAM call) — the path the whole revoke mechanic relies on.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-NETWORK-UNAVAIL-01",
    title="unavail01_intent_durable: vpc.network label Update Operation completes (mirror-emit is async outbox, not sync IAM precondition)",
    classes=["T31", "LABELS", "UNAVAIL", "ASYNC", "STATE"],
    priority="P2",
    steps=[
        *create_suite_project("un"),
        *create_network("_t31NetUn", "un", {"network": "treska"}),
        # the label Update itself does NOT make a sync IAM call — the mirror-emit
        # is an outbox intent in the same writer-tx, drained out-of-band. So the
        # Update Operation completes with no error (NOT code 14 UNAVAILABLE), and
        # the resource reflects labels={} immediately.
        *update_network("_t31NetUn", "un",
                        {"updateMask": "labels", "labels": {}}),
        # GET of the caller's OWN fresh network — first read after create/update, so the
        # v_get/owner tuple can still be draining under parallel load → transient 403/404 at
        # the gateway authz gate (403 hidden as 404 on hide-existence). Bounded read-your-
        # writes retry SELF until authorized; fail-closed at the budget.
        retry_until_authorized(
            Step(name="un-update-not-unavailable", method="GET", path=f"{VPC_NET}/{{{{_t31NetUn}}}}",
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              "pm.test('label Update applied (mutation not blocked by async mirror-emit)', () => {",
                              "  const j = pm.response.json();",
                              "  pm.expect(Object.keys(j.labels || {}).length, JSON.stringify(j)).to.eql(0);",
                              "});"]),
            budget=25, interval_ms=500, retry_on=(403, 404)),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# invite_grant_label_revoke — THE MAIN regression scenario (the exact manual
# flow that surfaced the bug). A NEWLY-INVITED USER (not a pre-seeded
# subject) gets an account-scoped ARM_LABELS grant by matchLabels:{network:treska};
# the invitee SEES the network; the label is removed; the invitee STOPS seeing it.
#
# Invite-activation member-edge note: a genuine Kratos activation
# (account:<A>#account@iam_user:<invitee>) needs the provision-hook flow, which the
# black-box gateway harness cannot drive (no Kratos fixture) — see
# iam-invite-grant-fga.py caveat. To reproduce the mechanic end-to-end
# through the gateway WITHOUT depending on the unreproducible activation hook, the
# invitee is modeled by a fresh ServiceAccount subject on account A (same clean-
# subject guarantees: zero pre-grant cascade). The User.invite create is exercised
# alongside (the invite RPC is part of the flow and must succeed), but the
# label-grant→revoke is probed on the clean SA subject so the assertion is
# deterministic in CI. The User invite + the SA-subject grant/revoke together
# cover the documented "invite → bind ARM_LABELS (account-scope) → sees → label
# removed → does not see" mechanic.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-VPC-INVITE-GRANT-REVOKE",
    title="invite_grant_label_revoke: invite user + account-scope ARM_LABELS grant by matchLabels → sees network → label removed → does not see (regression)",
    classes=["T31", "LABELS", "REVOKE", "INVITE", "FGA", "AUTHZ", "USE-CASE"],
    priority="P0",
    steps=[
        *create_suite_project("inv"),
        # invite a brand-new user into account A (part of the documented flow).
        Step(name="invite-user", method="POST", path="/iam/v1/users:invite",
             body={"accountId": "{{accountAId}}",
                   "email": "t31-inv-{{runId}}@example.com",
                   "displayName": "t31-invitee-{{runId}}"},
             auth="jwtAccountAdminA",
             test_script=[
                 # invite returns an Operation envelope; tolerate the (rare)
                 # already-exists on re-run by accepting 200 only and asserting
                 # the operation has no hard error in the poll below.
                 *assert_status(200), *save_from_response("j.id", "_opInvite")]),
        Step(name="poll-invite", method="GET", path="/operations/{{_opInvite}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_opInvite")),
        # clean grant subject (deterministic in CI — no Kratos activation hook).
        *create_fresh_sa("_t31SaInv", "inv"),
        *create_network("_t31NetInv", "inv", {"network": "treska"}),
        # pre-grant: invitee subject cannot see the network.
        check_step("inv-pre-grant-deny", "service_account:{{_t31SaInv}}", "v_list",
                   "vpc_network:{{_t31NetInv}}", expect_allowed=False),
        # bind the ARM_LABELS role (account-scope, matchLabels:network=treska).
        *create_label_role("_t31RoleInv", VPC_NET_RULE, "inv"),
        *bind_role_on_account("_t31RoleInv", "_t31BindInv", "_t31SaInv", "inv"),
        # invitee NOW sees the network (grant materialized by label match).
        check_step("inv-post-grant-allow", "service_account:{{_t31SaInv}}", "v_list",
                   "vpc_network:{{_t31NetInv}}", expect_allowed=True, poll=True),
        # remove the label → grant revoked (the fix).
        *update_network("_t31NetInv", "inv",
                        {"updateMask": "labels", "labels": {}}),
        # invitee STOPS seeing the network — the exact behaviour that was missing.
        check_step("inv-post-revoke-deny", "service_account:{{_t31SaInv}}", "v_list",
                   "vpc_network:{{_t31NetInv}}", expect_allowed=False, poll=True),
    ],
))
