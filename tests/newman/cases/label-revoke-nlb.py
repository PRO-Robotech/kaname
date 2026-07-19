# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Cross-service ARM_LABELS revoke-on-label-change, nlb.listener (e2e).

Same mechanic as label-revoke-vpc.py — see that file's module docstring for the
full clean-subject / assignability / v_list-probe / umbrella-only rationale.

verifies: removing the matching label on an nlb.listener Update revokes the
ARM_LABELS grant (Check v_list flips True→False); the listener mirror also emits
labels on Create.

nlb.listener is a DOUBLE BUG: listenerRegisterIntent emitted a
bare intent WITHOUT labels on Create AND emitted nothing on label-Update. So both
points are pinned:
  - post-grant ALLOW pins the Create-emit fix — an unlabeled mirror listener would
    never match the selector even freshly created, making any revoke test falsely
    green on an empty mirror.
  - post-Update DENY pins the Update-emit fix — label-remove revokes the grant.
nlb fga type: lb_listener (authzmap/fga_types.go: loadbalancer.listeners →
lb_listener). The rule module/resource is loadbalancer.listeners.

Seed chain: a listener needs a parent NetworkLoadBalancer (EXTERNAL, so the VIP
auto-allocates without a subnet). region_id = existingRegionId (region-1,
geo-seeded). The listener carries {lsn:treska}.

DEPLOYMENT SCOPE — full-umbrella stack: requires kacho-nlb (+ kacho-vpc for VIP
auto-allocation + kacho-geo for region) deployed behind the gateway so nlb→iam
RegisterResource feeds resource_mirror. The umbrella e2e brings up the full stack
and runs this shared iam suite, so these execute against a complete deployment.

REGION DISCOVERY (no env-fixture dependency). The shared kacho-iam newman env does
NOT define existingRegionId (it is a compute/nlb-suite env var, absent in the iam
harness the umbrella runs). A LoadBalancer Create with the unsubstituted literal
"{{existingRegionId}}" failed (region not found) → no LB → no listener → grant
never materialized → false-RED. Fix: the case first GETs the geo-seeded regions
via the PUBLIC read GET /geo/v1/regions (idempotent — same source geo-read.py
asserts) and stashes the first region id into a suite-local env var
{{_t31nRegionId}}, used as regionId.

Fixtures: jwtBootstrap, jwtAccountAdminA, accountAId, projectA1Id. The region is
DISCOVERED at runtime (see above), not read from env. Test-design: state-transition
+ ECP + the double-bug Create-emit anchor. One thought per pm.test().
"""

CASES = []

POLL_CAP = 30

NLB = "/nlb/v1/networkLoadBalancers"
LISTENERS = "/nlb/v1/listeners"


def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
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
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are served
    ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design (ban #6).
    gen.py emits {{baseUrl}}<path>; without this override the FGA-Check probe hits the
    public port → "404 page not found" → JSONError on the first pm.response.json().
    Mirrors label-revoke-vpc.py::_internal_url_override / iam-internal-only-check.py."""
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
    return Step(name=name, method="POST", path="/iam/v1/internal/iam:check",
                auth=auth, body={"subjectId": subject, "relation": relation, "object": obj},
                pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
                test_script=["const j = pm.response.json();", *retry, *verdict])


def create_fresh_sa(sa_var, name_suffix):
    return [
        Step(name=f"create-sa-{name_suffix}", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": f"t31n-sa-{name_suffix}-{{{{runId}}}}",
                   "description": "newman nlb label-revoke clean subject"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                          *save_from_response("j.id", f"_op_{sa_var}")]),
        Step(name=f"poll-sa-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{sa_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var)),
    ]


def create_label_role(role_var, name_suffix):
    rules = [{"module": "loadbalancer", "resources": ["listeners"], "verbs": ["get", "list"],
              "matchLabels": {"lsn": "treska"}}]
    return [
        Step(name=f"create-role-{name_suffix}", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": f"t31n_{name_suffix}_{{{{runId}}}}",
                   "description": "newman nlb ARM_LABELS probe role", "rules": rules},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", f"_op_{role_var}")]),
        Step(name=f"poll-role-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{role_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{role_var}", out_id_var=role_var)),
    ]


def assert_bind_succeeded(name):
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


def bind_role_on_account(role_var, bind_op_var, subject_var, name_suffix):
    return [
        Step(name=f"bind-{name_suffix}", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "service_account", "subjectId": f"{{{{{subject_var}}}}}",
                   "roleId": f"{{{{{role_var}}}}}", "resourceType": "account",
                   "resourceId": "{{accountAId}}"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", bind_op_var)]),
        Step(name=f"poll-bind-{name_suffix}", method="GET", path=f"/operations/{{{{{bind_op_var}}}}}",
             auth="jwtAccountAdminA", test_script=assert_bind_succeeded(f"bind-{name_suffix}")),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# revoke04_listener (double bug Create+Update).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="T31-LBLREVOKE-NLB-LISTENER-04",
    title="revoke04_listener: nlb.listener Create emits labels + Update label-remove revokes (double-bug, Check v_list True→False)",
    classes=["T31", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE", "NLB"],
    priority="P0",
    steps=[
        *create_fresh_sa("_t31nSa", "lsn"),
        # Discover a geo-seeded region (the iam env has no existingRegionId).
        # GET /geo/v1/regions is a public read; the geo migration seeds region-1.
        Step(name="discover-region", method="GET", path="/geo/v1/regions",
             auth="jwtBootstrap",
             test_script=[
                 "const j = pm.response.json();",
                 "pm.test('geo regions list reachable (region discovery)', () => {",
                 "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                 "  pm.expect(j.regions, JSON.stringify(j)).to.be.an('array');",
                 "  pm.expect(j.regions.length, 'at least one seeded region').to.be.greaterThan(0);",
                 "});",
                 "if (j.regions && j.regions.length > 0) { pm.environment.set('_t31nRegionId', j.regions[0].id); }",
             ]),
        # parent EXTERNAL load balancer (VIP auto-allocates, no subnet needed). An EXTERNAL
        # LB MUST declare a vip source for at least one ip family (nlb contract) — v4Source
        # {public:{}} auto-allocates a public IPv4 VIP. Without it the Create is a sync 400
        # "load balancer must declare a vip source for at least one ip family" (see the
        # load-balancer.py EXTERNAL bodies: type EXTERNAL + v4Source {public:{}}).
        Step(name="create-lb", method="POST", path=NLB,
             body={"projectId": "{{projectA1Id}}", "name": "t31n-lb-{{runId}}",
                   "regionId": "{{_t31nRegionId}}", "type": "EXTERNAL",
                   "v4Source": {"public": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.networkLoadBalancerId", "_t31nLb"),
                          *save_from_response("j.id", "_op_t31nLb")]),
        Step(name="poll-lb", method="GET", path="/operations/{{_op_t31nLb}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31nLb", out_id_var="_t31nLb")),
        # listener with a matching label — EXTERNAL auto-allocate VIP.
        Step(name="create-listener", method="POST", path=LISTENERS,
             body={"loadBalancerId": "{{_t31nLb}}", "name": "t31n-lsn-{{runId}}",
                   "protocol": "TCP", "port": 80, "targetPort": 8080, "ipVersion": "IPV4",
                   "addressSpec": {"auto": {}}, "labels": {"lsn": "treska"}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.listenerId", "_t31nLsn"),
                          *save_from_response("j.id", "_op_t31nLsn")]),
        Step(name="poll-listener", method="GET", path="/operations/{{_op_t31nLsn}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_op_t31nLsn", out_id_var="_t31nLsn")),
        check_step("lsn-pre-grant-deny", "service_account:{{_t31nSa}}", "v_list",
                   "lb_listener:{{_t31nLsn}}", expect_allowed=False),
        *create_label_role("_t31nRole", "lsn"),
        *bind_role_on_account("_t31nRole", "_t31nBind", "_t31nSa", "lsn"),
        # Create-emit fix anchor: a fresh listener WITH labels matches the selector
        # (a bare-intent mirror without labels would never match → false-green trap).
        check_step("lsn-post-grant-allow", "service_account:{{_t31nSa}}", "v_list",
                   "lb_listener:{{_t31nLsn}}", expect_allowed=True, poll=True),
        # Update-emit fix: remove the label → selector stops matching → revoke.
        # updateMask is a STRING ("labels"): protojson serializes FieldMask as a
        # comma-separated string, NOT a {paths:[...]} object (object form 400s →
        # op id never saved). The listener id is bound from the PATCH path and
        # MUST NOT appear in the body (mirrors working iam-account.py update).
        Step(name="update-listener-labels", method="PATCH", path=f"{LISTENERS}/{{{{_t31nLsn}}}}",
             body={"updateMask": "labels", "labels": {}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", "_opu_t31nLsn")]),
        Step(name="poll-update-listener", method="GET", path="/operations/{{_opu_t31nLsn}}",
             auth="jwtAccountAdminA", test_script=poll_op_done("_opu_t31nLsn")),
        check_step("lsn-post-revoke-deny", "service_account:{{_t31nSa}}", "v_list",
                   "lb_listener:{{_t31nLsn}}", expect_allowed=False, poll=True),
    ],
))
