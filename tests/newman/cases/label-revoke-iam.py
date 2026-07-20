# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""IAM-native label clear via updateMask=labels — revokes ARM_LABELS grant (e2e, black-box).

verifies: ProjectService.Update with update_mask=["labels"] and an empty labels
body CLEARS the labels (not a silent no-op), which revokes a label-scoped grant.

ProjectService.Update with update_mask=["labels"] and an EMPTY labels body must
CLEAR the project's labels (full clear), not be a silent no-op. proto3 maps carry
no field presence, so an empty `labels:{}` and an omitted labels are
indistinguishable at the wire — the ONLY signal that the caller wants to clear is
the presence of "labels" in update_mask. Before the fix the gate keyed on "labels
body non-nil" instead of "mask contains labels", so clearing was a 200-but-no-op:
a label-scoped grant could NOT be revoked by clearing the matching label (the admin
got 200, access silently persisted).

This is the IAM-native analogue of the cross-service label-revoke-vpc.py suite. The
selectable resource is iam.project (label-selectable iam-direct, same-DB from the
own-table labels — no resource_mirror feed needed), so the WHOLE mechanic is
black-box reachable through the gateway against the IAM-only stack:

  grant  — an ARM_LABELS rule {module:iam, resources:[project], verbs:[get,list],
           matchLabels:{labelrevoke:treska}} on an ACCOUNT-scoped role, bound on
           account A, materializes per-object `project:<id> # v_list @ subject` for
           projects under A whose labels match.
  revoke — clearing the matching label via ProjectService.Update
           (updateMask=labels, labels={}) re-materializes the iam-direct selector
           membership (≤2s) → the project stops matching → v_list revoked.

The observable contract: visibility is probed through InternalIAMService.Check on
{subject, relation=v_list, object="project:<id>"}. v_list on a verb-bearing type is
materialized ONLY by a vlist-tier label grant (not by a generic account/project
viewer cascade), so a True→False verdict isolates the effect of THIS label grant.

CLEAN SUBJECT: each case mints a FRESH ServiceAccount on account A —
zero `#v_list` grants, so no account-viewer cascade can pre-satisfy the probe; every
case asserts pre-grant DENY before the bind.

Fixtures (tests/authz-fixtures/setup.sh): jwtBootstrap,
jwtAccountAdminA, accountAId. Resources are self-seeded per case with
{{runId}}-suffixed names (self-contained, no cross-case collision).
"""

CASES = []

POLL_CAP = 30

IAM_PROJECTS = "/iam/v1/projects"

IAM_PROJECT_RULE = [{"module": "iam", "resources": ["project"], "verbs": ["get", "list"],
                     "matchLabels": {"labelrevoke": "treska"}}]


# ─────────────────────────────────────────────────────────────────────────────
# Reusable poll / probe / grant helpers (file-local, matching repo convention —
# each cases file redefines them so gen.py imports nothing case-to-case).
# ─────────────────────────────────────────────────────────────────────────────

def poll_op_done(op_var, out_id_var=None):
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
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are served
    ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design (ban #6).
    gen.py emits {{baseUrl}}<path>; without this override the FGA-Check probe hits the
    public port → "404 page not found" → JSONError on the first pm.response.json().
    Mirrors label-revoke-vpc.py::_internal_url_override / iam-internal-only-check.py.
    internalBaseUrl is injected at runtime by the newman harness (--env-var); if unset
    (local dev without the internal-rest port-forward) the step is skipped rather than
    hitting a spurious public 404."""
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
    """InternalIAMService.Check probe (POST /iam/v1/internal/iam:check) — served ONLY on
    the cluster-internal REST listener ({{internalBaseUrl}}, :18081); the pre_script
    redirects there (the public :18080 404s /iam/v1/internal/* by design, ban #6).
    expect_allowed=True asserts allowed===true (optionally polling the reconcile/fga-drain
    window); False asserts allowed !== true. One thought / pm.test."""
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
    subject) + op-poll, stashing the SA id. Zero `#v_list` grants."""
    return [
        Step(name=f"create-sa-{name_suffix}", method="POST", path="/iam/v1/serviceAccounts",
             body={"accountId": "{{accountAId}}", "name": f"lriam-sa-{name_suffix}-{{{{runId}}}}",
                   "description": "newman iam label-revoke clean subject"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                          *save_from_response("j.id", f"_op_{sa_var}")]),
        Step(name=f"poll-sa-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{sa_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var)),
    ]


def create_project(proj_var, suffix, labels):
    """ProjectService.Create under accountA with the given labels + op-poll. The
    project is label-selectable iam-direct (same-DB own-table labels)."""
    return [
        Step(name=f"create-proj-{suffix}", method="POST", path=IAM_PROJECTS,
             body={"accountId": "{{accountAId}}", "name": f"lriam-prj-{suffix}-{{{{runId}}}}",
                   "labels": labels},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.projectId", proj_var),
                          *save_from_response("j.id", f"_op_{proj_var}")]),
        Step(name=f"poll-proj-{suffix}", method="GET", path=f"/operations/{{{{_op_{proj_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{proj_var}", out_id_var=proj_var)),
    ]


def update_project(proj_var, suffix, body):
    """ProjectService.Update(project) PATCH + op-poll. `body` is a FLAT update body:
    mutable fields + a STRING `updateMask` (protojson serializes FieldMask as a
    comma-separated string). The project id is bound from the PATCH path, so it MUST
    NOT appear in the body.

    The PATCH needs the caller's v_update on the fresh project (owner/creator tuple).
    That tuple materializes eventually-consistent (registrar + fga_outbox drain +
    reconciler), so under PARALLEL load the PATCH right after Create races the drain and
    403s single-shot ('lacks relation v_update on project'). Bounded read-your-writes
    retry SELF on 403 until the tuple is visible; fail-closed at the budget (a genuine,
    non-converging deny still surfaces)."""
    return [
        retry_until_authorized(
            Step(name=f"update-proj-{suffix}", method="PATCH", path=f"{IAM_PROJECTS}/{{{{{proj_var}}}}}",
                 body=body, auth="jwtAccountAdminA",
                 test_script=[*assert_status(200), *save_from_response("j.id", f"_opu_{proj_var}")]),
            budget=25, interval_ms=500, retry_on=(403,)),
        Step(name=f"poll-update-proj-{suffix}", method="GET", path=f"/operations/{{{{_opu_{proj_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_opu_{proj_var}")),
    ]


def create_label_role(role_var, rules, name_suffix):
    """RoleService.Create(rules) on accountA + op-poll, stashing the role id.
    ACCOUNT-scoped. The rule is ARM_LABELS (matchLabels present)."""
    return [
        Step(name=f"create-role-{name_suffix}", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": f"lriam_{name_suffix}_{{{{runId}}}}",
                   "description": "newman iam ARM_LABELS probe role", "rules": rules},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", f"_op_{role_var}")]),
        Step(name=f"poll-role-{name_suffix}", method="GET", path=f"/operations/{{{{_op_{role_var}}}}}",
             auth="jwtAccountAdminA", test_script=poll_op_done(f"_op_{role_var}", out_id_var=role_var)),
    ]


def assert_bind_succeeded(name):
    """Poll the bind Operation and assert it SUCCEEDED — done, no error, NOT
    FAILED_PRECONDITION (code 9). A mis-scoped/failed bind cannot be masked by an
    FGA cascade."""
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
    """AccessBindingService.Create(role @ account:<accountA>) for the SA subject +
    op-poll asserting the bind SUCCEEDED (account-scoped role on its own account)."""
    return [
        Step(name=f"bind-{name_suffix}", method="POST", path="/iam/v1/accessBindings",
             body={"subjectType": "service_account", "subjectId": f"{{{{{subject_var}}}}}",
                   "roleId": f"{{{{{role_var}}}}}", "scopeType": "iam.account",
                   "scopeId": "{{accountAId}}", "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200), *save_from_response("j.id", bind_op_var)]),
        Step(name=f"poll-bind-{name_suffix}", method="GET", path=f"/operations/{{{{{bind_op_var}}}}}",
             auth="jwtAccountAdminA", test_script=assert_bind_succeeded(f"bind-{name_suffix}")),
    ]


def assert_labels_empty(name, proj_var):
    """GET the project and assert its labels map is empty — the direct, black-box
    reproduction: updateMask=labels + empty body MUST clear labels. This reads the
    caller's OWN fresh project, whose v_get owner-tuple can still be draining under
    parallel load → transient 403/404; bounded read-your-writes retry SELF until visible."""
    return retry_until_authorized(
        Step(
            name=name, method="GET", path=f"{IAM_PROJECTS}/{{{{{proj_var}}}}}",
            auth="jwtAccountAdminA",
            test_script=[*assert_status(200),
                         "pm.test('project labels now empty (clear is NOT a no-op)', () => {",
                         "  const j = pm.response.json();",
                         "  pm.expect(Object.keys(j.labels || {}).length, JSON.stringify(j)).to.eql(0);",
                         "});"]),
        budget=25, interval_ms=500, retry_on=(403, 404))


# ─────────────────────────────────────────────────────────────────────────────
# IAM-LBLCLEAR-PROJECT-EMPTY-01 — direct black-box reproduction.
# Create a project with labels {labelrevoke:treska}; clear them via
# updateMask=labels + empty body; GET shows labels empty. RED before the fix
# (clear was a silent no-op → labels stayed {labelrevoke:treska}).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="IAM-LBLCLEAR-PROJECT-EMPTY-01",
    title="project label-clear via updateMask=labels + empty body empties labels (was silent no-op)",
    classes=["IAM", "LABELS", "REVOKE", "NEG"],
    priority="P0",
    steps=[
        *create_project("_lriamPrjC", "clr", {"labelrevoke": "treska"}),
        # sanity: the project carries the label before the clear. First read of the
        # caller's OWN fresh project → v_get owner-tuple may still be draining under
        # parallel load; bounded read-your-writes retry SELF on 403/404 until visible.
        retry_until_authorized(
            Step(name="clr-precheck-has-label", method="GET", path=f"{IAM_PROJECTS}/{{{{_lriamPrjC}}}}",
                 auth="jwtAccountAdminA",
                 test_script=[*assert_status(200),
                              "pm.test('project has the label before clear', () => {",
                              "  const j = pm.response.json();",
                              "  pm.expect((j.labels || {}).labelrevoke, JSON.stringify(j)).to.eql('treska');",
                              "});"]),
            budget=25, interval_ms=500, retry_on=(403, 404)),
        # clear via updateMask=labels + empty body.
        *update_project("_lriamPrjC", "clr", {"updateMask": "labels", "labels": {}}),
        assert_labels_empty("clr-post-clear-empty", "_lriamPrjC"),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# IAM-LBLREVOKE-PROJECT-01 — the security mechanic: clearing the matching
# label via updateMask=labels REVOKES the ARM_LABELS grant. Create project
# {labelrevoke:treska} → grant ARM_LABELS{matchLabels:labelrevoke=treska} on
# account → pre/post-bind v_list DENY→ALLOW → clear label (updateMask=labels,{})
# → v_list converges to DENY (revoked) + labels are empty on GET.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="IAM-LBLREVOKE-PROJECT-01",
    title="project label-clear via updateMask=labels revokes ARM_LABELS grant (Check v_list True→False)",
    classes=["IAM", "LABELS", "REVOKE", "FGA", "AUTHZ", "STATE"],
    priority="P0",
    steps=[
        *create_fresh_sa("_lriamSa1", "r1"),
        *create_project("_lriamPrj1", "r1", {"labelrevoke": "treska"}),
        # clean subject: not yet a v_list-er of the project.
        check_step("r1-pre-grant-deny", "service_account:{{_lriamSa1}}", "v_list",
                   "project:{{_lriamPrj1}}", expect_allowed=False),
        *create_label_role("_lriamRole1", IAM_PROJECT_RULE, "r1"),
        *bind_role_on_account("_lriamRole1", "_lriamBind1", "_lriamSa1", "r1"),
        # grant materialized: label match (labelrevoke=treska) → per-object v_list.
        check_step("r1-post-grant-allow", "service_account:{{_lriamSa1}}", "v_list",
                   "project:{{_lriamPrj1}}", expect_allowed=True, poll=True),
        # clear the label via updateMask=labels + empty body → selector stops matching.
        *update_project("_lriamPrj1", "r1", {"updateMask": "labels", "labels": {}}),
        # labels are actually cleared (not a no-op).
        assert_labels_empty("r1-labels-empty", "_lriamPrj1"),
        # eventual consistency: visibility converges to DENY (grant revoked).
        check_step("r1-post-revoke-deny", "service_account:{{_lriamSa1}}", "v_list",
                   "project:{{_lriamPrj1}}", expect_allowed=False, poll=True),
    ],
))
