# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""RC-1 — anchor-grant FGA materialization (e2e, black-box) — GREEN BY THE RIGHT REASON.

Black-box, through api-gateway → IAM → OpenFGA. Verifies anchor-grant FGA
materialization (RC-1) and role assignability:

  RC-1 — binding a RULES-role with a tier-only `iam.<tier>` rule onto an anchor
         of the SAME tier-type mints a CONCRETE tier tuple on that anchor
         (`<anchorType>:<id>#viewer@<subject>`), making the subject a viewer of
         exactly that one scope object. Observable via InternalIAMService.Check.

─────────────────────────────────────────────────────────────────────────────
WHY THIS SUITE WAS REWRITTEN (the OLD suite was FALSELY GREEN)
─────────────────────────────────────────────────────────────────────────────
The previous version created an ACCOUNT-scoped custom role
(`create_project_rules_role` → accountId:{{accountAId}}) and bound it on
`resourceType=project, resourceId={{projectA1Id}}`, then probed
Check(viewer, project:A1)=True for subject `userNOB`.

Three independent facts made that a NON-test:

  1. ASSIGNABILITY (internal/domain/role_scope.go
     `IsRoleAssignable`): an account-scoped custom role is assignable ONLY on its
     own account, NEVER on a project (STRICT — no hierarchy-down). So
     AccessBinding.Create on `project:A1` MUST fail with the Operation carrying
     `error` FAILED_PRECONDITION (code 9) "role <id> is not assignable on
     project:A1" (internal/apps/kacho/api/access_binding/create.go doCreate).
     The bind the old suite relied on was contractually dead.

  2. FGA CASCADE (kacho-proto fga_model.fga): `project.viewer = … or viewer
     from account …`. Subject `userNOB` carries `viewer@account:A` from the
     shared iam-access-binding suite (fixture-pollution — authz-fixtures/setup.sh
     binds & the iam-access-binding suite re-grants NOB on account A). That
     account-A viewer CASCADES onto EVERY project in account A → Check(viewer,
     project:A1)=True regardless of the bind. The probe was true-by-the-fixture,
     not by the grant under test.

  3. So even though the bind Operation should error, the green Check verdict came
     from the account cascade — the suite asserted the RIGHT verdict for the
     WRONG reason and never noticed the bind failed.

─────────────────────────────────────────────────────────────────────────────
HOW THIS SUITE IS GREEN BY THE RIGHT REASON
─────────────────────────────────────────────────────────────────────────────
* CLEAN SUBJECT — each case creates a FRESH ServiceAccount on account A as the
  grant subject (sa_setup). A just-created SA has ZERO `…#viewer` grants: SA.Create
  emits only the reverse hierarchy pointer `account:A#account@iam_service_account:SA`
  (internal/apps/kacho/api/service_account/create.go), which gives the account
  OWNER a path TO the SA — it does NOT make the SA a viewer of the account. So no
  fixture-pollution path can mask a failed grant.

* PRE-BIND DENY (the cleanliness assertion) — every case asserts Check(viewer,
  <target>)=False BEFORE the bind. If a future pollution path ever granted the
  fresh SA the target relation, this pre-check fires and the suite goes RED.

* EXPLICIT BIND SUCCESS — the bind Operation is asserted done + NO error + NOT
  code-9 (assert_bind_succeeded). A mis-scoped / failed bind can no longer hide
  behind a cascade; the materialization is proven to come from THIS grant.

* POST-BIND ALLOW — Check(viewer, <target>)=True AFTER the bind (poll for the
  async fga_outbox drainer). True − False across the bind isolates the grant's
  effect to exactly the target object.

Account-path (T-E1) + ARM_NAMES parity (T-E3) are PUBLICLY REACHABLE and GREEN.
Cross-account containment (T-E2) is GREEN. The PROJECT-anchor path (T-E4) was
RED while the public CreateRoleRequest had no `project_id`: a project-scoped custom
role — the only role assignable on a `project` — could not be authored via the
public API, so the project-anchor RC-1 emit was unreachable; see the T-E4 block.

Probe RPC — InternalIAMService.Check (POST /iam/v1/internal/iam:check), exempt
from the per-RPC gate, FGA-native raw-tuple passthrough (the same path the
consumer authz-gate resolves). ALLOW → 200 {"allowed": true}; DENY → 200
{"reason": "..."} with `allowed` omitted (proto3 false). Mirrors
cases/iam-rbac-scope-grant.py.

Fixtures (tests/authz-fixtures/setup.sh): jwtBootstrap,
jwtAccountAdminA, accountAId, projectA1Id, projectB1Id (a project under account B
— the cross-account containment target a fresh account-A subject has NO path to).
The fresh-SA subject is created per-case via {{runId}}-suffixed names — no
dependency on any pre-seeded grantable subject.

RC-4 caveat: the deployed stand must run the CURRENT fga_model.fga (re-bootstrap)
— against a stale model RC-1 Check could false-positive at 0 tuples, masking the
fix. On a stale stand these cases surface RED until the re-bootstrap deploy step
runs. Not whitelisted green.
"""

CASES = []

POLL_CAP = 30


def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
    """Self-polling Step body: wait for an IAM Operation to be done; assert no error."""
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
    pm.response.json(). Mirrors label-revoke-vpc.py / iam-internal-only-check.py
    ::_internal_url_override. internalBaseUrl is injected at runtime by
    deploy/scripts/newman-e2e.sh (--env-var); if unset (local dev without the
    internal-rest port-forward) the step is skipped rather than hitting a spurious
    public 404."""
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
    """InternalIAMService.Check probe. expect_allowed=True asserts allowed===true
    (optionally polling the fga_outbox drainer window); False asserts allowed !== true.
    One thought per pm.test().

    The probe hits the cluster-internal REST listener via _internal_url_override
    (pre-request URL rewrite to {{internalBaseUrl}}): /iam/v1/internal/iam:check is
    served ONLY on :18081, so without the redirect gen.py's {{baseUrl}} (:18080)
    404s ("404 page not found" → JSONError). Matches label-revoke-vpc.py."""
    retry = []
    if poll:
        retry = [
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === {str(expect_allowed).lower()}) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
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
        name=name,
        method="POST",
        path="/iam/v1/internal/iam:check",
        auth=auth,
        body={"subjectId": subject, "relation": relation, "object": obj},
        pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
        test_script=[
            "const j = pm.response.json();",
            *retry,
            *verdict,
        ],
    )


def create_fresh_sa(sa_var, name_suffix):
    """ServiceAccountService.Create a FRESH SA on accountA (the clean grant subject)
    + op-poll, stashing the SA id. A new SA has zero `#viewer` grants — see the
    module docstring 'CLEAN SUBJECT'. The {{runId}} suffix keeps the name unique
    per run (self-contained, no cross-case collision)."""
    return [
        Step(
            name=f"create-sa-{name_suffix}",
            method="POST",
            path="/iam/v1/serviceAccounts",
            body={
                "accountId": "{{accountAId}}",
                "name": f"ig-sa-{name_suffix}-{{{{runId}}}}",
                "description": "newman invite-grant RC-1 clean subject",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.serviceAccountId", sa_var),
                *save_from_response("j.id", f"_op_{sa_var}"),
            ],
        ),
        Step(
            name=f"poll-sa-{name_suffix}",
            method="GET",
            path=f"/operations/{{{{_op_{sa_var}}}}}",
            auth="jwtAccountAdminA",
            test_script=poll_op_done(f"_op_{sa_var}", out_id_var=sa_var),
        ),
    ]


def create_account_rules_role(role_var, rules, name_suffix):
    """RoleService.Create(rules) on accountA + op-poll, stashing the role id.
    The role is ACCOUNT-scoped (this helper sets account_id only)."""
    return [
        Step(
            name=f"create-role-{name_suffix}",
            method="POST",
            path="/iam/v1/roles",
            body={
                "accountId": "{{accountAId}}",
                "name": f"ig_{name_suffix}_{{{{runId}}}}",
                "description": "newman invite-grant RC-1 probe role",
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


def assert_bind_succeeded(name):
    """Poll the bind Operation and assert it SUCCEEDED — done, NO error, and
    specifically NOT FAILED_PRECONDITION (code 9). This is THE assertion that
    makes the suite honest: a mis-scoped / failed bind can no longer be masked by
    an FGA cascade because the materialization is proven to come from a bind that
    actually committed."""
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


def bind_role(role_var, bind_op_var, resource_type, resource_id, subject_var, name_suffix):
    """AccessBindingService.Create(role @ <resource>) for the fresh SA subject +
    op-poll asserting the bind SUCCEEDED."""
    return [
        Step(
            name=f"bind-{name_suffix}",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "service_account",
                "subjectId": f"{{{{{subject_var}}}}}",
                "roleId": f"{{{{{role_var}}}}}",
                # IAM-1 F7/F8: dotted scopeType (callers pass bare account/project/cluster) + REQUIRED target.
                "scopeType": f"iam.{resource_type}",
                "scopeId": resource_id,
                "target": {"allInScope": {}},
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
            test_script=assert_bind_succeeded(f"bind-{name_suffix}"),
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# T-E1 — RC-1 ACCOUNT-anchor: an `iam.account [get,list]` rules-role bound on the
# SAME account mints `account:<A>#viewer@<SA>` (emitAnchorRule objType==anchorType,
# scope_grant_tuples.go). Clean fresh SA, pre-bind DENY → bind SUCCEEDS →
# post-bind ALLOW. This is the publicly-reachable RC-1 materialization.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="INVGRANT-TE1-ACCOUNT-ANCHOR-VIEWER-RC1",
    title="RC-1 account-anchor: iam.account [get,list] @ account → Check(viewer, account)=True for a clean subject",
    classes=["FGA", "AUTHZ", "GRANT-CHAIN", "RC1"],
    priority="P0",
    steps=[
        *create_fresh_sa("_igSaAnchor", "anchor"),
        # cleanliness: the fresh SA is NOT yet a viewer of the account.
        check_step(
            name="te1-pre-bind-deny",
            subject="service_account:{{_igSaAnchor}}",
            relation="viewer",
            obj="account:{{accountAId}}",
            expect_allowed=False,
        ),
        *create_account_rules_role(
            "_igRoleAnchor",
            [{"module": "iam", "resources": ["account"], "verbs": ["get", "list"]}],
            "anchor",
        ),
        *bind_role("_igRoleAnchor", "_igBindAnchorOp", "account", "{{accountAId}}",
                   "_igSaAnchor", "anchor"),
        # RC-1: the anchor grant now mints `account:<A>#viewer@service_account:<SA>`.
        check_step(
            name="te1-post-bind-account-viewer",
            subject="service_account:{{_igSaAnchor}}",
            relation="viewer",
            obj="account:{{accountAId}}",
            expect_allowed=True,
            poll=True,
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# T-E2 — scope containment: a grant on account A does NOT make a project in a
# DIFFERENT account (B) visible. Clean fresh SA gets viewer on account A; a
# project under account B has no upward/sibling path → stays deny. This is the
# real RC-1 / D-R3 boundary ("grant does not leak past its anchor's subtree").
#
# Containment target = projectB1Id (under account B). A project under account A
# would be reachable via the model's `project.viewer = … or viewer from account`
# cascade (fga_model.fga:544) — that is a LEGITIMATE cascade, not a leak, so it
# would test the wrong invariant. projectB1 is under account B where the fresh
# account-A SA has zero path → the genuine scopeless boundary.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="INVGRANT-TE2-CROSS-ACCOUNT-PROJECT-INVISIBLE",
    title="account-A viewer grant does NOT make a project in another account (B1) visible (RC-1 containment)",
    classes=["FGA", "AUTHZ", "ISOLATION", "RC1"],
    priority="P0",
    steps=[
        *create_fresh_sa("_igSaContain", "contain"),
        # the cross-account project is invisible BEFORE any grant …
        check_step(
            name="te2-pre-bind-cross-account-deny",
            subject="service_account:{{_igSaContain}}",
            relation="viewer",
            obj="project:{{projectB1Id}}",
            expect_allowed=False,
        ),
        *create_account_rules_role(
            "_igRoleContain",
            [{"module": "iam", "resources": ["account"], "verbs": ["get", "list"]}],
            "contain",
        ),
        *bind_role("_igRoleContain", "_igBindContainOp", "account", "{{accountAId}}",
                   "_igSaContain", "contain"),
        # granted account visible …
        check_step(
            name="te2-granted-account-visible",
            subject="service_account:{{_igSaContain}}",
            relation="viewer",
            obj="account:{{accountAId}}",
            expect_allowed=True,
            poll=True,
        ),
        # … a project under a DIFFERENT account (no grant, no path) stays NOT
        # visible (steady-state deny — the boundary holds immediately).
        check_step(
            name="te2-post-bind-cross-account-project-invisible",
            subject="service_account:{{_igSaContain}}",
            relation="viewer",
            obj="project:{{projectB1Id}}",
            expect_allowed=False,
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# T-E3 — ARM_NAMES parity: an `iam.account` names-role pinned to account A
# (resourceNames:[A]) bound on account A yields the SAME Check verdict as the
# ARM_ANCHOR (D-R1 parity). emitNamesRule mints a concrete `account:A#viewer`
# tuple (scope_grant_tuples.go) — the bounded, safe shape for a tier-only type.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="INVGRANT-TE3-ARMNAMES-ACCOUNT-PARITY",
    title="ARM_NAMES iam.account resourceNames:[A] @ account → Check(viewer, account:A)=True (≡ anchor)",
    classes=["FGA", "AUTHZ", "PARITY", "RC1"],
    priority="P1",
    steps=[
        *create_fresh_sa("_igSaNames", "names"),
        check_step(
            name="te3-pre-bind-deny",
            subject="service_account:{{_igSaNames}}",
            relation="viewer",
            obj="account:{{accountAId}}",
            expect_allowed=False,
        ),
        *create_account_rules_role(
            "_igRoleNames",
            [{"module": "iam", "resources": ["account"], "verbs": ["get", "list"],
              "resourceNames": ["{{accountAId}}"]}],
            "names",
        ),
        *bind_role("_igRoleNames", "_igBindNamesOp", "account", "{{accountAId}}",
                   "_igSaNames", "names"),
        check_step(
            name="te3-post-bind-account-viewer",
            subject="service_account:{{_igSaNames}}",
            relation="viewer",
            obj="account:{{accountAId}}",
            expect_allowed=True,
            poll=True,
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# T-E4 — RC-1 PROJECT-anchor.
# verifies: a project-scoped role bound on a project anchor mints the project
# viewer tuple (Check(viewer, project)=True).
#
# The project-anchor RC-1 emit (`project:<P>#viewer@<subject>`,
# scope_grant_tuples.go emitAnchorRule with objType==anchorType=="project") can
# ONLY be reached by binding a PROJECT-scoped custom role on a `project` resource:
# IsRoleAssignable (internal/domain/role_scope.go) makes an ACCOUNT-scoped role
# assignable only on its OWN account, NEVER on a project (STRICT, no
# hierarchy-down). But the public CreateRoleRequest (kacho-proto
# role_service.proto) has NO `project_id` field and the Role.Create handler
# (internal/apps/kacho/api/role/handler.go) maps only account_id — so a
# project-scoped custom role CANNOT be authored via the public API.
#
# This case attempts the realistic public flow against the DESIRED end-state:
# create the role, bind it on `project:A1`, expect Check(viewer, project:A1)=True
# for a clean cross-account-isolated subject. If the role is account-scoped, the
# bind on `project:A1` returns Operation.error FAILED_PRECONDITION (code 9) "role
# <id> is not assignable on project:A1" → assert_bind_succeeded fails on the
# `bind NOT FailedPrecondition` assertion. The case is whitelisted as known-RED in
# scripts/assert-suites-green.sh by the `bind-project-anchor` step name; it goes
# GREEN once a project-scoped role can be authored (project_id on CreateRoleRequest
# + handler).
#
# NOTE the clean subject is essential here too: the OLD suite probed userNOB which
# carried `viewer@account:A`, so Check(viewer, project:A1) was true-by-cascade
# even though the bind failed — exactly the false-green this rewrite removes. With
# the fresh account-A SA there is no account-A viewer cascade onto projectA1 for
# this subject; only a successful project-anchor grant could make the Check true.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="INVGRANT-TE4-PROJECT-ANCHOR-VIEWER-RC1",
    title="RC-1 project-anchor: iam.project [get,list] @ project → Check(viewer, project)=True (RED — no project-scoped role via public API)",
    classes=["FGA", "AUTHZ", "GRANT-CHAIN", "RC1", "KNOWN-RED"],
    priority="P0",
    steps=[
        *create_fresh_sa("_igSaProj", "proj"),
        check_step(
            name="te4-pre-bind-deny",
            subject="service_account:{{_igSaProj}}",
            relation="viewer",
            obj="project:{{projectA1Id}}",
            expect_allowed=False,
        ),
        *create_account_rules_role(
            "_igRoleProj",
            [{"module": "iam", "resources": ["project"], "verbs": ["get", "list"]}],
            "proj",
        ),
        # bind on project:A1 — REQUIRES a project-scoped role (unreachable via
        # the public API when CreateRoleRequest has no project_id) → Operation.error
        # FAILED_PRECONDITION until fixed.
        # The poll step name 'bind-project-anchor' is the known-RED whitelist key.
        *bind_role("_igRoleProj", "_igBindProjOp", "project", "{{projectA1Id}}",
                   "_igSaProj", "project-anchor"),
        check_step(
            name="te4-post-bind-project-viewer",
            subject="service_account:{{_igSaProj}}",
            relation="viewer",
            obj="project:{{projectA1Id}}",
            expect_allowed=True,
            poll=True,
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# RC-2 invite-activation member edge — NOT BLACK-BOX-TESTABLE HERE; covered at
# integration level (T-I3, internal/repo/kacho/pg/upsert_invite_grant_fga_integration_test.go,
# GREEN). RC-2 co-commits `account:<A>#account@iam_user:<invitee>` ONLY on genuine
# activation through the Kratos provision-hook flow
# (InternalUserService.UpsertFromIdentity). The black-box api-gateway harness has
# no Kratos-hook fixture, so the member tuple is never emitted in e2e — these
# cases asserted an activation tuple the fixture never produces (RED for a
# test-authoring reason, not a product bug; RC-2 is 150/0 GREEN at integration).
# Intentionally not reproduced here.
# ─────────────────────────────────────────────────────────────────────────────
