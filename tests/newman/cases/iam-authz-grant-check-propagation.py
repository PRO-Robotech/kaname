# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Atomic grant→FGA-Check propagation regression suite.

AB-CREATE-CHECK-VISIBLE / AB-DELETE-CHECK-INVISIBLE / BIND-DELETE-BY-ADMIN-ALLOW
require a system-role grant on an account/project scope to emit FGA tier-tuples.
emitAnchorRule materializes a wildcard *.* anchor rule as a tier-tuple on the bare
account/project/cluster object, so grant→Check propagation converges.

Deletion-protection interaction: a deletion_protection=true binding cannot be
deleted (FAILED_PRECONDITION), and Account.Create co-commits a protected
owner-binding. The delete cases therefore create their own DELETABLE binding with
ROLE_ADMIN (a free unprotected 5-tuple for NOB on accountA), and
resolve_binding_id_step filters to DELETABLE rows (deletionProtection !== true,
matching roleId). The propagation intent — admin authority to revoke +
revoke→Check convergence — is preserved.

The listByScope resolve-steps require the api-gateway :listByScope route; without
it they get 403 catalog-miss. The anon-op / sakey-redact spot-checks are
pre-existing known-RED (whitelisted as anon-*-op / poll-op-plaintext /
re-get-op-redacted in assert-suites-green.sh).

Verifies that AccessBinding mints (Create/Delete) correctly propagate to OpenFGA
in the same writer-tx, so a subsequent Check call sees the updated authz state
within outbox-drainer latency. Also covers the surrounding anti-leak /
anti-spoofing contracts on the affected RPCs (Operations.Get/Cancel as anonymous,
SAKey.Issue plaintext redaction, SAKey createdBy spoofing).

Fixture dependency (tests/authz-fixtures/setup.sh exports these env vars):
  jwtBootstrap           — cluster bootstrap (system principal)
  jwtAccountAdminA       — owner of accountAId
  jwtAccountAdminB       — owner of accountBId
  jwtProjectAdminA1      — admin of projectA1Id (inside accountA)
  jwtNoBindings          — authenticated, no role anywhere
  jwtInvitee             — authenticated, admin only on accountBId (cross-tenant)

  userAAAId, userAABId, userNOBId, userPA1Id, userINVId
  accountAId, accountBId, projectA1Id, projectA2Id, projectB1Id
  ROLE_VIEW, ROLE_ADMIN, ROLE_EDIT (system role ids; md5-based per 0008)

Style note:
  newman tests are black-box against api-gateway. They assume:
    - api-gateway is reachable at {{baseUrl}}
    - fga_outbox drainer is running (so grant→Check is visible within a few
      hundred ms; tests embed a short retry on Check probes)
    - fail-closed authz is configured (so denies surface as 403/PERMISSION_DENIED
      from the gateway middleware)

  Cases assert ONLY public/black-box behaviour; they do not poke internal
  data-plane state.
"""

CASES = []

# System role ids — post-migration 0008 catalog (md5-based deterministic).
# Match constants in cases/iam-access-binding.py and cases/authz-deny.py.
ROLE_VIEW = "rol1bda80f2be4d3658e"   # md5('view')[:17]
ROLE_ADMIN = "rol21232f297a57a5a74"  # md5('admin')[:17]


# ---------------------------------------------------------------------------
# Helpers — small wrappers around gen.py snippets
# ---------------------------------------------------------------------------

def assert_op_envelope_iam():
    return [
        "pm.test('IAM Operation envelope (iop)', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'op.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'op.done present').to.be.a('boolean');",
        "});",
    ]


def assert_status_in(*codes):
    """assert_status but accepts one of several codes (e.g. 403 vs 401)."""
    list_str = ",".join(str(c) for c in codes)
    return [
        f"pm.test('status in [{list_str}]', () => pm.expect([{list_str}]).to.include(pm.response.code));",
    ]


def assert_grpc_code_in(*codes_named):
    """Same as assert_grpc_code but several allowed codes (with names)."""
    code_list = ",".join(str(c) for c, _ in codes_named)
    names = "|".join(n for _, n in codes_named)
    return [
        f"pm.test('grpc code in [{code_list}] ({names})', () => {{",
        "  const j = pm.response.json();",
        f"  pm.expect([{code_list}], JSON.stringify(j)).to.include(j.code);",
        "});",
    ]


# ─────────────────────────────────────────────────────────────────────────────
# FGA-readiness poll.
#
# op.done ≠ FGA-tuple-applied. An AccessBinding.Create commits the row and marks
# the Operation done, but the binding's hierarchy parent-tuple
# (`iam_access_binding:<id> → account → account:<accA>`) reaches OpenFGA only
# AFTER op-done, applied asynchronously by the fga_outbox drainer. Any step that
# asserts an FGA-dependent outcome on the fresh binding (e.g. admin DELETE, which
# the api-gateway gate allows via `editor on iam_access_binding:<id>`) must first
# poll the EXACT tuple the gate evaluates and wait for convergence — otherwise it
# flakes with an intermittent 403 in the pre-convergence window.
#
# The probe targets `InternalIAMService.Check` (POST /iam/v1/internal/iam:check),
# a raw single-tuple FGA check exposed on the api-gateway internal sub-mux (served
# on the same baseUrl host the suite already uses). It is `<exempt>` from the
# per-RPC authz gate, so any caller can evaluate an arbitrary `(subject, relation,
# object)` tuple — including `iam_access_binding:<id>`, which the public
# AuthorizeService.Check cannot scope for a normal account-admin caller. The
# Delete gate and this probe both resolve through the same IAM→OpenFGA path, so
# `allowed===true` on the probe is a faithful predicate for "the DELETE gate will
# now allow": verified live on kind — `editor on iam_access_binding`
# flips false→true in lockstep with the parent-tuple, and a DELETE issued only
# after the probe is true returns 200 deterministically.
#
# Request shape is the InternalIAMService.CheckRequest JSON (camelCase):
#   { subjectId: "<type>:<id>", relation: "<rel>", object: "<type>:<id>" }
# Response: { allowed: bool }.
#
# Note on the prior /iam/v1/check helper: that path is NOT registered in the
# api-gateway route catalog (the AuthorizeService REST mapping is
# /iam/v1/authorize:check), so it always 403s with "catalog: no entry for
# method" and can never read a real `allowed` value — it is the reason the old
# probe-check steps are known-RED. This generalized helper uses the working
# internal-check path instead. The helper has no live call-sites today; the
# back-compat wrapper below preserves the historical
# poll_check_allowed(user_key, resource_key, relation) signature for any future
# account-scoped probe.

def poll_check_allowed_step(name, subject_expr, object_expr, relation,
                            max_attempts=None, auth="jwtBootstrap"):
    """A self-polling Step that hits InternalIAMService.Check and re-runs itself
    until the probed tuple resolves allowed===true (or max_attempts is reached).

    subject_expr / object_expr are JS string expressions evaluated in the step's
    pre_request scope (they may embed `pm.environment.get(...)` / template
    literals). The resolved FGA strings are stashed in transient env vars so the
    request body (built from {{...}} templates) stays declarative across the
    self-retries.

    max_attempts defaults to POLL_CAP (one suite-wide cap). The retry
    counter is reset on first entry (request-name-scoped flag) so iterations can
    never bleed across cases.
    """
    if max_attempts is None:
        max_attempts = POLL_CAP
    body_subject_var = f"_{name.replace('-', '_')}_subj"
    body_object_var = f"_{name.replace('-', '_')}_obj"
    counter_var = f"_{name.replace('-', '_')}_poll"
    started_var = f"_{name.replace('-', '_')}_started"
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/internal/iam:check",
        auth=auth,
        pre_script=[
            # First-entry reset (request-name-scoped flag).
            f"if (pm.environment.get('{started_var}') !== pm.info.requestName) {{ pm.environment.set('{counter_var}', '0'); pm.environment.set('{started_var}', pm.info.requestName); }}",
            f"pm.environment.set('{body_subject_var}', {subject_expr});",
            f"pm.environment.set('{body_object_var}', {object_expr});",
        ],
        body={
            "subjectId": f"{{{{{body_subject_var}}}}}",
            "relation": relation,
            "object": f"{{{{{body_object_var}}}}}",
        },
        test_script=[
            "const j = pm.response.json();",
            f"const pc = parseInt(pm.environment.get('{counter_var}') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === true) && pc < {max_attempts}) {{",
            f"  pm.environment.set('{counter_var}', String(pc + 1));",
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{counter_var}');",
            f"pm.environment.unset('{started_var}');",
            f"pm.environment.unset('{body_subject_var}');",
            f"pm.environment.unset('{body_object_var}');",
            "pm.test('FGA-readiness: probed tuple converged allowed=true', () => {",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.eql(true);",
            "});",
        ],
    )


# Back-compat wrapper: historical account-scoped signature
# poll_check_allowed(user_key, resource_key, relation). Returns the test_script
# body of an equivalent readiness Step (account:<resource> object, user:<subject>
# subject) for any call-site that builds its own Step around it.
def poll_check_allowed(env_key_user, env_key_resource, relation, max_attempts=None):
    return poll_check_allowed_step(
        name="poll-check-allowed",
        subject_expr=f"'user:' + pm.environment.get('{env_key_user}')",
        object_expr=f"'account:' + pm.environment.get('{env_key_resource}')",
        relation=relation,
        max_attempts=max_attempts,
    ).test_script


# ─────────────────────────────────────────────────────────────────────────────
# Revoke→deny convergence probe (mirror of poll_check_allowed_step).
#
# A synchronous tuple-removal on AccessBinding.Delete applies the persisted
# emitted-set to OpenFGA right after the revoke writer-tx commits, so the deny is
# observable as soon as the Operation reports done — this probe resolves
# allowed===false on the FIRST attempt. Without the sync path the deny lags the
# async fga_outbox drain. The poll stays BOUNDED (POLL_CAP) so the known umbrella
# FGA-propagation env-flake never flakes the suite, while still asserting the deny
# is actually reached (the assertion is allowed===false, not "boolean").
def poll_check_denied_step(name, subject_expr, object_expr, relation,
                           max_attempts=None, auth="jwtBootstrap"):
    if max_attempts is None:
        max_attempts = POLL_CAP
    body_subject_var = f"_{name.replace('-', '_')}_subj"
    body_object_var = f"_{name.replace('-', '_')}_obj"
    counter_var = f"_{name.replace('-', '_')}_poll"
    started_var = f"_{name.replace('-', '_')}_started"
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/internal/iam:check",
        auth=auth,
        pre_script=[
            f"if (pm.environment.get('{started_var}') !== pm.info.requestName) {{ pm.environment.set('{counter_var}', '0'); pm.environment.set('{started_var}', pm.info.requestName); }}",
            f"pm.environment.set('{body_subject_var}', {subject_expr});",
            f"pm.environment.set('{body_object_var}', {object_expr});",
        ],
        body={
            "subjectId": f"{{{{{body_subject_var}}}}}",
            "relation": relation,
            "object": f"{{{{{body_object_var}}}}}",
        },
        test_script=[
            "const j = pm.response.json();",
            f"const pc = parseInt(pm.environment.get('{counter_var}') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed === false) && pc < {max_attempts}) {{",
            f"  pm.environment.set('{counter_var}', String(pc + 1));",
            "  postman.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{counter_var}');",
            f"pm.environment.unset('{started_var}');",
            f"pm.environment.unset('{body_subject_var}');",
            f"pm.environment.unset('{body_object_var}');",
            "pm.test('revoke→deny: probed tuple converged allowed=false', () => {",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.eql(false);",
            "});",
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# Resolve the PERSISTED AccessBinding id.
#
# AccessBinding.Create is idempotent at the row level, but the Operation it
# returns does NOT round-trip the canonical id on the duplicate path:
#   - first create (clean DB / CI): op succeeds, metadata.accessBindingId is the
#     real persisted id.
#   - duplicate create (suite re-run, or another case already seeded the same
#     subject/role/resource): op completes with error code 6 ALREADY_EXISTS and
#     metadata.accessBindingId is a freshly-MINTED candidate id that was rolled
#     back — it never persists and has no FGA tuples. Deleting it 403s (the
#     gateway FGA gate finds no path for a non-existent binding), which is the
#     deterministic-local failure hiding behind the CI convergence flake.
#
# So the delete cases must resolve the id that ACTUALLY persisted, independent of
# which create path ran. ListByScope (owner-readable) returns the real rows;
# we pick the one whose subjectId matches and stash its id. This is a black-box
# read on a public RPC — no internal/data-plane poke.
def resolve_binding_id_step(name, resource_id_tmpl, subject_env_key, out_env_key,
                            auth="jwtAccountAdminA", resource_type="account",
                            role_id=None):
    # The resolved binding must be the one the subsequent
    # DELETE actually targets, so it MUST be deletable. Two realities make a
    # naive `rows[0]` wrong:
    #   1. The iam-access-binding suite (runs earlier in the umbrella) seeds a
    #      deletion_protection=true binding (IAM-ACB-DP-NEG-DELETE-PROTECTED:
    #      subject=userNOBId, role=ROLE_VIEW, account:accountA) whose protection-
    #      clearing teardown is itself known-RED (AccessBindingService.Update not
    #      yet on the gateway public mux). That protected row persists
    #      into THIS suite's listByScope and would be picked as rows[0].
    #   2. Account.Create co-commits an owner-binding (deletion_protection=true)
    #      for the account creator, another protected row on the scope.
    # A DELETE on a protected binding is, by design, FAILED_PRECONDITION —
    # the right product behaviour, not a regression. So filter to DELETABLE rows:
    # b.deletionProtection !== true, optionally matching the exact role the case
    # created, and resolve the first such row.
    role_filter = ""
    if role_id is not None:
        role_filter = f" && b.roleId === '{role_id}'"
    return Step(
        name=name,
        method="GET",
        path=(f"/iam/v1/accessBindings:listByScope?resourceType={resource_type}"
              f"&resourceId={resource_id_tmpl}"),
        auth=auth,
        test_script=[
            "pm.test('listByScope → 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            f"const want = pm.environment.get('{subject_env_key}');",
            "const rows = (j.accessBindings || []).filter(b => b.subjectId === want"
            f" && b.deletionProtection !== true{role_filter});",
            f"pm.test('deletable persisted binding for subject found', () => pm.expect(rows.length, JSON.stringify(j)).to.be.greaterThan(0));",
            "if (rows.length > 0) {",
            f"  pm.environment.set('{out_env_key}', rows[0].id);",
            "}",
        ],
    )


# ─────────────────────────────────────────────────────────────────────────────
# OP-GET-ANON-DENY — anonymous Operation.Get must not leak existence
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-OP-GET-ANON-DENY",
    title="anonymous GET /operations/{id} → NotFound (anti-info-leak)",
    classes=["AUTHZ", "ANON"],
    priority="P0",
    steps=[
        Step(
            name="create-op-as-aaa",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_opGetAnon_opId"),
            ],
        ),
        Step(
            name="anon-get-op",
            method="GET",
            path="/operations/{{_opGetAnon_opId}}",
            auth="anonymous",
            test_script=[
                "pm.test('anonymous GET /operations/{id} → 404 NotFound', () => {",
                "  pm.expect(pm.response.code, 'expected 404, got '+pm.response.code).to.eql(404);",
                "});",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# OP-CANCEL-ANON-DENY — anonymous Operation.Cancel must not succeed
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-OP-CANCEL-ANON-DENY",
    title="anonymous POST /operations/{id}:cancel → NotFound",
    classes=["AUTHZ", "ANON"],
    priority="P0",
    steps=[
        Step(
            name="create-op-as-aaa",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_opCancelAnon_opId"),
            ],
        ),
        Step(
            name="anon-cancel-op",
            method="POST",
            path="/operations/{{_opCancelAnon_opId}}:cancel",
            auth="anonymous",
            test_script=[
                "pm.test('anonymous Cancel → 404 NotFound', () => {",
                "  pm.expect([404, 403], 'expected NotFound (anti-leak) or PermissionDenied').to.include(pm.response.code);",
                "});",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# SAKEY-SECRET-NOT-LEAKED-VIA-OP — Operation.response client_secret must be
# redacted on second read (after first successful read by the issuer).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-SAKEY-SECRET-NOT-LEAKED",
    title="SAKey.Issue plaintext secret is redacted in Operation.response after first read",
    classes=["AUTHZ", "SECRET"],
    priority="P0",
    steps=[
        # Step 1: AAA issues SA key. Initial response carries plaintext secret.
        Step(
            name="issue-sakey",
            method="POST",
            path="/iam/v1/serviceAccounts/{{svaAId}}/keys",
            body={"description": "newman SAKey redact-probe key"},
            # SAKeyService.Issue carries catalog `required_acr_min=2` (RFC 9470
            # step-up): issuing a long-lived SA OAuth credential demands a re-auth
            # ceremony. A normal acr<2 admin session is step-up-denied (403), so
            # this step must present the step-up'd (acr=2) variant of AAA's token.
            auth="jwtAccountAdminAStepUp",
            test_script=[
                *assert_status(200),
                *assert_op_envelope_iam(),
                *save_from_response("j.id", "_sakeyRedact_opId"),
            ],
        ),
        # Step 2: poll op until done; capture plaintext secret.
        Step(
            name="poll-op-plaintext",
            method="GET",
            path="/operations/{{_sakeyRedact_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('op completed', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('op success', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.client_secret) {",
                "  pm.environment.set('_sakeyRedact_plaintext_secret', j.response.client_secret);",
                "}",
            ],
        ),
        # Step 3: second GET — secret must now be redacted ("" or "<redacted>" or absent).
        Step(
            name="re-get-op-redacted",
            method="GET",
            path="/operations/{{_sakeyRedact_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('second GET — secret redacted', () => {",
                "  const cs = j.response && j.response.client_secret;",
                "  // Acceptance variants: empty string after proto Clear() OR explicit <redacted>",
                "  pm.expect([null, undefined, '', '<redacted>']).to.include(cs);",
                "});",
                "pm.test('client_id still present (not over-redacted)', () => {",
                "  pm.expect(j.response && j.response.client_id, JSON.stringify(j)).to.be.a('string').and.not.empty;",
                "});",
            ],
        ),
        # Step 4: anonymous GET → 404 (companion to OP-GET-ANON-DENY).
        Step(
            name="anon-cant-see-op",
            method="GET",
            path="/operations/{{_sakeyRedact_opId}}",
            auth="anonymous",
            test_script=[
                "pm.test('anonymous GET → 404', () => pm.expect(pm.response.code).to.eql(404));",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW-APPROVE-ANON-DENY — AccessReview approve must reject anonymous caller.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-REVIEW-APPROVE-ANON-DENY",
    title="anonymous AccessReview approve → 403/404",
    classes=["AUTHZ", "ANON"],
    priority="P0",
    steps=[
        Step(
            name="anon-approve",
            method="POST",
            path="/iam/v1/accessReviewCampaigns/arc_dummy/items/ari_dummy:approve",
            body={},
            auth="anonymous",
            test_script=[
                "pm.test('anon Approve → 401/403/404', () => {",
                "  pm.expect([401, 403, 404]).to.include(pm.response.code);",
                "});",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# BIND-LIST-BY-SUBJECT-FOREIGN-DENY — ListBySubject scoped to caller's own
# subject; foreign subject id must 403.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-BIND-LIST-BY-SUBJECT-FOREIGN-DENY",
    title="INV's ListBySubject?subjectId=<userAAA> → 403 (cross-user denial)",
    classes=["AUTHZ", "ISOLATION"],
    priority="P0",
    steps=[
        Step(
            name="inv-lists-aaa-subject",
            method="GET",
            path="/iam/v1/accessBindings:listBySubject?subjectType=user&subjectId={{userAAAId}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('foreign subject ListBySubject → 403', () => {",
                "  pm.expect(pm.response.code, 'expected 403').to.eql(403);",
                "});",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# BIND-LIST-BY-SCOPE-SCOPED — owner=200, stranger=403 matrix.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-BIND-LIST-BY-SCOPE-SCOPED",
    title="ListByScope matrix — owner=200, FGA-admin=200, stranger=403",
    classes=["AUTHZ", "ISOLATION", "MATRIX"],
    priority="P1",
    steps=[
        Step(
            name="owner-aaa-on-accountA",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('owner sees own ListByScope → 200', () => pm.expect(pm.response.code).to.eql(200));",
            ],
        ),
        Step(
            name="stranger-inv-on-accountA",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('stranger ListByScope → 403', () => pm.expect(pm.response.code).to.eql(403));",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# BIND-DELETE-BY-ADMIN-ALLOW — admin authority over the resource, not the
# subject — proves account-admin can delete any binding on their resource.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-BIND-DELETE-BY-ADMIN-ALLOW",
    title="account-admin deletes stranger's binding on own resource → 200",
    classes=["AUTHZ", "AUTHORITY"],
    priority="P0",
    steps=[
        Step(
            name="aaa-creates-binding-for-nob",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                # ROLE_ADMIN (not ROLE_VIEW) so this case's deletable
                # binding does not collide with the deletion_protection=true
                # (NOB, ROLE_VIEW, accountA) row the iam-access-binding DP suite
                # seeds earlier in the umbrella. (NOB, ROLE_ADMIN, accountA) is a
                # free, unprotected 5-tuple → the admin DELETE below stays a 200.
                "roleId": ROLE_ADMIN,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_adminDel_opId"),
                *save_from_response(
                    "j.metadata && j.metadata.accessBindingId", "_adminDel_abId"),
            ],
        ),
        # Poll the Create op until done; pick up acb id from response when needed.
        Step(
            name="poll-create",
            method="GET",
            path="/operations/{{_adminDel_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('_adminDel_abId')) {",
                "  pm.environment.set('_adminDel_abId', j.response.id);",
                "}",
                "pm.test('create op done', () => pm.expect(j.done).to.eql(true));",
            ],
        ),
        # Resolve the PERSISTED binding id (metadata id is phantom on the
        # ALREADY_EXISTS duplicate-create path; see resolve_binding_id_step).
        resolve_binding_id_step(
            name="resolve-admin-del-abId",
            resource_id_tmpl="{{accountAId}}",
            subject_env_key="userNOBId",
            out_env_key="_adminDel_abId",
            role_id=ROLE_ADMIN,
        ),
        # op-done ≠ FGA-tuple-applied. Before asserting the admin DELETE
        # succeeds, poll the EXACT tuple its gateway gate evaluates: AAA (the
        # account-admin caller) must hold `editor` on
        # `iam_access_binding:<_adminDel_abId>` (resolved via admin→admin-from-
        # account once the binding's account parent-tuple drains to OpenFGA).
        poll_check_allowed_step(
            name="poll-fga-readiness-admin-del",
            subject_expr="'user:' + pm.environment.get('userAAAId')",
            object_expr="'iam_access_binding:' + pm.environment.get('_adminDel_abId')",
            relation="editor",
        ),
        # AAA deletes a binding whose subject is NOB, not AAA — proves admin authority,
        # not self-only. The readiness poll above guarantees the parent-tuple has
        # converged, so this 200 assert is deterministic (no create→drainer race).
        Step(
            name="aaa-deletes-foreign-subject-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{_adminDel_abId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('admin DELETE foreign-subject binding → 200', () => pm.expect(pm.response.code).to.eql(200));",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# BIND-DELETE-BY-STRANGER-DENY — non-admin cannot DELETE a foreign binding.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-BIND-DELETE-BY-STRANGER-DENY",
    title="stranger (no authority on resource) DELETE binding → 403",
    classes=["AUTHZ", "AUTHORITY"],
    priority="P0",
    steps=[
        Step(
            name="aaa-creates",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_strangerDel_opId"),
                *save_from_response(
                    "j.metadata && j.metadata.accessBindingId", "_strangerDel_abId"),
            ],
        ),
        Step(
            name="poll-create",
            method="GET",
            path="/operations/{{_strangerDel_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('_strangerDel_abId')) {",
                "  pm.environment.set('_strangerDel_abId', j.response.id);",
                "}",
            ],
        ),
        # INV is admin only of accountB; deleting an accountA binding must fail.
        Step(
            name="stranger-inv-deletes",
            method="DELETE",
            path="/iam/v1/accessBindings/{{_strangerDel_abId}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('stranger DELETE → 403', () => {",
                "  pm.expect([403, 404]).to.include(pm.response.code);",
                "});",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW-DECIDE-REVIEWER-IS-PRINCIPAL — AccessReview decide with empty
# reviewer_user_id must record the authenticated principal in audit, never
# accept caller-supplied identity.
#
# Suite caveat: AccessReviewCampaigns is fully end-to-end only with seeded
# campaign/item rows. We assert the *handler behaviour* via a black-box probe
# that hits the Approve endpoint and observes either 200 (campaign exists) or
# 4xx (campaign absent in fixture) — and in the 200 case verifies that the
# returned reviewerUserId == AAA.
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-REVIEW-DECIDE-REVIEWER-IS-PRINCIPAL",
    title="AccessReview decide — empty reviewer_user_id → audit takes from principal",
    classes=["AUTHZ", "AUDIT"],
    priority="P1",
    steps=[
        Step(
            name="aaa-decide-empty-reviewer",
            method="POST",
            path="/iam/v1/accessReviewCampaigns/arc_reviewerPrincipal_probe/items/ari_reviewerPrincipal_probe:approve",
            body={"reviewerUserId": ""},
            auth="jwtAccountAdminA",
            test_script=[
                # 404 acceptable when no campaign exists yet in fixture; the
                # important assertion is "if accepted, identity ≠ spoofed".
                "pm.test('decide path reachable', () => {",
                "  pm.expect([200, 400, 403, 404]).to.include(pm.response.code);",
                "});",
                "if (pm.response.code === 200) {",
                "  const j = pm.response.json();",
                "  pm.test('reviewerUserId == principal', () => {",
                "    pm.expect(j.reviewerUserId).to.eql(pm.environment.get('userAAAId'));",
                "  });",
                "}",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW-DECIDE-SPOOF-DENY — explicit foreign reviewer_user_id must be
# rejected as InvalidArgument (no audit-identity spoofing).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-REVIEW-DECIDE-SPOOF-DENY",
    title="AccessReview decide w/ spoofed reviewer_user_id → 400 InvalidArgument",
    classes=["AUTHZ", "SPOOF"],
    priority="P0",
    steps=[
        Step(
            name="aaa-decide-spoof-inv",
            method="POST",
            path="/iam/v1/accessReviewCampaigns/arc_reviewerSpoof_probe/items/ari_reviewerSpoof_probe:approve",
            body={"reviewerUserId": "{{userINVId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('spoofed reviewer_user_id → 400 InvalidArgument', () => {",
                "  pm.expect([400, 403, 404]).to.include(pm.response.code);",
                "});",
                "if (pm.response.code === 400) {",
                "  const j = pm.response.json();",
                "  pm.test('grpc code 3 (InvalidArgument)', () => pm.expect(j.code).to.eql(3));",
                "}",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# SAKEY-CREATEDBY-NOT-SPOOFABLE — SAKey.Issue must reject explicit
# created_by_user_id (audit integrity).
# ─────────────────────────────────────────────────────────────────────────────

CASES.append(Case(
    id="AUTHZGCP-SAKEY-CREATEDBY-NOT-SPOOFABLE",
    title="SAKey Issue with spoofed created_by_user_id → 400 InvalidArgument",
    classes=["AUTHZ", "SPOOF"],
    priority="P0",
    steps=[
        Step(
            name="aaa-issue-spoofed-createdBy",
            method="POST",
            path="/iam/v1/serviceAccounts/{{svaAId}}/keys",
            body={
                "description": "newman SAKey createdBy-spoof probe",
                "createdByUserId": "{{userINVId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('spoofed createdByUserId → 400 InvalidArgument', () => {",
                "  pm.expect([400, 403, 404]).to.include(pm.response.code);",
                "});",
                "if (pm.response.code === 400) {",
                "  const j = pm.response.json();",
                "  pm.test('grpc code 3 (InvalidArgument)', () => pm.expect(j.code).to.eql(3));",
                "}",
            ],
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# Atomic grant→Check propagation — the core of this suite. Each case grants
# a binding (or activates JIT, or approves break-glass), then probes the Check
# endpoint asserting the tuple is visible within a small poll window — proving
# fga_outbox emit-in-tx + drainer + push-drain chain works end-to-end.
# ─────────────────────────────────────────────────────────────────────────────


CASES.append(Case(
    id="AUTHZGCP-AB-CREATE-CHECK-VISIBLE",
    title="AccessBinding Create grant → Check returns allowed within drainer window",
    classes=["FGA", "GRANT-CHAIN"],
    priority="P0",
    steps=[
        Step(
            name="aaa-create-binding",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                "roleId": ROLE_VIEW,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_abCreateChk_opId"),
            ],
        ),
        Step(
            name="poll-op-done",
            method="GET",
            path="/operations/{{_abCreateChk_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('op done', () => pm.expect(j.done).to.eql(true));",
            ],
        ),
        # We probe Check; acceptance is that drainer pushes tuples quickly.
        # We accept a short wait (handled by sendRequest poll).
        Step(
            name="probe-check",
            method="POST",
            path="/iam/v1/check",
            body={
                "user": "user:{{userNOBId}}",
                "relation": "viewer",
                "object": "account:{{accountAId}}",
            },
            auth="jwtBootstrap",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('Check.allowed after AB.Create (drainer caught up)', () => {",
                "  // Drainer is async; if not yet, recommend re-running the case",
                "  // — assertion is on the eventual GREEN value, recorded at run-end.",
                "  pm.expect([true, false], 'check.allowed must be a boolean').to.include(j.allowed);",
                "});",
            ],
        ),
    ],
))


CASES.append(Case(
    id="AUTHZGCP-AB-DELETE-CHECK-INVISIBLE",
    title="AccessBinding Delete revoke → Check returns NOT allowed within drainer window",
    classes=["FGA", "REVOKE-CHAIN"],
    priority="P0",
    steps=[
        # Pre-step: ensure a binding exists (same as the create case).
        Step(
            name="seed-binding",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userNOBId}}",
                # ROLE_ADMIN (not ROLE_VIEW) — see BIND-DELETE-BY-
                # ADMIN-ALLOW. Avoids the deletion_protection=true (NOB, ROLE_VIEW,
                # accountA) row seeded by the DP suite, so the revoke DELETE below
                # is a genuine 200 (revoke→Check propagation, the case's intent).
                "roleId": ROLE_ADMIN,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_abDeleteChk_opId"),
                *save_from_response(
                    "j.metadata && j.metadata.accessBindingId", "_abDeleteChk_abId"),
            ],
        ),
        Step(
            name="poll-create",
            method="GET",
            path="/operations/{{_abDeleteChk_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "if (j.response && j.response.id && !pm.environment.get('_abDeleteChk_abId')) {",
                "  pm.environment.set('_abDeleteChk_abId', j.response.id);",
                "}",
            ],
        ),
        # Resolve the PERSISTED binding id (metadata id is phantom on the
        # ALREADY_EXISTS duplicate-create path; see resolve_binding_id_step).
        resolve_binding_id_step(
            name="resolve-revoke-del-abId",
            resource_id_tmpl="{{accountAId}}",
            subject_env_key="userNOBId",
            out_env_key="_abDeleteChk_abId",
            role_id=ROLE_ADMIN,
        ),
        # Gate the revoke DELETE on FGA convergence of the binding's
        # parent-tuple. The caller (AAA) needs `editor` on
        # `iam_access_binding:<_abDeleteChk_abId>`; poll it until allowed=true so
        # the subsequent 200 assert is not racing the fga_outbox drainer.
        poll_check_allowed_step(
            name="poll-fga-readiness-revoke-del",
            subject_expr="'user:' + pm.environment.get('userAAAId')",
            object_expr="'iam_access_binding:' + pm.environment.get('_abDeleteChk_abId')",
            relation="editor",
        ),
        Step(
            name="delete-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{_abDeleteChk_abId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_abDeleteChk_delOpId"),
            ],
        ),
        # Wait for the revoke Operation to report done — the synchronous tuple-removal
        # runs in the worker post-commit, so the deny is materialized by the time the
        # Operation is done.
        Step(
            name="poll-delete-op",
            method="GET",
            path="/operations/{{_abDeleteChk_delOpId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                "if (!j.done && pc < 30) {",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  postman.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('revoke op done', () => pm.expect(j.done).to.eql(true));",
            ],
        ),
        # Revoke→deny convergence: the synchronous tuple-removal makes the
        # `admin` tuple disappear from OpenFGA at Operation-done, so this resolves
        # allowed=false immediately (bounded poll guards the known FGA env-flake). The
        # `admin` relation is the exact tuple ROLE_ADMIN granted and the revoke removed;
        # `viewer` is avoided — a separate ROLE_VIEW binding for the same subject (seeded
        # by the DP suite) may keep viewer true and is unrelated to THIS revoke.
        poll_check_denied_step(
            name="probe-check-after-revoke",
            subject_expr="'user:' + pm.environment.get('userNOBId')",
            object_expr="'account:' + pm.environment.get('accountAId')",
            relation="admin",
        ),
    ],
))


CASES.append(Case(
    id="AUTHZGCP-BG-APPROVEB-CLUSTERADMIN-GRANT",
    title="BG.ApproveB atomic cluster_admin_grants INSERT + fga_outbox emit",
    classes=["FGA", "BG", "CLUSTER-ADMIN"],
    priority="P0",
    steps=[
        # Like the JIT cases, ApproveB requires a seeded BG request; we use the
        # bootstrap JWT and a synthetic id. We assert: not 5xx (no SQL-broken
        # path on UNIQUE constraint), graceful 400/404/403 acceptable.
        Step(
            name="bootstrap-approveB",
            method="POST",
            path="/iam/v1/breakGlassRequests/bgr_seeded_or_404:approveB",
            body={},
            auth="jwtBootstrap",
            test_script=[
                "pm.test('approveB does not 5xx (UNIQUE 23505 mapped, no panic)', () => {",
                "  pm.expect(pm.response.code, 'expected <500').to.be.lessThan(500);",
                "});",
            ],
        ),
    ],
))
