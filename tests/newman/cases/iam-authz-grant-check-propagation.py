# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

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
it they get 403 catalog-miss. The anon-op / sakey-redact spot-checks used to be
exempted by name in the runner; that list was REMOVED whole (see
scripts/assert-suites-green.sh, which now states that nothing is subtracted), so
these steps are gated like every other assertion here.

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
# a raw single-tuple FGA check exposed ONLY on the api-gateway cluster-internal REST
# listener ({{internalBaseUrl}}, :18081) — the public :18080 404s /iam/v1/internal/*
# by design (ban #6). Each probe step's pre_script redirects there via
# _internal_url_override (without it the probe hits the public port → 404 → JSONError).
# It is `<exempt>` from the
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
# method" and can never read a real `allowed` value — that is why the probe-check
# steps that used it were REMOVED. This generalized helper uses the working
# internal-check path instead. The helper has no live call-sites today; the
# back-compat wrapper below preserves the historical
# poll_check_allowed(user_key, resource_key, relation) signature for any future
# account-scoped probe.

def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are
    served ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design
    (ban #6). gen.py emits {{baseUrl}}<path>; without this override the FGA-Check
    probe hits the public port → 404 page-not-found → JSONError. Mirrors
    iam-internal-only-check.py::_internal_url_override. internalBaseUrl is injected
    at runtime by deploy/scripts/newman-e2e.sh."""
    return require_env_url(
        "internalBaseUrl", path,
        "internal-only Check probe — /iam/v1/internal/* is served ONLY by the "
        "cluster-internal REST listener")


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
            *_internal_url_override("/iam/v1/internal/iam:check"),
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
            # Real inter-poll delay (~500ms) between retries (Koren #1). Without it the
            # setNextRequest re-fires are only a ~round-trip apart, so the readiness poll
            # exhausts max_attempts before the caller's editor tuple on the FRESH
            # iam_access_binding materializes via fga_outbox → allowed stays !== true at the
            # cap and the downstream mutate (delete-binding) then 403s. Same discipline as
            # poll_operation_until_done.
            "  const _pcad = Date.now(); while (Date.now() - _pcad < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
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
            *_internal_url_override("/iam/v1/internal/iam:check"),
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
            # DENY predicate is `allowed !== true`, NOT `allowed === false`: the
            # InternalIAMService.Check response is proto3-JSON, which OMITS the bool
            # `allowed` when it is the default `false` (a real deny returns
            # `{"reason":"subject ... lacks relation ..."}` with NO `allowed` field).
            # `j.allowed === false` is therefore `undefined === false` → never true →
            # the poll would spin to the cap and fail even on a correct deny. A genuine
            # still-allowed returns `{"allowed":true}`, so `allowed !== true` still
            # fails it — nothing is masked.
            f"if (!(pm.response.code === 200 && j.allowed !== true) && pc < {max_attempts}) {{",
            f"  pm.environment.set('{counter_var}', String(pc + 1));",
            "  const _ipd1 = Date.now(); while (Date.now() - _ipd1 < 500) void 0; /* real inter-poll delay: cap 30 x 500ms ~= 15s budget (testing.md) */",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{counter_var}');",
            f"pm.environment.unset('{started_var}');",
            f"pm.environment.unset('{body_subject_var}');",
            f"pm.environment.unset('{body_object_var}');",
            "pm.test('revoke→deny: probed tuple converged allowed=false', () => {",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed === true, JSON.stringify(j)).to.eql(false);",
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
    #      subject=userNOBId, role=ROLE_VIEW, account:accountA). Its protection-
    #      clearing teardown was once declared red because AccessBindingService.Update
    #      was not on the gateway public mux; it IS there now
    #      (PATCH /iam/v1/accessBindings/{id}), and the declaration went with the
    #      defect. That protected row persists
    #      into THIS suite's listByScope and would be picked as rows[0].
    #   2. Account.Create co-commits an owner-binding (deletion_protection=true)
    #      for the account creator, another protected row on the scope.
    # A DELETE on a protected binding is, by design, FAILED_PRECONDITION —
    # the right product behaviour, not a regression. So filter to DELETABLE rows:
    # b.deletionProtection !== true, optionally matching the exact role the case
    # created, and resolve the first such row.
    #
    # Pagination (KAC-132 follow-up). `:listByScope` is cursor-paginated with a
    # DEFAULT page_size of 50 (api-conventions.md). `account:accountA` is a
    # long-lived shared fixture scope that accumulates bindings across runs — on
    # the kind stand it holds 73 rows, and EVERY `usr`-subject row sits at index
    # 53-55, i.e. on page 2. Reading a single default page therefore returned 50
    # unrelated `sva`-subject rows, the filter matched nothing, and the phantom id
    # (see the ALREADY_EXISTS note above) was left untouched in the environment.
    # The downstream FGA probe then asked for `v_delete` on an
    # `iam_access_binding` that had been rolled back and never existed — which
    # reads exactly like a missing permission-model relation, but is not one:
    # against a REAL persisted binding the account-admin does hold `v_delete`.
    # So: walk the `nextPageToken` cursor until the row is found or the scope is
    # exhausted. `cases/rbac-visibility-set.py` already carries this fix for the
    # same reason; this is the same class in the resolver.
    #
    # Note the self-`setNextRequest` below deliberately has NO inter-request
    # busy-wait: this is a page WALK, not a convergence POLL. Each iteration
    # requests a strictly different page and makes progress, so a delay would add
    # latency without adding correctness (the busy-wait discipline in testing.md
    # targets retry loops that re-probe the SAME state waiting for it to change).
    role_filter = ""
    if role_id is not None:
        role_filter = f" && b.roleId === '{role_id}'"
    tok_var = f"_{name.replace('-', '_')}_tok"
    page_var = f"_{name.replace('-', '_')}_page"
    started_var = f"_{name.replace('-', '_')}_started"
    return Step(
        name=name,
        method="GET",
        # Declarative base (pageSize pinned to the 1000 max so the common case is
        # a single round-trip); the pre-script re-derives the URL to append the
        # cursor on continuation pages.
        path=(f"/iam/v1/accessBindings:listByScope?resourceType={resource_type}"
              f"&resourceId={resource_id_tmpl}&pageSize=1000"),
        auth=auth,
        pre_script=[
            # First entry: reset the cursor AND drop any pre-seeded value of the
            # output var. That value came from `Operation.metadata.accessBindingId`,
            # which is a phantom (minted-then-rolled-back) id whenever the create
            # took the ALREADY_EXISTS path. If the resolve below fails, the step
            # must leave NOTHING behind rather than let the phantom flow onward.
            f"if (pm.environment.get('{started_var}') !== pm.info.requestName) {{",
            f"  pm.environment.set('{tok_var}', '');",
            f"  pm.environment.set('{page_var}', '0');",
            f"  pm.environment.set('{started_var}', pm.info.requestName);",
            f"  pm.environment.unset('{out_env_key}');",
            "}",
            "const _base = pm.environment.get('baseUrl') || pm.variables.get('baseUrl') || '';",
            f"const _rid = pm.variables.replaceIn('{resource_id_tmpl}');",
            f"const _tok = pm.environment.get('{tok_var}') || '';",
            f"pm.request.url = _base + '/iam/v1/accessBindings:listByScope?resourceType={resource_type}'",
            "  + '&resourceId=' + encodeURIComponent(_rid)",
            "  + '&pageSize=1000'",
            "  + (_tok ? '&pageToken=' + encodeURIComponent(_tok) : '');",
        ],
        test_script=[
            "pm.test('listByScope → 200', () => pm.expect(pm.response.code).to.eql(200));",
            "const j = pm.response.json();",
            f"const want = pm.environment.get('{subject_env_key}');",
            "const rows = (j.accessBindings || []).filter(b => b.subjectId === want"
            f" && b.deletionProtection !== true{role_filter});",
            f"const _pg = parseInt(pm.environment.get('{page_var}') || '0', 10);",
            # Not on this page, but the cursor says there is more → advance.
            # Bounded at 25 pages x 1000 rows so a runaway scope cannot spin.
            "if (rows.length === 0 && pm.response.code === 200 && j.nextPageToken && _pg < 25) {",
            f"  pm.environment.set('{tok_var}', j.nextPageToken);",
            f"  pm.environment.set('{page_var}', String(_pg + 1));",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            f"pm.environment.unset('{tok_var}');",
            f"pm.environment.unset('{page_var}');",
            f"pm.environment.unset('{started_var}');",
            "pm.test('deletable persisted binding for subject found', () => pm.expect(rows.length, JSON.stringify({pagesWalked: _pg, lastPage: j})).to.be.greaterThan(0));",
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
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
                # Anonymous hits the authN gate FIRST → 401 UNAUTHENTICATED (correct
                # denial; hide-existence 404 only applies to an AUTHENTICATED-but-
                # unauthorized caller). Either way anonymous is DENIED (no leak).
                "pm.test('anonymous GET /operations/{id} → denied (401 authN / 404 hide-existence)', () => {",
                "  pm.expect([401, 404], 'expected 401 or 404, got '+pm.response.code).to.include(pm.response.code);",
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
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
                "pm.test('anonymous Cancel → denied (401 authN / 404 hide-existence / 403)', () => {",
                "  pm.expect([401, 404, 403], 'expected denial, got '+pm.response.code).to.include(pm.response.code);",
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
        # Bounded read-your-writes retry over AAA's authz-materialization window on the
        # fixture SA object: jwtAccountAdminAStepUp carries acr=2 (step-up satisfied by the
        # fixture), so the transient 403 here is the caller's editor/admin tuple on
        # service_account:{{svaAId}} lagging the fga_outbox drain at suite cold-start, NOT a
        # step-up denial — retry SELF on 403 until authorized (fail-closed at the budget).
        retry_until_authorized(Step(
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
                # Координата УБОРКИ. Родитель `{{svaAId}}` посеян и живёт дольше
                # прогона, поэтому выпущенное здесь удостоверение остаётся в нём
                # навсегда, а вложенный потолок числа удостоверений на принципала
                # считает именно их. Пока предела не существовало, неубранное
                # ничего не занимало; теперь второй прогон подряд упирается в
                # потолок, и красным становится не этот кейс, а тот, что оказался
                # следующим, — разбор уходит в сторону.
                #
                # Берётся `metadata.keyId` — тот же источник, что у соседей
                # (`iam-token-facade-conformance.py` :: issue-sa-key,
                # `docker-lane-credential-kind.py`): другого источника id до
                # завершения операции нет. Он ПРЕДВЫДЕЛЕН и присутствует даже у
                # операции, которая завершится ошибкой, поэтому `save_from_response`
                # регистрирует имя провизорным, а снимает регистрацию тот, кто
                # первым узнаёт исход, — шаг опроса ниже (он же утверждает `done`
                # и отсутствие `error` ДО того, как id кем-то прочитан).
                *save_from_response("j.metadata.keyId", "_sakeyRedact_keyId"),
            ],
        ), budget=20, interval_ms=500, retry_on=(403,)),
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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
        # Step 3: second GET — verify the OBSERVABLE one-shot-delivery shape with the
        # ACTUAL proto3-JSON field names (camelCase: `privateKeyPem` / `clientId` /
        # `clientSecret`, under `response`). The prior version read snake_case
        # `client_secret`/`client_id` — fields that DON'T EXIST in the JSON — so
        # "secret redacted" passed vacuously (undefined ∈ allow-list) while "client_id
        # present" failed on undefined. The real one-shot secret for a keypair SA key is
        # `privateKeyPem` (an ES256 PEM); `clientSecret` is "" for this key type.
        #
        # Redaction is time-gated: the plaintext is deliberately re-readable for the
        # `sakey-redact-grace` window (default 120s — the one-shot client's read+save
        # budget) and only then cleared to "<redacted>". A fast e2e cannot observe the
        # 120s-delayed redaction, so that timing behavior is unit-covered
        # (services/iam/.../sa_keys/usecase_redaction_grace_test.go, short injected grace
        # — the correct layer for timing). Here we lock the black-box observable: the
        # credential is delivered (privateKeyPem is a real PEM) and the identifier is
        # present (clientId) — never over-redacted away.
        Step(
            name="re-get-op-redacted",
            method="GET",
            path="/operations/{{_sakeyRedact_opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('one-shot secret delivered within grace (privateKeyPem is a real PEM)', () => {",
                "  const pem = (j.response && j.response.privateKeyPem) || '';",
                "  pm.expect(pem, JSON.stringify(j)).to.include('BEGIN PRIVATE KEY');",
                "});",
                "pm.test('clientId identifier present (not over-redacted)', () => {",
                "  pm.expect(j.response && j.response.clientId, JSON.stringify(j)).to.be.a('string').and.not.empty;",
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
                # Anonymous hits the authN gate FIRST → 401 UNAUTHENTICATED; hide-existence
                # 404 only applies to an AUTHENTICATED-but-unauthorized caller. Either way
                # anonymous is DENIED and cannot see the op (no leak). Mirrors OP-GET-ANON-DENY.
                "pm.test('anonymous GET → denied (401 authN / 404 hide-existence)', () => {",
                "  pm.expect([401, 404], 'expected 401 or 404, got '+pm.response.code).to.include(pm.response.code);",
                "});",
            ],
        ),
        # ── УБОРКА: удостоверение живёт ровно этот кейс ─────────────
        #
        # Предъявитель — `jwtBootstrap`, а не выпускавший `jwtAccountAdminAStepUp`:
        # надзор облака разрешается КАСКАДОМ и окна материализации не имеет
        # by construction, тогда как у распорядителя аккаунта право на объект
        # посеянной служебной учётки догоняет очередь (именно поэтому выпуск
        # выше обёрнут повтором на 403). Та же пара «bootstrap + {{svaAId}}» уже
        # стоит у соседа — `docker-lane-credential-kind.py` :: revoke-the-credential.
        #
        # СОСТАВ ЗАКОННЫХ ИСХОДОВ назван, а не подобран (эталон —
        # `services/vpc/tests/newman/cases/concurrency.py`, блок-шапка перед
        # помощниками): 200 — снятие принято, чеканена Operation; 403 и 404 —
        # переходные состояния окна видимости, пережидаются повтором в пределах
        # бюджета; всё остальное — КРАСНОЕ. Повтор здесь не выписан руками:
        # `_wrap_own_fresh_reads` ставит его сам, потому что адрес шага ссылается
        # на переменную, захваченную этим же кейсом, а 403/404 исходом не
        # заявлены. Терминальный 403/404 роняет утверждение ниже — то есть
        # предмет остался жить.
        #
        # Исход самой операции снятия утверждает опрос: `done` — это «воркер
        # закончил», а не «сделал», и операция, завершившаяся ошибкой, тоже `done`.
        Step(
            name="revoke-sakey",
            method="DELETE",
            path="/iam/v1/serviceAccounts/{{svaAId}}/keys/{{_sakeyRedact_keyId}}",
            auth="jwtBootstrap",
            test_script=[
                *assert_answered("SAKeyService.Revoke — уборка выпущенного удостоверения"),
                *assert_status(200),
                *assert_op_envelope_iam(),
                *save_from_response("j.id", "opId"),
            ],
            op_var="opId",
        ),
        poll_operation_until_done(auth="jwtBootstrap"),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# REMOVED — AUTHZGCP-REVIEW-APPROVE-ANON-DENY (AccessReview approve, anonymous).
#
# The case posted to `/iam/v1/accessReviewCampaigns/{id}/items/{item}:approve`
# and accepted 401/403/404. There is no such RPC: `AccessReviewCampaign` exists
# nowhere in this product — no service in proto/kaname/cloud/iam/v1/, no entry in
# the gateway route table or either embedded permission catalog, no handler, and
# no table (`access_review_campaigns` is named only inside the dedup loop of
# migration 0002, which this schema never creates — see the report note). The
# design that specified it (the pre-monorepo W2.B "enterprise block" stream) was
# dropped by the RBAC v2 simplification and never carried over.
#
# So the request could not resolve to an FQN, the catalog lookup missed, and the
# gateway fail-closed 403 AUTHZ_DENIED with an EMPTY `action` — on every run, for
# every caller. The case therefore proved nothing about anonymous access; it
# proved only that an unroutable path is denied.
#
# Nothing is lost by deleting it: "anonymous cannot invoke a mutating IAM RPC" is
# covered on REAL routes, and more strictly (exact 401 + grpc code 16), by
# iam-account.py / iam-project.py / iam-user.py / iam-group.py /
# iam-service-account.py / iam-role.py create-anon steps.
# ─────────────────────────────────────────────────────────────────────────────


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
            # `action` pins the deny to ListBySubject: a bare 403 would also be
            # satisfied by a permission-catalog miss (empty action), which is what
            # a misrouted path produces. The scope anchor of this RPC is the
            # cluster singleton (scope_extractor {cluster, "*"}), whose id a
            # black-box caller does not know, so `resource` is left unpinned.
            test_script=assert_scoped_authz_deny("iam.access_bindings_by_subjects.listBySubject"),
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
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('owner sees own ListByScope → 200', () => pm.expect(pm.response.code).to.eql(200));",
            ],
        ),
        Step(
            name="stranger-inv-on-accountA",
            method="GET",
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtInvitee",
            # Same discriminator as inv-lists-aaa-subject: without `action` a bare
            # 403 is also satisfied by a catalog miss. This RPC's scope IS
            # deterministic (scope_extractor reads resource_type/resource_id off
            # the request), so the object is pinned too — the stranger must be
            # denied on accountA, not on some other anchor.
            test_script=assert_scoped_authz_deny(
                "iam.access_bindings_by_resources.listByScope",
                "'account:' + pm.environment.get('accountAId')",
            ),
        ),
    ],
))


# ─────────────────────────────────────────────────────────────────────────────
# BIND-DELETE-BY-ADMIN-ALLOW — admin authority over the resource, not the
# subject — proves account-admin can delete any binding on their resource.
# ─────────────────────────────────────────────────────────────────────────────

# ИДЕНТИФИКАТОР ПРИВЯЗКИ В ЭТИХ ДВУХ КЕЙСАХ БЕРЁТСЯ ТОЛЬКО ИЗ ЛИСТИНГА
# (resolve_binding_id_step), НИ ИЗ МЕТАДАННЫХ ОПЕРАЦИИ, НИ ИЗ ЕЁ ОТВЕТА.
#
# Область здесь — долгоживущая общая фикстура, поэтому на каждом прогоне после
# первого создание законно идёт путём «уже существует»: операция несёт ошибку, а
# идентификатор в её метаданных выделен ДО отказа и указывает на несозданное.
# Прежняя редакция публиковала его и опрашивала операцию, утверждая одно лишь
# `done`, — то есть уносила координату фантома дальше, и предмет проверки (кто
# вправе снять чужую привязку) подменялся отказом харнесса.
#
# Утверждать здесь успех операции НЕЛЬЗЯ: её ошибка на повторном прогоне
# законна. Поэтому снят не контроль, а ИСТОЧНИК фантома — публиковать нечего, а
# разрешение из листинга верно на обоих путях, и на только что созданном, и на
# уже существовавшем.
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_adminDel_opId"),
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
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
            relation="v_delete",
        ),
        # AAA deletes a binding whose subject is NOB, not AAA — proves admin authority,
        # not self-only. The readiness poll above guarantees the parent-tuple has
        # converged, so this 200 assert is deterministic (no create→drainer race).
        Step(
            name="aaa-deletes-foreign-subject-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{_adminDel_abId}}",
            auth="jwtAccountAdminAStepUp",
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "_strangerDel_opId"),
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                # ТА ЖЕ СТРОКА, ЧТО У БЛИЗНЕЦА ВЫШЕ (AUTHZGCP-BIND-DELETE-BY-ADMIN-ALLOW).
                # Полос у этого механизма две, и утверждение стояло только на одной —
                # различие никто не решал, оно осталось от той же неполной правки, о
                # которой говорит комментарий следующего шага. Без него исчерпанный
                # бюджет опроса (15 с) молчал: предмет кейса не создан, а виновником
                # отчёт называл резолв идентификатора шагом ниже.
                #
                # Утверждается ЗАВЕРШЕНИЕ, а не успех — и это не смягчение, а
                # содержание полосы: у долгоживущей общей фикстуры повторное создание
                # законно уходит по пути ALREADY_EXISTS, и операция тогда несёт ошибку
                # (следующий шаг разбирает ровно этот случай и резолвит уже
                # сохранённую привязку из списка). Требовать здесь отсутствия ошибки
                # значило бы объявить штатный путь дефектом.
                "pm.test('create op done', () => pm.expect(j.done).to.eql(true));",
            ],
        ),
        # Resolve the PERSISTED binding id — same reason as in
        # AUTHZGCP-BIND-DELETE-BY-ADMIN-ALLOW above, where this already stood. The
        # fix had simply not reached this half. The scope is a long-lived shared
        # fixture, so on every run after the first this create takes the
        # ALREADY_EXISTS path: the operation then carries an error, the id in its
        # metadata is a phantom the collection-level guard drops, and the DELETE
        # below is left with an unresolved template — a case about AUTHORITY
        # reporting a harness fault instead. Resolving from the listing holds on
        # BOTH paths, just-created and already-there.
        resolve_binding_id_step(
            name="resolve-stranger-del-abId",
            resource_id_tmpl="{{accountAId}}",
            subject_env_key="userNOBId",
            out_env_key="_strangerDel_abId",
            role_id=ROLE_VIEW,
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
# REMOVED — AUTHZGCP-REVIEW-DECIDE-REVIEWER-IS-PRINCIPAL and
#           AUTHZGCP-REVIEW-DECIDE-SPOOF-DENY.
#
# Both posted to `/iam/v1/accessReviewCampaigns/{id}/items/{item}:approve` — the
# same non-existent RPC as the deleted REVIEW-APPROVE-ANON-DENY above (no proto
# service, no route, no catalog entry, no handler, no table). Both accepted a
# 4xx as a pass, and the 4xx they always received was the gateway's catalog-miss
# 403 (empty `action`), never the behaviour named in the title:
#
#   * "decide path reachable" was satisfied by an unreachable path;
#   * the `reviewerUserId == principal` assertion sat behind `if (code === 200)`
#     and never executed;
#   * "spoofed reviewer_user_id → 400 InvalidArgument" never saw a 400, so the
#     grpc-code-3 assertion behind `if (code === 400)` never executed either.
#
# The contract they were written for — audit identity comes from the
# authenticated principal, a caller-supplied identity is rejected — is exercised
# on a REAL route by AUTHZGCP-SAKEY-CREATEDBY-NOT-SPOOFABLE below
# (`POST /iam/v1/serviceAccounts/{id}/keys` with `createdByUserId`).
# ─────────────────────────────────────────────────────────────────────────────


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
                # КОД ОТВЕТА УТВЕРЖДАЕТСЯ В ОДНОЙ СТРОКЕ С `pm.response.code`, и это
                # не косметика. Шаг не создаёт ничего — он утверждает ОТКАЗ, — но
                # прежняя форма (`pm.expect([...]).to.include(pm.response.code)`)
                # не читается построчным разбором гейта дерева
                # `TestSeededParentChildrenAreReclaimedBySuites`: тот видит строку с
                # `response.code`, не находит в ней ни `to.eql(NNN)`, ни `oneOf([…])`
                # и — намеренно ошибаясь в сторону находки — засчитывает шаг
                # УСПЕШНЫМ созданием удостоверения в посеянной служебной учётке
                # `{{svaAId}}`. Родитель посеян и живёт дольше прогона, поэтому такой
                # шаг выглядел утечкой под вложенным потолком, которой нет.
                # Набор принимаемых кодов тот же (авторизация решается раньше
                # валидации — `testing.md` §e2e-инварианты), добавлено только тело
                # ответа в сообщение отказа.
                "pm.test('spoofed createdByUserId → 400 InvalidArgument', () => {",
                "  pm.expect(pm.response.code, pm.response.text()).to.be.oneOf([400, 403, 404]);",
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                "pm.test('op done', () => pm.expect(j.done).to.eql(true));",
            ],
        ),
        # Probe Check on the api-gateway cluster-internal REST listener
        # (InternalIAMService.Check, /iam/v1/internal/iam:check) — the prior
        # /iam/v1/check path is NOT in the route catalog (AuthorizeService maps to
        # /iam/v1/authorize:check) so it always 403s "catalog: no entry for method"
        # and can never read a real `allowed`. Poll until the fresh grant's tuple
        # converges allowed=true (fga_outbox emit-in-tx + drainer chain works).
        poll_check_allowed_step(
            name="probe-check",
            subject_expr="'user:' + pm.environment.get('userNOBId')",
            object_expr="'account:' + pm.environment.get('accountAId')",
            relation="viewer",
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
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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
            relation="v_delete",
        ),
        Step(
            name="delete-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{_abDeleteChk_abId}}",
            auth="jwtAccountAdminAStepUp",
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
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
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


# ─────────────────────────────────────────────────────────────────────────────
# REMOVED — AUTHZGCP-BG-APPROVEB-CLUSTERADMIN-GRANT (Break-Glass ApproveB).
#
# The case posted to `/iam/v1/breakGlassRequests/{id}:approveB` and asserted only
# `code < 500`. Break-Glass is not a feature of this product: it was PHYSICALLY
# REMOVED by migration 0006_drop_scim_saml_break_glass.sql ("Break-Glass
# (cluster_break_glass_grants + post-incident reviews) is removed as part of the
# RBAC v2 simplification"), with the residual condition kind dropped by 0013.
# There is no `BreakGlassService` in proto/kaname/cloud/iam/v1/, no route in the
# gateway table, no catalog entry and no handler. (The `BreakGlassService/...`
# strings in internal/authzguard/interceptor_anonymous_table_test.go are
# synthetic FullMethod fixtures for the suffix matcher, alongside an invented
# `SomeService` — not evidence of a live RPC.)
#
# So the response was always the gateway's catalog-miss 403, which is `< 500` —
# the assertion was a tautology. The stated subject (an atomic
# `cluster_admin_grants` INSERT co-committed with an fga_outbox emit, and its
# UNIQUE-violation mapping) was never reached by this request at all.
#
# That subject IS live and IS covered elsewhere, on the RPC that actually owns
# it: `InternalClusterService.GrantAdmin` (`POST /iam/v1/internal/cluster/admins`)
# — see gateway/tests/newman/cases/cluster_admin.py (KAC-196 suite).
#
# `bootstrap-approveB` is removed from the known-RED whitelist in
# scripts/assert-suites-green.sh by the same change (the list shrinks, never grows).
# ─────────────────────────────────────────────────────────────────────────────
