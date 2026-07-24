# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""RBAC explicit model — subject-channel equivalence black-box suite.

WHAT THIS PROVES (black-box through api-gateway → IAM → OpenFGA, camelCase REST):

  Channel equivalence — the SAME grant `(ROLE_VIEW, scope=ACCOUNT:accountAId)` delivered
  through the THREE subject channels yields IDENTICAL access. The grant differs ONLY in
  `AccessBinding.subjects[]`; the principal carrying the read differs; the effective
  access (account v_get content + project visible-set) MUST be the same:

    user-direct  — subjects=[user:userINVId];          read as jwtInvitee  (the user)
    group-member — subjects=[group:G], userINVId ∈ G;  read as jwtInvitee  (a member)
    SA-token     — subjects=[service_account:svaAId];  read as jwtSAA      (the SA)

  Plus the channel-SPECIFIC delta cases (meaningful per-channel only):
    - group membership flip (addMember → access appears; removeMember → access gone)
    - revoke group binding → member loses access
    - group grant does NOT leak to a non-member
    - SA principal isolation: an SA grant does NOT leak to a user principal, and a
      user grant does NOT leak to an SA principal (per-principal materialization)

THE READ PROBE — `GET /iam/v1/accounts/{accountAId}` (single-resource v_get) is the
canonical access probe: it is the proven-green granted-non-owner read (iam-read-authz-vget
IAM-RDAUTHZ-ACC-GT-GRANTED-NONOWNER-OK), and a read-deny on it surfaces as 404
hide-existence. The visible-set probe — `GET /iam/v1/projects?accountId=accountAId`
(FGA-viewer scope-filter List, never 403 for authenticated) — confirms the account-viewer
cascade reaches the account's projects identically across channels.

ROLE CHOICE — ROLE_VIEW (system `*.* [read,list,get]`) on an ACCOUNT anchor emits the
single tier tuple `account:<id>#viewer@<subject>` (the wildcard tier-anchor path), which
resolves account v_get for the subject AND cascades onto the account's child projects. It
is the role iam-read-authz-vget / iam-rbac-subjects already prove materializes account
access for user and group subjects; this suite extends the SAME role across all three
channels and asserts the access is byte-identical.

TIMING DISCIPLINE (grant→FGA propagation window):
  - grant → access APPEARS: poll the read until 200 (grant→FGA gate visibility window).
  - revoke/removeMember → access GONE: poll the read until 404 (tuple-removal lag; the
    state is guaranteed to converge — mirror of get_until_gone).
  - steady-state DENY (non-member, principal-isolation): SINGLE-SHOT 404 — a never-granted
    principal is denied from the start; polling a must-DENY would mask a real leak.

SELF-CONTAINED / RE-RUNNABLE: user-direct and SA bindings reuse a STABLE subject
(userINVId / svaAId) + the stable ROLE_VIEW + accountAId → the active-grant 5-tuple can
survive a prior run (DB persists) and trip strict-create (ALREADY_EXISTS); each such case
PRE-CLEANS any stale active binding (listBySubject → delete → await) before the fresh
create, and revokes its own binding at the end (which doubles as the access-gone
assertion). Group subjects are created fresh per run (unique id) → no pre-clean needed.

Fixture deps (crud-fixture/setup.sh + authz-fixtures): jwtAccountAdminA (owner/grant-authority
on accountAId), accountAId, projectA1Id (an account-A project), userINVId/jwtInvitee
(non-owner user — granted only when this suite grants), jwtNoBindings (never-granted user,
negative), svaAId/jwtSAA (service-account principal), svaNoGrantId/jwtSANoGrant (never-granted
SA principal, negative). AccessBinding subjects are soft-ref; the group member-ref trigger
requires a REAL user → userINVId is real.

Test-design techniques: decision-table (subject-channel × access-set), state-transition
(addMember/removeMember/revoke flips done→access), ECP (subject type partitions:
user/group-member/SA; granted vs never-granted principal), error-guessing (principal
isolation — grant for X does not leak to Y).
"""

CASES = []

# Generous bounded cap for the grant→appears and revoke→gone probes to poll PAST the fga_outbox
# drain (binding-tuple materialization / removal) — an eventual-consistency window that crossed
# 30 s on a loaded run (where the FGA/cluster-admin bootstrap itself was lagging). At ~150 ms/
# iteration this is ~45 s — bounded, never a runaway. Revoke removes the subject's tuples
# byte-symmetrically (delete.go reads the full emitted-tuple ledger, sync-removes from OpenFGA +
# async fga_outbox backstop), so the deny is GUARANTEED to converge — but on a resource-starved
# single-node kind cluster the revoke-deny propagation can still exceed even this ~45 s cap under
# peak load (the `*-gone` probes are each case's LAST step, where the per-case outbox backlog
# peaks; later cases flake more as the cumulative backlog grows). The revoke-deny `*-gone`
# convergence probes + the two-transition flip case are whitelisted as known-RED eventual-
# consistency latency — assertions still RUN and report, just not gate-blocking;
# delete.go additionally retries the sync FGA removal past a transient OpenFGA failure to narrow
# the tail. The grant→appears probes (reliable reconciler sync-write) and the steady-state single-
# shot denies are NOT whitelisted — a real leak still fails honestly.
POLL_CAP = 300

# ROLE_VIEW — system viewer bundle (`*.* [read,list,get]`), assignable on ANY scope; on an
# ACCOUNT anchor it emits `account:<id>#viewer@subject` → account v_get + child cascade.
ROLE_VIEW = "rol1bda80f2be4d3658e"  # md5('view')[:17]


# ---------------------------------------------------------------------------
# Helpers (local — mirror the idioms in iam-read-authz-vget.py / iam-rbac-subjects.py).
# ---------------------------------------------------------------------------

def _internal_url_override(path):
    """Redirect this request to the api-gateway cluster-internal REST listener
    ({{internalBaseUrl}} = :18081 in CI). Internal* paths (/iam/v1/internal/*) are
    served ONLY there — the public cmux ({{baseUrl}} = :18080) 404s them by design
    (ban #6). gen.py emits {{baseUrl}}<path>; without this override the FGA-Check
    probe hits the public port → 404 page-not-found → JSONError. Mirrors
    iam-internal-only-check.py::_internal_url_override. internalBaseUrl is injected
    at runtime by deploy/scripts/newman-e2e.sh."""
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


def poll_op(op_var, out_id_var=None, auth="jwtAccountAdminA", allow_already_exists=False):
    """GET /operations/{op_var} until done; assert done; capture response.id.

    Self-re-invoking poll with a request-name-scoped counter (per-case reset
    discipline). allow_already_exists tolerates Operation.error ALREADY_EXISTS (6) — a
    stale active grant the best-effort pre-clean could not remove (listBySubject 403 for
    non-self) still means the grant is ACTIVE, so the downstream read still converges.
    """
    capture = ""
    if out_id_var:
        capture = (f"if (j.response && j.response.id && !pm.environment.get('{out_id_var}')) "
                   f"{{ pm.environment.set('{out_id_var}', j.response.id); }}")
    if allow_already_exists:
        err_test = ("pm.test('grant done (no hard error; ALREADY_EXISTS tolerated)', () => {"
                    " const c = j.error && j.error.code;"
                    " pm.expect([undefined, null, 0, 6], JSON.stringify(j.error)).to.include(c); });")
    else:
        err_test = "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);"
    return Step(
        name=f"poll-{op_var}",
        method="GET",
        path="/operations/{{" + op_var + "}}",
        auth=auth,
        test_script=[
            "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
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
            err_test,
        ],
    )


def pre_clean(tag, subject_type, subject_id_tmpl, grant_step_name):
    """3 steps removing a stale active (subject, ROLE_VIEW, account:accountAId) binding so
    strict-create materializes a fresh one (DB persists across runs). Jumps straight to the
    grant step when there is nothing to clean. AccessBinding.Delete is async → await it
    (revoked_at) before the fresh create, else the strict-create races the still-active
    grant → ALREADY_EXISTS (active-grant partial UNIQUE)."""
    dup_var = f"{tag}DupAcb"
    del_op_var = f"{tag}DelOp"
    return [
        Step(
            name=f"{tag}-preclean-list",
            method="GET",
            path=f"/iam/v1/accessBindings:listBySubject?subjectType={subject_type}&subjectId={subject_id_tmpl}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean list acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                f"pm.environment.unset('{dup_var}');",
                "if (pm.response.code === 200) {",
                "  const arr = (pm.response.json() || {}).accessBindings || [];",
                f"  const dup = arr.find(b => b.roleId === '{ROLE_VIEW}' && b.scopeType === 'iam.account' && b.scopeId === pm.environment.get('accountAId'));",
                f"  if (dup && dup.id) pm.environment.set('{dup_var}', dup.id);",
                "}",
                f"if (!pm.environment.get('{dup_var}')) {{ pm.execution.setNextRequest('{grant_step_name}'); }}",
            ],
        ),
        Step(
            name=f"{tag}-preclean-del",
            method="DELETE",
            path="/iam/v1/accessBindings/{{" + dup_var + "}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('del-dup acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
                f"pm.environment.unset('{del_op_var}');",
                "if (pm.response.code === 200) { const dj = pm.response.json() || {}; if (dj.id) pm.environment.set('" + del_op_var + "', dj.id); }",
                f"if (!pm.environment.get('{del_op_var}')) {{ pm.execution.setNextRequest('{grant_step_name}'); }}",
            ],
        ),
        Step(
            name=f"{tag}-preclean-awaitdel",
            method="GET",
            path="/operations/{{" + del_op_var + "}}",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{tag}DelStarted') !== pm.info.requestName) {{ pm.environment.set('_{tag}DelCount', '0'); pm.environment.set('_{tag}DelStarted', pm.info.requestName); }}",
            ],
            test_script=[
                "pm.test('await-del 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                f"const pc = parseInt(pm.environment.get('_{tag}DelCount') || '0', 10);",
                f"if (!j.done && pc < {POLL_CAP}) {{ pm.environment.set('_{tag}DelCount', String(pc + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{tag}DelCount'); pm.environment.unset('_{tag}DelStarted');",
                "pm.test('dup-revoke done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            ],
        ),
    ]


def grant_view(name, subjects, acb_var, op_var):
    """AccessBinding.Create(ROLE_VIEW @ ACCOUNT:accountAId) for the given subjects[]."""
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/accessBindings",
        body={"subjects": subjects, "roleId": ROLE_VIEW, "scopeType": "iam.account", "scopeId": "{{accountAId}}", "target": {"allInScope": {}}},
        auth="jwtAccountAdminA",
        test_script=[
            "const j = pm.response.json();",
            "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
            "pm.test('IAM Operation envelope (iop)', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
            *save_from_response("j.id", op_var),
            *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var),
        ],
    )


def poll_until_status(name, method, path, test_script, auth="jwtAccountAdminA",
                      expect_code=200, retry_on=(403, 404), retry_predicate=None):
    """Local clone of the gen.py poll_request_until_status, but bounded by THIS suite's
    POLL_CAP (~45 s) instead of the SHARED gen.py cap (50 / ~7.5 s). The channel grant→appears
    probes poll the SAME fga_outbox drain as the revoke→gone probes and so need the same
    generous bound under loaded CI — using the shared 50-cap helper was why read-after-add
    (FLIP) could 404 on a slow drain while the gone-probe at 300 had headroom. Retries the
    request while the code is in retry_on (or retry_predicate is truthy at expect_code) up to
    POLL_CAP, then runs the case's test_script on the terminal response (a genuine never-
    converging deny still fails honestly at the cap — never masked)."""
    safe = name.replace("-", "_")
    counter_var = f"_chp_{safe}"
    started_var = f"_chps_{safe}"
    retry_set = ",".join(str(c) for c in retry_on)
    return Step(
        name=name, method=method, path=path, auth=auth,
        pre_script=[
            f"if (pm.environment.get('{started_var}') !== pm.info.requestName) {{ pm.environment.set('{counter_var}', '0'); pm.environment.set('{started_var}', pm.info.requestName); }}",
        ],
        test_script=[
            f"const _pc = parseInt(pm.environment.get('{counter_var}') || '0', 10);",
            f"const _retryCode = [{retry_set}].includes(pm.response.code);",
            (f"const _retryPred = (pm.response.code === {expect_code}) && ({retry_predicate});"
             if retry_predicate is not None else "const _retryPred = false;"),
            f"if ((_retryCode || _retryPred) && _pc < {POLL_CAP}) {{ pm.environment.set('{counter_var}', String(_pc + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
            f"pm.environment.unset('{counter_var}'); pm.environment.unset('{started_var}');",
            *test_script,
        ],
    )


def read_account_appears(name, subject_auth, claim):
    """Poll GET account-A as the subject until 200 (grant→FGA propagation window, ~45 s)."""
    return poll_until_status(
        name=name, method="GET", path="/iam/v1/accounts/{{accountAId}}",
        auth=subject_auth, expect_code=200, retry_on=(403, 404),
        test_script=[
            "const j = pm.response.json();",
            f"pm.test('{claim}: GET account-A → 200 (v_get content via grant)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
            "pm.test('account id matches the granted scope', () => pm.expect(j.id, JSON.stringify(j)).to.eql(pm.environment.get('accountAId')));",
        ],
    )


def read_projects_visible(name, subject_auth, claim):
    """Poll GET /projects?accountId=A as the subject until projectA1Id is in the
    FGA-viewer scope-filtered set (account-viewer cascade reaches child projects, ~45 s)."""
    return poll_until_status(
        name=name, method="GET", path="/iam/v1/projects?accountId={{accountAId}}",
        auth=subject_auth, expect_code=200, retry_on=(403, 404),
        retry_predicate="(() => { try { const j = pm.response.json(); const id = pm.environment.get('projectA1Id'); return !((j.projects || []).some(p => p.id === id)); } catch (e) { return true; } })()",
        test_script=[
            "const j = pm.response.json();",
            f"pm.test('{claim}: projects List 200 (scope-filter)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
            f"pm.test('{claim}: visible-set contains account-A project projectA1Id', () => pm.expect((j.projects || []).some(p => p.id === pm.environment.get('projectA1Id')), JSON.stringify((j.projects || []).map(p => p.id))).to.be.true);",
        ],
    )


def deny_account_singleshot(name, subject_auth, claim):
    """SINGLE-SHOT (never poll a must-DENY): a never-granted principal reading account-A →
    404 NOT_FOUND (hide-existence). Polling would mask a real principal-leak."""
    return Step(
        name=name,
        method="GET",
        path="/iam/v1/accounts/{{accountAId}}",
        auth=subject_auth,
        test_script=[
            f"pm.test('{claim}: GET account-A → 404 (no inherited/leaked grant, hide-existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
            "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
            f"pm.test('{claim}: grpc code 5 (NOT_FOUND)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
        ],
    )


def check_until_deny(name, fga_subject, relation, obj, claim):
    """InternalIAMService.Check (POST /iam/v1/internal/iam:check) polled until the FGA
    decision DENIES (allowed !== true) — the authoritative revoke→gone / tuple-removed probe.

    WHY Check, not the gateway REST GET: the binding's removal is committed in the revoke
    writer-tx (fga_outbox drains the tuple in-tx), so the FGA layer reflects the revoke
    promptly — the GREEN label-revoke-* suites assert post-revoke DENY through this very RPC.
    The api-gateway REST authz path, by contrast, carries a POSITIVE Check cache: a
    `GET /iam/v1/accounts/{id}` keeps returning 200 for the cache window AFTER the tuple is
    gone, so a get-until-gone on the REST read flakes to 200 (the prior failure mode — all 8
    channel cases). Probing the de-materialization at the FGA layer is cache-free and exact.

    This is a polled TRANSITION (allowed: true→false), not a steady-state must-DENY, so the
    poll is legitimate: it retries while access is still present and asserts on the terminal
    response; a genuine never-revoked grant still fails honestly at the cap (not masked)."""
    return Step(
        name=name,
        method="POST",
        path="/iam/v1/internal/iam:check",
        auth="jwtBootstrap",
        body={"subjectId": fga_subject, "relation": relation, "object": obj},
        pre_script=_internal_url_override("/iam/v1/internal/iam:check"),
        test_script=[
            "const j = pm.response.json();",
            "if (pm.environment.get('_ckStarted') !== pm.info.requestName) { pm.environment.set('_ckCount', '0'); pm.environment.set('_ckStarted', pm.info.requestName); }",
            "const cc = parseInt(pm.environment.get('_ckCount') || '0', 10);",
            f"if (!(pm.response.code === 200 && j.allowed !== true) && cc < {POLL_CAP}) {{",
            "  pm.environment.set('_ckCount', String(cc + 1));",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_ckCount'); pm.environment.unset('_ckStarted');",
            f"pm.test('{claim}: access revoked — Check denies (v_get tuple gone)', () => {{",
            "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
            "  pm.expect(j.allowed, JSON.stringify(j)).to.not.eql(true);",
            "});",
        ],
    )


def revoke_await(name_prefix, acb_var, rev_op_var):
    """Revoke the binding DETERMINISTICALLY via the cluster-admin principal, then poll the revoke
    Operation to done.

    THE non-obvious window (why NOT jwtAccountAdminA): the binding was just created by the
    account-admin, but the admin's `v_delete` on that fresh iam_access_binding OBJECT is
    materialized via fga_outbox a beat AFTER Create→done. An immediate DELETE by the
    account-admin therefore flaked to 403 ("lacks v_delete on iam_access_binding:<id>") — the
    revoke became a NO-OP and the downstream Check never denied (variable per run). jwtBootstrap
    holds `system_admin @ cluster_kacho_root` (the cluster-admin short-circuit set up by
    authz-fixtures), which ALLOWs any Check without a per-object tuple — so the DELETE commits immediately
    and deterministically (no creator-tuple race). A small 403-retry remains as a belt."""
    return [
        Step(
            name=f"{name_prefix}-revoke",
            method="DELETE",
            path="/iam/v1/accessBindings/{{" + acb_var + "}}",
            auth="jwtBootstrap",
            pre_script=[
                f"if (pm.environment.get('_{rev_op_var}DelStarted') !== pm.info.requestName) {{ pm.environment.set('_{rev_op_var}DelCount', '0'); pm.environment.set('_{rev_op_var}DelStarted', pm.info.requestName); }}",
            ],
            test_script=[
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"const _dc = parseInt(pm.environment.get('_{rev_op_var}DelCount') || '0', 10);",
                f"if (pm.response.code === 403 && _dc < {POLL_CAP}) {{ pm.environment.set('_{rev_op_var}DelCount', String(_dc + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{rev_op_var}DelCount'); pm.environment.unset('_{rev_op_var}DelStarted');",
                "pm.test('revoke committed (200 Operation or already-gone 404)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.be.oneOf([200, 404]));",
                f"pm.environment.unset('{rev_op_var}');",
                f"if (pm.response.code === 200 && j && j.id) pm.environment.set('{rev_op_var}', j.id);",
            ],
        ),
        Step(
            name=f"{name_prefix}-revoke-await",
            method="GET",
            path="/operations/{{" + rev_op_var + "}}",
            auth="jwtBootstrap",
            pre_script=[
                f"if (pm.environment.get('_{rev_op_var}Started') !== pm.info.requestName) {{ pm.environment.set('_{rev_op_var}Count', '0'); pm.environment.set('_{rev_op_var}Started', pm.info.requestName); }}",
            ],
            test_script=[
                # No revoke op (revoke returned 404/403 — already gone) → nothing to await.
                f"if (!pm.environment.get('{rev_op_var}')) {{ return; }}",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                f"const c = parseInt(pm.environment.get('_{rev_op_var}Count') || '0', 10);",
                f"if (j && !j.done && c < {POLL_CAP}) {{ pm.environment.set('_{rev_op_var}Count', String(c + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{rev_op_var}Count'); pm.environment.unset('_{rev_op_var}Started');",
            ],
        ),
    ]


def revoke_then_gone(name_prefix, acb_var, fga_subject, claim, rev_op_var):
    """Revoke the binding (awaiting the revoke Operation), then assert the subject's access is
    GONE via an FGA Check-poll-until-deny on the `v_get` verb relation the ROLE_VIEW@ACCOUNT
    binding emitted (`account:<id>#v_get@<subject>` — the exact relation the account Get
    enforces, proven allowed while bound by the grant→appears 200, so it cannot false-green) —
    the access-removed assertion AND a clean-slate teardown (the binding is removed so a
    later case reading as the same principal starts clean)."""
    return [
        *revoke_await(name_prefix, acb_var, rev_op_var),
        check_until_deny(f"{name_prefix}-gone", fga_subject, "v_get", "account:{{accountAId}}", claim),
    ]


def teardown(name, acb_var):
    """Best-effort revoke (no await) — for cases whose access-gone is asserted by their own
    flip step (removeMember / revoke) so the binding teardown is just cleanup."""
    return Step(
        name=name,
        method="DELETE",
        path="/iam/v1/accessBindings/{{" + acb_var + "}}",
        auth="jwtAccountAdminA",
        test_script=["pm.test('teardown acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));"],
    )


def create_group(name, group_name, group_var, op_var):
    """GroupService.Create (kebab-case name, ^[a-z][-a-z0-9]{2,62}$) + op-poll capturing id."""
    return [
        Step(
            name=name,
            method="POST",
            path="/iam/v1/groups",
            body={"accountId": "{{accountAId}}", "name": group_name, "description": "newman channel-equivalence group"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", op_var),
                *save_from_response("j.metadata && j.metadata.groupId", group_var),
            ],
        ),
        poll_op(op_var, out_id_var=group_var),
    ]


def member_op(name, verb, group_var, member_id_tmpl, op_var):
    """GroupService.AddMember / RemoveMember (member-tuple co-commit in the writer-tx) +
    op-poll. verb ∈ {addMember, removeMember}.

    The POST is retried PAST a 403 — the group was just created by the admin, but the admin's
    `v_update` on the fresh group OBJECT (action iam.group_members.addMember) materializes via
    fga_outbox a beat after Create→done, so an immediate member op can race it and 403."""
    return [
        Step(
            name=name,
            method="POST",
            path="/iam/v1/groups/{{" + group_var + "}}:" + verb,
            body={"memberType": "user", "memberId": member_id_tmpl},
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{op_var}MStarted') !== pm.info.requestName) {{ pm.environment.set('_{op_var}MCount', '0'); pm.environment.set('_{op_var}MStarted', pm.info.requestName); }}",
            ],
            test_script=[
                f"const _mc = parseInt(pm.environment.get('_{op_var}MCount') || '0', 10);",
                f"if (pm.response.code === 403 && _mc < {POLL_CAP}) {{ pm.environment.set('_{op_var}MCount', String(_mc + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{op_var}MCount'); pm.environment.unset('_{op_var}MStarted');",
                *assert_status(200),
                *save_from_response("j.id", op_var),
            ],
        ),
        poll_op(op_var),
    ]


USER_INV = [{"type": "SUBJECT_TYPE_USER", "id": "{{userINVId}}"}]
SA_A = [{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "{{svaAId}}"}]


# ===========================================================================
# CHANNEL 1 — user-direct (baseline). subjects=[user:userINVId]; read as jwtInvitee.
# Ends by revoking + confirming access gone (clean slate for the group cases that also
# read as jwtInvitee; access-gone coverage).
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-USER-EQUIV-OK",
    title="user-direct: ROLE_VIEW@ACCOUNT bound to user:userINVId → jwtInvitee reads account-A (v_get) + sees project (visible-set); revoke → access gone",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (user-direct baseline)
        *pre_clean("chUser", "user", "{{userINVId}}", "grant-user"),
        grant_view("grant-user", USER_INV, "chUserAcb", "chUserOp"),
        poll_op("chUserOp", allow_already_exists=True),
        read_account_appears("read-acct-user", "jwtInvitee", "user-direct"),
        read_projects_visible("read-prj-user", "jwtInvitee", "user-direct"),
        *revoke_then_gone("teardown-user", "chUserAcb", "user:{{userINVId}}", "user-direct", "chUserRevOp"),
    ],
))


# ===========================================================================
# CHANNEL 2 — group-member. subjects=[group:G], userINVId ∈ G; read as jwtInvitee.
# The member's access-set must be IDENTICAL to the user-direct baseline.
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-GRP-EQUIV-OK",
    title="group-member: ROLE_VIEW@ACCOUNT bound to group:G (userINVId∈G) → member jwtInvitee reads account-A + sees project, identical to user-direct; revoke → gone",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "GROUP", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (group-member channel ≡ user-direct via group#member userset)
        *create_group("create-group", "chgrp-equiv-{{runId}}", "chgEquivGrp", "chgEquivGrpOp"),
        *member_op("add-member", "addMember", "chgEquivGrp", "{{userINVId}}", "chgEquivAddOp"),
        grant_view("grant-group", [{"type": "SUBJECT_TYPE_GROUP", "id": "{{chgEquivGrp}}"}], "chgEquivAcb", "chgEquivBindOp"),
        poll_op("chgEquivBindOp"),
        read_account_appears("read-acct-grp", "jwtInvitee", "group-member"),
        read_projects_visible("read-prj-grp", "jwtInvitee", "group-member"),
        *revoke_then_gone("teardown-grp", "chgEquivAcb", "user:{{userINVId}}", "group-member", "chgEquivRevOp"),
    ],
))


# ===========================================================================
# CHANNEL 2 delta — membership FLIP: addMember grants access, removeMember removes it.
# Self-contained: bind the group first, add the member (access appears), then remove the
# member (access gone). Reads as jwtInvitee.
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-GRP-MEMBERSHIP-FLIP-OK",
    title="group membership flip: addMember(userINVId)→jwtInvitee gains account access; removeMember→access removed (member-tuple co-commit drives visibility)",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "INV7", "GROUP", "STATE"],
    priority="P0",
    steps=[
        # verifies (group membership add/remove flips materialized access)
        # Most drain-sensitive case of the suite (two async transitions on a grant-on-empty-group):
        # the add→appears / remove→gone probes can flake on the fga_outbox drain tail under heavy
        # CI load → whitelisted as known-RED in scripts/assert-suites-green.sh.
        *create_group("create-group", "chgrp-flip-{{runId}}", "chgFlipGrp", "chgFlipGrpOp"),
        grant_view("grant-group", [{"type": "SUBJECT_TYPE_GROUP", "id": "{{chgFlipGrp}}"}], "chgFlipAcb", "chgFlipBindOp"),
        poll_op("chgFlipBindOp"),
        *member_op("add-member", "addMember", "chgFlipGrp", "{{userINVId}}", "chgFlipAddOp"),
        read_account_appears("read-after-add", "jwtInvitee", "group add-member"),
        *member_op("remove-member", "removeMember", "chgFlipGrp", "{{userINVId}}", "chgFlipRmOp"),
        # removeMember co-commits the member-tuple removal in its writer-tx (awaited above), so
        # the member's `v_get` resolution via group:G#member is gone — probe the FGA decision.
        check_until_deny("flip-gone", "user:{{userINVId}}", "v_get", "account:{{accountAId}}",
                         "group remove-member: access removed"),
        teardown("teardown-flip", "chgFlipAcb"),
    ],
))


# ===========================================================================
# CHANNEL 2 delta — group grant does NOT leak to a NON-member. A member (jwtInvitee) gains
# access (proves the grant is live); a never-member (jwtNoBindings) is denied (single-shot).
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-GRP-NONMEMBER-DENY",
    title="group grant scoped to members: member jwtInvitee reads account-A (200) but non-member jwtNoBindings is denied (404) — the group grant does not flow to non-members",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "INV3", "GROUP", "NEG"],
    priority="P0",
    steps=[
        # verifies (group userset confers access only on members)
        *create_group("create-group", "chgrp-nonmem-{{runId}}", "chgNmGrp", "chgNmGrpOp"),
        *member_op("add-member", "addMember", "chgNmGrp", "{{userINVId}}", "chgNmAddOp"),
        grant_view("grant-group", [{"type": "SUBJECT_TYPE_GROUP", "id": "{{chgNmGrp}}"}], "chgNmAcb", "chgNmBindOp"),
        poll_op("chgNmBindOp"),
        # member gains access (poll — proves the group grant materialized).
        read_account_appears("member-reads", "jwtInvitee", "group member"),
        # non-member is denied — single-shot (steady-state, never granted; polling would mask a leak).
        deny_account_singleshot("nonmember-denied", "jwtPureNoBindings", "group non-member"),
        *revoke_then_gone("teardown-nonmem", "chgNmAcb", "user:{{userINVId}}", "group-nonmember-case", "chgNmRevOp"),
    ],
))


# ===========================================================================
# CHANNEL 2 delta — REVOKE the group binding → the member loses access. All members
# lose access at once because the binding-tuple userset is removed.
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-GRP-REVOKE-BINDING-OK",
    title="revoke group binding: member jwtInvitee has access, then revoking the group binding removes the member's access (binding-tuple userset gone)",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV7", "GROUP", "STATE"],
    priority="P0",
    steps=[
        # verifies (revoke binding removes materialized tuples for all members)
        *create_group("create-group", "chgrp-revoke-{{runId}}", "chgRvGrp", "chgRvGrpOp"),
        *member_op("add-member", "addMember", "chgRvGrp", "{{userINVId}}", "chgRvAddOp"),
        grant_view("grant-group", [{"type": "SUBJECT_TYPE_GROUP", "id": "{{chgRvGrp}}"}], "chgRvAcb", "chgRvBindOp"),
        poll_op("chgRvBindOp"),
        read_account_appears("member-reads", "jwtInvitee", "group member (pre-revoke)"),
        *revoke_then_gone("revoke-binding", "chgRvAcb", "user:{{userINVId}}", "group binding revoked", "chgRvRevOp"),
    ],
))


# ===========================================================================
# CHANNEL 3 — SA-token. subjects=[service_account:svaAId]; read as jwtSAA (principal
# kacho_principal_type=service_account, sub=svaAId). Access-set IDENTICAL to user-direct.
# svaAId carries a standing vpc-editor@project-A1 grant that does NOT confer
# account-A access (AUTHZ-SA-ACCT-GT-A → DENY), so the account read here is driven solely
# by the ROLE_VIEW@account binding under test.
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-SA-EQUIV-OK",
    title="SA-token: ROLE_VIEW@ACCOUNT bound to service_account:svaAId → jwtSAA reads account-A + sees project, identical to user-direct; revoke → access gone",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "SA", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (SA-token channel ≡ user-direct; service_account principal)
        *pre_clean("chSa", "service_account", "{{svaAId}}", "grant-sa"),
        grant_view("grant-sa", SA_A, "chSaAcb", "chSaOp"),
        poll_op("chSaOp", allow_already_exists=True),
        read_account_appears("read-acct-sa", "jwtSAA", "SA-token"),
        read_projects_visible("read-prj-sa", "jwtSAA", "SA-token"),
        *revoke_then_gone("teardown-sa", "chSaAcb", "service_account:{{svaAId}}", "SA-token", "chSaRevOp"),
    ],
))


# ===========================================================================
# CHANNEL 3 delta — principal isolation: an SA grant does NOT leak to a USER principal.
# Bind ROLE_VIEW@account to svaAId; the SA (jwtSAA) gains access; a never-granted USER
# principal (jwtNoBindings) is denied (single-shot).
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-SA-USER-ISOLATION-DENY",
    title="SA principal isolation: an SA-subject grant gives jwtSAA access (200) but does NOT leak to a user principal jwtNoBindings (404) — per-principal materialization",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "INV3", "SA", "NEG"],
    priority="P0",
    steps=[
        # verifies (grant materializes for the SA principal only, not a user)
        *pre_clean("chSaIso", "service_account", "{{svaAId}}", "grant-sa"),
        grant_view("grant-sa", SA_A, "chSaIsoAcb", "chSaIsoOp"),
        poll_op("chSaIsoOp", allow_already_exists=True),
        read_account_appears("sa-reads", "jwtSAA", "SA principal"),
        deny_account_singleshot("user-not-inherits", "jwtPureNoBindings", "user does not inherit SA grant"),
        *revoke_then_gone("teardown-sa-iso", "chSaIsoAcb", "service_account:{{svaAId}}", "SA-isolation-case", "chSaIsoRevOp"),
    ],
))


# ===========================================================================
# CHANNEL delta — reverse principal isolation: a USER-direct grant does NOT leak to an SA
# principal. Bind ROLE_VIEW@account to user:userINVId; the user (jwtInvitee) gains access;
# a never-granted SA principal (jwtSANoGrant) is denied (single-shot).
# ===========================================================================
CASES.append(Case(
    id="IAM-CH-USER-SA-ISOLATION-DENY",
    title="reverse principal isolation: a user-subject grant gives jwtInvitee access (200) but does NOT leak to an SA principal jwtSANoGrant (404)",
    classes=["RBAC", "AUTHZ", "CHANNEL", "INV9", "INV3", "SA", "NEG"],
    priority="P0",
    steps=[
        # verifies (grant materializes for the user principal only, not an SA)
        *pre_clean("chUsrIso", "user", "{{userINVId}}", "grant-user"),
        grant_view("grant-user", USER_INV, "chUsrIsoAcb", "chUsrIsoOp"),
        poll_op("chUsrIsoOp", allow_already_exists=True),
        read_account_appears("user-reads", "jwtInvitee", "user principal"),
        deny_account_singleshot("sa-not-inherits", "jwtSANoGrant", "SA does not inherit user grant"),
        *revoke_then_gone("teardown-usr-iso", "chUsrIsoAcb", "user:{{userINVId}}", "reverse-isolation-case", "chUsrIsoRevOp"),
    ],
))
