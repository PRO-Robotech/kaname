# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""RBAC explicit model — exact-set visibility invariants black-box suite.

The "create several items per resource, compare visible-set vs created-set" invariants:
verb-bearing v_get/v_list; ProjectService.List = FGA-viewer∪v_list scope-filter; a
label-selector materializes v_list/v_get only on matching objects.

RESOURCE COVERAGE — under the unified label-scope model every iam content type is
label-selectable. A custom role rule with `matchLabels` on an iam content type materializes
per-object v_list/v_get on matching objects; the type's scope-filtered List then returns the
matched set. Coverage here is PER-TYPE-SELECTED because the per-type Get authz still differs
(role Get viewer-gates same-account → the v_list-only invariant is inapplicable to roles);
the List authz is UNIFORM — all five account-scoped IAM List RPCs are `<exempt>`:

  - **project** (first two cases) and **serviceAccount**: exact-set AND v_list-only
    both hold (List per-object-filters; Get gates on v_get).
  - **role**: List per-object-filters → the exact-set holds; but RoleService.Get viewer-gates
    (role/get.go) — a FOREIGN-account role 404s, but a SAME-account role is readable to any
    account member via the viewer tier, and the v_list-only subject holds account access (the
    binding), so it reads the same-account role → 200. The v_list-only → detail-404 invariant
    is thus INAPPLICABLE to same-account roles — only the exact-set case is emitted.
  - **group**: GroupService.List applies the per-object viewer∪v_list filter on iam_group AND
    GroupService.Get gates on v_get → BOTH the exact-set AND v_list-only invariants hold (parity
    with project/SA). GroupService.List is `<exempt>` — no account#v_list anchor needed; the
    by-label grant narrows to exactly the matched set.

Remaining (a later chunk): **user** (global scope; a labelled user is produced via invite +
Update) and **accessBinding** (bespoke listByScope, no flat List).

LIST-CALL AUTHZ (unified): ALL five account-scoped IAM List RPCs (Project / Group /
ServiceAccount / Role / User) are `<exempt>` — the gateway performs NO FGA pre-Check on the
List call. The sole authz gate is the in-handler `viewer ∪ v_list` scope filter, so a
per-object by-label `v_list` grant alone returns 200+filtered (never 403). The former
`{iam.account list}` anchor rule (which emitted `account#v_list` to authorize the Project/Group
List CALL) is therefore NO LONGER NEEDED and has been removed — the by-object listauthz filter
narrows to the matched set on its own (for the types whose List filters).

WHAT THIS PROVES (black-box through api-gateway → IAM → OpenFGA, camelCase REST):

  Non-matching label hidden — IAM-SET-PRJ-LABEL-EXACT-OK.
    In account A: create 3 projects {foo=<runId>} (M+), 3 with NO labels (M−), 2 with
    {baz=<runId>} (other-label). A custom role rule `{iam.project get,list matchLabels:{foo:<runId>}}`
    is bound to a subject on ACCOUNT:accountAId. The subject's project List then contains
    EXACTLY the M+ set: all three M+ visible, NONE of M− visible, NONE of the other-label
    set visible. Per-run unique label value (`foo=<runId>`) makes the matched set exactly
    THIS run's M+ (immune to projects accumulated by prior runs / other suites).

  v_list-only → content closed — IAM-SET-PRJ-VLIST-ONLY-DETAIL-404.
    A `verbs:[list]`-only by-label grant materializes v_list (the project APPEARS in the
    List) but NOT v_get → the single-resource detail Get is closed: 404 NOT_FOUND
    (hide-existence). v_list ≠ v_get (the explicit-model decoupling): a list-only
    grant must never open content. A 200 here would be a violation (content visible
    without v_get).

CLEAN-SLATE PRE-CLEAN — both cases read as jwtInvitee. jwtInvitee can carry a residual
account-A binding (a prior suite's best-effort, async-revoked teardown). A residual
account-VIEWER grant would cascade onto EVERY account-A project and defeat the by-label
filtering (M− would become visible). Each case therefore first deletes (with await) every
active account-A binding for userINVId via a bounded list→delete→await loop, asserting the
slate is clean (zero residual account-A bindings) before granting the by-label role. Discovery
uses the ADMIN-AUTHORIZED :listByScope on account/accountAId (owner sees all subjects, filter
by subjectId) — NOT :listBySubject, which is a cross-user query that 403s for the admin caller
and yielded a FALSE clean slate (the residual binding survived and leaked M− into the visible
set). This makes the exact-set assertion self-contained and deterministic — it does NOT depend
on any other case/suite having torn down.

PAGINATION — the reads use `pageSize=1000` so the run-created projects are returned on a
single page even as account A accumulates projects across runs (the page-boundary lesson
from assert-suites-green.sh's role list-with-account note); the M± projects are also
best-effort deleted at teardown to bound growth.

TIMING DISCIPLINE: the by-label materialization is reconciler-driven (≤2s + sweep). The
List-appears assertion POLLS until the M+ set converges (grant→reconcile window); the
detail-404 and the non-matching-hidden checks run on the CONVERGED terminal
response — a genuine never-converging materialization or a real over-grant fails honestly,
never masked.

Fixture deps (crud-fixture/setup.sh): jwtAccountAdminA (owner/grant-authority on accountAId),
accountAId, userINVId/jwtInvitee (non-owner reader). AccessBinding subject is soft-ref;
userINVId is a real user.

Test-design techniques: ECP (label equivalence classes — matching foo / no-label / other-label
baz), exact-set comparison (visible ≡ M+), decision-table (verb {get,list} vs {list} × read
path {List, single-Get}), state-transition (grant → materialize → visible), error-guessing
(other-label vs no-label both excluded; v_list-only must not leak content).
"""

CASES = []

POLL_CAP = 50


# ---------------------------------------------------------------------------
# Helpers (local — mirror iam-rbac-scope-grant.py / iam-read-authz-vget.py idioms).
# ---------------------------------------------------------------------------

def poll_op(op_var, out_id_var=None, auth="jwtAccountAdminA"):
    """GET /operations/{op_var} until done; assert done && no error; optionally capture id."""
    capture = ""
    if out_id_var:
        capture = (f"if (j.response && j.response.id && !pm.environment.get('{out_id_var}')) "
                   f"{{ pm.environment.set('{out_id_var}', j.response.id); }}")
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
            "pm.test('operation no error', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
        ],
    )


# A small cap on list↔delete iterations — a non-owner subject carries at most a
# handful of account-A bindings; this bounds the clean-slate loop independently of
# the (larger) Operation-await POLL_CAP.
PRECLEAN_LIST_CAP = 12


def preclean_account_loop(tag, next_step):
    """Bounded list→delete→await loop removing EVERY active account-A binding for userINVId
    (any role) so the by-label visibility starts from a clean slate, then jumps to `next_step`.

    CRITICAL flow discipline (the loop must TERMINATE FORWARD, never fall through into the
    delete machinery): the list step's terminal "clean slate" branch does
    `setNextRequest(next_step)` to jump PAST del/await to the first post-preclean step. The
    earlier version simply fell through with no setNextRequest, so Newman advanced to the
    NEXT sequential request — `del_step` — which (on a non-200 delete) jumped back to
    `list_step`, whose pre-request then RESET the iteration counter (the terminal branch had
    unset the request-name-scoped flag) → an unbounded list↔del ping-pong that never honoured
    the cap (observed: 17k+ list invocations, 35-min hang, CI timeout). Jumping forward on the
    terminal branch keeps the flag set across loop-backs, so the counter increments
    monotonically and the cap holds."""
    dup = f"{tag}Dup"
    delop = f"{tag}DelOp"
    list_step = f"{tag}-preclean-list"
    del_step = f"{tag}-preclean-del"
    await_step = f"{tag}-preclean-await"
    return [
        Step(
            name=list_step,
            method="GET",
            # Discovery MUST use an AUTHORIZED read: :listByScope on account/accountAId
            # (the account owner sees EVERY binding in the account scope, ALL subjects).
            # The prior :listBySubject?subjectId=userINVId is a CROSS-user query (the
            # jwtAccountAdminA caller is NOT the subject) → correctly 403; the test then
            # treated the empty result as a clean slate, so a residual account-scoped
            # view binding for userINVId leaked into the by-label visibility assertion
            # (M− projects became visible → exact-set mismatch). listByScope returns all
            # subjects → the filter narrows to subjectId=userINVId (pattern: IAM-ACB-CR-CRUD-OK
            # pre-clean-dup). pageSize=1000: the account scope accumulates >50 bindings
            # across re-runs, so the default page (50) could page-out the stale binding.
            path="/iam/v1/accessBindings:listByScope?resourceType=account&resourceId={{accountAId}}&pageSize=1000",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{tag}Started') !== pm.info.requestName) {{ pm.environment.set('_{tag}Count', '0'); pm.environment.set('_{tag}Started', pm.info.requestName); }}",
            ],
            test_script=[
                "pm.test('pre-clean list acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 403]));",
                f"const c = parseInt(pm.environment.get('_{tag}Count') || '0', 10);",
                "let arr = [];",
                "if (pm.response.code === 200) { arr = ((pm.response.json() || {}).accessBindings || []).filter(b => b.subjectId === pm.environment.get('userINVId') && b.scopeType === 'iam.account' && b.scopeId === pm.environment.get('accountAId')); }",
                f"if (arr.length > 0 && c < {PRECLEAN_LIST_CAP}) {{",
                f"  pm.environment.set('{dup}', arr[0].id);",
                f"  pm.environment.set('_{tag}Count', String(c + 1));",
                f"  pm.execution.setNextRequest('{del_step}');",
                "  return;",
                "}",
                # Terminal (clean slate OR cap hit): jump FORWARD past del/await to next_step.
                f"pm.environment.unset('_{tag}Count'); pm.environment.unset('_{tag}Started'); pm.environment.unset('{dup}');",
                "pm.test('jwtInvitee has zero residual account-A bindings (clean slate for by-label visibility)', () => pm.expect(arr.length, JSON.stringify(arr.map(b => b.id))).to.eql(0));",
                f"pm.execution.setNextRequest('{next_step}');",
            ],
        ),
        Step(
            name=del_step,
            method="DELETE",
            path="/iam/v1/accessBindings/{{" + dup + "}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('pre-clean delete acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
                f"pm.environment.unset('{delop}');",
                "if (pm.response.code === 200) { const dj = pm.response.json() || {}; if (dj.id) pm.environment.set('" + delop + "', dj.id); }",
                # 200 → fall through to await_step; non-200 (already gone / undeletable) → re-list
                # (bounded by the list-step counter, which does NOT reset on this loop-back).
                f"if (!pm.environment.get('{delop}')) {{ pm.execution.setNextRequest('{list_step}'); }}",
            ],
        ),
        Step(
            name=await_step,
            method="GET",
            path="/operations/{{" + delop + "}}",
            auth="jwtAccountAdminA",
            pre_script=[
                f"if (pm.environment.get('_{tag}AwaitStarted') !== pm.info.requestName) {{ pm.environment.set('_{tag}AwaitCount', '0'); pm.environment.set('_{tag}AwaitStarted', pm.info.requestName); }}",
            ],
            test_script=[
                "const j = pm.response.json();",
                f"const c = parseInt(pm.environment.get('_{tag}AwaitCount') || '0', 10);",
                f"if (!j.done && c < {POLL_CAP}) {{ pm.environment.set('_{tag}AwaitCount', String(c + 1)); pm.execution.setNextRequest(pm.info.requestName); return; }}",
                f"pm.environment.unset('_{tag}AwaitCount'); pm.environment.unset('_{tag}AwaitStarted');",
                f"pm.execution.setNextRequest('{list_step}');",
            ],
        ),
    ]


def create_suite_account(acc_var, op_var):
    """Create a FRESH, suite-private account per run (owner = userAAAId / jwtAccountAdminA) so
    the by-label PROJECT exact-set reads an account in which the subject (userINVId) is NOT a
    member.

    ROOT CAUSE of the persistent red this fixes (diagnosed, NOT a product over-emit): userINVId
    is seeded by authz-fixtures/setup.sh (KAC-125 invite-flow → editor@projectA1) as a MEMBER of
    the SHARED accountA, and ProjectService.List carries an account-member visibility floor that
    returns EVERY project in the account to any member. A member's project List therefore can
    NEVER be narrowed by a matchLabels grant — the account's M−/baz projects AND every other
    suite's projects (authz-test-*, t31-prj-*, …) leak into the visible set. The IDENTICAL
    account-scoped by-label grant is correctly filtered for serviceAccount/group/role (their List
    RPCs have no member floor — those exact-set cases PASS), which pins the leak to project-list
    MEMBERSHIP, not a by-label v_list over-emit. In a fresh account userINVId's ONLY relation is
    the by-label AccessBinding → per-object v_list on the foo-matched projects only → the exact
    set holds. Self-contained: no concurrent suite touches this per-run account (unique
    rbacvis-<runId> name), so it cannot be contaminated. (VLIST-ONLY / SVA / GRP / ROL cases stay
    on accountAId — they already pass; the member floor only breaks the exact-set's M−/baz-hidden
    assertion.)"""
    return [
        Step(name="create-suite-account", method="POST", path="/iam/v1/accounts",
             # IAM-1 F1: ownerUserId° derived-from-caller (jwtAccountAdminA == userAAAId) — not sent.
             body={"name": "rbacvis-{{runId}}",
                   "description": "rbac-visibility-set per-run private account"},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.accountId", acc_var),
                          *save_from_response("j.id", op_var)]),
        poll_op(op_var, out_id_var=acc_var),
    ]


def mk_project(short, label_key, id_var, op_var, acct_var="accountAId"):
    """ProjectService.Create (+ op-poll) capturing the new project id. label_key None → no
    labels (M−); 'foo'/'baz' → labels={key: <runId>} (per-run unique value). acct_var selects the
    parent account (default shared accountAId; the exact-set case passes a fresh suite-private
    account — see create_suite_account)."""
    body = {"accountId": "{{" + acct_var + "}}", "name": short + "-{{runId}}", "description": "newman exact-set project"}
    if label_key:
        body["labels"] = {label_key: "{{runId}}"}
    return [
        Step(
            name="create-" + short,
            method="POST",
            path="/iam/v1/projects",
            body=body,
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.projectId", id_var),
                *save_from_response("j.id", op_var),
            ],
        ),
        poll_op(op_var, out_id_var=id_var),
    ]


def grant_bylabel_role(role_var, acb_var, role_op, bind_op, verbs, role_name, acct_var="accountAId"):
    """RoleService.Create(rule {iam.project verbs matchLabels:{foo:runId}}) + AccessBinding
    bound to user:userINVId @ ACCOUNT:<acct_var>. Fresh role id per run → unique active 5-tuple
    → no strict-create dup → no pre-clean of THIS binding needed. acct_var selects the account
    the role lives in AND the binding scope (default shared accountAId; the exact-set case passes
    a fresh suite-private account — see create_suite_account)."""
    return [
        Step(
            name="create-role",
            method="POST",
            path="/iam/v1/roles",
            body={
                # Role.Create name enforces ^[a-z][a-z0-9_]{0,40}$ (underscores, NOT hyphens
                # — stricter than the proto annotation), so the run-suffix is `_`-joined.
                "accountId": "{{" + acct_var + "}}",
                "name": role_name + "_{{runId}}",
                "description": "newman exact-set by-label role",
                "rules": [
                    # ProjectService.List = <exempt>: the gateway no
                    # longer pre-Checks account:<id>#v_list — the in-handler viewer∪v_list filter
                    # is the SOLE gate. No account-anchor rule needed: a per-object by-label
                    # v_list grant alone now lists 200+filtered (was 403 under the old call-gate).
                    {"module": "iam", "resources": ["project"], "verbs": verbs,
                     "matchLabels": {"foo": "{{runId}}"}},
                ],
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.metadata && j.metadata.roleId", role_var),
                *save_from_response("j.id", role_op),
            ],
        ),
        poll_op(role_op, out_id_var=role_var),
        Step(
            name="grant-bylabel",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [{"type": "SUBJECT_TYPE_USER", "id": "{{userINVId}}"}],
                "roleId": "{{" + role_var + "}}",
                "scopeType": "iam.account",
                "scopeId": "{{" + acct_var + "}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                "pm.test('IAM Operation envelope (iop)', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
                *save_from_response("j.id", bind_op),
                *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var),
            ],
        ),
        poll_op(bind_op),
    ]


def teardown(name, path):
    return Step(
        name=name,
        method="DELETE",
        path=path,
        auth="jwtAccountAdminA",
        test_script=["pm.test('teardown acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));"],
    )


def robust_revoke_binding(name, acb_var):
    """Revoke the by-label binding, polling the DELETE PAST the creator-tuple 403 window so the
    grant is GUARANTEED gone before the SAME-TYPE v_list-only case runs.

    Why it must actually commit (not best-effort): the exact-set case grants {get,list} and the
    v_list-only case (same type, same run → same foo=runId label) grants {list}. If the exact-set
    binding leaks (its DELETE 403s on the admin's not-yet-materialized v_delete on the fresh
    binding object), the v_list-only object inherits v_get from the leaked {get,list} grant
    → its detail Get returns 200 instead of 404 (the invariant violated). The cross-subject preclean
    cannot clean it (admin gets 403 on listBySubject for another user), so the revoke itself must
    commit. Retry the DELETE while 403 until 200 (committed) or 404 (already gone)."""
    return Step(
        name=name, method="DELETE", path="/iam/v1/accessBindings/{{" + acb_var + "}}",
        auth="jwtAccountAdminA",
        pre_script=[
            f"if (pm.environment.get('_rv{acb_var}Started') !== pm.info.requestName) {{ pm.environment.set('_rv{acb_var}Count', '0'); pm.environment.set('_rv{acb_var}Started', pm.info.requestName); }}",
        ],
        test_script=[
            f"const _rc = parseInt(pm.environment.get('_rv{acb_var}Count') || '0', 10);",
            # Real inter-poll delay (~500ms) between the 403-retries (Koren #1): the admin's
            # v_delete on the FRESH binding object materializes via fga_outbox a beat AFTER
            # Create→done, and each re-fire is only a ~round-trip apart, so without the
            # busy-wait the POLL_CAP retries burn out in well under the materialization
            # window → the DELETE stays 403 at the cap and the revoke never commits (leaving
            # the leaked {get,list} grant that flips the v_list-only detail Get to 200).
            f"if (pm.response.code === 403 && _rc < {POLL_CAP}) {{ pm.environment.set('_rv{acb_var}Count', String(_rc + 1)); const _rvd = Date.now(); while (Date.now() - _rvd < 500) {{ /* inter-poll delay ~500ms (Koren #1) */ }} pm.execution.setNextRequest(pm.info.requestName); return; }}",
            f"pm.environment.unset('_rv{acb_var}Count'); pm.environment.unset('_rv{acb_var}Started');",
            "pm.test('by-label binding revoke committed (200 or already-gone 404)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([200, 404]));",
        ],
    )


# ===========================================================================
# exact-set: by-label grant → subject sees EXACTLY the matching (foo=<runId>) set.
# ===========================================================================
CASES.append(Case(
    id="IAM-SET-PRJ-LABEL-EXACT-OK",
    title="exact-set: 3 projects {foo=runId} (M+), 3 no-label (M−), 2 {baz=runId}; by-label grant {iam.project get,list matchLabels foo} → subject's project List == exactly the M+ set",
    classes=["RBAC", "AUTHZ", "VISIBILITY", "INV2", "LABELS", "EXACT-SET"],
    priority="P0",
    steps=[
        # verifies (non-matching label hidden)
        # FRESH suite-private account per run (see create_suite_account): the shared accountA
        # makes userINVId an account MEMBER (authz-fixtures KAC-125 invite), and
        # ProjectService.List's member floor returns EVERY account project to a member —
        # structurally defeating the by-label narrowing (M−/baz + other suites' projects leak
        # in). In this fresh account userINVId is NOT a member (only the by-label binding below),
        # so the List is narrowed to exactly the foo-matched set.
        *create_suite_account("visSetAcct", "visSetAcctOp"),
        # M+ (foo=runId) — 3 projects.
        *mk_project("setpp1", "foo", "visPP1", "visPP1Op", acct_var="visSetAcct"),
        *mk_project("setpp2", "foo", "visPP2", "visPP2Op", acct_var="visSetAcct"),
        *mk_project("setpp3", "foo", "visPP3", "visPP3Op", acct_var="visSetAcct"),
        # M− (no labels) — 3 projects.
        *mk_project("setpm1", None, "visPM1", "visPM1Op", acct_var="visSetAcct"),
        *mk_project("setpm2", None, "visPM2", "visPM2Op", acct_var="visSetAcct"),
        *mk_project("setpm3", None, "visPM3", "visPM3Op", acct_var="visSetAcct"),
        # other-label (baz=runId) — 2 projects.
        *mk_project("setbq1", "baz", "visBQ1", "visBQ1Op", acct_var="visSetAcct"),
        *mk_project("setbq2", "baz", "visBQ2", "visBQ2Op", acct_var="visSetAcct"),
        # No preclean loop: a fresh per-run account has ZERO residual bindings for userINVId by
        # construction (no other suite touches it), so the clean-slate the preclean used to
        # enforce on shared accountA is guaranteed here.
        # Grant the by-label role (get+list) to userINVId on ACCOUNT:visSetAcct.
        *grant_bylabel_role("visSetRole", "visSetAcb", "visSetRoleOp", "visSetBindOp",
                            ["get", "list"], "setlblrole", acct_var="visSetAcct"),
        # The subject lists projects: poll until the exact set is FULLY CONVERGED (all M+ present
        # AND no M− AND no baz), then assert it. Waiting for the whole set (not just M+ present)
        # rides out any transient half-materialized over-visibility during by-label reconcile; a
        # PERMANENT leak never converges → the negatives below still fail at budget (never masked).
        poll_request_until_status(
            name="read-exact-set",
            method="GET",
            path="/iam/v1/projects?accountId={{visSetAcct}}&pageSize=1000",
            auth="jwtInvitee",
            expect_code=200,
            retry_on=(403, 404),
            retry_predicate="(() => { try { const ids = (pm.response.json().projects || []).map(p => p.id); const want = ['visPP1','visPP2','visPP3'].map(v => pm.environment.get(v)); const mneg = ['visPM1','visPM2','visPM3'].map(v => pm.environment.get(v)); const bz = ['visBQ1','visBQ2'].map(v => pm.environment.get(v)); return !want.every(w => ids.indexOf(w) !== -1) || mneg.some(w => ids.indexOf(w) !== -1) || bz.some(w => ids.indexOf(w) !== -1); } catch (e) { return true; } })()",
            test_script=[
                "const j = pm.response.json();",
                "const ids = (j.projects || []).map(p => p.id);",
                "pm.test('all three M+ (foo=runId) projects are visible', () => {",
                "  const want = ['visPP1','visPP2','visPP3'].map(v => pm.environment.get(v));",
                "  pm.expect(want.every(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.true;",
                "});",
                "pm.test('no M− (no-label) project is visible (non-matching hidden)', () => {",
                "  const mneg = ['visPM1','visPM2','visPM3'].map(v => pm.environment.get(v));",
                "  pm.expect(mneg.some(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.false;",
                "});",
                "pm.test('no other-label (baz=runId) project is visible (label-scoped, not blanket)', () => {",
                "  const bq = ['visBQ1','visBQ2'].map(v => pm.environment.get(v));",
                "  pm.expect(bq.some(w => ids.indexOf(w) !== -1), 'visible ids: ' + JSON.stringify(ids)).to.be.false;",
                "});",
            ],
        ),
        # Teardown — revoke the grant (committed, not best-effort) + role; best-effort delete the
        # run's projects, then the suite-private account (bound growth). Account delete may 409
        # while its projects are still async-deleting — tolerated (a leaked per-run rbacvis-<runId>
        # account is harmless: unique name, not pool-constrained, never asserted).
        robust_revoke_binding("teardown-binding", "visSetAcb"),
        teardown("teardown-role", "/iam/v1/roles/{{visSetRole}}"),
        teardown("teardown-pp1", "/iam/v1/projects/{{visPP1}}"),
        teardown("teardown-pp2", "/iam/v1/projects/{{visPP2}}"),
        teardown("teardown-pp3", "/iam/v1/projects/{{visPP3}}"),
        teardown("teardown-pm1", "/iam/v1/projects/{{visPM1}}"),
        teardown("teardown-pm2", "/iam/v1/projects/{{visPM2}}"),
        teardown("teardown-pm3", "/iam/v1/projects/{{visPM3}}"),
        teardown("teardown-bq1", "/iam/v1/projects/{{visBQ1}}"),
        teardown("teardown-bq2", "/iam/v1/projects/{{visBQ2}}"),
        Step(name="teardown-suite-account", method="DELETE", path="/iam/v1/accounts/{{visSetAcct}}",
             auth="jwtAccountAdminA",
             test_script=["pm.test('suite-account teardown best-effort', () => pm.expect(pm.response.code).to.be.oneOf([200, 400, 403, 404, 409]));"]),
    ],
))


# ===========================================================================
# v_list-only grant: project appears in the List but the detail Get is closed (404).
# ===========================================================================
CASES.append(Case(
    id="IAM-SET-PRJ-VLIST-ONLY-DETAIL-404",
    title="v_list-only: by-label grant {iam.project list ONLY matchLabels foo} → project visible in List (v_list) but single-resource Get is 404 (no v_get; v_list ≠ v_get)",
    classes=["RBAC", "AUTHZ", "VISIBILITY", "INV1", "LABELS", "NEG"],
    priority="P0",
    steps=[
        # verifies (v_list-only → content closed)
        *mk_project("setvl", "foo", "visVlProj", "visVlProjOp"),
        *preclean_account_loop("visVl", "create-role"),
        # Grant LIST-ONLY (no 'get') → materializes v_list, NOT v_get.
        *grant_bylabel_role("visVlRole", "visVlAcb", "visVlRoleOp", "visVlBindOp",
                            ["list"], "setvllistonly"),
        # The project IS visible in the List (v_list materialized) — poll until it converges.
        poll_request_until_status(
            name="read-list-visible",
            method="GET",
            path="/iam/v1/projects?accountId={{accountAId}}&pageSize=1000",
            auth="jwtInvitee",
            expect_code=200,
            retry_on=(403, 404),
            retry_predicate="(() => { try { const ids = (pm.response.json().projects || []).map(p => p.id); return ids.indexOf(pm.environment.get('visVlProj')) === -1; } catch (e) { return true; } })()",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('v_list-only project IS visible in the List (v_list materialized)', () => {",
                "  const ids = (j.projects || []).map(p => p.id);",
                "  pm.expect(ids.indexOf(pm.environment.get('visVlProj')) !== -1, 'visible ids: ' + JSON.stringify(ids)).to.be.true;",
                "});",
            ],
        ),
        # The detail Get is CLOSED — single-shot (steady-state: v_get was never granted; a
        # 200 here is a violation — content visible without v_get; polling would mask it).
        Step(
            name="detail-get-closed",
            method="GET",
            path="/iam/v1/projects/{{visVlProj}}",
            auth="jwtInvitee",
            test_script=[
                "pm.test('detail Get on a v_list-only project → 404 (content closed, hide-existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                "pm.test('grpc code 5 (NOT_FOUND, not 200 — v_list ≠ v_get)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
            ],
        ),
        robust_revoke_binding("teardown-binding", "visVlAcb"),
        teardown("teardown-role", "/iam/v1/roles/{{visVlRole}}"),
        teardown("teardown-proj", "/iam/v1/projects/{{visVlProj}}"),
    ],
))


# ===========================================================================
# Generic exact-set engine for the account-scoped iam content types
# (serviceAccount / group / role). Under the unified label-scope model every iam
# content type materializes label-scope IAM-DIRECT from its own-table labels (no
# resource_mirror feed required — the feed-gate is reversed for iam content types;
# domain.feed_registry_materializable + iam-rbac-rules-labels RBACLBL-IAMTYPE-
# ACCEPTED), so the by-label exact-set read-path is black-box-reachable through the
# public api-gateway exactly like iam.project above. The FGA model carries the
# verb-bearing v_get/v_list relations for iam_user/iam_service_account/iam_group/
# iam_role/iam_access_binding (authzmap fga_model_drift_test).
#
# (kind → create/list REST path, List response array key, Operation-metadata id
#  field, role-rule resource token (camelCase: iam.serviceAccount / iam.group /
#  iam.role), short name stem, optional create-body extra.)
# ===========================================================================

# `sep` — the run-suffix joiner for this type's name: serviceAccount/group names match
# ^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$ (hyphens OK, NO underscore); role names match
# ^[a-z][a-z0-9_]{0,40}$ (underscores OK, NO hyphen) — so they differ.
TYPE_SPECS = {
    "serviceAccount": {"path": "/iam/v1/serviceAccounts", "key": "serviceAccounts",
                       "idmeta": "serviceAccountId", "rule_res": "serviceAccount",
                       "stem": "stsa", "sep": "-", "extra": None},
    "group": {"path": "/iam/v1/groups", "key": "groups",
              "idmeta": "groupId", "rule_res": "group", "stem": "stgr", "sep": "-", "extra": None},
    # Role.Create requires >=1 rule; a benign rule on the OBJECT role does not affect
    # whether the SELECTOR by-label rule materializes it (selection is by the object's
    # labels, not by its own rules).
    "role": {"path": "/iam/v1/roles", "key": "roles",
             "idmeta": "roleId", "rule_res": "role", "stem": "strl", "sep": "_",
             "extra": {"rules": [{"module": "iam", "resources": ["user"], "verbs": ["get"]}]}},
}


def mk_obj(spec, short, label_key, id_var, op_var):
    """Create one account-scoped object of the given type (+ op-poll capturing its id).
    label_key None → no labels (M−); 'foo'/'baz' → labels={key:<runId>} (per-run unique)."""
    body = {"accountId": "{{accountAId}}", "name": short + spec["sep"] + "{{runId}}",
            "description": "newman exact-set obj"}
    if spec["extra"]:
        body.update(spec["extra"])
    if label_key:
        body["labels"] = {label_key: "{{runId}}"}
    return [
        Step(name="create-" + short, method="POST", path=spec["path"], body=body,
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response(f"j.metadata && j.metadata.{spec['idmeta']}", id_var),
                          *save_from_response("j.id", op_var)]),
        poll_op(op_var, out_id_var=id_var),
    ]


def grant_bylabel_generic(spec, role_var, acb_var, role_op, bind_op, verbs, role_name):
    """RoleService.Create(rule {iam.<type> verbs matchLabels:{foo:runId}}) + AccessBinding
    bound to user:userINVId @ ACCOUNT:accountAId. Fresh role id per run → unique active
    5-tuple → no strict-create dup → no pre-clean of THIS binding needed."""
    return [
        Step(name="create-role", method="POST", path="/iam/v1/roles",
             body={"accountId": "{{accountAId}}", "name": role_name + "_{{runId}}",
                   "description": "newman exact-set by-label selector role",
                   # serviceAccount/role List have always been <exempt>; group/project List are
                   # now <exempt> too — no account#v_list anchor
                   # needed. The per-object by-label rule is the only grant; each type's
                   # in-handler viewer∪v_list filter narrows the List to the matched set.
                   "rules": [{"module": "iam", "resources": [spec["rule_res"]],
                              "verbs": verbs, "matchLabels": {"foo": "{{runId}}"}}]},
             auth="jwtAccountAdminA",
             test_script=[*assert_status(200),
                          *save_from_response("j.metadata && j.metadata.roleId", role_var),
                          *save_from_response("j.id", role_op)]),
        poll_op(role_op, out_id_var=role_var),
        Step(name="grant-bylabel", method="POST", path="/iam/v1/accessBindings",
             body={"subjects": [{"type": "SUBJECT_TYPE_USER", "id": "{{userINVId}}"}],
                   "roleId": "{{" + role_var + "}}",
                   "scopeType": "iam.account",
                   "scopeId": "{{accountAId}}",
                   "target": {"allInScope": {}}},
             auth="jwtAccountAdminA",
             test_script=["const j = pm.response.json();",
                          "pm.test('grant accepted (200 Operation)', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200));",
                          "pm.test('IAM Operation envelope (iop)', () => pm.expect(j.id, JSON.stringify(j)).to.match(/^iop[a-z0-9]+$/));",
                          *save_from_response("j.id", bind_op),
                          *save_from_response("j.metadata && j.metadata.accessBindingId", acb_var)]),
        poll_op(bind_op),
    ]


def _id_list_js(env_vars):
    return "['" + "','".join(env_vars) + "']"


def exact_set_case_steps(kind, pfx, role_name):
    """Exact-set steps: 3 M+ (foo) / 3 M− (no-label) / 2 baz (other-label) objects;
    by-label grant (get+list) → subject's List == exactly the M+ set."""
    spec = TYPE_SPECS[kind]
    pp = [f"{pfx}PP{i}" for i in (1, 2, 3)]
    mm = [f"{pfx}PM{i}" for i in (1, 2, 3)]
    bq = [f"{pfx}BQ{i}" for i in (1, 2)]
    objs = []
    for i, v in enumerate(pp, 1):
        objs += mk_obj(spec, f"{spec['stem']}p{i}", "foo", v, v + "Op")
    for i, v in enumerate(mm, 1):
        objs += mk_obj(spec, f"{spec['stem']}m{i}", None, v, v + "Op")
    for i, v in enumerate(bq, 1):
        objs += mk_obj(spec, f"{spec['stem']}b{i}", "baz", v, v + "Op")
    want, mneg, bz = _id_list_js(pp), _id_list_js(mm), _id_list_js(bq)
    read = poll_request_until_status(
        name="read-exact-set", method="GET",
        path=spec["path"] + "?accountId={{accountAId}}&pageSize=1000",
        auth="jwtInvitee", expect_code=200, retry_on=(403, 404),
        # Retry until the exact-set is FULLY CONVERGED, not merely until the M+ set is
        # present. The by-label reconciler materializes userINV's per-object v_list on the
        # foo-matched objects eventually-consistently; while it is still landing tuples, a
        # non-matching (M− / baz) object can be TRANSIENTLY visible before the negative
        # filter settles. Waiting only for "all M+ present" can therefore snapshot a
        # half-materialized set and see a baz object that a beat later is correctly hidden.
        # Converged = all M+ present AND no M− AND no baz. Bounded — a PERMANENT other-label
        # leak (a genuine per-object v_list over-emit) never converges, so the negative
        # asserts below still fail it at budget exhaustion (never masked).
        retry_predicate=("(() => { try { const ids = (pm.response.json()." + spec["key"]
                         + " || []).map(o => o.id); "
                         + "const want = " + want + ".map(v => pm.environment.get(v)); "
                         + "const mneg = " + mneg + ".map(v => pm.environment.get(v)); "
                         + "const bz = " + bz + ".map(v => pm.environment.get(v)); "
                         + "return !want.every(w => ids.indexOf(w) !== -1) "
                         + "|| mneg.some(w => ids.indexOf(w) !== -1) "
                         + "|| bz.some(w => ids.indexOf(w) !== -1); } catch (e) { return true; } })()"),
        test_script=[
            "const j = pm.response.json();",
            "const ids = (j." + spec["key"] + " || []).map(o => o.id);",
            "pm.test('" + kind + ": all three M+ (foo=runId) visible', () => { const want = "
            + want + ".map(v => pm.environment.get(v)); pm.expect(want.every(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.true; });",
            "pm.test('" + kind + ": no M− (no-label) visible (non-matching hidden)', () => { const mneg = "
            + mneg + ".map(v => pm.environment.get(v)); pm.expect(mneg.some(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.false; });",
            "pm.test('" + kind + ": no other-label (baz=runId) visible (label-scoped, not blanket)', () => { const bz = "
            + bz + ".map(v => pm.environment.get(v)); pm.expect(bz.some(w => ids.indexOf(w) !== -1), 'ids: ' + JSON.stringify(ids)).to.be.false; });",
        ],
    )
    teardowns = [robust_revoke_binding("teardown-binding", pfx + "Acb"),
                 teardown("teardown-role", "/iam/v1/roles/{{" + pfx + "Role}}")]
    for v in pp + mm + bq:
        teardowns.append(teardown("teardown-" + v, spec["path"] + "/{{" + v + "}}"))
    return [
        *objs,
        *preclean_account_loop(pfx + "Set", "create-role"),
        *grant_bylabel_generic(spec, pfx + "Role", pfx + "Acb", pfx + "RoleOp", pfx + "BindOp",
                               ["get", "list"], role_name),
        read,
        *teardowns,
    ]


def vlist_only_case_steps(kind, pfx, role_name):
    """v_list-only steps: one labeled object, list-only grant → object IS in the List
    (v_list) but the single-resource Get is 404 (no v_get; v_list ≠ v_get)."""
    spec = TYPE_SPECS[kind]
    obj = pfx + "Vl"
    return [
        *mk_obj(spec, f"{spec['stem']}vl", "foo", obj, obj + "Op"),
        *preclean_account_loop(pfx + "Vl", "create-role"),
        *grant_bylabel_generic(spec, pfx + "VlRole", pfx + "VlAcb", pfx + "VlRoleOp", pfx + "VlBindOp",
                               ["list"], role_name),
        poll_request_until_status(
            name="read-list-visible", method="GET",
            path=spec["path"] + "?accountId={{accountAId}}&pageSize=1000",
            auth="jwtInvitee", expect_code=200, retry_on=(403, 404),
            retry_predicate=("(() => { try { const ids = (pm.response.json()." + spec["key"]
                             + " || []).map(o => o.id); return ids.indexOf(pm.environment.get('" + obj + "')) === -1; } catch (e) { return true; } })()"),
            test_script=[
                "const j = pm.response.json();",
                "pm.test('" + kind + ": v_list-only object IS visible in the List (v_list materialized)', () => { const ids = (j."
                + spec["key"] + " || []).map(o => o.id); pm.expect(ids.indexOf(pm.environment.get('" + obj + "')) !== -1, 'ids: ' + JSON.stringify(ids)).to.be.true; });",
            ],
        ),
        Step(name="detail-get-closed", method="GET", path=spec["path"] + "/{{" + obj + "}}",
             auth="jwtInvitee",
             test_script=[
                 "pm.test('" + kind + ": detail Get on a v_list-only object → 404 (content closed, hide-existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(404));",
                 "let j; try { j = pm.response.json(); } catch (e) { j = null; }",
                 "pm.test('grpc code 5 (NOT_FOUND, not 200 — v_list ≠ v_get)', () => pm.expect(j && j.code, JSON.stringify(j)).to.eql(5));",
             ]),
        robust_revoke_binding("teardown-binding", pfx + "VlAcb"),
        teardown("teardown-role", "/iam/v1/roles/{{" + pfx + "VlRole}}"),
        teardown("teardown-obj", spec["path"] + "/{{" + obj + "}}"),
    ]


# Per-type case selection is NOT uniform — the per-type List/Get authz differs (confirmed on
# the stand against the permission catalog + the iam read-authz handlers):
#   - serviceAccount: List is <exempt> + per-object v_list-filtered, Get gates on v_get → BOTH
#     the exact-set and the v_list-only detail-404 hold.
#   - role: List filters per-object (exact-set holds) BUT RoleService.Get viewer-gates (role/get.go)
#     — a foreign-account role 404s, but a SAME-account role is readable to any account member
#     via the viewer tier; the v_list-only subject holds account access, so it reads the
#     same-account role → 200. The v_list-only → detail-404 invariant is INAPPLICABLE to
#     same-account roles, so only the exact-set case is emitted.
#   - group: GroupService.List per-object-filters (viewer∪v_list on iam_group) AND
#     GroupService.Get gates on v_get → BOTH the exact-set and the v_list-only
#     detail-404 hold. GroupService.List is <exempt>, so no
#     account#v_list anchor is needed; the by-label filter narrows to exactly the matched
#     set just like project/SA.
EXACT_SET_TYPES = [("serviceAccount", "setSva", "SVA"), ("role", "setRol", "ROL"),
                   ("group", "setGrp", "GRP")]
VLIST_ONLY_TYPES = [("serviceAccount", "setSva", "SVA"), ("group", "setGrp", "GRP")]

for _kind, _pfx, _abbr in EXACT_SET_TYPES:
    CASES.append(Case(
        id=f"IAM-SET-{_abbr}-LABEL-EXACT-OK",
        title=f"exact-set ({_kind}): 3 {{foo=runId}} (M+), 3 no-label (M−), 2 {{baz=runId}}; by-label grant {{iam.{_kind} get,list matchLabels foo}} → subject's List contains exactly the M+ set",
        classes=["RBAC", "AUTHZ", "VISIBILITY", "INV2", "LABELS", "EXACT-SET"],
        priority="P0",
        # verifies (non-matching label hidden)
        steps=exact_set_case_steps(_kind, _pfx, f"stlbl{_abbr.lower()}"),
    ))

for _kind, _pfx, _abbr in VLIST_ONLY_TYPES:
    CASES.append(Case(
        id=f"IAM-SET-{_abbr}-VLIST-ONLY-DETAIL-404",
        title=f"v_list-only ({_kind}): by-label grant {{iam.{_kind} list ONLY matchLabels foo}} → object visible in List (v_list) but single-resource Get is 404 (no v_get; v_list ≠ v_get)",
        classes=["RBAC", "AUTHZ", "VISIBILITY", "INV1", "LABELS", "NEG"],
        priority="P0",
        # verifies (v_list-only → content closed)
        steps=vlist_only_case_steps(_kind, _pfx, f"stvl{_abbr.lower()}"),
    ))
