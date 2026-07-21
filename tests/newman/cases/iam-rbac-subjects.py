# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""RBAC rules model — black-box subjects[] / ExpandAccess / ListByRole suite.

Black-box only: every probe goes through api-gateway REST (camelCase JSON); no
internal/ or cmd/ prod code is touched.

What this covers (one acceptance scenario per Case family):

  RBACSUBJ-CR-MULTI-OK
        Create a binding with TWO subjects (user + group) → Operation done →
        Get carries subjects[] of length 2, each subject independent
        (no double-grant anomaly).

  RBACSUBJ-EXPAND-GROUP-OK / -UNAUTH
        ExpandAccess on an object with a group-subject grant resolves the
        userset to CONCRETE principals (the group's members), not just the
        group. NEG: unauthenticated caller → 401/403 (authz: viewer-tier).

  RBACSUBJ-CR-VAL-SUBJECTS-EMPTY / -OVER32
        subjects[] bounds (BVA): empty (0) and >32 (33) → sync 400
        INVALID_ARGUMENT "Illegal argument subjects (must be 1..32)".
        Happy boundary (min=1) is exercised by the legacy→subjects[] (=1) and
        multi-subject (=2) cases; these two are the out-of-range partitions.

  RBACSUBJ-LISTBYROLE-OK / -VAL-MALFORMED / -UNAUTH
        ListByRole(roleId) lists the bindings carrying that role (audit "who
        holds role R"). NEG: malformed roleId → 400; unauthenticated → 401/403.

  RBACSUBJ-PROJ-NEWAUTHOR-LEGACY-FILLED / -LEGACYAUTHOR-SUBJECTS-FILLED
        Dual read-projection: a binding authored via the NEW
        subjects[]+scopeRef input has its legacy subjectType/subjectId
        (=subjects[0]) AND resourceType/resourceId/scope filled on Get; a
        binding authored via the LEGACY single subjectType/subjectId input has
        subjects[] filled with exactly one matching element (parity new←legacy).

Test-design techniques applied:
  - BVA (boundary value analysis): subjects[] count bounds — 0 / 1 / 2 / 33
    around the 1..32 range.
  - ECP (equivalence partitioning): subject types USER vs GROUP; new-author vs
    legacy-author input classes.
  - State / projection invariant: Create → Get the dual-projection equivalence —
    same DB row, both representations consistent.
  - Error guessing: empty vs >32 subjects, malformed roleId, anonymous caller.
  - Conformance: response shapes vs the proto contract (subjects[], principals[],
    accessBindings[]); error text "Illegal argument subjects (must be 1..32)".

Fixture dependency (tests/authz-fixtures/setup-jwt.py + setup.py): jwtAccountAdminA,
jwtNoBindings, accountAId, userAAAId, userAABId, userNOBId. AccessBinding subjects
must reference an EXISTING user/service_account/group in the iam DB — migration 0049
(subject_ref_exists BEFORE INSERT/UPDATE trigger) closes the (subject_type,
subject_id) within-service reference at the DB level (phantom-grant / delete-race,
hard-rule #10), so a made-up `usr-*`/`grp-*` string is rejected 23503 →
FAILED_PRECONDITION at Create. The create/projection cases therefore mint a fresh
REAL user per run via `mint_user()` (the PUBLIC UserService.Invite flow — a PENDING
user row that satisfies the existence trigger; UpsertFromIdentity is Internal-only,
no public REST route) and, for the multi-subject case, create a fresh REAL group; the
ExpandAccess case likewise uses
a REAL group with REAL user members (the group_members trigger requires existing users)
so the userset can resolve to concrete principals. Each minted principal is runId-scoped
(unique per run, no active-grant UNIQUE collision) and referenced by no other suite.

DEPLOY NOTE: the `subjects[]` Create field and the `:expandAccess` / `:listByRole`
public RPCs are registered (public mux) and the IAM build is live on the stack —
every case here runs green. None is in the shared known-RED whitelist
(assert-suites-green.sh), and none should be: this is a black-box conformance suite
that must stay fully green.

GROUP-NAME NOTE: the ExpandAccess case creates a REAL group whose name is
kebab-case (`rbac-e31-grp-{{runId}}`). Group.name is validated by domain
GroupName.Validate → ^[a-z][-a-z0-9]{2,62}$ (parity with Account/Project/
SvcAccount). An underscore in the name is rejected sync 400 INVALID_ARGUMENT
before the Operation is created — keep this name hyphenated, never `rbac_e31_*`.
"""

CASES = []

POLL_CAP = 30

# Dedicated retry budget for steps that wait on the ASYNC fga_outbox drainer
# (group→member userset / group-binding tuple materializing in OpenFGA), as
# opposed to the LRO operation-poll which only waits on the in-process worker.
#
# The drainer (cmd/kacho-iam/serve.go) is LISTEN/NOTIFY-driven with
# PollFallback=30s and BackoffMin/Max=1s/30s. On the happy NOTIFY path the
# tuple lands sub-second; but if a NOTIFY is missed (listener reconnect, the
# row committed mid-batch) the next attempt is only the 30s fallback poll, and
# a transient apply error backs the row off 1..30s. POLL_CAP=30 (~6-9s at
# 100ms --delay-request + RTT) is sized for the FAST worker and is too tight
# for that worst case → the ExpandAccess userset can still be empty when the
# loop gives up (the flake). FGA_POLL_CAP gives ~30-45s of budget so the
# NOTIFY-fallback window is comfortably covered. The assertion is NOT skipped:
# if the tuple never materializes within the budget the loop exits and the same
# member-presence test fails honestly (this is a hardened wait, not a mask).
FGA_POLL_CAP = 180

# Reusable SYSTEM role — `compute.instance.admin` carries permissions
# ["compute.instance.*"] (migration 0001 catalog) and, being a system role, is
# assignable on ANY scope. Same role the δ/α suites use. id = "rol" +
# md5("compute.instance.admin")[:17].
#
# IMPORTANT scope semantics (post-F rules model): this role's rules[] are
# {modules:[compute], resources:[instance], verbs:[*]} — a CONCRETE-type rule. On
# an ACCOUNT-scope binding it emits a TYPE-SCOPED `scope_grant` that cascades onto
# `compute_instance:*` WITHIN the account, NOT a tier tuple on the bare account
# object. So it grants `compute_instance#admin`, it does NOT grant `account#viewer`
# (verified: emitAnchorRule per-type scope_grant path — scope_grant_tuples.go). Use
# it where the test asserts compute-scoped access; do NOT use it to assert
# account-tier resolution (ExpandAccess on account#viewer) — see ROLE_VIEW below.
ROLE_COMPUTE_ADMIN = "rolfe4e91e8c9f6542a6"

# Reusable SYSTEM role — the `view` superuser role. rules[] (migration 0031 re-seed)
# are {modules:[*],resources:[*],verbs:[read,list,get]} — a FULL `*.*` wildcard. On
# a TIER-scope anchor (account/project/cluster) the wildcard tier-anchor path
# emits a single TIER tuple on the BARE anchor: `account:<id>#viewer@<subject>`,
# which cascades onto every child resource (the system-role superuser intent). This
# is the role that REALLY grants `account#viewer`, so a GROUP-subject binding of it
# resolves the group's members on `account#viewer` (the userset→principals
# scenario). id = "rol" + md5("view")[:17]. Being a system role it is assignable on
# any scope by a caller with grant-authority on that scope (jwtAccountAdminA on A).
ROLE_VIEW = "rol1bda80f2be4d3658e"

# A malformed (not well-formed) role id for the ListByRole negative — fails the
# corevalidate.ResourceID first-statement check → sync InvalidArgument, distinct
# from a well-formed-but-absent id (which would be NOT_FOUND / empty list).
MALFORMED_ROLE_ID = "not-a-role-id!!"


# ---------------------------------------------------------------------------
# Helpers (local — mirrors the idioms in iam-access-binding.py / iam-rbac-*.py).
# ---------------------------------------------------------------------------

def assert_iam_operation_envelope():
    return [
        "pm.test('IAM Operation envelope returned', () => {",
        "  const j = pm.response.json();",
        "  pm.expect(j.id, 'operation.id must start with iop').to.match(/^iop[a-z0-9]+$/);",
        "  pm.expect(j.done, 'operation.done present').to.be.a('boolean');",
        "});",
    ]


def poll_capture_acb(op_var, acb_var, auth="jwtAccountAdminA"):
    """GET /operations/{op} until done; assert done && !error; capture acb id.

    Self-re-invoking poll with a request-name-scoped counter (the per-case
    reset discipline) so iteration count never bleeds across cases.
    """
    return Step(
        name=f"poll-capture-{acb_var}",
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
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_pollCount');",
            "pm.environment.unset('_pollStarted');",
            "pm.test('operation done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
            "pm.test('operation succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
            f"if (j.response && j.response.id) pm.environment.set('{acb_var}', j.response.id);",
        ],
    )


def poll_op_done(op_var, auth="jwtAccountAdminA", out_id_var=None):
    """GET /operations/{op} until done; assert done && !error; optionally stash
    response.id into out_id_var (group/binding capture)."""
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
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
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


def teardown_delete(acb_var, auth="jwtAccountAdminA"):
    """Best-effort revoke so re-runs don't trip strict-create active-grant UNIQUE."""
    return Step(
        name=f"teardown-{acb_var}",
        method="DELETE",
        path="/iam/v1/accessBindings/{{" + acb_var + "}}",
        auth=auth,
        test_script=[
            "pm.test('teardown: status acceptable', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
        ],
    )


def mint_user(env_var, ext, auth="jwtAccountAdminA"):
    """Mint a fresh REAL user via the PUBLIC invite flow (UserService.Invite,
    POST /iam/v1/users:invite), wait for the user row to COMMIT, and stash its id —
    so it can be an AccessBinding subject.

    Returns TWO steps: the invite + a poll of the returned Operation to done.

    WHY REAL (migration 0049 — access_bindings subject_ref_exists trigger): a
    binding's (subject_type, subject_id) must reference an EXISTING
    user/service_account/group in the iam DB (a within-service invariant closing the
    phantom-grant / delete-race holes, hard-rule #10). A synthetic `usr-*-{{runId}}`
    string that was never created is rejected 23503 → FAILED_PRECONDITION at Create,
    so subjects can no longer be made up on the fly.

    WHY INVITE (not UpsertFromIdentity): UpsertFromIdentity is an Internal* RPC with
    no PUBLIC REST route — it lives ONLY on the api-gateway cluster-internal listener
    (:8081), so POSTing it at the public {{baseUrl}} (:8080) returns 404 (ban #6). The
    PUBLIC user-mint path a tenant admin can drive over REST is Invite: it INSERTs a
    PENDING user row (invite.go InsertPending) and returns metadata.userId synchronously.
    The row EXISTS in kacho_iam.users, so the 0049 trigger (existence, status-agnostic)
    passes and the id is a valid binding subject. email is runId-scoped → a distinct real
    user per run (unique per-run subject → no active-grant UNIQUE collision) referenced
    by no other suite (→ no cross-suite pollution — the property the old synthetic ids
    gave, now with a real principal). Idempotent by (account, email); jwtAccountAdminA
    can invite into account-A (canInviteUsers editor cascade). The invited id carries the
    `usr` prefix (domain.PrefixUser). This is the SAME public flow the GREEN
    iam-user IAM-USR-SETUP-INVITE-INV-TO-B case uses.

    WHY POLL: Invite is async (operations.Run → LRO worker commits the row in a
    dispatcher goroutine); the response returns before the row is committed. The
    immediately-following binding Create would race the commit and re-trip the 0049
    trigger. So we deterministically wait for the mint Operation to report done (not
    time.Sleep) — then the user row is committed and usable as a subject. metadata.userId
    is set synchronously (pre-allocated candidate id) and is stable for a fresh
    runId-scoped email."""
    op_var = f"{env_var}MintOp"
    return [
        Step(
            name=f"mint-{env_var}",
            method="POST",
            path="/iam/v1/users:invite",
            body={
                "accountId": "{{accountAId}}",
                "email": f"{ext}-{{{{runId}}}}@kacho.local",
                "displayName": f"rbac-subjects {ext} {{{{runId}}}}",
            },
            auth=auth,
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", op_var),
                *save_from_response("(j.metadata && j.metadata.userId) || (j.user && j.user.id) || j.id", env_var),
                f"pm.test('minted {env_var} has usr prefix', () => pm.expect(pm.environment.get('{env_var}') || '', 'minted user id').to.match(/^usr[a-z0-9]+$/));",
            ],
        ),
        Step(
            name=f"mint-poll-{env_var}",
            method="GET",
            path="/operations/{{" + op_var + "}}",
            auth=auth,
            test_script=[
                "pm.test('mint poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
                "const j = pm.response.json();",
                "if (pm.environment.get('_pollStarted') !== pm.info.requestName) { pm.environment.set('_pollCount', '0'); pm.environment.set('_pollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_pollCount') || '0', 10);",
                f"if (!j.done && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_pollCount', String(pc + 1));",
                "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_pollCount');",
                "pm.environment.unset('_pollStarted');",
                f"pm.test('minted {env_var} committed (operation done, no error)', () => {{",
                "  pm.expect(j.done, JSON.stringify(j)).to.eql(true);",
                "  pm.expect(j.error, JSON.stringify(j)).to.not.exist;",
                "});",
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# RBACSUBJ-CR-MULTI-OK: Create binding with 2 independent subjects (user +
# group) via the canonical subjects[]+scopeRef input → Operation done → Get shows
# subjects[] of length 2, each subject preserved. (R-5 — subjects independence.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-CR-MULTI-OK",
    title="Create AccessBinding with subjects[]=[user, group] → Operation done; Get carries subjects[] of length 2, each independent",
    classes=["RBAC", "RULES", "SUBJECTS", "CRUD", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (subjects[] independence — no double-grant anomaly)
        # Both subjects must be REAL principals (migration 0049 subject_ref_exists):
        # mint a fresh user and create a fresh group, then bind BOTH.
        *mint_user("e30UserId", "usr-e30"),
        Step(
            name="create-e30-group",
            method="POST",
            path="/iam/v1/groups",
            body={
                "accountId": "{{accountAId}}",
                "name": "rbac-e30-grp-{{runId}}",
                "description": "newman multi-subject probe group",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e30GrpOpId"),
                *save_from_response("j.metadata && j.metadata.groupId", "e30GroupId"),
            ],
        ),
        poll_op_done("e30GrpOpId", out_id_var="e30GroupId"),
        Step(
            name="create-multi-subject",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [
                    {"type": "SUBJECT_TYPE_USER", "id": "{{e30UserId}}"},
                    {"type": "SUBJECT_TYPE_GROUP", "id": "{{e30GroupId}}"},
                ],
                "roleId": ROLE_COMPUTE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "e30OpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "e30AcbId"),
            ],
        ),
        poll_capture_acb("e30OpId", "e30AcbId"),
        # Read-after-write on the fresh binding OBJECT: the owner/account-admin's
        # per-object v_get tuple forward-materializes a beat after Create→Operation-done
        # (flat-RBAC grant→visibility window), so a single-shot GET intermittently hits
        # the hide-existence 404 (read-deny == NOT_FOUND) before convergence — observed
        # on this FIRST case with a cold fga drainer (the binding EXISTS: the teardown
        # DELETE got 403, not 404). Poll past the 403/404 window to the terminal 200
        # (parity with the get-new-fills-legacy case; a genuine never-converge still
        # surfaces at the cap, never masked).
        poll_request_until_status(
            name="get-subjects-len-2",
            method="GET",
            path="/iam/v1/accessBindings/{{e30AcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                # One thought per test: count, then each member's identity.
                "pm.test('subjects[] length is 2', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  pm.expect(subs.length, JSON.stringify(subs)).to.eql(2);",
                "});",
                "pm.test('subjects[] carries the USER subject', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  const want = pm.environment.get('e30UserId');",
                "  pm.expect(subs.some(s => s.type === 'SUBJECT_TYPE_USER' && s.id === want), JSON.stringify(subs)).to.be.true;",
                "});",
                "pm.test('subjects[] carries the GROUP subject (independent)', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  const want = pm.environment.get('e30GroupId');",
                "  pm.expect(subs.some(s => s.type === 'SUBJECT_TYPE_GROUP' && s.id === want), JSON.stringify(subs)).to.be.true;",
                "});",
            ],
        ),
        teardown_delete("e30AcbId"),
    ],
))


# ---------------------------------------------------------------------------
# subjects[] bounds (BVA). The 1..32 range: empty (0, below-min) and 33
# (above-max) are the out-of-range partitions → sync 400 INVALID_ARGUMENT
# "Illegal argument subjects (must be 1..32)". Min/typical (1/2) are positive in
# the projection and multi-subject cases. Separate Cases (one thought each), not merged.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-CR-VAL-SUBJECTS-EMPTY",
    title="Create with subjects[]=[] (and no legacy single) → 400 INVALID_ARGUMENT 'Illegal argument subjects (must be 1..32)' (below-min BVA)",
    classes=["RBAC", "RULES", "SUBJECTS", "VAL", "BVA", "NEGATIVE"],
    priority="P0",
    steps=[
        # verifies (a) empty subjects → below-min boundary
        Step(
            name="create-empty-subjects",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [],
                "roleId": ROLE_COMPUTE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                # Bounds are checked SYNC (before the Operation) → HTTP 400.
                "const j = pm.response.json();",
                "pm.test('empty subjects rejected sync 400', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(400));",
                "pm.test('error code INVALID_ARGUMENT (3)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
                "pm.test('error text: Illegal argument subjects (must be 1..32)', () => pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.include('illegal argument subjects'));",
            ],
        ),
    ],
))

CASES.append(Case(
    id="RBACSUBJ-CR-VAL-SUBJECTS-OVER32",
    title="Create with subjects[] of 33 elements → 400 INVALID_ARGUMENT 'Illegal argument subjects (must be 1..32)' (above-max BVA)",
    classes=["RBAC", "RULES", "SUBJECTS", "VAL", "BVA", "NEGATIVE"],
    priority="P0",
    steps=[
        # verifies (a) >32 subjects → above-max boundary
        Step(
            name="create-33-subjects",
            method="POST",
            path="/iam/v1/accessBindings",
            # 33 distinct synthetic user subjects (above the 32 max). The body is
            # assembled as a REAL JSON array in the pre-request and assigned to
            # pm.request.body directly — a `"subjects": "{{var}}"` string-template
            # would substitute to a quoted JSON STRING (not an array) and be
            # rejected as malformed, masking the bounds error we want to assert.
            pre_script=[
                "const runId = pm.environment.get('runId');",
                "const accId = pm.environment.get('accountAId');",
                "const subs = [];",
                "for (let i = 0; i < 33; i++) {",
                "  subs.push({ type: 'SUBJECT_TYPE_USER', id: ('usr-e32-' + i + '-' + runId) });",
                "}",
                "const reqBody = {",
                "  subjects: subs,",
                f"  roleId: '{ROLE_COMPUTE_ADMIN}',",
                "  scopeType: 'iam.account',",
                "  scopeId: accId,",
                "  target: { allInScope: {} },",
                "};",
                "pm.request.body = { mode: 'raw', raw: JSON.stringify(reqBody), options: { raw: { language: 'json' } } };",
            ],
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('>32 subjects rejected sync 400', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(400));",
                "pm.test('error code INVALID_ARGUMENT (3)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
                "pm.test('error text: Illegal argument subjects (must be 1..32)', () => pm.expect((j.message || '').toLowerCase(), JSON.stringify(j)).to.include('illegal argument subjects'));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-PROJ-NEWAUTHOR-LEGACY-FILLED: a binding authored via the NEW
# subjects[]+scopeRef input has its LEGACY projection (subjectType/subjectId =
# subjects[0]; resourceType/resourceId/scope from scopeRef) filled on Get, so
# pre-E clients don't break. Output-only projection (O-6).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-PROJ-NEWAUTHOR-LEGACY-FILLED",
    title="Create via NEW subjects[]+scopeRef → Get fills legacy subjectType/subjectId (=subjects[0]) AND resourceType/resourceId/scope",
    classes=["RBAC", "RULES", "SUBJECTS", "PROJECTION", "DELTA"],
    priority="P0",
    steps=[
        # verifies (new-author → legacy-fields-filled)
        # subject must be a REAL user (migration 0049) — mint one for this run.
        *mint_user("e34NewUserId", "usr-e34-new"),
        Step(
            name="create-new-form",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                # Canonical NEW input ONLY — no legacy subjectType/subjectId,
                # no legacy resourceType/resourceId.
                "subjects": [
                    {"type": "SUBJECT_TYPE_USER", "id": "{{e34NewUserId}}"},
                ],
                "roleId": ROLE_COMPUTE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "e34NewOpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "e34NewAcbId"),
            ],
        ),
        poll_capture_acb("e34NewOpId", "e34NewAcbId"),
        # Read-after-write on the fresh binding OBJECT: the author's v_get on it
        # forward-materializes a beat after Create→Operation-done, so a
        # single-shot GET intermittently hits the hide-existence 404 (read-deny ==
        # NOT_FOUND) before convergence. Poll past the 403/404 window to the 200
        # (a genuine never-converge still surfaces at the cap, never masked).
        poll_request_until_status(
            name="get-new-fills-legacy",
            method="GET",
            path="/iam/v1/accessBindings/{{e34NewAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                # Canonical projection echoes the input.
                "pm.test('subjects[] length 1 (input)', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  pm.expect(subs.length, JSON.stringify(subs)).to.eql(1);",
                "});",
                # Legacy subject projection = subjects[0].
                "pm.test('legacy subjectType filled = user (subjects[0])', () => pm.expect(pm.response.json().subjectType).to.eql('user'));",
                "pm.test('legacy subjectId filled = subjects[0].id', () => {",
                "  const want = pm.environment.get('e34NewUserId');",
                "  pm.expect(pm.response.json().subjectId).to.eql(want);",
                "});",
                # Legacy scope projection derived from scopeRef.
                "pm.test('legacy resourceType filled = account (from scopeRef)', () => pm.expect(pm.response.json().scopeType).to.eql('iam.account'));",
                "pm.test('legacy resourceId filled = accountAId (from scopeRef)', () => pm.expect(pm.response.json().scopeId).to.eql(pm.environment.get('accountAId')));",
                "pm.test('legacy enum scope filled = ACCOUNT (from scopeRef)', () => pm.expect(pm.response.json().scope).to.eql('ACCOUNT'));",
            ],
        ),
        teardown_delete("e34NewAcbId"),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-PROJ-LEGACYAUTHOR-SUBJECTS-FILLED: a binding authored via the
# LEGACY single subjectType/subjectId input carries subjects[] of EXACTLY ONE
# element matching the legacy single (parity new←legacy). This is the reverse
# projection of the new-author case.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-PROJ-LEGACYAUTHOR-SUBJECTS-FILLED",
    title="Create via LEGACY single subjectType/subjectId → Get fills subjects[] with exactly one element matching the legacy single (parity new←legacy)",
    classes=["RBAC", "RULES", "SUBJECTS", "PROJECTION", "DELTA"],
    priority="P0",
    steps=[
        # verifies (legacy-author → subjects[]-filled)
        # subject must be a REAL user (migration 0049) — mint one for this run.
        *mint_user("e34LegUserId", "usr-e34-leg"),
        Step(
            name="create-legacy-form",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                # LEGACY single input ONLY — no subjects[], no scopeRef.
                "subjectType": "user",
                "subjectId": "{{e34LegUserId}}",
                "roleId": ROLE_COMPUTE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *assert_iam_operation_envelope(),
                *save_from_response("j.id", "e34LegOpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "e34LegAcbId"),
            ],
        ),
        poll_capture_acb("e34LegOpId", "e34LegAcbId"),
        # Read-after-write on the fresh binding OBJECT (same grant→visibility window as
        # get-new-fills-legacy / get-subjects-len-2): poll past the 403/404 hide window.
        poll_request_until_status(
            name="get-legacy-fills-subjects",
            method="GET",
            path="/iam/v1/accessBindings/{{e34LegAcbId}}",
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                # Legacy single unchanged.
                "pm.test('legacy subjectType unchanged = user', () => pm.expect(pm.response.json().subjectType).to.eql('user'));",
                "pm.test('legacy subjectId unchanged', () => {",
                "  const want = pm.environment.get('e34LegUserId');",
                "  pm.expect(pm.response.json().subjectId).to.eql(want);",
                "});",
                # Reverse projection: subjects[] = exactly one matching element.
                "pm.test('subjects[] length is exactly 1', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  pm.expect(subs.length, JSON.stringify(subs)).to.eql(1);",
                "});",
                "pm.test('subjects[0] matches the legacy single', () => {",
                "  const subs = pm.response.json().subjects || [];",
                "  const want = pm.environment.get('e34LegUserId');",
                "  pm.expect(subs[0] && subs[0].type, JSON.stringify(subs)).to.eql('SUBJECT_TYPE_USER');",
                "  pm.expect(subs[0] && subs[0].id, JSON.stringify(subs)).to.eql(want);",
                "});",
            ],
        ),
        teardown_delete("e34LegAcbId"),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-LISTBYROLE-OK: ListByRole(roleId) lists the bindings carrying
# the role (audit "who holds role R"). Self-contained: creates a binding on
# ROLE_COMPUTE_ADMIN, then ListByRole(ROLE_COMPUTE_ADMIN) must include it.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-LISTBYROLE-OK",
    title="ListByRole(roleId) → lists the bindings carrying the role (incl. the one just created)",
    classes=["RBAC", "RULES", "SUBJECTS", "LISTBYROLE", "AUDIT", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (audit who holds role R)
        # subject must be a REAL user (migration 0049) — mint one for this run.
        *mint_user("e33UserId", "usr-e33"),
        Step(
            name="create-binding-for-role",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [{"type": "SUBJECT_TYPE_USER", "id": "{{e33UserId}}"}],
                "roleId": ROLE_COMPUTE_ADMIN,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e33OpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "e33AcbId"),
            ],
        ),
        poll_capture_acb("e33OpId", "e33AcbId"),
        # Read-after-write on a LIST: ListByRole returns 200 immediately, but the
        # freshly-created binding enters the AUTHZ-FILTERED result only once the caller's
        # per-object v_get/v_list tuple propagates (same grant→visibility window). A
        # single-shot list can therefore miss the fresh row. Retry (retry_predicate)
        # while the created id is not yet in the set; assert on the terminal list (a
        # genuine never-appears still fails at the cap, never masked).
        poll_request_until_status(
            name="listbyrole-includes-binding",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId=" + ROLE_COMPUTE_ADMIN,
            auth="jwtAccountAdminA",
            retry_predicate="(() => { const j = pm.response.json(); const id = pm.environment.get('e33AcbId'); return id && !((j.accessBindings)||[]).some(b => b.id === id); })()",
            test_script=[
                *assert_status(200),
                "pm.test('response carries accessBindings[]', () => {",
                "  const arr = pm.response.json().accessBindings;",
                "  pm.expect(arr, JSON.stringify(pm.response.json())).to.be.an('array');",
                "});",
                "pm.test('every listed binding carries the queried roleId', () => {",
                "  const arr = pm.response.json().accessBindings || [];",
                f"  pm.expect(arr.every(b => b.roleId === '{ROLE_COMPUTE_ADMIN}'), JSON.stringify(arr)).to.be.true;",
                "});",
                "pm.test('the created binding is present', () => {",
                "  const arr = pm.response.json().accessBindings || [];",
                "  const want = pm.environment.get('e33AcbId');",
                "  pm.expect(arr.some(b => b.id === want), JSON.stringify(arr.map(b => b.id))).to.be.true;",
                "});",
            ],
        ),
        teardown_delete("e33AcbId"),
    ],
))


# ---------------------------------------------------------------------------
# malformed roleId → sync 400 INVALID_ARGUMENT (corevalidate.ResourceID
# first-statement guard), distinct from a well-formed-but-absent id.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-LISTBYROLE-VAL-MALFORMED",
    title="ListByRole with malformed roleId → 400 INVALID_ARGUMENT",
    classes=["RBAC", "RULES", "SUBJECTS", "LISTBYROLE", "VAL", "NEGATIVE"],
    priority="P1",
    steps=[
        # verifies (malformed roleId → 400)
        Step(
            name="listbyrole-malformed",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId=" + MALFORMED_ROLE_ID,
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('malformed roleId → 400', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(400));",
                "pm.test('error code INVALID_ARGUMENT (3)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# unauthenticated caller → 401/403 (ListByRole authz: viewer-tier;
# anonymous fail-closed). Auth removed at the step level.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-LISTBYROLE-UNAUTH",
    title="ListByRole unauthenticated → 401/403 (viewer-tier, anonymous fail-closed)",
    classes=["RBAC", "RULES", "SUBJECTS", "LISTBYROLE", "AUTHZ", "NEGATIVE"],
    priority="P1",
    steps=[
        # verifies (unauth → 401/403)
        Step(
            name="listbyrole-anon",
            method="GET",
            path="/iam/v1/accessBindings:listByRole?roleId=" + ROLE_COMPUTE_ADMIN,
            auth="anonymous",
            test_script=[
                "pm.test('unauthenticated ListByRole → 401/403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([401, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-EXPAND-GROUP-OK: ExpandAccess resolves a group-subject userset
# into CONCRETE principals (the group's members). Self-contained: create a REAL
# group, add REAL user members (userAAAId, userAABId — the group_members trigger
# requires existing users), bind a role that grants account#viewer to that group on
# the account, then ExpandAccess (objectType=account, objectId=accountAId,
# relation=viewer) must list the concrete member principals — NOT just the group.
#
# ROLE CHOICE — must grant `account#viewer` (not a compute-scoped grant):
# this case queries ExpandAccess on `account:accountAId#viewer`, so the bound role
# MUST emit a tuple that makes a group member resolve `account#viewer`. ROLE_VIEW
# (`*.*` verbs [read,list,get]) is the system superuser-view role: on the ACCOUNT
# anchor the wildcard tier-anchor path emits `account:accountAId#viewer@group:
# <gid>#member`, which (a) is a model-valid write — fga_model.fga `account.viewer:
# [user, service_account, group#member] …` — and (b) makes every group member
# resolve viewer on the account. A member therefore appears in ListUsers(account,
# viewer) → ExpandAccess returns the concrete members.
#
# WHY NOT ROLE_COMPUTE_ADMIN here: a prior revision bound ROLE_COMPUTE_ADMIN
# (`compute.instance.*`). Post-F that role's CONCRETE-type rule emits a TYPE-SCOPED
# scope_grant cascading onto `compute_instance:*` — it grants compute access, NOT
# `account#viewer`. So a group member NEVER resolved `account:accountAId#viewer`
# from it (correctly — the role doesn't grant the account tier). The account owner
# (userAAAId) still appeared via the ownership/admin path, masking the mismatch and
# making it look like only userAABId "failed"; in fact the case-setup asked the
# wrong object/relation for the role under test. The product is correct: a
# compute-scoped grant must not grant account-viewer. Fixed by binding ROLE_VIEW,
# the role that actually grants the queried `account#viewer` relation. This is a
# test-setup fix (object/relation aligned to what the role grants), not a product
# change — the live tier-anchor path + group userset resolution is unchanged.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-EXPAND-GROUP-OK",
    title="ExpandAccess on a group-subject grant → response.principals lists the concrete group members (userset→principals)",
    classes=["RBAC", "RULES", "SUBJECTS", "EXPAND", "AUDIT", "HAPPY"],
    priority="P0",
    steps=[
        # verifies (userset → concrete principals; audit "who really can X")
        # 1) Create a real group.
        Step(
            name="create-group",
            method="POST",
            path="/iam/v1/groups",
            body={
                # Group.name is kebab-case (domain GroupName.Validate →
                # ^[a-z][-a-z0-9]{2,62}$, same as Account/Project/SvcAccount).
                # Underscores are rejected sync 400 — keep this hyphenated.
                "accountId": "{{accountAId}}",
                "name": "rbac-e31-grp-{{runId}}",
                "description": "newman ExpandAccess probe group",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e31GrpOpId"),
                *save_from_response("j.metadata && j.metadata.groupId", "e31GroupId"),
            ],
        ),
        poll_op_done("e31GrpOpId", out_id_var="e31GroupId"),
        # 2) Add two REAL user members (trigger enforces existence).
        # Retry PAST the 403 creator-tuple window (admin v_update on the fresh group
        # materializes a beat after Create→done). Once this first AddMember commits the
        # tuple is materialized, so add-member-aab below cannot race it.
        poll_request_until_status(
            name="add-member-aaa",
            method="POST",
            path="/iam/v1/groups/{{e31GroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userAAAId}}"},
            auth="jwtAccountAdminA",
            expect_code=200,
            retry_on=(403,),
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e31AddAaaOpId"),
            ],
        ),
        poll_op_done("e31AddAaaOpId"),
        Step(
            name="add-member-aab",
            method="POST",
            path="/iam/v1/groups/{{e31GroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userAABId}}"},
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e31AddAabOpId"),
            ],
        ),
        poll_op_done("e31AddAabOpId"),
        # 3) Bind the account-viewer role to the GROUP subject on the account.
        #    ROLE_VIEW (`*.*` [read,list,get]) emits `account:<id>#viewer@group:
        #    <gid>#member` (the tier-anchor path), so the group's members
        #    resolve `account#viewer` — exactly the relation ExpandAccess queries.
        Step(
            name="bind-group-subject",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [{"type": "SUBJECT_TYPE_GROUP", "id": "{{e31GroupId}}"}],
                "roleId": ROLE_VIEW,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "e31BindOpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "e31AcbId"),
            ],
        ),
        poll_capture_acb("e31BindOpId", "e31AcbId"),
        # 4) ExpandAccess → concrete member principals (self-retries until the
        #    async FGA drainer materializes the group→members userset). The
        #    retry budget is FGA_POLL_CAP (not POLL_CAP) because this waits on
        #    the LISTEN/NOTIFY+30s-fallback fga_outbox drainer, not the fast LRO
        #    worker — see the FGA_POLL_CAP comment for the sizing rationale.
        Step(
            name="expand-access-members",
            method="GET",
            path="/iam/v1/accessBindings:expandAccess?objectType=account&objectId={{accountAId}}&relation=viewer",
            auth="jwtAccountAdminA",
            # Counter reset on FIRST entry only (request-name-scoped flag in the
            # pre-request), so the setNextRequest re-invocations do NOT reset the
            # count mid-loop — same discipline as poll_operation_until_done.
            pre_script=[
                "if (pm.environment.get('_expStarted') !== pm.info.requestName) {",
                "  pm.environment.set('_expCount', '0');",
                "  pm.environment.set('_expStarted', pm.info.requestName);",
                "}",
            ],
            test_script=[
                "const j = pm.response.json();",
                # Retry until BOTH expected members appear (FGA outbox drainer is
                # async) or FGA_POLL_CAP is hit, then assert the steady state.
                "const ec = parseInt(pm.environment.get('_expCount') || '0', 10);",
                "const ids = (j.principals || []).map(p => p.id);",
                "const wantA = pm.environment.get('userAAAId');",
                "const wantB = pm.environment.get('userAABId');",
                "const ready = (pm.response.code === 200 && ids.indexOf(wantA) !== -1 && ids.indexOf(wantB) !== -1);",
                f"if (!ready && ec < {FGA_POLL_CAP}) {{",
                "  pm.environment.set('_expCount', String(ec + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_expCount');",
                "pm.environment.unset('_expStarted');",
                *assert_status(200),
                "pm.test('response carries principals[]', () => pm.expect(j.principals, JSON.stringify(j)).to.be.an('array'));",
                "pm.test('concrete member userAAAId resolved (not just the group)', () => {",
                "  const ids = (j.principals || []).map(p => p.id);",
                "  pm.expect(ids, JSON.stringify(j.principals)).to.include(pm.environment.get('userAAAId'));",
                "});",
                "pm.test('concrete member userAABId resolved', () => {",
                "  const ids = (j.principals || []).map(p => p.id);",
                "  pm.expect(ids, JSON.stringify(j.principals)).to.include(pm.environment.get('userAABId'));",
                "});",
                "pm.test('principals are concrete (no GROUP type in the result)', () => {",
                "  const types = (j.principals || []).map(p => p.type);",
                "  pm.expect(types, JSON.stringify(j.principals)).to.not.include('SUBJECT_TYPE_GROUP');",
                "});",
            ],
        ),
        teardown_delete("e31AcbId"),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-GROUP-GRANTS-MEMBER-OK — the group-membership FGA mirror fix happy
# path: a member added to a group on which a viewer binding is granted actually
# GAINS access (InternalIAMService.Check(user:<member>, viewer, account) → allowed).
#
# This is the positive counterpart to the bug this case surfaced: AddMember used to
# persist only the iam-DB group_members row and never emitted the FGA
# `group:<gid>#member` userset tuple, so the binding's `@group:<gid>#member`
# userset resolved to EMPTY and the member got NO real access. The fix
# (add_member.go EmitFGARelationWrite, migration 0029 backfill) makes the
# member-tuple flow into OpenFGA so the Check below converges allowed=true.
#
# MEMBER + ROLE CHOICE — the probe must be DECISIVE, not satisfiable by another
# path. It checks `Check(user:userAABId, viewer, account:accountAId)`:
#   - userAABId is the owner/admin of account B, with NO independent grant on
#     account A — so it can resolve `account:accountAId#viewer` ONLY through the
#     group→member→binding userset. (A prior revision used userAAAId, the account-A
#     OWNER; that Check is true via ownership regardless of the group binding — a
#     false positive that masks the very path this case claims to verify.)
#   - ROLE_VIEW (`*.*` [read,list,get]) actually grants `account#viewer` via the
#     tier-anchor `account:<id>#viewer@group:<gid>#member` tuple. (A prior
#     revision bound ROLE_COMPUTE_ADMIN, which grants compute-scoped access, not
#     account-viewer — so the Check could never pass via the group on this object.)
# Together: a green result here PROVES the group-userset → account-viewer path
# (member-tuple ∧ binding-tier-tuple both drained), not an unrelated grant.
#
# The probe targets InternalIAMService.Check (/iam/v1/internal/iam:check) — the
# raw FGA Check the per-RPC authz gate uses — and self-retries while the async
# fga_outbox drainer materializes the member-tuple.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-GROUP-GRANTS-MEMBER-OK",
    title="Group membership FGA mirror: a group member gains access via a group-subject binding (Check member → allowed)",
    classes=["RBAC", "RULES", "SUBJECTS", "AUTHZ", "HAPPY"],
    priority="P0",
    steps=[
        # verifies the group-membership FGA mirror fix (AddMember emits group:#member)
        Step(
            name="create-group",
            method="POST",
            path="/iam/v1/groups",
            body={
                "accountId": "{{accountAId}}",
                "name": "rbac-gm-grant-grp-{{runId}}",
                "description": "newman group-grants-member probe group",
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "gmGrantGrpOpId"),
                *save_from_response("j.metadata && j.metadata.groupId", "gmGrantGroupId"),
            ],
        ),
        poll_op_done("gmGrantGrpOpId", out_id_var="gmGrantGroupId"),
        # Add a REAL user member (trigger enforces existence). userAABId has NO
        # independent grant on account A, so the Check below can only pass through
        # the group→member→binding userset — a decisive probe, not ownership.
        # The admin's `v_update` on the freshly-created group OBJECT (action
        # iam.group_members.addMember) materializes via fga_outbox a beat after the group
        # Create→done (propagation window), so an immediate AddMember can race it and 403
        # ("lacks v_update on iam_group"). Retry the POST PAST the 403 window until it commits.
        poll_request_until_status(
            name="add-member",
            method="POST",
            path="/iam/v1/groups/{{gmGrantGroupId}}:addMember",
            body={"memberType": "user", "memberId": "{{userAABId}}"},
            auth="jwtAccountAdminA",
            expect_code=200,
            retry_on=(403,),
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "gmGrantAddOpId"),
            ],
        ),
        poll_op_done("gmGrantAddOpId"),
        # Bind the account-viewer role (ROLE_VIEW) to the GROUP subject on the
        # account — it emits account:<id>#viewer@group:<gid>#member, the relation
        # the Check queries. (ROLE_COMPUTE_ADMIN would grant compute scope, not
        # account#viewer, so it could not satisfy this Check via the group.)
        Step(
            name="bind-group-subject",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjects": [{"type": "SUBJECT_TYPE_GROUP", "id": "{{gmGrantGroupId}}"}],
                "roleId": ROLE_VIEW,
                "scopeType": "iam.account",
                "scopeId": "{{accountAId}}",
                "target": {"allInScope": {}},
            },
            auth="jwtAccountAdminA",
            test_script=[
                *assert_status(200),
                *save_from_response("j.id", "gmGrantBindOpId"),
                *save_from_response("j.metadata && j.metadata.accessBindingId", "gmGrantAcbId"),
            ],
        ),
        poll_capture_acb("gmGrantBindOpId", "gmGrantAcbId"),
        # The decisive probe: the member must resolve viewer on the account via the
        # group userset. Self-retries while the fga_outbox drainer applies the
        # group:<gid>#member tuple (AddMember co-commit) + the binding tuple.
        Step(
            name="check-member-allowed",
            method="POST",
            path="/iam/v1/internal/iam:check",
            auth="jwtAccountAdminA",
            pre_script=[
                "if (pm.environment.get('_gmChkStarted') !== pm.info.requestName) { pm.environment.set('_gmChkCount', '0'); pm.environment.set('_gmChkStarted', pm.info.requestName); }",
                "pm.environment.set('_gmChkSubj', 'user:' + pm.environment.get('userAABId'));",
                "pm.environment.set('_gmChkObj', 'account:' + pm.environment.get('accountAId'));",
                "// InternalIAMService.Check (/iam/v1/internal/iam:check) is an Internal* RPC —",
                "// it lives ONLY on the api-gateway cluster-internal REST listener, NOT the",
                "// public cmux. Reach it via internalBaseUrl (:18081 in CI); the public baseUrl",
                "// 404s /iam/v1/internal/* by design (ban #6). If internalBaseUrl is unset",
                "// (local dev without the internal-rest port-forward) the URL is left on baseUrl.",
                "const _intBase = pm.environment.get('internalBaseUrl') || pm.variables.get('internalBaseUrl') || '';",
                "if (_intBase) { pm.request.url = _intBase + '/iam/v1/internal/iam:check'; }",
            ],
            body={
                "subjectId": "{{_gmChkSubj}}",
                "relation": "viewer",
                "object": "{{_gmChkObj}}",
            },
            test_script=[
                "const j = pm.response.json();",
                "const pc = parseInt(pm.environment.get('_gmChkCount') || '0', 10);",
                # FGA_POLL_CAP (not POLL_CAP): the member-tuple this Check depends
                # on lands via the same async LISTEN/NOTIFY+30s-fallback fga_outbox
                # drainer as the ExpandAccess case, so it needs the wider budget for the worst case.
                f"if (!(pm.response.code === 200 && j.allowed === true) && pc < {FGA_POLL_CAP}) {{",
                "  pm.environment.set('_gmChkCount', String(pc + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_gmChkCount');",
                "pm.environment.unset('_gmChkStarted');",
                "pm.environment.unset('_gmChkSubj');",
                "pm.environment.unset('_gmChkObj');",
                "pm.test('group member gains viewer access via the group-subject binding (Check allowed=true)', () => {",
                "  pm.expect(pm.response.code, JSON.stringify(j)).to.eql(200);",
                "  pm.expect(j.allowed, JSON.stringify(j)).to.eql(true);",
                "});",
            ],
        ),
        teardown_delete("gmGrantAcbId"),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-EXPAND-UNAUTH: ExpandAccess unauthenticated → 401/403
# (viewer-tier authz; anonymous fail-closed). No setup needed — the gate rejects
# before any expansion runs.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-EXPAND-UNAUTH",
    title="ExpandAccess unauthenticated → 401/403 (viewer-tier, anonymous fail-closed)",
    classes=["RBAC", "RULES", "SUBJECTS", "EXPAND", "AUTHZ", "NEGATIVE"],
    priority="P1",
    steps=[
        # verifies (unauth → 401/403)
        Step(
            name="expand-access-anon",
            method="GET",
            path="/iam/v1/accessBindings:expandAccess?objectType=account&objectId={{accountAId}}&relation=viewer",
            auth="anonymous",
            test_script=[
                "pm.test('unauthenticated ExpandAccess → 401/403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([401, 403]));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-EXPAND-FOREIGN-DENIED: a caller
# who is AUTHENTICATED but holds NO grant-authority on the target object's scope
# must be DENIED (403) — ExpandAccess used to gate only the anon-floor, letting
# ANY authenticated principal expand "who can do X" on a FOREIGN object (leaking
# the authz topology + group membership). The account-B admin has full authority
# on account B but none on account A, so expanding account A's object → 403.
# read==enforce: you may expand only objects you are authorized to administer.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-EXPAND-FOREIGN-DENIED",
    title="ExpandAccess on a FOREIGN object (caller lacks grant-authority on the scope) → 403 PERMISSION_DENIED (no effective-principal leak)",
    classes=["RBAC", "RULES", "SUBJECTS", "EXPAND", "AUTHZ", "SECURITY", "NEGATIVE"],
    priority="P0",
    steps=[
        # verifies (per-object authz on ExpandAccess; foreign object → denied)
        Step(
            name="expand-access-foreign-object",
            method="GET",
            # account-B admin tries to expand account A's object → no authority on A.
            path="/iam/v1/accessBindings:expandAccess?objectType=account&objectId={{accountAId}}&relation=viewer",
            auth="jwtAccountAdminB",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('ExpandAccess on a foreign object → 403', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(403));",
                "pm.test('error code PERMISSION_DENIED (7)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(7));",
                "pm.test('no effective principals leaked on denial', () => {",
                "  pm.expect(j.principals === undefined || (Array.isArray(j.principals) && j.principals.length === 0), JSON.stringify(j)).to.be.true;",
                "});",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# RBACSUBJ-EXPAND-VAL-RELATION: an unknown
# relation string must be rejected sync with 400 INVALID_ARGUMENT (closed
# known-relation set: per-verb v_*, tier viewer/editor/admin, member). The
# authorized account-A admin probes account A with a bogus relation → 400, NOT a
# silent empty 200 / arbitrary-string FGA probe.
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="RBACSUBJ-EXPAND-VAL-RELATION",
    title="ExpandAccess with an unknown relation → 400 INVALID_ARGUMENT (closed known-relation set, no arbitrary FGA probe)",
    classes=["RBAC", "RULES", "SUBJECTS", "EXPAND", "VAL", "SECURITY", "NEGATIVE"],
    priority="P1",
    steps=[
        # verifies (relation closed-set validation)
        Step(
            name="expand-access-unknown-relation",
            method="GET",
            path="/iam/v1/accessBindings:expandAccess?objectType=account&objectId={{accountAId}}&relation=sg_compute_instance",
            auth="jwtAccountAdminA",
            test_script=[
                "const j = pm.response.json();",
                "pm.test('unknown relation → 400', () => pm.expect(pm.response.code, JSON.stringify(j)).to.eql(400));",
                "pm.test('error code INVALID_ARGUMENT (3)', () => pm.expect(j.code, JSON.stringify(j)).to.eql(3));",
            ],
        ),
    ],
))
