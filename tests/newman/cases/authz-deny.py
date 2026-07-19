# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""Case-set authz-deny для kacho-iam.

Проверяет default-deny matrix для 6 субъектов на Account/Project/Group/SA/AB/User/Role,
плюс UserService.Invite (CanInviteUsers) и UserService.List scope-filter.

Семантика:
  - DENY  → 403 + grpc 7 + "permission denied" (ANON без токена → 401 + grpc 16)
  - ALLOW → != 403
  - EMPTY → 200 + body.<list>.length === 0 (scope-filter List: User / ServiceAccount /
            Project / Group возвращают 200 c пустым списком для non-member, никогда 403 —
            все 5 account-scoped IAM List унифицированы в <exempt>)

Pre-conditions: `tests/authz-fixtures/setup.sh`. Env-var'ы те же что у vpc/compute.

The ALLOW cases for INV (invitee→admin@account-B) and PA1 (proj-adm→edit@project-A1)
require a system-role grant on an account/project scope to emit FGA tier-tuples.
emitAnchorRule materializes a wildcard *.* anchor rule as a tier-tuple on the bare
account/project/cluster object (the permissions-path grant), so the fixture
viewer/editor tuple lands in OpenFGA and the ALLOW assertions pass.
"""

CASES = []

# System role ids — source of truth = migration 0008_role_catalog_kac122.sql,
# which DELETEs the legacy `rol00000000000000<tail>` roles (migration 0001) and
# re-seeds the catalog with deterministic ids `rol` + substr(md5(<name>),1,17).
# An AccessBinding.Create / Invite with a non-existent role_id fails the worker
# `FAILED_PRECONDITION Role <id> not found` (FK access_bindings_role_fk) — so
# these tests MUST reference the post-0008 ids.
ROLE_ADMIN = "rol21232f297a57a5a74"   # md5('admin')[:17] — global super-admin
ROLE_VIEW  = "rol1bda80f2be4d3658e"   # md5('view')[:17]  — global read-only

SUBJECTS = [
    ("ANON", "anon",       "anonymous"),
    ("NOB",  "no-bind",    "jwtNoBindings"),
    ("PA1",  "proj-adm",   "jwtProjectAdminA1"),
    ("AAA",  "acct-adm-a", "jwtAccountAdminA"),
    ("AAB",  "acct-adm-b", "jwtAccountAdminB"),
    ("INV",  "invitee",    "jwtInvitee"),
]

EXPECT = {
    "account-A":              {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"},
    "account-B":              {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    "project-A1":             {"ANON":"DENY","NOB":"DENY","PA1":"ALLOW","AAA":"ALLOW","AAB":"DENY","INV":"ALLOW"},
    "project-B1":             {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    "catalog-read":           {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    "cluster-role-mutate":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    "invite-to-account-A":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"},
    "invite-to-account-B":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"},
    # User.List is a scope-filter RPC (exempt at the gateway). The
    # kacho-iam handler returns 200 with only the Users of Accounts where the
    # principal is a member — EMPTY (200, zero users) when the caller is not a
    # member of the requested Account; never 403. Anonymous → DENY (IAM
    # anti-anonymous interceptor). So a non-member account-admin (e.g. AAB on
    # account-A) gets EMPTY, not PERMISSION_DENIED.
    "user-list-account-A":    {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "user-list-account-B":    {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # ServiceAccount.List is a scope-filter RPC (exempt at the
    # gateway, like User.List). The kacho-iam handler returns 200
    # with only the ServiceAccounts of Accounts where the principal is a
    # member — EMPTY (200, zero serviceAccounts) for a non-member; never 403.
    # Membership semantics are identical to user-list-account-*.
    "sa-list-account-A":      {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "sa-list-account-B":      {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # Project/Group List are in the scope-filter family (List = <exempt>):
    # non-member → 200 + empty, never 403; ANON → 401. Membership truth
    # from tests/authz-fixtures/setup.sh (PA1=editor@project-A1[in A]; AAA=admin@account-A;
    # AAB=admin@account-B; INV=admin@account-B + editor@project-A1[in A]; NOB=nothing):
    #   ProjectService.List filters owner-via-account ∪ viewer ∪ v_list on `project`:
    #     acc-A → PA1/INV see project-A1 (editor⊇viewer), AAA owns A → ALLOW; NOB/AAB → EMPTY.
    #     acc-B → AAB owns B, INV admin@B → ALLOW; NOB/PA1/AAA → EMPTY (no acc-B project grant).
    #   GroupService.List filters viewer ∪ v_list on `iam_group` (account-tier admin cascades;
    #   project-editor does NOT cascade to groups):
    #     acc-A → AAA (account-admin) → ALLOW; NOB/PA1/AAB → EMPTY. INV kept ALLOW (lenient
    #       non-403) so the by-label visibility suite granting INV a transient acc-A group
    #       v_list cannot flake a strict-empty assert.
    #     acc-B → AAB/INV (account-admin@B) → ALLOW; NOB/PA1/AAA → EMPTY.
    "prj-list-account-A":     {"ANON":"DENY","NOB":"EMPTY","PA1":"ALLOW","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "prj-list-account-B":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    "grp-list-account-A":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"ALLOW","AAB":"EMPTY","INV":"ALLOW"},
    "grp-list-account-B":     {"ANON":"DENY","NOB":"EMPTY","PA1":"EMPTY","AAA":"EMPTY","AAB":"ALLOW","INV":"ALLOW"},
    # AccountService.List — top-level scope-filter RPC (exempt at the
    # gateway, default-deny via the handler returning 200 with only the
    # caller's member-Accounts). Every authenticated subject gets a non-403.
    "account-list":           {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    # User.List WITHOUT accountId is a scope-filter RPC — the
    # kacho-iam handler returns 200 with only the Users of Accounts the
    # principal is a member of (its own user at minimum). Returning the
    # caller's own user is not a data leak. Every authenticated subject → ALLOW
    # (non-403, non-empty); anonymous → DENY.
    "user-list-unqualified":  {"ANON":"DENY","NOB":"ALLOW","PA1":"ALLOW","AAA":"ALLOW","AAB":"ALLOW","INV":"ALLOW"},
    # a per-resource-gated Get/Delete on a NON-EXISTENT id is
    # `no path` for EVERY subject — the FGA cascade has no parent-pointer tuple
    # for an object that never existed, so the Check cannot resolve regardless
    # of the caller's account/project role. DENY for all (the request never
    # reaches the repo to return 404).
    "garbage-perresource":    {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    # UserService.Get of a specific user — only that user
    # themselves resolves (`iam_user.viewer` includes `subject`); each base
    # test-user owns their own home account so no cross-user admin path exists.
    "user-get-nob":           {"ANON":"DENY","NOB":"ALLOW","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"},
    "user-get-inv":           {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"ALLOW"},
}


def deny_asserts(case_id):
    return [
        f"pm.test('[{case_id}] DENY: status 403', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(403));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] DENY: grpc code 7 (PERMISSION_DENIED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(7));",
        f"pm.test('[{case_id}] DENY: message contains permission denied', () => pm.expect((j && j.message || '').toLowerCase()).to.contain('permission denied'));",
    ]


def _is_single_resource_get(path):
    # A single-resource Get targets one object: the path's last segment is a
    # concrete id — a `{{var}}` placeholder or a literal resource id (3-char prefix
    # + ≥17 chars) — with NO query string. A List (collection) carries a ?query
    # (e.g. ?accountId=…) or ends in the bare plural (`/accounts`); those are NOT
    # single reads and a denied List stays PermissionDenied (403), not hidden as 404.
    if "?" in path:
        return False
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if last.startswith("{{") and last.endswith("}}"):
        return True
    # Literal resource id: 3-char alpha prefix + ≥17 trailing chars (matches the
    # GARBAGE_* / id format), distinguishing it from the bare plural collection name.
    return len(last) >= 20 and last[:3].isalpha() and last[3:].isalnum()


def read_deny_asserts(case_id):
    # BUG-2 hide-existence: a denied single-resource read (Get) on a verb-bearing
    # IAM resource is surfaced as NotFound (404 / code 5), never PermissionDenied —
    # no enumeration / existence leak. Applies to authenticated-but-denied AND to a
    # denied read of a (well-formed) nonexistent id — both yield the same 404, so an
    # attacker cannot tell "exists but forbidden" from "does not exist".
    return [
        f"pm.test('[{case_id}] READ-DENY: status 404 (hide existence)', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(404));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] READ-DENY: grpc code 5 (NOT_FOUND, not 7)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(5));",
        f"pm.test('[{case_id}] READ-DENY: no deny_reasons leak', () => pm.expect(JSON.stringify(j || {{}}).toLowerCase()).to.not.include('deny_reasons'));",
    ]


def unauth_asserts(case_id):
    # BUG-2: anonymous (no credentials) → 401 + code 16 (UNAUTHENTICATED),
    # not 403 + code 7 (PERMISSION_DENIED).
    # gRPC/HTTP convention: missing credentials → UNAUTHENTICATED (16) → HTTP 401;
    # authenticated-but-denied → PERMISSION_DENIED (7) → HTTP 403.
    return [
        f"pm.test('[{case_id}] UNAUTH: status 401', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(401));",
        "let j; try { j = pm.response.json(); } catch(e) { j = null; }",
        f"pm.test('[{case_id}] UNAUTH: grpc code 16 (UNAUTHENTICATED)', () => pm.expect(j && j.code, JSON.stringify(j)).to.equal(16));",
    ]


def allow_asserts(case_id):
    return [
        f"pm.test('[{case_id}] ALLOW: not 403', () => pm.expect(pm.response.code, 'unexpected 403: ' + pm.response.text()).to.not.equal(403));",
        "let _j; try { _j = pm.response.json(); } catch(e) { _j = null; }",
        f"pm.test('[{case_id}] ALLOW: not Unauthenticated (16)', () => pm.expect(_j && _j.code, JSON.stringify(_j)).to.not.equal(16));",
    ]


def empty_asserts(case_id, list_key="users"):
    # list_key — the JSON array field of the List response to assert empty on
    # (`users` for User.List, `serviceAccounts` for ServiceAccount.List, ...).
    return [
        f"pm.test('[{case_id}] EMPTY: status 200', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.equal(200));",
        "const body = pm.response.json();",
        f"pm.test('[{case_id}] EMPTY: zero {list_key} (scope-filter default-deny)', "
        f"() => pm.expect((body && body.{list_key} || []).length).to.equal(0));",
    ]


def reject_asserts(case_id):
    # BUG-3: AccountService.Create enforces RequireOwnerMatchesPrincipal
    # which returns code 3 (INVALID_ARGUMENT / 400) when ownerUserId != principal,
    # not code 7 (PERMISSION_DENIED / 403). Both are valid denial responses:
    # code 3 = "your request is malformed — you cannot set a foreign ownerUserId";
    # code 7 = "you don't have permission". Security-wise both reject the hijack.
    # This assert accepts either code 3 (400) or code 7 (403).
    return [
        f"let rj; try {{ rj = pm.response.json(); }} catch(e) {{ rj = null; }}",
        f"pm.test('[{case_id}] REJECT: status 400 or 403', () => "
        f"pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.be.oneOf([400, 403]));",
        f"pm.test('[{case_id}] REJECT: grpc code 3 or 7', () => "
        f"pm.expect(rj && rj.code, JSON.stringify(rj)).to.be.oneOf([3, 7]));",
    ]


def emit(case_id_prefix, title, scope, method, path, body, subject, empty_list_key="users"):
    code, label, auth = subject
    decision = EXPECT[scope][code]
    case_id = f"AUTHZ-{case_id_prefix}-{code}"
    if decision == "DENY":
        # BUG-2: ANON subject uses "anonymous" auth (no credentials sent).
        # Missing credentials → UNAUTHENTICATED(16)/401, not PERMISSION_DENIED(7)/403.
        # Authenticated subjects that are denied still use deny_asserts (7/403).
        if code == "ANON":
            asserts = unauth_asserts(case_id)
        elif scope == "esc-account-hijack":
            # BUG-3: Account.Create with mismatched ownerUserId returns
            # code 3 (INVALID_ARGUMENT / 400) via RequireOwnerMatchesPrincipal,
            # not code 7 (PERMISSION_DENIED / 403). Both are valid denial responses.
            asserts = reject_asserts(case_id)
        elif method == "GET" and _is_single_resource_get(path):
            # BUG-2 hide-existence: a denied single-resource read (Get) on a
            # verb-bearing IAM resource → NotFound (404 / code 5), not 403. ONLY a
            # single-resource Get (path ends in /{{id}}, no ?query) hides existence;
            # a denied List (e.g. /projects?accountId=…) stays PermissionDenied (403)
            # — a collection has no single object whose existence to hide. The
            # garbage-id single-Get probe denied for all subjects also surfaces as 404
            # (denied nonexistent == existing-denied → no enumeration leak).
            asserts = read_deny_asserts(case_id)
        else:
            asserts = deny_asserts(case_id)
    elif decision == "ALLOW":
        asserts = allow_asserts(case_id)
    elif decision == "EMPTY":
        asserts = empty_asserts(case_id, empty_list_key)
    else:
        raise ValueError(f"unknown decision {decision} for {case_id}")
    cls = ["AUTHZ"]
    if decision == "DENY":      cls.append("NEG")
    elif decision == "ALLOW":   cls.append("POS")
    elif decision == "EMPTY":   cls.append("SCOPE")
    CASES.append(Case(
        id=case_id,
        title=f"[{decision}] {title} as {label} ({scope})",
        classes=cls,
        priority="P1",
        steps=[Step(name=method.lower(), method=method, path=path, body=body, auth=auth, test_script=asserts)],
    ))


GARBAGE_ACCT = "accnonexistent000001"
GARBAGE_PROJ = "prjnonexistent000001"
GARBAGE_GRP  = "grpnonexistent000001"
GARBAGE_SA   = "svanonexistent000001"
GARBAGE_AB   = "acbnonexistent000001"
GARBAGE_USER = "usrnonexistent000001"
GARBAGE_ROLE = "rolnonexistent000001"


# ---------------------------------------------------------------------------
# Account (CRUD) — own A vs cross B
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # Create (any subject) — account-creation на стенде разрешено всем authenticated
    # (signup-flow), но для тестов intentionally probe whether DENY semantics work.
    # Decision for "account-create": same matrix as "account-A own" — only AAA expected ALLOW.
    # (Если стенд разрешает всем — это даст разные false-positives; задокументировано в matrix-doc.)
    emit("ACCT-GT-OWN", "Get account-A", "account-A",
         "GET", "/iam/v1/accounts/{{accountAId}}", None, subj)
    emit("ACCT-GT-CROSS", "Get account-B", "account-B",
         "GET", "/iam/v1/accounts/{{accountBId}}", None, subj)
    emit("ACCT-UP-OWN", "Update account-A", "account-A",
         "PATCH", "/iam/v1/accounts/{{accountAId}}", {"name": "x", "updateMask": "name"}, subj)
    emit("ACCT-UP-CROSS", "Update account-B", "account-B",
         "PATCH", "/iam/v1/accounts/{{accountBId}}", {"name": "x", "updateMask": "name"}, subj)
    # garbage-id Delete is per-resource-gated on a non-existent
    # `account:<garbage>` object → `no path` → 403 for every subject (never
    # reaches the repo). See garbage-perresource note in define_account_scoped.
    emit("ACCT-DL-OWN", "Delete account (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/accounts/{GARBAGE_ACCT}", None, subj)
    emit("ACCT-LS", "List accounts (scope-filter)", "account-list",
         "GET", "/iam/v1/accounts", None, subj)


# ---------------------------------------------------------------------------
# Project (CRUD) — A1 (own), A2 (same-account-cross-project), B1 (cross-account)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # Create в account-A
    emit("PRJ-CR-A", "Create project в account-A", "account-A",
         "POST", "/iam/v1/projects",
         {"accountId": "{{accountAId}}", "name": f"authz-prj-{subj[0].lower()}-{{{{runId}}}}"}, subj)
    # Create в account-B
    emit("PRJ-CR-B", "Create project в account-B", "account-B",
         "POST", "/iam/v1/projects",
         {"accountId": "{{accountBId}}", "name": f"authz-prj-{subj[0].lower()}-{{{{runId}}}}"}, subj)
    # Get project A1
    emit("PRJ-GT-A1", "Get project-A1", "project-A1",
         "GET", "/iam/v1/projects/{{projectA1Id}}", None, subj)
    # Get project B1
    emit("PRJ-GT-B1", "Get project-B1", "project-B1",
         "GET", "/iam/v1/projects/{{projectB1Id}}", None, subj)
    # Update project A1
    emit("PRJ-UP-A1", "Update project-A1", "project-A1",
         "PATCH", "/iam/v1/projects/{{projectA1Id}}",
         {"description": "x", "updateMask": "description"}, subj)
    # Update project B1
    emit("PRJ-UP-B1", "Update project-B1", "project-B1",
         "PATCH", "/iam/v1/projects/{{projectB1Id}}",
         {"description": "x", "updateMask": "description"}, subj)
    # garbage-id Delete — per-resource-gated on a non-existent
    # `project:<garbage>` → `no path` → 403 for all subjects.
    emit("PRJ-DL-A", "Delete project (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/projects/{GARBAGE_PROJ}", None, subj)
    # List projects ?accountId — scope-filter RPC (List = <exempt>):
    # non-member → 200 + empty `projects`, never 403.
    emit("PRJ-LS-A", "List projects ?accountId=A", "prj-list-account-A",
         "GET", "/iam/v1/projects?accountId={{accountAId}}", None, subj,
         empty_list_key="projects")
    emit("PRJ-LS-B", "List projects ?accountId=B", "prj-list-account-B",
         "GET", "/iam/v1/projects?accountId={{accountBId}}", None, subj,
         empty_list_key="projects")


# ---------------------------------------------------------------------------
# Group / ServiceAccount / AccessBinding — account-scoped, single set of cases per
# ---------------------------------------------------------------------------

def define_account_scoped(prefix_short, plural, body_template_a, body_template_b,
                          garbage_id, with_list=True,
                          list_scope_a="account-A", list_scope_b="account-B",
                          list_key="users"):
    # with_list=False — ресурс не имеет account-scoped плоского List RPC
    # (AccessBindingService экспонирует только
    # Get/Create/Delete/ListByScope/ListBySubject — `GET /iam/v1/accessBindings`
    # это catalog-miss, fail-closed 403, не valid default-deny scenario).
    #
    # list_scope_a / list_scope_b — the EXPECT scope-keys used for the LIST
    # sub-cases (separate from Get/Create/Delete which stay account-A/B). A
    # scope-filter List RPC (ServiceAccount.List) uses a
    # scope-filter scope (`sa-list-account-*`, EMPTY for non-members) rather
    # than the hard-deny `account-*` scope. list_key — the List response array
    # field asserted empty on EMPTY decisions.
    for subj in SUBJECTS:
        emit(f"{prefix_short}-CR-A", f"Create {prefix_short} в account-A", "account-A",
             "POST", f"/iam/v1/{plural}", body_template_a(subj), subj)
        emit(f"{prefix_short}-CR-B", f"Create {prefix_short} в account-B", "account-B",
             "POST", f"/iam/v1/{plural}", body_template_b(subj), subj)
        # a per-resource-gated Get/Delete on a NON-EXISTENT id is
        # always `no path` → 403 — the gateway extracts the scope object
        # `iam_<res>:<garbage-id>` and the FGA cascade has no parent-pointer
        # tuple (the object never existed). This holds for EVERY subject,
        # including the account-admin: there is no way to authorise a Check
        # against an object with no tuples. So the garbage-id probe is DENY for
        # all (it never reaches the repo to 404).
        emit(f"{prefix_short}-GT-A", f"Get {prefix_short} (garbage id — no FGA path)",
             "garbage-perresource", "GET", f"/iam/v1/{plural}/{garbage_id}", None, subj)
        if with_list:
            emit(f"{prefix_short}-LS-A", f"List {plural} ?accountId=A", list_scope_a,
                 "GET", f"/iam/v1/{plural}?accountId={{{{accountAId}}}}", None, subj,
                 empty_list_key=list_key)
            emit(f"{prefix_short}-LS-B", f"List {plural} ?accountId=B", list_scope_b,
                 "GET", f"/iam/v1/{plural}?accountId={{{{accountBId}}}}", None, subj,
                 empty_list_key=list_key)
        emit(f"{prefix_short}-DL-A", f"Delete {prefix_short} (garbage id — no FGA path)",
             "garbage-perresource", "DELETE", f"/iam/v1/{plural}/{garbage_id}", None, subj)


define_account_scoped(
    "GRP", "groups",
    lambda s: {"accountId": "{{accountAId}}", "name": f"authz-grp-{s[0].lower()}-{{{{runId}}}}"},
    lambda s: {"accountId": "{{accountBId}}", "name": f"authz-grp-{s[0].lower()}-{{{{runId}}}}"},
    GARBAGE_GRP,
    # GroupService.List is <exempt> — non-members get
    # 200 + empty `groups`, never 403. Create/Get/Delete stay hard-deny (account-A/B); only
    # the LIST sub-cases switch to the scope-filter scope (parity with serviceAccounts).
    list_scope_a="grp-list-account-A", list_scope_b="grp-list-account-B",
    list_key="groups",
)
define_account_scoped(
    "SA", "serviceAccounts",
    lambda s: {"accountId": "{{accountAId}}", "name": f"authz-sa-{s[0].lower()}-{{{{runId}}}}"},
    lambda s: {"accountId": "{{accountBId}}", "name": f"authz-sa-{s[0].lower()}-{{{{runId}}}}"},
    GARBAGE_SA,
    # ServiceAccount.List is a scope-filter RPC — non-members get
    # 200 + empty `serviceAccounts`, not 403. Create/Get/Delete stay hard-deny
    # (account-A/B). Only the LIST sub-cases switch to the scope-filter scope.
    list_scope_a="sa-list-account-A", list_scope_b="sa-list-account-B",
    list_key="serviceAccounts",
)
define_account_scoped(
    "AB", "accessBindings",
    lambda s: {"subjectType":"user","subjectId":"{{userNOBId}}","roleId":ROLE_VIEW,"resourceType":"account","resourceId":"{{accountAId}}"},
    lambda s: {"subjectType":"user","subjectId":"{{userNOBId}}","roleId":ROLE_VIEW,"resourceType":"account","resourceId":"{{accountBId}}"},
    GARBAGE_AB,
    with_list=False,  # AccessBindingService has no plain account-scoped List RPC.
)

# ---------------------------------------------------------------------------
# Non-member → Project & Group List → 200 + empty (was 403).
# verifies: a non-member gets 200 + empty (not 403) on Project & Group List.
#
# До unify Project/Group.List несли gateway call-gate `account:<id>#v_list`
# (+ required_acr_min=2). Non-member без этого якоря получал 403 PERMISSION_DENIED.
# Теперь List = <exempt>, единственный гейт — in-handler `viewer ∪ v_list`
# фильтр → 200 + пустой массив (existence не раскрывается кодом ошибки; паритет с
# ServiceAccount/User List). jwtNoBindings — субъект без единого гранта, гарантированно
# non-member на оба аккаунта → детерминированно пустой List (immune к pollution).
# ---------------------------------------------------------------------------
CASES.append(Case(
    id="AUTHZ-ULG04-NONMEMBER-PRJGRP-LIST-EMPTY",
    title="non-member (jwtNoBindings) → Project & Group List → 200 + empty (was 403 pre-unify call-gate)",
    classes=["AUTHZ", "SCOPE", "NEG", "RBAC"],
    priority="P1",
    steps=[
        Step(name="prj-list-nonmember-empty", method="GET",
             path="/iam/v1/projects?accountId={{accountAId}}", auth="jwtNoBindings",
             test_script=empty_asserts("ULG04-PRJ", "projects")),
        Step(name="grp-list-nonmember-empty", method="GET",
             path="/iam/v1/groups?accountId={{accountAId}}", auth="jwtNoBindings",
             test_script=empty_asserts("ULG04-GRP", "groups")),
    ],
))


# Fixture-pollution fix — NOB tuple teardown after AB-CR ALLOW cases.
#
# The AB-CR cases that succeed (ALLOW) grant NOB a `viewer` FGA tuple on the
# target account.  Those tuples are written inside the async Operation worker and
# persist in OpenFGA across newman runs (OpenFGA is backed by PostgreSQL, not an
# in-memory store).  On the next run the matrix still expects NOB → DENY on those
# accounts, but OpenFGA sees the lingering tuple and returns ALLOW, causing 24
# assertion failures across ACCT-GT, PRJ-GT, PRJ-LS, GRP-LS sub-cases.
#
# Fix: after each ALLOW AccessBinding.Create (AB-CR-A-AAA, AB-CR-B-AAB,
# AB-CR-B-INV), append three clean-up steps to the Case:
#   1. poll-op  — wait for the Create Operation to complete; extract abId.
#   2. delete-ab — DELETE /accessBindings/{abId} (authorised as the same
#                  subject that created it, so the authz gate passes).
#   3. poll-op-del — wait for the Delete Operation to complete (fire-and-forget
#                    style: we accept any `done` state; failure here is logged
#                    but does not mask the original ALLOW assertion).
#
# The three teardown steps are appended (not prepended) so the original single-
# step ALLOW assertion fires first — test semantics are unchanged.
#
# Subject → auth-var mapping (same as SUBJECTS list above):
#   AAA → jwtAccountAdminA
#   AAB → jwtAccountAdminB
#   INV → jwtInvitee

_AB_CR_ALLOW_AUTH = {
    "AUTHZ-AB-CR-A-AAA": "jwtAccountAdminA",
    "AUTHZ-AB-CR-B-AAB": "jwtAccountAdminB",
    "AUTHZ-AB-CR-B-INV": "jwtInvitee",
}

# GARBAGE_AB — a well-formed-but-nonexistent acb id used as the teardown DELETE
# fallback so an UNRESOLVED teardown id never reaches the gateway as a literal
# `{{...}}` template (a 400 InvalidArgument masquerading as a teardown failure).
# A DELETE on this id is a clean 404/403 — the expected "nothing to clean up".
_AB_TEARDOWN_FALLBACK = GARBAGE_AB

for _case in CASES:
    if _case.id not in _AB_CR_ALLOW_AUTH:
        continue
    _auth = _AB_CR_ALLOW_AUTH[_case.id]
    # Per-case-unique step names + env vars.
    #
    # The teardown steps used to share the names `poll-op-create` / `delete-ab-
    # teardown` / `poll-op-delete` and the env vars `_abTeardownOpId` /
    # `_abTeardownId` across ALL three AB-CR ALLOW cases. That caused two real,
    # NON-product flakes under CI load (verified in the flat-umbrella newman logs):
    #   1. setNextRequest(pm.info.requestName) re-runs the named request, but with a
    #      name shared across cases newman could re-enter the *wrong* case's poll —
    #      and worse, the prior case's self-re-poll jumped straight into the NEXT
    #      case's poll step, SKIPPING that case's create POST entirely. The next
    #      case then never saved its own op id and polled the PRIOR case's op as a
    #      DIFFERENT principal → 404 (Operation.Get is principal-scoped, anti-leak),
    #      exhausting the poll without resolving the teardown id.
    #   2. With the teardown id unresolved, the DELETE pre-script guard
    #      `setNextRequest(null)` does NOT skip the current request (it only sets the
    #      NEXT one), so the DELETE fired with a literal `{{_abTeardownId}}` URL →
    #      400 InvalidArgument → the `[teardown] 200 or 404` assert failed.
    # Fix (test-side, harness-only): unique per-case names so setNextRequest re-enters
    # the correct step and never bypasses a create; per-case env vars reset on the
    # create step so no stale op id bleeds in; and an unresolved teardown id falls
    # back to a well-formed garbage acb (clean 404), never a literal template (400).
    _cid = _case.id.replace("-", "_")
    _opvar = f"_abTeardownOpId_{_cid}"
    _idvar = f"_abTeardownId_{_cid}"
    _delopvar = f"_abDelOpId_{_cid}"
    _pollName = f"poll-op-create-{_case.id}"
    _delName = f"delete-ab-teardown"  # asserted by name in the green-gate; kept stable
    _delPollName = f"poll-op-delete-{_case.id}"
    # Step 1: the existing single step already has the POST and ALLOW asserts.
    # Reset the per-case teardown vars, then save THIS create's Operation id.
    _case.steps[0].test_script = list(_case.steps[0].test_script) + [
        f"pm.environment.unset('{_opvar}'); pm.environment.unset('{_idvar}'); pm.environment.unset('{_delopvar}');",
        # Save the Operation id returned by THIS case's Create RPC for teardown polling.
        f"try {{ const _op = pm.response.json(); if (_op && _op.id) pm.environment.set('{_opvar}', _op.id); }} catch(e) {{}}",
    ]
    # Step 2: poll until THIS case's Create Operation is done and extract abId.
    # A persistent 404 here means the op was never saved (create dup / response shape)
    # — bounded by POLL_CAP, it falls through leaving the teardown id unresolved, and
    # the DELETE below uses the garbage fallback (clean 404). No foreign-op polling.
    _case.steps.append(Step(
        name=_pollName,
        method="GET",
        path="/operations/{{" + _opvar + "}}",
        auth=_auth,
        pre_script=[
            # Skip the poll entirely if THIS case saved no op id (jump to delete).
            f"if (!pm.environment.get('{_opvar}')) {{ pm.execution.setNextRequest('{_delName}'); }}",
        ],
        test_script=[
            # First-entry reset (request-name-scoped flag) — keeps the iteration
            # count immune to cross-case bleed.
            "if (pm.environment.get('_abPollStarted') !== pm.info.requestName) { pm.environment.set('_abPollCount', '0'); pm.environment.set('_abPollStarted', pm.info.requestName); }",
            "const _pc = parseInt(pm.environment.get('_abPollCount') || '0', 10);",
            "let _j; try { _j = pm.response.json(); } catch(e) { _j = {}; }",
            # 404 (op not yet visible) or !done → retry within the cap. A non-converging
            # 404 (foreign/never-persisted op) falls through and resolves no id.
            f"if ((pm.response.code === 404 || !_j.done) && _pc < {POLL_CAP}) {{",
            "  pm.environment.set('_abPollCount', String(_pc + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_abPollCount');",
            "pm.environment.unset('_abPollStarted');",
            # Extract abId from Operation metadata for teardown.
            "try {",
            "  const _meta = _j.metadata || {};",
            "  const _abId = _meta.accessBindingId || _meta['@value'] && _meta['@value'].accessBindingId || '';",
            f"  if (_abId) pm.environment.set('{_idvar}', _abId);",
            "} catch(e) {}",
        ],
    ))
    # Step 3: DELETE the binding (teardown). Best-effort cleanup so re-runs don't
    # trip the strict-create active-grant UNIQUE. If THIS case's teardown id is
    # unresolved, target a well-formed garbage acb (clean 404) — never a literal
    # `{{...}}` template (which 400s). 200 (op returned) / 404 (gone) / 403 (no FGA
    # path on the garbage fallback) are all acceptable teardown outcomes.
    _case.steps.append(Step(
        name=_delName,
        method="DELETE",
        path="/iam/v1/accessBindings/{{_abTeardownDelId}}",
        auth=_auth,
        pre_script=[
            # Resolve the target: this case's id if present, else the garbage fallback
            # (a well-formed id that 404s — keeps the URL valid, no literal template).
            f"pm.environment.set('_abTeardownDelId', pm.environment.get('{_idvar}') || '{_AB_TEARDOWN_FALLBACK}');",
        ],
        test_script=[
            # Save delete Operation id for the follow-up poll (only on the real path).
            f"try {{ const _dop = pm.response.json(); if (_dop && _dop.id) pm.environment.set('{_delopvar}', _dop.id); }} catch(e) {{}}",
            # Teardown step: accept 200 (op returned), 404 (already gone / garbage
            # fallback), or 403 (no FGA path on the garbage fallback).
            "pm.test('[teardown] delete-ab: 200 or 404', () => pm.expect(pm.response.code).to.be.oneOf([200, 404, 403]));",
        ],
    ))
    # Step 4: poll THIS case's Delete Operation until done (best-effort cleanup).
    _case.steps.append(Step(
        name=_delPollName,
        method="GET",
        path="/operations/{{" + _delopvar + "}}",
        auth=_auth,
        pre_script=[
            f"if (!pm.environment.get('{_delopvar}')) {{ pm.execution.setNextRequest(null); }}",
        ],
        test_script=[
            # First-entry reset (request-name-scoped flag).
            "if (pm.environment.get('_abDelPollStarted') !== pm.info.requestName) { pm.environment.set('_abDelPollCount', '0'); pm.environment.set('_abDelPollStarted', pm.info.requestName); }",
            "const _dp = parseInt(pm.environment.get('_abDelPollCount') || '0', 10);",
            "let _dj; try { _dj = pm.response.json(); } catch(e) { _dj = {}; }",
            f"if (!_dj.done && _dp < {POLL_CAP}) {{",
            "  pm.environment.set('_abDelPollCount', String(_dp + 1));",
            "  const _pd = Date.now(); while (Date.now() - _pd < 500) { /* inter-poll delay ~500ms (Koren #1) */ }",
            "  pm.execution.setNextRequest(pm.info.requestName);",
            "  return;",
            "}",
            "pm.environment.unset('_abDelPollCount');",
            "pm.environment.unset('_abDelPollStarted');",
            f"pm.environment.unset('{_opvar}');",
            f"pm.environment.unset('{_idvar}');",
            f"pm.environment.unset('{_delopvar}');",
            "pm.environment.unset('_abTeardownDelId');",
        ],
    ))


# ---------------------------------------------------------------------------
# Role — cluster-scoped catalog (Get/List = catalog-read; Create/Update/Delete = cluster-role-mutate)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    emit("ROLE-LS", "List roles (catalog)", "catalog-read",
         "GET", "/iam/v1/roles", None, subj)
    emit("ROLE-GT", "Get role (catalog system role)", "catalog-read",
         "GET", f"/iam/v1/roles/{ROLE_VIEW}", None, subj)
    emit("ROLE-CR", "Create role (cluster admin)", "cluster-role-mutate",
         "POST", "/iam/v1/roles",
         {"name": f"authz-role-{subj[0].lower()}", "isSystem": False,
          "rules": [{"module": "iam", "resources": ["user"], "verbs": ["get"]}]}, subj)
    emit("ROLE-UP", "Update role (cluster admin)", "cluster-role-mutate",
         "PATCH", f"/iam/v1/roles/{GARBAGE_ROLE}", {"description":"x"}, subj)
    emit("ROLE-DL", "Delete role (cluster admin)", "cluster-role-mutate",
         "DELETE", f"/iam/v1/roles/{GARBAGE_ROLE}", None, subj)


# ---------------------------------------------------------------------------
# UserService.Invite (CanInviteUsers = Check editor on account)
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    emit("INV-A", "Invite user в account-A", "invite-to-account-A",
         "POST", "/iam/v1/users:invite",
         {"accountId":"{{accountAId}}","email": f"authz-invtarget-{subj[0].lower()}@example.com","roleId":ROLE_VIEW}, subj)
    emit("INV-B", "Invite user в account-B", "invite-to-account-B",
         "POST", "/iam/v1/users:invite",
         {"accountId":"{{accountBId}}","email": f"authz-invtarget-{subj[0].lower()}@example.com","roleId":ROLE_VIEW}, subj)


# ---------------------------------------------------------------------------
# UserService.Get / Update / Delete / List — scope-filter
# ---------------------------------------------------------------------------

for subj in SUBJECTS:
    # UserService.Get is per-resource-gated on `iam_user:<id>`.
    # The `iam_user.viewer` cascade is `subject or editor or viewer from
    # account` — i.e. the user themselves, or someone with viewer on the
    # user's HOME account. Each base test-user owns their own bootstrap
    # (home) account, so only the target user themselves can Get their own
    # record; no cross-user account-admin path exists (AAA is admin of
    # account-A, not of NOB's home account). USR-GT-A targets userNOB →
    # ALLOW only for NOB; USR-GT-B targets userINV → ALLOW only for INV.
    emit("USR-GT-A", "Get userNOB (self-viewable only)", "user-get-nob",
         "GET", "/iam/v1/users/{{userNOBId}}", None, subj)
    emit("USR-GT-B", "Get userINV (self-viewable only)", "user-get-inv",
         "GET", "/iam/v1/users/{{userINVId}}", None, subj)
    # List ?accountId — главный default-deny scope-filter case
    emit("USR-LS-A", "List users ?accountId=A", "user-list-account-A",
         "GET", "/iam/v1/users?accountId={{accountAId}}", None, subj)
    emit("USR-LS-B", "List users ?accountId=B", "user-list-account-B",
         "GET", "/iam/v1/users?accountId={{accountBId}}", None, subj)
    # garbage-id Delete — per-resource-gated on a non-existent
    # `iam_user:<garbage>` → `no path` → 403 for all subjects.
    emit("USR-DL-A", "Delete user (garbage id — no FGA path)", "garbage-perresource",
         "DELETE", f"/iam/v1/users/{GARBAGE_USER}", None, subj)


# ---------------------------------------------------------------------------
# Privilege escalation / Information disclosure / Isolation
# ---------------------------------------------------------------------------

# AccessBindingService.Create больше НЕ
# enforces identity-equality RequireSelfGrant. Grant-authority следует SCOPE
# гранта — caller обязан owner'ить owning Account ЛИБО держать FGA `admin` на
# scope. Account-owner, грантящий роль (в т.ч. iam.admin себе) в СВОЕМ account —
# allowed by design (он уже держит owner). Поэтому self-grant в собственном
# scope = ALLOW, в чужом = DENY. Зеркалит account-A / account-B матрицы.
EXPECT["esc-self-grant-A"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"}
EXPECT["esc-self-grant-B"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"ALLOW","INV":"ALLOW"}
# AccountService.Create enforces RequireOwnerMatchesPrincipal —
# ownerUserId обязан совпадать с caller'ом. Body фиксирует ownerUserId=AAA, так
# что для caller'а AAA это нормальное self-owned account creation (ALLOW); для
# любого другого subject — попытка назначить чужого owner'а (DENY = hijack).
EXPECT["esc-account-hijack"]   = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"}
# ESC-CUSTOM-ROLE creates a custom Role in account-A. Role.Create
# is gated `editor@account` — the account-A owner (AAA) holds it and may
# create custom roles in their own account (defining a role is not itself
# privilege escalation — the role only grants what an AccessBinding later
# assigns, and binding-grant authority is separately enforced). So AAA → ALLOW
# in their own account; every other subject → DENY.
EXPECT["esc-custom-role"]      = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"ALLOW","AAB":"DENY","INV":"DENY"}
EXPECT["iso-internal-rpc"]     = {"ANON":"DENY","NOB":"DENY","PA1":"DENY","AAA":"DENY","AAB":"DENY","INV":"DENY"}
# data-leak-user-list — removed in replaced by user-list-unqualified
# (scope-filter ALLOW, not DENY — returning the caller's own user is not a leak).

# ESC-1: каждый субъект пытается выдать СЕБЕ iam.admin. На своем account —
# ALLOW (Problem-3: owner grant-authority в своем scope); на чужом — DENY.
for subj in SUBJECTS:
    user_var = {
        "NOB": "{{userNOBId}}", "PA1": "{{userPA1Id}}",
        "AAA": "{{userAAAId}}", "AAB": "{{userAABId}}", "INV": "{{userINVId}}",
    }.get(subj[0], "{{userNOBId}}")  # для ANON хватает любого id — суть DENY на anon
    emit("ESC-SELF-ADMIN-A", "Self-grant iam.admin on account-A",
         "esc-self-grant-A", "POST", "/iam/v1/accessBindings",
         {"subjectType":"user","subjectId":user_var,"roleId":ROLE_ADMIN,
          "resourceType":"account","resourceId":"{{accountAId}}"}, subj)
    emit("ESC-SELF-ADMIN-B", "Self-grant iam.admin on account-B",
         "esc-self-grant-B", "POST", "/iam/v1/accessBindings",
         {"subjectType":"user","subjectId":user_var,"roleId":ROLE_ADMIN,
          "resourceType":"account","resourceId":"{{accountBId}}"}, subj)

# ESC-2: создание Account. Body фиксирует ownerUserId=AAA → для caller AAA это
# self-owned creation (ALLOW), для остальных — hijack (DENY).
for subj in SUBJECTS:
    emit("ESC-ACCT-HIJACK", "Create Account with ownerUserId=AAA",
         "esc-account-hijack", "POST", "/iam/v1/accounts",
         {"name": f"hack-{subj[0].lower()}", "description": "hijack", "ownerUserId": "{{userAAAId}}"}, subj)

# ESC-3: создание custom Role с broad (super-admin-shaped) rules (HIGH-3).
# RBAC rules model: the authored field is `rules`. A custom
# role canNOT use module/resource wildcard `*` (system-only → 400), so the
# legacy super-admin intent (iam.*.*.* / vpc.*.*.* / compute.*.*.*) is expressed
# as concrete resource lists with verb-wildcard `verbs:["*"]` (all verbs) across
# the three domains — still broad enough to make the escalation probe meaningful.
# role name must match ^[a-z][a-z0-9_]{0,40}$ — hyphen is invalid
# and would fail name-validation BEFORE authz, masking the authz check. Use a
# regex-valid underscore name so the request actually exercises authz.
for subj in SUBJECTS:
    emit("ESC-CUSTOM-ROLE", "Create custom Role with broad iam/vpc/compute rules (escalation prep)",
         "esc-custom-role", "POST", "/iam/v1/roles",
         {"accountId": "{{accountAId}}", "name": f"hack_role_{subj[0].lower()}",
          "rules": [
              {"module": "iam", "resources": ["user", "role", "account", "project"], "verbs": ["*"]},
              {"module": "vpc", "resources": ["network", "subnet", "securityGroup"], "verbs": ["*"]},
              {"module": "compute", "resources": ["instance", "disk"], "verbs": ["*"]},
          ]}, subj)

# HIGH-1: User.List unqualified (без accountId) — scope-filter RPC: 200 со
# списком только из member-Accounts caller'а (его собственный user как минимум).
# Возврат собственного user'а — не data leak. ALLOW, не DENY.
for subj in SUBJECTS:
    emit("DATA-LEAK-USR-LS", "User.List without accountId (scope-filter, returns own user)",
         "user-list-unqualified", "GET", "/iam/v1/users", None, subj)

# ISO-1..ISO-4: Internal RPC на external endpoint — должны 404 (но мы тестим
# на dev port 18080 который cluster-internal; этот класс для external TLS endpoint).
# Здесь — позитивный контроль что путь существует в principle.
# (Полноценный test против external endpoint — отдельная suite-variant.)


# ---------------------------------------------------------------------------
# AUTHZ-REVOKE-ENFORCED-A-INV push-drain end-to-end:
# AccessBinding revoke MUST de-authorise the subject within ~1s, not 30s.
#
# Pre-requires:
#   - iam emits subject_change_outbox on AccessBinding.Delete (writer-tx).
#   - iam push-drainer dials api-gateway internal listener and pushes
#     InvalidateSubject.
#   - api-gateway main.go wires the internal grpc listener so the drainer
#     can connect.
#
# Narrative (each step ~RTT-bound):
#   1. AAA grants jwtInvitee admin@account-A — fresh binding (different scope
#      than the setup.sh-baked INV→admin@account-B grant, so we can revoke it
#      cleanly without affecting INV's home account access).
#   2. Poll the create-Operation to done.
#   3. INV's first GET /iam/v1/accounts/{accountAId} → 200 (ALLOW + cache warm).
#   4. AAA DELETEs the binding (sync 200 + Operation).
#   5. Poll the delete-Operation to done.
#   6. Brief retry-on-ALLOW loop on INV's GET → expect 403 within a small
#      number of polls (≤8 ~= ≤1.6s @ 200ms). If still 200 the case fails:
#      either iam did not emit OR drainer did not push OR gateway did not
#      invalidate. (Without the push-drain wiring the gateway cache returns
#      ALLOW for ≤30s, the poll-loop fallback window.)
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="AUTHZ-REVOKE-ENFORCED-A-INV",
    title="push-drain enforces revoke→DENY within <2s (vs 30s poll-fallback)",
    classes=["AUTHZ", "FLOW", "PUSH_DRAIN"],
    priority="P0",
    steps=[
        # 1) AAA grants INV admin@account-A.
        Step(
            name="setup-grant-admin-to-inv",
            method="POST",
            path="/iam/v1/accessBindings",
            body={
                "subjectType": "user",
                "subjectId": "{{userINVId}}",
                "roleId": ROLE_ADMIN,
                "resourceType": "account",
                "resourceId": "{{accountAId}}",
            },
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('grant create accepted', () => pm.expect(pm.response.code).to.be.oneOf([200, 202]));",
                "const j = pm.response.json();",
                "if (j && j.id) pm.environment.set('opId', j.id);",
                "if (j && j.metadata && j.metadata.accessBindingId) {",
                "  pm.environment.set('w12RevokeBindingId', j.metadata.accessBindingId);",
                "}",
            ],
        ),
        # 2) Poll create-op to done; capture binding id from response if not in metadata.
        Step(
            name="poll-grant-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
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
                "pm.test('grant op done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('grant succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
                "if (j.response && j.response.id && !pm.environment.get('w12RevokeBindingId')) {",
                "  pm.environment.set('w12RevokeBindingId', j.response.id);",
                "}",
            ],
        ),
        # 3) INV's first GET → ALLOW (200) — populates the gateway's authz decision cache.
        #
        # AccessBinding.Create Operation done = iam DB commit done;
        # FGA tuple write happens async via the fga_outbox drainer. So a
        # single-shot GET right after the grant-binding poll-op can still see
        # 404 before the tuple lands. Wrap in a POLL_CAP-bounded retry,
        # symmetric to the post-revoke loop below at step 6.
        # Accept 200 as soon as the tuple is visible; fail with detail if
        # the budget is exhausted (drainer not functioning).
        Step(
            name="inv-get-account-allow-warm-cache",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtInvitee",
            test_script=[
                # First-entry reset (request-name-scoped flag).
                "if (pm.environment.get('_w12WarmStarted') !== pm.info.requestName) { pm.environment.set('_w12WarmPoll', '0'); pm.environment.set('_w12WarmStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_w12WarmPoll') || '0', 10);",
                f"if (pm.response.code !== 200 && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_w12WarmPoll', String(pc + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_w12WarmPoll');",
                "pm.environment.unset('_w12WarmStarted');",
                "pm.test('INV sees account-A (200) — cache warm within ~6s of grant', () => pm.expect(pm.response.code, JSON.stringify(pm.response.text())).to.eql(200));",
            ],
        ),
        # 4) AAA revokes the binding. iam emits subject_change_outbox row in the
        #    same writer-tx. The drainer pushes InvalidateSubject
        #    to api-gateway within ~1s.
        Step(
            name="revoke-binding",
            method="DELETE",
            path="/iam/v1/accessBindings/{{w12RevokeBindingId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('revoke accepted (200/202)', () => pm.expect(pm.response.code).to.be.oneOf([200, 202]));",
                "const j = pm.response.json();",
                "if (j && j.id) pm.environment.set('opId', j.id);",
            ],
        ),
        # 5) Poll the revoke-Operation to done — by the time the op is done the
        #    iam writer-tx (binding state-flip + subject_change_outbox INSERT)
        #    has committed. The drainer typically pushes InvalidateSubject within
        #    ~200-500ms of the commit (LISTEN/NOTIFY → claim → gRPC push).
        Step(
            name="poll-revoke-op",
            method="GET",
            path="/operations/{{opId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "pm.test('poll status 200', () => pm.expect(pm.response.code).to.eql(200));",
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
                "pm.test('revoke op done', () => pm.expect(j.done, JSON.stringify(j)).to.eql(true));",
                "pm.test('revoke succeeded (no error)', () => pm.expect(j.error, JSON.stringify(j)).to.not.exist);",
            ],
        ),
        # 6) INV's next GET — DENY within a poll budget. Retry-on-ALLOW
        #    loop bounded to POLL_CAP polls — well under the 30s
        #    WS-2.3 safety-net window. If still ALLOW after the budget, the
        #    push-drainer is NOT functioning (either iam side or gateway side).
        Step(
            name="inv-get-account-denied-post-revoke",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtInvitee",
            test_script=[
                # First-entry reset (request-name-scoped flag).
                "if (pm.environment.get('_w12PollStarted') !== pm.info.requestName) { pm.environment.set('_w12Poll', '0'); pm.environment.set('_w12PollStarted', pm.info.requestName); }",
                "const pc = parseInt(pm.environment.get('_w12Poll') || '0', 10);",
                f"if (pm.response.code === 200 && pc < {POLL_CAP}) {{",
                "  pm.environment.set('_w12Poll', String(pc + 1));",
                "  pm.execution.setNextRequest(pm.info.requestName);",
                "  return;",
                "}",
                "pm.environment.unset('_w12Poll');",
                "pm.environment.unset('_w12PollStarted');",
                # BUG-2 hide-existence: a verb-bearing IAM read-deny is surfaced as
                # NotFound (404 / code 5), never PermissionDenied — no enumeration leak.
                "pm.test('INV denied within ~2s of revoke (404 hide-existence)', () => {",
                "  pm.expect(pm.response.code, 'expected 404 post-revoke; got ' + pm.response.code + ' ' + pm.response.text()).to.equal(404);",
                "});",
                "let jj; try { jj = pm.response.json(); } catch(e) { jj = null; }",
                "pm.test('INV post-revoke: no deny_reasons leak', () => pm.expect(JSON.stringify(jj || {}).toLowerCase()).to.not.include('deny_reasons'));",
            ],
        ),
    ],
))


# ---------------------------------------------------------------------------
# gateway authz-middleware MUST fail-closed on OpenFGA outage.
#
# Pre-condition: the api-gateway is deployed with `authz.enabled=true,
# authz.failOpen=false` (prod-parity overlay) AND the OpenFGA deployment has
# been scaled to 0 replicas BEFORE this case runs (so the IAM AuthorizeService
# Check call fails → middleware enters outcomeError → fail-closed → 503).
#
# Orchestration of `kubectl scale deployment kacho-openfga --replicas=0/=1`
# lives OUTSIDE this case — it is the responsibility of a wrapper script
# (`tests/newman/scripts/run-failclosed.sh`) or CI step that drives the case.
# Without that orchestration the case is RED (OpenFGA is up → request returns
# 200 → assert fails). This is intentional: the case documents the contract;
# the deploy harness wires the outage.
#
# Known-RED (the newman-e2e harness does NOT scale OpenFGA to 0):
# this case is whitelisted as known-RED in newman-e2e.yml (step name
# `any-authz-gated-rpc-during-openfga-outage`). A future change wires the
# kubectl-scale orchestration (or moves fail-closed coverage to integration).
# ---------------------------------------------------------------------------

CASES.append(Case(
    id="AUTHZ-FAILCLOSED-OPENFGA-DOWN",
    title="gateway returns 503 Unavailable when OpenFGA unreachable (fail-closed)",
    classes=["AUTHZ", "FLOW", "FAIL_CLOSED"],
    priority="P0",
    steps=[
        Step(
            name="any-authz-gated-rpc-during-openfga-outage",
            method="GET",
            path="/iam/v1/accounts/{{accountAId}}",
            auth="jwtAccountAdminA",
            test_script=[
                "// fail-closed: when OpenFGA is unreachable the gateway's",
                "// authz-middleware enters outcomeError with FailOpen=false →",
                "// HTTP 503 Unavailable / gRPC code 14. NEVER 200.",
                "//",
                "// Orchestration NOTE: this case expects an external wrapper",
                "// (tests/newman/scripts/run-failclosed.sh or CI step) to have",
                "// already executed:",
                "//   kubectl scale deployment kacho-openfga --replicas=0",
                "// and to restore (--replicas=1) after the suite finishes.",
                "// Without that orchestration the case is RED — by design.",
                "pm.test('[FAIL-CLOSED] gateway 503 Unavailable', () => {",
                "  pm.expect(pm.response.code, 'got ' + pm.response.code + ' ' + pm.response.text()).to.eql(503);",
                "});",
                "pm.test('[FAIL-CLOSED] grpc code 14 (Unavailable)', () => {",
                "  let j; try { j = pm.response.json(); } catch (_) { j = {}; }",
                "  pm.expect(j.code, JSON.stringify(j)).to.eql(14);",
                "});",
            ],
        ),
    ],
))
