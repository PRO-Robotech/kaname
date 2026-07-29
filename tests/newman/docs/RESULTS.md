# Newman regression — results & known-failing disposition

The suite is gated by `scripts/assert-suites-green.sh`: the gate subtracts a small,
explicitly-enumerated known-RED set from each suite's failure count; everything else
must be 0. The known-RED set is kept tiny and each entry has a documented reason.

## Test-side fixes (round — 2026-07-26; base `adf1cb2`) — the suite starts checking itself

Context: `adf1cb2`/`647b5f8` repaired the execution guards, so ~325 previously-dropped
requests began to RUN. Nothing regressed — the 87 post-gate failures that appeared were
requests that had never executed, now reporting honestly. This round closes the test-side
debt they exposed. **No entry was added to the known-RED whitelist** and no assertion was
weakened; two assertions were re-pointed at the refusal that is actually reachable, and
several were strengthened.

### Harness (scripts/gen.py) — two classes that made green cases meaningless

- **The Operation poll ran as the wrong principal.** `poll_operation_until_done` /
  `assert_op_success` / `assert_op_error` hard-coded `jwtAccountAdminA`.
  `OperationService.Get` is principal-scoped and hides a foreign operation as 404, so any
  case whose mutation runs as somebody else polled an operation it may not see, for its
  whole retry budget — `IAM-USR-DL-CRUD-OK` alone was 52 of the 87 failures, one root.
  The default is now `AUTH_INHERIT_OP`: at collection-build time the poll takes the auth of
  the step that captured its operation-id variable (explicit `auth=` still wins; no local
  producer → the historical default; an `anonymous` producer is never inherited). Exactly
  two steps in the whole suite changed principal, which is the point — it is a
  root-cause fix, not 52 patches. Unit-locked in `scripts/gen_test.py`.

- **The Operation id survived between cases.** `opId` is one shared variable and a
  REJECTED mutation writes nothing to it, so the poll confirmed the PREVIOUS case's
  operation and the case passed having tested nothing. `save_from_response` now CLEARS any
  operation-id variable before the capture attempt, and the six hand-written
  `pm.environment.set('…OpId', …)` branches that had the same shape were given the same
  reset. Two live victims: `IAM-USR-INV-IDEM-REINVITE` (400 on a missing field → polled the
  prior invite → "idempotency" never once exercised) and `IAM-ROL-DL-NEG-SYSTEM` (403 →
  the stale id DEFEATED its own `if (!opId) skipRequest()` guard → asserted
  FAILED_PRECONDITION against the previous case's SUCCESSFUL delete). An empty id is now
  reported once, by name, at a `skipRequest()` guard (`required=False` on the 21
  best-effort `cleanup-*` polls, where a refused teardown genuinely has nothing to poll).
  Audit of other shared variables: resource-id captures (`crudRoleId`, `crudGroupId`, …)
  are deliberately NOT reset — they are read many steps later by design; the stale-poll
  class is specific to ids consumed by the next request.

### Fixture / subject defects

- **The "sees nothing" probes were run by a subject that genuinely sees things.**
  `jwtNoBindings` (userNOBId) is the standard grant TARGET of the AccessBinding suites:
  `iam-flat-authz-vbc` grants it `view` on account-A, the `authz-deny` AB-CR ALLOW rows
  grant it `view` on account-B, and both stay ACTIVE in Postgres across runs. Every
  DENY/EMPTY expectation for it was being asserted against an authorised principal.
  Switched to the DEDICATED never-granted `jwtPureNoBindings` (seeded by
  `tests/authz-fixtures/setup.sh`, never a grant target anywhere): the `authz-deny` NOB
  matrix row, `AUTHZ-ULG04`, and the foreign-Get / scope-filter probes in
  `iam-project` / `iam-group` / `iam-service-account`. The two self-referential rows
  (`USR-GT-A` self-get, `ESC-SELF-ADMIN-*` self-grant) were re-targeted to
  `userPureNoBindingsId` so "self" still means self. Stale titles naming `jwtNoBindings`
  on steps that already used the pure subject were corrected.

- **`IAM-USR-DL-CRUD-OK` deleted a user that cannot be deleted** (surfaced *by* the poll
  fix — the 404 had been hiding it). `userINVId` holds active AccessBindings by
  construction (own personal-account owner grant + default-project admin + the
  account-B admin grant from the seed), and `User.Delete` is guarded by the access-binding
  RESTRICT. The case asserted only `done`, never SUCCESS, and its get-after-delete ran as
  a principal that gets 404 on that record either way — "gone" was satisfied by
  hide-existence. **Case defect, not a product one**: the RESTRICT is deliberate and
  unit-locked (`pgmaperr_test.go`). The case now self-seeds a genuinely deletable user
  (invite without `roleId` → PENDING row, no binding), deletes it as the account owner and
  asserts the operation SUCCEEDED. The refusal it had been hitting is now covered on
  purpose by the new `IAM-USR-DL-NEG-ACTIVE-BINDINGS`, pinned to its verbatim text.

- **`IAM-USR-INV-IDEM-REINVITE` had never sent a valid request.** `project_id` is required
  whenever `role_id` is set, and the body omitted it → 400 on every run. Rebuilt
  self-contained: re-inviting the same email returns the SAME user row (asserted on
  `response.id`, not the pre-allocated `metadata.userId`), and re-issuing an
  already-active project grant returns Operation `ALREADY_EXISTS` — `AccessBinding.Insert`
  is a strict create by design (the `ON CONFLICT DO UPDATE` upsert was removed because it
  hid duplicate grants, `access_binding_repo.go:18`).

### Stale fixtures in `iam-role` (12 assertions)

| Case | Was | Now |
|---|---|---|
| `IAM-ROL-UP-T33-LABELS-OK` | used `crudRoleId`, deleted by `IAM-ROL-DL-CRUD-OK` earlier in the same collection → 404 on every step | self-seeds its own role (run-unique name) + cleanup |
| `IAM-ROL-LSOP-NEG-PAGE-TOKEN-GARBAGE` | listed the operations of a CLUSTER-scope system role → 403 AUTHZ_DENIED, never reached page-token validation | self-seeded own role; also pins the message to `page_token` |
| `IAM-ROL-DL-NEG-SYSTEM` | ran as an account subject, denied by `cluster-role-mutate` before the system-role guard; the 403 branch left `opId` stale | runs as `jwtBootstrap` (passes the gate, reaches the guard), clears `opId` |
| `IAM-ROL-CR-RULES-CAP-OVER-DENY` | 16 synthetic resource tokens per module, rejected by the closed-catalog check that was added after the payload | asserts the catalog rejection verbatim (see note below) |
| `IAM-ROL-CR-NEG-NO-SCOPE` | hard-expected 400 where the gateway fail-closes 403 on the unscoped `account:*` anchor first | `assert_unscoped_rejected('iam.roles.create', 'account:*')` — tolerant of both, but PINNED to the action + anchor so it cannot pass on an unrelated refusal |

**Note on the compiled-permission cap.** `>1024` is UNREACHABLE through the public API by
construction: the published catalog is 28 resource types × 5 closed verbs = 140 compiled
permissions, and a custom role may not use a module/resource wildcard
(`moduleResourceWildcardSystemOnly: true`). The numeric cap stays locked where it is
reachable — `domain.TestPermissions_Validate_CapRaise1024` (1024 accepted / 1025 rejected).
Re-pointing the black-box case at the closed-catalog gate loses no coverage and replaces an
assertion that could never pass with one that can.

**Product observation (not fixed here — test-only round).** `invite.go:277` still comments
the project bind as "idempotent через ON CONFLICT DO UPDATE"; that upsert was deliberately
removed and the insert is now strict create-or-conflict. The comment contradicts the code
(`architecture.md` doc-truthfulness) — worth a follow-up in the owning repo.

## Test-side fixes (round — 2026-07-21, qa; base `redesign/integration`@99f33d2)

Triaged the clean-seed umbrella CI artifact (`na4/iam/.../out/*.json`). Findings by class:

- **`iam-account-redesign` — 52 raw failures → 0 (ONE case, gate-blocking, FIXED).**
  All 52 collapse to `IAM-PRJ-RD-CR-DUP-NAME-PER-ACCOUNT :: poll-op #4`. Root: the case's
  `cleanup-dup-B` DELETE of account-B's **own freshly-created** project 403'd at the authz
  gate — the creator's `v_delete` FGA owner-tuple was still materialising (opgate removed →
  `op.done` ≠ tuple-visible; the prior create-op polls confirmed the *Operation*, not the
  project resource). The un-retried DELETE never saved a fresh `opId`, so the following
  poll polled the **stale** prior-delete op (minted by a DIFFERENT principal) → 404 from the
  principal-scoped `OperationService.Get` hide-existence (51 retries + 1 done-assert). Fix
  (test-only): wrap both own-fresh-resource cleanup deletes in `retry_until_authorized`
  (bounded read-your-writes, fail-closed at budget). Not a product bug — canonical EC lag.

- **`iam-authz-grant-check-propagation` — 3 (whitelisted, net-positive improvements).**
  (a) `poll_check_denied_step` asserted `j.allowed === false`, but a real
  `InternalIAMService.Check` deny returns `{"reason":…}` with the `false` bool OMITTED
  (proto3-JSON default omission) → the poll could never converge on a correct deny. Fixed
  to `code===200 && j.allowed !== true` (a genuine still-allowed `{"allowed":true}` still
  fails — nothing masked). (b) `AUTHZGCP-AB-CREATE-CHECK-VISIBLE::probe-check` hit the
  unregistered `/iam/v1/check` (always `403 catalog: no entry for method`) → migrated to the
  working `poll_check_allowed_step` internal `/iam/v1/internal/iam:check` probe. (c)
  `AUTHZGCP-SAKEY-SECRET-NOT-LEAKED::re-get-op-redacted` read non-existent snake_case
  `client_id/client_secret` (real fields are camelCase `clientId`/`privateKeyPem`/
  `clientSecret`) — the "redacted" assert passed vacuously, "client_id present" failed on
  `undefined`. Reframed to lock the black-box observable (one-shot delivery + identifier);
  the 120 s-grace redaction timing is unit-covered (`sa_keys/usecase_redaction_grace_test.go`).

- **`rbac-visibility-set` (12) + `iam-rbac-subjects` (11) — grant-materialisation timing
  under umbrella-parallel load; NOT confidently test-fixable, NOT force-masked.** These are
  dominated by FGA tuple-materialisation lag that exceeded even the ~25 s bounded
  `poll_request_until_status` window (`get-subjects-len-2`/`get-legacy-fills-subjects` → 404
  own-AB hide-existence for the full 51-poll cap; `check-member-allowed`/`expand-access-members`
  → 181 non-converging retries on group#member→viewer). **Wandering-flake signature**:
  `RBACSUBJ-CR-NEW-AUTHOR::get-new-fills-legacy` uses the identical pattern and CONVERGED,
  while its siblings did not — timing, not a functional/test hole (the hint's "0/138 green on
  a healthy seed" confirms). The documented replica-lag remedy (`iam replicaCount=1`) is
  **already** applied in `values.dev.yaml`; the residual is grant-materialisation THROUGHPUT
  under the full parallel run (see MEMORY "grant-materialization O(mirror) root"). Two
  `rbac-visibility-set` sub-classes are **over-shows** (`IAM-SET-*-VLIST-ONLY-DETAIL-404`
  detail-Get returned 200; `*-LABEL-EXACT-OK` List over-showed no-label/other-label objects)
  — deliberately **left RED, NOT whitelisted** (whitelisting an over-show could mask a real
  leak; the `GroupService.List` v_list-filter gap is a pre-existing product finding, above).
  Budget-inflation would be an anti-fix (MEMORY "budget-raise = timeout-cancel"). Disposition:
  re-run on a healthy/less-loaded stack to confirm convergence; a persistent over-show after a
  clean re-run is a product finding for TDD, not a test change. **The account-redesign fix is
  the only gate-blocker in this set that is a genuine test defect.**

- **Out of the artifact but NOT in scope**: `iam-internal-only-check` (8) fail with
  `getaddrinfo ENOTFOUND api.kacho.local` — the external endpoint is unresolvable in the
  port-forward-only newman CI (env limitation, not a leak); `iam-rbac-scope-grant` (7) not
  triaged this round.

## Resolved 2026-07-28 — the round-4 "product-bug floor" was no longer there

Everything this section described has been fixed, and the entries that named it are
gone from `assert-suites-green.sh`. It is kept, shortened, as a record of what was
believed and what turned out to be true — the previous text is in git history.

The claim was that a cluster administrator could not delete an access binding
somebody else had created (`652 x 403 vs 32 x 200` across an umbrella run), and that
an account administrator could not issue a key for a service account they had just
created; both were attributed to inherited access simply not existing for those
types. The inherited-access change of **2026-07-27** removed that cause.

Re-measured **2026-07-28** on the kind stand, by running the suites:

| Suite | Step | Was declared | Observed 2026-07-28 |
|---|---|---|---|
| `rbac-subject-channel-equivalence` | `teardown-user-revoke`, `teardown-usr-iso-revoke` | permanent 403 | **HTTP 200** |
| `rbac-subject-channel-equivalence` | the seven `*-gone` convergence probes | red, downstream of the refused revoke | **all pass** |
| `rbac-subject-channel-equivalence` | `IAM-CH-GRP-MEMBERSHIP-FLIP-OK` | red, drain tail | **case passes end to end** |
| `iam-authz-grant-check-propagation` | `issue-sakey` | permanent 403 | **HTTP 200** |
| `iam-authz-grant-check-propagation` | `probe-check-after-revoke`, `poll-op-plaintext`, `re-get-op-redacted` | red, downstream of `issue-sakey` | **all pass** |
| `iam-invite-grant-fga` | `poll-bind-project-anchor`, `te4-post-bind-project-viewer` | red (product gap, later restated as a stale case) | **49/49, zero failures** |

`PRO-Robotech/kacho#9`, `kacho-iam#212` and `kacho-iam#217` should be closed as fixed.

One red in `iam-authz-grant-check-propagation` was not covered by any of this and is
**not** masked: `AUTHZGCP-BIND-LIST-BY-SUBJECT-FOREIGN-DENY :: inv-lists-aaa-subject`
denied correctly, but the response carried no error detail, so the case could not tell a
scoped denial from a missing catalog entry.

**Fixed in the service.** iam now attaches the machine-readable reason (`AUTHZ_DENIED`),
domain and `metadata.action` to a refusal it decides itself — for every method on the
scope-filtered band, where the edge runs no per-RPC check and therefore names no action.
A method with no catalog row still gets nothing, so a catalog miss stays distinguishable,
which is the discriminator the case asserts. Unit coverage enumerates the band from the
catalog itself: `services/iam/internal/authzguard/deny_details_test.go`. The case is
expected green on the next stand run; this row stays until a run observes it, because the
fix is proven in-process and not yet end to end.

## Known failing — honest must-DENY canary (NOT whitelisted, NOT masked)

This one is an **over-SHOW** shape (a subject sees data). It is the last-standing honest
canary for user-list over-show — **deliberately left un-whitelisted** so a genuine leak
still fires the gate. It fires the gate honestly; leave RED until the product/fixture fix.

| Suite | Case / step | Signature (observed) | Root (product) | Issue |
|---|---|---|---|---|
| `iam-user` | `IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY::list-nonmember` (honest canary — intentionally NOT whitelisted) | `jwtNoBindings` lists `?accountId=accountA` → 200 + **1 user** (a PENDING invitee) instead of empty. Root: `nob_preclean_account_a` cannot strip NOB's residual account-A viewer left by the #276 cross-suite collision because **`GET /iam/v1/accessBindings:listBySubject?subjectId={userNOB}` as `jwtAccountAdminA` → `403 permission denied`** (listBySubject is self/cluster-admin-scoped; an account-admin listing *another* subject is denied), so the pre-clean is a no-op. | Compound: **#276 cross-suite fixture pollution** (IAM-ACB-CR-CRUD-OK grants `userNOB` a global `*.*` viewer on account-A) + the `listBySubject` non-self 403 leaves the pollution un-cleanable. Also documented as an env-flake that clears on re-run. Real fix = de-share the umbrella account across suites and/or a resource-scoped bindings-list the account-admin may call. | `kacho-iam#276` |

## Resolved — label-remove on storage revokes (was: known failing, NOT whitelisted)

`label-revoke-storage` was added as the OWNER-side analogue of `label-revoke-compute`
before the block-storage duplicate in kacho-compute was deleted, and it was declared
RED on its revoke half when it was written.

**It is green, and has been since the same day it was written.** The gap it found was
real: storage told the authority holding the label selector what a resource's labels
were when it was created and again when it was deleted, and nothing in between, so a
removal never reached the selector and the grant outlived the label it came from. That
is fixed — an update that touches labels now re-tells the authority the labels as they
are now, on all three resources. The declaration above it in this file and in the case
docstring simply outlived the fix by a day.

**Re-verified end to end (live umbrella, 2026-07-28)** against the whole collection,
not a re-reading of the code: `label-revoke-storage` runs **87/87 assertions, 0
failed**, all three `*-post-revoke-deny` steps included. Independently confirmed at
two more layers — the storage register queue carries a second intent per updated
resource stamped with the labels *after* the update (and drains clean: 320 rows, 320
sent, 0 pending), and a direct probe flips Check from `allowed:true` to denied on every
way a label can come off: cleared to nothing, one key dropped, the whole set replaced,
and under a full-object PATCH (empty `update_mask`) as well as an explicit one.

**A stale RED declaration is not a harmless leftover.** It states, in the file that
decides what the gate tolerates, that a live over-grant exists; anyone reading it
either goes hunting for a defect that is already closed or learns that a red revoke
check is something this suite lives with. Both are worse than saying nothing.

## Resolved 2026-07-28 — the "bounded-poll tail" entries

Both rows that stood here (`IAM-CH-GRP-MEMBERSHIP-FLIP-OK`, and the seven `*-gone`
revoke-to-deny probes) explained themselves as an eventual-consistency tail on a loaded
cluster. Neither explanation survived: the tail was measured at sub-second on 2026-07-26,
and on 2026-07-28 every one of these steps passes. They are removed from the gate rather
than re-justified — see the section above.

## Product findings (cases omitted, not RED)

| Finding | Disposition |
|---|---|
| `GroupService.List` does not apply the per-object `v_list` listauthz filter — over-shows ALL account groups to an `account#v_list` holder (project/SA/role List filter; group does not) | The group by-label exact-set (INV-2) case is **omitted** (the invariant the matrix expects is not implemented for group List). Group v_list-only (INV-1) IS emitted and green (group Get gates on v_get). |

## Pre-existing environmental flakes (clear on CI re-run)

`iam-access-binding` and `iam-user` occasionally flake whole-suite core-CRUD when the
cluster-admin / OpenFGA bootstrap has not materialized by the time the suite runs (e.g.
`AccessBinding.Create` → `operation.id ... expected undefined`, or the non-member scope-filter
seeing 1 user). These are environmental, not introduced by the suite code. Established remedy:
re-run the `newman-e2e` job.

## Account-scoped List authz uniformity

All five account-scoped IAM List RPCs (`User/ServiceAccount/Role/Project/Group`) carry
`permission = "<exempt>"` — the List CALL itself is not authz-gated; the result set is filtered
in-handler by `viewer ∪ v_list`. A non-member therefore gets **200 + empty**, not 403; an
anonymous caller (no token) still gets **401 UNAUTHENTICATED** (`<exempt>` removes authz-Check,
not authN). This is exercised black-box by `AUTHZ-ULG04-NONMEMBER-PRJGRP-LIST-EMPTY`
(`jwtNoBindings` → Project & Group List → 200 + empty), the `*-LS-*` scope-filter rows in
`authz-deny.py`, and the `IAM-SET-PRJ/GRP-LABEL-EXACT-OK` exact-set cases in `rbac-visibility-set.py`.

Content stays closed independently of List visibility: `v_list ≠ v_get`, so a `v_list`-only
subject sees a row in List but its detail Get returns 404 (`IAM-SET-*-VLIST-ONLY-DETAIL-404`).
When OpenFGA is unavailable the List RPCs fail closed (Unavailable), verified by
`project/list_*_test.go` / `group/list_*_test.go` (incl.
`TestListProjects_NilRelationPort_Unavailable` / `TestListGroups_NilRelationPort_Unavailable`).
Genuine `system/bootstrap` callers run on the internal listener (bypassing the gateway
annotation); on the public path `project`/`group` List treat `system/bootstrap` as anonymous →
empty (verified by `TestListGroups_SystemBootstrapFallback_FailClosed`).

## Test-side fixes (round 2 — `qa/iam-acb-fixture-green`)

Two RED classes in the umbrella CI report were **test-infra** defects (not product) and
are fixed here (verified locally via `py_compile` + `gen.py`; runtime GREEN is pending an
umbrella run):

- **`iam-invite-grant-fga` — `POST /iam/v1/internal/iam:check` → `404 page not found`
  (8 steps: `te{1,2,3}-*`, `te4-*`).** The `check_step` helper hit the **public** cmux
  (`{{baseUrl}}` :18080), which 404s `/iam/v1/internal/*` by design (ban #6) → JSONError on
  the first `pm.response.json()`. Fix: `check_step` now carries the same
  `_internal_url_override` pre-request URL rewrite to `{{internalBaseUrl}}` (:18081) that
  `label-revoke-vpc.py` uses (proven to reach 200 in the very same CI run). The 2 TE4
  `poll-bind-project-anchor` / `te4-post-bind-project-viewer` failures are GREEN as of
  2026-07-28 (whole suite 49/49) and are no longer whitelisted; **#212** is closed.

- **`label-revoke-{vpc,compute}` — cross-service create against a PHANTOM project
  (round-3 root).** Round-2 fixed the create-`403` by granting AAA an explicit
  `ROLE_EDIT @ project:A1` in `tests/authz-fixtures/setup.sh` (so the gateway authz gate
  passes). Round-3 CI then exposed the deeper root: the create Operation now returns `200`
  but completes `done:true` **with an error** — `create-net` → `{code:5,"Project
  prj3m3q…8ftb not found"}` (vpc), `create-disk` → `{code:5,"Folder with id prj3m3q…8ftb
  not found"}` (compute) — for the shared `{{projectA1Id}}`. Root: the fixture's
  `ensure_project` extracts `metadata.projectId` from the completed Create Operation
  **without checking `op.error`**; a Create that finishes with an error still carries the
  pre-allocated id in metadata, so `projectA1Id` was patched to a **phantom** — an id
  whose IAM project ROW never committed. The round-2 `ROLE_EDIT @ project:A1` binding then
  wrote FGA tuples **against that phantom id** (AccessBinding does not require the row to
  exist), so the gateway authz gate passes (tuple present → `200` op), but the
  cross-service peer-check (`vpc/compute → iam ProjectService.Get`) returns `NOT_FOUND` →
  the create op fails → the whole flow cascades RED on an unset resource var. Confirmed:
  `"prj3m3q… not found"` appears in **only** the two cross-service suites (36× vpc, 20×
  compute) and in no same-service suite — two independent services agreeing on `NOT_FOUND`
  ⇒ the row genuinely does not exist (not a per-edge bug). Fix (test-only, no product
  change): `label-revoke-{vpc,compute}.py` now **self-seed a fresh project per case**
  (`create_suite_project` → `{{_t31Proj}}` / `{{_t31cProj}}`, op-poll asserts `done` +
  **no error**) under `accountAId` and route all resource creates through it, replacing
  the shared `{{projectA1Id}}` dependency entirely — mirrors the existing runtime
  zone-discovery pattern in `label-revoke-compute.py`. accountAId stays the shared-tenant
  anchor (the ARM_LABELS role is account-scoped and containment matches
  `parent_account_id == accountAId`, which a project under account-A satisfies). A
  freshly-created, poll-confirmed project is guaranteed to exist for the peer-check, so
  these suites are now **GREEN by construction** (verified locally via `py_compile` +
  `gen.py`; runtime GREEN pending an umbrella run). Belt-and-suspenders: `setup.sh` gained
  a **non-fatal** post-create diagnostic that GETs `project:A1` and logs a loud `WARN` if
  it does not resolve, so a future phantom is diagnosable instead of hiding behind green
  FGA tuples. `label-revoke-nlb` is GREEN as of 2026-07-28 (47/47 requests, 23/23 assertions,
  including the revoke-side deny) and is no longer whitelisted.

---

## IAM-1 redesign (tenancy-tree + authz-core, F1–F11) — newman coverage

Black-box coverage of the **IAM-1** owner-side redesign
(`docs/specs/sub-phase-IAM-1-tenancy-authz-core-acceptance.md`), grounded in the
**landed** `services/iam` code (proto + use-cases + seed migrations), authored test-only
(ban #13 — no product code touched). Local newman env is blocked (no HTTPS ingress on the
kind stand); the cases are `gen.py`-generated + `coverage.py`-validated here and executed
by the `newman-e2e` CI job. IAM Operation id-prefix is **`iop`** (not `epd`).

### New case files (34 cases, `# verifies IAM-1-NN` in each title)

| File | F | Cases (IAM-1-NN) |
|---|---|---|
| `cases/iam-account-redesign.py` (9) | F1/F2/F3 | ownerUserId derive-from-caller + reject-in-body (attacker/self) + Update-immutable (01/02/03); Create-saga two-id metadata + default `"default"` Project + owner-binding `deletionProtection` (04); Delete RESTRICT-non-empty (06); Project.Create under account + no-parent (07); accountId immutable (08); dup-name per-account vs cross-account OK (09) |
| `cases/iam-role-redesign.py` (9) | F4/F5/F6 | definitionTier dotted + isSystem° derived + no scope-field (10); definitionTier empty-tierType + legacy both-scope XOR (11); public Get no compiled `permissions` (13); permissions-input reject + empty-rules reject (14); canonical catalog `view→edit→admin→owner` first-in-order + `edit.effectiveVerbs=[get,list,update,delete*]` + verbNotes verbatim (15); system-role Update (sync FP) + Delete (op.error FP) immutable (16) |
| `cases/iam-access-binding-redesign.py` (16) | F7/F8/F9/F10/F11 | scopeType dotted + target.allInScope + no resourceType/resourceId (18/21); per-object target.resources ResourceRef closed-table no-name (21/23); no-target reject (22); unknown target-type reject (23); scopeType-required + bare-not-dotted reject (18); scope/subjects immutable Update (19); RoleCoversType FP (24); IsRoleAssignable FP (25); malformed scopeId + missing-anchor (26); Delete-hard→gone (27); :revoke soft→REVOKED+revokedAt (28); re-grant-after-revoke new-ACTIVE + dup-ACTIVE ALREADY_EXISTS (29); List garbage-token / pageSize>1000 / unknown-filter-key before authz + whitelist-filter (32) |

Exact error texts/codes/fields are pinned from the landed code (e.g. `"Illegal argument
ownerUserId (derived from caller)"`, `"target is required; use target.allInScope{} to
grant all objects under the anchor"`, `"role %s does not grant verbs on compute.instance;
target type must be covered by role.rules"`, `verbNotes["delete*"] == "co-materialized on
in-scope leaf objects, NOT on the account/project anchor itself"`, seed catalog names
`view/edit/admin/owner`, `edit` rules `verbs=[get,list,update]` ⇒ editor-tier delete*).
`AccessBindingService.Revoke` (the new `:revoke` RPC) is now covered by newman.

### Existing cases updated to the IAM-1 contract (registry-agent style)

- **F1 ownerUserId derived-from-caller** (`Account.Create` body no longer carries
  `ownerUserId`; supplying any value → sync `INVALID_ARGUMENT`):
  - `iam-account.py` — 11 create/BVA/SEC bodies had `ownerUserId` removed (owner° derives
    from the caller = `userAAAId`, so the existing `Get.ownerUserId==userAAAId` assertions
    still hold); the two legacy owner-negatives **repurposed**:
    `IAM-ACC-CR-NEG-OWNER-MISSING` (was "unknown owner → error") and
    `IAM-ACC-CR-AUTHZ-OWNER-MISMATCH-DENY` (was anti-hijack 403) now both assert the
    reject-in-body `400 INVALID_ARGUMENT` — the AS-IS required-branch and anti-hijack-branch
    are gone.
  - `authz-deny.py` — `EXPECT["esc-account-hijack"]` flipped `AAA:ALLOW→DENY` (the
    ownerUserId-hijack vector is now closed for **every** subject, incl. self; `reject_asserts`
    already accepts code 3/400).
  - `rbac-visibility-set.py` — fixture-seed `create-suite-account` dropped `ownerUserId`.
- **F7/F8 AccessBinding scope-anchor + target** — the landed `CreateAccessBindingRequest`
  requires `scopeType` (dotted `iam.account|iam.cluster|iam.project`) + `scopeId` + a
  REQUIRED `target`; the resource message exposes **only** `scopeType`/`scopeId` (no legacy
  `resourceType`/`resourceId`). All **41** legacy create bodies across **15** files
  (`iam-access-binding.py` ×19, `authz-deny.py`, `authz-sa-apitoken.py`,
  `iam-authz-grant-check-propagation.py`, `iam-rbac-scope-grant.py`, `iam-rbac-subjects.py`,
  `iam-role.py`, `iam-invite-grant-fga.py`, `label-revoke-{vpc,compute,nlb,iam}.py`, …) were
  migrated: `resourceType:"account"→scopeType:"iam.account"` (+cluster/project),
  `resourceId→scopeId`, and a `target:{allInScope:{}}` injected (these are all whole-scope
  grants, so `allInScope` is the semantically-correct target). The ~40 response-reader
  assertions (`b.resourceType==='account'` → `b.scopeType==='iam.account'`,
  `.resourceId`→`.scopeId`) were migrated with the value change. The legacy
  `:listByScope?resourceType=…&resourceId=…` **query params stay** (the ListByScope/BySubject/
  ByRole/ByAccount RPCs still exist and their request messages keep `resource_type`/
  `resource_id`).
- **F8 target reintroduced** — `IAM-ACB-F51-TARGET-IGNORED` repurposed: the OLD premise
  ("`target` is a removed/ignored key") is inverted — `target` is now REQUIRED and HONORED;
  the case asserts `target.allInScope` IS honored while the still-removed `selector`/
  `targetRef` keys are unknown-ignored.

### `[PHASE-0-GATED]` scenarios — asserted UNGATED-only, gated part documented

The acceptance marks several scenarios `[PHASE-0-GATED]` (land only after the B1/B3/B6
governance change-set). The landed code is **pre-Phase-0**, so these newman cases assert
the **ungated** behavior and do NOT assert the gated part:

- **B3 prefix-derivation** — IAM-1-12 (`tierType` from `tierId` prefix) and IAM-1-18
  (`scopeType` from `scopeId` prefix) are gated. Landed code REQUIRES `tierType`/`scopeType`
  explicitly (`"scopeType is required"`, `role/handler.go` requires `tierType`). The cases
  send explicit dotted `tierType`/`scopeType` and additionally lock the pre-Phase-0
  requirement (empty → `INVALID_ARGUMENT`). Prefix-derivation is a follow-up.
- **B3 hyphen ids** — IAM-1-17 (system roles `rol-viewer`…). Seed ids are the current
  non-hyphen `rol1bda80f2be4d3658e`/`rolde95b43bceeb4b998`/`rol21232f297a57a5a74`/
  `rol72122ce96bfec66e2`. The catalog case keys on role **name** (`view/edit/admin/owner`)
  + verb preview, not the id form.
- **reason-token in `google.rpc.Status.details`** — IAM-1-24/25 gate `reason` tokens
  (`ROLE_DOES_NOT_COVER_TYPE`, `ROLE_NOT_ASSIGNABLE_ON_TIER`) are gated; the cases assert
  the **code + message text** (ungated), not the token.

### Non-black-box scenarios — integration-covered (NOT newman), declared honestly

- **IAM-1-13 (internal `GetRoleCompiled` positive)** — the compiled `permissions[]`
  projection lives on the internal listener (`InternalIAMService.GetRoleCompiled`, :9091),
  which is not reachable from this public-gateway newman env. Newman covers the **public**
  side (two-projection field-ABSENCE on public `Role.Get`/`List`); the internal-positive is
  covered by `services/iam/internal/apps/kacho/api/role/f5_compiled_projection_test.go`.
- **IAM-1-33 (INTERNAL never echoes pgx/SQL)** — requires injecting an uncategorized DB
  error on the write path (not reproducible black-box). Integration-covered
  (INTERNAL-opaque mapping tests). Documented here, not a newman case.
- **IAM-1-31 (Operation.done durability ≠ tuple-visibility materialization timing)** — not a
  standalone black-box assertion; it is the **read-your-writes discipline** applied across
  every positive case via `retry_until_authorized` / `poll_request_until_status`. The saga
  atomicity / re-grant-after-revoke CAS races are integration-covered
  (`create_saga_iam1_test.go`, `revoke_test.go`, `*_integration_test.go`).

### Validation

`gen.py` regenerates all 24 collections cleanly (Python-parse OK on all case files);
`coverage.py` reports **57%** RPC→case coverage (≥ the CI `--min 30` gate, exit 0); no
duplicate case-ids; **no product code touched** (diff is `tests/newman/**` + this doc).
Runtime GREEN is validated by the `newman-e2e` CI job (local env blocked).
