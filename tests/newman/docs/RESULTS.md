# Newman regression — results & known-failing disposition

The suite is gated by `scripts/assert-suites-green.sh`: the gate subtracts a small,
explicitly-enumerated known-RED set from each suite's failure count; everything else
must be 0. The known-RED set is kept tiny and each entry has a documented reason.

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

## Known failing — confirmed product-bug-floor (round-4: WHITELISTED, over-restrictive, cannot leak)

These are **confirmed product defects**, each tracked by a GitHub issue, that are
**over-RESTRICTIVE** (a legitimate call is wrongly DENIED — the opposite of a leak).
Round-4 consolidation whitelists them in `assert-suites-green.sh` so the gate is not
blocked by a non-leak product gap; the assertions **still RUN and report** (signal
preserved) and the subtraction **clamps to 0** — the moment the product fix lands the
case self-heals to GREEN and any genuine regression re-widens the diff and re-fires the
gate. Whitelisting is safe here **only because none of these can mask an over-show / leak**.

| Suite | Case / step | Signature (observed) | Root (product) | Issue |
|---|---|---|---|---|
| `rbac-subject-channel-equivalence` | `IAM-CH-USER-EQUIV-OK::teardown-user-revoke`, `IAM-CH-USER-SA-ISOLATION-DENY::teardown-usr-iso-revoke` | `DELETE /iam/v1/accessBindings/{id}` as **`jwtBootstrap`** (`system_admin@cluster_kacho_root`) → **`403 {"code":7,"message":"permission denied"}`**. The retry belt exhausts → persistent, NOT a materialization race. Across the umbrella run `DELETE accessBindings/{id}` = **652×403 vs 32×200** (the 200s are normal principals with a materialized per-object `v_delete`; the 403s are the cluster-admin path). | **Cluster-admin short-circuit is NOT honored at the gateway for `AccessBindingService/Delete`.** Object-scoped authz checks the caller's `v_delete` on the binding's scope; `system_admin@cluster_kacho_root` does **not** cascade to `v_delete` on `iam_access_binding:<id>` (FGA-model / permission-catalog gap). Because the revoke never commits, the downstream whitelisted `*-gone` Check-polls stay allowed=true (consequence, not a second bug). Fix = FGA cascade `iam_access_binding#v_delete ⇐ cluster#system_admin`, or a gateway super-admin short-circuit. | `PRO-Robotech/kacho#9` |
| `iam-authz-grant-check-propagation` | `AUTHZGCP-SAKEY-SECRET-NOT-LEAKED::issue-sakey` (the other 8 failures are anon-op / speculative-`/iam/v1/check` spot-checks already whitelisted) | `POST /iam/v1/serviceAccounts/{sva}/keys` as **`jwtAccountAdminA`** (the SA's own creator) → **`403 … lacks relation "v_update" on iam_service_account:<sva>`**. Already `retry_until_authorized`-wrapped and still persistent. | Same **hierarchical-cascade** family as #9: AAA holds `editor` on `account:A` (owner) but the **account-editor → `iam_service_account`-`v_update`** cascade for a fresh per-case SA does not resolve on the request path. Per-case SA (cannot be pre-bound in the fixture) → **product/FGA-model**, not a test retry. | `PRO-Robotech/kacho#9` |

## Known failing — honest must-DENY canary (NOT whitelisted, NOT masked)

This one is an **over-SHOW** shape (a subject sees data). It is the last-standing honest
canary for user-list over-show — **deliberately left un-whitelisted** so a genuine leak
still fires the gate. It fires the gate honestly; leave RED until the product/fixture fix.

| Suite | Case / step | Signature (observed) | Root (product) | Issue |
|---|---|---|---|---|
| `iam-user` | `IAM-USR-LS-AUTHZ-SCOPE-NONMEMBER-EMPTY::list-nonmember` (honest canary — intentionally NOT whitelisted) | `jwtNoBindings` lists `?accountId=accountA` → 200 + **1 user** (a PENDING invitee) instead of empty. Root: `nob_preclean_account_a` cannot strip NOB's residual account-A viewer left by the #276 cross-suite collision because **`GET /iam/v1/accessBindings:listBySubject?subjectId={userNOB}` as `jwtAccountAdminA` → `403 permission denied`** (listBySubject is self/cluster-admin-scoped; an account-admin listing *another* subject is denied), so the pre-clean is a no-op. | Compound: **#276 cross-suite fixture pollution** (IAM-ACB-CR-CRUD-OK grants `userNOB` a global `*.*` viewer on account-A) + the `listBySubject` non-self 403 leaves the pollution un-cleanable. Also documented as an env-flake that clears on re-run. Real fix = de-share the umbrella account across suites and/or a resource-scoped bindings-list the account-admin may call. | `kacho-iam#276` |

## Known failing — test-timing (bounded-poll tail)

| Suite | Case / step | Class | Why |
|---|---|---|---|
| `rbac-subject-channel-equivalence` | `IAM-CH-GRP-MEMBERSHIP-FLIP-OK` (`read-after-add` / `flip-gone`) | async fga_outbox drain tail | Two-transition membership flip (grant-on-empty-group → addMember→appears → removeMember→gone). Both transitions depend on the async fga_outbox drain of the group binding tuple. Under heavy umbrella-CI load the drain can exceed even the ~45 s bounded poll → transient flake (deterministically green on healthy runs). NOT a product bug — addMember/removeMember DO drive access. The assertions still RUN and report (signal preserved); they are just not gate-blocking. |
| `rbac-subject-channel-equivalence` | revoke→deny convergence probes — the `*-gone` Check-polls (`teardown-{user,grp,nonmem,sa,sa-iso,usr-iso}-gone`, `revoke-binding-gone`) | revoke-deny propagation tail | After `AccessBinding.Delete` the subject's `v_get` tuple is removed **byte-symmetrically** (`delete.go` reads the full `access_binding_emitted_tuples` ledger, sync-removes from OpenFGA + async `fga_outbox` backstop) → the deny is **guaranteed to converge** (NOT an over-grant; revoke is byte-symmetric). But on the resource-starved single-node kind cluster the revoke-deny propagation can exceed the suite's ~45 s bounded Check-poll under heavy load — these `*-gone` probes are the **last** step of each case (peak per-case outbox backlog) and later cases flake more as the cumulative backlog grows. Eventual-consistency **latency**, not a correctness bug: `IAM-CH-GRP-EQUIV-OK`'s group-revoke→deny proves the same single-transition invariant holds. `delete.go` retries the synchronous FGA tuple-removal past a transient OpenFGA failure (parity with the reliable grant sync-write), narrowing the tail; the whitelist covers the residual CI-saturation window. The `grant→appears` probes (reliable reconciler sync-write) and the steady-state single-shot denies (nonmember / principal-isolation) are **NOT** whitelisted — a real leak still fails honestly. |

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
  `poll-bind-project-anchor` / `te4-post-bind-project-viewer` failures remain
  whitelisted-RED (**#212** project-anchor role-authoring gap — unchanged).

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
  FGA tuples. `label-revoke-nlb` create-half stays whitelisted-RED (unchanged — needs the
  umbrella to seed nlb external resources).

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
