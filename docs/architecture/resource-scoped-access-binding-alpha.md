# Resource-scoped AccessBinding — per-object targets (by-design)

By-design notes for targeting one concrete object (or a set of named objects)
from a reusable role. Records the design decisions of the kacho-iam
implementation.

## Problem

Before resource-scoped targets, targeting **one concrete object** required a
custom Role whose permission 4th segment was the object id
(`compute.instance.<id>.start`) **and** a separate AccessBinding — two resources,
and the role stopped being reusable. The 4-segment permission grammar conflated
"what verbs" (reusable) with "over what" (instance-specific).

## Design

The **target** moves out of `role.permissions` into a new `AccessBinding.target`
oneof. Role becomes a reusable verb-bundle (wildcard `resourceName`); the concrete
object comes from the binding.

- `target.all_in_scope` — grant on the whole type within the `scope` anchor (the
  whole-type wildcard behaviour). Persisted as the **absence** of
  `access_binding_targets` rows.
- `target.resources[]` — per-object refs `{type, id}`. One child row per ref in
  `kacho_iam.access_binding_targets`.
- `target.selector` — label-based selection (see
  `resource-scoped-access-binding-gamma.md`).

### DB (migration 0018)

`kacho_iam.access_binding_targets`: `binding_id` FK →
`access_bindings(id) ON DELETE CASCADE` (same-DB cascade — ban #4 allows),
`UNIQUE(binding_id, type, id)` (idempotent add / dedup). `all_in_scope` ≡ zero
rows; the read-side projects 0 rows ⇒ all_in_scope (forward-only: no
migration-revoke of legacy bindings). `id` is an **opaque cross-DB soft-ref**
(no FK, no peer-existence — ban #8), like the parent `resource_id`.

### Three independent gates on Create/Add

1. **role-scope** — `domain.IsRoleAssignable(role, scope)`.
2. **role-coverage** — every `target.resources[].type` must be covered by a verb
   in `role.permissions` (`domain.RoleCoversType`). Deterministic, same-DB, no
   TOCTOU. Fail → `Operation.error` `FAILED_PRECONDITION`.
3. **target-containment** — the object must lie under the binding's scope. It is
   resolved SAME-DB from the `resource_mirror` (a push-fed copy of the owner's
   parent-scope), **not** via a peer-call `iam→compute/vpc` (that would create a
   **cycle** — `compute→iam` / `vpc→iam` already exist). See
   `resource-scoped-access-binding-gamma.md`.

Gates (1) and (2) are IAM-local (same-DB, no peer-call); gate (3) resolves
containment from the same-DB mirror. The privilege boundary rests on scope-level
grant-authority + role-coverage + containment.

### FGA emission

Per-object tuples reuse the per-verb tuple matrix, but the source of
`resourceName` is the **target**, not `role.permissions`:
- `resources[]` → for each `(verb-tier role grants on the ref's object-type) ×
  (ref)` emit `fga_type(ref.type):<ref.id>#<tier>@subject` (`tuplesForTarget`).
- `all_in_scope` → the whole-type tier / scope-anchor emission (`tuplesForBinding`).

Tuple emission ⊕ binding INSERT ⊕ target-row INSERT ⊕ subject_change/audit
outbox all commit in **one writer-tx** (atomic, ban #10).

### Set-mutations

`AddTargetResources` / `RemoveTargetResources` — async Operations, idempotent
(`INSERT … ON CONFLICT DO NOTHING` / `DELETE`). `CountTargetsForUpdate` takes a
`SELECT … FOR UPDATE` row-lock on the parent binding so concurrent add/remove of
the same binding serialize. State gates → `Operation.error` `FAILED_PRECONDITION`:
- add to an `all_in_scope` binding → rejected (no mixing oneof arms; switch arm
  = Delete+Create);
- remove the **last** ref → rejected ("use Delete to revoke") — NO
  auto-conversion to `all_in_scope` (that would be a silent privilege change).

### ListGrantableResources

Sync read; same `requireGrantAuthority` gate as Create / ListAssignableRoles.
- iam-owned `objectType` under the scope (`iam.project` under an account) → real
  rows from the IAM DB;
- non-iam `objectType` → resolved by the owner service; the UI resolves such
  objects client-side via the owner REST.

Output is a lean, output-only projection (`type`/`id`/`name`) — no infra-sensitive
fields.

## Scope boundary

- Legacy concrete-`resourceName` roles are left as-is — no migration-revoke or
  rewrite (forward-only).
- Label selectors and containment are handled separately (see
  `resource-scoped-access-binding-gamma.md`).

## Known behaviour

### Post-commit re-read may surface a late error (idempotent retry)

Add/Remove set-mutations commit the DML + FGA-outbox + subject-change outbox in
one writer-tx, then re-read the binding (`loadBindingWithTarget`) to build the
Operation response. The mutation is durable at **commit**; the re-read happens
**after** it. If the re-read fails (e.g. transient pool error) the Operation
finishes with an error **even though the change is already persisted**. This is
acceptable because Add/Remove are idempotent: the client retries the same
request — a re-add is `ON CONFLICT DO NOTHING`, a re-remove of an already-gone
ref is a no-op — and converges. We do NOT roll back a committed mutation on a
post-commit read failure.

### Tuple-emission fail-closed

A ref that clears the type-level role-coverage gate (`RoleCoversType`) must yield
≥1 per-object FGA tuple. The per-grant tier predicate (`grantCoversType`) and the
FGA object-type lookup are DIFFERENT predicates than `RoleCoversType`; if they ever
diverge, `tuplesForTarget` returns `INTERNAL` ("tuple emission inconsistent with
role coverage") and the writer-tx rolls back. Fail-closed is deliberate — never
persist a target row without a backing FGA tuple (a quiet privilege gap where the
grant is declared but Check denies).
