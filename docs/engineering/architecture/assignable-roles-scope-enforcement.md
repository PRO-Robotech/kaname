# Assignable roles + AccessBinding.Create scope-enforcement

By-design notes for the assignable-roles backend. These are deliberate design
decisions, not bugs — recorded as an architecture note rather than an issue.

## Single source-of-truth predicate (`domain.IsRoleAssignable`)

`internal/domain/role_scope.go` defines `IsRoleAssignable(role, resourceType,
resourceID)` — the **one** definition of "which roles may be bound on a
resource". It is shared verbatim by:

- `AccessBindingService.ListAssignableRoles` — the repo `Reader.ListAssignable`
  WHERE filter is the SQL mirror of the predicate; and
- `AccessBinding.Create` — `doCreate` enforces it before the binding INSERT.

This guarantees **list⇔create parity**: the assignable-set the UI shows is
exactly the set Create accepts. A direct gRPC call / deep-link cannot create a
binding the picker would not have offered (no bypass).

### STRICT matrix

| resource | SYSTEM role | ACCOUNT-scoped role | PROJECT-scoped role |
|---|---|---|---|
| `account acc-A` | ✅ | ✅ iff `account_id == acc-A` | ❌ |
| `project prj-P` | ✅ | ❌ (no hierarchy-down) | ✅ iff `project_id == prj-P` |
| `cluster …root` | ✅ | ❌ | ❌ |

- An account-role is **not** assignable on its own projects — STRICT, no
  hierarchy-down in v1 (additive follow-up). Note: role-scope (what may be
  bound) is **not** the account→project authz inheritance at FGA evaluation
  time — that is a separate concern, untouched here.
- The legacy `organization_id` role scope is ignored; `ScopeGroup` is one
  of `SYSTEM / ACCOUNT / PROJECT` only.

## Create is scope-authoritative

`AccessBinding.Create` is authoritative on role-vs-resource scope (not just role
existence via `access_bindings_role_fk`): it runs the `IsRoleAssignable` check in
the async worker (`doCreate`), **before** the binding INSERT and inside the same
writer-tx as the role read.

A mis-scoped role surfaces as **`Operation.error.code = FAILED_PRECONDITION`**
(message `"role <id> is not assignable on <type>:<id>"`) — the async contract is
preserved (ban #9 — mutations return `Operation`): Create keeps ONE error surface
(`Operation.error`), not a second sync class. The binding is never written (tx
rolls back).

A **non-existent** role on Create is **also `FAILED_PRECONDITION`** — the early
role-read (added for the scope check) explicitly maps role-not-found to
`FailedPrecondition`, matching the `access_bindings_role_fk` RESTRICT INSERT
(which raises 23503 → FailedPrecondition). Without that mapping the early read
would surface the role's raw `NotFound` and silently change the missing-role error
code from 9 to 5. Guarded by `TestCreate_RoleMissing_FailedPrecondition` (and
black-box `IAM-ACB-CR-NEG-ROLE-MISSING`).

## ListAssignableRoles malformed resource_id — 400 vs 403 layering

`ListAssignableRoles` validates `resource_id` format as its **first** statement
(→ `InvalidArgument`/400), asserted directly at the use-case level by an
integration test. **End-to-end through the api-gateway**, however, the per-RPC
authz interceptor runs **before** the handler: being a resource-scoped RPC, it
extracts the (malformed) `resource_id` as the FGA scope object and the `Check`
fail-closes (no grant-authority on an unresolvable object) →
`PERMISSION_DENIED`/403. Both are correct — 400 is the format contract, 403 is the
security layer legitimately pre-empting it (defense-in-depth: you cannot be
authorized on a malformed scope). The black-box newman case therefore accepts
**400 or 403** (same flexibility as `IAM-ACB-GT-NEG-ID-MALFORMED`'s 400-or-404).
The strict 400 contract still holds where it is reachable (direct use-case /
gRPC), which the integration test pins.

### No DB CHECK / no TOCTOU

The parity invariant is a use-case JOIN-predicate (role-scope vs resource), not
a single-row CHECK, so it is **not** expressed as a DB constraint. It is still
race-free: the predicate reads the role's **immutable** scope columns + the
target (type, id) — it does not depend on the state of other bindings, so there
is no TOCTOU window by design. A concurrent-non-regression integration test
(`TestCreate_ScopeEnforcement_ConcurrentMisScoped_BothRejected`, 2 goroutines)
proves both concurrent mis-scoped Creates fail and no binding is written.

## Forward-only enforcement

Enforcement gates **only new Create**. There is deliberately:

- **no migration-time revoke** — pre-existing mis-scoped bindings are left active;
- **no read-time hiding** — `ListByResource` / `ListSubjectPrivileges` keep
  showing legacy mis-scoped bindings;
- **no retro-filter** — `ListAssignableRoles` answers "what can be bound now",
  not "what is already bound";
- **Delete ungated** — a legacy mis-scoped binding is revocable as before.

Rationale: a retroactive revoke/hide would silently strip operators' existing
access. Same spirit as the cross-domain graceful dangling-ref rule: the system
**survives** previously-valid-now-mismatched rows. Cleaning up legacy mis-scoped
bindings is a separate, explicit data-cleanup decision — never a side effect of
turning enforcement on. Verified by
`TestCreate_ForwardOnly_LegacyMisScopedSurvives`.

## roleCols projection

`role_repo.go` `roleCols` (and `RoleReadAdapter.Get`) select
`cluster_id, project_id` in addition to `account_id`, so a role read populates
the full `domain.Role` scope the predicate needs. A regression test
(`TestRole_RoleColsRegression_ScopeFieldsPopulated`) pins their presence — an
earlier projection omitted them, leaving `ClusterID`/`ProjectID` empty after a
read.
