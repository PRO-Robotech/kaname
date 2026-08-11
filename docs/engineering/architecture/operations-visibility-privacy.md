# Operations visibility — privacy model

Status: **by-design** (conscious decision, not a leak).

## Decision: per-scope-viewer, NOT per-creator, for operation *lists*

The IAM operation **list** RPCs gate on **scope viewership**, not on the
identity of who created each operation:

| RPC | Scope gate | Per-creator filter? |
|---|---|---|
| `UserService.ListOperations` / `AccessBindingService.ListOperations` (+ the existing 5: Account/Project/SA/Group/Role) | viewer on the resource (api-gateway permission-catalog, `required_relation:"viewer"`) | **No** |
| `AccountService.ListAllOperations` (account-scoped public) | self (account owner) OR account-admin (FGA `admin@account`) — `requireAccountViewAuthority` | **No** |
| `InternalOperationsService.ListIamOperations` (cluster-wide Internal) | `system_admin@cluster` (in-handler ReBAC Check + gateway catalog) | **No** |
| `OperationService.Get` / `Cancel` (per-id) | ownership-gated per-creator | **Yes** |

So an account-viewer of `acc-X` sees the operations created by **every**
principal inside `acc-X` (including each operation's `principalId` /
`principalDisplayName` — the email/name of the actor). This is intentional
audit visibility ("who changed what inside my account"), not a leak.

### Why this is the right call

1. **Parity with the 5 already-deployed per-resource `ListOperations`.** Those
   never applied a per-creator filter; introducing one for User/AccessBinding or
   the new module feeds would diverge the contract of the existing five (out of
   scope). The list surface is uniform: scope in, all-in-scope out.
2. **`account` is the tenancy boundary.** A member with view authority over an
   account is entitled to the account's audit trail. Cross-account isolation is
   still absolute — the account_id column filter (migration 0016 partial index)
   guarantees `acc-X`'s list never contains `acc-OTHER`'s operations.
3. **The per-id path stays ownership-gated.** `OperationService.Get(opOfAnother)`
   still returns `NotFound` for an operation the caller did not create —
   so the *targeted* lookup of someone else's operation by id is not enabled;
   only the *scoped audit list* surfaces other members' operations.

### What is NOT exposed

- **No cross-account leakage.** account-scoped lists are filtered by the
  denormalized `operations.account_id` column; an op of another account is never
  returned (integration-tested).
- **No infra-sensitive data.** IAM operations carry only tenant-facing intent +
  result (id/description/createdAt/done/metadata with tenant ids); no
  placement/underlay/wiring fields exist on them by construction.
- **Cluster-wide feed is Internal-only.** `InternalOperationsService` is
  registered only on the :9091 internal listener (ban #6) and gated
  `system_admin@cluster` both at the api-gateway catalog and in-handler (a caller
  bypassing the gateway and dialing :9091 directly is rejected).

### account_id scope (which operations appear in the account-scoped list)

`AccountService.ListAllOperations` returns operations whose `account_id` column
is the requested account. `account_id` is stamped at op-build time (corelib
`extractAccountID`, exact field name) only for **category-(I)** metadata:
Account / Project / ServiceAccount / Group CRUD + AddGroupMember/RemoveGroupMember
+ DeleteUser + AccessBinding **when `ResourceType=="account"`** (narrow-scope).

**Category-(II)** operations leave `account_id` NULL and are deliberately absent
from account-scoped lists (visible per-resource + cluster-wide Internal):
cluster-global Role, project/cluster/cross-service AccessBinding,
SAKey-Issue/Revoke and Condition-Create/Update/Delete (narrow-scope),
and the Internal-only op-producers (GrantClusterAdmin / ForceLogout /
WriteTuples / UpsertFromIdentity / OnRecoveryCompleted, session-revocation).
Resolving an owning account for these would require an extra read on the
mutation path (rejected as not cheap).
