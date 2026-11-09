<!-- Copyright (c) PRO-Robotech; SPDX-License-Identifier: AGPL-3.0-or-later -->
# Installation assignments for account registration writers

The acceptance contract is [account-scoped-registration-writer](../acceptance/account-scoped-registration-writer.md).
Its independent review receipt is recorded under `docs/specs/reviews/account-scoped-registration-writer/`.
This implementation document is not execution evidence.

Production must explicitly declare the complete finite assignment list:

```yaml
registration-account-writers:
  assignments:
    - assignment_id: installation-registry-account-a-1
      account_id: <existing-account-id>
      module: registry
  disabled: []
  retire-cluster-writer: false
```

The Helm value is `registrationAccountWriters` with the same nested fields.
There is no default and no implicit enrollment when an account is created.
An installation intentionally enabling no registrars declares `assignments: []`.
The AuthN module roster is the existing `authn.module-identities` with its existing
issuer bindings; no additional SAN allowlist is introduced.

Before first switching an existing installation, close registration ingress (or
route it exclusively to the new revision). Inventory all current registrations.
For every canonical account/module pair either declare an assignment or record
an explicit operator decision in `disabled: [{account_id: ..., module: ..., reason: ...}]`.
The first application reports all missing assignments and invalid pairs and rolls
back the whole batch. That inventory is a first-switch requirement; retained
objects after an intentional revocation do not create a recurring startup gate.
The switch receipt persists the disabled exceptions.

Every assignment produces a regular system AccessBinding on the account with
one module service account subject, `granted_relation=fga_writer`, no role, and
deletion protection. Get/List expose it through the existing AccessBinding API.
Its subjects, emitted tuple ledger, relation outbox, subject-change event and
audit commit together. It does not grant account administration to the module.

To revoke, use the existing authorized Update/Revoke/Delete lifecycle. Removing
an assignment from the complete installation list also revokes it: the privileged
installation step clears protection only on its ledger-owned binding, obtains
the existing deactivation locks, and withdraws the persisted emitted set in the
same transaction. Any failure rolls back the plan. Other assignments survive.
The application identity ledger has no cascading reference to the binding.
Consequently a restart, deletion, reapplication or readdition of the old ID never
recreates a revoked assignment. An intentional reauthorization uses a new
`assignment_id`; changing coordinates of an existing ID is refused.

After verifying Get/List for the new assignments, confirming that ALL replicas
serving registration enforce the account contract and checking AW-01/AW-03,
set `retire-cluster-writer: true`. This one-way operator switch revokes the
historical system `module-relation-writers` cluster binding with its full emitted
set. The forward schema retains the compatibility group for existing joins;
the service manifest has an explicitly empty seed and creates no blanket grant.
Retirement ownership is persisted from the actual baseline group/account/binding
lineage and the canonical cluster anchor, independent of mutable group names.
One identity predicate is shared by selection, locked recheck and the DB fence;
foreign same-name groups and non-singleton coordinates are outside it.
A persistent schema fence refuses any attempt by the old seed writer to recreate
this specific retired blanket during binary rollback.
The complete old seed first upserts `system/module-relation-writers`, which can
mint a new ID after rename or deletion. A separate namespace fence reserves only
that proven legacy seed name in the immutable installation account after
retirement. It rejects the complete old UpsertGroup/GrantRelation transaction;
foreign tenant accounts with the same group name remain unaffected. This fence
does not adopt groups for revocation. If that installation namespace was already
recreated under another ID before retirement, application refuses completion
until the installation administrator resolves that group; it does not silently
revoke an unproven assignment. Namespace/grant writers and retirement share a
transaction advisory lock to close concurrent seed/retirement orderings.
Old binary startup may therefore fail on its retired seed. Rollback still keeps
registration ingress closed; this is a fail-closed rollback, not restored service.
The forward migration adds the assignment
and switch ledgers; historical migrations are untouched. New installs follow the
same migrations and receive zero account writer rights until the explicit plan.

Registration derives authority from the admission result inside its writer
transaction. Every compatible canonical hierarchy contributes an account;
distinct accounts are all checked before writes. Request account claims never
select authority. Applied registrations persist their derived canonical scope
separately from optional client claims; cleanup and publication therefore resolve
a registration even when the module omitted every parent field. Audit and backfill reuse the admission result rather than
reading the catalog/project again. The forward migration backfills legal legacy
registrations from catalog-declared pointer facts (including omitted claims);
first-switch census and runtime legacy reads use that same canonical resolver. Unregister and publication resolve their own
saved scope before any mutation. A permanent project binding remains a valid
source for an idempotent repeated unregister while the project is resolvable.
An unknown/lost scope is PermissionDenied, with no tombstone or cleanup writes.
All paths independently require the real roster module identity and an account
checker; dev mode and direct use-case invocation cannot bypass them.

A rollback to a version without account enforcement must keep registration
closed. Do not restore the blanket or remove account grants/assignment history.
The migration is explicitly irreversible: Down fails without changing its
bookkeeping or assignment history. Recover service using a corrected new binary. A partial rolling deployment is
not a safe boundary: any old serving replica can still admit blanket writers.

Validation must include the real mTLS/production identity path, bootstrap/Get/List,
normal revoke/delete, same-SHA lawful/refused twins, DP/PB compatibility, all
publication/cleanup branches, fast redelivery, clean installation, first upgrade,
restart and rollback. The implementation tests are not a runtime approval.
