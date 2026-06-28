# Recovery completion vs the multi-account uniqueness schema

By-design note for `InternalUserService.OnRecoveryCompleted`. Resolves a
discrepancy between an early design assumption and the actual uniqueness schema.

## The discrepancy

An early design reasoned about which multi-account states a single Kratos identity
(`external_id`) can occupy by citing only the **per-Account** uniqueness:

```
users_account_external_id_unique  UNIQUE (account_id, external_id) WHERE external_id <> ''
```

It **missed** migration `0011_users_drop_global_email_uniqueness.sql`, which adds a
stricter **GLOBAL** partial unique index:

```sql
CREATE UNIQUE INDEX users_active_external_id_uniq
    ON kacho_iam.users (external_id)
    WHERE invite_status = 'ACTIVE' AND external_id <> '';
```

## What the global guard actually allows

`users_active_external_id_uniq` enforces **at most one ACTIVE row per `external_id`,
globally** — but it does **not** restrict BLOCKED (or PENDING) rows. So:

| Multi-account state for one `external_id`           | Reachable? | Why |
|------------------------------------------------------|------------|-----|
| Two **ACTIVE** rows (different Accounts)             | **No**     | `users_active_external_id_uniq` forbids it (the "two-ACTIVE" premise is **unreachable**). |
| One **ACTIVE** (Account A) + one **BLOCKED** (Account B) | **Yes**    | BLOCKED rows are not covered by the partial index — both rows can coexist. |
| One **BLOCKED** + one **PENDING** (`external_id=''`) | **Yes**    | PENDING carries `external_id=''` (CHECK `users_invite_status_consistency`); not matched by `external_id`. |

So the "two-ACTIVE" premise is **impossible**. The genuinely reachable
multi-account collision case is **BLOCKED + ACTIVE across Accounts**.

## How recovery handles BLOCKED + ACTIVE across Accounts

Recovery matches the identity's ACTIVE/BLOCKED rows by `(external_id, email)` and, in
**one writer-tx**, re-enables each matched row (BLOCKED → ACTIVE), then revokes all of
the identity's live sessions and emits one audit row. Re-enabling a BLOCKED row beside
an already-ACTIVE sibling collides with `users_active_external_id_uniq` and raises
SQLSTATE `23505` (→ `ErrAlreadyExists`).

A raw `23505` inside a bare transaction aborts it (`25P02`), which would make every
subsequent statement (revoke / audit / commit) fail. But the security goal of recovery
is to **revoke the identity's old sessions even when one row's re-enable collides** —
the identity already has its canonical ACTIVE presence via the sibling. To make that
degradation possible on the real schema, each per-row re-enable is bounded by a
**SAVEPOINT**:

1. `SAVEPOINT sp_reenable` before each `ReEnable`.
2. On success → `RELEASE SAVEPOINT sp_reenable`.
3. On `ErrAlreadyExists` (the global-guard collision) → `ROLLBACK TO SAVEPOINT
   sp_reenable` (the tx is usable again), skip this row (it stays BLOCKED), continue.
4. Any other error → propagate (full rollback).

After the loop, revoke-all + audit run on the now-clean tx and the whole Operation
commits. Net effect for the BLOCKED+ACTIVE-across-accounts case: the colliding
BLOCKED row stays BLOCKED, but every matched row gets a revoke-all cutoff and exactly
one audit row commits.

The SAVEPOINT primitives live in the pg adapter (`internal/repo/kacho/pg/tx.go`,
exposed via the `kacho.Writer` port) so the use-case stays pgx-free. Savepoint names
are static literals (`sp_reenable`), validated by `safeSavepointName` — never user
input.

## Tests

- `internal/repo/kacho/pg/recovery_completions_integration_test.go`
  - `TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll` — canonical
    BLOCKED + PENDING-sibling multi-account shape.
  - `TestOnRecoveryCompleted_S09b_BlockedActiveAcrossAccounts_SkipReEnable_StillRevokeAudit`
    — the reachable BLOCKED + ACTIVE-across-accounts collision: re-enable skipped,
    revoke-all + audit still commit (fails without the SAVEPOINT handling, passes with it).
- `internal/repo/kacho/pg/user_reenable_concurrent_integration_test.go`
  - `TestUserReEnable_ConcurrentCAS_ExactlyOneWasBlocked` — N goroutines drive
    `ReEnable` directly; exactly one observes `wasBlocked=true`, proving the
    `UPDATE … FROM (SELECT … FOR UPDATE)` row-lock serializes.
