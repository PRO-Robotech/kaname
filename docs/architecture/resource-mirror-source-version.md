# resource_mirror — monotonic `source_version`

Records the design decision that makes `kacho_iam.resource_mirror`
**last-source-state-wins** instead of last-applier-wins.

## Problem

`resource_mirror` is an OUTPUT-ONLY mirror of the labels + parent-scope of
resources owned by another service (compute-first), fed PUSH-style over the
`compute→iam` FGA-proxy edge (`RegisterResource` / `UnregisterResource`,
Internal-only :9091, at-least-once via the transactional outbox +
register-drainer).

The original UPSERT was an unconditional `ON CONFLICT … DO UPDATE` — **last
APPLIER wins**. Under an HA register-drainer two register-intents for ONE object
can be applied out of order (replica B applies v2, then replica A applies a stale
v1): the mirror was overwritten with stale labels. Symmetrically a Delete-after-
Update reorder could let a stale tombstone wipe a fresher row.

Benign while the mirror is not read for an authz decision, but it must be
**last-source-state-wins** before the label-selector mechanism starts reading it
(see `resource-scoped-access-binding-gamma.md`).

## Decision: monotonic `source_version` stamped at the source

- **Source marker = intent-emit `now()`** (the DB clock at the instant the
  `compute_fga_register_outbox` intent row is INSERTed, inside the SAME writer-tx as
  the resource mutation). Carried in the intent payload (`source_version`) and
  forwarded as `RegisterResourceRequest.source_version` /
  `UnregisterResourceRequest.source_version` (proto field 8, additive).
- **Why not `instance.updated_at`?** compute resource tables (`instances`/`disks`/
  `images`/`snapshots`) have **no `updated_at` column** — only `created_at`. The
  intent-emit `now()` is the exact instant the source-state is recorded and is
  monotonic per-object for sequential mutations (a later mutation's tx commits-after
  the earlier one's, so its `now()` is strictly greater). It is the correct,
  least-invasive marker and needs no schema change on the resource tables.
- **IAM mirror** (`migration 0019`):
  `source_version TIMESTAMPTZ NOT NULL DEFAULT '-infinity'`.
  - `UpsertTx`: `ON CONFLICT … DO UPDATE … WHERE resource_mirror.source_version <
    EXCLUDED.source_version` — a stale/equal register updates 0 rows (no-op, not an
    error: at-least-once OK); newer applies and advances the version.
  - `DeleteTx`: `DELETE … WHERE source_version <= $tombstone` — a stale tombstone
    (older than the stored register) is a no-op, so a Delete-after-Update reorder
    cannot wipe a fresher row.
- **Back-compat**: an empty/nil proto `source_version` (legacy producer) maps to
  `'-infinity'`, so the old unconditional last-write is preserved during rollout
  (the producer is upgraded atomically — register & unregister carry the version
  together).

## Residual edge — resolved by the reconcile-sweep (documented, not a tombstone)

One reorder is NOT fully closed by the conditional UPSERT/DELETE alone: a **stale
register arriving AFTER an unregister**. The row is already gone, so `ON CONFLICT`
finds no conflict and INSERTs — resurrecting a dangling row with stale labels.

Chosen production-grade minimum: **do NOT add a tombstone table**. The mirror is
not read for an authz decision here, and a dangling row is the same
tolerated-dangling case the design already accepts (the owner object vanishing
without an Unregister). The **reconcile-sweep** (see
`resource-scoped-access-binding-gamma.md`) reconciles the mirror against the owner
and removes any dangling row. A tombstone (+ its GC) would add carrying cost for a
benign, sweep-handled edge and is deliberately deferred.

This is strictly better than the unconditional last-write (which lost fresh labels
on the *common* register-reorder and wiped rows on Delete-after-Update); the only
residual is the rarer stale-register-after-delete, which the reconcile-sweep
already handles.

## Tests

- IAM (`internal/repo/kacho/pg/resource_mirror/emitter_integration_test.go`,
  testcontainers): stale register → no-op (v2 kept); same-version repeat → no-op;
  newer register applies + advances version; stale tombstone does not wipe a fresh
  row; fresh tombstone removes the row.
- compute (`internal/repo/fga_register_mirror_integration_test.go`): Create then
  Update-on-labels stamp a strictly-increasing monotonic `source_version`;
  Delete stamps a tombstone-version `>=` the register.
