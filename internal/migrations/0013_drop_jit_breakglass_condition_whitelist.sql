-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0013_drop_jit_breakglass_condition_whitelist.sql — drop the two deprecated,
-- unenforceable condition kinds from the access_binding_conditions whitelist.
--
-- ban #5: new migration, never edits an applied one (0001 stays untouched).
--
-- ─── Problem ───────────────────────────────────────────────────────────────
-- The baseline (0001) CHECK `access_binding_conditions_expression_whitelist_ck`
-- still admits two condition kinds that no longer have a working runtime path:
--
--   * `jit_window`         — orphaned after the JIT/PIM pipeline removal.
--                            No flow ever sets the
--                            `activated_at` context the predicate needs, so a
--                            binding carrying it could never gate on real state
--                            — an unenforceable half-feature. The companion
--                            built-in (BREAK_GLASS_WINDOW) was already
--                            deprecated in the evaluator; JIT_WINDOW now mirrors
--                            it (rejected at evaluation, fail-closed).
--   * `break_glass_window` — removed with RBAC v2; the break-glass
--                            tables were dropped in 0006 but the kind lingered
--                            in this whitelist.
--
-- Leaving them in the CHECK lets unenforceable conditions be inserted, which is
-- a fail-OPEN footgun (a binding gated only on a kind that can never evaluate
-- true would, post-evaluator-fix, be rejected — but should never have been
-- storable in the first place).
--
-- ─── Fix ───────────────────────────────────────────────────────────────────
--   1. Forward-only data cleanup: DELETE any existing access_binding_conditions
--      rows carrying the two dropped kinds. The parent AccessBinding's
--      `condition_id` FK is `ON DELETE SET NULL` (0001 access_bindings_condition_fk),
--      so the binding survives with no condition (it loses an unenforceable
--      gate — fail-safe). Without this, re-attaching the tighter CHECK would
--      fail on any such pre-existing row.
--   2. Rebuild the CHECK without `jit_window` / `break_glass_window`, keeping the
--      five live kinds (mfa_fresh / non_expired / source_ip_in_range /
--      business_hours / device_compliant).
--
-- All three steps run in one goose transaction so a failure rolls everything
-- back atomically (ban #10 — DB-level invariants).
--
-- Idempotent: re-running after a DELETE on goose_db_version completes without
-- error (DELETE is naturally idempotent; DROP CONSTRAINT IF EXISTS + ADD).

-- +goose Up
-- +goose StatementBegin
DELETE FROM kacho_iam.access_binding_conditions
 WHERE expression IN ('jit_window', 'break_glass_window');

ALTER TABLE kacho_iam.access_binding_conditions
    DROP CONSTRAINT IF EXISTS access_binding_conditions_expression_whitelist_ck;

ALTER TABLE kacho_iam.access_binding_conditions
    ADD CONSTRAINT access_binding_conditions_expression_whitelist_ck
    CHECK (expression = ANY (ARRAY[
        'mfa_fresh'::text,
        'non_expired'::text,
        'source_ip_in_range'::text,
        'business_hours'::text,
        'device_compliant'::text
    ]));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Symmetric DDL rollback: restore the original 7-kind whitelist (matching the
-- 0001 baseline). Data deleted in the Up step is NOT restored — the dropped
-- rows were unenforceable conditions, not recoverable state.
ALTER TABLE kacho_iam.access_binding_conditions
    DROP CONSTRAINT IF EXISTS access_binding_conditions_expression_whitelist_ck;

ALTER TABLE kacho_iam.access_binding_conditions
    ADD CONSTRAINT access_binding_conditions_expression_whitelist_ck
    CHECK (expression = ANY (ARRAY[
        'mfa_fresh'::text,
        'non_expired'::text,
        'source_ip_in_range'::text,
        'break_glass_window'::text,
        'jit_window'::text,
        'business_hours'::text,
        'device_compliant'::text
    ]));
-- +goose StatementEnd
