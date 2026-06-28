-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0015_recovery_completions.sql — idempotency ledger for the Kratos
-- password-recovery webhook (InternalUserService.OnRecoveryCompleted).
--
-- ban #5: new migration, never edits an applied one (0001 baseline untouched).
--
-- ─── Problem ───────────────────────────────────────────────────────────────
-- Ory Kratos delivers the recovery-completed webhook AT-LEAST-ONCE: a duplicate
-- delivery of the SAME recovery flow must NOT re-run the recovery side-effects.
-- Re-running is not harmless — the per-user revoke-all cutoff
-- (user_token_revocations) is advanced to a NEW `now`, which would revoke
-- sessions the user legitimately established BETWEEN the first and the duplicate
-- delivery (a monotonicity regression relative to the recovery moment), and the
-- durable audit row would be duplicated.
--
-- ─── Fix ───────────────────────────────────────────────────────────────────
-- Dedup ON THE DB (ban #10), keyed by the Kratos recovery-flow id `recovery_jti`
-- (globally unique per flow). The recovery use-case opens its writer-tx with an
-- `INSERT … ON CONFLICT (recovery_jti) DO NOTHING RETURNING …` as the FIRST
-- step:
--   - 1 row returned  → first time this flow is seen → run re-enable +
--     revoke-all cutoff + audit, all in the SAME tx, then commit.
--   - 0 rows returned → already processed → idempotent no-op: the tx runs NONE
--     of the side-effects and the use-case replays the stored
--     user_id / revoked_session_count from the existing row.
-- The PK row-lock serializes concurrent deliveries of one recovery_jti: exactly
-- one writer wins the INSERT, the rest see 0 rows → no-op (no second cutoff, no
-- duplicate audit). The whole tx commits-together-or-rolls-back-together, so a
-- mid-tx failure leaves NO "stuck" idempotency key (the row rolls back with the
-- side-effects → the flow can be reprocessed on the next delivery).
--
-- The table is GLOBAL (not scoped by account_id): `recovery_jti` is flow-scoped,
-- and one Kratos identity may own N User-rows across N Accounts — a single
-- recovery flow re-enables/revokes the whole identity, so it is one ledger row.
--
-- No FK on user_id: the canonical user-row is resolved by external_id at request
-- time (one identity → N rows); the ledger stores the deterministic primary
-- user_id (first row by created_at ASC) for replay only. revoked_session_count
-- is stored so the idempotent-replay returns the same Operation.metadata.
--
-- New table on a fresh column-set — holds trivially for existing rows (none).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE kacho_iam.recovery_completions (
    recovery_jti          text        NOT NULL,
    external_id           text        NOT NULL,
    user_id               text        NOT NULL,
    revoked_session_count integer     NOT NULL DEFAULT 0,
    completed_at          timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT recovery_completions_pkey PRIMARY KEY (recovery_jti),
    CONSTRAINT recovery_completions_jti_check
        CHECK (length(recovery_jti) BETWEEN 1 AND 128),
    CONSTRAINT recovery_completions_external_id_check
        CHECK (length(external_id) BETWEEN 1 AND 128),
    CONSTRAINT recovery_completions_user_id_check
        CHECK (length(user_id) BETWEEN 1 AND 64),
    CONSTRAINT recovery_completions_count_check
        CHECK (revoked_session_count >= 0)
);

COMMENT ON TABLE kacho_iam.recovery_completions IS
    'Idempotency ledger for the Kratos recovery-completed webhook. PK recovery_jti dedups at-least-once delivery via INSERT … ON CONFLICT DO NOTHING; stores user_id / revoked_session_count for idempotent replay.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.recovery_completions;
-- +goose StatementEnd
