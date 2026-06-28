-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0012_user_token_revocations.sql — user-level ("revoke-all-before") token
-- revocation marker. Backs admin ForceLogout + Revoke(revoke_all_user_tokens).
--
-- ban #5: new migration, never edits an applied one (0001 baseline untouched).
--
-- ─── Problem ───────────────────────────────────────────────────────────────
-- The session_revocations table is keyed by the EXACT token jti (PK token_jti)
-- and the refresh-hook gate denies via `WHERE token_jti = $1` against the live
-- token's real jti. That gate can only deny a SINGLE, already-known jti.
--
-- Admin ForceLogout(user) and Revoke(revoke_all_user_tokens=true) must deny ALL
-- of a user's currently-live refresh tokens — but they do not know the jti of
-- every live token. The previous implementation wrote a SYNTHETIC jti
-- ("force-logout:<user>:<unixnano>") that the real token's jti can never match,
-- so the gate was INERT: the target's refresh tokens kept working while the RPC
-- reported success (silent false-success — worse than failing loud).
--
-- ─── Fix ───────────────────────────────────────────────────────────────────
-- A per-user "revoke-before" marker: any token whose originating session
-- authenticated at or before `revoke_before` is denied at refresh. The
-- refresh-hook compares the Hydra session `auth_time` against this cutoff; once
-- the user re-authenticates, `auth_time` advances past the cutoff and new
-- sessions are allowed again (no permanent lockout).
--
-- One row per user (PK user_id). Idempotent upsert that only ever advances the
-- cutoff (GREATEST) so concurrent / repeated revocations never roll the cutoff
-- backwards (ban #10 — invariant on the DB, monotonic via GREATEST inside the
-- single-statement upsert, serialized by the PK row-lock).
--
-- FK user_id -> users(id) ON DELETE CASCADE: a user-level marker is meaningless
-- once the user-row is gone, and cascading keeps it same-schema-consistent.
--
-- New table on a fresh column-set — holds trivially for existing rows (none).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE kacho_iam.user_token_revocations (
    user_id            text        NOT NULL,
    revoke_before      timestamptz NOT NULL,
    reason             text        NOT NULL DEFAULT '',
    revoked_by_user_id text,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_token_revocations_pkey PRIMARY KEY (user_id),
    CONSTRAINT user_token_revocations_reason_check
        CHECK (length(reason) <= 256),
    CONSTRAINT user_token_revocations_revoked_by_check
        CHECK ((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64)),
    CONSTRAINT user_token_revocations_user_fk
        FOREIGN KEY (user_id) REFERENCES kacho_iam.users (id) ON DELETE CASCADE
);

COMMENT ON TABLE kacho_iam.user_token_revocations IS
    'Per-user revoke-all-before cutoff. Refresh-hook denies a token whose session auth_time <= revoke_before. Backs admin ForceLogout + Revoke(revoke_all_user_tokens).';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.user_token_revocations;
-- +goose StatementEnd
