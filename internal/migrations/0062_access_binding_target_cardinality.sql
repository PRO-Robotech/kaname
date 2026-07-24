-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- DB-level mirror of domain.MaxTargetResourcesPerBinding (ban #10 — a within-service
-- invariant lives on the DB, not only in a software pre-check).
--
-- WHY: AccessBinding.target (migration 0055) carries the per-object selection
-- {"resources":[{"type":…,"id":…}, …]}. The reconciler intersects EVERY rule-matched
-- object with that set through a LINEAR membership scan (domain.AccessTarget.Contains),
-- inside the synchronous create writer-tx that holds the binding advisory lock, and
-- re-runs it for every object created cluster-wide (the forward fast-path). An
-- unbounded resources[] therefore costs |matched| × |target| comparisons on a hot path
-- and stores an unbounded (TOASTed) JSONB row. The API rejects >256 sync with
-- INVALID_ARGUMENT; this CHECK is the backstop for any raw-SQL / fixture / future
-- writer that bypasses the use-case, so the bound cannot silently drift.
--
-- Shape-tolerant by construction: the predicate only fires when target->'resources'
-- IS an array, so the whole-anchor {"allInScope":true} rows (and the column DEFAULT)
-- pass untouched.
--
-- ADD … NOT VALID + VALIDATE in one migration: NOT VALID takes only a brief
-- ACCESS EXCLUSIVE lock (no full-table scan under it) and VALIDATE re-checks existing
-- rows under a weaker SHARE UPDATE EXCLUSIVE lock. No pre-F8 row can violate it (they
-- were backfilled to allInScope), so validation is a formality that keeps the
-- constraint trusted by the planner.
ALTER TABLE kacho_iam.access_bindings
  ADD CONSTRAINT access_bindings_target_resources_card_ck
  CHECK (
    jsonb_typeof(target -> 'resources') <> 'array'
    OR jsonb_array_length(target -> 'resources') <= 256
  ) NOT VALID;

ALTER TABLE kacho_iam.access_bindings
  VALIDATE CONSTRAINT access_bindings_target_resources_card_ck;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE kacho_iam.access_bindings
  DROP CONSTRAINT IF EXISTS access_bindings_target_resources_card_ck;
-- +goose StatementEnd
