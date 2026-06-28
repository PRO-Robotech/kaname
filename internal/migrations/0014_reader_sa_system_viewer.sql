-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0014_reader_sa_system_viewer.sql — seed the legitimate
-- internal-reader module ServiceAccounts a cluster-level read-only relation
-- `system_viewer@cluster:cluster_kacho_root` so they pass the
-- authzguard.SystemViewerFloor on the :9091 READ-RPCs in production-mode.
--
-- Reader SAs seeded here: api-gateway, vpc, compute. They have NO existing
-- cluster relation (SEC-C 0009 gave only fga_writer to vpc/compute/nlb; the
-- api-gateway SA was identity-only). Without this tuple they would fail the
-- floor in prod and every internal READ-RPC they make would PermissionDenied.
--
--   - api-gateway — fronts admin-UI / forwarded user reads on :9091
--     (ListByUser, ReadTuples, GetFGAStoreInfo, LookupSubject, …).
--   - vpc / compute — service→service reader edges (LookupSubject /
--     InternalUserService.Get etc.). compute is seeded forward-looking
--     (least-priv read-only, harmless): its current edges (ProjectService.Get,
--     InternalIAMService.Check) are NOT in the floor set, but the seed covers
--     any future internal-READ call without a follow-up migration.
--
-- vpc-operator is NOT seeded here — it already holds
-- system_viewer@cluster:cluster_kacho_root from SEC-L migration 0010.
-- This keeps 0014's down migration scoped to exactly its
-- own 3 intents and avoids a duplicate intent-row. Should it ever be re-added,
-- ON CONFLICT DO NOTHING makes it a no-op.
--
-- Least-priv: ONLY `system_viewer` (a read relation) — no
-- editor/admin/owner/fga_writer. cluster.system_viewer is [user,
-- service_account] with NO `user:*` wildcard (FGA model), so the
-- relation has zero mutation capability and zero over-exposure risk.
--
-- ban #5: NEW migration, never edits applied ones (0009/0010 stay untouched).
--
-- Mirrors 0010 byte-for-byte: an FGA relation-tuple enqueued via
-- kacho_iam.fga_outbox; the drainer applies it to OpenFGA idempotently (same
-- payload shape, same ON CONFLICT DO NOTHING). The sva-id is the same
-- deterministic expression as 0009/0010
-- ('sva'||substr(md5('kacho-<svc>'),1,17)) so the subject matches the floor's
-- ServiceAccountIDForService exactly.

-- +goose Up
-- +goose StatementBegin
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'service_account:' || ('sva' || substr(md5('kacho-api-gateway'), 1, 17)),
     'relation', 'system_viewer',
     'object',   'cluster:cluster_kacho_root'),
   now()),
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'service_account:' || ('sva' || substr(md5('kacho-vpc'), 1, 17)),
     'relation', 'system_viewer',
     'object',   'cluster:cluster_kacho_root'),
   now()),
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'service_account:' || ('sva' || substr(md5('kacho-compute'), 1, 17)),
     'relation', 'system_viewer',
     'object',   'cluster:cluster_kacho_root'),
   now())
ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM kacho_iam.fga_outbox
 WHERE payload->>'relation' = 'system_viewer'
   AND payload->>'object'   = 'cluster:cluster_kacho_root'
   AND payload->>'user' IN (
     'service_account:' || ('sva' || substr(md5('kacho-api-gateway'), 1, 17)),
     'service_account:' || ('sva' || substr(md5('kacho-vpc'),         1, 17)),
     'service_account:' || ('sva' || substr(md5('kacho-compute'),     1, 17)));
-- +goose StatementEnd
