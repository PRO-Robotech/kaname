-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0010_sec_l_operator_system_viewer.sql — SEC-L: seed the kacho-vpc-operator
-- ServiceAccount a cluster-level read-only relation so AccountService.List /
-- ProjectService.List (now FGA-relation-driven) return ALL accounts/projects
-- to the operator's ns-syncer fan-out.
--
-- ban #5: new migration, never edits applied ones (0009 stays untouched).
--
-- Mirrors migration 0009 section 5 byte-for-byte: an FGA relation-tuple enqueued via
-- kacho_iam.fga_outbox; the drainer applies it to OpenFGA idempotently (same
-- payload shape, same ON CONFLICT DO NOTHING).
--
-- The relation is `system_viewer` (NOT `viewer`): cluster.system_viewer is
-- [user, service_account] with NO `user:*` wildcard, so an arbitrary
-- user:<rando> principal can NEVER satisfy the new
-- `account.viewer/project.viewer ... or system_viewer from cluster` cascade
-- (over-exposure guard). The operator SA, seeded here, DOES match and
-- thus resolves viewer on every account/project carrying the `#cluster`
-- parent-tuple (written on Create).
--
-- The operator SA row itself already exists (0009 section 2); only the relation-tuple
-- is new. Object is the singleton cluster:cluster_kacho_root, the same
-- root used by SEC-C cluster-scope AccessBindings. The operator-SA id is the
-- same deterministic expression as 0009 ('sva'||substr(md5('kacho-vpc-operator'),1,17))
-- so the subject matches exactly.

-- +goose Up
-- +goose StatementBegin
INSERT INTO kacho_iam.fga_outbox (event_type, payload, created_at) VALUES
  ('fga.tuple.write',
   jsonb_build_object(
     'user',     'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17)),
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
   AND payload->>'user'     = 'service_account:' || ('sva' || substr(md5('kacho-vpc-operator'), 1, 17));
-- +goose StatementEnd
