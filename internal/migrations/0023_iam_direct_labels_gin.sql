-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- The iam-direct selector feed: the
-- reconciler's MatchIAMDirect probes IAM's OWN tables SAME-DB with a JSONB
-- containment predicate — `WHERE labels @> $1::jsonb` — over kacho_iam.projects
-- AND kacho_iam.accounts (reconcile_adapter.go MatchIAMDirect). Without a GIN
-- index on the labels column that probe is a SEQ-SCAN of the whole table on every
-- selector-binding reconcile pass (and on every Project/Account label-change
-- event fan-out). As the tenant population grows this is the reconciler's
-- hot-path cost.
--
-- GIN with jsonb_path_ops is the operator-class purpose-built for the `@>`
-- containment operator (smaller, faster index than the default jsonb_ops; it does
-- NOT support key-existence `?`/`?|`/`?&`, which MatchIAMDirect never uses). This
-- mirrors the existing organizations_labels_gin (0001_initial.sql) and
-- resource_mirror_labels_gin (0019_resource_mirror.sql) — parity across every
-- labels-@>-probed table.
--
-- Read-side only (the index serves SELECT … @>); Create paths are unaffected.

CREATE INDEX projects_labels_gin ON kacho_iam.projects USING gin (labels jsonb_path_ops);
CREATE INDEX accounts_labels_gin ON kacho_iam.accounts USING gin (labels jsonb_path_ops);

-- +goose Down

DROP INDEX IF EXISTS kacho_iam.projects_labels_gin;
DROP INDEX IF EXISTS kacho_iam.accounts_labels_gin;
