-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0073_list_cursor_indexes.sql — give every paged listing in this service the access
-- path its cursor asks for.
--
-- THE SHAPE. Every public listing here orders by (created_at, id) and resumes with
-- `(created_at, id) > ($ts, $id)`. That is the platform's cursor convention and it is
-- correct. What was missing is the other half of it: not one of the eight tables it
-- runs over carried an index on those columns, so the planner had no ordered path at
-- all — each page is a sequential scan plus a top-N sort of everything that survived
-- the filter, and the cursor, whose whole purpose is to make page N cost the same as
-- page 1, saved only the rows it excluded.
--
-- WHERE IT BITES HARDEST, and why the ones that hurt less still get an index:
--   * access_bindings — the canonical unfiltered read. Its only mandatory predicate is
--     `status <> 'REVOKED'`, which no index serves, and the listing deliberately reads
--     the page BEFORE narrowing it to what the caller may see — so a caller entitled to
--     one row pays for the whole table, every page.
--   * accounts — the root of tenancy, and its listing has no mandatory predicate at
--     all. It is polled by an out-of-tree operator, page after page.
--   * users / groups / projects / service_accounts carry account_id, which is indexed,
--     so they are bounded in the common case — but only when the caller passes it, and
--     the sort still runs. roles carries a disjunction (`is_system OR account_id = $1`)
--     that no single index serves.
-- The class is "ordered by a cursor with no matching index", so it is closed by
-- measuring the tree for that shape rather than by picking the two that hurt today.
--
-- Not a hypothetical: this service is on the request path of every other one, and a
-- scan holds its pool connection for the whole of it. The neighbours already carry
-- these indexes (vpc on seven tables, storage on four, registry as an explicit
-- composite); iam was the outlier, not the rule.
--
-- COST. Eight B-trees on (created_at, id) over narrow rows. created_at is
-- monotonic, so inserts land at the right edge and the write amplification is one
-- page per index. No index here is UNIQUE and none changes any invariant — they are
-- access paths only.
--
-- CONCURRENTLY is deliberately NOT used: goose runs a migration in a transaction, and
-- CREATE INDEX CONCURRENTLY cannot run inside one. These tables are small at the time
-- this lands (the platform is pre-production), so the brief ACCESS SHARE-blocking
-- build is the right trade against splitting the migration out of the chain.

-- +goose Up
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS access_bindings_cursor_idx
    ON kacho_iam.access_bindings (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS accounts_cursor_idx
    ON kacho_iam.accounts (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS projects_cursor_idx
    ON kacho_iam.projects (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS users_cursor_idx
    ON kacho_iam.users (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS groups_cursor_idx
    ON kacho_iam.groups (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS roles_cursor_idx
    ON kacho_iam.roles (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS service_accounts_cursor_idx
    ON kacho_iam.service_accounts (created_at, id);
-- +goose StatementEnd
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS conditions_cursor_idx
    ON kacho_iam.conditions (created_at, id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS kacho_iam.access_bindings_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.accounts_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.projects_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.users_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.groups_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.roles_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.service_accounts_cursor_idx;
DROP INDEX IF EXISTS kacho_iam.conditions_cursor_idx;
-- +goose StatementEnd
