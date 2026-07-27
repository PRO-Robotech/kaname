-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0070_conditions_folder_to_project.sql — rename the Condition scope column to
-- the platform's name for that scope.
--
-- `conditions.folder_id` predates the seven-domain redesign and is the last
-- place in the product that still calls a Project a folder. Every other
-- resource in every service names the same reference `project_id`; compute
-- renamed its four tables the same way in 0009_rename_folder_to_project.sql.
-- The public field is renamed in the same change (Condition.project_id,
-- ListConditionsRequest.project_id, CreateConditionRequest.project_id) together
-- with the authorization scope extractor that reads it, so the column, the wire
-- field and the scope the gateway derives all carry one name.
--
-- Strategy, as in compute 0009: ALTER TABLE ... RENAME COLUMN plus ALTER INDEX
-- ... RENAME. Both are metadata-only and instant — Postgres retargets the
-- column references inside an index automatically on RENAME COLUMN, so only the
-- index identifiers need updating. The CHECK constraint is recreated because a
-- constraint's name is not auto-updated and its stored expression text still
-- reads the old column name.
--
-- `resource_version` is deliberately KEPT. It looks like the forbidden
-- Kubernetes envelope field, but it is not on the wire at all: the proto
-- Condition message has no such field and ConditionToProto never sets one. It
-- is the optimistic-concurrency token of the update path — UpdateMutable does
-- `SET resource_version = resource_version + 1 ... WHERE id = $1 AND
-- resource_version = $2` and decides NotFound vs "changed concurrently" from
-- the RETURNING cardinality. Dropping it would replace a compare-and-swap with
-- a blind write.

-- +goose Up
-- +goose StatementBegin

ALTER TABLE kacho_iam.conditions RENAME COLUMN folder_id TO project_id;

ALTER INDEX kacho_iam.conditions_folder_name_uniq  RENAME TO conditions_project_name_uniq;
ALTER INDEX kacho_iam.idx_conditions_folder_status RENAME TO idx_conditions_project_status;

ALTER TABLE kacho_iam.conditions
    DROP CONSTRAINT conditions_folder_id_not_empty;
ALTER TABLE kacho_iam.conditions
    ADD CONSTRAINT conditions_project_id_not_empty CHECK (length(project_id) > 0);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE kacho_iam.conditions RENAME COLUMN project_id TO folder_id;

ALTER INDEX kacho_iam.idx_conditions_project_status RENAME TO idx_conditions_folder_status;
ALTER INDEX kacho_iam.conditions_project_name_uniq  RENAME TO conditions_folder_name_uniq;

ALTER TABLE kacho_iam.conditions
    DROP CONSTRAINT conditions_project_id_not_empty;
ALTER TABLE kacho_iam.conditions
    ADD CONSTRAINT conditions_folder_id_not_empty CHECK (length(folder_id) > 0);

-- +goose StatementEnd
