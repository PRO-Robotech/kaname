-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up
-- +goose StatementBegin

-- Retire the tenant-facing condition surface from iam.
--
-- Two unrelated things share the word "condition" here. One is alive and is not
-- touched by this migration: conditions ON A TUPLE, declared in the authorization
-- model and carried on the internal listener, whose key the server supplies itself.
-- The other is what this migration removes: a tenant-facing Condition resource with
-- its own service, plus a per-binding overlay table, plus a column on the binding
-- pointing at that overlay.
--
-- The overlay was never joined to the resource. `access_bindings.condition_id`
-- references `access_binding_conditions(id)` — ids shaped `cond_…` — while the
-- resource lives in `conditions(id)` with ids shaped `cnd…`. Two designs, two id
-- spaces, no path between them. `access_binding_conditions` has no production
-- writer at all: every INSERT against it in this repository is in a test.
--
-- ORDER. This is the "retract the producers" step. The service that created rows
-- here, the request fields that referenced them and the projection that read them
-- ship removed in the same change, and the authorization TYPE (`type iam_condition`)
-- goes with them — by then nothing can emit onto it. The reverse order — dropping
-- the type while a producer still writes onto it — turns every such write into a
-- rejection the store never stops returning, which poisons the queue partition
-- behind it.
--
-- DATA. Nothing is migrated because there is nothing to migrate, and that is
-- measured rather than asserted: both tables are declared in dropguard.json with
-- expect_rows 0, and the guard reads the count from the database at the version
-- immediately before this drop. An unreachable database yields NOT VERIFIED, never
-- a convenient zero.
--
-- IDEMPOTENT. Every statement is keyed on the retired names, so a re-run (or a
-- re-apply against a database already retired) changes nothing. Additive to the
-- migration history — no applied migration is edited.

-- (1) The binding's pointer at the overlay. The FK
--     (access_bindings_condition_fk, 0001) goes with the column.
ALTER TABLE kacho_iam.access_bindings
    DROP COLUMN IF EXISTS condition_id;

-- +goose StatementEnd
-- +goose StatementBegin

-- (2) The trigger and function introduced by 0048 to keep the overlay's derived
--     condition_id in step with its params. Dropped BEFORE the table so the drop
--     order reads the same way the objects were created.
DROP TRIGGER IF EXISTS access_binding_conditions_sync_condition_id_trg
    ON kacho_iam.access_binding_conditions;

-- +goose StatementEnd
-- +goose StatementBegin

DROP FUNCTION IF EXISTS kacho_iam.access_binding_conditions_sync_condition_id();

-- +goose StatementEnd
-- +goose StatementBegin

-- (3) The overlay table. Its own FK to conditions(id) (0048) goes with it, which
--     is why it is dropped before the resource table.
DROP TABLE IF EXISTS kacho_iam.access_binding_conditions;

-- +goose StatementEnd
-- +goose StatementBegin

-- (4) The resource table.
DROP TABLE IF EXISTS kacho_iam.conditions;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Down recreates the SHAPE, not the data: there was none (expect_rows 0 above), so
-- an empty pair of tables and a nullable column is the exact state a rollback
-- returns to. Definitions follow 0001 as amended by 0013 (whitelist), 0048
-- (derived condition_id + FK + trigger) and 0070 (folder_id → project_id), so a
-- rollback lands on the schema this migration actually found.

CREATE TABLE IF NOT EXISTS kacho_iam.conditions (
    id text NOT NULL,
    project_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    expression text NOT NULL,
    parameters_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'CREATING'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT conditions_pkey PRIMARY KEY (id),
    CONSTRAINT conditions_description_length CHECK ((length(description) <= 256)),
    CONSTRAINT conditions_expression_length CHECK (((length(expression) >= 1) AND (length(expression) <= 2048))),
    CONSTRAINT conditions_project_id_not_empty CHECK ((length(project_id) > 0)),
    CONSTRAINT conditions_id_check CHECK ((id ~ '^cnd[a-z0-9]{1,17}$'::text)),
    CONSTRAINT conditions_name_pattern CHECK ((name ~ '^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT conditions_status_whitelist CHECK ((status = ANY (ARRAY['CREATING'::text, 'ACTIVE'::text, 'DELETING'::text, 'ERROR'::text])))
);

-- +goose StatementEnd
-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS conditions_project_name_uniq
    ON kacho_iam.conditions USING btree (project_id, name) WHERE (status <> 'DELETING'::text);

-- +goose StatementEnd
-- +goose StatementBegin

CREATE INDEX IF NOT EXISTS idx_conditions_project_status
    ON kacho_iam.conditions USING btree (project_id, status) WHERE (status <> 'DELETING'::text);

-- +goose StatementEnd
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS kacho_iam.access_binding_conditions (
    id text NOT NULL,
    binding_id text NOT NULL,
    expression text NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    condition_id text,
    CONSTRAINT access_binding_conditions_pkey PRIMARY KEY (id),
    CONSTRAINT access_binding_conditions_created_by_check CHECK ((length(created_by) <= 64)),
    CONSTRAINT access_binding_conditions_expression_whitelist_ck CHECK ((expression = ANY (ARRAY['mfa_fresh'::text, 'non_expired'::text, 'source_ip_in_range'::text, 'business_hours'::text, 'device_compliant'::text]))),
    CONSTRAINT access_binding_conditions_id_check CHECK ((id ~ '^cond_[a-z0-9_]{1,40}$'::text)),
    CONSTRAINT access_binding_conditions_params_object_ck CHECK ((jsonb_typeof(params) = 'object'::text)),
    CONSTRAINT access_binding_conditions_binding_fk FOREIGN KEY (binding_id)
        REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE,
    CONSTRAINT access_binding_conditions_condition_fk FOREIGN KEY (condition_id)
        REFERENCES kacho_iam.conditions(id) ON DELETE RESTRICT
);

-- +goose StatementEnd
-- +goose StatementBegin

CREATE UNIQUE INDEX IF NOT EXISTS access_binding_conditions_binding_unique
    ON kacho_iam.access_binding_conditions USING btree (binding_id);

-- +goose StatementEnd
-- +goose StatementBegin

CREATE OR REPLACE FUNCTION kacho_iam.access_binding_conditions_sync_condition_id()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.condition_id := NULLIF(NEW.params ->> 'condition_id', '');
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

CREATE TRIGGER access_binding_conditions_sync_condition_id_trg
    BEFORE INSERT OR UPDATE ON kacho_iam.access_binding_conditions
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.access_binding_conditions_sync_condition_id();

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    ADD COLUMN IF NOT EXISTS condition_id text;

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_condition_fk FOREIGN KEY (condition_id)
    REFERENCES kacho_iam.access_binding_conditions(id) ON DELETE SET NULL;

-- +goose StatementEnd
