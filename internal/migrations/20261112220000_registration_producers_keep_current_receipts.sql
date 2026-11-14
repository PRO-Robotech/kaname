-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: receipt фактически принятого источника, без backfill фактов.
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §§8.2–8.4.
-- +goose Up
CREATE TABLE kaname.producer_source_receipt (
 kind text NOT NULL CHECK (kind IN ('registration_owner','publication')),
 module text NOT NULL CHECK (module <> ''),
 catalog_type text NOT NULL CHECK (catalog_type <> ''),
 object_type text NOT NULL CHECK (object_type <> ''),
 object_id text NOT NULL CHECK (object_id <> ''),
 relation text NOT NULL,
 subject_type text NOT NULL,
 subject_id text NOT NULL CHECK (subject_id <> ''),
 condition_name text NOT NULL DEFAULT '' CHECK (condition_name = ''),
 condition_parameters text NOT NULL DEFAULT '' CHECK (condition_parameters = ''),
 scopes jsonb NOT NULL CHECK (jsonb_typeof(scopes)='array' AND jsonb_array_length(scopes) BETWEEN 1 AND 256),
 source_version timestamptz NOT NULL,
 versionless boolean NOT NULL,
 active boolean NOT NULL,
 invalidation text NOT NULL DEFAULT '',
 receipt_version integer NOT NULL DEFAULT 1 CHECK (receipt_version=1),
 model_identity text,
 catalog_identity text,
 projector_version text,
 CHECK (model_identity IS NULL AND catalog_identity IS NULL AND projector_version IS NULL),
 CHECK ((kind='registration_owner' AND relation='owner' AND subject_type IN ('user','service_account')) OR (kind='publication' AND relation='v_get' AND subject_type='system_class' AND subject_id='anonymous')),
 PRIMARY KEY(kind,module,object_type,object_id,relation,subject_type,subject_id)
);
CREATE INDEX producer_source_receipt_object ON kaname.producer_source_receipt(object_type,object_id,kind);
COMMENT ON TABLE kaname.producer_source_receipt IS 'Текущая provenance принятого producer. NULL bundle identity означает неподтверждённую authority; отсутствие receipt у старой строки не доказывает отсутствие выдачи.';
-- +goose Down
-- Замок и проверка остаются в одной goose TX: конкурентная вставка не теряется.
LOCK TABLE kaname.producer_source_receipt IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.producer_source_receipt) THEN
  RAISE EXCEPTION 'producer receipts are not empty';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE kaname.producer_source_receipt;
