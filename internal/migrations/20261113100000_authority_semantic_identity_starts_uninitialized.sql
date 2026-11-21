-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: граница сравнения identity, не активация strict authority.
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- kaname#1034: защита полного действия выдачи и сохранение прежних строк при накате (ESC-32).
CREATE TABLE kaname.authority_semantic_identity (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 phase text NOT NULL DEFAULT 'uninitialized' CHECK (phase IN ('uninitialized','transition','active')),
 protocol_version integer NOT NULL DEFAULT 0 CHECK (protocol_version >= 0),
 model_id text,
 catalog_id text,
 projector_version text,
 CHECK (phase <> 'uninitialized' OR (protocol_version=0 AND model_id IS NULL AND catalog_id IS NULL AND projector_version IS NULL)),
 CHECK (phase <> 'active' OR (protocol_version > 0 AND model_id IS NOT NULL AND model_id ~ '^[0-9a-f]{64}$' AND catalog_id IS NOT NULL AND catalog_id ~ '^[0-9a-f]{64}$' AND projector_version IS NOT NULL AND projector_version <> ''))
);
INSERT INTO kaname.authority_semantic_identity DEFAULT VALUES;
COMMENT ON TABLE kaname.authority_semantic_identity IS 'Сравнение закреплённой семантики. По умолчанию закрыто. Активация требует отдельного coordinator, drain и DB backstop; эта миграция их не удостоверяет.';
-- +goose Down
LOCK TABLE kaname.authority_semantic_identity IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM kaname.authority_semantic_identity WHERE phase <> 'uninitialized' OR protocol_version <> 0 OR model_id IS NOT NULL OR catalog_id IS NOT NULL OR projector_version IS NOT NULL) THEN
  RAISE EXCEPTION 'semantic identity has left the uninitialized state';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE kaname.authority_semantic_identity;
