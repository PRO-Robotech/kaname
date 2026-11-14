-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Добавляется только хранение: выдача, чтение и прежние привязки не активируются.
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §§2, 8.1–8.4.

-- +goose Up
SET LOCAL lock_timeout = '10s';

CREATE TABLE kaname.role_create_binding_rule (
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    PRIMARY KEY (role_id, rule_fp),
    CONSTRAINT role_create_binding_rule_owner_fk
        FOREIGN KEY (role_id) REFERENCES kaname.roles (id) ON DELETE CASCADE,
    CONSTRAINT role_create_binding_rule_fp_check CHECK (rule_fp ~ '^[0-9a-f]{64}$')
);

CREATE TABLE kaname.role_bind_role_rule (
    role_id text NOT NULL,
    rule_fp text NOT NULL,
    bound_role_id text NOT NULL,
    PRIMARY KEY (role_id, rule_fp, bound_role_id),
    CONSTRAINT role_bind_role_rule_owner_fk
        FOREIGN KEY (role_id) REFERENCES kaname.roles (id) ON DELETE CASCADE,
    CONSTRAINT role_bind_role_rule_target_fk
        FOREIGN KEY (bound_role_id) REFERENCES kaname.roles (id) ON DELETE CASCADE,
    CONSTRAINT role_bind_role_rule_fp_check CHECK (rule_fp ~ '^[0-9a-f]{64}$')
);
CREATE INDEX role_bind_role_rule_target_idx
    ON kaname.role_bind_role_rule (bound_role_id);

ALTER TABLE kaname.access_bindings
    ADD COLUMN grant_capability_version smallint NOT NULL DEFAULT 0,
    ADD CONSTRAINT access_bindings_grant_capability_version_check
        CHECK (grant_capability_version IN (0, 1));

COMMENT ON TABLE kaname.role_create_binding_rule IS
    'Явное право создания привязок с отпечатком исходного правила. Неактивно до включения выдачи и протокола полномочий.';
COMMENT ON TABLE kaname.role_bind_role_rule IS
    'Явное право привязки роли: владелец и цель ссылаются на роли независимо; отпечаток указывает исходное правило. До включения неактивно.';
COMMENT ON COLUMN kaname.access_bindings.grant_capability_version IS
    '0: прежняя привязка без включённых управляющих прав. 1: зарезервировано для будущего авторизованного изменения; эта миграция 1 не устанавливает.';

-- +goose Down
SET LOCAL lock_timeout = '10s';
ALTER TABLE kaname.access_bindings
    DROP CONSTRAINT access_bindings_grant_capability_version_check,
    DROP COLUMN grant_capability_version;
DROP TABLE kaname.role_bind_role_rule;
DROP TABLE kaname.role_create_binding_rule;
