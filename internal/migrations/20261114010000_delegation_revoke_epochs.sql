-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md (ESC-32, Р4).
-- PRO-Robotech/kaname#1034: строка делегирования входит в тот же protected
-- snapshot, что membership, carrier, subjects, members и emitted ledger.
-- access_bindings уже покрыты binding_epoch_*: INSERT делегированной выдачи,
-- смена grant_delegation_id и OLD+NEW ownership инвалидируют snapshot каскада.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
CREATE TRIGGER binding_epoch_insert AFTER INSERT ON kaname.grant_delegations
 REFERENCING NEW TABLE AS new_epoch_rows FOR EACH STATEMENT
 EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_update AFTER UPDATE ON kaname.grant_delegations
 REFERENCING OLD TABLE AS old_epoch_rows NEW TABLE AS new_epoch_rows FOR EACH STATEMENT
 EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_delete AFTER DELETE ON kaname.grant_delegations
 REFERENCING OLD TABLE AS old_epoch_rows FOR EACH STATEMENT
 EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
CREATE TRIGGER binding_epoch_truncate AFTER TRUNCATE ON kaname.grant_delegations
 FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed();
-- Снимки, начатые до расширения графа, не переносятся через handoff.
UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope='';
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
DROP TRIGGER binding_epoch_insert ON kaname.grant_delegations;
DROP TRIGGER binding_epoch_update ON kaname.grant_delegations;
DROP TRIGGER binding_epoch_delete ON kaname.grant_delegations;
DROP TRIGGER binding_epoch_truncate ON kaname.grant_delegations;
-- +goose StatementEnd
