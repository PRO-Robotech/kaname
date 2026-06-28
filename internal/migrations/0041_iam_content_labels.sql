-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- +goose Up

-- Unified IAM visibility model — labels on every iam-native content type.
--
-- WHY: владелец требует единую модель видимости для ВСЕХ iam-типов наравне с
-- эталоном account/project — user/serviceAccount/role/accessBinding становятся
-- label-selectable (ARM_LABELS-грант на iam.<type> материализует v_list по
-- `labels @> matchLabels`, а List фильтрует через viewer ∪ v_list). Это
-- переоткрывает прежнее решение, по которому эти типы были materializable только
-- через ARM_ANCHOR/ARM_NAMES (см. domain/feed_registry.go: перенос из
-- iamContentMaterializableTypes в labelSelectableTypes).
--
-- WHAT:
--   1. ADD COLUMN labels jsonb на users / service_accounts / roles /
--      access_bindings (которые ее еще не несли) — DEFAULT '{}' NOT NULL +
--      CHECK kacho_labels_valid (тот же предикат, что у accounts/projects/groups).
--   2. GIN(jsonb_path_ops) на labels этих таблиц + на groups.labels (колонка у
--      groups уже была с 0001, но GIN на нее не создавался — 0023 покрыл только
--      projects/accounts). Индекс обслуживает reconciler hot-path
--      `WHERE labels @> $1::jsonb` (MatchIAMDirect / IAMDirectSelectorBindings-
--      MatchingObject) и Account/Project-аналогичный label-change fan-out.
--
-- jsonb_path_ops — оператор-класс под `@>` containment (меньше/быстрее дефолтного
-- jsonb_ops; не поддерживает key-existence `?`/`?|`/`?&`, которые здесь не нужны).
-- Паритет с projects_labels_gin / accounts_labels_gin (0023) и
-- resource_mirror_labels_gin (0019).
--
-- Backfill: DEFAULT '{}' материализует пустые labels для всех существующих строк —
-- они НЕ матчат ни один непустой селектор (labels @> {k:v} → false на {}), так что
-- видимость legacy-строк не меняется (только viewer-ветка их покрывает).

ALTER TABLE kacho_iam.users
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT users_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

ALTER TABLE kacho_iam.service_accounts
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT service_accounts_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

ALTER TABLE kacho_iam.roles
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT roles_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

ALTER TABLE kacho_iam.access_bindings
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT access_bindings_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

CREATE INDEX users_labels_gin            ON kacho_iam.users            USING gin (labels jsonb_path_ops);
CREATE INDEX service_accounts_labels_gin ON kacho_iam.service_accounts USING gin (labels jsonb_path_ops);
CREATE INDEX roles_labels_gin            ON kacho_iam.roles            USING gin (labels jsonb_path_ops);
CREATE INDEX access_bindings_labels_gin  ON kacho_iam.access_bindings  USING gin (labels jsonb_path_ops);
CREATE INDEX groups_labels_gin           ON kacho_iam.groups          USING gin (labels jsonb_path_ops);

-- +goose Down

DROP INDEX IF EXISTS kacho_iam.users_labels_gin;
DROP INDEX IF EXISTS kacho_iam.service_accounts_labels_gin;
DROP INDEX IF EXISTS kacho_iam.roles_labels_gin;
DROP INDEX IF EXISTS kacho_iam.access_bindings_labels_gin;
DROP INDEX IF EXISTS kacho_iam.groups_labels_gin;

ALTER TABLE kacho_iam.users            DROP COLUMN IF EXISTS labels;
ALTER TABLE kacho_iam.service_accounts DROP COLUMN IF EXISTS labels;
ALTER TABLE kacho_iam.roles            DROP COLUMN IF EXISTS labels;
ALTER TABLE kacho_iam.access_bindings  DROP COLUMN IF EXISTS labels;
