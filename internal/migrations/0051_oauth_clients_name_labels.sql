-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0051_oauth_clients_name_labels.sql — create-only метаданные (name + labels) на
-- обеих token-таблицах: service_account_oauth_clients + user_oauth_clients.
--
-- WHY: токен становится самодостаточным ресурсом — пользователь даёт человекочитаемое
-- имя и произвольные labels на выпуске (Issue). Ресурсы несут только Issue/List/Revoke
-- (нет Update), поэтому оба поля выставляются на Insert и immutable.
--
-- WHAT:
--   name text DEFAULT '' NOT NULL — короткое имя (валидируется ≤63 в domain);
--   labels jsonb DEFAULT '{}' NOT NULL + CHECK kacho_labels_valid (тот же предикат,
--   что accounts/projects/groups/users) — единая модель labels iam-типов.
--
-- Backfill: DEFAULT '' / '{}' материализует пустые значения для существующих строк —
-- поведение legacy-строк не меняется. GIN-индекс на labels НЕ создаётся: эти таблицы
-- не участвуют в authz label-visibility-модели (reconciler их не селектит по labels).

-- +goose Up

ALTER TABLE kacho_iam.service_account_oauth_clients
  ADD COLUMN name text DEFAULT ''::text NOT NULL,
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT service_account_oauth_clients_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

ALTER TABLE kacho_iam.user_oauth_clients
  ADD COLUMN name text DEFAULT ''::text NOT NULL,
  ADD COLUMN labels jsonb DEFAULT '{}'::jsonb NOT NULL,
  ADD CONSTRAINT user_oauth_clients_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels));

-- +goose Down

ALTER TABLE kacho_iam.service_account_oauth_clients
  DROP CONSTRAINT IF EXISTS service_account_oauth_clients_labels_valid,
  DROP COLUMN IF EXISTS labels,
  DROP COLUMN IF EXISTS name;

ALTER TABLE kacho_iam.user_oauth_clients
  DROP CONSTRAINT IF EXISTS user_oauth_clients_labels_valid,
  DROP COLUMN IF EXISTS labels,
  DROP COLUMN IF EXISTS name;
