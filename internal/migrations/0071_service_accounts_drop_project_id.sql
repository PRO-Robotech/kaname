-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0071 — снятие `service_accounts.project_id` вместе с её внешним ключом и
-- частичным индексом.
--
-- Колонка объявляла проектную область служебной учётки, но заполнить её было
-- нечем: ни один запрос её не принимал (в Create/Update такого поля нет), ни
-- один INSERT/UPDATE её не передавал, а выборка агрегата её даже не выбирала.
-- Единственное чтение шло на пути чеканки токена и выводило claim, который не
-- читает никто. Значение было пустым всегда и у всех, поэтому переносить
-- нечего: снимается пустая колонка.
--
-- Проектные служебные учётки, если понадобятся, заводятся отдельной
-- подсистемой со своей приёмкой (область прав, извлечение области на краю), а
-- не колонкой, в которую никто не пишет.

-- +goose Up
ALTER TABLE kacho_iam.service_accounts
    DROP CONSTRAINT IF EXISTS service_accounts_project_fk;

DROP INDEX IF EXISTS kacho_iam.service_accounts_project_idx;

ALTER TABLE kacho_iam.service_accounts
    DROP COLUMN IF EXISTS project_id;

-- +goose Down
ALTER TABLE kacho_iam.service_accounts
    ADD COLUMN IF NOT EXISTS project_id text;

CREATE INDEX IF NOT EXISTS service_accounts_project_idx
    ON kacho_iam.service_accounts USING btree (project_id)
    WHERE (project_id IS NOT NULL);

ALTER TABLE kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_project_fk
    FOREIGN KEY (project_id) REFERENCES kacho_iam.projects(id) ON DELETE RESTRICT;
