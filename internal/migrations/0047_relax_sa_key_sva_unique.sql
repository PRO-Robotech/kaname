-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0047_relax_sa_key_sva_unique.sql — релакс SA-key с 1:1 до N:1.
--
-- service_account_oauth_clients ранее нёс UNIQUE(sva_id) → у одного ServiceAccount
-- не более одного ключа. Это противоречит plural-модели (выпуск нескольких токенов,
-- список). Снимаем UNIQUE-индекс: теперь у ServiceAccount может быть НЕСКОЛЬКО ключей
-- (симметрично user_oauth_clients). Остальные инварианты (UNIQUE hydra_client_id, FK,
-- CHECK) без изменений.

-- +goose Up
-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.service_account_oauth_clients_sva_unique;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Восстановление 1:1 возможно только если в таблице нет >1 ключа на один sva_id;
-- при наличии дублей CREATE UNIQUE INDEX откатит миграцию (ожидаемо для down-пути).
CREATE UNIQUE INDEX IF NOT EXISTS service_account_oauth_clients_sva_unique
    ON kacho_iam.service_account_oauth_clients USING btree (sva_id);

-- +goose StatementEnd
