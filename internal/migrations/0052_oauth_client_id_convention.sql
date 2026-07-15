-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0052_oauth_client_id_convention.sql — приведение генерации id токенов к
-- конвенции corelib `ids.NewID` (3-char prefix + 17-char crockford, БЕЗ
-- подчёркивания).
--
-- WHY: id токена совпадает с Hydra client id + JWK kid + private-key kid и
-- immutable — существующие строки нельзя перегенерировать. Поэтому CHECK на id
-- обеих token-таблиц ослабляется до приёма ОБОИХ форматов: legacy
-- `<prefix>_<17-crockford>` (уже в БД) И нового `<prefix><17-crockford>`
-- (генерируется с этого момента). Malformed id по-прежнему отвергается.
--
-- WHAT: DROP старого strict-CHECK + ADD ослабленного (`_?` делает подчёркивание
-- опциональным) на service_account_oauth_clients.id и user_oauth_clients.id.

-- +goose Up

ALTER TABLE kacho_iam.service_account_oauth_clients
  DROP CONSTRAINT IF EXISTS service_account_oauth_clients_id_check,
  ADD CONSTRAINT service_account_oauth_clients_id_check
    CHECK (id ~ '^soc_?[0-9a-hjkmnp-tv-z]{17}$'::text);

ALTER TABLE kacho_iam.user_oauth_clients
  DROP CONSTRAINT IF EXISTS user_oauth_clients_id_check,
  ADD CONSTRAINT user_oauth_clients_id_check
    CHECK (id ~ '^uoc_?[0-9a-hjkmnp-tv-z]{17}$'::text);

-- +goose Down

ALTER TABLE kacho_iam.service_account_oauth_clients
  DROP CONSTRAINT IF EXISTS service_account_oauth_clients_id_check,
  ADD CONSTRAINT service_account_oauth_clients_id_check
    CHECK (id ~ '^soc_[0-9a-hjkmnp-tv-z]{17}$'::text);

ALTER TABLE kacho_iam.user_oauth_clients
  DROP CONSTRAINT IF EXISTS user_oauth_clients_id_check,
  ADD CONSTRAINT user_oauth_clients_id_check
    CHECK (id ~ '^uoc_[0-9a-hjkmnp-tv-z]{17}$'::text);
