-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Секретный материал уходит из статистики планировщика (kaname#129).
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- `ANALYZE` кладёт в `pg_statistic` не только числа, но и САМИ ЗНАЧЕНИЯ колонки:
-- самые частые значения и границы гистограммы. Для колонки с секретным
-- материалом это вторая копия материала, живущая в каталоге. Её не затирает
-- затирание строки (одноразовый приватный ключ в ответе операции затирается по
-- истечении окна — в каталоге он остаётся), не удаляет удаление строки, и не
-- видит ни один продуктовый глагол.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ЗАМЕР, А НЕ ДОПУЩЕНИЕ
--
-- На живой базе (свод + `ANALYZE`, Postgres):
--
--   service_account_oauth_clients.secret_hash, 32 байта  → значения В СТАТИСТИКЕ
--   token_signing_keys.private_key_wrapped,  300 байт    → значения В СТАТИСТИКЕ
--   token_signing_keys.private_key_wrapped, 2048 байт    → строки статистики НЕТ
--
-- Третья строка — причина, по которой довод «наши ключи длинные, и так не
-- попадёт» негоден: порог ширины у `ANALYZE` — 1024 байта, и попадание решает
-- РАЗМЕР значения, то есть алгоритм и обёртка. Ключ EdDSA короче ключа RSA на
-- порядок; свойство, держащееся на длине значения, переживёт свой предмет молча.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО НИЧЕГО НЕ СТОИТ ПЛАНУ
--
-- Ни одна из этих колонок не участвует в отборе: перепись по дереву даёт НОЛЬ
-- вхождений в `WHERE` / `JOIN` / `ORDER BY`. Единственные индексы по
-- `secret_hash` — ЧАСТИЧНЫЕ уникальные; их избирательность выводится из
-- предиката и уникальности, а не из гистограммы значений. Колонки полезной
-- нагрузки операции читаются по идентификатору.
--
-- Колонка `access_bindings.target_digest` НЕ трогается намеренно: это не
-- секретный материал, а свёртка ЦЕЛИ выдачи (умолчание `all`), входящая в ключ
-- уникальности выдачи, — по ней отбирают.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ `ANALYZE` СТОИТ ЗДЕСЬ ЖЕ
--
-- Настройка действует на СЛЕДУЮЩИЙ сбор. Уже собранные значения останутся в
-- каталоге до него, то есть неопределённо долго. `ANALYZE` этих трёх таблиц
-- прямо здесь вычищает их немедленно — иначе миграция объявляет исключение, не
-- исполнив его.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE kaname.service_account_oauth_clients ALTER COLUMN secret_hash SET STATISTICS 0;
ALTER TABLE kaname.user_oauth_clients            ALTER COLUMN secret_hash SET STATISTICS 0;
ALTER TABLE kaname.token_signing_keys            ALTER COLUMN private_key_wrapped SET STATISTICS 0;
ALTER TABLE kaname.operations                    ALTER COLUMN metadata_data SET STATISTICS 0;
ALTER TABLE kaname.operations                    ALTER COLUMN response_data SET STATISTICS 0;
ALTER TABLE kaname.operations                    ALTER COLUMN error_details SET STATISTICS 0;
-- +goose StatementEnd

-- +goose StatementBegin
ANALYZE kaname.service_account_oauth_clients,
        kaname.user_oauth_clients,
        kaname.token_signing_keys,
        kaname.operations;
-- +goose StatementEnd

-- +goose Down
-- Обратный ход возвращает УМОЛЧАНИЕ (`-1`), а не какое-то число: своя величина
-- здесь была бы решением, которого никто не принимал.
-- +goose StatementBegin
ALTER TABLE kaname.service_account_oauth_clients ALTER COLUMN secret_hash SET STATISTICS -1;
ALTER TABLE kaname.user_oauth_clients            ALTER COLUMN secret_hash SET STATISTICS -1;
ALTER TABLE kaname.token_signing_keys            ALTER COLUMN private_key_wrapped SET STATISTICS -1;
ALTER TABLE kaname.operations                    ALTER COLUMN metadata_data SET STATISTICS -1;
ALTER TABLE kaname.operations                    ALTER COLUMN response_data SET STATISTICS -1;
ALTER TABLE kaname.operations                    ALTER COLUMN error_details SET STATISTICS -1;
-- +goose StatementEnd
