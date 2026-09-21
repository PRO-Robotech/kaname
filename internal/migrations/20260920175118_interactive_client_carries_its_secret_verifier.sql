-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- interactive_client_carries_its_secret_verifier — реестр ИНТЕРАКТИВНЫХ КЛИЕНТОВ
-- получает ПРОВЕРОЧНОЕ ЗНАЧЕНИЕ секрета (задача PRO-Robotech/kaname#313).
--
-- =============================================================================
-- ЧТО ИЗМЕРЕНО
-- =============================================================================
-- `sed -n '2063,2081p' internal/migrations/0001_initial.sql | grep -c secret` →
-- 0: у `kaname.interactive_clients` колонки секрета НЕТ НИ В КАКОМ ВИДЕ. Пока
-- её нет, реестр не может быть авторитетом по удостоверению клиента — только
-- зеркалом чужого поставщика. Соседи, у которых она есть, —
-- `kaname.user_oauth_clients.secret_hash` и
-- `kaname.service_account_oauth_clients.secret_hash`.
--
-- =============================================================================
-- АЛГОРИТМ И ПАРАМЕТРЫ — ТЕ ЖЕ, ЧТО У ПАРОЛЕЙ, И ОНИ НАЗВАНЫ
-- =============================================================================
-- Пароли этого репозитория пишутся argon2id с параметрами пола
-- `m=65536 КиБ, t=3, p=4` (`internal/domain/password_hash_format.go`, запись
-- формата argon2id, поля Floor; производитель — `passwordverify.Hasher.Hash`,
-- `internal/passwordverify/hasher.go`). Значение уходит в базу разметкой PHC:
--
--   $argon2id$v=19$m=<КиБ>,t=<проходы>,p=<параллельность>$<соль>$<тело>
--
-- соль 16 байт (`argon2idSaltLen`), тело 32 байта (`argon2idKeyLen`), обе
-- части — base64 без выравнивания, то есть 22 и 43 знака. Ограничение формы
-- ниже переносит ЭТУ разметку дословно, а не «какой-нибудь хеш»: значение
-- чужого формата (bcrypt популяции переноса, быстрый хеш, сырой секрет) база
-- отвергает, а не принимает молча.
--
-- ПАРАМЕТРЫ В ОГРАНИЧЕНИИ НЕ ЗАКРЕПЛЕНЫ ЧИСЛАМИ, и это решение: `Declared`
-- позволяет поднимать стоимость настройкой между полом и потолком
-- (`m=65536…131072`, `t=3…10`, `p=4…8`), и ограничение с выписанными числами
-- отвергало бы значения, законно записанные поднятой настройкой. Держит их
-- страж старта (`Declared.Validate`), у которого числа ОДНИ; схема держит
-- форму — то, чего стражу не видно на лежащей строке.
--
-- СЕКРЕТ В ОТКРЫТОМ ВИДЕ НЕ ХРАНИТСЯ НИГДЕ: колонка несёт только проверочное
-- значение, и копия таблицы не даёт ни одного годного секрета.
--
-- =============================================================================
-- ПУСТОЕ ЗНАЧЕНИЕ — ЭТО «СЕКРЕТА НЕТ», И ОНО ОТДЕЛЕНО ОТ ЗНАЧЕНИЯ
-- =============================================================================
-- Интерактивный клиент бывает публичным: у него секрета нет и быть не должно.
-- Пустая строка означает ровно это; момент установки (`secret_verifier_set_at`)
-- стоит РОВНО тогда, когда значение непусто, и согласие держит ограничение, а
-- не писатель. Лежащие строки переходят в «секрета нет» — умолчание колонки,
-- обратного заполнения нет и быть не может: секрет чужого поставщика нам не
-- известен, и выдумать его значило бы завести удостоверение, которого никто не
-- предъявлял.

-- +goose Up

ALTER TABLE kaname.interactive_clients
    ADD COLUMN secret_verifier text DEFAULT ''::text NOT NULL,
    ADD COLUMN secret_verifier_set_at timestamp with time zone;

-- +goose StatementBegin
ALTER TABLE kaname.interactive_clients
    ADD CONSTRAINT interactive_clients_secret_verifier_form_ck CHECK (
        ((secret_verifier = ''::text)
         OR (secret_verifier ~ '^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$'::text))),
    ADD CONSTRAINT interactive_clients_secret_verifier_stamp_ck CHECK (
        ((secret_verifier = ''::text) = (secret_verifier_set_at IS NULL)));
-- +goose StatementEnd

COMMENT ON COLUMN kaname.interactive_clients.secret_verifier IS
  'Проверочное значение секрета клиента: argon2id разметкой PHC, тот же алгоритм и те же параметры, что у паролей (internal/domain/password_hash_format.go, пол m=65536,t=3,p=4; производитель passwordverify.Hasher). Секрет в открытом виде не хранится. Пустая строка — секрета НЕТ (публичный клиент).';

COMMENT ON COLUMN kaname.interactive_clients.secret_verifier_set_at IS
  'Момент установки проверочного значения. Стоит РОВНО тогда, когда значение непусто; согласие держит interactive_clients_secret_verifier_stamp_ck.';

-- Проверочное значение не идёт в статистику планировщика: по нему не отбирают
-- (сверка идёт по найденной строке клиента), а выборка значений в `pg_stats`
-- была бы второй копией материала, живущей в каталоге и не видимой ни одному
-- продуктовому глаголу (гейт `TestSecretMaterialCandidatesAreAllAdjudicated`).
ALTER TABLE kaname.interactive_clients ALTER COLUMN secret_verifier SET STATISTICS 0;

-- +goose Down

-- Откат снимает колонку вместе с проверочными значениями. Невосстановимого
-- материала здесь нет: секрет клиента перевыпускается владельцем клиента, и
-- откат этой миграции означает возврат реестра в состояние зеркала, где
-- авторитетом по удостоверению он и не был.
ALTER TABLE kaname.interactive_clients
    DROP CONSTRAINT interactive_clients_secret_verifier_stamp_ck,
    DROP CONSTRAINT interactive_clients_secret_verifier_form_ck,
    DROP COLUMN secret_verifier_set_at,
    DROP COLUMN secret_verifier;
