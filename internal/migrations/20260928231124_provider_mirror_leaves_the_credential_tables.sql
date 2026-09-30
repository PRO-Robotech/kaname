-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- provider_mirror_leaves_the_credential_tables — СТОЛБЕЦ ЗЕРКАЛА ПРЕЖНЕГО
-- ИЗДАТЕЛЯ И ВИД `LEGACY` покидают обе таблицы удостоверений
-- (`service_account_oauth_clients`, `user_oauth_clients`; задача
-- PRO-Robotech/kaname#362).
--
-- Санкция: решение о порядке снятия
-- `docs/engineering/architecture/provider-mirror-column-retirement.md` §«Что
-- решено» п. 2 и маршрут эпика PRO-Robotech/kacho#2564, снявший календарное
-- ожидание окна. Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ПОЧЕМУ НОВАЯ МИГРАЦИЯ
-- =============================================================================
-- Столбец, его проверку формата, индекс уникальности и оба ограничения вида
-- завёл свод (`0001_initial.sql`). Правка применённого файла до базы, где он
-- применён, не доезжает: мигратор сверяет версию, а не содержимое (ban #5).
--
-- =============================================================================
-- ПРЕДОХРАНИТЕЛЬ — ПЕРВЫМ, ЧЕТЫРЕ ВЕЛИЧИНЫ
-- =============================================================================
-- Накат ОТКАЗЫВАЕТ, пока хоть одна строка говорит о прежнем издателе. Величин
-- четыре, а не две, потому что вид и столбец — не одно и то же у личности:
--
--   1. зеркало служебной учётки — имя клиента есть и оно не равно `id`
--      (на переведённом контуре туда кладётся наш `id`, и это не зеркало);
--   2. зеркало личности — имя клиента есть (своя выдача его не пишет);
--   3. вид LEGACY служебной учётки;
--   4. вид LEGACY личности — его строка законно несёт пустой столбец и под
--      предикат 2 не подпадает.
--
-- Строки не снимаются и не переписываются: их снимает арендатор отзывом либо
-- истечение срока. Отказ называет таблицу, величину и число — и ничего из
-- содержимого строк.
--
-- ИСКЛЮЧЕНИЕ ОДНО, И ОНО ЗАКРЕПЛЕНО ТРЕМЯ ЗНАЧЕНИЯМИ. Строку чеканки бутстрапа
-- (`bootstrap_token/ids.go`) путь запроса пишет с именем клиента
-- `kacho-bootstrap-admin`, отличным от её `id`, — по предикату 1 она зеркало, и
-- без исключения предохранитель отказывал бы на каждой живой базе навсегда.
-- Зеркалом она не является: токен для неё чеканит наш подписант, а край
-- токенов прежнего издателя больше не принимает (PRO-Robotech/kacho#2734).
-- Исключение сужено до тройки (`id`, `sva_id`, имя клиента) посевных значений:
-- строка, совпавшая с ней не целиком, считается зеркалом.
--
-- =============================================================================
-- ЗАХВАТ — ДО ПЕРЕСЧЁТА
-- =============================================================================
-- Обе таблицы захватываются ИСКЛЮЧИТЕЛЬНО первым оператором, в порядке
-- «служебная учётка, личность» — тот же порядок, что у снятия ниже. Пересчёт до
-- захвата пропустил бы строку, закоммиченную между пересчётом и снятием
-- столбца. Писатели обеих таблиц ждут конца наката; отказавший накат повторяем
-- — он исполняется одной транзакцией, частичного состояния у него нет.
--
-- =============================================================================
-- ПОРЯДОК СНЯТИЯ — ЯВНЫЙ, А НЕ КАСКАДОМ СТОЛБЦА
-- =============================================================================
-- `DROP COLUMN` без ошибки уносит и многостолбцовую проверку формы, и индекс
-- (проверено на Postgres 16). Полагаться на это нельзя: ограничение формы
-- держит инварианты ВСЕХ видов, и снятое молча, оно оставило бы таблицу без
-- них. Поэтому ограничения вида и формы и проверка формата имени снимаются
-- явно, затем индекс и столбец, затем ограничения вида и формы ставятся заново
-- ПОД ТЕМИ ЖЕ ИМЕНАМИ: имя — координата, по которой их читают ведомость
-- ограничений, пробы и откат.
--
-- Ветви вида, которого нет, у ограничения формы теперь исход `false`, а не
-- `NULL`: `ELSE NULL` пропускал строку неназванного вида, и держал её от этого
-- только словарь в соседнем ограничении.

-- +goose Up

LOCK TABLE kaname.service_account_oauth_clients, kaname.user_oauth_clients IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
DECLARE
    v_sa_mirror   bigint;
    v_user_mirror bigint;
    v_sa_legacy   bigint;
    v_user_legacy bigint;
BEGIN
    SELECT count(*) INTO v_sa_mirror
      FROM kaname.service_account_oauth_clients
     WHERE hydra_client_id IS NOT NULL
       AND hydra_client_id <> id
       AND NOT (id = 'soc_db27d17291ff453b6'
                AND sva_id = 'svab91854890de887e6d'
                AND hydra_client_id = 'kacho-bootstrap-admin');
    SELECT count(*) INTO v_user_mirror
      FROM kaname.user_oauth_clients
     WHERE hydra_client_id IS NOT NULL;
    SELECT count(*) INTO v_sa_legacy
      FROM kaname.service_account_oauth_clients
     WHERE credential_kind = 'LEGACY';
    SELECT count(*) INTO v_user_legacy
      FROM kaname.user_oauth_clients
     WHERE credential_kind = 'LEGACY';

    IF v_sa_mirror > 0 THEN
        RAISE EXCEPTION 'kaname.service_account_oauth_clients: строк с зеркалом у прежнего издателя: %', v_sa_mirror;
    END IF;
    IF v_user_mirror > 0 THEN
        RAISE EXCEPTION 'kaname.user_oauth_clients: строк с зеркалом у прежнего издателя: %', v_user_mirror;
    END IF;
    IF v_sa_legacy > 0 THEN
        RAISE EXCEPTION 'kaname.service_account_oauth_clients: строк вида LEGACY: %', v_sa_legacy;
    END IF;
    IF v_user_legacy > 0 THEN
        RAISE EXCEPTION 'kaname.user_oauth_clients: строк вида LEGACY: %', v_user_legacy;
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE kaname.service_account_oauth_clients
    DROP CONSTRAINT service_account_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT service_account_oauth_clients_credential_kind_ck,
    DROP CONSTRAINT service_account_oauth_clients_hydra_client_id_check;
DROP INDEX kaname.service_account_oauth_clients_hydra_client_id_unique;
ALTER TABLE kaname.service_account_oauth_clients DROP COLUMN hydra_client_id;
ALTER TABLE kaname.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_credential_kind_ck CHECK (
        (credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text, 'FEDERATED'::text]))),
    ADD CONSTRAINT service_account_oauth_clients_credential_shape_ck CHECK (
        CASE credential_kind
            WHEN 'KEYPAIR'::text THEN (secret_hash = '\x'::bytea)
            WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (trusted_subjects = '[]'::jsonb) AND (expires_at IS NOT NULL))
            WHEN 'FEDERATED'::text THEN ((secret_hash = '\x'::bytea) AND (public_key_pem = ''::text) AND (trusted_subjects <> '[]'::jsonb))
            ELSE false
        END);
COMMENT ON COLUMN kaname.service_account_oauth_clients.credential_kind IS 'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется.';

ALTER TABLE kaname.user_oauth_clients
    DROP CONSTRAINT user_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT user_oauth_clients_credential_kind_ck,
    DROP CONSTRAINT user_oauth_clients_hydra_client_id_check;
DROP INDEX kaname.user_oauth_clients_hydra_client_id_unique;
ALTER TABLE kaname.user_oauth_clients DROP COLUMN hydra_client_id;
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_credential_kind_ck CHECK (
        (credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text]))),
    ADD CONSTRAINT user_oauth_clients_credential_shape_ck CHECK (
        CASE credential_kind
            WHEN 'KEYPAIR'::text THEN (secret_hash = '\x'::bytea)
            WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (expires_at IS NOT NULL))
            ELSE false
        END);

-- +goose Down

-- Откат возвращает СТРОЕНИЕ обеих таблиц ровно в том виде, в каком его оставил
-- свод: столбец, проверку формата имени, индекс уникальности, оба ограничения
-- вида с ветвью LEGACY и комментарии. Совпадение строения держит проба
-- `TestIntegration_MirrorLeavingRollsBackToTheSameStructure`.
--
-- Значения столбца откат ВЫВОДИТ, а не восстанавливает: имени клиента у
-- прежнего издателя на этой базе больше нет нигде. У ключевой пары и
-- федеративного ключа служебной учётки ставится `id` — именно его и клал туда
-- переведённый контур, и ограничение формы отката требует столбец непустым у
-- обоих видов. У секрета и у личности столбец остаётся пустым: их выдача его не
-- писала.

LOCK TABLE kaname.service_account_oauth_clients, kaname.user_oauth_clients IN ACCESS EXCLUSIVE MODE;

ALTER TABLE kaname.service_account_oauth_clients
    DROP CONSTRAINT service_account_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT service_account_oauth_clients_credential_kind_ck;
ALTER TABLE kaname.service_account_oauth_clients ADD COLUMN hydra_client_id text;
UPDATE kaname.service_account_oauth_clients
   SET hydra_client_id = id
 WHERE credential_kind = ANY (ARRAY['KEYPAIR'::text, 'FEDERATED'::text]);
ALTER TABLE kaname.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_credential_kind_ck CHECK ((credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text, 'FEDERATED'::text, 'LEGACY'::text]))),
    ADD CONSTRAINT service_account_oauth_clients_credential_shape_ck CHECK (
        CASE credential_kind
            WHEN 'KEYPAIR'::text THEN ((secret_hash = '\x'::bytea) AND (hydra_client_id IS NOT NULL))
            WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (trusted_subjects = '[]'::jsonb) AND (expires_at IS NOT NULL) AND (hydra_client_id IS NULL))
            WHEN 'FEDERATED'::text THEN ((secret_hash = '\x'::bytea) AND (public_key_pem = ''::text) AND (trusted_subjects <> '[]'::jsonb) AND (hydra_client_id IS NOT NULL))
            WHEN 'LEGACY'::text THEN ((secret_hash = '\x'::bytea) AND (hydra_client_id IS NOT NULL))
            ELSE NULL::boolean
        END),
    ADD CONSTRAINT service_account_oauth_clients_hydra_client_id_check CHECK (((hydra_client_id IS NULL) OR ((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text))));
CREATE UNIQUE INDEX service_account_oauth_clients_hydra_client_id_unique ON kaname.service_account_oauth_clients USING btree (hydra_client_id);
COMMENT ON COLUMN kaname.service_account_oauth_clients.credential_kind IS 'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется. LEGACY описывает строки прежнего потока и не выдаётся ни одним глаголом.';

ALTER TABLE kaname.user_oauth_clients
    DROP CONSTRAINT user_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT user_oauth_clients_credential_kind_ck;
ALTER TABLE kaname.user_oauth_clients ADD COLUMN hydra_client_id text;
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_credential_kind_ck CHECK ((credential_kind = ANY (ARRAY['KEYPAIR'::text, 'SECRET'::text, 'LEGACY'::text]))),
    ADD CONSTRAINT user_oauth_clients_credential_shape_ck CHECK (
        CASE credential_kind
            WHEN 'KEYPAIR'::text THEN (secret_hash = '\x'::bytea)
            WHEN 'SECRET'::text THEN ((octet_length(secret_hash) = 32) AND (public_key_pem = ''::text) AND (key_algorithm = ''::text) AND (expires_at IS NOT NULL) AND (hydra_client_id IS NULL))
            WHEN 'LEGACY'::text THEN (secret_hash = '\x'::bytea)
            ELSE NULL::boolean
        END),
    ADD CONSTRAINT user_oauth_clients_hydra_client_id_check CHECK (((hydra_client_id IS NULL) OR ((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text))));
CREATE UNIQUE INDEX user_oauth_clients_hydra_client_id_unique ON kaname.user_oauth_clients USING btree (hydra_client_id);
COMMENT ON COLUMN kaname.user_oauth_clients.hydra_client_id IS 'Идентификатор клиента у внешнего поставщика. NULL — регистрации у него нет (выдача её больше не заводит); непустое значение принадлежит строке прежнего выпуска и держит окно двух издателей.';
