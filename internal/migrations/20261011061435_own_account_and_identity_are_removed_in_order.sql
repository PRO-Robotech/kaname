-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- own_account_and_identity_are_removed_in_order — арендатор снимает свой аккаунт
-- и затем свою личность, и этот порядок исполним (задача PRO-Robotech/kaname#664).
--
-- Санкция: приёмка
-- `docs/engineering/acceptance/own-account-and-identity-are-removed-in-order.md`,
-- решения Р3, Р4, Р8, Р10, Р11, сценарии KN664-01…04. Доводы там; здесь — то,
-- что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ЦИКЛ — И ПОЧЕМУ ОН НЕ РАЗРЫВАЕТСЯ ОТЛОЖЕННОСТЬЮ
-- =============================================================================
-- Колонка дома человека (`users.account_id`) ссылается на его личный аккаунт,
-- владелец аккаунта (`accounts.owner_user_id`) — на человека. Оба ключа были
-- `ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED`, и отложенность не
-- помогала: действие `RESTRICT` Postgres не откладывает никогда — откладывается
-- только `NO ACTION`. Аккаунт не снимался, пока на него указывает строка
-- владельца, строка владельца — пока он владеет аккаунтом.
--
-- Разрывает цикл действие ключа дома: `SET NULL`. Снятие аккаунта оставляет
-- всех, чей дом — этот аккаунт, без дома, и пустое значение означает «дома
-- нет» и только это. Пустой строки как второго написания отсутствия нет: ключ
-- отвергает всякое непустое значение, которому не соответствует аккаунт, а
-- аккаунта с пустым идентификатором не бывает. Отложенность ключа сохранена —
-- она нужна вставке регистрации, где строка человека пишется раньше аккаунта.
-- Ключ владельца не меняется: «владеет аккаунтами» остаётся законным шагом пути.
--
-- =============================================================================
-- ТРИ КЛЮЧА RESTRICT НА ТОМ ЖЕ ПУТИ — СНИМАЮТСЯ
-- =============================================================================
-- `session_revocations_user_fk` — запись отзыва удостоверения обязана действовать
-- до своего срока независимо от судьбы человека; уходит уборкой по сроку.
-- `user_oauth_clients_created_by_fk`, `service_account_oauth_clients_created_by_fk`
-- — «кто выпустил» есть атрибуция, исторический факт (как
-- `access_bindings.granted_by_user_id` и `roles.created_by_user_id`, у которых
-- ключа нет). Идентификатор снятого человека не переиспользуется (реестр ниже),
-- поэтому пережившая ссылка не укажет на другого.
--
-- =============================================================================
-- ОХРАНА СНЯТИЯ СУБЪЕКТА — ТОЛЬКО ДЕЙСТВУЮЩИЕ ВЫДАЧИ
-- =============================================================================
-- Функция `principal_not_referenced_as_subject` одна на три вида субъекта
-- (человек, группа, сервисный аккаунт). Отозванная выдача — история: права она
-- не даёт, её кортежи сняты отзывом, и держать ею субъекта значит требовать от
-- чужого аккаунта стереть журнал своих выдач. Действующая выдача — та, у которой
-- `revoked_at IS NULL` (то же условие отличает её в частичной уникальности
-- `access_bindings_active_grant_uniq`); `PENDING` считается действующей. Текст
-- отказа не меняется.
--
-- =============================================================================
-- РЕЕСТР ВЫДАННЫХ ИДЕНТИФИКАТОРОВ ЛЮДЕЙ
-- =============================================================================
-- По образцу `issued_account_ids`: пополняется триггером на КАЖДОЙ вставке
-- строки человека, снятием строки не очищается; вставка идентификатора из
-- реестра отвергается ключом `issued_user_ids_pkey`. Без него приглашение,
-- прочитавшее строку по почте до своей транзакции, заводило строку с
-- идентификатором человека, снятого между чтением и вставкой, — и тот
-- наследовал записи отзыва, атрибуцию и отозванные выдачи снятого.
--
-- Накат заполняет реестр из ЖИВЫХ строк `users`, и этого достаточно: строку
-- человека заводят два оператора, идентификатор у них либо свежий, либо
-- прочитан живым до транзакции. Идентификатор человека, снятого ДО наката, ни
-- одному писателю недостижим. Триггер ставится раньше заполнения под замком
-- таблицы: вставка, пришедшая во время наката, ждёт его конца и проходит через
-- триггер.
--
-- =============================================================================
-- ОТКАТ — НЕ ВЫДУМЫВАЕТ ДАННЫХ
-- =============================================================================
-- Откат возвращает прежнюю форму дословно, если вернуть её можно ничего не
-- изобретая. Есть человек без дома — откат отказывает (вернуть NOT NULL значило
-- бы изобрести ему аккаунт); есть запись отзыва, личный токен или ключ
-- сервисного аккаунта, ссылающиеся на отсутствующего человека, — отказывает
-- (вернуть ключи значило бы удалить записи). Отказ поднимается до любого
-- изменения схемы, тексты — часть контракта миграции. Реестр людей откат
-- снимает; повторный накат заполняет его заново из живых строк, и
-- идентификаторы людей, снятых между накатом и откатом, в него НЕ вернутся —
-- это сужение названо здесь.

-- +goose Up

LOCK TABLE kaname.users IN SHARE ROW EXCLUSIVE MODE;

-- Р3: ключ дома — SET NULL, колонка дома допускает пустое значение.
ALTER TABLE kaname.users ALTER COLUMN account_id DROP NOT NULL;
ALTER TABLE kaname.users DROP CONSTRAINT users_account_fk;
ALTER TABLE kaname.users
    ADD CONSTRAINT users_account_fk FOREIGN KEY (account_id) REFERENCES kaname.accounts(id)
    ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;

-- Р4: три ключа RESTRICT на users сняты — ссылки становятся мягкими.
ALTER TABLE kaname.session_revocations DROP CONSTRAINT session_revocations_user_fk;
ALTER TABLE kaname.user_oauth_clients DROP CONSTRAINT user_oauth_clients_created_by_fk;
ALTER TABLE kaname.service_account_oauth_clients DROP CONSTRAINT service_account_oauth_clients_created_by_fk;

-- Р10: охрана снятия субъекта считает только действующие выдачи.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.principal_not_referenced_as_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM kaname.access_binding_subjects s
          JOIN kaname.access_bindings b ON b.id = s.binding_id
         WHERE s.subject_type = TG_ARGV[0]
           AND s.subject_id   = OLD.id
           AND b.revoked_at IS NULL
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE    = '23503',
            CONSTRAINT = 'access_binding_subjects_subject_ref',
            MESSAGE    = format('%s %s is referenced by an access binding subject and cannot be deleted',
                                TG_ARGV[0], OLD.id);
    END IF;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd

-- Р11: реестр выданных идентификаторов людей.
CREATE TABLE kaname.issued_user_ids (
    id text NOT NULL,
    CONSTRAINT issued_user_ids_pkey PRIMARY KEY (id)
);

COMMENT ON TABLE kaname.issued_user_ids IS
    'Идентификаторы людей, выданные когда-либо. Пополняет только триггер на вставку строки человека; снятие строки реестр не трогает. Выданный идентификатор повторно не выдаётся.';

-- +goose StatementBegin
CREATE FUNCTION kaname.issued_user_ids_record() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.issued_user_ids (id) VALUES (NEW.id);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER users_issued_user_ids_trg AFTER INSERT ON kaname.users
    FOR EACH ROW EXECUTE FUNCTION kaname.issued_user_ids_record();

INSERT INTO kaname.issued_user_ids (id) SELECT id FROM kaname.users;

-- +goose Down

-- Р8: отказ — до любого изменения схемы, двумя фиксированными текстами; ни
-- идентификаторов, ни счётчиков строк в тексте нет.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.users WHERE account_id IS NULL) THEN
        RAISE EXCEPTION 'rollback refused: users without a home account exist';
    END IF;
    IF EXISTS (SELECT 1 FROM kaname.session_revocations r
                WHERE NOT EXISTS (SELECT 1 FROM kaname.users u WHERE u.id = r.user_id))
       OR EXISTS (SELECT 1 FROM kaname.user_oauth_clients c
                   WHERE NOT EXISTS (SELECT 1 FROM kaname.users u WHERE u.id = c.created_by_user_id))
       OR EXISTS (SELECT 1 FROM kaname.service_account_oauth_clients c
                   WHERE NOT EXISTS (SELECT 1 FROM kaname.users u WHERE u.id = c.created_by_user_id))
    THEN
        RAISE EXCEPTION 'rollback refused: records reference removed users';
    END IF;
END $$;
-- +goose StatementEnd

DROP TRIGGER users_issued_user_ids_trg ON kaname.users;
DROP FUNCTION kaname.issued_user_ids_record();
DROP TABLE kaname.issued_user_ids;

-- Прежнее тело функции охраны — дословно, как в 0001_initial.sql.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.principal_not_referenced_as_subject() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM kaname.access_binding_subjects
         WHERE subject_type = TG_ARGV[0]
           AND subject_id   = OLD.id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE    = '23503',
            CONSTRAINT = 'access_binding_subjects_subject_ref',
            MESSAGE    = format('%s %s is referenced by an access binding subject and cannot be deleted',
                                TG_ARGV[0], OLD.id);
    END IF;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd

ALTER TABLE kaname.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_created_by_fk FOREIGN KEY (created_by_user_id)
    REFERENCES kaname.users(id) ON DELETE RESTRICT;
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_created_by_fk FOREIGN KEY (created_by_user_id)
    REFERENCES kaname.users(id) ON DELETE RESTRICT;
ALTER TABLE kaname.session_revocations
    ADD CONSTRAINT session_revocations_user_fk FOREIGN KEY (user_id)
    REFERENCES kaname.users(id) ON DELETE RESTRICT;

ALTER TABLE kaname.users DROP CONSTRAINT users_account_fk;
ALTER TABLE kaname.users
    ADD CONSTRAINT users_account_fk FOREIGN KEY (account_id) REFERENCES kaname.accounts(id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE kaname.users ALTER COLUMN account_id SET NOT NULL;
