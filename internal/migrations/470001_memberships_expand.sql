-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 470001_memberships_expand — принадлежность аккаунту становится ОТДЕЛЬНОЙ связью.
-- Стадия S1 (expand) перехода IAM-ID-1, задача kacho#470.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- `kacho_iam.users` несёт `account_id text NOT NULL`, и уникальность объявлена
-- ПАРОЙ — `(account_id, lower(email))` и `(account_id, external_id)`. Отсюда
-- следствие, ради которого пишется этот переход: один человек, приглашённый в
-- два аккаунта, существует как ДВА РАЗНЫХ пользователя — два идентификатора,
-- два набора прав, две строки, из которых активировать можно только одну.
--
-- Пользователь обязан стать идентичностью платформы; принадлежность —
-- отдельной связью, которых у человека может быть несколько.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ ДЕЛАЕТ И ЧЕГО НЕ ДЕЛАЕТ
--
-- Делает: заводит `memberships`, наполняет её из существующих строк и заводит
-- зеркалирование вперёд. Авторитет принадлежности ОСТАЁТСЯ у `users.account_id`
-- — читателей у новой таблицы нет ни одного.
--
-- НЕ делает: не трогает колонку, не трогает ни один из трёх ключей уникальности
-- строки пользователя, не снимает ничего. Откат — снятие таблицы обратным шагом,
-- одно действие, и он полон by construction (IAM-ID-1-50).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЗЕРКАЛО ВЕДЁТ ТРИГГЕР, А НЕ Go
--
-- Писателей строки пользователя больше одного, и они не однородны: четыре пути
-- репозитория (Upsert · InsertPending · InsertActive · Delete) и три применённые
-- миграции, сеющие служебную строку-якорь сырым SQL (0009, 0044, 0057 — все три
-- пишут ОДНУ и ту же строку, выводя её идентификатор из md5, поэтому на дереве
-- она одна). Зеркало, написанное на пути use-case, отвечает одному вызывающему,
-- а не каждому писателю: посевные миграции, восстановление из дампа и следующая
-- посевная миграция прошли бы мимо него молча, и взаимная однозначность
-- разъехалась бы там, где этого не видно. Инвариант внутри одной БД выражается
-- КОНСТРУКЦИЕЙ (ban #10), поэтому зеркало ведёт триггер.
--
-- Та же посевная строка — причина, по которой идентификатор зеркала выводится
-- из md5, а не придуман здесь: это уже house-форма чеканки идентификатора в SQL
-- этого сервиса (`'usr' || substr(md5('kacho-system'), 1, 17)` в 0009).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ДВА ОТСТУПЛЕНИЯ ОТ ЦЕЛЕВОЙ ФОРМЫ — НАЗВАНЫ, А НЕ УМОЛЧАНЫ
--
-- 1. Ссылка на человека здесь CASCADE, а в целевой форме (приёмка §2.1) —
--    RESTRICT. Причина не в удобстве: RESTRICT на этой стадии сделал бы
--    неудаляемым КАЖДОГО пользователя (его собственное зеркало и стало бы
--    препятствием), а отказ пришёл бы нарушением ограничения, которого нет в
--    отображении отказов репозитория — то есть наружу уехал бы INTERNAL с
--    текстом драйвера. Пока членство есть ПРОЕКЦИЯ строки, оно обязано уходить
--    вместе с ней; RESTRICT вводится на S3 вместе со своим текстом отказа и
--    своим reason-токеном (IAM-ID-1-13), которых сегодня не существует.
--    Предикат смены: появление этого токена в таблице полос.
--
-- 2. Уникальность «человек × аккаунт» здесь ПОЛНАЯ, а приёмка называет её
--    частичной. Частичной она может быть только по какому-то предикату, а
--    состояний у членства два («приглашён» и «активно») и снятие есть удаление
--    строки — то есть предиката, по которому строку следовало бы исключить из
--    ключа, не существует. Выдумывать его значило бы заводить sentinel, который
--    завтра столкнётся с законным состоянием.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОБРАТНОЕ ЗАПОЛНЕНИЕ: НАПРАВЛЕНИЕ И ЧИСЛО
--
-- Направление — СТРОГО ДОБАВЛЯЮЩЕЕ: каждая существующая строка пользователя
-- получает ровно одно членство, ведущее в тот аккаунт, который стоит в её
-- колонке. Ни одна строка пользователя не читается на предмет изменения, ни одна
-- не переписывается и ни одна не удаляется — эта миграция не вправе изменить ни
-- одного байта в `users`, и проба это утверждает.
--
-- Число переписанных строк ПЕЧАТАЕТСЯ (RAISE NOTICE), а взаимная однозначность
-- ПРОВЕРЯЕТСЯ здесь же и роняет миграцию на расхождении: заявление о переносе,
-- которое никто не проверяет, перестаёт быть верным молча.

-- +goose Up

-- membership_mirror_id — идентификатор зеркала, выводимый из пары. Он
-- детерминирован намеренно: пока членство есть проекция строки, повторное
-- зеркалирование той же пары обязано давать ТУ ЖЕ строку, иначе обратное
-- заполнение и триггер разошлись бы на первом же повторе.
--
-- Форма — дефис-канон платформы (`<prefix>-<17 crockford-base32>`): членство
-- становится внешне-адресуемым на S3, а идентификатор чеканится уже здесь и
-- живёт с этой строкой всю её жизнь (ban #15 — идентичность не перечеканивается).
-- Шестнадцатеричные цифры md5 — подмножество крокфордова алфавита этого продукта
-- (`0123456789abcdefghjkmnpqrstvwxyz`), поэтому тело остаётся в алфавите.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_id(p_user_id text, p_account_id text)
RETURNS text
LANGUAGE sql IMMUTABLE
AS $$
    SELECT 'mbr-' || substr(md5('membership:' || p_user_id || ':' || p_account_id), 1, 17);
$$;
-- +goose StatementEnd

CREATE TABLE kacho_iam.memberships (
    id          text        NOT NULL,
    user_id     text        NOT NULL,
    account_id  text        NOT NULL,
    -- Состояний ровно два. Блокировка человека СЮДА НЕ ЕДЕТ: она свойство
    -- личности, а не членства (решение по вопросу В-8 приёмки), и строка
    -- заблокированного человека несёт обычное членство, оставаясь заблокированной
    -- сама. Приостановки членства отдельным состоянием этот переход не вводит.
    state       text        NOT NULL DEFAULT 'ACTIVE',
    invited_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT memberships_pkey PRIMARY KEY (id),
    CONSTRAINT memberships_state_check CHECK (state IN ('PENDING', 'ACTIVE')),
    CONSTRAINT memberships_id_form_check
        CHECK (id ~ '^mbr-[0-9abcdefghjkmnpqrstvwxyz]{17}$'),

    -- Ссылка на человека: пока членство — проекция строки, оно уходит вместе с
    -- ней (отступление 1 в шапке).
    CONSTRAINT memberships_user_fk FOREIGN KEY (user_id)
        REFERENCES kacho_iam.users (id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,

    -- Ссылка на аккаунт: CASCADE — членство принадлежит аккаунту и умирает
    -- вместе с ним (IAM-ID-1-08).
    --
    -- DEFERRABLE здесь ОБЯЗАТЕЛЬНО, и это не осторожность: заведение личного
    -- аккаунта вставляет строку пользователя ПЕРВОЙ, а сам аккаунт — следом, в
    -- той же транзакции (тот самый цикл, который держат отложенные ключи
    -- `users_account_fk` и `accounts_owner_fk`). Триггер зеркала сработает на
    -- вставке строки, когда аккаунта ещё нет; немедленная проверка отвергла бы
    -- КАЖДОЕ первое появление человека — то есть ровно ту директиву, которую
    -- этот переход обязан сохранить дословно.
    --
    -- Каскад при этом остаётся немедленным: отложить можно проверку вида
    -- NO ACTION, а не референциальное действие.
    CONSTRAINT memberships_account_fk FOREIGN KEY (account_id)
        REFERENCES kacho_iam.accounts (id) ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);

-- Человек состоит в аккаунте не более одного раза — полной уникальностью
-- (отступление 2 в шапке).
CREATE UNIQUE INDEX memberships_user_account_unique
    ON kacho_iam.memberships (user_id, account_id);

-- «Кто состоит в этом аккаунте» — вопрос, который на S3 заменит собой снимаемый
-- фильтр списка пользователей.
CREATE INDEX memberships_account_idx ON kacho_iam.memberships (account_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Обратное заполнение: строго добавляющее.
INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
SELECT kacho_iam.membership_mirror_id(u.id, u.account_id),
       u.id,
       u.account_id,
       CASE WHEN u.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
       u.invited_by,
       u.created_at,
       now()
  FROM kacho_iam.users u
ON CONFLICT (user_id, account_id) DO NOTHING;

-- Взаимная однозначность проверяется ЗДЕСЬ и роняет миграцию на расхождении.
-- Печатается объём осмотренного: «ноль расхождений» обязано быть отличимо от
-- «ноль прочитанного».
-- +goose StatementBegin
DO $$
DECLARE
    n_users      bigint;
    n_members    bigint;
    n_orphan_usr bigint;
    n_orphan_mem bigint;
    n_mismatch   bigint;
BEGIN
    SELECT count(*) INTO n_users   FROM kacho_iam.users;
    SELECT count(*) INTO n_members FROM kacho_iam.memberships;

    SELECT count(*) INTO n_orphan_usr
      FROM kacho_iam.users u
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.memberships m WHERE m.user_id = u.id);

    SELECT count(*) INTO n_orphan_mem
      FROM kacho_iam.memberships m
     WHERE NOT EXISTS (SELECT 1 FROM kacho_iam.users u WHERE u.id = m.user_id);

    SELECT count(*) INTO n_mismatch
      FROM kacho_iam.users u
      JOIN kacho_iam.memberships m ON m.user_id = u.id
     WHERE m.account_id <> u.account_id;

    RAISE NOTICE '470001 обратное заполнение: строк пользователей %, членств заведено %, '
                 'строк без членства %, членств без строки %, расхождений по аккаунту %',
                 n_users, n_members, n_orphan_usr, n_orphan_mem, n_mismatch;

    IF n_orphan_usr <> 0 OR n_orphan_mem <> 0 OR n_mismatch <> 0 OR n_users <> n_members THEN
        RAISE EXCEPTION
            '470001: обратное заполнение не взаимно однозначно (строк %, членств %, '
            'без членства %, без строки %, расхождений %) — перенос принадлежности '
            'не состоялся, и продолжать переход нельзя',
            n_users, n_members, n_orphan_usr, n_orphan_mem, n_mismatch;
    END IF;
END
$$;
-- +goose StatementEnd

-- ─────────────────────────────────────────────────────────────────────────────
-- Зеркалирование вперёд.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Строка сменила аккаунт. Сегодня колонка неизменяема на уровне use-case, но
    -- зеркало не вправе на это опираться: писателей больше одного, а неизменяемость
    -- держится проверкой одного из них.
    DELETE FROM kacho_iam.memberships
     WHERE user_id = NEW.id
       AND account_id <> NEW.account_id;

    INSERT INTO kacho_iam.memberships (id, user_id, account_id, state, invited_by, created_at, updated_at)
    VALUES (kacho_iam.membership_mirror_id(NEW.id, NEW.account_id),
            NEW.id,
            NEW.account_id,
            CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
            NEW.invited_by,
            NEW.created_at,
            now())
    ON CONFLICT (user_id, account_id) DO UPDATE
       SET state      = EXCLUDED.state,
           invited_by = EXCLUDED.invited_by,
           updated_at = now()
     WHERE kacho_iam.memberships.state      IS DISTINCT FROM EXCLUDED.state
        OR kacho_iam.memberships.invited_by IS DISTINCT FROM EXCLUDED.invited_by;

    -- Идентификатор членства в DO UPDATE намеренно НЕ трогается: активация
    -- меняет состояние, а не идентичность.
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER membership_mirrors_user_row
    AFTER INSERT OR UPDATE OF account_id, invite_status, invited_by
    ON kacho_iam.users
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.membership_mirror_from_user();

-- +goose Down

DROP TRIGGER IF EXISTS membership_mirrors_user_row ON kacho_iam.users;
DROP FUNCTION IF EXISTS kacho_iam.membership_mirror_from_user();
DROP TABLE IF EXISTS kacho_iam.memberships;
DROP FUNCTION IF EXISTS kacho_iam.membership_mirror_id(text, text);
