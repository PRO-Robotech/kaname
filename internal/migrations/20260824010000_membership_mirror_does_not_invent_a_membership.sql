-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260824010000_membership_mirror_does_not_invent_a_membership — зеркало
-- перестаёт ЗАВОДИТЬ членство на правке строки человека. Задача kacho#1127.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ: исключение из аккаунта, которое отменяется само
--
-- Здесь заводится действие «исключить человека из моего аккаунта» (#1127), и
-- выражается оно снятием строки `kacho_iam.memberships`. Зеркало 470001 (в
-- редакции 20260823053000) слушает `AFTER INSERT OR UPDATE OF account_id,
-- invite_status, invited_by ON users` и на КАЖДОМ срабатывании делает
-- `INSERT … ON CONFLICT DO UPDATE` членства, названного колонкой строки.
--
-- Следствие, ради которого пишется эта миграция: человек, исключённый из
-- аккаунта, чьё имя стоит в его `users.account_id`, ВОЗВРАЩАЕТСЯ туда от любой
-- последующей правки своей строки. Путь не гипотетический и самый частый из
-- возможных — первый вход: `ActivateInvite` пишет `invite_status`, триггер
-- срабатывает и заводит членство заново, уже в состоянии «активно». То есть
-- приглашения не было, решения распорядителя не было, а участие есть.
--
-- Обратный ход тише прямого: «не доехало» и «отозвано намеренно» снаружи
-- выглядят одинаково, поэтому такое воскрешение не выдаёт себя ничем.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО МЕНЯЕТСЯ — РОВНО ДВЕ ВЕЩИ
--
--   1. НА ПРАВКЕ строки зеркало больше не ВСТАВЛЯЕТ. Оно правит членство,
--      которое уже есть, и молчит, когда его нет. Заведение членства остаётся у
--      вставки строки (первое появление человека) и у путей репозитория, которые
--      пишут членство ЯВНО, в том же стейтменте (`Upsert`, `InsertPending` —
--      20260822234500).
--   2. Пустой (и NULL) аккаунт пропускается явно. Прежняя редакция такой
--      проверки не имела, и вставка строки без аккаунта уронила бы триггер о
--      `NOT NULL` на `memberships.account_id` — латентный отказ, до которого
--      просто не доходили.
--
-- Вторая половина зеркала — «первый вход переводит в активно ВСЕ членства»
-- (20260823053000) — воспроизведена ДОСЛОВНО. Она правит существующие строки и
-- к предмету этой миграции отношения не имеет; трогать её здесь значило бы
-- править чужой предмет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТО НЕ ЛОМАЕТ — ИЗМЕРЕНО, А НЕ ПРЕДПОЛОЖЕНО
--
-- Ветка «вставить на правке» могла быть кому-то нужна только если бы в дереве
-- был писатель, меняющий `users.account_id` уже существующей строке: тогда
-- членство в НОВОМ аккаунте появлялось бы триггером. Такого писателя нет:
--
--     git grep -n 'UPDATE users' services/iam/internal/repo/kacho/pg/user_repo.go
--     → три стейтмента: ActivateInvite (external_id/display_name/invite_status),
--       UpdateLabels (labels), SetInviteStatus (invite_status). Ни один не
--       называет account_id в списке SET.
--
-- То есть ветка отвечала ровно одному вызывающему — воскрешению снятого
-- членства, — и он не был задуман никем.
--
-- Колонка `users.account_id` этой миграцией НЕ ТРОГАЕТСЯ. Исключение снимает
-- членство и указатель области в журнале прав, а колонка остаётся легаси-полем
-- перехода IAM-ID-1: она называет ОДИН аккаунт человека из многих и снимается
-- своим шагом.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Первое появление человека: членство, названное колонкой строки,
        -- заводится здесь. Пустой аккаунт пропускается — строка без аккаунта
        -- законна, а членства без аккаунта не бывает.
        IF NEW.account_id IS NOT NULL AND NEW.account_id <> '' THEN
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
        END IF;
    ELSE
        -- Правка строки: зеркало ПРАВИТ существующее членство и НЕ заводит
        -- нового. Снятое членство не возвращается ничем, кроме приглашения.
        UPDATE kacho_iam.memberships m
           SET state      = CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END,
               invited_by = NEW.invited_by,
               updated_at = now()
         WHERE m.user_id = NEW.id
           AND m.account_id = NEW.account_id
           AND (m.state      IS DISTINCT FROM CASE WHEN NEW.invite_status = 'PENDING' THEN 'PENDING' ELSE 'ACTIVE' END
             OR m.invited_by IS DISTINCT FROM NEW.invited_by);
    END IF;

    -- Первый вход: человек перестал быть приглашённым — значит приглашённым он
    -- не остаётся НИ В ОДНОМ аккаунте (20260823053000, воспроизведено дословно).
    IF NEW.invite_status <> 'PENDING' THEN
        UPDATE kacho_iam.memberships
           SET state = 'ACTIVE', updated_at = now()
         WHERE user_id = NEW.id AND state = 'PENDING';
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- ─────────────────────────────────────────────────────────────────────────────
-- ВТОРОЕ, И ОНО ПРО ТЕКСТ ОТКАЗА, А НЕ ПРО ПОВЕДЕНИЕ
--
-- Страж 472002 отвергает снятие членства, несущего живую выдачу, поднимая
-- `integrity_constraint_violation` БЕЗ имени связи. Отображение отказов
-- (`repo/kacho/pg/pgmaperr.go`) ключуется именем: безымянный отказ уехал бы в
-- `INTERNAL` с фиксированным текстом, и распорядитель аккаунта, честно
-- упёршийся в «сперва отзови права», прочитал бы «сервис сломан».
--
-- Функция пересоздаётся ЦЕЛИКОМ (тело воспроизведено дословно) — иначе это была
-- бы правка применённой миграции (ban #5). Меняется одна строка: у RAISE
-- появляется `CONSTRAINT`, по которому отображение находит контракт-тон.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_carrying_rights_is_kept() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.accounts WHERE id = OLD.account_id) THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.users WHERE id = OLD.user_id) THEN
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM kacho_iam.memberships m
         WHERE m.user_id = OLD.user_id AND m.account_id = OLD.account_id)
    THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM kacho_iam.access_bindings b
         WHERE b.status = 'ACTIVE'
           AND (
                 (b.subject_type = 'user' AND b.subject_id = OLD.user_id)
              OR EXISTS (
                   SELECT 1 FROM kacho_iam.access_binding_subjects s
                    WHERE s.binding_id = b.id
                      AND s.subject_type = 'user'
                      AND s.subject_id = OLD.user_id)
               )
           AND (
                 (b.resource_type = 'account' AND b.resource_id = OLD.account_id)
              OR (b.resource_type = 'project' AND EXISTS (
                    SELECT 1 FROM kacho_iam.projects p
                     WHERE p.id = b.resource_id AND p.account_id = OLD.account_id))
               )
    )
    THEN
        RAISE EXCEPTION
            'Membership of user % in account % still carries active access bindings',
            OLD.user_id, OLD.account_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'membership_carrying_rights_is_kept';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- +goose Down

-- Возврат к определению 20260823053000: зеркало снова заводит членство на любом
-- срабатывании, то есть воскрешает снятое.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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

    IF NEW.invite_status <> 'PENDING' THEN
        UPDATE kacho_iam.memberships
           SET state = 'ACTIVE', updated_at = now()
         WHERE user_id = NEW.id AND state = 'PENDING';
    END IF;

    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- Возврат к определению 472002: тот же страж, но RAISE без имени связи.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_carrying_rights_is_kept() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.accounts WHERE id = OLD.account_id) THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.users WHERE id = OLD.user_id) THEN
        RETURN NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM kacho_iam.memberships m
         WHERE m.user_id = OLD.user_id AND m.account_id = OLD.account_id)
    THEN
        RETURN NULL;
    END IF;

    IF EXISTS (
        SELECT 1
          FROM kacho_iam.access_bindings b
         WHERE b.status = 'ACTIVE'
           AND (
                 (b.subject_type = 'user' AND b.subject_id = OLD.user_id)
              OR EXISTS (
                   SELECT 1 FROM kacho_iam.access_binding_subjects s
                    WHERE s.binding_id = b.id
                      AND s.subject_type = 'user'
                      AND s.subject_id = OLD.user_id)
               )
           AND (
                 (b.resource_type = 'account' AND b.resource_id = OLD.account_id)
              OR (b.resource_type = 'project' AND EXISTS (
                    SELECT 1 FROM kacho_iam.projects p
                     WHERE p.id = b.resource_id AND p.account_id = OLD.account_id))
               )
    )
    THEN
        RAISE EXCEPTION
            'Membership of user % in account % still carries active access bindings',
            OLD.user_id, OLD.account_id
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
