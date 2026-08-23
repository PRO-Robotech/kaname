-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260823053000_first_login_activates_every_membership — первый вход человека
-- переводит в «активно» ВСЕ его членства, а не одно.
-- Стадия S4-expand перехода IAM-ID-1, задачи kacho#470 / kacho#981.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Зеркало ведёт ОДНО членство — то, чей аккаунт стоит в колонке строки. Пока
-- членство было проекцией строки, этого было довольно: оно и было одно.
--
-- С глобальным ключом идентичности (20260823050000) человек, приглашённый в два
-- аккаунта, есть ОДНА строка с ДВУМЯ членствами, и колонка называет из них одно.
-- Активация переводит в «активно» ровно его, а второе остаётся «приглашён»
-- НАВСЕГДА: другого перехода в этом состоянии у строки больше не будет.
--
-- Наблюдаемо для арендатора так: человек вошёл, во втором аккаунте он числится
-- приглашённым и не входившим — при том что вошёл он один раз и в платформу, а
-- не в аккаунт.
--
-- Ровно это дерево обещает сегодня godoc пути активации («ActivateInvite
-- каждой») и приёмка (IAM-ID-1-04). Обещание становится исполнимым только
-- здесь: активировать нужно одну строку и все её членства, а не N строк.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЭТО ТРИГГЕР, А НЕ ШАГ В GO
--
-- Тем же доводом, каким зеркало заведено триггером в 470001: писателей строки
-- больше одного и они не однородны — четыре пути репозитория и посевные
-- миграции, пишущие строку сырым SQL. Шаг на пути use-case отвечает ОДНОМУ
-- вызывающему; восстановление из дампа, следующая посевная миграция и любой
-- будущий писатель прошли бы мимо него молча. Инвариант внутри одной БД
-- выражается конструкцией (ban #10).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ГРАНИЦА: ПОЧЕМУ УСЛОВИЕ — «СТРОКА БОЛЬШЕ НЕ ПРИГЛАШЕНА», А НЕ «СТАЛА ACTIVE»
--
-- Состояний у строки три, у членства два: блокировка есть свойство ЛИЧНОСТИ, а
-- не членства (решение по вопросу В-8 приёмки), и членство заблокированного
-- человека остаётся обычным. Поэтому и здесь, и в самом зеркале действует одно
-- и то же правило `PENDING → PENDING, иначе ACTIVE`.
--
-- Перехода «приглашён → заблокирован» не существует by construction:
-- `users_invite_status_consistency` требует у заблокированной строки непустой
-- внешний субъект, а у приглашённой — пустой. Значит единственный выход из
-- «приглашён» — вход, и расширение условия ничего лишнего не накрывает.
--
-- Обратного хода нет намеренно: членство, ставшее активным, назад в «приглашён»
-- не возвращается. Снятие членства есть удаление строки, а не состояние
-- (470001), и приостановки этот переход не вводит.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_mirror_from_user() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Членство, названное колонкой строки. Добавляющее: чужих членств зеркало
    -- не снимает — колонка называет одно членство из многих, а не все
    -- (20260822234500).
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

    -- Первый вход: человек перестал быть приглашённым — значит приглашённым он
    -- не остаётся НИ В ОДНОМ аккаунте. Это и есть та половина, которой у
    -- зеркала не было.
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
-- Догоняющая правка уже лежащих строк: человек, вошедший ДО этой миграции, мог
-- оставить членства в «приглашён». Число печатается — заявление о переносе,
-- которое никто не считает, перестаёт быть верным молча.
-- +goose StatementBegin
DO $catchup$
DECLARE
    n bigint;
BEGIN
    UPDATE kacho_iam.memberships m
       SET state = 'ACTIVE', updated_at = now()
      FROM kacho_iam.users u
     WHERE u.id = m.user_id
       AND m.state = 'PENDING'
       AND u.invite_status <> 'PENDING';
    GET DIAGNOSTICS n = ROW_COUNT;
    RAISE NOTICE 'членств, догнавших состояние вошедшего человека: %', n;
END;
$catchup$;
-- +goose StatementEnd

-- +goose Down

-- Возврат к определению 20260822234500: добавляющее зеркало без второй половины.
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
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
