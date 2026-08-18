-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 472002_membership_carries_rights — членство нельзя снять, пока на него
-- опирается живая выдача. Стадия S2 перехода IAM-ID-1, задача kacho#472.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ: три роли, и их нельзя путать
--
--   невозможность осиротить  — КОНСТРУКЦИЯ базы (эта миграция);
--   снятие выдач             — ШАГ use-case в той же транзакции;
--   исчезновение доступа     — материализация, наблюдаемая Check'ом.
--
-- Здесь заводится ПЕРВАЯ и только она, и она — гарантия, а не шаг: если код
-- снятия выдач однажды напишут неверно, транзакция не пройдёт вовсе, вместо
-- того чтобы тихо оставить право без носителя. Полагаться на шаг как на
-- гарантию — ровно то, что запрещает ban #10.
--
-- Отзыв тише выдачи: «не доехало» и «отозвано намеренно» снаружи выглядят
-- одинаково — оба суть отсутствие. Поэтому молчаливое сиротство закрывается
-- конструкцией, а не дисциплиной вызывающего.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ТРИГГЕР, А НЕ ВНЕШНИЙ КЛЮЧ
--
-- Естественным решением выглядит ссылка `access_binding_subjects → memberships`
-- с `ON DELETE RESTRICT`. Она НЕИСПОЛНИМА на этом дереве, и это измерено, а не
-- предположено: выдача НЕ требует членства. Путь создания выдачи не проверяет,
-- состоит ли субъект в аккаунте области (проверяется область РОЛИ, а не
-- принадлежность человека), поэтому для законной выдачи человеку из другого
-- аккаунта строки членства не существует — и `NOT NULL`-ссылке не на что
-- указывать. Ключ отверг бы не ошибку, а штатный ввод.
--
-- Триггер выражает то же свойство без этого допущения: он смотрит на выдачи,
-- которые ФАКТИЧЕСКИ опираются на снимаемое членство, и молчит про все прочие.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ОТЛОЖЕННЫЙ
--
-- Немедленная проверка навязала бы вызывающему порядок стейтментов внутри
-- транзакции — снять выдачи строго раньше членства, — а это деталь реализации,
-- не контракт. Отложенная задаёт вопрос на COMMIT, когда состояние приведено к
-- целевому. То же свойство сохранит будущий путь удаления аккаунта (IAM-ID-1-08,
-- стадия S3): он снимает свои выдачи и свои членства одной транзакцией, и
-- порядок внутри неё остаётся его делом.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ГРАНИЦА ЗАПРЕТА — названа с обеих сторон
--
-- Удерживают членство только выдачи, которые: (а) ЖИВЫЕ (`status='ACTIVE'`) —
-- отозванная носителем не является; (б) адресуют ЭТОГО человека — субъектом в
-- любой из двух проекций, легаси-одиночной и множественной; (в) лежат в области
-- ЭТОГО аккаунта — сам аккаунт либо проект этого аккаунта.
--
-- Область намеренно ограничена двумя иерархическими носителями арендаторских
-- прав. Прочие типы ресурсов сюда не включены: их выдачи адресуют объект, а не
-- участие человека в аккаунте, и расширять запрет на них значило бы отвергать
-- то, чего он не охраняет.

-- +goose Up

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.membership_carrying_rights_is_kept() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Аккаунта уже нет — держать нечего (его сняли в этой же транзакции).
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.accounts WHERE id = OLD.account_id) THEN
        RETURN NULL;
    END IF;
    -- Человека уже нет — его выдачи стерегутся собственным гвардом снятия строки.
    IF NOT EXISTS (SELECT 1 FROM kacho_iam.users WHERE id = OLD.user_id) THEN
        RETURN NULL;
    END IF;
    -- Членство перезавели в этой же транзакции — вопрос беспредметен.
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

CREATE CONSTRAINT TRIGGER membership_carrying_rights_is_kept
    AFTER DELETE ON kacho_iam.memberships
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION kacho_iam.membership_carrying_rights_is_kept();

-- +goose Down

DROP TRIGGER IF EXISTS membership_carrying_rights_is_kept ON kacho_iam.memberships;
DROP FUNCTION IF EXISTS kacho_iam.membership_carrying_rights_is_kept();
