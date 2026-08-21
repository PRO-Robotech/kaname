-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 893001_grant_surface_admits_the_relation_form — у выдачи появляется ВТОРАЯ
-- ФОРМА: выдача именованного отношения, и признак «системная».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Встроенные права платформы (служебные учётки, служебные группы, публичное
-- чтение справочников) заведены прямыми фактами посева — помимо поверхности
-- выдач. Следствия наблюдаемы: перечисление выдач о них молчит, отзыв работает
-- над выдачей, а её нет, и «ничего не выдано» неотличимо от «выдано в обход».
--
-- Роль здесь не подходит: роль раздаёт ГЛАГОЛЫ (`v_get`…`v_delete`) через свои
-- правила, а встроенные права выражены ИМЕНОВАННЫМИ отношениями модели
-- (`system_viewer`, `quota_reader`, `viewer` на кластере). Подобрать роль под
-- каждое означало бы завести роли с пустыми правилами — форму без содержания.
--
-- Поэтому вторая форма: выдача несёт `granted_relation` ВМЕСТО `role_id`,
-- взаимоисключающе, и материализуется ровно одним прямым фактом через тот же
-- журнал намерений, каким идёт любой другой кортеж. Отзыв кладёт в журнал
-- снятие — факт исчезает, доступ закрыт.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ФОРМА ОТНОШЕНИЯ — ТОЛЬКО СИСТЕМНАЯ
--
-- Отношение модели — это не «роль, выданная арендатором», а внутреннее имя, от
-- которого зависит решение о доступе. Дать арендатору выдавать отношения значило
-- бы дать ему выписывать себе любое имя, включая те, что гейтят внутренние
-- вызовы. Ограничение стоит В БАЗЕ, а не в use-case: путь записи не один
-- (миграция, посев, use-case), и проверка в одном из них не связывает остальные.
--
-- ПОДСТАНОВОЧНЫЙ СУБЪЕКТ (`user:*`, «любой аутентифицированный») допустим по той
-- же причине только у системной выдачи: это единственный субъект, которого
-- нельзя ни назвать, ни отозвать поимённо, и выдавать его вправе только
-- платформа.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЯКОРЬ — ТОЛЬКО ЯРУС ИЕРАРХИИ, И ЭТО НАЗВАНО, А НЕ УМОЛЧАНО
--
-- Область выдачи — один из трёх ярусов (`cluster`/`account`/`project`): на них
-- держатся и право выдавать, и вложенность, и колонка яруса с закрытым набором
-- значений. Факт на объекте ВНЕ иерархии (например право модуля писать кортежи
-- на служебном синглтоне) этой формой не выражается — у такого якоря нет ни
-- яруса, ни владельца, который мог бы отозвать. Это отдельный предмет: либо
-- словарь якорей растёт за пределы трёх ярусов, либо способность переезжает на
-- кластерное отношение. Перепись такие факты СЧИТАЕТ и печатает отдельным
-- классом, чтобы «не покрыт» было отличимо от «не существует».

-- +goose Up
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    ADD COLUMN IF NOT EXISTS granted_relation text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS is_system        boolean NOT NULL DEFAULT false;

-- +goose StatementEnd
-- +goose StatementBegin

COMMENT ON COLUMN kacho_iam.access_bindings.granted_relation IS
    'Имя отношения модели, выдаваемое напрямую на области выдачи. Взаимоисключающе с role_id.';
COMMENT ON COLUMN kacho_iam.access_bindings.is_system IS
    'Выдача заведена платформой. Только для чтения на публичном контракте.';

-- +goose StatementEnd
-- +goose StatementBegin

-- Роль перестаёт быть обязательной: у формы отношения её нет. Внешний ключ
-- остаётся и продолжает работать — NULL он пропускает by construction, поэтому
-- ссылочная целостность формы роли не ослабляется ни на йоту.
ALTER TABLE kacho_iam.access_bindings ALTER COLUMN role_id DROP NOT NULL;

-- +goose StatementEnd
-- +goose StatementBegin

-- РОВНО ОДНА форма. Обе сразу — два источника материализации у одной строки;
-- ни одной — выдача, которая ничего не выдаёт.
ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_grant_form_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_grant_form_ck CHECK (
        (role_id IS NOT NULL AND granted_relation = '')
     OR (role_id IS NULL     AND granted_relation <> '')
    );

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_relation_form_is_system_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_relation_form_is_system_ck
        CHECK (granted_relation = '' OR is_system);

-- +goose StatementEnd
-- +goose StatementBegin

-- Форма имени отношения — та же, что у прямого факта. Отношение с точкой либо с
-- заглавной буквой в факт не спроецируется, и выдача осталась бы объявленной, но
-- недействующей.
ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_granted_relation_shape_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_granted_relation_shape_ck
        CHECK (granted_relation = '' OR granted_relation ~ '^[a-z][a-z0-9_]*$');

-- +goose StatementEnd
-- +goose StatementBegin

-- Подстановочный субъект — только у системной выдачи и только в виде `user:*`.
ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_wildcard_subject_is_system_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_wildcard_subject_is_system_ck
        CHECK (subject_id <> '*' OR (is_system AND subject_type = 'user'));

-- +goose StatementEnd
-- +goose StatementBegin

-- Уникальность формы отношения. Существующий индекс действующей выдачи ключуется
-- по роли, а у формы отношения роль NULL — в уникальном индексе NULL'ы различны,
-- поэтому он такую пару не удержал бы вовсе.
CREATE UNIQUE INDEX IF NOT EXISTS access_bindings_active_relation_grant_uniq
    ON kacho_iam.access_bindings (subject_type, subject_id, granted_relation, resource_type, resource_id)
    WHERE granted_relation <> '' AND revoked_at IS NULL;

-- +goose StatementEnd
-- +goose StatementBegin

-- Ярус выдачи с формой отношения — только иерархия. Причина в шапке.
ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_relation_form_anchor_ck;
ALTER TABLE kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_relation_form_anchor_ck CHECK (
        granted_relation = '' OR resource_type IN ('cluster', 'account', 'project')
    );

-- +goose StatementEnd
-- +goose StatementBegin

-- Проверка существования субъекта учится подстановке. Подстановочный субъект —
-- НЕ ссылка на строку: «любой аутентифицированный» строкой не представлен и
-- представлен быть не может, поэтому ветка явная. Сужение на системность у
-- родительской таблицы держит CHECK выше; у дочерней его выразить нечем —
-- признак лежит у родителя, — поэтому здесь запрос к нему.
CREATE OR REPLACE FUNCTION kacho_iam.subject_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    parent_is_system boolean;
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.subject_type = OLD.subject_type
       AND NEW.subject_id   = OLD.subject_id THEN
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' AND NEW.subject_id = '*' THEN
        IF TG_TABLE_NAME = 'access_binding_subjects' THEN
            SELECT b.is_system INTO parent_is_system
              FROM kacho_iam.access_bindings b
             WHERE b.id = NEW.binding_id
             FOR KEY SHARE;
            IF NOT FOUND OR NOT parent_is_system THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    MESSAGE = 'Illegal argument subject_id * on a non-system access binding';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' THEN
        PERFORM 1 FROM kacho_iam.users
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'service_account' THEN
        PERFORM 1 FROM kacho_iam.service_accounts
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM kacho_iam.groups
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument subject_type %s', NEW.subject_type);
    END IF;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.subject_type, NEW.subject_id);
    END IF;
    RETURN NEW;
END;
$$;

-- +goose StatementEnd
-- +goose StatementBegin

-- Стража назначаемости роли учится форме без роли. Прежняя редакция доходила до
-- нужного исхода случайно — через ветку «роли не нашлось», — и следующий
-- читатель принял бы это за дефект. Ветка названа явно.
CREATE OR REPLACE FUNCTION kacho_iam.access_binding_role_assignable() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    r_is_system  boolean;
    r_account_id text;
    r_project_id text;
    scope_account text;
BEGIN
    -- Форма отношения роли не несёт — судить нечего.
    IF NEW.role_id IS NULL THEN
        RETURN NEW;
    END IF;

    IF TG_OP = 'UPDATE'
       AND NEW.role_id       = OLD.role_id
       AND NEW.resource_type = OLD.resource_type
       AND NEW.resource_id   = OLD.resource_id THEN
        RETURN NEW;
    END IF;

    SELECT is_system, coalesce(account_id, ''), coalesce(project_id, '')
      INTO r_is_system, r_account_id, r_project_id
      FROM kacho_iam.roles
     WHERE id = NEW.role_id
     FOR KEY SHARE;

    IF NOT FOUND THEN
        RETURN NEW;
    END IF;

    IF r_is_system THEN
        RETURN NEW;
    END IF;

    IF NEW.resource_type = 'account' THEN
        IF r_account_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
    ELSIF NEW.resource_type = 'project' THEN
        IF r_project_id = NEW.resource_id THEN
            RETURN NEW;
        END IF;
        IF r_project_id = '' AND r_account_id <> '' THEN
            SELECT account_id INTO scope_account
              FROM kacho_iam.projects
             WHERE id = NEW.resource_id;
            IF FOUND AND scope_account = r_account_id THEN
                RETURN NEW;
            END IF;
        END IF;
    ELSE
        IF NEW.resource_type <> 'cluster' THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION USING ERRCODE = '23514',
        MESSAGE = format(
            'role %s is not assignable on %s:%s',
            NEW.role_id, NEW.resource_type, NEW.resource_id);
END;
$$;

-- +goose StatementEnd

-- +goose Down
--
-- ОБРАТНЫЙ ХОД СНИМАЕТ СТОЛБЦЫ И ОГРАНИЧЕНИЯ, НО НЕ ТЕЛА ФУНКЦИЙ — и это сказано,
-- а не умолчано. Обе переписанные функции — НАДМНОЖЕСТВА прежних: они принимают
-- всё, что принимали те, и вдобавок подстановочный субъект и выдачу без роли.
-- После снятия столбцов ни того, ни другого в таблице не остаётся, поэтому
-- поведение возвращается к прежнему by construction; восстанавливать текст
-- значило бы держать в дереве ТРЕТЬЮ его копию ради состояния, которого не будет.

-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.access_bindings_active_relation_grant_uniq;

-- +goose StatementEnd
-- +goose StatementBegin

DELETE FROM kacho_iam.access_bindings WHERE granted_relation <> '';

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    DROP CONSTRAINT IF EXISTS access_bindings_grant_form_ck,
    DROP CONSTRAINT IF EXISTS access_bindings_relation_form_is_system_ck,
    DROP CONSTRAINT IF EXISTS access_bindings_granted_relation_shape_ck,
    DROP CONSTRAINT IF EXISTS access_bindings_wildcard_subject_is_system_ck,
    DROP CONSTRAINT IF EXISTS access_bindings_relation_form_anchor_ck;

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings ALTER COLUMN role_id SET NOT NULL;

-- +goose StatementEnd
-- +goose StatementBegin

ALTER TABLE kacho_iam.access_bindings
    DROP COLUMN IF EXISTS granted_relation,
    DROP COLUMN IF EXISTS is_system;

-- +goose StatementEnd
