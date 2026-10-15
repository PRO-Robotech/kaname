-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- anonymous_and_authenticated_are_subject_classes — четвёртый вид субъекта
-- привязки прав, системный класс (`anonymous` | `authenticated`), и переезд
-- подстановки `user:*` на классы (задача PRO-Robotech/kaname#829).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md`,
-- SHA-256
-- `ae9ba373d26c8f4cc2a3c0036d04ff9e1a20b7cc0a8e43c1fca4690560427f51`
-- (запись `docs/specs/reviews/anonymous-and-authenticated-are-subject-classes/ae9ba373d26c8f4cc2a3c0036d04ff9e1a20b7cc0a8e43c1fca4690560427f51.yaml`,
-- `APPROVED`, событие
-- https://github.com/PRO-Robotech/kaname/issues/829#issuecomment-6181952152;
-- решения Р1, Р4, Р8, сценарии SC-01…09, SC-21…23, SC-40…44). Доводы там;
-- здесь — то, что нужно читателю СХЕМЫ. Применённые миграции не правятся:
-- ограничения снимаются и объявляются заново под ТЕМИ ЖЕ именами, функции
-- переобъявляются целиком.
--
-- =============================================================================
-- 1. ВИД СУБЪЕКТА `system_class`
-- =============================================================================
-- Оба ограничения О ВЫДАЧЕ (`access_bindings_subject_ck`,
-- `access_binding_subjects_type_ck`) принимают новый вид. Ограничения членства
-- в группе (`group_members_type_check`) и кластерного администратора
-- (`cluster_admin_grants_subject_type_check`) НЕ трогаются: класс не бывает ни
-- членом группы, ни кластерным администратором (SC-08, SC-09).
--
-- Существование субъекта (`kaname.subject_ref_exists`) у класса — закрытый
-- словарь из двух имён без поиска строки ресурса. Подстановка `*` субъектом не
-- бывает ни у какой выдачи: у обычной она отвергалась и прежде, у системной
-- заменена классом (п. 3).
--
-- =============================================================================
-- 2. КЛАССУ — ТОЛЬКО ЧТЕНИЕ (Р4)
-- =============================================================================
-- Субъект-класс у выдачи с ролью принимается, только если КАЖДЫЙ глагол роли —
-- `get` либо `list` (`kaname.role_grants_reads_only`; `*` пишущим считается
-- всегда — он раскрывается в набор типа, а набор растёт). Порядок двух
-- параллельных сторон держит замок строки роли, и берёт его выдача РАНЬШЕ
-- этого стража: `INSERT INTO access_bindings` зовёт триггер
-- `access_bindings_role_is_live_trg`, а тот читает роль под `FOR SHARE`. Правка
-- роли берёт ту же строку под `FOR NO KEY UPDATE`
-- (`RolesW().GuardSystemClassReads`), замки несовместимы, и из двух сторон
-- проходит ровно одна (SC-22, гонка DoD S2). Замер пробы SC-22
-- (`system_class_role_edit_race_integration_test.go`): выдача, пришедшая
-- второй, стоит на операторе `INSERT INTO access_bindings`, а не на вставке
-- субъекта. Страж класса перечитывает роль под `FOR SHARE` уже держащейся
-- транзакцией — нового ожидания это не даёт, зато правила он видит после
-- коммита правки. Отказ — 23000 с именем связи; текст ставит служба по связи,
-- а роль приходит деталью.
--
-- Роль, получившая пишущий глагол путём, который правкой роли не является
-- (поставка модулем), этим стражем не ловится — его судит выдача ответа:
-- ветви выдач формы вердикта раздают классу только чтение на каждом вопросе
-- (SC-23).
--
-- =============================================================================
-- 3. ПЕРЕЕЗД ПОДСТАНОВКИ (Р8)
-- =============================================================================
-- Системная выдача чтения справочников (`acbc5d32d66fc8dc4952`, отношение
-- `viewer` на кластере) переходит на субъекта `system_class/authenticated`; id,
-- отношение, системность и защита от удаления сохраняются. Выпущенные факты
-- выдачи (`access_binding_emitted_tuples`) — туда же. Прямые факты
-- (`relation_fact`) с подстановкой делятся по отношению: `v_get` — это
-- публикация владельца для чтения без входа, её хранимый субъект —
-- `system_class:anonymous` (`domain.PublicationSubject`); всё прочее —
-- «любой вошедший», `system_class:authenticated`.
--
-- ЯКОРЬ КЛАСТЕРА НЕ ВЫПИСАН. Выдача находится по субъекту, факты — по
-- субъекту и отношению: написание якоря — свойство установки (его переписывает
-- `kaname.rename_cluster_anchor`), и предикат с литералом якоря на установке с
-- другим написанием переписал бы ноль строк и прошёл молча.
--
-- НОЛЬ — НЕ ТИШИНА. После переписи подстановка не обязана встречаться ни в
-- одном из четырёх мест (SC-43); встретилась — отказ миграции целиком, а не
-- частичное состояние.
--
-- НОЛЬ ДЕРЖИТ ОГРАНИЧЕНИЕ, А НЕ ПЕРЕПИСЬ. Перепись судит состояние на миг
-- наката; писатель прежней версии, работающий во время выкатки, положил бы
-- подстановку и после неё — прямо в выпущенные факты выдачи либо журналом,
-- который проекция переносит в `relation_fact`. Поэтому после переписи обе
-- таблицы фактов получают проверочные ограничения
-- `relation_fact_subject_not_wildcard` и
-- `access_binding_emitted_tuples_user_not_wildcard`: субъект, чей идентификатор
-- — `*` (`тип:*` и `тип:*#отношение`), отвергается с 23514 при любой записи,
-- в том числе журнальной. Выдачи держит `kaname.subject_ref_exists`.
--
-- ПОВТОР БЕЗВРЕДЕН (SC-44): выборка — по подстановке, которой после первого
-- наката нет; вставки — `ON CONFLICT DO NOTHING` без цели; ограничения и
-- функции переобъявляются целиком.
--
-- Журнал `fga_outbox` НЕ переписывается: он история доставки, применённое в
-- нём не повторяется, а проекция журнала в факт срабатывает только на вставке.

-- +goose Up

-- 1. Вид субъекта.
ALTER TABLE kaname.access_bindings DROP CONSTRAINT IF EXISTS access_bindings_subject_ck;
ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_subject_ck
        CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text, 'system_class'::text])));

ALTER TABLE kaname.access_binding_subjects DROP CONSTRAINT IF EXISTS access_binding_subjects_type_ck;
ALTER TABLE kaname.access_binding_subjects
    ADD CONSTRAINT access_binding_subjects_type_ck
        CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text, 'system_class'::text])));

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.subject_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.subject_type = OLD.subject_type
       AND NEW.subject_id   = OLD.subject_id THEN
        RETURN NEW;
    END IF;

    -- Подстановка субъектом не бывает ни у какой выдачи (Инвариант 3 приёмки):
    -- «любой вошедший» и «аноним» — системные классы.
    IF NEW.subject_id = '*' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = 'Illegal argument subject_id * on a non-system access binding';
    END IF;

    IF NEW.subject_type = 'system_class' THEN
        IF NEW.subject_id NOT IN ('anonymous', 'authenticated') THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = format('Illegal argument subject id %s for subject type system_class', NEW.subject_id);
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.subject_type = 'user' THEN
        PERFORM 1 FROM kaname.users
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'service_account' THEN
        PERFORM 1 FROM kaname.service_accounts
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM kaname.groups
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

-- 2. Классу — только чтение.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.role_grants_reads_only(p_rules jsonb, p_permissions jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE
        WHEN jsonb_array_length(coalesce(p_rules, '[]'::jsonb)) > 0 THEN
            NOT EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(p_rules) AS r(rule),
                       jsonb_array_elements_text(coalesce(r.rule -> 'verbs', '[]'::jsonb)) AS v(verb)
                 WHERE lower(btrim(v.verb)) NOT IN ('get', 'list'))
        ELSE
            NOT EXISTS (
                SELECT 1
                  FROM jsonb_array_elements_text(coalesce(p_permissions, '[]'::jsonb)) AS p(perm)
                 WHERE position('.' IN p.perm) = 0
                    OR lower(btrim(regexp_replace(p.perm, '^.*\.', ''))) NOT IN ('get', 'list'))
    END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.role_grants_reads_only(jsonb, jsonb) IS 'Каждый глагол роли — get либо list (Р4 приёмки системного класса, kaname#829). Судится авторское написание: `*` пишущим считается всегда, потому что раскрывается в набор типа, а набор растёт. Роль без правил судится по хранимой проекции прав (последний сегмент — глагол). Зеркало domain.Role.GrantsReadsOnly; здесь — ради последнего слова записи.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.access_binding_subject_class_reads_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_role  text;
    v_rules jsonb;
    v_perms jsonb;
BEGIN
    IF NEW.subject_type <> 'system_class' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
       AND NEW.subject_type = OLD.subject_type
       AND NEW.subject_id   = OLD.subject_id THEN
        RETURN NEW;
    END IF;

    SELECT b.role_id INTO v_role
      FROM kaname.access_bindings b
     WHERE b.id = NEW.binding_id;
    IF v_role IS NULL THEN
        -- Выдача ОТНОШЕНИЯ (системная форма, роли нет): её заводит только
        -- платформа, и отношение названо ею самой.
        RETURN NEW;
    END IF;

    SELECT r.rules, r.permissions INTO v_rules, v_perms
      FROM kaname.roles r
     WHERE r.id = v_role
       FOR SHARE;
    IF NOT FOUND THEN
        -- Отсутствующую роль судит внешний ключ выдачи.
        RETURN NEW;
    END IF;

    IF NOT kaname.role_grants_reads_only(v_rules, v_perms) THEN
        RAISE EXCEPTION
            'role % grants verbs beyond get and list; a system class subject accepts read-only roles', v_role
            USING ERRCODE = '23000',
                  CONSTRAINT = 'access_binding_subjects_system_class_reads_only',
                  DETAIL = v_role;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.access_binding_subject_class_reads_only() IS 'Субъект-класс принимается у выдачи только с ролью, все глаголы которой — get/list (Р4, SC-21). Строка роли — под FOR SHARE; порядок с правкой роли (FOR NO KEY UPDATE) держит замок, который выдача берёт раньше, — FOR SHARE триггера access_bindings_role_is_live_trg на вставке выдачи, и из параллельных «выдача классу» и «правка роли» проходит ровно одна (SC-22). Отказ — 23000 с именем связи; роль — в DETAIL, текст ставит служба (kaname#829).';

DROP TRIGGER IF EXISTS access_binding_subjects_class_reads_only_trg ON kaname.access_binding_subjects;
CREATE TRIGGER access_binding_subjects_class_reads_only_trg
    BEFORE INSERT OR UPDATE ON kaname.access_binding_subjects
    FOR EACH ROW EXECUTE FUNCTION kaname.access_binding_subject_class_reads_only();

-- 3. Переезд подстановки.
UPDATE kaname.access_bindings
   SET subject_type = 'system_class', subject_id = 'authenticated'
 WHERE subject_type = 'user' AND subject_id = '*' AND is_system;

UPDATE kaname.access_binding_subjects bs
   SET subject_type = 'system_class', subject_id = 'authenticated'
  FROM kaname.access_bindings b
 WHERE b.id = bs.binding_id AND b.is_system
   AND bs.subject_type = 'user' AND bs.subject_id = '*';

INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
SELECT et.binding_id, 'system_class:authenticated', et.relation, et.object, et.source
  FROM kaname.access_binding_emitted_tuples et
 WHERE et.fga_user = 'user:*'
ON CONFLICT DO NOTHING;
DELETE FROM kaname.access_binding_emitted_tuples WHERE fga_user = 'user:*';

INSERT INTO kaname.relation_fact
       (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params)
SELECT f.object_type, f.object_id, f.relation,
       CASE WHEN f.relation = 'v_get' THEN 'system_class:anonymous'
            ELSE 'system_class:authenticated' END,
       f.source_version, f.created_at, f.condition_name, f.condition_params
  FROM kaname.relation_fact f
 WHERE f.subject = 'user:*'
ON CONFLICT DO NOTHING;
DELETE FROM kaname.relation_fact WHERE subject = 'user:*';

-- Ноль — не тишина: подстановка не встречается ни в одном из четырёх мест.
-- +goose StatementBegin
DO $$
DECLARE
    v_bindings int;
    v_subjects int;
    v_emitted  int;
    v_facts    int;
BEGIN
    SELECT count(*) INTO v_bindings FROM kaname.access_bindings WHERE subject_id = '*';
    SELECT count(*) INTO v_subjects FROM kaname.access_binding_subjects WHERE subject_id = '*';
    SELECT count(*) INTO v_emitted  FROM kaname.access_binding_emitted_tuples WHERE fga_user LIKE '%:*';
    SELECT count(*) INTO v_facts    FROM kaname.relation_fact WHERE subject LIKE '%:*';
    IF v_bindings + v_subjects + v_emitted + v_facts > 0 THEN
        RAISE EXCEPTION
            'subject classes: the wildcard subject survived the move (bindings %, binding subjects %, emitted tuples %, facts %) — a wildcard left behind would grant by a subject nobody can name or revoke',
            v_bindings, v_subjects, v_emitted, v_facts;
    END IF;
END
$$;
-- +goose StatementEnd

-- Ноль держит ограничение: запись подстановки после переезда отвергается.
ALTER TABLE kaname.relation_fact DROP CONSTRAINT IF EXISTS relation_fact_subject_not_wildcard;
ALTER TABLE kaname.relation_fact
    ADD CONSTRAINT relation_fact_subject_not_wildcard
        CHECK ((subject !~ ':\*($|#)'::text));

ALTER TABLE kaname.access_binding_emitted_tuples DROP CONSTRAINT IF EXISTS access_binding_emitted_tuples_user_not_wildcard;
ALTER TABLE kaname.access_binding_emitted_tuples
    ADD CONSTRAINT access_binding_emitted_tuples_user_not_wildcard
        CHECK ((fga_user !~ ':\*($|#)'::text));

-- +goose Down

-- Откат возвращает подстановку на место классов — но ТОЛЬКО если классу не
-- выдано ничего, кроме системной выдачи и публикаций: выдачу классу,
-- заведённую арендатором, прежняя схема выразить не может, и молча снять её
-- значило бы отозвать право без следа.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM kaname.access_binding_subjects bs
                 JOIN kaname.access_bindings b ON b.id = bs.binding_id
                WHERE bs.subject_type = 'system_class' AND NOT b.is_system) THEN
        RAISE EXCEPTION
            'subject classes: tenant grants to a system class exist; the previous schema cannot express them — revoke them before rolling back';
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE kaname.relation_fact DROP CONSTRAINT IF EXISTS relation_fact_subject_not_wildcard;
ALTER TABLE kaname.access_binding_emitted_tuples DROP CONSTRAINT IF EXISTS access_binding_emitted_tuples_user_not_wildcard;

DROP TRIGGER IF EXISTS access_binding_subjects_class_reads_only_trg ON kaname.access_binding_subjects;
DROP FUNCTION IF EXISTS kaname.access_binding_subject_class_reads_only();
DROP FUNCTION IF EXISTS kaname.role_grants_reads_only(jsonb, jsonb);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.subject_ref_exists() RETURNS trigger
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
              FROM kaname.access_bindings b
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
        PERFORM 1 FROM kaname.users
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'service_account' THEN
        PERFORM 1 FROM kaname.service_accounts
            WHERE id = NEW.subject_id FOR KEY SHARE;
    ELSIF NEW.subject_type = 'group' THEN
        PERFORM 1 FROM kaname.groups
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

UPDATE kaname.access_bindings
   SET subject_type = 'user', subject_id = '*'
 WHERE subject_type = 'system_class' AND is_system;

UPDATE kaname.access_binding_subjects bs
   SET subject_type = 'user', subject_id = '*'
  FROM kaname.access_bindings b
 WHERE b.id = bs.binding_id AND b.is_system
   AND bs.subject_type = 'system_class';

INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
SELECT et.binding_id, 'user:*', et.relation, et.object, et.source
  FROM kaname.access_binding_emitted_tuples et
 WHERE et.fga_user LIKE 'system_class:%'
ON CONFLICT DO NOTHING;
DELETE FROM kaname.access_binding_emitted_tuples WHERE fga_user LIKE 'system_class:%';

INSERT INTO kaname.relation_fact
       (object_type, object_id, relation, subject, source_version, created_at, condition_name, condition_params)
SELECT f.object_type, f.object_id, f.relation, 'user:*',
       f.source_version, f.created_at, f.condition_name, f.condition_params
  FROM kaname.relation_fact f
 WHERE f.subject LIKE 'system_class:%'
ON CONFLICT DO NOTHING;
DELETE FROM kaname.relation_fact WHERE subject LIKE 'system_class:%';

ALTER TABLE kaname.access_binding_subjects DROP CONSTRAINT IF EXISTS access_binding_subjects_type_ck;
ALTER TABLE kaname.access_binding_subjects
    ADD CONSTRAINT access_binding_subjects_type_ck
        CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text])));

ALTER TABLE kaname.access_bindings DROP CONSTRAINT IF EXISTS access_bindings_subject_ck;
ALTER TABLE kaname.access_bindings
    ADD CONSTRAINT access_bindings_subject_ck
        CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text])));
