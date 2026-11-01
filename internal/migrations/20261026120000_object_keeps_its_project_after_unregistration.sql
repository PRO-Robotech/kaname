-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- object_keeps_its_project_after_unregistration — привязка объекта модуля к
-- проекту, переживающая снятие регистрации (задача PRO-Robotech/kaname#983).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md,
-- редакция 2, отпечаток одобренной редакции
-- 9bd07e389bdce22cad13b556b4fe78cfda3f878285895282a5580fa211e5122a (записи ревью —
-- docs/specs/reviews/object-keeps-its-project-after-unregistration/), решения Р1,
-- Р3, Р4, Р7, Р8, Р8а, Р9.
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `catalog_resource.permanent_project` — тип объявлен манифестом модуля
--      ключом `permanentProject: true` (Р7). Пишет применитель каталога из
--      доставленного манифеста; посеянные строки ключа не несут.
--   2. `catalog_resource.project_bindings_held` — у типа МОГУТ быть привязки:
--      признак ставится вместе с объявлением и не снимается снятием объявления
--      (Р8а). Нужен затем, чтобы регистрация НИКОГДА не объявлявшегося типа не
--      обращалась к привязкам вовсе (критерий производительности приёмки), а
--      снятое объявление не снимало суда по уже заведённым привязкам.
--   3. `object_project_binding` — привязка `(модельный тип, id) → проект` с
--      первичным ключом. Ссылки на проект у неё нет: удаление проекта она не
--      блокирует и при нём не исчезает (PB-21). Проект привязки не меняется, и
--      привязка не удаляется ни снятием регистрации, ни иным путём (триггеры
--      `…_is_permanent`, в том числе `BEFORE TRUNCATE`, PB-20).
--   4. `object_project_binding_refuses` — ЕДИНСТВЕННЫЙ предикат «привязка
--      отвергает эту регистрацию»: им судят и оба триггера записи (зеркала и
--      цепи), и use-case, когда к запросу приложимы и отказ вывода родителя, и
--      отказ привязки (порядок Р10 приёмки kaname#982, §7 строка 4). Второго
--      предиката привязки нигде нет.
--   5. Триггер строки зеркала заводит привязку первой принятой регистрацией
--      объявленного типа (проект — проект строки) и сверяет с ней проект строки
--      на КАЖДОЙ записи; триггер цепи сверяет каждое звено `project`. Оба —
--      на всех путях записи зеркала и цепи (Р9), а не в use-case.
--   6. Объявление, впервые выставленное типу, той же транзакцией привязывает
--      каждый зарегистрированный объект типа с непустым проектом (Р8).
--
-- ПОРЯДОК ОБЪЯВЛЕНИЯ И РЕГИСТРАЦИИ (PB-18). Триггер строки зеркала читает строку
-- каталога `FOR SHARE`: этот замок конфликтует с правкой строки каталога, поэтому
-- регистрация и объявление, идущие одновременно, упорядочиваются замком строки
-- каталога. Объявление первым — регистрация ждёт его коммита и видит признак;
-- регистрация первой — объявление ждёт её коммита и привязывает её строку.
--
-- ОТКАЗ — SQLSTATE класса 23 (`integrity_constraint_violation`) с именем
-- `object_project_binding_holds`: по имени его узнаёт и переводит в отказ привязки
-- адаптер записи зеркала (`resource_mirror`), а не в INTERNAL.
--
-- ОТКАТ снимает триггеры, функции, таблицу и колонки. Откат отказывает, пока
-- лежит хоть одна привязка: прежняя схема её не знает, и снять её молча значило
-- бы вернуть перенос объекта между проектами снятием и повторной регистрацией.

-- +goose Up
ALTER TABLE kaname.catalog_resource
    ADD COLUMN permanent_project boolean NOT NULL DEFAULT false,
    ADD COLUMN project_bindings_held boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN kaname.catalog_resource.permanent_project IS 'Тип объявлен манифестом модуля ключом permanentProject: регистрация объекта типа привязывает его id к проекту, и привязка переживает снятие регистрации. kaname#983.';
COMMENT ON COLUMN kaname.catalog_resource.project_bindings_held IS 'У типа могут быть привязки к проекту: признак ставится вместе с объявлением permanent_project и снятием объявления не снимается (Р8а) — заведённые привязки продолжают действовать. Регистрация типа без признака к привязкам не обращается. kaname#983.';

CREATE TABLE kaname.object_project_binding (
    object_type text NOT NULL,
    object_id   text NOT NULL,
    project_id  text NOT NULL,
    bound_at    timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT object_project_binding_pkey PRIMARY KEY (object_type, object_id),
    CONSTRAINT object_project_binding_object_type_model_dictionary CHECK (object_type !~~ '%.%'::text),
    CONSTRAINT object_project_binding_object_type_nonempty CHECK (object_type <> ''::text),
    CONSTRAINT object_project_binding_object_id_nonempty CHECK (object_id <> ''::text),
    CONSTRAINT object_project_binding_project_id_nonempty CHECK (project_id <> ''::text)
);

COMMENT ON TABLE kaname.object_project_binding IS 'Привязка id объекта модуля к проекту (модельный тип, id → проект): заводится первой принятой регистрацией объявленного типа либо объявлением ключа permanentProject, не меняется и не удаляется — переживает снятие регистрации и удаление проекта. Ссылки на проект нет намеренно. kaname#983.';

-- +goose StatementBegin
CREATE FUNCTION kaname.object_project_binding_is_permanent() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.object_type = OLD.object_type
       AND NEW.object_id = OLD.object_id
       AND NEW.project_id = OLD.project_id THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'object project binding is permanent: % is refused', TG_OP
        USING ERRCODE = 'restrict_violation',
              CONSTRAINT = 'object_project_binding_is_permanent',
              TABLE = 'object_project_binding',
              SCHEMA = 'kaname';
END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.object_project_binding_is_permanent() IS 'Проект привязки объекта не меняется, привязка не удаляется ни строкой, ни TRUNCATE (Р3, Р9). Отказ — SQLSTATE 23001. kaname#983.';

CREATE TRIGGER object_project_binding_is_permanent
    BEFORE UPDATE OR DELETE ON kaname.object_project_binding
    FOR EACH ROW EXECUTE FUNCTION kaname.object_project_binding_is_permanent();

CREATE TRIGGER object_project_binding_is_not_truncated
    BEFORE TRUNCATE ON kaname.object_project_binding
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.object_project_binding_is_permanent();

-- object_project_binding_refuses — привязка отвергает регистрацию объекта
-- (p_model_type, p_object_id) с проектом поля p_project (NULL — поле не судится)
-- и цепью p_chain (звенья `<тип>:<id>`). Привязка — заведённая раньше либо та,
-- которую заведёт эта регистрация объявленного типа (её проект — p_project).
-- Тип без объявления и без заведённых привязок не судится и к привязкам не
-- обращается.
-- +goose StatementBegin
CREATE FUNCTION kaname.object_project_binding_refuses(
    p_model_type text, p_object_id text, p_project text, p_chain text[]
) RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_declared boolean;
    v_held     boolean;
    v_bound    text;
BEGIN
    SELECT coalesce(bool_or(cr.permanent_project AND cr.live), false),
           coalesce(bool_or(cr.permanent_project OR cr.project_bindings_held), false)
      INTO v_declared, v_held
      FROM kaname.catalog_resource cr
     WHERE cr.object_type = p_model_type;
    IF NOT v_held THEN
        RETURN false;
    END IF;
    SELECT b.project_id INTO v_bound
      FROM kaname.object_project_binding b
     WHERE b.object_type = p_model_type AND b.object_id = p_object_id;
    IF v_bound IS NULL THEN
        IF v_declared AND coalesce(p_project, '') <> '' THEN
            v_bound := p_project;
        ELSE
            RETURN false;
        END IF;
    END IF;
    IF p_project IS NOT NULL AND p_project IS DISTINCT FROM v_bound THEN
        RETURN true;
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM unnest(coalesce(p_chain, ARRAY[]::text[])) AS l(link)
         WHERE split_part(l.link, ':', 1) = 'project'
           AND substr(l.link, strpos(l.link, ':') + 1) <> v_bound);
END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.object_project_binding_refuses(text, text, text, text[]) IS 'Единственный предикат «привязка к проекту отвергает регистрацию»: проект поля (NULL — не судится) и каждое звено project цепи против привязки — заведённой либо заводимой этой регистрацией объявленного типа. Им судят триггеры зеркала и цепи и use-case (порядок отказов kaname#982 Р10). kaname#983.';

-- resource_mirror_keeps_the_bound_project — триггер строки зеркала: заводит
-- привязку первой принятой регистрацией объявленного типа и сверяет с привязкой
-- проект строки на каждой записи.
-- +goose StatementBegin
CREATE FUNCTION kaname.resource_mirror_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_model_type text;
    v_declared   boolean;
    v_held       boolean;
BEGIN
    -- Замок строки каталога — FOR SHARE: он упорядочивает регистрацию с
    -- объявлением признака (PB-18), а регистрации между собой не держит.
    SELECT cr.object_type, cr.permanent_project AND cr.live, cr.permanent_project OR cr.project_bindings_held
      INTO v_model_type, v_declared, v_held
      FROM kaname.catalog_resource cr
     WHERE cr.dotted = NEW.object_type
       FOR SHARE;
    IF NOT FOUND OR NOT v_held THEN
        RETURN NEW;
    END IF;
    IF v_declared AND NEW.parent_project_id <> '' THEN
        INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
        VALUES (v_model_type, NEW.object_id, NEW.parent_project_id)
        ON CONFLICT (object_type, object_id) DO NOTHING;
    END IF;
    IF kaname.object_project_binding_refuses(v_model_type, NEW.object_id, NEW.parent_project_id, ARRAY[]::text[]) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', v_model_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_mirror',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.resource_mirror_keeps_the_bound_project() IS 'Строка зеркала объекта с привязкой несёт проект привязки: первая принятая регистрация объявленного типа заводит привязку, каждая запись сверяется с ней (Р3, Р4, Р9). Отказ — SQLSTATE 23000, ограничение object_project_binding_holds. kaname#983.';

CREATE TRIGGER resource_mirror_keeps_the_bound_project
    BEFORE INSERT OR UPDATE ON kaname.resource_mirror
    FOR EACH ROW EXECUTE FUNCTION kaname.resource_mirror_keeps_the_bound_project();

-- resource_parent_edge_keeps_the_bound_project — триггер цепи: звено `project`
-- объекта с привязкой называет проект привязки.
-- +goose StatementBegin
CREATE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF kaname.object_project_binding_refuses(NEW.object_type, NEW.object_id, NULL,
                                             ARRAY[NEW.parent_type || ':' || NEW.parent_id]) THEN
        RAISE EXCEPTION 'object %:% is bound to another project', NEW.object_type, NEW.object_id
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'object_project_binding_holds',
                  TABLE = 'resource_parent_edge',
                  SCHEMA = 'kaname';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() IS 'Каждое звено project цепи объекта с привязкой называет проект привязки (Р4, Р9, Д-983-1). Отказ — SQLSTATE 23000, ограничение object_project_binding_holds. kaname#983.';

CREATE TRIGGER resource_parent_edge_keeps_the_bound_project
    BEFORE INSERT OR UPDATE ON kaname.resource_parent_edge
    FOR EACH ROW WHEN (NEW.parent_type = 'project')
    EXECUTE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project();

-- catalog_resource_holds_project_bindings — объявление ставит признак «у типа
-- могут быть привязки» той же записью строки каталога; снятие объявления его не
-- снимает (Р8а).
-- +goose StatementBegin
CREATE FUNCTION kaname.catalog_resource_holds_project_bindings() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.permanent_project THEN
        NEW.project_bindings_held := true;
    ELSIF TG_OP = 'UPDATE' THEN
        NEW.project_bindings_held := OLD.project_bindings_held OR NEW.project_bindings_held;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER catalog_resource_holds_project_bindings
    BEFORE INSERT OR UPDATE ON kaname.catalog_resource
    FOR EACH ROW EXECUTE FUNCTION kaname.catalog_resource_holds_project_bindings();

-- catalog_resource_binds_registered_objects — объявление, впервые выставленное
-- типу, привязывает каждый его зарегистрированный объект с непустым проектом к
-- этому проекту той же транзакцией (Р8). Объект, чья привязка уже заведена, не
-- перепривязывается.
-- +goose StatementBegin
CREATE FUNCTION kaname.catalog_resource_binds_registered_objects() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
    SELECT NEW.object_type, m.object_id, m.parent_project_id
      FROM kaname.resource_mirror m
     WHERE m.object_type = NEW.dotted AND m.parent_project_id <> ''
    ON CONFLICT (object_type, object_id) DO NOTHING;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.catalog_resource_binds_registered_objects() IS 'Объявление permanentProject, впервые выставленное типу, привязывает его зарегистрированные объекты с непустым проектом той же транзакцией (Р8). kaname#983.';

CREATE TRIGGER catalog_resource_binds_registered_objects_on_insert
    AFTER INSERT ON kaname.catalog_resource
    FOR EACH ROW WHEN (NEW.permanent_project)
    EXECUTE FUNCTION kaname.catalog_resource_binds_registered_objects();

CREATE TRIGGER catalog_resource_binds_registered_objects_on_declare
    AFTER UPDATE OF permanent_project ON kaname.catalog_resource
    FOR EACH ROW WHEN (NEW.permanent_project AND NOT OLD.permanent_project)
    EXECUTE FUNCTION kaname.catalog_resource_binds_registered_objects();

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    v_bound bigint;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'object project binding rollback requires READ COMMITTED'
            USING ERRCODE = '25001';
    END IF;
    -- Сначала исключаем всех производителей привязки, затем читаем свежий
    -- снимок: ожидаемый writer мог закоммитить первую привязку под замком.
    LOCK TABLE kaname.catalog_resource, kaname.resource_mirror,
               kaname.resource_parent_edge, kaname.object_project_binding
        IN ACCESS EXCLUSIVE MODE;
    SELECT count(*) INTO v_bound FROM kaname.object_project_binding;
    IF v_bound > 0 THEN
        RAISE EXCEPTION
            'object project binding: % binding(s) exist; rolling back would let an object move between projects', v_bound;
    END IF;
END
$$;
-- +goose StatementEnd

DROP TRIGGER catalog_resource_binds_registered_objects_on_declare ON kaname.catalog_resource;
DROP TRIGGER catalog_resource_binds_registered_objects_on_insert ON kaname.catalog_resource;
DROP FUNCTION kaname.catalog_resource_binds_registered_objects();
DROP TRIGGER catalog_resource_holds_project_bindings ON kaname.catalog_resource;
DROP FUNCTION kaname.catalog_resource_holds_project_bindings();
DROP TRIGGER resource_parent_edge_keeps_the_bound_project ON kaname.resource_parent_edge;
DROP FUNCTION kaname.resource_parent_edge_keeps_the_bound_project();
DROP TRIGGER resource_mirror_keeps_the_bound_project ON kaname.resource_mirror;
DROP FUNCTION kaname.resource_mirror_keeps_the_bound_project();
DROP FUNCTION kaname.object_project_binding_refuses(text, text, text, text[]);
DROP TRIGGER object_project_binding_is_not_truncated ON kaname.object_project_binding;
DROP TRIGGER object_project_binding_is_permanent ON kaname.object_project_binding;
DROP TABLE kaname.object_project_binding;
DROP FUNCTION kaname.object_project_binding_is_permanent();
ALTER TABLE kaname.catalog_resource
    DROP COLUMN project_bindings_held,
    DROP COLUMN permanent_project;
