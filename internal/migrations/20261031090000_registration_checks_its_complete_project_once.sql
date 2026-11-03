-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- САНКЦИЯ: docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md
-- kaname#983: один полный валидатор регистрации под управлением БД. Без сохранённого допуска,
-- дополнительной роли, SECURITY DEFINER, клиентского флага или вызываемого частичного пути записи.
-- See docs/engineering/architecture/registration-command-validation.md.
-- +goose Up

CREATE VIEW kaname.resource_registration_command AS
SELECT NULL::text AS dotted_type, NULL::text AS object_id,
       NULL::text AS parent_project_id, NULL::text AS parent_account_id,
       NULL::jsonb AS labels, NULL::timestamptz AS source_version,
       NULL::text[] AS parent_chain, false AS type_live,
       NULL::text AS model_type, false AS applied, false AS projection_unchanged
 WHERE false;

-- +goose StatementBegin
CREATE FUNCTION kaname.resource_registration_command_apply() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, kaname AS $$
DECLARE
    v_declared boolean;
    v_held boolean;
    v_bound text;
    v_chain text[] := ARRAY[]::text[];
    v_link text;
    v_type text;
    v_id text;
    v_count bigint;
    v_locked boolean;
BEGIN
    IF pg_trigger_depth() <> 1 THEN
        RAISE EXCEPTION 'registration command requires a direct entry'
            USING ERRCODE = 'integrity_constraint_violation',
                  CONSTRAINT = 'resource_registration_command_direct_entry';
    END IF;
    -- Выходы — исключительно решения БД, никогда не входное полномочие.
    NEW.type_live := false;
    NEW.model_type := NULL;
    NEW.applied := false;
    NEW.projection_unchanged := false;
    NEW.labels := coalesce(NEW.labels, '{}'::jsonb);
    NEW.parent_chain := coalesce(NEW.parent_chain, ARRAY[]::text[]);

    -- kaname#874: сравнение ниже — ДРУГОЙ оператор/снимок SPI после
    -- ожидания этого замка. VOLATILE обязателен; не объединять в один CTE.
    PERFORM 1 FROM kaname.resource_mirror m
     WHERE m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       FOR NO KEY UPDATE;
    v_locked := FOUND;
    -- Настоящая запись кортежа — барьер конфликта RR: устаревшая транзакция должна
    -- сериализоваться/повториться, а не считать невидимую привязку или ребро отсутствующим.
    -- Присваивание неключевого поля сохраняет все логические столбцы каталога. Обратный вызов
    -- признака удержания сохраняет его значение; дозаполнение UPDATE OF permanent_project
    -- не вызывается. Дополнительное чтение привязки или сохранённое свидетельство не нужны.
    UPDATE kaname.catalog_resource cr
       SET project_bindings_held = cr.project_bindings_held
     WHERE cr.dotted = NEW.dotted_type AND cr.live
     RETURNING cr.object_type, cr.permanent_project,
               cr.permanent_project OR cr.project_bindings_held
          INTO NEW.model_type, v_declared, v_held;
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    NEW.type_live := true;

    FOREACH v_link IN ARRAY NEW.parent_chain LOOP
        IF v_link IS NULL OR strpos(v_link, ':') <= 1
           OR strpos(v_link, ':') = length(v_link) THEN
            RAISE EXCEPTION 'invalid registration parent reference'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_reference_form';
        END IF;
        v_type := split_part(v_link, ':', 1);
        v_id := substr(v_link, strpos(v_link, ':') + 1);
        IF strpos(v_type, '.') > 0 THEN
            SELECT cr.object_type INTO v_type FROM kaname.catalog_resource cr
             WHERE cr.dotted = split_part(v_link, ':', 1);
            IF NOT FOUND THEN
                RAISE EXCEPTION 'unknown registration parent type'
                    USING ERRCODE = 'check_violation', CONSTRAINT = 'registration_parent_type_known';
            END IF;
        END IF;
        v_chain := array_append(v_chain, v_type || ':' || v_id);
    END LOOP;

    -- Сначала зеркало, затем привязка для КАЖДОГО писателя, включая прямой UPSERT.
    -- Эти записи предварительные: полная валидация ниже обязательна
    -- даже для устаревшего/пустого действия, любой отказ откатывает весь оператор.
    UPDATE kaname.resource_mirror m
       SET source_version = NEW.source_version, updated_at = now()
     WHERE v_locked AND m.object_type = NEW.dotted_type AND m.object_id = NEW.object_id
       AND m.parent_project_id = NEW.parent_project_id
       AND m.parent_account_id = NEW.parent_account_id
       AND m.labels = NEW.labels AND m.source_version < NEW.source_version
       AND v_chain = ARRAY(SELECT pe.parent_type || ':' || pe.parent_id
                            FROM kaname.resource_parent_edge pe
                           WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id
                           ORDER BY pe.depth);
    GET DIAGNOSTICS v_count = ROW_COUNT;
    NEW.applied := v_count > 0;
    NEW.projection_unchanged := NEW.applied;
    IF NOT NEW.applied THEN
        INSERT INTO kaname.resource_mirror
            (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
        VALUES (NEW.dotted_type, NEW.object_id, NEW.parent_project_id, NEW.parent_account_id,
                NEW.labels, NEW.source_version, now())
        ON CONFLICT (object_type, object_id) DO UPDATE
            SET parent_project_id = EXCLUDED.parent_project_id,
                parent_account_id = EXCLUDED.parent_account_id,
                labels = EXCLUDED.labels, source_version = EXCLUDED.source_version, updated_at = now()
          WHERE resource_mirror.source_version < EXCLUDED.source_version;
        GET DIAGNOSTICS v_count = ROW_COUNT;
        NEW.applied := v_count > 0;
    END IF;

    IF v_held THEN
        -- Устаревший запрос никогда не должен устанавливать первую привязку. Конкурентная
        -- вставка первой взяла замок зеркала; эта фактическая запись теперь сериализуется
        -- на той же строке до обращения к уникальному индексу привязки.
        IF NEW.applied AND v_declared AND NEW.parent_project_id <> '' THEN
            INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
            VALUES (NEW.model_type, NEW.object_id, NEW.parent_project_id)
            ON CONFLICT (object_type, object_id) DO NOTHING;
        END IF;
        -- ЕДИНСТВЕННОЕ чтение привязки на пути полной команды, свежее после
        -- ожидания конфликта. Каждая ссылка на проект сравнивается с этим локальным значением.
        SELECT b.project_id INTO v_bound FROM kaname.object_project_binding b
         WHERE b.object_type = NEW.model_type AND b.object_id = NEW.object_id;
        IF v_bound IS NULL AND v_declared AND NEW.parent_project_id <> '' THEN
            v_bound := NEW.parent_project_id;
        END IF;
        IF v_bound IS NOT NULL AND
           (NEW.parent_project_id IS DISTINCT FROM v_bound OR EXISTS (
               SELECT 1 FROM unnest(v_chain) AS l(link)
                WHERE split_part(l.link, ':', 1) = 'project'
                  AND substr(l.link, strpos(l.link, ':') + 1) <> v_bound)) THEN
            RAISE EXCEPTION 'object %:% is bound to another project', NEW.model_type, NEW.object_id
                USING ERRCODE = 'integrity_constraint_violation',
                      CONSTRAINT = 'object_project_binding_holds',
                      TABLE = 'resource_mirror', SCHEMA = 'kaname';
        END IF;
    END IF;
    IF NEW.applied AND NOT NEW.projection_unchanged THEN
        DELETE FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = NEW.model_type AND pe.object_id = NEW.object_id;
        INSERT INTO kaname.resource_parent_edge
            (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
        SELECT NEW.model_type, NEW.object_id, split_part(l.link, ':', 1),
               substr(l.link, strpos(l.link, ':') + 1), l.n, NEW.source_version, now()
          FROM unnest(v_chain) WITH ORDINALITY AS l(link, n);
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER resource_registration_command_apply
    INSTEAD OF INSERT ON kaname.resource_registration_command
    FOR EACH ROW EXECUTE FUNCTION kaname.resource_registration_command_apply();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_mirror_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
DECLARE
    v_model_type text;
    v_declared   boolean;
    v_held       boolean;
    v_new_binding boolean := false;
    v_raw_chain text[] := ARRAY[]::text[];
BEGIN
    -- Только прямой триггер полной команды пишет эти таблицы на глубине 2.
    -- Это опирается на замкнутый граф установленных триггеров/обратных вызовов, не только на
    -- глубину. Защиты постоянства привязки НИКОГДА не входят в эту ветвь.
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'BEFORE' THEN
        -- Тот же барьер конфликта RR, что и у полной команды, до прямого изменения.
        -- SQLSTATE 40001 передаётся без изменения; это не вердикт целостности.
        UPDATE kaname.catalog_resource cr
           SET project_bindings_held = cr.project_bindings_held
         WHERE cr.dotted = NEW.object_type
         RETURNING cr.object_type, cr.permanent_project AND cr.live,
                   cr.permanent_project OR cr.project_bindings_held
              INTO v_model_type, v_declared, v_held;
    ELSE
        -- AFTER использует кортеж каталога, уже записанный этим прямым оператором.
        SELECT cr.object_type, cr.permanent_project AND cr.live, cr.permanent_project OR cr.project_bindings_held
          INTO v_model_type, v_declared, v_held
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = NEW.object_type;
    END IF;
    IF NOT FOUND OR NOT v_held THEN
        RETURN NEW;
    END IF;
    IF TG_WHEN = 'AFTER' AND v_declared AND NEW.parent_project_id <> '' THEN
        INSERT INTO kaname.object_project_binding (object_type, object_id, project_id)
        VALUES (v_model_type, NEW.object_id, NEW.parent_project_id)
        ON CONFLICT (object_type, object_id) DO NOTHING;
        v_new_binding := FOUND;
    END IF;
    IF v_new_binding THEN
        SELECT coalesce(array_agg(pe.parent_type || ':' || pe.parent_id), ARRAY[]::text[])
          INTO v_raw_chain FROM kaname.resource_parent_edge pe
         WHERE pe.object_type = v_model_type AND pe.object_id = NEW.object_id;
    END IF;
    IF kaname.object_project_binding_refuses(v_model_type, NEW.object_id, NEW.parent_project_id, v_raw_chain) THEN
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

CREATE TRIGGER resource_mirror_binds_effective_registration
    AFTER INSERT OR UPDATE ON kaname.resource_mirror
    FOR EACH ROW EXECUTE FUNCTION kaname.resource_mirror_keeps_the_bound_project();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pg_catalog, kaname
    AS $$
BEGIN
    IF pg_trigger_depth() = 2 THEN
        RETURN NEW;
    END IF;
    -- Прямые рёбра проекта участвуют в том же настоящем барьере конфликта записи.
    -- Это также защищает обратное расписание RR: ребро, закоммиченное после снимка
    -- писателя первой привязки, заставляет этого писателя сериализоваться/повториться.
    UPDATE kaname.catalog_resource cr
       SET project_bindings_held = cr.project_bindings_held
     WHERE cr.object_type = NEW.object_type;
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

-- Барьер берётся до физических замков строк, включая прямой UPDATE.
-- Каждый участвующий оператор сразу берёт EXCLUSIVE:
-- команда с последующим прямым DML в одной транзакции никогда не повышает общий замок.
-- +goose StatementBegin
CREATE FUNCTION kaname.resource_registration_locks_writers() RETURNS trigger
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, kaname AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers', 0));
    RETURN NULL;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER resource_registration_locks_writers
    BEFORE INSERT ON kaname.resource_registration_command
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.resource_registration_locks_writers();
CREATE TRIGGER resource_registration_locks_writers
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.resource_mirror
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.resource_registration_locks_writers();
CREATE TRIGGER resource_registration_locks_writers
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.resource_parent_edge
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.resource_registration_locks_writers();
CREATE TRIGGER resource_registration_locks_writers
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.catalog_resource
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.resource_registration_locks_writers();

-- +goose Down
DROP TRIGGER resource_registration_locks_writers ON kaname.resource_registration_command;
DROP TRIGGER resource_registration_locks_writers ON kaname.resource_mirror;
DROP TRIGGER resource_registration_locks_writers ON kaname.resource_parent_edge;
DROP TRIGGER resource_registration_locks_writers ON kaname.catalog_resource;
DROP FUNCTION kaname.resource_registration_locks_writers();
DROP VIEW kaname.resource_registration_command;
DROP FUNCTION kaname.resource_registration_command_apply();
DROP TRIGGER resource_mirror_binds_effective_registration ON kaname.resource_mirror;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_mirror_keeps_the_bound_project() RETURNS trigger
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

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.resource_parent_edge_keeps_the_bound_project() RETURNS trigger
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
