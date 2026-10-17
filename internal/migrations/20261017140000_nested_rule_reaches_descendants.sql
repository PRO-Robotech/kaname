-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- nested_rule_reaches_descendants — вложенное правило роли достаёт до потомков
-- контейнера, выбранного выдачей (задача PRO-Robotech/kaname#874).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md`
-- (редакция 2, отпечаток f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6),
-- решения Р1, Р3, Р5; заказ производителей M1 круга 1 — стражи базы читают
-- вложенные правила.
--
-- ЧТО МЕНЯЕТСЯ — ТРИ СТРАЖА И ОДНА ПРОЕКЦИЯ, данных не трогает ни одна строка:
--
--   1. `kaname.role_rule_selectors` — КОНТЕЙНЕР вложенного селектора: тип и
--      ветвь отбора правила-владельца (`container_type`, `container_arm`,
--      `container_resource_names`, `container_match_labels`) и модельное имя типа
--      контейнера (`container_object_type`). Решение о доступе читает их одним
--      предикатом ветви выдач: объект охвачен, если среди его предков (рёбра
--      `resource_parent_edge`) есть контейнер этого типа, прошедший отбор и
--      входящий в цель выдачи. Модельное имя ВЫВОДИТ страж из живой строки
--      каталога — писатель его не пишет, и двух написаний одного типа не
--      возникает. У селектора правила верхнего уровня все пять пусты.
--   2. `kaname.role_rule_selector_types_live()` — тот же страж «тип — живая
--      строка каталога» судит и тип контейнера (под тем же замком FOR KEY
--      SHARE) и выводит его модельное имя.
--   3. `kaname.iam_rules_valid(jsonb)` — форма вложенности в `roles.rules`:
--      ключ `children` либо отсутствует, либо непустой перечень (≤ 16);
--      правило-владелец — ровно один ресурс, не `*`, модуль не `*`; у
--      вложенного нет `module` и своих `children`, ресурсы 1..16 без `*` и без
--      ресурса владельца, глаголы 1..16, селектор — та же форма, что у
--      владельца. Родство по `parents` база не судит — у неё нет манифеста; его
--      судит загрузчик (ND-04 (а)).
--   4. `kaname.role_grants_reads_only(jsonb, jsonb)` — «классу только чтение»
--      читает глаголы вложенных правил наравне с верхним уровнем (SC-21, M1).
--
-- ПОЧЕМУ НЕ ЗАМЕНА ТАБЛИЦЫ. Вложенный селектор — та же строка селектора роли
-- (тот же ключ «роль, отпечаток», тот же индекс по типам объекта), что и
-- селектор верхнего уровня, с одним добавленным фактом — контейнером. Своя
-- таблица дала бы второе место, где живёт «правило роли даёт тип», и ветвь
-- выдач читала бы два источника.

-- +goose Up
ALTER TABLE kaname.role_rule_selectors
    ADD COLUMN container_type text,
    ADD COLUMN container_object_type text,
    ADD COLUMN container_arm text,
    ADD COLUMN container_resource_names text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN container_match_labels jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Форма контейнера — та же, что у ветви самого селектора
-- (`role_rule_selectors_arm_shape`): якорь без имён и меток, имена без меток,
-- метки без имён. Селектор верхнего уровня — все пять пусты, и это
-- одно состояние, а не пять независимых.
ALTER TABLE kaname.role_rule_selectors
    ADD CONSTRAINT role_rule_selectors_container_shape CHECK (
        (container_type IS NULL AND container_object_type IS NULL AND container_arm IS NULL
         AND cardinality(container_resource_names) = 0 AND container_match_labels = '{}'::jsonb)
     OR (container_type IS NOT NULL AND container_object_type IS NOT NULL AND (
            (container_arm = 'anchor' AND cardinality(container_resource_names) = 0
             AND container_match_labels = '{}'::jsonb)
         OR (container_arm = 'names' AND cardinality(container_resource_names) >= 1
             AND container_match_labels = '{}'::jsonb)
         OR (container_arm = 'labels' AND cardinality(container_resource_names) = 0
             AND container_match_labels <> '{}'::jsonb)))),
    ADD CONSTRAINT role_rule_selectors_container_labels_obj
        CHECK (jsonb_typeof(container_match_labels) = 'object'),
    ADD CONSTRAINT role_rule_selectors_container_labels_valid
        CHECK (kaname.kacho_labels_valid(container_match_labels)),
    -- Сам себе тип потомком не является (Р1 п. 3).
    ADD CONSTRAINT role_rule_selectors_container_not_own_type
        CHECK (container_type IS NULL OR NOT (container_type = ANY (object_types)));

COMMENT ON COLUMN kaname.role_rule_selectors.container_type IS 'Тип контейнера вложенного правила (точечная форма каталога, `registry.registries`): селектор охватывает объекты своих object_types, у которых среди предков есть контейнер этого типа, прошедший отбор container_arm и входящий в цель выдачи. NULL — селектор правила верхнего уровня. kaname#874.';
COMMENT ON COLUMN kaname.role_rule_selectors.container_object_type IS 'Тип контейнера в форме модели (`registry_registry`) — тем написанием, каким тип предка лежит в resource_parent_edge. Выводит страж role_rule_selector_types_live из живой строки каталога; писатель его не пишет. kaname#874.';
COMMENT ON COLUMN kaname.role_rule_selectors.container_arm IS 'Ветвь отбора правила-владельца: anchor — все контейнеры типа, names — container_resource_names, labels — метки контейнера содержат container_match_labels. kaname#874.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.role_rule_selector_types_live() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    declared_type text;
    container_model text;
BEGIN
    FOREACH declared_type IN ARRAY NEW.object_types LOOP
        -- FOR KEY SHARE — тот же замок, который взял бы внешний ключ, будь он на
        -- элемент массива выразим. Он не даёт снятию строки каталога разойтись с
        -- этой записью по разным снимкам: снятие меняет `live`, входящий в
        -- уникальные ограничения — цели внешних ключей, то есть обновляет КЛЮЧ и
        -- берёт FOR UPDATE, а FOR UPDATE с FOR KEY SHARE конфликтует.
        PERFORM 1 FROM kaname.catalog_resource cr
         WHERE cr.dotted = declared_type AND cr.live
           FOR KEY SHARE OF cr;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'object_types: % is not a live platform resource (role %)',
                declared_type, NEW.role_id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'role_rule_selectors_types_live';
        END IF;
    END LOOP;

    -- Контейнер вложенного правила (kaname#874): тот же суд и тот же замок.
    -- Модельное имя выводится ЗДЕСЬ, из той же строки: написание типа предка в
    -- resource_parent_edge — форма модели, и писатель второго написания не несёт.
    IF NEW.container_type IS NULL THEN
        NEW.container_object_type := NULL;
    ELSE
        SELECT cr.object_type INTO container_model
          FROM kaname.catalog_resource cr
         WHERE cr.dotted = NEW.container_type AND cr.live
           FOR KEY SHARE OF cr;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'container_type: % is not a live platform resource (role %)',
                NEW.container_type, NEW.role_id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'role_rule_selectors_types_live';
        END IF;
        NEW.container_object_type := container_model;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.role_rule_selector_types_live() IS 'Референт ТРЕТЬЕЙ поверхности проекции правила: каждый элемент role_rule_selectors.object_types и тип контейнера вложенного правила (container_type, kaname#874) обязаны называть живую строку kaname.catalog_resource; модельное имя контейнера (container_object_type) выводится из той же строки. Внешний ключ на элемент массива невыразим, проверка в коде запрещена (ban #10) — поэтому триггер. Отказ 23514 называет элемент и роль. Строка каталога читается ПОД FOR KEY SHARE — тем же замком, который взял бы внешний ключ (#1985).';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
    child      jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;

        -- Вложенные правила (kaname#874). Ключа нет — правило без вложенных.
        IF rule ? 'children' THEN
            IF jsonb_typeof(rule -> 'children') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'children') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
            -- Владелец — ровно один ресурс, не подстановка, модуль не подстановка.
            IF rule ->> 'module' = '*' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resources') <> 1 THEN RETURN false; END IF;
            IF rule -> 'resources' ->> 0 = '*' THEN RETURN false; END IF;

            FOR child IN SELECT value FROM jsonb_array_elements(rule -> 'children') LOOP
                IF jsonb_typeof(child) <> 'object' THEN RETURN false; END IF;
                -- Модуль — владельца; глубину выражает тип, а не структура роли.
                IF child ? 'module' OR child ? 'children' THEN RETURN false; END IF;
                FOR arr IN SELECT child -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
                    IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END LOOP;
                -- Вложенное называет тип: не подстановку и не тип владельца.
                IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(child -> 'resources') e
                            WHERE e = '*' OR e = rule -> 'resources' ->> 0) THEN
                    RETURN false;
                END IF;

                has_names  := (child ? 'resource_names') AND jsonb_typeof(child -> 'resource_names') <> 'null';
                has_labels := (child ? 'match_labels')   AND jsonb_typeof(child -> 'match_labels')   <> 'null';
                IF has_names AND has_labels THEN RETURN false; END IF;
                IF has_names THEN
                    IF jsonb_typeof(child -> 'resource_names') <> 'array' THEN RETURN false; END IF;
                    IF jsonb_array_length(child -> 'resource_names') > 256 THEN RETURN false; END IF;
                    IF EXISTS (SELECT 1 FROM jsonb_array_elements(child -> 'resource_names') e
                               WHERE jsonb_typeof(e) <> 'string') THEN
                        RETURN false;
                    END IF;
                END IF;
                IF has_labels THEN
                    IF jsonb_typeof(child -> 'match_labels') <> 'object' THEN RETURN false; END IF;
                    IF (SELECT count(*) FROM jsonb_object_keys(child -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                        RETURN false;
                    END IF;
                END IF;
            END LOOP;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.role_grants_reads_only(p_rules jsonb, p_permissions jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
    SELECT CASE
        WHEN jsonb_array_length(coalesce(p_rules, '[]'::jsonb)) > 0 THEN
            NOT EXISTS (
                SELECT 1
                  FROM jsonb_array_elements(p_rules) AS r(rule)
                 CROSS JOIN LATERAL (
                        SELECT r.rule
                      UNION ALL
                        -- Вложенные правила (kaname#874, M1): их глаголы — глаголы роли.
                        SELECT c.value
                          FROM jsonb_array_elements(
                                   CASE WHEN jsonb_typeof(r.rule -> 'children') = 'array'
                                        THEN r.rule -> 'children' ELSE '[]'::jsonb END) AS c
                       ) AS g(grant_rule)
                 CROSS JOIN LATERAL jsonb_array_elements_text(coalesce(g.grant_rule -> 'verbs', '[]'::jsonb)) AS v(verb)
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

COMMENT ON FUNCTION kaname.role_grants_reads_only(jsonb, jsonb) IS 'Каждый глагол роли — get либо list (Р4 приёмки системного класса, kaname#829), включая глаголы вложенных правил (kaname#874). Судится авторское написание: `*` пишущим считается всегда, потому что раскрывается в набор типа, а набор растёт. Роль без правил судится по хранимой проекции прав (последний сегмент — глагол). Зеркало domain.Role.GrantsReadsOnly; здесь — ради последнего слова записи.';

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    v_roles int;
    v_sels  int;
BEGIN
    SELECT count(*) INTO v_roles FROM kaname.roles r
     WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(r.rules) e WHERE e.value ? 'children');
    SELECT count(*) INTO v_sels FROM kaname.role_rule_selectors WHERE container_type IS NOT NULL;
    IF v_roles > 0 OR v_sels > 0 THEN
        RAISE EXCEPTION
            'nested rules: % role(s) carry children and % selector(s) carry a container; withdraw the roles before rolling back',
            v_roles, v_sels;
    END IF;
END
$$;
-- +goose StatementEnd

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
CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    rule       jsonb;
    arr        jsonb;
    has_names  boolean;
    has_labels boolean;
BEGIN
    IF rules IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(rules) <> 'array' THEN RETURN false; END IF;
    -- Empty array is valid (legacy permissions-only role; back-compat).
    IF jsonb_array_length(rules) = 0 THEN RETURN true; END IF;
    IF jsonb_array_length(rules) > 64 THEN RETURN false; END IF;

    FOR rule IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(rule) <> 'object' THEN RETURN false; END IF;

        -- module: required, non-empty string scalar. The array `modules` key is
        -- NO LONGER valid.
        IF NOT (rule ? 'module') THEN RETURN false; END IF;
        IF jsonb_typeof(rule -> 'module') <> 'string' THEN RETURN false; END IF;
        IF length(rule ->> 'module') < 1 THEN RETURN false; END IF;

        -- resources / verbs: required non-empty string arrays, 1..16.
        FOR arr IN SELECT rule -> k FROM (VALUES ('resources'), ('verbs')) AS t(k) LOOP
            IF arr IS NULL OR jsonb_typeof(arr) <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(arr) < 1 OR jsonb_array_length(arr) > 16 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(arr) e WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END LOOP;

        has_names  := (rule ? 'resource_names') AND jsonb_typeof(rule -> 'resource_names') <> 'null';
        has_labels := (rule ? 'match_labels')   AND jsonb_typeof(rule -> 'match_labels')   <> 'null';

        -- resource_names XOR match_labels (both → reject).
        IF has_names AND has_labels THEN RETURN false; END IF;

        IF has_names THEN
            IF jsonb_typeof(rule -> 'resource_names') <> 'array' THEN RETURN false; END IF;
            IF jsonb_array_length(rule -> 'resource_names') > 256 THEN RETURN false; END IF;
            IF EXISTS (SELECT 1 FROM jsonb_array_elements(rule -> 'resource_names') e
                       WHERE jsonb_typeof(e) <> 'string') THEN
                RETURN false;
            END IF;
        END IF;

        IF has_labels THEN
            IF jsonb_typeof(rule -> 'match_labels') <> 'object' THEN RETURN false; END IF;
            IF (SELECT count(*) FROM jsonb_object_keys(rule -> 'match_labels')) NOT BETWEEN 1 AND 16 THEN
                RETURN false;
            END IF;
        END IF;
    END LOOP;

    RETURN true;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.role_rule_selector_types_live() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    declared_type text;
BEGIN
    FOREACH declared_type IN ARRAY NEW.object_types LOOP
        -- FOR KEY SHARE — тот же замок, который взял бы внешний ключ, будь он на
        -- элемент массива выразим. Он не даёт снятию строки каталога разойтись с
        -- этой записью по разным снимкам: снятие меняет `live`, входящий в
        -- уникальные ограничения — цели внешних ключей, то есть обновляет КЛЮЧ и
        -- берёт FOR UPDATE, а FOR UPDATE с FOR KEY SHARE конфликтует.
        PERFORM 1 FROM kaname.catalog_resource cr
         WHERE cr.dotted = declared_type AND cr.live
           FOR KEY SHARE OF cr;
        IF NOT FOUND THEN
            RAISE EXCEPTION
                'object_types: % is not a live platform resource (role %)',
                declared_type, NEW.role_id
                USING ERRCODE = '23514',
                      CONSTRAINT = 'role_rule_selectors_types_live';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.role_rule_selector_types_live() IS 'Референт ТРЕТЬЕЙ поверхности проекции правила: каждый элемент role_rule_selectors.object_types обязан называть живую строку kaname.catalog_resource. Внешний ключ на элемент массива невыразим, проверка в коде запрещена (ban #10) — поэтому триггер. Проверяется КАЖДЫЙ элемент; отказ 23514 называет элемент и роль. Локальная переменная названа declared_type, а не именем колонки catalog_resource: совпадение имён даёт 42702 на КАЖДОЙ записи селектора. Строка каталога читается ПОД FOR KEY SHARE — тем же замком, который взял бы внешний ключ: без него снятие строки и запись селектора расходятся по своим снимкам (перекос записи, #1985).';

ALTER TABLE kaname.role_rule_selectors
    DROP CONSTRAINT role_rule_selectors_container_not_own_type,
    DROP CONSTRAINT role_rule_selectors_container_labels_valid,
    DROP CONSTRAINT role_rule_selectors_container_labels_obj,
    DROP CONSTRAINT role_rule_selectors_container_shape;
ALTER TABLE kaname.role_rule_selectors
    DROP COLUMN container_match_labels,
    DROP COLUMN container_resource_names,
    DROP COLUMN container_arm,
    DROP COLUMN container_object_type,
    DROP COLUMN container_type;
