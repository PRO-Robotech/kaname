-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- container_passes_public_read_to_its_children — публичное чтение контейнера
-- (стадия S5, задача PRO-Robotech/kaname#856).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md`
-- (редакция 10), решение Р9 и уточнение У1: тип сам объявляет в манифесте своего
-- модуля, что публичное чтение переходит на его детей (`publicReadToChildren`);
-- разворачивание выдачи системному классу пишет отношение `public_reader` для
-- ЛЮБОГО такого типа, если правило роли покрывает тип-ребёнок; источник «тип
-- объявлен» — ЖИВОЙ КАТАЛОГ из доставленных манифестов, а не литерал с именем
-- модуля (SC-65).
--
-- ДВЕ КОЛОНКИ строки ресурса каталога — то, что манифест о ресурсе говорит и чего
-- каталог до сих пор не хранил:
--   * `parent_types` — типы модели прав, на которые указывают указатели ресурса
--     (`parents` манифеста), в порядке манифеста. По ним видно, кто чей ребёнок:
--     ворота выдачи называют тип-ребёнок необъявленного контейнера (SC-65), а
--     разворачивание выдачи — детей объявленного. Пусто у строки, которую не
--     объявил доставленный манифест (посев литерала), — связь тогда неизвестна,
--     и через неё ничего не открывается;
--   * `public_read_to_children` — тип объявлен контейнером.
-- Пишет обе применитель каталога (`modulecatalog`) из доставленного манифеста.
--
-- ПРЯМОЙ ФАКТ: `public_reader` — отношение ЧТЕНИЯ. Его единственный читатель —
-- `v_get` и `v_list` детей (`… or public_reader from <указатель>`), пишущий глагол
-- от него не выводится ни у одного типа канона. Поэтому оно входит в закрытый
-- положительный перечень отношений, на которых класс субъектов допустим в прямом
-- факте (`relation_fact_subject_class_reads_only`, миграция 20261015140000); без
-- этого факт выдачи ПЧ отвергался бы при свёртке журнала (23514).
--
-- СУБЪЕКТ `public_reader` — только класс (`relation_fact_public_reader_subject_is_class`):
-- модель объявляет `public_reader: [system_class]`, а ветвь фактов вердикта
-- соединяет говорящего с субъектом факта без разбора типа. Человек, учётка или
-- группа на этом отношении открывали бы детей контейнера мимо выдачи классу.

-- +goose Up
ALTER TABLE kaname.catalog_resource
    ADD COLUMN parent_types text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN public_read_to_children boolean NOT NULL DEFAULT false;

-- Форма каждого элемента — имя типа модели (та же грамматика, что у
-- `catalog_resource_object_type_form`). Склейка идёт ЗАПЯТОЙ, и образец требует
-- непустого имени между запятыми: пустой элемент (`{''}`, `{'a',''}`) и элемент
-- с пробелом (`{'a b'}`) давали бы строку, которую образец через пробел принимал.
-- `array_to_string` пропускает NULL молча, поэтому NULL-элемент судится отдельно.
ALTER TABLE kaname.catalog_resource
    ADD CONSTRAINT catalog_resource_parent_types_form
        CHECK (array_position(parent_types, NULL) IS NULL
               AND (cardinality(parent_types) = 0
                    OR array_to_string(parent_types, ',') ~ '^[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$'));

COMMENT ON COLUMN kaname.catalog_resource.parent_types IS 'Типы модели прав, на которые указывают указатели ресурса (parents манифеста), в порядке манифеста. Пусто у строки, не объявленной доставленным манифестом: связь «ребёнок → контейнер» тогда неизвестна, и публичное чтение через неё не открывается. kaname#856.';
COMMENT ON COLUMN kaname.catalog_resource.public_read_to_children IS 'Тип объявлен контейнером публичного чтения (publicReadToChildren манифеста): выдача системному классу на его объект ролью с правилом над типом-ребёнком разворачивается в public_reader. kaname#856.';

ALTER TABLE kaname.relation_fact DROP CONSTRAINT relation_fact_subject_class_reads_only;
ALTER TABLE kaname.relation_fact
    ADD CONSTRAINT relation_fact_subject_class_reads_only
        CHECK ((split_part(subject, ':', 1) <> 'system_class'
                OR (subject = ANY (ARRAY['system_class:anonymous'::text, 'system_class:authenticated'::text])
                    AND relation = ANY (ARRAY['v_get'::text, 'viewer'::text, 'system_viewer'::text, 'public_reader'::text]))));

COMMENT ON CONSTRAINT relation_fact_subject_class_reads_only ON kaname.relation_fact IS 'Класс субъектов (system_class:anonymous | system_class:authenticated) в прямом факте — только на отношении чтения: v_get (публикация), viewer и system_viewer (ярус чтения), public_reader (публичное чтение контейнера, kaname#856). Р4 приёмки системного класса; сужение приёма класса субъекта, kaname#838.';

-- `public_reader` принимает ТОЛЬКО класс субъектов — так объявлено в модели
-- (`define public_reader: [system_class]`). Ветвь фактов вердикта соединяет
-- говорящего с субъектом факта без разбора типа, поэтому последнее слово о
-- субъекте этого отношения — у таблицы фактов, а не у пишущего.
ALTER TABLE kaname.relation_fact
    ADD CONSTRAINT relation_fact_public_reader_subject_is_class
        CHECK (relation <> 'public_reader'
               OR subject = ANY (ARRAY['system_class:anonymous'::text, 'system_class:authenticated'::text]));

COMMENT ON CONSTRAINT relation_fact_public_reader_subject_is_class ON kaname.relation_fact IS 'Отношение public_reader (публичное чтение контейнера) — только у класса субъектов system_class:anonymous | system_class:authenticated, как объявляет модель. kaname#856.';

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    v_bad int;
BEGIN
    SELECT count(*) INTO v_bad FROM kaname.relation_fact
     WHERE relation = 'public_reader' AND split_part(subject, ':', 1) = 'system_class';
    IF v_bad > 0 THEN
        RAISE EXCEPTION
            'public read: % direct fact(s) carry public_reader of a system class; revoke the grants before rolling back', v_bad;
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE kaname.relation_fact DROP CONSTRAINT relation_fact_public_reader_subject_is_class;
ALTER TABLE kaname.relation_fact DROP CONSTRAINT relation_fact_subject_class_reads_only;
ALTER TABLE kaname.relation_fact
    ADD CONSTRAINT relation_fact_subject_class_reads_only
        CHECK ((split_part(subject, ':', 1) <> 'system_class'
                OR (subject = ANY (ARRAY['system_class:anonymous'::text, 'system_class:authenticated'::text])
                    AND relation = ANY (ARRAY['v_get'::text, 'viewer'::text, 'system_viewer'::text]))));

COMMENT ON CONSTRAINT relation_fact_subject_class_reads_only ON kaname.relation_fact IS 'Класс субъектов (system_class:anonymous | system_class:authenticated) в прямом факте — только на отношении чтения: v_get (публикация), viewer и system_viewer (ярус чтения). Р4 приёмки системного класса; сужение приёма класса субъекта, kaname#838.';

ALTER TABLE kaname.catalog_resource DROP CONSTRAINT catalog_resource_parent_types_form;
ALTER TABLE kaname.catalog_resource
    DROP COLUMN public_read_to_children,
    DROP COLUMN parent_types;
