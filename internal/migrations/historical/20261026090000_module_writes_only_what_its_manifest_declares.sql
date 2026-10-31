-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- module_writes_only_what_its_manifest_declares — закрытая политика записи модуля
-- в строке каталога ресурсов (задача PRO-Robotech/kaname#982).
--
-- САНКЦИЯ: приёмка docs/engineering/acceptance/kaname-derives-the-parent-of-a-registered-object.md,
-- редакция 2, отпечаток одобренной редакции
-- 1f2991d64d0f8a9b90f8dbcaabeadd8e6af3d2b38e4f573c5d49dfe1a5a1f6e8 (записи ревью —
-- docs/specs/reviews/kaname-derives-the-parent-of-a-registered-object/), решения Р1, Р2.
--
-- ЧТО МЕНЯЕТСЯ:
--
--   1. `parent_names` — ИМЕНА указателей ресурса, позиционно парные `parent_types`.
--      Политика записи адресует указатель именем отношения: у
--      `registry.repositories` это `parent` при типе `registry_registry`, у прочих
--      имя равно типу. Колонка `parent_types` имени не несла.
--   2. `writes` — отношения сверх указателя, которые модуль пишет сам (ключ
--      `writes` манифеста), парами `<отношение>:<тип субъекта>`. Пусто — модуль
--      пишет только указатель.
--   Обе колонки пишет применитель каталога (`modulecatalog`) из доставленного
--   манифеста; политика типа — указатели плюс записи, и регистрация вне неё
--   отвергается.
--
-- ПОСЕВ — В ПАРИТЕТЕ С ПОСТАВЛЯЕМЫМИ МАНИФЕСТАМИ
-- (`TestModuleCatalogApplierAgreesWithTheSeededCatalog`): первое применение на
-- старте иначе «изменило» бы каждую строку. Имена указателей выведены
-- `modulecatalog.RowsOf` из манифестов модулей платформы и манифеста iam: у всех
-- посеянных строк, кроме `registry.repositories`, указатель записан короткой
-- формой (имя равно типу); записей `writes` поставляемые манифесты не несут.
--
-- ФОРМА каждого элемента — та же грамматика, что у `parent_types`; склейка через
-- запятую, NULL-элемент судится отдельно (`array_to_string` пропускает его молча).
--
-- ОТКАТ снимает обе колонки и их проверки: прежняя схема их не знает, а политика
-- без них — только указатель по типу.

-- +goose Up
ALTER TABLE kaname.catalog_resource
    ADD COLUMN parent_names text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN writes text[] NOT NULL DEFAULT '{}'::text[];

UPDATE kaname.catalog_resource c
   SET parent_names = c.parent_types
 WHERE cardinality(c.parent_types) > 0;

UPDATE kaname.catalog_resource c
   SET parent_names = v.names
  FROM (VALUES
        ('registry', 'repositories', ARRAY['parent']::text[])
       ) AS v(module, resource, names)
 WHERE c.module = v.module AND c.resource = v.resource;

ALTER TABLE kaname.catalog_resource
    ADD CONSTRAINT catalog_resource_parent_names_form
        CHECK (array_position(parent_names, NULL) IS NULL
               AND cardinality(parent_names) = cardinality(parent_types)
               AND (cardinality(parent_names) = 0
                    OR array_to_string(parent_names, ',') ~ '^[a-z][a-z0-9_]*(,[a-z][a-z0-9_]*)*$')),
    ADD CONSTRAINT catalog_resource_writes_form
        CHECK (array_position(writes, NULL) IS NULL
               AND (cardinality(writes) = 0
                    OR array_to_string(writes, ',')
                       ~ '^[a-z][a-z0-9_]*:(user|service_account)(,[a-z][a-z0-9_]*:(user|service_account))*$'));

COMMENT ON COLUMN kaname.catalog_resource.parent_names IS 'Имена указателей ресурса (parents манифеста), позиционно парные parent_types: политика записи модуля адресует указатель именем отношения. Пусто — у строки нет указателей. kaname#982.';
COMMENT ON COLUMN kaname.catalog_resource.writes IS 'Отношения сверх указателя, которые модуль пишет сам (writes манифеста), парами «отношение:тип субъекта». Вместе с указателями — закрытая политика записи модуля; регистрация вне неё отвергается. Пусто — модуль пишет только указатель. kaname#982.';

-- +goose Down
ALTER TABLE kaname.catalog_resource
    DROP CONSTRAINT catalog_resource_writes_form,
    DROP CONSTRAINT catalog_resource_parent_names_form;
ALTER TABLE kaname.catalog_resource
    DROP COLUMN writes,
    DROP COLUMN parent_names;
