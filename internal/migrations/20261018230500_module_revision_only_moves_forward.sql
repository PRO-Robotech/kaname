-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- module_revision_only_moves_forward — редакция манифеста модуля только растёт
-- (стадия S1, задача PRO-Robotech/kaname#865).
--
-- Санкция: одобренная приёмка
-- `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`
-- (круг 2, отпечаток 6339dc63…c9d63d), решения Д1, Д2 и Д9.
--
-- ДВЕ КОЛОНКИ строки модуля каталога:
--   * `applied_revision` — номер последней применённой редакции манифеста
--     модуля (ключ `revision`). Пусто — модуль ни разу не применён с
--     объявленной редакцией; ноль номером не бывает и запрещён проверкой;
--   * `applied_digest` — отпечаток содержимого той же редакции: `sha256:` и 64
--     строчные шестнадцатеричные цифры над канонической формой документа.
-- Номер без отпечатка и отпечаток без номера непредставимы: третья проверка
-- связывает колонки — обе пусты либо обе заполнены.
--
-- Пишет обе ровно один оператор — сравнение-и-запись применителя каталога
-- (`catalogWriter.AdvanceRevision`), под глобальным замком каталога, первым
-- пишущим оператором транзакции. ОБРАТНОГО ЗАПОЛНЕНИЯ НЕТ: существующие строки
-- получают обе колонки пустыми, и первая объявленная редакция заводит пару.

-- +goose Up
ALTER TABLE kaname.catalog_module
    ADD COLUMN applied_revision bigint,
    ADD COLUMN applied_digest text,
    ADD CONSTRAINT catalog_module_applied_revision_positive
        CHECK (applied_revision IS NULL OR applied_revision >= 1),
    ADD CONSTRAINT catalog_module_applied_digest_form
        CHECK (applied_digest IS NULL OR applied_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT catalog_module_applied_pair
        CHECK ((applied_revision IS NULL) = (applied_digest IS NULL));

COMMENT ON COLUMN kaname.catalog_module.applied_revision IS 'Номер последней применённой редакции манифеста модуля (ключ revision). Пусто — модуль ни разу не применён с объявленной редакцией. Редакция младше применённой каталога не меняет; откат — новой, большей редакцией. kaname#865.';
COMMENT ON COLUMN kaname.catalog_module.applied_digest IS 'Отпечаток содержимого применённой редакции: sha256: и 64 строчные шестнадцатеричные цифры над канонической формой документа (JCS над деревом узлов YAML). Равный номер с иным отпечатком — конфликт содержимого, не повтор. kaname#865.';
COMMENT ON CONSTRAINT catalog_module_applied_revision_positive ON kaname.catalog_module IS 'Номер редакции — целое не меньше 1: ноль редакцией не бывает, отсутствие — NULL. kaname#865.';
COMMENT ON CONSTRAINT catalog_module_applied_digest_form ON kaname.catalog_module IS 'Форма отпечатка — sha256: и 64 строчные шестнадцатеричные цифры. kaname#865.';
COMMENT ON CONSTRAINT catalog_module_applied_pair ON kaname.catalog_module IS 'Номер и отпечаток применённой редакции — пара: обе колонки пусты либо обе заполнены. kaname#865.';

-- +goose Down
ALTER TABLE kaname.catalog_module
    DROP CONSTRAINT catalog_module_applied_pair,
    DROP CONSTRAINT catalog_module_applied_digest_form,
    DROP CONSTRAINT catalog_module_applied_revision_positive,
    DROP COLUMN applied_digest,
    DROP COLUMN applied_revision;
