-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Основание неизменяемости обеих редакций — п. 3 контракта docs/engineering/acceptance/live-business-catalog-publication.md.
-- Журналы публикаций содержат исходные байты и их отпечатки. Эти строки
-- исключены из обхода рабочих координат: транзакция смены якоря сохраняет
-- историю и её запреты UPDATE, DELETE и TRUNCATE.

-- +goose Up
-- +goose StatementBegin
DO $anchor$
DECLARE
    item record;
    original text;
    replacement text;
    definition text;
    delimiter text;
    from_filter constant text := $filter$           AND tb.table_type = 'BASE TABLE'
$filter$;
    to_filter constant text := $filter$           AND tb.table_type = 'BASE TABLE'
           AND c.table_name NOT IN ('module_part_revision', 'publication_model_revision')
$filter$;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('kaname.cluster_anchor_residue(text)', '5bf31590df0b73d2fd53d99be3dd22a0246b638ce9b4ac61abdb17a95250a67a', '0b01ce61bda0529873ef62b07263043cea4cbd21b7fa2fb908dff15ce8f358fe'),
        ('kaname.rename_cluster_anchor(text,text)', 'feab0b8f3cb9e9ec56538d30fdb24ab3a46afa1b0da9e8a4dd366d49d499ee20', '500a40796682d44588d87b57f64bba50ecf6cdbb0baaff24c6bc3edd77585ce5')
    ) AS changes(signature, before_hash, after_hash) LOOP
        SELECT p.prosrc, pg_get_functiondef(p.oid) INTO STRICT original, definition
          FROM pg_proc p WHERE p.oid = to_regprocedure(item.signature);
        IF encode(sha256(convert_to(original, 'UTF8')), 'hex') IS DISTINCT FROM item.before_hash THEN
            RAISE EXCEPTION 'Исходное тело функции % изменилось', item.signature;
        END IF;
        replacement := replace(original, from_filter, to_filter);
        IF encode(sha256(convert_to(replacement, 'UTF8')), 'hex') IS DISTINCT FROM item.after_hash THEN
            RAISE EXCEPTION 'Итоговое тело функции % изменилось', item.signature;
        END IF;
        delimiter := substring(left(definition, strpos(definition, original) - 1) FROM '([$][[:alnum:]_]*[$])$');
        IF delimiter IS NULL OR strpos(definition, delimiter || original || delimiter) = 0 THEN
            RAISE EXCEPTION 'Не найдено точное тело функции %', item.signature;
        END IF;
        EXECUTE replace(definition, delimiter || original || delimiter, quote_literal(replacement));
    END LOOP;
END
$anchor$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $anchor$
DECLARE
    item record;
    original text;
    replacement text;
    definition text;
    delimiter text;
    from_filter constant text := $filter$           AND tb.table_type = 'BASE TABLE'
           AND c.table_name NOT IN ('module_part_revision', 'publication_model_revision')
$filter$;
    to_filter constant text := $filter$           AND tb.table_type = 'BASE TABLE'
$filter$;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('kaname.cluster_anchor_residue(text)', '0b01ce61bda0529873ef62b07263043cea4cbd21b7fa2fb908dff15ce8f358fe', '5bf31590df0b73d2fd53d99be3dd22a0246b638ce9b4ac61abdb17a95250a67a'),
        ('kaname.rename_cluster_anchor(text,text)', '500a40796682d44588d87b57f64bba50ecf6cdbb0baaff24c6bc3edd77585ce5', 'feab0b8f3cb9e9ec56538d30fdb24ab3a46afa1b0da9e8a4dd366d49d499ee20')
    ) AS changes(signature, before_hash, after_hash) LOOP
        SELECT p.prosrc, pg_get_functiondef(p.oid) INTO STRICT original, definition
          FROM pg_proc p WHERE p.oid = to_regprocedure(item.signature);
        IF encode(sha256(convert_to(original, 'UTF8')), 'hex') IS DISTINCT FROM item.before_hash THEN
            RAISE EXCEPTION 'Исходное тело функции % изменилось', item.signature;
        END IF;
        replacement := replace(original, from_filter, to_filter);
        IF encode(sha256(convert_to(replacement, 'UTF8')), 'hex') IS DISTINCT FROM item.after_hash THEN
            RAISE EXCEPTION 'Итоговое тело функции % изменилось', item.signature;
        END IF;
        delimiter := substring(left(definition, strpos(definition, original) - 1) FROM '([$][[:alnum:]_]*[$])$');
        IF delimiter IS NULL OR strpos(definition, delimiter || original || delimiter) = 0 THEN
            RAISE EXCEPTION 'Не найдено точное тело функции %', item.signature;
        END IF;
        EXECUTE replace(definition, delimiter || original || delimiter, quote_literal(replacement));
    END LOOP;
END
$anchor$;
-- +goose StatementEnd
