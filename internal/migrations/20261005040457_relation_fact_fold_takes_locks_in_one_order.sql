-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- relation_fact_fold_takes_locks_in_one_order — свёртка журнала прав в прямой
-- факт берёт блокировки строк факта в ОДНОМ порядке, какой бы писатель ни
-- положил строки (kaname#568).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Прямой факт складывает триггер журнала: на каждый кортеж он вставляет или
-- снимает строку `kaname.relation_fact` и тем берёт её блокировку. До этой
-- миграции триггер был построчным и шёл в порядке строк ОПЕРАТОРА, а внутри
-- строки — в порядке отношений её набора, то есть в порядке ПИСАТЕЛЯ. Два
-- оператора с пересекающимися ключами, перечисленными встречно, брали одни и те
-- же блокировки встречно, и база снимала один из них отказом 40P01: снятие
-- выдачи кончалось ошибкой, а выдача оставалась жить.
--
-- Правка #357 (0fecf7e55) положила в общий порядок наборы ЭМИТТЕРА. Журнал
-- пишет не только он: обратное заполнение старта кладёт строки одним
-- `INSERT … SELECT` в порядке просмотра таблицы (а синхронный просмотр двух
-- подов начинает его с разных мест), посев модулей — своим циклом, сырой SQL
-- миграций — как написан. Порядок, который держит один писатель из многих, не
-- общий.
--
-- Поэтому порядок держит БАЗА: триггер становится операторным с таблицей
-- перехода, сворачивает строки оператора по (объект, субъект) побайтно, а строки
-- одного ключа — по `id` (выдача и снятие одного ключа НЕ коммутируют, и их
-- порядок задан писателем); отношения внутри строки — тоже побайтно. Строки
-- разных ключей коммутируют, поэтому перестановка ничего не меняет в исходе.
--
-- ГРАНИЦА: порядок общий ВНУТРИ ОПЕРАТОРА. Между операторами одной транзакции
-- он остаётся порядком писателя — свёртка видит только строки своего оператора.
--
-- Имя триггера и имя функции сохранены: на них ссылаются пробы целости журнала.

-- +goose Up
-- +goose StatementBegin
DROP TRIGGER relation_fact_follows_journal ON kaname.fga_outbox;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.relation_fact_fold_row(
    p_event_type text, p_payload jsonb, p_created_at timestamptz) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user      text := p_payload ->> 'user';
    v_object    text := p_payload ->> 'object';
    -- Версия ВЛАДЕЛЬЦА. Есть только у строки, которую владелец упорядочил сам.
    v_owner     text := p_payload ->> 'source_version';
    v_version   timestamptz;
    v_relations text[];
    v_relation  text;
    v_type      text;
    v_id        text;
    v_colon     int;
BEGIN
    -- Набор ВЫИГРЫВАЕТ у скаляра: на выдаче набора присутствуют оба поля, и
    -- скаляр там — эхо для пода прежнего выпуска, а не весь предмет строки.
    IF jsonb_array_length(coalesce(p_payload -> 'relations', '[]'::jsonb)) > 0 THEN
        -- Отношения набора — в ОБЩЕМ порядке, а не в порядке писателя: строка
        -- факта ключуется отношением, и два набора одного субъекта на одном
        -- объекте, перечисленные встречно, брали бы их блокировки встречно.
        SELECT array_agg(value ORDER BY value COLLATE "C") INTO v_relations
          FROM jsonb_array_elements_text(p_payload -> 'relations') AS value;
    ELSIF p_payload ->> 'relation' IS NOT NULL THEN
        v_relations := ARRAY[p_payload ->> 'relation'];
    END IF;

    IF v_user IS NULL OR v_relations IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            p_payload;
    END IF;

    -- Порядок строки. У строки, упорядоченной владельцем, его задаёт версия
    -- владельца: метка журнала — момент НАЧАЛА транзакции службы, и у снятия,
    -- начавшего транзакцию раньше открытия, она оказалась бы старше того, что
    -- снятие обязано снять. Неразбираемая версия роняет строку, а не
    -- подменяется меткой: молчаливая подмена вернула бы ровно тот порядок, от
    -- которого поле защищает.
    v_version := coalesce(v_owner::timestamptz, p_created_at);

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    --
    -- ИСКЛЮЧЕНИЕ ОДНО: строка, упорядоченная владельцем, — публикация для
    -- анонимного чтения. Её не выводит ни одна выдача, и отброшенная здесь, она
    -- не существовала бы нигде (kaname#107).
    IF v_owner IS NULL THEN
        v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
        IF array_length(v_relations, 1) IS NULL THEN
            RETURN;
        END IF;
    END IF;

    v_colon := position(':' in v_object);
    IF v_colon <= 1 OR v_colon = length(v_object) THEN
        RAISE EXCEPTION
            'fga_outbox: объект % не имеет формы "<тип>:<идентификатор>" — спроецировать прямой факт нельзя.',
            v_object;
    END IF;
    v_type := substr(v_object, 1, v_colon - 1);
    v_id   := substr(v_object, v_colon + 1);

    IF v_type LIKE '%.%' THEN
        RAISE EXCEPTION
            'fga_outbox: тип объекта % назван словарём каталога. Вопрос о доступе приходит словарём модели прав, и такая строка не совпала бы ни с одним вопросом.',
            v_type;
    END IF;

    FOREACH v_relation IN ARRAY v_relations LOOP
        IF p_event_type = 'fga.tuple.write' THEN
            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at)
            VALUES (v_type, v_id, v_relation, v_user, v_version, now())
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF p_event_type = 'fga.tuple.delete' THEN
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= v_version;
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz) IS 'Свёртка ОДНОЙ строки журнала намерений в прямой факт (тело прежней построчной проекции). Отношения набора — в побайтном порядке. Зовётся только операторной проекцией kaname.relation_fact_from_journal(), которая задаёт порядок строк (kaname#568).';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    r record;
BEGIN
    -- Общий порядок захвата строк факта: по ключу (объект, субъект) побайтно;
    -- строки одного ключа — в порядке их появления, который задал писатель.
    FOR r IN
        SELECT j.event_type, j.payload, j.created_at
          FROM journal_rows j
         ORDER BY j.payload ->> 'object' COLLATE "C",
                  j.payload ->> 'user'   COLLATE "C",
                  j.id
    LOOP
        PERFORM kaname.relation_fact_fold_row(r.event_type, r.payload, r.created_at);
    END LOOP;
    RETURN NULL;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт — ОПЕРАТОРНАЯ: строки оператора сворачиваются в общем порядке (объект, субъект, id), поэтому два оператора с пересекающимися ключами берут блокировки строк факта в одном порядке, кто бы их ни писал (kaname#568). Свёртку строки делает kaname.relation_fact_fold_row; правила строки — прежние (kaname#107).';

-- +goose StatementBegin
CREATE TRIGGER relation_fact_follows_journal
    AFTER INSERT ON kaname.fga_outbox
    REFERENCING NEW TABLE AS journal_rows
    FOR EACH STATEMENT EXECUTE FUNCTION kaname.relation_fact_from_journal();
-- +goose StatementEnd

-- +goose Down
-- Откат возвращает построчную проекцию дословно (20260916020000) и снимает
-- свёртку строки, у которой не остаётся вызывающего.
-- +goose StatementBegin
DROP TRIGGER relation_fact_follows_journal ON kaname.fga_outbox;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user      text := NEW.payload ->> 'user';
    v_object    text := NEW.payload ->> 'object';
    -- Версия ВЛАДЕЛЬЦА. Есть только у строки, которую владелец упорядочил сам.
    v_owner     text := NEW.payload ->> 'source_version';
    v_version   timestamptz;
    v_relations text[];
    v_relation  text;
    v_type      text;
    v_id        text;
    v_colon     int;
BEGIN
    -- Набор ВЫИГРЫВАЕТ у скаляра: на выдаче набора присутствуют оба поля, и
    -- скаляр там — эхо для пода прежнего выпуска, а не весь предмет строки.
    IF jsonb_array_length(coalesce(NEW.payload -> 'relations', '[]'::jsonb)) > 0 THEN
        SELECT array_agg(value) INTO v_relations
          FROM jsonb_array_elements_text(NEW.payload -> 'relations') AS value;
    ELSIF NEW.payload ->> 'relation' IS NOT NULL THEN
        v_relations := ARRAY[NEW.payload ->> 'relation'];
    END IF;

    IF v_user IS NULL OR v_relations IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            NEW.payload;
    END IF;

    -- Порядок строки. У строки, упорядоченной владельцем, его задаёт версия
    -- владельца: метка журнала — момент НАЧАЛА транзакции службы, и у снятия,
    -- начавшего транзакцию раньше открытия, она оказалась бы старше того, что
    -- снятие обязано снять. Неразбираемая версия роняет строку, а не
    -- подменяется меткой: молчаливая подмена вернула бы ровно тот порядок, от
    -- которого поле защищает.
    v_version := coalesce(v_owner::timestamptz, NEW.created_at);

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    --
    -- ИСКЛЮЧЕНИЕ ОДНО: строка, упорядоченная владельцем, — публикация для
    -- анонимного чтения. Её не выводит ни одна выдача, и отброшенная здесь, она
    -- не существовала бы нигде (kaname#107).
    IF v_owner IS NULL THEN
        v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
        IF array_length(v_relations, 1) IS NULL THEN
            RETURN NULL;
        END IF;
    END IF;

    v_colon := position(':' in v_object);
    IF v_colon <= 1 OR v_colon = length(v_object) THEN
        RAISE EXCEPTION
            'fga_outbox: объект % не имеет формы "<тип>:<идентификатор>" — спроецировать прямой факт нельзя.',
            v_object;
    END IF;
    v_type := substr(v_object, 1, v_colon - 1);
    v_id   := substr(v_object, v_colon + 1);

    IF v_type LIKE '%.%' THEN
        RAISE EXCEPTION
            'fga_outbox: тип объекта % назван словарём каталога. Вопрос о доступе приходит словарём модели прав, и такая строка не совпала бы ни с одним вопросом.',
            v_type;
    END IF;

    FOREACH v_relation IN ARRAY v_relations LOOP
        IF NEW.event_type = 'fga.tuple.write' THEN
            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at)
            VALUES (v_type, v_id, v_relation, v_user, v_version, now())
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF NEW.event_type = 'fga.tuple.delete' THEN
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= v_version;
        END IF;
    END LOOP;
    RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER relation_fact_follows_journal
    AFTER INSERT ON kaname.fga_outbox
    FOR EACH ROW EXECUTE FUNCTION kaname.relation_fact_from_journal();
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством. Исключение — строка, упорядоченная ВЛАДЕЛЬЦЕМ (поле `source_version` полезной нагрузки): публикация для анонимного чтения, которую выдача не выводит; она переносится и сравнивается по версии владельца, а не по метке журнала (kaname#107).';

DROP FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz);
