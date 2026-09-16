-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Публикация объекта для АНОНИМНОГО ЧТЕНИЯ (`user:* #v_get`) доходит до вердикта и
-- судится ПОРЯДКОМ ВЛАДЕЛЬЦА, а не порядком доставок (задача kaname#107).
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ — ДВА ДЕФЕКТА ОДНОГО ПУТИ, И ЧИНЯТСЯ ОНИ ТОЛЬКО ВМЕСТЕ
--
-- Путь чистой выдачи (RegisterResource / UnregisterResource с кортежем
-- `user:* #v_get`) клал строку журнала `kaname.fga_outbox`, и проекция журнала в
-- прямой факт её ОТБРАСЫВАЛА: отношение-глагол (`v_*`) не переносится, потому что
-- форма E выводит глагол из выдачи. Публикация выдачей не выводится ничем — её
-- объявляет владелец ресурса, — поэтому опубликованный репозиторий оставался
-- закрытым для анонимного `pull` при любом входе. Замер на стволе до правки:
-- строка журнала 1, прямых фактов 0, вердикт `deny`. План формы E этот факт при
-- этом СПРАШИВАЛ (атом `('', 'v_get')` у `registry_repository`, компилятор модели
-- прямо называет его «накладным кортежем публичного чтения»): два места об одном
-- предмете разошлись, и молча.
--
-- Второй дефект дремал за первым. Порядок двух противоположных намерений об одном
-- объекте не судило ничто: версию владельца путь принимал и не читал, а журнал
-- упорядочен меткой `now()` — моментом НАЧАЛА транзакции службы, а не намерением
-- владельца. Производитель доставляет открытие дважды (синхронно и надёжной
-- очередью), закрытие — один раз; запоздавшая синхронная доставка открытия после
-- закрытия вернула бы анонимное чтение приватному репозиторию. Сегодня это не
-- происходило только потому, что не открывалось ничто, — и правка проекции без
-- стража порядка сделала бы дефект живым.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ЧТО ЗАВОДИТСЯ
--
-- 1. `kaname.public_read_publication` — ПОСЛЕДНЕЕ ПРИМЕНЁННОЕ намерение владельца
--    по каждому объекту: его версия и то, открывает ли оно. Это надгробие, а не
--    журнал: строка переживает снятие и поэтому отличает «закрыто в v2» от «не
--    было ничего», — без неё запоздавшее открытие v1 после закрытия v2 нашло бы
--    пустое место и легло бы заново. Сравнение версий идёт ОДНИМ оператором
--    (`INSERT … ON CONFLICT … DO UPDATE … WHERE`) под блокировкой строки, а не
--    чтением-и-действием (запрет #10); строку журнала путь кладёт ТОЛЬКО когда
--    намерение применилось, в той же транзакции.
--
--    Рост таблицы ограничен числом различных объектов, когда-либо опубликованных
--    или снятых. Идентификатор репозитория — его имя внутри реестра, поэтому
--    пересоздание репозитория с тем же именем переиспользует ту же строку.
--
-- 2. Проекция журнала узнаёт строку, УПОРЯДОЧЕННУЮ ВЛАДЕЛЬЦЕМ, по полю
--    `source_version` в полезной нагрузке. Такая строка:
--      • сравнивается по версии владельца, а не по метке `now()` — иначе снятие,
--        чья транзакция началась раньше открытия, не сняло бы его;
--      • переносится в прямой факт, даже будучи глаголом: публикацию выдача не
--        выводит, значит без факта её нет нигде.
--    Строки без поля ведут себя дословно как прежде, включая отказ переносить
--    глагол, выведенный из выдачи. Пишет поле ЕДИНСТВЕННЫЙ производитель — путь
--    публикации (`fga_outbox.EmitPublicationTx`), и форма кортежа у него
--    закреплена построением: субъект и отношение он берёт у правила приёма, а не
--    у вызывающего.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЗДЕСЬ НЕТ, И ЭТО РЕШЕНИЕ
--
-- ОБРАТНОГО ЗАПОЛНЕНИЯ ИЗ ЖУРНАЛА НЕТ. Строки чистой выдачи, положенные до правки,
-- версии владельца не несут, а упорядочены приходом в службу — то есть ровно тем
-- порядком, который правка перестаёт признавать. Проиграть их означало бы
-- впечатать в новое состояние ту самую перестановку, от которой оно защищает, в
-- сторону ЛИШНЕГО доступа. До правки анонимное чтение не открывалось ни у кого,
-- поэтому отказ от заполнения ничего не отнимает: публикации, объявленные раньше,
-- доедут со следующей сменой видимости у владельца.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE kaname.public_read_publication (
    object_type    text                     NOT NULL,
    object_id      text                     NOT NULL,
    source_version timestamp with time zone NOT NULL,
    published      boolean                  NOT NULL,
    updated_at     timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT public_read_publication_pkey PRIMARY KEY (object_type, object_id),
    CONSTRAINT public_read_publication_object_type_model_dictionary
        CHECK (object_type <> '' AND object_type NOT LIKE '%.%'),
    CONSTRAINT public_read_publication_object_id_nonempty CHECK (object_id <> '')
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.public_read_publication IS 'Последнее применённое намерение владельца о публикации объекта для анонимного чтения (`user:* #v_get`): версия владельца и то, открывает ли оно. Надгробие, а не журнал: строка переживает снятие, поэтому запоздавшая доставка старшего открытия не находит пустого места. Сравнение версий — одним оператором под блокировкой строки; строка журнала кладётся только применившимся намерением (kaname#107).';
COMMENT ON COLUMN kaname.public_read_publication.object_type IS 'Тип объекта в словаре МОДЕЛИ ПРАВ — как в кортеже публикации и в kaname.relation_fact.object_type.';
COMMENT ON COLUMN kaname.public_read_publication.source_version IS 'Версия владельца последнего применённого намерения. ''-infinity'' — намерения без версии, порядка не доказывающие.';

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

COMMENT ON FUNCTION kaname.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством. Исключение — строка, упорядоченная ВЛАДЕЛЬЦЕМ (поле `source_version` полезной нагрузки): публикация для анонимного чтения, которую выдача не выводит; она переносится и сравнивается по версии владельца, а не по метке журнала (kaname#107).';

-- +goose Down
-- Откат возвращает проекцию ДОСЛОВНО к прежнему телу (0001) и снимает то, что
-- прежнее тело произвести не могло: прямые факты-глаголы. Оставленные, они
-- продолжали бы отвечать «читать может всякий», а снять их было бы нечем —
-- прежняя проекция строку снятия глагола отбрасывает. Откат уходит в сторону
-- отказа: до правки анонимное чтение не открывалось ни у кого.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user      text := NEW.payload ->> 'user';
    v_object    text := NEW.payload ->> 'object';
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

    -- Глагол выводится из выдачи и копией не хранится (см. 0098). Набор из
    -- одних глаголов выходит здесь — до разбора объекта, как и одиночный.
    v_relations := ARRAY(SELECT r FROM unnest(v_relations) AS r WHERE r NOT LIKE 'v\_%');
    IF array_length(v_relations, 1) IS NULL THEN
        RETURN NULL;
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
            VALUES (v_type, v_id, v_relation, v_user, NEW.created_at, now())
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF NEW.event_type = 'fga.tuple.delete' THEN
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= NEW.created_at;
        END IF;
    END LOOP;
    RETURN NULL;
END $$;

-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством.';

DELETE FROM kaname.relation_fact WHERE relation LIKE 'v\_%';

DROP TABLE kaname.public_read_publication;
