-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0100_relation_fact_reads_the_whole_grant — проекция журнала читает ОБЕ формы
-- строки: одиночное отношение и набор отношений одной выдачи.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Две линии сошлись в накопительной ветке в один вечер и разошлись по форме
-- строки журнала `kacho_iam.fga_outbox`:
--
--   * 0098 завела триггер `relation_fact_from_journal`, складывающий прямой
--     факт из журнала. Он читает ОДНО поле — `payload->>'relation'` — и роняет
--     вставку исключением, если его нет;
--   * 0099 (и её код) ввела ВТОРУЮ форму строки: набор глаголов одной выдачи
--     едет одной строкой в `payload->'relations'`, и у такой строки скалярного
--     `relation` НЕТ вовсе (отзыв набора его не несёт намеренно — совместимое
--     эхо кладётся только на выдачу, см. шапку `fga_outbox/emitter.go`).
--
-- Каждая сторона по отдельности верна, и обе прошли свои пробы. Вместе они
-- дают отказ на пути ЗАПИСИ: всякая выдача или отзыв, где у субъекта больше
-- одного отношения на объекте, роняет транзакцию вызывающего с
-- «строка без user/relation/object». То есть набор глаголов — ровно тот
-- случай, ради которого вторая форма и заведена, — не проходит вовсе.
--
-- Дефект не был виден ни одной из двух линий: до перенумерации миграций
-- (#526) обе объявляли версию 98, мигратор падал паникой на сборе списка, и
-- сервис не стартовал — а значит до этого места не доходила ни одна проба.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- РЕШЕНИЕ
--
-- Проекция читает набор, когда он есть, и скаляр — когда набора нет. Порядок
-- важен и обратным быть не может: строка ВЫДАЧИ набора несёт ОБА поля —
-- `relations` (весь набор) и `relation` (совместимое эхо, первый элемент).
-- Прочтя скаляр первым, проекция взяла бы из выдачи одно отношение из
-- нескольких и молча потеряла остальные — то есть своя БД знала бы о меньшем
-- доступе, чем выдан движку, ровно там, где это не видно.
--
-- Всё прочее поведение 0098 сохранено дословно: глагол (`v_*`) в прямой факт
-- НЕ переносится (его форма E выводит из выдачи), объект без формы
-- `<тип>:<идентификатор>` и точечный тип ОТВЕРГАЮТСЯ, а строка, не назвавшая
-- отношения НИ В ОДНОЙ из форм, по-прежнему роняет вставку — этот же инвариант
-- стоит ограничением `fga_outbox_relation_present_check` из 0099.
--
-- Порядок проверок сохранён тоже: набор, состоящий из одних глаголов, выходит
-- ДО разбора объекта — как одиночный глагол выходил в 0098. Иначе строка,
-- которую проекция и так не хранит, начала бы ронять вставку из-за формы
-- объекта, до которой прежде не доходила.
--
-- Досыпать накопленное не требуется, и это не умолчание: свёртка 0098 идёт в
-- момент 0098, а строки-наборы производит только код, приехавший с 0099, —
-- то есть на момент свёртки их в журнале нет ни на одной базе. Вперёд их
-- забирает триггер.

-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.relation_fact_from_journal() RETURNS trigger
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
            INSERT INTO kacho_iam.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at)
            VALUES (v_type, v_id, v_relation, v_user, NEW.created_at, now())
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF NEW.event_type = 'fga.tuple.delete' THEN
            DELETE FROM kacho_iam.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= NEW.created_at;
        END IF;
    END LOOP;
    RETURN NULL;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kacho_iam.relation_fact_from_journal() IS
  'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством.';

-- +goose Down
-- +goose StatementBegin
-- Назад к чтению ОДНОГО скалярного отношения (форма 0098). Откатывать это
-- имеет смысл только вместе с кодом, перестающим эмитировать наборы: на
-- строке-наборе прежняя проекция роняет вставку.
CREATE OR REPLACE FUNCTION kacho_iam.relation_fact_from_journal() RETURNS trigger
    LANGUAGE plpgsql
AS $$
DECLARE
    v_user     text := NEW.payload ->> 'user';
    v_relation text := NEW.payload ->> 'relation';
    v_object   text := NEW.payload ->> 'object';
    v_type     text;
    v_id       text;
    v_colon    int;
BEGIN
    IF v_user IS NULL OR v_relation IS NULL OR v_object IS NULL THEN
        RAISE EXCEPTION
            'fga_outbox: строка без user/relation/object (%). Прямой факт складывается из этого журнала, и строка, которую нельзя спроецировать, дала бы движку право, о котором своя БД не знает.',
            NEW.payload;
    END IF;

    IF v_relation LIKE 'v\_%' THEN
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

    IF NEW.event_type = 'fga.tuple.write' THEN
        INSERT INTO kacho_iam.relation_fact
               (object_type, object_id, relation, subject, source_version, created_at)
        VALUES (v_type, v_id, v_relation, v_user, NEW.created_at, now())
        ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
           SET source_version = EXCLUDED.source_version
         WHERE relation_fact.source_version < EXCLUDED.source_version;
    ELSIF NEW.event_type = 'fga.tuple.delete' THEN
        DELETE FROM kacho_iam.relation_fact
         WHERE object_type = v_type AND object_id = v_id
           AND relation = v_relation AND subject = v_user
           AND source_version <= NEW.created_at;
    END IF;
    RETURN NULL;
END $$;
-- +goose StatementEnd
