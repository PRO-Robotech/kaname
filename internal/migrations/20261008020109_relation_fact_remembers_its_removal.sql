-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- relation_fact_remembers_its_removal — прямой факт права помнит своё снятие:
-- запоздалая запись выдачи, не новее снятия того же кортежа, права не
-- восстанавливает (задачи PRO-Robotech/kaname#636 и #484; сценарий NTF3-184).
--
-- Санкция: приёмка `docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
-- репозитория PRO-Robotech/kacho-workspace, Р30 «Поколение и проекция — один
-- производитель» и §1.15 (редакция 39, решение Д134 B2: `relation_fact`
-- сохраняет СВОЙ порядок записи и снятия — страж от воскрешения снятого права),
-- отпечаток `6e7444a4d53e7a3ebfa423f9da5420344ae6a0ed2f43ce33ff7796f8db189ae6`.
-- Доводы там; здесь — то, что нужно читателю СХЕМЫ.
--
-- =============================================================================
-- ДЕФЕКТ
-- =============================================================================
-- Проекция журнала `relation_fact_from_journal` сравнивала версию записи с
-- версией ХРАНИМОГО факта, а снятие удаляло строку целиком. После снятия
-- сравнивать было не с чем: запись с версией `t1`, пришедшая после снятия `t2 >
-- t1` (повторная доставка, запоздавшая очередь), находила пустое место и
-- ложилась заново — право возвращалось тому, у кого его сняли. Приёмка считала
-- порядок проекции стражем от воскрешения; проба NTF3-184 это опровергла.
--
-- =============================================================================
-- ЧТО ЗАВОДИТСЯ
-- =============================================================================
-- `kaname.relation_fact_removal` — версия последнего применённого СНЯТИЯ по
-- каждому кортежу. Это надгробие, а не журнал (та же форма, что у
-- `public_read_publication`): строка переживает удаление факта и поэтому
-- отличает «снято в t2» от «не было ничего».
--
--   * снятие удаляет факт не новее себя (как прежде) и поднимает версию
--     надгробия до своей — ОДНИМ оператором `INSERT … ON CONFLICT … DO UPDATE …
--     WHERE`, версия только растёт; след остаётся и тогда, когда факта не было:
--     снятие, доставленное раньше своей записи, обязано отвергнуть и её;
--   * запись применяется, только если надгробия СТРОГО новее её нет — условие
--     стоит в том же операторе, что вставка, а не чтением перед ней (запрет
--     #10). Равенство версий записи не отвергает: на равных версиях порядок —
--     порядок журнала, как и прежде (снятие и запись одной транзакции с одной
--     меткой — это «снять и выдать заново», и выдача остаётся);
--   * применённая запись снимает надгробие своего кортежа: факт теперь сам
--     несёт версию новее снятия, и запоздалую запись не новее неё отвергает
--     прежнее сравнение с хранимой версией.
--
-- Тип версии — `timestamptz`, как у факта: поколение объекта (`bigint`) сюда не
-- пишется (Д134 B2, NTF3-182).
--
-- Рост таблицы ограничен числом различных кортежей, снятых и с тех пор не
-- выданных заново; выдача кортежа строку снимает.
--
-- Пишет таблицу ТОЛЬКО эта проекция — производитель факта один (гейт
-- `internal/check` о единственном писателе `relation_fact`), и его след
-- рождается в том же операторе журнала.
--
-- =============================================================================
-- ЧЕГО ЗДЕСЬ НЕТ, И ЭТО РЕШЕНИЕ
-- =============================================================================
-- ОБРАТНОГО ЗАПОЛНЕНИЯ НЕТ. Снятия, применённые до этой миграции, следа не
-- оставили, и восстановить их версию не из чего: строка журнала снятия не
-- хранит, был ли за ней факт. Надгробия начинаются с первого снятия после
-- миграции.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE kaname.relation_fact_removal (
    object_type    text                     NOT NULL,
    object_id      text                     NOT NULL,
    relation       text                     NOT NULL,
    subject        text                     NOT NULL,
    source_version timestamp with time zone NOT NULL,
    CONSTRAINT relation_fact_removal_pkey PRIMARY KEY (object_type, object_id, relation, subject),
    CONSTRAINT relation_fact_removal_object_type_model_dictionary
        CHECK (object_type <> '' AND object_type NOT LIKE '%.%'),
    CONSTRAINT relation_fact_removal_object_id_nonempty CHECK (object_id <> ''),
    CONSTRAINT relation_fact_removal_relation_nonempty CHECK (relation <> ''),
    CONSTRAINT relation_fact_removal_subject_nonempty CHECK (subject <> '')
);
-- +goose StatementEnd

COMMENT ON TABLE kaname.relation_fact_removal IS 'Надгробие прямого факта: версия последнего применённого снятия кортежа. Запись не новее его факта не создаёт; применённая запись строку снимает. Пишет только проекция журнала relation_fact_from_journal (NTF3-184, kaname#636).';
COMMENT ON COLUMN kaname.relation_fact_removal.source_version IS 'Версия снятия в порядке kaname.relation_fact.source_version: версия владельца у упорядоченной им строки журнала, иначе метка строки журнала.';

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
            -- Запись применяется, только если она новее хранимого факта И не
            -- старше последнего применённого снятия. Оба сравнения — в ОДНОМ
            -- операторе с записью, а не чтением перед ней (запрет #10).
            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at)
            SELECT v_type, v_id, v_relation, v_user, v_version, now()
             WHERE NOT EXISTS (
                   SELECT 1 FROM kaname.relation_fact_removal r
                    WHERE r.object_type = v_type AND r.object_id = v_id
                      AND r.relation = v_relation AND r.subject = v_user
                      AND r.source_version > v_version)
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE relation_fact.source_version < EXCLUDED.source_version;
            -- Применённая запись новее снятия: след снятия больше ничего не
            -- стережёт — факт теперь сам несёт версию новее него.
            IF FOUND THEN
                DELETE FROM kaname.relation_fact_removal
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_user;
            END IF;
        ELSIF NEW.event_type = 'fga.tuple.delete' THEN
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= v_version;
            -- Снятие оставляет след — даже когда снимать было нечего: снятие,
            -- доставленное раньше своей записи, обязано отвергнуть и её.
            INSERT INTO kaname.relation_fact_removal AS r
                   (object_type, object_id, relation, subject, source_version)
            VALUES (v_type, v_id, v_relation, v_user, v_version)
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version
             WHERE r.source_version < EXCLUDED.source_version;
        END IF;
    END LOOP;
    RETURN NULL;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_from_journal() IS 'Проекция журнала намерений в прямой факт. Читает обе формы строки: набор отношений одной выдачи (`relations`, выигрывает у скаляра — он на выдаче лишь эхо) и одиночное `relation`. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством. Исключение — строка, упорядоченная ВЛАДЕЛЬЦЕМ (поле `source_version` полезной нагрузки): публикация для анонимного чтения, которую выдача не выводит; она переносится и сравнивается по версии владельца, а не по метке журнала (kaname#107). Запись, не новее последнего применённого снятия того же кортежа (kaname.relation_fact_removal), факта не создаёт; снятие оставляет след и тогда, когда снимать было нечего (NTF3-184, kaname#636).';

-- +goose Down
-- Откат возвращает проекцию ДОСЛОВНО к телу 20260916020000 и снимает надгробия:
-- прежнее тело их не читает.
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

DROP TABLE kaname.relation_fact_removal;
