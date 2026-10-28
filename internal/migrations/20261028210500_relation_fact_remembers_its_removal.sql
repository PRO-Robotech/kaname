-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- relation_fact_remembers_its_removal — прямой факт права помнит своё снятие:
-- запоздалая запись, упорядоченная владельцем и не новее снятия того же
-- кортежа, права не восстанавливает (задача PRO-Robotech/kaname#636, сценарий
-- NTF3-184).
--
-- Санкция: одобренная приёмка редакции 2 (круг 2)
-- `docs/engineering/acceptance/relation-fact-remembers-its-removal.md`,
-- SHA-256 `f5b979630f087295e8b8038a0ac4dbe43936c9522a920cfe1d9b96a3600b9304`.
-- Публичный контракт не меняется; отказ проверки таблицы — дефект писателя, она
-- в полосе дефекта службы (`check_value_lanes.go`, `relation_fact_removal: nil`).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ДЕФЕКТ
--
-- Свёртка `kaname.relation_fact_fold_row` сравнивала версию строки журнала с
-- версией ХРАНИМОГО факта, а снятие удаляло строку факта целиком. После снятия
-- сравнивать было не с чем: запись с версией владельца `t1`, пришедшая после
-- снятия `t2 > t1` (повторная доставка, запоздавшая очередь, сырой писатель
-- журнала), находила пустое место и ложилась заново — право возвращалось тому,
-- у кого его сняли. То же — снятие, доставленное раньше своей записи: оно не
-- находило факта и следа не оставляло.
--
-- 2. ЧТО ВВОДИТСЯ
--
-- `kaname.relation_fact_removal` — версия последнего применённого СНЯТИЯ по
-- каждому кортежу. Это надгробие, а не журнал (та же форма, что у
-- `public_read_publication`): строка переживает удаление факта и поэтому
-- отличает «снято в t2» от «не было ничего».
--   * снятие удаляет факт не новее себя (как прежде) и поднимает версию
--     надгробия до своей — одним `INSERT … ON CONFLICT … DO UPDATE … WHERE`,
--     версия только растёт; след остаётся и тогда, когда факта не было;
--   * запись применяется, только если надгробия СТРОГО новее её нет — условие
--     стоит в том же операторе, что вставка, а не чтением перед ней (запрет
--     #10). Равенство версий запись не отвергает: на равных версиях порядок —
--     порядок журнала, как и прежде;
--   * применённая запись снимает надгробие своего кортежа: факт теперь сам
--     несёт версию не старше снятия, и запоздалую запись не новее неё
--     отвергает прежнее сравнение с хранимой версией. Рост таблицы поэтому
--     ограничен числом кортежей, снятых и с тех пор не выданных заново.
--     Строку с версией владельца пишет лишь путь публикации, кортеж на объект
--     (`fga_outbox.EmitPublicationTx`), — надгробий не больше строк
--     `kaname.public_read_publication`.
-- Тип версии — `timestamptz`, как у факта; ключ — ключ факта; ключ снятия —
-- хранимый субъект (`user:*` прежнего писателя переводится, как и в ветви
-- снятия свёртки, kaname#829). Порядок замков — строка факта, затем строка
-- надгробия, в обеих ветвях.
--
-- 3. ГРАНИЦА: надгробие судит ТОЛЬКО строки, упорядоченные владельцем
--
-- Строка без версии владельца (выведенная выдачей) упорядочена меткой журнала:
-- у выдачи — начало её транзакции (`now()`), у снятия — момент вставки
-- (`clock_timestamp()`, emitter.go, kaname#919, kaname#923). Выдача, начавшая
-- транзакцию раньше снятия и свёрнутая после его коммита, по этому порядку
-- ОБЯЗАНА лечь заново (`TestEmitDeleteTx_GrantFoldedAfterTheRevokeSurvives`):
-- её метка старше метки снятия, но она — действующее состояние выдачи, а не
-- запоздалая доставка. Надгробие на таких строках снимало бы право действующей
-- выдачи. От воскрешения их стережёт реестр держателей (kaname#919): строку без
-- версии владельца пишет транзакция самой выдачи, свёртка идёт в ней же.
--
-- Строки, упорядоченные владельцем, пишет путь публикации
-- (`fga_outbox.EmitPublicationTx`), лишь когда намерение применилось к
-- состоянию публикации; замок строки состояния упорядочивает намерения одного
-- объекта. Надгробие держит тот же порядок у ЕДИНСТВЕННОГО производителя факта,
-- кто бы ни положил строку журнала.
--
-- 4. ЧЕГО ЗДЕСЬ НЕТ, И ЭТО РЕШЕНИЕ
--
-- ОБРАТНОГО ЗАПОЛНЕНИЯ НЕТ. Снятия, применённые до этой миграции, следа не
-- оставили, и восстановить их версию не из чего: строка журнала снятия не
-- хранит, был ли за ней факт. Надгробия начинаются с первого снятия после
-- миграции.
--
-- Свёртка ниже — тело 20261019180000 с двумя правками: условие записи и след
-- снятия, обе — только для строк с версией владельца.

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

COMMENT ON TABLE kaname.relation_fact_removal IS 'Надгробие прямого факта: версия последнего применённого снятия кортежа, упорядоченного владельцем. Запись не новее его факта не создаёт; применённая запись строку снимает. Пишет только свёртка журнала kaname.relation_fact_fold_row (NTF3-184, kaname#636).';
COMMENT ON COLUMN kaname.relation_fact_removal.source_version IS 'Версия снятия в порядке kaname.relation_fact.source_version: версия владельца строки журнала.';

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_fold_row(
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
    -- Условие, которое модель объявляет на прямом списке этого отношения для
    -- типа субъекта строки (`[user with mfa_fresh]`); пусто — безусловно.
    v_condition text;
    -- Хранимый субъект строки снятия (п. 4 шапки миграции kaname#829).
    v_stored    text;
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
            -- Условие прикладывает ПИСАТЕЛЬ, и только он: факт человека на
            -- условном отношении без условия значил бы безусловный допуск там,
            -- где модель объявляет допуск лишь при выполненном условии.
            -- Перечень — дословно `with`-записи канонической модели; гейт
            -- `TestConditionedRelationHasAProducer` сверяет его с моделью в обе
            -- стороны (запись модели без строки и строка без записи модели —
            -- находки).
            SELECT c.condition_name INTO v_condition
              FROM (VALUES
                    ('compute_instance', 'console', 'user', 'mfa_fresh'),
                    ('compute_instance', 'ssh',     'user', 'mfa_fresh')
                   ) AS c(object_type, relation, subject_type, condition_name)
             WHERE c.object_type = v_type AND c.relation = v_relation
               AND c.subject_type = split_part(v_user, ':', 1);

            -- Запись, упорядоченная владельцем, применяется, только если она
            -- новее хранимого факта И не старше последнего применённого снятия
            -- того же кортежа (п. 2 шапки). Оба сравнения — в ОДНОМ операторе с
            -- записью, а не чтением перед ней (запрет #10). Строку без версии
            -- владельца надгробие не судит (п. 3 шапки).
            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at, condition_name)
            SELECT v_type, v_id, v_relation, v_user, v_version, now(), coalesce(v_condition, '')
             WHERE v_owner IS NULL OR NOT EXISTS (
                   SELECT 1 FROM kaname.relation_fact_removal r
                    WHERE r.object_type = v_type AND r.object_id = v_id
                      AND r.relation = v_relation AND r.subject = v_user
                      AND r.source_version > v_version)
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version,
                   condition_name = EXCLUDED.condition_name
             WHERE relation_fact.source_version < EXCLUDED.source_version;
            -- Применённая запись не старше снятия: след снятия больше ничего не
            -- стережёт — факт сам несёт версию не старше него, и запоздалую
            -- запись не новее неё отвергает сравнение с хранимой версией.
            IF FOUND AND v_owner IS NOT NULL THEN
                DELETE FROM kaname.relation_fact_removal
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_user;
            END IF;
        ELSIF p_event_type = 'fga.tuple.delete' THEN
            -- Снятие с подстановкой прежнего писателя снимает строку, в которую
            -- переезд (п. 3) перенёс то, что этот писатель когда-то положил:
            -- перевод тот же, что у переписи, по отношению (п. 4 шапки).
            v_stored := v_user;
            IF v_user = 'user:*' THEN
                v_stored := CASE WHEN v_relation = 'v_get' THEN 'system_class:anonymous'
                                 ELSE 'system_class:authenticated' END;
            END IF;
            -- Факт, выведенный выдачей (строка без версии владельца), снимается
            -- лишь тогда, когда его не держит больше НИКТО (п. 2 шапки). Сперва
            -- замок строки факта: снятие ждёт любого, кто держит её незафиксированной
            -- (выдачу, свёрнутую в той же строке, второе снятие), и вопрос «держит
            -- ли кто-то ещё» задаётся уже после его коммита, свежим снимком.
            IF v_owner IS NULL THEN
                PERFORM 1 FROM kaname.relation_fact
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_stored
                   FOR UPDATE;
                IF NOT FOUND THEN
                    CONTINUE;
                END IF;
                IF EXISTS (
                       SELECT 1
                         FROM kaname.access_binding_emitted_tuples et
                         JOIN kaname.access_bindings ab ON ab.id = et.binding_id
                        WHERE et.object = v_object AND et.relation = v_relation
                          AND et.fga_user = v_stored AND ab.status = 'ACTIVE')
                   OR (v_type = 'cluster' AND v_relation = 'system_admin' AND EXISTS (
                       SELECT 1
                         FROM kaname.cluster_admin_grants g
                        WHERE g.cluster_id = v_id
                          AND g.subject_type || ':' || g.subject_id = v_stored
                          AND (g.granted_until IS NULL OR g.granted_until > clock_timestamp())))
                THEN
                    CONTINUE;
                END IF;
            END IF;
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND source_version <= v_version;
            -- Снятие, упорядоченное владельцем, оставляет след — и тогда, когда
            -- снимать было нечего: снятие, доставленное раньше своей записи,
            -- обязано отвергнуть и её. Версия следа только растёт.
            IF v_owner IS NOT NULL THEN
                INSERT INTO kaname.relation_fact_removal AS r
                       (object_type, object_id, relation, subject, source_version)
                VALUES (v_type, v_id, v_relation, v_stored, v_version)
                ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
                   SET source_version = EXCLUDED.source_version
                 WHERE r.source_version < EXCLUDED.source_version;
            END IF;
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz) IS 'Свёртка ОДНОЙ строки журнала намерений в прямой факт. Отношения набора — в побайтном порядке (kaname#568). К факту прикладывается условие, которое модель объявляет на прямом списке отношения для типа субъекта строки (`[user with mfa_fresh]` на compute_instance#ssh и #console, kaname#133). Снятие с подстановкой `user:*` (писатель прежнего выпуска) снимает хранимого субъекта-класс (kaname#829). Снятие факта, выведенного выдачей, — под замком строки факта и лишь когда его не держит ни реестр действующей выдачи, ни действующее назначение администратора кластера: кто бы ни писал строку снятия (kaname#919). Строка, упорядоченная владельцем: снятие оставляет надгробие kaname.relation_fact_removal и тогда, когда снимать было нечего, а запись не новее надгробия факта не создаёт (NTF3-184, kaname#636). Зовётся только операторной проекцией kaname.relation_fact_from_journal().';

-- +goose Down
-- Свёртка — дословно тело 20261019180000: надгробие не читается и не пишется,
-- после чего таблица снимается.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_fold_row(
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
    -- Условие, которое модель объявляет на прямом списке этого отношения для
    -- типа субъекта строки (`[user with mfa_fresh]`); пусто — безусловно.
    v_condition text;
    -- Хранимый субъект строки снятия (п. 4 шапки миграции kaname#829).
    v_stored    text;
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
            -- Условие прикладывает ПИСАТЕЛЬ, и только он: факт человека на
            -- условном отношении без условия значил бы безусловный допуск там,
            -- где модель объявляет допуск лишь при выполненном условии.
            -- Перечень — дословно `with`-записи канонической модели; гейт
            -- `TestConditionedRelationHasAProducer` сверяет его с моделью в обе
            -- стороны (запись модели без строки и строка без записи модели —
            -- находки).
            SELECT c.condition_name INTO v_condition
              FROM (VALUES
                    ('compute_instance', 'console', 'user', 'mfa_fresh'),
                    ('compute_instance', 'ssh',     'user', 'mfa_fresh')
                   ) AS c(object_type, relation, subject_type, condition_name)
             WHERE c.object_type = v_type AND c.relation = v_relation
               AND c.subject_type = split_part(v_user, ':', 1);

            INSERT INTO kaname.relation_fact
                   (object_type, object_id, relation, subject, source_version, created_at, condition_name)
            VALUES (v_type, v_id, v_relation, v_user, v_version, now(), coalesce(v_condition, ''))
            ON CONFLICT (object_type, object_id, relation, subject) DO UPDATE
               SET source_version = EXCLUDED.source_version,
                   condition_name = EXCLUDED.condition_name
             WHERE relation_fact.source_version < EXCLUDED.source_version;
        ELSIF p_event_type = 'fga.tuple.delete' THEN
            -- Снятие с подстановкой прежнего писателя снимает строку, в которую
            -- переезд (п. 3) перенёс то, что этот писатель когда-то положил:
            -- перевод тот же, что у переписи, по отношению (п. 4 шапки).
            v_stored := v_user;
            IF v_user = 'user:*' THEN
                v_stored := CASE WHEN v_relation = 'v_get' THEN 'system_class:anonymous'
                                 ELSE 'system_class:authenticated' END;
            END IF;
            -- Факт, выведенный выдачей (строка без версии владельца), снимается
            -- лишь тогда, когда его не держит больше НИКТО (п. 2 шапки). Сперва
            -- замок строки факта: снятие ждёт любого, кто держит её незафиксированной
            -- (выдачу, свёрнутую в той же строке, второе снятие), и вопрос «держит
            -- ли кто-то ещё» задаётся уже после его коммита, свежим снимком.
            IF v_owner IS NULL THEN
                PERFORM 1 FROM kaname.relation_fact
                 WHERE object_type = v_type AND object_id = v_id
                   AND relation = v_relation AND subject = v_stored
                   FOR UPDATE;
                IF NOT FOUND THEN
                    CONTINUE;
                END IF;
                IF EXISTS (
                       SELECT 1
                         FROM kaname.access_binding_emitted_tuples et
                         JOIN kaname.access_bindings ab ON ab.id = et.binding_id
                        WHERE et.object = v_object AND et.relation = v_relation
                          AND et.fga_user = v_stored AND ab.status = 'ACTIVE')
                   OR (v_type = 'cluster' AND v_relation = 'system_admin' AND EXISTS (
                       SELECT 1
                         FROM kaname.cluster_admin_grants g
                        WHERE g.cluster_id = v_id
                          AND g.subject_type || ':' || g.subject_id = v_stored
                          AND (g.granted_until IS NULL OR g.granted_until > clock_timestamp())))
                THEN
                    CONTINUE;
                END IF;
            END IF;
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND source_version <= v_version;
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz) IS 'Свёртка ОДНОЙ строки журнала намерений в прямой факт. Отношения набора — в побайтном порядке (kaname#568). К факту прикладывается условие, которое модель объявляет на прямом списке отношения для типа субъекта строки (`[user with mfa_fresh]` на compute_instance#ssh и #console, kaname#133). Снятие с подстановкой `user:*` (писатель прежнего выпуска) снимает хранимого субъекта-класс (kaname#829). Снятие факта, выведенного выдачей, — под замком строки факта и лишь когда его не держит ни реестр действующей выдачи, ни действующее назначение администратора кластера: кто бы ни писал строку снятия (kaname#919). Зовётся только операторной проекцией kaname.relation_fact_from_journal().';

DROP TABLE kaname.relation_fact_removal;
