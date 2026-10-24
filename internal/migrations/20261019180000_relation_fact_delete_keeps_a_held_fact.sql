-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- relation_fact_delete_keeps_a_held_fact — строка снятия не снимает прямой
-- факт, который ещё держит кто-то другой (PRO-Robotech/kaname#919).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ПРЕДМЕТ
--
-- Прямой факт `kaname.relation_fact` ключуется (объект, отношение, субъект) и
-- счётчика держателей не несёт. Держателей у одного ключа бывает несколько:
-- реестры выпущенных кортежей РАЗНЫХ действующих выдач
-- (`access_binding_emitted_tuples`, ключ — выдача) и действующее назначение
-- администратора кластера (`cluster_admin_grants`, кортеж
-- `<тип>:<id> system_admin cluster:<id>`, тот же, что выдача роли кластера).
--
-- До этой миграции вопрос «держит ли факт кто-то ещё» решало ПРИЛОЖЕНИЕ —
-- чтением реестров соседей до вставки строки снятия, на снимке своей
-- транзакции. Ответ устаревал раньше, чем применялся: вторая выдача того же
-- кортежа, зафиксированная между чтением и вставкой, теряла факт, а два снятия,
-- читавшие друг друга живыми, оба оставляли факт без держателя. Половина
-- писателей строки снятия (снос области, смена роли, отзыв администратора
-- кластера) не спрашивала вовсе.
--
-- 2. ПРАВИЛО — в базе, у единственного места, где факт снимается
--
-- Свёртка строки снятия факта, выведенного выдачей (без версии владельца),
-- берёт замок строки факта и только потом спрашивает о держателях — отдельным
-- оператором, то есть свежим снимком READ COMMITTED:
--   * держатель, свёрнутый в эту строку незафиксированным (выдача, второе
--     снятие), держит её замок; снятие ждёт его коммита и видит его исход;
--   * выдача, не дошедшая до свёртки, строку не держит; снятие её не видит и
--     снимает факт, а её свёртка кладёт факт заново — вставкой;
--   * держатели — реестр выдачи со статусом ACTIVE и назначение администратора
--     кластера без истёкшего срока. Свой реестр снимающий писатель обязан
--     убрать ДО строки снятия (статус выдачи, удаление строки, забытые строки
--     реестра) — иначе он держит факт сам.
-- Строки, упорядоченные владельцем (публикация, kaname#107), правило не
-- трогает: их не выводит ни одна выдача.
--
-- Индекс по ключу кортежа — для вопроса о держателях: первичный ключ реестра
-- начинается с выдачи и такого вопроса не обслуживает.
--
-- Свёртка ниже — тело 20261015120000 с одной правкой: ветвь снятия.

-- +goose Up
CREATE INDEX access_binding_emitted_tuples_by_tuple
    ON kaname.access_binding_emitted_tuples (object, relation, fga_user);

COMMENT ON INDEX kaname.access_binding_emitted_tuples_by_tuple IS 'Вопрос свёртки снятия «держит ли кортеж реестр другой действующей выдачи» — по ключу кортежа (kaname#919).';

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

-- +goose Down
-- Свёртка — дословно тело 20261015120000: снятие снова не спрашивает о держателях.
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
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND source_version <= v_version;
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz) IS 'Свёртка ОДНОЙ строки журнала намерений в прямой факт. Отношения набора — в побайтном порядке (kaname#568). К факту прикладывается условие, которое модель объявляет на прямом списке отношения для типа субъекта строки (`[user with mfa_fresh]` на compute_instance#ssh и #console, kaname#133). Снятие с подстановкой `user:*` (писатель прежнего выпуска) снимает хранимого субъекта-класс: `v_get` — system_class:anonymous, прочее — system_class:authenticated, перевод переезда; запись подстановки отвергает relation_fact_subject_not_wildcard (kaname#829). Зовётся только операторной проекцией kaname.relation_fact_from_journal().';

DROP INDEX kaname.access_binding_emitted_tuples_by_tuple;
