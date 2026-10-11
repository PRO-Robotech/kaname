-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- person_machine_entry_fact_carries_its_condition — факт человека на условном
-- отношении несёт условие, объявленное моделью (kaname#133, исход (а); приёмка
-- `assurance-level-is-declared-by-our-session.md` §3.4, звено З2).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Модель объявляет человека на `compute_instance#ssh` и `#console` только
-- `[user with mfa_fresh]`. Условие лежит на самой строке прямого факта
-- (`relation_fact.condition_name`), и вопрос о доступе вычисляет его сам; строка
-- без условия — безусловное основание. Единственный писатель факта — свёртка
-- журнала — колонок условия не заполнял, поэтому объявленное условие не было в
-- силе нигде: факт человека на этих отношениях был бы безусловным допуском, а
-- прямая ветвь — фактически «не допускает никого» либо «допускает всегда»,
-- смотря кто его положит.
--
-- Свёртка строки (`kaname.relation_fact_fold_row`) теперь прикладывает к факту
-- условие из перечня, дословно повторяющего `with`-записи канонической модели;
-- перечень и модель сверяет гейт `TestConditionedRelationHasAProducer`. Факт
-- служебной учётки на `ssh` модель объявляет без условия — и строка остаётся
-- безусловной.
--
-- Обратное заполнение: строки человека на этих отношениях, сложенные прежним
-- писателем, получают то же условие — значение выражается одним способом, и
-- факта человека на них без условия не бывает (§3.4, «З2»).
--
-- Имя функции и её сигнатура сохранены: её зовёт операторная проекция
-- `kaname.relation_fact_from_journal()` (20261005040457), и та не меняется.

-- +goose Up
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
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_user
               AND source_version <= v_version;
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd

COMMENT ON FUNCTION kaname.relation_fact_fold_row(text, jsonb, timestamptz) IS 'Свёртка ОДНОЙ строки журнала намерений в прямой факт. Отношения набора — в побайтном порядке (kaname#568). К факту прикладывается условие, которое модель объявляет на прямом списке отношения для типа субъекта строки (`[user with mfa_fresh]` на compute_instance#ssh и #console, kaname#133). Зовётся только операторной проекцией kaname.relation_fact_from_journal().';

UPDATE kaname.relation_fact
   SET condition_name = 'mfa_fresh'
 WHERE object_type = 'compute_instance'
   AND relation IN ('ssh', 'console')
   AND split_part(subject, ':', 1) = 'user'
   AND condition_name = '';

-- +goose Down
-- Откат возвращает свёртку строки дословно (20261005040457) и снимает условие,
-- приложенное этой миграцией: прежний писатель его не производил.
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

UPDATE kaname.relation_fact
   SET condition_name = ''
 WHERE object_type = 'compute_instance'
   AND relation IN ('ssh', 'console')
   AND split_part(subject, ':', 1) = 'user'
   AND condition_name = 'mfa_fresh';
