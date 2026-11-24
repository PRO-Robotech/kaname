-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1031: точное доказательство ранее допущенного named pointer.
-- Старые факты и текущий каталог не доказывают прежнее владение: backfill нет.
-- История без FK к каталогу/зеркалу сохраняется для повторного cleanup.
-- Приёмка: docs/engineering/acceptance/account-scoped-registration-writer.md
-- §1/§2.1/§2.2(5): сохранённая регистрация для законного снятия после изменения policy,
-- повтор и порядок source_version без восстановления снятого владения.
-- +goose Up
CREATE TABLE kaname.resource_registration_pointer (
 module text NOT NULL CHECK (module <> ''),
 object_type text NOT NULL CHECK (object_type <> '' AND position(':' in object_type)=0),
 object_id text NOT NULL CHECK (object_id <> '' AND position(':' in object_id)=0),
 relation text NOT NULL CHECK (relation ~ '^[a-z][a-z0-9_]*$' AND relation NOT IN ('project','parent','owner')),
 subject text NOT NULL CHECK (subject ~ '^[^:#[:space:]]+:[^:#*[:space:]]+$'),
 source_version timestamptz NOT NULL,
 active boolean NOT NULL DEFAULT true,
 versionless boolean NOT NULL DEFAULT false,
 PRIMARY KEY(module,object_type,object_id,relation,subject)
);
CREATE INDEX resource_registration_pointer_by_tuple ON kaname.resource_registration_pointer(object_type,object_id,relation,subject);
COMMENT ON TABLE kaname.resource_registration_pointer IS 'Именованные указатели, допущенные писателем регистрации в одной TX с фактом; история владения, не текущая policy.';
-- Отдельная квитанция принятого combined снятия legacy contribution.
-- Up ничего не присваивает стоящим фактам; named CHECK остаётся прежним.
CREATE TABLE kaname.resource_registration_retirement (
 object_type text NOT NULL CHECK (object_type <> '' AND position(':' in object_type)=0),
 object_id text NOT NULL CHECK (object_id <> '' AND position(':' in object_id)=0),
 relation text NOT NULL CHECK (relation IN ('project','parent','owner')),
 subject text NOT NULL CHECK (subject <> ''),
 delete_through timestamptz NOT NULL CHECK (isfinite(delete_through)),
 PRIMARY KEY(object_type,object_id,relation,subject)
);
-- Оба порядка снятия: выдача видит действующую named-регистрацию, а
-- регистрация видит действующую выдачу. Вопрос после замка факта — отдельный
-- оператор на свежем READ COMMITTED, а не preflight или общий CTE.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.relation_fact_fold_row(
    p_event_type text, p_payload jsonb, p_created_at timestamptz) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_delete_through timestamptz;
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
            -- Новый typed mixed-set также проверяет держателей legacy строки;
            -- флаг кладёт только внутренний combined-delete, не запрос клиента.
            IF v_owner IS NULL OR p_payload->'protect_holders' = 'true'::jsonb OR EXISTS (
                   SELECT 1 FROM kaname.resource_registration_pointer rp
                    WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation AND rp.subject=v_stored) THEN
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
                   OR EXISTS (SELECT 1 FROM kaname.resource_registration_pointer rp
                               WHERE rp.object_type=v_type AND rp.object_id=v_id AND rp.relation=v_relation
                                 AND rp.subject=v_stored AND rp.active)
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
            v_delete_through := NULL;
            IF v_owner IS NULL AND v_relation IN ('project','parent','owner') THEN
                -- Отдельный свежий RC statement ПОСЛЕ fact lock и held read.
                -- Без обратного замка receipt: registrar меняет её ДО факта.
                SELECT delete_through INTO v_delete_through
                  FROM kaname.resource_registration_retirement
                 WHERE object_type=v_type AND object_id=v_id
                   AND relation=v_relation AND subject=v_stored;
            END IF;
            -- У exact named tuple последний держатель может уйти меткой AB,
            -- отличной от шкалы владельца. После fresh held-check снимаем его
            -- без произвольного повышения надгробия; stale owner не проходит
            -- сохранённую версию claim. Для legacy tuple сравнение прежнее.
            DELETE FROM kaname.relation_fact
             WHERE object_type = v_type AND object_id = v_id
               AND relation = v_relation AND subject = v_stored
               AND (source_version <= v_version
                    OR (v_owner IS NULL AND v_delete_through IS NOT NULL AND source_version <= v_delete_through) OR EXISTS (
                    SELECT 1 FROM kaname.resource_registration_pointer rp
                     WHERE rp.object_type=v_type AND rp.object_id=v_id
                       AND rp.relation=v_relation AND rp.subject=v_stored
                       AND NOT rp.active
                       AND (v_owner IS NULL OR rp.source_version <= v_version)));
        END IF;
    END LOOP;
    RETURN;
END $$;
-- +goose StatementEnd
-- +goose Down
-- Замок ждёт всех writers и исключает новые claims до конца всей миграции.
-- Проверка ниже отдельная и потому видит исход writer после ожидания.
LOCK TABLE kaname.resource_registration_pointer, kaname.resource_registration_retirement IN ACCESS EXCLUSIVE MODE;
-- Потеря даже неактивной истории без явного reconciliation недопустима.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM kaname.resource_registration_pointer) OR EXISTS (SELECT 1 FROM kaname.resource_registration_retirement) THEN
  RAISE EXCEPTION 'named registration provenance requires explicit quiescence and reconciliation before downgrade';
 END IF;
END $$;
-- +goose StatementEnd
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
DROP TABLE kaname.resource_registration_retirement;
DROP TABLE kaname.resource_registration_pointer;
