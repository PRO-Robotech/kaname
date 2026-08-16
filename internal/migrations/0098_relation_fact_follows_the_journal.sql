-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 0098_relation_fact_follows_the_journal — прямой факт складывается из ТОГО ЖЕ
-- журнала, из которого складывается состояние движка отношений.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Состояние чужого хранилища отношений есть свёртка одного журнала —
-- `kacho_iam.fga_outbox`: каждый кортеж туда попадает строкой намерения, и
-- порядок применения задан порядком строк. Прямой факт (`relation_fact`) —
-- то же самое, прочитанное своей БД.
--
-- Наполнял его ОДИН производитель из многих: путь чистой выдачи в
-- `RegisterResource`. Владение, поставленное при создании ресурса, указатель на
-- предка, уровневое отношение легаси-выдачи, право служебной учётки модуля,
-- посевы миграций — всё это попадало в журнал и не попадало в факт. Форма E,
-- отвечающая по своим таблицам, на таких вопросах отвечала «нет», тогда как
-- движок отвечал «да».
--
-- Отвечала МОЛЧА: пустая проекция ничем не отличается от честного отказа, и
-- расхождение разбирают в правах, а не в наполнении.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СХЕМОЙ, А НЕ ЕЩЁ ОДНИМ ПИСАТЕЛЕМ В КОДЕ
--
-- Производителей кортежа много и они разной природы: use-case, реконсайлер,
-- посев старта, сырой SQL миграции. Писатель, добавленный в код, не покрывает
-- SQL вовсе, а перечень «кто ещё обязан писать факт» — это список, который
-- расходится с деревом при первой же новой миграции, причём молча.
--
-- Здесь наполнение привязано к ЕДИНСТВЕННОМУ месту, через которое проходят все
-- четверо, — к строке журнала. Появится пятый производитель — он попадёт в
-- проекцию by construction, не зная о ней.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО В ПРОЕКЦИЮ НЕ ИДЁТ, И ЭТО НЕ УПУЩЕНИЕ
--
-- Отношение-ГЛАГОЛ (`v_*`) не переносится. Глагол форма E ВЫВОДИТ из выдачи
-- (роль → тип × глагол → область), и в этом её предмет: она обязана вычислить
-- вердикт своими таблицами, а не хранить копию чужих кортежей. Скопировать
-- глагол фактом значило бы сделать теневое сравнение тождеством — самая тихая
-- из масок, потому что выглядит она как согласие форм.
--
-- Отсюда единственный дискриминатор — приставка глагола, и он же объясняет,
-- почему проекция не «зеркало журнала»: она берёт ровно то, что не выводимо.

-- +goose Up

-- ── 1. Функция проекции ──────────────────────────────────────────────────────
--
-- Читает полезную нагрузку строки журнала (`user`/`relation`/`object` — форма
-- одна у всех производителей) и приводит проекцию в соответствие.
--
-- Версия берётся у самой строки журнала. Это не «время записи ради времени»:
-- порядок строк журнала И ЕСТЬ порядок применения кортежей (клейм дренажа идёт
-- поголовно по партиции ключа), поэтому свёртка журнала в факт даёт то же
-- состояние, что свёртка журнала в хранилище движка. Версия из источника
-- расходилась бы с этим порядком ровно там, где расхождение не видно.
--
-- Объект без формы `<тип>:<идентификатор>` либо с точечным типом ОТВЕРГАЕТСЯ, а
-- не пропускается: пропущенная строка означала бы доступ, о котором своя БД не
-- знает, при том что чужая его получила. Тот же инвариант уже стоит на цепи
-- предков (миграция 0091), и производитель, нарушающий его, ломается там же.
-- +goose StatementBegin
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

    -- Глагол выводится из выдачи и копией не хранится (см. шапку).
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

COMMENT ON FUNCTION kacho_iam.relation_fact_from_journal() IS
  'Проекция журнала намерений в прямой факт. Отношение-глагол (v_*) НЕ переносится: его форма E выводит из выдачи, и копия сделала бы теневое сравнение тождеством.';

-- ── 2. Провязка ──────────────────────────────────────────────────────────────
--
-- AFTER INSERT: строка журнала уже видна, и откат вызывающей транзакции снимает
-- оба следа сразу — иначе своя БД разошлась бы с чужой молча.
CREATE TRIGGER relation_fact_follows_journal
    AFTER INSERT ON kacho_iam.fga_outbox
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.relation_fact_from_journal();

-- ── 3. Свёртка уже накопленного журнала ──────────────────────────────────────
--
-- Провязка действует ВПЕРЁД, а права, выданные до неё, продолжают жить в
-- движке. Складываем накопленное: по каждому ключу кортежа берётся ПОСЛЕДНЕЕ
-- событие (идентификатор строки монотонен и задаёт порядок применения), и факт
-- ставится только там, где последним было «записать».
--
-- Строки, которые спроецировать нельзя (нет полей, чужая форма объекта,
-- точечный тип), здесь ОТБРАСЫВАЮТСЯ, а не роняют миграцию: журнал — история, в
-- ней могут лежать строки, оставленные снятыми подсистемами, и ронять на них
-- обновление схемы значило бы запретить его из-за прошлого. Инвариант держит
-- триггер — он смотрит вперёд, где производитель ещё можно поправить.
INSERT INTO kacho_iam.relation_fact
       (object_type, object_id, relation, subject, source_version, created_at)
SELECT substr(last_event.object, 1, position(':' in last_event.object) - 1),
       substr(last_event.object, position(':' in last_event.object) + 1),
       last_event.relation,
       last_event.subject,
       last_event.created_at,
       now()
  FROM (
        SELECT DISTINCT ON (o.payload ->> 'user', o.payload ->> 'relation', o.payload ->> 'object')
               o.payload ->> 'user'     AS subject,
               o.payload ->> 'relation' AS relation,
               o.payload ->> 'object'   AS object,
               o.event_type             AS event_type,
               o.created_at             AS created_at
          FROM kacho_iam.fga_outbox o
         WHERE o.payload ? 'user' AND o.payload ? 'relation' AND o.payload ? 'object'
           AND (o.payload ->> 'relation') NOT LIKE 'v\_%'
           AND position(':' in (o.payload ->> 'object')) > 1
           AND position(':' in (o.payload ->> 'object')) < length(o.payload ->> 'object')
           AND substr(o.payload ->> 'object', 1,
                      position(':' in (o.payload ->> 'object')) - 1) NOT LIKE '%.%'
         ORDER BY o.payload ->> 'user', o.payload ->> 'relation', o.payload ->> 'object', o.id DESC
       ) AS last_event
 WHERE last_event.event_type = 'fga.tuple.write'
    ON CONFLICT (object_type, object_id, relation, subject) DO NOTHING;

-- ── 4. Самопроверка свёртки ──────────────────────────────────────────────────
--
-- Журнал, в котором есть непроецируемые кортежи, — находка, а не норма: значит
-- какой-то производитель кладёт форму, которой проекция не понимает. Миграция
-- НЕ падает (см. довод в п.3), но НАЗЫВАЕТ число: молчаливый пропуск неотличим
-- от «нечего было проецировать».
-- +goose StatementBegin
DO $$
DECLARE unprojectable bigint;
BEGIN
  SELECT count(*) INTO unprojectable
    FROM kacho_iam.fga_outbox o
   WHERE NOT (o.payload ? 'user' AND o.payload ? 'relation' AND o.payload ? 'object')
      OR position(':' in COALESCE(o.payload ->> 'object', '')) <= 1
      OR substr(COALESCE(o.payload ->> 'object', ''), 1,
                position(':' in COALESCE(o.payload ->> 'object', '')) - 1) LIKE '%.%';
  IF unprojectable > 0 THEN
    RAISE WARNING
      'fga_outbox: строк, не поддающихся проекции в прямой факт: %. Права по ним у движка есть, у формы E нет.',
      unprojectable;
  END IF;
END $$;
-- +goose StatementEnd

-- +goose Down

DROP TRIGGER IF EXISTS relation_fact_follows_journal ON kacho_iam.fga_outbox;
DROP FUNCTION IF EXISTS kacho_iam.relation_fact_from_journal();
