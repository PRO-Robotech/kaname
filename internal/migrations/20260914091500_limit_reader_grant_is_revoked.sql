-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Выдача права читать пределы ОТЗЫВАЕТСЯ (kaname#59, стадия S4 kacho#2117).
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Право заведено РАДИ двух глаголов авторитета величин (`Resolve`,
-- `ListChangedSince`). Оба сняты стадией S4 вместе со всем модулем; выдача
-- осталась. Право, которое ничего не открывает, хуже отсутствующего: его
-- перечисляют в ведомостях выдач, его видит всякий, кто читает системную
-- поверхность, и следующий читатель заключит, что чтение пределов чем-то
-- сужено, — тогда как спрашивать его некому.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ЧТО ЭТА МИГРАЦИЯ СНИМАЕТ, А ЧТО НЕТ — ГРАНИЦА НАЗВАНА, А НЕ УМОЛЧАНА
--
-- Снимается ВЫДАЧА: строка таблицы выдач и всё, что из неё выведено. НЕ
-- снимается группа-получатель `module-quota-readers` — это решение прежней
-- миграции (`20260909202745`, §«ГРУППЫ НЕ СНИМАЮТСЯ»), и здесь оно не
-- отменяется: пустая группа не даёт никому ничего, а производителя, который
-- завёл бы её заново, нет — валидатор связности требует, чтобы заведённую
-- манифестом группу он же и одарил. Снятие сломало бы установку платформы.
--
-- Применённую миграцию `0001` эта не правит (запрет #5): всё, что ей нужно от
-- посева, она берёт операторами над его СТРОКАМИ.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ДВА СОСТОЯНИЯ УСТАНОВКИ ТРЕБУЮТ РАЗНОГО, И РАЗЛИЧАЕТ ИХ САМА ОЧЕРЕДЬ
--
-- У очереди нет столбца отправки: дренаж УДАЛЯЕТ строку, отправив её. Значит
-- наличие строки записи и есть признак того, что кортеж НЕ написан:
--
--   строка записи ЕЩЁ В ОЧЕРЕДИ   кортежа в движке прав нет и не было. Снимать
--   (свежая установка)            нечего — убирается сама строка записи.
--                                 Оставить её нельзя: она применится ПОСЛЕ
--                                 подъёма на модели без отношения, движок
--                                 отвергнет её, и дренаж отравит строку;
--
--   строки записи НЕТ             кортеж в движке лежит. Убрать его может
--   (живая установка)             только строка снятия — в очереди удалять
--                                 нечего.
--
-- Различение идёт ПОКОРТЕЖНО, а не одним условием на всю выдачу: частичный
-- дренаж законен, и общее условие оставило бы половину предмета необработанной.
--
-- ПОЧЕМУ ОБА ИСХОДА, А НЕ ОДИН — ЭТО ЗАМЕР, А НЕ ПРЕДОСТОРОЖНОСТЬ. Первая
-- редакция этой миграции эмитировала снятие ВСЕГДА и строки записи не трогала.
-- На живой установке это верно, на свежей — нет: проба показала в очереди ОБЕ
-- строки (запись из `0001` и снятие отсюда), и первая отравилась бы на модели
-- без отношения. Переезда отравленных строк обратно в работу у этой очереди
-- нет by construction — партиции разбираются по идентификатору ресурса,
-- которого у неё не бывает, — поэтому цена не задержка, а остановка партиции
-- до вмешательства оператора.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЯМОЙ ФАКТ: ГДЕ ЕСТЬ ПРОИЗВОДИТЕЛЬ — ЕГО, ГДЕ НЕТ — ПРЯМО
--
-- `kaname.relation_fact` — ПРОЕКЦИЯ очереди: её ведёт триггер
-- `relation_fact_follows_journal` (`0001`), снимая факт на всякой строке
-- `fga.tuple.delete`. Где строка снятия эмитируется, факт снимает он, и
-- дублировать его руками значило бы завести второе место об одном предмете.
--
-- НО ТАМ, ГДЕ УБИРАЕТСЯ САМА СТРОКА ЗАПИСИ, производителя не остаётся: факт
-- завела эта строка при накате, а разбудить триггер удалением нельзя — он
-- висит на ВСТАВКЕ. Поэтому остаток факта снимается прямо, последним
-- оператором; на живой установке он тронет НОЛЬ строк, и это верно — там факт
-- уже снят строкой снятия. Тем же доводом снимает факт прямо соседняя
-- миграция (`20260909202745`).
--
-- ────────────────────────────────────────────────────────────────────────────
-- СЛЕД ОБЯЗАТЕЛЕН, И ЕГО ДЕРЖИТ ГЕЙТ
--
-- Накатная половина ОТБИРАЕТ у арендатора доступ. Без записи в
-- `kaname.audit_outbox` «отобрано» неотличимо от «никогда не выдавалось».
-- Держит это `TestMigrationRemovingGrantsLeavesATrace` (храповик заведён
-- нулём), а тип события берётся ТОТ ЖЕ, что производит штатный отзыв
-- (`AuditEventTypeRevoked`), — свой тип был бы вторым словарём для одного
-- события.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ТРИ ИСХОДА, А НЕ ДВА
--
-- Установка, поднятая без этого посева, — законное состояние, а не отказ. Но
-- молчать о нём нельзя: «снимать нечего» и «сняли одну» снаружи одинаковы,
-- поэтому перепись печатается ВСЕГДА.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    -- Отношение названо ОДИН раз: два места об одном предмете здесь разошлись
    -- бы молча — отзыв снял бы одну выдачу, а след назвал бы другую.
    v_relation  CONSTANT text := 'quota_reader';
    v_account   text;
    v_spread    int;
    v_bindings  int;
    v_tuples    int;
    v_dropped   int;
    v_emitted   int;
    v_facts     int;
BEGIN
    -- 0. ЕСТЬ ЛИ ПРЕДМЕТ. Читается отдельным оператором, а не соединением
    --    внутри вставки следа: разбор дерева считает всякий оператор,
    --    называющий таблицу служебных записей, ПИСАТЕЛЕМ этих записей, и
    --    соединение ради чтения от записи не отличает.
    SELECT count(*), count(DISTINCT g.account_id), min(g.account_id)
      INTO v_bindings, v_spread, v_account
      FROM kaname.access_bindings b
      JOIN kaname.groups g ON g.id = b.subject_id AND b.subject_type = 'group'
     WHERE b.granted_relation = v_relation;

    IF v_bindings = 0 THEN
        RAISE NOTICE 'перепись отзыва: выдач права «%» не найдено — снимать нечего', v_relation;
        RETURN;
    END IF;

    IF v_spread <> 1 THEN
        -- Запись аудита УТВЕРЖДАЕТ, чьему арендатору принадлежала снятая
        -- выдача. Взять величину из невырожденного набора значило бы записать
        -- в аудит утверждение без производителя.
        RAISE EXCEPTION 'выдачи права «%» лежат в % аккаунтах, а не в одном — '
                        'называть арендатора записи аудита нечем', v_relation, v_spread;
    END IF;

    -- 1. СЛЕД — ДО удаления, пока строки выдач ещё читаются. После удаления
    --    составить запись было бы не из чего, а составленная «по памяти»
    --    назвала бы не то, что сняли.
    INSERT INTO kaname.audit_outbox (id, event_type, tenant_account_id, event_payload)
    SELECT 'evt_' || substr(md5('limit-reader-grant-revoked:' || b.id), 1, 24),
           'iam.access_binding.revoked',
           v_account,
           jsonb_build_object(
               'actor',            '',
               'binding_id',       b.id,
               'subject_type',     b.subject_type,
               'subject_id',       b.subject_id,
               'resource_type',    b.resource_type,
               'resource_id',      b.resource_id,
               'granted_relation', b.granted_relation,
               'reason',           'limit authority left the service: the two verbs this right '
                                   || 'was created for are gone (kaname#59, stage S4 of kacho#2117)')
      FROM kaname.access_bindings b
     WHERE b.granted_relation = v_relation
    ON CONFLICT (id) DO NOTHING;

    -- 2а. КОРТЕЖИ, ЧЬЯ ЗАПИСЬ УЖЕ ОТПРАВЛЕНА, — снимаются строкой снятия.
    --     Отправленную строку дренаж удалил, поэтому её отсутствие и есть
    --     признак того, что кортеж лежит в движке прав. Полезная нагрузка
    --     берётся из ведомости эмитированного: она хранит ТО, ЧТО БЫЛО
    --     отправлено, а литерал утверждал бы это и разошёлся бы с
    --     действительностью на всякой установке, где выдачу трогали.
    --
    --     Идёт ПЕРВЫМ: оператор ниже убирает строки записи, и после него
    --     признак «запись ещё в очереди» перестал бы существовать для всех.
    INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
    SELECT 'fga.tuple.delete',
           jsonb_build_object('user', t.fga_user, 'object', t.object, 'relation', t.relation),
           now()
      FROM kaname.access_binding_emitted_tuples t
      JOIN kaname.access_bindings b ON b.id = t.binding_id
     WHERE b.granted_relation = v_relation
       AND NOT EXISTS (
             SELECT 1 FROM kaname.fga_outbox o
              WHERE o.event_type = 'fga.tuple.write'
                AND o.payload ->> 'user'     = t.fga_user
                AND o.payload ->> 'object'   = t.object
                AND o.payload ->> 'relation' = t.relation);
    GET DIAGNOSTICS v_tuples = ROW_COUNT;

    -- 2б. КОРТЕЖИ, ЧЬЯ ЗАПИСЬ ЕЩЁ В ОЧЕРЕДИ, — писать было нечего, и снимать
    --     нечего: убирается сама строка записи.
    WITH dropped AS (
        DELETE FROM kaname.fga_outbox o
              WHERE o.event_type = 'fga.tuple.write'
                AND EXISTS (
                      SELECT 1
                        FROM kaname.access_binding_emitted_tuples t
                        JOIN kaname.access_bindings b ON b.id = t.binding_id
                       WHERE b.granted_relation = v_relation
                         AND o.payload ->> 'user'     = t.fga_user
                         AND o.payload ->> 'object'   = t.object
                         AND o.payload ->> 'relation' = t.relation)
          RETURNING 1)
    SELECT count(*) INTO v_dropped FROM dropped;

    -- 3. ВЫДАЧА: ведомость эмитированного и субъекты уходят каскадом ключа,
    --    поэтому перепись читается ДО удаления.
    SELECT count(*) INTO v_emitted
      FROM kaname.access_binding_emitted_tuples t
      JOIN kaname.access_bindings b ON b.id = t.binding_id
     WHERE b.granted_relation = v_relation;

    DELETE FROM kaname.access_bindings WHERE granted_relation = v_relation;
    GET DIAGNOSTICS v_bindings = ROW_COUNT;

    -- 4. ОСТАТОК ПРОЕКЦИИ — см. раздел шапки о прямом факте.
    WITH gone AS (
        DELETE FROM kaname.relation_fact WHERE relation = v_relation RETURNING 1)
    SELECT count(*) INTO v_facts FROM gone;

    RAISE NOTICE 'перепись отзыва: выдач снято % · строк снятия эмитировано % · строк записи убрано % · '
                 'строк ведомости эмитированного % · остатков проекции снято % · арендатор %',
        v_bindings, v_tuples, v_dropped, v_emitted, v_facts, v_account;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    -- Откат восстанавливает СИСТЕМНУЮ выдачу посева дословно — включая её
    -- идентификатор: он стоит в ведомости эмитированного и в записи аудита, и
    -- выданный заново отвязал бы откат от того, что снимала накатная половина.
    v_binding  CONSTANT text := 'acb1296746dc06ec9e25';
    v_group    CONSTANT text := 'grp1ed8897b56bb9106f';
    v_relation CONSTANT text := 'quota_reader';
    v_cluster  text;
BEGIN
    -- Якорь кластера читается, а не выписывается: его написание меняла
    -- отдельная миграция, и литерал здесь разошёлся бы с деревом молча.
    SELECT b.resource_id INTO v_cluster
      FROM kaname.access_bindings b
     WHERE b.resource_type = 'cluster' AND b.is_system
     LIMIT 1;

    IF v_cluster IS NULL THEN
        RAISE NOTICE 'откат: якоря кластера нет — восстанавливать выдачу не на чем';
        RETURN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM kaname.groups WHERE id = v_group) THEN
        RAISE NOTICE 'откат: группы-получателя % нет — восстанавливать выдачу некому', v_group;
        RETURN;
    END IF;

    INSERT INTO kaname.access_bindings
        (id, subject_type, subject_id, role_id, resource_type, resource_id, created_at,
         status, expires_at, granted_by_user_id, revoked_at, revoked_by_user_id, scope,
         deletion_protection, labels, target, target_digest, granted_relation, is_system)
    VALUES (v_binding, 'group', v_group, NULL, 'cluster', v_cluster, now(),
            'ACTIVE', NULL, '', NULL, NULL, 1, true, '{}', '{"allInScope": true}', 'all',
            v_relation, true)
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO kaname.access_binding_subjects
        (binding_id, subject_type, subject_id, ordinal, resource_type, resource_id)
    VALUES (v_binding, 'group', v_group, 0, 'cluster', v_cluster)
    ON CONFLICT DO NOTHING;

    INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
    VALUES (v_binding, 'group:' || v_group || '#member', v_relation, 'cluster:' || v_cluster, 'binding')
    ON CONFLICT DO NOTHING;

    -- Кортеж возвращается тем же путём, каким снимался, — строкой очереди.
    -- Прямой факт вернёт триггер проекции: у него один производитель, и
    -- обходить его на откате значило бы завести второй.
    INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
    VALUES ('fga.tuple.write',
            jsonb_build_object('user', 'group:' || v_group || '#member',
                               'object', 'cluster:' || v_cluster,
                               'relation', v_relation),
            now());

    RAISE NOTICE 'откат: выдача % восстановлена на якоре cluster:%', v_binding, v_cluster;
END
$$;
-- +goose StatementEnd
