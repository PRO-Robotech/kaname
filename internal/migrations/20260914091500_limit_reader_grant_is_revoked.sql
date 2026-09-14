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
-- снимаются три вещи, и у каждой свой держатель:
--
--   объявление отношения в модели   снять нельзя, пока каталог прав его
--                                   ТРЕБУЕТ: каталог порождается у КРАЯ
--                                   платформы и обязан совпадать со своей
--                                   копией побайтово. Порядок обратный —
--                                   сперва край, потом модель (kaname#59);
--   группа-получатель               решение прежней миграции
--   `module-quota-readers`          (`20260909202745`, §«ГРУППЫ НЕ СНИМАЮТСЯ»)
--                                   и оно не отменяется здесь: пустая группа
--                                   не даёт никому ничего, а производителя,
--                                   который завёл бы её заново, нет — снятие
--                                   сломало бы установку платформы;
--   строки очереди из `0001`        применённую не правят (запрет #5), а
--                                   удалять её строку отдельно нельзя: см.
--                                   следующий раздел.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СОБЫТИЕ СНЯТИЯ, А НЕ УДАЛЕНИЕ СТРОКИ ОЧЕРЕДИ — ОБА СОСТОЯНИЯ РАЗОБРАНЫ
--
-- У очереди нет столбца отправки: дренаж УДАЛЯЕТ строку, отправив её. Значит
-- два состояния установки различимы и требуют разного:
--
--   установка ЖИВАЯ     строка выдачи `0001` давно отправлена и удалена, а
--                       кортеж лежит в движке прав. Убрать его может только
--                       событие снятия — удалять в очереди нечего;
--   установка СВЕЖАЯ    строка `0001` ещё в очереди. Накат идёт ДО пуска
--                       службы, поэтому к дренажу приедут обе строки по
--                       порядку: запись, затем снятие. Итог тот же — кортежа
--                       нет.
--
-- Удалить строку `0001` вместо события было бы верно только для второго
-- состояния и оставило бы первое с живым кортежем НАВСЕГДА. Обратное — снять
-- строку и эмитировать снятие — дало бы снятие кортежа, которого не писали.
-- Событие покрывает оба, и это единственная форма, которая покрывает оба.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЯМОЙ ФАКТ ЗДЕСЬ НЕ ТРОГАЕТСЯ, И ЭТО НЕ ЗАБЫВЧИВОСТЬ
--
-- `kaname.relation_fact` — ПРОЕКЦИЯ очереди: её ведёт триггер
-- `relation_fact_follows_journal` (`0001`), снимая факт на всякой строке
-- `fga.tuple.delete`. Снять факт ещё и руками значило бы завести второе место
-- об одном предмете; разойтись они могут молча, и разойдётся то, которое не
-- исполняется штатным отзывом. Соседняя миграция (`20260909202745`) снимает
-- факт прямо — и правильно: она УДАЛЯЕТ строки очереди, то есть производителя
-- проекции, и опереться ей не на что.
--
-- ────────────────────────────────────────────────────────────────────────────
-- СЛЕД ОБЯЗАТЕЛЕН, И ЕГО ДЕРЖИТ ГЕЙТ
--
-- Накатная половина ОТБИРАЕТ у арендатора доступ. Без записи в
-- `kaname.audit_outbox` «отобрано» неотличимо от «никогда не выдавалось»:
-- спросивший позже увидит отсутствие выдачи и не узнает, что она была. Держит
-- это `TestMigrationRemovingGrantsLeavesATrace` (храповик заведён нулём), а
-- тип события берётся ТОТ ЖЕ, что производит штатный отзыв
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
    v_emitted   int;
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

    -- 2. СНЯТИЕ КОРТЕЖЕЙ — из ведомости эмитированного, а не из литерала.
    --    Ведомость хранит ТО, ЧТО БЫЛО отправлено; литерал утверждал бы, что
    --    именно, — и разошёлся бы с действительностью на всякой установке, где
    --    выдачу трогали. Прямой факт снимет триггер проекции.
    INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
    SELECT 'fga.tuple.delete',
           jsonb_build_object('user', t.fga_user, 'object', t.object, 'relation', t.relation),
           now()
      FROM kaname.access_binding_emitted_tuples t
      JOIN kaname.access_bindings b ON b.id = t.binding_id
     WHERE b.granted_relation = v_relation;
    GET DIAGNOSTICS v_tuples = ROW_COUNT;

    -- 3. ВЫДАЧА последней: ведомость эмитированного и субъекты уходят
    --    каскадом ключа, и читать их после удаления было бы нечего.
    SELECT count(*) INTO v_emitted
      FROM kaname.access_binding_emitted_tuples t
      JOIN kaname.access_bindings b ON b.id = t.binding_id
     WHERE b.granted_relation = v_relation;

    DELETE FROM kaname.access_bindings WHERE granted_relation = v_relation;
    GET DIAGNOSTICS v_bindings = ROW_COUNT;

    RAISE NOTICE 'перепись отзыва: выдач снято % · кортежей к снятию % · строк ведомости эмитированного % · арендатор %',
        v_bindings, v_tuples, v_emitted, v_account;
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
    -- Прямой факт вернёт триггер проекции: у него один производитель в обе
    -- стороны, и обходить его на откате значило бы завести второй.
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
