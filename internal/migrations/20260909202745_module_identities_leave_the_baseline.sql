-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- module_identities_leave_the_baseline — служебные учётки МОДУЛЕЙ ПЛАТФОРМЫ
-- уходят из цепочки миграций службы доступа.
--
-- Задача продукта #2452, линия `release:standalone-iam`.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ: данные окружения в применённой миграции
--
-- Миграция применяется ВЕЗДЕ, включая установку, где платформы нет вовсе. Свод
-- `0001_initial.sql` заводит служебные учётки пяти модулей платформы, их
-- членства, выдачи и прямые факты отношений — то есть арендатор, развернувший
-- ТОЛЬКО службу доступа, получает пять служебных ЛИЧНОСТЕЙ продукта, которого
-- он не ставил, с выданными правами и без способа узнать, откуда они взялись.
--
-- Различает вопрос из самой нормы (`data-integrity.md` §«Данные СТЕНДА
-- заводятся посевом, а не миграцией»): обязана ли эта строка существовать у
-- арендатора, который развернул продукт у себя? Для личности чужого модуля
-- ответ — нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- КУДА ОНИ ПЕРЕЕЗЖАЮТ, И ПОЧЕМУ ЭТО НЕ ПОТЕРЯ
--
-- В посев, который уже ОБЪЯВЛЕН и до этой задачи не имел применителя: раздел
-- `seed` манифеста модуля (`services/<модуль>/manifest.yaml`). Манифесты
-- доставляет ОПЕРАТОР установки — каталогом доставки (`manifests.dir`), который
-- кладёт зонтичный чарт платформы и не кладёт чарт самостоятельной службы.
-- Значит доставка манифеста модуля И ЕСТЬ признак присутствия платформы, а
-- условность посева выражена тем, что установка объявила, а не догадкой кода.
--
-- Применитель заведён этой же задачей — `internal/apps/kaname/moduleseed`,
-- позван из композиционного корня после применителя ролей. До него объявленное
-- манифестом состояние доезжало до базы только пересборкой образа службы.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПЕРЕЧЕНЬ ЗАКРЫТ И НАЗВАН ПОИМЁННО — ДВЕ УЧЁТКИ ОСТАЮТСЯ, И ЭТО РЕШЕНИЕ
--
-- Снимаются ПЯТЬ: `kacho-vpc`, `kacho-compute`, `kacho-nlb`, `kacho-registry`,
-- `kacho-storage`. У каждой есть модуль-владелец, каждая объявлена разделом
-- `seed` своего манифеста, и после снятия её заведёт применитель.
--
-- ОСТАЮТСЯ две, и у каждой свой довод:
--
--   `kacho-bootstrap-admin` — личность САМОЙ службы: под ней чеканится
--      неинтерактивный токен в production-посадке. Её читает прод-код службы
--      (`internal/repo/kaname/pg/bootstrap_token_repo.go`), то есть у неё есть
--      читатель, и снятие сломало бы продукт молча.
--
--   `kacho-api-gateway` — край платформы, а край МОДУЛЕМ не является:
--      манифеста у него нет ни одного, объявить его посев некому, и снятие
--      оставило бы платформу без производителя. Это ОСТАТОК, названный вслух,
--      а не недосмотр: он снимается вместе со своим производителем, а не раньше.
--
-- Именно поэтому перечень ниже ВЫПИСАН, а не выведен предикатом `LIKE
-- 'kacho-%'`: выведенный задел бы обе оставшиеся строки, и снятие каждой из них
-- стоит разного.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ГРУППЫ НЕ СНИМАЮТСЯ, И ЭТО ТОЖЕ РЕШЕНИЕ
--
-- `module-quota-readers` и `module-relation-writers` остаются пустыми. Довода
-- два, и каждый самостоятельно достаточен. Первый: группа — не учётка;
-- предъявить её нельзя, войти под ней нельзя, и пустая группа не даёт никому
-- ничего. Второй: объявить её посевом СЕГОДНЯ нельзя — валидатор связности
-- требует, чтобы заведённая манифестом группа была им же и одарена
-- (`ErrGroupNeverGranted`), а выдача этих групп принадлежит службе, не модулю.
-- Снять то, у чего нет производителя, значит сломать установку платформы.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- СНЯТИЕ ВЫДАЧИ ОСТАВЛЯЕТ СЛЕД, И ЭТО НЕ ФОРМАЛЬНОСТЬ
--
-- Две выдачи (`system_viewer` на якоре кластера у vpc и compute) снимаются
-- накатной половиной, то есть у субъекта ОТБИРАЕТСЯ доступ. Без записи в
-- `kaname.audit_outbox` «отобрано» неотличимо от «никогда не выдавалось»: тот,
-- кто позже спросит, почему модуль не читает внутреннюю поверхность соседа,
-- увидит отсутствие выдачи и не узнает, что она была.
--
-- Тип события берётся ТОТ ЖЕ, что производит штатный отзыв
-- (`iam.access_binding.revoked`, `internal/repo/kaname/access_binding/iface.go`):
-- второй словарь для того же предмета разошёлся бы с первым молча, и витрина
-- аудита показывала бы два разных имени одного события.
--
-- Идентификатор события ВЫВОДИТСЯ из идентификатора выдачи, а не чеканится
-- случайным: повторный накат на ту же базу не заводит второй записи о том же
-- снятии. Держит это `ON CONFLICT (id) DO NOTHING`, а не надежда на то, что
-- миграция применится однажды.
--
-- Действующее лицо — ПЛАТФОРМА, и поле сказано пустым, а не подставленной
-- учёткой: приписать снятие якорному пользователю значило бы записать в аудит
-- действие, которого он не совершал.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОРЯДОК СНЯТИЯ НЕСУЩИЙ
--
-- Строку служебной записи стережёт `service_accounts_subject_ref_before_delete_trg`:
-- запись, названная субъектом выдачи, не удаляется. Поэтому выдачи снимаются
-- ПЕРВЫМИ (дочерние строки уходят каскадом FK), и только потом личность.
--
-- Носитель потолка (`project_resource_quotas`) здесь НЕ упоминается: его ведёт
-- триггер `service_accounts_quota_carrier_credential` на вставке и удалении
-- записи. Снимать его вручную значило бы завести второе место об одном
-- предмете.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ОБРАТНЫЙ ХОД ВОССТАНАВЛИВАЕТ, И ЧЕГО ОН НЕ ОБЕЩАЕТ
--
-- `Down` возвращает ровно те строки, которыми их сеет свод: те же
-- идентификаторы (они выводятся из имени, а не случайны), те же назначения, те
-- же членства, те же выдачи. Прямой факт отношения он не пишет напрямую — его
-- складывает триггер `relation_fact_follows_journal` из строки журнала, ровно
-- как на прямом ходу продукта.
--
-- Чего `Down` не обещает: он не восстановит строки, которые появились ПОСЛЕ
-- прямого хода — их заводит применитель, и его состояние принадлежит доставке
-- манифестов, а не этой миграции. Обратный ход снимает то, что завёл сам, и это
-- сказано, чтобы «откатились» не читалось как «вернулись в прежнее состояние».

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    -- Пять личностей модулей платформы. Перечень выписан осознанно — см. шапку.
    module_names CONSTANT text[] := ARRAY[
        'kacho-vpc',
        'kacho-compute',
        'kacho-nlb',
        'kacho-registry',
        'kacho-storage'
    ];
    module_ids    text[];
    module_subjects text[];
    system_account text;
    account_spread int;
    n_bindings    int;
    n_members     int;
    n_facts       int;
    n_journal     int;
    n_accounts    int;
BEGIN
    -- ЧТЕНИЕ отдельным оператором, а не соединением внутри вставки аудита.
    -- Довод не стилистический: разбор дерева считает всякий INSERT/UPDATE/DELETE,
    -- называющий таблицу служебных записей, ПИСАТЕЛЕМ этих записей — соединение
    -- ради чтения он от записи не отличает. Форма, которой он не знает, не даёт
    -- ни красного, ни зелёного: она молчит. Читать здесь и подставлять величину
    -- ниже дешевле, чем учить чужой разбор новой форме.
    SELECT array_agg(id), array_agg('service_account:' || id),
           count(DISTINCT account_id), min(account_id)
      INTO module_ids, module_subjects, account_spread, system_account
      FROM kaname.service_accounts
     WHERE name = ANY(module_names);

    IF module_ids IS NOT NULL AND account_spread <> 1 THEN
        -- Запись аудита УТВЕРЖДАЕТ, чьему арендатору принадлежит снятая выдача.
        -- Взять эту величину из набора, не убедившись, что он вырожден, значило
        -- бы записать в аудит утверждение без производителя.
        RAISE EXCEPTION 'служебные записи модулей лежат в % аккаунтах, а не в одном — '
                        'называть арендатора записи аудита нечем', account_spread;
    END IF;

    IF module_ids IS NULL THEN
        -- Законное состояние: установка, поднятая уже без посева модулей.
        -- Молчать нельзя — «снимать нечего» и «сняли пять» снаружи одинаковы.
        RAISE NOTICE 'служебных записей модулей платформы не найдено — снимать нечего';
        RETURN;
    END IF;

    -- 1. СЛЕД — до удаления, пока строки выдач ещё можно прочитать. После
    --    удаления составить запись было бы не из чего, а составленная «по
    --    памяти» назвала бы не то, что сняли.
    INSERT INTO kaname.audit_outbox (id, event_type, tenant_account_id, event_payload)
    SELECT 'evt_' || substr(md5('module-identity-withdrawal:' || b.id), 1, 24),
           'iam.access_binding.revoked',
           system_account,
           jsonb_build_object(
               'actor',         '',
               'binding_id',    b.id,
               'subject_type',  b.subject_type,
               'subject_id',    b.subject_id,
               'resource_type', b.resource_type,
               'resource_id',   b.resource_id,
               'granted_relation', b.granted_relation,
               'reason',        'module identity leaves the applied schema: platform module '
                                || 'seed moves from the migration to the delivered manifest (kacho#2452)')
      FROM kaname.access_bindings b
     WHERE b.subject_type = 'service_account'
       AND b.subject_id = ANY(module_ids)
    ON CONFLICT (id) DO NOTHING;

    -- 2. Выдачи: дочерние субъекты и эмитированные кортежи уходят каскадом FK,
    --    и только после этого личность перестаёт быть субъектом.
    WITH gone AS (
        DELETE FROM kaname.access_bindings
              WHERE subject_type = 'service_account'
                AND subject_id = ANY(module_ids)
          RETURNING 1)
    SELECT count(*) INTO n_bindings FROM gone;

    WITH gone AS (
        DELETE FROM kaname.group_members
              WHERE member_type = 'service_account'
                AND member_id = ANY(module_ids)
          RETURNING 1)
    SELECT count(*) INTO n_members FROM gone;

    -- 3. Прямой факт отношения снимается прямо, а не строкой журнала со
    --    событием снятия: журнальные строки этих личностей уходят следом, и
    --    оставить факт зависящим от строки, которую мы же и удаляем, значило бы
    --    получить состояние, где снятие держится порядком двух удалений.
    WITH gone AS (
        DELETE FROM kaname.relation_fact
              WHERE subject = ANY(module_subjects)
          RETURNING 1)
    SELECT count(*) INTO n_facts FROM gone;

    WITH gone AS (
        DELETE FROM kaname.fga_outbox
              WHERE payload ->> 'user' = ANY(module_subjects)
          RETURNING 1)
    SELECT count(*) INTO n_journal FROM gone;

    -- 4. Личность последней. Носитель потолка уходит триггером.
    --
    -- Имена стоят ЛИТЕРАЛАМИ, а не переменной, и это не дублирование перечня
    -- выше. Разбор дерева ведёт модель «какие личности модулей цепочка оставляет
    -- живыми», и снятие он читает по именам В САМОМ ОПЕРАТОРЕ: за переменную он
    -- заглянуть не может, поэтому снятие через `ANY(module_names)` осталось бы
    -- ему невидимым — модель продолжала бы считать эти пять живыми, и её
    -- молчание было бы неотличимо от согласия.
    DELETE FROM kaname.service_accounts
          WHERE name IN ('kacho-vpc', 'kacho-compute', 'kacho-nlb',
                         'kacho-registry', 'kacho-storage');
    GET DIAGNOSTICS n_accounts = ROW_COUNT;

    RAISE NOTICE 'перепись снятия: личностей % · выдач % · членств % · прямых фактов % · строк журнала %',
        n_accounts, n_bindings, n_members, n_facts, n_journal;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    -- Пара «имя личности → назначение», дословно как в своде.
    seeded CONSTANT text[][] := ARRAY[
        ARRAY['kacho-vpc',      'Module SA: kacho-vpc (SEC-C least-priv)'],
        ARRAY['kacho-compute',  'Module SA: kacho-compute (SEC-C least-priv)'],
        ARRAY['kacho-nlb',      'Module SA: kacho-nlb (SEC-C least-priv)'],
        ARRAY['kacho-registry', 'Module SA: kacho-registry (SEC-C least-priv)'],
        ARRAY['kacho-storage',  'Module SA: kacho-storage (SEC-C least-priv)']
    ];
    -- Личности, получавшие чтение внутренней поверхности соседей.
    viewers CONSTANT text[] := ARRAY['kacho-vpc', 'kacho-compute'];
    system_account CONSTANT text := 'acc' || substr(md5('kacho-system'), 1, 17);
    anchor         text;
    i              int;
    sa_name        text;
    sa_id          text;
    grp_id         text;
BEGIN
    SELECT id INTO anchor FROM kaname.clusters ORDER BY created_at LIMIT 1;
    IF anchor IS NULL THEN
        RAISE EXCEPTION 'якоря кластера нет — восстанавливать выдачи не на чем';
    END IF;

    FOR i IN 1 .. array_length(seeded, 1) LOOP
        sa_name := seeded[i][1];
        sa_id   := 'sva' || substr(md5(sa_name), 1, 17);

        INSERT INTO kaname.service_accounts (id, account_id, name, description, created_at, enabled, labels)
        VALUES (sa_id, system_account, sa_name, seeded[i][2], now(), true, '{}')
        ON CONFLICT (id) DO NOTHING;

        -- Членства в обеих группах модулей.
        FOR grp_id IN
            SELECT g.id FROM kaname.groups g
             WHERE g.account_id = system_account
               AND g.name IN ('module-quota-readers', 'module-relation-writers')
        LOOP
            INSERT INTO kaname.group_members (group_id, member_type, member_id, added_at)
            VALUES (grp_id, 'service_account', sa_id, now())
            ON CONFLICT DO NOTHING;

            INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
            VALUES ('fga.tuple.write',
                    jsonb_build_object('user', 'service_account:' || sa_id,
                                       'object', 'group:' || grp_id,
                                       'relation', 'member'),
                    now());
        END LOOP;

        IF sa_name = ANY(viewers) THEN
            INSERT INTO kaname.access_bindings (
                id, subject_type, subject_id, role_id, granted_relation, is_system,
                resource_type, resource_id, status, deletion_protection,
                granted_by_user_id, scope, labels, target)
            VALUES (
                'acb' || substr(md5('system-grant:service_account:' || sa_id
                                    || ':system_viewer:cluster:' || anchor), 1, 17),
                'service_account', sa_id, NULL, 'system_viewer', true,
                'cluster', anchor, 'ACTIVE', true, '', 1, '{}', '{"allInScope": true}')
            ON CONFLICT (id) DO NOTHING;

            INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
            VALUES ('acb' || substr(md5('system-grant:service_account:' || sa_id
                                        || ':system_viewer:cluster:' || anchor), 1, 17),
                    'service_account', sa_id, 0)
            ON CONFLICT DO NOTHING;

            INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
            VALUES ('acb' || substr(md5('system-grant:service_account:' || sa_id
                                        || ':system_viewer:cluster:' || anchor), 1, 17),
                    'service_account:' || sa_id, 'system_viewer', 'cluster:' || anchor, 'binding')
            ON CONFLICT DO NOTHING;

            INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
            VALUES ('fga.tuple.write',
                    jsonb_build_object('user', 'service_account:' || sa_id,
                                       'object', 'cluster:' || anchor,
                                       'relation', 'system_viewer'),
                    now());
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd
