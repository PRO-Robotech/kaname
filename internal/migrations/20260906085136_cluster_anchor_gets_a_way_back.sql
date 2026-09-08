-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- cluster_anchor_gets_a_way_back — у якоря кластера появляются ОБЪЯВЛЕННЫЙ
-- путь возврата доступа и переписчик, знающий все места, где якорь записан.
--
-- ОБЪЯВЛЕНА процедура в `docs/architecture/cluster-admin-access-recovery.md` —
-- там она и только там: шапки ниже ссылаются и своей редакции не имеют.
--
-- Задача продукта #2087, поверхность F5 приёмки
-- `sub-phase-KAN-WIRE-1-four-surface-producers-acceptance.md`
-- (сценарии KAN-W5-04, KAN-W5-05, KAN-W5-07); предметы ПР-6 и ПР-7.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО СЕГОДНЯ НЕТ, И ПОЧЕМУ ЭТО ДОРОЖЕ ОСТАЛЬНОГО
--
-- Якорь кластера — объект, на котором висит право кластерного администратора.
-- Ошибка вокруг него отбирает доступ У ТОГО ЕДИНСТВЕННОГО, кто мог бы её
-- починить: служба к этому моменту отвечает отказом ему самому, и остаётся
-- только прямой доступ к базе.
--
-- Базовая миграция обратного шага не имеет BY CONSTRUCTION. Значит путь возврата
-- обязан существовать ОТДЕЛЬНЫМ объявленным действием, и объявлен он обязан быть
-- ЗАРАНЕЕ: сочинять его в момент отказа будет тот, у кого доступа уже нет.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ФУНКЦИИ БАЗЫ, А НЕ ПОДКОМАНДА СЛУЖБЫ
--
-- Предпосылка отказа — «доступ администратора не подтверждается». В этом
-- состоянии всякий путь, идущий ЧЕРЕЗ службу, отвечает отказом ему же: путь
-- возврата, требующий доступа, которого нет, путём возврата не является.
--
-- Прав функции НЕ ДОБАВЛЯЮТ: у того, кто может их позвать, уже есть право писать
-- в эту базу, то есть он и так способен сделать всё то же самое рукой. Они
-- добавляют ПРАВИЛЬНОСТЬ — три записи одной транзакцией и разрешение якоря по
-- факту, а не по памяти оператора.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ЯКОРЬ РАЗРЕШАЕТСЯ, А НЕ ПИШЕТСЯ ЛИТЕРАЛОМ
--
-- Путь возврата понадобится РОВНО ТОГДА, когда про якорь неизвестно, как он
-- сейчас называется, — во время перехода написания либо после его половины.
-- Литерал в этом месте означал бы «путь возврата работает, пока возвращать не
-- нужно». `kaname.cluster_anchor()` читает единственную строку `kaname.clusters`,
-- поэтому работает до перехода, после него и между.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ ПЕРЕПИСЧИК ОБХОДИТ КАТАЛОГ, А НЕ ПЕРЕЧЕНЬ ТАБЛИЦ
--
-- Перечень колонок, выписанный рукой, стареет молча: следующая миграция заводит
-- колонку, а перечень о ней не знает — и переход оставляет якорь наполовину
-- переписанным ИМЕННО В ТОМ месте, о котором никто не подумал. Обход каталога
-- (`information_schema`) полон ПО ПОСТРОЕНИЮ и в отчёте называет каждое
-- тронутое место.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧАСТИЧНОГО СОСТОЯНИЯ У ПЕРЕПИСИ НЕ БЫВАЕТ, И ЭТО ДОКАЗЫВАЕТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ
--
-- Приёмка требует, чтобы прерывание переписи было ОТЛИЧИМО от её завершения.
-- Родительский разбор исходил из того, что кортежи живут в чужом хранилище, куда
-- транзакция не достаёт, — и там частичное состояние было бы ожидаемым исходом
-- прерывания. ЭТА ПОСЫЛКА БОЛЬШЕ НЕ ВЕРНА: внешний движок прав снят (стадия S6
-- эпика #747), решение о доступе вычисляет реляционная форма в СВОЕЙ базе, и
-- проекция отношений — `kaname.relation_fact` — лежит в той же транзакции, что и
-- остальное.
--
-- Поэтому требование выполняется СИЛЬНЕЕ, чем просило: прерывание даёт откат, то
-- есть состояние «не начато», и оно отличимо от завершённого самим значением
-- якоря. `kaname.cluster_anchor_residue()` отвечает на этот вопрос числом, а не
-- впечатлением, и покажет расхождение, если якорь когда-нибудь перепишут мимо
-- этой функции.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОБОЧНОЕ ДЕЙСТВИЕ ПЕРЕПИСЧИКА НАЗВАНО, А НЕ УМОЛЧАНО
--
-- Переписчик откладывает внешние ключи схемы на время своей работы и в конце
-- переводит режим проверки обратно (`SET CONSTRAINTS ALL IMMEDIATE`). Режим
-- транзакционный и ОБЩИЙ, поэтому вызывающий, отложивший СВОИ ключи ради
-- собственного порядка вставок, получит их проверенными здесь же. На пути, ради
-- которого функция заведена — переход написания одной командой, — вызывающего с
-- отложенными ключами нет; но знать это надо заранее, а не выяснять по отказу.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF to_regclass('kaname.clusters') IS NULL THEN
        RAISE EXCEPTION 'kaname.clusters не существует — цепочка миграций применена не с начала';
    END IF;
    IF to_regclass('kaname.cluster_admin_grants') IS NULL THEN
        RAISE EXCEPTION 'kaname.cluster_admin_grants не существует — цепочка миграций применена не с начала';
    END IF;
    IF to_regclass('kaname.fga_outbox') IS NULL THEN
        RAISE EXCEPTION 'kaname.fga_outbox не существует — цепочка миграций применена не с начала';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.cluster_anchor() RETURNS text
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_id  text;
    v_cnt int;
BEGIN
    SELECT count(*) INTO v_cnt FROM kaname.clusters;
    IF v_cnt <> 1 THEN
        RAISE EXCEPTION
            'якорь кластера не единственный: строк в kaname.clusters — %. Ограничение-синглтон снято либо не восстановлено; путь возврата доступа не вправе гадать, какая из строк якорь.',
            v_cnt;
    END IF;
    SELECT id INTO v_id FROM kaname.clusters;
    RETURN v_id;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON FUNCTION kaname.cluster_anchor() IS 'Текущее написание якоря кластера, прочитанное из единственной строки kaname.clusters. Читается, а не пишется литералом: путь возврата доступа нужен ровно тогда, когда про написание якоря неизвестно, каким оно сейчас стало.';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.restore_cluster_admin(
    p_subject_type text,
    p_subject_id   text
) RETURNS text
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_anchor  text := kaname.cluster_anchor();
    v_subject text;
    v_grant   text;
    v_had     boolean;
    v_exists  boolean;
BEGIN
    IF p_subject_type NOT IN ('user', 'service_account') THEN
        RAISE EXCEPTION
            'вид субъекта % не поддерживается: доступ кластерного администратора выдаётся человеку (user) либо служебной учётке (service_account).',
            p_subject_type;
    END IF;
    IF p_subject_id IS NULL OR p_subject_id = '' THEN
        RAISE EXCEPTION 'идентификатор субъекта пуст — возвращать доступ некому.';
    END IF;

    -- Субъект обязан СУЩЕСТВОВАТЬ. Возврат доступа несуществующему субъекту
    -- оставил бы отношение, которое никогда никому не ответит, и оператор
    -- прочитал бы «сделано» там, где не сделано ничего.
    IF p_subject_type = 'user' THEN
        SELECT EXISTS(SELECT 1 FROM kaname.users WHERE id = p_subject_id) INTO v_exists;
    ELSE
        SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id = p_subject_id) INTO v_exists;
    END IF;
    IF NOT v_exists THEN
        RAISE EXCEPTION
            'субъект %:% в этой базе не существует — возвращать доступ некому. Проверьте идентификатор.',
            p_subject_type, p_subject_id;
    END IF;

    v_subject := p_subject_type || ':' || p_subject_id;

    -- Уже действующее отношение — законный вход: процедура ИДЕМПОТЕНТНА,
    -- оператор зовёт её, не зная состояния.
    SELECT EXISTS(
        SELECT 1 FROM kaname.relation_fact
         WHERE object_type = 'cluster' AND object_id = v_anchor
           AND relation = 'system_admin' AND subject = v_subject
    ) INTO v_had;

    -- Строка выдачи. Уникальность (cluster_id, subject_id) держит база; повтор
    -- не заводит второй.
    SELECT id INTO v_grant
      FROM kaname.cluster_admin_grants
     WHERE cluster_id = v_anchor AND subject_id = p_subject_id;

    IF v_grant IS NULL THEN
        -- Форма идентификатора выдачи закреплена ограничением таблицы:
        -- `cag_` плюс 17 знаков крокфордовой базы-32. Шестнадцатеричные знаки
        -- (`0-9a-f`) в неё входят целиком — исключённые `i`, `l`, `o`, `u` среди
        -- них не встречаются, — поэтому срез уникального значения годен без
        -- перекодирования. `gen_random_uuid` встроен, а не приходит расширением:
        -- путь возврата не вправе зависеть от того, поставил ли оператор
        -- pgcrypto.
        v_grant := 'cag_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 17);
        INSERT INTO kaname.cluster_admin_grants
               (id, cluster_id, subject_type, subject_id, granted_by, granted_at)
        VALUES (v_grant, v_anchor, p_subject_type, p_subject_id, 'restore', now());
    END IF;

    -- Отношение кладётся ЧЕРЕЗ журнал намерений, а не прямой вставкой в
    -- проекцию: проекцию складывает триггер журнала, и запись мимо него завела
    -- бы второй путь к одному предмету — тот, что разойдётся молча.
    INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
    VALUES ('fga.tuple.write',
            jsonb_build_object(
                'user',     v_subject,
                'relation', 'system_admin',
                'object',   'cluster:' || v_anchor),
            now());

    RETURN format(
        'доступ кластерного администратора восстановлен: якорь=%s субъект=%s выдача=%s отношение_было=%s',
        v_anchor, v_subject, v_grant, v_had);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON FUNCTION kaname.restore_cluster_admin(text, text) IS 'ОБЪЯВЛЕННЫЙ путь возврата доступа кластерного администратора. Идёт мимо службы намеренно: предпосылка отказа — доступа нет, и всякий путь через службу ответил бы отказом ему же. Прав не добавляет — зовущий уже пишет в эту базу; добавляет правильность: якорь разрешается по факту, три записи идут одной транзакцией, повтор безопасен.';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.cluster_anchor_residue(p_anchor text)
    RETURNS TABLE(place text, kind text, hits bigint)
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    r        record;
    v_cnt    bigint;
    v_looked bigint := 0;
BEGIN
    IF p_anchor IS NULL OR p_anchor = '' THEN
        RAISE EXCEPTION 'перепись остатка без написания якоря беспредметна.';
    END IF;

    -- Текстовые колонки: значение целиком равно якорю либо форме объекта прав.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col
          FROM information_schema.columns c
          JOIN information_schema.tables tb
            ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
         WHERE c.table_schema = 'kaname'
           AND tb.table_type = 'BASE TABLE'
           AND c.data_type IN ('text', 'character varying')
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        EXECUTE format(
            'SELECT count(*) FROM kaname.%I WHERE %I = $1 OR %I = $2',
            r.t, r.col, r.col)
           INTO v_cnt USING p_anchor, 'cluster:' || p_anchor;
        IF v_cnt > 0 THEN
            place := r.t || '.' || r.col; kind := 'текст'; hits := v_cnt; RETURN NEXT;
        END IF;
    END LOOP;

    -- Колонки jsonb: якорь стоит внутри значения, а не равен ему целиком.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col
          FROM information_schema.columns c
          JOIN information_schema.tables tb
            ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
         WHERE c.table_schema = 'kaname'
           AND tb.table_type = 'BASE TABLE'
           AND c.data_type = 'jsonb'
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        EXECUTE format(
            'SELECT count(*) FROM kaname.%I WHERE %I::text LIKE $1',
            r.t, r.col)
           INTO v_cnt USING '%' || p_anchor || '%';
        IF v_cnt > 0 THEN
            place := r.t || '.' || r.col; kind := 'jsonb'; hits := v_cnt; RETURN NEXT;
        END IF;
    END LOOP;

    -- Умолчания колонок: умолчание, оставшееся прежним, ТИХО вернёт старое
    -- написание на первой же вставке, не назвавшей столбец.
    --
    -- Обход идёт по ВСЕМ умолчаниям, а отбор по написанию — внутри. Иначе объём
    -- осмотренного зависел бы от того, что нашлось: перепись «до» и перепись
    -- «после» осмотрели бы разное, и их числа стали бы несравнимы — то есть
    -- перепись перестала бы отвечать на вопрос, ради которого заведена.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col, c.column_default AS def
          FROM information_schema.columns c
         WHERE c.table_schema = 'kaname' AND c.column_default IS NOT NULL
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        IF r.def LIKE '%' || p_anchor || '%' THEN
            place := r.t || '.' || r.col; kind := 'умолчание'; hits := 1; RETURN NEXT;
        END IF;
    END LOOP;

    -- Ограничения-проверки: якорь стоит в предикате. Обход — по всем, отбор
    -- внутри, по той же причине.
    FOR r IN
        SELECT con.conname AS t, pg_get_constraintdef(con.oid) AS def
          FROM pg_constraint con
          JOIN pg_namespace ns ON ns.oid = con.connamespace
         WHERE ns.nspname = 'kaname' AND con.contype = 'c'
         ORDER BY con.conname
    LOOP
        v_looked := v_looked + 1;
        IF r.def LIKE '%' || p_anchor || '%' THEN
            place := r.t; kind := 'ограничение'; hits := 1; RETURN NEXT;
        END IF;
    END LOOP;

    -- Объём осмотренного — ОТДЕЛЬНОЙ строкой, всегда. «Ноль находок» обязано
    -- быть отличимо от «ноль прочитанного»: перепись, обошедшая пустой каталог,
    -- молчит ровно так же, как перепись по чистой базе.
    place := '(осмотрено мест)'; kind := 'перепись'; hits := v_looked; RETURN NEXT;
    RETURN;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON FUNCTION kaname.cluster_anchor_residue(text) IS 'Перепись остатка написания якоря по ВСЕЙ схеме: текстовые колонки, jsonb, умолчания столбцов, предикаты ограничений. Обходит каталог, а не выписанный перечень таблиц, — перечень старел бы молча вместе с каждой новой миграцией. Последняя строка называет объём осмотренного: ноль находок обязано быть отличимо от нуля прочитанного.';
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.rename_cluster_anchor(p_old text, p_new text)
    RETURNS TABLE(place text, kind text, moved bigint)
    LANGUAGE plpgsql
    AS $$
DECLARE
    r        record;
    v_cnt    bigint;
    v_looked bigint := 0;
    v_checks text[] := ARRAY[]::text[];
    v_fks    text[] := ARRAY[]::text[];
    v_def    text;
BEGIN
    IF p_old IS NULL OR p_old = '' OR p_new IS NULL OR p_new = '' THEN
        RAISE EXCEPTION 'перепись якоря требует обоих написаний.';
    END IF;
    IF p_old = p_new THEN
        RAISE EXCEPTION 'написания совпадают — переписывать нечего.';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM kaname.clusters WHERE id = p_old) THEN
        RAISE EXCEPTION
            'якоря % в kaname.clusters нет: переход уже прошёл либо написание названо неверно. Текущее написание — %.',
            p_old, kaname.cluster_anchor();
    END IF;
    IF EXISTS(SELECT 1 FROM kaname.clusters WHERE id = p_new) THEN
        RAISE EXCEPTION 'якорь % уже существует — синглтон не вправе стать парой.', p_new;
    END IF;

    -- 1. Ограничения-проверки, называющие старое написание, снимаются: без
    --    этого не завести строку под новым именем, а сама проверка отвергла бы
    --    результат перехода. Определения запоминаются дословно и возвращаются
    --    ниже с заменённым написанием.
    FOR r IN
        SELECT con.conname AS name, cl.relname AS tbl, pg_get_constraintdef(con.oid) AS def
          FROM pg_constraint con
          JOIN pg_namespace ns ON ns.oid = con.connamespace
          JOIN pg_class cl     ON cl.oid = con.conrelid
         WHERE ns.nspname = 'kaname' AND con.contype = 'c'
           AND pg_get_constraintdef(con.oid) LIKE '%' || p_old || '%'
    LOOP
        v_checks := v_checks || (r.tbl || '|' || r.name || '|' || replace(r.def, p_old, p_new));
        EXECUTE format('ALTER TABLE kaname.%I DROP CONSTRAINT %I', r.tbl, r.name);
        place := r.name; kind := 'ограничение снято'; moved := 1; RETURN NEXT;
    END LOOP;

    -- 2. Внешние ключи схемы откладываются до конца транзакции.
    --
    --    Порядок обхода колонок — каталожный, а не топологический, поэтому
    --    ребёнок может быть переписан раньше родителя. Откладывание снимает
    --    вопрос порядка ЦЕЛИКОМ: проверка случится один раз, когда переписано
    --    всё. Восстанавливаются ключи ниже — в этой же транзакции.
    FOR r IN
        SELECT con.conname AS name, cl.relname AS tbl
          FROM pg_constraint con
          JOIN pg_namespace ns ON ns.oid = con.connamespace
          JOIN pg_class cl     ON cl.oid = con.conrelid
         WHERE ns.nspname = 'kaname' AND con.contype = 'f' AND NOT con.condeferrable
    LOOP
        v_fks := v_fks || (r.tbl || '|' || r.name);
        EXECUTE format('ALTER TABLE kaname.%I ALTER CONSTRAINT %I DEFERRABLE INITIALLY IMMEDIATE',
                       r.tbl, r.name);
    END LOOP;
    SET CONSTRAINTS ALL DEFERRED;

    -- 3. Текстовые колонки — все, кроме самого якоря: его строка переписывается
    --    последней, когда на неё уже никто не смотрит старым написанием.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col
          FROM information_schema.columns c
          JOIN information_schema.tables tb
            ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
         WHERE c.table_schema = 'kaname'
           AND tb.table_type = 'BASE TABLE'
           AND c.data_type IN ('text', 'character varying')
           AND NOT (c.table_name = 'clusters' AND c.column_name = 'id')
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        EXECUTE format(
            'UPDATE kaname.%I SET %I = CASE WHEN %I = $1 THEN $2 ELSE $4 END WHERE %I IN ($1, $3)',
            r.t, r.col, r.col, r.col)
           USING p_old, p_new, 'cluster:' || p_old, 'cluster:' || p_new;
        GET DIAGNOSTICS v_cnt = ROW_COUNT;
        IF v_cnt > 0 THEN
            place := r.t || '.' || r.col; kind := 'текст'; moved := v_cnt; RETURN NEXT;
        END IF;
    END LOOP;

    -- 4. Колонки jsonb — якорь стоит внутри значения.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col
          FROM information_schema.columns c
          JOIN information_schema.tables tb
            ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
         WHERE c.table_schema = 'kaname'
           AND tb.table_type = 'BASE TABLE'
           AND c.data_type = 'jsonb'
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        EXECUTE format(
            'UPDATE kaname.%I SET %I = replace(%I::text, $1, $2)::jsonb WHERE %I::text LIKE $3',
            r.t, r.col, r.col, r.col)
           USING p_old, p_new, '%' || p_old || '%';
        GET DIAGNOSTICS v_cnt = ROW_COUNT;
        IF v_cnt > 0 THEN
            place := r.t || '.' || r.col; kind := 'jsonb'; moved := v_cnt; RETURN NEXT;
        END IF;
    END LOOP;

    -- 5. Сам якорь.
    UPDATE kaname.clusters SET id = p_new WHERE id = p_old;
    place := 'clusters.id'; kind := 'якорь'; moved := 1; RETURN NEXT;

    -- 6. Отложенные ключи проверяются ЗДЕСЬ, до правки схемы.
    --
    --    Порядок несущий, и он куплен отказом: `ALTER TABLE` отвергается, пока
    --    у таблицы есть неразрешённые события отложенных ключей
    --    (SQLSTATE 55006). Проверка здесь же означает ещё и то, что отказ ключа
    --    назовёт СЕБЯ внутри функции, а не превратится в «транзакция не
    --    закоммитилась» у вызывающего.
    SET CONSTRAINTS ALL IMMEDIATE;
    FOREACH v_def IN ARRAY v_fks LOOP
        EXECUTE format('ALTER TABLE kaname.%I ALTER CONSTRAINT %I NOT DEFERRABLE',
                       split_part(v_def, '|', 1), split_part(v_def, '|', 2));
    END LOOP;

    -- 7. Умолчания столбцов. Умолчание, оставшееся прежним, ТИХО вернёт старое
    --    написание на первой же вставке, не назвавшей столбец, — и вернёт его
    --    туда, где уже никто не ищет.
    FOR r IN
        SELECT c.table_name AS t, c.column_name AS col, c.column_default AS def
          FROM information_schema.columns c
         WHERE c.table_schema = 'kaname'
           AND c.column_default LIKE '%' || p_old || '%'
         ORDER BY c.table_name, c.column_name
    LOOP
        v_looked := v_looked + 1;
        v_def := replace(r.def, p_old, p_new);
        EXECUTE format('ALTER TABLE kaname.%I ALTER COLUMN %I SET DEFAULT %s', r.t, r.col, v_def);
        place := r.t || '.' || r.col; kind := 'умолчание'; moved := 1; RETURN NEXT;
    END LOOP;

    -- 8. Ограничения-проверки возвращаются с новым написанием. Возврат идёт
    --    ПОСЛЕДНИМ: проверка, поставленная раньше правки данных, отвергла бы
    --    строки, ещё не переехавшие.
    FOREACH v_def IN ARRAY v_checks LOOP
        EXECUTE format('ALTER TABLE kaname.%I ADD CONSTRAINT %I %s',
                       split_part(v_def, '|', 1), split_part(v_def, '|', 2), split_part(v_def, '|', 3));
        place := split_part(v_def, '|', 2); kind := 'ограничение возвращено'; moved := 1; RETURN NEXT;
    END LOOP;

    place := '(осмотрено мест)'; kind := 'перепись'; moved := v_looked; RETURN NEXT;
    RETURN;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON FUNCTION kaname.rename_cluster_anchor(text, text) IS 'Переписчик написания якоря кластера по ВСЕЙ схеме одной транзакцией: текстовые колонки, jsonb, умолчания столбцов, предикаты ограничений, сама строка якоря. Обходит каталог, а не выписанный перечень таблиц. Частичного состояния не производит by construction: прерывание даёт откат, то есть «не начато», и это отличимо от завершения значением якоря.';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS kaname.rename_cluster_anchor(text, text);
DROP FUNCTION IF EXISTS kaname.cluster_anchor_residue(text);
DROP FUNCTION IF EXISTS kaname.restore_cluster_admin(text, text);
DROP FUNCTION IF EXISTS kaname.cluster_anchor();
-- +goose StatementEnd
