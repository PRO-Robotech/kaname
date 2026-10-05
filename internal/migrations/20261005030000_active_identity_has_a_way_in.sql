-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- active_identity_has_a_way_in — у действующей личности есть способ входа
-- паролем либо открытый путь восстановления; держит БАЗА (задача
-- PRO-Robotech/kaname#608).
--
-- Санкция: приёмка `docs/engineering/acceptance/active-identity-has-a-way-in.md`
-- (отпечаток 6763b971…c1bb4e, запись
-- `docs/specs/reviews/active-identity-has-a-way-in/6763b9713a16db3205fed2f383936b2b8110f9f4be502559fb13781f47c1bb4e.yaml`,
-- `APPROVED`, событие опубликовано в kaname#608): C1 (инвариант базой) и C6
-- (перенос без смены статуса), сценарии AWI-01…07, AWI-11. Пара — Ф5
-- `recovery-of-access.md` редакции 9 (be4dfb5a…), Р9: законный выход личности
-- с открытым путём — восстановление по почте.
--
-- =============================================================================
-- ЗАЧЕМ
-- =============================================================================
-- Личность `ACTIVE` без строки пароля — тупик: войти нечем, регистрация на её
-- адрес отвечает единым отказом «занято», восстановление первого способа не
-- заводило. Такие строки производили активация приглашения до kaname#456 и
-- внутреннее заведение личности по удостоверению внешнего поставщика.
--
-- =============================================================================
-- КАК ДЕРЖИТСЯ
-- =============================================================================
-- (1) ОТМЕТКА `recovery_path_opened_at` — открытый путь восстановления. Ставит её
--     ТОЛЬКО этот перенос, снимает ТОЛЬКО завершение восстановления (Ф5-30) той
--     же транзакцией, что заводит первый пароль (держит гейт дерева
--     `TestTheRecoveryPathMarkHasTwoNamedWriters`, AWI-10). Снаружи её не видно.
--
-- (2) ВЫЧИСЛЯЕМАЯ КОЛОНКА `expected_login_kind` — вид способа входа, который
--     строка личности ОБЯЗАНА иметь: `password`, пока личность `ACTIVE` и пути
--     восстановления у неё нет; NULL во всех остальных случаях. Писателя у неё
--     нет — её вычисляет база из статуса и отметки, и забыть её не может ни
--     один производитель.
--
-- (3) ОТЛОЖЕННЫЙ СОСТАВНОЙ КЛЮЧ `users_active_has_a_way_in_fk`
--     (id, expected_login_kind) → user_login_methods (user_id, kind). Ключ с
--     NULL в колонке не судится (MATCH SIMPLE), поэтому `PENDING`, `BLOCKED` и
--     личность с открытым путём он не трогает. Отложенность — несущая часть:
--     строка личности и строка пароля пишутся одной транзакцией в любом
--     порядке, и снятие отметки идёт вместе со вставкой первого пароля (AWI-02,
--     AWI-05). Ключ ловит все пути разом:
--       - вставка `ACTIVE` без пароля и без отметки (AWI-01);
--       - снятие отметки без пароля (AWI-05), возврат из блокировки (AWI-06) —
--         вычисляемая колонка меняется, ключ перепроверяется;
--       - удаление строки пароля либо смена её вида у `ACTIVE` (AWI-04) —
--         служебная проверка ключа на стороне таблицы способов;
--       - удаление личности целиком проходит (AWI-07): каскад уносит строку
--         пароля вместе со ссылающейся строкой, ссылки не остаётся.
--     Отказ — класс нарушения ключа, `23503`, текст называет ограничение.
--
-- ПОЧЕМУ КЛЮЧ, А НЕ ПОЛЬЗОВАТЕЛЬСКИЙ ТРИГГЕР. Таблица способов входа хранит
-- секрет, и механизмов, исполняющихся при записи без ведома писателя, на ней нет
-- (комментарий таблицы; держит `TestIntegration_LoginVerifierStaysInside`).
-- Пользовательский триггер на её удалении видел бы строку целиком, с
-- материалом. Служебная проверка ключа читает только ключевые колонки.
--
-- =============================================================================
-- ПЕРЕНОС (C6)
-- =============================================================================
-- Каждая существующая строка `ACTIVE`/`BLOCKED` без строки пароля получает
-- отметку; статус, адрес, подтверждённость и прочее не меняются (AWI-11).
-- `BLOCKED` отметку получает тоже: после снятия блокировки строка — `ACTIVE` с
-- отметкой, и выход Ф5-29 к ней применим (AWI-06 близнец). Ключ заводится
-- ПОСЛЕ переноса и проверяет каждую лежащую строку: накат, не переведший хоть
-- одну строку, откатывается целиком, а не оставляет тупик.
--
-- Замок — тот же, что берёт откат соседней миграции способов входа: писатель,
-- зафиксировавший строку пароля или личности между переносом и ключом, иначе
-- оставил бы перенос неполным, и ключ отверг бы накат.
--
-- +goose Up
LOCK TABLE kaname.user_login_methods, kaname.users IN SHARE ROW EXCLUSIVE MODE;

ALTER TABLE kaname.users ADD COLUMN recovery_path_opened_at timestamp with time zone;

COMMENT ON COLUMN kaname.users.recovery_path_opened_at IS
  'Открытый путь восстановления (kaname#608): ставит только миграция переноса 20261005030000, снимает только завершение восстановления той же транзакцией, что заводит первый пароль. Не способ входа и не статус.';

UPDATE kaname.users u
   SET recovery_path_opened_at = now()
 WHERE u.invite_status <> 'PENDING'   -- ACTIVE и BLOCKED: словарь статусов закрыт (users_invite_status_check)
   AND NOT EXISTS (
         SELECT 1 FROM kaname.user_login_methods m
          WHERE m.user_id = u.id AND m.kind = 'password');

ALTER TABLE kaname.users ADD COLUMN expected_login_kind text
  GENERATED ALWAYS AS (
    CASE WHEN invite_status = 'ACTIVE' AND recovery_path_opened_at IS NULL THEN 'password' END
  ) STORED;

COMMENT ON COLUMN kaname.users.expected_login_kind IS
  'Вид способа входа, который строка ОБЯЗАНА иметь (kaname#608): password у ACTIVE без открытого пути, иначе NULL. Вычисляется базой; держит ключ users_active_has_a_way_in_fk.';

ALTER TABLE kaname.users
  ADD CONSTRAINT users_active_has_a_way_in_fk
  FOREIGN KEY (id, expected_login_kind)
  REFERENCES kaname.user_login_methods (user_id, kind)
  DEFERRABLE INITIALLY DEFERRED;

-- =============================================================================
-- ПЕРЕПИСЧИК ЯКОРЯ КЛАСТЕРА НЕ ПИШЕТ В ВЫЧИСЛЯЕМЫЕ КОЛОНКИ
-- =============================================================================
-- `kaname.rename_cluster_anchor` (миграция 20260906085136) обходит КАЖДУЮ
-- текстовую и jsonb-колонку схемы и пишет в неё `UPDATE … SET`. Вычисляемая
-- колонка такой записи не принимает («can only be updated to DEFAULT») даже на
-- нуле совпавших строк, и переписчик отказывал бы целиком. До этой миграции
-- вычисляемых колонок в схеме не было; `expected_login_kind` — первая. Тело
-- переписчика повторено дословно, с одним отбором `is_generated = 'NEVER'` в
-- обходах текста и jsonb: значение вычисляемой колонки база выводит из
-- переписанных соседей сама. Держат `TestClusterAnchor_*` в
-- `cluster_anchor_way_back_integration_test.go`.
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
           -- Вычисляемая колонка значения не принимает: её выводит база из
           -- переписанных соседей (kaname#608, `users.expected_login_kind`).
           AND c.is_generated = 'NEVER'
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
           AND c.is_generated = 'NEVER'
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

-- +goose Down
-- Откат снимает ключ, вычисляемую колонку и отметку; личностей, их статусов и
-- строк способов входа не трогает (AWI §4.1 п. 4). Отбор вычисляемых колонок в
-- переписчике якоря остаётся: без вычисляемых колонок он не отбирает ничего, и
-- поведение переписчика совпадает с прежним.
ALTER TABLE kaname.users DROP CONSTRAINT users_active_has_a_way_in_fk;
ALTER TABLE kaname.users DROP COLUMN expected_login_kind;
ALTER TABLE kaname.users DROP COLUMN recovery_path_opened_at;
