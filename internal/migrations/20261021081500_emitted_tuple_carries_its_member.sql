-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- emitted_tuple_carries_its_member — строка реестра выпущенного выдачей несёт
-- координату члена, который её выпустил (задача PRO-Robotech/kaname#933).
--
-- Санкция: задача #933 (корректность снятия доступа). Публичный контракт не
-- меняется: реестр пишет и читает только служба. Отказ новой проверки — дефект
-- писателя, а не ввод вызывающего; таблица целиком в полосе дефекта службы
-- (`check_value_lanes.go`, запись `access_binding_emitted_tuples: nil`), и служба
-- отвечает на него фиксированным INTERNAL.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- 1. ПРЕДМЕТ
--
-- Ключ реестра был (выдача, субъект, отношение, объект): какому члену выдачи
-- принадлежит строка, база не знала, и снятие члена выбирало его строки
-- РАЗБОРОМ объекта в коде — по имени типа модели из снимка каталога процесса, а
-- при промахе снимка по суффиксу `:<id>`. Суффикс у объектов РАЗНЫХ типов одной
-- выдачи совпадает, и снятие члена одного типа забирало строки и факты члена
-- другого типа с тем же идентификатором.
--
-- Тип модели из каталога координатой не служит: `object_type` строки каталога
-- переписывается применением манифеста (`catalog_writer.go`), а живая и снятая
-- строки вправе носить один тип модели. Реестр обязан помнить, ЧТО и ЗА КЕМ
-- выдано, без опоры на каталог.
--
-- 2. ЧТО ВВОДИТСЯ
--
--   * `member_object_type`, `member_object_id` — точечное имя типа и
--     идентификатор члена (`access_binding_target_members.object_type`,
--     `.object_id`). У строки уровня выдачи (`source='binding'`) координата
--     пуста — `('', '')`: члена у неё нет.
--   * Первичный ключ — (выдача, координата члена, субъект, отношение, объект):
--     один кортеж от двух координат одной выдачи — две строки, и уход одной
--     координаты не забирает строку другой.
--   * `access_binding_emitted_tuples_member_coordinate` — координата согласна с
--     источником строки, а идентификатор координаты — с объектом кортежа
--     (часть объекта после первого `:`; имя типа модели двоеточия не несёт,
--     `catalog_resource_object_type_form`). Второго источника идентификатора,
--     способного разойтись с объектом, нет.
--   `rule_fp` в координату не входит: какое правило выпустило кортеж, база не
--   вычислит, и заполнение приписало бы строку правилу, которое её не выпускало.
--   Два правила на одном объекте развязывает вычитание кортежей выживших членов
--   той же координаты в коде.
--
-- 3. ЗАПОЛНЕНИЕ существующих строк `source='member'` — по классам:
--   * ТОЧНОЕ: в выдаче есть член с идентификатором объекта, чьё точечное имя
--     каталог (живой или снятой строкой — `dotted` уникален) переводит в тип
--     модели объекта, и такое имя ровно одно — координата проставляется.
--   * СИРОТА: члена с таким идентификатором в выдаче нет вовсе — строка без
--     владельца держит факт, это остаток самого #933. Строка снимается, затем
--     пишется строка снятия кортежа: свою строку реестра — раньше строки
--     снятия, иначе выдача держит факт сама (свёртка kaname#919). Факт, который
--     держит кто-то ещё, свёртка оставляет.
--   * НЕОДНОЗНАЧНО: члены с этим идентификатором есть, а точного совпадения нет
--     (тип модели сменился либо кандидатов больше одного), а также строка члена
--     без `:` в объекте. Накат ОТКАЗЫВАЕТ с числами по классам: приписать —
--     лишний доступ, снять — потеря доступа выдачи одному субъекту навсегда
--     (дописывание недостающего идёт лишь у выдачи двум и более субъектам).
--   Перепись классов печатается строкой NOTICE до любого решения; там же —
--   число строк уровня выдачи, чей объект совпадает с объектом её члена (посылка
--   «пространства объектов не пересекаются» данными до сих пор не мерена).
--
-- 4. ЗАМКИ. Реестр берётся `ACCESS EXCLUSIVE` первым (его требует замена
-- ключа), члены — `SHARE` следом: множество членов, по которому идёт заполнение,
-- не меняется до коммита наката.
--
-- 5. ЦЕНА. Колонки с постоянным умолчанием — правка каталога, без переписи
-- таблицы. Замена ключа — одна уникальная индексация реестра под
-- `ACCESS EXCLUSIVE`. Новых индексов нет: префикс нового ключа
-- (выдача, координата) обслуживает снятие члена, префикс (выдача) — чтение
-- реестра выдачи, вопрос свёртки — прежний `access_binding_emitted_tuples_by_tuple`.
--
-- 6. ОТКАТ восстанавливает прежний ключ: строки, совпавшие по нему, схлопываются
-- в одну (строка члена старше строки уровня выдачи — так её размечала прежняя
-- запись). Снятые накатом сироты НЕ возвращаются: откат доступа заново не выдаёт.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    v_member    bigint;
    v_exact     bigint;
    v_orphan    bigint;
    v_ambiguous bigint;
    v_nocolon   bigint;
    v_overlap   bigint;
    v_revoked   bigint;
BEGIN
    LOCK TABLE kaname.access_binding_emitted_tuples IN ACCESS EXCLUSIVE MODE;
    LOCK TABLE kaname.access_binding_target_members IN SHARE MODE;

    ALTER TABLE kaname.access_binding_emitted_tuples
        ADD COLUMN member_object_type text NOT NULL DEFAULT '',
        ADD COLUMN member_object_id   text NOT NULL DEFAULT '';

    -- Классы считаются одним проходом и до любой записи: перепись печатается
    -- раньше решения, и отказ наката называет те же числа.
    CREATE TEMPORARY TABLE ledger_member_class ON COMMIT DROP AS
    SELECT et.ctid AS row_ctid,
           et.binding_id,
           et.fga_user,
           et.relation,
           et.object,
           CASE
               WHEN strpos(et.object, ':') <= 1 THEN 'nocolon'
               WHEN c.n_exact = 1 THEN 'exact'
               WHEN c.n_same_id = 0 THEN 'orphan'
               ELSE 'ambiguous'
           END AS class,
           c.dotted
      FROM kaname.access_binding_emitted_tuples et
      CROSS JOIN LATERAL (
            SELECT count(DISTINCT tm.object_type) FILTER (
                       WHERE cr.object_type = split_part(et.object, ':', 1)) AS n_exact,
                   min(tm.object_type) FILTER (
                       WHERE cr.object_type = split_part(et.object, ':', 1)) AS dotted,
                   count(tm.object_type) AS n_same_id
              FROM kaname.access_binding_target_members tm
              LEFT JOIN kaname.catalog_resource cr ON cr.dotted = tm.object_type
             WHERE tm.binding_id = et.binding_id
               AND strpos(et.object, ':') > 1
               AND tm.object_id = substr(et.object, strpos(et.object, ':') + 1)
           ) c
     WHERE et.source = 'member';

    SELECT count(*),
           count(*) FILTER (WHERE class = 'exact'),
           count(*) FILTER (WHERE class = 'orphan'),
           count(*) FILTER (WHERE class = 'ambiguous'),
           count(*) FILTER (WHERE class = 'nocolon')
      INTO v_member, v_exact, v_orphan, v_ambiguous, v_nocolon
      FROM ledger_member_class;

    SELECT count(*) INTO v_overlap
      FROM kaname.access_binding_emitted_tuples et
     WHERE et.source = 'binding'
       AND EXISTS (
             SELECT 1
               FROM kaname.access_binding_target_members tm
               JOIN kaname.catalog_resource cr ON cr.dotted = tm.object_type
              WHERE tm.binding_id = et.binding_id
                AND et.object = cr.object_type || ':' || tm.object_id);

    RAISE NOTICE 'перепись реестра выпущенного (kaname#933): строк членов % · точных % · сирот % · '
                 'неоднозначных % · без двоеточия % · строк уровня выдачи на объекте её члена %',
        v_member, v_exact, v_orphan, v_ambiguous, v_nocolon, v_overlap;

    IF v_ambiguous > 0 OR v_nocolon > 0 THEN
        RAISE EXCEPTION 'реестр выпущенного: строк членов, чью координату не вывести однозначно, — % '
                        '(неоднозначных %, без двоеточия %); приписать их значило бы выдать лишний '
                        'доступ, снять — отнять доступ, который дописывание не вернёт',
            v_ambiguous + v_nocolon, v_ambiguous, v_nocolon;
    END IF;

    UPDATE kaname.access_binding_emitted_tuples et
       SET member_object_type = c.dotted,
           member_object_id   = substr(et.object, strpos(et.object, ':') + 1)
      FROM ledger_member_class c
     WHERE c.class = 'exact' AND et.ctid = c.row_ctid;

    -- Сирота: своя строка реестра уходит ПЕРВОЙ, строка снятия — следом (п. 3).
    DELETE FROM kaname.access_binding_emitted_tuples et
     USING ledger_member_class c
     WHERE c.class = 'orphan' AND et.ctid = c.row_ctid;

    INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
    SELECT 'fga.tuple.delete',
           jsonb_build_object('user', c.fga_user, 'object', c.object, 'relation', c.relation),
           now()
      FROM ledger_member_class c
     WHERE c.class = 'orphan'
     ORDER BY c.object, c.relation, c.fga_user;
    GET DIAGNOSTICS v_revoked = ROW_COUNT;

    ALTER TABLE kaname.access_binding_emitted_tuples
        DROP CONSTRAINT access_binding_emitted_tuples_pk;
    ALTER TABLE kaname.access_binding_emitted_tuples
        ADD CONSTRAINT access_binding_emitted_tuples_pk
        PRIMARY KEY (binding_id, member_object_type, member_object_id, fga_user, relation, object);

    ALTER TABLE kaname.access_binding_emitted_tuples
        ADD CONSTRAINT access_binding_emitted_tuples_member_coordinate CHECK (
            (source = 'binding' AND member_object_type = '' AND member_object_id = '')
            OR (source = 'member'
                AND member_object_type ~ '^[^.]+\.[^.]+$'
                AND member_object_id <> ''
                AND strpos(object, ':') > 1
                AND substr(object, strpos(object, ':') + 1) = member_object_id));

    RAISE NOTICE 'реестр выпущенного (kaname#933): координата проставлена % строкам · сирот снято % · строк снятия %',
        v_exact, v_orphan, v_revoked;
END
$$;
-- +goose StatementEnd

COMMENT ON COLUMN kaname.access_binding_emitted_tuples.member_object_type IS 'Точечное имя типа члена, выпустившего строку (access_binding_target_members.object_type); пусто у строки уровня выдачи (kaname#933).';
COMMENT ON COLUMN kaname.access_binding_emitted_tuples.member_object_id IS 'Идентификатор члена, выпустившего строку; равен части объекта после первого двоеточия; пусто у строки уровня выдачи (kaname#933).';

-- +goose Down
-- +goose StatementBegin
DO $$
BEGIN
    LOCK TABLE kaname.access_binding_emitted_tuples IN ACCESS EXCLUSIVE MODE;

    ALTER TABLE kaname.access_binding_emitted_tuples
        DROP CONSTRAINT access_binding_emitted_tuples_member_coordinate;

    -- Прежний ключ не различает координат: из строк одного кортежа выдачи
    -- остаётся одна, строка члена — раньше строки уровня выдачи.
    DELETE FROM kaname.access_binding_emitted_tuples et
     USING (
            SELECT ctid AS row_ctid,
                   row_number() OVER (
                       PARTITION BY binding_id, fga_user, relation, object
                       ORDER BY (source = 'member') DESC, member_object_type, member_object_id) AS rn
              FROM kaname.access_binding_emitted_tuples
           ) d
     WHERE d.rn > 1 AND et.ctid = d.row_ctid;

    ALTER TABLE kaname.access_binding_emitted_tuples
        DROP CONSTRAINT access_binding_emitted_tuples_pk;
    ALTER TABLE kaname.access_binding_emitted_tuples
        ADD CONSTRAINT access_binding_emitted_tuples_pk
        PRIMARY KEY (binding_id, fga_user, relation, object);

    ALTER TABLE kaname.access_binding_emitted_tuples
        DROP COLUMN member_object_type,
        DROP COLUMN member_object_id;
END
$$;
-- +goose StatementEnd
