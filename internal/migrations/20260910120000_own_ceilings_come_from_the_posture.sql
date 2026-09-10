-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- own_ceilings_come_from_the_posture — ТРИ СОБСТВЕННЫХ ПОТОЛКА СЛУЖБЫ ДОСТУПА
-- берут величину из ПОСАДКИ, а не у авторитета величин.
--
-- Задача продукта #2117, приёмка `KAN-QUOTA-1`, `П25`, сценарии `KAN-Q3-01`,
-- `KAN-Q3-02`, `KAN-Q3-05`, `KAN-Q3-06`; условие готовности `DoD S3` пп. 1-2.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ: ПОТОЛОК ОСТАЁТСЯ, УХОДИТ ЕГО ИСТОЧНИК
--
-- Служба доступа перестаёт быть авторитетом величин. Три её собственных потолка
-- при этом ДЕЙСТВУЮЩИЕ: сколько аккаунтов заводит одна личность (`iam.account`)
-- и сколько путей входа держит человек (`iam.user.credential`) и машина
-- (`iam.serviceAccount.credential`). Снять их вместе с модулем значило бы
-- РАСШИРИТЬ ПОВЕРХНОСТЬ, не назвав расширения: самостоятельная установка
-- осталась бы без ограничения на число аккаунтов и удостоверений.
--
-- Поэтому величина ПЕРЕВЫРАЖАЕТСЯ: её объявляет посадка службы — ручкой с
-- отказом старта при незаданном значении, — а не назначает внешний авторитет,
-- которого в самостоятельной установке нет by construction.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕМ `kaname.own_ceilings` НЕ ЯВЛЯЕТСЯ — АВТОРИТЕТОМ ПОД ДРУГИМ ИМЕНЕМ
--
-- Приёмка прямо отвергает «завести авторитет внутри самой службы доступа: это
-- тот же модуль под другим именем». Различие названо ПО ОСЯМ, а не словами:
--
--   ось          | авторитет величин          | проекция посадки
--   -------------|----------------------------|--------------------------------
--   контракт     | две службы, 12 методов     | НЕТ ни одного глагола
--   область      | DEFAULT / ACCOUNT / PROJECT| одна величина на установку
--   старшинство  | резолв между областями     | сравнивать нечего
--   дельта       | ревизия и курсор догона    | версии нет вовсе
--   писатель     | арендатор через API        | ТОЛЬКО пуск процесса
--
-- Таблица есть ПРОЕКЦИЯ величины из файла настроек в схему, и нужна она ровно
-- потому, что списание обязано быть В ТОЙ ЖЕ ТРАНЗАКЦИИ, что вставка строки
-- ресурса: инвариант держит оператор базы, а не проверка-перед-записью. Прочесть
-- настройку процесса из триггера нельзя — значит величина обязана лежать рядом.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ МИГРАЦИЯ ПЕРЕНОСИТ ВЕЛИЧИНУ, А НЕ ПРОСТО СНИМАЕТ СТАРУЮ
--
-- Триггерная функция живёт в БАЗЕ, поэтому новую читают ВСЕ работающие поды
-- сразу после наката — включая поды прежней версии, которые ещё обслуживают
-- запросы во время перекатки. Пустая проекция означала бы, что в этом окне
-- каждое создание аккаунта и удостоверения отвергается.
--
-- Поэтому миграция ПЕРЕНОСИТ объявленную авторитетом величину области `DEFAULT`
-- в проекцию, и лишь затем снимает её у авторитета. Первый пуск новой версии
-- перезаписывает перенесённое тем, что объявила посадка.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ МИГРАЦИЯ, А НЕ ПОСЕВ
--
-- Величины заведены ПРИМЕНЁННОЙ миграцией `0001_initial.sql` и обязаны
-- существовать у всякого, кто развернул продукт, — это справочник продукта, а не
-- данные стенда. Применённую не правят (ban #5), поэтому снятие идёт НОВОЙ.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО ЭТА МИГРАЦИЯ НЕ ДЕЛАЕТ
--
--   * НЕ трогает строки учёта (`kaname.project_resource_quotas`): счёт по трём
--     видам сохраняется, потому что сохраняется его предмет. Потребление обязано
--     пережить и накат, и перезапуск, и понижение величины;
--   * НЕ трогает предел СКОРОСТИ приёма аккаунтов
--     (`kaname.account_admission_rate_limits`): это защита службы от
--     злоупотребления, а не потолок количества, и слово «квота» в её отказе —
--     совпадение написания;
--   * НЕ трогает `kaname.kacho_quota_refuse`: производитель отказа рендерится
--     ОДНИМ шаблоном шести владельцам, и своя редакция здесь разошлась бы с
--     остальными пятью. Тон отказа не меняется — меняется только то, откуда
--     взялась величина в его тексте;
--   * НЕ снимает таблицу `kaname.limits` и остальные 24 вида: они уходят
--     стадией S4 вместе со всем авторитетом.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    posture CONSTANT text[] := ARRAY[
        'iam.account',
        'iam.user.credential',
        'iam.serviceAccount.credential'
    ];
    charging bigint;
BEGIN
    -- ОХРАНА ПРЕДПОСЫЛКИ, обратная охране миграции шести снятых видов.
    --
    -- Эта миграция верна ровно потому, что все три названных вида СПИСЫВАЮТСЯ:
    -- у каждого свой вызов `kacho_quota_count` в применённой миграции. Пропади
    -- у любого списывающий триггер — перевыражать было бы нечего, и величина
    -- посадки стала бы принята-и-проигнорирована, то есть ровно тем классом,
    -- который эта стадия закрывает.
    SELECT count(DISTINCT k.kind) INTO charging
    FROM unnest(posture) AS k(kind)
    WHERE EXISTS (
        SELECT 1
        FROM pg_trigger t
        JOIN pg_proc p ON p.oid = t.tgfoid
        WHERE NOT t.tgisinternal
          AND p.proname = 'kacho_quota_count'
          AND pg_get_triggerdef(t.oid) LIKE '%''' || k.kind || '''%'
    );

    IF charging <> array_length(posture, 1) THEN
        RAISE EXCEPTION 'предпосылка неверна: списывающий триггер есть у % из % видов посадки — у остальных величина посадки была бы принята и не применена ни разу',
            charging, array_length(posture, 1);
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE kaname.own_ceilings (
    kind        text NOT NULL,
    limit_value bigint NOT NULL,
    stated_at   timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT own_ceilings_pkey PRIMARY KEY (kind),
    -- МНОЖЕСТВО ЗАКРЫТО, и закрыто оно СХЕМОЙ, а не соглашением. Проекция посадки
    -- не бывает авторитетом: вид, которого служба не считает, сюда не попадает
    -- даже опечаткой, и величина на нём не может быть принята молча.
    CONSTRAINT own_ceilings_kind_ck CHECK (kind = ANY (ARRAY[
        'iam.account'::text,
        'iam.user.credential'::text,
        'iam.serviceAccount.credential'::text])),
    -- НОЛЬ ЗАКОНЕН и означает «ресурсов этого вида не заводить»; отрицательное не
    -- означает «без ограничения» и отвергается здесь так же, как стражем старта.
    CONSTRAINT own_ceilings_limit_ck CHECK (limit_value >= 0)
);
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON TABLE kaname.own_ceilings IS 'projection of the deployment posture into the schema: the ceiling for each kind this service OWNS. Not an authority and not a smaller one — it has no contract, no scope arms, no seniority between them and no revision, and the only writer is the process start. It exists because the charge must happen in the same transaction as the resource row, and a trigger cannot read a process setting: the value has to lie next to the rows it bounds. Written by the composition root before any listener comes up; the startup guard refuses to boot while any of the three values is unstated or negative';
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON COLUMN kaname.own_ceilings.limit_value IS 'the ceiling, as the posture stated it. Zero is legal and means "none of this kind may be created" — it is NOT "unset": absence is a refusal to start, not a value';
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON COLUMN kaname.own_ceilings.stated_at IS 'when the running process last projected this value. Diagnostic only: nothing reads it to decide anything — a value that changes behaviour would be a revision, and the posture has none';
-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    posture CONSTANT text[] := ARRAY[
        'iam.account',
        'iam.user.credential',
        'iam.serviceAccount.credential'
    ];
    carried   bigint;
    unstated  text[];
    withdrawn bigint;
    scoped    text[];
BEGIN
    -- ПЕРЕНОС объявленного авторитетом в проекцию посадки. Область — только
    -- `DEFAULT`: у трёх собственных видов величина одна на установку, и области
    -- `ACCOUNT`/`PROJECT` к ним не применялись (у одного применялась, и её
    -- перенос обсуждается ниже отдельной строкой).
    INSERT INTO kaname.own_ceilings (kind, limit_value)
    SELECT l.kind, l.limit_value
      FROM kaname.limits l
     WHERE l.withdrawn_at IS NULL
       AND l.scope = 'DEFAULT'
       AND l.kind = ANY (posture)
    ON CONFLICT (kind) DO NOTHING;
    GET DIAGNOSTICS carried = ROW_COUNT;

    SELECT COALESCE(array_agg(k.kind ORDER BY k.kind), ARRAY[]::text[])
      INTO unstated
      FROM unnest(posture) AS k(kind)
     WHERE NOT EXISTS (SELECT 1 FROM kaname.own_ceilings oc WHERE oc.kind = k.kind);

    IF array_length(unstated, 1) > 0 THEN
        -- ВЕЛИЧИНУ, КОТОРОЙ АВТОРИТЕТ НЕ НАЗЫВАЛ, ПЕРЕНЕСТИ НЕЧЕМ, и придумать её
        -- нельзя: подставленное число объявило бы арендатору потолок, которого
        -- никто не назначал, а ноль запретил бы вид, который до наката работал.
        --
        -- Отказать в накате тоже нельзя: у такой установки КАЖДОЕ создание этого
        -- вида отвергается и СЕГОДНЯ (величина не названа — списание отказывает),
        -- то есть накат блокировался бы из-за состояния, которое он же и лечит.
        --
        -- Поэтому строка не заводится, состояние НАЗЫВАЕТСЯ, и первый пуск новой
        -- версии закрывает его величиной посадки.
        RAISE WARNING 'величина не перенесена для видов % — авторитет её не называл; до первого пуска новой версии создание этих видов отвергается ровно как сегодня, посадка закроет это при старте', unstated;
    END IF;

    -- ВЕЛИЧИНЫ ОБЛАСТЕЙ `ACCOUNT`/`PROJECT` ПЕРЕСТАЮТ ДЕЙСТВОВАТЬ, и это
    -- называется ПОИМЁННО, а не сводится к числу.
    --
    -- У посадки нет per-account измерения и быть не может: она объявляет одну
    -- величину на установку. Значит установка, ограничившая ОТДЕЛЬНЫЙ аккаунт,
    -- после наката получает величину посадки — её ограничение перестаёт
    -- действовать, и в сторону ОСЛАБЛЕНИЯ тоже.
    --
    -- Это следствие принятого решения (`П25`, сценарий `KAN-Q3-02`: «единственный
    -- способ изменить величину — посадка службы»), а не побочный эффект. Накат не
    -- отказывает: у продукта нет способа выразить прежнее ограничение, поэтому
    -- отказ был бы тупиком, а не выбором. Но молчать о нём нельзя — оператор
    -- обязан узнать, ЧТО именно перестало действовать, а не «сколько строк».
    SELECT COALESCE(array_agg(
               l.scope || ' ' || l.scope_id || ' ' || l.kind || ' = ' || l.limit_value
               ORDER BY l.kind, l.scope, l.scope_id), ARRAY[]::text[])
      INTO scoped
      FROM kaname.limits l
     WHERE l.kind = ANY (posture) AND l.scope <> 'DEFAULT';

    IF array_length(scoped, 1) > 0 THEN
        RAISE WARNING 'величины областей перестают действовать (посадка per-account измерения не имеет): %', scoped;
    END IF;

    -- СНЯТИЕ У АВТОРИТЕТА — всех областей, а не только `DEFAULT`.
    --
    -- Оставленная строка была бы «принято-и-проигнорировано»: администратор
    -- назначил бы величину, продукт сохранил бы её и НЕ ПРИМЕНИЛ — списание
    -- читает проекцию посадки. Отказ по имени вида на входе авторитета заводится
    -- тем же изменением (`domain.LimitKind.Validate`), поэтому новых строк
    -- появиться уже не может.
    DELETE FROM kaname.limits WHERE kind = ANY (posture);
    GET DIAGNOSTICS withdrawn = ROW_COUNT;

    -- Перепись печатается ВСЕГДА: «ноль перенесённого» обязано быть отличимо от
    -- «ничего не осмотрено», иначе повторный накат на уже переведённой базе
    -- неотличим от миграции, не нашедшей своего предмета.
    RAISE NOTICE 'видов посадки %, величин перенесено %, снято у авторитета %, без перенесённой величины %, величин областей перестало действовать %',
        array_length(posture, 1), carried, withdrawn,
        COALESCE(array_length(unstated, 1), 0), COALESCE(array_length(scoped, 1), 0);
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_quota_carrier_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель выводится из вида по тому же правилу, что и в списании: у
    -- вложенного вида он ЕСТЬ его родительская часть. Два места об одном
    -- предмете здесь разошлись бы молча — строка учёта завелась бы под одним
    -- носителем, а списание искало бы её под другим.
    v_carrier_type text := substring(TG_ARGV[0] from '^(.*)\.[^.]+$');
    v_account      text := '';
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Ноль затронутых строк здесь НЕ отказ: строки учёта могло не быть
        -- (величина отозвана), и удаление принципала не вправе от этого зависеть.
        DELETE FROM kaname.project_resource_quotas
         WHERE carrier_type = v_carrier_type AND carrier_id = OLD.id AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Зеркало аккаунта — только у носителя, принадлежащего ровно одному.
    IF v_carrier_type = 'iam.serviceAccount' THEN
        v_account := COALESCE(NEW.account_id, '');
    END IF;

    -- Строка заводится с НУЛЁМ, и это верно: у нового принципала удостоверений
    -- нет by construction. Уже лежащие покрыты затравкой ниже.
    --
    -- ИСТОЧНИК ВЕЛИЧИНЫ ВЫБИРАЕТСЯ ПО РОЛИ ВИДА — тем же различением, каким его
    -- выбирает списание (`П25`). Это ВТОРОЙ читатель величины, и найден он не
    -- чтением, а пробой: она покраснела на отсутствующей строке учёта, потому
    -- что перенос величины к посадке оставил этот путь смотреть в опустевший
    -- авторитет. Класс — распознаватель, не знающий всех форм своего предмета:
    -- правка одного читателя выглядела полной.
    IF EXISTS (SELECT 1 FROM kaname.own_ceilings oc WHERE oc.kind = v_kind) THEN
        INSERT INTO kaname.project_resource_quotas
            (carrier_type, carrier_id, kind, used, limit_value,
             source_scope, source_scope_id, limit_revision, synced_at, account_id)
        SELECT v_carrier_type, NEW.id, v_kind, 0,
               oc.limit_value, 'DEFAULT', '', 0, now(), v_account
          FROM kaname.own_ceilings oc
         WHERE oc.kind = v_kind
        ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;
    ELSE
        INSERT INTO kaname.project_resource_quotas
            (carrier_type, carrier_id, kind, used, limit_value,
             source_scope, source_scope_id, limit_revision, synced_at, account_id)
        SELECT v_carrier_type, NEW.id, v_kind, 0,
               l.limit_value, l.scope, l.scope_id, l.revision, now(), v_account
          FROM kaname.limits l
         WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT'
        ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;
    END IF;

    RETURN NULL;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_quota_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель ВЫВОДИТСЯ из вида, а не передаётся отдельным аргументом.
    --
    -- У вложенного вида носитель ЕСТЬ его родительская часть — этого требует
    -- гейт каталога от КАЖДОЙ записи, поэтому вывод здесь не догадка, а чтение
    -- того же правила. Отдельный аргумент был бы вторым местом об одном
    -- предмете и разошёлся бы с каталогом молча.
    --
    -- Плюс цена, замеренная сразу: носитель, стоящий в объявлении триггера
    -- строкой в кавычках, неотличим от ВИДА для гейтов дерева, которые читают
    -- аргументы списания. Два таких гейта объявили `iam.user` и
    -- `iam.serviceAccount` «получившими производителя списания» — то есть форма
    -- записи начала подменять факт.
    v_carrier_type text := CASE
        WHEN array_length(string_to_array(TG_ARGV[0], '.'), 1) = 3
        THEN substring(TG_ARGV[0] from '^(.*)\.[^.]+$')
        ELSE ''
    END;
    v_carrier_col  text := COALESCE(TG_ARGV[1], '');
    v_row          jsonb;
    v_owner        text;
    v_identity     text;
    v_carrier      text;
    v_account      text := '';
    v_existing     bigint;
    v_limit        bigint;
    v_scope        text;
    v_scope_id     text;
    v_revision     bigint;
    -- ВЕЛИЧИНУ ЭТОГО ВИДА ОБЪЯВЛЯЕТ ПОСАДКА, а не авторитет величин
    -- (приёмка `KAN-QUOTA-1`, `П25`; задача продукта #2117).
    --
    -- Множество ЗАКРЫТО и стоит здесь ОДНИМ местом: членство читается из
    -- таблицы проекции посадки, а не выписывается вторым списком в теле. Второй
    -- список разошёлся бы с таблицей молча — правку одного видно только тому,
    -- кто в этот день ставит службу.
    v_posture      boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;

    -- Роль выбирается ПО ВИДУ, а не по имени службы: одна и та же служба владеет
    -- своими видами и потребляет чужие, и источник величины у них разный.
    v_posture := EXISTS (SELECT 1 FROM kaname.own_ceilings oc WHERE oc.kind = v_kind);

    -- ─── Полоса носителя-ПРИНЦИПАЛА (задача #1191) ───────────────────────────
    IF v_carrier_type <> '' THEN
        v_carrier := v_row ->> v_carrier_col;
        IF v_carrier IS NULL OR v_carrier = '' THEN
            RAISE EXCEPTION 'quota: row of % carries no %', TG_TABLE_NAME, v_carrier_col
                USING ERRCODE = 'KQ003';
        END IF;

        IF TG_OP = 'DELETE' THEN
            -- Возврат — в той же транзакции, что отзыв. GREATEST не даёт уйти
            -- ниже нуля; ноль затронутых строк не отказ (см. lifecycle выше).
            UPDATE kaname.project_resource_quotas
               SET used = GREATEST(used - 1, 0), updated_at = now()
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            RETURN NULL;
        END IF;

        IF v_carrier_type = 'iam.serviceAccount' THEN
            SELECT COALESCE(sa.account_id, '') INTO v_account
              FROM kaname.service_accounts sa WHERE sa.id = v_carrier;
            v_account := COALESCE(v_account, '');
        END IF;

        -- ИСТОЧНИК ВЕЛИЧИНЫ ЧИТАЕТСЯ ПЕРВЫМ, и он зависит от РОЛИ.
        --
        -- Вид, чей владелец — сама служба доступа, берёт величину из ПРОЕКЦИИ
        -- ПОСАДКИ: внешнего авторитета в самостоятельной установке нет by
        -- construction, и спросить у него нельзя. Область у такой величины одна
        -- на установку, поэтому она объявляется `DEFAULT` — это и есть честный
        -- ответ на вопрос «кто может её поднять»: тот, кто ставит службу.
        --
        -- Ревизии у посадки не бывает: у неё нет дельты, которую кто-то
        -- догоняет. Ноль здесь означает «версии нет», а не «версия нулевая», и
        -- ни один читатель на неё не ключуется.
        IF v_posture THEN
            SELECT oc.limit_value, 'DEFAULT', '', 0
              INTO v_limit, v_scope, v_scope_id, v_revision
              FROM kaname.own_ceilings oc
             WHERE oc.kind = v_kind;
        ELSE
        -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не
        -- «полно». Область аккаунта применима ТОЛЬКО к видам, объявленным
        -- област-ными (`domain.accountScopedKinds`; согласие держит гейт G7):
        -- удостоверение человека действует во всех его аккаунтах, и величина
        -- одного из них управляла бы доступом в чужих.
        SELECT l.limit_value, l.scope, l.scope_id, l.revision
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kaname.limits l
         WHERE l.withdrawn_at IS NULL
           AND l.kind = v_kind
           AND (l.scope = 'DEFAULT'
                OR (l.scope = 'ACCOUNT'
                    AND v_account <> ''
                    AND l.scope_id = v_account
                    AND v_kind IN ('iam.serviceAccount.credential')))
         ORDER BY CASE l.scope WHEN 'ACCOUNT' THEN 2 ELSE 1 END DESC
         LIMIT 1;
        END IF;

        IF NOT FOUND THEN
            -- Строка учёта не вправе пережить авторитет: иначе отказ назвал бы
            -- величину, которой больше нет. Снятие до фиксации не доживёт —
            -- следующий оператор возбуждает исключение.
            --
            -- НА ПОЛОСЕ ПОСАДКИ ЭТА ВЕТВЬ НЕДОСТИЖИМА ПОСЛЕ ПЕРВОГО ПУСКА, и это
            -- сказано здесь, а не подразумевается: страж старта не пускает
            -- процесс без всех трёх величин, а композиционный корень проецирует
            -- их в таблицу до того, как поднимет слушатели. Достижима она ровно в
            -- окне между накатом этой миграции и первым пуском новой версии — и
            -- только у установки, где авторитет величину НЕ НАЗЫВАЛ вовсе:
            -- миграция переносит объявленное, а необъявленное перенести нечем.
            --
            -- Поведение в этом окне — ТОЧНО СЕГОДНЯШНЕЕ: у установки без
            -- объявленной величины каждое создание отвергается и сегодня. Ветвь
            -- сохранена дословно именно поэтому: правка сделала бы окно наката
            -- отличимым от нынешнего состояния, ничего не улучшив.
            DELETE FROM kaname.project_resource_quotas
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            PERFORM kaname.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
            RETURN NULL;
        END IF;

        -- Строка могла быть СНЯТА отзывом величины и заводится теперь заново.
        -- Считать её с нуля нельзя: у принципала уже лежат удостоверения, и
        -- возврат величины подарил бы ему полный потолок сверх имеющегося.
        -- Своя строка исключается — она уже вставлена и будет списана ниже.
        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE %I = $1 AND id <> $2',
            TG_TABLE_SCHEMA, TG_TABLE_NAME, v_carrier_col)
           INTO v_existing
          USING v_carrier, v_row ->> 'id';

        INSERT INTO kaname.project_resource_quotas
            (carrier_type, carrier_id, kind, used, limit_value,
             source_scope, source_scope_id, limit_revision, synced_at, account_id)
        VALUES (v_carrier_type, v_carrier, v_kind, v_existing,
                v_limit, v_scope, v_scope_id, v_revision, now(), v_account)
        ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

        -- Снимок величины обновляется БЕЗУСЛОВНО и ДО списания, а не вместе с
        -- ним. Иначе понижение предела администратором доезжало бы до строки
        -- учёта только при УСПЕШНОМ списании, и отказ называл бы арендатору
        -- прежнее число: «предел 12» там, где предел уже 10. Текст отказа —
        -- часть контракта, и величина в нём обязана быть действующей.
        --
        -- Блокировку строки берёт этот оператор; второй писатель ждёт фиксации
        -- первого и видит его результат — гонку по-прежнему разрешает база.
        UPDATE kaname.project_resource_quotas
           SET limit_value     = v_limit,
               source_scope    = v_scope,
               source_scope_id = v_scope_id,
               limit_revision  = v_revision,
               synced_at       = now(),
               updated_at      = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;

        -- Списание. Условие читает УЖЕ ОБНОВЛЁННЫЙ снимок той же строки.
        UPDATE kaname.project_resource_quotas
           SET used = used + 1, updated_at = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind
           AND used < limit_value;

        IF FOUND THEN
            RETURN NULL;
        END IF;

        PERFORM kaname.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
        RETURN NULL;
    END IF;

    -- ─── Полоса носителя-ЛИЧНОСТИ (потолок числа аккаунтов, #484) ────────────
    -- Сохранена ДОСЛОВНО: смена её поведения здесь была бы правкой чужого
    -- предмета под видом расширения.
    v_owner := v_row ->> 'owner_user_id';

    SELECT u.external_id INTO v_identity
      FROM kaname.users u
     WHERE u.id = v_owner;

    IF v_identity IS NULL OR v_identity = '' THEN
        IF TG_OP = 'INSERT' THEN
            RAISE WARNING 'quota: account % is not counted — its owner % carries no login identity',
                          COALESCE(v_row ->> 'id', '?'), COALESCE(v_owner, '?')
                USING ERRCODE = 'KQ003';
        END IF;
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        UPDATE kaname.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Тот же выбор источника по роли, что и в полосе принципала выше. Носитель
    -- здесь другой (личность, а не принципал), а вопрос «откуда величина» — тот
    -- же, и отвечать на него двумя разными способами было бы двумя местами об
    -- одном предмете.
    IF v_posture THEN
        SELECT oc.limit_value, 'DEFAULT', '', 0
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kaname.own_ceilings oc
         WHERE oc.kind = v_kind;
    ELSE
    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kaname.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';
    END IF;

    IF NOT FOUND THEN
        DELETE FROM kaname.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kaname.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kaname.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    -- СНИМОК ВЕЛИЧИНЫ ОБНОВЛЯЕТСЯ БЕЗУСЛОВНО И ДО СПИСАНИЯ — так же, как в
    -- полосе носителя-принципала выше. Здесь стояло ОДНО утверждение на два
    -- предмета: обновление снимка было СЛИТО со списанием и потому доезжало до
    -- строки учёта только при УСПЕШНОМ списании.
    --
    -- Расхождение двух полос одного механизма никто не решал: соседняя полоса
    -- несла ровно этот фикс и объясняла его комментарием, а эта — нет.
    -- Наблюдаемое следствие: понижение величины отказ НЕ НАЗЫВАЛ — арендатор
    -- читал «предел 5» там, где предел уже 0, то есть отказ отправлял его менять
    -- то, что уже изменено. Текст отказа — часть контракта, и величина в нём
    -- обязана быть действующей.
    --
    -- Блокировку строки берёт этот оператор; второй писатель ждёт фиксации
    -- первого и видит его результат — гонку по-прежнему разрешает база.
    UPDATE kaname.project_resource_quotas
       SET limit_value     = v_limit,
           source_scope    = v_scope,
           source_scope_id = v_scope_id,
           limit_revision  = v_revision,
           synced_at       = now(),
           updated_at      = now()
     WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;

    -- Списание. Условие читает УЖЕ ОБНОВЛЁННЫЙ снимок той же строки.
    UPDATE kaname.project_resource_quotas
       SET used = used + 1, updated_at = now()
     WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind
       AND used < limit_value;

    IF FOUND THEN
        RETURN NULL;
    END IF;

    PERFORM kaname.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
COMMENT ON FUNCTION kaname.kacho_quota_count() IS 'charges one slot on insert and returns it on delete, in the same transaction as the resource row. The SOURCE of the ceiling now depends on the ROLE of the kind: a kind this service OWNS takes its value from kaname.own_ceilings, the projection of the deployment posture; every other kind still takes it from the local authority in kaname.limits. Role is chosen per KIND, not per service: one service owns some kinds and consumes others. Deferred to commit on accounts because the identity is resolved through the owner row, whose foreign key is itself deferred. The snapshot of the ceiling is refreshed unconditionally BEFORE the charge, so a refusal always names the value in force. Refusals come from kacho_quota_refuse, untouched: KQ001 = full, KQ002 = no ceiling stated. An account whose owner carries no login identity is NOT counted and says so with a KQ003 warning';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_quota_carrier_lifecycle() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель выводится из вида по тому же правилу, что и в списании: у
    -- вложенного вида он ЕСТЬ его родительская часть. Два места об одном
    -- предмете здесь разошлись бы молча — строка учёта завелась бы под одним
    -- носителем, а списание искало бы её под другим.
    v_carrier_type text := substring(TG_ARGV[0] from '^(.*)\.[^.]+$');
    v_account      text := '';
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Ноль затронутых строк здесь НЕ отказ: строки учёта могло не быть
        -- (величина отозвана), и удаление принципала не вправе от этого зависеть.
        DELETE FROM kaname.project_resource_quotas
         WHERE carrier_type = v_carrier_type AND carrier_id = OLD.id AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Зеркало аккаунта — только у носителя, принадлежащего ровно одному.
    IF v_carrier_type = 'iam.serviceAccount' THEN
        v_account := COALESCE(NEW.account_id, '');
    END IF;

    -- Строка заводится с НУЛЁМ, и это верно: у нового принципала удостоверений
    -- нет by construction. Уже лежащие покрыты затравкой ниже.
    INSERT INTO kaname.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    SELECT v_carrier_type, NEW.id, v_kind, 0,
           l.limit_value, l.scope, l.scope_id, l.revision, now(), v_account
      FROM kaname.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT'
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    RETURN NULL;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.kacho_quota_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $_$
DECLARE
    v_kind         text := TG_ARGV[0];
    -- Носитель ВЫВОДИТСЯ из вида, а не передаётся отдельным аргументом.
    --
    -- У вложенного вида носитель ЕСТЬ его родительская часть — этого требует
    -- гейт каталога от КАЖДОЙ записи, поэтому вывод здесь не догадка, а чтение
    -- того же правила. Отдельный аргумент был бы вторым местом об одном
    -- предмете и разошёлся бы с каталогом молча.
    --
    -- Плюс цена, замеренная сразу: носитель, стоящий в объявлении триггера
    -- строкой в кавычках, неотличим от ВИДА для гейтов дерева, которые читают
    -- аргументы списания. Два таких гейта объявили `iam.user` и
    -- `iam.serviceAccount` «получившими производителя списания» — то есть форма
    -- записи начала подменять факт.
    v_carrier_type text := CASE
        WHEN array_length(string_to_array(TG_ARGV[0], '.'), 1) = 3
        THEN substring(TG_ARGV[0] from '^(.*)\.[^.]+$')
        ELSE ''
    END;
    v_carrier_col  text := COALESCE(TG_ARGV[1], '');
    v_row          jsonb;
    v_owner        text;
    v_identity     text;
    v_carrier      text;
    v_account      text := '';
    v_existing     bigint;
    v_limit        bigint;
    v_scope        text;
    v_scope_id     text;
    v_revision     bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;

    -- ─── Полоса носителя-ПРИНЦИПАЛА (задача #1191) ───────────────────────────
    IF v_carrier_type <> '' THEN
        v_carrier := v_row ->> v_carrier_col;
        IF v_carrier IS NULL OR v_carrier = '' THEN
            RAISE EXCEPTION 'quota: row of % carries no %', TG_TABLE_NAME, v_carrier_col
                USING ERRCODE = 'KQ003';
        END IF;

        IF TG_OP = 'DELETE' THEN
            -- Возврат — в той же транзакции, что отзыв. GREATEST не даёт уйти
            -- ниже нуля; ноль затронутых строк не отказ (см. lifecycle выше).
            UPDATE kaname.project_resource_quotas
               SET used = GREATEST(used - 1, 0), updated_at = now()
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            RETURN NULL;
        END IF;

        IF v_carrier_type = 'iam.serviceAccount' THEN
            SELECT COALESCE(sa.account_id, '') INTO v_account
              FROM kaname.service_accounts sa WHERE sa.id = v_carrier;
            v_account := COALESCE(v_account, '');
        END IF;

        -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не
        -- «полно». Область аккаунта применима ТОЛЬКО к видам, объявленным
        -- област-ными (`domain.accountScopedKinds`; согласие держит гейт G7):
        -- удостоверение человека действует во всех его аккаунтах, и величина
        -- одного из них управляла бы доступом в чужих.
        SELECT l.limit_value, l.scope, l.scope_id, l.revision
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kaname.limits l
         WHERE l.withdrawn_at IS NULL
           AND l.kind = v_kind
           AND (l.scope = 'DEFAULT'
                OR (l.scope = 'ACCOUNT'
                    AND v_account <> ''
                    AND l.scope_id = v_account
                    AND v_kind IN ('iam.serviceAccount.credential')))
         ORDER BY CASE l.scope WHEN 'ACCOUNT' THEN 2 ELSE 1 END DESC
         LIMIT 1;

        IF NOT FOUND THEN
            -- Строка учёта не вправе пережить авторитет: иначе отказ назвал бы
            -- величину, которой больше нет. Снятие до фиксации не доживёт —
            -- следующий оператор возбуждает исключение.
            DELETE FROM kaname.project_resource_quotas
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            PERFORM kaname.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
            RETURN NULL;
        END IF;

        -- Строка могла быть СНЯТА отзывом величины и заводится теперь заново.
        -- Считать её с нуля нельзя: у принципала уже лежат удостоверения, и
        -- возврат величины подарил бы ему полный потолок сверх имеющегося.
        -- Своя строка исключается — она уже вставлена и будет списана ниже.
        EXECUTE format(
            'SELECT count(*) FROM %I.%I WHERE %I = $1 AND id <> $2',
            TG_TABLE_SCHEMA, TG_TABLE_NAME, v_carrier_col)
           INTO v_existing
          USING v_carrier, v_row ->> 'id';

        INSERT INTO kaname.project_resource_quotas
            (carrier_type, carrier_id, kind, used, limit_value,
             source_scope, source_scope_id, limit_revision, synced_at, account_id)
        VALUES (v_carrier_type, v_carrier, v_kind, v_existing,
                v_limit, v_scope, v_scope_id, v_revision, now(), v_account)
        ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

        -- Снимок величины обновляется БЕЗУСЛОВНО и ДО списания, а не вместе с
        -- ним. Иначе понижение предела администратором доезжало бы до строки
        -- учёта только при УСПЕШНОМ списании, и отказ называл бы арендатору
        -- прежнее число: «предел 12» там, где предел уже 10. Текст отказа —
        -- часть контракта, и величина в нём обязана быть действующей.
        --
        -- Блокировку строки берёт этот оператор; второй писатель ждёт фиксации
        -- первого и видит его результат — гонку по-прежнему разрешает база.
        UPDATE kaname.project_resource_quotas
           SET limit_value     = v_limit,
               source_scope    = v_scope,
               source_scope_id = v_scope_id,
               limit_revision  = v_revision,
               synced_at       = now(),
               updated_at      = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;

        -- Списание. Условие читает УЖЕ ОБНОВЛЁННЫЙ снимок той же строки.
        UPDATE kaname.project_resource_quotas
           SET used = used + 1, updated_at = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind
           AND used < limit_value;

        IF FOUND THEN
            RETURN NULL;
        END IF;

        PERFORM kaname.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
        RETURN NULL;
    END IF;

    -- ─── Полоса носителя-ЛИЧНОСТИ (потолок числа аккаунтов, #484) ────────────
    -- Сохранена ДОСЛОВНО: смена её поведения здесь была бы правкой чужого
    -- предмета под видом расширения.
    v_owner := v_row ->> 'owner_user_id';

    SELECT u.external_id INTO v_identity
      FROM kaname.users u
     WHERE u.id = v_owner;

    IF v_identity IS NULL OR v_identity = '' THEN
        IF TG_OP = 'INSERT' THEN
            RAISE WARNING 'quota: account % is not counted — its owner % carries no login identity',
                          COALESCE(v_row ->> 'id', '?'), COALESCE(v_owner, '?')
                USING ERRCODE = 'KQ003';
        END IF;
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        UPDATE kaname.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kaname.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';

    IF NOT FOUND THEN
        DELETE FROM kaname.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kaname.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kaname.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    UPDATE kaname.project_resource_quotas
       SET used            = used + 1,
           limit_value     = v_limit,
           source_scope    = v_scope,
           source_scope_id = v_scope_id,
           limit_revision  = v_revision,
           synced_at       = now(),
           updated_at      = now()
     WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind
       AND used < v_limit;

    IF FOUND THEN
        RETURN NULL;
    END IF;

    PERFORM kaname.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
INSERT INTO kaname.limits (id, created_at, scope, scope_id, kind, limit_value, withdrawn_at, revision) VALUES
    ('lim-00000000000000032', now(), 'DEFAULT', '', 'iam.account',                    5, NULL, 32),
    ('lim-00000000000000033', now(), 'DEFAULT', '', 'iam.user.credential',           12, NULL, 35),
    ('lim-00000000000000034', now(), 'DEFAULT', '', 'iam.serviceAccount.credential', 24, NULL, 36)
ON CONFLICT DO NOTHING;
-- +goose StatementEnd

-- +goose StatementBegin
-- `Down` возвращает ТРИ УМОЛЧАНИЯ ровно теми величинами, которыми их сеет
-- `0001_initial.sql`. Величины, объявленные ПОСАДКОЙ, обратно не восстанавливаются
-- и восстановиться не могут: они живут в файле настроек, а не в базе, и после
-- откатa их читателя не существует. Величины, назначенные оператором на области
-- `ACCOUNT`/`PROJECT` до наката, тоже не возвращаются — их значения не выводятся
-- ниоткуда, и придумать их значило бы объявить арендатору потолок, которого он не
-- назначал. Оба факта названы здесь, а не умолчаны.
DROP TABLE kaname.own_ceilings;
-- +goose StatementEnd
