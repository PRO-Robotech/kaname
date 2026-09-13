-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Хранилище авторитета величин покидает схему (kaname#58, стадия S4 kacho#2117).
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Авторитет величин снят из службы доступа: контракт, код, маршруты и каталог
-- видов ушли стадией S4. ХРАНИЛИЩЕ осталось целиком — таблица с живыми строками
-- величин ЧУЖИХ доменов, её последовательность, три функции и два триггера на
-- чужих таблицах. Это хуже пустой таблицы: следующий читатель схемы решит, что
-- потолки сети и хранения задаются здесь, тогда как не спрашивает её никто.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПОЧЕМУ СНЯТИЕ ВЕТВИ ЧТЕНИЯ НИЧЕГО НЕ МЕНЯЕТ — ЭТО ЗАМЕР, А НЕ ДОВОД
--
-- Две живые функции доходили до таблицы ветвью `ELSE`, выбираемой по виду:
-- вид, чью величину объявляет посадка, читает `kaname.own_ceilings`, всякий
-- другой — авторитет. Считаемых видов ТРИ, и они перечислены триггерами:
-- `iam.account`, `iam.user.credential`, `iam.serviceAccount.credential`.
-- Ровно эти три объявлены посадочными (`domain.PostureStatedKinds`), и ровно их
-- миграция посадки УДАЛИЛА из авторитета (`DELETE FROM kaname.limits WHERE
-- kind = ANY (posture)`).
--
-- Значит ветвь `ELSE` недостижима не только после первого пуска, но и в окне
-- наката: строки этих трёх видов в таблице нет, и `SELECT` в ней вернул бы
-- `NOT FOUND` — тот же исход, что и её отсутствие. Поведение сохраняется
-- ДОСЛОВНО, включая отказ `KQ002` у установки без объявленной величины.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ПОРЯДОК ОПЕРАТОРОВ НЕСУЩИЙ
--
-- Сначала снимаются ЧИТАТЕЛИ (две функции переписываются), затем триггеры на
-- ЧУЖИХ таблицах, затем сама таблица, и только потом функции предмета.
--
-- Порядок установлен ОТКАЗОМ БАЗЫ, а не рассуждением: функции снимались раньше
-- таблицы, и накат обрывался на `cannot drop function … because other objects
-- depend on it` (SQLSTATE 2BP01) — две из трёх обслуживают триггеры самой
-- таблицы. Читатели при этом обязаны идти ПЕРВЫМИ: функция, оставшаяся со
-- ссылкой на снятую таблицу, собирается и падает на первом вызове, то есть в
-- чужой транзакции арендатора.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ДАННЫЕ ЭТОЙ МИГРАЦИЕЙ НЕ ВОССТАНАВЛИВАЮТСЯ, И ОТКАТ ЭТОГО НЕ ОБЕЩАЕТ
--
-- Обратная половина возвращает СТРОЕНИЕ — таблицу, последовательность, ключ,
-- индексы, три функции и четыре триггера, — и не возвращает строк: их нет
-- откуда взять. Именно поэтому накат стережёт `dropguard`: он отказывает, пока
-- число строк не объявлено, и называет оператору процедуру выгрузки.
-- +goose Up
-- ── 1. ЧИТАТЕЛИ: ветвь авторитета снята, источник величины остаётся один ──
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
    INSERT INTO kaname.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    SELECT v_carrier_type, NEW.id, v_kind, 0,
           oc.limit_value, 'DEFAULT', '', 0, now(), v_account
      FROM kaname.own_ceilings oc
     WHERE oc.kind = v_kind
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
    -- ВЕЛИЧИНУ ЭТОГО ВИДА ОБЪЯВЛЯЕТ ПОСАДКА, а не авторитет величин
    -- (приёмка `KAN-QUOTA-1`, `П25`; задача продукта #2117).
    --
    -- Множество ЗАКРЫТО и стоит здесь ОДНИМ местом: членство читается из
    -- таблицы проекции посадки, а не выписывается вторым списком в теле. Второй
    -- список разошёлся бы с таблицей молча — правку одного видно только тому,
    -- кто в этот день ставит службу.
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;

    -- Роль выбирается ПО ВИДУ, а не по имени службы: одна и та же служба владеет
    -- своими видами и потребляет чужие, и источник величины у них разный.

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
        SELECT oc.limit_value, 'DEFAULT', '', 0
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kaname.own_ceilings oc
         WHERE oc.kind = v_kind;

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
    SELECT oc.limit_value, 'DEFAULT', '', 0
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kaname.own_ceilings oc
     WHERE oc.kind = v_kind;

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
COMMENT ON FUNCTION kaname.kacho_quota_count() IS 'charges one slot on insert and returns it on delete, in the same transaction as the resource row. The ceiling has ONE source: kaname.own_ceilings, the projection of the deployment posture. The local authority it used to fall back to (kaname.limits) is gone — its storage left the schema together with the authority itself, and the three kinds this service counts had already been removed from it, so the fallback could not be reached by any kind. Deferred to commit on accounts because the identity is resolved through the owner row, whose foreign key is itself deferred. The snapshot of the ceiling is refreshed unconditionally BEFORE the charge, so a refusal always names the value in force. Refusals come from kacho_quota_refuse, untouched: KQ001 = full, KQ002 = no ceiling stated. An account whose owner carries no login identity is NOT counted and says so with a KQ003 warning';
-- +goose StatementEnd

-- ── 2. ТРИГГЕРЫ НА ЧУЖИХ ТАБЛИЦАХ ───────────────────────────────────────────
--
-- Они снимаются ОТДЕЛЬНО и раньше таблицы: `DROP TABLE` уносит триггеры самой
-- таблицы, но не те, что висят на `accounts` и `projects`. Оставленные, они
-- ссылались бы на снятую функцию и роняли бы удаление аккаунта и проекта.
DROP TRIGGER IF EXISTS accounts_withdraw_limits_trg ON kaname.accounts;
DROP TRIGGER IF EXISTS projects_withdraw_limits_trg ON kaname.projects;

-- ── 3. САМО ХРАНИЛИЩЕ ───────────────────────────────────────────────────────
--
-- Форма сноса — каноническая для дерева (`DROP TABLE IF EXISTS <схема>.<имя>;`):
-- ровно её узнаёт распознаватель стража, и ровно на ней доказана его способность
-- отказать. Таблица уносит свои индексы и свои триггеры.
DROP TABLE IF EXISTS kaname.limits;

-- ── 4. ФУНКЦИИ ПРЕДМЕТА — ПОСЛЕ таблицы, и это не вкус ──────────────────────
--
-- Две из трёх обслуживают триггеры САМОЙ таблицы, и пока таблица жива, база
-- отказывает: `cannot drop function … because other objects depend on it`
-- (SQLSTATE 2BP01). Прежняя редакция этой миграции снимала функции раньше и
-- падала ровно так — накат обрывался на середине. `CASCADE` здесь не годится:
-- он снял бы вместе с функцией и то, о чём мы не знаем, а предмет снятия обязан
-- быть назван поимённо.
DROP FUNCTION IF EXISTS kaname.limits_withdraw_for_scope_object();
DROP FUNCTION IF EXISTS kaname.limits_stamp_revision();
DROP FUNCTION IF EXISTS kaname.limits_scope_ref_exists();

DROP SEQUENCE IF EXISTS kaname.limits_revision_seq;

-- +goose Down
-- Возвращается СТРОЕНИЕ, а не содержимое: строк взять неоткуда.
CREATE SEQUENCE kaname.limits_revision_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE kaname.limits (
    id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scope text NOT NULL,
    scope_id text DEFAULT ''::text NOT NULL,
    kind text NOT NULL,
    limit_value bigint NOT NULL,
    withdrawn_at timestamp with time zone,
    revision bigint DEFAULT 0 NOT NULL,
    CONSTRAINT limits_id_form_ck CHECK ((id ~ '^lim-[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT limits_kind_form_ck CHECK ((kind ~ '^[a-z][a-z0-9]*\.[a-zA-Z][a-zA-Z0-9]*(\.[a-zA-Z][a-zA-Z0-9]*)?$'::text)),
    CONSTRAINT limits_scope_ck CHECK ((scope = ANY (ARRAY['DEFAULT'::text, 'ACCOUNT'::text, 'PROJECT'::text]))),
    CONSTRAINT limits_scope_subject_ck CHECK ((((scope = 'DEFAULT'::text) AND (scope_id = ''::text)) OR ((scope <> 'DEFAULT'::text) AND (scope_id <> ''::text)))),
    CONSTRAINT limits_value_nonnegative_ck CHECK ((limit_value >= 0))
);

ALTER TABLE ONLY kaname.limits
    ADD CONSTRAINT limits_pkey PRIMARY KEY (id);

CREATE INDEX limits_created_at_id_idx ON kaname.limits USING btree (created_at, id);
CREATE INDEX limits_revision_idx ON kaname.limits USING btree (revision);
CREATE UNIQUE INDEX limits_scope_kind_uk ON kaname.limits USING btree (scope, scope_id, kind) WHERE (withdrawn_at IS NULL);
CREATE INDEX limits_scope_lookup_idx ON kaname.limits USING btree (scope, scope_id) WHERE (withdrawn_at IS NULL);

-- +goose StatementBegin
CREATE FUNCTION kaname.limits_scope_ref_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.scope    = OLD.scope
       AND NEW.scope_id = OLD.scope_id THEN
        RETURN NEW;
    END IF;

    IF NEW.scope = 'DEFAULT' THEN
        RETURN NEW;
    ELSIF NEW.scope = 'ACCOUNT' THEN
        PERFORM 1 FROM kaname.accounts WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Account %s not found', NEW.scope_id);
        END IF;
    ELSIF NEW.scope = 'PROJECT' THEN
        PERFORM 1 FROM kaname.projects WHERE id = NEW.scope_id FOR KEY SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE    = '23503',
                CONSTRAINT = 'limits_scope_ref',
                MESSAGE    = format('Project %s not found', NEW.scope_id);
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument scope %s', NEW.scope);
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.limits_stamp_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.limit_value  IS NOT DISTINCT FROM OLD.limit_value
       AND NEW.withdrawn_at IS NOT DISTINCT FROM OLD.withdrawn_at THEN
        -- Ничего наблюдаемого не изменилось: тянущие не обязаны об этом узнать.
        NEW.revision := OLD.revision;
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('kaname.limits_revision'));
    NEW.revision := nextval('kaname.limits_revision_seq');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.limits_withdraw_for_scope_object() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE kaname.limits
       SET withdrawn_at = now()
     WHERE scope        = TG_ARGV[0]
       AND scope_id     = OLD.id
       AND withdrawn_at IS NULL;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER limits_scope_ref_exists_trg BEFORE INSERT OR UPDATE ON kaname.limits FOR EACH ROW EXECUTE FUNCTION kaname.limits_scope_ref_exists();
CREATE TRIGGER limits_stamp_revision_trg BEFORE INSERT OR UPDATE ON kaname.limits FOR EACH ROW EXECUTE FUNCTION kaname.limits_stamp_revision();
CREATE TRIGGER accounts_withdraw_limits_trg BEFORE DELETE ON kaname.accounts FOR EACH ROW EXECUTE FUNCTION kaname.limits_withdraw_for_scope_object('ACCOUNT');
CREATE TRIGGER projects_withdraw_limits_trg BEFORE DELETE ON kaname.projects FOR EACH ROW EXECUTE FUNCTION kaname.limits_withdraw_for_scope_object('PROJECT');

-- Читатели возвращаются к прежним телам — с ветвью авторитета.
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
