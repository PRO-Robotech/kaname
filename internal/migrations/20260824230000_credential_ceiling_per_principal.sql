-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260824230000_credential_ceiling_per_principal — ПОТОЛОК ЧИСЛА УДОСТОВЕРЕНИЙ
-- НА ПРИНЦИПАЛА.
--
-- Задача `PRO-Robotech/kacho#1191`; приёмка —
-- `services/iam/docs/engineering/acceptance/credential-ceiling-per-principal.md`
-- (вердикт APPROVED, круг 3). Предмет вынесен из фазы базового токена доступа,
-- потому что ломает её аддитивность в обоих прочтениях.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧЕГО НЕ БЫЛО
--
-- Число удостоверений, которые принципал держит одновременно, не ограничено
-- ничем. Каждое — самостоятельный путь входа: пока оно живо, предъявитель
-- действует от имени принципала. Отсутствие потолка не создаёт нагрузочного
-- предмета (это измерено приёмкой базового токена, §8), но создаёт три другие
-- беды: поверхность утечки растёт линейно; стоимость обзора и отзыва при
-- компрометации равна числу строк; накопление идёт за спиной владельца и
-- переживает доступ того, кто накопил.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЧТО ИМЕННО СЧИТАЕТСЯ — И ЭТО СКАЗАНО В ИМЕНИ ВИДА, А НЕ В КОММЕНТАРИИ
--
-- Считаются ВСЕ удостоверения принципала: KEYPAIR, SECRET, FEDERATED, строки
-- прежнего потока — и действующие, и с истёкшим сроком.
--
-- Потолок ставится на РЕСУРС, а не на значение его поля-дискриминатора: у
-- удостоверения один глагол выдачи, один список, один глагол отзыва и одна
-- таблица строк, а вид предъявления — поле внутри него. Счёт по виду
-- предъявления обходится сменой вида, а обходимый потолок хуже отсутствующего:
-- он создаёт впечатление меры.
--
-- Отсюда имена: `iam.user.credential` и `iam.serviceAccount.credential` —
-- `credential`, а не `secret`. Считай мы только новый вид, имя обязано было бы
-- это назвать.
--
-- ИСТЁКШЕЕ УДОСТОВЕРЕНИЕ МЕСТО ЗАНИМАЕТ. Слот освобождает ОТЗЫВ, а не течение
-- времени: события «срок истёк» не существует, и счёт, зависящий от часов, сделал
-- бы потребление расходящимся с тем, что владелец видит в своём перечне.
-- Оплачено запасом в величине (см. посев ниже).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- НОСИТЕЛЬ — САМ ПРИНЦИПАЛ, И ЭТО ОТЛИЧАЕТСЯ ОТ СОСЕДНЕГО ПОТОЛКА ОСОЗНАННО
--
-- Потолок числа аккаунтов считается в ЛИЧНОСТИ (внешнем субъекте входа), и его
-- миграция обосновала это тем, что строка пользователя есть членство. **Это было
-- верно в день записи и перестало быть верным**: ключи уникальности строки
-- пользователя стали ГЛОБАЛЬНЫМИ (по почте — полный, по внешнему субъекту —
-- частичный), а членство выражается собственной таблицей. Второй строки одному
-- человеку схема больше не даёт.
--
-- Поэтому носитель здесь — сама строка принципала, и это лучше внешнего субъекта
-- по трём причинам: счёт ведётся там, где живёт внешний ключ строки
-- удостоверения (без соединения на каждом списании); приглашённый, у которого
-- внешнего субъекта ещё нет, остаётся под потолком; у машины внешнего субъекта
-- нет вовсе, и один принцип на оба ресурса объясняется одной фразой.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОБЛАСТЬ ВЕЛИЧИНЫ РАЗНАЯ У ДВУХ ВИДОВ
--
-- Служебная учётка — ресурс ровно одного аккаунта, и её удостоверения действуют
-- в его границах: величину `ACCOUNT` администратор аккаунта назначает по праву.
-- Человек состоит во МНОГИХ аккаунтах, а его удостоверение действует во всех
-- сразу — величина одного администратора управляла бы числом путей входа в
-- чужих границах. Поэтому для вида человека действует только `DEFAULT`.
--
-- Перечень видов, читающих область аккаунта, объявлен в каталоге
-- (`domain.accountScopedKinds`) и повторён здесь литералом; согласие двух мест
-- держит гейт (G7). Литерал здесь неизбежен — SQL не читает Go, — и потому
-- анкерен, а не оставлен на внимание.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЗЕРКАЛО АККАУНТА: У МАШИНЫ ЕСТЬ, У ЧЕЛОВЕКА ПУСТО
--
-- Ограничение таблицы учёта требует непустой `account_id` у всякого носителя,
-- кроме личности. У служебной учётки он резолвится соединением и заполняется.
-- У человека остаётся ПУСТЫМ: колонка `users.account_id` жива и обязательна, но
-- называет ОДИН аккаунт из многих его членств — записать её значило бы
-- утверждать принадлежность, которой нет. Опираться на неё нельзя и по второй
-- причине: её снимает переход отрыва личности, и читатель цепи областей с неё
-- уже переведён.
--
-- Ограничение поэтому ЗАМЕНЯЕТСЯ (снимается и заводится заново — применённую
-- миграцию не правим), а не ослабляется: у носителей `project`, `account` и
-- `iam.serviceAccount` требование остаётся в силе.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ЗАТРАВКА СЧИТАЕТ УЖЕ ЛЕЖАЩИЕ СТРОКИ — И ЭТО САМОЕ РИСКОВАННОЕ МЕСТО ВЫКАТКИ
--
-- Триггер срабатывает на вставке; по строкам, лежащим до этой миграции, он не
-- сработает by construction. Строка учёта, заведённая с нулём при существующих
-- удостоверениях, подарила бы принципалу полный потолок СВЕРХ имеющегося —
-- молча, потому что выглядит она исправной. Поэтому потребление считается
-- оператором здесь.
--
-- Существующие сверх предела при этом НЕ УДАЛЯЮТСЯ: состояние «потребление
-- больше предела» выразимо (ограничение таблицы его не запрещает) и означает
-- «выпускать больше нельзя», а не «что-то надо снять».

-- +goose Up
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- -----------------------------------------------------------------------------
-- Носители учёта: два новых.
-- -----------------------------------------------------------------------------
ALTER TABLE kacho_iam.project_resource_quotas
    DROP CONSTRAINT IF EXISTS project_resource_quotas_carrier_ck;
ALTER TABLE kacho_iam.project_resource_quotas
    ADD CONSTRAINT project_resource_quotas_carrier_ck
    CHECK (carrier_type IN ('project', 'account', 'identity', 'iam.user', 'iam.serviceAccount')
           AND carrier_id <> '');

ALTER TABLE kacho_iam.project_resource_quotas
    DROP CONSTRAINT IF EXISTS project_resource_quotas_account_mirror_ck;
ALTER TABLE kacho_iam.project_resource_quotas
    ADD CONSTRAINT project_resource_quotas_account_mirror_ck
    CHECK ((carrier_type IN ('identity', 'iam.user')     AND account_id =  '')
        OR (carrier_type NOT IN ('identity', 'iam.user') AND account_id <> ''));

COMMENT ON CONSTRAINT project_resource_quotas_account_mirror_ck
    ON kacho_iam.project_resource_quotas IS
    'the account mirror is required of every carrier that BELONGS to exactly one '
    'account. The login identity has no account, and a person belongs to many: '
    'writing one of them would state a membership that does not hold. A service '
    'account belongs to exactly one, and carries it';

-- -----------------------------------------------------------------------------
-- Величины умолчания.
-- -----------------------------------------------------------------------------
-- Десять у человека и двадцать у машины. Обе выведены как «типичное
-- одновременное использование, умноженное на два», и множитель назван, а не
-- спрятан в числе: он существует ровно потому, что истёкшие удостоверения
-- занимают места. Появится автоматическое их снятие — величины пересматриваются
-- вниз, до одновременного использования.
INSERT INTO kacho_iam.limits (id, scope, scope_id, kind, limit_value) VALUES
    ('lim-00000000000000033', 'DEFAULT', '', 'iam.user.credential',           10),
    ('lim-00000000000000034', 'DEFAULT', '', 'iam.serviceAccount.credential', 20)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Строка учёта носителя заводится и снимается ВМЕСТЕ с ним.
-- -----------------------------------------------------------------------------
-- В той же транзакции, что сам принципал, — поэтому у строки всегда есть
-- производитель, и её отсутствие означает не «ещё не спросили», а «принципал
-- заведён до появления этой оси либо величина отозвана».
CREATE OR REPLACE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle()
RETURNS trigger
LANGUAGE plpgsql
AS $$
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
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = v_carrier_type AND carrier_id = OLD.id AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Зеркало аккаунта — только у носителя, принадлежащего ровно одному.
    IF v_carrier_type = 'iam.serviceAccount' THEN
        v_account := COALESCE(NEW.account_id, '');
    END IF;

    -- Строка заводится с НУЛЁМ, и это верно: у нового принципала удостоверений
    -- нет by construction. Уже лежащие покрыты затравкой ниже.
    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    SELECT v_carrier_type, NEW.id, v_kind, 0,
           l.limit_value, l.scope, l.scope_id, l.revision, now(), v_account
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT'
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION kacho_iam.kacho_quota_carrier_lifecycle() IS
    'creates and removes the accounting row of a PRINCIPAL carrier in the same '
    'transaction as the principal itself, so the row always has a producer. '
    'Neither arm can refuse: a missing row is zero affected rows, not an error — '
    'otherwise a person holding credentials would become undeletable';

-- -----------------------------------------------------------------------------
-- Списание — теперь по ДВУМ семействам носителей.
-- -----------------------------------------------------------------------------
-- Тело заменяется целиком (`CREATE OR REPLACE`): применённую миграцию править
-- нельзя (ban #5). Прежний триггер аккаунтов зовёт функцию с ОДНИМ аргументом,
-- и его ветвь ниже сохранена дословно — второй аргумент у него пуст.
CREATE OR REPLACE FUNCTION kacho_iam.kacho_quota_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
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
            UPDATE kacho_iam.project_resource_quotas
               SET used = GREATEST(used - 1, 0), updated_at = now()
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            RETURN NULL;
        END IF;

        IF v_carrier_type = 'iam.serviceAccount' THEN
            SELECT COALESCE(sa.account_id, '') INTO v_account
              FROM kacho_iam.service_accounts sa WHERE sa.id = v_carrier;
            v_account := COALESCE(v_account, '');
        END IF;

        -- Авторитет читается ПЕРВЫМ: его отсутствие — отдельный исход, а не
        -- «полно». Область аккаунта применима ТОЛЬКО к видам, объявленным
        -- област-ными (`domain.accountScopedKinds`; согласие держит гейт G7):
        -- удостоверение человека действует во всех его аккаунтах, и величина
        -- одного из них управляла бы доступом в чужих.
        SELECT l.limit_value, l.scope, l.scope_id, l.revision
          INTO v_limit, v_scope, v_scope_id, v_revision
          FROM kacho_iam.limits l
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
            DELETE FROM kacho_iam.project_resource_quotas
             WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;
            PERFORM kacho_iam.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
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

        INSERT INTO kacho_iam.project_resource_quotas
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
        UPDATE kacho_iam.project_resource_quotas
           SET limit_value     = v_limit,
               source_scope    = v_scope,
               source_scope_id = v_scope_id,
               limit_revision  = v_revision,
               synced_at       = now(),
               updated_at      = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind;

        -- Списание. Условие читает УЖЕ ОБНОВЛЁННЫЙ снимок той же строки.
        UPDATE kacho_iam.project_resource_quotas
           SET used = used + 1, updated_at = now()
         WHERE carrier_type = v_carrier_type AND carrier_id = v_carrier AND kind = v_kind
           AND used < limit_value;

        IF FOUND THEN
            RETURN NULL;
        END IF;

        PERFORM kacho_iam.kacho_quota_refuse(v_carrier_type, v_carrier, v_kind);
        RETURN NULL;
    END IF;

    -- ─── Полоса носителя-ЛИЧНОСТИ (потолок числа аккаунтов, #484) ────────────
    -- Сохранена ДОСЛОВНО: смена её поведения здесь была бы правкой чужого
    -- предмета под видом расширения.
    v_owner := v_row ->> 'owner_user_id';

    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
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
        UPDATE kacho_iam.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';

    IF NOT FOUND THEN
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    UPDATE kacho_iam.project_resource_quotas
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

    PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$$;

-- -----------------------------------------------------------------------------
-- Затравка: строки учёта по УЖЕ существующим принципалам.
-- -----------------------------------------------------------------------------
-- Потребление считается ОПЕРАТОРОМ, а не оставляется триггеру: по строкам,
-- лежащим до этой миграции, он не сработает by construction.
INSERT INTO kacho_iam.project_resource_quotas
    (carrier_type, carrier_id, kind, used, limit_value,
     source_scope, source_scope_id, limit_revision, synced_at, account_id)
SELECT 'iam.user', u.id, 'iam.user.credential', COALESCE(c.n, 0),
       l.limit_value, l.scope, l.scope_id, l.revision, now(), ''
  FROM kacho_iam.users u
  LEFT JOIN (SELECT user_id, count(*) AS n
               FROM kacho_iam.user_oauth_clients GROUP BY user_id) c ON c.user_id = u.id
 CROSS JOIN LATERAL (
       SELECT limit_value, scope, scope_id, revision
         FROM kacho_iam.limits
        WHERE withdrawn_at IS NULL AND kind = 'iam.user.credential' AND scope = 'DEFAULT') l
ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

INSERT INTO kacho_iam.project_resource_quotas
    (carrier_type, carrier_id, kind, used, limit_value,
     source_scope, source_scope_id, limit_revision, synced_at, account_id)
SELECT 'iam.serviceAccount', sa.id, 'iam.serviceAccount.credential', COALESCE(c.n, 0),
       l.limit_value, l.scope, l.scope_id, l.revision, now(), sa.account_id
  FROM kacho_iam.service_accounts sa
  LEFT JOIN (SELECT sva_id, count(*) AS n
               FROM kacho_iam.service_account_oauth_clients GROUP BY sva_id) c ON c.sva_id = sa.id
 CROSS JOIN LATERAL (
       SELECT limit_value, scope, scope_id, revision
         FROM kacho_iam.limits
        WHERE withdrawn_at IS NULL AND kind = 'iam.serviceAccount.credential' AND scope = 'DEFAULT') l
 WHERE sa.account_id <> ''
ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Триггеры.
-- -----------------------------------------------------------------------------
DROP TRIGGER IF EXISTS users_quota_carrier_credential ON kacho_iam.users;
CREATE TRIGGER users_quota_carrier_credential
    AFTER INSERT OR DELETE ON kacho_iam.users
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle(
        'iam.user.credential');

DROP TRIGGER IF EXISTS service_accounts_quota_carrier_credential ON kacho_iam.service_accounts;
CREATE TRIGGER service_accounts_quota_carrier_credential
    AFTER INSERT OR DELETE ON kacho_iam.service_accounts
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_carrier_lifecycle(
        'iam.serviceAccount.credential');

DROP TRIGGER IF EXISTS user_oauth_clients_quota_count ON kacho_iam.user_oauth_clients;
CREATE TRIGGER user_oauth_clients_quota_count
    AFTER INSERT OR DELETE ON kacho_iam.user_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count(
        'iam.user.credential', 'user_id');

DROP TRIGGER IF EXISTS sa_oauth_clients_quota_count ON kacho_iam.service_account_oauth_clients;
CREATE TRIGGER sa_oauth_clients_quota_count
    AFTER INSERT OR DELETE ON kacho_iam.service_account_oauth_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count(
        'iam.serviceAccount.credential', 'sva_id');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

DROP TRIGGER IF EXISTS user_oauth_clients_quota_count ON kacho_iam.user_oauth_clients;
DROP TRIGGER IF EXISTS sa_oauth_clients_quota_count ON kacho_iam.service_account_oauth_clients;
DROP TRIGGER IF EXISTS users_quota_carrier_credential ON kacho_iam.users;
DROP TRIGGER IF EXISTS service_accounts_quota_carrier_credential ON kacho_iam.service_accounts;
DROP FUNCTION IF EXISTS kacho_iam.kacho_quota_carrier_lifecycle();

DELETE FROM kacho_iam.project_resource_quotas
 WHERE carrier_type IN ('iam.user', 'iam.serviceAccount');
DELETE FROM kacho_iam.limits
 WHERE id IN ('lim-00000000000000033', 'lim-00000000000000034');

-- Ограничения возвращаются к той форме, какая стояла ДО этой миграции: откат,
-- оставляющий другую форму, тихо сменил бы правило вместо того, чтобы его
-- вернуть.
ALTER TABLE kacho_iam.project_resource_quotas
    DROP CONSTRAINT IF EXISTS project_resource_quotas_account_mirror_ck;
ALTER TABLE kacho_iam.project_resource_quotas
    ADD CONSTRAINT project_resource_quotas_account_mirror_ck
    CHECK ((carrier_type =  'identity' AND account_id =  '')
        OR (carrier_type <> 'identity' AND account_id <> ''));

ALTER TABLE kacho_iam.project_resource_quotas
    DROP CONSTRAINT IF EXISTS project_resource_quotas_carrier_ck;
ALTER TABLE kacho_iam.project_resource_quotas
    ADD CONSTRAINT project_resource_quotas_carrier_ck
    CHECK (carrier_type IN ('project', 'account', 'identity') AND carrier_id <> '');

-- Тело списания возвращается к однополосной форме прежней миграции: две полосы
-- при снятых триггерах безвредны, но откат обязан ВЕРНУТЬ, а не оставить.
CREATE OR REPLACE FUNCTION kacho_iam.kacho_quota_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_kind     text := TG_ARGV[0];
    v_row      jsonb;
    v_owner    text;
    v_identity text;
    v_limit    bigint;
    v_scope    text;
    v_scope_id text;
    v_revision bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_row := to_jsonb(OLD);
    ELSE
        v_row := to_jsonb(NEW);
    END IF;
    v_owner := v_row ->> 'owner_user_id';

    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
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
        UPDATE kacho_iam.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';

    IF NOT FOUND THEN
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    UPDATE kacho_iam.project_resource_quotas
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

    PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
