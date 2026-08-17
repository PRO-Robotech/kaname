-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- =============================================================================
-- Потолок на число аккаунтов ОДНОЙ личности.
-- =============================================================================
-- Задача `PRO-Robotech/kacho#484`.
--
-- ЧЕГО НЕ БЫЛО. Над аккаунтом не стояло потолка ни одного. Аккаунт — корень
-- аренды и заводится самообслуживанием, поэтому ЛЮБОЕ ограничение внутри
-- аккаунта обходилось заведением второго: второй комплект пределов доставался
-- тем же действием, которым получен первый.
--
-- Это измерено, а не предположено: на дереве до этой миграции одна личность
-- заводила шесть аккаунтов подряд и ни один не был отвергнут. `owner_user_id` не
-- несёт уникальности (и не должен — строка пользователя законно владеет многими
-- аккаунтами), а имя аккаунта случайно, поэтому глобальная уникальность имени
-- ничего не ограничивала.
--
-- НОСИТЕЛЬ — ЛИЧНОСТЬ, и это не выбор из удобства. Носитель обязан быть ВНЕШНИМ
-- по отношению к предмету счёта: аккаунт нельзя считать в аккаунте, а проекта у
-- него нет. Личность — единственное, что существует до аккаунта и переживает
-- его. Потолок платформы был бы дешевле и негоден как единственная мера: отказ
-- по нему приходит СЛЕДУЮЩЕМУ честному человеку, а не тому, кто исчерпал полку.
--
-- ЛИЧНОСТЬ — ЭТО ВНЕШНИЙ ИДЕНТИФИКАТОР ВХОДА, а не строка пользователя. Строка
-- пользователя есть ЧЛЕНСТВО: она привязана к одному аккаунту, и один человек
-- законно держит по строке на каждый свой аккаунт. Считать по строке значило бы
-- привязать потолок ровно к тому, что размножается при снятии этой привязки, —
-- то есть выдать обход вместе с изменением, которое потолок обязан пережить.
--
-- ПОЧЕМУ ЭТО ТРИГГЕР, А НЕ ПРОВЕРКА В USE-CASE. Аккаунт заводится ДВУМЯ путями:
-- явным созданием и первым входом (личная область заводится сама, если у
-- человека ещё нет ни одного аккаунта). Проверка в коде обязана была бы стоять в
-- обоих и разошлась бы на третьем; триггер стоит на ТАБЛИЦЕ и потому верен для
-- каждого писателя, включая будущего. Плюс «посчитал → вставил» есть
-- check-then-act через границу оператора: между чтением и вставкой помещается
-- чужая запись, и оба создателя видят одно и то же свободное место (ban #10).
--
-- ОТКАЗ ПРИХОДИТ ДО ФИКСАЦИИ, а не до вставки, и это следствие устройства схемы,
-- а не послабление: личность резолвится строкой владельца, чей внешний ключ сам
-- отложен до фиксации. Строки аккаунта не остаётся ни при каком исходе.
--
-- ПЕРВЫЙ ВХОД НЕ ЛОМАЕТСЯ. Личная область заводится только когда у личности НОЛЬ
-- аккаунтов, а ноль меньше любого назначенного потолка. Отказ на этом пути
-- достижим ровно в одном случае — потолок снят администратором совсем, и тогда
-- «не сказано = отказ» действует так же, как у всех прочих видов платформы.

-- +goose Up
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

-- -----------------------------------------------------------------------------
-- Строки учёта. Та же таблица, что у пяти прочих владельцев.
-- -----------------------------------------------------------------------------
-- Форма повторяет их не ради симметрии: единственный производитель отказа
-- (`kacho_quota_refuse`, файл 484001) читает ИМЕННО эти столбцы, и своя форма
-- здесь означала бы шестую копию контракта отказа.
--
-- Отличие ровно одно и оно про носитель: `carrier_type` здесь принимает
-- `identity`, а `carrier_id` — внешний идентификатор входа.
CREATE TABLE IF NOT EXISTS kacho_iam.project_resource_quotas (
    carrier_type    text        NOT NULL,
    carrier_id      text        NOT NULL,
    kind            text        NOT NULL,

    -- Потребление. Пишет ТОЛЬКО триггер ниже: Go-путь, способный его записать,
    -- сделал бы расхождение счётчика с тем, что он считает, выразимым.
    used            bigint      NOT NULL DEFAULT 0,

    -- Снимок величины. У владельца величин он обновляется В ТОЙ ЖЕ транзакции,
    -- что списание (авторитет лежит в этой же базе), поэтому устареть не может
    -- by construction — и курсора дельты этому владельцу не нужно.
    limit_value     bigint      NOT NULL,
    source_scope    text        NOT NULL,
    source_scope_id text        NOT NULL DEFAULT '',
    limit_revision  bigint      NOT NULL DEFAULT 0,
    synced_at       timestamptz,

    -- Зеркало аккаунта. У носителя-личности аккаунта нет by construction:
    -- личность существует ДО него. Пусто здесь означает «неприменимо», а не
    -- «забыли», и это сказано ограничением ниже, а не комментарием.
    account_id      text        NOT NULL DEFAULT '',

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT project_resource_quotas_pkey PRIMARY KEY (carrier_type, carrier_id, kind),
    CONSTRAINT project_resource_quotas_used_ck   CHECK (used >= 0),
    CONSTRAINT project_resource_quotas_limit_ck  CHECK (limit_value >= 0),
    CONSTRAINT project_resource_quotas_scope_ck  CHECK (source_scope IN ('DEFAULT', 'ACCOUNT', 'PROJECT')),
    CONSTRAINT project_resource_quotas_carrier_ck
        CHECK (carrier_type IN ('project', 'account', 'identity') AND carrier_id <> ''),
    -- Носитель-личность аккаунта не имеет; всякий другой носитель обязан нести
    -- зеркало, иначе аккаунтная дельта его не найдёт и он проживёт со старой
    -- величиной, выглядя исправным.
    CONSTRAINT project_resource_quotas_account_mirror_ck
        CHECK ((carrier_type =  'identity' AND account_id =  '')
            OR (carrier_type <> 'identity' AND account_id <> ''))
);

COMMENT ON TABLE kacho_iam.project_resource_quotas IS
    'resource-count accounting rows of the limit owner. iam is the only service '
    'that both states values and charges one of them: the accounts it counts live '
    'in this database, so the charge shares the transaction with the insert and '
    'the snapshot is refreshed from the authority in that same statement';

COMMENT ON COLUMN kacho_iam.project_resource_quotas.carrier_id IS
    'for carrier_type=identity this is the external login subject '
    '(users.external_id), NOT a user row id: a user row is a membership scoped to '
    'one account, and counting per membership would hand out the bypass';

-- -----------------------------------------------------------------------------
-- Величина умолчания.
-- -----------------------------------------------------------------------------
-- Пять аккаунтов на личность — решение владельца. Ставится как DEFAULT, то есть
-- тем же механизмом, которым администратор облака меняет любой другой потолок.
--
-- Личностной области у величины нет: словарь областей знает DEFAULT, ACCOUNT и
-- PROJECT, и ни одна из двух последних к личности не применима. Личный потолок
-- отдельному человеку сегодня не выразим — это названо предметом, а не обещано.
INSERT INTO kacho_iam.limits (id, scope, scope_id, kind, limit_value) VALUES
    ('lim-00000000000000032', 'DEFAULT', '', 'iam.account', 5)
ON CONFLICT (id) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Затравка строк учёта по УЖЕ существующим аккаунтам.
-- -----------------------------------------------------------------------------
-- Заводится ЗДЕСЬ, а не первым списанием, и это несущее решение.
--
-- Триггер ниже умеет ровно ±1 и заводит строку с НУЛЁМ. Ноль верен только для
-- личности, у которой аккаунтов ещё не было; для всех прочих его пришлось бы
-- считать на лету — а под вставкой нескольких аккаунтов одной транзакцией счёт
-- «сколько их сейчас» уже включает вставляемые, и первое же срабатывание учло бы
-- их дважды. Затравка снимает этот случай целиком: после неё «строки нет»
-- означает ровно «аккаунтов не было».
INSERT INTO kacho_iam.project_resource_quotas
    (carrier_type, carrier_id, kind, used, limit_value,
     source_scope, source_scope_id, limit_revision, synced_at, account_id)
SELECT 'identity', u.external_id, 'iam.account', count(*),
       l.limit_value, l.scope, l.scope_id, l.revision, now(), ''
  FROM kacho_iam.accounts a
  JOIN kacho_iam.users u ON u.id = a.owner_user_id
 CROSS JOIN LATERAL (
       SELECT limit_value, scope, scope_id, revision
         FROM kacho_iam.limits
        WHERE withdrawn_at IS NULL AND kind = 'iam.account' AND scope = 'DEFAULT') l
 WHERE u.external_id <> ''
 GROUP BY u.external_id, l.limit_value, l.scope, l.scope_id, l.revision
ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

-- -----------------------------------------------------------------------------
-- Списание.
-- -----------------------------------------------------------------------------
-- ОТЛОЖЕННЫЙ ограничительный триггер, а не BEFORE, и причина не в стиле.
--
-- Личность резолвится строкой владельца, а внешний ключ на владельца объявлен
-- `DEFERRABLE INITIALLY DEFERRED` — то есть схема ЯВНО разрешает вставить аккаунт
-- раньше его пользователя и сойтись на фиксации. Триггер, срабатывающий сразу,
-- этот порядок ломает: он не находит владельца и отвергает вставку, которую
-- схема считает законной. Это не гипотеза — так устроены существующие фикстуры,
-- и первая же из них покраснела.
--
-- Отложенный триггер срабатывает там же, где проверяется внешний ключ, поэтому
-- владелец к этому моменту виден при любом порядке. Отказ приходит ДО ФИКСАЦИИ:
-- строки аккаунта не остаётся ни при каком исходе, и наблюдаемое для вызывающего
-- то же самое. Сказано это здесь потому, что «до записи» и «до фиксации» — разные
-- утверждения, и второе слабее ровно на одно: между ними строка видна СВОЕЙ же
-- транзакции.
--
-- Блокировка строки учёта берётся тем же единственным оператором, что и раньше,
-- поэтому гонка разрешается базой, а не порядком срабатываний.
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

    -- Личность берётся РЕЗОЛВОМ строки владельца в этой же базе — соединением, а
    -- не денормализованным столбцом. Столбец пришлось бы поддерживать в согласии
    -- со строкой пользователя, и разошёлся бы он молча.
    SELECT u.external_id INTO v_identity
      FROM kacho_iam.users u
     WHERE u.id = v_owner;

    -- Владелец БЕЗ личности — законное состояние схемы, а не дефект: строка
    -- пользователя в состоянии приглашения внешнего идентификатора не несёт
    -- (ограничение `users_invite_status_consistency` этого прямо требует), а
    -- внешний ключ аккаунта на владельца её принимает.
    --
    -- Такой аккаунт НЕ СЧИТАЕТСЯ, и это решение, а не упущение. Отвергнуть его
    -- значило бы изменить то, ЧТО ПЛАТФОРМА ПРИНИМАЕТ, — под видом счёта; счётчик
    -- не вправе запрещать состояния, которых схема не запрещает.
    --
    -- Обходом это не является: самообслуживаемое создание выводит владельца из
    -- ПРОВЕРЕННОГО принципала, а тот по построению вошёл, то есть личность несёт.
    -- Аккаунт без личности достижим только тем путём, которого у арендатора нет.
    --
    -- И оно НЕ МОЛЧАЛИВОЕ. Мягкий пропуск, о котором не слышно, — это дыра,
    -- которая живёт ровно столько, сколько никто не смотрит; предупреждение
    -- называет предмет в тот момент, когда он возникает.
    IF v_identity IS NULL OR v_identity = '' THEN
        IF TG_OP = 'INSERT' THEN
            RAISE WARNING 'quota: account % is not counted — its owner % carries no login identity',
                          COALESCE(v_row ->> 'id', '?'), COALESCE(v_owner, '?')
                USING ERRCODE = 'KQ003';
        END IF;
        RETURN NULL;
    END IF;

    IF TG_OP = 'DELETE' THEN
        -- Возврат — в той же транзакции, что удаление. GREATEST не даёт уйти
        -- ниже нуля, если строка учёта заведена позже самих аккаунтов.
        UPDATE kacho_iam.project_resource_quotas
           SET used = GREATEST(used - 1, 0), updated_at = now()
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        RETURN NULL;
    END IF;

    -- Авторитет читается ПЕРВЫМ, потому что его отсутствие — отдельный исход, а
    -- не «полно». Снят потолок — строка учёта не вправе его пережить: иначе отказ
    -- назвал бы величину, которой больше нет, вместо «не сказано».
    SELECT l.limit_value, l.scope, l.scope_id, l.revision
      INTO v_limit, v_scope, v_scope_id, v_revision
      FROM kacho_iam.limits l
     WHERE l.withdrawn_at IS NULL AND l.kind = v_kind AND l.scope = 'DEFAULT';

    IF NOT FOUND THEN
        -- Снятие строки здесь НЕ доживёт до фиксации: следующий оператор
        -- возбуждает исключение, и транзакция откатывается целиком. Оно нужно
        -- ровно затем, чтобы единственный производитель отказа увидел ту же
        -- картину, что и на свежей личности, и дал `KQ002` («потолок не назван»),
        -- а не `KQ001` с числом, которого больше нет.
        DELETE FROM kacho_iam.project_resource_quotas
         WHERE carrier_type = 'identity' AND carrier_id = v_identity AND kind = v_kind;
        PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
        RETURN NULL;
    END IF;

    -- Строка заводится с НУЛЁМ, и это верно: затравка выше покрыла всех, у кого
    -- аккаунты уже были, поэтому «строки нет» означает «аккаунтов не было».
    INSERT INTO kacho_iam.project_resource_quotas
        (carrier_type, carrier_id, kind, used, limit_value,
         source_scope, source_scope_id, limit_revision, synced_at, account_id)
    VALUES ('identity', v_identity, v_kind, 0,
            v_limit, v_scope, v_scope_id, v_revision, now(), '')
    ON CONFLICT (carrier_type, carrier_id, kind) DO NOTHING;

    -- Списание. Единственный оператор, берущий блокировку строки: второй писатель
    -- ждёт коммита первого и видит его результат. Снимок величины обновляется
    -- ЗДЕСЬ ЖЕ — авторитет в этой же базе, поэтому отставания снимка у владельца
    -- величин не существует как понятия, и догоняющего ему не нужно.
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

    -- Ноль строк — два разных состояния, и разбирает их единственный
    -- производитель отказа. Это не check-then-act: решение уже принято атомарным
    -- оператором выше, и последующее чтение только классифицирует случившееся.
    PERFORM kacho_iam.kacho_quota_refuse('identity', v_identity, v_kind);
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION kacho_iam.kacho_quota_count() IS
    'charges one slot on insert and returns it on delete, in the same transaction '
    'as the account row. Deferred to commit because the identity is resolved '
    'through the owner row, whose foreign key is itself deferred — the schema '
    'allows the account to be inserted first. The snapshot of the ceiling is '
    'refreshed from the local authority in the charging statement: the limit owner '
    'has no delta to catch up with. Refusals come from kacho_quota_refuse: KQ001 = '
    'full, KQ002 = no ceiling stated. An account whose owner carries no login '
    'identity is NOT counted and says so with a KQ003 warning: refusing it would '
    'change what the platform accepts under the guise of counting';

DROP TRIGGER IF EXISTS accounts_quota_count ON kacho_iam.accounts;
CREATE CONSTRAINT TRIGGER accounts_quota_count
    AFTER INSERT OR DELETE ON kacho_iam.accounts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.kacho_quota_count('iam.account');
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SET search_path TO kacho_iam, public;

DROP TRIGGER IF EXISTS accounts_quota_count ON kacho_iam.accounts;
DROP FUNCTION IF EXISTS kacho_iam.kacho_quota_count();
DELETE FROM kacho_iam.limits WHERE id = 'lim-00000000000000032';
DROP TABLE IF EXISTS kacho_iam.project_resource_quotas;
-- +goose StatementEnd
