-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1
--
-- 20260824210000_basic_access_token_credential_kind — ВИД УДОСТОВЕРЕНИЯ И ХЕШ
-- БАЗОВОГО СЕКРЕТА (задача #1142, приёмка BAT-1 §4).
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ПРЕДМЕТ
--
-- Платформа заводит второй вид удостоверения — однострочный непрозрачный
-- секрет, предъявляемый как есть. Его инварианты обязан произносить ОПЕРАТОР
-- БАЗЫ, а не проверка в коде (ban #10): «у секрета нет ключевого материала»,
-- «бессрочного секрета не бывает», «в хранилище нет ни одной колонки, откуда
-- секрет восстановим».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- СЛОВАРЬ ЗАКРЫТ, ЧЕТЫРЁХЗНАЧЕН И НЕ ОДИНАКОВ У ДВУХ ТАБЛИЦ
--
-- KEYPAIR · SECRET · FEDERATED · LEGACY — у служебной учётки.
-- KEYPAIR · SECRET ·             LEGACY — у личности: федеративного вида у неё
-- нет BY CONSTRUCTION, в её контракте нет поля, которым он задаётся. Допустить
-- четвёртое значение там, где оно недостижимо, значило бы объявить состояние,
-- у которого нет ни входа, ни производителя.
--
-- LEGACY ОПИСЫВАЕТ, НО НЕ ВЫДАЁТСЯ. Среди уже лежащих строк есть форма без
-- ключевого материала и без перечня доверенных субъектов — удостоверение
-- прежнего потока. Она существует независимо от того, назвали мы её или нет;
-- отнести её к KEYPAIR значило бы записать в колонку вида ЛОЖНОЕ значение и
-- получить строку, которая по своему виду обязана нести материал и не несёт
-- его. Предикат снятия элемента словаря: строк этого вида в обеих таблицах
-- ноль.
--
-- ─────────────────────────────────────────────────────────────────────────────
-- ОБРАТНОЕ ЗАПОЛНЕНИЕ — ЧЕТЫРЬМЯ ВЕТВЯМИ, И ЧЕТВЁРТАЯ ОБЯЗАТЕЛЬНА
--
-- Двузначный классификатор над четырёхформенным корпусом отдаёт входу, которому
-- не находится вида, ЧУЖОЙ вид молча — «корзина прочее» наоборот, и она опаснее
-- обычной, потому что выглядит решением. Правило вывода по содержимому живёт
-- ровно на ЭТОМ пути и после него не применяется никогда: дальше вид
-- ЗАПИСЫВАЕТСЯ, а читателем не вычисляется.
--
-- Перепись печатает число строк ПО КАЖДОМУ виду, а не общее: одно число не
-- отличает «LEGACY не встретилось» от «LEGACY не искали».
--
-- ─────────────────────────────────────────────────────────────────────────────
-- КОЛОНКА ЗЕРКАЛА У ПОСТАВЩИКА: ОСЛАБЛЕНИЕ ЧАСТИЧНОЕ, А НЕ СНЯТИЕ
--
-- `hydra_client_id` описывает регистрацию у внешнего поставщика, а у вида
-- SECRET такой регистрации нет by construction — в этом и состоит предмет
-- фазы. Форма правки не изобретается: она зеркалит уже применённую к таблице
-- личности (20260823180500). Уникальность колонки сохраняется — она продолжает
-- делить домен настоящих зеркал и НЕ получает синтетических значений.
--
-- Асимметрия двух таблиц ИЗМЕРЕНА, а не выведена по аналогии:
--   * у служебной учётки колонка непуста ВСЕГДА — на переведённом контуре в неё
--     кладётся наш собственный идентификатор строки, и докерная полоса ищет
--     строку по нему. Поэтому «не-SECRET ⇒ значение есть» здесь ИСТИННО, и
--     ограничение его закрепляет: ослабили ≠ сняли;
--   * у личности выдача зеркала не заводит с #1121 (`doIssue`: «Зеркало
--     поставщика ПУСТО»). Требовать там значение у KEYPAIR значило бы задним
--     числом объявить негодным то, что было годным, — и сломать выдачу.
-- Требование поэтому ставится ровно там, где оно верно.

-- ─────────────────────────────────────────────────────────────────────────────
-- ОБРАТНЫЙ ХОД ОТКАЗЫВАЕТСЯ, А НЕ УДАЛЯЕТ
--
-- Откат описан как ШТАТНАЯ процедура развёртывания, поэтому предупреждения
-- здесь недостаточно: комментарий не читают в момент набора команды и он ничего
-- не останавливает. Обратный ход, встретив хоть одну строку вида SECRET,
-- ОТКАЗЫВАЕТСЯ выполняться — до первого разрушающего оператора — и называет
-- последствие: секрет показан один раз, в хранилище только свёртка, удалённое
-- удостоверение не восстановимо ни резервной копией, ни повторной выдачей.
-- Без строк этого вида откат проходит ровно как прежде. Разбор — у самого
-- стража, в начале секции обратного хода ниже. (Разметку goose эта строка
-- намеренно НЕ цитирует: аннотация распознаётся в любом комментарии, и цитата
-- сделала бы файл неразбираемым.)

-- +goose Up
-- +goose StatementBegin

ALTER TABLE kacho_iam.service_account_oauth_clients
    ADD COLUMN credential_kind text,
    ADD COLUMN secret_hash bytea DEFAULT ''::bytea NOT NULL;

ALTER TABLE kacho_iam.user_oauth_clients
    ADD COLUMN credential_kind text,
    ADD COLUMN secret_hash bytea DEFAULT ''::bytea NOT NULL;

COMMENT ON COLUMN kacho_iam.service_account_oauth_clients.credential_kind IS
    'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется. LEGACY описывает строки прежнего потока и не выдаётся ни одним глаголом.';
COMMENT ON COLUMN kacho_iam.service_account_oauth_clients.secret_hash IS
    'sha256 по идентификатору строки И секретной части вместе, 32 байта. Сам секрет не хранится нигде: он существует только в теле ответа, полученного вызывающим выдачи.';
COMMENT ON COLUMN kacho_iam.user_oauth_clients.credential_kind IS
    'Вид удостоверения. Записывается при вставке; читателем НЕ вычисляется.';
COMMENT ON COLUMN kacho_iam.user_oauth_clients.secret_hash IS
    'sha256 по идентификатору строки И секретной части вместе, 32 байта.';

-- Обратное заполнение по ФАКТИЧЕСКОМУ содержимому. Порядок ветвей значим:
-- федеративная строка ключевого материала не несёт, поэтому материал
-- спрашивается первым.
UPDATE kacho_iam.service_account_oauth_clients
   SET credential_kind = CASE
        WHEN public_key_pem <> ''             THEN 'KEYPAIR'
        WHEN trusted_subjects <> '[]'::jsonb  THEN 'FEDERATED'
        ELSE                                       'LEGACY'
       END;

UPDATE kacho_iam.user_oauth_clients
   SET credential_kind = CASE
        WHEN public_key_pem <> '' THEN 'KEYPAIR'
        ELSE                           'LEGACY'
       END;

ALTER TABLE kacho_iam.service_account_oauth_clients
    ALTER COLUMN credential_kind SET NOT NULL;
ALTER TABLE kacho_iam.user_oauth_clients
    ALTER COLUMN credential_kind SET NOT NULL;

-- Ослабление требования непустоты у колонки зеркала — зеркалит 20260823180500.
ALTER TABLE kacho_iam.service_account_oauth_clients
    ALTER COLUMN hydra_client_id DROP NOT NULL;

ALTER TABLE kacho_iam.service_account_oauth_clients
    DROP CONSTRAINT IF EXISTS service_account_oauth_clients_hydra_client_id_check,
    ADD CONSTRAINT service_account_oauth_clients_hydra_client_id_check
        CHECK (hydra_client_id IS NULL
               OR ((length(hydra_client_id) >= 1)
                   AND (length(hydra_client_id) <= 128)
                   AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text)));

-- Закрытые словари.
ALTER TABLE kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_credential_kind_ck
        CHECK (credential_kind IN ('KEYPAIR', 'SECRET', 'FEDERATED', 'LEGACY'));

ALTER TABLE kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_credential_kind_ck
        CHECK (credential_kind IN ('KEYPAIR', 'SECRET', 'LEGACY'));

-- Взаимоисключение — ОДНО ограничение на таблицу, по видам.
--
-- Ветвь SECRET и есть «бессрочного секрета не бывает», сказанное оператором
-- базы. Длина хеша названа числом: 32 байта — объявленная форма хранения
-- (§2.1), и усечённый хеш был бы ослаблением сравнения, а не опечаткой.
ALTER TABLE kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_credential_shape_ck
        CHECK (CASE credential_kind
                 WHEN 'KEYPAIR' THEN secret_hash = ''::bytea
                                 AND hydra_client_id IS NOT NULL
                 WHEN 'SECRET'  THEN octet_length(secret_hash) = 32
                                 AND public_key_pem = ''
                                 AND key_algorithm = ''
                                 AND trusted_subjects = '[]'::jsonb
                                 AND expires_at IS NOT NULL
                                 AND hydra_client_id IS NULL
                 WHEN 'FEDERATED' THEN secret_hash = ''::bytea
                                   AND public_key_pem = ''
                                   AND trusted_subjects <> '[]'::jsonb
                                   AND hydra_client_id IS NOT NULL
                 WHEN 'LEGACY'  THEN secret_hash = ''::bytea
                                 AND hydra_client_id IS NOT NULL
               END);

ALTER TABLE kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_credential_shape_ck
        CHECK (CASE credential_kind
                 WHEN 'KEYPAIR' THEN secret_hash = ''::bytea
                 WHEN 'SECRET'  THEN octet_length(secret_hash) = 32
                                 AND public_key_pem = ''
                                 AND key_algorithm = ''
                                 AND expires_at IS NOT NULL
                                 AND hydra_client_id IS NULL
                 WHEN 'LEGACY'  THEN secret_hash = ''::bytea
               END);

-- Частичный уникальный индекс по хешу — ДЕШЁВЫЙ БЭКСТОП от точного дубля
-- строки, и большего он не обещает. Детектором испорченного источника
-- случайности он НЕ является: хеш покрывает идентификатор вместе с секретом, а
-- идентификаторы строк различны by construction, поэтому совпадение секретных
-- частей хешей не сближает. Свойство «источник случайности исправен» меряет
-- проба формы (BAT-1-08).
CREATE UNIQUE INDEX service_account_oauth_clients_secret_hash_unique
    ON kacho_iam.service_account_oauth_clients USING btree (secret_hash)
    WHERE credential_kind = 'SECRET';

CREATE UNIQUE INDEX user_oauth_clients_secret_hash_unique
    ON kacho_iam.user_oauth_clients USING btree (secret_hash)
    WHERE credential_kind = 'SECRET';

-- +goose StatementEnd

-- +goose StatementBegin
DO $$
DECLARE
    k text;
    n bigint;
BEGIN
    FOR k IN SELECT unnest(ARRAY['KEYPAIR', 'SECRET', 'FEDERATED', 'LEGACY']) LOOP
        EXECUTE format('SELECT count(*) FROM kacho_iam.service_account_oauth_clients WHERE credential_kind = %L', k) INTO n;
        RAISE NOTICE 'обратное заполнение: service_account_oauth_clients вид % строк %', k, n;
    END LOOP;
    FOR k IN SELECT unnest(ARRAY['KEYPAIR', 'SECRET', 'LEGACY']) LOOP
        EXECUTE format('SELECT count(*) FROM kacho_iam.user_oauth_clients WHERE credential_kind = %L', k) INTO n;
        RAISE NOTICE 'обратное заполнение: user_oauth_clients вид % строк %', k, n;
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down

-- ОБРАТНЫЙ ХОД ОТКАЗЫВАЕТСЯ ВЫПОЛНЯТЬСЯ ПРИ ЖИВЫХ УДОСТОВЕРЕНИЯХ ВИДА SECRET.
--
-- Страж стоит ПЕРВЫМ — до единого разрушающего оператора. Отказ, наступивший
-- после первого DROP, оставил бы схему разобранной, и оператор чинил бы уже
-- две беды вместо одной.
--
-- Почему отказ, а не удаление. Секрет вида SECRET предъявляется арендатору ОДИН
-- раз; в хранилище лежит только его свёртка. Значит удалённая строка не
-- восстанавливается НИЧЕМ: резервной копии секрета не существует by
-- construction, а повторная выдача даёт другое удостоверение с другим
-- идентификатором — то есть работу по перенастройке каждого предъявителя.
-- Обычное удаление данных обратимо восстановлением; это — нет.
--
-- Почему не «предупредить комментарием». Обратный ход описан как ШТАТНАЯ
-- процедура на странице развёртывания каждого сервиса, то есть набирается не
-- задумываясь. Комментарий в файле миграции не читают в этот момент и он ничего
-- не останавливает: единственный исход, который останавливает, — отказ.
--
-- Почему не «сохранить строки и откатить схему». Это невыразимо: у строки вида
-- SECRET колонка зеркала поставщика ПУСТА by construction (в этом предмет
-- фазы), а обратный ход возвращает ей требование непустоты. Сохранённая строка
-- уронила бы ALTER ... SET NOT NULL непрозрачной ошибкой Postgres вместо
-- внятного текста — тот же отказ, но без объяснения.
--
-- ШТАТНЫЙ ВЫХОД НАЗВАН В ТЕКСТЕ ОТКАЗА: снять удостоверения продуктовым
-- глаголом отзыва (это осознанное действие оператора, о котором арендатор
-- узнаёт), после чего обратный ход проходит. Без единой строки вида SECRET
-- откат остаётся ровно той штатной процедурой, какой он описан, — и это
-- утверждается положительным контролем BAT-1-DOWN-2: страж, отказывающий
-- всегда, отнял бы процедуру там, где она безопасна.
--
-- Предикат снятия САМОГО стража: он уходит вместе с этой миграцией и не раньше.
-- Пока колонка `credential_kind` заводится здесь, здесь же и живёт её защита.

-- +goose StatementBegin
DO $$
DECLARE
    sa_secrets   bigint;
    user_secrets bigint;
BEGIN
    SELECT count(*) INTO sa_secrets
      FROM kacho_iam.service_account_oauth_clients WHERE credential_kind = 'SECRET';
    SELECT count(*) INTO user_secrets
      FROM kacho_iam.user_oauth_clients WHERE credential_kind = 'SECRET';

    -- Перепись печатается ВСЕГДА, включая ноль: иначе «удостоверений вида
    -- SECRET нет» неотличимо от «их не считали».
    RAISE NOTICE 'обратный ход 20260824210000: удостоверений вида SECRET — service_account_oauth_clients %, user_oauth_clients %',
        sa_secrets, user_secrets;

    IF sa_secrets > 0 OR user_secrets > 0 THEN
        -- ВСЁ СУЩЕСТВЕННОЕ — В ОСНОВНОМ СООБЩЕНИИ, а не в DETAIL/HINT.
        --
        -- Измерено, а не предположено: goose оборачивает отказ и доносит до
        -- оператора ТОЛЬКО основное сообщение — DETAIL и HINT в его вывод не
        -- попадают. Штатный выход, положенный туда, не доехал бы ни до кого, и
        -- оператор, прочитав «откат невозможен», обошёл бы страж вместо того
        -- чтобы отозвать удостоверения. DETAIL/HINT оставлены для psql, где их
        -- видно, но НИ ОДНО существенное слово не живёт только в них.
        RAISE EXCEPTION
            'REFUSING to roll back 20260824210000: it would IRREVERSIBLY destroy % live SECRET credential(s) '
            '(service_account_oauth_clients %, user_oauth_clients %). Such a credential is shown to the tenant '
            'ONCE and only its digest is stored, so a deleted row cannot be restored from any backup, and '
            're-issuing yields a DIFFERENT credential every holder must be reconfigured for. WAY OUT: revoke '
            'these credentials deliberately through the product verb first (so their holders learn about it), '
            'then roll back — with zero SECRET rows this migration rolls back cleanly. The rollback is safe '
            'exactly when both counts above are 0.',
            sa_secrets + user_secrets, sa_secrets, user_secrets
        USING
            DETAIL =
                'A SECRET credential is shown to the tenant exactly once and only its digest is stored. '
                'This is not ordinary data loss — it is irreversible.',
            HINT =
                'Revoke the credentials through the product verb, then roll back. Safe when both counts are 0.';
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin

DROP INDEX IF EXISTS kacho_iam.user_oauth_clients_secret_hash_unique;
DROP INDEX IF EXISTS kacho_iam.service_account_oauth_clients_secret_hash_unique;

ALTER TABLE kacho_iam.user_oauth_clients
    DROP CONSTRAINT IF EXISTS user_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT IF EXISTS user_oauth_clients_credential_kind_ck;

ALTER TABLE kacho_iam.service_account_oauth_clients
    DROP CONSTRAINT IF EXISTS service_account_oauth_clients_credential_shape_ck,
    DROP CONSTRAINT IF EXISTS service_account_oauth_clients_credential_kind_ck;

ALTER TABLE kacho_iam.service_account_oauth_clients
    DROP CONSTRAINT IF EXISTS service_account_oauth_clients_hydra_client_id_check,
    ADD CONSTRAINT service_account_oauth_clients_hydra_client_id_check
        CHECK (((length(hydra_client_id) >= 1)
                AND (length(hydra_client_id) <= 128)
                AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text)));

ALTER TABLE kacho_iam.service_account_oauth_clients
    ALTER COLUMN hydra_client_id SET NOT NULL;

ALTER TABLE kacho_iam.user_oauth_clients
    DROP COLUMN IF EXISTS secret_hash,
    DROP COLUMN IF EXISTS credential_kind;

ALTER TABLE kacho_iam.service_account_oauth_clients
    DROP COLUMN IF EXISTS secret_hash,
    DROP COLUMN IF EXISTS credential_kind;

-- +goose StatementEnd
