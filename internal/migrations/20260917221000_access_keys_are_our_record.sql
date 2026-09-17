-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
--
-- access_keys_are_our_record — КЛЮЧ ДОСТУПА человека (WebAuthn) и ИСПЫТАНИЕ
-- его церемоний становятся хранилищем службы (фаза Ф7, задача
-- PRO-Robotech/kacho#1273; приёмка
-- `docs/engineering/acceptance/access-keys-are-ours.md`, Р1, Р3, Р6, Р8, Р10).
--
-- Санкция: одобренная приёмка Ф7 (запись ревью
-- `docs/specs/reviews/access-keys-are-ours/12e9608d….yaml`, круг 6, внешнее
-- событие kacho#1273). Доводы — там; здесь только то, что нужно читателю схемы.
--
-- =============================================================================
-- КЛЮЧ — СТРОКА СВОЕЙ ТАБЛИЦЫ, А НЕ СТРОКА СПОСОБА ВХОДА (Р1)
-- =============================================================================
-- Человеку положено иметь несколько ключей; строка способа по построению одна
-- на пару «человек, вид». Второй ключ не есть второй способ — он второй
-- ЭКЗЕМПЛЯР одного способа, и F4d-14 об экземплярах не высказывается: её
-- предикат («две строки одного вида у одного человека») по-прежнему даёт ноль.
--
-- Уникальность держит ИДЕНТИФИКАТОР УДОСТОВЕРЕНИЯ — он глобально уникален по
-- норме, — а не пара с человеком: два одновременных заведения одного `K`
-- разрешает ключ уникальности (23505), а не сравнение прочитанного (Ф7-05,
-- Ф7-15). Адресом он НЕ является (Р10): наружу ключ назван только `id` формы
-- `ak-<17>` — та же дефисная форма, что у членства, и то же ограничение формы
-- столбца.
--
-- Открытый ключ секретом не является: его ищут по индексированной колонке
-- идентификатора удостоверения на каждом предъявлении. Материал аттестации
-- НЕ выражается — поля для него нет (Р4, Ф7-31). Признака резервного
-- копирования и проверки пользователя нет: различитель ступени берётся из
-- флагов каждого утверждения, а не из памяти о регистрации (Ф11 Р3).
--
-- Счётчик подписи хранится числом; сдвиг — ОДИН оператор с условием на прежнее
-- значение, и его 0 строк — проигравший конкуренции (Р6, Ф7-20). Инвариант
-- держит оператор, а не проверка перед записью (ban #10).
--
-- Рукоятка `user_handle` — то, что церемония положила в `user.id` (у ключей
-- Ф7 — платформенный `id` человека как байты); её читатель — полоса входа Ф13
-- (Р3 Ф13). NULL — источник переноса рукоятки не нёс, и это отличимо от
-- пустой.
--
-- Словарь алгоритмов открытого ключа закрыт ограничением и совпадает со
-- словарём проверяющего (`webauthnverify.KnownAlgorithms`); какие из них
-- принимает установка, объявляет посадка (Р2).
--
-- Имя — та же регулярка, что у `accounts_name_check`; описание — тот же
-- предел в ЗНАКАХ, что у `*_oauth_clients_description_check` (Р10).
--
-- ПОТОЛОК: строка списывает слот вида `iam.user.accessKey` тем же триггером,
-- что удостоверения-соседи, на вставке; удаление возвращает слот в той же
-- транзакции (Р8, Ф7-37). Механизм ограничения роста у таблицы — потолок, а не
-- уборка: срока у ключа нет by construction, проверка утверждения читает его
-- при каждом предъявлении, и момента, после которого строка перестаёт менять
-- чей-либо исход, у неё нет (`retention-sweep-has-a-caller.md`).
--
-- =============================================================================
-- ИСПЫТАНИЕ — СТРОКА, ПРИВЯЗАННАЯ К ВЫЗЫВАЮЩЕМУ (Р11)
-- =============================================================================
-- Испытание выдаётся вызывающему и находится только из его сессии (Ф7-55);
-- однократно (Ф7-03, Ф7-53) — потребляется одним оператором с условием
-- «не потреблено и не истекло»; срочно (Ф7-34, Ф7-54) — срок один на обе
-- процедуры. Процедура — закрытый словарь: испытание регистрации
-- утверждением не предъявить.
--
-- Механизм ограничения роста — УБОРКА: у строки есть момент, после которого
-- ни один читатель не изменит из-за неё исхода (срок вышел либо предъявлено),
-- и с этого момента она хранится ровно столько, сколько нужно, чтобы отказ
-- регистрации различал «просрочено» от «не выдавалось» (Ф7-34); порог и
-- уборщик объявлены реестром уборки службы.

-- +goose Up

CREATE TABLE kaname.user_access_keys (
    id            text NOT NULL,
    user_id       text NOT NULL,
    credential_id bytea NOT NULL,
    public_key    bytea NOT NULL,
    algorithm     bigint NOT NULL,
    sign_count    bigint DEFAULT 0 NOT NULL,
    user_handle   bytea,
    name          text NOT NULL,
    description   text DEFAULT ''::text NOT NULL,
    created_at    timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at  timestamp with time zone,
    CONSTRAINT user_access_keys_pkey PRIMARY KEY (id),
    CONSTRAINT user_access_keys_id_form_check CHECK ((id ~ '^ak-[0-9abcdefghjkmnpqrstvwxyz]{17}$'::text)),
    CONSTRAINT user_access_keys_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT user_access_keys_credential_id_key UNIQUE (credential_id),
    CONSTRAINT user_access_keys_credential_id_check CHECK ((octet_length(credential_id) >= 16 AND octet_length(credential_id) <= 1023)),
    CONSTRAINT user_access_keys_public_key_check CHECK ((octet_length(public_key) > 0)),
    CONSTRAINT user_access_keys_algorithm_check CHECK ((algorithm = ANY (ARRAY[(-7)::bigint, (-8)::bigint, (-257)::bigint]))),
    CONSTRAINT user_access_keys_sign_count_check CHECK ((sign_count >= 0 AND sign_count <= 4294967295)),
    CONSTRAINT user_access_keys_user_handle_check CHECK ((user_handle IS NULL OR (octet_length(user_handle) >= 1 AND octet_length(user_handle) <= 64))),
    CONSTRAINT user_access_keys_name_check CHECK ((name ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT user_access_keys_description_check CHECK ((length(description) <= 256))
);

COMMENT ON TABLE kaname.user_access_keys IS
  'Ключ доступа человека (WebAuthn): строка на ключ, несколько строк на человека. Уникальность — идентификатор удостоверения; адрес — id формы ak-<17>. Аттестация не хранится; признаков резервного копирования и проверки пользователя нет — их читают из каждого утверждения. Рост ограничен потолком iam.user.accessKey (триггер списания), а не уборкой: срока у ключа нет.';
COMMENT ON COLUMN kaname.user_access_keys.credential_id IS 'Идентификатор удостоверения WebAuthn — байты нормы, глобально уникальны; наружу не выходят.';
COMMENT ON COLUMN kaname.user_access_keys.public_key IS 'Открытый ключ в форме COSE_Key, байт в байт как принят; секретом не является.';
COMMENT ON COLUMN kaname.user_access_keys.sign_count IS 'Сохранённое значение счётчика подписи (Р6): сдвигается одним оператором с условием на прежнее значение.';
COMMENT ON COLUMN kaname.user_access_keys.user_handle IS 'Рукоятка user.id церемонии (у ключей Ф7 — платформенный id человека как байты); NULL — источник переноса её не нёс. Читатель — полоса входа Ф13.';

CREATE INDEX user_access_keys_user_created_idx ON kaname.user_access_keys USING btree (user_id, created_at, id);

-- Статистика планировщика по байтовым колонкам НЕ собирается: анализ таблицы
-- кладёт выборку значений в `pg_statistic`, и эта копия живёт до следующего
-- анализа, переживая удаление строки. Ни один запрос службы не отбирает по
-- ним диапазоном: идентификатор удостоверения ищется точным равенством по
-- ключу уникальности, открытый ключ и рукоятка читаются по строке.
ALTER TABLE kaname.user_access_keys ALTER COLUMN credential_id SET STATISTICS 0;
ALTER TABLE kaname.user_access_keys ALTER COLUMN public_key SET STATISTICS 0;
ALTER TABLE kaname.user_access_keys ALTER COLUMN user_handle SET STATISTICS 0;

CREATE TRIGGER user_access_keys_quota_count AFTER INSERT OR DELETE ON kaname.user_access_keys
    FOR EACH ROW EXECUTE FUNCTION kaname.quota_count('iam.user.accessKey', 'user_id');

CREATE TABLE kaname.access_key_challenges (
    challenge   bytea NOT NULL,
    user_id     text NOT NULL,
    purpose     text NOT NULL,
    issued_at   timestamp with time zone DEFAULT now() NOT NULL,
    expires_at  timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT access_key_challenges_pkey PRIMARY KEY (challenge),
    CONSTRAINT access_key_challenges_user_fk FOREIGN KEY (user_id)
        REFERENCES kaname.users(id) ON DELETE CASCADE,
    CONSTRAINT access_key_challenges_purpose_check CHECK ((purpose = ANY (ARRAY['registration'::text, 'assertion'::text]))),
    CONSTRAINT access_key_challenges_challenge_check CHECK ((octet_length(challenge) = 32)),
    CONSTRAINT access_key_challenges_span_check CHECK ((expires_at > issued_at))
);

COMMENT ON TABLE kaname.access_key_challenges IS
  'Выданные испытания церемоний ключа доступа: привязаны к вызывающему, однократны (consumed_at), срочны (expires_at, одна величина на обе процедуры). Убираются реестром уборки после срока хранения отказа.';

CREATE INDEX access_key_challenges_expires_idx ON kaname.access_key_challenges USING btree (expires_at);

-- Испытание — одноразовое случайное значение: выборка в статистике планировщика
-- была бы его копией с чужим сроком хранения; отбирается оно точным равенством
-- по первичному ключу.
ALTER TABLE kaname.access_key_challenges ALTER COLUMN challenge SET STATISTICS 0;

-- +goose Down

-- Откат ОТКАЗЫВАЕТСЯ уничтожать материал, который не восстанавливается ниоткуда:
-- открытый ключ доступа заведён церемонией ЖИВОГО аутентификатора либо перенесён
-- из источника, которого после снятия компонента нет (Р3 п. 4). Снесённая
-- строка означает, что человек потерял способ входа, и вернуть его можно
-- только новой церемонией каждым держателем — та же массовая процедура, от
-- которой Р3 отказывается как от способа миграции. Та же мера, что у отката
-- таблицы способов входа (Ф2 П1); замок — по тем же доводам, что там.
LOCK TABLE kaname.user_access_keys IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
DECLARE
  v_rows bigint;
BEGIN
  SELECT count(*) INTO v_rows FROM kaname.user_access_keys;
  IF v_rows > 0 THEN
    RAISE EXCEPTION 'refusing to roll back: kaname.user_access_keys holds % access key row(s); a rollback would destroy them irreversibly (a lost key is recoverable only by every holder running a new ceremony). WAY OUT: if losing them is the intent, revoke those keys deliberately first; the rollback is safe exactly when the count is 0', v_rows
      USING ERRCODE = 'restrict_violation';
  END IF;
END;
$$;
-- +goose StatementEnd

DROP TABLE kaname.access_key_challenges;
DROP TABLE kaname.user_access_keys;
