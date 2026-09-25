-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Церемония OAuth 2.1 `authorization_code` нашими силами (под-фаза LINE-A-1,
-- PRO-Robotech/kacho#2721; приёмка
-- `sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md`,
-- APPROVED, отпечаток b755886f…).
--
-- ────────────────────────────────────────────────────────────────────────────
-- ЧТО ЗАВОДИТСЯ
--
--   * проверочное значение секрета интерактивного клиента — клиент
--     конфиденциален и аутентифицируется на обмене (Р3);
--   * запись кода — связка, которую назначает ВЫДАЧА (Р5): человек, сессия,
--     клиент, цель, область, вызов PKCE; одноразовость и срок держит база;
--   * авторизация — семейство токенов, выданных по одному коду (Р8);
--   * обновляющее удостоверение — цепочка ротации внутри семейства.
--
-- ────────────────────────────────────────────────────────────────────────────
-- УРОВЕНЬ И МОМЕНТ АУТЕНТИФИКАЦИИ ЗДЕСЬ НЕ ХРАНЯТСЯ — ОНИ ЧИТАЮТСЯ У СЕССИИ
--
-- Уровень уверенности как состояние лежит в ОДНОМ месте — записи сессии
-- (гейт `TestAssuranceLevelHasOneWriterAndOneHome`), момент аутентификации там
-- же и неподвижен всю жизнь записи. Код и авторизация несут ссылку на сессию,
-- а выдача предъявителя читает оба значения у неё. Перенос «сессия → код →
-- предъявитель» поэтому точен by construction: второй копии, способной
-- разойтись с первой, нет.
--
-- ────────────────────────────────────────────────────────────────────────────
-- ВРЕМЯ ЖИЗНИ — СТРОКИ НЕ ПЕРЕЖИВАЮТ СЕССИЮ, КОТОРОЙ ВЫДАНЫ
--
-- Все три таблицы ссылаются на сессию с каскадом: уборка сессии снимает и её
-- коды, и её авторизации с цепочками. Код, кроме того, убирается своим
-- уборщиком через окно узнавания повтора после срока.

-- +goose Up

-- Человек записи кода и авторизации — ТОТ ЖЕ, чья сессия: пара (сессия,
-- человек) ссылается на запись сессии целиком, и расхождение невыразимо.
-- Удаление человека снимает его сессии, а с ними — коды и авторизации.
ALTER TABLE kaname.human_sessions
    ADD CONSTRAINT human_sessions_id_user_uniq UNIQUE (id, user_id);

ALTER TABLE kaname.interactive_clients
    ADD COLUMN secret_verifier        text,
    ADD COLUMN secret_verifier_set_at timestamp with time zone,
    ADD CONSTRAINT interactive_clients_secret_pair_check
        CHECK (((secret_verifier IS NULL) = (secret_verifier_set_at IS NULL))),
    ADD CONSTRAINT interactive_clients_secret_verifier_check
        CHECK (((secret_verifier IS NULL) OR ((length(secret_verifier) >= 1) AND (length(secret_verifier) <= 512))));

COMMENT ON COLUMN kaname.interactive_clients.secret_verifier IS
  'Проверочное значение секрета конфиденциального клиента (PHC: argon2id/bcrypt), по которому клиент аутентифицируется на обмене кода. Сам секрет не хранится. NULL — секрета нет: обмен отвечает invalid_client.';

ALTER TABLE kaname.interactive_clients ALTER COLUMN secret_verifier SET STATISTICS 0;

CREATE TABLE kaname.authorization_codes (
    code_digest    text NOT NULL,
    client_id      text NOT NULL,
    session_id     text NOT NULL,
    user_id        text NOT NULL,
    redirect_uri   text NOT NULL,
    scope          text DEFAULT ''::text NOT NULL,
    code_challenge text NOT NULL,
    issued_at      timestamp with time zone DEFAULT now() NOT NULL,
    expires_at     timestamp with time zone NOT NULL,
    consumed_at    timestamp with time zone,
    CONSTRAINT authorization_codes_pkey PRIMARY KEY (code_digest),
    CONSTRAINT authorization_codes_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(id) ON DELETE CASCADE,
    CONSTRAINT authorization_codes_session_fk FOREIGN KEY (session_id, user_id)
        REFERENCES kaname.human_sessions(id, user_id) ON DELETE CASCADE,
    CONSTRAINT authorization_codes_digest_check CHECK ((code_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT authorization_codes_redirect_uri_check CHECK (((length(redirect_uri) >= 1) AND (length(redirect_uri) <= 512))),
    CONSTRAINT authorization_codes_scope_check CHECK ((length(scope) <= 1024)),
    CONSTRAINT authorization_codes_challenge_check CHECK ((code_challenge ~ '^[A-Za-z0-9_-]{43}$'::text)),
    CONSTRAINT authorization_codes_span_check CHECK ((expires_at > issued_at)),
    CONSTRAINT authorization_codes_consumed_check CHECK (((consumed_at IS NULL) OR (consumed_at >= issued_at)))
);

COMMENT ON TABLE kaname.authorization_codes IS
  'Выданные коды авторизации (LINE-A-1 Р5): хранится СВЁРТКА кода; связку назначает выдача; одноразовость — consumed_at, выставляемый одним оператором с условием «ещё не потреблён и не истёк»; срок — предикат базы. Потреблённая запись живёт окно узнавания повтора и убирается реестром уборки.';

CREATE INDEX authorization_codes_expires_at_idx ON kaname.authorization_codes USING btree (expires_at);
CREATE INDEX authorization_codes_session_id_idx ON kaname.authorization_codes USING btree (session_id, user_id);
CREATE INDEX authorization_codes_client_id_idx ON kaname.authorization_codes USING btree (client_id);

ALTER TABLE kaname.authorization_codes ALTER COLUMN code_digest SET STATISTICS 0;

CREATE TABLE kaname.authorization_grants (
    id             text NOT NULL,
    code_digest    text,
    client_id      text NOT NULL,
    session_id     text NOT NULL,
    user_id        text NOT NULL,
    scope          text DEFAULT ''::text NOT NULL,
    created_at     timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at     timestamp with time zone,
    revoked_reason text,
    CONSTRAINT authorization_grants_pkey PRIMARY KEY (id),
    CONSTRAINT authorization_grants_code_uniq UNIQUE (code_digest),
    CONSTRAINT authorization_grants_code_fk FOREIGN KEY (code_digest)
        REFERENCES kaname.authorization_codes(code_digest) ON DELETE SET NULL,
    CONSTRAINT authorization_grants_client_fk FOREIGN KEY (client_id)
        REFERENCES kaname.interactive_clients(id) ON DELETE CASCADE,
    CONSTRAINT authorization_grants_session_fk FOREIGN KEY (session_id, user_id)
        REFERENCES kaname.human_sessions(id, user_id) ON DELETE CASCADE,
    CONSTRAINT authorization_grants_id_form_check CHECK ((id ~ '^agr[0-9abcdefghjkmnpqrstvwxyz]{17}$'::text)),
    CONSTRAINT authorization_grants_scope_check CHECK ((length(scope) <= 1024)),
    CONSTRAINT authorization_grants_revoked_pair_check CHECK (((revoked_at IS NULL) = (revoked_reason IS NULL))),
    CONSTRAINT authorization_grants_revoked_reason_check CHECK (((revoked_reason IS NULL) OR (revoked_reason = ANY (ARRAY['code-replay'::text, 'refresh-replay'::text]))))
);

COMMENT ON TABLE kaname.authorization_grants IS
  'Авторизация — семейство токенов, выданных по одному коду (LINE-A-1 Р8). Отзыв семейства — revoked_at той же транзакцией, что отсечка его предъявителей по ключу kaname_authorization_id; живёт не дольше сессии, которой выдана.';

CREATE INDEX authorization_grants_session_id_idx ON kaname.authorization_grants USING btree (session_id, user_id);
CREATE INDEX authorization_grants_client_id_idx ON kaname.authorization_grants USING btree (client_id);

ALTER TABLE kaname.authorization_grants ALTER COLUMN code_digest SET STATISTICS 0;

CREATE TABLE kaname.authorization_refresh_tokens (
    token_digest text NOT NULL,
    grant_id     text NOT NULL,
    issued_at    timestamp with time zone DEFAULT now() NOT NULL,
    rotated_at   timestamp with time zone,
    CONSTRAINT authorization_refresh_tokens_pkey PRIMARY KEY (token_digest),
    CONSTRAINT authorization_refresh_tokens_grant_fk FOREIGN KEY (grant_id)
        REFERENCES kaname.authorization_grants(id) ON DELETE CASCADE,
    CONSTRAINT authorization_refresh_tokens_digest_check CHECK ((token_digest ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT authorization_refresh_tokens_rotated_check CHECK (((rotated_at IS NULL) OR (rotated_at >= issued_at)))
);

COMMENT ON TABLE kaname.authorization_refresh_tokens IS
  'Обновляющие удостоверения авторизации (LINE-A-1 Р8): хранится СВЁРТКА; ротация выставляет rotated_at предшественнику той же транзакцией, что заводит преемника; действующее у семейства ровно одно (частичный уникальный индекс).';

CREATE UNIQUE INDEX authorization_refresh_tokens_one_current_uk
    ON kaname.authorization_refresh_tokens USING btree (grant_id) WHERE (rotated_at IS NULL);

ALTER TABLE kaname.authorization_refresh_tokens ALTER COLUMN token_digest SET STATISTICS 0;

-- +goose Down

DROP TABLE kaname.authorization_refresh_tokens;
DROP TABLE kaname.authorization_grants;
DROP TABLE kaname.authorization_codes;

ALTER TABLE kaname.interactive_clients
    DROP CONSTRAINT interactive_clients_secret_verifier_check,
    DROP CONSTRAINT interactive_clients_secret_pair_check,
    DROP COLUMN secret_verifier_set_at,
    DROP COLUMN secret_verifier;

ALTER TABLE kaname.human_sessions DROP CONSTRAINT human_sessions_id_user_uniq;
