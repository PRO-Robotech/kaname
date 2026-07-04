-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0046_user_oauth_clients.sql — таблица персональных access-токенов пользователя
-- (private_key_jwt через Hydra static-client), зеркало service_account_oauth_clients.
--
-- kacho-iam на выпуск генерирует пару ключей ECDSA P-256, регистрирует публичный
-- JWK в Hydra и возвращает приватный PEM ровно один раз. Здесь хранится только
-- маппинг hydra_client_id → user_id + публичная часть; секрет не хранится.
--
-- N:1 — у пользователя может быть НЕСКОЛЬКО токенов (нет UNIQUE(user_id)).
-- hydra_client_id UNIQUE по всем строкам. FK user_id → users(id) ON DELETE CASCADE:
-- удаление пользователя снимает его токены. created_by_user_id → users(id) ON DELETE
-- RESTRICT (audit-инвариант — создатель не удаляется, пока есть выпущенные им токены).
-- Within-service инварианты — на DB-уровне (CHECK/UNIQUE/FK), не software check-then-act.

-- +goose Up
-- +goose StatementBegin

CREATE TABLE kacho_iam.user_oauth_clients (
    id text NOT NULL,
    user_id text NOT NULL,
    hydra_client_id text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_by_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    -- private_key_jwt: SPKI-encoded ECDSA P-256 публичный ключ, для диагностики.
    -- Hydra хранит каноническую JWK в метаданных зарегистрированного клиента.
    public_key_pem text DEFAULT ''::text NOT NULL,
    -- JOSE alg зарегистрированного ключа. Всегда 'ES256' для новых токенов.
    key_algorithm text DEFAULT ''::text NOT NULL,
    CONSTRAINT user_oauth_clients_pkey PRIMARY KEY (id),
    CONSTRAINT user_oauth_clients_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT user_oauth_clients_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT user_oauth_clients_hydra_client_id_check CHECK ((((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128)) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text))),
    CONSTRAINT user_oauth_clients_id_check CHECK ((id ~ '^uoc_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA')))
);

CREATE UNIQUE INDEX user_oauth_clients_hydra_client_id_unique
    ON kacho_iam.user_oauth_clients USING btree (hydra_client_id);

-- Индекс под authz-filtered List (WHERE user_id = $1 ORDER BY id ASC, cursor-based).
CREATE INDEX user_oauth_clients_user_id_id_idx
    ON kacho_iam.user_oauth_clients USING btree (user_id, id);

ALTER TABLE ONLY kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_user_fk
    FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY kacho_iam.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_created_by_fk
    FOREIGN KEY (created_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS kacho_iam.user_oauth_clients;

-- +goose StatementEnd
