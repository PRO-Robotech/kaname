-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0065_drop_oidc_jwks_keys.sql — retire the signing-key store iam never owned.
--
-- kacho-iam mints nothing. Its only signature is over an assertion signed with
-- the CALLER's own presented credential, and the access token itself is issued
-- by Hydra. The public keyset iam serves on :9097 is a byte-identical, short-TTL
-- read-only MIRROR of Hydra's — Hydra stays the issuer and the signer, and iam
-- deliberately never serves its own `kacho-*` kids (they would be a guaranteed
-- verification miss). The private key this table stored was never decrypted
-- anywhere in production: the only helper that could do so lived in a test whose
-- own comment recorded that no production path reads it back. A key nothing can
-- decrypt cannot sign.
--
-- The table is therefore unreachable in both directions:
--   * WRITES — its only writers were OIDCJwksKeyRepo.InsertBootstrap / .Rotate,
--     called exclusively by the nightly JWKSRotationService. That service, its
--     rotator binary, the CronJob and the image build step were all removed in
--     713f7e1, leaving both methods without a single non-test caller.
--   * READS  — the only reader left was InternalIAMService.GetJWKSStatus, which
--     could consequently report nothing but an empty keyset. Its repository and
--     read port are removed alongside this migration; the RPC itself is retained
--     (published wire contract, `buf breaking` FILE-rules gate it against main)
--     and now answers with an empty algorithm set — byte-identical to what it
--     already returned while reading the empty table.
--
-- On a fully working stand the table held ZERO rows: the entire platform
-- authenticates with this store empty. Dropping it loses no state.

-- +goose Up
-- +goose StatementBegin
DROP TABLE IF EXISTS kacho_iam.oidc_jwks_keys CASCADE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Symmetric DDL rollback: recreate the table exactly as the 0001 baseline
-- defined it (columns, CHECKs, PK and all three indexes). No data is restored —
-- there was none to lose.
CREATE TABLE IF NOT EXISTS kacho_iam.oidc_jwks_keys (
    kid text NOT NULL,
    alg text NOT NULL,
    current boolean NOT NULL,
    rotated_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    public_key_pem text NOT NULL,
    private_key_pem_encrypted bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oidc_jwks_keys_alg_check CHECK ((alg = ANY (ARRAY['RS256'::text, 'ES256'::text, 'EdDSA'::text]))),
    CONSTRAINT oidc_jwks_keys_current_rotation_consistency_ck CHECK ((((current = true) AND (rotated_at IS NULL)) OR ((current = false) AND (rotated_at IS NOT NULL)))),
    CONSTRAINT oidc_jwks_keys_expires_future_ck CHECK ((expires_at > created_at)),
    CONSTRAINT oidc_jwks_keys_kid_check CHECK ((((length(kid) >= 1) AND (length(kid) <= 128)) AND (kid ~ '^[A-Za-z0-9._:-]+$'::text))),
    CONSTRAINT oidc_jwks_keys_private_key_check CHECK (((octet_length(private_key_pem_encrypted) >= 1) AND (octet_length(private_key_pem_encrypted) <= 32768))),
    CONSTRAINT oidc_jwks_keys_public_key_check CHECK (((length(public_key_pem) >= 1) AND (length(public_key_pem) <= 16384)))
);

ALTER TABLE ONLY kacho_iam.oidc_jwks_keys
    ADD CONSTRAINT oidc_jwks_keys_pkey PRIMARY KEY (kid);

CREATE INDEX oidc_jwks_keys_alg_idx ON kacho_iam.oidc_jwks_keys USING btree (alg, created_at);

CREATE UNIQUE INDEX oidc_jwks_keys_current_unique ON kacho_iam.oidc_jwks_keys USING btree (alg) WHERE (current = true);

CREATE INDEX oidc_jwks_keys_expires_idx ON kacho_iam.oidc_jwks_keys USING btree (expires_at) WHERE (current = true);
-- +goose StatementEnd
