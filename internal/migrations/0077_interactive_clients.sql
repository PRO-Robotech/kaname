-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- 0077_interactive_clients.sql — the OAuth2 client a HUMAN signs in through.
--
-- WHY THIS TABLE EXISTS. Every client the identity provider knows was registered
-- by one of three iam use-cases, and all three hard-code `client_credentials` or
-- `jwt-bearer`. There was no creator of an `authorization_code` client at all, so
-- an interactive sign-in ceremony had nothing to run against and a human could
-- not end up holding a bearer the edge accepts. This is that client's row.
--
-- WHY THE UNIQUENESS IS HERE AND NOT IN THE SERVICE. `name` is cluster-unique,
-- and the rule is expressed as a UNIQUE constraint rather than a read-then-write
-- check in Go (запрет #10). Two concurrent Creates naming the same client must
-- produce one row and one ALREADY_EXISTS, not two rows or a second silent
-- winner; a software guard cannot promise that, and the concurrency test for
-- scenario 02 asserts exactly the promise the constraint makes.
--
-- WHY THE REDIRECT TARGETS ARE CHECKED IN THE DATABASE TOO. A redirect target is
-- where an authorization code — a credential — is delivered. The service
-- validates the list so the caller gets a named field back; the CHECKs below
-- make the same rule unavoidable for every writer that exists and every writer
-- that will exist. The two agree by construction: the bounds here are the same
-- numbers domain.maxRedirectURIs / maxRedirectURILen state.
--
-- NOTE ON THE PROVIDER-SIDE COLUMNS. `client_id` is assigned by the identity
-- provider and is UNIQUE here as well: it is the handle the ceremony is started
-- against, so two rows claiming one provider client would make "which row owns
-- this ceremony" unanswerable.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS interactive_clients (
    id                          TEXT        PRIMARY KEY,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    name                        TEXT        NOT NULL,
    description                 TEXT        NOT NULL DEFAULT '',
    labels                      JSONB       NOT NULL DEFAULT '{}'::jsonb,

    redirect_uris               TEXT[]      NOT NULL,
    post_logout_redirect_uris   TEXT[]      NOT NULL DEFAULT '{}',

    client_id                   TEXT        NOT NULL,
    audiences                   TEXT[]      NOT NULL DEFAULT '{}',
    grant_types                 TEXT[]      NOT NULL DEFAULT '{}',
    token_endpoint_auth_method  TEXT        NOT NULL DEFAULT '',

    status                      TEXT        NOT NULL DEFAULT 'ACTIVE',

    -- id form: `ic-<17 crockford-base32>`, 20 chars (ids.PrefixInteractiveClientHyphen).
    -- The alphabet is LOWERCASE crockford (ids.crockfordAlphabet:
    -- 0-9 a-h j k m n p-t v-z; no i, l, o, u). Writing it uppercase here refused
    -- every id the generator actually produces — caught by the integration test,
    -- which is the only place that runs this DDL against a real server.
    CONSTRAINT interactive_clients_id_form_ck
        CHECK (id ~ '^ic-[0-9a-hjkmnp-tv-z]{17}$'),

    -- name: the same kebab convention every other iam resource name uses, so the
    -- DB CHECK and domain.InteractiveClientName.Validate agree.
    CONSTRAINT interactive_clients_name_form_ck
        CHECK (name ~ '^[a-z][-a-z0-9]{2,62}$'),

    CONSTRAINT interactive_clients_status_ck
        CHECK (status IN ('ACTIVE', 'DELETING')),

    -- Bounds are expressible as plain CHECKs; the per-entry shape is not
    -- (Postgres forbids a subquery in a CHECK, and `unnest` needs one), so it is
    -- enforced by the trigger below. Both are the database's word, not the
    -- service's — that is the point.
    -- coalesce is load-bearing: array_length of an EMPTY array is NULL, and
    -- `NULL BETWEEN 1 AND 16` evaluates to NULL, which a CHECK treats as
    -- satisfied. Written without it the constraint accepted exactly the case it
    -- exists to refuse — a client with no target at all.
    CONSTRAINT interactive_clients_redirect_uris_count_ck
        CHECK (coalesce(array_length(redirect_uris, 1), 0) BETWEEN 1 AND 16),

    CONSTRAINT interactive_clients_post_logout_uris_count_ck
        CHECK (coalesce(array_length(post_logout_redirect_uris, 1), 0) <= 16)
);
-- +goose StatementEnd

-- Per-entry shape of both target lists. A CHECK cannot express this (no
-- subqueries, and `unnest` requires one), so the rule lives in a trigger that
-- every writer passes — the service validates the same rule to give the caller a
-- named field, and this makes it unavoidable.
--
-- The predicate is the same one domain.ValidateRedirectURIs applies: absolute
-- https://, a non-empty host, no fragment, within the length bound. A fragment
-- never reaches the server, so such a target cannot receive the code it would be
-- registered for.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kacho_iam.interactive_client_uris_wellformed()
RETURNS TRIGGER AS $$
DECLARE
    u TEXT;
BEGIN
    FOREACH u IN ARRAY (NEW.redirect_uris || NEW.post_logout_redirect_uris) LOOP
        IF u !~ '^https://[^/?#]+' OR position('#' in u) > 0 OR length(u) > 512 THEN
            RAISE EXCEPTION
                'Illegal argument redirect_uris: entry must be an absolute https:// URL without a fragment'
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER interactive_clients_uris_wellformed_trg
    BEFORE INSERT OR UPDATE ON interactive_clients
    FOR EACH ROW EXECUTE FUNCTION kacho_iam.interactive_client_uris_wellformed();
-- +goose StatementEnd

-- Cluster-unique name. The service maps 23505 on this constraint to
-- ALREADY_EXISTS; the concurrency test asserts exactly one winner.
-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS interactive_clients_name_uk
    ON interactive_clients (name);
-- +goose StatementEnd

-- One row per provider-side client.
-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS interactive_clients_client_id_uk
    ON interactive_clients (client_id);
-- +goose StatementEnd

-- Cursor pagination on (created_at, id) — the platform's List ordering.
-- +goose StatementBegin
CREATE INDEX IF NOT EXISTS interactive_clients_created_at_id_idx
    ON interactive_clients (created_at, id);
-- +goose StatementEnd
