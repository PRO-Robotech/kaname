-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: BUSL-1.1

-- ─────────────────────────────────────────────────────────────────────────────
-- kacho-iam — squashed baseline schema.
--
-- Регенерирован 2026-05-25 путем fresh-PG → goose up (24 миграций
-- 0001…0025) → pg_dump --schema-only → cleanup → seed-data inline.
--
-- Старые 20 миграций (0001…0025 с пропусками) заархивированы в
-- docs/architecture/migrations-history/ — там же README с индексом и
-- per-migration описаниями для audit-trail.
--
-- Schema: kacho_iam (search_path задается прямо здесь и через libpq option
-- options=-c search_path=kacho_iam,public на рантайме pgxpool).
--
-- Helper-функции (PL/pgSQL):
--   • kacho_iam.kacho_labels_valid(jsonb) — JSON-объект labels (≤64 пар,
--     ключи/значения ≤63 байт).
--   • kacho_iam.iam_permissions_valid(jsonb) — массив "module.resource.verb"
--     или wildcard (camelCase resource/verb поддерживается).
--   • kacho_iam.group_members_member_exists() — trigger-функция, проверяет
--     subject_type/subject_id перед INSERT/UPDATE в group_members.
--   • *_notify() — trigger-функции для outbox-tables (LISTEN/NOTIFY).
--
-- Seed-данные (см. раздел 3 ниже):
--   • clusters: 1 строка (cluster_kacho_root — singleton).
--   • roles: 58 system-ролей (cluster-scoped, account_id=NULL, is_system=true),
--     id = 'rol' || substr(md5(name), 1, 17), deterministic.
--
-- ── Запреты (non-negotiables) ──────────────────────────────────────────────
--   #4  cross-service cascade — нет (FK только внутри kacho_iam).
--   #5  не редактировать примененную миграцию — squash safe только до
--       первого deploy в prod (pre-prod статус).
--   #8  database-per-service — да (схема kacho_iam в собственной БД).
--   #10 within-service refs — FK / UNIQUE / partial UNIQUE / CHECK / триггеры.
-- ─────────────────────────────────────────────────────────────────────────────

-- +goose Up
-- +goose StatementBegin

-- ── 1. Schema + search_path ─────────────────────────────────────────────────

CREATE SCHEMA IF NOT EXISTS kacho_iam;

-- search_path для миграционных DDL: чтобы unqualified-имена резолвились в
-- kacho_iam. На рантайме (pgxpool) этот же search_path задается через
-- libpq-параметр options=-c search_path=kacho_iam,public (config.baseDSN()).
SET search_path TO kacho_iam, public;

-- ── 2. DDL (functions / tables / indexes / triggers / FKs) ──────────────────
--
-- Name: audit_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.audit_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('audit_event', '');
    RETURN NULL;
END;
$$;


--
-- Name: fga_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.fga_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_fga_outbox', NEW.id::text);
    RETURN NEW;
END;
$$;


--
-- Name: group_members_member_exists(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.group_members_member_exists() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    found bool;
BEGIN
    IF NEW.member_type = 'user' THEN
        SELECT EXISTS(SELECT 1 FROM kacho_iam.users WHERE id = NEW.member_id) INTO found;
    ELSIF NEW.member_type = 'service_account' THEN
        SELECT EXISTS(SELECT 1 FROM kacho_iam.service_accounts WHERE id = NEW.member_id) INTO found;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514',
            MESSAGE = format('Illegal argument member_type %s', NEW.member_type);
    END IF;
    IF NOT found THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = format('%s %s not found', NEW.member_type, NEW.member_id);
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: iam_permissions_valid(jsonb); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.iam_permissions_valid(perms jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $_$
DECLARE
    v text;
BEGIN
    IF perms IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(perms) <> 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(perms) = 0 THEN RETURN false; END IF;
    IF jsonb_array_length(perms) > 256 THEN RETURN false; END IF;
    FOR v IN SELECT value::text FROM jsonb_array_elements_text(perms) LOOP
        IF v !~ '^([a-z][a-z0-9]*|\*)\.([a-z][a-zA-Z0-9_]*|\*)\.([a-zA-Z][a-zA-Z0-9]*|\*)$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$_$;


--
-- Name: kacho_labels_valid(jsonb); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.kacho_labels_valid(labels jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $_$
DECLARE
    k text;
    v text;
    cnt int;
BEGIN
    IF labels IS NULL THEN RETURN false; END IF;
    IF jsonb_typeof(labels) <> 'object' THEN RETURN false; END IF;
    cnt := 0;
    FOR k, v IN SELECT key, value FROM jsonb_each_text(labels) LOOP
        cnt := cnt + 1;
        IF cnt > 64 THEN RETURN false; END IF;
        IF length(k) = 0 OR length(k) > 63 THEN RETURN false; END IF;
        IF k !~ '^[a-z][-_./@a-z0-9]{0,62}$' THEN RETURN false; END IF;
        IF length(v) > 63 THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$_$;


--
-- Name: session_revocations_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.session_revocations_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('session_revoked', NEW.token_jti);
    RETURN NEW;
END;
$$;


--
-- Name: subject_change_outbox_notify(); Type: FUNCTION; Schema: kacho_iam; Owner: -
--

CREATE FUNCTION kacho_iam.subject_change_outbox_notify() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify('kacho_iam_subject_outbox_added', NEW.id::text);
    RETURN NEW;
END;
$$;


SET default_table_access_method = heap;

--
-- Name: access_binding_conditions; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_binding_conditions (
    id text NOT NULL,
    binding_id text NOT NULL,
    expression text NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    CONSTRAINT access_binding_conditions_created_by_check CHECK ((length(created_by) <= 64)),
    CONSTRAINT access_binding_conditions_expression_whitelist_ck CHECK ((expression = ANY (ARRAY['mfa_fresh'::text, 'non_expired'::text, 'source_ip_in_range'::text, 'break_glass_window'::text, 'jit_window'::text, 'business_hours'::text, 'device_compliant'::text]))),
    CONSTRAINT access_binding_conditions_id_check CHECK ((id ~ '^cond_[a-z0-9_]{1,40}$'::text)),
    CONSTRAINT access_binding_conditions_params_object_ck CHECK ((jsonb_typeof(params) = 'object'::text))
);


--
-- Name: access_bindings; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.access_bindings (
    id text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    role_id text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'ACTIVE'::text NOT NULL,
    condition_id text,
    expires_at timestamp with time zone,
    granted_by_user_id text DEFAULT ''::text NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_user_id text,
    CONSTRAINT access_bindings_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT access_bindings_granted_by_check CHECK ((length(granted_by_user_id) <= 64)),
    CONSTRAINT access_bindings_resource_ck CHECK (((resource_type ~ '^[a-z][a-z0-9_]*$'::text) OR (resource_type = '*'::text))),
    CONSTRAINT access_bindings_revoked_by_check CHECK (((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64))),
    CONSTRAINT access_bindings_revoked_consistency_ck CHECK ((((status = 'REVOKED'::text) AND (revoked_at IS NOT NULL)) OR ((status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text])) AND (revoked_at IS NULL) AND (revoked_by_user_id IS NULL)))),
    CONSTRAINT access_bindings_status_ck CHECK ((status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text, 'REVOKED'::text]))),
    CONSTRAINT access_bindings_subject_ck CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text, 'group'::text])))
);


--
-- access_bindings_jit_eligibility + access_bindings_jit_pending tables
-- are intentionally absent in this baseline (JIT/PIM pipeline removed).
--


--
-- Name: accounts; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.accounts (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    owner_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id text,
    CONSTRAINT accounts_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT accounts_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT accounts_name_check CHECK ((name ~ '^[a-z][-a-z0-9]{2,62}$'::text))
);


--
-- Name: audit_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.audit_outbox (
    id text NOT NULL,
    event_type text NOT NULL,
    tenant_account_id text,
    tenant_organization_id text,
    event_payload jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_outbox_attempts_check CHECK ((attempts >= 0)),
    CONSTRAINT audit_outbox_event_type_check CHECK ((((length(event_type) >= 1) AND (length(event_type) <= 128)) AND (event_type ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'::text))),
    CONSTRAINT audit_outbox_id_check CHECK ((id ~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'::text)),
    CONSTRAINT audit_outbox_payload_object_ck CHECK ((jsonb_typeof(event_payload) = 'object'::text)),
    CONSTRAINT audit_outbox_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'in_flight'::text, 'sent'::text, 'failed'::text])))
);


--
-- Name: break_glass_post_incident_reviews; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.break_glass_post_incident_reviews (
    grant_id text NOT NULL,
    review_issue_url text DEFAULT ''::text NOT NULL,
    escalated_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT bg_pir_review_url_check CHECK ((length(review_issue_url) <= 2048))
);


--
-- Name: cluster_admin_grants; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.cluster_admin_grants (
    id text NOT NULL,
    cluster_id text DEFAULT 'cluster_kacho_root'::text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    granted_by text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    granted_until timestamp with time zone,
    CONSTRAINT cluster_admin_grants_granted_by_check CHECK (((length(granted_by) >= 1) AND (length(granted_by) <= 64))),
    CONSTRAINT cluster_admin_grants_id_check CHECK ((id ~ '^cag_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT cluster_admin_grants_subject_id_check CHECK (((length(subject_id) >= 1) AND (length(subject_id) <= 64))),
    CONSTRAINT cluster_admin_grants_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text]))),
    CONSTRAINT cluster_admin_grants_until_check CHECK (((granted_until IS NULL) OR (granted_until > granted_at)))
);


--
-- Name: cluster_break_glass_grants; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.cluster_break_glass_grants (
    id text NOT NULL,
    cluster_id text DEFAULT 'cluster_kacho_root'::text NOT NULL,
    subject_type text NOT NULL,
    subject_id text NOT NULL,
    state text NOT NULL,
    requested_by_user_id text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    approver_a_user_id text,
    approver_a_at timestamp with time zone,
    approver_b_user_id text,
    approver_b_at timestamp with time zone,
    activated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoked_by_user_id text,
    expires_at timestamp with time zone NOT NULL,
    rationale text DEFAULT ''::text NOT NULL,
    CONSTRAINT break_glass_grants_expires_after_request CHECK ((expires_at > requested_at)),
    CONSTRAINT break_glass_grants_id_check CHECK ((id ~ '^bgg_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT break_glass_grants_rationale_check CHECK ((length(rationale) <= 2048)),
    CONSTRAINT break_glass_grants_state_check CHECK ((state = ANY (ARRAY['AWAITING_APPROVAL_A'::text, 'AWAITING_APPROVAL_B'::text, 'ACTIVE'::text, 'EXPIRED'::text, 'DENIED'::text, 'REVOKED'::text]))),
    CONSTRAINT break_glass_grants_subject_type_check CHECK ((subject_type = ANY (ARRAY['user'::text, 'service_account'::text])))
);


--
-- Name: clusters; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.clusters (
    id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT clusters_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT clusters_id_singleton_ck CHECK ((id = 'cluster_kacho_root'::text)),
    CONSTRAINT clusters_name_check CHECK ((((length(name) >= 1) AND (length(name) <= 64)) AND (name ~ '^[a-z][-a-z0-9]{0,62}[a-z0-9]?$'::text)))
);


--
-- Name: conditions; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.conditions (
    id text NOT NULL,
    folder_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    expression text NOT NULL,
    parameters_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'CREATING'::text NOT NULL,
    resource_version bigint DEFAULT 1 NOT NULL,
    CONSTRAINT conditions_description_length CHECK ((length(description) <= 256)),
    CONSTRAINT conditions_expression_length CHECK (((length(expression) >= 1) AND (length(expression) <= 2048))),
    CONSTRAINT conditions_folder_id_not_empty CHECK ((length(folder_id) > 0)),
    CONSTRAINT conditions_id_check CHECK ((id ~ '^cnd[a-z0-9]{1,17}$'::text)),
    CONSTRAINT conditions_name_pattern CHECK ((name ~ '^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$'::text)),
    CONSTRAINT conditions_status_whitelist CHECK ((status = ANY (ARRAY['CREATING'::text, 'ACTIVE'::text, 'DELETING'::text, 'ERROR'::text])))
);


--
-- Name: dpop_replay_jti; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.dpop_replay_jti (
    jti text NOT NULL,
    seen_at timestamp with time zone DEFAULT now() NOT NULL,
    htm text DEFAULT ''::text NOT NULL,
    htu text DEFAULT ''::text NOT NULL,
    jkt text DEFAULT ''::text NOT NULL,
    CONSTRAINT dpop_replay_jti_htm_check CHECK ((length(htm) <= 16)),
    CONSTRAINT dpop_replay_jti_htu_check CHECK ((length(htu) <= 2048)),
    CONSTRAINT dpop_replay_jti_jkt_check CHECK ((length(jkt) <= 128)),
    CONSTRAINT dpop_replay_jti_jti_check CHECK (((length(jti) >= 1) AND (length(jti) <= 128)))
);


--
-- Name: fga_model_version; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.fga_model_version (
    id bigint NOT NULL,
    authorization_model_id text NOT NULL,
    dsl_sha256 text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_by text DEFAULT 'bootstrap-job'::text NOT NULL
);


--
-- Name: fga_model_version_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.fga_model_version_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fga_model_version_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.fga_model_version_id_seq OWNED BY kacho_iam.fga_model_version.id;


--
-- Name: fga_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.fga_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    sent_at timestamp with time zone,
    last_error text,
    attempt_count integer DEFAULT 0 NOT NULL,
    CONSTRAINT fga_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['fga.tuple.write'::text, 'fga.tuple.delete'::text])))
);


--
-- Name: fga_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.fga_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fga_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.fga_outbox_id_seq OWNED BY kacho_iam.fga_outbox.id;


--
-- gdpr_erasure_audit + gdpr_erasure_requests tables are intentionally absent
-- in this baseline (GDPR erasure pipeline removed; cluster_admin_grant
-- mint + break-glass survive).
--


--
-- Name: group_members; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.group_members (
    group_id text NOT NULL,
    member_type text NOT NULL,
    member_id text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT group_members_type_check CHECK ((member_type = ANY (ARRAY['user'::text, 'service_account'::text])))
);


--
-- Name: groups; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.groups (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT groups_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT groups_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT groups_name_check CHECK ((name ~ '^[a-z][-a-z0-9]{2,62}$'::text))
);


--
-- Name: oidc_jwks_keys; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.oidc_jwks_keys (
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


--
-- Name: operations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.operations (
    id text NOT NULL,
    description text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text DEFAULT 'anonymous'::text NOT NULL,
    principal_type text DEFAULT 'system'::text NOT NULL,
    principal_id text DEFAULT 'bootstrap'::text NOT NULL,
    principal_display_name text DEFAULT 'kacho-iam-bootstrap'::text NOT NULL,
    modified_at timestamp with time zone DEFAULT now() NOT NULL,
    done boolean DEFAULT false NOT NULL,
    metadata_type text,
    metadata_data bytea,
    resource_id text,
    error_code integer,
    error_message text,
    error_details bytea,
    response_type text,
    response_data bytea,
    CONSTRAINT operations_principal_type_check CHECK ((principal_type = ANY (ARRAY['system'::text, 'anonymous'::text, 'user'::text, 'service_account'::text])))
);


--
-- Name: organizations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.organizations (
    id text NOT NULL,
    name text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    domain text,
    scim_endpoint_url text DEFAULT ''::text NOT NULL,
    saml_metadata_url text DEFAULT ''::text NOT NULL,
    saml_idp_entity_id text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    domain_claim text,
    domain_verification_state text DEFAULT 'unverified'::text NOT NULL,
    domain_verification_token text,
    domain_verification_started_at timestamp with time zone,
    domain_verified_at timestamp with time zone,
    default_account_id text,
    saml_metadata_xml text,
    saml_metadata_uploaded_at timestamp with time zone,
    saml_acs_url text,
    saml_entity_id text,
    initial_role_id text,
    scim_token_hash bytea,
    scim_token_issued_at timestamp with time zone,
    scim_token_revoked_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organizations_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT organizations_display_name_check CHECK ((length(display_name) <= 128)),
    CONSTRAINT organizations_domain_check CHECK (((domain IS NULL) OR (((length(domain) >= 3) AND (length(domain) <= 253)) AND (domain ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)+$'::text)))),
    CONSTRAINT organizations_domain_claim_format_ck CHECK (((domain_claim IS NULL) OR (((length(domain_claim) >= 3) AND (length(domain_claim) <= 253)) AND (domain_claim ~ '^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)+$'::text)))),
    CONSTRAINT organizations_domain_verification_state_ck CHECK ((domain_verification_state = ANY (ARRAY['unverified'::text, 'pending'::text, 'verified'::text, 'revoked'::text]))),
    CONSTRAINT organizations_id_check CHECK ((id ~ '^org_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT organizations_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT organizations_name_check CHECK ((name ~ '^[a-z][-a-z0-9]{2,62}$'::text)),
    CONSTRAINT organizations_saml_acs_url_ck CHECK (((saml_acs_url IS NULL) OR (saml_acs_url ~ '^https://'::text))),
    CONSTRAINT organizations_saml_metadata_check CHECK (((saml_metadata_url = ''::text) OR (saml_metadata_url ~ '^https://'::text))),
    CONSTRAINT organizations_scim_endpoint_check CHECK (((scim_endpoint_url = ''::text) OR (scim_endpoint_url ~ '^https://'::text)))
);


--
-- Name: projects; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.projects (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT projects_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT projects_labels_valid CHECK (kacho_iam.kacho_labels_valid(labels)),
    CONSTRAINT projects_name_check CHECK ((name ~ '^[a-z][-a-z0-9]{2,62}$'::text))
);


--
-- Name: refresh_token_counters; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.refresh_token_counters (
    user_id text NOT NULL,
    family_id text NOT NULL,
    refresh_count bigint DEFAULT 0 NOT NULL,
    last_refresh_at timestamp with time zone,
    family_started_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT refresh_token_counters_count_check CHECK ((refresh_count >= 0)),
    CONSTRAINT refresh_token_counters_family_check CHECK (((length(family_id) >= 1) AND (length(family_id) <= 128)))
);


--
-- Name: roles; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.roles (
    id text NOT NULL,
    account_id text,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    permissions jsonb NOT NULL,
    is_system boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    cluster_id text,
    organization_id text,
    project_id text,
    CONSTRAINT roles_custom_name_check CHECK ((is_system OR (name ~ '^[a-z][a-z0-9_]{0,40}$'::text))),
    CONSTRAINT roles_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT roles_permissions_valid CHECK (kacho_iam.iam_permissions_valid(permissions)),
    CONSTRAINT roles_scope_xor CHECK ((((is_system = true) AND (cluster_id IS NOT NULL) AND (organization_id IS NULL) AND (account_id IS NULL) AND (project_id IS NULL)) OR ((is_system = false) AND (cluster_id IS NULL) AND (((organization_id IS NOT NULL) AND (account_id IS NULL) AND (project_id IS NULL)) OR ((organization_id IS NULL) AND (account_id IS NOT NULL) AND (project_id IS NULL)) OR ((organization_id IS NULL) AND (account_id IS NULL) AND (project_id IS NOT NULL)))))),
    CONSTRAINT roles_system_name_check CHECK (((NOT is_system) OR (name ~ '^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$'::text)))
);


--
-- Name: saml_sessions; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.saml_sessions (
    id text NOT NULL,
    organization_id text NOT NULL,
    relay_state text DEFAULT ''::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT saml_sessions_expiry_future_ck CHECK ((expires_at > created_at)),
    CONSTRAINT saml_sessions_id_check CHECK ((id ~ '^sms_[a-z0-9_]{1,40}$'::text))
);


--
-- Name: scim_group_members; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.scim_group_members (
    id text NOT NULL,
    scim_group_id text NOT NULL,
    scim_user_mapping_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_group_members_id_check CHECK ((id ~ '^sgm_[a-z0-9_]{1,40}$'::text))
);


--
-- Name: scim_groups; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.scim_groups (
    id text NOT NULL,
    organization_id text NOT NULL,
    scim_external_id text NOT NULL,
    display_name text NOT NULL,
    scim_active boolean DEFAULT true NOT NULL,
    scim_meta_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_scim_sync_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_groups_display_name_check CHECK (((length(display_name) >= 1) AND (length(display_name) <= 256))),
    CONSTRAINT scim_groups_external_id_check CHECK (((length(scim_external_id) >= 1) AND (length(scim_external_id) <= 256))),
    CONSTRAINT scim_groups_id_check CHECK ((id ~ '^scg_[a-z0-9_]{1,40}$'::text))
);


--
-- Name: scim_user_mappings; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.scim_user_mappings (
    id text NOT NULL,
    organization_id text NOT NULL,
    user_id text NOT NULL,
    scim_external_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scim_active boolean DEFAULT true NOT NULL,
    scim_meta_resource_type text DEFAULT 'User'::text NOT NULL,
    scim_meta_version text,
    last_scim_sync_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT scim_user_mappings_id_check CHECK ((id ~ '^scim_[a-z0-9_]{1,40}$'::text)),
    CONSTRAINT scim_user_mappings_scim_external_id_check CHECK (((length(scim_external_id) >= 1) AND (length(scim_external_id) <= 256)))
);


--
-- Name: service_account_oauth_clients; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.service_account_oauth_clients (
    id text NOT NULL,
    sva_id text NOT NULL,
    hydra_client_id text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_by_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    -- private_key_jwt flow: SPKI-encoded ECDSA P-256 public key kept
    -- for rotation diagnostics. Hydra stores the canonical JWK in its
    -- registered client metadata. DEFAULT '' covers legacy rows from the
    -- `client_secret_basic` flow AND federated rows
    -- (no key material in kacho-iam).
    public_key_pem text DEFAULT ''::text NOT NULL,
    -- JOSE alg of the registered key. Empty for legacy rows and federated rows.
    key_algorithm text DEFAULT ''::text NOT NULL,
    -- Federation IN: when non-empty array, this row uses the
    -- RFC 7521/7523 jwt-bearer grant with an EXTERNAL IdP — kacho-iam holds
    -- no key material and the Hydra OAuth2 client is registered with
    -- `grant_types=[urn:ietf:params:oauth:grant-type:jwt-bearer]` +
    -- `token_endpoint_auth_method=none`. Each element is
    -- {"issuer": <oidc-iss-url>, "subject_pattern": <re2-regex>} — the
    -- token-hook + `FindByExternalSubject` repo helper enforce the (iss, sub)
    -- restriction when Hydra forwards the assertion subject.
    trusted_subjects jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT service_account_oauth_clients_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT service_account_oauth_clients_expires_future_ck CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT service_account_oauth_clients_hydra_client_id_check CHECK ((((length(hydra_client_id) >= 1) AND (length(hydra_client_id) <= 128)) AND (hydra_client_id ~ '^[A-Za-z0-9._:-]+$'::text))),
    CONSTRAINT service_account_oauth_clients_id_check CHECK ((id ~ '^soc_[0-9a-hjkmnp-tv-z]{17}$'::text)),
    CONSTRAINT service_account_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA'))),
    CONSTRAINT service_account_oauth_clients_trusted_subjects_array_ck CHECK ((jsonb_typeof(trusted_subjects) = 'array'))
);


--
-- Name: service_accounts; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.service_accounts (
    id text NOT NULL,
    account_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    enabled boolean DEFAULT true NOT NULL,
    CONSTRAINT service_accounts_description_check CHECK ((length(description) <= 256)),
    CONSTRAINT service_accounts_name_check CHECK ((name ~ '^[a-z][-a-z0-9]{2,62}$'::text))
);


--
-- Name: session_revocations; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.session_revocations (
    token_jti text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    user_id text NOT NULL,
    ttl_expires_at timestamp with time zone NOT NULL,
    revoked_by_user_id text,
    CONSTRAINT session_revocations_reason_check CHECK ((length(reason) <= 256)),
    CONSTRAINT session_revocations_revoked_by_check CHECK (((revoked_by_user_id IS NULL) OR (length(revoked_by_user_id) <= 64))),
    CONSTRAINT session_revocations_token_jti_check CHECK (((length(token_jti) >= 1) AND (length(token_jti) <= 128))),
    CONSTRAINT session_revocations_ttl_future_ck CHECK ((ttl_expires_at > revoked_at))
);


--
-- Name: subject_change_outbox; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.subject_change_outbox (
    id bigint NOT NULL,
    subject_id text NOT NULL,
    op text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    notified_at timestamp with time zone,
    event_type text,
    resource_type text,
    resource_id text,
    sent_at timestamp with time zone,
    attempt_count integer DEFAULT 0 NOT NULL,
    last_error text,
    payload jsonb,
    CONSTRAINT subject_change_op_check CHECK ((op = ANY (ARRAY['binding_upsert'::text, 'binding_delete'::text, 'group_member_change'::text, 'binding_grant'::text, 'binding_revoke'::text, 'jit_revoke'::text, 'bg_revoke'::text])))
);


--
-- Name: subject_change_outbox_id_seq; Type: SEQUENCE; Schema: kacho_iam; Owner: -
--

CREATE SEQUENCE kacho_iam.subject_change_outbox_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: subject_change_outbox_id_seq; Type: SEQUENCE OWNED BY; Schema: kacho_iam; Owner: -
--

ALTER SEQUENCE kacho_iam.subject_change_outbox_id_seq OWNED BY kacho_iam.subject_change_outbox.id;


--
-- Name: users; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.users (
    id text NOT NULL,
    external_id text NOT NULL,
    email text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    account_id text NOT NULL,
    invite_status text DEFAULT 'ACTIVE'::text NOT NULL,
    invited_by text,
    CONSTRAINT users_display_name_check CHECK ((length(display_name) <= 128)),
    CONSTRAINT users_email_check CHECK ((((length(email) >= 3) AND (length(email) <= 254)) AND (email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'::text))),
    CONSTRAINT users_external_id_check CHECK (((length(external_id) >= 0) AND (length(external_id) <= 256))),
    CONSTRAINT users_invite_status_check CHECK ((invite_status = ANY (ARRAY['PENDING'::text, 'ACTIVE'::text, 'BLOCKED'::text]))),
    CONSTRAINT users_invite_status_consistency CHECK ((((invite_status = 'PENDING'::text) AND (external_id = ''::text)) OR ((invite_status = ANY (ARRAY['ACTIVE'::text, 'BLOCKED'::text])) AND (length(external_id) > 0))))
);


--
-- Name: watch_cursors; Type: TABLE; Schema: kacho_iam; Owner: -
--

CREATE TABLE kacho_iam.watch_cursors (
    service text NOT NULL,
    last_event_id text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT watch_cursors_service_ck CHECK ((service = ANY (ARRAY['vpc'::text, 'compute'::text, 'loadbalancer'::text])))
);


--
--
--
-- Name: fga_model_version id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_model_version ALTER COLUMN id SET DEFAULT nextval('kacho_iam.fga_model_version_id_seq'::regclass);


--
-- Name: fga_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.fga_outbox_id_seq'::regclass);


--
-- Name: subject_change_outbox id; Type: DEFAULT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.subject_change_outbox ALTER COLUMN id SET DEFAULT nextval('kacho_iam.subject_change_outbox_id_seq'::regclass);


--
-- Name: access_binding_conditions access_binding_conditions_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_conditions
    ADD CONSTRAINT access_binding_conditions_pkey PRIMARY KEY (id);


--
-- access_bindings_jit_eligibility + access_bindings_jit_pending PK
-- constraints are intentionally absent in this baseline (tables gone).
--


--
-- Name: access_bindings access_bindings_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_pkey PRIMARY KEY (id);


--
-- Name: accounts accounts_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_name_unique UNIQUE (name);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: audit_outbox audit_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.audit_outbox
    ADD CONSTRAINT audit_outbox_pkey PRIMARY KEY (id);


--
-- Name: break_glass_post_incident_reviews break_glass_post_incident_reviews_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.break_glass_post_incident_reviews
    ADD CONSTRAINT break_glass_post_incident_reviews_pkey PRIMARY KEY (grant_id);


--
-- Name: cluster_admin_grants cluster_admin_grants_cluster_subject_uniq; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_cluster_subject_uniq UNIQUE (cluster_id, subject_id);


--
-- Name: cluster_admin_grants cluster_admin_grants_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_pkey PRIMARY KEY (id);


--
-- Name: cluster_break_glass_grants cluster_break_glass_grants_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT cluster_break_glass_grants_pkey PRIMARY KEY (id);


--
-- Name: clusters clusters_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.clusters
    ADD CONSTRAINT clusters_pkey PRIMARY KEY (id);


--
-- Name: conditions conditions_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.conditions
    ADD CONSTRAINT conditions_pkey PRIMARY KEY (id);


--
-- Name: dpop_replay_jti dpop_replay_jti_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.dpop_replay_jti
    ADD CONSTRAINT dpop_replay_jti_pkey PRIMARY KEY (jti);


--
-- Name: fga_model_version fga_model_version_authorization_model_id_key; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_model_version
    ADD CONSTRAINT fga_model_version_authorization_model_id_key UNIQUE (authorization_model_id);


--
-- Name: fga_model_version fga_model_version_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_model_version
    ADD CONSTRAINT fga_model_version_pkey PRIMARY KEY (id);


--
-- Name: fga_outbox fga_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.fga_outbox
    ADD CONSTRAINT fga_outbox_pkey PRIMARY KEY (id);


--
-- gdpr_erasure_audit + gdpr_erasure_requests PK constraints are intentionally
-- absent in this baseline (tables gone).
--


--
-- Name: group_members group_members_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.group_members
    ADD CONSTRAINT group_members_pkey PRIMARY KEY (group_id, member_type, member_id);


--
-- Name: groups groups_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_account_name_unique UNIQUE (account_id, name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: oidc_jwks_keys oidc_jwks_keys_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.oidc_jwks_keys
    ADD CONSTRAINT oidc_jwks_keys_pkey PRIMARY KEY (kid);


--
-- Name: operations operations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.operations
    ADD CONSTRAINT operations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: projects projects_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_account_name_unique UNIQUE (account_id, name);


--
-- Name: projects projects_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);


--
-- Name: refresh_token_counters refresh_token_counters_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.refresh_token_counters
    ADD CONSTRAINT refresh_token_counters_pkey PRIMARY KEY (user_id, family_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: saml_sessions saml_sessions_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.saml_sessions
    ADD CONSTRAINT saml_sessions_pkey PRIMARY KEY (id);


--
-- Name: scim_group_members scim_group_members_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_group_members
    ADD CONSTRAINT scim_group_members_pkey PRIMARY KEY (id);


--
-- Name: scim_group_members scim_group_members_unique_membership; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_group_members
    ADD CONSTRAINT scim_group_members_unique_membership UNIQUE (scim_group_id, scim_user_mapping_id);


--
-- Name: scim_groups scim_groups_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_groups
    ADD CONSTRAINT scim_groups_pkey PRIMARY KEY (id);


--
-- Name: scim_user_mappings scim_user_mappings_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_user_mappings
    ADD CONSTRAINT scim_user_mappings_pkey PRIMARY KEY (id);


--
-- Name: service_account_oauth_clients service_account_oauth_clients_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_pkey PRIMARY KEY (id);


--
-- Name: service_accounts service_accounts_account_name_unique; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_account_name_unique UNIQUE (account_id, name);


--
-- Name: service_accounts service_accounts_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (id);


--
-- Name: session_revocations session_revocations_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.session_revocations
    ADD CONSTRAINT session_revocations_pkey PRIMARY KEY (token_jti);


--
-- Name: subject_change_outbox subject_change_outbox_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.subject_change_outbox
    ADD CONSTRAINT subject_change_outbox_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: watch_cursors watch_cursors_pkey; Type: CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.watch_cursors
    ADD CONSTRAINT watch_cursors_pkey PRIMARY KEY (service);


--
--
-- Name: access_binding_conditions_binding_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX access_binding_conditions_binding_unique ON kacho_iam.access_binding_conditions USING btree (binding_id);


--
-- Name: access_bindings_expires_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_expires_idx ON kacho_iam.access_bindings USING btree (expires_at) WHERE ((expires_at IS NOT NULL) AND (status = 'ACTIVE'::text));


--
-- Name: access_bindings_resource_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_resource_idx ON kacho_iam.access_bindings USING btree (resource_type, resource_id);


--
-- Name: access_bindings_role_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_role_idx ON kacho_iam.access_bindings USING btree (role_id);


--
-- Name: access_bindings_status_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_status_idx ON kacho_iam.access_bindings USING btree (status);


--
-- Name: access_bindings_subject_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX access_bindings_subject_idx ON kacho_iam.access_bindings USING btree (subject_type, subject_id);


--
-- Name: access_bindings_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX access_bindings_unique ON kacho_iam.access_bindings USING btree (subject_type, subject_id, role_id, resource_type, resource_id) WHERE (status = 'ACTIVE'::text);


--
-- Name: accounts_organization_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX accounts_organization_idx ON kacho_iam.accounts USING btree (organization_id) WHERE (organization_id IS NOT NULL);


--
-- Name: accounts_owner_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX accounts_owner_idx ON kacho_iam.accounts USING btree (owner_user_id);


--
-- Name: audit_outbox_federation_event_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_federation_event_idx ON kacho_iam.audit_outbox USING btree (created_at) WHERE (event_type ~~ 'iam.federation.%'::text);


--
-- Name: audit_outbox_status_next_attempt_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_status_next_attempt_idx ON kacho_iam.audit_outbox USING btree (status, next_attempt_at) WHERE (status = ANY (ARRAY['pending'::text, 'in_flight'::text]));


--
-- Name: audit_outbox_tenant_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_tenant_account_idx ON kacho_iam.audit_outbox USING btree (tenant_account_id, created_at) WHERE (tenant_account_id IS NOT NULL);


--
-- Name: audit_outbox_tenant_org_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX audit_outbox_tenant_org_idx ON kacho_iam.audit_outbox USING btree (tenant_organization_id, created_at) WHERE (tenant_organization_id IS NOT NULL);


--
-- Name: bg_pir_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX bg_pir_pending_idx ON kacho_iam.break_glass_post_incident_reviews USING btree (created_at) WHERE (completed_at IS NULL);


--
-- Name: break_glass_grants_expires_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX break_glass_grants_expires_idx ON kacho_iam.cluster_break_glass_grants USING btree (expires_at) WHERE (state = ANY (ARRAY['ACTIVE'::text, 'AWAITING_APPROVAL_A'::text, 'AWAITING_APPROVAL_B'::text]));


--
-- Name: break_glass_grants_state_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX break_glass_grants_state_idx ON kacho_iam.cluster_break_glass_grants USING btree (state);


--
-- Name: cluster_admin_grants_cluster_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX cluster_admin_grants_cluster_idx ON kacho_iam.cluster_admin_grants USING btree (cluster_id);


--
-- Name: cluster_admin_grants_subject_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX cluster_admin_grants_subject_unique ON kacho_iam.cluster_admin_grants USING btree (subject_type, subject_id) WHERE (granted_until IS NULL);


--
-- Name: conditions_folder_name_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX conditions_folder_name_uniq ON kacho_iam.conditions USING btree (folder_id, name) WHERE (status <> 'DELETING'::text);


--
-- Name: dpop_replay_jti_seen_at_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX dpop_replay_jti_seen_at_idx ON kacho_iam.dpop_replay_jti USING btree (seen_at);


--
-- Name: fga_outbox_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX fga_outbox_pending_idx ON kacho_iam.fga_outbox USING btree (created_at) WHERE (sent_at IS NULL);


--
-- gdpr_erasure_audit + gdpr_erasure_requests indexes are intentionally absent
-- in this baseline (tables gone).
--


--
-- Name: group_members_member_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX group_members_member_idx ON kacho_iam.group_members USING btree (member_type, member_id);


--
-- Name: groups_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX groups_account_idx ON kacho_iam.groups USING btree (account_id);


--
-- Name: idx_conditions_folder_status; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX idx_conditions_folder_status ON kacho_iam.conditions USING btree (folder_id, status) WHERE (status <> 'DELETING'::text);


--
-- jit_eligibility_* + jit_pending_* indexes are intentionally absent in this
-- baseline (access_bindings_jit_eligibility + access_bindings_jit_pending
-- tables gone).
--


--
-- Name: oidc_jwks_keys_alg_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX oidc_jwks_keys_alg_idx ON kacho_iam.oidc_jwks_keys USING btree (alg, created_at);


--
-- Name: oidc_jwks_keys_current_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX oidc_jwks_keys_current_unique ON kacho_iam.oidc_jwks_keys USING btree (alg) WHERE (current = true);


--
-- Name: oidc_jwks_keys_expires_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX oidc_jwks_keys_expires_idx ON kacho_iam.oidc_jwks_keys USING btree (expires_at) WHERE (current = true);


--
-- Name: operations_created_at_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_created_at_idx ON kacho_iam.operations USING btree (created_at);


--
-- Name: operations_done_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_done_idx ON kacho_iam.operations USING btree (done);


--
-- Name: operations_principal_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_principal_idx ON kacho_iam.operations USING btree (principal_type, principal_id);


--
-- Name: operations_resource_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX operations_resource_idx ON kacho_iam.operations USING btree (resource_id);


--
-- Name: organizations_domain_claim_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX organizations_domain_claim_uniq ON kacho_iam.organizations USING btree (domain_claim) WHERE ((domain_claim IS NOT NULL) AND (domain_verification_state = ANY (ARRAY['pending'::text, 'verified'::text])));


--
-- Name: organizations_domain_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX organizations_domain_unique ON kacho_iam.organizations USING btree (domain) WHERE (domain IS NOT NULL);


--
-- Name: organizations_labels_gin; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX organizations_labels_gin ON kacho_iam.organizations USING gin (labels jsonb_path_ops);


--
-- Name: organizations_name_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX organizations_name_unique ON kacho_iam.organizations USING btree (name);


--
-- Name: organizations_scim_token_hash_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX organizations_scim_token_hash_uniq ON kacho_iam.organizations USING btree (scim_token_hash) WHERE ((scim_token_hash IS NOT NULL) AND (scim_token_revoked_at IS NULL));


--
-- Name: projects_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX projects_account_idx ON kacho_iam.projects USING btree (account_id);


--
-- Name: refresh_token_counters_user_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX refresh_token_counters_user_idx ON kacho_iam.refresh_token_counters USING btree (user_id, last_refresh_at);


--
-- Name: roles_acc_custom_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_acc_custom_unique ON kacho_iam.roles USING btree (account_id, name) WHERE ((is_system = false) AND (account_id IS NOT NULL));


--
-- Name: roles_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_account_idx ON kacho_iam.roles USING btree (account_id) WHERE (account_id IS NOT NULL);


--
-- Name: roles_cluster_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_cluster_idx ON kacho_iam.roles USING btree (cluster_id) WHERE (cluster_id IS NOT NULL);


--
-- Name: roles_org_custom_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_org_custom_unique ON kacho_iam.roles USING btree (organization_id, name) WHERE ((is_system = false) AND (organization_id IS NOT NULL));


--
-- Name: roles_organization_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_organization_idx ON kacho_iam.roles USING btree (organization_id) WHERE (organization_id IS NOT NULL);


--
-- Name: roles_prj_custom_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_prj_custom_unique ON kacho_iam.roles USING btree (project_id, name) WHERE ((is_system = false) AND (project_id IS NOT NULL));


--
-- Name: roles_project_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX roles_project_idx ON kacho_iam.roles USING btree (project_id) WHERE (project_id IS NOT NULL);


--
-- Name: roles_system_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX roles_system_unique ON kacho_iam.roles USING btree (cluster_id, name) WHERE (is_system = true);


--
-- Name: saml_sessions_expires_at_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX saml_sessions_expires_at_idx ON kacho_iam.saml_sessions USING btree (expires_at);


--
-- Name: scim_group_members_mapping_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX scim_group_members_mapping_idx ON kacho_iam.scim_group_members USING btree (scim_user_mapping_id);


--
-- Name: scim_groups_org_external_active_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX scim_groups_org_external_active_uniq ON kacho_iam.scim_groups USING btree (organization_id, scim_external_id) WHERE (scim_active = true);


--
-- Name: scim_user_mappings_org_external_active_uniq; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX scim_user_mappings_org_external_active_uniq ON kacho_iam.scim_user_mappings USING btree (organization_id, scim_external_id) WHERE (scim_active = true);


--
-- Name: scim_user_mappings_user_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX scim_user_mappings_user_idx ON kacho_iam.scim_user_mappings USING btree (user_id);


--
-- Name: service_account_oauth_clients_hydra_client_id_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX service_account_oauth_clients_hydra_client_id_unique ON kacho_iam.service_account_oauth_clients USING btree (hydra_client_id);


--
-- Name: service_account_oauth_clients_sva_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX service_account_oauth_clients_sva_unique ON kacho_iam.service_account_oauth_clients USING btree (sva_id);


--
-- Name: service_accounts_account_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_account_idx ON kacho_iam.service_accounts USING btree (account_id);


--
-- Name: service_accounts_enabled_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_enabled_idx ON kacho_iam.service_accounts USING btree (account_id) WHERE (enabled = true);


--
-- Name: service_accounts_project_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX service_accounts_project_idx ON kacho_iam.service_accounts USING btree (project_id) WHERE (project_id IS NOT NULL);


--
-- Name: session_revocations_recent_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_recent_idx ON kacho_iam.session_revocations USING btree (revoked_at, token_jti) WHERE (revoked_at > '2000-01-01 00:00:00+00'::timestamp with time zone);


--
-- Name: INDEX session_revocations_recent_idx; Type: COMMENT; Schema: kacho_iam; Owner: -
--

COMMENT ON INDEX kacho_iam.session_revocations_recent_idx IS 'Cache warm-up при холодном старте api-gateway pod; query: SELECT token_jti FROM session_revocations WHERE revoked_at > now() - INTERVAL ''24 hours''';


--
-- Name: session_revocations_ttl_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_ttl_idx ON kacho_iam.session_revocations USING btree (ttl_expires_at);


--
-- Name: session_revocations_user_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX session_revocations_user_idx ON kacho_iam.session_revocations USING btree (user_id);


--
-- Name: subject_change_pending_v2_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX subject_change_pending_v2_idx ON kacho_iam.subject_change_outbox USING btree (created_at) WHERE (sent_at IS NULL);


--
-- Name: users_account_email_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_account_email_unique ON kacho_iam.users USING btree (account_id, lower(email));


--
-- Name: users_account_external_id_unique; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE UNIQUE INDEX users_account_external_id_unique ON kacho_iam.users USING btree (account_id, external_id) WHERE (external_id <> ''::text);


--
-- Name: users_active_external_id_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_active_external_id_idx ON kacho_iam.users USING btree (external_id) WHERE ((invite_status = 'ACTIVE'::text) AND (external_id <> ''::text));


--
-- Name: users_email_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_email_idx ON kacho_iam.users USING btree (lower(email));


--
-- Name: users_email_pending_idx; Type: INDEX; Schema: kacho_iam; Owner: -
--

CREATE INDEX users_email_pending_idx ON kacho_iam.users USING btree (lower(email)) WHERE (invite_status = 'PENDING'::text);


--
-- Name: audit_outbox audit_outbox_notify_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER audit_outbox_notify_trg AFTER INSERT ON kacho_iam.audit_outbox FOR EACH STATEMENT EXECUTE FUNCTION kacho_iam.audit_outbox_notify();


--
-- Name: fga_outbox fga_outbox_notify_trigger; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER fga_outbox_notify_trigger AFTER INSERT ON kacho_iam.fga_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.fga_outbox_notify();


--
-- Name: group_members group_members_member_exists_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER group_members_member_exists_trg BEFORE INSERT OR UPDATE ON kacho_iam.group_members FOR EACH ROW EXECUTE FUNCTION kacho_iam.group_members_member_exists();


--
-- Name: session_revocations session_revocations_notify_trg; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER session_revocations_notify_trg AFTER INSERT ON kacho_iam.session_revocations FOR EACH ROW EXECUTE FUNCTION kacho_iam.session_revocations_notify();


--
-- Name: subject_change_outbox subject_change_outbox_notify_trigger; Type: TRIGGER; Schema: kacho_iam; Owner: -
--

CREATE TRIGGER subject_change_outbox_notify_trigger AFTER INSERT ON kacho_iam.subject_change_outbox FOR EACH ROW EXECUTE FUNCTION kacho_iam.subject_change_outbox_notify();


--
-- Name: access_binding_conditions access_binding_conditions_binding_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_binding_conditions
    ADD CONSTRAINT access_binding_conditions_binding_fk FOREIGN KEY (binding_id) REFERENCES kacho_iam.access_bindings(id) ON DELETE CASCADE;


--
-- Name: access_bindings access_bindings_condition_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_condition_fk FOREIGN KEY (condition_id) REFERENCES kacho_iam.access_binding_conditions(id) ON DELETE SET NULL;


--
-- access_bindings_jit_eligibility_fk and the access_bindings
-- jit_eligibility_id column are intentionally absent in this baseline
-- (parent table + provenance link gone).
--


--
-- Name: access_bindings access_bindings_role_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.access_bindings
    ADD CONSTRAINT access_bindings_role_fk FOREIGN KEY (role_id) REFERENCES kacho_iam.roles(id) ON DELETE RESTRICT;


--
-- Name: accounts accounts_organization_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_organization_fk FOREIGN KEY (organization_id) REFERENCES kacho_iam.organizations(id) ON DELETE RESTRICT;


--
-- Name: accounts accounts_owner_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.accounts
    ADD CONSTRAINT accounts_owner_fk FOREIGN KEY (owner_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;


--
-- Name: break_glass_post_incident_reviews bg_pir_grant_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.break_glass_post_incident_reviews
    ADD CONSTRAINT bg_pir_grant_fk FOREIGN KEY (grant_id) REFERENCES kacho_iam.cluster_break_glass_grants(id) ON DELETE RESTRICT;


--
-- Name: cluster_break_glass_grants break_glass_grants_approver_a_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT break_glass_grants_approver_a_fk FOREIGN KEY (approver_a_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: cluster_break_glass_grants break_glass_grants_approver_b_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT break_glass_grants_approver_b_fk FOREIGN KEY (approver_b_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: cluster_break_glass_grants break_glass_grants_cluster_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT break_glass_grants_cluster_fk FOREIGN KEY (cluster_id) REFERENCES kacho_iam.clusters(id) ON DELETE RESTRICT;


--
-- Name: cluster_break_glass_grants break_glass_grants_requested_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT break_glass_grants_requested_by_fk FOREIGN KEY (requested_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: cluster_break_glass_grants break_glass_grants_revoked_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_break_glass_grants
    ADD CONSTRAINT break_glass_grants_revoked_by_fk FOREIGN KEY (revoked_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: cluster_admin_grants cluster_admin_grants_cluster_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.cluster_admin_grants
    ADD CONSTRAINT cluster_admin_grants_cluster_fk FOREIGN KEY (cluster_id) REFERENCES kacho_iam.clusters(id) ON DELETE RESTRICT;


--
-- gdpr_erasure_audit + gdpr_erasure_requests FKs are intentionally absent in
-- this baseline (tables gone).
--


--
-- Name: group_members group_members_group_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.group_members
    ADD CONSTRAINT group_members_group_fk FOREIGN KEY (group_id) REFERENCES kacho_iam.groups(id) ON DELETE CASCADE;


--
-- Name: groups groups_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.groups
    ADD CONSTRAINT groups_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- jit_eligibility_* + jit_pending_* FKs are intentionally absent in this
-- baseline (parent tables gone).
--


--
-- Name: organizations organizations_default_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.organizations
    ADD CONSTRAINT organizations_default_account_fk FOREIGN KEY (default_account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: organizations organizations_initial_role_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.organizations
    ADD CONSTRAINT organizations_initial_role_fk FOREIGN KEY (initial_role_id) REFERENCES kacho_iam.roles(id) ON DELETE RESTRICT;


--
-- Name: projects projects_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.projects
    ADD CONSTRAINT projects_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: refresh_token_counters refresh_token_counters_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.refresh_token_counters
    ADD CONSTRAINT refresh_token_counters_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE;


--
-- Name: roles roles_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: roles roles_cluster_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_cluster_fk FOREIGN KEY (cluster_id) REFERENCES kacho_iam.clusters(id) ON DELETE RESTRICT;


--
-- Name: roles roles_organization_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_organization_fk FOREIGN KEY (organization_id) REFERENCES kacho_iam.organizations(id) ON DELETE RESTRICT;


--
-- Name: roles roles_project_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.roles
    ADD CONSTRAINT roles_project_fk FOREIGN KEY (project_id) REFERENCES kacho_iam.projects(id) ON DELETE RESTRICT;


--
-- Name: saml_sessions saml_sessions_org_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.saml_sessions
    ADD CONSTRAINT saml_sessions_org_fk FOREIGN KEY (organization_id) REFERENCES kacho_iam.organizations(id) ON DELETE CASCADE;


--
-- Name: scim_group_members scim_group_members_group_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_group_members
    ADD CONSTRAINT scim_group_members_group_fk FOREIGN KEY (scim_group_id) REFERENCES kacho_iam.scim_groups(id) ON DELETE CASCADE;


--
-- Name: scim_group_members scim_group_members_mapping_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_group_members
    ADD CONSTRAINT scim_group_members_mapping_fk FOREIGN KEY (scim_user_mapping_id) REFERENCES kacho_iam.scim_user_mappings(id) ON DELETE CASCADE;


--
-- Name: scim_groups scim_groups_org_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_groups
    ADD CONSTRAINT scim_groups_org_fk FOREIGN KEY (organization_id) REFERENCES kacho_iam.organizations(id) ON DELETE CASCADE;


--
-- Name: scim_user_mappings scim_user_mappings_organization_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_user_mappings
    ADD CONSTRAINT scim_user_mappings_organization_fk FOREIGN KEY (organization_id) REFERENCES kacho_iam.organizations(id) ON DELETE CASCADE;


--
-- Name: scim_user_mappings scim_user_mappings_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.scim_user_mappings
    ADD CONSTRAINT scim_user_mappings_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE CASCADE;


--
-- Name: service_account_oauth_clients service_account_oauth_clients_created_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_created_by_fk FOREIGN KEY (created_by_user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: service_account_oauth_clients service_account_oauth_clients_sva_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_account_oauth_clients
    ADD CONSTRAINT service_account_oauth_clients_sva_fk FOREIGN KEY (sva_id) REFERENCES kacho_iam.service_accounts(id) ON DELETE RESTRICT;


--
-- Name: service_accounts service_accounts_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT;


--
-- Name: service_accounts service_accounts_project_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.service_accounts
    ADD CONSTRAINT service_accounts_project_fk FOREIGN KEY (project_id) REFERENCES kacho_iam.projects(id) ON DELETE RESTRICT;


--
-- Name: session_revocations session_revocations_user_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.session_revocations
    ADD CONSTRAINT session_revocations_user_fk FOREIGN KEY (user_id) REFERENCES kacho_iam.users(id) ON DELETE RESTRICT;


--
-- Name: users users_account_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_account_fk FOREIGN KEY (account_id) REFERENCES kacho_iam.accounts(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;


--
-- Name: users users_invited_by_fk; Type: FK CONSTRAINT; Schema: kacho_iam; Owner: -
--

ALTER TABLE ONLY kacho_iam.users
    ADD CONSTRAINT users_invited_by_fk FOREIGN KEY (invited_by) REFERENCES kacho_iam.users(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED;


-- ── 3. Seed: cluster_kacho_root (singleton) ──────────────────────────────────

INSERT INTO kacho_iam.clusters (id, name, description)
VALUES ('cluster_kacho_root', 'kacho-root', 'Root cluster for Kachō control plane')
ON CONFLICT (id) DO NOTHING;

-- ── 4. Seed: system roles (cluster-scoped, deterministic id) ─────────────────
--
-- id = 'rol' || substr(md5(name), 1, 17).
-- Verb semantics:
--   admin = wildcard `*` для всех verb'ов на ресурсе.
--   edit  = только `update` (не create/delete — admin-операции).
--   view  = только `read`, `list`, `get`.
--
-- All system roles are cluster-scoped to 'cluster_kacho_root'
-- (account_id=NULL, is_system=true).

-- 4.1 Wildcards (3).
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, is_system) VALUES
  ('rol' || substr(md5('admin'), 1, 17), 'cluster_kacho_root', NULL, 'admin',  'Global super-admin (all modules, all resources, all verbs)',
    '["*.*.*"]'::jsonb, true),
  ('rol' || substr(md5('edit'),  1, 17), 'cluster_kacho_root', NULL, 'edit',   'Global edit-only (update operations on all resources, no create/delete/admin)',
    '["*.*.update"]'::jsonb, true),
  ('rol' || substr(md5('view'),  1, 17), 'cluster_kacho_root', NULL, 'view',   'Global read-only (read/list/get all)',
    '["*.*.read","*.*.list","*.*.get"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;

-- 4.2 IAM narrow — 7 resources × 3 verbs = 21.
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, is_system) VALUES
  ('rol' || substr(md5('iam.account.admin'),         1, 17), 'cluster_kacho_root', NULL, 'iam.account.admin',         'Admin Account (CRUD)',                  '["iam.account.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.account.edit'),          1, 17), 'cluster_kacho_root', NULL, 'iam.account.edit',          'Edit Account (update only)',            '["iam.account.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.account.view'),          1, 17), 'cluster_kacho_root', NULL, 'iam.account.view',          'Read Account',                          '["iam.account.read","iam.account.list","iam.account.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.project.admin'),         1, 17), 'cluster_kacho_root', NULL, 'iam.project.admin',         'Admin Project',                         '["iam.project.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.project.edit'),          1, 17), 'cluster_kacho_root', NULL, 'iam.project.edit',          'Edit Project',                          '["iam.project.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.project.view'),          1, 17), 'cluster_kacho_root', NULL, 'iam.project.view',          'Read Project',                          '["iam.project.read","iam.project.list","iam.project.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.user.admin'),            1, 17), 'cluster_kacho_root', NULL, 'iam.user.admin',            'Admin User mirror',                     '["iam.user.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.user.edit'),             1, 17), 'cluster_kacho_root', NULL, 'iam.user.edit',             'Edit User',                             '["iam.user.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.user.view'),             1, 17), 'cluster_kacho_root', NULL, 'iam.user.view',             'Read User',                             '["iam.user.read","iam.user.list","iam.user.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.service_account.admin'), 1, 17), 'cluster_kacho_root', NULL, 'iam.service_account.admin', 'Admin ServiceAccount',                  '["iam.service_account.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.service_account.edit'),  1, 17), 'cluster_kacho_root', NULL, 'iam.service_account.edit',  'Edit ServiceAccount',                   '["iam.service_account.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.service_account.view'),  1, 17), 'cluster_kacho_root', NULL, 'iam.service_account.view',  'Read ServiceAccount',                   '["iam.service_account.read","iam.service_account.list","iam.service_account.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.group.admin'),           1, 17), 'cluster_kacho_root', NULL, 'iam.group.admin',           'Admin Group',                           '["iam.group.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.group.edit'),            1, 17), 'cluster_kacho_root', NULL, 'iam.group.edit',            'Edit Group',                            '["iam.group.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.group.view'),            1, 17), 'cluster_kacho_root', NULL, 'iam.group.view',            'Read Group',                            '["iam.group.read","iam.group.list","iam.group.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.role.admin'),            1, 17), 'cluster_kacho_root', NULL, 'iam.role.admin',            'Admin Role catalog',                    '["iam.role.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.role.edit'),             1, 17), 'cluster_kacho_root', NULL, 'iam.role.edit',             'Edit Role',                             '["iam.role.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.role.view'),             1, 17), 'cluster_kacho_root', NULL, 'iam.role.view',             'Read Role',                             '["iam.role.read","iam.role.list","iam.role.get"]'::jsonb, true),
  ('rol' || substr(md5('iam.access_binding.admin'),  1, 17), 'cluster_kacho_root', NULL, 'iam.access_binding.admin',  'Admin AccessBinding',                   '["iam.access_binding.*"]'::jsonb, true),
  ('rol' || substr(md5('iam.access_binding.edit'),   1, 17), 'cluster_kacho_root', NULL, 'iam.access_binding.edit',   'Edit AccessBinding',                    '["iam.access_binding.update"]'::jsonb, true),
  ('rol' || substr(md5('iam.access_binding.view'),   1, 17), 'cluster_kacho_root', NULL, 'iam.access_binding.view',   'Read AccessBinding',                    '["iam.access_binding.read","iam.access_binding.list","iam.access_binding.get"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;

-- 4.3 VPC narrow — 6 resources × 3 verbs = 18.
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, is_system) VALUES
  ('rol' || substr(md5('vpc.network.admin'),         1, 17), 'cluster_kacho_root', NULL, 'vpc.network.admin',         'Admin Network',                         '["vpc.network.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.network.edit'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.network.edit',          'Edit Network',                          '["vpc.network.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.network.view'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.network.view',          'Read Network',                          '["vpc.network.read","vpc.network.list","vpc.network.get"]'::jsonb, true),
  ('rol' || substr(md5('vpc.subnet.admin'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.subnet.admin',          'Admin Subnet',                          '["vpc.subnet.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.subnet.edit'),           1, 17), 'cluster_kacho_root', NULL, 'vpc.subnet.edit',           'Edit Subnet',                           '["vpc.subnet.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.subnet.view'),           1, 17), 'cluster_kacho_root', NULL, 'vpc.subnet.view',           'Read Subnet',                           '["vpc.subnet.read","vpc.subnet.list","vpc.subnet.get"]'::jsonb, true),
  ('rol' || substr(md5('vpc.security_group.admin'),  1, 17), 'cluster_kacho_root', NULL, 'vpc.security_group.admin',  'Admin SecurityGroup',                   '["vpc.security_group.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.security_group.edit'),   1, 17), 'cluster_kacho_root', NULL, 'vpc.security_group.edit',   'Edit SecurityGroup',                    '["vpc.security_group.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.security_group.view'),   1, 17), 'cluster_kacho_root', NULL, 'vpc.security_group.view',   'Read SecurityGroup',                    '["vpc.security_group.read","vpc.security_group.list","vpc.security_group.get"]'::jsonb, true),
  ('rol' || substr(md5('vpc.address.admin'),         1, 17), 'cluster_kacho_root', NULL, 'vpc.address.admin',         'Admin Address',                         '["vpc.address.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.address.edit'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.address.edit',          'Edit Address',                          '["vpc.address.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.address.view'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.address.view',          'Read Address',                          '["vpc.address.read","vpc.address.list","vpc.address.get"]'::jsonb, true),
  ('rol' || substr(md5('vpc.route_table.admin'),     1, 17), 'cluster_kacho_root', NULL, 'vpc.route_table.admin',     'Admin RouteTable',                      '["vpc.route_table.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.route_table.edit'),      1, 17), 'cluster_kacho_root', NULL, 'vpc.route_table.edit',      'Edit RouteTable',                       '["vpc.route_table.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.route_table.view'),      1, 17), 'cluster_kacho_root', NULL, 'vpc.route_table.view',      'Read RouteTable',                       '["vpc.route_table.read","vpc.route_table.list","vpc.route_table.get"]'::jsonb, true),
  ('rol' || substr(md5('vpc.gateway.admin'),         1, 17), 'cluster_kacho_root', NULL, 'vpc.gateway.admin',         'Admin Gateway',                         '["vpc.gateway.*"]'::jsonb, true),
  ('rol' || substr(md5('vpc.gateway.edit'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.gateway.edit',          'Edit Gateway',                          '["vpc.gateway.update"]'::jsonb, true),
  ('rol' || substr(md5('vpc.gateway.view'),          1, 17), 'cluster_kacho_root', NULL, 'vpc.gateway.view',          'Read Gateway',                          '["vpc.gateway.read","vpc.gateway.list","vpc.gateway.get"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;

-- 4.4 Compute narrow — 4 resources × 3 verbs = 12.
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, is_system) VALUES
  ('rol' || substr(md5('compute.instance.admin'),    1, 17), 'cluster_kacho_root', NULL, 'compute.instance.admin',    'Admin Instance',                        '["compute.instance.*"]'::jsonb, true),
  ('rol' || substr(md5('compute.instance.edit'),     1, 17), 'cluster_kacho_root', NULL, 'compute.instance.edit',     'Edit Instance',                         '["compute.instance.update"]'::jsonb, true),
  ('rol' || substr(md5('compute.instance.view'),     1, 17), 'cluster_kacho_root', NULL, 'compute.instance.view',     'Read Instance',                         '["compute.instance.read","compute.instance.list","compute.instance.get"]'::jsonb, true),
  ('rol' || substr(md5('compute.disk.admin'),        1, 17), 'cluster_kacho_root', NULL, 'compute.disk.admin',        'Admin Disk',                            '["compute.disk.*"]'::jsonb, true),
  ('rol' || substr(md5('compute.disk.edit'),         1, 17), 'cluster_kacho_root', NULL, 'compute.disk.edit',         'Edit Disk',                             '["compute.disk.update"]'::jsonb, true),
  ('rol' || substr(md5('compute.disk.view'),         1, 17), 'cluster_kacho_root', NULL, 'compute.disk.view',         'Read Disk',                             '["compute.disk.read","compute.disk.list","compute.disk.get"]'::jsonb, true),
  ('rol' || substr(md5('compute.image.admin'),       1, 17), 'cluster_kacho_root', NULL, 'compute.image.admin',       'Admin Image',                           '["compute.image.*"]'::jsonb, true),
  ('rol' || substr(md5('compute.image.edit'),        1, 17), 'cluster_kacho_root', NULL, 'compute.image.edit',        'Edit Image',                            '["compute.image.update"]'::jsonb, true),
  ('rol' || substr(md5('compute.image.view'),        1, 17), 'cluster_kacho_root', NULL, 'compute.image.view',        'Read Image',                            '["compute.image.read","compute.image.list","compute.image.get"]'::jsonb, true),
  ('rol' || substr(md5('compute.snapshot.admin'),    1, 17), 'cluster_kacho_root', NULL, 'compute.snapshot.admin',    'Admin Snapshot',                        '["compute.snapshot.*"]'::jsonb, true),
  ('rol' || substr(md5('compute.snapshot.edit'),     1, 17), 'cluster_kacho_root', NULL, 'compute.snapshot.edit',     'Edit Snapshot',                         '["compute.snapshot.update"]'::jsonb, true),
  ('rol' || substr(md5('compute.snapshot.view'),     1, 17), 'cluster_kacho_root', NULL, 'compute.snapshot.view',     'Read Snapshot',                         '["compute.snapshot.read","compute.snapshot.list","compute.snapshot.get"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;

-- 4.5 kacho-system built-in (2, hand-rolled deterministic ids).
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, name, description, permissions, is_system) VALUES
    ('rol000000000sysadmin',  'cluster_kacho_root', NULL, 'kacho-system.admin',
        'Built-in system administrator (all permissions across all scopes)',
        '["*.*.*"]'::jsonb, true),
    ('rol000000000sysviewer', 'cluster_kacho_root', NULL, 'kacho-system.viewer',
        'Built-in system viewer (read-only)',
        '["*.*.read", "*.*.list", "*.*.get"]'::jsonb, true)
ON CONFLICT (id) DO NOTHING;

-- 4.6 NLB operator + target_manager (camelCase permission strings,
--     per kacho-nlb authoritative catalog).
INSERT INTO kacho_iam.roles (id, cluster_id, account_id, is_system, name, description, permissions) VALUES
    (
        'rol' || substr(md5('loadbalancer.operator'), 1, 17),
        'cluster_kacho_root', NULL, true,
        'loadbalancer.operator',
        'NLB operator (start/stop/getTargetStates/listOperations + viewer on LB hierarchy)',
        '[
          "loadbalancer.networkLoadBalancers.start",
          "loadbalancer.networkLoadBalancers.stop",
          "loadbalancer.networkLoadBalancers.getTargetStates",
          "loadbalancer.networkLoadBalancers.listOperations",
          "loadbalancer.networkLoadBalancers.get",
          "loadbalancer.networkLoadBalancers.list",
          "loadbalancer.listeners.get",
          "loadbalancer.listeners.list",
          "loadbalancer.listeners.listOperations",
          "loadbalancer.targetGroups.get",
          "loadbalancer.targetGroups.list",
          "loadbalancer.targetGroups.listOperations",
          "loadbalancer.operations.get"
        ]'::jsonb
    ),
    (
        'rol' || substr(md5('loadbalancer.target_manager'), 1, 17),
        'cluster_kacho_root', NULL, true,
        'loadbalancer.target_manager',
        'NLB target manager (addTargets/removeTargets/getTargetStates + viewer on LB hierarchy)',
        '[
          "loadbalancer.targetGroups.addTargets",
          "loadbalancer.targetGroups.removeTargets",
          "loadbalancer.networkLoadBalancers.getTargetStates",
          "loadbalancer.targetGroups.get",
          "loadbalancer.targetGroups.list",
          "loadbalancer.targetGroups.listOperations",
          "loadbalancer.networkLoadBalancers.get",
          "loadbalancer.networkLoadBalancers.list",
          "loadbalancer.listeners.get",
          "loadbalancer.listeners.list",
          "loadbalancer.operations.get"
        ]'::jsonb
    )
ON CONFLICT (id) DO NOTHING;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Squash-baseline: irreversibly drops the whole kacho_iam schema. The original
-- 20-step migration trail is archived under docs/architecture/migrations-history/
-- for audit but cannot be replayed step-by-step from this single file.
DROP SCHEMA IF EXISTS kacho_iam CASCADE;

-- +goose StatementEnd
