-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Финальная отметка времени относится к уже зарезервированной pending-операции.
-- Вызов предшествует native record_writer/grant и отдельному SQL apply.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_user_finalize_v1(p_user_id text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $finalize$
DECLARE
    saved jsonb;
    images jsonb;
    program jsonb;
    command jsonb;
    proof jsonb;
    mode_name text;
    at_time timestamptz;
BEGIN
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    PERFORM kaname._authority_metadata_user_write_acl_v1(saved,true);
    images:=saved->'user_images';
    mode_name:=images->>'mode';
    program:=kaname._authority_sequence_store_v3();
    command:=program->'frozen';
    proof:=kaname.authority_protocol_attestation();
    at_time:=(proof->>'decision_at')::timestamptz;
    IF p_user_id IS NULL OR p_user_id IS DISTINCT FROM images->>'root_id' OR images->>'root_type' IS DISTINCT FROM 'iam.user'
        OR p_user_id IS DISTINCT FROM command#>>'{pending,2,resource_id}'
        OR command#>>'{pending,2,user_access_labels}' IS DISTINCT FROM 'true'
        OR command#>>'{pending,2,done}' IS DISTINCT FROM 'false'
        OR command->'question' IS DISTINCT FROM images->'update_question'
        OR proof->'nonce' IS DISTINCT FROM images->'nonce' OR proof->'nonce' IS DISTINCT FROM program->'nonce'
        OR program->>'family' IS DISTINCT FROM 'metadata' OR command->>'phase' IS DISTINCT FROM 'reserved'
        OR mode_name IS NULL OR mode_name NOT IN ('noop','ordinary','access_labels')
        OR program->>'frozen_mode' IS DISTINCT FROM 'user_'||mode_name OR command->>'mode' IS DISTINCT FROM program->>'frozen_mode'
        OR command->>'kind' IS DISTINCT FROM 'metadata.user.'||mode_name
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR at_time IS NULL OR NOT isfinite(at_time) OR (program->>'staged_decision_at')::timestamptz IS NULL
        OR at_time<=(program->>'staged_decision_at')::timestamptz THEN
        RAISE EXCEPTION 'user metadata final clock requires its reserved operation' USING ERRCODE='42501';
    END IF;
    IF mode_name='noop' THEN
        IF program->'maximum' IS DISTINCT FROM '[]'::jsonb THEN
            RAISE EXCEPTION 'user noop final clock requires an empty reservation' USING ERRCODE='42501';
        END IF;
    ELSIF program->>'maximum_count' IS DISTINCT FROM '1'
        OR program#>>'{maximum,0,table}' IS DISTINCT FROM 'resource_journal'
        OR program#>'{maximum,0,origin}' IS DISTINCT FROM command#>'{effects,maximum,0,origin}'
        OR (mode_name='access_labels' AND saved->'user_protected_reserved' IS DISTINCT FROM proof->'nonce') THEN
        RAISE EXCEPTION 'user metadata final clock differs from its journal reservation' USING ERRCODE='42501';
    END IF;
    PERFORM kaname.authority_scalar_sequence_finalize_v3();
END;
$finalize$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname.authority_metadata_user_finalize_v1(text)'::regprocedure; recipient record;
BEGIN
    IF EXISTS(SELECT FROM (VALUES
        ('authority_scalar_sequence_finalize_v3()','c403ea97073dc0833cacdbfbd79691ccd1b11a6b0ca4c71fb2a73112e7d58be8',true),
        ('_authority_metadata_user_write_acl_v1(jsonb,boolean)','8b7ca5f72127039c83bcf26667da160d7c7a518337419db1c0d9108f29264b7b',false),
        ('authority_metadata_user_finalize_v1(text)','ff8aa07d3c8f01cb20428ab0d708818be2a0985e7d4a088689b82574a12a942c',true)
    ) dep(signature,digest,definer)
    WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||dep.signature)
        AND p.proowner=current_user::regrole AND p.prosecdef=dep.definer AND p.provolatile='v'
        AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
        AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=dep.digest)) THEN
        RAISE EXCEPTION 'user metadata final clock contract differs' USING ERRCODE='55000';
    END IF;
    FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE format('%I',recipient.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_metadata_user_finalize_v1(text);
