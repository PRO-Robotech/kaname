-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Фасады оставлены закрытыми до готовности установленной цепочки User.Update.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_user_access_labels_operation_create_v1(
    p_id text,p_created_at timestamptz,p_user_id text,p_account_id text,p_metadata bytea,
    p_actor_type text,p_actor_id text,p_display_name text
) RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $create$
DECLARE invoker oid;
BEGIN
    SELECT r.oid INTO STRICT invoker FROM pg_catalog.pg_roles r
    WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
    -- Дискриминатор user_access_labels выставляет владелец. Всё остальное
    -- должно быть доступно исходной роли так же, как в обычном INSERT.
    IF has_table_privilege(invoker,'kaname.users','SELECT') IS DISTINCT FROM true
        OR EXISTS(SELECT FROM unnest(ARRAY['id','description','created_at','created_by','modified_at',
            'done','metadata_type','metadata_data','resource_id','account_id','principal_type','principal_id',
            'principal_display_name']) f
            WHERE has_column_privilege(invoker,'kaname.operations',f,'INSERT') IS DISTINCT FROM true) THEN
        RAISE EXCEPTION 'user operation original data privileges absent' USING ERRCODE='42501';
    END IF;
    IF coalesce(octet_length(p_metadata),0) NOT BETWEEN 1 AND 8388608 THEN
        RAISE EXCEPTION 'user operation metadata size exceeds budget' USING ERRCODE='54000';
    END IF;
    PERFORM kaname._authority_user_access_labels_operation_create_v1(
        p_id,p_created_at,p_user_id,p_account_id,p_metadata,p_actor_type,p_actor_id,p_display_name);
END;
$create$;

CREATE FUNCTION kaname.authority_metadata_user_prepare_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_memberships jsonb,p_patch jsonb,
    p_actor_type text,p_actor_id text,p_policy_expected jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS TABLE(used_rows integer,used_reads integer,used_work integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
    image_mode text;
    target jsonb;
    proof jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 4 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 3 AND 400000 THEN
        RAISE EXCEPTION 'user metadata preparation budget invalid' USING ERRCODE='54000';
    END IF;
    image_mode:=kaname._authority_metadata_user_patch_images_v1(p_old,p_patch)->>'mode';
    IF image_mode='access_labels' THEN
        RETURN QUERY SELECT * FROM kaname._authority_metadata_user_prepare_v1(p_id,p_xmin,p_ctid,p_old,p_memberships,
            p_patch,p_actor_type,p_actor_id,p_policy_expected,p_rows,p_reads,p_work);
        RETURN;
    END IF;
    IF jsonb_typeof(p_policy_expected) IS DISTINCT FROM 'object'
        OR NOT (p_policy_expected ?& ARRAY['*','user:'||p_id]) THEN
        RAISE EXCEPTION 'user metadata policy epochs are incomplete' USING ERRCODE='P1034';
    END IF;
    proof:=kaname.authority_protocol_attestation();
    target:=kaname._authority_metadata_user_patch_target_v1(p_id,p_xmin,p_ctid,p_old,p_memberships,p_patch,
        p_actor_type,p_actor_id,p_rows-2,p_reads-2);
    IF target->>'mode' IS DISTINCT FROM image_mode OR image_mode NOT IN ('noop','ordinary') THEN
        RAISE EXCEPTION 'user metadata classification changed' USING ERRCODE='40001';
    END IF;
    used_rows:=2+(target->>'rows')::integer;
    used_reads:=2+(target->>'reads')::integer;
    used_work:=used_rows+1;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads
        OR used_work IS NULL OR used_work>p_work THEN
        RAISE EXCEPTION 'user metadata preparation budget exhausted' USING ERRCODE='54000';
    END IF;
    PERFORM kaname._authority_metadata_access_label_stash_v1(jsonb_build_object(
        'root',target,'discovery','{}'::jsonb,'plan',proof,'catalog_id',proof->'catalog_id'));
    RETURN NEXT;
END;
$prepare$;

CREATE FUNCTION kaname.authority_metadata_user_retention_inputs_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $retention$
DECLARE
    held jsonb;
    apply_receipt jsonb;
    retained jsonb;
    used_rows integer;
    used_reads integer;
    used_work integer;
BEGIN
    held:=kaname._authority_metadata_user_hold_and_replay_v1(p_actor_type,p_actor_id,p_rows,p_reads,p_work);
    used_rows:=(held->>'rows')::integer;
    used_reads:=(held->>'reads')::integer;
    used_work:=(held->>'work')::integer;
    apply_receipt:=kaname._authority_metadata_user_hold_apply_and_carry_v1(p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(apply_receipt->>'rows')::integer;
    used_reads:=used_reads+(apply_receipt->>'reads')::integer;
    retained:=kaname._authority_metadata_user_retention_prepare_v1(p_rows-used_rows,p_reads-used_reads,p_work-used_work);
    used_rows:=used_rows+(retained->>'rows')::integer;
    used_reads:=used_reads+(retained->>'reads')::integer;
    used_work:=used_work+(retained->>'work')::integer;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'user metadata retention budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN retained||jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$retention$;

CREATE FUNCTION kaname.authority_metadata_user_reserve_v1(
    p_op text,p_created timestamptz,p_metadata bytea,p_account text,p_actor_type text,p_actor_id text,p_display text,
    p_audit text,p_desired jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
    image_mode text;
    resource jsonb;
    used_rows integer;
    used_reads integer;
    used_work integer;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 2 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
        RAISE EXCEPTION 'user metadata reservation budget invalid' USING ERRCODE='54000';
    END IF;
    image_mode:=kaname._authority_metadata_access_label_stashed_v1()#>>'{root,mode}';
    CASE
        WHEN image_mode='noop' AND p_desired IS NULL AND p_audit IS NULL THEN
            resource:=kaname._authority_metadata_user_noop_reserve_v1(
                p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows-1,p_reads-1);
        WHEN image_mode='ordinary' AND p_desired IS NULL AND p_audit IS NOT NULL THEN
            resource:=kaname._authority_metadata_user_ordinary_reserve_v1(
                p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows-1,p_reads-1,p_audit);
        WHEN image_mode='access_labels' AND jsonb_typeof(p_desired)='object' AND p_audit IS NOT NULL THEN
            resource:=kaname._authority_metadata_user_protected_reserve_v1(
                p_op,p_created,p_metadata,p_account,p_actor_type,p_actor_id,p_display,p_rows-1,p_reads-1,p_audit,p_desired,p_work);
        ELSE
            RAISE EXCEPTION 'user metadata reservation does not match held mode' USING ERRCODE='42501';
    END CASE;
    used_rows:=1+(resource->>'rows')::integer;
    used_reads:=1+(resource->>'reads')::integer;
    used_work:=CASE WHEN image_mode='access_labels' THEN (resource->>'work')::integer ELSE 1 END;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'user metadata reservation budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN resource||jsonb_build_object('mode',image_mode,'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$reserve$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_user_apply_v1(
    p_op text,p_nonce uuid,p_decision timestamptz,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $apply$
DECLARE
    images jsonb;
    proof jsonb;
    program jsonb;
    resource jsonb;
    image_mode text;
    cost jsonb;
    used_rows integer:=3;
    used_reads integer:=3;
    used_work integer:=1;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
        RAISE EXCEPTION 'user metadata apply budget invalid' USING ERRCODE='54000';
    END IF;
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    proof:=kaname.authority_protocol_attestation();
    program:=kaname._authority_sequence_store_v3();
    image_mode:=images->>'mode';
    IF proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
        OR p_nonce IS NULL OR p_nonce::text IS DISTINCT FROM proof->>'nonce'
        OR proof->'nonce' IS DISTINCT FROM images->'nonce' OR proof->'nonce' IS DISTINCT FROM program->'nonce'
        OR p_op IS DISTINCT FROM program#>>'{frozen,pending,2,id}' OR program#>>'{frozen,phase}' IS DISTINCT FROM 'reserved'
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program->>'frozen_mode' IS DISTINCT FROM 'user_'||image_mode
        OR p_decision IS NULL OR NOT isfinite(p_decision)
        OR p_decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR p_decision IS DISTINCT FROM (program->>'decision_at')::timestamptz
        OR (program->>'staged_decision_at')::timestamptz IS NULL
        OR p_decision<=(program->>'staged_decision_at')::timestamptz THEN
        RAISE EXCEPTION 'user metadata apply does not match final operation' USING ERRCODE='42501';
    END IF;
    CASE image_mode
        WHEN 'noop' THEN
            IF program->'selected' IS DISTINCT FROM '[]'::jsonb OR images->'new_row' IS DISTINCT FROM images->'old_row' THEN
                RAISE EXCEPTION 'user metadata no-op acquired effects' USING ERRCODE='42501';
            END IF;
            resource:=images->'new_row';
        WHEN 'ordinary' THEN
            used_rows:=used_rows+12;
            used_reads:=used_reads+12;
            IF used_rows>p_rows OR used_reads>p_reads THEN
                RAISE EXCEPTION 'ordinary user metadata apply budget exhausted' USING ERRCODE='54000';
            END IF;
            resource:=kaname._authority_metadata_user_ordinary_write_v1(p_op,p_nonce,p_decision);
        WHEN 'access_labels' THEN
            used_rows:=used_rows+12;
            used_reads:=used_reads+12;
            cost:=kaname._authority_metadata_user_protected_approve_v1(
                p_op,p_nonce,p_decision,p_rows-used_rows,p_reads-used_reads,p_work-used_work);
            used_rows:=used_rows+(cost->>'rows')::integer;
            used_reads:=used_reads+(cost->>'reads')::integer;
            used_work:=used_work+(cost->>'work')::integer;
            IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads
                OR used_work IS NULL OR used_work>p_work THEN
                RAISE EXCEPTION 'protected user metadata apply budget exhausted' USING ERRCODE='54000';
            END IF;
            resource:=kaname._authority_metadata_user_protected_write_v1(p_op,p_nonce,p_decision);
        ELSE
            RAISE EXCEPTION 'user metadata apply mode unknown' USING ERRCODE='42501';
    END CASE;
    IF resource IS DISTINCT FROM images->'new_row' OR jsonb_typeof(resource) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'user metadata result differs from held image' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('user',resource,'mode',image_mode,'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$apply$;

CREATE FUNCTION kaname.authority_metadata_user_complete_v1(
    p_op text,p_nonce uuid,p_decision timestamptz,p_response bytea
) RETURNS kaname.operations LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE mode_name text;
BEGIN
    mode_name:=kaname._authority_sequence_store_v3()->>'frozen_mode';
    CASE mode_name
        WHEN 'user_noop' THEN
            RETURN kaname._authority_metadata_user_noop_complete_v1(p_op,p_nonce,p_decision,p_response);
        WHEN 'user_ordinary' THEN
            RETURN kaname._authority_metadata_user_ordinary_complete_v1(p_op,p_nonce,p_decision,p_response);
        WHEN 'user_access_labels' THEN
            RETURN kaname._authority_metadata_user_protected_complete_v1(p_op,p_nonce,p_decision,p_response);
        ELSE
            RAISE EXCEPTION 'user metadata completion has no reserved mode' USING ERRCODE='42501';
    END CASE;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)'::regprocedure,
        'kaname.authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer)'::regprocedure,
        'kaname.authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer)'::regprocedure,
        'kaname.authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer)'::regprocedure,
        'kaname.authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer)'::regprocedure,
        'kaname.authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea)'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_metadata_user_complete_v1(text,uuid,timestamptz,bytea);
DROP FUNCTION kaname.authority_metadata_user_apply_v1(text,uuid,timestamptz,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_user_reserve_v1(text,timestamptz,bytea,text,text,text,text,text,jsonb,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_user_retention_inputs_v1(text,text,integer,integer,integer);
DROP FUNCTION kaname.authority_metadata_user_prepare_v1(text,text,text,jsonb,jsonb,jsonb,text,text,jsonb,integer,integer,integer);
DROP FUNCTION kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text);
