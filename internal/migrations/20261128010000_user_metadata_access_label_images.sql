-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Маска нормализована до отсутствующего поля либо выбранной карты. Оба типа
-- меток используют тот же контракт domain.Labels: строки, пределы в байтах,
-- не более 64 ключей. Наличие access_labels обязательно для этого пути.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_patch_images_v1(p_old jsonb,p_patch jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $images$
DECLARE
    next_row jsonb;
    changed text[]:=ARRAY[]::text[];
    mode_name text:='noop';
BEGIN
    IF jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR jsonb_typeof(p_patch) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'invalid user metadata image or patch' USING ERRCODE='42501';
    END IF;
    IF octet_length(p_old::text)::bigint+octet_length(p_patch::text)>8388608 THEN
        RAISE EXCEPTION 'user metadata images exceed input budget' USING ERRCODE='54000';
    END IF;
    IF coalesce(p_old->>'id','') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR (p_patch-ARRAY['labels','access_labels'])<>'{}'::jsonb
        OR kaname.access_labels_valid_v1(p_old->'labels') IS DISTINCT FROM true
        OR kaname.access_labels_valid_v1(p_old->'access_labels') IS DISTINCT FROM true
        OR kaname.access_labels_valid_v1(p_patch->'access_labels') IS DISTINCT FROM true
        OR (p_patch ? 'labels' AND kaname.access_labels_valid_v1(p_patch->'labels') IS DISTINCT FROM true) THEN
        RAISE EXCEPTION 'user metadata patch or source maps differ from contract' USING ERRCODE='42501';
    END IF;
    next_row:=p_old||p_patch;
    IF next_row->'labels' IS DISTINCT FROM p_old->'labels' THEN
        changed:=array_append(changed,'labels');
        mode_name:='ordinary';
    END IF;
    IF next_row->'access_labels' IS DISTINCT FROM p_old->'access_labels' THEN
        changed:=array_append(changed,'access_labels');
        mode_name:='access_labels';
    END IF;
    RETURN jsonb_build_object('new_row',next_row,'changed_fields',changed,'mode',mode_name);
END;
$images$;
-- +goose StatementEnd

-- Родительская подготовка помещает этот target целиком в штатный stash
-- вместе с планом источников. nonce связывает его с этим входом в протокол.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_patch_target_v1(
    p_id text,p_xmin text,p_ctid text,p_old jsonb,p_memberships jsonb,p_patch jsonb,
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $target$
DECLARE
    target jsonb;
    proof jsonb;
    images jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    target:=kaname._authority_metadata_user_target_v1(p_id,p_xmin,p_ctid,p_old,p_memberships,
        p_actor_type,p_actor_id,p_rows,p_reads);
    proof:=kaname.authority_protocol_attestation();
    IF nullif(proof->>'nonce','') IS NULL THEN
        RAISE EXCEPTION 'user metadata patch requires the current attempt' USING ERRCODE='42501';
    END IF;
    images:=kaname._authority_metadata_user_patch_images_v1(target#>'{root_state,2}',p_patch);
    RETURN target||jsonb_build_object('patch',p_patch,'patch_nonce',proof->'nonce',
        'mode',images->'mode','changed_fields',images->'changed_fields');
END;
$target$;
-- +goose StatementEnd

-- После получения epoch/row locks повторно выводим образы из закрытого stash,
-- сохраняем их один раз. Это вход для расчёта выдач и проверки apply.
-- Права на запись и фактические эффекты устанавливаются позднее.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_freeze_images_v1(
    p_actor_type text,p_actor_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $freeze$
DECLARE
    session_state jsonb;
    target jsonb;
    held jsonb;
    old_row jsonb;
    images jsonb;
    packet jsonb;
    replacement jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096 THEN
        RAISE EXCEPTION 'user metadata freeze exceeds budget' USING ERRCODE='54000';
    END IF;
    session_state:=kaname._authority_metadata_access_label_stashed_v1();
    target:=session_state->'root';
    IF session_state ? 'user_images' OR nullif(session_state#>>'{plan,nonce}','') IS NULL
        OR target->'patch_nonce' IS DISTINCT FROM session_state#>'{plan,nonce}' THEN
        RAISE EXCEPTION 'user metadata patch is absent, foreign, or already frozen' USING ERRCODE='42501';
    END IF;
    held:=kaname._authority_metadata_user_target_hold_v1(p_actor_type,p_actor_id,p_rows-2,p_reads-2);
    old_row:=held#>'{root_state,2}';
    images:=kaname._authority_metadata_user_patch_images_v1(old_row,target->'patch');
    IF held->'root_state' IS DISTINCT FROM target->'root_state'
        OR held->'membership_states' IS DISTINCT FROM target->'membership_states'
        OR held->'update_question' IS DISTINCT FROM target->'update_question'
        OR images->'mode' IS DISTINCT FROM target->'mode'
        OR images->'changed_fields' IS DISTINCT FROM target->'changed_fields' THEN
        RAISE EXCEPTION 'user metadata held image or classification differs' USING ERRCODE='40001';
    END IF;
    packet:=images||jsonb_build_object('nonce',target->'patch_nonce','root_type','iam.user',
        'root_model','iam_user','root_source_kind',30,'root_id',old_row->>'id',
        'root_physical',jsonb_build_object('table','users','id',old_row->>'id',
            'xmin',held#>>'{root_state,0}','ctid',held#>>'{root_state,1}'),
        'actor',jsonb_build_object('type',p_actor_type,'id',p_actor_id),'update_question',held->'update_question',
        'membership_states',held->'membership_states','patch',target->'patch','old_row',old_row);
    replacement:=session_state||jsonb_build_object('user_images',packet);
    IF octet_length(replacement::text)>67108864 THEN
        RAISE EXCEPTION 'user metadata private packet exceeds storage budget' USING ERRCODE='54000';
    END IF;
    UPDATE pg_temp.kaname_authority_metadata_discovery AS d SET prepared=replacement
    WHERE d.singleton AND d.prepared=session_state AND NOT (d.prepared ? 'user_images');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user metadata image custody changed' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('rows',(held->>'rows')::integer+2,'reads',(held->>'reads')::integer+2,
        'changed_fields',images->'changed_fields','mode',images->'mode');
END;
$freeze$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure;
    recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_patch_images_v1(jsonb,jsonb)'::regprocedure,
        'kaname._authority_metadata_user_patch_target_v1(text,text,text,jsonb,jsonb,jsonb,text,text,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_freeze_images_v1(text,text,integer,integer)'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE quote_ident(recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_user_freeze_images_v1(text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_patch_target_v1(text,text,text,jsonb,jsonb,jsonb,text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_patch_images_v1(jsonb,jsonb);
