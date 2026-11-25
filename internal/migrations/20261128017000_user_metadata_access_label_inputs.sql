-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Писатель удерживает старое поколение после физического User, как worker.
-- Сохранённые факты остаются кандидатами на проверку и отзыв при смене меток.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_carry_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $carry$
DECLARE
    session_state jsonb;
    images jsonb;
    held_row jsonb;
    held_physical jsonb;
    v_user text;
    previous_generation uuid;
    previous_labels jsonb;
    facts jsonb;
    fact_count integer;
    used_rows integer:=3;
    used_reads integer:=3;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'user access label carry budget exhausted' USING ERRCODE='54000';
    END IF;
    session_state:=kaname._authority_metadata_access_label_stashed_v1();
    images:=session_state->'user_images';
    v_user:=images->>'root_id';
    IF images->>'root_type' IS DISTINCT FROM 'iam.user' OR images->>'root_model' IS DISTINCT FROM 'iam_user'
        OR images->'root_source_kind' IS DISTINCT FROM '30'::jsonb
        OR images->>'mode' IS DISTINCT FROM 'access_labels'
        OR images->'nonce' IS DISTINCT FROM session_state#>'{plan,nonce}'
        OR coalesce(v_user,'') COLLATE "C" !~ '^usr[a-zA-Z0-9_-]{1,61}$'
        OR session_state#>'{root,root_coordinate}' IS DISTINCT FROM jsonb_build_array('iam.user',v_user)
        OR images->'old_row' IS DISTINCT FROM session_state#>'{root,root_state,2}'
        OR images->'membership_states' IS DISTINCT FROM session_state#>'{root,membership_states}'
        OR kaname.access_labels_valid_v1(images#>'{old_row,access_labels}') IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'user access label carry needs held user images' USING ERRCODE='42501';
    END IF;

    SELECT to_jsonb(u),jsonb_build_object('table','users','id',u.id,'xmin',u.xmin::text,'ctid',u.ctid::text)
    INTO held_row,held_physical FROM ONLY kaname.users u WHERE u.id=v_user FOR UPDATE OF u NOWAIT;
    IF NOT FOUND OR held_row IS DISTINCT FROM images->'old_row'
        OR held_physical IS DISTINCT FROM images->'root_physical' THEN
        RAISE EXCEPTION 'user changed before access label carry' USING ERRCODE='40001';
    END IF;
    LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact
        IN ROW EXCLUSIVE MODE NOWAIT;
    SELECT d.generation,d.new_labels INTO previous_generation,previous_labels
    FROM kaname.authority_access_label_dirty_root d
    WHERE d.root_type='iam.user' AND d.root_id=v_user FOR UPDATE OF d NOWAIT;
    IF NOT FOUND THEN
        RETURN jsonb_build_object('prior_generation',NULL,'prior_facts','[]'::jsonb,'rows',used_rows,'reads',used_reads);
    END IF;
    IF previous_labels IS DISTINCT FROM images#>'{old_row,access_labels}' THEN
        RAISE EXCEPTION 'user access label generation differs from the held image' USING ERRCODE='40001';
    END IF;
    IF used_reads=p_reads THEN
        RAISE EXCEPTION 'user access label carry budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT count(*)::integer,coalesce(jsonb_agg(to_jsonb(f)
        ORDER BY f.object_type COLLATE "C",f.object_id COLLATE "C",f.relation COLLATE "C",f.subject COLLATE "C"),'[]')
    INTO fact_count,facts FROM (
        SELECT d.object_type,d.object_id,d.relation,d.subject FROM kaname.authority_access_label_dirty_fact d
        WHERE d.root_type='iam.user' AND d.root_id=v_user AND d.generation=previous_generation
        LIMIT p_rows-used_rows+1 FOR UPDATE OF d NOWAIT
    ) f;
    IF fact_count>p_rows-used_rows THEN
        RAISE EXCEPTION 'user access label carry budget exhausted' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object('prior_generation',previous_generation,'prior_facts',facts,
        'rows',used_rows+fact_count,'reads',used_reads+1);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'user access label prior generation busy; restage required' USING ERRCODE='40001';
END;
$carry$;
-- +goose StatementEnd

-- Закрепляем доказательства apply и прежнего поколения за одним nonce.
-- Финальная программа берёт их здесь, пока удерживаются физические блокировки.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_hold_apply_and_carry_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $inputs$
DECLARE
    session_state jsonb;
    compiled jsonb;
    carry jsonb;
    evidence jsonb;
    used_rows integer:=2;
    used_reads integer:=2;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
        RAISE EXCEPTION 'user access label input budget exhausted' USING ERRCODE='54000';
    END IF;
    session_state:=kaname._authority_metadata_access_label_stashed_v1();
    IF session_state ? 'user_access_label_inputs'
        OR session_state#>>'{user_images,mode}' IS DISTINCT FROM 'access_labels'
        OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
        RAISE EXCEPTION 'user access label inputs at the wrong phase' USING ERRCODE='42501';
    END IF;
    compiled:=kaname._authority_metadata_user_apply_sources_v1(p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(compiled->>'rows')::integer;
    used_reads:=used_reads+(compiled->>'reads')::integer;
    carry:=kaname._authority_metadata_user_carry_v1(p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(carry->>'rows')::integer;
    used_reads:=used_reads+(carry->>'reads')::integer;
    IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
        RAISE EXCEPTION 'user access label input budget exhausted' USING ERRCODE='54000';
    END IF;
    evidence:=jsonb_build_object('nonce',session_state#>'{plan,nonce}','root_id',session_state#>'{user_images,root_id}',
        'requirements',compiled->'requirements','authority',compiled->'authority','carry',carry-ARRAY['rows','reads']);
    IF octet_length(session_state::text)::bigint+octet_length(evidence::text)>67108608 THEN
        RAISE EXCEPTION 'user access label input evidence exceeds storage budget' USING ERRCODE='54000';
    END IF;
    UPDATE pg_temp.kaname_authority_metadata_discovery d
    SET prepared=session_state||jsonb_build_object('user_access_label_inputs',evidence)
    WHERE d.singleton AND d.prepared=session_state AND NOT (d.prepared ? 'user_access_label_inputs');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user access label input custody changed' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads);
END;
$inputs$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_carry_v1(integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_hold_apply_and_carry_v1(integer,integer)'::regprocedure
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
DROP FUNCTION kaname._authority_metadata_user_hold_apply_and_carry_v1(integer,integer);
DROP FUNCTION kaname._authority_metadata_user_carry_v1(integer,integer);
