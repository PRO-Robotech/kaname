-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Go предлагает только итоговые факты по удержанным координатам. Владелец
-- сверяет предложения с расчётом и возвращает снимок для exact preflight.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_retention_compile_v1(p_desired jsonb,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $compile$
DECLARE
    session_state jsonb;
    packet jsonb;
    v_group text;
    source_key text;
    certificate jsonb;
    required jsonb;
    physical_sources jsonb;
    used_work integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    session_state:=kaname._authority_metadata_access_label_stashed_v1();
    packet:=session_state->'retention';
    v_group:=session_state#>>'{root,root_coordinate,1}';
    source_key:=jsonb_build_array(30,'iam.group',v_group,'')::text;
    IF jsonb_typeof(packet) IS DISTINCT FROM 'object'
        OR session_state#>>'{root,root_coordinate,0}' IS DISTINCT FROM 'iam.group'
        OR coalesce(v_group,'')='' OR packet->>'root_id' IS DISTINCT FROM v_group
        OR packet->>'root_type' IS DISTINCT FROM 'iam.group'
        OR packet->>'root_model' IS DISTINCT FROM 'iam_group'
        OR packet->>'root_source_kind' IS DISTINCT FROM '30'
        OR packet->'update_question' IS DISTINCT FROM session_state#>'{root,update_question}'
        OR packet->'old_row' IS DISTINCT FROM session_state#>'{root,root_state,2}'
        OR packet#>ARRAY['source_index',source_key,'states','0'] IS DISTINCT FROM session_state#>'{root,root_state}'
        OR jsonb_typeof(packet->'candidate_facts') IS DISTINCT FROM 'array'
        OR jsonb_typeof(packet->'partition_required') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'group retention certificate custody differs' USING ERRCODE='42501';
    END IF;
    IF p_work IS NULL OR p_work NOT BETWEEN 1 AND 400000 THEN
        RAISE EXCEPTION 'group retention certificate work budget invalid' USING ERRCODE='54000';
    END IF;
    certificate:=kaname._authority_metadata_access_label_retention_certify_v1(
        packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work-1);
    required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(source_key,true);
    physical_sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);
    used_work:=1+(certificate->>'work')::integer+(physical_sources->>'work')::integer;
    IF used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'group retention certificate work exceeded' USING ERRCODE='54000';
    END IF;
    RETURN jsonb_build_object(
        'receipt',jsonb_build_object('root_type','iam.group','root_id',v_group,
            'old_labels',packet#>'{old_row,access_labels}','new_labels',packet#>'{new_row,access_labels}',
            'facts',packet->'candidate_facts'),
        'retention',jsonb_build_object('certificate',certificate,'sources',physical_sources,
            'physical',jsonb_build_object('members',physical_sources->'members','ledger',physical_sources->'ledger'),
            'folded',jsonb_build_object('facts',physical_sources->'facts')),
        'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',
        'update_question',packet->'update_question','rows',1,'reads',1,'work',used_work);
END;
$compile$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
    fn regprocedure:='kaname._authority_metadata_group_retention_compile_v1(jsonb,integer)'::regprocedure;
    grantee record;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
        CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
        WHERE p.oid=fn AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_group_retention_compile_v1(jsonb,integer);
