-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Проверяем apply на финальном времени из той же RC-транзакции.
-- Перед этим доверенный writer проверяет обычный v_update для того же актора.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_group_accept_v1(
 p_actor_type text,p_actor_id text,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $approve$
DECLARE
 proof jsonb;
 header jsonb;
 program jsonb;
 frozen_program jsonb;
 authority_receipt jsonb;
 requirements jsonb;
 freshness jsonb;
 group_id text;
 decision timestamptz;
 matches integer;
 affected integer;
 receipt_cost jsonb;
 retained jsonb; final_freshness jsonb;
 used_work integer:=1; compare_work integer;
 used_rows integer:=4;
 used_reads integer:=3;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
  RAISE EXCEPTION 'group metadata apply approval budget exhausted' USING ERRCODE='54000';END IF;
 SELECT x.proof,x.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() x;
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'full'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
  OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'purpose' IS DISTINCT FROM 'decision'
  OR header->>'family' IS DISTINCT FROM 'metadata'
  OR header#>>'{frozen,mode}' IS DISTINCT FROM 'group_access_labels'
  OR (header->>'maximum_count')::integer IS DISTINCT FROM 1
  OR (header->>'selected_count')::integer IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'group metadata apply approval lacks final owner program' USING ERRCODE='42501';END IF;
 program:=kaname._authority_sequence_store_v3();
 frozen_program:=program->'frozen';
 authority_receipt:=frozen_program->'access_label_authority';
 requirements:=frozen_program->'access_label_requirements';
 freshness:=frozen_program->'access_label_freshness';
 decision:=(program->>'decision_at')::timestamptz;
 group_id:=freshness->>'root_id';
 IF frozen_program->>'kind' IS DISTINCT FROM 'metadata.access_labels'
  OR frozen_program->>'mode' IS DISTINCT FROM 'group_access_labels'
  OR frozen_program ? 'access_label_approved_at'
  OR decision IS NULL OR NOT isfinite(decision)
  OR decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
  OR (program->>'staged_decision_at')::timestamptz IS NULL
  OR decision<=(program->>'staged_decision_at')::timestamptz
  OR jsonb_typeof(requirements) IS DISTINCT FROM 'array' OR jsonb_array_length(requirements) NOT BETWEEN 1 AND 128
  OR jsonb_typeof(freshness) IS DISTINCT FROM 'object'
  OR jsonb_typeof(freshness->'facts') IS DISTINCT FROM 'array'
  OR freshness->>'root_type' IS DISTINCT FROM 'iam.group' OR coalesce(group_id,'')=''
  OR coalesce(p_actor_type,'') NOT IN ('user','service_account')
  OR coalesce(p_actor_id,'')='' OR octet_length(p_actor_id)>16384 OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
  OR authority_receipt->'actor' IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id)
  OR frozen_program->'group_update_question' IS DISTINCT FROM jsonb_build_object(
    'subject',p_actor_type||':'||p_actor_id,'relation','v_update','object_type','iam_group','object_id',group_id) THEN
  RAISE EXCEPTION 'group metadata apply actor or evidence differs from prepared command' USING ERRCODE='42501';END IF;
 SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e
 WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1
  AND e.table_name='resource_journal' AND e.selected
  AND NOT (e.registered OR e.claimed OR e.consumed)
  AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'
  AND e.origin->>'table'='groups'
  AND e.origin#>>'{old,id}'=group_id AND e.origin#>>'{new,id}'=group_id
  AND e.origin#>'{old,access_labels}'=freshness->'old_labels'
  AND e.origin#>'{new,access_labels}'=freshness->'new_labels';
 IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN
  RAISE EXCEPTION 'group metadata apply origin changed before approval' USING ERRCODE='42501';END IF;
 receipt_cost:=kaname._authority_resource_access_label_sources_require_v1(
  authority_receipt,requirements,decision,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(receipt_cost->>'rows')::integer;
 used_reads:=used_reads+(receipt_cost->>'reads')::integer;
 IF used_rows IS NULL OR used_rows>p_rows OR used_reads IS NULL OR used_reads>p_reads THEN
  RAISE EXCEPTION 'group metadata apply approval budget exhausted' USING ERRCODE='54000';END IF;
 -- На окончательном времени решения используем удержанные сертификат
 -- и физические свидетельства.
 retained:=kaname._authority_metadata_access_label_retained_select_v1(
  frozen_program->'access_label_freshness_proofs',decision,p_work-used_work);
 used_work:=used_work+(retained->>'work')::integer;
 IF jsonb_typeof(retained->'facts') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'group metadata retained selection omitted facts' USING ERRCODE='42501';END IF;
 compare_work:=2*jsonb_array_length(retained->'facts')+jsonb_array_length(freshness->'facts')
  +jsonb_array_length(frozen_program#>'{access_label_freshness_proofs,prior_facts}');
 IF used_work IS NULL OR compare_work IS NULL OR used_work+compare_work>p_work THEN
  RAISE EXCEPTION 'group metadata retained selection shared budget exhausted' USING ERRCODE='54000';END IF;
 used_work:=used_work+compare_work;
 IF EXISTS(SELECT value FROM jsonb_array_elements(retained->'facts')
    EXCEPT SELECT value FROM jsonb_array_elements(freshness->'facts'))
  OR EXISTS(SELECT value FROM jsonb_array_elements(frozen_program#>'{access_label_freshness_proofs,prior_facts}')
    EXCEPT SELECT value FROM jsonb_array_elements(retained->'facts')) THEN
  RAISE EXCEPTION 'group metadata retained selection escaped reserved maximum or lost prior facts' USING ERRCODE='42501';END IF;
 final_freshness:=jsonb_set(freshness,'{facts}',retained->'facts');
 UPDATE pg_temp.kaname_authority_sequence_program p
 SET frozen=p.frozen||jsonb_build_object('access_label_approved_at',decision,
  'access_label_freshness',final_freshness)
 WHERE p.singleton AND p.nonce=(header->>'nonce')::uuid AND p.family='metadata'
  AND p.decision_at=decision AND p.frozen=frozen_program;
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN RAISE EXCEPTION 'group metadata apply approval was not recorded exactly once' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$approve$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE
 fn regprocedure:='kaname._authority_metadata_group_accept_v1(text,text,integer,integer,integer)'::regprocedure;
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
DROP FUNCTION kaname._authority_metadata_group_accept_v1(text,text,integer,integer,integer);
