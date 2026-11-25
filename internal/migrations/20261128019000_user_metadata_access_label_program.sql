-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Сохраняем общий максимум текущих кандидатов и прежнего поколения.
-- Подтверждение на окончательном времени может только сузить этот набор.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_protected_program_v1(
    p_desired jsonb,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $program$
DECLARE
    saved jsonb;
    images jsonb;
    inputs jsonb;
    held jsonb;
    retained jsonb;
    candidate_facts jsonb;
    prior_facts jsonb;
    freshness jsonb;
    input_count integer;
    used_rows integer:=1;
    used_reads integer:=1;
    used_work integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN 3 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 3 AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN 3 AND 400000 THEN
        RAISE EXCEPTION 'user protected program budget invalid' USING ERRCODE='54000';
    END IF;
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    images:=saved->'user_images';
    inputs:=saved->'user_access_label_inputs';
    held:=saved->'user_held';
    IF images->>'mode' IS DISTINCT FROM 'access_labels'
        OR kaname._authority_sequence_store_v3() IS NOT NULL
        OR saved ? 'user_protected_reserved'
        OR inputs->'nonce' IS DISTINCT FROM images->'nonce'
        OR held->'nonce' IS DISTINCT FROM images->'nonce'
        OR held->'root_physical' IS DISTINCT FROM images->'root_physical'
        OR held->'update_question' IS DISTINCT FROM images->'update_question'
        OR inputs->'root_id' IS DISTINCT FROM images->'root_id'
        OR inputs#>'{authority,actor}' IS DISTINCT FROM images->'actor'
        OR jsonb_typeof(inputs->'requirements') IS DISTINCT FROM 'array'
        OR jsonb_array_length(inputs->'requirements') NOT BETWEEN 1 AND 128
        OR NOT coalesce((inputs->'carry') ? 'prior_generation',false)
        OR jsonb_typeof(inputs#>'{carry,prior_facts}') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_desired) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'user protected program lacks held request and sources' USING ERRCODE='42501';
    END IF;
    retained:=kaname._authority_metadata_user_retention_compile_v1(p_desired,p_work-used_work);
    IF retained#>>'{receipt,root_type}' IS DISTINCT FROM 'iam.user'
        OR retained#>'{receipt,root_id}' IS DISTINCT FROM images->'root_id'
        OR retained#>'{receipt,old_labels}' IS DISTINCT FROM images#>'{old_row,access_labels}'
        OR retained#>'{receipt,new_labels}' IS DISTINCT FROM images#>'{new_row,access_labels}'
        OR retained->'old_row' IS DISTINCT FROM images->'old_row' OR retained->'new_row' IS DISTINCT FROM images->'new_row'
        OR retained->'root_physical' IS DISTINCT FROM images->'root_physical'
        OR retained->'update_question' IS DISTINCT FROM images->'update_question'
        OR jsonb_typeof(retained->'retention') IS DISTINCT FROM 'object'
        OR jsonb_typeof(retained#>'{receipt,facts}') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'user protected candidate facts differ from held command' USING ERRCODE='42501';
    END IF;
    candidate_facts:=retained#>'{receipt,facts}';
    prior_facts:=inputs#>'{carry,prior_facts}';
    input_count:=jsonb_array_length(candidate_facts)+jsonb_array_length(prior_facts);
    used_rows:=used_rows+(retained->>'rows')::integer+input_count;
    used_reads:=used_reads+(retained->>'reads')::integer;
    used_work:=used_work+(retained->>'work')::integer+2*input_count;
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'user protected program budget exhausted' USING ERRCODE='54000';
    END IF;
    SELECT jsonb_build_object('root_type','iam.user','root_id',images->'root_id',
        'old_labels',images#>'{old_row,access_labels}','new_labels',images#>'{new_row,access_labels}',
        'prior_generation',inputs#>'{carry,prior_generation}',
        'facts',coalesce(jsonb_agg(fact ORDER BY fact::text COLLATE "C"),'[]'::jsonb))
    INTO freshness FROM (
        SELECT value AS fact FROM jsonb_array_elements(candidate_facts)
        UNION SELECT value AS fact FROM jsonb_array_elements(prior_facts)
    ) maximum;
    RETURN jsonb_build_object('requirements',inputs->'requirements','authority',inputs->'authority',
        'freshness',freshness,'freshness_proofs',jsonb_build_object('candidate_facts',candidate_facts,
            'prior_facts',prior_facts,'retention',retained->'retention'),
        'rows',used_rows,'reads',used_reads,'work',used_work);
END;
$program$;
-- +goose StatementEnd

-- Финальную фазу вызывает owner после проверки record_writer и дельты
-- выдач. Повторно проверяются точные apply sources и удержанный сертификат.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_protected_approve_v1(
    p_op text,p_nonce uuid,p_decision timestamptz,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $approve$
DECLARE
    saved jsonb;
    images jsonb;
    proof jsonb;
    program jsonb;
    command jsonb;
    freshness jsonb;
    authority jsonb;
    requirements jsonb;
    retained jsonb;
    apply_cost jsonb;
    final_facts jsonb;
    used_rows integer:=4;
    used_reads integer:=4;
    used_work integer:=1;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
        OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR p_work IS NULL OR p_work NOT BETWEEN used_work AND 400000 THEN
        RAISE EXCEPTION 'final user access label budget invalid' USING ERRCODE='54000';
    END IF;
    saved:=kaname._authority_metadata_access_label_stashed_v1();
    images:=saved->'user_images';
    proof:=kaname.authority_protocol_attestation();
    program:=kaname._authority_sequence_store_v3();
    command:=program->'frozen';
    freshness:=command->'access_label_freshness';
    authority:=command->'access_label_authority';
    requirements:=command->'access_label_requirements';
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'consumer_finalized' IS DISTINCT FROM 'true'
        OR p_nonce IS NULL OR p_nonce::text IS DISTINCT FROM proof->>'nonce'
        OR proof->'nonce' IS DISTINCT FROM images->'nonce' OR proof->'nonce' IS DISTINCT FROM program->'nonce'
        OR p_decision IS NULL OR NOT isfinite(p_decision)
        OR p_decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR p_decision IS DISTINCT FROM (program->>'decision_at')::timestamptz
        OR (program->>'staged_decision_at')::timestamptz IS NULL
        OR p_decision<=(program->>'staged_decision_at')::timestamptz
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program->>'frozen_mode' IS DISTINCT FROM 'user_access_labels'
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR program->>'selected_count' IS DISTINCT FROM '1'
        OR command->>'kind' IS DISTINCT FROM 'metadata.user.access_labels'
        OR command->>'phase' IS DISTINCT FROM 'reserved' OR command ? 'access_label_approved_at'
        OR saved->'user_protected_reserved' IS DISTINCT FROM proof->'nonce'
        OR p_op IS DISTINCT FROM command#>>'{pending,2,id}'
        OR images->>'mode' IS DISTINCT FROM 'access_labels'
        OR command->'question' IS DISTINCT FROM images->'update_question'
        OR command->'access_label_root_physical' IS DISTINCT FROM images->'root_physical'
        OR authority IS DISTINCT FROM saved#>'{user_access_label_inputs,authority}'
        OR requirements IS DISTINCT FROM saved#>'{user_access_label_inputs,requirements}'
        OR authority->'actor' IS DISTINCT FROM images->'actor'
        OR freshness->>'root_type' IS DISTINCT FROM 'iam.user'
        OR freshness->'root_id' IS DISTINCT FROM images->'root_id'
        OR freshness->'old_labels' IS DISTINCT FROM images#>'{old_row,access_labels}'
        OR freshness->'new_labels' IS DISTINCT FROM images#>'{new_row,access_labels}'
        OR NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=p_nonce AND e.ordinal=1 AND e.table_name='resource_journal' AND e.selected
              AND NOT (e.registered OR e.claimed OR e.consumed)
              AND e.origin=command#>'{effects,maximum,0,origin}'
              AND e.origin->'old'=images->'old_row' AND e.origin->'new'=images->'new_row') THEN
        RAISE EXCEPTION 'user protected approval lacks the matching final command' USING ERRCODE='42501';
    END IF;
    apply_cost:=kaname._authority_resource_access_label_sources_require_v1(
        authority,requirements,p_decision,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(apply_cost->>'rows')::integer;
    used_reads:=used_reads+(apply_cost->>'reads')::integer;
    retained:=kaname._authority_metadata_access_label_retained_select_v1(
        command->'access_label_freshness_proofs',p_decision,p_work-used_work);
    final_facts:=retained->'facts';
    IF jsonb_typeof(final_facts) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'user protected retained selection omitted facts' USING ERRCODE='42501';
    END IF;
    used_work:=used_work+(retained->>'work')::integer+2*jsonb_array_length(final_facts)
        +jsonb_array_length(freshness->'facts')
        +jsonb_array_length(command#>'{access_label_freshness_proofs,prior_facts}');
    IF used_rows IS NULL OR used_rows NOT BETWEEN 1 AND p_rows OR used_reads IS NULL OR used_reads NOT BETWEEN 1 AND p_reads
        OR used_work IS NULL OR used_work NOT BETWEEN 1 AND p_work THEN
        RAISE EXCEPTION 'final user access label budget exhausted' USING ERRCODE='54000';
    END IF;
    IF EXISTS(SELECT value FROM jsonb_array_elements(final_facts)
            EXCEPT SELECT value FROM jsonb_array_elements(freshness->'facts'))
        OR EXISTS(SELECT value FROM jsonb_array_elements(command#>'{access_label_freshness_proofs,prior_facts}')
            EXCEPT SELECT value FROM jsonb_array_elements(final_facts)) THEN
        RAISE EXCEPTION 'user protected retained selection changed reserved coverage' USING ERRCODE='42501';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s
    SET frozen=command||jsonb_build_object('access_label_approved_at',p_decision,
        'access_label_freshness',jsonb_set(freshness,'{facts}',final_facts))
    WHERE s.singleton AND s.nonce=p_nonce AND s.family='metadata' AND s.decision_at=p_decision AND s.frozen=command;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'user protected approval was not recorded exactly once' USING ERRCODE='42501';
    END IF;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$approve$;
-- +goose StatementEnd

-- Специализируем проверенные выходы и захват ожидающей операции.
-- +goose StatementBegin
DO $user_protected$
DECLARE item record; pair jsonb; src text;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_metadata_user_ordinary_effects_v1(text)','_authority_metadata_user_protected_effects_v1','p_audit text',
         '9d1cdbe9ee805b7c840b38d2b2093255abb79962b9641be74bf2ab018be8cac9','439c54034b7f6f20e3c37a8e6db132e48cc204db3229ba0185eb1924a992ede3',
         $changes$[
 [
  "images->>'mode' IS DISTINCT FROM 'ordinary' OR images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb",
  "images->>'mode' IS DISTINCT FROM 'access_labels'\n        OR images->'changed_fields' IS NULL OR images->'changed_fields' NOT IN ('[\"access_labels\"]'::jsonb,'[\"labels\",\"access_labels\"]'::jsonb)"
 ],
 [
  "(desired-'labels') IS DISTINCT FROM (prev-'labels') OR desired->'labels' IS NOT DISTINCT FROM prev->'labels'",
  "(desired-ARRAY['labels','access_labels']) IS DISTINCT FROM (prev-ARRAY['labels','access_labels'])\n        OR desired->'access_labels' IS NOT DISTINCT FROM prev->'access_labels'"
 ],
 [
  "AND has_column_privilege(invoker,'kaname.users','labels','UPDATE'),false)",
  "AND has_column_privilege(invoker,'kaname.users','access_labels','UPDATE')\n        AND (images->'changed_fields'='[\"access_labels\"]'::jsonb\n             OR has_column_privilege(invoker,'kaname.users','labels','UPDATE')),false)"
 ]
]$changes$::jsonb),
        ('_authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text)','_authority_metadata_user_protected_reserve_v1','p_op text,p_created timestamptz,p_metadata bytea,p_account text,p_actor_type text,p_actor_id text,p_display text,p_rows integer,p_reads integer,p_audit text,p_desired jsonb,p_work integer',
         '5e947bed8a60334a202d41137e44a561e2f352555707d3c07fb9b87242a4c18f','c526da7587930a83ecfa596f64cd20495f342493913a9aa16617a087f57bab47',
         $changes$[
 [
  "    effects jsonb;",
  "    effects jsonb;\n    protected_program jsonb;"
 ],
 [
  "stash ? 'user_images' OR target->>'mode' IS DISTINCT FROM 'ordinary'",
  "NOT (stash ? 'user_images') OR stash ? 'user_protected_reserved' OR target->>'mode' IS DISTINCT FROM 'access_labels'"
 ],
 [
  "target->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb",
  "target->'changed_fields' IS NULL OR target->'changed_fields' NOT IN ('[\"access_labels\"]'::jsonb,'[\"labels\",\"access_labels\"]'::jsonb)"
 ],
 [
  "CREATE CONSTRAINT TRIGGER user_metadata_ordinary_commit",
  "CREATE CONSTRAINT TRIGGER user_metadata_protected_commit"
 ],
 [
  "OLD.prepared->'user_images' IS NULL AND NEW.prepared ? 'user_images'",
  "OLD.prepared->'user_protected_reserved' IS NULL AND NEW.prepared ? 'user_protected_reserved'"
 ],
 [
  "_authority_metadata_user_ordinary_commit_v1()",
  "_authority_metadata_user_protected_commit_v1()"
 ],
 [
  "cost:=kaname._authority_metadata_user_freeze_images_v1(p_actor_type,p_actor_id,p_rows-64-2*members,p_reads-64);",
  "cost:=kaname._authority_metadata_user_protected_program_v1(p_desired,p_rows-64-2*members,p_reads-64,p_work);\n    protected_program:=cost-ARRAY['rows','reads','work'];"
 ],
 [
  "IF cost->>'mode' IS DISTINCT FROM 'ordinary' OR images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb",
  "IF images->>'mode' IS DISTINCT FROM 'access_labels' OR images->'changed_fields' IS DISTINCT FROM target->'changed_fields'\n        OR images->'actor' IS DISTINCT FROM jsonb_build_object('type',p_actor_type,'id',p_actor_id)"
 ],
 [
  "((images->'new_row')-'labels') IS DISTINCT FROM ((images->'old_row')-'labels')",
  "((images->'new_row')-ARRAY['labels','access_labels']) IS DISTINCT FROM\n           ((images->'old_row')-ARRAY['labels','access_labels'])\n        OR images#>'{new_row,access_labels}' IS NOT DISTINCT FROM images#>'{old_row,access_labels}'"
 ],
 [
  "_authority_metadata_user_ordinary_effects_v1(p_audit)",
  "_authority_metadata_user_protected_effects_v1(p_audit)"
 ],
 [
  "'kind','metadata.user.ordinary','mode','user_ordinary','effects',effects,\n        'phase','reserved','pending',pending,'question',images->'update_question'));",
  "'kind','metadata.user.access_labels','mode','user_access_labels','effects',effects,\n        'phase','reserved','pending',pending,'question',images->'update_question',\n        'access_label_authority',protected_program->'authority',\n        'access_label_requirements',protected_program->'requirements',\n        'access_label_root_physical',images->'root_physical',\n        'access_label_freshness',protected_program->'freshness',\n        'access_label_freshness_proofs',protected_program->'freshness_proofs'));\n    UPDATE pg_temp.kaname_authority_metadata_discovery d\n    SET prepared=stash||jsonb_build_object('user_protected_reserved',images->'nonce')\n    WHERE d.singleton AND d.prepared=stash AND NOT (d.prepared ? 'user_protected_reserved');\n    IF NOT FOUND THEN RAISE EXCEPTION 'user protected reserve custody changed' USING ERRCODE='42501';END IF;"
 ],
 [
  "'rows',(cost->>'rows')::integer+64+2*members,'reads',(cost->>'reads')::integer+48+reads);",
  "'mode','access_labels','rows',(cost->>'rows')::integer+64+2*members,\n        'reads',(cost->>'reads')::integer+48+reads,'work',(cost->>'work')::integer);"
 ]
]$changes$::jsonb)
    ) s(signature,name,args,preceding_digest,result_digest,changes) LOOP
        SELECT p.prosrc INTO STRICT src FROM pg_catalog.pg_proc p
        WHERE p.oid=to_regprocedure('kaname.'||item.signature) AND p.proowner=current_user::regrole
          AND NOT p.prosecdef AND p.provolatile='v';
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM item.preceding_digest THEN
            RAISE EXCEPTION 'user protected predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
            IF length(pair->>0)=0
                OR (length(src)-length(replace(src,pair->>0,'')))/length(pair->>0)<>1 THEN
                RAISE EXCEPTION 'user protected command changed: %',item.name USING ERRCODE='55000';
            END IF;
            src:=replace(src,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM item.result_digest THEN
            RAISE EXCEPTION 'user protected result differs: %',item.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS jsonb LANGUAGE plpgsql VOLATILE
            SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',item.name,item.args,src);
    END LOOP;
END;
$user_protected$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_protected_program_v1(jsonb,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_protected_approve_v1(text,uuid,timestamptz,integer,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_protected_effects_v1(text)'::regprocedure,
        'kaname._authority_metadata_user_protected_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text,jsonb,integer)'::regprocedure
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
DROP FUNCTION kaname._authority_metadata_user_protected_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text,jsonb,integer);
DROP FUNCTION kaname._authority_metadata_user_protected_effects_v1(text);
DROP FUNCTION kaname._authority_metadata_user_protected_approve_v1(text,uuid,timestamptz,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_protected_program_v1(jsonb,integer,integer,integer);
