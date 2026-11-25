-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_write_v1(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
 program jsonb; command jsonb; state jsonb; physical jsonb; old_row jsonb; new_row jsonb;
 actual jsonb; after_version jsonb; after_root jsonb; write_nonce uuid; n integer;
 audit_row kaname.audit_outbox; reconcile_row kaname.resource_reconcile_outbox;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 program:=kaname._authority_metadata_mirror_command_v1();
 command:=program#>'{frozen,mirror_command}'; state:=program#>'{frozen,mirror_state}';
 physical:=command->'physical'; old_row:=command->'old'; new_row:=command->'new';
 write_nonce:=(program->>'nonce')::uuid;
 IF program IS NULL OR write_nonce IS NULL
  OR p_dotted IS DISTINCT FROM command#>>'{identity,dotted}' OR p_id IS DISTINCT FROM command#>>'{identity,id}'
  OR program#>>'{frozen,mirror_write_epoch}' IS NULL
  OR program#>>'{frozen,mirror_write_epoch}' NOT IN ('*','scope:'||(command#>>'{identity,account_id}'))
  OR state IS DISTINCT FROM '{"root_applied":false,"root_after":null,"audit_consumed":false,"reconcile_consumed":false}'::jsonb
  OR (program->'frozen') ? 'access_label_freshness_installed' THEN
  RAISE EXCEPTION 'external metadata write coordinate or state changed' USING ERRCODE='42501';
 END IF;
 -- Оба UPDATE проверяют полную версию OLD. При неизменной обычной карте
 -- не обновляем её колонку: у исходной роли может быть только UPDATE(access_labels).
 IF old_row->'labels' IS DISTINCT FROM new_row->'labels' THEN
  UPDATE ONLY kaname.resource_mirror AS m
  SET labels=new_row->'labels',access_labels=new_row->'access_labels'
  WHERE m.object_type=p_dotted AND m.object_id=p_id AND m.xmin::text=physical->>'xmin'
   AND m.ctid::text=physical->>'ctid' AND to_jsonb(m)=old_row
  RETURNING to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO actual,after_version;
 ELSE
  UPDATE ONLY kaname.resource_mirror AS m SET access_labels=new_row->'access_labels'
  WHERE m.object_type=p_dotted AND m.object_id=p_id AND m.xmin::text=physical->>'xmin'
   AND m.ctid::text=physical->>'ctid' AND to_jsonb(m)=old_row
  RETURNING to_jsonb(m),jsonb_build_array(m.xmin::text,m.ctid::text) INTO actual,after_version;
 END IF;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 OR actual IS DISTINCT FROM new_row THEN
  RAISE EXCEPTION 'external metadata exact physical root changed' USING ERRCODE='40001';
 END IF;
 after_root:=actual;
 -- Следующая инструкция видит результат AFTER ROW. До него marker отсутствовал.
 IF NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program p
  WHERE p.singleton AND p.nonce=write_nonce AND p.family='metadata'
   AND p.frozen=program->'frozen'||jsonb_build_object('access_label_freshness_installed',write_nonce)) THEN
  RAISE EXCEPTION 'external metadata freshness generation missing after update' USING ERRCODE='42501';
 END IF;
 audit_row:=jsonb_populate_record(NULL::kaname.audit_outbox,command->'audit_row');
 INSERT INTO kaname.audit_outbox AS a
  (id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at,sent_at,last_error)
 VALUES(audit_row.id,audit_row.event_type,audit_row.tenant_account_id,audit_row.event_payload,audit_row.status,
  audit_row.attempts,audit_row.created_at,audit_row.next_attempt_at,audit_row.sent_at,audit_row.last_error)
 RETURNING to_jsonb(a) INTO actual;
 IF actual IS DISTINCT FROM command->'audit_row' THEN
  RAISE EXCEPTION 'external metadata audit output differs from reservation' USING ERRCODE='42501';
 END IF;
 reconcile_row:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,command->'reconcile_row');
 INSERT INTO kaname.resource_reconcile_outbox AS r
  (id,object_type,object_id,event_type,created_at,sent_at,last_error,attempt_count)
 OVERRIDING SYSTEM VALUE VALUES(reconcile_row.id,reconcile_row.object_type,reconcile_row.object_id,reconcile_row.event_type,
  reconcile_row.created_at,reconcile_row.sent_at,reconcile_row.last_error,reconcile_row.attempt_count)
 RETURNING to_jsonb(r) INTO actual;
 IF actual IS DISTINCT FROM command->'reconcile_row' THEN
  RAISE EXCEPTION 'external metadata reconcile output differs from reservation' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_sequence_program p
 SET frozen=jsonb_set(p.frozen,'{mirror_state}',jsonb_build_object(
  'root_applied',true,'root_after',after_version,'audit_consumed',true,'reconcile_consumed',true))
 WHERE p.singleton AND p.nonce=write_nonce AND p.family='metadata'
  AND p.frozen=(program->'frozen'||jsonb_build_object('access_label_freshness_installed',write_nonce));
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'external metadata output state changed' USING ERRCODE='42501';END IF;
 RETURN after_root;
END;
$write$;

CREATE FUNCTION kaname.authority_metadata_mirror_write_v1(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $write$
 SELECT kaname._authority_metadata_mirror_write_v1(p_dotted,p_id)
$write$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
 FOREACH fn IN ARRAY ARRAY[
 'kaname._authority_metadata_mirror_write_v1(text,text)'::regprocedure,
 'kaname.authority_metadata_mirror_write_v1(text,text)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd
-- Owner ABI patch
-- +goose StatementBegin
DO $install$
DECLARE step record; replacement jsonb; target oid; body text; definition text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)','5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763','f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444',$change$[
 [
  " root_type:=compiled#>>'{receipt,root_type}';root_id:=compiled#>>'{receipt,root_id}';",
  " root_type:=compiled#>>'{receipt,root_type}';root_id:=compiled#>>'{receipt,root_id}';\n IF physical->>'table'='resource_mirror' THEN\n  RETURN kaname._authority_metadata_mirror_reserve_v1(compiled,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work);\n END IF;"
 ]
]$change$::jsonb),
 ('_authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer)','9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565','43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54',$change$[
 [
  " IF frozen_program->>'kind' IS DISTINCT FROM 'metadata.access_labels'",
  " IF coalesce(frozen_program->>'kind','') NOT IN ('metadata.access_labels','metadata.mirror')"
 ],
 [
  " SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e\n WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1\n  AND e.table_name='resource_journal' AND e.selected\n  AND NOT (e.registered OR e.claimed OR e.consumed)\n  AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'\n  AND e.origin->>'table'=CASE freshness->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects' WHEN 'iam.serviceAccount' THEN 'service_accounts' END\n  AND e.origin#>>'{old,id}'=freshness->>'root_id' AND e.origin#>>'{new,id}'=freshness->>'root_id'\n  AND e.origin#>'{old,access_labels}'=freshness->'old_labels'\n  AND e.origin#>'{new,access_labels}'=freshness->'new_labels';\n IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN\n  RAISE EXCEPTION 'metadata apply origin changed before approval' USING ERRCODE='42501';END IF;\n",
  " IF frozen_program->>'kind'='metadata.mirror' THEN\n  -- Проверка окончательного времени и источников apply общая для обеих ветвей.\n  -- Подтверждаем точный reserve, включая определения, с которыми был собран\n  -- список источников; отложенная проверка повторит сверку при commit.\n  used_rows:=used_rows+4;used_reads:=used_reads+4;used_work:=used_work+4;\n  IF used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN\n   RAISE EXCEPTION 'external metadata final acceptance budget exhausted' USING ERRCODE='54000';END IF;\n  IF program->>'frozen_mode' IS DISTINCT FROM 'external_access_labels'\n   OR program->'maximum' IS DISTINCT FROM '[]'::jsonb OR program->'selected' IS DISTINCT FROM '[]'::jsonb\n   OR requirements IS DISTINCT FROM kaname._authority_metadata_access_label_stashed_v1()#>'{retention,resource_requirements}'\n   OR frozen_program ? 'access_label_freshness_installed'\n   OR frozen_program->'mirror_state' IS DISTINCT FROM\n    '{\"root_applied\":false,\"root_after\":null,\"audit_consumed\":false,\"reconcile_consumed\":false}'::jsonb THEN\n   RAISE EXCEPTION 'external metadata final evidence differs' USING ERRCODE='42501';END IF;\n ELSE\n  SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e\n  WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1\n   AND e.table_name='resource_journal' AND e.selected\n   AND NOT (e.registered OR e.claimed OR e.consumed)\n   AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'\n   AND e.origin->>'table'=CASE freshness->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects' WHEN 'iam.serviceAccount' THEN 'service_accounts' END\n   AND e.origin#>>'{old,id}'=freshness->>'root_id' AND e.origin#>>'{new,id}'=freshness->>'root_id'\n   AND e.origin#>'{old,access_labels}'=freshness->'old_labels'\n   AND e.origin#>'{new,access_labels}'=freshness->'new_labels';\n  IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN\n   RAISE EXCEPTION 'metadata apply origin changed before approval' USING ERRCODE='42501';END IF;\n END IF;\n"
 ],
 [
  " RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);",
  " IF frozen_program->>'kind'='metadata.mirror' AND kaname._authority_metadata_mirror_command_v1() IS NULL THEN\n  RAISE EXCEPTION 'external metadata final approval failed custody' USING ERRCODE='42501';END IF;\n RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);"
 ]
]$change$::jsonb),
 ('access_labels_immutable_v1()','9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992','b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc',$change$[
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')"
 ],
 [
  " command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);",
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n  IF command IS NULL OR TG_RELID<>'kaname.resource_mirror'::regclass\n   OR command#>>'{identity,dotted}' IS DISTINCT FROM OLD.object_type\n   OR command#>>'{identity,id}' IS DISTINCT FROM OLD.object_id THEN\n   RAISE EXCEPTION 'external metadata trigger lacks exact approved command' USING ERRCODE='42501';END IF;\n ELSE\n  command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);\n END IF;"
 ]
]$change$::jsonb),
 ('_authority_metadata_access_label_freshness_v1()','d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8','d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f',$change$[
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')"
 ],
 [
  " command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);",
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n  IF command IS NULL OR TG_RELID<>'kaname.resource_mirror'::regclass\n   OR command#>>'{identity,dotted}' IS DISTINCT FROM OLD.object_type\n   OR command#>>'{identity,id}' IS DISTINCT FROM OLD.object_id THEN\n   RAISE EXCEPTION 'external metadata trigger lacks exact approved command' USING ERRCODE='42501';END IF;\n ELSE\n  command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);\n END IF;"
 ]
]$change$::jsonb),
 ('resource_mirror_keeps_the_bound_project()','4ce622a3d49c99bf4b3e4dc540cc82d05e9e4a050209d3898475649c170a6ab3','71f936f3383ae6f73f2e3ff2eca2c95ccc9fb79c8962aa3e964c803b311ed34b',$change$[
 [
  "    v_catalog record;",
  "    v_catalog record;\n    approved jsonb;"
 ],
 [
  "    -- Только прямой триггер полной команды пишет эти таблицы на глубине 2.",
  "    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN\n        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n        IF TG_TABLE_SCHEMA<>'kaname' OR TG_RELID<>'kaname.resource_mirror'::regclass\n           OR TG_LEVEL<>'ROW' OR TG_WHEN NOT IN ('BEFORE','AFTER')\n           OR approved IS NULL OR approved->'old' IS DISTINCT FROM to_jsonb(OLD)\n           OR approved->'new' IS DISTINCT FROM to_jsonb(NEW) THEN\n            RAISE EXCEPTION 'external metadata registration identity differs' USING ERRCODE='42501';\n        END IF;\n        -- Удержанная регистрация включает отсутствие привязки. Для изменения\n        -- только карт меток не создаём первую привязку и не переписываем каталог.\n        PERFORM kaname._authority_metadata_registration_binding_check_v1(\n            approved#>>'{identity,model}',approved#>>'{identity,id}');\n        RETURN NEW;\n    END IF;\n    -- Только прямой триггер полной команды пишет эти таблицы на глубине 2."
 ]
]$change$::jsonb),
 ('authority_access_label_storage_valid_v1()','a7821d7f58ee98dc10277fb53d2f588763b27e2dbdb4476d361f6474439e1055','4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921',$change$[
 [
  "9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992",
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc"
 ]
]$change$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5','75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986',$change$[
 [
  "5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763",
  "f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444"
 ],
 [
  "9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565",
  "43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54"
 ],
 [
  "d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8",
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f"
 ],
 [
  " manifest jsonb:=$manifest$\n[\n",
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_mirror_epoch_hold_v1()\",\n    \"digest\": \"0a0edbe9d5f3f4852b682493cc31576e3eed96e2bf4036fb6c49cf8e927d0d54\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"text\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": null,\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_mirror_reserve_v1(jsonb,text,text,text,integer,integer,integer)\",\n    \"digest\": \"81cbd7c0affb568b7506c905d86b9d913c6214289af66fa7dcb40aa41468e98c\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_compiled\",\n      \"p_audit\",\n      \"p_actor_type\",\n      \"p_actor_id\",\n      \"p_rows\",\n      \"p_reads\",\n      \"p_work\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_mirror_write_v1(text,text)\",\n    \"digest\": \"335eb3b91f0638ed0cb944b77d8b2ba5bc3e51cdf33c798b76c4db7210fcd97a\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"authority_metadata_mirror_write_v1(text,text)\",\n    \"digest\": \"2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1\",\n    \"definer\": true,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"sql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n"
 ],
 [
  " FOREACH target IN ARRAY ARRAY['accounts','projects'] LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t",
  " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror'] LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t"
 ]
]$change$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','f9e0e1c697eb521752665775ce760b354bfb815a7f3b5b01a0a14ba55345af84','6098027fa50d3962ef2b898886b041ddbea5f9df9c4d029da7fda152f61f8233',$change$[
 [
  "5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763",
  "f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444"
 ],
 [
  "9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565",
  "43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54"
 ],
 [
  "9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992",
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc"
 ],
 [
  "d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8",
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f"
 ],
 [
  "a7821d7f58ee98dc10277fb53d2f588763b27e2dbdb4476d361f6474439e1055",
  "4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921"
 ],
 [
  "57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5",
  "75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986"
 ]
]$change$::jsonb)
 ) AS expected(signature,prior,installed,changes) LOOP
  target:=to_regprocedure('kaname.'||step.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=target AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.prior THEN
   RAISE EXCEPTION 'external metadata predecessor differs: %',step.signature;END IF;
  FOR replacement IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,replacement->>0,''))<>octet_length(replacement->>0) THEN
    RAISE EXCEPTION 'external metadata splice is ambiguous: %',step.signature;END IF;
   body:=replace(body,replacement->>0,replacement->>1);
   definition:=replace(definition,replacement->>0,replacement->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.installed THEN
   RAISE EXCEPTION 'external metadata result differs: %',step.signature;END IF;
  EXECUTE definition;
 END LOOP;
END;
$install$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER access_labels_000_commit_freshness AFTER UPDATE ON kaname.resource_mirror
FOR EACH ROW WHEN (OLD.access_labels IS DISTINCT FROM NEW.access_labels)
EXECUTE FUNCTION kaname._authority_metadata_access_label_freshness_v1();
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP TRIGGER access_labels_000_commit_freshness ON kaname.resource_mirror;
-- +goose StatementBegin
DO $install$
DECLARE step record; replacement jsonb; target oid; body text; definition text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','6098027fa50d3962ef2b898886b041ddbea5f9df9c4d029da7fda152f61f8233','f9e0e1c697eb521752665775ce760b354bfb815a7f3b5b01a0a14ba55345af84',$change$[
 [
  "75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986",
  "57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5"
 ],
 [
  "4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921",
  "a7821d7f58ee98dc10277fb53d2f588763b27e2dbdb4476d361f6474439e1055"
 ],
 [
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f",
  "d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8"
 ],
 [
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc",
  "9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992"
 ],
 [
  "43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54",
  "9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565"
 ],
 [
  "f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444",
  "5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763"
 ]
]$change$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','75edcda1114c591fa1dfd40a80930d3fade6f9eb6a9b34caebc97eef02f64986','57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5',$change$[
 [
  " FOREACH target IN ARRAY ARRAY['accounts','projects','resource_mirror'] LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t",
  " FOREACH target IN ARRAY ARRAY['accounts','projects'] LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t"
 ],
 [
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_mirror_epoch_hold_v1()\",\n    \"digest\": \"0a0edbe9d5f3f4852b682493cc31576e3eed96e2bf4036fb6c49cf8e927d0d54\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"text\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": null,\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_mirror_reserve_v1(jsonb,text,text,text,integer,integer,integer)\",\n    \"digest\": \"81cbd7c0affb568b7506c905d86b9d913c6214289af66fa7dcb40aa41468e98c\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_compiled\",\n      \"p_audit\",\n      \"p_actor_type\",\n      \"p_actor_id\",\n      \"p_rows\",\n      \"p_reads\",\n      \"p_work\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"_authority_metadata_mirror_write_v1(text,text)\",\n    \"digest\": \"335eb3b91f0638ed0cb944b77d8b2ba5bc3e51cdf33c798b76c4db7210fcd97a\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n  {\n    \"signature\": \"authority_metadata_mirror_write_v1(text,text)\",\n    \"digest\": \"2993793f4e7d0a5f24fbdcf9450f95fffced40066dd3c66bf264acced3645bf1\",\n    \"definer\": true,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"sql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n",
  " manifest jsonb:=$manifest$\n[\n"
 ],
 [
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f",
  "d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8"
 ],
 [
  "43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54",
  "9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565"
 ],
 [
  "f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444",
  "5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763"
 ]
]$change$::jsonb),
 ('authority_access_label_storage_valid_v1()','4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921','a7821d7f58ee98dc10277fb53d2f588763b27e2dbdb4476d361f6474439e1055',$change$[
 [
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc",
  "9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992"
 ]
]$change$::jsonb),
 ('resource_mirror_keeps_the_bound_project()','71f936f3383ae6f73f2e3ff2eca2c95ccc9fb79c8962aa3e964c803b311ed34b','4ce622a3d49c99bf4b3e4dc540cc82d05e9e4a050209d3898475649c170a6ab3',$change$[
 [
  "    IF TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels THEN\n        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n        IF TG_TABLE_SCHEMA<>'kaname' OR TG_RELID<>'kaname.resource_mirror'::regclass\n           OR TG_LEVEL<>'ROW' OR TG_WHEN NOT IN ('BEFORE','AFTER')\n           OR approved IS NULL OR approved->'old' IS DISTINCT FROM to_jsonb(OLD)\n           OR approved->'new' IS DISTINCT FROM to_jsonb(NEW) THEN\n            RAISE EXCEPTION 'external metadata registration identity differs' USING ERRCODE='42501';\n        END IF;\n        -- Удержанная регистрация включает отсутствие привязки. Для изменения\n        -- только карт меток не создаём первую привязку и не переписываем каталог.\n        PERFORM kaname._authority_metadata_registration_binding_check_v1(\n            approved#>>'{identity,model}',approved#>>'{identity,id}');\n        RETURN NEW;\n    END IF;\n    -- Только прямой триггер полной команды пишет эти таблицы на глубине 2.",
  "    -- Только прямой триггер полной команды пишет эти таблицы на глубине 2."
 ],
 [
  "    v_catalog record;\n    approved jsonb;",
  "    v_catalog record;"
 ]
]$change$::jsonb),
 ('_authority_metadata_access_label_freshness_v1()','d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f','d3f11fdcbc31b583098c4ddec750fdd4dd4f31b60de169a0d355df7ab75857b8',$change$[
 [
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n  IF command IS NULL OR TG_RELID<>'kaname.resource_mirror'::regclass\n   OR command#>>'{identity,dotted}' IS DISTINCT FROM OLD.object_type\n   OR command#>>'{identity,id}' IS DISTINCT FROM OLD.object_id THEN\n   RAISE EXCEPTION 'external metadata trigger lacks exact approved command' USING ERRCODE='42501';END IF;\n ELSE\n  command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);\n END IF;",
  " command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);"
 ],
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts')"
 ]
]$change$::jsonb),
 ('access_labels_immutable_v1()','b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc','9d3a52a7920a1f0532c932c31de06f4a8f19e39c5ef1375b0b3bebe603b65992',$change$[
 [
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';\n  IF command IS NULL OR TG_RELID<>'kaname.resource_mirror'::regclass\n   OR command#>>'{identity,dotted}' IS DISTINCT FROM OLD.object_type\n   OR command#>>'{identity,id}' IS DISTINCT FROM OLD.object_id THEN\n   RAISE EXCEPTION 'external metadata trigger lacks exact approved command' USING ERRCODE='42501';END IF;\n ELSE\n  command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);\n END IF;",
  " command:=kaname._authority_metadata_access_label_origin_v1(TG_TABLE_NAME,OLD.id);"
 ],
 [
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts','resource_mirror')",
  "TG_TABLE_NAME NOT IN ('accounts','projects','service_accounts')"
 ]
]$change$::jsonb),
 ('_authority_metadata_access_label_retention_accept_v1(text,text,integer,integer,integer)','43e39491b715dc6bee6b805c8fcad0bb1c526c594d684232933dac5092e6ba54','9e15fcfed80830c65b5a91c7fbd3629433a9c8c962579328bee3e3b5e7e66565',$change$[
 [
  " IF frozen_program->>'kind'='metadata.mirror' AND kaname._authority_metadata_mirror_command_v1() IS NULL THEN\n  RAISE EXCEPTION 'external metadata final approval failed custody' USING ERRCODE='42501';END IF;\n RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);",
  " RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);"
 ],
 [
  " IF frozen_program->>'kind'='metadata.mirror' THEN\n  -- Проверка окончательного времени и источников apply общая для обеих ветвей.\n  -- Подтверждаем точный reserve, включая определения, с которыми был собран\n  -- список источников; отложенная проверка повторит сверку при commit.\n  used_rows:=used_rows+4;used_reads:=used_reads+4;used_work:=used_work+4;\n  IF used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN\n   RAISE EXCEPTION 'external metadata final acceptance budget exhausted' USING ERRCODE='54000';END IF;\n  IF program->>'frozen_mode' IS DISTINCT FROM 'external_access_labels'\n   OR program->'maximum' IS DISTINCT FROM '[]'::jsonb OR program->'selected' IS DISTINCT FROM '[]'::jsonb\n   OR requirements IS DISTINCT FROM kaname._authority_metadata_access_label_stashed_v1()#>'{retention,resource_requirements}'\n   OR frozen_program ? 'access_label_freshness_installed'\n   OR frozen_program->'mirror_state' IS DISTINCT FROM\n    '{\"root_applied\":false,\"root_after\":null,\"audit_consumed\":false,\"reconcile_consumed\":false}'::jsonb THEN\n   RAISE EXCEPTION 'external metadata final evidence differs' USING ERRCODE='42501';END IF;\n ELSE\n  SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e\n  WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1\n   AND e.table_name='resource_journal' AND e.selected\n   AND NOT (e.registered OR e.claimed OR e.consumed)\n   AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'\n   AND e.origin->>'table'=CASE freshness->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects' WHEN 'iam.serviceAccount' THEN 'service_accounts' END\n   AND e.origin#>>'{old,id}'=freshness->>'root_id' AND e.origin#>>'{new,id}'=freshness->>'root_id'\n   AND e.origin#>'{old,access_labels}'=freshness->'old_labels'\n   AND e.origin#>'{new,access_labels}'=freshness->'new_labels';\n  IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN\n   RAISE EXCEPTION 'metadata apply origin changed before approval' USING ERRCODE='42501';END IF;\n END IF;\n",
  " SELECT count(*)::integer INTO matches FROM pg_temp.kaname_authority_sequence_effects e\n WHERE e.nonce=(header->>'nonce')::uuid AND e.ordinal=1\n  AND e.table_name='resource_journal' AND e.selected\n  AND NOT (e.registered OR e.claimed OR e.consumed)\n  AND e.origin->>'operation'='UPDATE' AND e.origin->>'when'='AFTER'\n  AND e.origin->>'table'=CASE freshness->>'root_type' WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects' WHEN 'iam.serviceAccount' THEN 'service_accounts' END\n  AND e.origin#>>'{old,id}'=freshness->>'root_id' AND e.origin#>>'{new,id}'=freshness->>'root_id'\n  AND e.origin#>'{old,access_labels}'=freshness->'old_labels'\n  AND e.origin#>'{new,access_labels}'=freshness->'new_labels';\n IF matches<>1 OR (program->>'selected_count')::integer IS DISTINCT FROM 1 THEN\n  RAISE EXCEPTION 'metadata apply origin changed before approval' USING ERRCODE='42501';END IF;\n"
 ],
 [
  " IF coalesce(frozen_program->>'kind','') NOT IN ('metadata.access_labels','metadata.mirror')",
  " IF frozen_program->>'kind' IS DISTINCT FROM 'metadata.access_labels'"
 ]
]$change$::jsonb),
 ('_authority_metadata_access_label_compile_reserve_v1(jsonb,text,text,text,integer,integer,integer)','f7a3293081fe9356281e2022040aa3113069e89ea573fb328752f74cce447444','5b99413fb55cfcab7302e560b12fc68b286a52ae4534b905893f623f0de2c763',$change$[
 [
  " root_type:=compiled#>>'{receipt,root_type}';root_id:=compiled#>>'{receipt,root_id}';\n IF physical->>'table'='resource_mirror' THEN\n  RETURN kaname._authority_metadata_mirror_reserve_v1(compiled,p_audit,p_actor_type,p_actor_id,p_rows,p_reads,p_work);\n END IF;",
  " root_type:=compiled#>>'{receipt,root_type}';root_id:=compiled#>>'{receipt,root_id}';"
 ]
]$change$::jsonb)
 ) AS expected(signature,prior,installed,changes) LOOP
  target:=to_regprocedure('kaname.'||step.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=target AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.prior THEN
   RAISE EXCEPTION 'external metadata predecessor differs: %',step.signature;END IF;
  FOR replacement IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,replacement->>0,''))<>octet_length(replacement->>0) THEN
    RAISE EXCEPTION 'external metadata splice is ambiguous: %',step.signature;END IF;
   body:=replace(body,replacement->>0,replacement->>1);
   definition:=replace(definition,replacement->>0,replacement->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM step.installed THEN
   RAISE EXCEPTION 'external metadata result differs: %',step.signature;END IF;
  EXECUTE definition;
 END LOOP;
END;
$install$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_metadata_mirror_write_v1(text,text);
DROP FUNCTION kaname._authority_metadata_mirror_write_v1(text,text);
