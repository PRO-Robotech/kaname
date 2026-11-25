-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_mirror_grant_v1(p_runtime regrole)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $grant$
DECLARE runtime_name name; facade record; fn regprocedure;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF kaname._authority_metadata_access_label_runtime_cohort_v2(p_runtime::oid) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'external metadata requires the main runtime cohort' USING ERRCODE='42501';
 END IF;
 -- Основной установщик поддерживает и роли NOLOGIN. Внешний ABI доступен
 -- только ограниченной учётной записи сервиса с правом LOGIN.
 SELECT r.rolname INTO runtime_name FROM pg_catalog.pg_roles r WHERE r.oid=p_runtime::oid
  AND kaname._authority_role_actor_ordinary_login_v1(r.oid);
 IF NOT FOUND THEN RETURN; END IF;

 FOR facade IN SELECT * FROM (VALUES
  ('authority_metadata_mirror_ordinary_identity_v1(text,text)','438b1f5b2c18e1ee14595ba2748cdd6b354cc86b8689579a3612a6db2331778e'),
  ('authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)','d781ab3c4a458e8372b1e9b2da20839c2ac819f7132b3aaafd526e712e62e317'),
  ('authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)','adef1db014842ae1bbeb10f5cea328848c5b78e50736a9b2f36b2e76af1f1fc4'),
  ('authority_metadata_mirror_ordinary_accept_v1(text,text)','505a89d1cbd2b901d4e795a493233b5b8d2c84a9efff5504ed895c447b993e33'),
  ('authority_metadata_mirror_apply_v1(text,text)','cb2691ba2ab143446991753d836ffceeed021851c0cca47767eda7301a4edc14'),
  ('authority_metadata_mirror_update_ready_v1(text)','3b25169f5b6d337434cebd806fc4a258f8ae019ce60c1cc637f307ae637380db')
 ) AS exports(signature,digest) LOOP
  fn:=to_regprocedure('kaname.'||facade.signature);
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=facade.digest) THEN
   RAISE EXCEPTION 'unexpected external metadata facade: %',facade.signature USING ERRCODE='55000';
  END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I',fn,runtime_name);
 END LOOP;
END;
$grant$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $seal$
DECLARE fn regprocedure:='kaname._authority_metadata_mirror_grant_v1(regrole)'::regprocedure; recipient record;
BEGIN
 EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
 END LOOP;
END;
$seal$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_protocol_grant_runtime(regrole)','004cc0ab12aafce9d8284311b6e9b45bb94c0f3e78a39d8d9f2b610c41e5f051','524976d0f58dff2732037db4f65291423b7e2129e384f8892176be24503c2e62',
   $pairs$[
 [
  " PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);",
  " PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);\n PERFORM kaname._authority_metadata_mirror_grant_v1(p_runtime);"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b','ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee',
   $pairs$[
 [
  " ('authority_protocol_grant_runtime(regrole)','004cc0ab12aafce9d8284311b6e9b45bb94c0f3e78a39d8d9f2b610c41e5f051',false,'v',true,'preserve'),",
  " ('authority_protocol_grant_runtime(regrole)','524976d0f58dff2732037db4f65291423b7e2129e384f8892176be24503c2e62',false,'v',true,'preserve'),\n ('_authority_metadata_mirror_grant_v1(regrole)','894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7',false,'v',true,'private'),"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b','3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145',
   $pairs$[
 [
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b",
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee"
 ]
]$pairs$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','cc1b08c90db8a42c290cd0404a0d6692c0cd28a7ce0d7a711d79ed7367a48b07','65a6271c581e9577a6065f4a1355e0376b1dbdef7fc63822d7aacead13fe8805',
   $pairs$[
 [
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b",
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee"
 ],
 [
  "71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b",
  "3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'unexpected predecessor: %',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'ambiguous splice: %',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'unexpected result: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'invalid runtime grant contract' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $backfill$
DECLARE recipient record;
BEGIN
 FOR recipient IN SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolcanlogin
  AND kaname._authority_metadata_access_label_runtime_cohort_v2(r.oid) LOOP
  PERFORM kaname._authority_metadata_mirror_grant_v1(recipient.oid::regrole);
 END LOOP;
END;
$backfill$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','65a6271c581e9577a6065f4a1355e0376b1dbdef7fc63822d7aacead13fe8805','cc1b08c90db8a42c290cd0404a0d6692c0cd28a7ce0d7a711d79ed7367a48b07',
   $pairs$[
 [
  "3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145",
  "71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b"
 ],
 [
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee",
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','3a0f261127fe44e479df420fea71603f5f1131f4b08a87219d3282e70e0b1145','71ca5801eac3776fc448745b5abde9387b58f9cc267bada41de0b7196d0d639b',
   $pairs$[
 [
  "ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee",
  "b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','ef90143402897fd414dbbd8d5645f585ed9a8b93bdc6d69da8e9c309555824ee','b44ee8e5cca78dbd2e8301fc9dafc3e7fbee4b88a10a052afad82d5e37f8f92b',
   $pairs$[
 [
  " ('authority_protocol_grant_runtime(regrole)','524976d0f58dff2732037db4f65291423b7e2129e384f8892176be24503c2e62',false,'v',true,'preserve'),\n ('_authority_metadata_mirror_grant_v1(regrole)','894c502c7964cd37d073107df6b5eed59a16f02228b3a7352fb50cf13e47d8a7',false,'v',true,'private'),",
  " ('authority_protocol_grant_runtime(regrole)','004cc0ab12aafce9d8284311b6e9b45bb94c0f3e78a39d8d9f2b610c41e5f051',false,'v',true,'preserve'),"
 ]
]$pairs$::jsonb),
  ('authority_protocol_grant_runtime(regrole)','524976d0f58dff2732037db4f65291423b7e2129e384f8892176be24503c2e62','004cc0ab12aafce9d8284311b6e9b45bb94c0f3e78a39d8d9f2b610c41e5f051',
   $pairs$[
 [
  " PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);\n PERFORM kaname._authority_metadata_mirror_grant_v1(p_runtime);",
  " PERFORM kaname._authority_metadata_access_label_grant_v2(p_runtime);"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'unexpected predecessor: %',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'ambiguous splice: %',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'unexpected result: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'invalid runtime grant contract' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

-- Возвращаем шести фасадам права владельца, заданные при их создании.
-- В выборку входят и прежние получатели, у которых успели измениться права или атрибуты роли.
-- +goose StatementBegin
DO $close$
DECLARE fn regprocedure; recipient record;
BEGIN
 FOREACH fn IN ARRAY ARRAY[
  'kaname.authority_metadata_mirror_ordinary_identity_v1(text,text)'::regprocedure,
  'kaname.authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)'::regprocedure,
  'kaname.authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)'::regprocedure,
  'kaname.authority_metadata_mirror_ordinary_accept_v1(text,text)'::regprocedure,
  'kaname.authority_metadata_mirror_apply_v1(text,text)'::regprocedure,
  'kaname.authority_metadata_mirror_update_ready_v1(text)'::regprocedure
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$close$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_mirror_grant_v1(regrole);
