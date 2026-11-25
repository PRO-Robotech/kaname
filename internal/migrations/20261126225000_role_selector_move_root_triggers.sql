-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Триггеры обычного metadata writer и переноса роли сверяют один actual OLD/NEW.
-- Отложенная проверка требует сохранения результата каждого корня до COMMIT.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $root_custody$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('access_labels_immutable_v1()','b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036',$changes$[
 [
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=",
  " IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;\n IF TG_TABLE_NAME='resource_mirror' THEN\n  command:="
 ]
]$changes$::jsonb),
  ('_authority_metadata_access_label_freshness_v1()','d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e',$changes$[
 [
  " command jsonb;",
  " command jsonb;\n move_root jsonb;"
 ],
 [
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=",
  " move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n IF move_root IS NOT NULL THEN\n  command:=move_root;\n ELSIF TG_TABLE_NAME='resource_mirror' THEN\n  command:="
 ],
 [
  " receipt:=store#>'{frozen,access_label_freshness}';",
  " receipt:=CASE WHEN move_root IS NULL THEN store#>'{frozen,access_label_freshness}' ELSE move_root->'freshness' END;"
 ],
 [
  "  OR (store->'frozen') ? 'access_label_freshness_installed'",
  "  OR (store->'frozen') ? 'access_label_freshness_installed' OR coalesce(move_root ? 'installed',false)"
 ],
 [
  " UPDATE pg_temp.kaname_authority_sequence_program p\n SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n GET DIAGNOSTICS affected=ROW_COUNT;",
  " IF move_root IS NULL THEN\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n  GET DIAGNOSTICS affected=ROW_COUNT;\n ELSE\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=jsonb_set(p.frozen,'{selector_move_active,installed}',to_jsonb(v_generation))\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='role' AND p.frozen->'selector_move_active'=move_root;\n  GET DIAGNOSTICS affected=ROW_COUNT;\n END IF;"
 ]
]$changes$::jsonb),
  ('resource_mirror_keeps_the_bound_project()','1857706cd41c2dfce6c97b2e162d8431260a72152840c43ff6d1a98fef80d994','78b2480af1d4597adba99929856dfa58b95e2d8c5645b962725fde4aa0579cfd',$changes$[
 [
  "        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';",
  "        IF current_user::regrole=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid='kaname.authority_writer_protocol'::regclass) THEN\n          IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN\n            IF TG_TABLE_SCHEMA<>'kaname' OR TG_RELID<>'kaname.resource_mirror'::regclass OR TG_LEVEL<>'ROW'\n                OR (TG_WHEN,TG_NAME) NOT IN (('BEFORE','resource_mirror_keeps_the_bound_project'),\n                    ('AFTER','resource_mirror_binds_effective_registration')) THEN\n                RAISE EXCEPTION 'selector move mirror registration trigger differs' USING ERRCODE='42501';\n            END IF;\n            RETURN NEW;\n          END IF;\n        END IF;\n        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';"
 ]
]$changes$::jsonb),
  ('_authority_sequence_complete_v3()','319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4','4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5',$changes$[
 [
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'",
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program r WHERE r.singleton AND r.frozen ? 'selector_move') THEN\n   PERFORM kaname._authority_role_move_roots_complete_v1();\n  END IF;\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'"
 ]
]$changes$::jsonb),
  ('authority_access_label_storage_valid_v1()','4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921','a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74',$changes$[
 [
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc",
  "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036"
 ]
]$changes$::jsonb),
  ('authority_metadata_access_label_ready_v2(text)','a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1','198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252',$changes$[
 [
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f",
  "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410','e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57',$changes$[
 [
  "319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4",
  "4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5"
 ],
 [
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),",
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint)','eeb53f9cc5f1d57ba74d72f00fc46179c7a27e6a9cd50a29ccd84bb46b78a4b3',false,'s',true,'private'),\n ('_authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer)','2a394cac84875f296557ae0792828a6a1258cbdb1129e8c2e97162fafb3eacf5',false,'s',true,'private'),\n ('_authority_role_move_root_outputs_hold_v1(jsonb,integer,integer)','6d535a374ba91de4292e5baa2731b2a35e361507dfc07d2cc662a719cecea5c0',false,'v',true,'private'),\n ('_authority_role_move_root_registration_v1(jsonb)','5c924628aad1ff58ee43dfb8fc79dfdbad1bdc7f819a4200f210119c2d63aef6',false,'v',true,'private'),\n ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),\n ('_authority_role_move_roots_write_v1()','47e6f3077fc18fe2877a718ad49b7c66be6bb19e4143c1160583ae584f339bb6',false,'v',true,'private'),\n ('_authority_role_move_roots_complete_v1()','f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e',false,'v',true,'private'),\n ('access_labels_immutable_v1()','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036',false,'v',true,'private'),\n ('_authority_metadata_access_label_freshness_v1()','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e',false,'v',true,'private'),"
 ],
 [
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),",
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint)','jsonb',4,ARRAY['p_root','p_actor','p_audit','p_reconcile']),\n  ('_authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_role','p_root','p_labels','p_rows','p_reads']),\n  ('_authority_role_move_root_outputs_hold_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_frozen','p_rows','p_reads']),\n  ('_authority_role_move_root_registration_v1(jsonb)','void',1,ARRAY['p_root']),\n  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_role_move_roots_write_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_roots_complete_v1()','void',0,NULL::text[]),"
 ],
 [
  " IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass",
  " IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.resource_mirror_keeps_the_bound_project()')\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND NOT p.proretset\n  AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, kaname']\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='78b2480af1d4597adba99929856dfa58b95e2d8c5645b962725fde4aa0579cfd') THEN RETURN false;END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f','384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344',$changes$[
 [
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410",
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','ddd528b7365fd23685693207053e82a4fba204d2eb55d61f87506889a78c5559','9310a1ee07187723e1cdfd931a693cecf22c1f160752d18ddd5dabb448932b7a',$changes$[
 [
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc",
  "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036"
 ],
 [
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f",
  "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e"
 ],
 [
  "4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921",
  "a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74"
 ],
 [
  "a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1",
  "198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252"
 ],
 [
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410",
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57"
 ],
 [
  "69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f",
  "384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344"
 ]
]$changes$::jsonb)
 ) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move root predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move root splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move root body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move root function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move root function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move trigger custody differs after migration' USING ERRCODE='55000';END IF;
END;
$root_custody$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $root_custody$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','9310a1ee07187723e1cdfd931a693cecf22c1f160752d18ddd5dabb448932b7a','ddd528b7365fd23685693207053e82a4fba204d2eb55d61f87506889a78c5559',$changes$[
 [
  "384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344",
  "69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f"
 ],
 [
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57",
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410"
 ],
 [
  "198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252",
  "a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1"
 ],
 [
  "a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74",
  "4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921"
 ],
 [
  "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e",
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f"
 ],
 [
  "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036",
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344','69b30e1a511507c6d0e27a5e3b0eeb71d2302504e0bd884c01646e134c20d59f',$changes$[
 [
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57",
  "3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57','3b2369bd73c9e96a3a2a7825ec68f7ea11b14eaa6a13797c49ef2cf1f3904410',$changes$[
 [
  " IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.resource_mirror_keeps_the_bound_project()')\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND NOT p.proretset\n  AND p.provolatile='v' AND p.proconfig=ARRAY['search_path=pg_catalog, kaname']\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='78b2480af1d4597adba99929856dfa58b95e2d8c5645b962725fde4aa0579cfd') THEN RETURN false;END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass",
  " IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass"
 ],
 [
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint)','jsonb',4,ARRAY['p_root','p_actor','p_audit','p_reconcile']),\n  ('_authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_role','p_root','p_labels','p_rows','p_reads']),\n  ('_authority_role_move_root_outputs_hold_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_frozen','p_rows','p_reads']),\n  ('_authority_role_move_root_registration_v1(jsonb)','void',1,ARRAY['p_root']),\n  ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','jsonb',5,ARRAY['p_rel','p_old','p_new','p_xmin','p_ctid']),\n  ('_authority_role_move_roots_write_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_roots_complete_v1()','void',0,NULL::text[]),",
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),"
 ],
 [
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_root_outputs_v1(jsonb,jsonb,text,bigint)','eeb53f9cc5f1d57ba74d72f00fc46179c7a27e6a9cd50a29ccd84bb46b78a4b3',false,'s',true,'private'),\n ('_authority_role_move_root_carriers_v1(text,jsonb,jsonb,integer,integer)','2a394cac84875f296557ae0792828a6a1258cbdb1129e8c2e97162fafb3eacf5',false,'s',true,'private'),\n ('_authority_role_move_root_outputs_hold_v1(jsonb,integer,integer)','6d535a374ba91de4292e5baa2731b2a35e361507dfc07d2cc662a719cecea5c0',false,'v',true,'private'),\n ('_authority_role_move_root_registration_v1(jsonb)','5c924628aad1ff58ee43dfb8fc79dfdbad1bdc7f819a4200f210119c2d63aef6',false,'v',true,'private'),\n ('_authority_role_move_root_trigger_v1(oid,jsonb,jsonb,text,text)','347ce6b789b9a8334216f7a202949fd833ead9154bf0178371536078ccf9f523',false,'v',true,'private'),\n ('_authority_role_move_roots_write_v1()','47e6f3077fc18fe2877a718ad49b7c66be6bb19e4143c1160583ae584f339bb6',false,'v',true,'private'),\n ('_authority_role_move_roots_complete_v1()','f8ab09fd1664a0a1bf70f4708848bd2ac68ab0e2db4a36da668e3f90e686513e',false,'v',true,'private'),\n ('access_labels_immutable_v1()','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036',false,'v',true,'private'),\n ('_authority_metadata_access_label_freshness_v1()','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e',false,'v',true,'private'),",
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),"
 ],
 [
  "4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5",
  "319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4"
 ]
]$changes$::jsonb),
  ('authority_metadata_access_label_ready_v2(text)','198d63dd8dc6d1c112a124ea06399a521ad37cf0402a8ed78a4ca105b80f0252','a164a004464da5e8a822c3c235775c6801a7d2201edb2089b37c69559ffd71d1',$changes$[
 [
  "0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e",
  "d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f"
 ]
]$changes$::jsonb),
  ('authority_access_label_storage_valid_v1()','a64e35aa7a1e913aef34260331117978538d81740fcdbe24fd413344f95f7b74','4708a00b2e8b4c941ccd1b23adeac44dbe61cbdf71f9636485af88c9ed0e4921',$changes$[
 [
  "acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036",
  "b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc"
 ]
]$changes$::jsonb),
  ('_authority_sequence_complete_v3()','4d590ae391a2bff05a7c8346055fa364b342ac290a58079372a661dffffb28e5','319c4cda0e3e509c803b5429e1184baaf105a1fbdf02b08d833646a193ae02f4',$changes$[
 [
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program r WHERE r.singleton AND r.frozen ? 'selector_move') THEN\n   PERFORM kaname._authority_role_move_roots_complete_v1();\n  END IF;\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'",
  " IF program->>'family'='role' AND program#>>'{frozen,mode}' IN ('selector_move','access_label_transition') THEN\n  IF EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_program s WHERE s.singleton AND s.frozen ? 'selector_move'"
 ]
]$changes$::jsonb),
  ('resource_mirror_keeps_the_bound_project()','78b2480af1d4597adba99929856dfa58b95e2d8c5645b962725fde4aa0579cfd','1857706cd41c2dfce6c97b2e162d8431260a72152840c43ff6d1a98fef80d994',$changes$[
 [
  "        IF current_user::regrole=(SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid='kaname.authority_writer_protocol'::regclass) THEN\n          IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN\n            IF TG_TABLE_SCHEMA<>'kaname' OR TG_RELID<>'kaname.resource_mirror'::regclass OR TG_LEVEL<>'ROW'\n                OR (TG_WHEN,TG_NAME) NOT IN (('BEFORE','resource_mirror_keeps_the_bound_project'),\n                    ('AFTER','resource_mirror_binds_effective_registration')) THEN\n                RAISE EXCEPTION 'selector move mirror registration trigger differs' USING ERRCODE='42501';\n            END IF;\n            RETURN NEW;\n          END IF;\n        END IF;\n        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';",
  "        approved:=kaname._authority_metadata_mirror_command_v1()#>'{frozen,mirror_command}';"
 ]
]$changes$::jsonb),
  ('_authority_metadata_access_label_freshness_v1()','0e85aa4801946331a742372d50b1f4af2cf92e81547a9e375e278095b0f8aa8e','d132528b577029a6ba65d0418ed0d60da0344068d1ba208fcd3c827682e0e59f',$changes$[
 [
  " IF move_root IS NULL THEN\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n  GET DIAGNOSTICS affected=ROW_COUNT;\n ELSE\n  UPDATE pg_temp.kaname_authority_sequence_program p\n  SET frozen=jsonb_set(p.frozen,'{selector_move_active,installed}',to_jsonb(v_generation))\n  WHERE p.singleton AND p.nonce=v_generation AND p.family='role' AND p.frozen->'selector_move_active'=move_root;\n  GET DIAGNOSTICS affected=ROW_COUNT;\n END IF;",
  " UPDATE pg_temp.kaname_authority_sequence_program p\n SET frozen=p.frozen||jsonb_build_object('access_label_freshness_installed',v_generation)\n WHERE p.singleton AND p.nonce=v_generation AND p.family='metadata' AND p.frozen=store->'frozen';\n GET DIAGNOSTICS affected=ROW_COUNT;"
 ],
 [
  "  OR (store->'frozen') ? 'access_label_freshness_installed' OR coalesce(move_root ? 'installed',false)",
  "  OR (store->'frozen') ? 'access_label_freshness_installed'"
 ],
 [
  " receipt:=CASE WHEN move_root IS NULL THEN store#>'{frozen,access_label_freshness}' ELSE move_root->'freshness' END;",
  " receipt:=store#>'{frozen,access_label_freshness}';"
 ],
 [
  " move_root:=kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text);\n IF move_root IS NOT NULL THEN\n  command:=move_root;\n ELSIF TG_TABLE_NAME='resource_mirror' THEN\n  command:=",
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:="
 ],
 [
  " command jsonb;\n move_root jsonb;",
  " command jsonb;"
 ]
]$changes$::jsonb),
  ('access_labels_immutable_v1()','acc1d3c05b3ce197ed945cab419e1aa12a9b145daae5460a20ecd2e6b60b6036','b50b808f723e06da8d64824d576344b9b86d0518558dd97aec6bf97867c813dc',$changes$[
 [
  " IF kaname._authority_role_move_root_trigger_v1(TG_RELID,to_jsonb(OLD),to_jsonb(NEW),OLD.xmin::text,OLD.ctid::text) IS NOT NULL THEN RETURN NEW;END IF;\n IF TG_TABLE_NAME='resource_mirror' THEN\n  command:=",
  " IF TG_TABLE_NAME='resource_mirror' THEN\n  command:="
 ]
]$changes$::jsonb)
 ) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move root predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move root splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move root body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move root function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move root function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move trigger custody differs after migration' USING ERRCODE='55000';END IF;
END;
$root_custody$;
-- +goose StatementEnd
