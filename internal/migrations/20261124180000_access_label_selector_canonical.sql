-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Храним селекторы меток доступа отдельно от обычных. Точные образы
-- прежних строк получают пустые карты, а их канонические отпечатки сохраняются.

-- +goose Up
SELECT kaname.authority_protocol_drain();
-- +goose StatementBegin
DO $$ BEGIN IF NOT kaname._authority_full_contract_storage_v3() OR NOT kaname.authority_access_label_storage_valid_v1() THEN RAISE EXCEPTION 'selector canonical baseline closure mismatch' USING ERRCODE='55000';END IF;END $$;
-- +goose StatementEnd
LOCK TABLE kaname.role_rule_selectors IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
CREATE FUNCTION kaname.access_label_selector_shape_v1(p_arm text,p_names text[],p_labels jsonb,p_access jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $shape$
BEGIN
 IF p_arm IS NULL OR p_names IS NULL OR jsonb_typeof(p_labels) IS DISTINCT FROM 'object'
  OR kaname.access_labels_valid_v1(p_access) IS DISTINCT FROM true THEN RETURN false;END IF;
 IF p_arm='access_labels' THEN
  RETURN p_labels='{}'::jsonb AND cardinality(p_names)=0 AND p_access<>'{}'::jsonb
   AND (SELECT count(*) FROM jsonb_object_keys(p_access))<=16;
 END IF;
 IF p_access<>'{}'::jsonb THEN RETURN false;END IF;
 RETURN (p_arm='anchor' AND cardinality(p_names)=0 AND p_labels='{}'::jsonb)
  OR (p_arm='names' AND cardinality(p_names)>=1 AND p_labels='{}'::jsonb)
  OR (p_arm='labels' AND cardinality(p_names)=0 AND p_labels<>'{}'::jsonb);
END;
$shape$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.access_label_selector_shape_v1(text,text[],jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.access_label_selector_shape_v1(text,text[],jsonb,jsonb) TO PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION kaname.access_label_selector_container_shape_v1(p_type text,p_object_type text,p_arm text,p_names text[],p_labels jsonb,p_access jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $shape$
BEGIN
 IF p_type IS NULL THEN
  RETURN p_object_type IS NULL AND p_arm IS NULL AND p_names IS NOT NULL
   AND cardinality(p_names)=0 AND p_labels IS NOT DISTINCT FROM '{}'::jsonb
   AND p_access IS NOT DISTINCT FROM '{}'::jsonb;
 END IF;
 IF p_object_type IS NULL OR p_arm IS NULL THEN RETURN false;END IF;
 RETURN kaname.access_label_selector_shape_v1(p_arm,p_names,p_labels,p_access);
END;
$shape$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb) TO PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE f record;r record;BEGIN
 FOR f IN SELECT p.oid,p.oid::regprocedure AS signature,p.proowner FROM pg_catalog.pg_proc p
 WHERE p.oid IN ('kaname.access_label_selector_shape_v1(text,text[],jsonb,jsonb)'::regprocedure,
 'kaname.access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb)'::regprocedure) LOOP
  FOR r IN SELECT DISTINCT u.rolname FROM aclexplode(coalesce((SELECT proacl FROM pg_proc WHERE oid=f.oid),acldefault('f',f.proowner))) a
   JOIN pg_roles u ON u.oid=a.grantee WHERE a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE kaname.role_rule_selectors
 ADD COLUMN match_access_labels jsonb NOT NULL DEFAULT '{}'::jsonb,
 ADD COLUMN container_match_access_labels jsonb NOT NULL DEFAULT '{}'::jsonb,
 DROP CONSTRAINT role_rule_selectors_arm_shape,
 DROP CONSTRAINT role_rule_selectors_arm_valid,
 DROP CONSTRAINT role_rule_selectors_container_shape;
ALTER TABLE kaname.role_rule_selectors
 ADD CONSTRAINT role_rule_selectors_access_labels_valid
  CHECK (kaname.access_labels_valid_v1(match_access_labels)),
 ADD CONSTRAINT role_rule_selectors_container_access_labels_valid
  CHECK (kaname.access_labels_valid_v1(container_match_access_labels)),
 ADD CONSTRAINT role_rule_selectors_arm_valid CHECK (arm IN ('anchor','names','labels','access_labels')),
 ADD CONSTRAINT role_rule_selectors_arm_shape
  CHECK (kaname.access_label_selector_shape_v1(arm,resource_names,match_labels,match_access_labels)),
 ADD CONSTRAINT role_rule_selectors_container_shape
  CHECK (kaname.access_label_selector_container_shape_v1(container_type,container_object_type,container_arm,container_resource_names,container_match_labels,container_match_access_labels));
COMMENT ON COLUMN kaname.role_rule_selectors.match_access_labels IS
 'Предикат защищённых меток объекта.';
COMMENT ON COLUMN kaname.role_rule_selectors.container_match_access_labels IS
 'Предикат защищённых меток контейнера вложенного правила.';


-- +goose StatementBegin
DO $selector_images$
DECLARE item record; pair jsonb; fn regprocedure; old_body text; new_body text; definition text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('_authority_resource_rule_fingerprint_v2(jsonb,boolean)','4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5','518f677f8bfd19b991616777cef08c197ec6d3a7a8b39e7db567145fee89d286',$patch$[[" children:=coalesce(nullif(p_rule->'children','null'::jsonb),'[]'::jsonb);", " -- New namespace contributes bytes only when explicitly authored; legacy bytes are frozen.\n IF p_rule ? 'match_access_labels' THEN\n  labels:=p_rule->'match_access_labels';\n  IF kaname.access_labels_valid_v1(labels) IS DISTINCT FROM true OR labels='{}'::jsonb\n   OR (SELECT count(*) FROM jsonb_object_keys(labels))>16\n   OR p_rule ? 'match_labels' OR p_rule ? 'resource_names' OR p_rule ? 'created_by_subject'\n   OR p_rule->>'module'='*' OR p_rule->'resources' ? '*' OR p_rule->'verbs' ? '*' THEN\n   RAISE EXCEPTION 'authored protected label selector invalid' USING ERRCODE='42501';END IF;\n  data:=data||convert_to('access_labels','UTF8')||nul||convert_to('l','UTF8')||nul;\n  FOR entry IN SELECT * FROM jsonb_each_text(labels) ORDER BY key COLLATE \"C\" LOOP\n   data:=data||convert_to(entry.key,'UTF8')||nul||convert_to(entry.value,'UTF8')||nul;\n  END LOOP;\n  data:=data||ending;\n END IF;\n children:=coalesce(nullif(p_rule->'children','null'::jsonb),'[]'::jsonb);"]]$patch$::jsonb),
 ('_authority_resource_encode_proposed_rules_v2(jsonb,boolean)','e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc','949ffb2668d8c51c852a6470006410b3e9e899aa3da0ce94e686c33a551ae3d1',$patch$[["(SELECT count(*) FROM jsonb_object_keys(r))<>7", "r-ARRAY['Module','Resources','Verbs','ResourceNames','MatchLabels','MatchAccessLabels','Children','CreatedBySubject']<>'{}'::jsonb"], ["  IF NOT p_child THEN\n   children:=kaname._authority_resource_encode_proposed_rules_v2(r->'Children',true);", "  IF r ? 'MatchAccessLabels' THEN\n   IF kaname.access_labels_valid_v1(r->'MatchAccessLabels') IS DISTINCT FROM true\n    OR r->'MatchAccessLabels'='{}'::jsonb\n    OR (SELECT count(*) FROM jsonb_object_keys(r->'MatchAccessLabels'))>16\n    OR r->'MatchLabels' IS DISTINCT FROM 'null'::jsonb OR jsonb_array_length(names)<>0\n    OR r->'CreatedBySubject' IS DISTINCT FROM 'false'::jsonb\n    OR r->>'Module'='*' OR r->'Resources' ? '*' OR r->'Verbs' ? '*' THEN\n    RAISE EXCEPTION 'invalid proposed protected selector' USING ERRCODE='42501';END IF;\n   encoded:=encoded||jsonb_build_object('match_access_labels',r->'MatchAccessLabels');\n  END IF;\n  IF NOT p_child THEN\n   children:=kaname._authority_resource_encode_proposed_rules_v2(r->'Children',true);"]]$patch$::jsonb),
 ('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6','4bed730285f3ee92f2976612cc57b7e42830aafb8cb32b938f382d5c83e8588a',$patch$[["node-ARRAY['resources','verbs','resource_names','match_labels']", "node-ARRAY['resources','verbs','resource_names','match_labels','match_access_labels']"], ["node-ARRAY['module','resources','verbs','resource_names','match_labels','children','created_by_subject']", "node-ARRAY['module','resources','verbs','resource_names','match_labels','match_access_labels','children','created_by_subject']"], ["    IF octet_length(node::text)>1048576 THEN", "    IF node ? 'match_access_labels' THEN\n     IF kaname.access_labels_valid_v1(node->'match_access_labels') IS DISTINCT FROM true\n      OR node->'match_access_labels'='{}'::jsonb\n      OR (SELECT count(*) FROM jsonb_object_keys(node->'match_access_labels'))>16\n      OR node ? 'match_labels' OR node ? 'resource_names' OR node ? 'created_by_subject'\n      OR owner->>'module'='*' OR node->'resources' ? '*' OR node->'verbs' ? '*' THEN\n      RAISE EXCEPTION 'invalid protected label rule' USING ERRCODE='42501';END IF;\n    END IF;\n    IF octet_length(node::text)>1048576 THEN"], ["owner_arm:=CASE WHEN owner ? 'resource_names' THEN 1 WHEN owner ? 'match_labels' THEN 2 ELSE 0 END;", "owner_arm:=CASE WHEN owner ? 'match_access_labels' THEN 3 WHEN owner ? 'resource_names' THEN 1 WHEN owner ? 'match_labels' THEN 2 ELSE 0 END;"], ["arm:=CASE WHEN node ? 'resource_names' THEN 1 WHEN node ? 'match_labels' THEN 2 ELSE 0 END;", "arm:=CASE WHEN node ? 'match_access_labels' THEN 3 WHEN node ? 'resource_names' THEN 1 WHEN node ? 'match_labels' THEN 2 ELSE 0 END;"], ["IF NOT is_child AND arm<>2 AND", "IF NOT is_child AND arm NOT IN (2,3) AND"], ["'MatchLabels',CASE WHEN owner_arm=2 THEN owner->'match_labels' ELSE 'null'::jsonb END);", "'MatchLabels',CASE WHEN owner_arm=2 THEN owner->'match_labels' ELSE 'null'::jsonb END)\n      ||CASE WHEN owner_arm=3 THEN jsonb_build_object('MatchAccessLabels',owner->'match_access_labels') ELSE '{}'::jsonb END;"], ["'Container',container,'CreatedBySubject',coalesce((node->>'created_by_subject')::boolean,false),'Grants',grants);", "'Container',container,'CreatedBySubject',coalesce((node->>'created_by_subject')::boolean,false),'Grants',grants)\n     ||CASE WHEN arm=3 THEN jsonb_build_object('MatchAccessLabels',node->'match_access_labels') ELSE '{}'::jsonb END;"]]$patch$::jsonb),
 ('_authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68','a89f11ab8338e4937cc32bb1bc6e5e4a771aea853599004e6b10d4f24c40f568',$patch$[["'container_type','container_object_type','container_arm','container_resource_names','container_match_labels','verbs_by_type','created_by_subject']", "'container_type','container_object_type','container_arm','container_resource_names','container_match_labels','match_access_labels','container_match_access_labels','verbs_by_type','created_by_subject']"], ["ARRAY['match_labels','container_match_labels']", "ARRAY['match_labels','container_match_labels','match_access_labels','container_match_access_labels']"], ["OR jsonb_typeof(item->'Container') NOT IN ('object','null') THEN", "OR jsonb_typeof(item->'Container') NOT IN ('object','null')\n     OR (item ? 'MatchAccessLabels' AND (jsonb_typeof(item->'MatchAccessLabels') IS DISTINCT FROM 'object'\n      OR NOT kaname.access_labels_valid_v1(item->'MatchAccessLabels'))) THEN"], ["arm_name:=CASE item->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' ELSE 'anchor' END;", "IF item->>'Arm' NOT IN ('0','1','2','3') THEN RAISE EXCEPTION 'invalid selector arm' USING ERRCODE='42501';END IF;\n     arm_name:=CASE item->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' WHEN '3' THEN 'access_labels' ELSE 'anchor' END;"], ["'match_labels',coalesce(nullif(item->'MatchLabels','null'::jsonb),'{}'::jsonb),", "'match_labels',coalesce(nullif(item->'MatchLabels','null'::jsonb),'{}'::jsonb),\n      'match_access_labels',coalesce(item->'MatchAccessLabels','{}'::jsonb),"], ["'container_match_labels','{}'::jsonb,'verbs_by_type'", "'container_match_labels','{}'::jsonb,'container_match_access_labels','{}'::jsonb,'verbs_by_type'"], ["OR jsonb_typeof(container->'ResourceNames') NOT IN ('array','null') OR jsonb_typeof(container->'MatchLabels') NOT IN ('object','null') THEN", "OR jsonb_typeof(container->'ResourceNames') NOT IN ('array','null') OR jsonb_typeof(container->'MatchLabels') NOT IN ('object','null')\n      OR container->>'Arm' NOT IN ('0','1','2','3')\n      OR (container ? 'MatchAccessLabels' AND (jsonb_typeof(container->'MatchAccessLabels') IS DISTINCT FROM 'object'\n       OR NOT kaname.access_labels_valid_v1(container->'MatchAccessLabels'))) THEN"], ["'container_arm',CASE container->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' ELSE 'anchor' END,", "'container_arm',CASE container->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' WHEN '3' THEN 'access_labels' ELSE 'anchor' END,"], ["'container_match_labels',coalesce(nullif(container->'MatchLabels','null'::jsonb),'{}'::jsonb));", "'container_match_labels',coalesce(nullif(container->'MatchLabels','null'::jsonb),'{}'::jsonb),\n       'container_match_access_labels',coalesce(container->'MatchAccessLabels','{}'::jsonb));"], ["     stored:=attempted||jsonb_build_object('container_object_type',live_types->(attempted->>'container_type'));", "     IF (arm_name='access_labels') IS DISTINCT FROM (attempted->'match_access_labels'<>'{}'::jsonb)\n      OR (arm_name='access_labels' AND (attempted->'match_labels'<>'{}'::jsonb OR attempted->'resource_names'<>'[]'::jsonb))\n      OR (coalesce(attempted->>'container_arm','')='access_labels') IS DISTINCT FROM (attempted->'container_match_access_labels'<>'{}'::jsonb)\n      OR (attempted->>'container_arm'='access_labels' AND (attempted->'container_match_labels'<>'{}'::jsonb OR attempted->'container_resource_names'<>'[]'::jsonb)) THEN\n      RAISE EXCEPTION 'protected selector shape differs' USING ERRCODE='42501';END IF;\n     stored:=attempted||jsonb_build_object('container_object_type',live_types->(attempted->>'container_type'));"]]$patch$::jsonb),
 ('_authority_crud_storage_v3()','2c4e608b52e90f966e2d32990f276826245f761a280e9fe2f38057c1fa2eacca','2381b78fd5700ac591d16576a0002e6fd29705bdb388d3508b4257fd989f35bb',$patch$[["4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5", "518f677f8bfd19b991616777cef08c197ec6d3a7a8b39e7db567145fee89d286"], ["e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc", "949ffb2668d8c51c852a6470006410b3e9e899aa3da0ce94e686c33a551ae3d1"], ["89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6", "4bed730285f3ee92f2976612cc57b7e42830aafb8cb32b938f382d5c83e8588a"], ["414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68", "a89f11ab8338e4937cc32bb1bc6e5e4a771aea853599004e6b10d4f24c40f568"], [" RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();", " -- Protected selector columns and constraints are part of the exact storage closure.\n FOR expected IN SELECT * FROM (VALUES\n ('access_label_selector_shape_v1(text,text[],jsonb,jsonb)','dcf3bc20fd365a918a73815fd6f491d5825c2ff7e22e8be1e5d3dbae485c6e0c'),\n ('access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb)','273e28fec954a67a65a764efa9ace98b03b081434889427afd1c7a8cf971e1db'),\n ('access_labels_valid_v1(jsonb)','5bdcbf012ab0dee0838575bc22c3109d97483e1caf2f5543d810f46be03f9c60')\n ) x(signature,digest) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)\n   AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='i' AND p.prokind='f'\n   AND p.prorettype='boolean'::regtype AND NOT p.proretset AND NOT p.proisstrict\n   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']\n   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest\n   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a\n    WHERE a.grantee<>owner_oid AND NOT (a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))) THEN RETURN false;END IF;\n END LOOP;\n FOR expected IN SELECT * FROM (VALUES ('match_access_labels'),('container_match_access_labels')) x(column_name) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum\n   WHERE a.attrelid='kaname.role_rule_selectors'::regclass AND a.attname=expected.column_name\n    AND NOT a.attisdropped AND a.atttypid='jsonb'::regtype AND a.attnotnull AND a.attgenerated=''\n    AND pg_get_expr(d.adbin,d.adrelid)='''{}''::jsonb') THEN RETURN false;END IF;\n END LOOP;\n FOR expected IN SELECT * FROM (VALUES\n ('role_rule_selectors_access_labels_valid','kaname.access_labels_valid_v1(match_access_labels)'),\n ('role_rule_selectors_container_access_labels_valid','kaname.access_labels_valid_v1(container_match_access_labels)'),\n ('role_rule_selectors_arm_shape','kaname.access_label_selector_shape_v1(arm, resource_names, match_labels, match_access_labels)'),\n ('role_rule_selectors_container_shape','kaname.access_label_selector_container_shape_v1(container_type, container_object_type, container_arm, container_resource_names, container_match_labels, container_match_access_labels)')\n ) x(constraint_name,expression) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='kaname.role_rule_selectors'::regclass\n   AND c.conname=expected.constraint_name AND c.contype='c' AND c.convalidated\n   AND NOT c.connoinherit AND pg_get_expr(c.conbin,c.conrelid)=expected.expression) THEN RETURN false;END IF;\n END LOOP;\n RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();"]]$patch$::jsonb),
 ('_authority_full_contract_storage_v3()','bd7b954c72a8c66d3548bcf587bf803f9384cd0c590599f8cc3b9032e7f0ae7d','7c77cf767ad393b3f16aaae4bcda5df7594aaed73b41a17877735bdb4e92e72b',$patch$[["2c4e608b52e90f966e2d32990f276826245f761a280e9fe2f38057c1fa2eacca", "2381b78fd5700ac591d16576a0002e6fd29705bdb388d3508b4257fd989f35bb"]]$patch$::jsonb)
 ) AS changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT prosrc INTO STRICT old_body FROM pg_catalog.pg_proc WHERE oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'selector images baseline mismatch: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   IF length(new_body)-length(replace(new_body,pair->>0,'')) IS DISTINCT FROM length(pair->>0) THEN
    RAISE EXCEPTION 'selector images substitution not unique' USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'selector images calculated pin mismatch' USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
   RAISE EXCEPTION 'selector images body not unique' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'selector images closure mismatch' USING ERRCODE='55000';END IF;
END $selector_images$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
LOCK TABLE kaname.role_rule_selectors IN ACCESS EXCLUSIVE MODE;
-- Перед откатом нужно явно перенести правила с метками доступа.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM kaname.role_rule_selectors
  WHERE arm='access_labels' OR container_arm='access_labels'
   OR match_access_labels<>'{}'::jsonb OR container_match_access_labels<>'{}'::jsonb) THEN
  RAISE EXCEPTION 'access-label selector rows require explicit policy migration before rollback' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $selector_images$
DECLARE item record; pair jsonb; fn regprocedure; old_body text; new_body text; definition text;
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('_authority_full_contract_storage_v3()','7c77cf767ad393b3f16aaae4bcda5df7594aaed73b41a17877735bdb4e92e72b','bd7b954c72a8c66d3548bcf587bf803f9384cd0c590599f8cc3b9032e7f0ae7d',$patch$[["2381b78fd5700ac591d16576a0002e6fd29705bdb388d3508b4257fd989f35bb", "2c4e608b52e90f966e2d32990f276826245f761a280e9fe2f38057c1fa2eacca"]]$patch$::jsonb),
 ('_authority_crud_storage_v3()','2381b78fd5700ac591d16576a0002e6fd29705bdb388d3508b4257fd989f35bb','2c4e608b52e90f966e2d32990f276826245f761a280e9fe2f38057c1fa2eacca',$patch$[[" -- Protected selector columns and constraints are part of the exact storage closure.\n FOR expected IN SELECT * FROM (VALUES\n ('access_label_selector_shape_v1(text,text[],jsonb,jsonb)','dcf3bc20fd365a918a73815fd6f491d5825c2ff7e22e8be1e5d3dbae485c6e0c'),\n ('access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb)','273e28fec954a67a65a764efa9ace98b03b081434889427afd1c7a8cf971e1db'),\n ('access_labels_valid_v1(jsonb)','5bdcbf012ab0dee0838575bc22c3109d97483e1caf2f5543d810f46be03f9c60')\n ) x(signature,digest) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)\n   AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='i' AND p.prokind='f'\n   AND p.prorettype='boolean'::regtype AND NOT p.proretset AND NOT p.proisstrict\n   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']\n   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest\n   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a\n    WHERE a.grantee<>owner_oid AND NOT (a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))) THEN RETURN false;END IF;\n END LOOP;\n FOR expected IN SELECT * FROM (VALUES ('match_access_labels'),('container_match_access_labels')) x(column_name) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum\n   WHERE a.attrelid='kaname.role_rule_selectors'::regclass AND a.attname=expected.column_name\n    AND NOT a.attisdropped AND a.atttypid='jsonb'::regtype AND a.attnotnull AND a.attgenerated=''\n    AND pg_get_expr(d.adbin,d.adrelid)='''{}''::jsonb') THEN RETURN false;END IF;\n END LOOP;\n FOR expected IN SELECT * FROM (VALUES\n ('role_rule_selectors_access_labels_valid','kaname.access_labels_valid_v1(match_access_labels)'),\n ('role_rule_selectors_container_access_labels_valid','kaname.access_labels_valid_v1(container_match_access_labels)'),\n ('role_rule_selectors_arm_shape','kaname.access_label_selector_shape_v1(arm, resource_names, match_labels, match_access_labels)'),\n ('role_rule_selectors_container_shape','kaname.access_label_selector_container_shape_v1(container_type, container_object_type, container_arm, container_resource_names, container_match_labels, container_match_access_labels)')\n ) x(constraint_name,expression) LOOP\n  IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid='kaname.role_rule_selectors'::regclass\n   AND c.conname=expected.constraint_name AND c.contype='c' AND c.convalidated\n   AND NOT c.connoinherit AND pg_get_expr(c.conbin,c.conrelid)=expected.expression) THEN RETURN false;END IF;\n END LOOP;\n RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();", " RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();"], ["a89f11ab8338e4937cc32bb1bc6e5e4a771aea853599004e6b10d4f24c40f568", "414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68"], ["4bed730285f3ee92f2976612cc57b7e42830aafb8cb32b938f382d5c83e8588a", "89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6"], ["949ffb2668d8c51c852a6470006410b3e9e899aa3da0ce94e686c33a551ae3d1", "e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc"], ["518f677f8bfd19b991616777cef08c197ec6d3a7a8b39e7db567145fee89d286", "4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5"]]$patch$::jsonb),
 ('_authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a89f11ab8338e4937cc32bb1bc6e5e4a771aea853599004e6b10d4f24c40f568','414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68',$patch$[["     IF (arm_name='access_labels') IS DISTINCT FROM (attempted->'match_access_labels'<>'{}'::jsonb)\n      OR (arm_name='access_labels' AND (attempted->'match_labels'<>'{}'::jsonb OR attempted->'resource_names'<>'[]'::jsonb))\n      OR (coalesce(attempted->>'container_arm','')='access_labels') IS DISTINCT FROM (attempted->'container_match_access_labels'<>'{}'::jsonb)\n      OR (attempted->>'container_arm'='access_labels' AND (attempted->'container_match_labels'<>'{}'::jsonb OR attempted->'container_resource_names'<>'[]'::jsonb)) THEN\n      RAISE EXCEPTION 'protected selector shape differs' USING ERRCODE='42501';END IF;\n     stored:=attempted||jsonb_build_object('container_object_type',live_types->(attempted->>'container_type'));", "     stored:=attempted||jsonb_build_object('container_object_type',live_types->(attempted->>'container_type'));"], ["'container_match_labels',coalesce(nullif(container->'MatchLabels','null'::jsonb),'{}'::jsonb),\n       'container_match_access_labels',coalesce(container->'MatchAccessLabels','{}'::jsonb));", "'container_match_labels',coalesce(nullif(container->'MatchLabels','null'::jsonb),'{}'::jsonb));"], ["'container_arm',CASE container->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' WHEN '3' THEN 'access_labels' ELSE 'anchor' END,", "'container_arm',CASE container->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' ELSE 'anchor' END,"], ["OR jsonb_typeof(container->'ResourceNames') NOT IN ('array','null') OR jsonb_typeof(container->'MatchLabels') NOT IN ('object','null')\n      OR container->>'Arm' NOT IN ('0','1','2','3')\n      OR (container ? 'MatchAccessLabels' AND (jsonb_typeof(container->'MatchAccessLabels') IS DISTINCT FROM 'object'\n       OR NOT kaname.access_labels_valid_v1(container->'MatchAccessLabels'))) THEN", "OR jsonb_typeof(container->'ResourceNames') NOT IN ('array','null') OR jsonb_typeof(container->'MatchLabels') NOT IN ('object','null') THEN"], ["'container_match_labels','{}'::jsonb,'container_match_access_labels','{}'::jsonb,'verbs_by_type'", "'container_match_labels','{}'::jsonb,'verbs_by_type'"], ["'match_labels',coalesce(nullif(item->'MatchLabels','null'::jsonb),'{}'::jsonb),\n      'match_access_labels',coalesce(item->'MatchAccessLabels','{}'::jsonb),", "'match_labels',coalesce(nullif(item->'MatchLabels','null'::jsonb),'{}'::jsonb),"], ["IF item->>'Arm' NOT IN ('0','1','2','3') THEN RAISE EXCEPTION 'invalid selector arm' USING ERRCODE='42501';END IF;\n     arm_name:=CASE item->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' WHEN '3' THEN 'access_labels' ELSE 'anchor' END;", "arm_name:=CASE item->>'Arm' WHEN '1' THEN 'names' WHEN '2' THEN 'labels' ELSE 'anchor' END;"], ["OR jsonb_typeof(item->'Container') NOT IN ('object','null')\n     OR (item ? 'MatchAccessLabels' AND (jsonb_typeof(item->'MatchAccessLabels') IS DISTINCT FROM 'object'\n      OR NOT kaname.access_labels_valid_v1(item->'MatchAccessLabels'))) THEN", "OR jsonb_typeof(item->'Container') NOT IN ('object','null') THEN"], ["ARRAY['match_labels','container_match_labels','match_access_labels','container_match_access_labels']", "ARRAY['match_labels','container_match_labels']"], ["'container_type','container_object_type','container_arm','container_resource_names','container_match_labels','match_access_labels','container_match_access_labels','verbs_by_type','created_by_subject']", "'container_type','container_object_type','container_arm','container_resource_names','container_match_labels','verbs_by_type','created_by_subject']"]]$patch$::jsonb),
 ('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','4bed730285f3ee92f2976612cc57b7e42830aafb8cb32b938f382d5c83e8588a','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6',$patch$[["'Container',container,'CreatedBySubject',coalesce((node->>'created_by_subject')::boolean,false),'Grants',grants)\n     ||CASE WHEN arm=3 THEN jsonb_build_object('MatchAccessLabels',node->'match_access_labels') ELSE '{}'::jsonb END;", "'Container',container,'CreatedBySubject',coalesce((node->>'created_by_subject')::boolean,false),'Grants',grants);"], ["'MatchLabels',CASE WHEN owner_arm=2 THEN owner->'match_labels' ELSE 'null'::jsonb END)\n      ||CASE WHEN owner_arm=3 THEN jsonb_build_object('MatchAccessLabels',owner->'match_access_labels') ELSE '{}'::jsonb END;", "'MatchLabels',CASE WHEN owner_arm=2 THEN owner->'match_labels' ELSE 'null'::jsonb END);"], ["IF NOT is_child AND arm NOT IN (2,3) AND", "IF NOT is_child AND arm<>2 AND"], ["arm:=CASE WHEN node ? 'match_access_labels' THEN 3 WHEN node ? 'resource_names' THEN 1 WHEN node ? 'match_labels' THEN 2 ELSE 0 END;", "arm:=CASE WHEN node ? 'resource_names' THEN 1 WHEN node ? 'match_labels' THEN 2 ELSE 0 END;"], ["owner_arm:=CASE WHEN owner ? 'match_access_labels' THEN 3 WHEN owner ? 'resource_names' THEN 1 WHEN owner ? 'match_labels' THEN 2 ELSE 0 END;", "owner_arm:=CASE WHEN owner ? 'resource_names' THEN 1 WHEN owner ? 'match_labels' THEN 2 ELSE 0 END;"], ["    IF node ? 'match_access_labels' THEN\n     IF kaname.access_labels_valid_v1(node->'match_access_labels') IS DISTINCT FROM true\n      OR node->'match_access_labels'='{}'::jsonb\n      OR (SELECT count(*) FROM jsonb_object_keys(node->'match_access_labels'))>16\n      OR node ? 'match_labels' OR node ? 'resource_names' OR node ? 'created_by_subject'\n      OR owner->>'module'='*' OR node->'resources' ? '*' OR node->'verbs' ? '*' THEN\n      RAISE EXCEPTION 'invalid protected label rule' USING ERRCODE='42501';END IF;\n    END IF;\n    IF octet_length(node::text)>1048576 THEN", "    IF octet_length(node::text)>1048576 THEN"], ["node-ARRAY['module','resources','verbs','resource_names','match_labels','match_access_labels','children','created_by_subject']", "node-ARRAY['module','resources','verbs','resource_names','match_labels','children','created_by_subject']"], ["node-ARRAY['resources','verbs','resource_names','match_labels','match_access_labels']", "node-ARRAY['resources','verbs','resource_names','match_labels']"]]$patch$::jsonb),
 ('_authority_resource_encode_proposed_rules_v2(jsonb,boolean)','949ffb2668d8c51c852a6470006410b3e9e899aa3da0ce94e686c33a551ae3d1','e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc',$patch$[["  IF r ? 'MatchAccessLabels' THEN\n   IF kaname.access_labels_valid_v1(r->'MatchAccessLabels') IS DISTINCT FROM true\n    OR r->'MatchAccessLabels'='{}'::jsonb\n    OR (SELECT count(*) FROM jsonb_object_keys(r->'MatchAccessLabels'))>16\n    OR r->'MatchLabels' IS DISTINCT FROM 'null'::jsonb OR jsonb_array_length(names)<>0\n    OR r->'CreatedBySubject' IS DISTINCT FROM 'false'::jsonb\n    OR r->>'Module'='*' OR r->'Resources' ? '*' OR r->'Verbs' ? '*' THEN\n    RAISE EXCEPTION 'invalid proposed protected selector' USING ERRCODE='42501';END IF;\n   encoded:=encoded||jsonb_build_object('match_access_labels',r->'MatchAccessLabels');\n  END IF;\n  IF NOT p_child THEN\n   children:=kaname._authority_resource_encode_proposed_rules_v2(r->'Children',true);", "  IF NOT p_child THEN\n   children:=kaname._authority_resource_encode_proposed_rules_v2(r->'Children',true);"], ["r-ARRAY['Module','Resources','Verbs','ResourceNames','MatchLabels','MatchAccessLabels','Children','CreatedBySubject']<>'{}'::jsonb", "(SELECT count(*) FROM jsonb_object_keys(r))<>7"]]$patch$::jsonb),
 ('_authority_resource_rule_fingerprint_v2(jsonb,boolean)','518f677f8bfd19b991616777cef08c197ec6d3a7a8b39e7db567145fee89d286','4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5',$patch$[[" -- New namespace contributes bytes only when explicitly authored; legacy bytes are frozen.\n IF p_rule ? 'match_access_labels' THEN\n  labels:=p_rule->'match_access_labels';\n  IF kaname.access_labels_valid_v1(labels) IS DISTINCT FROM true OR labels='{}'::jsonb\n   OR (SELECT count(*) FROM jsonb_object_keys(labels))>16\n   OR p_rule ? 'match_labels' OR p_rule ? 'resource_names' OR p_rule ? 'created_by_subject'\n   OR p_rule->>'module'='*' OR p_rule->'resources' ? '*' OR p_rule->'verbs' ? '*' THEN\n   RAISE EXCEPTION 'authored protected label selector invalid' USING ERRCODE='42501';END IF;\n  data:=data||convert_to('access_labels','UTF8')||nul||convert_to('l','UTF8')||nul;\n  FOR entry IN SELECT * FROM jsonb_each_text(labels) ORDER BY key COLLATE \"C\" LOOP\n   data:=data||convert_to(entry.key,'UTF8')||nul||convert_to(entry.value,'UTF8')||nul;\n  END LOOP;\n  data:=data||ending;\n END IF;\n children:=coalesce(nullif(p_rule->'children','null'::jsonb),'[]'::jsonb);", " children:=coalesce(nullif(p_rule->'children','null'::jsonb),'[]'::jsonb);"]]$patch$::jsonb)
 ) AS changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT prosrc INTO STRICT old_body FROM pg_catalog.pg_proc WHERE oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'selector images baseline mismatch: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   IF length(new_body)-length(replace(new_body,pair->>0,'')) IS DISTINCT FROM length(pair->>0) THEN
    RAISE EXCEPTION 'selector images substitution not unique' USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'selector images calculated pin mismatch' USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
   RAISE EXCEPTION 'selector images body not unique' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'selector images closure mismatch' USING ERRCODE='55000';END IF;
END $selector_images$;
-- +goose StatementEnd
ALTER TABLE kaname.role_rule_selectors
 DROP CONSTRAINT role_rule_selectors_arm_shape,
 DROP CONSTRAINT role_rule_selectors_arm_valid,
 DROP CONSTRAINT role_rule_selectors_container_shape,
 DROP CONSTRAINT role_rule_selectors_access_labels_valid,
 DROP CONSTRAINT role_rule_selectors_container_access_labels_valid,
 DROP COLUMN match_access_labels,
 DROP COLUMN container_match_access_labels;
ALTER TABLE kaname.role_rule_selectors
 ADD CONSTRAINT role_rule_selectors_arm_valid CHECK (arm IN ('anchor','names','labels')),
 ADD CONSTRAINT role_rule_selectors_arm_shape CHECK ((arm = 'labels' AND match_labels <> '{}'::jsonb AND cardinality(resource_names) = 0)
 OR (arm = 'names' AND match_labels = '{}'::jsonb AND cardinality(resource_names) >= 1)
 OR (arm = 'anchor' AND match_labels = '{}'::jsonb AND cardinality(resource_names) = 0)),
 ADD CONSTRAINT role_rule_selectors_container_shape CHECK ((container_type IS NULL AND container_object_type IS NULL AND container_arm IS NULL
  AND cardinality(container_resource_names) = 0 AND container_match_labels = '{}'::jsonb)
 OR (container_type IS NOT NULL AND container_object_type IS NOT NULL AND container_arm IS NOT NULL AND (
     (container_arm = 'anchor' AND cardinality(container_resource_names) = 0 AND container_match_labels = '{}'::jsonb)
  OR (container_arm = 'names' AND cardinality(container_resource_names) >= 1 AND container_match_labels = '{}'::jsonb)
  OR (container_arm = 'labels' AND cardinality(container_resource_names) = 0 AND container_match_labels <> '{}'::jsonb))));

DROP FUNCTION kaname.access_label_selector_container_shape_v1(text,text,text,text[],jsonb,jsonb);
DROP FUNCTION kaname.access_label_selector_shape_v1(text,text[],jsonb,jsonb);
