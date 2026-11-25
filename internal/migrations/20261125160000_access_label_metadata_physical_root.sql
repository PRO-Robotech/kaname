-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Общее физическое свидетельство для метаданных. Метки внешнего объекта
-- сможет менять только отдельная защищённая команда со своими доказательствами.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_root_state_v1(p_dotted text,p_id text,p_hold boolean)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $root$
DECLARE table_name text; key_predicate text; root_state jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF coalesce(p_dotted,'')='' OR octet_length(p_dotted)>16384
  OR coalesce(p_id,'')='' OR octet_length(p_id)>16384 OR p_id='*'
  OR p_id ~ '[[:cntrl:]]' OR p_hold IS NULL THEN
  RAISE EXCEPTION 'metadata physical root coordinate invalid' USING ERRCODE='42501';END IF;
 table_name:=CASE p_dotted WHEN 'iam.account' THEN 'accounts' WHEN 'iam.project' THEN 'projects'
  WHEN 'iam.serviceAccount' THEN 'service_accounts' END;
 IF table_name IS NULL THEN
  IF split_part(p_dotted,'.',1)='iam' OR NOT EXISTS(
   SELECT 1 FROM kaname.catalog_resource c WHERE c.dotted=p_dotted AND c.live AND c.module<>'iam'
  ) THEN
   RAISE EXCEPTION 'metadata physical root type invalid' USING ERRCODE='42501';END IF;
  table_name:='resource_mirror';
  key_predicate:='o.object_type=$1 AND o.object_id=$2';
 ELSE
  key_predicate:='o.id=$2';
 END IF;
 -- Сохраняем точную строку и её физическую версию: повторные записи с теми
 -- же метками и повторная регистрация не должны совпасть с прежним снимком.
 EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))
  FROM ONLY kaname.%I o WHERE %s%s',table_name,key_predicate,
  CASE WHEN p_hold THEN ' FOR UPDATE OF o' ELSE '' END)
 INTO root_state USING p_dotted,p_id;
 RETURN root_state;
END;
$root$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_metadata_root_state_v1(text,text,boolean) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_metadata_root_state_v1(text,text,boolean)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_metadata_root_state_v1(text,text,boolean) FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860','6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f',
  $changes$[
 [
  " EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))\n  FROM ONLY kaname.%I o WHERE o.id=$1',table_name) INTO root_state USING p_id;",
  " root_state:=kaname._authority_metadata_root_state_v1(\n  CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END,p_id,false);"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1','790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c',
  $changes$[
 [
  " EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))\n  FROM ONLY kaname.%I o WHERE o.id=$1 FOR UPDATE OF o',table_name)\n INTO physical_state USING resource_id;",
  " physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','86d73a4052674f53f8bc1616750878aefa0d14b521d5f1c9c73e5acfd52f1d35','7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34',
  $changes$[
 [
  "4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860",
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f"
 ],
 [
  "8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1",
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c"
 ],
 [
  " manifest jsonb:=$manifest$\n[\n",
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_root_state_v1(text,text,boolean)\",\n    \"digest\": \"3206b57ba4fe7afc579c98df293d07cbb792b0741ac7146aa1c69f1f4c2de350\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\",\n      \"p_hold\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','e0cfa186e2bf899327f36b5e0944613a9863345c8103e8c77cbf4062742e5d82','ca5d2ea3eef68b77de0444dd370a803ad490e33008cc99347937745450ecba67',
  $changes$[
 [
  "4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860",
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f"
 ],
 [
  "8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1",
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c"
 ],
 [
  "86d73a4052674f53f8bc1616750878aefa0d14b521d5f1c9c73e5acfd52f1d35",
  "7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata root predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata root patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata root expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata root installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','ca5d2ea3eef68b77de0444dd370a803ad490e33008cc99347937745450ecba67','e0cfa186e2bf899327f36b5e0944613a9863345c8103e8c77cbf4062742e5d82',
  $changes$[
 [
  "7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34",
  "86d73a4052674f53f8bc1616750878aefa0d14b521d5f1c9c73e5acfd52f1d35"
 ],
 [
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c",
  "8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1"
 ],
 [
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f",
  "4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','7266b951857e921d1b47b5a93c75caa6be5fc05d5b87acd5e522eb3a07faae34','86d73a4052674f53f8bc1616750878aefa0d14b521d5f1c9c73e5acfd52f1d35',
  $changes$[
 [
  " manifest jsonb:=$manifest$\n[\n  {\n    \"signature\": \"_authority_metadata_root_state_v1(text,text,boolean)\",\n    \"digest\": \"3206b57ba4fe7afc579c98df293d07cbb792b0741ac7146aa1c69f1f4c2de350\",\n    \"definer\": false,\n    \"volatility\": \"v\",\n    \"exported\": false,\n    \"result_type\": \"jsonb\",\n    \"result_set\": false,\n    \"language\": \"plpgsql\",\n    \"argnames\": [\n      \"p_dotted\",\n      \"p_id\",\n      \"p_hold\"\n    ],\n    \"argmodes\": null,\n    \"allargtypes\": null\n  },\n",
  " manifest jsonb:=$manifest$\n[\n"
 ],
 [
  "790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c",
  "8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1"
 ],
 [
  "6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f",
  "4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_hold_and_replay_v1(jsonb,boolean,integer,integer,integer)','790f98119e777889a0b92abf51fe480875da4e504e9853a763627048aba0da6c','8322223a45741ef4a169d62b03e8e827baa6bf276af10bc60e330c365ff040e1',
  $changes$[
 [
  " physical_state:=kaname._authority_metadata_root_state_v1(root_coordinate->>0,resource_id,true);",
  " EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))\n  FROM ONLY kaname.%I o WHERE o.id=$1 FOR UPDATE OF o',table_name)\n INTO physical_state USING resource_id;"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)','6f6abd4b8133c2bde6d037a7d30b591cefd32c5e1079d05979cc72144aeabe0f','4ee4541d07e9e609445d477a23163a82b297be0bb8588698d4aec8930ae77860',
  $changes$[
 [
  " root_state:=kaname._authority_metadata_root_state_v1(\n  CASE p_kind WHEN 'service_account' THEN 'iam.serviceAccount' ELSE 'iam.'||p_kind END,p_id,false);",
  " EXECUTE format('SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))\n  FROM ONLY kaname.%I o WHERE o.id=$1',table_name) INTO root_state USING p_id;"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata root predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata root patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata root expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata root installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_metadata_root_state_v1(text,text,boolean);
