-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Перечитываем тот же полный набор кандидатов проекта под оградой решения.
-- Собственные строки используются для прямого выбора. Вложенный выбор
-- подтверждается зеркалом, ребром, каталогом и собственной строкой аккаунта.
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_resource_match_wait_v2(jsonb,integer,integer)','58889d87678c744de3fb80c8a95234c22ffdbb8e0c195aa0cf159c7673aa4e73','17033236bfca53bd4decf47fabc43d2f2e2b4a56b7033bfd4f129a5b9dcdbe19',$changes$[
 [
  " projection jsonb; requested jsonb; used integer:=0; reads integer:=0;",
  " projection jsonb; requested jsonb; used integer:=0; reads integer:=0;\n nested_project text:='';"
 ],
 [
  " IF requested IS DISTINCT FROM projection THEN RAISE EXCEPTION 'direct IAM projection changed' USING ERRCODE='P1034'; END IF;",
  " IF requested IS DISTINCT FROM projection THEN RAISE EXCEPTION 'direct IAM projection changed' USING ERRCODE='P1034'; END IF;\n  IF typ='iam.project' THEN\n   IF NOT has_table_privilege(invoker,'kaname.resource_mirror','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.resource_parent_edge','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.catalog_resource','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.accounts','SELECT') THEN\n    RAISE EXCEPTION 'nested project match SELECT required' USING ERRCODE='42501';\n   END IF;\n   nested_project:=$project$ OR (rrs.container_type='iam.account' AND EXISTS (\n    SELECT 1\n    FROM kaname.resource_mirror m\n    JOIN kaname.catalog_resource child ON child.dotted=m.object_type AND child.live\n    JOIN kaname.resource_parent_edge edge ON edge.object_type=child.object_type AND edge.object_id=m.object_id\n    JOIN kaname.catalog_resource owner ON owner.object_type=edge.parent_type AND owner.dotted='iam.account' AND owner.live\n    JOIN ONLY kaname.accounts a ON a.id=edge.parent_id\n    WHERE m.object_type=$1 AND m.object_id=$2\n     AND (b.resource_type NOT IN ('account','project') OR (b.resource_type='account' AND b.resource_id=a.id))\n     AND (rrs.container_arm='anchor'\n      OR (rrs.container_arm='names' AND a.id=ANY(rrs.container_resource_names))\n      OR (rrs.container_arm='labels' AND a.labels @> rrs.container_match_labels)\n      OR (rrs.container_arm='access_labels' AND a.access_labels @> rrs.container_match_access_labels))\n     AND (rrs.arm='anchor'\n      OR (rrs.arm='names' AND $2=ANY(rrs.resource_names))\n      OR (rrs.arm='labels' AND m.labels @> rrs.match_labels)\n      OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels))\n   ))$project$;\n  END IF;"
 ],
 [
  "OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels)) LIMIT $3 FOR SHARE OF b,rrs,o$query$,table_name);",
  "OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels)%s) LIMIT $3 FOR SHARE OF b,rrs,o$query$,table_name,nested_project);"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9','4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f',$changes$[
 [
  "58889d87678c744de3fb80c8a95234c22ffdbb8e0c195aa0cf159c7673aa4e73",
  "17033236bfca53bd4decf47fabc43d2f2e2b4a56b7033bfd4f129a5b9dcdbe19"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76','5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de',$changes$[
 [
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9",
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','6eb2f8f8356dcbd1fbd9646806062a4f827f332bcf1a394380cb930d875cae18','87ed8dc13f1b393377d6850c1666fb4e6b2cccdf0be1bc60d5bea074bc33a6b5',$changes$[
 [
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9",
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f"
 ],
 [
  "e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76",
  "5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'object project candidate census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'object project candidate census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'object project candidate census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'object project candidate census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed object project candidate census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'object project candidate census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','87ed8dc13f1b393377d6850c1666fb4e6b2cccdf0be1bc60d5bea074bc33a6b5','6eb2f8f8356dcbd1fbd9646806062a4f827f332bcf1a394380cb930d875cae18',$changes$[
 [
  "5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de",
  "e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76"
 ],
 [
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f",
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','5a0fbdfa186b8ce67133769aab2e0844af997fab15dab6c4d6eb285de25642de','e2563ecb2fc5a6cc6df92070cae7f37c55233c34dde064a185e5d8d021b58c76',$changes$[
 [
  "4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f",
  "4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','4ac1f34dbb751749be55fe8f86bf03472e74addb1a06f5d428eb87741bc6ed3f','4b7124a3872cf53dec09e2b231bf34074e0c577cc96f1e8e5402a04e0613b1f9',$changes$[
 [
  "17033236bfca53bd4decf47fabc43d2f2e2b4a56b7033bfd4f129a5b9dcdbe19",
  "58889d87678c744de3fb80c8a95234c22ffdbb8e0c195aa0cf159c7673aa4e73"
 ]
]$changes$::jsonb),
  ('_authority_resource_match_wait_v2(jsonb,integer,integer)','17033236bfca53bd4decf47fabc43d2f2e2b4a56b7033bfd4f129a5b9dcdbe19','58889d87678c744de3fb80c8a95234c22ffdbb8e0c195aa0cf159c7673aa4e73',$changes$[
 [
  "OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels)%s) LIMIT $3 FOR SHARE OF b,rrs,o$query$,table_name,nested_project);",
  "OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels)) LIMIT $3 FOR SHARE OF b,rrs,o$query$,table_name);"
 ],
 [
  " IF requested IS DISTINCT FROM projection THEN RAISE EXCEPTION 'direct IAM projection changed' USING ERRCODE='P1034'; END IF;\n  IF typ='iam.project' THEN\n   IF NOT has_table_privilege(invoker,'kaname.resource_mirror','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.resource_parent_edge','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.catalog_resource','SELECT')\n    OR NOT has_table_privilege(invoker,'kaname.accounts','SELECT') THEN\n    RAISE EXCEPTION 'nested project match SELECT required' USING ERRCODE='42501';\n   END IF;\n   nested_project:=$project$ OR (rrs.container_type='iam.account' AND EXISTS (\n    SELECT 1\n    FROM kaname.resource_mirror m\n    JOIN kaname.catalog_resource child ON child.dotted=m.object_type AND child.live\n    JOIN kaname.resource_parent_edge edge ON edge.object_type=child.object_type AND edge.object_id=m.object_id\n    JOIN kaname.catalog_resource owner ON owner.object_type=edge.parent_type AND owner.dotted='iam.account' AND owner.live\n    JOIN ONLY kaname.accounts a ON a.id=edge.parent_id\n    WHERE m.object_type=$1 AND m.object_id=$2\n     AND (b.resource_type NOT IN ('account','project') OR (b.resource_type='account' AND b.resource_id=a.id))\n     AND (rrs.container_arm='anchor'\n      OR (rrs.container_arm='names' AND a.id=ANY(rrs.container_resource_names))\n      OR (rrs.container_arm='labels' AND a.labels @> rrs.container_match_labels)\n      OR (rrs.container_arm='access_labels' AND a.access_labels @> rrs.container_match_access_labels))\n     AND (rrs.arm='anchor'\n      OR (rrs.arm='names' AND $2=ANY(rrs.resource_names))\n      OR (rrs.arm='labels' AND m.labels @> rrs.match_labels)\n      OR (rrs.arm='access_labels' AND o.access_labels @> rrs.match_access_labels))\n   ))$project$;\n  END IF;",
  " IF requested IS DISTINCT FROM projection THEN RAISE EXCEPTION 'direct IAM projection changed' USING ERRCODE='P1034'; END IF;"
 ],
 [
  " projection jsonb; requested jsonb; used integer:=0; reads integer:=0;\n nested_project text:='';",
  " projection jsonb; requested jsonb; used integer:=0; reads integer:=0;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'object project candidate census predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'object project candidate census splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'object project candidate census body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'object project candidate census function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed object project candidate census function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'object project candidate census custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd
