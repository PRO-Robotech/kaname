-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Чтение OLD-источника до публикации DML. Владелец связывает первый
-- зарезервированный слот роли с финальным временем и актором. Подтверждение
-- точки записывается в ту же временную таблицу, что и при обычной правке.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_native_clock_v1(p_proof jsonb,p_frozen jsonb)
RETURNS timestamptz LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $clock$
DECLARE
    receipt jsonb:=p_frozen#>'{selector_move_pending,native}';
BEGIN
    IF p_proof->>'writer_contract' IS DISTINCT FROM '2' OR p_proof->>'kind' IS DISTINCT FROM 'role'
        OR p_proof->>'purpose' IS DISTINCT FROM 'decision' OR p_proof->>'mode' IS DISTINCT FROM 'global'
        OR jsonb_typeof(receipt) IS DISTINCT FROM 'object' OR p_frozen ? 'selector_move_approved'
        OR p_frozen->>'mode' IS DISTINCT FROM 'access_label_transition' OR p_frozen->>'kind' IS DISTINCT FROM 'role.mutation'
        OR receipt->'nonce' IS DISTINCT FROM p_proof->'nonce' OR receipt->'invoker_oid' IS DISTINCT FROM p_proof->'invoker_oid'
        OR receipt->'role_id' IS DISTINCT FROM p_frozen#>'{access_label_transition,role_id}'
        OR receipt->'actor' IS DISTINCT FROM p_frozen#>'{access_label_authority,actor}'
        OR (receipt->>'decision_at')::timestamptz IS DISTINCT FROM (p_proof->>'decision_at')::timestamptz THEN
        RAISE EXCEPTION 'pending native proof outside reserved selector move' USING ERRCODE='42501';
    END IF;
    RETURN (p_proof->>'decision_at')::timestamptz;
END;
$clock$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_native_clock_v1(jsonb,jsonb)'::regprocedure;
BEGIN
    FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
            CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $native_proof$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213','ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422',$changes$[
 [
  "    row_cost integer;",
  "    row_cost integer;\n    root jsonb; native_receipt jsonb;"
 ],
 [
  "    -- До одобрения результат хранится",
  "    IF frozen->>'mode'='access_label_transition' THEN\n        root:=p_program#>'{maximum,0}';\n        IF root->>'table' IS DISTINCT FROM 'resource_journal' OR root->'ordinal' IS DISTINCT FROM '1'::jsonb\n            OR root->>'stamp' IS DISTINCT FROM 'transaction' OR (root->>'reserved_id')::bigint IS NULL\n            OR root#>>'{row,event_type}' IS DISTINCT FROM 'UPDATED' OR root#>>'{row,resource_kind}' IS DISTINCT FROM 'iam_role'\n            OR root#>'{row,resource_id}' IS DISTINCT FROM decision->'role_id'\n            OR root->'origin' IS DISTINCT FROM jsonb_build_object('table','roles','operation','UPDATE','when','AFTER',\n                'old',frozen#>'{access_label_transition,old_row}','new',frozen#>'{access_label_transition,new_row}')\n            OR chosen->0 IS DISTINCT FROM jsonb_set(root,'{row,created_at}',to_jsonb(transaction_timestamp()),true)\n            OR jsonb_typeof(decision->'actor') IS DISTINCT FROM 'object'\n            OR decision->'actor' IS DISTINCT FROM frozen#>'{access_label_authority,actor}' THEN\n            RAISE EXCEPTION 'pending native proof differs from exact reserved role slot' USING ERRCODE='42501';\n        END IF;\n        native_receipt:=jsonb_build_object('nonce',p_program->'nonce','invoker_oid',p_program->'invoker_oid',\n            'actor',decision->'actor','role_id',decision->'role_id','decision_at',decision->'decision_at',\n            'reserved_id',root->'reserved_id','origin_hash',encode(sha256(convert_to((root->'origin')::text,'UTF8')),'hex'),\n            'row_hash',encode(sha256(convert_to((root->'row')::text,'UTF8')),'hex'));\n    END IF;\n    -- До одобрения результат хранится"
 ],
 [
  "'selector_move_pending',jsonb_build_object('selected',chosen,'unselected',discarded))",
  "'selector_move_pending',jsonb_strip_nulls(jsonb_build_object('native',native_receipt))\n            ||jsonb_build_object('selected',chosen,'unselected',discarded))"
 ]
]$changes$::jsonb),
  ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf','7f6fb57e2f50772e6c69f6f1a30a6f002791aec17dabfa254d7685b8c7b65351',$changes$[
 [
  "'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time",
  "'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END=at_time"
 ],
 [
  "'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time",
  "'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END=at_time"
 ]
]$changes$::jsonb),
  ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba','b7bb0159944522c4ea1a6fad1088f70e8738c6d726384f2e5c31c9623365ce89',$changes$[
 [
  "jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'",
  "coalesce(jsonb_typeof(program->'selected'),'') NOT IN ('array','null')"
 ],
 [
  "s.decision_at,s.staged_decision_at",
  "CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END,s.staged_decision_at"
 ]
]$changes$::jsonb),
  ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8','c834ec007abb90b0241d48be1e24dfad0678222f8d7bdeef366ffbb3cbcc953a',$changes$[
 [
  "jsonb_typeof(header->'selected') IS DISTINCT FROM 'array'",
  "coalesce(jsonb_typeof(header->'selected'),'') NOT IN ('array','null')"
 ],
 [
  "s.decision_at,s.staged_decision_at",
  "CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END,s.staged_decision_at"
 ],
 [
  "EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n   WHERE e.ordinal=1 AND e.nonce=s.nonce AND e.selected AND e.registered\n    AND e.table_name='resource_journal' AND e.origin->>'table'='roles')",
  "CASE WHEN s.selected IS NULL THEN NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n    WHERE e.ordinal=1 AND e.nonce=s.nonce AND NOT e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n     AND e.table_name='resource_journal'\n     AND e.reserved_id=(s.frozen#>>'{selector_move_pending,native,reserved_id}')::bigint\n     AND e.origin_digest=decode(s.frozen#>>'{selector_move_pending,native,origin_hash}','hex')\n     AND e.row_digest=decode(s.frozen#>>'{selector_move_pending,native,row_hash}','hex'))\n   ELSE EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n   WHERE e.ordinal=1 AND e.nonce=s.nonce AND e.selected AND e.registered\n    AND e.table_name='resource_journal' AND e.origin->>'table'='roles') END"
 ]
]$changes$::jsonb),
  ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723','fd8351c31b1974897d4eca6e178dc22b2071d759462bec72c78ff35e6ac4e71e',$changes$[
 [
  "'{access_label_transition,role_id}',s.decision_at,",
  "'{access_label_transition,role_id}',\n        CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN (s.frozen#>>'{selector_move_pending,native,decision_at}')::timestamptz ELSE s.decision_at END,"
 ],
 [
  "e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n         AND e.table_name='resource_journal' AND e.origin->>'table'='roles'",
  "CASE WHEN s.selected IS NULL THEN NOT e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n     AND e.table_name='resource_journal'\n     AND e.reserved_id=(s.frozen#>>'{selector_move_pending,native,reserved_id}')::bigint\n     AND e.origin_digest=decode(s.frozen#>>'{selector_move_pending,native,origin_hash}','hex')\n     AND e.row_digest=decode(s.frozen#>>'{selector_move_pending,native,row_hash}','hex')\n        ELSE e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n         AND e.table_name='resource_journal' AND e.origin->>'table'='roles' END"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57','d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f',$changes$[
 [
  "09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213",
  "ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422"
 ],
 [
  "6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf",
  "7f6fb57e2f50772e6c69f6f1a30a6f002791aec17dabfa254d7685b8c7b65351"
 ],
 [
  "a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba",
  "b7bb0159944522c4ea1a6fad1088f70e8738c6d726384f2e5c31c9623365ce89"
 ],
 [
  "8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8",
  "c834ec007abb90b0241d48be1e24dfad0678222f8d7bdeef366ffbb3cbcc953a"
 ],
 [
  "77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723",
  "fd8351c31b1974897d4eca6e178dc22b2071d759462bec72c78ff35e6ac4e71e"
 ],
 [
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),",
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),"
 ],
 [
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),",
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344','64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa',$changes$[
 [
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57",
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','9310a1ee07187723e1cdfd931a693cecf22c1f160752d18ddd5dabb448932b7a','03027a7eb8686e4ef8a2c8245db2e2ed21e522808197aa30bc317f5ce55a19ef',$changes$[
 [
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57",
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f"
 ],
 [
  "384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344",
  "64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move native proof predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move native proof splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move native proof body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move native proof function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move native proof function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move native proof custody differs after migration' USING ERRCODE='55000';END IF;
END;
$native_proof$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $native_proof$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','03027a7eb8686e4ef8a2c8245db2e2ed21e522808197aa30bc317f5ce55a19ef','9310a1ee07187723e1cdfd931a693cecf22c1f160752d18ddd5dabb448932b7a',$changes$[
 [
  "64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa",
  "384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344"
 ],
 [
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f",
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','64ed933ee4c9bdd585a3a128b3dec8b47cf24b41f2bb1db23f46836af2ea29fa','384d68ad9a04b734e8691bd3b3e872643353bd1c3aa1d8b103fe6131ac95a344',$changes$[
 [
  "d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f",
  "e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','d7d6c9b9157a9e145a7c1fce9b474c77602971d99645ea57fca33e2168f7c83f','e37e7f2576727f76969fc74bb979d31de0f0078f04035eb62deb481013aaeb57',$changes$[
 [
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),\n  ('_authority_role_move_native_clock_v1(jsonb,jsonb)','timestamp with time zone',2,ARRAY['p_proof','p_frozen']),",
  "  ('_authority_role_move_root_journal_v1(jsonb,integer)','jsonb',2,ARRAY['p_command','p_ordinal']),"
 ],
 [
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),\n ('_authority_role_move_native_clock_v1(jsonb,jsonb)','e109f864a07dd2cb8814989eb915da415700bf84bf80576e6b6c281d4a5a3a47',false,'s',true,'private'),",
  " ('_authority_role_move_root_journal_v1(jsonb,integer)','19eade41e3bd6c1673dc5a739143c335d67957af1c9a8b66ba2e847708506746',false,'s',true,'private'),"
 ],
 [
  "fd8351c31b1974897d4eca6e178dc22b2071d759462bec72c78ff35e6ac4e71e",
  "77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723"
 ],
 [
  "c834ec007abb90b0241d48be1e24dfad0678222f8d7bdeef366ffbb3cbcc953a",
  "8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8"
 ],
 [
  "b7bb0159944522c4ea1a6fad1088f70e8738c6d726384f2e5c31c9623365ce89",
  "a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba"
 ],
 [
  "7f6fb57e2f50772e6c69f6f1a30a6f002791aec17dabfa254d7685b8c7b65351",
  "6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf"
 ],
 [
  "ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422",
  "09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213"
 ]
]$changes$::jsonb),
  ('authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','fd8351c31b1974897d4eca6e178dc22b2071d759462bec72c78ff35e6ac4e71e','77c9967452f5540e08d91d63df53e137afd450c0fb8bfefc9699ea561c207723',$changes$[
 [
  "CASE WHEN s.selected IS NULL THEN NOT e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n     AND e.table_name='resource_journal'\n     AND e.reserved_id=(s.frozen#>>'{selector_move_pending,native,reserved_id}')::bigint\n     AND e.origin_digest=decode(s.frozen#>>'{selector_move_pending,native,origin_hash}','hex')\n     AND e.row_digest=decode(s.frozen#>>'{selector_move_pending,native,row_hash}','hex')\n        ELSE e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n         AND e.table_name='resource_journal' AND e.origin->>'table'='roles' END",
  "e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n         AND e.table_name='resource_journal' AND e.origin->>'table'='roles'"
 ],
 [
  "'{access_label_transition,role_id}',\n        CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN (s.frozen#>>'{selector_move_pending,native,decision_at}')::timestamptz ELSE s.decision_at END,",
  "'{access_label_transition,role_id}',s.decision_at,"
 ]
]$changes$::jsonb),
  ('authority_access_label_role_question_require_v1(text,text,text,text,uuid,integer,integer)','c834ec007abb90b0241d48be1e24dfad0678222f8d7bdeef366ffbb3cbcc953a','8790c6de466bd69d3f9430dd7061cb68fc3f856b89b7f0ddd4756c49d1086eb8',$changes$[
 [
  "CASE WHEN s.selected IS NULL THEN NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n    WHERE e.ordinal=1 AND e.nonce=s.nonce AND NOT e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed\n     AND e.table_name='resource_journal'\n     AND e.reserved_id=(s.frozen#>>'{selector_move_pending,native,reserved_id}')::bigint\n     AND e.origin_digest=decode(s.frozen#>>'{selector_move_pending,native,origin_hash}','hex')\n     AND e.row_digest=decode(s.frozen#>>'{selector_move_pending,native,row_hash}','hex'))\n   ELSE EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n   WHERE e.ordinal=1 AND e.nonce=s.nonce AND e.selected AND e.registered\n    AND e.table_name='resource_journal' AND e.origin->>'table'='roles') END",
  "EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e\n   WHERE e.ordinal=1 AND e.nonce=s.nonce AND e.selected AND e.registered\n    AND e.table_name='resource_journal' AND e.origin->>'table'='roles')"
 ],
 [
  "CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END,s.staged_decision_at",
  "s.decision_at,s.staged_decision_at"
 ],
 [
  "coalesce(jsonb_typeof(header->'selected'),'') NOT IN ('array','null')",
  "jsonb_typeof(header->'selected') IS DISTINCT FROM 'array'"
 ]
]$changes$::jsonb),
  ('authority_access_label_prepared_definition_v1(text,text,uuid,integer,integer)','b7bb0159944522c4ea1a6fad1088f70e8738c6d726384f2e5c31c9623365ce89','a2bcc1f0193fe47bfcd7bcb0c4727cffbc892ee049826b28cbf78e418afe71ba',$changes$[
 [
  "CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END,s.staged_decision_at",
  "s.decision_at,s.staged_decision_at"
 ],
 [
  "coalesce(jsonb_typeof(program->'selected'),'') NOT IN ('array','null')",
  "jsonb_typeof(program->'selected') IS DISTINCT FROM 'array'"
 ]
]$changes$::jsonb),
  ('_authority_role_move_sequence_finalize_v1(jsonb,integer,integer)','7f6fb57e2f50772e6c69f6f1a30a6f002791aec17dabfa254d7685b8c7b65351','6f0700709a8b82c29973349ae74232b9d1ae57bfb5bf2002fa26432f05efbedf',$changes$[
 [
  "'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END=at_time",
  "'access_label_required_index',required_index)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time"
 ],
 [
  "'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND CASE WHEN s.selected IS NULL AND s.decision_at IS NULL THEN\n     kaname._authority_role_move_native_clock_v1(proof,s.frozen) ELSE s.decision_at END=at_time",
  "'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time"
 ]
]$changes$::jsonb),
  ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422','09b3bbd42c75e5a01bec9fd1b0829b9604e32a3de35ec777ce411e3bb50ff213',$changes$[
 [
  "'selector_move_pending',jsonb_strip_nulls(jsonb_build_object('native',native_receipt))\n            ||jsonb_build_object('selected',chosen,'unselected',discarded))",
  "'selector_move_pending',jsonb_build_object('selected',chosen,'unselected',discarded))"
 ],
 [
  "    IF frozen->>'mode'='access_label_transition' THEN\n        root:=p_program#>'{maximum,0}';\n        IF root->>'table' IS DISTINCT FROM 'resource_journal' OR root->'ordinal' IS DISTINCT FROM '1'::jsonb\n            OR root->>'stamp' IS DISTINCT FROM 'transaction' OR (root->>'reserved_id')::bigint IS NULL\n            OR root#>>'{row,event_type}' IS DISTINCT FROM 'UPDATED' OR root#>>'{row,resource_kind}' IS DISTINCT FROM 'iam_role'\n            OR root#>'{row,resource_id}' IS DISTINCT FROM decision->'role_id'\n            OR root->'origin' IS DISTINCT FROM jsonb_build_object('table','roles','operation','UPDATE','when','AFTER',\n                'old',frozen#>'{access_label_transition,old_row}','new',frozen#>'{access_label_transition,new_row}')\n            OR chosen->0 IS DISTINCT FROM jsonb_set(root,'{row,created_at}',to_jsonb(transaction_timestamp()),true)\n            OR jsonb_typeof(decision->'actor') IS DISTINCT FROM 'object'\n            OR decision->'actor' IS DISTINCT FROM frozen#>'{access_label_authority,actor}' THEN\n            RAISE EXCEPTION 'pending native proof differs from exact reserved role slot' USING ERRCODE='42501';\n        END IF;\n        native_receipt:=jsonb_build_object('nonce',p_program->'nonce','invoker_oid',p_program->'invoker_oid',\n            'actor',decision->'actor','role_id',decision->'role_id','decision_at',decision->'decision_at',\n            'reserved_id',root->'reserved_id','origin_hash',encode(sha256(convert_to((root->'origin')::text,'UTF8')),'hex'),\n            'row_hash',encode(sha256(convert_to((root->'row')::text,'UTF8')),'hex'));\n    END IF;\n    -- До одобрения результат хранится",
  "    -- До одобрения результат хранится"
 ],
 [
  "    row_cost integer;\n    root jsonb; native_receipt jsonb;",
  "    row_cost integer;"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move native proof predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move native proof splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move native proof body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move native proof function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move native proof function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move native proof custody differs after migration' USING ERRCODE='55000';END IF;
END;
$native_proof$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_native_clock_v1(jsonb,jsonb);
