-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $scope_install$
DECLARE item record;fn regprocedure;original text;body text;definition text;source_literal text;pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5',$changes$[
 [
  "invalid_id boolean;item",
  "invalid_id boolean;scope_id_hit boolean;item"
 ],
 [
  "bool_or((v->>2)='' OR (v->>2) ~ '[:#*[:space:][:cntrl:]]') INTO hits,invalid_id FROM unnest(images) v",
  "bool_or((v->>2)='' OR (v->>2) ~ '[:#*[:space:][:cntrl:]]'),\n                        bool_or((v->>2)=(entry#>>'{scope,1}')) INTO hits,invalid_id,scope_id_hit FROM unnest(images) v"
 ],
 [
  "item:=item||jsonb_build_object('children',CASE WHEN hits='[]'::jsonb THEN 'empty' ELSE 'pending' END);",
  "-- containerSelected берет iam.account только в его аккаунте или в кластере.\n                        -- Сохраняем все candidate_ids для проверки обычных ветвей и REJECTED.\n                        item:=item||jsonb_build_object('children',CASE\n                            WHEN hits='[]'::jsonb THEN 'empty'\n                            WHEN typ='iam.account' AND entry->>'child_type'='iam.project'\n                                AND (entry#>>'{scope,0}'='project' OR (entry#>>'{scope,0}'='account' AND scope_id_hit IS FALSE))\n                                THEN 'empty'\n                            ELSE 'pending' END);"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac','55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc',$changes$[
 [
  "ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0",
  "1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c','92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233',$changes$[
 [
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac",
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc"
 ]
]$changes$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','4c2d792d1541847ebd71c7e1c08b70193ac3babe6967e4beb438a6b5fc7566da','3a73fb6d18fa0d9435e9a2dcdf9fb57baa1fbb5eee213eb2cee28b1adf6f25b7',$changes$[
 [
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac",
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc"
 ],
 [
  "118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c",
  "92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move account container scope predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move account container scope splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move account container scope body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move account container scope function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move account container scope function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move account container scope custody differs after migration' USING ERRCODE='55000';END IF;
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
  ('authority_metadata_service_account_access_label_ready_v1()','3a73fb6d18fa0d9435e9a2dcdf9fb57baa1fbb5eee213eb2cee28b1adf6f25b7','4c2d792d1541847ebd71c7e1c08b70193ac3babe6967e4beb438a6b5fc7566da',$changes$[
 [
  "92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233",
  "118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c"
 ],
 [
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc",
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac"
 ]
]$changes$::jsonb),
  ('_authority_full_contract_storage_v3()','92d0154becb27b062a829705d047554f6e70d057f7e53a20721c7d69070f4233','118dc9d4b0a043157b35dd37052c88b6f15e5df0c6ec02b9ff064fbd97d4e63c',$changes$[
 [
  "55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc",
  "8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac"
 ]
]$changes$::jsonb),
  ('_authority_crud_storage_v3()','55eed41ac17fb4d8a2df9441a5dbe684ff2d222dab7c5da9da8c3d06a45133fc','8c3cc9e8c6f21152ab96d259fdf48d4de6084166f65198efef15428588d8a7ac',$changes$[
 [
  "1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5",
  "ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0"
 ]
]$changes$::jsonb),
  ('_authority_role_move_local_label_candidates_v1(jsonb,jsonb,jsonb,integer,integer)','1c3c9eea115f6370d6776ec0d18fdfd22f612db49e78b5f4af9f8050d1231fc5','ff793372e4386bfdbf9e8b9e8e8431c0a1046972339261787e9fb53fe73fc4b0',$changes$[
 [
  "-- containerSelected берет iam.account только в его аккаунте или в кластере.\n                        -- Сохраняем все candidate_ids для проверки обычных ветвей и REJECTED.\n                        item:=item||jsonb_build_object('children',CASE\n                            WHEN hits='[]'::jsonb THEN 'empty'\n                            WHEN typ='iam.account' AND entry->>'child_type'='iam.project'\n                                AND (entry#>>'{scope,0}'='project' OR (entry#>>'{scope,0}'='account' AND scope_id_hit IS FALSE))\n                                THEN 'empty'\n                            ELSE 'pending' END);",
  "item:=item||jsonb_build_object('children',CASE WHEN hits='[]'::jsonb THEN 'empty' ELSE 'pending' END);"
 ],
 [
  "bool_or((v->>2)='' OR (v->>2) ~ '[:#*[:space:][:cntrl:]]'),\n                        bool_or((v->>2)=(entry#>>'{scope,1}')) INTO hits,invalid_id,scope_id_hit FROM unnest(images) v",
  "bool_or((v->>2)='' OR (v->>2) ~ '[:#*[:space:][:cntrl:]]') INTO hits,invalid_id FROM unnest(images) v"
 ],
 [
  "invalid_id boolean;scope_id_hit boolean;item",
  "invalid_id boolean;item"
 ]
]$changes$::jsonb)
) AS x(signature,prior,installed,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition FROM pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
   OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
   RAISE EXCEPTION 'selector move account container scope predecessor differs: %',item.signature USING ERRCODE='55000';END IF;
  body:=original;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF octet_length(body)-octet_length(replace(body,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'selector move account container scope splice is ambiguous: %',item.signature USING ERRCODE='55000';END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'selector move account container scope body differs: %',item.signature USING ERRCODE='55000';END IF;
  source_literal:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
  IF source_literal IS NULL OR strpos(definition,source_literal||original||source_literal)=0 THEN
   RAISE EXCEPTION 'selector move account container scope function literal missing: %',item.signature USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,source_literal||original||source_literal,quote_literal(body));
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.installed THEN
   RAISE EXCEPTION 'installed selector move account container scope function differs: %',item.signature USING ERRCODE='55000';END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'selector move account container scope custody differs after migration' USING ERRCODE='55000';END IF;
END;
$scope_install$;
-- +goose StatementEnd
