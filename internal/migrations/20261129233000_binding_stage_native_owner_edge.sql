-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e','849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe',$edits$[
 [
  "nested_project boolean;",
  "nested_project boolean;protected_project boolean;"
 ],
 [
  "false AS account_child FROM roots",
  "false AS account_child,false AS protected_child FROM roots"
 ],
 [
  "r.rule->'resources'='[\"account\"]'::jsonb)",
  "r.rule->'resources'='[\"account\"]'::jsonb),jsonb_typeof(c.value->'match_access_labels')='object'"
 ],
 [
  "bool_or(s.account_child) AS account_child",
  "bool_or(s.account_child) AS account_child,bool_or(s.account_child AND s.protected_child) AS protected_child"
 ],
 [
  " INTO types,has_nonanchor,nested_project;",
  ",\n  EXISTS(SELECT FROM distinct_types WHERE protected_child AND dotted='iam.project')\n INTO types,has_nonanchor,nested_project,protected_project;"
 ],
 [
  "'nested_project',nested_project)",
  "'nested_project',nested_project,'protected_project',protected_project)"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e','d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284',$edits$[
 [
  "owner_ancestors jsonb;",
  "owner_ancestors jsonb;edges jsonb;own_edges integer;own_direct boolean;"
 ],
 [
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb THEN",
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb\n   AND jsonb_array_length(graph->'current_accounts')=1\n   AND (binding->>'resource_type'='cluster' OR (binding->>'resource_type'='account' AND binding->>'resource_id'=graph#>>'{current_accounts,0}'))\n   AND (coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb)='[]'::jsonb OR\n    (binding#>'{target,resources}') @> jsonb_build_array(jsonb_build_object('type','iam.account','id',graph#>'{current_accounts,0}'))) THEN"
 ],
 [
  "    IF jsonb_array_length(graph->'current_accounts') IS DISTINCT FROM 1\n     OR ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n     RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors",
  "    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors"
 ],
 [
  "    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);",
  "    IF owner_ancestors<>'[]'::jsonb THEN\n     IF ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n      RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n     IF role_projection->'protected_project'='true'::jsonb THEN\n      -- Источник сохраняет тип ребёнка, все глубины, повторы и чужие рёбра.\n      -- Право на нативные пары несёт только прямое ребро собственного аккаунта.\n      edges:=kaname._authority_resource_require_capture_v2(source_index,3,physical_models->>'iam.project',identifier)->'states';\n      used_rows:=used_rows+jsonb_array_length(edges);\n      IF used_rows>p_rows THEN RAISE EXCEPTION 'binding native project edges exceed budget' USING ERRCODE='54000';END IF;\n      SELECT count(*),coalesce(bool_and(e#>>'{2,depth}'='1'),false) INTO own_edges,own_direct\n       FROM jsonb_array_elements(edges) e\n       WHERE e#>>'{2,object_type}'=physical_models->>'iam.project' AND e#>>'{2,object_id}'=identifier\n        AND e#>>'{2,parent_type}'=physical_models->>'iam.account' AND e#>'{2,parent_id}'=graph#>'{current_accounts,0}';\n      IF own_edges<>1 OR NOT own_direct OR jsonb_array_length(owner_ancestors)<>1 THEN\n       RAISE EXCEPTION 'binding protected project needs its direct native owner edge' USING ERRCODE='42501';END IF;\n     END IF;\n    END IF;\n    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142','922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6',$edits$[
 [
  "25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e",
  "849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe"
 ],
 [
  "9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e",
  "d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183','fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa',$edits$[
 [
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142",
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','326ab9c3f9d0f2afe126b76bff6ff279283fbc6056dec6c9fde2d87fce151229','592b95d51bd7f3e75fd976a67f938a848420c6c6006b189655f2a455e3d7e55a',$edits$[
 [
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142",
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6"
 ],
 [
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183",
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858','d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e',$edits$[
 [
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183",
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','a0d2827d9e324f24bef752754a4b6e39c75da8ee4cea01f4e4cfeb3e6260d895','cc500d3cb15257e541a264b87f0cd8e82df5eddb2de254f76bce8a5e4aa7c05d',$edits$[
 [
  "7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858",
  "d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project owner edge predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project owner edge replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project owner edge body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project owner edge installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project owner edge storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe','25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e',$edits$[
 [
  "'nested_project',nested_project,'protected_project',protected_project)",
  "'nested_project',nested_project)"
 ],
 [
  ",\n  EXISTS(SELECT FROM distinct_types WHERE protected_child AND dotted='iam.project')\n INTO types,has_nonanchor,nested_project,protected_project;",
  " INTO types,has_nonanchor,nested_project;"
 ],
 [
  "bool_or(s.account_child) AS account_child,bool_or(s.account_child AND s.protected_child) AS protected_child",
  "bool_or(s.account_child) AS account_child"
 ],
 [
  "r.rule->'resources'='[\"account\"]'::jsonb),jsonb_typeof(c.value->'match_access_labels')='object'",
  "r.rule->'resources'='[\"account\"]'::jsonb)"
 ],
 [
  "false AS account_child,false AS protected_child FROM roots",
  "false AS account_child FROM roots"
 ],
 [
  "nested_project boolean;protected_project boolean;",
  "nested_project boolean;"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284','9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e',$edits$[
 [
  "    IF owner_ancestors<>'[]'::jsonb THEN\n     IF ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n      RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n     IF role_projection->'protected_project'='true'::jsonb THEN\n      -- Источник сохраняет тип ребёнка, все глубины, повторы и чужие рёбра.\n      -- Право на нативные пары несёт только прямое ребро собственного аккаунта.\n      edges:=kaname._authority_resource_require_capture_v2(source_index,3,physical_models->>'iam.project',identifier)->'states';\n      used_rows:=used_rows+jsonb_array_length(edges);\n      IF used_rows>p_rows THEN RAISE EXCEPTION 'binding native project edges exceed budget' USING ERRCODE='54000';END IF;\n      SELECT count(*),coalesce(bool_and(e#>>'{2,depth}'='1'),false) INTO own_edges,own_direct\n       FROM jsonb_array_elements(edges) e\n       WHERE e#>>'{2,object_type}'=physical_models->>'iam.project' AND e#>>'{2,object_id}'=identifier\n        AND e#>>'{2,parent_type}'=physical_models->>'iam.account' AND e#>'{2,parent_id}'=graph#>'{current_accounts,0}';\n      IF own_edges<>1 OR NOT own_direct OR jsonb_array_length(owner_ancestors)<>1 THEN\n       RAISE EXCEPTION 'binding protected project needs its direct native owner edge' USING ERRCODE='42501';END IF;\n     END IF;\n    END IF;\n    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);",
  "    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);"
 ],
 [
  "    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors",
  "    IF jsonb_array_length(graph->'current_accounts') IS DISTINCT FROM 1\n     OR ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n     RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors"
 ],
 [
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb\n   AND jsonb_array_length(graph->'current_accounts')=1\n   AND (binding->>'resource_type'='cluster' OR (binding->>'resource_type'='account' AND binding->>'resource_id'=graph#>>'{current_accounts,0}'))\n   AND (coalesce(nullif(binding#>'{target,resources}','null'::jsonb),'[]'::jsonb)='[]'::jsonb OR\n    (binding#>'{target,resources}') @> jsonb_build_array(jsonb_build_object('type','iam.account','id',graph#>'{current_accounts,0}'))) THEN",
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb THEN"
 ],
 [
  "owner_ancestors jsonb;edges jsonb;own_edges integer;own_direct boolean;",
  "owner_ancestors jsonb;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6','992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142',$edits$[
 [
  "d198f5d173014c7c7197f6e1987b9cd96cf2588597e1ce562604c3b42ad6e284",
  "9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e"
 ],
 [
  "849a2b29bd3a74847c0a173befc95374d46959691f519eba0da2d64d59cf2efe",
  "25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa','b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183',$edits$[
 [
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6",
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','592b95d51bd7f3e75fd976a67f938a848420c6c6006b189655f2a455e3d7e55a','326ab9c3f9d0f2afe126b76bff6ff279283fbc6056dec6c9fde2d87fce151229',$edits$[
 [
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa",
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183"
 ],
 [
  "922ae298a69359b8df896d84971ba69afa89bd75f4f5e78c76e17a7b2d3277e6",
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e','7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858',$edits$[
 [
  "fc6c7393f0d22d82d795726acb153e3d78fcd9db461b09bd43e0a1ca8c2a00fa",
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','cc500d3cb15257e541a264b87f0cd8e82df5eddb2de254f76bce8a5e4aa7c05d','a0d2827d9e324f24bef752754a4b6e39c75da8ee4cea01f4e4cfeb3e6260d895',$edits$[
 [
  "d2067328045b913de7a59d7012f3a43115bbb2546880a786fa44c22aa0e9130e",
  "7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged native project owner edge predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged native project owner edge replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project owner edge body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged native project owner edge installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged native project owner edge storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
