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
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88','25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e',$edits$[
 [
  "has_nonanchor boolean;",
  "has_nonanchor boolean;nested_project boolean;"
 ],
 [
  "SELECT rule AS authored,p_scope AS scope FROM roots",
  "SELECT rule AS authored,p_scope AS scope,false AS account_child FROM roots"
 ],
 [
  "SELECT c.value||jsonb_build_object('module',r.rule->>'module'),1",
  "SELECT c.value||jsonb_build_object('module',r.rule->>'module'),1,(r.rule->>'module'='iam' AND r.rule->'resources'='[\"account\"]'::jsonb)"
 ],
 [
  "SELECT DISTINCT t.value COLLATE \"C\" AS dotted",
  "SELECT t.value COLLATE \"C\" AS dotted,bool_or(s.account_child) AS account_child"
 ],
 [
  "s.authored,s.scope,p_catalog)) t",
  "s.authored,s.scope,p_catalog)) t GROUP BY t.value COLLATE \"C\""
 ],
 [
  " INTO types,has_nonanchor;",
  ",\n  EXISTS(SELECT FROM distinct_types WHERE account_child AND dotted='iam.project')\n INTO types,has_nonanchor,nested_project;"
 ],
 [
  "'has_nonanchor',has_nonanchor)",
  "'has_nonanchor',has_nonanchor,'nested_project',nested_project)"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6','9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e',$edits$[
 [
  "catalog jsonb;coordinate jsonb;",
  "physical_models jsonb;catalog_models jsonb;owner_ancestors jsonb;\n catalog jsonb;coordinate jsonb;"
 ],
 [
  " global_scope:=NOT narrow;accounts:=CASE WHEN narrow THEN ARRAY[binding->>'resource_id'] ELSE NULL END;",
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  -- Все источники проверены в одном RR snapshot. Без наследования их\n  -- xmin/ctid однозначно принадлежат родной таблице. Каталог дополнительно\n  -- связывает оба model type с фактическими строками и закреплённым bundle.\n  used_rows:=used_rows+10+jsonb_array_length(catalog#>'{Live,Resources}');used_reads:=used_reads+2;\n  IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'binding nested graph custody exceeds budget' USING ERRCODE='54000';END IF;\n  IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n   'kaname.resource_parent_edge'::regclass,'kaname.accounts'::regclass,'kaname.projects'::regclass]) src(oid)\n   WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=src.oid AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n    AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules))\n    OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=src.oid OR i.inhrelid=src.oid)\n    OR NOT has_table_privilege(invoker,src.oid,'SELECT')) THEN\n   RAISE EXCEPTION 'binding nested graph physical source custody differs' USING ERRCODE='42501';END IF;\n  SELECT jsonb_object_agg(c.dotted,c.object_type) INTO physical_models FROM ONLY kaname.catalog_resource c\n   WHERE c.live AND c.module='iam' AND c.dotted IN ('iam.account','iam.project');\n  SELECT jsonb_object_agg('iam.'||(v->>'Resource'),v->'ObjectType') INTO catalog_models\n   FROM jsonb_array_elements(catalog#>'{Live,Resources}') v WHERE v->>'Module'='iam' AND v->>'Resource' IN ('account','project');\n  IF physical_models IS NULL OR NOT (physical_models ?& ARRAY['iam.account','iam.project'])\n   OR physical_models IS DISTINCT FROM catalog_models THEN\n   RAISE EXCEPTION 'binding nested project model mapping differs' USING ERRCODE='42501';END IF;\n END IF;\n global_scope:=NOT narrow;accounts:=CASE WHEN narrow THEN ARRAY[binding->>'resource_id'] ELSE NULL END;"
 ],
 [
  "  ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);\n  graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');",
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb THEN\n   used_rows:=used_rows+8;\n   IF used_rows>p_rows THEN RAISE EXCEPTION 'binding nested project proof exceeds budget' USING ERRCODE='54000';END IF;\n   ancestry:=kaname._authority_resource_project_graph_v3(source_index,catalog,graph);\n   IF ancestry->'present'='true'::jsonb THEN\n    IF jsonb_array_length(graph->'current_accounts') IS DISTINCT FROM 1\n     OR ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n     RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors\n     FROM jsonb_array_elements(ancestry->'ancestors') WITH ORDINALITY v(a,pos)\n     WHERE a->>'object_type'='iam.account' AND a->'object_id'=graph#>'{current_accounts,0}';\n    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);\n   END IF;\n   graph:=graph||jsonb_build_object('ancestors','[]'::jsonb,'nested_project',ancestry-'required');\n  ELSE\n   ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);\n   graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');\n  END IF;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96','992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142',$edits$[
 [
  "7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88",
  "25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e"
 ],
 [
  "e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6",
  "9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546','b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183',$edits$[
 [
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96",
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','9928f9f11164425338025544c5c375dc5a01bd1e634d309e63536b091d456f8c','326ab9c3f9d0f2afe126b76bff6ff279283fbc6056dec6c9fde2d87fce151229',$edits$[
 [
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96",
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142"
 ],
 [
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546",
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5','7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858',$edits$[
 [
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546",
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','660b8812c3efa517c1edb20cdaa3694779e0a43a9fb43a0620ef8e41f16da584','a0d2827d9e324f24bef752754a4b6e39c75da8ee4cea01f4e4cfeb3e6260d895',$edits$[
 [
  "57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5",
  "7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged account project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged account project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged account project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged account project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged account project graph storage graph differs' USING ERRCODE='55000';
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
        ('_authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)','25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e','7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88',$edits$[
 [
  "'has_nonanchor',has_nonanchor,'nested_project',nested_project)",
  "'has_nonanchor',has_nonanchor)"
 ],
 [
  ",\n  EXISTS(SELECT FROM distinct_types WHERE account_child AND dotted='iam.project')\n INTO types,has_nonanchor,nested_project;",
  " INTO types,has_nonanchor;"
 ],
 [
  "s.authored,s.scope,p_catalog)) t GROUP BY t.value COLLATE \"C\"",
  "s.authored,s.scope,p_catalog)) t"
 ],
 [
  "SELECT t.value COLLATE \"C\" AS dotted,bool_or(s.account_child) AS account_child",
  "SELECT DISTINCT t.value COLLATE \"C\" AS dotted"
 ],
 [
  "SELECT c.value||jsonb_build_object('module',r.rule->>'module'),1,(r.rule->>'module'='iam' AND r.rule->'resources'='[\"account\"]'::jsonb)",
  "SELECT c.value||jsonb_build_object('module',r.rule->>'module'),1"
 ],
 [
  "SELECT rule AS authored,p_scope AS scope,false AS account_child FROM roots",
  "SELECT rule AS authored,p_scope AS scope FROM roots"
 ],
 [
  "has_nonanchor boolean;nested_project boolean;",
  "has_nonanchor boolean;"
 ]
]$edits$::jsonb),
        ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e','e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6',$edits$[
 [
  "  IF typ='iam.project' AND graph->'present'='true'::jsonb AND role_projection->'nested_project'='true'::jsonb THEN\n   used_rows:=used_rows+8;\n   IF used_rows>p_rows THEN RAISE EXCEPTION 'binding nested project proof exceeds budget' USING ERRCODE='54000';END IF;\n   ancestry:=kaname._authority_resource_project_graph_v3(source_index,catalog,graph);\n   IF ancestry->'present'='true'::jsonb THEN\n    IF jsonb_array_length(graph->'current_accounts') IS DISTINCT FROM 1\n     OR ancestry->'current_accounts' IS DISTINCT FROM graph->'current_accounts' THEN\n     RAISE EXCEPTION 'binding nested project native account differs from mirror' USING ERRCODE='42501';END IF;\n    SELECT coalesce(jsonb_agg(a ORDER BY pos),'[]'::jsonb) INTO owner_ancestors\n     FROM jsonb_array_elements(ancestry->'ancestors') WITH ORDINALITY v(a,pos)\n     WHERE a->>'object_type'='iam.account' AND a->'object_id'=graph#>'{current_accounts,0}';\n    ancestry:=jsonb_set(ancestry,'{ancestors}',owner_ancestors);\n   END IF;\n   graph:=graph||jsonb_build_object('ancestors','[]'::jsonb,'nested_project',ancestry-'required');\n  ELSE\n   ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);\n   graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');\n  END IF;",
  "  ancestry:=kaname._authority_resource_ancestor_graph_v2(source_index,catalog,graph);\n  graph:=graph||jsonb_build_object('ancestors',ancestry->'ancestors');"
 ],
 [
  " IF role_projection->'nested_project'='true'::jsonb THEN\n  -- Все источники проверены в одном RR snapshot. Без наследования их\n  -- xmin/ctid однозначно принадлежат родной таблице. Каталог дополнительно\n  -- связывает оба model type с фактическими строками и закреплённым bundle.\n  used_rows:=used_rows+10+jsonb_array_length(catalog#>'{Live,Resources}');used_reads:=used_reads+2;\n  IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'binding nested graph custody exceeds budget' USING ERRCODE='54000';END IF;\n  IF EXISTS(SELECT FROM unnest(ARRAY['kaname.catalog_resource'::regclass,'kaname.resource_mirror'::regclass,\n   'kaname.resource_parent_edge'::regclass,'kaname.accounts'::regclass,'kaname.projects'::regclass]) src(oid)\n   WHERE NOT EXISTS(SELECT FROM pg_class c WHERE c.oid=src.oid AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n    AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relispartition OR c.relhasrules))\n    OR EXISTS(SELECT FROM pg_inherits i WHERE i.inhparent=src.oid OR i.inhrelid=src.oid)\n    OR NOT has_table_privilege(invoker,src.oid,'SELECT')) THEN\n   RAISE EXCEPTION 'binding nested graph physical source custody differs' USING ERRCODE='42501';END IF;\n  SELECT jsonb_object_agg(c.dotted,c.object_type) INTO physical_models FROM ONLY kaname.catalog_resource c\n   WHERE c.live AND c.module='iam' AND c.dotted IN ('iam.account','iam.project');\n  SELECT jsonb_object_agg('iam.'||(v->>'Resource'),v->'ObjectType') INTO catalog_models\n   FROM jsonb_array_elements(catalog#>'{Live,Resources}') v WHERE v->>'Module'='iam' AND v->>'Resource' IN ('account','project');\n  IF physical_models IS NULL OR NOT (physical_models ?& ARRAY['iam.account','iam.project'])\n   OR physical_models IS DISTINCT FROM catalog_models THEN\n   RAISE EXCEPTION 'binding nested project model mapping differs' USING ERRCODE='42501';END IF;\n END IF;\n global_scope:=NOT narrow;accounts:=CASE WHEN narrow THEN ARRAY[binding->>'resource_id'] ELSE NULL END;",
  " global_scope:=NOT narrow;accounts:=CASE WHEN narrow THEN ARRAY[binding->>'resource_id'] ELSE NULL END;"
 ],
 [
  "physical_models jsonb;catalog_models jsonb;owner_ancestors jsonb;\n catalog jsonb;coordinate jsonb;",
  "catalog jsonb;coordinate jsonb;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142','504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96',$edits$[
 [
  "9a4bb4195c31168691c16a66eb5075239b2cf52c468f95cfe57b70779a4d925e",
  "e61e4cb14a0cbe97eaae4466df38f79e9996e0eff1eb8ed79421835733dc19f6"
 ],
 [
  "25830db86ee785488504ef91ce88c875d406425c679252de89eaeb6be45ed01e",
  "7b70bf0d54064f23d175e73416750e1aafc719127c1fa73cee0d9bc70b541e88"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183','f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546',$edits$[
 [
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142",
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','326ab9c3f9d0f2afe126b76bff6ff279283fbc6056dec6c9fde2d87fce151229','9928f9f11164425338025544c5c375dc5a01bd1e634d309e63536b091d456f8c',$edits$[
 [
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183",
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546"
 ],
 [
  "992fad95cba18f103e66c70ed4eaf2ab97bc767a0d4d8728355a6a601af65142",
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858','57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5',$edits$[
 [
  "b91ec4dea72d89f261863fcba0f292585960cc2101df2ee8b9c72d61ac0fa183",
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','a0d2827d9e324f24bef752754a4b6e39c75da8ee4cea01f4e4cfeb3e6260d895','660b8812c3efa517c1edb20cdaa3694779e0a43a9fb43a0620ef8e41f16da584',$edits$[
 [
  "7e2713d6c7e64c7e52c385a366c8d2463cfd514fc6710fa8f007d8d605589858",
  "57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'staged account project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'staged account project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged account project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'staged account project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'staged account project graph storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
