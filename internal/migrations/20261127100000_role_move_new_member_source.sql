-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Фиксируем в программе владельца логическую проекцию NEW, включая
-- физический формат селекторов для проверки полного состава членов.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $selector_member_role$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',$changes$[
  [
    "    scope_root jsonb;plan jsonb;catalog_rows integer;",
    "    scope_root jsonb;plan jsonb;catalog_rows integer;\n    materialized jsonb;selector_states jsonb;new_role_index jsonb:='{}'::jsonb;"
  ],
  [
    "'catalog_id',proof->'catalog_id','holders','[]'::jsonb,'items','[]'::jsonb)",
    "'catalog_id',proof->'catalog_id','holders','[]'::jsonb,'items','[]'::jsonb,'new_role_index','{}'::jsonb)"
  ],
  [
    "        compiled:=kaname._authority_resource_withdrawal_role_projection_v2(role_row,'[]',layout,catalog);\n        used_rows:=used_rows+(compiled->>'work')::integer+jsonb_array_length(layout);\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector layout work budget exceeded' USING ERRCODE='54000';END IF;",
    "        compiled:=kaname._authority_resource_withdrawal_role_projection_v2(role_row,'[]',layout,catalog);\n        used_rows:=used_rows+(compiled->>'work')::integer+jsonb_array_length(layout);\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector layout work budget exceeded' USING ERRCODE='54000';END IF;\n        IF side='new' THEN\n            -- Этим представлением проверяют семантику NEW. Пустые позиции версий\n            -- не означают физические строки и не участвуют в повторном чтении OLD.\n            materialized:=kaname._authority_resource_withdrawal_role_images_v2(role_row,role_row->'rules',\n                compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n                '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n                catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n            used_rows:=used_rows+(materialized->>'work')::integer;\n            IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n            IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n                RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n            END IF;\n            SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n                ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n                FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n            new_role_index:=jsonb_build_object(\n                jsonb_build_array(12,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,new_role))),\n                jsonb_build_array(13,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n            IF octet_length(new_role_index::text)>8388608 THEN\n                RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n            END IF;\n        END IF;"
  ],
  [
    "    plan:=jsonb_build_object('catalog_id',bundle.catalog_id,'holders',to_jsonb(summaries),'items',to_jsonb(items));",
    "    plan:=jsonb_build_object('catalog_id',bundle.catalog_id,'holders',to_jsonb(summaries),'items',to_jsonb(items),\n        'new_role_index',new_role_index);"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa','134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685',$changes$[
  [
    "cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9",
    "76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629','7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644',$changes$[
  [
    "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa",
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','cc3e2aff7e31c47fa51bc7a63e29d98c5b40759b4b1d1f6e86dcec6b85c58472','ed179fb390b147a778ea3a29877d4445a2ae6544667e041411f6bad18be8c8b9',$changes$[
  [
    "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa",
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685"
  ],
  [
    "d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629",
    "7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector member role predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector member role replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector member role body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector member role installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector member role storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$selector_member_role$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $selector_member_role$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','ed179fb390b147a778ea3a29877d4445a2ae6544667e041411f6bad18be8c8b9','cc3e2aff7e31c47fa51bc7a63e29d98c5b40759b4b1d1f6e86dcec6b85c58472',$changes$[
  [
    "7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644",
    "d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629"
  ],
  [
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685",
    "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644','d03bfd87fb04ec3da910fb119b13d2061dd248316e799a317cae3bdf53d39629',$changes$[
  [
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685",
    "49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685','49713a25044e6fc0aa577f2433e0a30cb34a252cd3015756ccafc0c09c00cbfa',$changes$[
  [
    "76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8",
    "cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9"
  ]
]$changes$::jsonb),
        ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8','cb231a595f6dd57a28f293c74b87d2dae78fdfcca5ab9deb538130f1cfc7cab9',$changes$[
  [
    "    plan:=jsonb_build_object('catalog_id',bundle.catalog_id,'holders',to_jsonb(summaries),'items',to_jsonb(items),\n        'new_role_index',new_role_index);",
    "    plan:=jsonb_build_object('catalog_id',bundle.catalog_id,'holders',to_jsonb(summaries),'items',to_jsonb(items));"
  ],
  [
    "        compiled:=kaname._authority_resource_withdrawal_role_projection_v2(role_row,'[]',layout,catalog);\n        used_rows:=used_rows+(compiled->>'work')::integer+jsonb_array_length(layout);\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector layout work budget exceeded' USING ERRCODE='54000';END IF;\n        IF side='new' THEN\n            -- Этим представлением проверяют семантику NEW. Пустые позиции версий\n            -- не означают физические строки и не участвуют в повторном чтении OLD.\n            materialized:=kaname._authority_resource_withdrawal_role_images_v2(role_row,role_row->'rules',\n                compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n                '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n                catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n            used_rows:=used_rows+(materialized->>'work')::integer;\n            IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n            IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n                RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n            END IF;\n            SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n                ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n                FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n            new_role_index:=jsonb_build_object(\n                jsonb_build_array(12,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,new_role))),\n                jsonb_build_array(13,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n            IF octet_length(new_role_index::text)>8388608 THEN\n                RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n            END IF;\n        END IF;",
    "        compiled:=kaname._authority_resource_withdrawal_role_projection_v2(role_row,'[]',layout,catalog);\n        used_rows:=used_rows+(compiled->>'work')::integer+jsonb_array_length(layout);\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector layout work budget exceeded' USING ERRCODE='54000';END IF;"
  ],
  [
    "'catalog_id',proof->'catalog_id','holders','[]'::jsonb,'items','[]'::jsonb,'new_role_index','{}'::jsonb)",
    "'catalog_id',proof->'catalog_id','holders','[]'::jsonb,'items','[]'::jsonb)"
  ],
  [
    "    scope_root jsonb;plan jsonb;catalog_rows integer;\n    materialized jsonb;selector_states jsonb;new_role_index jsonb:='{}'::jsonb;",
    "    scope_root jsonb;plan jsonb;catalog_rows integer;"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector member role predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector member role replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector member role body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector member role installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector member role storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$selector_member_role$;
-- +goose StatementEnd
