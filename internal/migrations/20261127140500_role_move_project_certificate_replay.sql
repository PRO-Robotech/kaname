-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $member_project_graph$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6','93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c',$changes$[
  [
    "    tuple_count bigint;",
    "    tuple_count bigint;\n    role_item record;actual_model text;"
  ],
  [
    "    IF receipt='null'::jsonb THEN",
    "    IF receipt='null'::jsonb THEN\n        -- Проверяем также пустые обратные источники: собственная запись TX\n        -- после финализации не конфликтует с ранее удержанным SHARE.\n        observed:=kaname._authority_role_move_member_projects_v1(plan,\n            (prepared->'binding_census')||jsonb_build_object('moved_role_id',role_id),universe,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(observed->>'rows')::integer;used_reads:=used_reads+(observed->>'reads')::integer;"
  ],
  [
    "        IF EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i\n            JOIN LATERAL jsonb_array_elements(",
    "        IF nested->'present'='true'::jsonb THEN\n            FOR role_item IN SELECT DISTINCT i->>'read_type' AS dotted,i->>'model' AS bundle_model,i->>'child_model' AS child_model\n                FROM jsonb_array_elements(plan->'items') i WHERE i->>'binding_id'=p_binding_id\n                    AND i->>'child_type'='iam.project' AND i->>'read_type'<>'iam.account' LOOP\n                IF used_reads>=p_reads OR used_rows>=p_rows THEN RAISE EXCEPTION 'project parent model budget exceeded' USING ERRCODE='54000';END IF;\n                used_reads:=used_reads+1;used_rows:=used_rows+1;\n                SELECT c.object_type INTO actual_model FROM ONLY kaname.catalog_resource c WHERE c.dotted=role_item.dotted AND c.live;\n                IF actual_model IS DISTINCT FROM role_item.bundle_model OR role_item.child_model IS DISTINCT FROM\n                    (SELECT c#>>'{2,object_type}' FROM jsonb_array_elements(receipt->'catalog') c WHERE c#>>'{2,dotted}'='iam.project') THEN\n                    RAISE EXCEPTION 'project certificate live parent or child model changed' USING ERRCODE='40001';\n                END IF;\n            END LOOP;\n        END IF;\n        IF EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i\n            JOIN LATERAL jsonb_array_elements("
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d','89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6',$changes$[
  [
    "41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6",
    "93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda','34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87',$changes$[
  [
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d",
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','542edc10f7ddaf91dd6898047d135d3cd959f991dbaca0d23c3b0410331ad95b','f8acf975bc2d6d91f7289893f776e4a3eb39bbd934cc8da97a36e00f65bd8de2',$changes$[
  [
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d",
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6"
  ],
  [
    "dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda",
    "34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move project graph storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$member_project_graph$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $member_project_graph$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','f8acf975bc2d6d91f7289893f776e4a3eb39bbd934cc8da97a36e00f65bd8de2','542edc10f7ddaf91dd6898047d135d3cd959f991dbaca0d23c3b0410331ad95b',$changes$[
  [
    "34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87",
    "dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda"
  ],
  [
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6",
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87','dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda',$changes$[
  [
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6",
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6','9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d',$changes$[
  [
    "93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c",
    "41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6"
  ]
]$changes$::jsonb),
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c','41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6',$changes$[
  [
    "        IF nested->'present'='true'::jsonb THEN\n            FOR role_item IN SELECT DISTINCT i->>'read_type' AS dotted,i->>'model' AS bundle_model,i->>'child_model' AS child_model\n                FROM jsonb_array_elements(plan->'items') i WHERE i->>'binding_id'=p_binding_id\n                    AND i->>'child_type'='iam.project' AND i->>'read_type'<>'iam.account' LOOP\n                IF used_reads>=p_reads OR used_rows>=p_rows THEN RAISE EXCEPTION 'project parent model budget exceeded' USING ERRCODE='54000';END IF;\n                used_reads:=used_reads+1;used_rows:=used_rows+1;\n                SELECT c.object_type INTO actual_model FROM ONLY kaname.catalog_resource c WHERE c.dotted=role_item.dotted AND c.live;\n                IF actual_model IS DISTINCT FROM role_item.bundle_model OR role_item.child_model IS DISTINCT FROM\n                    (SELECT c#>>'{2,object_type}' FROM jsonb_array_elements(receipt->'catalog') c WHERE c#>>'{2,dotted}'='iam.project') THEN\n                    RAISE EXCEPTION 'project certificate live parent or child model changed' USING ERRCODE='40001';\n                END IF;\n            END LOOP;\n        END IF;\n        IF EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i\n            JOIN LATERAL jsonb_array_elements(",
    "        IF EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i\n            JOIN LATERAL jsonb_array_elements("
  ],
  [
    "    IF receipt='null'::jsonb THEN\n        -- Проверяем также пустые обратные источники: собственная запись TX\n        -- после финализации не конфликтует с ранее удержанным SHARE.\n        observed:=kaname._authority_role_move_member_projects_v1(plan,\n            (prepared->'binding_census')||jsonb_build_object('moved_role_id',role_id),universe,p_rows-used_rows,p_reads-used_reads);\n        used_rows:=used_rows+(observed->>'rows')::integer;used_reads:=used_reads+(observed->>'reads')::integer;",
    "    IF receipt='null'::jsonb THEN"
  ],
  [
    "    tuple_count bigint;\n    role_item record;actual_model text;",
    "    tuple_count bigint;"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move project graph predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move project graph replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move project graph installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move project graph storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$member_project_graph$;
-- +goose StatementEnd
