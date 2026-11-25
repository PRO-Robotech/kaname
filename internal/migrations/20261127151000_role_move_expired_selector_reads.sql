-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Физические источники истёкшей привязки для чтения двух сторон селектора.
CREATE FUNCTION kaname._authority_role_move_expired_selector_reads_v1(
    p_prepared jsonb,p_status jsonb,p_held_versions jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $read_scopes$
DECLARE
    census jsonb:=p_prepared->'binding_census';
    role_row jsonb:=p_prepared#>'{role,new_role}';
    role_id text:=p_prepared->>'role_id';
    used_rows integer;
    used_reads integer:=0;
    selector_source jsonb;
    read_input jsonb;
    predicates jsonb;
    positions jsonb;
    binding_labels jsonb;
    local_labels jsonb;
    member_projects jsonb;
    source jsonb;
    receipt record;
    invalid boolean;
    scopes jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    IF jsonb_typeof(census->'bindings') IS DISTINCT FROM 'array'
        OR jsonb_typeof(census->'subjects') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_status) IS DISTINCT FROM 'object'
        OR coalesce(role_id,'')='' OR role_row->>'id' IS DISTINCT FROM role_id THEN
        RAISE EXCEPTION 'expired selector read inputs incomplete' USING ERRCODE='42501';
    END IF;
    IF octet_length(p_prepared::text)>8388608 OR octet_length(p_status::text)>8388608 THEN
        RAISE EXCEPTION 'expired selector read inputs exceed byte budget' USING ERRCODE='54000';
    END IF;
    used_rows:=jsonb_array_length(census->'bindings');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
        RAISE EXCEPTION 'expired selector read census budget exceeded' USING ERRCODE='54000';
    END IF;
    IF NOT EXISTS (SELECT FROM jsonb_array_elements(census->'bindings') b
        WHERE b#>>'{2,role_id}'=role_id AND b#>>'{2,status}' IN ('ACTIVE','PENDING')
            AND b#>>'{2,revoked_at}' IS NULL AND p_status->>(b#>>'{2,id}')='EXPIRED') THEN
        RETURN jsonb_build_object('source',NULL,'rows',used_rows,'reads',used_reads);
    END IF;
    IF role_row->'live' IS DISTINCT FROM 'true'::jsonb
        OR jsonb_typeof(role_row->'rules') IS DISTINCT FROM 'array' OR role_row->'rules'='[]'::jsonb THEN
        RAISE EXCEPTION 'expired selector role source incomplete' USING ERRCODE='42501';
    END IF;
    used_rows:=used_rows+2*jsonb_array_length(census->'bindings')+jsonb_array_length(census->'subjects');
    IF used_rows>p_rows THEN RAISE EXCEPTION 'expired selector recipients exceed budget' USING ERRCODE='54000';END IF;

    -- Только прямые физические ACTIVE/PENDING, истёкшие по часам владельца.
    -- Поля области и получателей проверяются так же, как у действующей привязки.
    WITH bindings AS MATERIALIZED (
        SELECT s->2 AS b,s#>>'{2,id}' AS id,p_status->>(s#>>'{2,id}') AS class
        FROM jsonb_array_elements(census->'bindings') s
    ), eligible AS MATERIALIZED (
        SELECT id,b FROM bindings WHERE b->>'role_id'=role_id AND class='EXPIRED'
            AND b->>'status' IN ('ACTIVE','PENDING') AND b->>'revoked_at' IS NULL
    ), recipients AS (
        SELECT e.id,s->2 AS subject,e.b,
            s#>>'{2,subject_type}' AS typ,s#>>'{2,subject_id}' AS identifier,
            s#>>'{2,ordinal}' AS ordinal_text
        FROM jsonb_array_elements(census->'subjects') s JOIN eligible e ON e.id=s#>>'{2,binding_id}'
    ), per_binding AS (
        SELECT id,count(*) AS n,count(DISTINCT (typ,identifier)) AS distinct_n,
            bool_or(typ=b->>'subject_type' AND identifier=b->>'subject_id') AS has_primary,
            bool_and((subject->'resource_type'=b->'resource_type' AND subject->'resource_id'=b->'resource_id'
                AND typ IN ('user','group','service_account','system_class') AND octet_length(identifier) BETWEEN 1 AND 64
                AND (identifier !~ '[:#*[:space:][:cntrl:]]'
                    OR (identifier='*' AND typ='user' AND b->'is_system'='true'::jsonb))
                AND (typ<>'system_class' OR identifier IN ('anonymous','authenticated'))
                AND jsonb_typeof(subject->'ordinal')='number' AND ordinal_text ~ '^(0|[1-9][0-9]{0,9})$') IS TRUE) AS valid,
            jsonb_agg(jsonb_build_array(typ,identifier)
                ORDER BY length(ordinal_text),ordinal_text COLLATE "C",typ COLLATE "C",identifier COLLATE "C") AS subjects
        FROM recipients GROUP BY id
    )
    SELECT EXISTS(SELECT FROM bindings WHERE coalesce(class,'') NOT IN ('ACTIVE','PENDING','EXPIRED','REVOKED'))
        OR EXISTS(SELECT k FROM jsonb_object_keys(p_status) k EXCEPT SELECT id FROM bindings)
        OR coalesce(bool_or((p.n BETWEEN 1 AND 32 AND p.n=p.distinct_n AND p.has_primary AND p.valid
            AND coalesce(e.id,'')<>'' AND e.id !~ '[:#*[:space:][:cntrl:]]'
            AND e.b->>'granted_relation'='' AND jsonb_typeof(e.b->'target')='object'
            AND e.b->>'resource_id' !~ '[:#*[:space:][:cntrl:]]'
            AND CASE e.b->>'resource_type'
                WHEN 'account' THEN e.b->'scope'='2'::jsonb AND starts_with(e.b->>'resource_id','acc')
                WHEN 'project' THEN e.b->'scope'='3'::jsonb AND starts_with(e.b->>'resource_id','prj')
                WHEN 'cluster' THEN e.b->'scope'='1'::jsonb AND e.b->>'resource_id'='cluster_root'
                ELSE false END) IS NOT TRUE),false),
        coalesce(jsonb_object_agg(e.id,jsonb_build_object(
            'scope',jsonb_build_array(e.b->>'resource_type',e.b->>'resource_id'),
            'target',e.b->'target','subjects',p.subjects)),'{}'::jsonb)
        INTO invalid,scopes FROM eligible e LEFT JOIN per_binding p USING(id);
    IF invalid THEN RAISE EXCEPTION 'expired selector read recipients or scope differ' USING ERRCODE='42501';END IF;
    IF octet_length(scopes::text)>8388608 THEN
        RAISE EXCEPTION 'expired selector read receipt exceeds byte budget' USING ERRCODE='54000';
    END IF;
    IF p_held_versions IS NULL THEN
        selector_source:=kaname._authority_role_move_selector_versions_v1(p_prepared->>'role_id',p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(selector_source->>'rows')::integer;used_reads:=used_reads+(selector_source->>'reads')::integer;
    ELSE
        selector_source:=jsonb_build_object('versions',p_held_versions);
    END IF;
    read_input:=p_prepared||jsonb_build_object('selector_versions',selector_source->'versions');
    predicates:=kaname._authority_role_move_predicate_plan_v1(read_input,scopes,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(predicates->>'rows')::integer;used_reads:=used_reads+(predicates->>'reads')::integer;
    positions:=kaname._authority_role_move_finite_positions_v1(read_input,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(positions->>'rows')::integer;used_reads:=used_reads+(positions->>'reads')::integer;
    binding_labels:=kaname._authority_role_move_binding_label_candidates_v1(read_input,predicates->'plan',false,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(binding_labels->>'rows')::integer;used_reads:=used_reads+(binding_labels->>'reads')::integer;
    local_labels:=kaname._authority_role_move_local_label_candidates_v1(read_input,predicates->'plan',NULL,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(local_labels->>'rows')::integer;used_reads:=used_reads+(local_labels->>'reads')::integer;
    member_projects:=kaname._authority_role_move_member_projects_v1(predicates->'plan',
        (p_prepared->'binding_census')||jsonb_build_object('moved_role_id',p_prepared->'role_id'),NULL,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(member_projects->>'rows')::integer;used_reads:=used_reads+(member_projects->>'reads')::integer;
    -- Некоторые общие сборщики сохраняют явный pending для последующей
    -- обработки. Такой ответ не подтверждает источник в квитанции чтения.
    FOR receipt IN
        SELECT 'finite' kind,k.key,k.value->>'state' state FROM jsonb_each(positions->'positions') k
        UNION ALL SELECT 'local',k.key,k.value->>'state' FROM jsonb_each(local_labels->'sources') k
        UNION ALL SELECT 'binding','',binding_labels#>>'{source,state}'
        UNION ALL SELECT 'children','',local_labels#>>'{raw_project_children,state}'
    LOOP
        used_rows:=used_rows+1;
        IF used_rows>p_rows OR receipt.state='pending_budget' THEN
            RAISE EXCEPTION 'expired selector read sources exceed budget' USING ERRCODE='54000';
        END IF;
        IF receipt.kind='finite' AND receipt.state='pending_absence'
            AND starts_with(receipt.key,'iam.project:') AND (member_projects#>'{source,projects}')->substr(receipt.key,13)='null'::jsonb THEN
            CONTINUE;
        END IF;
        IF receipt.state IS NULL OR (receipt.kind='finite' AND receipt.state NOT IN ('present','absent'))
            OR (receipt.kind<>'finite' AND receipt.state NOT IN ('held','unused')) THEN
            RAISE EXCEPTION 'expired selector read source unconfirmed' USING ERRCODE='42501';
        END IF;
    END LOOP;
    source:=jsonb_build_object('selector_versions',selector_source->'versions','scopes',scopes,'plan',predicates->'plan',
        'finite_positions',positions->'positions','binding_label_source',binding_labels->'source',
        'local_label_sources',local_labels->'sources','raw_project_children',local_labels->'raw_project_children',
        'member_projects',member_projects->'source');
    IF octet_length(source::text)>8388608 THEN RAISE EXCEPTION 'expired selector read images exceed byte budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('source',source,'rows',used_rows,'reads',used_reads);
END;
$read_scopes$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer)'::regprocedure;
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
DO $expired_reads$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660','b359d9e130e985fb0cd1d5d86193cad06f44aaf07f6c99e5d711c2ba3feff7ca',$changes$[
  [
    "    eligible jsonb;",
    "    eligible jsonb;\n    expired_reads jsonb;"
  ],
  [
    "    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');",
    "    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');\n    -- Дополнительная перепись принадлежит только чтению OLD/NEW. Она не\n    -- участвует в выборе держателей, подготовке копий и финальном решении.\n    expired_reads:=kaname._authority_role_move_expired_selector_reads_v1(frozen,carriers->'binding_status',\n        selector_source->'versions',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(expired_reads->>'rows')::integer;used_reads:=used_reads+(expired_reads->>'reads')::integer;\n    IF expired_reads->'source'<>'null'::jsonb THEN\n        frozen:=frozen||jsonb_build_object('expired_selector_reads',expired_reads->'source');\n    END IF;"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5','2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc',$changes$[
  [
    " ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660',false,'v',true,'private'),\n",
    " ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b359d9e130e985fb0cd1d5d86193cad06f44aaf07f6c99e5d711c2ba3feff7ca',false,'v',true,'private'),\n ('_authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer)','66f2ca104a1623bde08315442e541a87567fd23c10ef8754b7df2ceaafbb59c0',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n",
    "  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_prepared','p_status','p_held_versions','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360','d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2',$changes$[
  [
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5",
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','2ec5547197150217f89b63fe48573c59f983f3333ec5c781b881e10de7501feb','51dc4c43cd456bbfe7cdf7584dd8feae69b759b5ed13602c6a1be8fa65e36e3e',$changes$[
  [
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5",
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc"
  ],
  [
    "0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360",
    "d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'expired selector read predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'expired selector read replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'expired selector read body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'expired selector read installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'expired selector read storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$expired_reads$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $expired_reads$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','51dc4c43cd456bbfe7cdf7584dd8feae69b759b5ed13602c6a1be8fa65e36e3e','2ec5547197150217f89b63fe48573c59f983f3333ec5c781b881e10de7501feb',$changes$[
  [
    "d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2",
    "0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360"
  ],
  [
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc",
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2','0d79f56c1f2223464e356a58a727a08c937f9f4dc1e28ab46cdf9ae8ddf5c360',$changes$[
  [
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc",
    "97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc','97000d07f0b6396c3c95cd9ac00819642f49fa9c92b503befc57c3638edebcb5',$changes$[
  [
    "  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n  ('_authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer)','jsonb',5,ARRAY['p_prepared','p_status','p_held_versions','p_rows','p_reads']),\n",
    "  ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_input','p_actor','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b359d9e130e985fb0cd1d5d86193cad06f44aaf07f6c99e5d711c2ba3feff7ca',false,'v',true,'private'),\n ('_authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer)','66f2ca104a1623bde08315442e541a87567fd23c10ef8754b7df2ceaafbb59c0',false,'v',true,'private'),\n",
    " ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660',false,'v',true,'private'),\n"
  ]
]$changes$::jsonb),
        ('_authority_role_move_prepare_checks_v1(jsonb,jsonb,integer,integer)','b359d9e130e985fb0cd1d5d86193cad06f44aaf07f6c99e5d711c2ba3feff7ca','139d02e18dec6d344339a5b496e0e761e13213f57260a7db5334c8a3b3ed9660',$changes$[
  [
    "    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');\n    -- Дополнительная перепись принадлежит только чтению OLD/NEW. Она не\n    -- участвует в выборе держателей, подготовке копий и финальном решении.\n    expired_reads:=kaname._authority_role_move_expired_selector_reads_v1(frozen,carriers->'binding_status',\n        selector_source->'versions',p_rows-used_rows,p_reads-used_reads);\n    used_rows:=used_rows+(expired_reads->>'rows')::integer;used_reads:=used_reads+(expired_reads->>'reads')::integer;\n    IF expired_reads->'source'<>'null'::jsonb THEN\n        frozen:=frozen||jsonb_build_object('expired_selector_reads',expired_reads->'source');\n    END IF;",
    "    frozen:=frozen||jsonb_build_object('member_projects',member_projects->'source');"
  ],
  [
    "    eligible jsonb;\n    expired_reads jsonb;",
    "    eligible jsonb;"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'expired selector read predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'expired selector read replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'expired selector read body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'expired selector read installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'expired selector read storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$expired_reads$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_expired_selector_reads_v1(jsonb,jsonb,jsonb,integer,integer);
