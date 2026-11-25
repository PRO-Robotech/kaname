-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Сертификат одной удержанной координаты участника. Единственный вход
-- внешнего компилятора — набор предполагаемых членов; строки и часы
-- восстанавливает закрытая программа владельца.
CREATE FUNCTION kaname._authority_role_move_account_member_certificate_v1(
    p_binding_id text,p_account_id text,p_desired jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $member$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen';
    prepared jsonb:=frozen->'selector_move';
    decision jsonb:=frozen->'selector_move_decision';
    plan jsonb:=decision->'predicate_plan';
    role_id text:=prepared->>'role_id';
    holder jsonb:=decision#>ARRAY['binding_new',p_binding_id];
    position jsonb:=decision#>ARRAY['finite_positions','iam.account:'||p_account_id];
    decision_at timestamptz;
    census jsonb;
    binding_triples jsonb;
    subject_triples jsonb;
    bindings jsonb:=prepared#>'{binding_census,bindings}';
    subjects jsonb:=prepared#>'{binding_census,subjects}';
    binding jsonb;
    account_row jsonb;
    copies jsonb;
    current_account jsonb;
    current_role_image jsonb;
    graph jsonb;
    logical_index jsonb:=plan->'new_role_index';
    catalog_row record;
    verified jsonb;
    used_rows integer;
    used_reads integer:=3;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 4 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_desired::text)>8388608 THEN
        RAISE EXCEPTION 'selector member coordinate budget exceeded' USING ERRCODE='54000';
    END IF;
    IF p_binding_id IS NULL OR octet_length(p_binding_id) NOT BETWEEN 1 AND 16384
        OR p_account_id IS NULL OR octet_length(p_account_id) NOT BETWEEN 1 AND 16384
        OR p_binding_id ~ '[:#*[:space:][:cntrl:]]' OR p_account_id ~ '[:#*[:space:][:cntrl:]]'
        OR jsonb_typeof(p_desired) IS DISTINCT FROM 'array'
        OR program->>'family' IS DISTINCT FROM 'role'
        OR frozen->>'kind' IS DISTINCT FROM 'role.mutation'
        OR coalesce(frozen->>'mode','') NOT IN ('selector_move','access_label_transition')
        OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR jsonb_typeof(frozen#>'{selector_move_pending,selected}') IS DISTINCT FROM 'array'
        OR jsonb_typeof(frozen#>'{selector_move_pending,unselected}') IS DISTINCT FROM 'array'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb
        OR frozen ? 'selector_move_approved'
        OR prepared->'nonce' IS DISTINCT FROM proof->'nonce'
        OR prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR decision->>'role_id' IS DISTINCT FROM role_id
        OR decision->'actor' IS DISTINCT FROM prepared->'actor'
        OR plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR jsonb_typeof(plan->'holders') IS DISTINCT FROM 'array'
        OR jsonb_typeof(bindings) IS DISTINCT FROM 'array'
        OR jsonb_typeof(subjects) IS DISTINCT FROM 'array'
        OR jsonb_typeof(decision->'commands') IS DISTINCT FROM 'array'
        OR jsonb_typeof(logical_index) IS DISTINCT FROM 'object'
        OR jsonb_typeof(holder) IS DISTINCT FROM 'object'
        OR holder->>'class' IS DISTINCT FROM 'ACTIVE'
        OR decision#>>ARRAY['binding_status',p_binding_id] IS DISTINCT FROM 'ACTIVE'
        OR position->>'state' IS DISTINCT FROM 'present'
        OR position#>>'{row,id}' IS DISTINCT FROM p_account_id THEN
        RAISE EXCEPTION 'selector member coordinate outside held ACTIVE decision' USING ERRCODE='42501';
    END IF;
    -- Нативный переход имеет дополнительную квитанцию. Обычный перенос
    -- сверяется с подписанным временем и запечатанной программой.
    decision_at:=CASE WHEN frozen->>'mode'='access_label_transition'
        THEN kaname._authority_role_move_native_clock_v1(proof,frozen)
        ELSE (proof->>'decision_at')::timestamptz END;
    IF (isfinite(decision_at) AND decision_at>(prepared->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR decision_at IS DISTINCT FROM (decision->>'decision_at')::timestamptz THEN
        RAISE EXCEPTION 'selector member coordinate final clock differs' USING ERRCODE='42501';
    END IF;
    used_rows:=4+jsonb_array_length(bindings)+jsonb_array_length(subjects)
        +jsonb_array_length(plan->'holders')+jsonb_array_length(decision->'commands');
    IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member coordinate census budget exceeded' USING ERRCODE='54000';END IF;
    IF NOT EXISTS(SELECT FROM jsonb_array_elements(plan->'holders') h
        WHERE h->>'binding_id'=p_binding_id AND h->'scope_root'=jsonb_build_array('iam.account',p_account_id)) THEN
        RAISE EXCEPTION 'selector member coordinate is outside held account scope' USING ERRCODE='42501';
    END IF;

    -- Отдельный вызов после finalize может видеть собственную запись TX.
    -- Повторно сверяем весь состав, включая добавленных или удалённых subjects.
    census:=kaname._authority_role_move_binding_census_v1(role_id,prepared->'binding_census',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(census->>'rows')::integer;
    used_reads:=used_reads+(census->>'reads')::integer;
    IF census->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN
        RAISE EXCEPTION 'selector member coordinate binding status changed' USING ERRCODE='40001';
    END IF;
    SELECT coalesce(jsonb_agg(x),'[]'::jsonb) INTO binding_triples FROM jsonb_array_elements(bindings) x
        WHERE x#>>'{2,id}'=p_binding_id AND x#>>'{2,role_id}'=role_id;
    SELECT coalesce(jsonb_agg(x ORDER BY (x#>>'{2,ordinal}')::integer),'[]'::jsonb) INTO subject_triples
        FROM jsonb_array_elements(subjects) x WHERE x#>>'{2,binding_id}'=p_binding_id;
    binding:=binding_triples#>'{0,2}';
    IF jsonb_array_length(binding_triples)<>1 OR jsonb_array_length(subject_triples) NOT BETWEEN 1 AND 32
        OR binding->>'status' IS DISTINCT FROM 'ACTIVE' OR binding->>'revoked_at' IS NOT NULL
        OR (binding->>'expires_at')::timestamptz<=decision_at THEN
        RAISE EXCEPTION 'selector member coordinate lacks a current role holder' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_object('generation',jsonb_build_array(a.xmin::text,a.ctid::text),
        'row',jsonb_build_object('id',a.id,'labels',a.labels,'access_labels',a.access_labels))
        INTO current_account FROM ONLY kaname.accounts a WHERE a.id=p_account_id;
    IF current_account IS DISTINCT FROM (position-'state') THEN
        RAISE EXCEPTION 'selector member coordinate account source changed' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO current_role_image
        FROM ONLY kaname.roles r WHERE r.id=role_id;
    IF current_role_image IS DISTINCT FROM prepared#>'{role,physical}' THEN
        RAISE EXCEPTION 'selector member coordinate role source changed' USING ERRCODE='40001';
    END IF;
    account_row:=position->'row';
    SELECT coalesce(jsonb_agg(c),'[]'::jsonb) INTO copies FROM jsonb_array_elements(decision->'commands') c
        WHERE c->>'root_type'='iam.account' AND c->>'root_id'=p_account_id;
    IF jsonb_array_length(copies)>1 THEN RAISE EXCEPTION 'selector member coordinate copy is ambiguous' USING ERRCODE='42501';END IF;
    IF jsonb_array_length(copies)=1 THEN
        IF copies#>'{0,physical,0}' IS DISTINCT FROM position#>'{generation,0}'
            OR copies#>'{0,physical,1}' IS DISTINCT FROM position#>'{generation,1}'
            OR (copies#>'{0,physical,2}' @> account_row) IS DISTINCT FROM true
            OR kaname.access_labels_valid_v1(copies#>'{0,access_labels}') IS DISTINCT FROM true THEN
            RAISE EXCEPTION 'selector member coordinate copy differs from prepared account' USING ERRCODE='42501';
        END IF;
        account_row:=jsonb_set(account_row,'{access_labels}',copies#>'{0,access_labels}',false);
    END IF;
    SELECT b.catalog_json,b.model_id,b.catalog_id,b.projector_version INTO catalog_row
        FROM ONLY kaname.authority_bundle_handoff b WHERE b.singleton;
    IF NOT FOUND OR catalog_row.catalog_id IS DISTINCT FROM proof->>'catalog_id'
        OR catalog_row.model_id IS DISTINCT FROM proof->>'model_id'
        OR catalog_row.projector_version IS DISTINCT FROM proof->>'projector_version'
        OR octet_length(catalog_row.catalog_json) NOT BETWEEN 1 AND 8388608
        OR encode(sha256(catalog_row.catalog_json),'hex') IS DISTINCT FROM catalog_row.catalog_id THEN
        RAISE EXCEPTION 'selector member coordinate catalog changed' USING ERRCODE='40001';
    END IF;
    logical_index:=logical_index||jsonb_build_object(
        jsonb_build_array(8,'binding',p_binding_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',binding_triples),
        jsonb_build_array(9,'binding',p_binding_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',subject_triples));
    graph:=jsonb_build_object('object_type','iam.account','object_id',p_account_id,'present',true,
        'projection',account_row,'current_accounts',jsonb_build_array(p_account_id),'current_project','','ancestors','[]'::jsonb);
    verified:=kaname._authority_resource_coordinate_certificate_v2(logical_index,
        convert_from(catalog_row.catalog_json,'UTF8')::jsonb,p_binding_id,graph,p_desired);
    used_rows:=used_rows+(verified->>'work')::integer;
    IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member coordinate work exceeded' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('binding_id',p_binding_id,'role_id',role_id,'coordinate',jsonb_build_array('iam.account',p_account_id),
        'decision_at',decision_at,'desired',verified->'desired','rows',used_rows,'reads',used_reads);
END;
$member$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer)'::regprocedure;
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
DO $held_account_member$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_crud_storage_v3()','134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685','a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf',$changes$[
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer)','0bbb4910e96beee15e177837f990ab8e0e309026aaa12ff4266ddc4748278d17',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_binding_id','p_account_id','p_desired','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644','ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51',$changes$[
  [
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685",
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','ed179fb390b147a778ea3a29877d4445a2ae6544667e041411f6bad18be8c8b9','9bd4dca7d23a94b5523251cc79c4dadc2163cd32d18d689902c996918b794a0b',$changes$[
  [
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685",
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf"
  ],
  [
    "7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644",
    "ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51"
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
$held_account_member$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $held_account_member$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','9bd4dca7d23a94b5523251cc79c4dadc2163cd32d18d689902c996918b794a0b','ed179fb390b147a778ea3a29877d4445a2ae6544667e041411f6bad18be8c8b9',$changes$[
  [
    "ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51",
    "7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644"
  ],
  [
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf",
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','ec0f4597ada3c6b79e9cc4855a8296b50a7179c882ca754634c248001c213e51','7004e4bb5294f9dcce0101644658eb17cd8588c23364b6b54eb89afcdf43b644',$changes$[
  [
    "a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf",
    "134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','a0a44d52691dfd2a9dc11e2d9470ea6f0f60d07bf6a5b33b5c2572a75f2d65cf','134aedf87e669c4129f7b991f7459c501d5621d251efa81f42b971fe7a150685',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_binding_id','p_account_id','p_desired','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer)','0bbb4910e96beee15e177837f990ab8e0e309026aaa12ff4266ddc4748278d17',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
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
$held_account_member$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_account_member_certificate_v1(text,text,jsonb,integer,integer);
