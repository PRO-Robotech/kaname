-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Вложенный селектор перечисляет всех потомков выбранного аккаунта. Даже у
-- потомка без совпадений вклад OLD/NEW проверяется на его собственной координате.
CREATE FUNCTION kaname._authority_role_move_nested_positions_v1(p_binding_id text,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $positions$
DECLARE
    program jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=program->'frozen'; prepared jsonb:=frame->'selector_move'; decision jsonb:=frame->'selector_move_decision';
    projects jsonb:=prepared->'member_projects'; items jsonb:=decision#>'{predicate_plan,items}';
    slots jsonb; aid text; pid text; account_ref jsonb; parent_key text; edges jsonb;
    pairs jsonb:=prepared#>'{role,physical,2,rules,0,children,0,match_labels}';
    positions jsonb; side text; candidate_bytes bigint; source_missing boolean; used_rows integer:=108;used_reads integer:=14;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads+1 AND 4096 THEN
        RAISE EXCEPTION 'nested binding coordinate budget exhausted' USING ERRCODE='54000';END IF;
    IF frame->>'selector_move_transport' IS DISTINCT FROM 'active_nested_project_no_copy_v1'
        OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR program->>'family' IS DISTINCT FROM 'role'
        OR program->>'maximum_count' IS DISTINCT FROM '3' OR program->'selected' IS DISTINCT FROM 'null'::jsonb
        OR coalesce(p_binding_id,'')='' OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(p_binding_id,'ACTIVE')
        OR decision->'commands' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(items) IS DISTINCT FROM 4 THEN
        RAISE EXCEPTION 'nested positions outside reserved binding decision' USING ERRCODE='42501';END IF;
    slots:=kaname._authority_role_move_nested_slots_v1(prepared,80,12);
    aid:=slots#>>'{0,origin,object_id}';pid:=slots#>>'{1,origin,object_id}';
    account_ref:=jsonb_build_array('iam.account',aid);
    parent_key:=account_ref::text;
    IF slots#>>'{0,origin,binding}' IS DISTINCT FROM p_binding_id OR slots#>>'{1,origin,binding}' IS DISTINCT FROM p_binding_id
        OR (program#>'{maximum,1}')-'reserved_id' IS DISTINCT FROM slots->0
        OR (program#>'{maximum,2}')-'reserved_id' IS DISTINCT FROM slots->1
        OR projects->'finite_parents' IS DISTINCT FROM jsonb_build_array(account_ref)
        OR projects#>ARRAY['parent_states',parent_key,'included'] IS DISTINCT FROM 'true'::jsonb
        OR jsonb_typeof(projects#>ARRAY['parent_edges',parent_key]) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'nested account scope or reserved member generation differs' USING ERRCODE='40001';END IF;
    -- План составлен владельцем по обеим версиям единственного правила.
    -- Прямое и вложенное чтения должны именовать тот же конечный аккаунт.
    IF EXISTS(SELECT FROM jsonb_array_elements(items) i WHERE i->>'binding_id' IS DISTINCT FROM p_binding_id
        OR i->'scope' IS DISTINCT FROM jsonb_build_array('account',aid) OR i->>'read_type' IS DISTINCT FROM 'iam.account'
        OR i->>'guard' IS DISTINCT FROM 'objects' OR i->'object_ids' IS DISTINCT FROM jsonb_build_array(aid)
        OR i->'target_ids' IS DISTINCT FROM jsonb_build_array(aid) OR i#>>'{predicate,Arm}' IS DISTINCT FROM '1'
        OR i#>'{predicate,ResourceNames}' IS DISTINCT FROM jsonb_build_array(aid)) THEN
        RAISE EXCEPTION 'nested binding selector escapes named account' USING ERRCODE='42501';END IF;
    FOREACH side IN ARRAY ARRAY['old','new'] LOOP
        IF NOT EXISTS(SELECT FROM jsonb_array_elements(items) i WHERE i->>'side'=side AND NOT (i ? 'child_predicate'))
            OR NOT EXISTS(SELECT FROM jsonb_array_elements(items) i WHERE i->>'side'=side AND i->>'child_type'='iam.project'
                AND CASE side WHEN 'old' THEN i#>>'{child_predicate,Arm}'='2' AND i#>'{child_predicate,MatchLabels}'=pairs
                    ELSE i#>>'{child_predicate,Arm}'='3' AND i#>'{child_predicate,MatchAccessLabels}'=pairs END) THEN
            RAISE EXCEPTION 'nested binding selector side differs' USING ERRCODE='42501';END IF;
    END LOOP;
    edges:=kaname._authority_role_move_member_project_parent_edges_v1('iam.account',aid,projects#>ARRAY['parent_edges',parent_key],
        p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(edges->>'rows')::integer+2*jsonb_array_length(edges->'candidate_ids');
    used_reads:=used_reads+(edges->>'reads')::integer;
    IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'nested descendant census exceeds budget' USING ERRCODE='54000';END IF;
    IF NOT ((edges->'candidate_ids') ? pid) THEN RAISE EXCEPTION 'reserved project is absent from reverse edge census' USING ERRCODE='40001';END IF;
    -- Проверяем границу до построения карты. JSON-строка с экранированием
    -- входит в неё дважды: в ключ и в идентификатор ресурса.
    SELECT coalesce(sum(2*octet_length(to_jsonb(c.id)::text)+48),0),
        coalesce(bool_or(projects#>>ARRAY['projects',c.id,'native','2','id'] IS DISTINCT FROM c.id),false)
        INTO candidate_bytes,source_missing FROM jsonb_array_elements_text(edges->'candidate_ids') c(id);
    IF source_missing THEN RAISE EXCEPTION 'nested project source differs from bounded reverse census' USING ERRCODE='40001';END IF;
    IF candidate_bytes+2*octet_length(to_jsonb(aid)::text)+48>8388608 THEN
        RAISE EXCEPTION 'nested binding positions exceed byte budget' USING ERRCODE='54000';END IF;
    -- nested_slots сверил область и все исторические строки members и ledger.
    -- Единственный исторический проект уже входит в проверенное множество потомков.
    SELECT jsonb_build_object('iam.account:'||aid,account_ref)||jsonb_object_agg(
        'iam.project:'||c.id,jsonb_build_array('iam.project',c.id)) INTO positions
        FROM jsonb_array_elements_text(edges->'candidate_ids') c(id);
    IF octet_length(positions::text)>8388608 THEN RAISE EXCEPTION 'nested binding positions exceed byte budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('positions',positions,'rows',used_rows,'reads',used_reads);
END;
$positions$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_nested_positions_v1(text,integer,integer)'::regprocedure;grantee record;
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
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1','4cfb653e73cee6af71ff5c481063f7fe3634a21417fac123de10377e1e38dfc5',$edits$[
 [
  "    step:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);",
  "    IF frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n        step:=kaname._authority_role_move_nested_positions_v1(p_binding_id,p_rows-used_rows,p_reads-used_reads);\n        used_reads:=used_reads+(step->>'reads')::integer;\n    ELSE\n        step:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n    END IF;"
 ]
]$edits$::jsonb),
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777','d40b87b53a7c3981f99222ce271e258ee0f6e2a0e584a0088880b6b51c8ea05c',$edits$[
 [
  "        observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);",
  "        IF frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n            observed:=kaname._authority_role_move_nested_positions_v1(p_binding_id,p_rows-used_rows,p_reads-used_reads);\n            used_reads:=used_reads+(observed->>'reads')::integer;\n        ELSE\n            observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n        END IF;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3','504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96',$edits$[
 [
  "b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1",
  "4cfb653e73cee6af71ff5c481063f7fe3634a21417fac123de10377e1e38dfc5"
 ],
 [
  "6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777",
  "d40b87b53a7c3981f99222ce271e258ee0f6e2a0e584a0088880b6b51c8ea05c"
 ],
 [
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6','f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546',$edits$[
 [
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3",
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','c6e37fcf8bb31f9f9bb6b3a887ce64b7e0bf5fb6de6f212f729612879feba24d','9928f9f11164425338025544c5c375dc5a01bd1e634d309e63536b091d456f8c',$edits$[
 [
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3",
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96"
 ],
 [
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6",
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306','57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5',$edits$[
 [
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6",
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','5c25a08a4dead51806b59e6debadccbcf33c4d25069d6a590e738b65379b783f','660b8812c3efa517c1edb20cdaa3694779e0a43a9fb43a0620ef8e41f16da584',$edits$[
 [
  "e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306",
  "57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested role binding coordinate proof predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested role binding coordinate proof replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested role binding coordinate proof body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested role binding coordinate proof installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested role binding coordinate proof storage graph differs' USING ERRCODE='55000';
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
        ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','4cfb653e73cee6af71ff5c481063f7fe3634a21417fac123de10377e1e38dfc5','b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1',$edits$[
 [
  "    IF frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n        step:=kaname._authority_role_move_nested_positions_v1(p_binding_id,p_rows-used_rows,p_reads-used_reads);\n        used_reads:=used_reads+(step->>'reads')::integer;\n    ELSE\n        step:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n    END IF;",
  "    step:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);"
 ]
]$edits$::jsonb),
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','d40b87b53a7c3981f99222ce271e258ee0f6e2a0e584a0088880b6b51c8ea05c','6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777',$edits$[
 [
  "        IF frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n            observed:=kaname._authority_role_move_nested_positions_v1(p_binding_id,p_rows-used_rows,p_reads-used_reads);\n            used_reads:=used_reads+(observed->>'reads')::integer;\n        ELSE\n            observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n        END IF;",
  "        observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96','5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3',$edits$[
 [
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n  ('_authority_role_move_nested_positions_v1(text,integer,integer)','jsonb',3,ARRAY['p_binding_id','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n ('_authority_role_move_nested_positions_v1(text,integer,integer)','1b96f2cd3f41db997fdc59449c038e26ff94e09cce1f40a301263e0763730aa1',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n"
 ],
 [
  "d40b87b53a7c3981f99222ce271e258ee0f6e2a0e584a0088880b6b51c8ea05c",
  "6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777"
 ],
 [
  "4cfb653e73cee6af71ff5c481063f7fe3634a21417fac123de10377e1e38dfc5",
  "b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546','20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6',$edits$[
 [
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96",
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','9928f9f11164425338025544c5c375dc5a01bd1e634d309e63536b091d456f8c','c6e37fcf8bb31f9f9bb6b3a887ce64b7e0bf5fb6de6f212f729612879feba24d',$edits$[
 [
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546",
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6"
 ],
 [
  "504066cb477f8401384ef8a6b3da825428657fe6c34af6db12abb7b3bdb2bf96",
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5','e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306',$edits$[
 [
  "f945cb485a2228c0fcdd19e1f60c0a4c15667f61061300f5d2f8ed7b71e47546",
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','660b8812c3efa517c1edb20cdaa3694779e0a43a9fb43a0620ef8e41f16da584','5c25a08a4dead51806b59e6debadccbcf33c4d25069d6a590e738b65379b783f',$edits$[
 [
  "57be5298ad575ed77dddd3be684389cb6c6cbb9e6217fcfa5c458f88af37ffe5",
  "e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested role binding coordinate proof predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested role binding coordinate proof replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested role binding coordinate proof body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested role binding coordinate proof installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested role binding coordinate proof storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_nested_positions_v1(text,integer,integer);
