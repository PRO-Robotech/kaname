-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Запечатанная перепись подтверждает источники одной выдачи. Решение о праве
-- актёра на метод и Grant имеет отдельную границу перед публикацией и COMMIT.
CREATE FUNCTION kaname._authority_role_move_pending_sources_v1(p_sets jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $pending_sources$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    held_program jsonb:=program->'frozen'; prepared jsonb:=held_program->'selector_move'; decision jsonb:=held_program->'selector_move_decision';
    census jsonb:=prepared->'binding_census'; plan jsonb:=decision->'predicate_plan';
    saved jsonb:=held_program->'selector_move_pending_sources'; sets jsonb:=coalesce(p_sets,saved->'sets');
    binding_row jsonb:=census#>'{bindings,0,2}'; bid text:=binding_row->>'id'; rid text:=prepared->>'role_id';
    account_id_value text:=binding_row->>'resource_id'; project_id_value text:=binding_row#>>'{target,resources,0,id}';
    ledger_row jsonb:=census#>'{ledger,0,2}'; root_entry jsonb:=program#>'{maximum,0}'; origin_image jsonb:=root_entry->'origin';
    old_role_image jsonb:=prepared#>'{role,physical}'; actual_role_image jsonb; selector_images jsonb;
    published boolean:=jsonb_typeof(program->'selected')='array'; step jsonb; receipt jsonb; selector_image jsonb;
    used_rows integer:=16;used_reads integer:=5;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(sets::text)>65536 THEN RAISE EXCEPTION 'pending member source budget exceeded' USING ERRCODE='54000';END IF;
    IF program->>'family' IS DISTINCT FROM 'role' OR held_program->>'kind' IS DISTINCT FROM 'role.mutation'
        OR held_program->>'mode' IS DISTINCT FROM 'selector_move' OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR prepared->'nonce' IS DISTINCT FROM proof->'nonce' OR prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR decision->'actor' IS DISTINCT FROM prepared->'actor' OR jsonb_typeof(decision->'actor') IS DISTINCT FROM 'object'
        OR (decision->>'decision_at')::timestamptz IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR (isfinite((proof->>'decision_at')::timestamptz) AND (proof->>'decision_at')::timestamptz>(prepared->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR coalesce(rid,'')='' OR decision->>'role_id' IS DISTINCT FROM rid OR held_program->>'id' IS DISTINCT FROM rid
        OR held_program#>'{request,retier}' IS DISTINCT FROM 'true'::jsonb
        OR jsonb_array_length(program->'maximum') IS DISTINCT FROM 1 OR held_program->>'selector_move_fixed' IS DISTINCT FROM '1'
        OR root_entry->>'table' IS DISTINCT FROM 'resource_journal' OR root_entry->>'ordinal' IS DISTINCT FROM '1'
        OR origin_image->>'table' IS DISTINCT FROM 'roles' OR origin_image->>'operation' IS DISTINCT FROM 'UPDATE'
        OR origin_image->'old' IS DISTINCT FROM old_role_image->2 OR origin_image#>>'{new,id}' IS DISTINCT FROM rid
        OR origin_image#>'{new,rules}' IS DISTINCT FROM prepared#>'{role,new_role,rules}'
        OR prepared#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb OR decision->'commands' IS DISTINCT FROM '[]'::jsonb
        OR plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR jsonb_typeof(sets) IS DISTINCT FROM 'object' OR coalesce(bid,'')='' OR coalesce(account_id_value,'')='' OR coalesce(project_id_value,'')=''
        OR (p_sets IS NOT NULL AND (saved IS NOT NULL OR published IS DISTINCT FROM false))
        OR (p_sets IS NULL AND jsonb_typeof(saved) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'pending member sources outside final role decision' USING ERRCODE='42501';
    END IF;
    -- Отбор по конечной цели сам по себе не обнаруживает правила других типов.
    -- Ограничиваем исходную форму роли до проверки полного набора позиций.
    IF jsonb_array_length(origin_image#>'{old,rules}') IS DISTINCT FROM 1 OR jsonb_array_length(origin_image#>'{new,rules}') IS DISTINCT FROM 1
        OR (origin_image#>'{old,rules,0}')-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb
        OR (origin_image#>'{new,rules,0}')-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb
        OR origin_image#>>'{old,rules,0,module}' IS DISTINCT FROM 'iam' OR origin_image#>'{old,rules,0,resources}' IS DISTINCT FROM '["project"]'::jsonb
        OR origin_image#>'{old,rules,0,verbs}' IS DISTINCT FROM '["get"]'::jsonb
        OR (origin_image#>'{old,rules,0}')-'match_labels' IS DISTINCT FROM (origin_image#>'{new,rules,0}')-'match_access_labels'
        OR origin_image#>'{old,rules,0,match_labels}' IS DISTINCT FROM origin_image#>'{new,rules,0,match_access_labels}' THEN
        RAISE EXCEPTION 'pending member role exceeds direct source coverage' USING ERRCODE='42501';END IF;
    IF NOT EXISTS(SELECT FROM ONLY kaname.authority_bundle_handoff b WHERE b.singleton AND b.model_id=proof->>'model_id'
        AND b.projector_version=proof->>'projector_version' AND b.catalog_id=proof->>'catalog_id'
        AND octet_length(b.catalog_json) BETWEEN 1 AND 8388608 AND encode(sha256(b.catalog_json),'hex')=b.catalog_id) THEN
        RAISE EXCEPTION 'pending member catalog identity changed' USING ERRCODE='40001';END IF;
    IF published THEN
        IF held_program->>'selector_move_pending_sources_approved' IS DISTINCT FROM encode(sha256(convert_to(saved::text,'UTF8')),'hex')
            OR held_program ? 'selector_move_pending' OR program->'decision_at' IS DISTINCT FROM decision->'decision_at'
            OR held_program#>'{selector_move_approved,nonce}' IS DISTINCT FROM proof->'nonce'
            OR held_program#>'{selector_move_approved,actor}' IS DISTINCT FROM decision->'actor'
            OR held_program#>>'{selector_move_approved,role_id}' IS DISTINCT FROM rid
            OR held_program#>'{selector_move_approved,decision_at}' IS DISTINCT FROM decision->'decision_at' THEN
            RAISE EXCEPTION 'pending member publication changed' USING ERRCODE='42501';END IF;
    ELSIF program->'selected' IS DISTINCT FROM 'null'::jsonb OR held_program ? 'selector_move_approved' OR held_program ? 'selector_move_pending_sources_approved'
        OR jsonb_typeof(held_program#>'{selector_move_pending,selected}') IS DISTINCT FROM 'array'
        OR jsonb_typeof(held_program#>'{selector_move_pending,unselected}') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'pending member reservation changed' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(census->'bindings') IS DISTINCT FROM 1 OR jsonb_array_length(census->'subjects') IS DISTINCT FROM 1
        OR census#>>'{subjects,0,2,binding_id}' IS DISTINCT FROM bid OR binding_row->>'role_id' IS DISTINCT FROM rid
        OR binding_row->>'status' IS DISTINCT FROM 'PENDING' OR binding_row->>'revoked_at' IS NOT NULL OR binding_row->>'expires_at' IS NOT NULL
        OR binding_row->>'resource_type' IS DISTINCT FROM 'account' OR binding_row->'target' IS DISTINCT FROM
            jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',project_id_value)))
        OR census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1
        OR ledger_row->>'binding_id' IS DISTINCT FROM bid OR ledger_row->>'source' IS DISTINCT FROM 'binding'
        OR coalesce(ledger_row->>'member_object_type','')<>'' OR coalesce(ledger_row->>'member_object_id','')<>''
        OR ledger_row->>'fga_user' IS DISTINCT FROM 'account:'||account_id_value OR ledger_row->>'relation' IS DISTINCT FROM 'account'
        OR ledger_row->>'object' IS DISTINCT FROM 'iam_access_binding:'||bid
        OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(bid,'PENDING')
        OR decision#>ARRAY['binding_new',bid,'binding_tuples'] IS DISTINCT FROM '[]'::jsonb
        OR jsonb_array_length(plan->'items') IS DISTINCT FROM 2 OR jsonb_array_length(plan->'holders') IS DISTINCT FROM 1
        OR plan#>>'{holders,0,binding_id}' IS DISTINCT FROM bid OR (SELECT count(*) FROM jsonb_object_keys(sets))<>1
        OR NOT (sets ? bid) OR jsonb_typeof(sets->bid) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'pending member source coverage is not the exact finite carrier' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(sets->bid)<>2 OR EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i WHERE i->>'binding_id' IS DISTINCT FROM bid
        OR i ? 'child_predicate' OR i->>'guard' IS DISTINCT FROM 'objects' OR i->>'read_type' IS DISTINCT FROM 'iam.project'
        OR i->'object_ids' IS DISTINCT FROM jsonb_build_array(project_id_value))
        OR (SELECT count(*) FROM jsonb_array_elements(plan->'items') i WHERE i->>'side'='old' AND i#>>'{predicate,Arm}'='2')<>1
        OR (SELECT count(*) FROM jsonb_array_elements(plan->'items') i WHERE i->>'side'='new' AND i#>>'{predicate,Arm}'='3')<>1
        OR NOT EXISTS(SELECT FROM jsonb_array_elements(sets->bid) c WHERE c->'Present'='true'::jsonb
            AND c->'Resource'=jsonb_build_object('Type','iam.project','ID',project_id_value))
        OR NOT EXISTS(SELECT FROM jsonb_array_elements(sets->bid) c WHERE c->'Present'='true'::jsonb
            AND c->'Resource'=jsonb_build_object('Type','iam.account','ID',account_id_value)) THEN
        RAISE EXCEPTION 'pending member finite positions differ' USING ERRCODE='42501';END IF;
    -- В RR-spool обязательны ровно две равные структурные записи OLD и NEW.
    -- До обращения к pg_temp общий владелец сверяет ACL, типы и индекс.
    step:=kaname._authority_role_move_stage_tuple_census_v1(true,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
    IF step->'counts' IS DISTINCT FROM jsonb_build_object(bid,2) OR step->>'tuples' IS DISTINCT FROM '2'
        OR (SELECT count(DISTINCT t.side) FROM ONLY pg_temp.kaname_role_stage_tuples t WHERE t.binding_id=bid
            AND t.side IN ('old','new') AND t.fga_user=ledger_row->>'fga_user' AND t.relation=ledger_row->>'relation'
            AND t.object=ledger_row->>'object')<>2 THEN RAISE EXCEPTION 'pending member structural tuples changed' USING ERRCODE='40001';END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO actual_role_image FROM ONLY kaname.roles r WHERE r.id=rid;
    IF NOT published THEN
        IF actual_role_image IS DISTINCT FROM old_role_image THEN RAISE EXCEPTION 'pending member role OLD changed' USING ERRCODE='40001';END IF;
        step:=kaname._authority_role_move_direct_member_sets_v1(sets,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
        IF step->'bindings' IS DISTINCT FROM jsonb_build_object(bid,encode(sha256(convert_to((sets->bid)::text,'UTF8')),'hex'))
            OR step->'proposed_claims' IS DISTINCT FROM '{}'::jsonb THEN RAISE EXCEPTION 'pending member claims differ' USING ERRCODE='42501';END IF;
    ELSE
        IF actual_role_image->2 IS DISTINCT FROM origin_image->'new' OR NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=(proof->>'nonce')::uuid AND e.ordinal=1 AND e.origin=origin_image AND e.selected AND e.registered AND e.claimed AND e.consumed) THEN
            RAISE EXCEPTION 'pending member committed role differs from its journal' USING ERRCODE='40001';END IF;
        -- После штатного UPDATE старая роль недоступна. Её поколение закреплено
        -- квитанцией; переписи остальных таблиц должны совпасть побайтно.
        step:=kaname._authority_role_move_binding_census_v1(rid,census,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
        IF step->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN RAISE EXCEPTION 'pending member carrier changed' USING ERRCODE='40001';END IF;
        step:=kaname._authority_role_move_finite_positions_v1(prepared,plan,true,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
        IF step->'positions' IS DISTINCT FROM decision->'finite_positions' THEN RAISE EXCEPTION 'pending member finite universe changed' USING ERRCODE='40001';END IF;
        step:=kaname._authority_role_move_member_projects_v1(plan,census||jsonb_build_object('moved_role_id',rid),
            prepared->'member_projects',p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
        IF step->'source' IS DISTINCT FROM prepared->'member_projects' THEN RAISE EXCEPTION 'pending member project source changed' USING ERRCODE='40001';END IF;
        selector_images:=plan->'new_role_index'->(jsonb_build_array(13,'role',rid,'')::text)->'states';
        IF jsonb_array_length(selector_images) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'pending member selector image absent' USING ERRCODE='42501';END IF;
        SELECT jsonb_agg(to_jsonb(v)) INTO selector_image FROM (SELECT s.* FROM ONLY kaname.role_rule_selectors s WHERE s.role_id=rid LIMIT 2) v;
        IF jsonb_array_length(selector_image) IS DISTINCT FROM 1 OR (selector_image->0)-ARRAY['created_at','updated_at'] IS DISTINCT FROM
            (selector_images#>'{0,2}')-ARRAY['created_at','updated_at'] THEN RAISE EXCEPTION 'pending member selector projection changed' USING ERRCODE='40001';END IF;
    END IF;
    receipt:=jsonb_build_object('nonce',proof->'nonce','invoker_oid',proof->'invoker_oid','backend',pg_backend_pid(),'xid',pg_current_xact_id()::text,
        'actor',decision->'actor','role_id',rid,'role_generation',jsonb_build_array(old_role_image->0,old_role_image->1),'binding_id',bid,
        'decision_at',decision->'decision_at','model_id',proof->'model_id','catalog_id',proof->'catalog_id','projector_version',proof->'projector_version',
        'prepared_sha256',encode(sha256(convert_to(prepared::text,'UTF8')),'hex'),'decision_sha256',encode(sha256(convert_to(decision::text,'UTF8')),'hex'),
        'role_origin_sha256',encode(sha256(convert_to(origin_image::text,'UTF8')),'hex'),
        'sets_sha256',encode(sha256(convert_to(sets::text,'UTF8')),'hex'),'sets',sets);
    IF p_sets IS NOT NULL THEN
        IF octet_length(held_program::text)+octet_length(receipt::text)+64>8388608 THEN RAISE EXCEPTION 'pending member receipt exceeds byte budget' USING ERRCODE='54000';END IF;
        UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_pending_sources',receipt)
            WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.family='role' AND s.selected IS NULL AND s.frozen=held_program;
        IF NOT FOUND THEN RAISE EXCEPTION 'pending member source seal changed' USING ERRCODE='40001';END IF;
    ELSIF receipt IS DISTINCT FROM saved THEN RAISE EXCEPTION 'pending member source receipt changed' USING ERRCODE='40001';END IF;
    RETURN jsonb_build_object('sha256',encode(sha256(convert_to(receipt::text,'UTF8')),'hex'),'rows',used_rows,'reads',used_reads);
END;
$pending_sources$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_pending_sources_v1(jsonb,integer,integer)'::regprocedure;
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
DO $pending_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_binding_empty_require_v1(jsonb)','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379','7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7',$changes$[
  [
    "    IF coalesce(v_role_id,'')='' OR v_role_id IS DISTINCT FROM",
    "    IF p_frozen ? 'selector_move_pending_sources' THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n        -- Собранные источники не являются правом актёра. Предикат метода и\n        -- prospective Grant ещё не подтверждены владельцем для этого решения.\n        RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';\n    END IF;\n    IF coalesce(v_role_id,'')='' OR v_role_id IS DISTINCT FROM"
  ]
]$changes$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8','bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e',$changes$[
  [
    "frozen=(s.frozen-'selector_move_pending')||jsonb_build_object('selector_move_approved',approval)",
    "frozen=(s.frozen-'selector_move_pending')||jsonb_build_object('selector_move_approved',approval)\n            ||(CASE WHEN s.frozen ? 'selector_move_pending_sources' THEN\n                jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'))\n                ELSE '{}'::jsonb END)"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc','012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9',$changes$[
  [
    "048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379",
    "7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7"
  ],
  [
    "427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8",
    "bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e"
  ],
  [
    " ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n",
    " ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n",
    "  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2','873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7',$changes$[
  [
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc",
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','51dc4c43cd456bbfe7cdf7584dd8feae69b759b5ed13602c6a1be8fa65e36e3e','4c07b6a922eb38ce74e84a05e7750b2a73de1ef7a97f646c0e025f41637d76c9',$changes$[
  [
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc",
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9"
  ],
  [
    "d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2",
    "873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move tuple stage predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move tuple stage replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$pending_guard$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $pending_guard$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('authority_metadata_service_account_access_label_ready_v1()','4c07b6a922eb38ce74e84a05e7750b2a73de1ef7a97f646c0e025f41637d76c9','51dc4c43cd456bbfe7cdf7584dd8feae69b759b5ed13602c6a1be8fa65e36e3e',$changes$[
  [
    "873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7",
    "d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2"
  ],
  [
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9",
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','873236f5cb33c0e147fcfaa2534e50d9f0c54296825df3981fa4797850ada0a7','d34172e8c1431500a24fd6b2cd3dde0a3f2813ae3272ab58d9bba4f9b1aa97c2',$changes$[
  [
    "012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9",
    "2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','012ff77b4f259e4156b26a5e3eafc1ea22f3556bce46d90b5d6284f783a5f8e9','2dc33f9358616832ef6c2fc836d3dd7814a9fb34c9d28126362949974d8bc6dc',$changes$[
  [
    "  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n  ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','jsonb',3,ARRAY['p_retier','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n ('_authority_role_move_pending_sources_v1(jsonb,integer,integer)','822bc546ee78f94c62b272ef908abf524d36af70f72810a77f2ee00d137e1569',false,'v',true,'private'),\n",
    " ('_authority_role_move_stage_tuple_census_v1(boolean,integer,integer)','b14c4cae3e8cd03329139aeb83e13a0de0df6589453589f4fe56c1054197eb6a',false,'v',true,'private'),\n"
  ],
  [
    "bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e",
    "427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8"
  ],
  [
    "7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7",
    "048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379"
  ]
]$changes$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','bf68e469d6ad37c6eb627640a9b992f2bf233f30cb99092f6e111f6898c4f16e','427e98aeb8679cb18e253760abacff4757905d9dcdcc087cabbd3b4e0dc23cb8',$changes$[
  [
    "frozen=(s.frozen-'selector_move_pending')||jsonb_build_object('selector_move_approved',approval)\n            ||(CASE WHEN s.frozen ? 'selector_move_pending_sources' THEN\n                jsonb_build_object('selector_move_pending_sources_approved',encode(sha256(convert_to((s.frozen->'selector_move_pending_sources')::text,'UTF8')),'hex'))\n                ELSE '{}'::jsonb END)",
    "frozen=(s.frozen-'selector_move_pending')||jsonb_build_object('selector_move_approved',approval)"
  ]
]$changes$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','7260da43b7c40f9b9021c57de81450fb4a46437cda5928844175229a8cf062d7','048b60e9637befdbbca317dba9db6d192bece6b298b1704bbcd306006b63c379',$changes$[
  [
    "    IF p_frozen ? 'selector_move_pending_sources' THEN\n        IF p_frozen IS DISTINCT FROM (kaname._authority_sequence_store_v3()->'frozen') THEN\n            RAISE EXCEPTION 'pending member source outside owner program' USING ERRCODE='42501';END IF;\n        PERFORM kaname._authority_role_move_pending_sources_v1(NULL,100000,4096);\n        -- Собранные источники не являются правом актёра. Предикат метода и\n        -- prospective Grant ещё не подтверждены владельцем для этого решения.\n        RAISE EXCEPTION 'pending member sources require owner method and grant authority' USING ERRCODE='42501';\n    END IF;\n    IF coalesce(v_role_id,'')='' OR v_role_id IS DISTINCT FROM",
    "    IF coalesce(v_role_id,'')='' OR v_role_id IS DISTINCT FROM"
  ]
]$changes$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'selector move tuple stage predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'selector move tuple stage replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'selector move tuple stage installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'selector move tuple stage storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$pending_guard$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_pending_sources_v1(jsonb,integer,integer);
