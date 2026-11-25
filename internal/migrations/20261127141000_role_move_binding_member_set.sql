-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Полная область одной выдачи для прямых проектных селекторов и собственного
-- аккаунта/проекта. Любая неподтверждённая ветвь останавливает весь набор.
CREATE FUNCTION kaname._authority_role_move_binding_direct_positions_v1(p_prepared jsonb,p_decision jsonb,p_binding_id text,p_rows integer)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $positions$
DECLARE
    plan jsonb:=p_decision->'predicate_plan'; holder jsonb:=p_decision#>ARRAY['binding_new',p_binding_id];
    projects jsonb:=p_prepared#>'{member_projects,projects}'; census jsonb:=p_prepared->'binding_census';
    revoked boolean:=p_decision#>>ARRAY['binding_status',p_binding_id]='REVOKED';
    roots jsonb:=p_prepared#>'{copies,roots}'; positions jsonb:='{}'::jsonb;
    candidate record; coord jsonb; image jsonb; copy_image jsonb; selector jsonb; item jsonb;
    used_rows integer;mode text;typ text;identifier text;match_old boolean;match_overlay boolean;
BEGIN
    IF coalesce(p_binding_id,'')='' OR revoked IS NULL
        OR (revoked AND holder IS NOT NULL)
        OR (NOT revoked AND (jsonb_typeof(holder) IS DISTINCT FROM 'object' OR coalesce(holder->>'class','') NOT IN ('ACTIVE','PENDING')))
        OR jsonb_typeof(plan->'items') IS DISTINCT FROM 'array' OR jsonb_typeof(roots) IS DISTINCT FROM 'object'
        OR jsonb_typeof(projects) IS DISTINCT FROM 'object' OR jsonb_typeof(census->'members') IS DISTINCT FROM 'array'
        OR jsonb_typeof(census->'ledger') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'binding coordinate sources missing' USING ERRCODE='42501';END IF;
    used_rows:=2+jsonb_array_length(plan->'items')+jsonb_array_length(census->'members')+2*jsonb_array_length(census->'ledger');
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 THEN RAISE EXCEPTION 'binding coordinate input exceeds budget' USING ERRCODE='54000';END IF;
    IF EXISTS(SELECT FROM jsonb_array_elements(census->'ledger') l WHERE l#>>'{2,binding_id}'=p_binding_id AND
        (coalesce(l#>>'{2,source}','') NOT IN ('binding','member')
        OR ((coalesce(l#>>'{2,member_object_type}','')<>'') IS DISTINCT FROM (l#>>'{2,source}'='member'))
        OR ((coalesce(l#>>'{2,member_object_id}','')<>'') IS DISTINCT FROM (l#>>'{2,source}'='member'))
        OR coalesce(l#>>'{2,fga_user}','')='' OR coalesce(l#>>'{2,relation}','')=''
        OR coalesce(l#>>'{2,object}','') !~ '^[^.:#*[:space:][:cntrl:]]+:[^:#*[:space:][:cntrl:]]+$')) THEN
        RAISE EXCEPTION 'binding ledger coordinate is not confirmed' USING ERRCODE='42501';END IF;
    FOR coord IN
        SELECT jsonb_build_array(m#>'{2,object_type}',m#>'{2,object_id}') FROM jsonb_array_elements(census->'members') m WHERE m#>>'{2,binding_id}'=p_binding_id
        UNION ALL SELECT jsonb_build_array(l#>'{2,member_object_type}',l#>'{2,member_object_id}') FROM jsonb_array_elements(census->'ledger') l
            WHERE l#>>'{2,binding_id}'=p_binding_id AND l#>>'{2,source}'='member'
        UNION ALL SELECT jsonb_build_array('iam.'||(holder#>>'{scope,0}'),holder#>'{scope,1}')
            WHERE holder#>>'{scope,0}' IN ('account','project')
    LOOP
        typ:=coord->>0;identifier:=coord->>1;
        IF coalesce(typ,'') NOT IN ('iam.account','iam.project') OR coalesce(identifier,'')='' OR
            (typ='iam.account' AND holder->'scope' IS DISTINCT FROM jsonb_build_array('account',identifier)) OR
            (typ='iam.project' AND NOT (projects ? identifier)) THEN RAISE EXCEPTION 'historical binding coordinate source unsupported' USING ERRCODE='42501';END IF;
        positions:=positions||jsonb_build_object(typ||':'||identifier,coord);
    END LOOP;
    FOR item IN SELECT i FROM jsonb_array_elements(plan->'items') i WHERE i->>'binding_id'=p_binding_id LOOP
        IF revoked OR item ? 'child_predicate' OR item->>'read_type' IS DISTINCT FROM 'iam.project'
            OR coalesce(item->>'side','') NOT IN ('old','new') OR coalesce(item->>'guard','') NOT IN ('objects','whole_type','scope')
            OR jsonb_typeof(item->'object_ids') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'binding coordinate plan contains an unproved selector branch' USING ERRCODE='42501';
        END IF;
        mode:=item#>>'{predicate,Arm}';
        selector:=jsonb_build_object('object_types',jsonb_build_array('iam.project'))||CASE mode
            WHEN '1' THEN jsonb_build_object('arm','names','resource_names',item#>'{predicate,ResourceNames}')
            WHEN '2' THEN jsonb_build_object('arm','labels','match_labels',item#>'{predicate,MatchLabels}')
            WHEN '3' THEN jsonb_build_object('arm','access_labels','match_access_labels',item#>'{predicate,MatchAccessLabels}')
            ELSE '{}'::jsonb END;
        IF mode IS NULL OR mode NOT IN ('0','1','2','3') OR
            (item->>'guard'<>'objects' AND p_prepared#>'{member_projects,all_native}' IS DISTINCT FROM 'true'::jsonb
             AND (mode<>'0' OR holder#>>'{scope,0}' IS DISTINCT FROM 'project')) THEN
            RAISE EXCEPTION 'binding selector lacks a complete project census' USING ERRCODE='42501';
        END IF;
        -- У Go names/labels сохраняют и чужую строку для REJECTED, только
        -- anchor ограничивает родную выборку областью до вывода координат.
        FOR candidate IN
            SELECT p.key,p.value FROM jsonb_each(CASE WHEN item->>'guard'<>'objects' THEN projects ELSE '{}'::jsonb END) p
            UNION ALL SELECT v.id,projects->v.id FROM jsonb_array_elements_text(item->'object_ids') v(id) WHERE item->>'guard'='objects'
        LOOP
            used_rows:=used_rows+4;
            IF used_rows>p_rows THEN RAISE EXCEPTION 'binding project predicate budget exceeded' USING ERRCODE='54000';END IF;
            IF candidate.value IS NULL THEN RAISE EXCEPTION 'prepared project enumeration is incomplete' USING ERRCODE='40001';END IF;
            IF candidate.value='null'::jsonb THEN CONTINUE;END IF;
            image:=candidate.value#>'{native,2}';identifier:=candidate.key;
            IF image->>'id' IS DISTINCT FROM identifier THEN RAISE EXCEPTION 'binding project identity differs' USING ERRCODE='42501';END IF;
            copy_image:=roots->('iam.project:'||identifier);
            match_overlay:=false;
            IF mode='0' THEN
                match_old:=kaname._authority_resource_contained_v2(holder#>>'{scope,0}',holder#>>'{scope,1}',
                    jsonb_build_array(image->'account_id'),identifier);
            ELSE
                match_old:=kaname._authority_resource_selector_matches_v3(selector,'iam.project',identifier,image->'labels',image->'access_labels');
                IF mode='3' AND item->>'side'='new' AND copy_image IS NOT NULL THEN
                    IF copy_image->'physical' IS DISTINCT FROM candidate.value->'native' THEN RAISE EXCEPTION 'potential project copy source differs' USING ERRCODE='40001';END IF;
                    match_overlay:=kaname._authority_resource_selector_matches_v3(selector,'iam.project',identifier,image->'labels',copy_image->'new_access_labels');
                END IF;
            END IF;
            IF match_old OR match_overlay THEN positions:=positions||jsonb_build_object('iam.project:'||identifier,jsonb_build_array('iam.project',identifier));END IF;
        END LOOP;
    END LOOP;
    IF octet_length(positions::text)>8388608 THEN RAISE EXCEPTION 'binding coordinate positions exceed byte budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('positions',positions,'rows',used_rows);
END;
$positions$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer)'::regprocedure;
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
-- Сопоставляет целый набор OLD/NEW одной выдачи с физической переписью.
-- Набор утраченных притязаний используется только для проверки других держателей.
CREATE FUNCTION kaname._authority_role_move_binding_member_set_v1(p_binding_id text,p_coordinates jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $binding_set$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen';prepared jsonb:=frozen->'selector_move';decision jsonb:=frozen->'selector_move_decision';
    plan jsonb:=decision->'predicate_plan';holder jsonb:=decision#>ARRAY['binding_new',p_binding_id];
    role_id text:=prepared->>'role_id';class_name text:=decision#>>ARRAY['binding_status',p_binding_id];at_time timestamptz;
    old_index jsonb:=plan->'old_role_index';new_index jsonb:=plan->'new_role_index';
    catalog_row record;catalog jsonb;current_role_image jsonb;step jsonb;binding_rows jsonb;subject_rows jsonb;logical jsonb;
    expected jsonb;seen jsonb:='{}'::jsonb;entry jsonb;key_value text;typ text;identifier text;
    held jsonb;native jsonb;actual jsonb;graph jsonb;new_graph jsonb;copy_command jsonb;project_new jsonb;
    old_desired jsonb;new_desired jsonb;confirmed jsonb;claims jsonb;old_claims jsonb:='{}'::jsonb;new_claims jsonb:='{}'::jsonb;
    lost jsonb;residual jsonb;counted bigint;result jsonb;
    coordinate_effects jsonb:='{}'::jsonb;effect jsonb;copied boolean;
    member_images jsonb:=prepared#>'{binding_census,members}';ledger_images jsonb:=prepared#>'{binding_census,ledger}';
    old_members jsonb;old_ledger jsonb;proposed_members jsonb;proposed_ledger jsonb;
    member_add jsonb;member_remove jsonb;ledger_add jsonb;ledger_remove jsonb;
    used_rows integer:=12;used_reads integer:=8;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_coordinates::text)>8388608 THEN RAISE EXCEPTION 'whole binding member proof exceeds budget' USING ERRCODE='54000';END IF;
    IF coalesce(p_binding_id,'')='' OR jsonb_typeof(p_coordinates) IS DISTINCT FROM 'array'
        OR program->>'family' IS DISTINCT FROM 'role' OR frozen->>'kind' IS DISTINCT FROM 'role.mutation'
        OR coalesce(frozen->>'mode','') NOT IN ('selector_move','access_label_transition') OR program->'nonce' IS DISTINCT FROM proof->'nonce'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR frozen ? 'selector_move_approved'
        OR jsonb_typeof(frozen#>'{selector_move_pending,selected}') IS DISTINCT FROM 'array'
        OR jsonb_typeof(frozen#>'{selector_move_pending,unselected}') IS DISTINCT FROM 'array'
        OR prepared->'nonce' IS DISTINCT FROM proof->'nonce' OR prepared->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR decision->>'role_id' IS DISTINCT FROM role_id OR decision->'actor' IS DISTINCT FROM prepared->'actor'
        OR jsonb_typeof(old_index) IS DISTINCT FROM 'object' OR jsonb_typeof(new_index) IS DISTINCT FROM 'object'
        OR coalesce(class_name,'') NOT IN ('ACTIVE','PENDING','REVOKED','EXPIRED')
        OR (class_name IN ('ACTIVE','PENDING') AND holder->>'class' IS DISTINCT FROM class_name)
        OR (class_name IN ('REVOKED','EXPIRED') AND holder IS NOT NULL)
        OR jsonb_typeof(decision->'commands') IS DISTINCT FROM 'array'
        OR jsonb_typeof(plan->'holders') IS DISTINCT FROM 'array'
        OR (EXISTS(SELECT FROM jsonb_array_elements(plan->'holders') h WHERE h->>'binding_id'=p_binding_id)
            IS DISTINCT FROM (class_name IN ('ACTIVE','PENDING')))
        OR plan->'catalog_id' IS DISTINCT FROM proof->'catalog_id' THEN RAISE EXCEPTION 'whole binding member proof outside decision' USING ERRCODE='42501';END IF;
    at_time:=CASE WHEN frozen->>'mode'='access_label_transition' THEN kaname._authority_role_move_native_clock_v1(proof,frozen)
        ELSE (proof->>'decision_at')::timestamptz END;
    IF (isfinite(at_time) AND at_time>(prepared->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR at_time IS DISTINCT FROM (decision->>'decision_at')::timestamptz THEN RAISE EXCEPTION 'whole binding member clock differs' USING ERRCODE='42501';END IF;
    step:=kaname._authority_role_move_binding_census_v1(role_id,prepared->'binding_census',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
    IF step->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN RAISE EXCEPTION 'whole binding census changed' USING ERRCODE='40001';END IF;
    -- Go читает селекторы ACTIVE/PENDING до проверки TTL, поэтому EXPIRED
    -- нельзя заменить исторической переписью даже при истечении до prepare.
    IF class_name='EXPIRED' THEN RAISE EXCEPTION 'expired binding needs captured selector positions' USING ERRCODE='42501';END IF;
    IF class_name<>'REVOKED' THEN
        step:=kaname._authority_role_move_selector_versions_v1(role_id,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
        IF step->'versions' IS DISTINCT FROM prepared->'selector_versions' THEN RAISE EXCEPTION 'whole binding selectors changed' USING ERRCODE='40001';END IF;
    END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO current_role_image FROM ONLY kaname.roles r WHERE r.id=role_id;
    IF current_role_image IS DISTINCT FROM prepared#>'{role,physical}' THEN RAISE EXCEPTION 'whole binding role changed' USING ERRCODE='40001';END IF;
    step:=kaname._authority_role_move_member_projects_v1(plan,(prepared->'binding_census')||jsonb_build_object('moved_role_id',role_id),
        prepared->'member_projects',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
    IF decision->>'member_projects_sha256' IS DISTINCT FROM encode(sha256(convert_to((step->'source')::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'whole binding project census changed' USING ERRCODE='40001';END IF;
    step:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);
    used_rows:=used_rows+(step->>'rows')::integer;expected:=step->'positions';
    IF jsonb_array_length(p_coordinates)<>(SELECT count(*) FROM jsonb_object_keys(expected)) THEN
        RAISE EXCEPTION 'whole binding coordinate count differs' USING ERRCODE='42501';END IF;
    used_rows:=used_rows+jsonb_array_length(decision->'commands')+jsonb_array_length(plan->'holders')+jsonb_array_length(prepared#>'{binding_census,bindings}')+jsonb_array_length(prepared#>'{binding_census,subjects}')
        +jsonb_array_length(prepared#>'{binding_census,ledger}')+jsonb_array_length(p_coordinates);
    IF used_rows>p_rows THEN RAISE EXCEPTION 'whole binding source reads exceed budget' USING ERRCODE='54000';END IF;
    SELECT coalesce(jsonb_agg(b),'[]'::jsonb) INTO binding_rows FROM jsonb_array_elements(prepared#>'{binding_census,bindings}') b
        WHERE b#>>'{2,id}'=p_binding_id AND b#>>'{2,role_id}'=role_id;
    SELECT coalesce(jsonb_agg(s ORDER BY (s#>>'{2,ordinal}')::integer),'[]'::jsonb) INTO subject_rows
        FROM jsonb_array_elements(prepared#>'{binding_census,subjects}') s WHERE s#>>'{2,binding_id}'=p_binding_id;
    IF jsonb_array_length(binding_rows)<>1 OR jsonb_array_length(subject_rows) NOT BETWEEN 1 AND 32
        OR binding_rows#>>'{0,2,status}' IS DISTINCT FROM class_name
        OR ((binding_rows#>>'{0,2,revoked_at}' IS NOT NULL) IS DISTINCT FROM (class_name='REVOKED'))
        OR (class_name<>'REVOKED' AND (binding_rows#>>'{0,2,expires_at}')::timestamptz<=at_time) THEN RAISE EXCEPTION 'whole binding recipient or TTL differs' USING ERRCODE='42501';END IF;
    IF class_name='REVOKED' THEN
        used_rows:=used_rows+jsonb_array_length(member_images);
        IF used_rows>p_rows THEN RAISE EXCEPTION 'revoked binding history exceeds budget' USING ERRCODE='54000';END IF;
        IF EXISTS(SELECT FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
            AND m#>>'{2,role_id}' IS DISTINCT FROM role_id) THEN RAISE EXCEPTION 'revoked member role differs' USING ERRCODE='42501';END IF;
    ELSE
        logical:=jsonb_build_object(jsonb_build_array(8,'binding',p_binding_id,'')::text,
            jsonb_build_object('source','{}'::jsonb,'states',jsonb_set(binding_rows,'{0,2,status}','"ACTIVE"'::jsonb,false)),
            jsonb_build_array(9,'binding',p_binding_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',subject_rows));
        old_index:=old_index||logical;new_index:=new_index||logical;
        SELECT b.catalog_json,b.model_id,b.catalog_id,b.projector_version INTO catalog_row FROM ONLY kaname.authority_bundle_handoff b WHERE b.singleton;
        IF NOT FOUND OR catalog_row.model_id IS DISTINCT FROM proof->>'model_id' OR catalog_row.catalog_id IS DISTINCT FROM proof->>'catalog_id'
            OR catalog_row.projector_version IS DISTINCT FROM proof->>'projector_version' OR octet_length(catalog_row.catalog_json) NOT BETWEEN 1 AND 8388608
            OR encode(sha256(catalog_row.catalog_json),'hex') IS DISTINCT FROM catalog_row.catalog_id THEN RAISE EXCEPTION 'whole member catalog changed' USING ERRCODE='40001';END IF;
        catalog:=convert_from(catalog_row.catalog_json,'UTF8')::jsonb;
    END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(p_coordinates) LOOP
        IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR NOT (entry ?& ARRAY['Resource','Present','Before','Proposed'])
            OR entry-ARRAY['Resource','Present','Before','Proposed']<>'{}'::jsonb OR jsonb_typeof(entry->'Resource') IS DISTINCT FROM 'object'
            OR NOT ((entry->'Resource') ?& ARRAY['Type','ID']) OR (entry->'Resource')-ARRAY['Type','ID']<>'{}'::jsonb
            OR coalesce(jsonb_typeof(entry->'Before'),'') NOT IN ('array','null') OR coalesce(jsonb_typeof(entry->'Proposed'),'') NOT IN ('array','null') THEN
            RAISE EXCEPTION 'invalid whole binding coordinate proposal' USING ERRCODE='42501';END IF;
        typ:=entry#>>'{Resource,Type}';identifier:=entry#>>'{Resource,ID}';key_value:=typ||':'||identifier;
        IF key_value IS NULL OR seen ? key_value OR expected->key_value IS DISTINCT FROM jsonb_build_array(typ,identifier) THEN
            RAISE EXCEPTION 'unexpected or duplicate whole binding coordinate' USING ERRCODE='42501';END IF;
        seen:=seen||jsonb_build_object(key_value,true);
        old_desired:=coalesce(nullif(entry->'Before','null'::jsonb),'[]'::jsonb);
        new_desired:=coalesce(nullif(entry->'Proposed','null'::jsonb),'[]'::jsonb);
        IF class_name='REVOKED' THEN
            -- canSelect() уже ложен до чтения селекторов: остаются только
            -- координаты реальных OLD members и журнала. Их записи сохраняются.
            held:=prepared#>ARRAY['member_projects','projects',identifier];
            IF typ<>'iam.project' OR held IS NULL OR (held<>'null'::jsonb AND held#>>'{native,2,id}' IS DISTINCT FROM identifier)
                OR entry->'Present' IS DISTINCT FROM to_jsonb(held<>'null'::jsonb)
                OR old_desired<>'[]'::jsonb OR new_desired<>'[]'::jsonb THEN
                RAISE EXCEPTION 'revoked binding coordinate or contribution differs' USING ERRCODE='42501';END IF;
            coordinate_effects:=coordinate_effects||jsonb_build_object(key_value,jsonb_build_object('upsert_members','{}'::jsonb,
                'remove_members','{}'::jsonb,'add_ledger','[]'::jsonb,'remove_ledger','[]'::jsonb));
            CONTINUE;
        END IF;
        IF typ='iam.project' THEN
            held:=prepared#>ARRAY['member_projects','projects',identifier];native:=held#>'{native,2}';
            graph:=jsonb_build_object('object_type',typ,'object_id',identifier,'present',held<>'null'::jsonb,'projection',native,
                'current_accounts',CASE WHEN native IS NULL THEN '[]'::jsonb ELSE jsonb_build_array(native->'account_id') END,
                'current_project',coalesce(native->>'id',''),'ancestors','[]'::jsonb);
            IF native IS NOT NULL THEN graph:=graph||jsonb_build_object('nested_project',(held->'graph')-'required');END IF;
            project_new:=kaname._authority_role_move_project_member_certificate_v1(p_binding_id,identifier,new_desired,p_rows-used_rows,p_reads-used_reads);
            used_rows:=used_rows+(project_new->>'rows')::integer;used_reads:=used_reads+(project_new->>'reads')::integer;
            effect:=project_new-ARRAY['binding_id','role_id','coordinate','class','present','decision_at','member_projects_sha256','desired','rows','reads'];
        ELSE
            held:=decision#>ARRAY['finite_positions',key_value];native:=held->'row';
            IF typ<>'iam.account' OR held->>'state' IS DISTINCT FROM 'present' OR native->>'id' IS DISTINCT FROM identifier THEN
                RAISE EXCEPTION 'whole binding account coordinate not held' USING ERRCODE='42501';END IF;
            IF used_reads>=p_reads THEN RAISE EXCEPTION 'binding account read exceeds budget' USING ERRCODE='54000';END IF;
            used_reads:=used_reads+1;
            SELECT jsonb_build_object('generation',jsonb_build_array(a.xmin::text,a.ctid::text),
                'row',jsonb_build_object('id',a.id,'labels',a.labels,'access_labels',a.access_labels)) INTO actual FROM ONLY kaname.accounts a WHERE a.id=identifier;
            IF actual IS DISTINCT FROM held-'state' THEN RAISE EXCEPTION 'binding account row changed' USING ERRCODE='40001';END IF;
            graph:=jsonb_build_object('object_type',typ,'object_id',identifier,'present',true,'projection',native,
                'current_accounts',jsonb_build_array(identifier),'current_project','','ancestors','[]'::jsonb);
            new_graph:=graph;copied:=false;
            FOR copy_command IN SELECT c FROM jsonb_array_elements(decision->'commands') c WHERE c->>'root_type'=typ AND c->>'root_id'=identifier LOOP
                IF copied OR copy_command#>'{physical,0}' IS DISTINCT FROM held#>'{generation,0}'
                    OR copy_command#>'{physical,1}' IS DISTINCT FROM held#>'{generation,1}'
                    OR (copy_command#>'{physical,2}' @> native) IS DISTINCT FROM true OR kaname.access_labels_valid_v1(copy_command->'access_labels') IS DISTINCT FROM true THEN
                    RAISE EXCEPTION 'binding account copy differs' USING ERRCODE='40001';END IF;
                copied:=true;new_graph:=jsonb_set(new_graph,'{projection,access_labels}',copy_command->'access_labels',false);
            END LOOP;
            IF class_name='ACTIVE' THEN
                step:=kaname._authority_role_move_account_member_certificate_v1(p_binding_id,identifier,new_desired,p_rows-used_rows,p_reads-used_reads);
                used_rows:=used_rows+(step->>'rows')::integer;used_reads:=used_reads+(step->>'reads')::integer;
            ELSE
                step:=kaname._authority_resource_coordinate_certificate_v2(new_index,catalog,p_binding_id,new_graph,new_desired);
                used_rows:=used_rows+(step->>'work')::integer;
            END IF;
            used_rows:=used_rows+2*jsonb_array_length(member_images)+jsonb_array_length(ledger_images)+5*jsonb_array_length(new_desired);
            SELECT coalesce(sum(jsonb_array_length(coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb))),0) INTO counted FROM jsonb_array_elements(new_desired) d;
            IF 4*counted>p_rows-used_rows THEN RAISE EXCEPTION 'binding account local effect exceeds budget' USING ERRCODE='54000';END IF;
            used_rows:=used_rows+4*counted::integer;
            IF EXISTS(SELECT FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
                AND m#>>'{2,object_type}'='iam.account' AND m#>>'{2,object_id}'=identifier
                AND m#>>'{2,role_id}' IS DISTINCT FROM role_id) THEN RAISE EXCEPTION 'account member role differs' USING ERRCODE='42501';END IF;
            SELECT coalesce(jsonb_object_agg(m#>>'{2,rule_fp}',m#>'{2,verification_status}'),'{}'::jsonb) INTO old_members
                FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
                    AND m#>>'{2,object_type}'='iam.account' AND m#>>'{2,object_id}'=identifier;
            SELECT coalesce(jsonb_object_agg(t::text,t),'{}'::jsonb) INTO old_ledger FROM (
                SELECT jsonb_build_object('User',l#>'{2,fga_user}','Relation',l#>'{2,relation}','Object',l#>'{2,object}') AS t
                FROM jsonb_array_elements(ledger_images) l WHERE l#>>'{2,binding_id}'=p_binding_id AND l#>>'{2,source}'='member'
                    AND l#>>'{2,member_object_type}'='iam.account' AND l#>>'{2,member_object_id}'=identifier) old_rows;
            IF EXISTS(SELECT FROM jsonb_array_elements(new_desired) d GROUP BY d->>'RuleFP' HAVING count(DISTINCT d->>'Status')>1) THEN
                RAISE EXCEPTION 'conflicting account member contributions' USING ERRCODE='42501';
            END IF;
            SELECT coalesce(jsonb_object_agg(d->>'RuleFP',d->'Status'),'{}'::jsonb) INTO proposed_members FROM jsonb_array_elements(new_desired) d;
            SELECT coalesce(jsonb_object_agg(t.value::text,t.value),'{}'::jsonb) INTO proposed_ledger
                FROM jsonb_array_elements(new_desired) d CROSS JOIN LATERAL jsonb_array_elements(
                    coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb)) t WHERE d->>'Status'='ACTIVE';
            SELECT coalesce(jsonb_object_agg(v.key,v.value),'{}'::jsonb) INTO member_add FROM jsonb_each(proposed_members) v
                WHERE class_name='ACTIVE' AND old_members->v.key IS DISTINCT FROM v.value;
            SELECT coalesce(jsonb_object_agg(v.key,v.value),'{}'::jsonb) INTO member_remove FROM jsonb_each(old_members) v
                WHERE class_name='ACTIVE' AND NOT (proposed_members ? v.key);
            SELECT coalesce(jsonb_agg(v.value ORDER BY v.key COLLATE "C"),'[]'::jsonb) INTO ledger_add FROM jsonb_each(proposed_ledger) v
                WHERE class_name='ACTIVE' AND NOT (old_ledger ? v.key);
            SELECT coalesce(jsonb_agg(v.value ORDER BY v.key COLLATE "C"),'[]'::jsonb) INTO ledger_remove FROM jsonb_each(old_ledger) v
                WHERE class_name='ACTIVE' AND NOT (proposed_ledger ? v.key);
            effect:=jsonb_build_object('upsert_members',member_add,'remove_members',member_remove,'add_ledger',ledger_add,'remove_ledger',ledger_remove);
        END IF;
        coordinate_effects:=coordinate_effects||jsonb_build_object(key_value,effect);
        IF entry->'Present' IS DISTINCT FROM graph->'present' THEN RAISE EXCEPTION 'binding project/account presence differs' USING ERRCODE='42501';END IF;
        step:=kaname._authority_resource_coordinate_certificate_v2(old_index,catalog,p_binding_id,graph,old_desired);
        used_rows:=used_rows+(step->>'work')::integer+jsonb_array_length(old_desired)+jsonb_array_length(new_desired);
        IF used_rows>p_rows THEN RAISE EXCEPTION 'whole binding member work exceeds budget' USING ERRCODE='54000';END IF;
        IF class_name='ACTIVE' THEN
            FOR confirmed IN SELECT value FROM jsonb_array_elements(jsonb_build_array(old_desired,new_desired)) WITH ORDINALITY q(value,ord) ORDER BY ord LOOP
                SELECT coalesce(sum(jsonb_array_length(coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb))),0) INTO counted
                    FROM jsonb_array_elements(confirmed) d WHERE d->>'Status'='ACTIVE';
                IF counted>p_rows-used_rows THEN RAISE EXCEPTION 'binding claim work exceeds budget' USING ERRCODE='54000';END IF;
                used_rows:=used_rows+counted::integer;
                SELECT coalesce(jsonb_object_agg(t.value::text,t.value),'{}'::jsonb) INTO claims FROM jsonb_array_elements(confirmed) d
                    CROSS JOIN LATERAL jsonb_array_elements(coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb)) t WHERE d->>'Status'='ACTIVE';
                IF confirmed=old_desired THEN old_claims:=old_claims||claims;END IF;
                IF confirmed=new_desired THEN new_claims:=new_claims||claims;END IF;
            END LOOP;
        END IF;
    END LOOP;
    SELECT coalesce(jsonb_agg(v.value ORDER BY v.key COLLATE "C"),'[]'::jsonb) INTO lost FROM jsonb_each(old_claims) v WHERE NOT (new_claims ? v.key);
    SELECT coalesce(jsonb_agg(t ORDER BY t),'[]'::jsonb) INTO residual FROM (
        SELECT DISTINCT jsonb_build_object('User',l#>'{2,fga_user}','Relation',l#>'{2,relation}','Object',l#>'{2,object}') t
        FROM jsonb_array_elements(prepared#>'{binding_census,ledger}') l WHERE l#>>'{2,binding_id}'=p_binding_id AND l#>>'{2,source}'='member') ledger
        WHERE NOT (new_claims ? t::text);
    result:=jsonb_build_object('binding_id',p_binding_id,'class',class_name,'coordinates',expected,'effects',coordinate_effects,'before_claims',old_claims,
        'proposed_claims',new_claims,'lost_claims',lost,'unclaimed_ledger',residual,'rows',used_rows,'reads',used_reads);
    IF octet_length(result::text)>8388608 THEN RAISE EXCEPTION 'whole binding receipt exceeds byte budget' USING ERRCODE='54000';END IF;
    RETURN result;
END;
$binding_set$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)'::regprocedure;
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
-- Доступная часть проверки всех прямых выдач одной роли. Остаточное снятие
-- требует самостоятельного доказательства для сторонних держателей.
CREATE FUNCTION kaname._authority_role_move_direct_member_sets_v1(p_sets jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $member_sets$
DECLARE
    program jsonb:=kaname._authority_sequence_store_v3();proof jsonb:=kaname._authority_role_move_attestation_v1();
    prepared jsonb:=program#>'{frozen,selector_move}'; decision jsonb:=program#>'{frozen,selector_move_decision}';
    census jsonb:=prepared->'binding_census';ids jsonb;covered jsonb:='{}'::jsonb;future jsonb:='{}'::jsonb;
    candidates jsonb:='{}'::jsonb;receipt jsonb;step jsonb;b record;result jsonb;
    used_rows integer:=3;used_reads integer:=2;id_count integer;
BEGIN
    IF jsonb_typeof(p_sets) IS DISTINCT FROM 'object' OR coalesce(prepared->>'role_id','')=''
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR jsonb_typeof(census->'bindings') IS DISTINCT FROM 'array'
        OR decision->>'role_id' IS DISTINCT FROM prepared->>'role_id' THEN RAISE EXCEPTION 'whole role member proof outside decision' USING ERRCODE='42501';END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_sets::text)>8388608 THEN RAISE EXCEPTION 'whole role members input exceeds budget' USING ERRCODE='54000';END IF;
    step:=kaname._authority_role_move_binding_census_v1(prepared->>'role_id',census,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(step->>'rows')::integer+jsonb_array_length(census->'bindings');used_reads:=used_reads+(step->>'reads')::integer;
    IF step->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN RAISE EXCEPTION 'whole role binding census changed' USING ERRCODE='40001';END IF;
    SELECT coalesce(jsonb_object_agg(v#>>'{2,id}',true),'{}'::jsonb),count(*) INTO ids,id_count FROM jsonb_array_elements(census->'bindings') v
        WHERE v#>>'{2,role_id}'=prepared->>'role_id';
    IF id_count=0 OR id_count<>(SELECT count(*) FROM jsonb_object_keys(p_sets))
        OR EXISTS(SELECT FROM jsonb_object_keys(ids) x WHERE NOT (p_sets ? x)) THEN
        RAISE EXCEPTION 'whole role binding set differs' USING ERRCODE='42501';END IF;
    FOR b IN SELECT s.key,s.value FROM jsonb_each(p_sets) s ORDER BY s.key COLLATE "C" LOOP
        receipt:=kaname._authority_role_move_binding_member_set_v1(b.key,b.value,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(receipt->>'rows')::integer+jsonb_array_length(receipt->'lost_claims')+jsonb_array_length(receipt->'unclaimed_ledger')
            +(SELECT count(*) FROM jsonb_object_keys(receipt->'proposed_claims'));
        used_reads:=used_reads+(receipt->>'reads')::integer;
        IF used_rows>p_rows THEN RAISE EXCEPTION 'whole role tuple work exceeds budget' USING ERRCODE='54000';END IF;
        future:=future||(receipt->'proposed_claims');
        -- История PENDING сохраняется, однако её журнал не удерживает общий факт.
        SELECT candidates||coalesce(jsonb_object_agg(t::text,t),'{}'::jsonb) INTO candidates
            FROM jsonb_array_elements((receipt->'lost_claims')||(receipt->'unclaimed_ledger')) t;
        covered:=covered||jsonb_build_object(b.key,encode(sha256(convert_to(b.value::text,'UTF8')),'hex'));
        IF octet_length(future::text)+octet_length(candidates::text)+octet_length(covered::text)>8388608 THEN
            RAISE EXCEPTION 'whole role tuple proof exceeds byte budget' USING ERRCODE='54000';END IF;
    END LOOP;
    IF EXISTS(SELECT FROM jsonb_object_keys(candidates) k WHERE NOT (future ? k)) THEN
        RAISE EXCEPTION 'global member tuple removal lacks independent holder proof' USING ERRCODE='42501';END IF;
    result:=jsonb_build_object('bindings',covered,'proposed_claims',future,'rows',used_rows,'reads',used_reads);
    RETURN result;
END;
$member_sets$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_direct_member_sets_v1(jsonb,integer,integer)'::regprocedure;
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
DO $member_project_graph$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8','4b7c03ddafb6230c6705eb3e08e9dbae4982554ae3e8ac84063c3c6625bfe427',$changes$[
  [
    "selector_states jsonb;new_role_index",
    "selector_states jsonb;old_role_index jsonb:='{}'::jsonb;logical_role jsonb;member_index jsonb;new_role_index"
  ],
  [
    "'items','[]'::jsonb,'new_role_index'",
    "'items','[]'::jsonb,'old_role_index','{}'::jsonb,'new_role_index'"
  ],
  [
    "        IF side='new' THEN\n            -- Этим представлением проверяют семантику NEW. Пустые позиции версий\n            -- не означают физические строки и не участвуют в повторном чтении OLD.\n            materialized:=kaname._authority_resource_withdrawal_role_images_v2(role_row,role_row->'rules',\n                compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n                '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n                catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n            used_rows:=used_rows+(materialized->>'work')::integer;\n            IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n            IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n                RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n            END IF;\n            SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n                ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n                FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n            new_role_index:=jsonb_build_object(\n                jsonb_build_array(12,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,new_role))),\n                jsonb_build_array(13,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n            IF octet_length(new_role_index::text)>8388608 THEN\n                RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n            END IF;\n        END IF;",
    "        -- OLD использует удержанную раскладку отпечатков. Для NEW сохраняем\n        -- исходную запись роли. Оба индекса служат чистому вычислению членов.\n        logical_role:=CASE WHEN side='new' THEN new_role ELSE jsonb_set(role_row,'{rules}',layout,false) END;\n        materialized:=kaname._authority_resource_withdrawal_role_images_v2(logical_role,logical_role->'rules',\n            compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n            '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n            catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n        used_rows:=used_rows+(materialized->>'work')::integer;\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n        IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n            RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n        END IF;\n        SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n            ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n            FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n        member_index:=jsonb_build_object(\n            jsonb_build_array(12,'role',role_id,'')::text,\n                jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,logical_role))),\n            jsonb_build_array(13,'role',role_id,'')::text,\n                jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n        IF octet_length(member_index::text)>8388608 THEN\n            RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n        END IF;\n        IF side='new' THEN new_role_index:=member_index;ELSE old_role_index:=member_index;END IF;"
  ],
  [
    "'new_role_index',new_role_index);",
    "'old_role_index',old_role_index,'new_role_index',new_role_index);"
  ]
]$changes$::jsonb),
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c','6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777',$changes$[
  [
    "    IF scope_known IS DISTINCT FROM true THEN RAISE EXCEPTION 'project outside confirmed binding coordinates'",
    "    IF scope_known IS DISTINCT FROM true THEN\n        observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n        used_rows:=used_rows+(observed->>'rows')::integer;\n        scope_known:=(observed->'positions') ? ('iam.project:'||p_project_id);\n    END IF;\n    IF scope_known IS DISTINCT FROM true THEN RAISE EXCEPTION 'project outside confirmed binding coordinates'"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6','0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d',$changes$[
  [
    "76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8",
    "4b7c03ddafb6230c6705eb3e08e9dbae4982554ae3e8ac84063c3c6625bfe427"
  ],
  [
    "93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c",
    "6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777"
  ],
  [
    " ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','e2e79305218512b68a200fa43947585a859010fee955656ff199552457674ceb',false,'v',true,'private'),\n",
    " ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','e2e79305218512b68a200fa43947585a859010fee955656ff199552457674ceb',false,'v',true,'private'),\n ('_authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer)','2ba6c07cc5cc769c93da5453ded70b90e6411e178c7cb40548a14e58395017ef',false,'i',true,'private'),\n ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1',false,'v',true,'private'),\n ('_authority_role_move_direct_member_sets_v1(jsonb,integer,integer)','4ce049c2e7b207edd738004564c90fe66a3d8f564c879993c567c996b825be30',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n",
    "  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n  ('_authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer)','jsonb',4,ARRAY['p_prepared','p_decision','p_binding_id','p_rows']),\n  ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_binding_id','p_coordinates','p_rows','p_reads']),\n  ('_authority_role_move_direct_member_sets_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87','6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18',$changes$[
  [
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6",
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','f8acf975bc2d6d91f7289893f776e4a3eb39bbd934cc8da97a36e00f65bd8de2','0ad2b530fe004c714ec1b5a3e156c06e93e1232dfd6267a452486e5a89f827c9',$changes$[
  [
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6",
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d"
  ],
  [
    "34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87",
    "6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18"
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
        ('authority_metadata_service_account_access_label_ready_v1()','0ad2b530fe004c714ec1b5a3e156c06e93e1232dfd6267a452486e5a89f827c9','f8acf975bc2d6d91f7289893f776e4a3eb39bbd934cc8da97a36e00f65bd8de2',$changes$[
  [
    "6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18",
    "34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87"
  ],
  [
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d",
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','6dd773315b80c6262d317ee415bf5092f038f616ec62054cea869e0683c80d18','34249a7fad31911e774e742e639fc2da218cc2b717c7d0042b0eb8e83b543b87',$changes$[
  [
    "0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d",
    "89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','0eb2a9eb2edcd6a5f4213dcf4f7570fe4ccac0d62a9939e863643756bf03c76d','89f8acae90ab236517522e7cffb267ae4f2fb32d4b681e6908fdf2af40d4e5e6',$changes$[
  [
    "  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n  ('_authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer)','jsonb',4,ARRAY['p_prepared','p_decision','p_binding_id','p_rows']),\n  ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_binding_id','p_coordinates','p_rows','p_reads']),\n  ('_authority_role_move_direct_member_sets_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_sets','p_rows','p_reads']),\n",
    "  ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','jsonb',4,ARRAY['p_project_id','p_native','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','e2e79305218512b68a200fa43947585a859010fee955656ff199552457674ceb',false,'v',true,'private'),\n ('_authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer)','2ba6c07cc5cc769c93da5453ded70b90e6411e178c7cb40548a14e58395017ef',false,'i',true,'private'),\n ('_authority_role_move_binding_member_set_v1(text,jsonb,integer,integer)','b11af1204ac687ac4aecb24ca5a699c927a0915b3bcc13acb64fd34102179ea1',false,'v',true,'private'),\n ('_authority_role_move_direct_member_sets_v1(jsonb,integer,integer)','4ce049c2e7b207edd738004564c90fe66a3d8f564c879993c567c996b825be30',false,'v',true,'private'),\n",
    " ('_authority_role_move_project_member_graph_hold_v1(text,jsonb,integer,integer)','e2e79305218512b68a200fa43947585a859010fee955656ff199552457674ceb',false,'v',true,'private'),\n"
  ],
  [
    "6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777",
    "93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c"
  ],
  [
    "4b7c03ddafb6230c6705eb3e08e9dbae4982554ae3e8ac84063c3c6625bfe427",
    "76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8"
  ]
]$changes$::jsonb),
        ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','6a30089babf2c3ddedec74234be9a628977189307af66c0dda1d6bdaf9b2c777','93dd921bfd7a4cbb746fd451a487e66ad3c849e4218778624a0e6aed54627a4c',$changes$[
  [
    "    IF scope_known IS DISTINCT FROM true THEN\n        observed:=kaname._authority_role_move_binding_direct_positions_v1(prepared,decision,p_binding_id,p_rows-used_rows);\n        used_rows:=used_rows+(observed->>'rows')::integer;\n        scope_known:=(observed->'positions') ? ('iam.project:'||p_project_id);\n    END IF;\n    IF scope_known IS DISTINCT FROM true THEN RAISE EXCEPTION 'project outside confirmed binding coordinates'",
    "    IF scope_known IS DISTINCT FROM true THEN RAISE EXCEPTION 'project outside confirmed binding coordinates'"
  ]
]$changes$::jsonb),
        ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','4b7c03ddafb6230c6705eb3e08e9dbae4982554ae3e8ac84063c3c6625bfe427','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',$changes$[
  [
    "'old_role_index',old_role_index,'new_role_index',new_role_index);",
    "'new_role_index',new_role_index);"
  ],
  [
    "        -- OLD использует удержанную раскладку отпечатков. Для NEW сохраняем\n        -- исходную запись роли. Оба индекса служат чистому вычислению членов.\n        logical_role:=CASE WHEN side='new' THEN new_role ELSE jsonb_set(role_row,'{rules}',layout,false) END;\n        materialized:=kaname._authority_resource_withdrawal_role_images_v2(logical_role,logical_role->'rules',\n            compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n            '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n            catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n        used_rows:=used_rows+(materialized->>'work')::integer;\n        IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n        IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n            RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n        END IF;\n        SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n            ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n            FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n        member_index:=jsonb_build_object(\n            jsonb_build_array(12,'role',role_id,'')::text,\n                jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,logical_role))),\n            jsonb_build_array(13,'role',role_id,'')::text,\n                jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n        IF octet_length(member_index::text)>8388608 THEN\n            RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n        END IF;\n        IF side='new' THEN new_role_index:=member_index;ELSE old_role_index:=member_index;END IF;",
    "        IF side='new' THEN\n            -- Этим представлением проверяют семантику NEW. Пустые позиции версий\n            -- не означают физические строки и не участвуют в повторном чтении OLD.\n            materialized:=kaname._authority_resource_withdrawal_role_images_v2(role_row,role_row->'rules',\n                compiled||jsonb_build_object('verbs','[]'::jsonb,'refs','[]'::jsonb),'null'::jsonb,\n                '{\"selectors\":[],\"verbs\":[],\"refs\":[],\"create_rules\":[],\"bind_rules\":[],\"pending\":[]}'::jsonb,\n                catalog,transaction_timestamp(),(proof->>'decision_at')::timestamptz);\n            used_rows:=used_rows+(materialized->>'work')::integer;\n            IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member projection work exceeds budget' USING ERRCODE='54000';END IF;\n            IF jsonb_typeof(materialized#>'{projections,selectors}') IS DISTINCT FROM 'array' THEN\n                RAISE EXCEPTION 'selector member projection missing' USING ERRCODE='42501';\n            END IF;\n            SELECT coalesce(jsonb_agg(jsonb_build_array(NULL::text,NULL::text,v)\n                ORDER BY (v->>'rule_fp') COLLATE \"C\"),'[]'::jsonb) INTO selector_states\n                FROM jsonb_array_elements(materialized#>'{projections,selectors}') v;\n            new_role_index:=jsonb_build_object(\n                jsonb_build_array(12,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',jsonb_build_array(jsonb_build_array(NULL::text,NULL::text,new_role))),\n                jsonb_build_array(13,'role',role_id,'')::text,\n                    jsonb_build_object('source','{}'::jsonb,'states',selector_states));\n            IF octet_length(new_role_index::text)>8388608 THEN\n                RAISE EXCEPTION 'selector member projection bytes exceed budget' USING ERRCODE='54000';\n            END IF;\n        END IF;"
  ],
  [
    "'items','[]'::jsonb,'old_role_index','{}'::jsonb,'new_role_index'",
    "'items','[]'::jsonb,'new_role_index'"
  ],
  [
    "selector_states jsonb;old_role_index jsonb:='{}'::jsonb;logical_role jsonb;member_index jsonb;new_role_index",
    "selector_states jsonb;new_role_index"
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

DROP FUNCTION kaname._authority_role_move_direct_member_sets_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_binding_member_set_v1(text,jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_binding_direct_positions_v1(jsonb,jsonb,text,integer);
