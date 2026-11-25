-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Сертификат одной удержанной координаты участника. Единственный вход
-- внешнего компилятора — набор предполагаемых членов; строки и часы
-- восстанавливает закрытая программа владельца.
CREATE FUNCTION kaname._authority_role_move_project_member_certificate_v1(
    p_binding_id text,p_project_id text,p_desired jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $project_member$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3();
    frozen jsonb:=program->'frozen';
    prepared jsonb:=frozen->'selector_move';
    decision jsonb:=frozen->'selector_move_decision';
    plan jsonb:=decision->'predicate_plan';
    role_id text:=prepared->>'role_id';
    holder jsonb:=decision#>ARRAY['binding_new',p_binding_id];
    universe jsonb:=prepared->'member_projects';
    receipt jsonb:=universe#>ARRAY['projects',p_project_id];
    selected_class text:=holder->>'class';
    member_images jsonb:=prepared#>'{binding_census,members}';
    ledger_images jsonb:=prepared#>'{binding_census,ledger}';
    old_members jsonb;
    old_ledger jsonb;
    proposed_members jsonb;
    proposed_ledger jsonb;
    member_add jsonb;member_remove jsonb;ledger_add jsonb;ledger_remove jsonb;
    commands_seen jsonb:='{}'::jsonb;
    native jsonb;
    held_sources jsonb;
    old_physical jsonb;
    source_key text;
    command jsonb;
    tuple_count bigint;
    physical_catalog jsonb;
    nested jsonb;
    scope_known boolean;
    observed jsonb;
    decision_at timestamptz;
    census jsonb;
    binding_triples jsonb;
    subject_triples jsonb;
    bindings jsonb:=prepared#>'{binding_census,bindings}';
    subjects jsonb:=prepared#>'{binding_census,subjects}';
    binding jsonb;
    logical_binding jsonb;
    current_role_image jsonb;
    graph jsonb;
    logical_index jsonb:=plan->'new_role_index';
    catalog_row record;
    verified jsonb;
    used_rows integer;
    used_reads integer:=8;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 4 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096
        OR octet_length(p_desired::text)>8388608 THEN
        RAISE EXCEPTION 'selector member coordinate budget exceeded' USING ERRCODE='54000';
    END IF;
    IF p_binding_id IS NULL OR octet_length(p_binding_id) NOT BETWEEN 1 AND 16384
        OR p_project_id IS NULL OR octet_length(p_project_id) NOT BETWEEN 1 AND 16384
        OR p_binding_id ~ '[:#*[:space:][:cntrl:]]' OR p_project_id ~ '[:#*[:space:][:cntrl:]]'
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
        OR coalesce(selected_class,'') NOT IN ('ACTIVE','PENDING')
        OR decision#>>ARRAY['binding_status',p_binding_id] IS DISTINCT FROM selected_class
        OR jsonb_typeof(plan->'items') IS DISTINCT FROM 'array'
        OR jsonb_typeof(decision#>'{local_label_candidates,items}') IS DISTINCT FROM 'array'
        OR jsonb_typeof(member_images) IS DISTINCT FROM 'array' OR jsonb_typeof(ledger_images) IS DISTINCT FROM 'array'
        OR jsonb_typeof(universe->'projects') IS DISTINCT FROM 'object' OR receipt IS NULL
        OR decision->>'member_projects_sha256' IS DISTINCT FROM encode(sha256(convert_to(universe::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'selector member coordinate outside held project decision' USING ERRCODE='42501';
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
    used_rows:=used_rows+5*jsonb_array_length(member_images)+4*jsonb_array_length(ledger_images)+6*jsonb_array_length(p_desired)
        +6*jsonb_array_length(plan->'items')+jsonb_array_length(decision#>'{local_label_candidates,items}');
    IF used_rows>p_rows THEN RAISE EXCEPTION 'project contribution scope exceeds budget' USING ERRCODE='54000';END IF;
    IF NOT EXISTS(SELECT FROM jsonb_array_elements(plan->'holders') h WHERE h->>'binding_id'=p_binding_id) THEN
        RAISE EXCEPTION 'project member lacks a held binding' USING ERRCODE='42501';
    END IF;
    -- Координата подтверждается историей выдачи, собственной областью,
    -- именованным проектом или завершённым отбором прямого селектора меток.
    SELECT holder->'scope'=jsonb_build_array('project',p_project_id)
        OR EXISTS(SELECT FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
            AND m#>>'{2,role_id}'=role_id AND m#>>'{2,object_type}'='iam.project' AND m#>>'{2,object_id}'=p_project_id)
        OR EXISTS(SELECT FROM jsonb_array_elements(ledger_images) l WHERE l#>>'{2,binding_id}'=p_binding_id
            AND l#>>'{2,source}'='member' AND l#>>'{2,member_object_type}'='iam.project' AND l#>>'{2,member_object_id}'=p_project_id)
        OR (decision#>>ARRAY['finite_positions','iam.project:'||p_project_id,'state']='present'
            AND EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i WHERE i->>'binding_id'=p_binding_id
                AND i->>'read_type'='iam.project' AND NOT (i ? 'child_predicate') AND i->>'guard'='objects'
                AND i#>>'{predicate,Arm}'='1' AND i->'object_ids' ? p_project_id)
            AND kaname._authority_resource_contained_v2(holder#>>'{scope,0}',holder#>>'{scope,1}',
                jsonb_build_array(receipt#>'{native,2,account_id}'),p_project_id))
        OR EXISTS(SELECT FROM jsonb_array_elements(decision#>'{local_label_candidates,items}') i
            JOIN LATERAL (SELECT plan->'items'->((i->>'plan_item')::integer-1) AS item) h ON true
            WHERE i->>'binding_id'=p_binding_id AND i->>'read_type'='iam.project' AND i->>'state'='complete'
            AND (i->'candidate_ids') ? p_project_id AND h.item->>'binding_id'=p_binding_id
            AND h.item->>'read_type'='iam.project' AND NOT (h.item ? 'child_predicate'))
        INTO scope_known;
    IF scope_known IS DISTINCT FROM true THEN RAISE EXCEPTION 'project outside confirmed binding coordinates' USING ERRCODE='42501';END IF;
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
        OR binding->>'status' IS DISTINCT FROM selected_class OR binding->>'revoked_at' IS NOT NULL
        OR (binding->>'expires_at')::timestamptz<=decision_at THEN
        RAISE EXCEPTION 'selector member coordinate lacks a current role holder' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO current_role_image
        FROM ONLY kaname.roles r WHERE r.id=role_id;
    IF current_role_image IS DISTINCT FROM prepared#>'{role,physical}' THEN
        RAISE EXCEPTION 'selector member coordinate role source changed' USING ERRCODE='40001';
    END IF;
    observed:=kaname._authority_role_move_selector_versions_v1(role_id,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(observed->>'rows')::integer;used_reads:=used_reads+(observed->>'reads')::integer;
    IF observed->'versions' IS DISTINCT FROM prepared->'selector_versions' THEN
        RAISE EXCEPTION 'project member role selector generations changed' USING ERRCODE='40001';
    END IF;
    -- Блокировка родной таблицы охватывает отрицательную координату и остаётся
    -- обязательной после finalize, в том числе при повторном вызове в той же TX.
    IF NOT EXISTS(SELECT FROM pg_locks l WHERE l.pid=pg_backend_pid() AND l.granted AND l.locktype='relation'
            AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND l.mode='ShareLock'
            AND l.relation='kaname.projects'::regclass) THEN RAISE EXCEPTION 'held project census lock missing' USING ERRCODE='42501';END IF;
    SELECT jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p)) INTO native FROM ONLY kaname.projects p WHERE p.id=p_project_id;
    IF receipt='null'::jsonb THEN
        IF native IS NOT NULL THEN RAISE EXCEPTION 'absent project appeared' USING ERRCODE='40001';END IF;
        graph:=jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',false,
            'projection',NULL,'current_accounts','[]'::jsonb,'current_project','','ancestors','[]'::jsonb);
    ELSE
        IF native IS NULL OR native IS DISTINCT FROM receipt->'native' THEN RAISE EXCEPTION 'project source changed' USING ERRCODE='40001';END IF;
        observed:=kaname._authority_role_move_project_member_graph_hold_v1(p_project_id,native,p_rows-used_rows,p_reads-used_reads);
        used_rows:=used_rows+(observed->>'rows')::integer;used_reads:=used_reads+(observed->>'reads')::integer;
        IF observed IS DISTINCT FROM receipt THEN RAISE EXCEPTION 'member project graph changed' USING ERRCODE='40001';END IF;
        held_sources:=receipt->'sources';
        -- Замена меток только у физических строк из сохранённого графа.
        FOR command IN SELECT value FROM jsonb_array_elements(decision->'commands') LOOP
            source_key:=CASE command->>'root_type'
                WHEN 'iam.account' THEN jsonb_build_array(30,'iam.account',command->>'root_id','')::text
                WHEN 'iam.project' THEN jsonb_build_array(1,'project',command->>'root_id','')::text END;
            IF source_key IS NULL OR (NOT (held_sources ? source_key)
                AND NOT (command->>'root_type'='iam.project' AND command->>'root_id'=p_project_id)) THEN CONTINUE;END IF;
            IF commands_seen ? source_key OR kaname.access_labels_valid_v1(command->'access_labels') IS DISTINCT FROM true THEN
                RAISE EXCEPTION 'invalid or duplicate selected project graph command' USING ERRCODE='42501';
            END IF;
            commands_seen:=commands_seen||jsonb_build_object(source_key,true);
            old_physical:=command->'physical';
            IF command->>'root_type'='iam.project' AND command->>'root_id'=p_project_id THEN
                IF old_physical IS DISTINCT FROM native THEN RAISE EXCEPTION 'project copy physical source differs' USING ERRCODE='40001';END IF;
                native:=jsonb_set(native,'{2,access_labels}',command->'access_labels',false);
            END IF;
            IF held_sources ? source_key THEN
                IF held_sources#>ARRAY[source_key,'states'] IS DISTINCT FROM jsonb_build_array(old_physical)
                    OR jsonb_typeof(old_physical) IS DISTINCT FROM 'array' THEN
                    RAISE EXCEPTION 'ancestor copy physical source differs' USING ERRCODE='40001';
                END IF;
                held_sources:=jsonb_set(held_sources,ARRAY[source_key,'states','0','2','access_labels'],command->'access_labels',false);
            END IF;
        END LOOP;
        SELECT jsonb_build_object('Live',jsonb_build_object('Resources',coalesce(jsonb_agg(jsonb_build_object('Module','iam',
            'Resource',substring(c#>>'{2,dotted}' from 5),'ObjectType',c#>'{2,object_type}')),'[]'::jsonb))) INTO physical_catalog
            FROM jsonb_array_elements(receipt->'catalog') c;
        graph:=jsonb_build_object('object_type','iam.project','object_id',p_project_id,'present',true,'projection',native->2,
            'current_accounts',jsonb_build_array(native#>>'{2,account_id}'),'current_project',p_project_id,'ancestors','[]'::jsonb);
        nested:=kaname._authority_resource_project_graph_v3(held_sources,physical_catalog,graph);
        -- Текущий граф удерживает родные аккаунты-предки. Для вложенной ветви
        -- иного физического типа понадобится его самостоятельная проекция.
        IF EXISTS(SELECT FROM jsonb_array_elements(plan->'items') i
            JOIN LATERAL jsonb_array_elements(coalesce(held_sources#>ARRAY[jsonb_build_array(3,
                (SELECT c#>>'{2,object_type}' FROM jsonb_array_elements(receipt->'catalog') c WHERE c#>>'{2,dotted}'='iam.project'),
                p_project_id,'')::text,'states'],'[]'::jsonb)) e ON true
            WHERE i->>'binding_id'=p_binding_id AND i->>'child_type'='iam.project' AND i->>'read_type'<>'iam.account'
                AND i->>'model'=e#>>'{2,parent_type}') THEN
            RAISE EXCEPTION 'project coordinate needs additional ancestor projection' USING ERRCODE='42501';
        END IF;
        graph:=graph||jsonb_build_object('nested_project',nested-'required');
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
    -- PENDING судим как будущую активацию только внутри чистого вычисления.
    logical_binding:=jsonb_set(binding_triples,'{0,2,status}','"ACTIVE"'::jsonb,false);
    logical_index:=logical_index||jsonb_build_object(
        jsonb_build_array(8,'binding',p_binding_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',logical_binding),
        jsonb_build_array(9,'binding',p_binding_id,'')::text,jsonb_build_object('source','{}'::jsonb,'states',subject_triples));
    verified:=kaname._authority_resource_coordinate_certificate_v2(logical_index,
        convert_from(catalog_row.catalog_json,'UTF8')::jsonb,p_binding_id,graph,p_desired);
    used_rows:=used_rows+(verified->>'work')::integer;
    IF used_rows>p_rows THEN RAISE EXCEPTION 'selector member coordinate work exceeded' USING ERRCODE='54000';END IF;
    SELECT coalesce(sum(jsonb_array_length(coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb))),0)
        INTO tuple_count FROM jsonb_array_elements(verified->'desired') d;
    IF 6*tuple_count>p_rows-used_rows THEN RAISE EXCEPTION 'member project tuple budget exceeded' USING ERRCODE='54000';END IF;
    used_rows:=used_rows+6*tuple_count::integer;
    IF EXISTS(SELECT FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
        AND m#>>'{2,object_type}'='iam.project' AND m#>>'{2,object_id}'=p_project_id
        AND m#>>'{2,role_id}' IS DISTINCT FROM role_id) THEN RAISE EXCEPTION 'project member role differs' USING ERRCODE='42501';END IF;
    SELECT coalesce(jsonb_object_agg(m#>>'{2,rule_fp}',m#>'{2,verification_status}'),'{}'::jsonb) INTO old_members
        FROM jsonb_array_elements(member_images) m WHERE m#>>'{2,binding_id}'=p_binding_id
            AND m#>>'{2,object_type}'='iam.project' AND m#>>'{2,object_id}'=p_project_id;
    SELECT coalesce(jsonb_object_agg(t::text,t),'{}'::jsonb) INTO old_ledger FROM (
        SELECT jsonb_build_object('User',l#>'{2,fga_user}','Relation',l#>'{2,relation}','Object',l#>'{2,object}') AS t
        FROM jsonb_array_elements(ledger_images) l WHERE l#>>'{2,binding_id}'=p_binding_id AND l#>>'{2,source}'='member'
            AND l#>>'{2,member_object_type}'='iam.project' AND l#>>'{2,member_object_id}'=p_project_id) old_rows;
    IF EXISTS(SELECT FROM jsonb_array_elements(verified->'desired') d GROUP BY d->>'RuleFP' HAVING count(DISTINCT d->>'Status')>1) THEN
        RAISE EXCEPTION 'conflicting project member contributions' USING ERRCODE='42501';
    END IF;
    SELECT coalesce(jsonb_object_agg(d->>'RuleFP',d->'Status'),'{}'::jsonb) INTO proposed_members FROM jsonb_array_elements(verified->'desired') d;
    SELECT coalesce(jsonb_object_agg(t.value::text,t.value),'{}'::jsonb) INTO proposed_ledger
        FROM jsonb_array_elements(verified->'desired') d CROSS JOIN LATERAL jsonb_array_elements(
            coalesce(nullif(d->'Tuples','null'::jsonb),'[]'::jsonb)) t WHERE d->>'Status'='ACTIVE';
    SELECT coalesce(jsonb_object_agg(v.key,v.value),'{}'::jsonb) INTO member_add FROM jsonb_each(proposed_members) v
        WHERE selected_class='ACTIVE' AND old_members->v.key IS DISTINCT FROM v.value;
    SELECT coalesce(jsonb_object_agg(v.key,v.value),'{}'::jsonb) INTO member_remove FROM jsonb_each(old_members) v
        WHERE selected_class='ACTIVE' AND NOT (proposed_members ? v.key);
    SELECT coalesce(jsonb_agg(v.value ORDER BY v.key COLLATE "C"),'[]'::jsonb) INTO ledger_add FROM jsonb_each(proposed_ledger) v
        WHERE selected_class='ACTIVE' AND NOT (old_ledger ? v.key);
    SELECT coalesce(jsonb_agg(v.value ORDER BY v.key COLLATE "C"),'[]'::jsonb) INTO ledger_remove FROM jsonb_each(old_ledger) v
        WHERE selected_class='ACTIVE' AND NOT (proposed_ledger ? v.key);
    -- Это разность точных записей одной выдачи. Удаление общего факта FGA
    -- определяется совокупностью притязаний остальных выдач отдельной проверкой.
    observed:=jsonb_build_object('binding_id',p_binding_id,'role_id',role_id,'coordinate',jsonb_build_array('iam.project',p_project_id),
        'class',selected_class,'present',graph->'present','decision_at',decision_at,'member_projects_sha256',decision->'member_projects_sha256',
        'desired',verified->'desired','upsert_members',member_add,'remove_members',member_remove,
        'add_ledger',ledger_add,'remove_ledger',ledger_remove,'rows',used_rows,'reads',used_reads);
    IF octet_length(observed::text)>8388608 THEN RAISE EXCEPTION 'project member result exceeds byte budget' USING ERRCODE='54000';END IF;
    RETURN observed;
END;
$project_member$;

DO $private$
DECLARE grantee record;fn regprocedure:='kaname._authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)'::regprocedure;
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
        ('_authority_crud_storage_v3()','dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66','9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d',$changes$[
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6',false,'v',true,'private'),\n"
  ],
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_binding_id','p_project_id','p_desired','p_rows','p_reads']),\n"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc','dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda',$changes$[
  [
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66",
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d"
  ]
]$changes$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','d67b88ffe3581d55fa2cc391ed7a2af656151108ba5f67fef343d831a6018064','542edc10f7ddaf91dd6898047d135d3cd959f991dbaca0d23c3b0410331ad95b',$changes$[
  [
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66",
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d"
  ],
  [
    "aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc",
    "dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda"
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
        ('authority_metadata_service_account_access_label_ready_v1()','542edc10f7ddaf91dd6898047d135d3cd959f991dbaca0d23c3b0410331ad95b','d67b88ffe3581d55fa2cc391ed7a2af656151108ba5f67fef343d831a6018064',$changes$[
  [
    "dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda",
    "aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc"
  ],
  [
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d",
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66"
  ]
]$changes$::jsonb),
        ('_authority_full_contract_storage_v3()','dbaecbf4221f35fef3586955b65914ecb893d1593692ad370d79f02a7fee1dda','aea7772c5a201f684f0ebfd0c7fff715bf02c8faef4ab3a81554efa08d7a07dc',$changes$[
  [
    "9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d",
    "dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66"
  ]
]$changes$::jsonb),
        ('_authority_crud_storage_v3()','9dcc69b979f23751065862db8eb9471fb1da460443c3725f87b4d28dfe6b2c5d','dd4e3deef26c9d759f4cb7e43a47a70e1aa81e4648bc8751daa6a01713c69d66',$changes$[
  [
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n  ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','jsonb',5,ARRAY['p_binding_id','p_project_id','p_desired','p_rows','p_reads']),\n",
    "  ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','jsonb',4,ARRAY['p_prepared','p_holders','p_rows','p_reads']),\n"
  ],
  [
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n ('_authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer)','41cfc10882d8867d1a7f1d370d89638588d2c7acb3928ffb163e82a720619aa6',false,'v',true,'private'),\n",
    " ('_authority_role_move_predicate_plan_v1(jsonb,jsonb,integer,integer)','76f34f09ba725721cc1ed5d89abc29faff364785ed4ddb0e1a0d3c96cb3a53c8',false,'v',true,'private'),\n"
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

DROP FUNCTION kaname._authority_role_move_project_member_certificate_v1(text,text,jsonb,integer,integer);
