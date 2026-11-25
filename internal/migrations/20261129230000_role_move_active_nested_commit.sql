-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_nested_certificate_v1(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $certificate$
DECLARE
    att jsonb:=kaname._authority_role_move_attestation_v1(); pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; held jsonb:=frame->'selector_move'; decision jsonb:=frame->'selector_move_decision';
    rid text:=held->>'role_id'; bid text:=held#>>'{binding_census,bindings,0,2,id}'; coords jsonb:=p_input->'coordinates';
    commands jsonb:=p_input->'commands'; requested jsonb:='[]'; removes jsonb:='[]'; certified jsonb; expected_effect jsonb:='{}';
    blank constant jsonb:='{"Binding":"","Members":null,"Refs":null,"Rows":null,"Tuples":null,"Member":{"ObjectType":"","ObjectID":""},"RuleFP":"","Scope":{"Type":"","ID":""}}';
    max_slot jsonb; origin_image jsonb; held_slots jsonb; step integer; item jsonb; prior jsonb; proposed jsonb;
    pairs jsonb; refs jsonb; coord jsonb; member jsonb; delete_command jsonb; old_fp text; new_fp text;
    expected_tuples jsonb; models text[]:=ARRAY['account','project']; source jsonb; replacement jsonb:='[]';
    source_cost integer:=164; read_cost integer:=16;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN source_cost+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN read_cost+1 AND 4096
        OR octet_length(p_input::text)>131072 THEN RAISE EXCEPTION 'nested role certificate budget exhausted' USING ERRCODE='54000';END IF;
    IF frame->>'selector_move_transport' IS DISTINCT FROM 'active_nested_project_no_copy_v1' OR pgm->>'family' IS DISTINCT FROM 'role'
        OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR pgm->'nonce' IS DISTINCT FROM att->'nonce'
        OR pgm->>'backend' IS DISTINCT FROM pg_backend_pid()::text OR pgm->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR pgm->'selected' IS DISTINCT FROM 'null'::jsonb OR pgm->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR held->'nonce' IS DISTINCT FROM att->'nonce' OR held->'invoker_oid' IS DISTINCT FROM pgm->'invoker_oid'
        OR frame->'selector_move_transport_actor' IS DISTINCT FROM held->'actor' OR held->'actor' IS DISTINCT FROM decision->'actor'
        OR decision->'decision_at' IS DISTINCT FROM att->'decision_at' OR ((att->>'decision_at')::timestamptz>(held->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR decision->'commands' IS DISTINCT FROM '[]'::jsonb OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(bid,'ACTIVE')
        OR frame ?| ARRAY['selector_move_approved','selector_move_content_approval','selector_move_nested_seal']
        OR pgm->>'maximum_count' IS DISTINCT FROM '3' OR jsonb_typeof(p_input) IS DISTINCT FROM 'object'
        OR p_input-ARRAY['coordinates','commands'] IS DISTINCT FROM '{}'::jsonb OR jsonb_array_length(coords) IS DISTINCT FROM 2
        OR jsonb_array_length(commands) IS DISTINCT FROM 8 THEN
        RAISE EXCEPTION 'nested role certificate requires the initial two-coordinate decision' USING ERRCODE='42501';END IF;
    held_slots:=kaname._authority_role_move_nested_slots_v1(held,80,12);
    certified:=kaname._authority_role_move_binding_member_set_v1(bid,coords,p_rows-source_cost,p_reads-read_cost);
    IF certified->>'class' IS DISTINCT FROM 'ACTIVE' OR certified->'before_claims' IS DISTINCT FROM certified->'proposed_claims'
        OR certified->'lost_claims' IS DISTINCT FROM '[]'::jsonb OR certified->'unclaimed_ledger' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'nested role changes effective holder rights' USING ERRCODE='42501';END IF;
    FOR step IN 1..2 LOOP
        max_slot:=pgm->'maximum'->step; origin_image:=max_slot->'origin'; item:=coords->(step-1);
        IF max_slot-'reserved_id' IS DISTINCT FROM held_slots->(step-1)
            OR item->'Present' IS DISTINCT FROM 'true'::jsonb OR item->'Resource' IS DISTINCT FROM jsonb_build_object('Type',origin_image->'object_type','ID',origin_image->'object_id')
            OR jsonb_array_length(item->'Before') IS DISTINCT FROM 1 OR jsonb_array_length(item->'Proposed') IS DISTINCT FROM 1 THEN
            RAISE EXCEPTION 'nested role reserved generation or coordinate differs' USING ERRCODE='40001';END IF;
        prior:=item#>'{Before,0}';proposed:=item#>'{Proposed,0}';old_fp:=prior->>'RuleFP';new_fp:=proposed->>'RuleFP';
        pairs:=proposed->'Tuples';
        SELECT jsonb_agg(jsonb_build_object('User',origin_image->'user','Relation',v,'Object',models[step]||':'||(origin_image->>'object_id')) ORDER BY v COLLATE "C")
            INTO expected_tuples FROM unnest(ARRAY['v_get','viewer']) v;
        IF old_fp IS DISTINCT FROM origin_image->>'rule_fp' OR new_fp IS NULL OR new_fp !~ '^[0-9a-f]{64}$' OR new_fp=old_fp
            OR proposed-'RuleFP' IS DISTINCT FROM prior-'RuleFP' OR proposed->>'Status' IS DISTINCT FROM 'ACTIVE'
            OR jsonb_array_length(pairs) IS DISTINCT FROM 2 OR NOT ((pairs @> expected_tuples) AND (pairs <@ expected_tuples)) THEN
            RAISE EXCEPTION 'nested member replacement is not an exact retained grant' USING ERRCODE='42501';END IF;
        coord:=jsonb_build_object('ObjectType',origin_image->'object_type','ObjectID',origin_image->'object_id');
        member:=coord||jsonb_build_object('BindingID',bid,'RoleID',rid,'RuleFP',new_fp,'VerificationStatus','ACTIVE');
        SELECT jsonb_agg(jsonb_build_object('BindingID',bid,'Member',coord,'Tuple',v) ORDER BY pos)
            INTO refs FROM jsonb_array_elements(pairs) WITH ORDINALITY AS t(v,pos);
        requested:=requested||jsonb_build_array(blank||jsonb_build_object('Kind','members','Members',jsonb_build_array(member)),
            blank||jsonb_build_object('Kind','write','Tuples',pairs),blank||jsonb_build_object('Kind','record','Refs',refs));
        delete_command:=blank||jsonb_build_object('Kind','member_delete','Binding',bid,'Member',coord,'RuleFP',old_fp);
        removes:=removes||jsonb_build_array(delete_command);
        replacement:=replacement||jsonb_build_array(jsonb_build_object('member',member,'old',origin_image->'member_old'));
        expected_effect:=expected_effect||jsonb_build_object((origin_image->>'object_type')||':'||(origin_image->>'object_id'),
            jsonb_build_object('upsert_members',jsonb_build_object(new_fp,'ACTIVE'),'remove_members',jsonb_build_object(old_fp,'ACTIVE'),
            'add_ledger','[]'::jsonb,'remove_ledger','[]'::jsonb));
    END LOOP;
    -- applyDiff traverses the two dropped OLD keys in Go map order. Both exact,
    -- distinct commands must follow the ordered writes; consume them in SQL coordinate order.
    IF certified->'effects' IS DISTINCT FROM expected_effect OR commands-7-6 IS DISTINCT FROM requested
        OR NOT (jsonb_build_array(commands->6,commands->7) @> removes) THEN
        RAISE EXCEPTION 'nested owner commands differ from both certified deltas' USING ERRCODE='42501';END IF;
    source:=jsonb_build_object('members',replacement,'commands',requested||removes,'role_id',rid,'binding_id',bid,
        'actor',held->'actor','nonce',att->'nonce','decision_at',att->'decision_at','backend',pgm->'backend','xid',pgm->'transaction_id',
        'invoker_oid',att->'invoker_oid','model_id',att->'model_id','catalog_id',att->'catalog_id','projector_version',att->'projector_version');
    RETURN jsonb_build_object('source',source,'rows',source_cost+(certified->>'rows')::integer,'reads',read_cost+(certified->>'reads')::integer);
END;
$certificate$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_nested_receipt_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $receipt$
DECLARE
    att jsonb:=kaname._authority_role_move_attestation_v1(); pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; held jsonb:=frame->'selector_move'; decision jsonb:=frame->'selector_move_decision';
    source jsonb:=frame->'selector_move_nested_seal'; completion jsonb:=frame->'selector_move_nested_completion';
    rid text:=held->>'role_id'; bid text:=source->>'binding_id'; plan jsonb:=decision->'predicate_plan';
    req jsonb:=frame->'request'; old_role jsonb:=held#>'{role,physical}'; origin_role jsonb:=pgm#>'{maximum,0,origin}';
    published boolean:=jsonb_typeof(pgm->'selected')='array'; chosen jsonb; expected jsonb; actual jsonb; members jsonb;
    before_census jsonb:=held->'binding_census'; replay jsonb; new_index jsonb; which integer; m jsonb; outbox jsonb;
    slot jsonb; f jsonb; name text; model text; used_rows integer:=64;used_reads integer:=16;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads+1 AND 4096 THEN
        RAISE EXCEPTION 'nested member replay exceeds budget' USING ERRCODE='54000';END IF;
    chosen:=CASE WHEN published THEN pgm->'selected' ELSE frame#>'{selector_move_pending,selected}' END;
    IF pgm->>'family' IS DISTINCT FROM 'role' OR frame->>'mode' IS DISTINCT FROM 'selector_move'
        OR frame->>'selector_move_transport' IS DISTINCT FROM 'active_nested_project_no_copy_v1' OR jsonb_typeof(source) IS DISTINCT FROM 'object'
        OR source->'nonce' IS DISTINCT FROM pgm->'nonce' OR source->'nonce' IS DISTINCT FROM att->'nonce'
        OR source->'xid' IS DISTINCT FROM pgm->'transaction_id' OR source->>'xid' IS DISTINCT FROM pg_current_xact_id()::text
        OR source->'backend' IS DISTINCT FROM pgm->'backend' OR source->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR source->'invoker_oid' IS DISTINCT FROM pgm->'invoker_oid' OR source->'invoker_oid' IS DISTINCT FROM att->'invoker_oid'
        OR source->'decision_at' IS DISTINCT FROM att->'decision_at' OR decision->'decision_at' IS DISTINCT FROM att->'decision_at'
        OR source->'model_id' IS DISTINCT FROM att->'model_id' OR source->'catalog_id' IS DISTINCT FROM att->'catalog_id'
        OR source->'projector_version' IS DISTINCT FROM att->'projector_version' OR source->'actor' IS DISTINCT FROM held->'actor'
        OR source->'actor' IS DISTINCT FROM frame->'selector_move_transport_actor' OR source->'actor' IS DISTINCT FROM decision->'actor'
        OR jsonb_typeof(source->'actor') IS DISTINCT FROM 'object' OR source->>'role_id' IS DISTINCT FROM rid OR coalesce(bid,'')=''
        OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(bid,'ACTIVE') OR decision->'commands' IS DISTINCT FROM '[]'::jsonb
        OR held#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb OR req->'create' IS DISTINCT FROM 'false'::jsonb
        OR req->'retier' IS DISTINCT FROM 'true'::jsonb OR req->'rules' IS DISTINCT FROM 'true'::jsonb OR req->'mask' IS DISTINCT FROM '["rules"]'::jsonb
        OR req#>>'{role,id}' IS DISTINCT FROM rid OR req->>'version' IS DISTINCT FROM old_role->>0 OR req#>'{role,rules}' IS DISTINCT FROM held#>'{role,new_role,rules}'
        OR pgm->>'maximum_count' IS DISTINCT FROM '3' OR jsonb_array_length(chosen) IS DISTINCT FROM 3
        OR origin_role->>'table' IS DISTINCT FROM 'roles' OR origin_role->>'operation' IS DISTINCT FROM 'UPDATE'
        OR origin_role->'old' IS DISTINCT FROM old_role->2 OR origin_role#>>'{new,id}' IS DISTINCT FROM rid
        OR origin_role#>'{new,rules}' IS DISTINCT FROM req#>'{role,rules}' OR pgm#>>'{maximum,0,table}' IS DISTINCT FROM 'resource_journal'
        OR (published AND (pgm->'decision_at' IS DISTINCT FROM att->'decision_at' OR pgm->'unselected' IS DISTINCT FROM '[]'::jsonb))
        OR (NOT published AND (pgm->'selected' IS DISTINCT FROM 'null'::jsonb OR frame#>'{selector_move_pending,unselected}' IS DISTINCT FROM '[]'::jsonb)) THEN
        RAISE EXCEPTION 'nested owner context escaped exact role or coordinate set' USING ERRCODE='42501';END IF;
    FOR which IN 0..2 LOOP
        IF chosen->which IS DISTINCT FROM jsonb_set(pgm->'maximum'->which,'{row,created_at}',to_jsonb(transaction_timestamp()),true) THEN
            RAISE EXCEPTION 'nested selected slot differs from pre-clock reservation' USING ERRCODE='42501';END IF;
    END LOOP;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO actual FROM ONLY kaname.roles r WHERE r.id=rid;
    IF published THEN
        IF actual->2 IS DISTINCT FROM origin_role->'new' OR jsonb_array_length(completion->'members') IS DISTINCT FROM 2
            OR completion->>'seal_sha256' IS DISTINCT FROM encode(sha256(convert_to(source::text,'UTF8')),'hex')
            OR completion->'decision_at' IS DISTINCT FROM att->'decision_at' OR completion->'nonce' IS DISTINCT FROM att->'nonce'
            OR completion->'xid' IS DISTINCT FROM pgm->'transaction_id' THEN
            RAISE EXCEPTION 'nested role or consumed member generation changed' USING ERRCODE='40001';END IF;
        new_index:=plan->'new_role_index'->(jsonb_build_array(13,'role',rid,'')::text)->'states';
        IF jsonb_array_length(new_index) IS DISTINCT FROM 2 OR (SELECT count(*) FROM(SELECT FROM ONLY kaname.role_rule_selectors s WHERE s.role_id=rid LIMIT 3) ss)<>2
            OR EXISTS(SELECT FROM jsonb_array_elements(new_index) i WHERE NOT EXISTS(
                SELECT FROM ONLY kaname.role_rule_selectors s WHERE s.role_id=rid AND s.rule_fp=i#>>'{2,rule_fp}'
                AND to_jsonb(s)-ARRAY['created_at','updated_at'] IS NOT DISTINCT FROM (i->2)-ARRAY['created_at','updated_at'])) THEN
            RAISE EXCEPTION 'nested committed selector projections differ' USING ERRCODE='40001';END IF;
        FOR which IN 1..2 LOOP
            slot:=chosen->which;m:=completion->'members'->(which-1);model:=CASE which WHEN 1 THEN 'account' ELSE 'project' END;
            IF m#>>'{2,rule_fp}' IS DISTINCT FROM source#>>ARRAY['members',(which-1)::text,'member','RuleFP']
                OR m#>>'{2,object_id}' IS DISTINCT FROM slot#>>'{origin,object_id}' OR m#>>'{2,binding_id}' IS DISTINCT FROM bid
                OR NOT EXISTS(SELECT FROM jsonb_array_elements(new_index) i WHERE i#>>'{2,rule_fp}'=m#>>'{2,rule_fp}') THEN
                RAISE EXCEPTION 'nested member changed its owner or selector' USING ERRCODE='40001';END IF;
            SELECT jsonb_build_array(q.xmin::text,q.ctid::text,to_jsonb(q)) INTO outbox FROM ONLY kaname.fga_outbox q
                JOIN ONLY pg_temp.kaname_authority_sequence_effects e ON e.table_name='fga_outbox' AND e.reserved_id=q.id
                WHERE e.nonce=(att->>'nonce')::uuid AND e.ordinal=which+1 AND e.selected AND e.claimed AND e.consumed
                AND e.origin=slot->'origin' AND e.row_value=to_jsonb(q)-'id' AND e.row_value=slot->'row';
            IF outbox IS DISTINCT FROM completion->'outboxes'->(which-1) OR outbox IS NULL THEN RAISE EXCEPTION 'nested FGA emit changed at commit' USING ERRCODE='40001';END IF;
            FOREACH name IN ARRAY ARRAY['viewer','v_get'] LOOP
                SELECT jsonb_build_array(t.xmin::text,t.ctid::text,to_jsonb(t)) INTO f FROM ONLY kaname.relation_fact t
                    WHERE t.object_type=model AND t.object_id=slot#>>'{origin,object_id}' AND t.relation=name AND t.subject=slot#>>'{origin,user}';
                IF coalesce(f,'null'::jsonb) IS DISTINCT FROM completion#>ARRAY['facts',(which-1)::text,name] THEN
                    RAISE EXCEPTION 'nested physical relation changed at commit' USING ERRCODE='40001';END IF;
            END LOOP;
        END LOOP;
        SELECT jsonb_agg(v ORDER BY (v->>1)::tid) INTO members FROM jsonb_array_elements(completion->'members') v;
    ELSE
        IF actual IS DISTINCT FROM old_role OR completion IS NOT NULL OR EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e
            WHERE e.selected OR e.registered OR e.claimed OR e.consumed) THEN RAISE EXCEPTION 'nested program already used' USING ERRCODE='40001';END IF;
        members:=before_census->'members';
    END IF;
    replay:=kaname._authority_role_move_binding_census_v1(rid,jsonb_set(before_census,'{members}',members),p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(replay->>'rows')::integer;used_reads:=used_reads+(replay->>'reads')::integer;
    IF replay->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN RAISE EXCEPTION 'nested binding changed' USING ERRCODE='40001';END IF;
    replay:=kaname._authority_role_move_finite_positions_v1(held,plan,true,p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(replay->>'rows')::integer;used_reads:=used_reads+(replay->>'reads')::integer;
    IF replay->'positions' IS DISTINCT FROM decision->'finite_positions' THEN RAISE EXCEPTION 'nested finite account changed' USING ERRCODE='40001';END IF;
    replay:=kaname._authority_role_move_member_projects_v1(plan,before_census||jsonb_build_object('moved_role_id',rid),held->'member_projects',p_rows-used_rows,p_reads-used_reads);
    used_rows:=used_rows+(replay->>'rows')::integer;used_reads:=used_reads+(replay->>'reads')::integer;
    IF replay->'source' IS DISTINCT FROM held->'member_projects' THEN RAISE EXCEPTION 'nested project or ancestry changed' USING ERRCODE='40001';END IF;
    RETURN jsonb_build_object('rows',used_rows,'reads',used_reads,'receipt',jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1',
        'operation','role.update','role_id',rid,'binding_id',bid,'actor',source->'actor','role_generation',jsonb_build_array(old_role->0,old_role->1),
        'source_sha256',encode(sha256(convert_to(source::text,'UTF8')),'hex'),'selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex'),
        'nonce',att->'nonce','invoker_oid',att->'invoker_oid','decision_at',att->'decision_at','backend',pgm->'backend','transaction_id',pgm->'transaction_id'));
END;
$receipt$;
-- +goose StatementEnd
-- +goose StatementBegin
-- Вход только из AFTER расходованного журнала роли. Записываем обе координаты
-- по запечатанным OLD и уже выбранным ID текущей backend-транзакции.
CREATE FUNCTION kaname._authority_role_move_nested_apply_v1()
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $apply$
DECLARE
    att jsonb:=kaname._authority_role_move_attestation_v1(); pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; held jsonb:=frame->'selector_move'; seal jsonb:=frame->'selector_move_nested_seal';
    chosen jsonb:=pgm->'selected'; approval jsonb:=frame->'selector_move_content_approval';
    rid text:=seal->>'role_id';bid text:=seal->>'binding_id';which integer; member jsonb; old_image jsonb; post jsonb;
    slot jsonb; origin_image jsonb; wanted jsonb; fid bigint; outbox_image jsonb; stored jsonb; expected jsonb;
    model text; typ text; oid_value text; recipient text; name text; facts jsonb; old_fact jsonb; updated jsonb;
    new_members jsonb:='[]';new_outboxes jsonb:='[]';new_facts jsonb:='[]';complete jsonb; touched integer; refs jsonb;
    ledger jsonb:=held#>'{binding_census,ledger}';
BEGIN
    IF pgm->>'family' IS DISTINCT FROM 'role' OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR frame->>'selector_move_transport' IS DISTINCT FROM 'active_nested_project_no_copy_v1'
        OR frame ? 'selector_move_nested_completion' OR jsonb_typeof(seal) IS DISTINCT FROM 'object'
        OR seal->'nonce' IS DISTINCT FROM att->'nonce' OR seal->'nonce' IS DISTINCT FROM pgm->'nonce'
        OR seal->'xid' IS DISTINCT FROM pgm->'transaction_id' OR seal->>'xid' IS DISTINCT FROM pg_current_xact_id()::text
        OR seal->'backend' IS DISTINCT FROM pgm->'backend' OR seal->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR seal->'invoker_oid' IS DISTINCT FROM att->'invoker_oid' OR seal->'decision_at' IS DISTINCT FROM att->'decision_at'
        OR pgm->'decision_at' IS DISTINCT FROM att->'decision_at' OR seal->'model_id' IS DISTINCT FROM att->'model_id' OR seal->'catalog_id' IS DISTINCT FROM att->'catalog_id'
        OR seal->'projector_version' IS DISTINCT FROM att->'projector_version' OR seal->'actor' IS DISTINCT FROM frame->'selector_move_transport_actor'
        OR frame->'selector_move_approved' IS DISTINCT FROM jsonb_build_object('actor',seal->'actor','role_id',rid,'nonce',att->'nonce','decision_at',att->'decision_at')
        OR approval->>'contract' IS DISTINCT FROM 'RequireRole/v1+v_update+RequireSelectorMoveGrants/v1' OR approval->>'operation' IS DISTINCT FROM 'role.update'
        OR approval->'actor' IS DISTINCT FROM seal->'actor' OR approval->>'role_id' IS DISTINCT FROM rid OR approval->>'binding_id' IS DISTINCT FROM bid
        OR approval->>'source_sha256' IS DISTINCT FROM encode(sha256(convert_to(seal::text,'UTF8')),'hex')
        OR frame->>'selector_move_approved_content_sha256' IS DISTINCT FROM encode(sha256(convert_to(approval::text,'UTF8')),'hex')
        OR approval->>'selected_sha256' IS DISTINCT FROM encode(sha256(convert_to(chosen::text,'UTF8')),'hex')
        OR pgm->>'selected_count' IS DISTINCT FROM '3' OR pgm->>'maximum_count' IS DISTINCT FROM '3' OR pgm->'unselected' IS DISTINCT FROM '[]'::jsonb
        OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e JOIN ONLY kaname.resource_journal j ON j.sequence_no=e.reserved_id
            WHERE e.ordinal=1 AND e.nonce=(att->>'nonce')::uuid AND e.table_name='resource_journal' AND e.reserved_id=(chosen#>>'{0,reserved_id}')::bigint
            AND e.selected AND e.registered AND e.claimed AND e.consumed AND e.origin=chosen#>'{0,origin}' AND e.row_value=to_jsonb(j)-'sequence_no')
        OR NOT EXISTS(SELECT FROM ONLY kaname.roles r WHERE r.id=rid AND to_jsonb(r)=chosen#>'{0,origin,new}') THEN
        RAISE EXCEPTION 'nested member commands lack exact role journal and owner approval' USING ERRCODE='42501';END IF;
    IF jsonb_array_length(ledger) IS DISTINCT FROM 5 OR (SELECT count(*) FROM (SELECT FROM ONLY kaname.access_binding_emitted_tuples l WHERE l.binding_id=bid LIMIT 6) a)<>5
        OR EXISTS(SELECT FROM jsonb_array_elements(ledger) l WHERE NOT EXISTS (SELECT FROM ONLY kaname.access_binding_emitted_tuples t
            WHERE t.binding_id=bid AND t.member_object_type=l#>>'{2,member_object_type}' AND t.member_object_id=l#>>'{2,member_object_id}'
            AND t.fga_user=l#>>'{2,fga_user}' AND t.relation=l#>>'{2,relation}' AND t.object=l#>>'{2,object}'
            AND jsonb_build_array(t.xmin::text,t.ctid::text,to_jsonb(t))=l)) THEN
        RAISE EXCEPTION 'nested source ledger changed before replay' USING ERRCODE='40001';END IF;
    FOR which IN 1..2 LOOP
        member:=seal#>ARRAY['members',(which-1)::text,'member'];old_image:=seal#>ARRAY['members',(which-1)::text,'old'];
        slot:=chosen->which;origin_image:=slot->'origin';wanted:=slot->'row';model:=CASE which WHEN 1 THEN 'account' ELSE 'project' END;
        typ:='iam.'||model;oid_value:=origin_image->>'object_id';recipient:=origin_image->>'user';facts:='{}'::jsonb;
        IF slot->>'table' IS DISTINCT FROM 'fga_outbox' OR slot->>'ordinal' IS DISTINCT FROM (which+1)::text
            OR origin_image->>'family' IS DISTINCT FROM 'role.selector_move.active_nested_member' OR origin_image->>'binding' IS DISTINCT FROM bid
            OR origin_image->>'role' IS DISTINCT FROM rid OR origin_image->>'object_type' IS DISTINCT FROM typ OR origin_image->'member_old' IS DISTINCT FROM old_image
            OR origin_image->>'ledger_sha256' IS DISTINCT FROM encode(sha256(convert_to(ledger::text,'UTF8')),'hex')
            OR member->>'BindingID' IS DISTINCT FROM bid OR member->>'RoleID' IS DISTINCT FROM rid OR member->>'ObjectType' IS DISTINCT FROM typ
            OR member->>'ObjectID' IS DISTINCT FROM oid_value OR member->>'VerificationStatus' IS DISTINCT FROM 'ACTIVE'
            OR member->>'RuleFP' IS NOT DISTINCT FROM old_image#>>'{2,rule_fp}' THEN
            RAISE EXCEPTION 'nested member command or reserved source changed' USING ERRCODE='42501';END IF;
        INSERT INTO kaname.access_binding_target_members AS m(binding_id,role_id,rule_fp,object_type,object_id,verification_status,created_at,updated_at)
        SELECT bid,rid,member->>'RuleFP',typ,oid_value,'ACTIVE',now(),now() FROM ONLY kaname.access_binding_target_members om
            WHERE om.binding_id=bid AND om.role_id=rid AND om.object_type=typ AND om.object_id=oid_value AND om.rule_fp=old_image#>>'{2,rule_fp}'
            AND jsonb_build_array(om.xmin::text,om.ctid::text,to_jsonb(om))=old_image
        ON CONFLICT(binding_id,role_id,rule_fp,object_type,object_id) DO NOTHING
        RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO post;
        IF NOT FOUND OR post->2 IS DISTINCT FROM (old_image->2)||jsonb_build_object('rule_fp',member->'RuleFP','created_at',now(),'updated_at',now()) THEN
            RAISE EXCEPTION 'nested member CAS insert changed' USING ERRCODE='40001';END IF;
        new_members:=new_members||jsonb_build_array(post);
        FOREACH name IN ARRAY ARRAY['viewer','v_get'] LOOP
            SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO stored FROM ONLY kaname.relation_fact f
                WHERE f.object_type=model AND f.object_id=oid_value AND f.subject=recipient AND f.relation=name;
            IF coalesce(stored,'null'::jsonb) IS DISTINCT FROM origin_image#>ARRAY['facts',name] THEN RAISE EXCEPTION 'nested relation OLD changed' USING ERRCODE='40001';END IF;
        END LOOP;
        fid:=kaname._authority_sequence_claim_v3('fga_outbox',origin_image,wanted);
        IF fid IS DISTINCT FROM (slot->>'reserved_id')::bigint THEN RAISE EXCEPTION 'nested FGA ID changed' USING ERRCODE='40001';END IF;
        INSERT INTO kaname.fga_outbox AS q(id,event_type,payload,created_at)
        VALUES(fid,wanted->>'event_type',wanted->'payload',(wanted->>'created_at')::timestamptz)
        RETURNING jsonb_build_array(q.xmin::text,q.ctid::text,to_jsonb(q)) INTO outbox_image;
        IF outbox_image->2 IS DISTINCT FROM wanted||jsonb_build_object('id',fid) OR NOT EXISTS (SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e
            WHERE e.nonce=(att->>'nonce')::uuid AND e.ordinal=which+1 AND e.reserved_id=fid AND e.selected AND e.claimed AND e.consumed
            AND e.table_name='fga_outbox' AND e.origin=origin_image AND e.row_value=wanted) THEN
            RAISE EXCEPTION 'nested FGA write was not consumed' USING ERRCODE='40001';END IF;
        new_outboxes:=new_outboxes||jsonb_build_array(outbox_image);
        FOREACH name IN ARRAY ARRAY['viewer','v_get'] LOOP
            old_fact:=origin_image#>ARRAY['facts',name];
            SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO stored FROM ONLY kaname.relation_fact f
                WHERE f.object_type=model AND f.object_id=oid_value AND f.subject=recipient AND f.relation=name;
            IF old_fact='null'::jsonb THEN
                IF stored IS NOT NULL THEN RAISE EXCEPTION 'nested replay introduced a new fact' USING ERRCODE='42501';END IF;
            ELSE
                updated:=(old_fact->2)||jsonb_build_object('source_version',greatest((old_fact#>>'{2,source_version}')::timestamptz,transaction_timestamp()));
                IF stored IS DISTINCT FROM old_fact AND stored->2 IS DISTINCT FROM updated THEN
                    RAISE EXCEPTION 'nested physical fact changed its meaning' USING ERRCODE='40001';END IF;
            END IF;
            facts:=facts||jsonb_build_object(name,stored);
        END LOOP;
        new_facts:=new_facts||jsonb_build_array(facts);
        refs:=seal#>ARRAY['commands',((which-1)*3+2)::text,'Refs'];
        INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
        SELECT bid,typ,oid_value,r#>>'{Tuple,User}',r#>>'{Tuple,Relation}',r#>>'{Tuple,Object}','member' FROM jsonb_array_elements(refs) r
        ON CONFLICT(binding_id,member_object_type,member_object_id,fga_user,relation,object) DO NOTHING;
        GET DIAGNOSTICS touched=ROW_COUNT;
        IF touched<>0 THEN RAISE EXCEPTION 'nested record introduced an extra grant' USING ERRCODE='42501';END IF;
    END LOOP;
    FOR which IN 1..2 LOOP
        old_image:=seal#>ARRAY['members',(which-1)::text,'old'];member:=seal->'commands'->(which+5);
        DELETE FROM ONLY kaname.access_binding_target_members om WHERE om.binding_id=bid AND om.role_id=rid AND om.rule_fp=member->>'RuleFP'
            AND om.object_type=member#>>'{Member,ObjectType}' AND om.object_id=member#>>'{Member,ObjectID}'
            AND jsonb_build_array(om.xmin::text,om.ctid::text,to_jsonb(om))=old_image
        RETURNING jsonb_build_array(om.xmin::text,om.ctid::text,to_jsonb(om)) INTO post;
        IF NOT FOUND OR post IS DISTINCT FROM old_image THEN RAISE EXCEPTION 'nested OLD member CAS delete changed' USING ERRCODE='40001';END IF;
    END LOOP;
    complete:=jsonb_build_object('members',new_members,'outboxes',new_outboxes,'facts',new_facts,'nonce',att->'nonce',
        'xid',pgm->'transaction_id','decision_at',att->'decision_at','seal_sha256',approval->'source_sha256');
    IF octet_length(frame::text)+octet_length(complete::text)+64>8388608 THEN RAISE EXCEPTION 'nested completion exceeds frame budget' USING ERRCODE='54000';END IF;
    UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_nested_completion',complete)
        WHERE s.singleton AND s.family='role' AND s.nonce=(att->>'nonce')::uuid AND s.frozen=frame AND s.selected=chosen;
    IF NOT FOUND THEN RAISE EXCEPTION 'nested effect receipt changed' USING ERRCODE='40001';END IF;
END;
$apply$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_nested_finish_v1(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $finish$
DECLARE
    att jsonb:=kaname._authority_role_move_attestation_v1();pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; rows_left integer:=p_rows-12;reads_left integer:=p_reads-9;step jsonb;source jsonb;content jsonb;
    allowance jsonb;phase integer;sr integer;sd integer;replay_rows integer;replay_reads integer;source_hash text;content_hash text;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 13 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 10 AND 4096
        OR octet_length(p_input::text)>131072 THEN RAISE EXCEPTION 'nested role finish budget exhausted' USING ERRCODE='54000';END IF;
    IF frame->>'selector_move_transport' IS DISTINCT FROM 'active_nested_project_no_copy_v1' OR pgm->>'family' IS DISTINCT FROM 'role'
        OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR pgm->'nonce' IS DISTINCT FROM att->'nonce'
        OR pgm->>'maximum_count' IS DISTINCT FROM '3' OR pgm->'selected' IS DISTINCT FROM 'null'::jsonb OR pgm->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR frame->'selector_move_transport_actor' IS DISTINCT FROM frame#>'{selector_move,actor}' OR ((att->>'decision_at')::timestamptz>(frame#>>'{selector_move,prepared_at}')::timestamptz) IS DISTINCT FROM true
        OR frame ?| ARRAY['selector_move_decision','selector_move_pending','selector_move_approved','selector_move_content_approval','selector_move_nested_seal','selector_move_nested_completion','selector_move_active_replay','selector_move_pending_sources']
        THEN RAISE EXCEPTION 'nested finish requires an untouched transaction and decision' USING ERRCODE='42501';END IF;
    FOR phase IN 1..3 LOOP
        CASE phase
        WHEN 1 THEN step:=kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,rows_left,reads_left);
        WHEN 2 THEN
            step:=kaname._authority_role_move_nested_certificate_v1(p_input,rows_left,reads_left);source:=step->'source';
            frame:=kaname._authority_sequence_store_v3()->'frozen';
            IF octet_length(frame::text)+octet_length(source::text)+64>8388608 THEN RAISE EXCEPTION 'nested seal exceeds frame' USING ERRCODE='54000';END IF;
            UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_nested_seal',source)
                WHERE s.singleton AND s.family='role' AND s.nonce=(att->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=frame;
            IF NOT FOUND THEN RAISE EXCEPTION 'nested seal owner frame changed' USING ERRCODE='40001';END IF;
        WHEN 3 THEN step:=kaname._authority_role_move_nested_receipt_v1(rows_left,reads_left);
        END CASE;
        sr:=(step->>'rows')::integer;sd:=(step->>'reads')::integer;
        IF sr IS NULL OR sr NOT BETWEEN 1 AND rows_left OR sd IS NULL OR sd NOT BETWEEN 1 AND reads_left THEN
            RAISE EXCEPTION 'nested owner phase cost differs' USING ERRCODE='54000';END IF;
        rows_left:=rows_left-sr;reads_left:=reads_left-sd;
    END LOOP;
    content:=step->'receipt';content_hash:=encode(sha256(convert_to(content::text,'UTF8')),'hex');source_hash:=encode(sha256(convert_to(source::text,'UTF8')),'hex');
    IF content->>'source_sha256' IS DISTINCT FROM source_hash OR jsonb_typeof(content) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'nested content lacks its seal' USING ERRCODE='42501';END IF;
    -- The admission, fixed physical consumer and deferred replay each retain an
    -- independent allowance; returning deferred credit consumes the writer budget.
    replay_rows:=sr+64;replay_reads:=sd+20;
    IF rows_left<2*replay_rows+120 OR reads_left<2*replay_reads+52 THEN RAISE EXCEPTION 'nested role replay credit missing' USING ERRCODE='54000';END IF;
    allowance:=jsonb_build_object('rows',replay_rows,'reads',replay_reads);
    frame:=kaname._authority_sequence_store_v3()->'frozen';
    IF octet_length(frame::text)+octet_length(content::text)+256>8388608 THEN RAISE EXCEPTION 'nested content exceeds budget' USING ERRCODE='54000';END IF;
    UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_content_approval',content,'selector_move_active_replay',allowance)
        WHERE s.singleton AND s.family='role' AND s.nonce=(att->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=frame;
    IF NOT FOUND THEN RAISE EXCEPTION 'nested content owner frame changed' USING ERRCODE='40001';END IF;
    PERFORM kaname._authority_role_move_sequence_approve_v1();
    pgm:=kaname._authority_sequence_store_v3();frame:=pgm->'frozen';
    IF pgm->>'selected_count' IS DISTINCT FROM '3' OR pgm->'unselected' IS DISTINCT FROM '[]'::jsonb OR pgm->'decision_at' IS DISTINCT FROM att->'decision_at'
        OR frame->>'selector_move_approved_content_sha256' IS DISTINCT FROM content_hash OR frame->'selector_move_content_approval' IS DISTINCT FROM content
        OR frame->'selector_move_nested_seal' IS DISTINCT FROM source OR frame ? 'selector_move_nested_completion' THEN
        RAISE EXCEPTION 'nested owner publication differs from approved program' USING ERRCODE='40001';END IF;
    rows_left:=rows_left-replay_rows;reads_left:=reads_left-replay_reads;
    RETURN jsonb_build_object('selector_move_transport','active_nested_project_no_copy_v1','phase','selected','source_sha256',source_hash,'content_sha256',content_hash,
        'rows',p_rows-rows_left,'reads',p_reads-reads_left,'deferred_rows',rows_left,'deferred_reads',reads_left);
END;
$finish$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_nested_certificate_v1(jsonb,integer,integer)'::regprocedure,
        'kaname._authority_role_move_nested_receipt_v1(integer,integer)'::regprocedure,
        'kaname._authority_role_move_nested_apply_v1()'::regprocedure,
        'kaname._authority_role_move_nested_finish_v1(jsonb,integer,integer)'::regprocedure] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE format('%I',grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $storage$
DECLARE item record;fn regprocedure;original text;body text;definition text;marker text;edit jsonb;
BEGIN
    FOR item IN SELECT * FROM (VALUES
        ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab','f0f080330e5b130a1060fea1c9f1dcb09260fa4d2dc569e3220b1a3e38f3fd32',$edits$[
 [
  "            ELSE c.cmd IS NOT NULL END AS selected",
  "            WHEN frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' AND fixed=1 AND slot_count=3 AND s.position IN (2,3)\n                AND s.value->>'table'='fga_outbox' AND s.value->>'ordinal'=s.position::text AND s.value#>>'{origin,family}'='role.selector_move.active_nested_member'\n                AND s.value#>>'{origin,object_type}'=CASE s.position WHEN 2 THEN 'iam.account' ELSE 'iam.project' END\n                AND s.value#>'{origin,role}'=decision->'role_id' AND decision->'commands'='[]'::jsonb\n                AND decision->'binding_status'=jsonb_build_object(s.value#>>'{origin,binding}','ACTIVE') THEN true\n            ELSE c.cmd IS NOT NULL END AS selected"
 ]
]$edits$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6','4bec35adddb1b0e8cbab491e1879f9415860e49f37b153855ee3b8fd1ded8086',$edits$[
 [
  "    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n",
  "    IF p_frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_nested_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'nested role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_nested_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'nested role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126','972b8d88f852f68356e5f997aef19d44173f2083cef933b7724b9c48b9778130',$edits$[
 [
  "WHEN s.frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN",
  "WHEN s.frozen->>'selector_move_transport' IN ('active_project_no_copy_v1','active_nested_project_no_copy_v1') THEN"
 ]
]$edits$::jsonb),
        ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a','aaad732c4d4f5864fc7a76dc57df946b6185b0e85c40a5f9945a1638f5cce2f2',$edits$[
 [
  "    IF p_sets ? 'commands' THEN",
  "    IF p_sets ? 'commands' AND kaname._authority_sequence_store_v3()#>>'{frozen,selector_move_transport}'='active_nested_project_no_copy_v1' THEN\n        RETURN kaname._authority_role_move_nested_finish_v1(p_sets,p_rows,p_reads);\n    END IF;\n    IF p_sets ? 'commands' THEN"
 ]
]$edits$::jsonb),
        ('authority_sequence_program_applied_v3()','11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828','672de8289e428fbad854310431c5165d497ab44a263f8e16d7e7360de2eaef1a',$edits$[
 [
  "    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n END IF;",
  "    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n ELSIF TG_TABLE_NAME='resource_journal' AND program->>'family'='role' AND program#>>'{frozen,mode}'='selector_move'\n    AND EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_program a WHERE a.singleton AND a.nonce=(proof->>'nonce')::uuid\n        AND a.frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' AND a.frozen ? 'selector_move_nested_seal') THEN\n    PERFORM kaname._authority_role_move_nested_apply_v1();\n END IF;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2','5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3',$edits$[
 [
  "10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab",
  "f0f080330e5b130a1060fea1c9f1dcb09260fa4d2dc569e3220b1a3e38f3fd32"
 ],
 [
  "31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6",
  "4bec35adddb1b0e8cbab491e1879f9415860e49f37b153855ee3b8fd1ded8086"
 ],
 [
  "aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126",
  "972b8d88f852f68356e5f997aef19d44173f2083cef933b7724b9c48b9778130"
 ],
 [
  "5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a",
  "aaad732c4d4f5864fc7a76dc57df946b6185b0e85c40a5f9945a1638f5cce2f2"
 ],
 [
  "11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828",
  "672de8289e428fbad854310431c5165d497ab44a263f8e16d7e7360de2eaef1a"
 ],
 [
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n ('_authority_role_move_nested_certificate_v1(jsonb,integer,integer)','fe2215ed041fdba6ccb7658bb65232f2eaa3ffd7e6d2403c613056f8502204bd',false,'v',true,'private'),\n ('_authority_role_move_nested_receipt_v1(integer,integer)','b9a5544e7bb955addf673bd932582d047cb7dcc7a5ffa74da91ff419fc9d40b2',false,'v',true,'private'),\n ('_authority_role_move_nested_apply_v1()','e42c33cb0af4e187c1e6b561c03d0f5e435b3095ead1978d3276441b91334b2b',false,'v',true,'private'),\n ('_authority_role_move_nested_finish_v1(jsonb,integer,integer)','8309adb032c52df01e8f59d429a18982bb51ebf2de965c0b176c4ca188c1b0f0',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n  ('_authority_role_move_nested_certificate_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_nested_receipt_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_nested_apply_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_nested_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568','20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6',$edits$[
 [
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2",
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','230514cacc711cb8cfa248dc35883f990a108a0526ad57a0d5c7e490af170650','c6e37fcf8bb31f9f9bb6b3a887ce64b7e0bf5fb6de6f212f729612879feba24d',$edits$[
 [
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2",
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3"
 ],
 [
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568",
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce','e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306',$edits$[
 [
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568",
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','f00a6cd43c791f583cc70fbfa0eb14b189c9ac3bfa016b873557c302d3fcbcca','5c25a08a4dead51806b59e6debadccbcf33c4d25069d6a590e738b65379b783f',$edits$[
 [
  "049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce",
  "e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested active member commit predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested active member commit replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active member commit body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active member commit installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested active member commit storage graph differs' USING ERRCODE='55000';
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
        ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','f0f080330e5b130a1060fea1c9f1dcb09260fa4d2dc569e3220b1a3e38f3fd32','10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab',$edits$[
 [
  "            WHEN frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' AND fixed=1 AND slot_count=3 AND s.position IN (2,3)\n                AND s.value->>'table'='fga_outbox' AND s.value->>'ordinal'=s.position::text AND s.value#>>'{origin,family}'='role.selector_move.active_nested_member'\n                AND s.value#>>'{origin,object_type}'=CASE s.position WHEN 2 THEN 'iam.account' ELSE 'iam.project' END\n                AND s.value#>'{origin,role}'=decision->'role_id' AND decision->'commands'='[]'::jsonb\n                AND decision->'binding_status'=jsonb_build_object(s.value#>>'{origin,binding}','ACTIVE') THEN true\n            ELSE c.cmd IS NOT NULL END AS selected",
  "            ELSE c.cmd IS NOT NULL END AS selected"
 ]
]$edits$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','4bec35adddb1b0e8cbab491e1879f9415860e49f37b153855ee3b8fd1ded8086','31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6',$edits$[
 [
  "    IF p_frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_nested_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'nested role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_nested_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'nested role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n",
  "    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','972b8d88f852f68356e5f997aef19d44173f2083cef933b7724b9c48b9778130','aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126',$edits$[
 [
  "WHEN s.frozen->>'selector_move_transport' IN ('active_project_no_copy_v1','active_nested_project_no_copy_v1') THEN",
  "WHEN s.frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN"
 ]
]$edits$::jsonb),
        ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','aaad732c4d4f5864fc7a76dc57df946b6185b0e85c40a5f9945a1638f5cce2f2','5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a',$edits$[
 [
  "    IF p_sets ? 'commands' AND kaname._authority_sequence_store_v3()#>>'{frozen,selector_move_transport}'='active_nested_project_no_copy_v1' THEN\n        RETURN kaname._authority_role_move_nested_finish_v1(p_sets,p_rows,p_reads);\n    END IF;\n    IF p_sets ? 'commands' THEN",
  "    IF p_sets ? 'commands' THEN"
 ]
]$edits$::jsonb),
        ('authority_sequence_program_applied_v3()','672de8289e428fbad854310431c5165d497ab44a263f8e16d7e7360de2eaef1a','11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828',$edits$[
 [
  "    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n ELSIF TG_TABLE_NAME='resource_journal' AND program->>'family'='role' AND program#>>'{frozen,mode}'='selector_move'\n    AND EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_program a WHERE a.singleton AND a.nonce=(proof->>'nonce')::uuid\n        AND a.frozen->>'selector_move_transport'='active_nested_project_no_copy_v1' AND a.frozen ? 'selector_move_nested_seal') THEN\n    PERFORM kaname._authority_role_move_nested_apply_v1();\n END IF;",
  "    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n END IF;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3','887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2',$edits$[
 [
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n  ('_authority_role_move_nested_certificate_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_nested_receipt_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_nested_apply_v1()','void',0,NULL::text[]),\n  ('_authority_role_move_nested_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n",
  "  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n ('_authority_role_move_nested_certificate_v1(jsonb,integer,integer)','fe2215ed041fdba6ccb7658bb65232f2eaa3ffd7e6d2403c613056f8502204bd',false,'v',true,'private'),\n ('_authority_role_move_nested_receipt_v1(integer,integer)','b9a5544e7bb955addf673bd932582d047cb7dcc7a5ffa74da91ff419fc9d40b2',false,'v',true,'private'),\n ('_authority_role_move_nested_apply_v1()','e42c33cb0af4e187c1e6b561c03d0f5e435b3095ead1978d3276441b91334b2b',false,'v',true,'private'),\n ('_authority_role_move_nested_finish_v1(jsonb,integer,integer)','8309adb032c52df01e8f59d429a18982bb51ebf2de965c0b176c4ca188c1b0f0',false,'v',true,'private'),\n",
  " ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n"
 ],
 [
  "672de8289e428fbad854310431c5165d497ab44a263f8e16d7e7360de2eaef1a",
  "11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828"
 ],
 [
  "aaad732c4d4f5864fc7a76dc57df946b6185b0e85c40a5f9945a1638f5cce2f2",
  "5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a"
 ],
 [
  "972b8d88f852f68356e5f997aef19d44173f2083cef933b7724b9c48b9778130",
  "aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126"
 ],
 [
  "4bec35adddb1b0e8cbab491e1879f9415860e49f37b153855ee3b8fd1ded8086",
  "31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6"
 ],
 [
  "f0f080330e5b130a1060fea1c9f1dcb09260fa4d2dc569e3220b1a3e38f3fd32",
  "10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6','0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568',$edits$[
 [
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3",
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','c6e37fcf8bb31f9f9bb6b3a887ce64b7e0bf5fb6de6f212f729612879feba24d','230514cacc711cb8cfa248dc35883f990a108a0526ad57a0d5c7e490af170650',$edits$[
 [
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6",
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568"
 ],
 [
  "5f4d79319be4a204f916bfaec8a2eba532bcea8fc0aa228ea85d6b3de71e9fc3",
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306','049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce',$edits$[
 [
  "20fba0793c10a6151d7daf44763ea2b60c7dc7e90495e065e3a63c0f2b6838f6",
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','5c25a08a4dead51806b59e6debadccbcf33c4d25069d6a590e738b65379b783f','f00a6cd43c791f583cc70fbfa0eb14b189c9ac3bfa016b873557c302d3fcbcca',$edits$[
 [
  "e365f5053eac2cb3e4979dad86f0166f20c1704d62a5b18e4af28f3cc6fc5306",
  "049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested active member commit predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested active member commit replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active member commit body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active member commit installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested active member commit storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_nested_finish_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_nested_apply_v1();
DROP FUNCTION kaname._authority_role_move_nested_receipt_v1(integer,integer);
DROP FUNCTION kaname._authority_role_move_nested_certificate_v1(jsonb,integer,integer);
