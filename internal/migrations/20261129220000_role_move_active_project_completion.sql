-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_active_receipt_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $active$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1(); pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; sealed jsonb:=frame->'selector_move_active_project_seal'; cur jsonb:=frame->'selector_move_active_command_cursor';
    prepared jsonb:=frame->'selector_move'; decision jsonb:=frame->'selector_move_decision'; w jsonb:=sealed->'witness';
    req jsonb:=frame->'request'; origin_image jsonb:=pgm#>'{maximum,0,origin}'; plan jsonb:=decision->'predicate_plan';
    rid text:=prepared->>'role_id'; bid text:=w->>'binding_id'; pid text:=w->>'project_id';
    max_fga jsonb:=pgm#>'{maximum,1}'; old_role jsonb:=prepared#>'{role,physical}'; actual jsonb; want jsonb; new_image jsonb;
    published boolean:=jsonb_typeof(pgm->'selected')='array'; chosen jsonb; census jsonb:=prepared->'binding_census';
    source_hash text:=encode(sha256(convert_to(sealed::text,'UTF8')),'hex'); logical_rows integer:=32; logical_reads integer:=12; step jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN logical_rows+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN logical_reads+1 AND 4096 THEN
        RAISE EXCEPTION 'active role content replay budget exhausted' USING ERRCODE='54000';END IF;
    chosen:=CASE WHEN published THEN pgm->'selected' ELSE frame#>'{selector_move_pending,selected}' END;
    IF frame->>'selector_move_transport' IS DISTINCT FROM 'active_project_no_copy_v1' OR pgm->>'family' IS DISTINCT FROM 'role'
        OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR pgm->'nonce' IS DISTINCT FROM proof->'nonce'
        OR pgm->>'backend' IS DISTINCT FROM pg_backend_pid()::text OR pgm->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR pgm->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid' OR w->'nonce' IS DISTINCT FROM proof->'nonce'
        OR w->'xid' IS DISTINCT FROM pgm->'transaction_id' OR sealed->'invoker_oid' IS DISTINCT FROM proof->'invoker_oid'
        OR sealed->'model_id' IS DISTINCT FROM proof->'model_id' OR sealed->'catalog_id' IS DISTINCT FROM proof->'catalog_id'
        OR sealed->'projector_version' IS DISTINCT FROM proof->'projector_version' OR w->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR prepared->'actor' IS DISTINCT FROM sealed->'actor' OR decision->'actor' IS DISTINCT FROM sealed->'actor'
        OR jsonb_typeof(sealed->'actor') IS DISTINCT FROM 'object' OR frame->'selector_move_transport_actor' IS DISTINCT FROM sealed->'actor'
        OR prepared->'invoker_oid' IS DISTINCT FROM pgm->'invoker_oid' OR prepared->'nonce' IS DISTINCT FROM proof->'nonce'
        OR decision->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR ((proof->>'decision_at')::timestamptz>(prepared->>'prepared_at')::timestamptz) IS DISTINCT FROM true
        OR req->'create' IS DISTINCT FROM 'false'::jsonb OR req->'retier' IS DISTINCT FROM 'true'::jsonb OR req->'rules' IS DISTINCT FROM 'true'::jsonb
        OR req->'mask' IS DISTINCT FROM '["rules"]'::jsonb OR req#>>'{role,id}' IS DISTINCT FROM rid
        OR req->>'version' IS DISTINCT FROM old_role->>0 OR req#>'{role,rules}' IS DISTINCT FROM origin_image#>'{new,rules}'
        OR origin_image->>'table' IS DISTINCT FROM 'roles' OR origin_image->>'operation' IS DISTINCT FROM 'UPDATE'
        OR origin_image->'old' IS DISTINCT FROM old_role->2 OR origin_image#>>'{new,id}' IS DISTINCT FROM rid
        OR origin_image#>'{new,rules}' IS DISTINCT FROM prepared#>'{role,new_role,rules}' OR rid IS DISTINCT FROM w->>'role_id'
        OR prepared#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb OR decision->'commands' IS DISTINCT FROM '[]'::jsonb
        OR coalesce(bid,'')='' OR coalesce(pid,'')='' OR decision->'binding_status' IS DISTINCT FROM jsonb_build_object(bid,'ACTIVE')
        OR pgm->>'maximum_count' IS DISTINCT FROM '2' OR jsonb_array_length(chosen) IS DISTINCT FROM 2
        OR pgm#>>'{maximum,0,table}' IS DISTINCT FROM 'resource_journal' OR max_fga->>'table' IS DISTINCT FROM 'fga_outbox'
        OR max_fga#>>'{origin,family}' IS DISTINCT FROM 'role.selector_move.active_member'
        OR max_fga#>>'{origin,binding}' IS DISTINCT FROM bid OR max_fga#>>'{origin,role}' IS DISTINCT FROM rid OR max_fga#>>'{origin,project}' IS DISTINCT FROM pid
        OR max_fga#>'{origin,ledger_sha256}' IS DISTINCT FROM w->'ledger_sha256' OR pgm#>'{maximum,0,reserved_id}' IS DISTINCT FROM cur->'role_journal_id'
        OR chosen->0 IS DISTINCT FROM jsonb_set(pgm#>'{maximum,0}','{row,created_at}',to_jsonb(transaction_timestamp()),true)
        OR chosen->1 IS DISTINCT FROM jsonb_set(max_fga,'{row,created_at}',to_jsonb(transaction_timestamp()),true)
        OR cur->>'seal_sha256' IS DISTINCT FROM source_hash OR cur->'xid' IS DISTINCT FROM pgm->'transaction_id' OR cur->'nonce' IS DISTINCT FROM proof->'nonce' THEN
        RAISE EXCEPTION 'active role content lost exact method, actor or selected slots' USING ERRCODE='42501';END IF;
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO actual FROM ONLY kaname.roles r WHERE r.id=rid;
    IF published THEN
        IF pgm->'unselected' IS DISTINCT FROM '[]'::jsonb OR cur->>'last_consumed' IS DISTINCT FROM '4'
            OR cur->'deleted_member' IS DISTINCT FROM w->'member_old' OR actual->2 IS DISTINCT FROM origin_image->'new'
            OR pgm->'decision_at' IS DISTINCT FROM proof->'decision_at' THEN
            RAISE EXCEPTION 'active committed role or command cursor changed' USING ERRCODE='40001';END IF;
        want:=jsonb_build_array(cur->'member_new');
        new_image:=plan->'new_role_index'->(jsonb_build_array(13,'role',rid,'')::text)->'states';
        SELECT jsonb_agg(to_jsonb(v)) INTO actual FROM (SELECT s.* FROM ONLY kaname.role_rule_selectors s WHERE s.role_id=rid LIMIT 2) v;
        IF jsonb_array_length(new_image) IS DISTINCT FROM 1 OR jsonb_array_length(actual) IS DISTINCT FROM 1
            OR (actual->0)-ARRAY['created_at','updated_at'] IS DISTINCT FROM (new_image#>'{0,2}')-ARRAY['created_at','updated_at']
            OR actual#>>'{0,rule_fp}' IS DISTINCT FROM w->>'new_rule_fp' THEN
            RAISE EXCEPTION 'active committed selector projection changed' USING ERRCODE='40001';END IF;
    ELSE
        IF actual IS DISTINCT FROM old_role OR cur->>'last_consumed' IS DISTINCT FROM '1'
            OR pgm->'selected' IS DISTINCT FROM 'null'::jsonb OR frame#>'{selector_move_pending,unselected}' IS DISTINCT FROM '[]'::jsonb
            OR EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e WHERE e.selected OR e.registered OR e.claimed OR e.consumed) THEN
            RAISE EXCEPTION 'active proposal is not an untouched slot program' USING ERRCODE='40001';END IF;
        SELECT jsonb_agg(x ORDER BY (x->>1)::tid) INTO want FROM (VALUES(w->'member_old'),(cur->'member_new')) held_members(x);
    END IF;
    -- Состав меняется лишь в двух удостоверенных физических строках. Остальные
    -- строки binding, всех subjects и ledger проверяет прежняя полная перепись.
    step:=kaname._authority_role_move_binding_census_v1(rid,jsonb_set(census,'{members}',want),p_rows-logical_rows,p_reads-logical_reads);
    logical_rows:=logical_rows+(step->>'rows')::integer;logical_reads:=logical_reads+(step->>'reads')::integer;
    IF step->'binding_status' IS DISTINCT FROM decision->'binding_status' THEN RAISE EXCEPTION 'active carrier changed' USING ERRCODE='40001';END IF;
    step:=kaname._authority_role_move_finite_positions_v1(prepared,plan,true,p_rows-logical_rows,p_reads-logical_reads);
    logical_rows:=logical_rows+(step->>'rows')::integer;logical_reads:=logical_reads+(step->>'reads')::integer;
    IF step->'positions' IS DISTINCT FROM decision->'finite_positions' THEN RAISE EXCEPTION 'active role finite positions changed' USING ERRCODE='40001';END IF;
    step:=kaname._authority_role_move_member_projects_v1(plan,census||jsonb_build_object('moved_role_id',rid),prepared->'member_projects',p_rows-logical_rows,p_reads-logical_reads);
    logical_rows:=logical_rows+(step->>'rows')::integer;logical_reads:=logical_reads+(step->>'reads')::integer;
    IF step->'source' IS DISTINCT FROM prepared->'member_projects' THEN RAISE EXCEPTION 'active project or ancestry changed' USING ERRCODE='40001';END IF;
    RETURN jsonb_build_object('rows',logical_rows,'reads',logical_reads,'receipt',jsonb_build_object('contract','RequireRole/v1+v_update+RequireSelectorMoveGrants/v1',
        'operation','role.update','actor',sealed->'actor','role_id',rid,'role_generation',jsonb_build_array(old_role->0,old_role->1),
        'binding_id',bid,'decision_at',proof->'decision_at','nonce',proof->'nonce','invoker_oid',proof->'invoker_oid','backend',pgm->'backend','transaction_id',pgm->'transaction_id',
        'source_sha256',source_hash,'selected_sha256',encode(sha256(convert_to(chosen::text,'UTF8')),'hex')));
END;
$active$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_active_finish_v1(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $active$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1(); pgm jsonb:=kaname._authority_sequence_store_v3();
    frame jsonb:=pgm->'frozen'; step jsonb; source_hash text; content_hash text; content jsonb; limits jsonb;
    rows_left integer:=p_rows-12;reads_left integer:=p_reads-12;phase integer;sr integer;sd integer;
    replay_rows integer;replay_reads integer;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 13 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 13 AND 4096 OR octet_length(p_input::text)>131072 THEN
        RAISE EXCEPTION 'active role finish budget exhausted' USING ERRCODE='54000';END IF;
    IF frame->>'selector_move_transport' IS DISTINCT FROM 'active_project_no_copy_v1' OR pgm->>'family' IS DISTINCT FROM 'role'
        OR frame->>'mode' IS DISTINCT FROM 'selector_move' OR pgm->'nonce' IS DISTINCT FROM proof->'nonce'
        OR pgm->>'maximum_count' IS DISTINCT FROM '2' OR pgm->'selected' IS DISTINCT FROM 'null'::jsonb
        OR pgm->'decision_at' IS DISTINCT FROM 'null'::jsonb OR frame->'selector_move_transport_actor' IS DISTINCT FROM frame#>'{selector_move,actor}'
        OR ((proof->>'decision_at')::timestamptz>(frame#>>'{selector_move,prepared_at}')::timestamptz) IS DISTINCT FROM true
        OR frame ?| ARRAY['selector_move_decision','selector_move_pending','selector_move_active_project_seal','selector_move_active_command_cursor',
            'selector_move_active_replay','selector_move_content_approval','selector_move_approved','selector_move_pending_sources']
        OR jsonb_typeof(p_input) IS DISTINCT FROM 'object' OR NOT (p_input ?& ARRAY['coordinates','commands']) THEN
        RAISE EXCEPTION 'active role finish requires its fresh enrolled transport' USING ERRCODE='42501';END IF;
    FOR phase IN 1..4 LOOP
        CASE phase
            WHEN 1 THEN step:=kaname._authority_role_move_sequence_finalize_v1('[]'::jsonb,rows_left,reads_left);
            WHEN 2 THEN step:=kaname._authority_role_move_active_project_seal_v1(p_input,rows_left,reads_left);
            WHEN 3 THEN step:=kaname._authority_role_move_active_member_insert_v1(rows_left,reads_left);
            WHEN 4 THEN step:=kaname._authority_role_move_active_receipt_v1(rows_left,reads_left);
        END CASE;
        sr:=(step->>'rows')::integer;sd:=(step->>'reads')::integer;
        IF sr IS NULL OR sr NOT BETWEEN 1 AND rows_left OR sd IS NULL OR sd NOT BETWEEN 1 AND reads_left THEN
            RAISE EXCEPTION 'active role phase cost exceeds budget' USING ERRCODE='54000';END IF;
        rows_left:=rows_left-sr;reads_left:=reads_left-sd;
        IF phase=2 THEN source_hash:=step->>'sha256';END IF;
    END LOOP;
    content:=step->'receipt';content_hash:=encode(sha256(convert_to(content::text,'UTF8')),'hex');
    IF jsonb_typeof(content) IS DISTINCT FROM 'object' OR content->>'source_sha256' IS DISTINCT FROM source_hash OR source_hash IS NULL THEN
        RAISE EXCEPTION 'active source and role-content replay disagree' USING ERRCODE='42501';END IF;
    -- Второе чтение выполняет общий publisher, третье — deferred trigger.
    -- Запас покрывает фиксированный SQL publisher и смену OLD+NEW на единственный NEW.
    replay_rows:=sr+20;replay_reads:=sd+10;
    IF rows_left<2*replay_rows OR reads_left<2*replay_reads THEN RAISE EXCEPTION 'active role replay credit absent' USING ERRCODE='54000';END IF;
    limits:=jsonb_build_object('rows',replay_rows,'reads',replay_reads);
    frame:=kaname._authority_sequence_store_v3()->'frozen';
    IF octet_length(frame::text)+octet_length(content::text)+256>8388608 THEN
        RAISE EXCEPTION 'active role content exceeds frame' USING ERRCODE='54000';END IF;
    UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object(
        'selector_move_content_approval',content,'selector_move_active_replay',limits)
        WHERE s.singleton AND s.family='role' AND s.nonce=(proof->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=frame;
    IF NOT FOUND THEN RAISE EXCEPTION 'active role content owner frame changed' USING ERRCODE='40001';END IF;
    PERFORM kaname._authority_role_move_sequence_approve_v1();
    pgm:=kaname._authority_sequence_store_v3();frame:=pgm->'frozen';
    IF pgm->>'selected_count' IS DISTINCT FROM '2' OR pgm->'unselected' IS DISTINCT FROM '[]'::jsonb OR pgm->'decision_at' IS DISTINCT FROM proof->'decision_at'
        OR frame->>'selector_move_approved_content_sha256' IS DISTINCT FROM content_hash OR frame->'selector_move_content_approval' IS DISTINCT FROM content
        OR frame#>>'{selector_move_active_command_cursor,last_consumed}' IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'active role slot publication differs from content' USING ERRCODE='40001';END IF;
    rows_left:=rows_left-replay_rows;reads_left:=reads_left-replay_reads;
    RETURN jsonb_build_object('selector_move_transport','active_project_no_copy_v1','phase','selected','source_sha256',source_hash,'content_sha256',content_hash,
        'rows',p_rows-rows_left,'reads',p_reads-reads_left,'deferred_rows',rows_left,'deferred_reads',reads_left);
END;
$active$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure;grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY['kaname._authority_role_move_active_receipt_v1(integer,integer)'::regprocedure,
        'kaname._authority_role_move_active_finish_v1(jsonb,integer,integer)'::regprocedure] LOOP
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
        ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1','bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854',$edits$[
 [
  "row_cost integer:=4;",
  "transport text:=p_input->>'_selector_move';\n    row_cost integer:=4;"
 ],
 [
  "p_input->'_selector_move' IS DISTINCT FROM '\"pending_no_copy_v1\"'::jsonb",
  "coalesce(transport,'') NOT IN ('pending_no_copy_v1','active_project_no_copy_v1')"
 ],
 [
  "OR program->>'maximum_count' IS DISTINCT FROM '1'",
  "OR program->>'maximum_count' IS DISTINCT FROM (CASE transport WHEN 'active_project_no_copy_v1' THEN '2' ELSE '1' END)"
 ],
 [
  "binding_image->>'status' IS DISTINCT FROM 'PENDING'",
  "binding_image->>'status' IS DISTINCT FROM (CASE transport WHEN 'active_project_no_copy_v1' THEN 'ACTIVE' ELSE 'PENDING' END)"
 ],
 [
  "census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1",
  "(transport='pending_no_copy_v1' AND (census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1))\n        OR (transport='active_project_no_copy_v1' AND (jsonb_array_length(census->'members') IS DISTINCT FROM 1 OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 3\n            OR program#>>'{maximum,1,origin,family}' IS DISTINCT FROM 'role.selector_move.active_member'\n            OR program#>>'{maximum,1,origin,role}' IS DISTINCT FROM prepared->>'role_id' OR program#>>'{maximum,1,origin,binding}' IS DISTINCT FROM binding_image->>'id'\n            OR program#>>'{maximum,1,origin,project}' IS DISTINCT FROM target_project))"
 ],
 [
  "octet_length(held::text)+64",
  "octet_length(held::text)+64+(CASE WHEN transport='active_project_no_copy_v1' THEN octet_length((authority_input->'actor')::text)+48 ELSE 0 END)"
 ],
 [
  "s.frozen||jsonb_build_object('selector_move_transport','pending_no_copy_v1')",
  "s.frozen||jsonb_build_object('selector_move_transport',transport)\n        ||CASE WHEN transport='active_project_no_copy_v1' THEN jsonb_build_object('selector_move_transport_actor',authority_input->'actor') ELSE '{}'::jsonb END"
 ],
 [
  "'selector_move_transport','pending_no_copy_v1');",
  "'selector_move_transport',transport);"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422','10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab',$edits$[
 [
  "            ELSE c.cmd IS NOT NULL END AS selected",
  "            WHEN frozen->>'selector_move_transport'='active_project_no_copy_v1' AND fixed=1 AND slot_count=2 AND s.position=2\n                AND s.value->>'table'='fga_outbox' AND s.value#>>'{origin,family}'='role.selector_move.active_member'\n                AND decision->'commands'='[]'::jsonb AND decision->'binding_status'=jsonb_build_object(s.value#>>'{origin,binding}','ACTIVE')\n                AND s.value#>'{origin,role}'=decision->'role_id' THEN true\n            ELSE c.cmd IS NOT NULL END AS selected"
 ]
]$edits$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004','31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6',$edits$[
 [
  "    -- Публичный prepare",
  "    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n    -- Публичный prepare"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a','aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126',$edits$[
 [
  "||(CASE WHEN s.frozen ? 'selector_move_pending_sources' THEN",
  "||(CASE WHEN s.frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n                jsonb_build_object('selector_move_approved_content_sha256',encode(sha256(convert_to((s.frozen->'selector_move_content_approval')::text,'UTF8')),'hex'))\n                WHEN s.frozen ? 'selector_move_pending_sources' THEN"
 ]
]$edits$::jsonb),
        ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4','5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a',$edits$[
 [
  "    RETURN kaname.authority_role_move_pending_finalize_v1",
  "    IF p_sets ? 'commands' THEN\n        RETURN kaname._authority_role_move_active_finish_v1(p_sets,p_rows,p_reads);\n    END IF;\n    RETURN kaname.authority_role_move_pending_finalize_v1"
 ]
]$edits$::jsonb),
        ('_authority_role_move_active_write_record_v1(integer,integer)','27b1481cea9bf6b0745b4f42edaaef22b73eb0dc61d9d72cae248d2bbe3d353d','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39',$edits$[
 [
  "    cursor_row:=cursor_row||jsonb_build_object('last_consumed',3,'outbox',outbox_image,'viewer_new',viewer_new);",
  "    -- Команда 4 относится к тому же transaction, seal и program ordinal.\n    -- Удаляем единственный OLD по полной физической версии. В PK участника входит rule_fp.\n    IF commands#>>'{3,Kind}' IS DISTINCT FROM 'member_delete' OR commands#>>'{3,Binding}' IS DISTINCT FROM bid\n        OR commands#>>'{3,Member,ObjectType}' IS DISTINCT FROM 'iam.project' OR commands#>>'{3,Member,ObjectID}' IS DISTINCT FROM pid\n        OR commands#>>'{3,RuleFP}' IS DISTINCT FROM witness#>>'{member_old,2,rule_fp}'\n        OR commands#>>'{3,RuleFP}' IS NOT DISTINCT FROM witness->>'new_rule_fp' THEN\n        RAISE EXCEPTION 'active removal differs from sealed old fingerprint' USING ERRCODE='42501';END IF;\n    DELETE FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=bid AND m.role_id=rid\n        AND m.object_type='iam.project' AND m.object_id=pid AND m.rule_fp=commands#>>'{3,RuleFP}'\n        AND jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))=witness->'member_old'\n        RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO actual;\n    IF NOT FOUND OR actual IS DISTINCT FROM witness->'member_old' THEN\n        RAISE EXCEPTION 'active removed member is stale' USING ERRCODE='40001';END IF;\n    cursor_row:=cursor_row||jsonb_build_object('last_consumed',4,'outbox',outbox_image,\n        'viewer_new',viewer_new,'deleted_member',actual);"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba','746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8',$edits$[
 [
  "p_rows-used_rows<84 OR p_reads-used_reads<33",
  "p_rows-used_rows<88 OR p_reads-used_reads<35"
 ],
 [
  "used_rows:=used_rows+84;used_reads:=used_reads+33",
  "used_rows:=used_rows+88;used_reads:=used_reads+35"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f','d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac',$edits$[
 [
  "32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1",
  "bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854"
 ],
 [
  "ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422",
  "10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab"
 ],
 [
  "b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004",
  "31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6"
 ],
 [
  "21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a",
  "aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126"
 ],
 [
  "2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4",
  "5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a"
 ],
 [
  "27b1481cea9bf6b0745b4f42edaaef22b73eb0dc61d9d72cae248d2bbe3d353d",
  "28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39"
 ],
 [
  "a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba",
  "746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8"
 ],
 [
  " ('_authority_role_move_active_write_record_v1(integer,integer)','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39',false,'v',true,'private'),\n",
  " ('_authority_role_move_active_write_record_v1(integer,integer)','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39',false,'v',true,'private'),\n ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826',false,'v',true,'private'),\n ('_authority_role_move_active_project_seal_v1(jsonb,integer,integer)','4959735c66dec9dc2cdc0a796ff5c1637ffd0b892a33a4942f24e3b39d905bcf',false,'v',true,'private'),\n ('_authority_role_move_active_member_insert_v1(integer,integer)','c05e1765ce725e7fa821bef8fd194c6f1e584ab176e86fd2fa640408b842bdba',false,'v',true,'private'),\n ('_authority_role_move_active_receipt_v1(integer,integer)','311e8cdc554273f0aa1ab78b54f9a3b0ee959eff1871f803101803d3171b4e9a',false,'v',true,'private'),\n ('_authority_role_move_active_finish_v1(jsonb,integer,integer)','6a7a7a501eaa13f459bd1b31727c43b70c748689d7d87873f9b7c0b37449bb72',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n",
  "  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_coordinates','p_rows','p_reads']),\n  ('_authority_role_move_active_project_seal_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_active_member_insert_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_receipt_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131','ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b',$edits$[
 [
  "e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f",
  "d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','ef3f0d3afdf5f9deaaaaf0fc08029a6329b43d1954e79d279ed2248c95236587','3dcd78286c42a56371a2111c13e3d78c618d5f092d57dfe2ed81449bdea05afa',$edits$[
 [
  "e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f",
  "d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac"
 ],
 [
  "677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131",
  "ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','d633306d362ebdeef19c87786ce6c194de52e5e8225ddc55395b6b3b8f68bcab','472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4',$edits$[
 [
  "677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131",
  "ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','7f490f6bd3b4573ab4bdc228640d19b9e3515707636c634d727e1b2df9cfa22c','d3f1433033dc3c43fd8aa9bb3bf965cc6b888f7db2337fee156a580367d87405',$edits$[
 [
  "d633306d362ebdeef19c87786ce6c194de52e5e8225ddc55395b6b3b8f68bcab",
  "472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active project content and member predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active project content and member replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project content and member body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project content and member installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active project content and member storage graph differs' USING ERRCODE='55000';
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
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','d3f1433033dc3c43fd8aa9bb3bf965cc6b888f7db2337fee156a580367d87405','7f490f6bd3b4573ab4bdc228640d19b9e3515707636c634d727e1b2df9cfa22c',$edits$[
 [
  "472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4",
  "d633306d362ebdeef19c87786ce6c194de52e5e8225ddc55395b6b3b8f68bcab"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','472060c1ff35f223c9b960cbefd4a35793af442ec2551582dd8617d9923127b4','d633306d362ebdeef19c87786ce6c194de52e5e8225ddc55395b6b3b8f68bcab',$edits$[
 [
  "ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b",
  "677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','3dcd78286c42a56371a2111c13e3d78c618d5f092d57dfe2ed81449bdea05afa','ef3f0d3afdf5f9deaaaaf0fc08029a6329b43d1954e79d279ed2248c95236587',$edits$[
 [
  "ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b",
  "677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131"
 ],
 [
  "d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac",
  "e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','ecb3b446e31adeb43418742d3a012ff321fc42ce39ae3b9cfc0efbca65479e7b','677ff8c9ba5c7dbaf62e23beb04ce5e30963333ef42035133aec77bb4234d131',$edits$[
 [
  "d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac",
  "e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','d22a84673647caece6ca57630ddae79bf7a9b73740996ed5885d8c88ce92b7ac','e6bc6d79e9b014a65ac66a7471dc10b25626e616b1348105e7f6f14191dfbc2f',$edits$[
 [
  "  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_coordinates','p_rows','p_reads']),\n  ('_authority_role_move_active_project_seal_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_active_member_insert_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_receipt_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n  ('_authority_role_move_active_finish_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n",
  "  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_active_write_record_v1(integer,integer)','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39',false,'v',true,'private'),\n ('_authority_role_move_active_project_witness_v1(jsonb,integer,integer)','6cd17d6bdd7e630c45a642ec8b0373df820ae30361d007eb35779cb861a01826',false,'v',true,'private'),\n ('_authority_role_move_active_project_seal_v1(jsonb,integer,integer)','4959735c66dec9dc2cdc0a796ff5c1637ffd0b892a33a4942f24e3b39d905bcf',false,'v',true,'private'),\n ('_authority_role_move_active_member_insert_v1(integer,integer)','c05e1765ce725e7fa821bef8fd194c6f1e584ab176e86fd2fa640408b842bdba',false,'v',true,'private'),\n ('_authority_role_move_active_receipt_v1(integer,integer)','311e8cdc554273f0aa1ab78b54f9a3b0ee959eff1871f803101803d3171b4e9a',false,'v',true,'private'),\n ('_authority_role_move_active_finish_v1(jsonb,integer,integer)','6a7a7a501eaa13f459bd1b31727c43b70c748689d7d87873f9b7c0b37449bb72',false,'v',true,'private'),\n",
  " ('_authority_role_move_active_write_record_v1(integer,integer)','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39',false,'v',true,'private'),\n"
 ],
 [
  "746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8",
  "a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba"
 ],
 [
  "28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39",
  "27b1481cea9bf6b0745b4f42edaaef22b73eb0dc61d9d72cae248d2bbe3d353d"
 ],
 [
  "5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a",
  "2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4"
 ],
 [
  "aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126",
  "21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a"
 ],
 [
  "31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6",
  "b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004"
 ],
 [
  "10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab",
  "ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422"
 ],
 [
  "bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854",
  "32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8','a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba',$edits$[
 [
  "used_rows:=used_rows+88;used_reads:=used_reads+35",
  "used_rows:=used_rows+84;used_reads:=used_reads+33"
 ],
 [
  "p_rows-used_rows<88 OR p_reads-used_reads<35",
  "p_rows-used_rows<84 OR p_reads-used_reads<33"
 ]
]$edits$::jsonb),
        ('_authority_role_move_active_write_record_v1(integer,integer)','28b9bf7d1eb307e4315a7884c91a5d1f9795215ec514b9b4cf3149c9de767f39','27b1481cea9bf6b0745b4f42edaaef22b73eb0dc61d9d72cae248d2bbe3d353d',$edits$[
 [
  "    -- Команда 4 относится к тому же transaction, seal и program ordinal.\n    -- Удаляем единственный OLD по полной физической версии. В PK участника входит rule_fp.\n    IF commands#>>'{3,Kind}' IS DISTINCT FROM 'member_delete' OR commands#>>'{3,Binding}' IS DISTINCT FROM bid\n        OR commands#>>'{3,Member,ObjectType}' IS DISTINCT FROM 'iam.project' OR commands#>>'{3,Member,ObjectID}' IS DISTINCT FROM pid\n        OR commands#>>'{3,RuleFP}' IS DISTINCT FROM witness#>>'{member_old,2,rule_fp}'\n        OR commands#>>'{3,RuleFP}' IS NOT DISTINCT FROM witness->>'new_rule_fp' THEN\n        RAISE EXCEPTION 'active removal differs from sealed old fingerprint' USING ERRCODE='42501';END IF;\n    DELETE FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=bid AND m.role_id=rid\n        AND m.object_type='iam.project' AND m.object_id=pid AND m.rule_fp=commands#>>'{3,RuleFP}'\n        AND jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))=witness->'member_old'\n        RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO actual;\n    IF NOT FOUND OR actual IS DISTINCT FROM witness->'member_old' THEN\n        RAISE EXCEPTION 'active removed member is stale' USING ERRCODE='40001';END IF;\n    cursor_row:=cursor_row||jsonb_build_object('last_consumed',4,'outbox',outbox_image,\n        'viewer_new',viewer_new,'deleted_member',actual);",
  "    cursor_row:=cursor_row||jsonb_build_object('last_consumed',3,'outbox',outbox_image,'viewer_new',viewer_new);"
 ]
]$edits$::jsonb),
        ('authority_role_move_enrolled_finish_v1(jsonb,integer,integer)','5bac298f5f76bc4e6e72c7f595d2958c6947787b2b3f71aebe16d79b916bc24a','2421cff1eaeb06a585e12505fe38f8e636698a5977dd1e176f49b2b120c7d0c4',$edits$[
 [
  "    IF p_sets ? 'commands' THEN\n        RETURN kaname._authority_role_move_active_finish_v1(p_sets,p_rows,p_reads);\n    END IF;\n    RETURN kaname.authority_role_move_pending_finalize_v1",
  "    RETURN kaname.authority_role_move_pending_finalize_v1"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_approve_v1()','aa0f1930c57c0c63a9af76a58bb0afedbc8e1400b498e7942034fe45a8191126','21661aeae6a43fd14316b73d2b71a8994ef87b7a154c2d55623376df9f7b3d3a',$edits$[
 [
  "||(CASE WHEN s.frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n                jsonb_build_object('selector_move_approved_content_sha256',encode(sha256(convert_to((s.frozen->'selector_move_content_approval')::text,'UTF8')),'hex'))\n                WHEN s.frozen ? 'selector_move_pending_sources' THEN",
  "||(CASE WHEN s.frozen ? 'selector_move_pending_sources' THEN"
 ]
]$edits$::jsonb),
        ('_authority_role_move_binding_empty_require_v1(jsonb)','31a2e3c7d7f3484bbbf88f907d15f23b70cd6634cbc5402380df17630bd350a6','b846e2025d6246d9b9431667f828b05abd86594bbb142bee38e46ad9d44ef004',$edits$[
 [
  "    IF p_frozen->>'selector_move_transport'='active_project_no_copy_v1' THEN\n        DECLARE\n            program jsonb:=kaname._authority_sequence_store_v3(); approval_image jsonb:=p_frozen->'selector_move_content_approval';\n            allowance jsonb:=p_frozen->'selector_move_active_replay'; replay jsonb;\n        BEGIN\n            IF p_frozen IS DISTINCT FROM program->'frozen' OR jsonb_typeof(allowance) IS DISTINCT FROM 'object'\n                OR jsonb_typeof(approval_image) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frozen->'selector_move_active_project_seal') IS DISTINCT FROM 'object'\n                OR ((p_frozen ? 'selector_move_approved') IS DISTINCT FROM (p_frozen ? 'selector_move_approved_content_sha256'))\n                OR ((p_frozen ? 'selector_move_approved') AND p_frozen->>'selector_move_approved_content_sha256' IS DISTINCT FROM\n                    encode(sha256(convert_to(approval_image::text,'UTF8')),'hex')) THEN\n                RAISE EXCEPTION 'active role has no bound approval and replay allowance' USING ERRCODE='42501';END IF;\n            replay:=kaname._authority_role_move_active_receipt_v1((allowance->>'rows')::integer,(allowance->>'reads')::integer);\n            IF replay->'receipt' IS DISTINCT FROM approval_image THEN\n                RAISE EXCEPTION 'active role content changed after owner approval' USING ERRCODE='40001';END IF;\n        END;\n        RETURN;\n    END IF;\n    -- Публичный prepare",
  "    -- Публичный prepare"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_publish_v1(jsonb,integer,integer)','10785c1ad5e325ab5f251a9cc32c9fbfea5f09f04010fa9e1e23aa4d554859ab','ffb2a3fe0779973dc73ab270a18d6386bc62931b995a751f98bd612da0fc7422',$edits$[
 [
  "            WHEN frozen->>'selector_move_transport'='active_project_no_copy_v1' AND fixed=1 AND slot_count=2 AND s.position=2\n                AND s.value->>'table'='fga_outbox' AND s.value#>>'{origin,family}'='role.selector_move.active_member'\n                AND decision->'commands'='[]'::jsonb AND decision->'binding_status'=jsonb_build_object(s.value#>>'{origin,binding}','ACTIVE')\n                AND s.value#>'{origin,role}'=decision->'role_id' THEN true\n            ELSE c.cmd IS NOT NULL END AS selected",
  "            ELSE c.cmd IS NOT NULL END AS selected"
 ]
]$edits$::jsonb),
        ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854','32d277a02b227a7966b8339fc9aebe5ac4139fb71b95cf2a8535d390a46bd1c1',$edits$[
 [
  "'selector_move_transport',transport);",
  "'selector_move_transport','pending_no_copy_v1');"
 ],
 [
  "s.frozen||jsonb_build_object('selector_move_transport',transport)\n        ||CASE WHEN transport='active_project_no_copy_v1' THEN jsonb_build_object('selector_move_transport_actor',authority_input->'actor') ELSE '{}'::jsonb END",
  "s.frozen||jsonb_build_object('selector_move_transport','pending_no_copy_v1')"
 ],
 [
  "octet_length(held::text)+64+(CASE WHEN transport='active_project_no_copy_v1' THEN octet_length((authority_input->'actor')::text)+48 ELSE 0 END)",
  "octet_length(held::text)+64"
 ],
 [
  "(transport='pending_no_copy_v1' AND (census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1))\n        OR (transport='active_project_no_copy_v1' AND (jsonb_array_length(census->'members') IS DISTINCT FROM 1 OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 3\n            OR program#>>'{maximum,1,origin,family}' IS DISTINCT FROM 'role.selector_move.active_member'\n            OR program#>>'{maximum,1,origin,role}' IS DISTINCT FROM prepared->>'role_id' OR program#>>'{maximum,1,origin,binding}' IS DISTINCT FROM binding_image->>'id'\n            OR program#>>'{maximum,1,origin,project}' IS DISTINCT FROM target_project))",
  "census->'members' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 1"
 ],
 [
  "binding_image->>'status' IS DISTINCT FROM (CASE transport WHEN 'active_project_no_copy_v1' THEN 'ACTIVE' ELSE 'PENDING' END)",
  "binding_image->>'status' IS DISTINCT FROM 'PENDING'"
 ],
 [
  "OR program->>'maximum_count' IS DISTINCT FROM (CASE transport WHEN 'active_project_no_copy_v1' THEN '2' ELSE '1' END)",
  "OR program->>'maximum_count' IS DISTINCT FROM '1'"
 ],
 [
  "coalesce(transport,'') NOT IN ('pending_no_copy_v1','active_project_no_copy_v1')",
  "p_input->'_selector_move' IS DISTINCT FROM '\"pending_no_copy_v1\"'::jsonb"
 ],
 [
  "transport text:=p_input->>'_selector_move';\n    row_cost integer:=4;",
  "row_cost integer:=4;"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active project content and member predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active project content and member replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project content and member body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active project content and member installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active project content and member storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_role_move_active_finish_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_role_move_active_receipt_v1(integer,integer);
