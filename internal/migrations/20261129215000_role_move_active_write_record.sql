-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_active_write_record_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $consume$
DECLARE
    att jsonb:=kaname._authority_role_move_attestation_v1();
    program jsonb:=kaname._authority_sequence_store_v3(); frame jsonb:=program->'frozen';
    seal jsonb:=frame->'selector_move_active_project_seal'; cursor_row jsonb:=frame->'selector_move_active_command_cursor';
    approval jsonb:=frame->'selector_move_approved'; content jsonb:=frame->'selector_move_content_approval';
    witness jsonb:=seal->'witness'; chosen jsonb:=program->'selected'; fga jsonb:=chosen->1;
    source jsonb:=fga->'origin'; wanted jsonb:=fga->'row'; commands jsonb:=seal#>'{input,commands}';
    ledger jsonb:=frame#>'{selector_move,binding_census,ledger}'; actual jsonb; expected jsonb;
    bid text:=witness->>'binding_id'; rid text:=witness->>'role_id'; pid text:=witness->>'project_id';
    member_ref jsonb; outbox_image jsonb; viewer_new jsonb; touched integer; claimed bigint;
    digest text:=encode(sha256(convert_to(seal::text,'UTF8')),'hex');
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 40 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 18 AND 4096 THEN
        RAISE EXCEPTION 'active write and ledger budget exhausted' USING ERRCODE='54000';END IF;
    IF program->>'family' IS DISTINCT FROM 'role' OR frame->>'mode' IS DISTINCT FROM 'selector_move'
        OR jsonb_typeof(seal) IS DISTINCT FROM 'object' OR jsonb_typeof(content) IS DISTINCT FROM 'object'
        OR program->'nonce' IS DISTINCT FROM att->'nonce' OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text OR program->'invoker_oid' IS DISTINCT FROM att->'invoker_oid'
        OR witness->'xid' IS DISTINCT FROM program->'transaction_id' OR witness->'nonce' IS DISTINCT FROM att->'nonce'
        OR cursor_row->>'last_consumed' IS DISTINCT FROM '1' OR cursor_row->>'seal_sha256' IS DISTINCT FROM digest
        OR cursor_row->'xid' IS DISTINCT FROM program->'transaction_id' OR cursor_row->'nonce' IS DISTINCT FROM att->'nonce'
        OR jsonb_typeof(chosen) IS DISTINCT FROM 'array' OR jsonb_array_length(chosen) IS DISTINCT FROM 2
        OR program->'unselected' IS DISTINCT FROM '[]'::jsonb OR program->'decision_at' IS DISTINCT FROM att->'decision_at'
        OR frame->>'selector_move_approved_content_sha256' IS DISTINCT FROM encode(sha256(convert_to(content::text,'UTF8')),'hex')
        OR approval IS DISTINCT FROM jsonb_build_object('actor',seal->'actor','role_id',rid,'nonce',att->'nonce','decision_at',att->'decision_at')
        OR content->>'contract' IS DISTINCT FROM 'RequireRole/v1+v_update+RequireSelectorMoveGrants/v1' OR content->>'operation' IS DISTINCT FROM 'role.update'
        OR content->'actor' IS DISTINCT FROM seal->'actor' OR content->'nonce' IS DISTINCT FROM att->'nonce'
        OR content->'decision_at' IS DISTINCT FROM att->'decision_at' OR content->>'role_id' IS DISTINCT FROM rid OR content->>'binding_id' IS DISTINCT FROM bid
        OR content->'invoker_oid' IS DISTINCT FROM att->'invoker_oid' OR content->'backend' IS DISTINCT FROM program->'backend'
        OR content->'transaction_id' IS DISTINCT FROM program->'transaction_id' OR content->>'source_sha256' IS DISTINCT FROM digest
        OR content->>'selected_sha256' IS DISTINCT FROM encode(sha256(convert_to(chosen::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'active member write requires published actor approval and first command' USING ERRCODE='42501';END IF;
    IF fga->>'table' IS DISTINCT FROM 'fga_outbox' OR fga->>'ordinal' IS DISTINCT FROM '2'
        OR source->>'family' IS DISTINCT FROM 'role.selector_move.active_member' OR source->>'binding' IS DISTINCT FROM bid
        OR source->>'role' IS DISTINCT FROM rid OR source->>'project' IS DISTINCT FROM pid OR source->>'rule_fp' IS DISTINCT FROM witness#>>'{member_old,2,rule_fp}'
        OR source->'ledger_sha256' IS DISTINCT FROM witness->'ledger_sha256' OR source->>'ledger_sha256' IS DISTINCT FROM encode(sha256(convert_to(ledger::text,'UTF8')),'hex')
        OR fga->'origin' IS DISTINCT FROM program#>'{maximum,1,origin}' OR fga->'reserved_id' IS DISTINCT FROM program#>'{maximum,1,reserved_id}'
        OR wanted IS DISTINCT FROM (program#>'{maximum,1,row}')||jsonb_build_object('created_at',transaction_timestamp())
        OR wanted->>'event_type' IS DISTINCT FROM 'fga.tuple.write' OR jsonb_array_length(commands) IS DISTINCT FROM 4
        OR commands#>>'{1,Kind}' IS DISTINCT FROM 'write' OR commands#>>'{2,Kind}' IS DISTINCT FROM 'record'
        OR jsonb_array_length(commands#>'{1,Tuples}') IS DISTINCT FROM 2 OR jsonb_array_length(commands#>'{2,Refs}') IS DISTINCT FROM 2
        OR chosen#>>'{0,table}' IS DISTINCT FROM 'resource_journal' OR chosen#>'{0,reserved_id}' IS DISTINCT FROM cursor_row->'role_journal_id'
        OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e JOIN ONLY kaname.resource_journal j ON j.sequence_no=e.reserved_id
            WHERE e.nonce=(att->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal' AND e.reserved_id=(chosen#>>'{0,reserved_id}')::bigint
            AND e.selected AND e.registered AND e.claimed AND e.consumed AND e.origin=chosen#>'{0,origin}' AND e.row_value=to_jsonb(j)-'sequence_no')
        OR NOT EXISTS(SELECT FROM ONLY kaname.roles r WHERE r.id=rid AND to_jsonb(r)=chosen#>'{0,origin,new}') THEN
        RAISE EXCEPTION 'active member storage differs from approved slots' USING ERRCODE='40001';END IF;
    expected:=jsonb_build_array(witness->'member_old',cursor_row->'member_new');
    SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) ORDER BY m.rule_fp=witness->>'new_rule_fp')
        INTO actual FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=bid;
    IF actual IS DISTINCT FROM expected OR jsonb_array_length(ledger) IS DISTINCT FROM 3 OR EXISTS(
        SELECT FROM jsonb_array_elements(ledger) l WHERE NOT EXISTS(SELECT FROM ONLY kaname.access_binding_emitted_tuples t WHERE t.binding_id=bid
            AND t.member_object_type=l#>>'{2,member_object_type}' AND t.member_object_id=l#>>'{2,member_object_id}' AND t.fga_user=l#>>'{2,fga_user}'
            AND t.relation=l#>>'{2,relation}' AND t.object=l#>>'{2,object}' AND jsonb_build_array(t.xmin::text,t.ctid::text,to_jsonb(t))=l)) THEN
        RAISE EXCEPTION 'active member or old ledger changed' USING ERRCODE='40001';END IF;

    SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO actual FROM ONLY kaname.relation_fact f
        WHERE f.object_type='project' AND f.object_id=pid AND f.relation='viewer' AND f.subject=source->>'user';
    IF actual IS DISTINCT FROM source->'viewer_old' OR jsonb_typeof(actual) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'active viewer changed after reservation' USING ERRCODE='40001';END IF;
    -- Тот же matcher и AFTER-consume, что у общего sequence. Все параметры DML выводятся из selected.
    claimed:=kaname._authority_sequence_claim_v3('fga_outbox',source,wanted);
    IF claimed IS DISTINCT FROM (fga->>'reserved_id')::bigint THEN
        RAISE EXCEPTION 'active member received a foreign FGA ID' USING ERRCODE='40001';END IF;
    INSERT INTO kaname.fga_outbox AS q(id,event_type,payload,created_at)
        VALUES(claimed,wanted->>'event_type',wanted->'payload',(wanted->>'created_at')::timestamptz)
        RETURNING jsonb_build_array(q.xmin::text,q.ctid::text,to_jsonb(q)) INTO outbox_image;
    SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO viewer_new FROM ONLY kaname.relation_fact f
        WHERE f.object_type='project' AND f.object_id=pid AND f.relation='viewer' AND f.subject=source->>'user';
    expected:=(actual->2)||jsonb_build_object('source_version',greatest((actual#>>'{2,source_version}')::timestamptz,transaction_timestamp()));
    IF (viewer_new->2) IS DISTINCT FROM expected OR (outbox_image->2) IS DISTINCT FROM wanted||jsonb_build_object('id',claimed)
        OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e WHERE e.ordinal=2 AND e.nonce=(att->>'nonce')::uuid
            AND e.table_name='fga_outbox' AND e.reserved_id=claimed AND e.selected AND e.claimed AND e.consumed AND e.origin=source AND e.row_value=wanted) THEN
        RAISE EXCEPTION 'active member FGA effect differs from the approved duplicate write' USING ERRCODE='40001';END IF;

    -- Штатный ключ ledger не содержит rule_fp. Каждая sealed ref обязана попасть в физический OLD.
    FOR member_ref IN SELECT value FROM jsonb_array_elements(commands#>'{2,Refs}') LOOP
        IF member_ref->>'BindingID' IS DISTINCT FROM bid OR member_ref#>>'{Member,ObjectType}' IS DISTINCT FROM 'iam.project'
            OR member_ref#>>'{Member,ObjectID}' IS DISTINCT FROM pid OR member_ref#>>'{Tuple,User}' IS DISTINCT FROM source->>'user'
            OR member_ref#>>'{Tuple,Object}' IS DISTINCT FROM 'project:'||pid OR NOT EXISTS(SELECT FROM jsonb_array_elements(ledger) l
                WHERE l#>>'{2,source}'='member' AND l#>>'{2,relation}'=member_ref#>>'{Tuple,Relation}') THEN
            RAISE EXCEPTION 'active record outside OLD references' USING ERRCODE='40001';END IF;
    END LOOP;
    INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
        SELECT bid,'iam.project',pid,r#>>'{Tuple,User}',r#>>'{Tuple,Relation}',r#>>'{Tuple,Object}','member'
            FROM jsonb_array_elements(commands#>'{2,Refs}') r
        ON CONFLICT(binding_id,member_object_type,member_object_id,fga_user,relation,object) DO NOTHING;
    GET DIAGNOSTICS touched=ROW_COUNT;
    IF touched<>0 THEN RAISE EXCEPTION 'active record unexpectedly introduced a grant' USING ERRCODE='40001';END IF;
    cursor_row:=cursor_row||jsonb_build_object('last_consumed',3,'outbox',outbox_image,'viewer_new',viewer_new);
    IF octet_length(frame::text)+octet_length(cursor_row::text)>8388608 THEN
        RAISE EXCEPTION 'active command cursor exceeds budget' USING ERRCODE='54000';END IF;
    UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=jsonb_set(s.frozen,'{selector_move_active_command_cursor}',cursor_row,false)
        WHERE s.singleton AND s.family='role' AND s.nonce=(att->>'nonce')::uuid AND s.frozen=frame AND s.selected=chosen;
    IF NOT FOUND THEN RAISE EXCEPTION 'active write and record cursor changed' USING ERRCODE='40001';END IF;
    RETURN cursor_row||jsonb_build_object('rows',40,'reads',18);
END;
$consume$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_active_write_record_v1(integer,integer)'::regprocedure;grantee record;
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
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d','a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba',$edits$[
 [
  "        slots:=array_append(slots,slot);used_rows:=used_rows+24;used_reads:=used_reads+5;",
  "        -- Резервируем работу записи FGA/ledger и повторного чтения в deferred trigger.\n        IF p_rows-used_rows<84 OR p_reads-used_reads<33 THEN\n            RAISE EXCEPTION 'active member body and deferred budget missing' USING ERRCODE='54000';END IF;\n        slots:=array_append(slots,slot);used_rows:=used_rows+84;used_reads:=used_reads+33;"
 ]
]$edits$::jsonb),
        ('authority_sequence_program_applied_v3()','6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc','11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828',$edits$[
 [
  " IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;\nEND;\n RETURN NULL;",
  " IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;\nEND;\n IF TG_TABLE_NAME='resource_journal' AND program->>'family'='role' AND program#>>'{frozen,mode}'='selector_move'\n    AND EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_program a WHERE a.singleton AND a.nonce=(proof->>'nonce')::uuid\n        AND a.frozen ? 'selector_move_active_project_seal') THEN\n    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n END IF;\n RETURN NULL;"
 ]
]$edits$::jsonb),
        ('_authority_role_move_roots_complete_v1()','cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c','baac3d8195cd4dbd9866e122c192860b93f06c0c1a8b688b4072790d5b35104c',$edits$[
 [
  "    IF NOT (frozen ? 'selector_move') THEN RETURN;END IF;",
  "    IF NOT (frozen ? 'selector_move') THEN RETURN;END IF;\n    IF frozen ? 'selector_move_active_project_seal' THEN\n        DECLARE\n            s jsonb:=frozen->'selector_move_active_project_seal'; c jsonb:=frozen->'selector_move_active_command_cursor';\n            w jsonb:=s->'witness'; fga jsonb:=program#>'{selected,1}'; old_ledger jsonb:=frozen#>'{selector_move,binding_census,ledger}';\n            bid text:=w->>'binding_id'; actual jsonb;\n        BEGIN\n            IF c->>'last_consumed' IS DISTINCT FROM '4' OR c->>'seal_sha256' IS DISTINCT FROM encode(sha256(convert_to(s::text,'UTF8')),'hex')\n                OR c->'nonce' IS DISTINCT FROM program->'nonce' OR c->'xid' IS DISTINCT FROM program->'transaction_id'\n                OR (c#>'{member_new,2,rule_fp}') IS DISTINCT FROM w->'new_rule_fp'\n                OR c#>>'{member_new,2,verification_status}' IS DISTINCT FROM 'ACTIVE'\n                OR jsonb_array_length(old_ledger) IS DISTINCT FROM 3 OR w->>'ledger_sha256' IS DISTINCT FROM encode(sha256(convert_to(old_ledger::text,'UTF8')),'hex')\n                OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e JOIN ONLY kaname.fga_outbox q ON q.id=e.reserved_id\n                    WHERE e.nonce=v_nonce AND e.ordinal=2 AND e.table_name='fga_outbox' AND e.selected AND e.claimed AND e.consumed\n                    AND e.reserved_id=(fga->>'reserved_id')::bigint AND e.origin=fga->'origin' AND e.row_value=fga->'row'\n                    AND e.row_value=to_jsonb(q)-'id' AND jsonb_build_array(q.xmin::text,q.ctid::text,to_jsonb(q))=c->'outbox') THEN\n                RAISE EXCEPTION 'active project command sequence is incomplete at commit' USING ERRCODE='42501';END IF;\n            SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))) INTO actual\n                FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=bid;\n            IF actual IS DISTINCT FROM jsonb_build_array(c->'member_new') OR (SELECT count(*) FROM ONLY kaname.access_binding_emitted_tuples l WHERE l.binding_id=bid)<>3\n                OR EXISTS(SELECT FROM jsonb_array_elements(old_ledger) l WHERE NOT EXISTS(SELECT FROM ONLY kaname.access_binding_emitted_tuples t\n                    WHERE t.binding_id=bid AND t.member_object_type=l#>>'{2,member_object_type}' AND t.member_object_id=l#>>'{2,member_object_id}'\n                    AND t.object=l#>>'{2,object}' AND t.fga_user=l#>>'{2,fga_user}' AND t.relation=l#>>'{2,relation}'\n                    AND jsonb_build_array(t.xmin::text,t.ctid::text,to_jsonb(t))=l))\n                OR NOT EXISTS(SELECT FROM ONLY kaname.relation_fact f WHERE f.object_type='project' AND f.object_id=w->>'project_id'\n                    AND f.subject=fga#>>'{origin,user}' AND f.relation='viewer' AND jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f))=c->'viewer_new') THEN\n                RAISE EXCEPTION 'active project member, viewer or ledger changed at commit' USING ERRCODE='40001';END IF;\n        END;\n    END IF;"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1','ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865',$edits$[
 [
  "34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d",
  "a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba"
 ],
 [
  "6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc",
  "11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828"
 ],
 [
  "cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c",
  "baac3d8195cd4dbd9866e122c192860b93f06c0c1a8b688b4072790d5b35104c"
 ],
 [
  " ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n",
  " ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n ('_authority_role_move_active_write_record_v1(integer,integer)','3c4fcecb0239a76b812a8fc8e257bc1b89c2bd7ca95acd9ac7d8f808c604dca7',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n",
  "  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77','b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0',$edits$[
 [
  "f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1",
  "ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','2ef7eeb6a95ef6d4a03c3622d5b7df1cadd8d33c94408ba45bab6ee2774e5c43','8713cf96229ebffaeb9c2f52c6195a1388d812c9c44a6036458e7fa83989f9cb',$edits$[
 [
  "f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1",
  "ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865"
 ],
 [
  "4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77",
  "b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','100e565d8f35cd980754f9b5daed5cfdea3bc81dc0f6a3b9c4deadc221848f0c','6349cbdf933540d958c9749acbd701eb43f86a345a7170353398dbaab09f66e9',$edits$[
 [
  "4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77",
  "b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','78805dd7d48c4a425d9ea93501461a9f911244f05bf6973cae42265c93c33974','807f50e43d9803fbdba1b3e6e3d74b1a969d5fd2266f5ac37a4b118a4884d9af',$edits$[
 [
  "100e565d8f35cd980754f9b5daed5cfdea3bc81dc0f6a3b9c4deadc221848f0c",
  "6349cbdf933540d958c9749acbd701eb43f86a345a7170353398dbaab09f66e9"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active member FGA slot predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active member FGA slot replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active member FGA slot body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active member FGA slot installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active member FGA slot storage graph differs' USING ERRCODE='55000';
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
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','807f50e43d9803fbdba1b3e6e3d74b1a969d5fd2266f5ac37a4b118a4884d9af','78805dd7d48c4a425d9ea93501461a9f911244f05bf6973cae42265c93c33974',$edits$[
 [
  "6349cbdf933540d958c9749acbd701eb43f86a345a7170353398dbaab09f66e9",
  "100e565d8f35cd980754f9b5daed5cfdea3bc81dc0f6a3b9c4deadc221848f0c"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','6349cbdf933540d958c9749acbd701eb43f86a345a7170353398dbaab09f66e9','100e565d8f35cd980754f9b5daed5cfdea3bc81dc0f6a3b9c4deadc221848f0c',$edits$[
 [
  "b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0",
  "4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','8713cf96229ebffaeb9c2f52c6195a1388d812c9c44a6036458e7fa83989f9cb','2ef7eeb6a95ef6d4a03c3622d5b7df1cadd8d33c94408ba45bab6ee2774e5c43',$edits$[
 [
  "b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0",
  "4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77"
 ],
 [
  "ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865",
  "f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','b9c3e62c3ede0d7f8959a6a99b398a107ec79d74dcb2c03c1f615c2eec977aa0','4adabc1d85217185a343128358ebf6a60a0b56dc250a7c2e412a2c8336a77e77',$edits$[
 [
  "ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865",
  "f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','ee6eaad76bec695c718f708c734ed5d6ab4b10c3fc1a7a73055be7e93ccbf865','f43195bd02321e1a384b1bf41eccaf7118907572c8f60b8e0856dbe63bc064e1',$edits$[
 [
  "  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n  ('_authority_role_move_active_write_record_v1(integer,integer)','jsonb',2,ARRAY['p_rows','p_reads']),\n",
  "  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n ('_authority_role_move_active_write_record_v1(integer,integer)','3c4fcecb0239a76b812a8fc8e257bc1b89c2bd7ca95acd9ac7d8f808c604dca7',false,'v',true,'private'),\n",
  " ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n"
 ],
 [
  "baac3d8195cd4dbd9866e122c192860b93f06c0c1a8b688b4072790d5b35104c",
  "cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c"
 ],
 [
  "11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828",
  "6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc"
 ],
 [
  "a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba",
  "34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d"
 ]
]$edits$::jsonb),
        ('_authority_role_move_roots_complete_v1()','baac3d8195cd4dbd9866e122c192860b93f06c0c1a8b688b4072790d5b35104c','cf50ce308de57a7afb3cb6451b268e566d5d84d105da533181835db32967c87c',$edits$[
 [
  "    IF NOT (frozen ? 'selector_move') THEN RETURN;END IF;\n    IF frozen ? 'selector_move_active_project_seal' THEN\n        DECLARE\n            s jsonb:=frozen->'selector_move_active_project_seal'; c jsonb:=frozen->'selector_move_active_command_cursor';\n            w jsonb:=s->'witness'; fga jsonb:=program#>'{selected,1}'; old_ledger jsonb:=frozen#>'{selector_move,binding_census,ledger}';\n            bid text:=w->>'binding_id'; actual jsonb;\n        BEGIN\n            IF c->>'last_consumed' IS DISTINCT FROM '4' OR c->>'seal_sha256' IS DISTINCT FROM encode(sha256(convert_to(s::text,'UTF8')),'hex')\n                OR c->'nonce' IS DISTINCT FROM program->'nonce' OR c->'xid' IS DISTINCT FROM program->'transaction_id'\n                OR (c#>'{member_new,2,rule_fp}') IS DISTINCT FROM w->'new_rule_fp'\n                OR c#>>'{member_new,2,verification_status}' IS DISTINCT FROM 'ACTIVE'\n                OR jsonb_array_length(old_ledger) IS DISTINCT FROM 3 OR w->>'ledger_sha256' IS DISTINCT FROM encode(sha256(convert_to(old_ledger::text,'UTF8')),'hex')\n                OR NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e JOIN ONLY kaname.fga_outbox q ON q.id=e.reserved_id\n                    WHERE e.nonce=v_nonce AND e.ordinal=2 AND e.table_name='fga_outbox' AND e.selected AND e.claimed AND e.consumed\n                    AND e.reserved_id=(fga->>'reserved_id')::bigint AND e.origin=fga->'origin' AND e.row_value=fga->'row'\n                    AND e.row_value=to_jsonb(q)-'id' AND jsonb_build_array(q.xmin::text,q.ctid::text,to_jsonb(q))=c->'outbox') THEN\n                RAISE EXCEPTION 'active project command sequence is incomplete at commit' USING ERRCODE='42501';END IF;\n            SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))) INTO actual\n                FROM ONLY kaname.access_binding_target_members m WHERE m.binding_id=bid;\n            IF actual IS DISTINCT FROM jsonb_build_array(c->'member_new') OR (SELECT count(*) FROM ONLY kaname.access_binding_emitted_tuples l WHERE l.binding_id=bid)<>3\n                OR EXISTS(SELECT FROM jsonb_array_elements(old_ledger) l WHERE NOT EXISTS(SELECT FROM ONLY kaname.access_binding_emitted_tuples t\n                    WHERE t.binding_id=bid AND t.member_object_type=l#>>'{2,member_object_type}' AND t.member_object_id=l#>>'{2,member_object_id}'\n                    AND t.object=l#>>'{2,object}' AND t.fga_user=l#>>'{2,fga_user}' AND t.relation=l#>>'{2,relation}'\n                    AND jsonb_build_array(t.xmin::text,t.ctid::text,to_jsonb(t))=l))\n                OR NOT EXISTS(SELECT FROM ONLY kaname.relation_fact f WHERE f.object_type='project' AND f.object_id=w->>'project_id'\n                    AND f.subject=fga#>>'{origin,user}' AND f.relation='viewer' AND jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f))=c->'viewer_new') THEN\n                RAISE EXCEPTION 'active project member, viewer or ledger changed at commit' USING ERRCODE='40001';END IF;\n        END;\n    END IF;",
  "    IF NOT (frozen ? 'selector_move') THEN RETURN;END IF;"
 ]
]$edits$::jsonb),
        ('authority_sequence_program_applied_v3()','11178dc9c0d78c18e0d57cbde286036349f5791e5edc1828316dc3e266fcd828','6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc',$edits$[
 [
  " IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;\nEND;\n IF TG_TABLE_NAME='resource_journal' AND program->>'family'='role' AND program#>>'{frozen,mode}'='selector_move'\n    AND EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_program a WHERE a.singleton AND a.nonce=(proof->>'nonce')::uuid\n        AND a.frozen ? 'selector_move_active_project_seal') THEN\n    PERFORM kaname._authority_role_move_active_write_record_v1(40,18);\n END IF;\n RETURN NULL;",
  " IF changed<>1 THEN RAISE EXCEPTION 'sequence applied ID replay or foreign row' USING ERRCODE='42501';END IF;\nEND;\n RETURN NULL;"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','a27e1d7ff966b37e669c91266f18cce4df76004d3ee8ae027ce82d995c28efba','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',$edits$[
 [
  "        -- Резервируем работу записи FGA/ledger и повторного чтения в deferred trigger.\n        IF p_rows-used_rows<84 OR p_reads-used_reads<33 THEN\n            RAISE EXCEPTION 'active member body and deferred budget missing' USING ERRCODE='54000';END IF;\n        slots:=array_append(slots,slot);used_rows:=used_rows+84;used_reads:=used_reads+33;",
  "        slots:=array_append(slots,slot);used_rows:=used_rows+24;used_reads:=used_reads+5;"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'active member FGA slot predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'active member FGA slot replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active member FGA slot body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'active member FGA slot installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'active member FGA slot storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_role_move_active_write_record_v1(integer,integer);
