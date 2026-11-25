-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_move_active_fga_slot_v1(p_held jsonb,p_ordinal integer,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $slot$
DECLARE
    census jsonb:=p_held->'binding_census'; carrier jsonb:=census#>'{bindings,0,2}';
    member_row jsonb:=census#>'{members,0,2}'; subject_row jsonb:=census#>'{subjects,0,2}';
    old_rule jsonb:=p_held#>'{role,physical,2,rules,0}'; next_rule jsonb:=p_held#>'{role,new_role,rules,0}';
    bid text:=carrier->>'id'; rid text:=p_held->>'role_id'; pid text:=carrier#>>'{target,resources,0,id}';
    aid text:=carrier->>'resource_id'; recipient text:='user:'||(subject_row->>'subject_id');
    obj text:='project:'||pid; pr jsonb:=p_held#>ARRAY['member_projects','projects',coalesce(pid,''),'native','2'];
    fact jsonb; origin_image jsonb; payload jsonb; members jsonb;
BEGIN
    IF p_ordinal IS DISTINCT FROM 2 OR p_rows IS NULL OR p_rows NOT BETWEEN 24 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 5 AND 4096
        THEN RAISE EXCEPTION 'active project FGA slot exceeds budget or prefix' USING ERRCODE='54000';END IF;
    IF p_held->'nonce' IS DISTINCT FROM kaname._authority_role_move_attestation_v1()->'nonce' OR p_held->'nonce' IS NULL
        OR p_held#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM '{"module":"iam","resources":["project"],"verbs":["get"]}'::jsonb
        OR next_rule-'match_access_labels' IS DISTINCT FROM old_rule-'match_labels'
        OR jsonb_typeof(old_rule->'match_labels') IS DISTINCT FROM 'object' OR old_rule->'match_labels'='{}'::jsonb
        OR old_rule->'match_labels' IS DISTINCT FROM next_rule->'match_access_labels'
        OR jsonb_array_length(p_held#>'{role,physical,2,rules}') IS DISTINCT FROM 1 OR jsonb_array_length(p_held#>'{role,new_role,rules}') IS DISTINCT FROM 1
        OR jsonb_array_length(census->'bindings') IS DISTINCT FROM 1 OR jsonb_array_length(census->'subjects') IS DISTINCT FROM 1
        OR jsonb_array_length(census->'members') IS DISTINCT FROM 1 OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 3
        OR carrier->>'role_id' IS DISTINCT FROM rid OR carrier->>'status' IS DISTINCT FROM 'ACTIVE'
        OR carrier->>'expires_at' IS NOT NULL OR carrier->>'revoked_at' IS NOT NULL OR carrier->>'resource_type' IS DISTINCT FROM 'account'
        OR carrier->'target' IS DISTINCT FROM jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.project','id',pid)))
        OR subject_row->>'binding_id' IS DISTINCT FROM bid OR subject_row->>'subject_type' IS DISTINCT FROM 'user'
        OR coalesce(recipient,'user:')='user:' OR coalesce(rid,'')='' OR coalesce(bid,'')='' OR coalesce(pid,'')='' OR coalesce(aid,'')=''
        OR pr->>'id' IS DISTINCT FROM pid OR pr->>'account_id' IS DISTINCT FROM aid OR pr->'labels' IS DISTINCT FROM pr->'access_labels'
        OR (pr->'access_labels' @> (old_rule->'match_labels')) IS DISTINCT FROM true
        OR member_row->>'role_id' IS DISTINCT FROM rid OR member_row->>'binding_id' IS DISTINCT FROM bid
        OR member_row->>'object_type' IS DISTINCT FROM 'iam.project' OR member_row->>'object_id' IS DISTINCT FROM pid
        OR member_row->>'verification_status' IS DISTINCT FROM 'ACTIVE' OR member_row->'live' IS DISTINCT FROM 'true'::jsonb
        OR coalesce(member_row->>'rule_fp','') !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'active project FGA preimage is outside the exact direct binding' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_agg(l#>>'{2,relation}' ORDER BY (l#>>'{2,relation}') COLLATE "C") INTO members
      FROM jsonb_array_elements(census->'ledger') l WHERE l#>>'{2,binding_id}'=bid AND l#>>'{2,source}'='member'
      AND l#>>'{2,member_object_type}'='iam.project' AND l#>>'{2,member_object_id}'=pid AND l#>>'{2,fga_user}'=recipient AND l#>>'{2,object}'=obj;
    IF members IS DISTINCT FROM '["v_get","viewer"]'::jsonb OR NOT EXISTS(SELECT FROM jsonb_array_elements(census->'ledger') l
        WHERE l#>>'{2,binding_id}'=bid AND l#>>'{2,source}'='binding' AND l#>>'{2,fga_user}'='account:'||aid
        AND l#>>'{2,relation}'='account' AND l#>>'{2,object}'='iam_access_binding:'||bid AND coalesce(l#>>'{2,member_object_type}','')=''
        AND coalesce(l#>>'{2,member_object_id}','')='') THEN
        RAISE EXCEPTION 'active project FGA ledger is not an existing exact write' USING ERRCODE='42501';END IF;

    -- Штатная свёртка пропускает производный v_get. Одноимённый viewer с условием
    -- нельзя переводить в безусловный. Блокируем физическую строку до любых часов решения.
    LOCK TABLE ONLY kaname.relation_fact IN ROW EXCLUSIVE MODE NOWAIT;
    IF EXISTS(SELECT FROM pg_inherits WHERE inhparent='kaname.relation_fact'::regclass OR inhrelid='kaname.relation_fact'::regclass)
        OR NOT EXISTS(SELECT FROM pg_class WHERE oid='kaname.relation_fact'::regclass AND relkind='r'
            AND NOT (relispartition OR relrowsecurity OR relforcerowsecurity)) THEN
        RAISE EXCEPTION 'active project FGA fact table changed' USING ERRCODE='42501';END IF;
    SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO fact FROM ONLY kaname.relation_fact f
        WHERE f.object_type='project' AND f.object_id=pid AND f.relation='viewer' AND f.subject=recipient
        AND f.condition_name='' AND f.condition_params='{}'::jsonb FOR NO KEY UPDATE OF f NOWAIT;
    IF fact IS NULL THEN RAISE EXCEPTION 'active project unconditional viewer is absent' USING ERRCODE='40001';END IF;
    origin_image:=jsonb_build_object('family','role.selector_move.active_member','binding',bid,'role',rid,'project',pid,
        'user',recipient,'rule_fp',member_row->'rule_fp','viewer_old',fact,
        'ledger_sha256',encode(sha256(convert_to((census->'ledger')::text,'UTF8')),'hex'));
    payload:=jsonb_build_object('object',obj,'user',recipient,'relation',members->0,'relations',members);
    IF octet_length(origin_image::text)+octet_length(payload::text)>32768 THEN
        RAISE EXCEPTION 'active project FGA slot exceeds byte budget' USING ERRCODE='54000';END IF;
    RETURN jsonb_build_object('table','fga_outbox','ordinal',p_ordinal,'origin',origin_image,
        'row',jsonb_build_object('event_type','fga.tuple.write','payload',payload),'stamp','transaction');
END;
$slot$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)'::regprocedure;grantee record;
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
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',$edits$[
 [
  "    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);",
  "    IF p_frozen#>'{copies,roots}'='{}'::jsonb AND p_fixed=1\n        AND jsonb_array_length(p_frozen#>'{binding_census,bindings}')=1 AND p_frozen#>>'{binding_census,bindings,0,2,status}'='ACTIVE'\n        AND jsonb_array_length(p_frozen#>'{binding_census,members}')=1 AND jsonb_array_length(p_frozen#>'{role,physical,2,rules}')=1\n        AND (p_frozen#>'{role,physical,2,rules,0}')-'match_labels'='{\"module\":\"iam\",\"resources\":[\"project\"],\"verbs\":[\"get\"]}'::jsonb\n        AND (p_frozen#>'{role,new_role,rules,0}') ? 'match_access_labels' THEN\n        slot:=kaname._authority_role_move_active_fga_slot_v1(p_frozen,p_fixed+1,p_rows-used_rows,p_reads-used_reads);\n        slots:=array_append(slots,slot);used_rows:=used_rows+24;used_reads:=used_reads+5;\n    END IF;\n    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80','9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f',$edits$[
 [
  "a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577",
  "34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d"
 ],
 [
  " ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',false,'v',true,'private'),\n",
  " ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',false,'v',true,'private'),\n ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n",
  "  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f','b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2',$edits$[
 [
  "e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80",
  "9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','ca6302c65e6738c9ff9ac0e5e54c190bd2f5e2fa445f933d294c3f5666d3118c','ef49cdedd7e60295deff493de109d4b9101f2c25e40fd7b14fa105f045256139',$edits$[
 [
  "e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80",
  "9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f"
 ],
 [
  "2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f",
  "b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','e90747cd52de4dfb2dd8861be8bac6f958a8711fb82dd16cce79131b4ec1905b','7c7cb9edea3cfb06e3fa607a8db91500f8185006ef4766b7355176ad0308d4ff',$edits$[
 [
  "2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f",
  "b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','6fcba8df5615e45f64fecd7724fa219effe0a4ec658dcb793bdd545f1ca2164c','be3f48e5567655cb21c98a5b6595894f4e267cee7815345247aa21c217dd891d',$edits$[
 [
  "e90747cd52de4dfb2dd8861be8bac6f958a8711fb82dd16cce79131b4ec1905b",
  "7c7cb9edea3cfb06e3fa607a8db91500f8185006ef4766b7355176ad0308d4ff"
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
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','be3f48e5567655cb21c98a5b6595894f4e267cee7815345247aa21c217dd891d','6fcba8df5615e45f64fecd7724fa219effe0a4ec658dcb793bdd545f1ca2164c',$edits$[
 [
  "7c7cb9edea3cfb06e3fa607a8db91500f8185006ef4766b7355176ad0308d4ff",
  "e90747cd52de4dfb2dd8861be8bac6f958a8711fb82dd16cce79131b4ec1905b"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','7c7cb9edea3cfb06e3fa607a8db91500f8185006ef4766b7355176ad0308d4ff','e90747cd52de4dfb2dd8861be8bac6f958a8711fb82dd16cce79131b4ec1905b',$edits$[
 [
  "b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2",
  "2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','ef49cdedd7e60295deff493de109d4b9101f2c25e40fd7b14fa105f045256139','ca6302c65e6738c9ff9ac0e5e54c190bd2f5e2fa445f933d294c3f5666d3118c',$edits$[
 [
  "b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2",
  "2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f"
 ],
 [
  "9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f",
  "e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','b9f99fb5334ad256eca53326cf9bf2ba5a9fcd17a2382d74e6e6322d6b26caf2','2981bc05c2ee02ea1fd90a9e73ad400e1b82c471788e80019e6613cd0f55c42f',$edits$[
 [
  "9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f",
  "e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','9378c40cee3e4912ec5aec7705d3f2c8a8f682bb69e711b3b0f7c39ffea07a6f','e97d5bac873cafaa5a08f13bfd50da25e43b817ea42cf164815774571ca48c80',$edits$[
 [
  "  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n  ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_held','p_ordinal','p_rows','p_reads']),\n",
  "  ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','jsonb',4,ARRAY['p_frozen','p_fixed','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',false,'v',true,'private'),\n ('_authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer)','f46d147bd9a7101f1dc2a3af0875a8f94dfadc0125b3848431456a751850c60a',false,'v',true,'private'),\n",
  " ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d',false,'v',true,'private'),\n"
 ],
 [
  "34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d",
  "a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577"
 ]
]$edits$::jsonb),
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','34ae2f688dc9b22da0b2d52b7e784d01550f3c9f162eb79dffb959ea204fa84d','a61a057c02720031cd029075490eb56a6cacabbca9bc18ef1e7d27463a40c577',$edits$[
 [
  "    IF p_frozen#>'{copies,roots}'='{}'::jsonb AND p_fixed=1\n        AND jsonb_array_length(p_frozen#>'{binding_census,bindings}')=1 AND p_frozen#>>'{binding_census,bindings,0,2,status}'='ACTIVE'\n        AND jsonb_array_length(p_frozen#>'{binding_census,members}')=1 AND jsonb_array_length(p_frozen#>'{role,physical,2,rules}')=1\n        AND (p_frozen#>'{role,physical,2,rules,0}')-'match_labels'='{\"module\":\"iam\",\"resources\":[\"project\"],\"verbs\":[\"get\"]}'::jsonb\n        AND (p_frozen#>'{role,new_role,rules,0}') ? 'match_access_labels' THEN\n        slot:=kaname._authority_role_move_active_fga_slot_v1(p_frozen,p_fixed+1,p_rows-used_rows,p_reads-used_reads);\n        slots:=array_append(slots,slot);used_rows:=used_rows+24;used_reads:=used_reads+5;\n    END IF;\n    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);",
  "    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);"
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
DROP FUNCTION kaname._authority_role_move_active_fga_slot_v1(jsonb,integer,integer,integer);
