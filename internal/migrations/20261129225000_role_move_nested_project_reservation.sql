-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Исходная выдача выбирает аккаунт. Только одно наблюдённое типизированное
-- ребро этого аккаунта ведёт к единственному проекту из переписи.
CREATE FUNCTION kaname._authority_role_move_nested_slots_v1(p_held jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $slots$
DECLARE
    proof jsonb:=kaname._authority_role_move_attestation_v1(); census jsonb:=p_held->'binding_census';
    holder jsonb:=census#>'{bindings,0,2}'; subj jsonb:=census#>'{subjects,0,2}';
    aid text:=holder->>'resource_id'; bid text:=holder->>'id'; rid text:=p_held->>'role_id';
    recipient text:='user:'||(subj->>'subject_id'); pid text; receipt jsonb; project jsonb; graph jsonb;
    prior jsonb:=p_held#>'{role,physical,2,rules,0}'; proposed jsonb:=p_held#>'{role,new_role,rules,0}';
    child jsonb:=prior#>'{children,0}'; pairs jsonb:=child->'match_labels';
    account_rule jsonb; account_fp text; project_fp text; typed text; oid_value text; model text; fp text;
    member jsonb; facts jsonb; rows_expected jsonb; origin_value jsonb; physical jsonb;
    slots jsonb:='[]'; ledger jsonb:=census->'ledger'; member_rows jsonb:=census->'members';
    verbs constant jsonb:='["v_get","viewer"]'; kind integer; project_model text; owner_model text; edges jsonb;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN 80 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 12 AND 4096 THEN
        RAISE EXCEPTION 'nested role slot reservation exceeds budget' USING ERRCODE='54000';END IF;
    IF p_held->'nonce' IS DISTINCT FROM proof->'nonce' OR proof->'nonce' IS NULL OR coalesce(aid,'')=''
        OR coalesce(bid,'')='' OR coalesce(rid,'')='' OR coalesce(recipient,'user:')='user:'
        OR p_held#>'{copies,roots}' IS DISTINCT FROM '{}'::jsonb
        OR jsonb_array_length(p_held#>'{role,physical,2,rules}') IS DISTINCT FROM 1
        OR jsonb_array_length(p_held#>'{role,new_role,rules}') IS DISTINCT FROM 1
        OR p_held#>>'{role,physical,2,account_id}' IS DISTINCT FROM aid
        OR holder->>'role_id' IS DISTINCT FROM rid OR holder->>'resource_type' IS DISTINCT FROM 'account'
        OR holder->>'status' IS DISTINCT FROM 'ACTIVE' OR holder->>'expires_at' IS NOT NULL OR holder->>'revoked_at' IS NOT NULL
        OR holder->'target' IS DISTINCT FROM jsonb_build_object('resources',jsonb_build_array(jsonb_build_object('type','iam.account','id',aid)))
        OR jsonb_array_length(census->'bindings') IS DISTINCT FROM 1 OR jsonb_array_length(census->'subjects') IS DISTINCT FROM 1
        OR subj->>'binding_id' IS DISTINCT FROM bid OR subj->>'subject_type' IS DISTINCT FROM 'user'
        OR jsonb_array_length(member_rows) IS DISTINCT FROM 2 OR jsonb_array_length(ledger) IS DISTINCT FROM 5
        OR kaname.access_labels_valid_v1(pairs) IS DISTINCT FROM true OR pairs='{}'::jsonb THEN
        RAISE EXCEPTION 'nested role requires one permanent account recipient and two materialized coordinates' USING ERRCODE='42501';END IF;
    account_rule:=jsonb_build_object('module','iam','resources',jsonb_build_array('account'),'verbs',jsonb_build_array('get'),
        'resource_names',jsonb_build_array(aid));
    IF prior IS DISTINCT FROM account_rule||jsonb_build_object('children',jsonb_build_array(
        jsonb_build_object('resources',jsonb_build_array('project'),'verbs',jsonb_build_array('get'),'match_labels',pairs)))
        OR proposed IS DISTINCT FROM jsonb_set(prior,'{children,0}',(child-'match_labels')||jsonb_build_object('match_access_labels',pairs)) THEN
        RAISE EXCEPTION 'nested role selected child or its parent differs' USING ERRCODE='42501';END IF;
    SELECT m#>>'{2,object_id}' INTO STRICT pid FROM jsonb_array_elements(member_rows) m WHERE m#>>'{2,object_type}'='iam.project';
    receipt:=p_held#>ARRAY['member_projects','projects',pid];project:=receipt#>'{native,2}';graph:=receipt->'graph';
    IF coalesce(pid,'')='' OR receipt->'nonce' IS DISTINCT FROM proof->'nonce' OR receipt->>'txid' IS DISTINCT FROM pg_current_xact_id()::text
        OR receipt->>'backend_pid' IS DISTINCT FROM pg_backend_pid()::text OR receipt->>'project_id' IS DISTINCT FROM pid
        OR project->>'id' IS DISTINCT FROM pid OR project->>'account_id' IS DISTINCT FROM aid
        OR graph->'present' IS DISTINCT FROM 'true'::jsonb OR graph#>>'{projection,object_id}' IS DISTINCT FROM pid
        OR graph#>>'{projection,object_type}' IS DISTINCT FROM 'iam.project'
        OR graph->'current_accounts' IS DISTINCT FROM jsonb_build_array(aid)
        OR jsonb_array_length(graph->'ancestors') IS DISTINCT FROM 1 OR graph#>>'{ancestors,0,projection,id}' IS DISTINCT FROM aid
        OR (graph#>'{projection,labels}' @> pairs) IS DISTINCT FROM true
        OR graph#>'{projection,access_labels}' IS DISTINCT FROM project->'access_labels'
        OR (project->'access_labels' @> pairs) IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested project ancestry or selected pairs changed' USING ERRCODE='40001';END IF;
    SELECT c#>>'{2,object_type}' INTO STRICT project_model FROM jsonb_array_elements(receipt->'catalog') c WHERE c#>>'{2,dotted}'='iam.project';
    SELECT c#>>'{2,object_type}' INTO STRICT owner_model FROM jsonb_array_elements(receipt->'catalog') c WHERE c#>>'{2,dotted}'='iam.account';
    edges:=receipt#>ARRAY['sources',jsonb_build_array(3,project_model,pid,'')::text,'states'];
    IF jsonb_array_length(edges) IS DISTINCT FROM 1 OR edges#>>'{0,2,object_id}' IS DISTINCT FROM pid
        OR edges#>>'{0,2,object_type}' IS DISTINCT FROM project_model OR edges#>>'{0,2,parent_type}' IS DISTINCT FROM owner_model
        OR edges#>>'{0,2,parent_id}' IS DISTINCT FROM aid OR edges#>>'{0,2,depth}' IS DISTINCT FROM '1' THEN
        RAISE EXCEPTION 'nested project needs one direct catalog edge' USING ERRCODE='42501';END IF;
    account_fp:=kaname._authority_resource_rule_fingerprint_v2(prior,false);
    project_fp:=encode(sha256(convert_to('nested','UTF8')||decode('00','hex')||convert_to(account_fp,'UTF8')||
        decode('00','hex')||convert_to(kaname._authority_resource_rule_fingerprint_v2(child,true),'UTF8')),'hex');
    IF NOT EXISTS (SELECT FROM jsonb_array_elements(ledger) l WHERE l#>>'{2,binding_id}'=bid AND l#>>'{2,source}'='binding'
        AND l#>>'{2,fga_user}'='account:'||aid AND l#>>'{2,relation}'='account' AND l#>>'{2,object}'='iam_access_binding:'||bid
        AND coalesce(l#>>'{2,member_object_type}','')='' AND coalesce(l#>>'{2,member_object_id}','')='') THEN
        RAISE EXCEPTION 'nested role structural binding grant changed' USING ERRCODE='42501';END IF;
    LOCK TABLE ONLY kaname.relation_fact IN ROW EXCLUSIVE MODE NOWAIT;
    IF EXISTS(SELECT FROM pg_inherits WHERE inhparent='kaname.relation_fact'::regclass OR inhrelid='kaname.relation_fact'::regclass)
        OR NOT EXISTS(SELECT FROM pg_class WHERE oid='kaname.relation_fact'::regclass AND relkind='r'
            AND NOT (relispartition OR relrowsecurity OR relforcerowsecurity)) THEN
        RAISE EXCEPTION 'nested role fact storage changed' USING ERRCODE='42501';END IF;
    FOR kind IN 1..2 LOOP
        IF kind=1 THEN typed:='iam.account';oid_value:=aid;model:='account';fp:=account_fp;
        ELSE typed:='iam.project';oid_value:=pid;model:='project';fp:=project_fp;END IF;
        SELECT m INTO STRICT member FROM jsonb_array_elements(member_rows) m
            WHERE m#>>'{2,object_type}'=typed AND m#>>'{2,object_id}'=oid_value AND m#>>'{2,rule_fp}'=fp
            AND m#>>'{2,role_id}'=rid AND m#>>'{2,binding_id}'=bid AND m#>>'{2,verification_status}'='ACTIVE' AND m#>'{2,live}'='true'::jsonb;
        SELECT jsonb_agg(l#>>'{2,relation}' ORDER BY (l#>>'{2,relation}') COLLATE "C") INTO rows_expected
            FROM jsonb_array_elements(ledger) l WHERE l#>>'{2,source}'='member' AND l#>>'{2,binding_id}'=bid
            AND l#>>'{2,member_object_type}'=typed AND l#>>'{2,member_object_id}'=oid_value
            AND l#>>'{2,fga_user}'=recipient AND l#>>'{2,object}'=model||':'||oid_value;
        IF rows_expected IS DISTINCT FROM verbs THEN RAISE EXCEPTION 'nested retained member ledger differs' USING ERRCODE='40001';END IF;
        SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO physical FROM ONLY kaname.relation_fact f
            WHERE f.object_type=model AND f.object_id=oid_value AND f.relation='viewer' AND f.subject=recipient
            AND f.condition_name='' AND f.condition_params='{}'::jsonb FOR NO KEY UPDATE OF f NOWAIT;
        IF physical IS NULL THEN RAISE EXCEPTION 'nested unconditional viewer is absent' USING ERRCODE='40001';END IF;
        facts:=jsonb_build_object('viewer',physical);
        -- Если v_get хранится напрямую, его повторная доставка также не должна
        -- превратить условный факт в безусловный или создать ранее отсутствующий доступ.
        SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) INTO physical FROM ONLY kaname.relation_fact f
            WHERE f.object_type=model AND f.object_id=oid_value AND f.relation='v_get' AND f.subject=recipient FOR NO KEY UPDATE OF f NOWAIT;
        IF physical IS NOT NULL AND (physical#>>'{2,condition_name}' IS DISTINCT FROM '' OR physical#>'{2,condition_params}' IS DISTINCT FROM '{}'::jsonb) THEN
            RAISE EXCEPTION 'nested v_get fact has a condition' USING ERRCODE='42501';END IF;
        facts:=facts||jsonb_build_object('v_get',physical);
        origin_value:=jsonb_build_object('family','role.selector_move.active_nested_member','binding',bid,'role',rid,'object_type',typed,
            'object_id',oid_value,'rule_fp',fp,'user',recipient,'member_old',member,'facts',facts,
            'ledger_sha256',encode(sha256(convert_to(ledger::text,'UTF8')),'hex'));
        IF octet_length(origin_value::text)>32768 THEN RAISE EXCEPTION 'nested source exceeds byte budget' USING ERRCODE='54000';END IF;
        slots:=slots||jsonb_build_array(jsonb_build_object('table','fga_outbox','ordinal',kind+1,'origin',origin_value,
            'row',jsonb_build_object('event_type','fga.tuple.write','payload',jsonb_build_object('user',recipient,'object',model||':'||oid_value,
            'relation','v_get','relations',verbs)),'stamp','transaction'));
    END LOOP;
    RETURN slots;
END;
$slots$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_nested_slots_v1(jsonb,integer,integer)'::regprocedure;grantee record;
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
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8','ae5cef923d284eca1cb88c39fbfe35463ec940e51a6d161a7757016d620afd3c',$edits$[
 [
  "    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);",
  "    IF p_fixed=1 AND p_frozen#>'{copies,roots}'='{}'::jsonb AND cardinality(slots)=0\n        AND p_frozen#>>'{binding_census,bindings,0,2,status}'='ACTIVE'\n        AND p_frozen#>'{role,physical,2,rules,0,children,0}' ? 'match_labels'\n        AND p_frozen#>'{role,new_role,rules,0,children,0}' ? 'match_access_labels'\n        AND jsonb_array_length(p_frozen#>'{role,physical,2,rules}')=1 AND jsonb_array_length(p_frozen#>'{role,physical,2,rules,0,children}')=1\n        AND jsonb_array_length(p_frozen#>'{binding_census,bindings}')=1 AND jsonb_array_length(p_frozen#>'{binding_census,members}')=2 THEN\n        IF p_rows-used_rows<80 OR p_reads-used_reads<12 THEN RAISE EXCEPTION 'nested reservation budget missing' USING ERRCODE='54000';END IF;\n        FOR slot IN SELECT value FROM jsonb_array_elements(kaname._authority_role_move_nested_slots_v1(p_frozen,p_rows-used_rows,p_reads-used_reads)) LOOP\n            slots:=array_append(slots,slot);\n        END LOOP;\n        used_rows:=used_rows+80;used_reads:=used_reads+12;\n    END IF;\n    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);"
 ]
]$edits$::jsonb),
        ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a',$edits$[
 [
  "transport text:=p_input->>'_selector_move';",
  "transport text:=p_input->>'_selector_move';\n    nested_mode boolean:=coalesce(transport='active_nested_project_no_copy_v1',false);"
 ],
 [
  "NOT IN ('pending_no_copy_v1','active_project_no_copy_v1')",
  "NOT IN ('pending_no_copy_v1','active_project_no_copy_v1','active_nested_project_no_copy_v1')"
 ],
 [
  "hold_image->'moves' IS DISTINCT FROM '[{\"rule_index\":0,\"child_index\":-1}]'::jsonb",
  "hold_image->'moves' IS DISTINCT FROM jsonb_build_array(jsonb_build_object('rule_index',0,'child_index',CASE WHEN nested_mode THEN 0 ELSE -1 END))"
 ],
 [
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN '2' ELSE '1' END)",
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN '2' WHEN 'active_nested_project_no_copy_v1' THEN '3' ELSE '1' END)"
 ],
 [
  "old_rule-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR new_rule-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR old_rule->>'module' IS DISTINCT FROM 'iam' OR old_rule->'resources' IS DISTINCT FROM '[\"project\"]'::jsonb\n        OR old_rule->'verbs' IS DISTINCT FROM '[\"get\"]'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM new_rule-'match_access_labels'\n        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'",
  "(NOT nested_mode AND (old_rule-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR new_rule-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR old_rule->>'module' IS DISTINCT FROM 'iam' OR old_rule->'resources' IS DISTINCT FROM '[\"project\"]'::jsonb\n        OR old_rule->'verbs' IS DISTINCT FROM '[\"get\"]'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM new_rule-'match_access_labels'\n        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'))"
 ],
 [
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN 'ACTIVE' ELSE 'PENDING' END)",
  "(CASE transport WHEN 'pending_no_copy_v1' THEN 'PENDING' ELSE 'ACTIVE' END)"
 ],
 [
  "jsonb_build_object('type','iam.project','id',target_project)",
  "jsonb_build_object('type',CASE WHEN nested_mode THEN 'iam.account' ELSE 'iam.project' END,'id',target_project)"
 ],
 [
  "        OR (transport='pending_no_copy_v1' AND",
  "        OR (nested_mode AND (binding_image->>'resource_id' IS DISTINCT FROM target_project\n            OR jsonb_array_length(census->'members') IS DISTINCT FROM 2 OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 5\n            OR program#>>'{maximum,1,origin,family}' IS DISTINCT FROM 'role.selector_move.active_nested_member'\n            OR program#>>'{maximum,2,origin,family}' IS DISTINCT FROM 'role.selector_move.active_nested_member'\n            OR program#>>'{maximum,1,origin,role}' IS DISTINCT FROM prepared->>'role_id' OR program#>>'{maximum,2,origin,role}' IS DISTINCT FROM prepared->>'role_id'\n            OR program#>>'{maximum,1,origin,binding}' IS DISTINCT FROM binding_image->>'id' OR program#>>'{maximum,2,origin,binding}' IS DISTINCT FROM binding_image->>'id'\n            OR program#>>'{maximum,1,origin,object_type}' IS DISTINCT FROM 'iam.account' OR program#>>'{maximum,1,origin,object_id}' IS DISTINCT FROM target_project\n            OR program#>>'{maximum,2,origin,object_type}' IS DISTINCT FROM 'iam.project'))\n        OR (transport='pending_no_copy_v1' AND"
 ],
 [
  "CASE WHEN transport='active_project_no_copy_v1' THEN octet_length",
  "CASE WHEN transport<>'pending_no_copy_v1' THEN octet_length"
 ],
 [
  "CASE WHEN transport='active_project_no_copy_v1' THEN jsonb_build_object",
  "CASE WHEN transport<>'pending_no_copy_v1' THEN jsonb_build_object"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495','887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2',$edits$[
 [
  "746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8",
  "ae5cef923d284eca1cb88c39fbfe35463ec940e51a6d161a7757016d620afd3c"
 ],
 [
  "bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854",
  "3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a"
 ],
 [
  " ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a',false,'v',true,'private'),\n",
  " ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a',false,'v',true,'private'),\n ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n"
 ],
 [
  "  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n",
  "  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692','0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568',$edits$[
 [
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495",
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','930c422666f0da334bc3bf03190f43185a4cbf7fd9d57db5f4eb2b29bee99d37','230514cacc711cb8cfa248dc35883f990a108a0526ad57a0d5c7e490af170650',$edits$[
 [
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495",
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2"
 ],
 [
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692",
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2','049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce',$edits$[
 [
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692",
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','32b0e594751f3a6a5e3b9929434be3062dc2ef89dcfe95bc6434d9d81ee2f1db','f00a6cd43c791f583cc70fbfa0eb14b189c9ac3bfa016b873557c302d3fcbcca',$edits$[
 [
  "56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2",
  "049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested active source reservation predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested active source reservation replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active source reservation body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active source reservation installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested active source reservation storage graph differs' USING ERRCODE='55000';
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
        ('_authority_role_move_sequence_extend_v1(jsonb,integer,integer,integer)','ae5cef923d284eca1cb88c39fbfe35463ec940e51a6d161a7757016d620afd3c','746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8',$edits$[
 [
  "    IF p_fixed=1 AND p_frozen#>'{copies,roots}'='{}'::jsonb AND cardinality(slots)=0\n        AND p_frozen#>>'{binding_census,bindings,0,2,status}'='ACTIVE'\n        AND p_frozen#>'{role,physical,2,rules,0,children,0}' ? 'match_labels'\n        AND p_frozen#>'{role,new_role,rules,0,children,0}' ? 'match_access_labels'\n        AND jsonb_array_length(p_frozen#>'{role,physical,2,rules}')=1 AND jsonb_array_length(p_frozen#>'{role,physical,2,rules,0,children}')=1\n        AND jsonb_array_length(p_frozen#>'{binding_census,bindings}')=1 AND jsonb_array_length(p_frozen#>'{binding_census,members}')=2 THEN\n        IF p_rows-used_rows<80 OR p_reads-used_reads<12 THEN RAISE EXCEPTION 'nested reservation budget missing' USING ERRCODE='54000';END IF;\n        FOR slot IN SELECT value FROM jsonb_array_elements(kaname._authority_role_move_nested_slots_v1(p_frozen,p_rows-used_rows,p_reads-used_reads)) LOOP\n            slots:=array_append(slots,slot);\n        END LOOP;\n        used_rows:=used_rows+80;used_reads:=used_reads+12;\n    END IF;\n    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);",
  "    RETURN jsonb_build_object('slots',to_jsonb(slots),'outputs',outputs,'rows',used_rows,'reads',used_reads);"
 ]
]$edits$::jsonb),
        ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a','bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854',$edits$[
 [
  "CASE WHEN transport<>'pending_no_copy_v1' THEN jsonb_build_object",
  "CASE WHEN transport='active_project_no_copy_v1' THEN jsonb_build_object"
 ],
 [
  "CASE WHEN transport<>'pending_no_copy_v1' THEN octet_length",
  "CASE WHEN transport='active_project_no_copy_v1' THEN octet_length"
 ],
 [
  "        OR (nested_mode AND (binding_image->>'resource_id' IS DISTINCT FROM target_project\n            OR jsonb_array_length(census->'members') IS DISTINCT FROM 2 OR jsonb_array_length(census->'ledger') IS DISTINCT FROM 5\n            OR program#>>'{maximum,1,origin,family}' IS DISTINCT FROM 'role.selector_move.active_nested_member'\n            OR program#>>'{maximum,2,origin,family}' IS DISTINCT FROM 'role.selector_move.active_nested_member'\n            OR program#>>'{maximum,1,origin,role}' IS DISTINCT FROM prepared->>'role_id' OR program#>>'{maximum,2,origin,role}' IS DISTINCT FROM prepared->>'role_id'\n            OR program#>>'{maximum,1,origin,binding}' IS DISTINCT FROM binding_image->>'id' OR program#>>'{maximum,2,origin,binding}' IS DISTINCT FROM binding_image->>'id'\n            OR program#>>'{maximum,1,origin,object_type}' IS DISTINCT FROM 'iam.account' OR program#>>'{maximum,1,origin,object_id}' IS DISTINCT FROM target_project\n            OR program#>>'{maximum,2,origin,object_type}' IS DISTINCT FROM 'iam.project'))\n        OR (transport='pending_no_copy_v1' AND",
  "        OR (transport='pending_no_copy_v1' AND"
 ],
 [
  "jsonb_build_object('type',CASE WHEN nested_mode THEN 'iam.account' ELSE 'iam.project' END,'id',target_project)",
  "jsonb_build_object('type','iam.project','id',target_project)"
 ],
 [
  "(CASE transport WHEN 'pending_no_copy_v1' THEN 'PENDING' ELSE 'ACTIVE' END)",
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN 'ACTIVE' ELSE 'PENDING' END)"
 ],
 [
  "(NOT nested_mode AND (old_rule-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR new_rule-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR old_rule->>'module' IS DISTINCT FROM 'iam' OR old_rule->'resources' IS DISTINCT FROM '[\"project\"]'::jsonb\n        OR old_rule->'verbs' IS DISTINCT FROM '[\"get\"]'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM new_rule-'match_access_labels'\n        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'))",
  "old_rule-ARRAY['module','resources','verbs','match_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR new_rule-ARRAY['module','resources','verbs','match_access_labels'] IS DISTINCT FROM '{}'::jsonb\n        OR old_rule->>'module' IS DISTINCT FROM 'iam' OR old_rule->'resources' IS DISTINCT FROM '[\"project\"]'::jsonb\n        OR old_rule->'verbs' IS DISTINCT FROM '[\"get\"]'::jsonb OR old_rule-'match_labels' IS DISTINCT FROM new_rule-'match_access_labels'\n        OR old_rule->'match_labels' IS DISTINCT FROM new_rule->'match_access_labels'"
 ],
 [
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN '2' WHEN 'active_nested_project_no_copy_v1' THEN '3' ELSE '1' END)",
  "(CASE transport WHEN 'active_project_no_copy_v1' THEN '2' ELSE '1' END)"
 ],
 [
  "hold_image->'moves' IS DISTINCT FROM jsonb_build_array(jsonb_build_object('rule_index',0,'child_index',CASE WHEN nested_mode THEN 0 ELSE -1 END))",
  "hold_image->'moves' IS DISTINCT FROM '[{\"rule_index\":0,\"child_index\":-1}]'::jsonb"
 ],
 [
  "NOT IN ('pending_no_copy_v1','active_project_no_copy_v1','active_nested_project_no_copy_v1')",
  "NOT IN ('pending_no_copy_v1','active_project_no_copy_v1')"
 ],
 [
  "transport text:=p_input->>'_selector_move';\n    nested_mode boolean:=coalesce(transport='active_nested_project_no_copy_v1',false);",
  "transport text:=p_input->>'_selector_move';"
 ]
]$edits$::jsonb),
        ('_authority_crud_storage_v3()','887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2','b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495',$edits$[
 [
  "  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n  ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_held','p_rows','p_reads']),\n",
  "  ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','jsonb',3,ARRAY['p_input','p_rows','p_reads']),\n"
 ],
 [
  " ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a',false,'v',true,'private'),\n ('_authority_role_move_nested_slots_v1(jsonb,integer,integer)','150b03137a22333146fd1bec0051407672729b26901aa3045a4d07d1229c060b',false,'v',true,'private'),\n",
  " ('_authority_role_move_prepare_request_v1(jsonb,integer,integer)','3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a',false,'v',true,'private'),\n"
 ],
 [
  "3860f4991fe07b35e6fd4a51a9b23f1bee49ed98294d1234ab478284b54e867a",
  "bfdb783a77f06fe508970896135bbb7adb05356df4c1b71a573249d8eca59854"
 ],
 [
  "ae5cef923d284eca1cb88c39fbfe35463ec940e51a6d161a7757016d620afd3c",
  "746076caf4015fe2c2c982edce229ae89d6d58a00268ffc52865b4c03be25ae8"
 ]
]$edits$::jsonb),
        ('_authority_full_contract_storage_v3()','0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568','822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692',$edits$[
 [
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2",
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495"
 ]
]$edits$::jsonb),
        ('authority_metadata_service_account_access_label_ready_v1()','230514cacc711cb8cfa248dc35883f990a108a0526ad57a0d5c7e490af170650','930c422666f0da334bc3bf03190f43185a4cbf7fd9d57db5f4eb2b29bee99d37',$edits$[
 [
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568",
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692"
 ],
 [
  "887a5069a8ce6ee9bb5c7698968805b85669ab5b87288bbd064a425f6f656ff2",
  "b24879ddb0e3b8f134f1a56333732fbfdd2be9958e1ebdc35089fcdefaf25495"
 ]
]$edits$::jsonb),
        ('_authority_metadata_user_exports_v1(oid,boolean)','049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce','56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2',$edits$[
 [
  "0a6f7e84250775e4aed35e03287ccff4ff71ee5a3c03df904100134203ba9568",
  "822c79b98bc6f0045ded4c5f028a2a3e96b46a108d7d5fe6df839cf170a1c692"
 ]
]$edits$::jsonb),
        ('authority_metadata_user_install_v1(regrole,regrole,boolean)','f00a6cd43c791f583cc70fbfa0eb14b189c9ac3bfa016b873557c302d3fcbcca','32b0e594751f3a6a5e3b9929434be3062dc2ef89dcfe95bc6434d9d81ee2f1db',$edits$[
 [
  "049e27ddfae9da943ee7bf7fd5d34ee2060f3057985be02a35bdb38cd95fc1ce",
  "56e14e491def1c66df6b279eb0b5a3948221dd990a82ccafdf7cc322ac50e8d2"
 ]
]$edits$::jsonb)
    ) AS x(signature,prior,installed,edits) LOOP
        fn:=to_regprocedure('kaname.'||item.signature);
        SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT original,definition
            FROM pg_catalog.pg_proc p WHERE p.oid=fn AND p.proowner=current_user::regrole;
        IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM item.prior
            OR octet_length(definition)-octet_length(replace(definition,original,''))<>octet_length(original) THEN
            RAISE EXCEPTION 'nested active source reservation predecessor differs: %',item.signature USING ERRCODE='55000';
        END IF;
        body:=original;
        FOR edit IN SELECT value FROM jsonb_array_elements(item.edits) LOOP
            IF octet_length(body)-octet_length(replace(body,edit->>0,''))<>octet_length(edit->>0) THEN
                RAISE EXCEPTION 'nested active source reservation replacement ambiguous: %',item.signature USING ERRCODE='55000';
            END IF;
            body:=replace(body,edit->>0,edit->>1);
        END LOOP;
        marker:=substring(left(definition,strpos(definition,original)-1) FROM '([$][[:alnum:]_]*[$])$');
        IF marker IS NULL OR strpos(definition,marker||original||marker)=0
            OR encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active source reservation body differs: %',item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,marker||original||marker,quote_literal(body));
        IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
            IS DISTINCT FROM item.installed THEN
            RAISE EXCEPTION 'nested active source reservation installed body differs: %',item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true
        OR kaname.authority_access_label_storage_valid_v1() IS DISTINCT FROM true THEN
        RAISE EXCEPTION 'nested active source reservation storage graph differs' USING ERRCODE='55000';
    END IF;
END;
$storage$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_role_move_nested_slots_v1(jsonb,integer,integer);
