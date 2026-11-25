-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Обе карты выбраны либо access_labels одна выбрана по публичной маске.
-- Здесь private freeze допускает единственный переход: изменились labels.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_ordinary_effects_v1(p_audit text)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $effects$
DECLARE
    stash jsonb;
    images jsonb;
    prev jsonb;
    desired jsonb;
    uid text;
    scope jsonb;
    policy_epoch jsonb;
    binding_epoch jsonb;
    journal jsonb;
    audit kaname.audit_outbox;
    reconcile kaname.resource_reconcile_outbox;
    invoker oid;
    rel regclass;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    stash:=kaname._authority_metadata_access_label_stashed_v1();
    images:=stash->'user_images';
    prev:=images->'old_row'; desired:=images->'new_row'; uid:=images->>'root_id';
    invoker:=(stash#>>'{plan,invoker_oid}')::oid;
    IF images->>'mode' IS DISTINCT FROM 'ordinary' OR images->'changed_fields' IS DISTINCT FROM '["labels"]'::jsonb
        OR (desired-'labels') IS DISTINCT FROM (prev-'labels') OR desired->'labels' IS NOT DISTINCT FROM prev->'labels'
        OR coalesce(p_audit,'') COLLATE "C" !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$'
        OR kaname.authority_policy_keys('users',prev) IS DISTINCT FROM ARRAY['user:'||uid]
        OR kaname.authority_policy_keys('users',desired) IS DISTINCT FROM ARRAY['user:'||uid]
        OR kaname.authority_binding_epoch_scope('users',prev) IS DISTINCT FROM ''
        OR kaname.authority_binding_epoch_scope('users',desired) IS DISTINCT FROM '' THEN
        RAISE EXCEPTION 'ordinary user mutation differs from retained labels' USING ERRCODE='42501';
    END IF;
    LOCK TABLE ONLY kaname.authority_policy_epoch, ONLY kaname.authority_binding_epoch, ONLY kaname.audit_outbox,
        ONLY kaname.resource_reconcile_outbox, ONLY kaname.resource_journal IN ROW EXCLUSIVE MODE NOWAIT;
    FOREACH rel IN ARRAY ARRAY['kaname.authority_policy_epoch'::regclass,'kaname.authority_binding_epoch'::regclass,
        'kaname.audit_outbox'::regclass,'kaname.resource_reconcile_outbox'::regclass,'kaname.resource_journal'::regclass] LOOP
        IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=rel AND c.relkind='r' AND c.relpersistence='p'
            AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition OR c.relhassubclass)
            AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=rel)) THEN
            RAISE EXCEPTION 'ordinary user output storage differs' USING ERRCODE='42501';
        END IF;
    END LOOP;
    IF NOT coalesce(has_table_privilege(invoker,'kaname.audit_outbox','INSERT')
        AND has_table_privilege(invoker,'kaname.resource_reconcile_outbox','INSERT')
        AND has_sequence_privilege(invoker,'kaname.resource_reconcile_outbox_id_seq','USAGE,UPDATE')
        AND has_column_privilege(invoker,'kaname.users','labels','UPDATE'),false)
        OR to_regclass(pg_get_serial_sequence('kaname.resource_reconcile_outbox','id'))
            IS DISTINCT FROM 'kaname.resource_reconcile_outbox_id_seq'::regclass THEN
        RAISE EXCEPTION 'ordinary user output privileges or identity differs' USING ERRCODE='42501';
    END IF;
    IF EXISTS(SELECT FROM (VALUES
        ('kaname.audit_outbox'::regclass,'authority_audit_id_guard_v2','kaname.authority_audit_id_guard_v2()'::regprocedure),
        ('kaname.resource_reconcile_outbox'::regclass,'authority_reconcile_id_guard_v2','kaname.authority_reconcile_id_guard_v2()'::regprocedure)
    ) need(rel,name,fn) WHERE NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attname='id'
        WHERE t.tgrelid=need.rel AND t.tgname=need.name AND t.tgfoid=need.fn AND t.tgtype=23
            AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal AND t.tgqual IS NULL AND t.tgattr::text=a.attnum::text)) THEN
        RAISE EXCEPTION 'ordinary user output id guard differs' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(e.generation,e.revision) INTO policy_epoch FROM ONLY kaname.authority_policy_epoch e
    WHERE e.key='user:'||uid FOR UPDATE NOWAIT;
    SELECT jsonb_build_array(e.generation,e.revision) INTO binding_epoch FROM ONLY kaname.authority_binding_epoch e
    WHERE e.scope='' FOR UPDATE NOWAIT;
    IF policy_epoch IS NULL OR binding_epoch IS NULL THEN
        RAISE EXCEPTION 'ordinary user epoch absent' USING ERRCODE='40001';
    END IF;
    IF NOT pg_try_advisory_xact_lock(1262569298,hashtext(p_audit)) THEN
        RAISE EXCEPTION 'ordinary user audit id busy' USING ERRCODE='40001';
    END IF;
    reconcile.id:=nextval('kaname.resource_reconcile_outbox_id_seq');
    IF reconcile.id<=0 OR NOT pg_try_advisory_xact_lock(1262569299,hashtext(reconcile.id::text)) THEN
        RAISE EXCEPTION 'ordinary user reconcile id busy' USING ERRCODE='40001';
    END IF;
    IF EXISTS(SELECT FROM ONLY kaname.audit_outbox a WHERE a.id=p_audit)
        OR EXISTS(SELECT FROM ONLY kaname.resource_reconcile_outbox r WHERE r.id=reconcile.id) THEN
        RAISE EXCEPTION 'ordinary user output id occupied' USING ERRCODE='40001';
    END IF;
    -- Подписка User использует весь удержанный source 31, включая пустой набор.
    SELECT coalesce(jsonb_agg(jsonb_build_object('type','account','id',m#>>'{2,account_id}') ORDER BY m#>>'{2,account_id}'),'[]')
    INTO scope FROM jsonb_array_elements(images->'membership_states') m;
    IF scope IS DISTINCT FROM kaname.resource_journal_scope('iam_user',desired) THEN
        RAISE EXCEPTION 'ordinary user journal scope changed' USING ERRCODE='40001';
    END IF;
    journal:=jsonb_build_object('table','resource_journal','ordinal',1,'stamp','transaction',
        'origin',jsonb_build_object('table','users','operation','UPDATE','when','AFTER','old',prev,'new',desired),
        'row',jsonb_build_object('resource_kind','iam_user','resource_id',uid,'project_id',kaname.resource_journal_project('iam_user',desired),
            'scope',scope,'event_type','UPDATED','payload',jsonb_build_object('id',uid)));
    audit.id:=p_audit;
    audit.event_type:='iam.user.updated';
    audit.tenant_account_id:=nullif(prev->>'account_id','');
    audit.event_payload:=jsonb_build_object('actor',images#>>'{actor,id}','resource_type','user','resource_id',uid,
        'account_id',coalesce(prev->>'account_id',''),'changed_fields',images->'changed_fields');
    audit.status:='pending'; audit.attempts:=0; audit.created_at:=transaction_timestamp(); audit.next_attempt_at:=audit.created_at;
    reconcile.object_type:='iam.user'; reconcile.object_id:=uid; reconcile.event_type:='mirror.upsert';
    reconcile.created_at:=transaction_timestamp(); reconcile.attempt_count:=0;
    RETURN jsonb_build_object('maximum',jsonb_build_array(journal),'audit',to_jsonb(audit),'reconcile',to_jsonb(reconcile),
        'policy_epoch',policy_epoch,'binding_epoch',binding_epoch);
END;
$effects$;
-- +goose StatementEnd

-- Снимок после физического UPDATE: точные три выхода и один bump именно тех
-- epoch, в которые пишут guards User. Физические версии сверяются повторно на COMMIT.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_ordinary_versions_v1()
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $versions$
DECLARE
    images jsonb;
    program jsonb;
    effects jsonb;
    slot jsonb;
    uid text;
    ur jsonb;
    jr jsonb;
    ar jsonb;
    rr jsonb;
    policy_epoch jsonb;
    binding_epoch jsonb;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    uid:=images->>'root_id';
    program:=kaname._authority_sequence_store_v3();
    effects:=program#>'{frozen,effects}';
    slot:=program#>'{selected,0}';
    IF program->>'frozen_mode' IS DISTINCT FROM 'user_ordinary' OR images->>'mode' IS DISTINCT FROM 'ordinary'
        OR program->'nonce' IS DISTINCT FROM images->'nonce' OR program->>'selected_count' IS DISTINCT FROM '1'
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR slot->'origin' IS DISTINCT FROM effects#>'{maximum,0,origin}'
        OR slot->'row' IS DISTINCT FROM (effects#>'{maximum,0,row}')||jsonb_build_object('created_at',transaction_timestamp()) THEN
        RAISE EXCEPTION 'ordinary user selected effects differ' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(u.xmin::text,u.ctid::text) INTO ur FROM ONLY kaname.users u
    WHERE u.id=uid AND to_jsonb(u)=images->'new_row';
    SELECT jsonb_build_array(j.xmin::text,j.ctid::text) INTO jr FROM ONLY kaname.resource_journal j
    WHERE j.sequence_no=(slot->>'reserved_id')::bigint AND to_jsonb(j)=slot->'row'||jsonb_build_object('sequence_no',slot->'reserved_id');
    SELECT jsonb_build_array(a.xmin::text,a.ctid::text) INTO ar FROM ONLY kaname.audit_outbox a
    WHERE a.id=effects#>>'{audit,id}' AND to_jsonb(a)=effects->'audit';
    SELECT jsonb_build_array(r.xmin::text,r.ctid::text) INTO rr FROM ONLY kaname.resource_reconcile_outbox r
    WHERE r.id=(effects#>>'{reconcile,id}')::bigint AND to_jsonb(r)=effects->'reconcile';
    SELECT jsonb_build_array(e.generation,e.revision) INTO policy_epoch FROM ONLY kaname.authority_policy_epoch e WHERE e.key='user:'||uid;
    SELECT jsonb_build_array(e.generation,e.revision) INTO binding_epoch FROM ONLY kaname.authority_binding_epoch e WHERE e.scope='';
    IF num_nonnulls(ur,jr,ar,rr)<>4
        OR policy_epoch IS DISTINCT FROM jsonb_build_array(effects#>'{policy_epoch,0}',(effects#>>'{policy_epoch,1}')::numeric+1)
        OR binding_epoch IS DISTINCT FROM jsonb_build_array(effects#>'{binding_epoch,0}',(effects#>>'{binding_epoch,1}')::numeric+1) THEN
        RAISE EXCEPTION 'ordinary user output or epoch differs' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('user',ur,'journal',jr,'audit',ar,'reconcile',rr);
END;
$versions$;
-- +goose StatementEnd

-- Вызывается только доверенным writer после финального native record_writer и
-- RequireMetadataGrant для фактической дельты labels. Аргументы не содержат NEW.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_ordinary_write_v1(p_op text,p_nonce uuid,p_decision timestamptz)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $write$
DECLARE
    proof jsonb;
    program jsonb;
    cmd jsonb;
    images jsonb;
    physical jsonb;
    actual jsonb;
    version jsonb;
    versions jsonb;
    audit kaname.audit_outbox;
    reconcile kaname.resource_reconcile_outbox;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    program:=kaname._authority_sequence_store_v3(); cmd:=program->'frozen';
    proof:=kaname.authority_protocol_attestation(); physical:=images->'root_physical';
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'purpose' IS DISTINCT FROM 'decision'
        OR proof->>'writer_contract' IS DISTINCT FROM '2' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR p_nonce IS NULL OR proof->>'nonce' IS DISTINCT FROM p_nonce::text OR images->'nonce' IS DISTINCT FROM proof->'nonce'
        OR p_decision IS NULL OR p_decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR p_decision IS DISTINCT FROM (program->>'decision_at')::timestamptz OR p_decision<=(program->>'staged_decision_at')::timestamptz
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program->>'frozen_mode' IS DISTINCT FROM 'user_ordinary'
        OR cmd->>'kind' IS DISTINCT FROM 'metadata.user.ordinary' OR cmd->>'phase' IS DISTINCT FROM 'reserved'
        OR p_op IS DISTINCT FROM cmd#>>'{pending,2,id}' OR cmd->'question' IS DISTINCT FROM images->'update_question'
        OR images->>'mode' IS DISTINCT FROM 'ordinary' OR images->'changed_fields' IS DISTINCT FROM '["labels"]'::jsonb
        OR ((images->'new_row')-'labels') IS DISTINCT FROM ((images->'old_row')-'labels')
        OR program->>'maximum_count' IS DISTINCT FROM '1' OR program->>'selected_count' IS DISTINCT FROM '1'
        OR program#>'{selected,0,origin}' IS DISTINCT FROM cmd#>'{effects,maximum,0,origin}'
        OR NOT EXISTS(SELECT FROM pg_temp.kaname_authority_sequence_effects e WHERE e.nonce=p_nonce
            AND e.ordinal=1 AND e.selected AND NOT(e.registered OR e.claimed OR e.consumed)) THEN
        RAISE EXCEPTION 'ordinary user mutation has no matching final decision' USING ERRCODE='42501';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=cmd||jsonb_build_object('phase','writing')
    WHERE s.singleton AND s.nonce=p_nonce AND s.frozen=cmd;
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary user mutation repeated' USING ERRCODE='42501'; END IF;
    UPDATE ONLY kaname.users u SET labels=images#>'{new_row,labels}'
    WHERE u.id=images->>'root_id' AND u.xmin::text=physical->>'xmin' AND u.ctid::text=physical->>'ctid'
        AND to_jsonb(u)=images->'old_row'
    RETURNING to_jsonb(u),jsonb_build_array(u.xmin::text,u.ctid::text) INTO actual,version;
    IF NOT FOUND OR actual IS DISTINCT FROM images->'new_row' THEN
        RAISE EXCEPTION 'ordinary user physical update changed' USING ERRCODE='40001';
    END IF;
    audit:=jsonb_populate_record(NULL::kaname.audit_outbox,cmd#>'{effects,audit}');
    INSERT INTO kaname.audit_outbox(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at,sent_at,last_error)
    VALUES(audit.id,audit.event_type,audit.tenant_account_id,audit.event_payload,audit.status,audit.attempts,audit.created_at,audit.next_attempt_at,audit.sent_at,audit.last_error);
    reconcile:=jsonb_populate_record(NULL::kaname.resource_reconcile_outbox,cmd#>'{effects,reconcile}');
    INSERT INTO kaname.resource_reconcile_outbox(id,object_type,object_id,event_type,created_at,sent_at,last_error,attempt_count)
    OVERRIDING SYSTEM VALUE VALUES(reconcile.id,reconcile.object_type,reconcile.object_id,reconcile.event_type,reconcile.created_at,reconcile.sent_at,reconcile.last_error,reconcile.attempt_count);
    versions:=kaname._authority_metadata_user_ordinary_versions_v1();
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=cmd||jsonb_build_object('phase','written','versions',versions)
    WHERE s.singleton AND s.nonce=p_nonce AND s.frozen=cmd||jsonb_build_object('phase','writing') AND versions->'user'=version;
    IF NOT FOUND THEN RAISE EXCEPTION 'ordinary user receipt changed' USING ERRCODE='40001'; END IF;
    RETURN actual;
END;
$write$;
-- +goose StatementEnd
-- Общая pending CAS, обе фазы terminal triggers и точное чтение ответа из
-- 12000. У обычной записи один journal slot, фаза written и проверка NEW на COMMIT.
-- +goose StatementBegin
DO $specialize$
DECLARE r record; pair jsonb; src text; sig text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
    ('reserve','p_op text,p_created timestamptz,p_metadata bytea,p_account text,p_actor_type text,p_actor_id text,p_display text,p_rows integer,p_reads integer,p_audit text','jsonb','INVOKER',
        '9f3804647e2534539abc841df97eaff42d4107f24cb19bd05c9378a7dab60143','5e947bed8a60334a202d41137e44a561e2f352555707d3c07fb9b87242a4c18f',
        $changes$[
 [
  "    cost jsonb;",
  "    cost jsonb;\n    effects jsonb;"
 ],
 [
  "target->>'mode' IS DISTINCT FROM 'noop'",
  "target->>'mode' IS DISTINCT FROM 'ordinary'"
 ],
 [
  "target->'changed_fields' IS DISTINCT FROM '[]'::jsonb",
  "target->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb"
 ],
 [
  "BETWEEN 12 AND 100000 OR members>p_rows-12",
  "BETWEEN 64 AND 100000 OR members>(p_rows-64)/2"
 ],
 [
  "BETWEEN 24 AND 4096",
  "BETWEEN 64 AND 4096"
 ],
 [
  "CREATE CONSTRAINT TRIGGER user_metadata_noop_commit",
  "CREATE CONSTRAINT TRIGGER user_metadata_ordinary_commit"
 ],
 [
  "_authority_metadata_user_noop_commit_v1()",
  "_authority_metadata_user_ordinary_commit_v1()"
 ],
 [
  "p_rows-12-members,p_reads-24",
  "p_rows-64-2*members,p_reads-64"
 ],
 [
  "cost->>'mode' IS DISTINCT FROM 'noop' OR images->'changed_fields' IS DISTINCT FROM '[]'::jsonb",
  "cost->>'mode' IS DISTINCT FROM 'ordinary' OR images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb"
 ],
 [
  "OR images->'new_row' IS DISTINCT FROM images->'old_row'",
  "OR ((images->'new_row')-'labels') IS DISTINCT FROM ((images->'old_row')-'labels')"
 ],
 [
  "reads:=kaname._authority_sequence_reserve_v3('metadata','[]'::jsonb,16);",
  "effects:=kaname._authority_metadata_user_ordinary_effects_v1(p_audit);\n    reads:=kaname._authority_sequence_reserve_v3('metadata',effects->'maximum',16);"
 ],
 [
  "'kind','metadata.user.noop','mode','user_noop'",
  "'kind','metadata.user.ordinary','mode','user_ordinary','effects',effects"
 ],
 [
  "+12+members,'reads',(cost->>'reads')::integer+8+reads",
  "+64+2*members,'reads',(cost->>'reads')::integer+48+reads"
 ],
 [
  "user noop reservation differs",
  "ordinary user reservation differs"
 ],
 [
  "user noop reservation exceeds",
  "ordinary user reservation exceeds"
 ]
]$changes$::jsonb),
    ('complete','p_op text,p_nonce uuid,p_decision timestamptz,p_response bytea','kaname.operations','INVOKER',
        'def1bd362158dd3e1e6e02656255ee630dcebc8f9647f15bffc1b2bcb3516735','675bcd6a9a8db783d5bfcc8ee4a8f8662e3d7c7099f6576cd92b15fc00c4067b',
        $changes$[
 [
  "program->>'frozen_mode' IS DISTINCT FROM 'user_noop'",
  "program->>'frozen_mode' IS DISTINCT FROM 'user_ordinary'"
 ],
 [
  "cmd->>'kind' IS DISTINCT FROM 'metadata.user.noop' OR cmd->>'phase' IS DISTINCT FROM 'reserved'",
  "cmd->>'kind' IS DISTINCT FROM 'metadata.user.ordinary' OR cmd->>'phase' IS DISTINCT FROM 'written'"
 ],
 [
  "program->'maximum' IS DISTINCT FROM '[]'::jsonb OR program->'selected' IS DISTINCT FROM '[]'::jsonb",
  "cmd->'versions' IS DISTINCT FROM kaname._authority_metadata_user_ordinary_versions_v1()"
 ],
 [
  "program->>'maximum_count' IS DISTINCT FROM '0' OR program->>'selected_count' IS DISTINCT FROM '0'",
  "program->>'maximum_count' IS DISTINCT FROM '1' OR program->>'selected_count' IS DISTINCT FROM '1'"
 ],
 [
  "images->>'mode' IS DISTINCT FROM 'noop'",
  "images->>'mode' IS DISTINCT FROM 'ordinary'"
 ],
 [
  "user noop has",
  "ordinary user has"
 ],
 [
  "user noop already",
  "ordinary user already"
 ],
 [
  "user noop final",
  "ordinary user final"
 ],
 [
  "user noop terminal",
  "ordinary user terminal"
 ]
]$changes$::jsonb),
    ('commit','','trigger','DEFINER',
        '2ed2f252361b97cf84afba68ed2fdd78e0ddf9c1d2e31dbc5431f64733af54c1','abff163a2ac3a7e5148ec44181ca115f21be07fff6a1cfe66732113b631ead4c',
        $changes$[
 [
  "images->>'mode' IS DISTINCT FROM 'noop'",
  "images->>'mode' IS DISTINCT FROM 'ordinary'"
 ],
 [
  "images->'changed_fields' IS DISTINCT FROM '[]'::jsonb OR images->'old_row' IS DISTINCT FROM images->'new_row'",
  "images->'changed_fields' IS DISTINCT FROM '[\"labels\"]'::jsonb OR ((images->'old_row')-'labels') IS DISTINCT FROM ((images->'new_row')-'labels')"
 ],
 [
  "cmd->>'kind' IS DISTINCT FROM 'metadata.user.noop'",
  "cmd->>'kind' IS DISTINCT FROM 'metadata.user.ordinary'"
 ],
 [
  "program->>'frozen_mode' IS DISTINCT FROM 'user_noop'",
  "program->>'frozen_mode' IS DISTINCT FROM 'user_ordinary'"
 ],
 [
  "program->'selected' IS DISTINCT FROM '[]'::jsonb OR program->'maximum' IS DISTINCT FROM '[]'::jsonb",
  "program->>'maximum_count' IS DISTINCT FROM '1' OR program->>'selected_count' IS DISTINCT FROM '1'"
 ],
 [
  "actual IS DISTINCT FROM NEW.prepared#>'{root,root_state}'",
  "actual->2 IS DISTINCT FROM images->'new_row' OR cmd->'versions' IS DISTINCT FROM kaname._authority_metadata_user_ordinary_versions_v1()"
 ],
 [
  "user noop commit",
  "ordinary user commit"
 ],
 [
  "user noop operation",
  "ordinary user operation"
 ],
 [
  "user noop terminal",
  "ordinary user terminal"
 ],
 [
  "user noop retained",
  "ordinary user retained"
 ]
]$changes$::jsonb)
    ) AS item(name,args,ret,security,before_hash,after_hash,changes) LOOP
        sig:=CASE r.name WHEN 'reserve' THEN 'text,timestamptz,bytea,text,text,text,text,integer,integer' WHEN 'complete' THEN 'text,uuid,timestamptz,bytea' ELSE '' END;
        SELECT prosrc INTO STRICT src FROM pg_catalog.pg_proc WHERE oid=to_regprocedure(
            'kaname._authority_metadata_user_noop_'||r.name||'_v1('||sig||')') AND proowner=current_user::regrole
            AND prosecdef=(r.security='DEFINER') AND provolatile='v';
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM r.before_hash THEN
            RAISE EXCEPTION 'ordinary user prerequisite changed: %',r.name USING ERRCODE='55000';
        END IF;
        FOR pair IN SELECT value FROM jsonb_array_elements(r.changes) LOOP
            IF length(src)-length(replace(src,pair->>0,''))<>length(pair->>0) THEN
                RAISE EXCEPTION 'ordinary user change is not unique: %',r.name USING ERRCODE='55000';
            END IF;
            src:=replace(src,pair->>0,pair->>1);
        END LOOP;
        IF encode(sha256(convert_to(src,'UTF8')),'hex') IS DISTINCT FROM r.after_hash THEN
            RAISE EXCEPTION 'ordinary user specialization differs: %',r.name USING ERRCODE='55000';
        END IF;
        EXECUTE format('CREATE FUNCTION kaname.%I(%s) RETURNS %s LANGUAGE plpgsql VOLATILE SECURITY %s
            SET search_path=pg_catalog,pg_temp AS %L','_authority_metadata_user_ordinary_'||r.name||'_v1',r.args,r.ret,r.security,src);
    END LOOP;
END;
$specialize$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $guard$
DECLARE src text; fn regprocedure:='kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)'::regprocedure;
BEGIN
    SELECT prosrc INTO STRICT src FROM pg_catalog.pg_proc WHERE oid=fn AND proowner=current_user::regrole AND NOT prosecdef;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'14b8e074bc69e5bc6dc6d9089c730a5bba9e35a365018ca512cc6fafb190f9fa' THEN
        RAISE EXCEPTION 'unexpected protected user transition' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$IF header#>>'{frozen,mode}' IS DISTINCT FROM 'user_noop' THEN RETURN false; END IF;$old$,$new$IF coalesce(header#>>'{frozen,mode}','') NOT IN ('user_noop','user_ordinary') THEN RETURN false; END IF;$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'1c096fa8d245f942634532aeb8244eca49d62e8c076b899ca8bff0b6c09ebe7e' THEN
        RAISE EXCEPTION 'protected user transition upgrade differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_metadata_user_noop_transition_v1(p_when text,p_old jsonb,p_new jsonb)
        RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$guard$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; grantee record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_ordinary_effects_v1(text)'::regprocedure,
        'kaname._authority_metadata_user_ordinary_versions_v1()'::regprocedure,
        'kaname._authority_metadata_user_ordinary_write_v1(text,uuid,timestamptz)'::regprocedure,
        'kaname._authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text)'::regprocedure,
        'kaname._authority_metadata_user_ordinary_complete_v1(text,uuid,timestamptz,bytea)'::regprocedure,
        'kaname._authority_metadata_user_ordinary_commit_v1()'::regprocedure
    ] LOOP
        FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN grantee.grantee=0 THEN 'PUBLIC' ELSE quote_ident(grantee.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE ONLY kaname.operations IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $guard$
DECLARE src text; fn regprocedure:='kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)'::regprocedure;
BEGIN
    SELECT prosrc INTO STRICT src FROM pg_catalog.pg_proc WHERE oid=fn AND proowner=current_user::regrole AND NOT prosecdef;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'1c096fa8d245f942634532aeb8244eca49d62e8c076b899ca8bff0b6c09ebe7e' THEN
        RAISE EXCEPTION 'unexpected protected user transition' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$IF coalesce(header#>>'{frozen,mode}','') NOT IN ('user_noop','user_ordinary') THEN RETURN false; END IF;$old$,$new$IF header#>>'{frozen,mode}' IS DISTINCT FROM 'user_noop' THEN RETURN false; END IF;$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'14b8e074bc69e5bc6dc6d9089c730a5bba9e35a365018ca512cc6fafb190f9fa' THEN
        RAISE EXCEPTION 'protected user transition upgrade differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_metadata_user_noop_transition_v1(p_when text,p_old jsonb,p_new jsonb)
        RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$guard$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_user_ordinary_commit_v1();
DROP FUNCTION kaname._authority_metadata_user_ordinary_complete_v1(text,uuid,timestamptz,bytea);
DROP FUNCTION kaname._authority_metadata_user_ordinary_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer,text);
DROP FUNCTION kaname._authority_metadata_user_ordinary_write_v1(text,uuid,timestamptz);
DROP FUNCTION kaname._authority_metadata_user_ordinary_versions_v1();
DROP FUNCTION kaname._authority_metadata_user_ordinary_effects_v1(text);
