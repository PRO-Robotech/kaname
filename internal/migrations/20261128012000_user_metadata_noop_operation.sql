-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- Проверяется при COMMIT штатным deferred-механизмом PostgreSQL. Триггер
-- ставится на одноразовый закрытый stash перед сохранением удержанных образов.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_noop_commit_v1()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $commit$
DECLARE
    program jsonb;
    cmd jsonb;
    images jsonb;
    actual jsonb;
    members jsonb;
BEGIN
    IF TG_RELID IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_metadata_discovery')
        OR TG_OP<>'UPDATE' OR TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' THEN
        RAISE EXCEPTION 'user noop commit origin differs' USING ERRCODE='42501';
    END IF;
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    program:=kaname._authority_sequence_store_v3();
    cmd:=program->'frozen';
    IF images IS DISTINCT FROM NEW.prepared->'user_images' OR images->>'mode' IS DISTINCT FROM 'noop'
        OR images->'changed_fields' IS DISTINCT FROM '[]'::jsonb OR images->'old_row' IS DISTINCT FROM images->'new_row'
        OR cmd->>'kind' IS DISTINCT FROM 'metadata.user.noop' OR cmd->>'phase' IS DISTINCT FROM 'done'
        OR program->>'frozen_mode' IS DISTINCT FROM 'user_noop' OR program->>'family' IS DISTINCT FROM 'metadata'
        OR program->'nonce' IS DISTINCT FROM images->'nonce' OR cmd->'question' IS DISTINCT FROM images->'update_question'
        OR program->'selected' IS DISTINCT FROM '[]'::jsonb OR program->'maximum' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'user noop operation was not completed by this decision' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) INTO actual
    FROM ONLY kaname.operations o WHERE o.id=cmd#>>'{pending,2,id}';
    IF actual IS NULL OR actual IS DISTINCT FROM cmd->'terminal' THEN
        RAISE EXCEPTION 'user noop terminal operation changed' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u)) INTO actual
    FROM ONLY kaname.users u WHERE u.id=images->>'root_id';
    members:=kaname._authority_metadata_access_label_held_source_v1(31,'iam.user',images->>'root_id',
        jsonb_array_length(images->'membership_states'),1);
    IF actual IS DISTINCT FROM NEW.prepared#>'{root,root_state}'
        OR members->'states' IS DISTINCT FROM images->'membership_states' THEN
        RAISE EXCEPTION 'user noop retained identity changed' USING ERRCODE='40001';
    END IF;
    RETURN NULL;
END;
$commit$;
-- +goose StatementEnd

-- Сравнение включает исходную Any и immutable identity pending. Heartbeat
-- до захвата допускается: версия modified_at берётся из удержанной строки.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_noop_reserve_v1(
    p_op text,p_created timestamptz,p_metadata bytea,p_account text,
    p_actor_type text,p_actor_id text,p_display text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE
    stash jsonb;
    target jsonb;
    uid text;
    pending jsonb;
    invoker oid;
    images jsonb;
    cost jsonb;
    members integer;
    reads integer;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    stash:=kaname._authority_metadata_access_label_stashed_v1();
    target:=stash->'root';
    uid:=target#>>'{root_state,2,id}';
    members:=jsonb_array_length(target->'membership_states');
    IF stash ? 'user_images' OR target->>'mode' IS DISTINCT FROM 'noop'
        OR target->'changed_fields' IS DISTINCT FROM '[]'::jsonb OR target#>>'{update_question,subject}'
            IS DISTINCT FROM p_actor_type||':'||p_actor_id
        OR kaname._authority_sequence_store_v3() IS NOT NULL THEN
        RAISE EXCEPTION 'user noop reservation differs from prepared patch' USING ERRCODE='42501';
    END IF;
    IF p_rows IS NULL OR p_rows NOT BETWEEN 12 AND 100000 OR members>p_rows-12
        OR p_reads IS NULL OR p_reads NOT BETWEEN 24 AND 4096
        OR coalesce(octet_length(p_metadata),0) NOT BETWEEN 1 AND 8388608 THEN
        RAISE EXCEPTION 'user noop reservation exceeds budget' USING ERRCODE='54000';
    END IF;
    LOCK TABLE ONLY kaname.operations IN ROW EXCLUSIVE MODE NOWAIT;
    invoker:=(stash#>>'{plan,invoker_oid}')::oid;
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid='kaname.operations'::regclass
        AND c.relkind='r' AND c.relpersistence='p' AND NOT (c.relrowsecurity OR c.relforcerowsecurity OR c.relhassubclass
        OR c.relispartition OR c.relhasrules) AND NOT EXISTS(SELECT FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid)
        AND has_table_privilege(invoker,c.oid,'SELECT')) OR EXISTS(
        SELECT FROM unnest(ARRAY['done','modified_at','response_type','response_data']) f
        WHERE has_column_privilege(invoker,'kaname.operations',f,'UPDATE') IS DISTINCT FROM true
    ) OR EXISTS(SELECT FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.operations'::regclass
        AND NOT t.tgisinternal AND (t.tgtype::int & 16)<>0 AND
        (t.tgname NOT IN ('user_access_labels_operation_interrupt','user_access_labels_operation_update')
            OR t.tgfoid<>'kaname._authority_user_access_labels_operation_guard_v1()'::regprocedure OR t.tgenabled<>'A')) THEN
        RAISE EXCEPTION 'protected operation update shape or caller privilege differs' USING ERRCODE='42501';
    END IF;
    SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) INTO pending
    FROM ONLY kaname.operations o WHERE o.id=p_op AND o.user_access_labels AND NOT o.done
        AND o.created_at=p_created AND o.created_by=p_actor_id AND o.resource_id=uid
        AND o.description='Update user '||uid AND o.principal_type=p_actor_type AND o.principal_id=p_actor_id
        AND o.principal_display_name=p_display AND o.account_id IS NOT DISTINCT FROM nullif(p_account,'')
        AND o.account_id IS NOT DISTINCT FROM target#>>'{root_state,2,account_id}'
        AND o.metadata_type='type.googleapis.com/kaname.cloud.iam.v1.UpdateUserMetadata'
        AND o.metadata_data=p_metadata AND num_nonnulls(o.response_type,o.response_data,o.error_code,o.error_message,o.error_details)=0
        FOR UPDATE OF o NOWAIT;
    IF pending IS NULL THEN
        RAISE EXCEPTION 'protected pending user operation changed' USING ERRCODE='40001';
    END IF;
    CREATE CONSTRAINT TRIGGER user_metadata_noop_commit AFTER UPDATE ON pg_temp.kaname_authority_metadata_discovery
        DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
        WHEN (OLD.prepared->'user_images' IS NULL AND NEW.prepared ? 'user_images')
        EXECUTE FUNCTION kaname._authority_metadata_user_noop_commit_v1();
    cost:=kaname._authority_metadata_user_freeze_images_v1(p_actor_type,p_actor_id,p_rows-12-members,p_reads-24);
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    IF cost->>'mode' IS DISTINCT FROM 'noop' OR images->'changed_fields' IS DISTINCT FROM '[]'::jsonb
        OR images->'new_row' IS DISTINCT FROM images->'old_row' OR images->'update_question' IS DISTINCT FROM
            jsonb_build_object('subject',p_actor_type||':'||p_actor_id,'relation','record_writer','object_type','iam_user','object_id',uid) THEN
        RAISE EXCEPTION 'held user patch changes identity' USING ERRCODE='42501';
    END IF;
    reads:=kaname._authority_sequence_reserve_v3('metadata','[]'::jsonb,16);
    PERFORM kaname._authority_sequence_freeze_v3(jsonb_build_object('kind','metadata.user.noop','mode','user_noop',
        'phase','reserved','pending',pending,'question',images->'update_question'));
    RETURN jsonb_build_object('user',images->'new_row','nonce',images->'nonce',
        'rows',(cost->>'rows')::integer+12+members,'reads',(cost->>'reads')::integer+8+reads);
EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'protected pending user operation busy' USING ERRCODE='40001';
END;
$reserve$;
-- +goose StatementEnd

-- Вызывается только из исходного guard под владельцем. Обе фазы сравнивают
-- полные OLD/NEW. Сохранённые фазы требуют прохождения обоих реальных триггеров.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_noop_transition_v1(p_when text,p_old jsonb,p_new jsonb)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $transition$
DECLARE
    proof jsonb;
    header jsonb;
    cmd jsonb;
    from_phase text;
    to_phase text;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    -- У legacy recovery нет FULL entry, в strict режиме даже вызов
    -- attestation в таком контексте был бы изменением прежнего поведения.
    IF to_regclass('pg_temp.kaname_authority_metadata_discovery') IS NULL
        OR to_regclass('pg_temp.kaname_authority_sequence_program') IS NULL THEN RETURN false; END IF;
    SELECT q.proof,q.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() q;
    IF header#>>'{frozen,mode}' IS DISTINCT FROM 'user_noop' THEN RETURN false; END IF;
    cmd:=kaname._authority_sequence_store_v3()->'frozen';
    from_phase:=CASE p_when WHEN 'BEFORE' THEN 'applying' WHEN 'AFTER' THEN 'before_seen' END;
    to_phase:=CASE p_when WHEN 'BEFORE' THEN 'before_seen' WHEN 'AFTER' THEN 'after_seen' END;
    IF from_phase IS NULL OR cmd->>'phase' IS DISTINCT FROM from_phase
        OR cmd#>'{pending,2}' IS DISTINCT FROM p_old OR cmd->'expected' IS DISTINCT FROM p_new
        OR (cmd->>'decision')::timestamptz IS DISTINCT FROM (proof->>'decision_at')::timestamptz THEN
        RAISE EXCEPTION 'protected user terminal transition differs from command' USING ERRCODE='42501';
    END IF;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=cmd||jsonb_build_object('phase',to_phase)
    WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.frozen=cmd;
    IF NOT FOUND THEN RAISE EXCEPTION 'protected user terminal transition repeated' USING ERRCODE='42501'; END IF;
    RETURN true;
END;
$transition$;
-- +goose StatementEnd

-- Только доверенный Go-порт после финального native record_writer на том же
-- writer кодирует возвращённый reserve образ через штатный domain.User DTO.
-- Он передаёт nonce вместе с байтами; SQL фиксирует exact Any атомарно с CAS.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_user_noop_complete_v1(p_op text,p_nonce uuid,p_decision timestamptz,p_response bytea)
RETURNS kaname.operations LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $complete$
DECLARE
    proof jsonb;
    program jsonb;
    cmd jsonb;
    images jsonb;
    actual jsonb;
    expected jsonb;
    result kaname.operations;
    modified timestamptz;
BEGIN
    PERFORM kaname.authority_protocol_require_owner();
    images:=kaname._authority_metadata_access_label_stashed_v1()->'user_images';
    proof:=kaname.authority_protocol_attestation();
    program:=kaname._authority_sequence_store_v3();
    cmd:=program->'frozen';
    IF proof->>'mode' IS DISTINCT FROM 'global' OR proof->>'writer_contract' IS DISTINCT FROM '2'
        OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'resource'
        OR p_nonce IS NULL OR p_nonce IS DISTINCT FROM (proof->>'nonce')::uuid
        OR p_decision IS NULL OR p_decision IS DISTINCT FROM (proof->>'decision_at')::timestamptz
        OR p_decision IS DISTINCT FROM (program->>'decision_at')::timestamptz OR p_decision<=(program->>'staged_decision_at')::timestamptz
        OR program->>'family' IS DISTINCT FROM 'metadata' OR program->>'frozen_mode' IS DISTINCT FROM 'user_noop'
        OR cmd->>'kind' IS DISTINCT FROM 'metadata.user.noop' OR cmd->>'phase' IS DISTINCT FROM 'reserved'
        OR program->'maximum' IS DISTINCT FROM '[]'::jsonb OR program->'selected' IS DISTINCT FROM '[]'::jsonb
        OR program->>'maximum_count' IS DISTINCT FROM '0' OR program->>'selected_count' IS DISTINCT FROM '0'
        OR cmd#>>'{pending,2,id}' IS DISTINCT FROM p_op OR cmd->'question' IS DISTINCT FROM images->'update_question'
        OR images->'nonce' IS DISTINCT FROM proof->'nonce' OR images->>'mode' IS DISTINCT FROM 'noop'
        OR coalesce(octet_length(p_response),0) NOT BETWEEN 1 AND 8388608 THEN
        RAISE EXCEPTION 'user noop has no final decision for this operation' USING ERRCODE='42501';
    END IF;
    modified:=clock_timestamp();
    expected:=(cmd#>'{pending,2}')||jsonb_build_object('done',true,'modified_at',modified,
        'response_type','type.googleapis.com/kaname.cloud.iam.v1.User','response_data',p_response);
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=cmd||jsonb_build_object('phase','applying',
        'decision',p_decision,'expected',expected)
    WHERE s.singleton AND s.nonce=p_nonce AND s.frozen=cmd;
    IF NOT FOUND THEN RAISE EXCEPTION 'user noop already consumed' USING ERRCODE='42501'; END IF;
    UPDATE ONLY kaname.operations o SET done=true,modified_at=modified,
        response_type='type.googleapis.com/kaname.cloud.iam.v1.User',response_data=p_response
    WHERE o.id=p_op AND NOT o.done AND jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))=cmd->'pending'
    RETURNING o.* INTO result;
    IF NOT FOUND OR to_jsonb(result) IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'user noop final operation changed' USING ERRCODE='40001';
    END IF;
    SELECT jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o)) INTO actual
    FROM ONLY kaname.operations o WHERE o.id=p_op;
    UPDATE pg_temp.kaname_authority_sequence_program s SET frozen=(s.frozen-'expected')||
        jsonb_build_object('phase','done','terminal',actual)
    WHERE s.singleton AND s.nonce=p_nonce AND s.frozen->>'phase'='after_seen' AND actual->2=expected;
    IF NOT FOUND THEN RAISE EXCEPTION 'user noop terminal receipt absent' USING ERRCODE='42501'; END IF;
    RETURN result;
END;
$complete$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $patch$
DECLARE
    fn regprocedure:='kaname._authority_user_access_labels_operation_guard_v1()'::regprocedure;
    src text;
BEGIN
    SELECT prosrc INTO STRICT src FROM pg_catalog.pg_proc WHERE oid=fn AND proowner=current_user::regrole AND NOT prosecdef;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'a9528e05a2941ed63ca3b92847bf959cd7eeb1f189d7c8c5d073c4da9d000ed4' THEN
        RAISE EXCEPTION 'unexpected protected user operation guard' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$        IF TG_WHEN='BEFORE' THEN$old$,$new$        -- Доверенный owner DML проходит только с разовым полным OLD/NEW.
        -- При обычном resolver сохраняется прежний Interrupted CAS.
        IF NEW.done AND NEW.response_type='type.googleapis.com/kaname.cloud.iam.v1.User' AND NEW.response_data IS NOT NULL
            AND current_user::regrole=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass) THEN
            IF kaname._authority_metadata_user_noop_transition_v1(TG_WHEN,to_jsonb(OLD),to_jsonb(NEW)) THEN RETURN NEW; END IF;
        END IF;
        IF TG_WHEN='BEFORE' THEN$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'f54eba9554e36977dfb767d8c3113bd5e09194ec0546e33ba9f5540b56b6f5c9' THEN
        RAISE EXCEPTION 'protected user operation guard patch differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_user_access_labels_operation_guard_v1()
        RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$patch$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure; recipient record;
BEGIN
    FOREACH fn IN ARRAY ARRAY[
        'kaname._authority_metadata_user_noop_commit_v1()'::regprocedure,
        'kaname._authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer)'::regprocedure,
        'kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)'::regprocedure,
        'kaname._authority_metadata_user_noop_complete_v1(text,uuid,timestamptz,bytea)'::regprocedure
    ] LOOP
        FOR recipient IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_proc p
            CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
            LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %s',fn,
                CASE WHEN recipient.grantee=0 THEN 'PUBLIC' ELSE format('%I',recipient.rolname) END);
        END LOOP;
    END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
LOCK TABLE ONLY kaname.operations IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $patch$
DECLARE
    fn regprocedure:='kaname._authority_user_access_labels_operation_guard_v1()'::regprocedure;
    src text;
BEGIN
    SELECT prosrc INTO STRICT src FROM pg_catalog.pg_proc WHERE oid=fn AND proowner=current_user::regrole AND NOT prosecdef;
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'f54eba9554e36977dfb767d8c3113bd5e09194ec0546e33ba9f5540b56b6f5c9' THEN
        RAISE EXCEPTION 'unexpected protected user operation guard' USING ERRCODE='55000';
    END IF;
    src:=replace(src,$old$        -- Доверенный owner DML проходит только с разовым полным OLD/NEW.
        -- При обычном resolver сохраняется прежний Interrupted CAS.
        IF NEW.done AND NEW.response_type='type.googleapis.com/kaname.cloud.iam.v1.User' AND NEW.response_data IS NOT NULL
            AND current_user::regrole=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass) THEN
            IF kaname._authority_metadata_user_noop_transition_v1(TG_WHEN,to_jsonb(OLD),to_jsonb(NEW)) THEN RETURN NEW; END IF;
        END IF;
        IF TG_WHEN='BEFORE' THEN$old$,$new$        IF TG_WHEN='BEFORE' THEN$new$);
    IF encode(sha256(convert_to(src,'UTF8')),'hex')<>'a9528e05a2941ed63ca3b92847bf959cd7eeb1f189d7c8c5d073c4da9d000ed4' THEN
        RAISE EXCEPTION 'protected user operation guard patch differs' USING ERRCODE='55000';
    END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_user_access_labels_operation_guard_v1()
        RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS %L',src);
END;
$patch$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_metadata_user_noop_complete_v1(text,uuid,timestamptz,bytea);
DROP FUNCTION kaname._authority_metadata_user_noop_transition_v1(text,jsonb,jsonb);
DROP FUNCTION kaname._authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer);
DROP FUNCTION kaname._authority_metadata_user_noop_commit_v1();
