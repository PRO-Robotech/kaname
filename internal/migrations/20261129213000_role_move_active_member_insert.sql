-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- Применяет первый members той же закрытой программы. Значения таблицы, ключа,
-- статуса или саму команду вызывающий не передаёт. Незавершённая программа
-- остаётся под обязательным deferred authority_sequence_program_completion_v3.
CREATE FUNCTION kaname._authority_role_move_active_member_insert_v1(p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $insert$
DECLARE
    att jsonb; program jsonb; frame jsonb; seal jsonb; certified jsonb; command_row jsonb; physical jsonb;
    postimage jsonb; expected jsonb; cursor_image jsonb; max_id bigint;
    fixed_rows constant integer:=10;fixed_reads constant integer:=7;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_rows+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_reads+1 AND 4096
        THEN RAISE EXCEPTION 'active member insert budget exceeded' USING ERRCODE='54000';END IF;
    att:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();
    frame:=program->'frozen';seal:=frame->'selector_move_active_project_seal';
    IF program->>'family' IS DISTINCT FROM 'role' OR frame->>'mode' IS DISTINCT FROM 'selector_move'
        OR frame ? 'selector_move_active_command_cursor' OR jsonb_typeof(seal) IS DISTINCT FROM 'object'
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'nonce' IS DISTINCT FROM att->'nonce'
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR seal#>'{witness,nonce}' IS DISTINCT FROM att->'nonce' OR seal#>'{witness,xid}' IS DISTINCT FROM program->'transaction_id'
        OR seal#>'{witness,decision_at}' IS DISTINCT FROM att->'decision_at' THEN
        RAISE EXCEPTION 'active project members command is not the next owner step' USING ERRCODE='42501';END IF;
    certified:=kaname._authority_role_move_active_project_seal_v1(NULL,p_rows-fixed_rows,p_reads-fixed_reads);
    IF certified->>'sha256' IS DISTINCT FROM encode(sha256(convert_to(seal::text,'UTF8')),'hex')
        OR seal#>>'{input,commands,0,Kind}' IS DISTINCT FROM 'members' THEN
        RAISE EXCEPTION 'active members command source changed' USING ERRCODE='40001';END IF;
    -- Физический слот журнала роли должен оставаться невыбранным и неиспользованным.
    -- Слот fga_outbox относится ко второй команде и здесь не потребляется.
    max_id:=(program#>>'{maximum,0,reserved_id}')::bigint;
    IF NOT EXISTS(SELECT FROM ONLY pg_temp.kaname_authority_sequence_effects e
        WHERE e.nonce=(att->>'nonce')::uuid AND e.ordinal=1 AND e.table_name='resource_journal' AND e.reserved_id=max_id
        AND e.row_value=program#>'{maximum,0,row}' AND e.origin=program#>'{maximum,0,origin}' AND e.origin#>>'{old,id}'=seal#>>'{witness,role_id}'
        AND e.origin#>>'{new,id}'=seal#>>'{witness,role_id}'
        AND NOT(e.selected OR e.registered OR e.claimed OR e.consumed)) THEN
        RAISE EXCEPTION 'active member lost its reserved role journal' USING ERRCODE='40001';
    END IF;
    physical:=seal#>'{witness,member_old}';command_row:=seal#>'{input,commands,0,Members,0}';
    -- Ожидается новая координата PK. Census уже подтвердил её отсутствие и
    -- удерживает всю выборку. Конфликт — повтор сделки, а не UPDATE чужой строки.
    INSERT INTO kaname.access_binding_target_members AS m
        (binding_id,role_id,rule_fp,object_type,object_id,verification_status,created_at,updated_at)
    SELECT command_row->>'BindingID',command_row->>'RoleID',command_row->>'RuleFP',command_row->>'ObjectType',
        command_row->>'ObjectID',command_row->>'VerificationStatus',now(),now()
    FROM ONLY kaname.access_binding_target_members old_member
    WHERE old_member.binding_id=command_row->>'BindingID' AND old_member.role_id=command_row->>'RoleID'
        AND old_member.rule_fp=physical#>>'{2,rule_fp}' AND old_member.object_type=command_row->>'ObjectType'
        AND old_member.object_id=command_row->>'ObjectID'
        AND jsonb_build_array(old_member.xmin::text,old_member.ctid::text,to_jsonb(old_member))=physical
    ON CONFLICT (binding_id,role_id,rule_fp,object_type,object_id) DO NOTHING
    RETURNING jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) INTO postimage;
    expected:=(physical->2)||jsonb_build_object('rule_fp',command_row->'RuleFP','created_at',now(),'updated_at',now());
    IF NOT FOUND OR postimage->2 IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'active project member insert differs from sealed OLD' USING ERRCODE='40001';
    END IF;
    cursor_image:=jsonb_build_object('last_consumed',1,'seal_sha256',certified->'sha256','member_new',postimage,
        'nonce',att->'nonce','xid',program->'transaction_id','role_journal_id',max_id);
    IF octet_length(frame::text)+octet_length(cursor_image::text)+64>8388608 THEN
        RAISE EXCEPTION 'active member cursor exceeds owner frame budget' USING ERRCODE='54000';END IF;
    UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_active_command_cursor',cursor_image)
        WHERE s.singleton AND s.family='role' AND s.nonce=(att->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=frame;
    IF NOT FOUND THEN RAISE EXCEPTION 'active members cursor changed' USING ERRCODE='40001';END IF;
    RETURN cursor_image||jsonb_build_object('rows',fixed_rows+(certified->>'rows')::integer,'reads',fixed_reads+(certified->>'reads')::integer);
END;
$insert$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_active_member_insert_v1(integer,integer)'::regprocedure;grantee record;
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

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_role_move_active_member_insert_v1(integer,integer);
