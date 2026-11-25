-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
-- До публикации владелец сохраняет точный физический OLD и четыре команды обычного
-- reconcile. SQL NULL повторяет проверку на сохранённых входах. Эта функция
-- не выбирает слот, не пишет члена и не подтверждает предикаты после DML.
CREATE FUNCTION kaname._authority_role_move_active_project_seal_v1(p_input jsonb,p_rows integer,p_reads integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $seal$
DECLARE
    proof jsonb; program jsonb; prior_frozen jsonb; saved jsonb; candidate jsonb; witness jsonb;
    coordinates jsonb; tuples jsonb; refs jsonb; commands jsonb; member jsonb; coord jsonb; receipt jsonb;
    blank constant jsonb := '{"Binding":"","Members":null,"Refs":null,"Rows":null,"Tuples":null,"Member":{"ObjectType":"","ObjectID":""},"RuleFP":"","Scope":{"Type":"","ID":""}}';
    fixed_rows constant integer:=40;fixed_reads constant integer:=3;
    rows_used integer;reads_used integer;
BEGIN
    IF p_rows IS NULL OR p_rows NOT BETWEEN fixed_rows+1 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN fixed_reads+1 AND 4096
        OR octet_length(p_input::text)>131072 THEN RAISE EXCEPTION 'active project command budget exceeded' USING ERRCODE='54000';END IF;
    proof:=kaname._authority_role_move_attestation_v1();program:=kaname._authority_sequence_store_v3();
    prior_frozen:=program->'frozen';saved:=prior_frozen->'selector_move_active_project_seal';
    IF program->>'family' IS DISTINCT FROM 'role' OR prior_frozen->>'mode' IS DISTINCT FROM 'selector_move'
        OR program->'nonce' IS DISTINCT FROM proof->'nonce' OR program->>'backend' IS DISTINCT FROM pg_backend_pid()::text
        OR program->>'transaction_id' IS DISTINCT FROM pg_current_xact_id()::text
        OR program->'selected' IS DISTINCT FROM 'null'::jsonb OR program->'decision_at' IS DISTINCT FROM 'null'::jsonb
        OR prior_frozen ?| ARRAY['selector_move_approved','selector_move_content_approval','selector_move_pending_sources']
        OR (p_input IS NULL) IS DISTINCT FROM (saved IS NOT NULL) THEN
        RAISE EXCEPTION 'active project command seal outside its owner phase' USING ERRCODE='42501';
    END IF;
    candidate:=coalesce(p_input,saved->'input');coordinates:=candidate->'coordinates';
    IF jsonb_typeof(candidate) IS DISTINCT FROM 'object' OR candidate-ARRAY['coordinates','commands'] IS DISTINCT FROM '{}'::jsonb
        OR jsonb_typeof(coordinates) IS DISTINCT FROM 'array' OR jsonb_typeof(candidate->'commands') IS DISTINCT FROM 'array'
        OR jsonb_array_length(candidate->'commands') IS DISTINCT FROM 4 OR octet_length(candidate::text)>131072 THEN
        RAISE EXCEPTION 'incomplete active project command proposal' USING ERRCODE='42501';
    END IF;
    -- Тот же backend повторно проверяет и физический ledger, и OLD/NEW из каталога.
    witness:=kaname._authority_role_move_active_project_witness_v1(coordinates,p_rows-fixed_rows,p_reads-fixed_reads);
    rows_used:=fixed_rows+(witness->>'rows')::integer;reads_used:=fixed_reads+(witness->>'reads')::integer;
    IF rows_used IS NULL OR rows_used NOT BETWEEN fixed_rows+1 AND p_rows OR reads_used IS NULL OR reads_used NOT BETWEEN fixed_reads+1 AND p_reads
        THEN RAISE EXCEPTION 'active project witness cost differs' USING ERRCODE='54000';END IF;
    coord:=jsonb_build_object('ObjectType','iam.project','ObjectID',witness->'project_id');
    member:=coord||jsonb_build_object('BindingID',witness->'binding_id','RoleID',witness->'role_id','RuleFP',witness->'new_rule_fp','VerificationStatus','ACTIVE');
    SELECT c#>'{Proposed,0,Tuples}' INTO STRICT tuples FROM jsonb_array_elements(coordinates) c
        WHERE c->'Resource'=jsonb_build_object('Type','iam.project','ID',witness->'project_id');
    IF jsonb_typeof(tuples) IS DISTINCT FROM 'array' OR jsonb_array_length(tuples) NOT BETWEEN 1 AND 8
        OR (SELECT count(DISTINCT t) FROM jsonb_array_elements(tuples) t)<>jsonb_array_length(tuples) THEN
        RAISE EXCEPTION 'active project tuple set differs' USING ERRCODE='42501';END IF;
    SELECT jsonb_agg(jsonb_build_object('BindingID',witness->'binding_id','Member',coord,'Tuple',v) ORDER BY pos)
        INTO refs FROM jsonb_array_elements(tuples) WITH ORDINALITY AS t(v,pos);
    -- Полная форма reconcile.BindingCommand, включая пустые поля и порядок обычного diff.
    commands:=jsonb_build_array(
        blank||jsonb_build_object('Kind','members','Members',jsonb_build_array(member)),
        blank||jsonb_build_object('Kind','write','Tuples',tuples),
        blank||jsonb_build_object('Kind','record','Refs',refs),
        blank||jsonb_build_object('Kind','member_delete','Binding',witness->'binding_id','RuleFP',witness#>'{member_old,2,rule_fp}','Member',coord));
    IF commands IS DISTINCT FROM candidate->'commands' THEN RAISE EXCEPTION 'active project commands differ from owner proof' USING ERRCODE='42501';END IF;
    receipt:=jsonb_build_object('input',candidate,'witness',witness-ARRAY['rows','reads'],'actor',prior_frozen#>'{selector_move,actor}',
        'owner_frame_sha256',encode(sha256(convert_to((prior_frozen-'selector_move_active_project_seal')::text,'UTF8')),'hex'),
        'backend',program->'backend','invoker_oid',proof->'invoker_oid','model_id',proof->'model_id','catalog_id',proof->'catalog_id',
        'projector_version',proof->'projector_version');
    IF p_input IS NOT NULL THEN
        IF octet_length(prior_frozen::text)+octet_length(receipt::text)+64>8388608 THEN
            RAISE EXCEPTION 'active project seal exceeds owner frame budget' USING ERRCODE='54000';END IF;
        UPDATE ONLY pg_temp.kaname_authority_sequence_program s SET frozen=s.frozen||jsonb_build_object('selector_move_active_project_seal',receipt)
            WHERE s.singleton AND s.family='role' AND s.nonce=(proof->>'nonce')::uuid AND s.selected IS NULL AND s.frozen=prior_frozen;
        IF NOT FOUND THEN RAISE EXCEPTION 'active project owner frame changed' USING ERRCODE='40001';END IF;
    ELSIF receipt IS DISTINCT FROM saved THEN
        RAISE EXCEPTION 'active project command receipt changed' USING ERRCODE='40001';
    END IF;
    RETURN jsonb_build_object('sha256',encode(sha256(convert_to(receipt::text,'UTF8')),'hex'),'rows',rows_used,'reads',reads_used);
END;
$seal$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE fn regprocedure:='kaname._authority_role_move_active_project_seal_v1(jsonb,integer,integer)'::regprocedure;grantee record;
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
DROP FUNCTION kaname._authority_role_move_active_project_seal_v1(jsonb,integer,integer);
