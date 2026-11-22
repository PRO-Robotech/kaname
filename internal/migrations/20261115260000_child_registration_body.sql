-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: исполнение точной программы регистрации потомка.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Закрытый вход вызывается после повторной проверки права в том же runner.
-- Снаружи передаётся только исходное намерение, а не образы строк или исход.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_begin_body_v1(p_intent jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE m jsonb; selected jsonb; packed jsonb; result jsonb; outcome text;
 entry jsonb; field text; actual_keys text[]; held_keys text[];
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 m:=kaname._authority_resource_manifest_v2();
 selected:=m#>'{registration_body,selected}';
 IF m->>'state' IS DISTINCT FROM 'final' OR m->'intent'->>'kind' IS DISTINCT FROM 'child_registration'
  OR p_intent IS DISTINCT FROM m->'intent' OR selected->'decision_at' IS DISTINCT FROM m->'decision_at'
  OR m->'writes' IS DISTINCT FROM '[]'::jsonb OR jsonb_typeof(selected) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'child registration body requires the same final intent' USING ERRCODE='42501';
 END IF;
 outcome:=selected->>'outcome';
 result:=jsonb_build_object('outcome',outcome,'source_version',selected->'source_version',
  'certificate',selected->'certificate','commands','[]'::jsonb,
  'transaction_at',m->'transaction_at','decision_at',m->'decision_at');
 IF outcome IN ('parent_missing','parent_closed','child_occupied','capacity','rate') THEN
  RETURN result;
 END IF;
 IF outcome='create' THEN
  packed:=selected->'registration_body';
  IF jsonb_typeof(packed->'writes') IS DISTINCT FROM 'array'
   OR jsonb_array_length(packed->'writes') NOT BETWEEN 1 AND 100000
   OR jsonb_typeof(packed#>'{program,commands}') IS DISTINCT FROM 'array'
   OR jsonb_array_length(packed#>'{program,commands}') NOT BETWEEN 1 AND 100000
   OR jsonb_typeof(packed->'physical') IS DISTINCT FROM 'object'
   OR jsonb_typeof(packed->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'child registration physical program missing' USING ERRCODE='42501';
  END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(packed->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(m->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(m->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'child registration physical effect exceeds held maximum' USING ERRCODE='42501';
    END IF;
   END LOOP;
  END LOOP;
 ELSIF outcome='replay' AND selected->>'source_version' IS NOT NULL THEN
  packed:='{"writes":[],"program":{"commands":[]},"physical":{"bindings":[],"audits":[],"reconcile":[],
    "subject_changes":[],"outboxes":[]},"step_obligations":{},"registration_outbox_write_ordinals":[]}'::jsonb;
 ELSE
  RAISE EXCEPTION 'child registration unknown body outcome' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body',registration_program_claimed=true,
  writes=packed->'writes',registration_program=packed->'program',registration_physical=packed->'physical',
  registration_step_obligations=packed->'step_obligations',
  registration_outbox_write_ordinals=packed->'registration_outbox_write_ordinals';
 RETURN result||jsonb_build_object('commands',packed#>'{program,commands}');
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_step_done_v1(m jsonb,p_step integer) RETURNS void
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE needed jsonb; effect record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 needed:=m->'registration_step_obligations'->p_step::text;
 IF m->'intent'->>'kind' IS DISTINCT FROM 'child_registration' OR m->>'state' IS DISTINCT FROM 'body'
  OR p_step IS NULL OR p_step<1 OR jsonb_typeof(needed) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'child registration command obligations missing' USING ERRCODE='42501';
 END IF;
 FOR effect IN SELECT * FROM (VALUES
  ('writes',m->'consumed_required_writes'),('audits',m->'consumed_audit_ids'),('folds',m->'consumed_object_folds'),
  ('bindings',m->'consumed_registration_bindings'),('reconcile',m->'consumed_reconcile_ids'),
  ('subject_changes',m->'consumed_subject_change_ids')) AS e(kind,actual) LOOP
  IF jsonb_typeof(needed->effect.kind) IS DISTINCT FROM 'array'
   OR jsonb_typeof(effect.actual) IS DISTINCT FROM 'array' OR NOT effect.actual @> (needed->effect.kind) THEN
   RAISE EXCEPTION 'child registration command has an unfinished effect' USING ERRCODE='42501';
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_step_v1(p_ordinal integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE m jsonb; current_step integer; commands jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 m:=kaname._authority_resource_manifest_v2();
 current_step:=(m->>'object_command')::integer;
 commands:=m#>'{registration_program,commands}';
 IF m->'intent'->>'kind' IS DISTINCT FROM 'child_registration' OR m->>'state' IS DISTINCT FROM 'body'
  OR m->>'registration_program_claimed' IS DISTINCT FROM 'true' OR p_ordinal IS NULL OR current_step IS NULL
  OR p_ordinal<>current_step+1 OR p_ordinal<1 OR p_ordinal>jsonb_array_length(commands)
  OR jsonb_typeof(commands) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'child registration command is not the next step' USING ERRCODE='42501';
 END IF;
 IF current_step>0 THEN PERFORM kaname._authority_child_registration_step_done_v1(m,current_step); END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET object_command=p_ordinal;
 RETURN commands->(p_ordinal-1);
END $$;
-- +goose StatementEnd

-- Закрытые строки квоты записываются только после завершения общей
-- программы. На COMMIT независимая проверка требует этот последний эффект.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_complete_v1() RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE m jsonb; selected jsonb; last_step integer; state_row jsonb; receipt jsonb; written jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 m:=kaname._authority_resource_manifest_v2();
 selected:=m#>'{registration_body,selected}';
 last_step:=jsonb_array_length(m#>'{registration_program,commands}');
 IF m->'intent'->>'kind' IS DISTINCT FROM 'child_registration' OR m->>'state' IS DISTINCT FROM 'body'
  OR m->>'registration_program_claimed' IS DISTINCT FROM 'true' OR last_step IS NULL
  OR (m->>'object_command')::integer IS DISTINCT FROM last_step
  OR m->'registration_body' ? 'private_effects_done' THEN
  RAISE EXCEPTION 'child registration completion requires all bound commands' USING ERRCODE='42501';
 END IF;
 IF selected->>'outcome'='create' AND last_step>0 THEN
  PERFORM kaname._authority_child_registration_step_done_v1(m,last_step);
  state_row:=selected->'parent_state';
  receipt:=selected->'receipt';
  IF jsonb_typeof(receipt) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'child registration creation receipt missing' USING ERRCODE='42501';
  END IF;
  IF jsonb_typeof(state_row)='object' THEN
   INSERT INTO kaname.authority_child_parent_state AS stored(object_type,object_id,incarnation,closed_at)
   SELECT object_type,object_id,incarnation,closed_at
   FROM jsonb_populate_record(NULL::kaname.authority_child_parent_state,state_row)
   RETURNING to_jsonb(stored) INTO STRICT written;
   IF written IS DISTINCT FROM state_row THEN
    RAISE EXCEPTION 'child registration parent state escaped final image' USING ERRCODE='42501';
   END IF;
  END IF;
  INSERT INTO kaname.authority_child_creation AS stored(child_type,child_id,source_version,parent_incarnation,created_at,user_id)
  SELECT child_type,child_id,source_version,parent_incarnation,created_at,user_id
  FROM jsonb_populate_record(NULL::kaname.authority_child_creation,receipt)
  RETURNING to_jsonb(stored) INTO STRICT written;
  IF written IS DISTINCT FROM receipt THEN
   RAISE EXCEPTION 'child registration receipt escaped final image' USING ERRCODE='42501';
  END IF;
 ELSIF selected->>'outcome' IS DISTINCT FROM 'replay' OR last_step<>0 THEN
  RAISE EXCEPTION 'child registration invalid completion outcome' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest
  SET registration_body=registration_body||'{"private_effects_done":true}'::jsonb;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE helper record; principal record; BEGIN
 FOR helper IN SELECT oid,oid::regprocedure AS signature,proowner FROM pg_catalog.pg_proc
 WHERE oid IN ('kaname._authority_child_registration_begin_body_v1(jsonb)'::regprocedure,
  'kaname._authority_child_registration_step_done_v1(jsonb,integer)'::regprocedure,
  'kaname._authority_child_registration_step_v1(integer)'::regprocedure,
  'kaname._authority_child_registration_complete_v1()'::regprocedure)
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',helper.signature);
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=helper.oid AND a.grantee<>helper.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',helper.signature,principal.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_complete_v1();
DROP FUNCTION kaname._authority_child_registration_step_v1(integer);
DROP FUNCTION kaname._authority_child_registration_step_done_v1(jsonb,integer);
DROP FUNCTION kaname._authority_child_registration_begin_body_v1(jsonb);
