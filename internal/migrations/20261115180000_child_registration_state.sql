-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: состояние текущей регистрации родителя и квитанции создания.
-- Приёмка: docs/engineering/acceptance/user-child-registration.md
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Текущая инкарнация переживает обновление метаданных зеркала. Снятие
-- регистрации удаляет строку состояния в той же транзакции.
CREATE TABLE kaname.authority_child_parent_state (
 object_type text NOT NULL CHECK(object_type LIKE '%.%'),
 object_id text NOT NULL CHECK(object_id<>''),
 incarnation uuid NOT NULL DEFAULT gen_random_uuid(),
 closed_at timestamptz CHECK(isfinite(closed_at)),
 PRIMARY KEY(object_type,object_id),
 UNIQUE(incarnation),
 FOREIGN KEY(object_type,object_id) REFERENCES kaname.resource_mirror(object_type,object_id) ON DELETE CASCADE
);

-- Снятие потомка и родителя не возвращает расход текущего окна. Квитанция
-- связывается с конкретной версией потомка и сохраняет пользователя для аудита.
CREATE TABLE kaname.authority_child_creation (
 child_type text NOT NULL CHECK(child_type LIKE '%.%'),
 child_id text NOT NULL CHECK(child_id<>''),
 source_version timestamptz NOT NULL CHECK(isfinite(source_version)),
 parent_incarnation uuid NOT NULL,
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 user_id text NOT NULL CHECK(user_id<>''),
 PRIMARY KEY(child_type,child_id,source_version)
);

CREATE INDEX authority_child_creation_rate
 ON kaname.authority_child_creation(parent_incarnation,child_type,created_at);
CREATE INDEX resource_parent_edge_direct_children
 ON kaname.resource_parent_edge(parent_type,parent_id,object_type,object_id) WHERE depth=1;

-- FK не должен ждать закрытое состояние родителя впервые после DecisionAt.
-- В закрытый план попадают только фактические удаления зеркала.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_parent_cascade_prewait_v1(p_direct jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(held_relations jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF jsonb_typeof(p_direct->'steps') IS DISTINCT FROM 'array' OR jsonb_array_length(p_direct->'steps')>100000
  OR p_rows IS NULL OR p_reads IS NULL THEN
  RAISE EXCEPTION 'child parent cascade plan invalid' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('object_type',coordinate.dotted_type,'object_id',coordinate.object_id)),'[]'::jsonb)
 INTO keys FROM (
  SELECT DISTINCT step->>'dotted_type' dotted_type,step->>'object_id' object_id
  FROM jsonb_array_elements(p_direct->'steps') step
  WHERE step->>'kind'='cleanup_mirror_delete' AND step->'deleted'='true'::jsonb
 ) coordinate;
 logical_rows:=jsonb_array_length(keys);
 held_relations:='[]'::jsonb;
 logical_reads:=0;
 IF logical_rows=0 THEN RETURN NEXT;RETURN;END IF;
 IF logical_rows>p_rows OR p_reads<2 THEN
  RAISE EXCEPTION 'child parent cascade lock budget exceeded' USING ERRCODE='54000';
 END IF;
 LOCK TABLE ONLY kaname.authority_child_parent_state IN ROW EXCLUSIVE MODE;
 PERFORM 1 FROM jsonb_to_recordset(keys) AS item(object_type text,object_id text)
  JOIN ONLY kaname.authority_child_parent_state p USING(object_type,object_id)
  ORDER BY p.object_type COLLATE "C",p.object_id COLLATE "C" FOR UPDATE OF p;
 held_relations:=jsonb_build_array(jsonb_build_object(
  'oid','kaname.authority_child_parent_state'::regclass::oid,'mode','RowExclusiveLock'));
 logical_reads:=2;
 RETURN NEXT;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_child_parent_cascade_prewait_v1(jsonb,integer,integer) FROM PUBLIC;
 FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_parent_cascade_prewait_v1(jsonb,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_parent_cascade_prewait_v1(jsonb,integer,integer) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE target text;r record;BEGIN
 FOREACH target IN ARRAY ARRAY['authority_child_parent_state','authority_child_creation'] LOOP
  EXECUTE format('REVOKE ALL ON TABLE kaname.%I FROM PUBLIC',target);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
   WHERE c.oid=to_regclass('kaname.'||target) AND a.grantee<>c.relowner LOOP
   EXECUTE format('REVOKE ALL ON TABLE kaname.%I FROM %I',target,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding runtime grant closure incomplete' USING ERRCODE='55000';END IF;
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 -- Исторический GRANT SELECT ON ALL TABLES не открывает состояние допуска.
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_child_parent_state,kaname.authority_child_creation FROM %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_child_parent_state','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_child_creation','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains private child registration privileges' USING ERRCODE='42501';
 END IF;
 FOREACH signature IN ARRAY ARRAY[
  'authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()',
  'authority_native_delete_batch_read_v4()',
  'authority_native_delete_emit_v4(jsonb[])',
  'authority_native_delete_prepare_v4(jsonb[])',
  'authority_native_delete_stamp_v4(uuid,bigint,jsonb)',
  'authority_forward_emit_v4(jsonb[])',
  'authority_forward_prepare_v4(jsonb[])',
  'authority_forward_claim_v4(uuid)',
  'authority_forward_finish_v4(uuid)',
  'authority_group_add_prepare_v3(jsonb,integer,integer)',
  'authority_group_add_finalize_v3(jsonb,integer,integer)',
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_group_add_subject_id_v3()',
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_command_begin_v3(jsonb)',
  'authority_binding_command_end_v3(jsonb)',
  'authority_binding_command_audit_v3(jsonb)',
  'authority_binding_sequence_prepare_v3(text,jsonb)',
  'authority_binding_sequence_finalize_v3()',
  'authority_binding_insert_stamp_v3(text)',
  'authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_finalize_v3(text)',
  'authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)',
  'authority_binding_withdrawal_sequence_finalize_v3()',
  'authority_cluster_admin_preflight_v4(text,text,text)',
  'authority_resource_journal_id_v3()',
  'authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
  'authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_metadata_preflight_v4(text,text,boolean,text,jsonb)',
  'authority_sa_state_preflight_v4(text,boolean,text)',
  'authority_scalar_sequence_finalize_v3()',
  'authority_crud_storage_v3()',

  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_reconcile_enter_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
 -- После полной поставки выдаём runtime только узкие входы тела потомка.
 IF to_regprocedure('kaname._authority_child_runtime_storage_v1()') IS NOT NULL THEN
  FOREACH signature IN ARRAY ARRAY['authority_child_registration_begin_body_v1(jsonb)',
   'authority_child_registration_step_v1(integer)','authority_child_registration_complete_v1()',
   'authority_child_parent_close_apply_v1(jsonb)'] LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
  END LOOP;
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_assert_body_v2(p_intent jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->'intent'->>'kind' IN ('child_registration','child_parent_close') THEN
  RAISE EXCEPTION 'child registration body requires its own authorization path' USING ERRCODE='42501';
 END IF;
 IF manifest->>'state' IS DISTINCT FROM 'final' OR p_intent IS DISTINCT FROM manifest->'intent'
 OR manifest->>'decision_at' IS NULL THEN
  RAISE EXCEPTION 'resource closed body requires final manifest' USING ERRCODE='42501';
 END IF;
 -- Resource не является writer личности или каталога. Проверка действует
 -- до смены state на body: даже ошибочный private creator не может включить
 -- SA INSERT/DELETE/reparent и обойти GLOBAL/root защиту absence witness.
 -- Точные разрешённые OLD/NEW оставшихся таблиц дополнительно проверяет
 -- semantic creator; принадлежность этому перечню сама по себе не allow.
 IF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
 ELSE
 IF jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
  WHERE coalesce(w->>'table','') NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox')) THEN
  RAISE EXCEPTION 'resource manifest contains unsupported write domain' USING ERRCODE='42501';
 END IF;
 END IF;
 -- Второй запуск того же тела в одной TX также отвергается. Изменение
 -- касается только уже открытой private temp строки, новых waits нет.
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body';
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_require_completion_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;
BEGIN
 storage:=to_regclass('pg_temp.kaname_authority_resource_manifest');
 IF TG_RELID IS DISTINCT FROM storage OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid=storage AND c.relowner=current_user::regrole::oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'resource completion trigger target invalid' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'body'
 OR jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000 THEN
  RAISE EXCEPTION 'resource body did not complete' USING ERRCODE='42501';
 END IF;
 SELECT consumed_required_writes INTO STRICT consumed FROM pg_temp.kaname_authority_resource_manifest;
 IF consumed IS NULL OR cardinality(consumed)>100000
 OR EXISTS(SELECT 1 FROM unnest(consumed) n WHERE n IS NULL OR n<1 OR n>jsonb_array_length(manifest->'writes'))
 OR EXISTS(SELECT 1 FROM unnest(consumed) n GROUP BY n HAVING count(*)<>1)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w WHERE jsonb_typeof(w->'required') IS DISTINCT FROM 'boolean') THEN
  RAISE EXCEPTION 'resource completion inventory is invalid' USING ERRCODE='42501';
 END IF;
 SELECT count(*)::integer INTO required_count FROM jsonb_array_elements(manifest->'writes') w WHERE w->>'required'='true';
 SELECT count(*)::integer INTO consumed_count FROM unnest(consumed) n
  WHERE manifest->'writes'->(n-1)->>'required'='true';
 IF required_count<>consumed_count THEN
  RAISE EXCEPTION 'resource mandatory effect was omitted' USING ERRCODE='42501';
 END IF;
 -- Audit и вспомогательные очереди не входят в authority32; их точное
 -- применение и завершение последней команды проверяются отдельно.
 IF manifest->'intent'->>'kind'='object' THEN
  IF manifest->>'object_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{object_program,commands}') THEN
   RAISE EXCEPTION 'resource object program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'object_physical';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  PERFORM kaname._authority_crud_require_completion_v3(manifest);
  physical:=manifest->'registration_physical';
 ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4','5')
  OR manifest->'intent'->>'kind' IN ('child_registration','child_parent_close') THEN
  IF manifest->'intent'->>'kind' IN ('child_registration','child_parent_close')
   AND manifest#>'{registration_body,private_effects_done}' IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'child registration private effects were omitted' USING ERRCODE='42501';END IF;
  IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{registration_program,commands}') THEN
   RAISE EXCEPTION 'resource registration program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'registration_physical';
  IF jsonb_typeof(physical->'bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'reconcile') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_registration_bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_reconcile_ids') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'subject_changes') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_subject_change_ids') IS DISTINCT FROM 'array'
   OR jsonb_array_length(physical->'subject_changes')<>jsonb_array_length(manifest->'consumed_subject_change_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'subject_changes') r
    WHERE NOT (manifest->'consumed_subject_change_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_subject_change_ids') n GROUP BY n HAVING count(*)<>1)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'bindings') WITH ORDINALITY e(value,ordinality)
    WHERE e.value->>'required'='true' AND NOT (manifest->'consumed_registration_bindings') @> jsonb_build_array(e.ordinality))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n
    WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'bindings')
     OR physical->'bindings'->(n::integer-1)->>'required' IS DISTINCT FROM 'true')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n GROUP BY n HAVING count(*)<>1)
   OR jsonb_array_length(physical->'reconcile')<>jsonb_array_length(manifest->'consumed_reconcile_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'reconcile') r
    WHERE NOT (manifest->'consumed_reconcile_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_reconcile_ids') n GROUP BY n HAVING count(*)<>1) THEN
    RAISE EXCEPTION 'resource registration auxiliary effect omitted' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'resource completion intent unsupported' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(physical->'audits') IS DISTINCT FROM 'array'
  OR jsonb_typeof(manifest->'consumed_audit_ids') IS DISTINCT FROM 'array'
  OR jsonb_array_length(physical->'audits')<>jsonb_array_length(manifest->'consumed_audit_ids')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'audits') a
   WHERE NOT (manifest->'consumed_audit_ids') ? (a->'row'->>'id'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_audit_ids') identifier GROUP BY identifier HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory audit was omitted' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
  OR jsonb_typeof(physical->'outboxes') IS DISTINCT FROM 'array'
  OR jsonb_array_length(manifest->'consumed_object_folds')<>jsonb_array_length(physical->'outboxes')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n
   WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'outboxes'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n GROUP BY n HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_fold_body_v2(p_event_type text,p_payload jsonb,p_created_at timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;item jsonb;expected jsonb;row_value jsonb;image jsonb;invoker oid;
 ordinal integer;write_ordinal integer;selected integer:=0;outboxes jsonb;fold_images jsonb;outbox_ordinals jsonb;requires_update boolean:=true;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  IF kaname._authority_binding_mirror_store_v3() IS NULL THEN RETURN false;END IF;
  expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
  SELECT i.image_no,i.outbox_no INTO write_ordinal,selected FROM pg_temp.kaname_binding_mirror_images i
   WHERE i.table_name='fga_outbox' AND i.new_image=expected AND i.attempted AND i.consumed AND NOT i.folded
   ORDER BY i.command_no,i.image_no LIMIT 1;
  IF write_ordinal IS NULL THEN RAISE EXCEPTION 'binding mirror fold lacks actual journal' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=selected WHERE singleton;
  invoker:=(kaname.authority_protocol_attestation()->>'invoker_oid')::oid;
  FOR image IN SELECT jsonb_build_object('operation',i.operation,'old',i.old_image,'new',i.new_image)
   FROM pg_temp.kaname_binding_mirror_images i WHERE i.table_name='relation_fact' AND i.outbox_no=selected ORDER BY i.image_no LOOP
   IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT') THEN
    RAISE EXCEPTION 'binding mirror fold requires original SELECT ACL' USING ERRCODE='42501';END IF;
   IF image->>'operation'='INSERT' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT') OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original upsert ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'new';
    INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
    VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
     (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,row_value->>'condition_name',row_value->'condition_params')
    ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
     SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
     WHERE relation_fact.source_version<EXCLUDED.source_version;
   ELSE
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE') OR NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original delete ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'old';
    DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
     AND relation=row_value->>'relation' AND subject=row_value->>'subject';
   END IF;
  END LOOP;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=NULL WHERE singleton;
  UPDATE pg_temp.kaname_binding_mirror_images SET folded=true WHERE image_no=write_ordinal;
  RETURN true;
 END IF;
 IF manifest->'intent'->>'kind'='object' THEN
  outboxes:=manifest#>'{object_physical,outboxes}';fold_images:=manifest#>'{object_fold,images}';
  outbox_ordinals:=manifest->'object_outbox_write_ordinals';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4')
  OR manifest->'intent'->>'kind'='child_registration' THEN
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSE RAISE EXCEPTION 'resource fold intent unsupported' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(outboxes) IS DISTINCT FROM 'array' OR jsonb_typeof(fold_images) IS DISTINCT FROM 'array'
 OR jsonb_typeof(outbox_ordinals) IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
 OR jsonb_array_length(outboxes)>100000 OR jsonb_array_length(fold_images)>100000
 OR jsonb_array_length(outbox_ordinals)<>jsonb_array_length(outboxes) THEN
  RAISE EXCEPTION 'resource fold private program unavailable' USING ERRCODE='42501';END IF;
 expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
 ordinal:=0;
 FOR item IN SELECT value FROM jsonb_array_elements(outboxes) LOOP
  ordinal:=ordinal+1;
  IF item->'command' IS DISTINCT FROM manifest->'object_command'
  OR item->'row' IS DISTINCT FROM expected OR (manifest->'consumed_object_folds') @> jsonb_build_array(ordinal) THEN CONTINUE;END IF;
  write_ordinal:=(outbox_ordinals->>(ordinal-1))::integer;
  IF write_ordinal IS NULL OR write_ordinal<1 OR write_ordinal>jsonb_array_length(manifest->'writes') THEN
   RAISE EXCEPTION 'resource fold outbox linkage invalid' USING ERRCODE='42501';END IF;
  -- BEFORE INSERT сопоставил exact image, AFTER ROW подтвердил actual INSERT.
  -- Только обе отметки разрешают fold. Операторный journal trigger идёт
  -- после row triggers; попытка ON CONFLICT DO NOTHING не даёт этого права.
  IF NOT (manifest->'consumed_outbox_writes') @> jsonb_build_array(write_ordinal)
  OR NOT (manifest->'consumed_required_writes') @> jsonb_build_array(write_ordinal) THEN CONTINUE;END IF;
  IF selected=0 THEN selected:=ordinal;END IF;
 END LOOP;
 IF selected=0 THEN RAISE EXCEPTION 'resource fold without matching inserted journal' USING ERRCODE='42501';END IF;
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'object' THEN
  IF jsonb_typeof(outboxes->(selected-1)->'requires_update_acl') IS DISTINCT FROM 'boolean' THEN
   RAISE EXCEPTION 'registration fold row-lock ACL proof missing' USING ERRCODE='42501';END IF;
  requires_update:=(outboxes->(selected-1)->>'requires_update_acl')::boolean;
 END IF;
 invoker:=(manifest->>'invoker_oid')::oid;
 IF manifest->'intent'->>'Action'='2' THEN
  PERFORM kaname._authority_resource_unregistration_operation_acl_v2(manifest#>'{registration_body,acl}',invoker,
   jsonb_build_object('steps',jsonb_build_array(manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1))));
 END IF;
 FOR image IN SELECT value FROM jsonb_array_elements(fold_images) LOOP
  IF (image->>'outbox')::integer IS DISTINCT FROM selected THEN CONTINUE;END IF;
  IF image->>'table' IS DISTINCT FROM 'relation_fact' OR image->>'operation' NOT IN ('INSERT','UPDATE','DELETE') THEN
   RAISE EXCEPTION 'invalid resource folded physical action' USING ERRCODE='42501';END IF;
  -- INSERT исполняет тот же ON CONFLICT UPDATE, поэтому UPDATE image ниже
  -- является его проверяемым исходом, а не второй независимой командой.
  IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
  IF image->>'operation'='INSERT' THEN
   IF manifest->'intent'->>'Action'='2' THEN
    RAISE EXCEPTION 'cleanup cannot fold a fact write' USING ERRCODE='42501';END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
    RAISE EXCEPTION 'resource fold requires caller fact upsert ACL' USING ERRCODE='42501';END IF;
   row_value:=image->'new';
   INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
   VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
    (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,
    row_value->>'condition_name',row_value->'condition_params')
   ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
    SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
    WHERE relation_fact.source_version<EXCLUDED.source_version;
  ELSE
   IF manifest->'intent'->>'Action' IS DISTINCT FROM '2' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
    OR NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE')
    OR (requires_update AND NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE')) THEN
     RAISE EXCEPTION 'resource fold requires caller fact delete ACL' USING ERRCODE='42501';END IF;
   END IF;
   row_value:=image->'old';
   DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
    AND relation=row_value->>'relation' AND subject=row_value->>'subject';
  END IF;
 END LOOP;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_object_folds=array_append(consumed_object_folds,selected);
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; manifest jsonb; allowed boolean;step jsonb;sequence_program jsonb;
BEGIN
 -- Один свежий proof/header на этот вызов. Probe сохраняет unsigned NULL
 -- и прежний порядок attestation перед owner/ACL/header проверками.
 SELECT q.proof,q.header INTO STRICT proof,sequence_program FROM kaname._authority_sequence_probe_v3() q;
 IF sequence_program#>>'{frozen,mode}'='authorize' THEN
  RAISE EXCEPTION 'authorization-only callback cannot mutate persistent state' USING ERRCODE='42501';
 END IF;
 IF kaname._authority_group_add_statement_v3(TG_TABLE_NAME,TG_OP) THEN RETURN NULL;END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  allowed:=false;
  IF manifest->'intent'->>'kind'='object' THEN
   step:=manifest#>'{object_program,commands}'->((manifest->>'object_command')::integer-1);
   -- Проверяем только текущий выданный private command, не соседние шаги.
   -- Два закрытых UPSERT: members и fact fold команды write. Оба вызывают
   -- statement UPDATE даже без конфликтующей строки или при stale версии.
   -- Синтаксическое UPDATE подтверждает attempted INSERT того же шага;
   -- разрешённые actual row images и обязательность consumption не меняются.
   SELECT manifest->>'object_program_claimed'='true' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
    WHERE w->'command'=manifest->'object_command' AND w->>'table'=TG_TABLE_NAME
    AND (w->>'operation'=TG_OP OR
     (TG_OP='UPDATE' AND w->>'operation'='INSERT'
      AND ((step->>'Kind'='members' AND TG_TABLE_NAME='access_binding_target_members')
       OR (step->>'Kind'='write' AND TG_TABLE_NAME='relation_fact'))))) INTO allowed;
  ELSIF manifest->'intent'->>'kind'='crud' THEN
   -- Новый маршрут читает только текущую закрытую owner-private команду.
   -- Указание kind в caller JSON само по себе не создаёт ни proof, ни программу.
   PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4')
   OR manifest->'intent'->>'kind' IN ('child_registration','child_parent_close') THEN
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  END IF;
  IF TG_OP='TRUNCATE' OR NOT coalesce(allowed,false) THEN
   RAISE EXCEPTION 'resource statement absent from current private command' USING ERRCODE='42501';
  END IF;
  RETURN NULL;
 END IF;
 -- В NULL-ветке producer выполнены только private consumer reads;
 -- ни DML, ни callback, ни изменение clock/identity между proof и проверкой нет.
 -- kaname#1034: после удаления parent каскадный child уже не обязан видеть
 -- его anchor; role target cascade также может затронуть другой account.
 -- До отдельной proven классификации adapter выбирает global ДО всех locks.
 IF proof IS NOT NULL AND proof->>'mode'<>'global'
 AND (TG_OP='TRUNCATE' OR (TG_OP='DELETE' AND TG_TABLE_NAME IN ('roles','groups','accounts'))) THEN
  RAISE EXCEPTION 'authority truncate or parent cascade requires global intent' USING ERRCODE='42501';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_registration_command_values_v2(p_input jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;certificate jsonb;step jsonb;expected jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();IF manifest IS NULL THEN RETURN NULL;END IF;
 IF manifest->'intent'->>'kind'='child_registration' THEN
  certificate:=manifest#>'{registration_body,selected,certificate}';
  expected:=certificate->'command';
 ELSIF manifest->'intent'->>'Action'='1' THEN
  certificate:=manifest->'registration_certificate';
  expected:=certificate->'input_command';
 END IF;
 step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object'
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
 OR step->>'kind' IS DISTINCT FROM 'mirror'
 OR p_input IS DISTINCT FROM expected
 OR jsonb_typeof(step->'applied') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(step->'projection_unchanged') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'canonical registration command differs from current private step' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('command',certificate->'command','catalog',certificate->'catalog',
  'applied',step->'applied','projection_unchanged',step->'projection_unchanged');
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_prewait_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;prepared record;
BEGIN
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'resource prewait input budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->'abi' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(p_envelope->'intent') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource prewait ABI mismatch' USING ERRCODE='42501';END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'resource prewait requires fresh typed participant' USING ERRCODE='42501';END IF;
 IF p_envelope->'intent'->>'kind'='child_parent_close' THEN
  IF proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
   OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'child parent close requires exact full source participant' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_child_parent_close_prepare_v1(p_envelope,p_rows,p_reads);
 ELSIF p_envelope->'intent'->>'kind'='child_registration' THEN
  IF p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'child registration requires exact full source participant' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_child_registration_prepare_v1(p_envelope,p_rows,p_reads);
 ELSIF p_envelope->'intent'->>'kind'='crud' THEN
  IF p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'CRUD requires exact full source participant' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_crud_prepare_v3(p_envelope,p_rows,p_reads);
 ELSIF p_envelope->'intent' ? 'kind' THEN
  IF p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
  OR p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending' THEN
   RAISE EXCEPTION 'object route requires exact pending object intent' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_object_prepare_v2(p_envelope,p_rows,p_reads);
 ELSE
  -- The closed family dispatcher checks Action and delegates to the complete
  -- direct, withdrawal or refusal compiler. Unknown intents never fall back.
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_registration_prepare_v2(p_envelope,p_rows,p_reads);
 END IF;
 IF prepared.logical_rows IS NULL OR prepared.logical_rows<0 OR prepared.logical_rows>p_rows
 OR prepared.logical_reads IS NULL OR prepared.logical_reads<0 OR prepared.logical_reads>p_reads THEN
  RAISE EXCEPTION 'resource compiler exceeded shared budget' USING ERRCODE='54000';END IF;
 RETURN QUERY SELECT prepared.logical_rows::integer,prepared.logical_reads::integer;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_finalize_v2(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(decision_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; expected jsonb; actual jsonb; keys text[]; at_time timestamptz; count_rows integer;
 materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];
BEGIN
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'resource final budget exceeded' USING ERRCODE='54000';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'prepared' OR p_intent IS DISTINCT FROM manifest->'intent' THEN
  RAISE EXCEPTION 'resource final intent mismatch or repeated final clock' USING ERRCODE='42501';
 END IF;
 IF manifest->'intent'->>'kind'='child_registration' THEN
  RETURN QUERY SELECT * FROM kaname._authority_child_registration_finalize_v1(p_intent,p_rows,p_reads);
  RETURN;
 END IF;
 expected:=manifest->'native_epochs';
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource native epoch manifest missing' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(k),ARRAY[]::text[]) INTO keys FROM jsonb_object_keys(expected) k;
 count_rows:=cardinality(keys);
 IF count_rows>4096 OR count_rows>p_rows THEN
  RAISE EXCEPTION 'resource final epoch budget exceeded' USING ERRCODE='54000';
 END IF;
 -- Отсутствие exact epoch не превращается в нулевую revision. Prewait уже
 -- закрепил каждый ключ и его gap; здесь не INSERT и не FOR SHARE/UPDATE.
 SELECT coalesce(jsonb_object_agg(k,CASE WHEN e.key IS NULL THEN 'null'::jsonb
  ELSE jsonb_build_array(e.generation,e.revision) END),'{}'::jsonb)
 INTO actual FROM unnest(keys) k LEFT JOIN kaname.authority_policy_epoch e ON e.key=k;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'resource native source changed' USING ERRCODE='P1034';
 END IF;
 at_time:=clock_timestamp();
 IF manifest->'intent'->>'kind'='child_parent_close' THEN
  PERFORM kaname._authority_resource_registration_authority_final_v2(manifest->'registration_authority',at_time);
 ELSIF manifest->'intent'->>'kind'='object' THEN
  materialized:=kaname._authority_resource_object_materialize_v2(manifest->'object_certificate',
   manifest->'object_effects',manifest->'object_sources',manifest->'object_audit_reservations',
   (manifest->>'transaction_at')::timestamptz,at_time);
  -- Чистая финальная сборка не расширяет preclock maximum: обе TTL ветви
  -- заранее закрыли все logical/physical waits и возможные scope keys.
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final object effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',
   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',
   object_outbox_write_ordinals=materialized->'object_outbox_write_ordinals',
   object_step_obligations=materialized->'step_obligations';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  materialized:=kaname._authority_resource_crud_materialize_v3(manifest->'intent',
   manifest->'registration_certificate',manifest->'registration_sources',
   manifest->'registration_body',(manifest->>'transaction_at')::timestamptz,at_time);
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized#>'{program,commands}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final CRUD effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4','5') THEN
  IF manifest->'intent'->>'Action'='5' THEN
   -- A verified negative audit has no installation/native permission to grant.
   -- Its exact one-row body was derived and protected before the final clock.
   IF manifest#>'{registration_authority,refusal_only}' IS DISTINCT FROM 'true'::jsonb
   OR manifest#>'{registration_authority,accounts}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_authority,native_epochs}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_body,writes}' IS DISTINCT FROM '[]'::jsonb
   OR manifest#>>'{registration_certificate,action}' IS DISTINCT FROM '5'
   OR manifest#>>'{registration_body,program,commands,0,kind}' IS DISTINCT FROM 'refusal_audit'
   OR jsonb_array_length(manifest#>'{registration_body,program,commands}') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'refusal final audit-only invariant invalid' USING ERRCODE='42501';END IF;
  ELSE
   PERFORM kaname._authority_resource_registration_authority_final_v2(manifest->'registration_authority',at_time);
  END IF;
  materialized:=manifest->'registration_body';
  IF manifest->'intent'->>'Action'='2' THEN
   materialized:=kaname._authority_resource_unregistration_materialize_v2(
    materialized->'source_index',materialized->'verified',materialized->'catalog',materialized->'direct',
    materialized->'maximum',materialized->'current',materialized->'reservations',
    (manifest->>'transaction_at')::timestamptz,at_time);
   PERFORM kaname._authority_resource_unregistration_operation_acl_v2(
    manifest#>'{registration_body,acl}',(manifest->>'invoker_oid')::oid,materialized->'cleanup_program');
   materialized:=materialized||jsonb_build_object('acl',manifest#>'{registration_body,acl}');
  END IF;
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized->'program'->'commands') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'registration private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final registration effect exceeds preclock maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  IF manifest->'intent'->>'Action'<>'5' THEN
   PERFORM kaname._authority_resource_registration_sequence_final_v3(materialized,at_time);
  END IF;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSE
  RAISE EXCEPTION 'resource final intent compiler unavailable' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='final',decision_at=at_time;
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 UPDATE pg_temp.kaname_authority_consumer SET finalized=true;
 RETURN QUERY SELECT at_time,count_rows,1;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_unregistration_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;verified jsonb;certificate jsonb;direct jsonb;plan jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 current_state jsonb;reservations jsonb;body jsonb;compiled jsonb;required jsonb;operations jsonb;expected_accounts jsonb;expected_sources jsonb;
 audit_ids jsonb:='{}';audit_id text;key_value text;global_required boolean;source_required boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 audit_result record;reconcile_result record;subject_result record;relation_result record;lifecycle_result record;
 sequence_body jsonb;used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'cleanup compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864
 OR p_envelope#>>'{intent,Action}' IS DISTINCT FROM '2' THEN
  RAISE EXCEPTION 'cleanup compiler input invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 verified:=kaname._authority_resource_unregistration_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope->'catalogs',p_envelope);
 certificate:=verified->'certificate';
 direct:=kaname._authority_resource_unregistration_direct_program_v2(source_index,verified,transaction_timestamp());
 plan:=kaname._authority_resource_unregistration_operation_maximum_v2(verified,direct);
 source_required:=plan->'source_effects'='true'::jsonb;
 IF (proof->>'consumer_profile'='resource_source_pending') IS DISTINCT FROM source_required THEN
  RAISE EXCEPTION 'cleanup SOURCE classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('kind',effect.kind,'id',effect.id) ORDER BY effect.kind COLLATE "C",effect.id COLLATE "C"),'[]'::jsonb)
 INTO expected_sources FROM (
  SELECT 'binding'::text kind,k id FROM jsonb_object_keys(verified->'changed_bindings') k
  UNION ALL SELECT 'role',k FROM jsonb_object_keys(verified->'changed_roles') k) effect;
 IF coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb) IS DISTINCT FROM expected_sources THEN
  RAISE EXCEPTION 'cleanup SOURCE write census differs' USING ERRCODE='P1034';END IF;
 maximum:=kaname._authority_resource_unregistration_maximum_v2(source_index,verified,direct,catalog_result.catalog_rows,plan,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'cleanup complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(q.key ORDER BY q.key COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') q(key);
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'cleanup complete mutation accounts changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  maximum->'write_sources',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'cleanup current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 FOR audit_id IN SELECT jsonb_array_elements_text(verified->'withdrawal_audit_ids') LOOP
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END LOOP;
 audit_id:=NULL;
 IF plan->'audit_possible'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF coalesce(audit_id,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' OR audit_ids ? audit_id THEN
   RAISE EXCEPTION 'cleanup root audit reservation invalid' USING ERRCODE='42501';END IF;
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END IF;
 IF audit_ids<>'{}'::jsonb THEN
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_capture_wait_v2(audit_ids,p_rows-used_rows,p_reads-used_reads,true);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2((plan->>'reconcile_count')::integer,p_reads-used_reads);
 used_reads:=used_reads+reconcile_result.logical_reads;
 IF (verified->>'withdrawal_subject_count')::integer>0 THEN
  SELECT * INTO STRICT subject_result FROM kaname._authority_resource_subject_change_wait_v2((verified->>'withdrawal_subject_count')::integer,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO subject_result;END IF;
 used_reads:=used_reads+subject_result.logical_reads;
 operations:=(maximum->'operations')-ARRAY['resource_reconcile_outbox','subject_change_outbox'];
 SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_capture_v2(operations,p_reads-used_reads,true);
 used_reads:=used_reads+relation_result.logical_reads;
 SELECT * INTO STRICT lifecycle_result FROM kaname._authority_child_parent_cascade_prewait_v1(
  direct,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+lifecycle_result.logical_rows;
 used_reads:=used_reads+lifecycle_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'audit_ids',verified->'withdrawal_audit_ids',
  'subject_ids',subject_result.reserved_ids,'reconcile_ids',reconcile_result.reserved_ids);
 current_state:=kaname._authority_resource_unregistration_current_v2(source_index,maximum,direct);
 body:=jsonb_build_object('source_index',source_index,'verified',verified,'catalog',bundle_result.catalog,'direct',direct,
  'maximum',maximum,'current',current_state,'reservations',reservations,'acl',relation_result.acl_capabilities);
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'cleanup aggregate prewait exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',jsonb_build_object('required',required),
  'program',plan,'authority',authority_result.authority,'body',body,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,
  'held_relations',relation_result.lock_witness||reconcile_result.held_relations||subject_result.held_relations||lifecycle_result.held_relations,
  'held_advisory',(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness||reconcile_result.held_advisory||subject_result.held_advisory);
 -- Только server-verified frozen inputs; предварительные часы — placeholder
 -- для формы. Authority/fold decision остаётся у единственного finalizer.
 sequence_body:=kaname._authority_resource_unregistration_materialize_v2(source_index,verified,bundle_result.catalog,direct,
  maximum,current_state,reservations,transaction_timestamp(),transaction_timestamp());
 used_reads:=used_reads+kaname._authority_resource_registration_sequence_prepare_v3(sequence_body,2,p_reads-used_reads);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_crud_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record;owner_oid oid;trigger_counts jsonb;trigger_count bigint;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
  WHERE a.attrelid='kaname.users'::regclass AND a.attname='expected_login_kind'
   AND NOT a.attisdropped AND a.attgenerated='s' AND a.atttypid='pg_catalog.name'::regtype) THEN RETURN false;END IF;
 -- ACL typed-entry читается в том же statement и только при обращении к CTE;
 -- строгая подпись и правила экспортного EXECUTE остаются прежними.
 IF EXISTS(WITH typed_entry_exec_acl AS MATERIALIZED (
  SELECT g.grantee FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
  WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
   AND g.privilege_type='EXECUTE'
 ) SELECT 1 FROM (VALUES
 ('_authority_native_write_weights_v4(jsonb)','907111b7e806c46a660311a6a97fcc2ab2f86ea0430260fb501306f0e2ef522e',true,'s',true,'private'),
 ('_authority_native_write_closure_v4()','a6da6a23e1899bf23d71ba4c5969f66cdfe15a4038fb9a89223df803b74c0e14',true,'s',true,'private'),
 ('authority_native_write_arm_v4(uuid)','ec1e1600c2673f4d02947f7dca7b4a719abc794a91d0045bad38fc2c642e5638',true,'v',true,'export'),
 ('authority_native_write_read_v4()','f6a0242967e246de3f3d305655783afd29ed8bef4f4e8d95a8821c965aa33e9c',true,'v',true,'export'),
 ('authority_native_delete_batch_read_v4()','79e71a95aac2ded09885f8c65165ad8ac169ef3b7f09bbda82a11ce1baec80f9',true,'v',true,'export'),
 ('_authority_native_delete_batch_begin_v4()','d5f062e5543ded46945e843444184aed9f958ee776d63413095cc98c0ad5bd10',true,'v',true,'private'),
 ('_authority_native_delete_batch_end_v4()','3b8173b76b57f85ae4f73287e25b6e143a40c72a13d1423bf6ee218fa04d65fa',true,'v',true,'private'),
 ('_authority_native_delete_batch_graph_v4()','7b70a67aa67a72d2bf2a1136bf0477cda6239ef79b6ace61e4b2e6d8f3f841e6',true,'s',true,'private'),
 ('authority_native_delete_emit_v4(jsonb[])','3e36607d0fad78d6e89bf4b1d8212b939225c87f95bdfd0643020d5bb2933c1b',false,'v',true,'export'),
 ('authority_native_delete_prepare_v4(jsonb[])','b25ff1292dbced07ecffa2be2f736411cc61a3bf75dbcacd879ceeb01bc719cf',true,'v',true,'export'),
 ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','bed995919371e883bb0d88698a79f8d634c453068c4caab199d7a76cf026088c',true,'v',true,'export'),
 ('authority_forward_emit_v4(jsonb[])','d41825e5a57dbdc4f78b630f19877f54e94303e6fefc2b79b10e483fc6dd65e3',false,'v',true,'export'),
 ('authority_forward_prepare_v4(jsonb[])','8bfb60e9ff8c301d79c11215fdaac99c8788a78c920cae86182115bdc8e90d74',true,'v',true,'export'),
 ('authority_forward_claim_v4(uuid)','8a7c8ee8eae47a467c0d3370ef6185e93f3db6138aa14319563990fabd3b7be7',true,'v',true,'export'),
 ('authority_forward_finish_v4(uuid)','75683ffd52d23834a7e28814676b67a06d47cfa5a4fd2c2049d5f299f4c00199',true,'v',true,'export'),
 ('_authority_forward_context_v4()','67a9f0c6d896048f52b3eeb396250c7e33e16ab3170b874734154197d247dd5c',true,'v',true,'private'),
 ('_authority_forward_custody_v4()','c5d84795becb1a5b12efc89bb553ac12db864c5ce31c90272041b15a09cd59b4',true,'v',true,'private'),
 ('_authority_forward_shape_v4()','ef281d009e6201f0c03e49cfc049b4950290fe1953bb05b3638536b45b0d66aa',true,'v',true,'private'),
 ('_authority_forward_program_v4(uuid)','d1100eb62bfc267ed7cc58d4d0cd0194f42b6285f8f465939381b60161607cca',true,'v',true,'private'),
 ('_authority_forward_row_v4(bigint,jsonb,boolean)','31eb7a5ae8eec2af1f31d7aa9e55d49c80e787838ec3a34130de6db4b3dcc56f',true,'v',true,'private'),
 ('_authority_forward_complete_v4(uuid)','06cfcd8f144243fc529aacba57f452b0913cc6d5b1ab6bf2daf7c4e6a9a38290',true,'v',true,'private'),
 ('_authority_forward_anchor_complete_v4()','0d9fdf6c02abe69e333b5584eee4628cafb7ec37849b7820e33aba4bea4396f1',true,'v',true,'private'),
 ('_authority_forward_storage_v4()','e8a9cd61f6ee6cc4fbde7361210cf493c8df166cdf3bfd8c49ed47190aa4ef0c',true,'s',true,'private'),
 ('_authority_group_add_program_v3()','e78556f1ccd014face052206b727651ce7e238bc9c3706f5a8d65f1f6559cce4',true,'v',true,'private'),
 ('authority_group_add_prepare_v3(jsonb,integer,integer)','ffe5527b2aed54dd69fa79b366c3717044cafdc98bed16f4c8ed9d39702d606e',true,'v',true,'export'),
 ('authority_group_add_finalize_v3(jsonb,integer,integer)','21d1ddc68b3e1cbf4bdbaabb6038c5bff865e7439420bd96c5e41590c91370dc',true,'v',true,'export'),
 ('_authority_group_add_row_v3(text,text,jsonb,jsonb)','a5973b00860baf37167efaf588cd3f3fe492248214708e3db6fa94ad7367590a',true,'v',true,'private'),
 ('_authority_group_add_statement_v3(text,text)','b2bad5333c59b9db498767c0a6546c089633f849799ab87efa991183ee799b11',true,'v',true,'private'),
 ('authority_group_add_fold_v3(text,jsonb,timestamptz)','cb582cd47c5e210fa7f4c4a4c0a211ba1b120b455ce9a868a453d05335a2d1ef',true,'v',true,'export'),
 ('authority_group_add_subject_id_v3()','bde80ceb4ed141b31a755dadb40e653acf46e9c89171b1bc93b2ac5f7916300e',true,'v',true,'export'),
 ('_authority_group_add_subject_v3(text,text,jsonb)','93f1e1147874032a6e7f4e1c08ad7651148e6ec5f25da7ffc2486d234ae14a8c',true,'v',true,'private'),
 ('_authority_group_add_complete_v3()','158eca8cc62068a844f08ce5f746ad909a504fb429567d11c30d6f496dcd17eb',true,'v',true,'private'),
 ('_authority_group_add_storage_v3()','123966ac8ae04e91375122a48bc6c07c8c48bda2791a763d779f00e506ff81fc',true,'s',true,'private'),
 ('relation_fact_fold_row(text,jsonb,timestamptz)','d22d72ceba1dabe7edc7ff3c197c42ed92beacd87aed68add50aa99150a1d067',false,'v',false,'preserve'),
 ('authority_subject_change_id_guard_v2()','aa4bc39730f137bdf11491afaf41d9c8451c88e2cda40358fc0e33be2f29cb53',true,'v',true,'private'),
 ('authority_subject_change_applied_v2()','fa776df6d3b95dadb13fa1684424b2db105b21f5b8862bd045680fb8129d094e',true,'v',true,'private'),
 ('authority_subject_change_statement_guard_v2()','600129602604e3cac17840ff155738e5c886677cd8be781b62b9b29f2fe785b0',true,'v',true,'private'),
 ('relation_fact_from_journal()','604d827358eab2f756c0c53d9a65cfbaf31b3f5d19ff8adc6e3dab944e8fa70a',false,'v',false,'preserve'),
 ('authority_protocol_grant_runtime(regrole)','d754231dce790f01596d86b4e2d3e0d4c5fd0672ab5bbd0bf9443687bc960df6',false,'v',true,'preserve'),
 ('authority_binding_command_begin_v3(jsonb)','39696919bfed78731817c77a37920e661801933c5ac544bc26ea5603a7fa39b1',true,'v',true,'export'),
 ('authority_binding_command_end_v3(jsonb)','2c9ee43be689f773c543fc800645f2aae482ec02d392fd28937efa50558915b2',true,'v',true,'export'),
 ('authority_binding_command_audit_v3(jsonb)','93c1bfc6bd6b753868e68ff6e408089f701d189ed6e7c30a32c7998baade872f',true,'v',true,'export'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','62483d22c74491cc60dcbc011c5517f743b3a764dc91a48fa8628ce31bfadcd4',true,'v',true,'private'),
 ('authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d',true,'v',true,'preserve'),
 ('authority_audit_id_guard_v2()','a349a4a051b336afdec4cb5422edf5738fe4e354acec98163abc0d4a2c70d8f2',true,'v',true,'preserve'),
 ('authority_audit_applied_v2()','b43a45a017d3b646301d3b0eb746d46ae7ee7d3a0539b2c8b91600c5a4c697a3',true,'v',true,'preserve'),
 ('authority_audit_statement_guard_v2()','cc9fd152b1c8fa68a65eb6451baf977a12b0866cc52668254280265f10f9271c',true,'v',true,'preserve'),
 ('membership_mirror_from_user()','d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405',false,'v',false,'preserve'),
 ('_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','10cfd5fcbe108b1f0b62f688d7ae80b72e34a536593fae3343c730cc0cb82da5',true,'v',true,'private'),
 ('_authority_resource_effect_applied_v2()','759a821396ab5850fd5aac25756c0403129d685aec1aa7e7f63bf95c8126f136',true,'v',true,'private'),
 ('_authority_resource_write_v2(jsonb,text,text,jsonb,jsonb)','cdb26211660f6fc89ee193516c9bc7cfa3e3bdcd427d3cf71c17c4a047272c2f',true,'v',true,'private'),
 ('_authority_resource_side_v2(jsonb,text,text,text,jsonb)','09f8a713bf8e2a59ec0051910a49f5df93dec5bc5c776271c2f1a54dbb1eb8f1',true,'v',true,'private'),
 ('_authority_crud_anchor_capture_v3(jsonb,integer,integer)','2dee8b172ebd3b228b5c6cc4dec189feae30db2c1c9a4bc98752525025d823c7',true,'s',true,'private'),
 ('_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','3ce64fcc9997385efdac3a546dc44ab66e0b5022ec5d9cb5de8d5bfdcffaec9d',true,'s',true,'private'),
 ('_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','cbe93565f4de42904c6a0e2434db9a21ce0d528902d2a3908a2fec92cb821318',true,'s',true,'private'),
 ('_authority_crud_aux_write_v3()','5b549be379610152a2c2efc86836606fb82c298d885be0125cee3b535cf8cd32',true,'v',true,'private'),
 ('_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','f7cf945fa67c0bf19182121b6e31655f1939257dabac972618a15cd6fa9eda8b',true,'i',true,'private'),
 ('_authority_crud_aux_statement_v3()','8d2c6a5f46066b400d9c42c158a337eb784a405c895145beedc7205133be7bc6',true,'v',true,'private'),
 ('authority_resource_crud_capture_v3(jsonb,integer,integer)','4ed7f709885d233f48bfd4ff0ced2cabf6b0ec6db07906156530bb6120391f32',true,'s',true,'export'),
 ('_authority_crud_merge_tables_v3(jsonb,jsonb)','beb1fb11dc689c0b6e22411c4edd3ac6025b76fa6bdb74f49bad95b27fa9c1ae',true,'i',true,'private'),
 ('_authority_crud_capture_v3(jsonb,integer,integer)','794f687a5c86e36d6ff91984e7942497dc6765fa3c9c685b514ac8a406cf8182',true,'s',true,'private'),
 ('_authority_crud_cascade_capture_v3(jsonb,integer,integer)','a155c5bf5c0d2e81b9b2b2d3d85f5cb234a3cc162585041237c4e9f6257fd73c',true,'s',true,'private'),
 ('authority_resource_crud_body_values_v3()','d7440d3bbf47f4dbc2b8e254cdfc248b1d79d6dd839de9fb2243e8fc4d76158b',true,'v',true,'export'),
 ('_authority_crud_step_complete_v3(jsonb,integer)','6a1951e0f4eb8b4dcd3a417f68938ac5e4771f04b1cf085938994dc45130e146',true,'v',true,'private'),
 ('authority_resource_crud_step_v3(text,jsonb)','51b2b069757a6860df25f6dcc47558881ce21accf0a5b2ce0f813cd55d37aa50',true,'v',true,'export'),
 ('authority_resource_crud_lock_held_v3(text)','2101acd7137f106b763dbdccf69f7f257ccd8650bc89e7f1d191132fffb51f6f',true,'v',true,'export'),
 ('_authority_crud_require_completion_v3(jsonb)','9a9d56a95bbb255d52eeddf6c07a6f5e5663490ded6d8a558d097848a885d75c',true,'v',true,'private'),
 ('_authority_crud_command_v3(text,jsonb)','c5002541ff2bbabedbcd9d74b6adc04b13a6a36833eefd1631f875d47652eb75',true,'i',true,'private'),
 ('_authority_crud_structural_v3(text,text,text,text)','00d37afb9a7b7c9d4534df79f313c14e13fc16a1756d368d85ca2e5f4d939c13',true,'i',true,'private'),
 ('_authority_crud_command_plan_v3(jsonb,jsonb)','ea252acb7bcebc7c96da591416609deb3b606d01eeda6a3a32e911a0e77af3d1',true,'i',true,'private'),
 ('authority_resource_registration_command_values_v2(jsonb)','ba55237e2826a2f425437d0993210204ab578a04decf5f7bbdf91fbf3c45aa3b',true,'v',true,'preserve'),
 ('authority_resource_assert_body_v2(jsonb)','6aeb29fc8290e51a32a03b5902b485305bd2736b80f9a328fac55cea738ac3a1',true,'v',true,'preserve'),
 ('_authority_resource_require_completion_v2()','e1c6b94cd3542ce6e1055c70a7ef067675ebbd3826084e24c04d21b3df29f203',true,'v',true,'preserve'),
 ('authority_resource_fold_body_v2(text,jsonb,timestamptz)','6be8def5de6ed9a89e95f50764835b8da6baa06ca26a053b84bb4d6279b38282',true,'v',true,'preserve'),
 ('authority_resource_prewait_v2(jsonb,integer,integer)','6db93afbea0e41ec3015366f85a71fd440bbeeac259424e982556df55ed41522',true,'v',true,'preserve'),
 ('_authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean)','967a84fb10617c3a5f376d63aaf2903538edc5fe1548150b307bae33a70ee3f9',true,'i',true,'private'),
 ('_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)','2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e',true,'i',true,'private'),
 ('_authority_crud_intent_v3(jsonb)','e62f470c0c69a980308bec36a35f515609cb8fea56c79ec7632ac654a43e0f49',true,'i',true,'private'),
 ('_authority_crud_manifest_domain_v3(jsonb)','72c12f24e9c426b44fcc41b7690423a30675175589cd2ea6554beb48ad555387',true,'v',true,'private'),
 ('_authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz)','d84adbcbed2a7a07b7080ddd83eaab375144edbdbb4b4ad9c50ffce92012fc5c',true,'i',true,'private'),
 ('authority_crud_fga_id_guard_v3()','cc6115bf7fafa0e7a70da14aa14db4232644f3a10d1ba34b1df131d93c616a49',true,'v',true,'private'),
 ('authority_crud_fga_id_applied_v3()','12aadb134df61a6f55b28252be5d22773e70f7b75f0a2117577faa2565a99594',true,'v',true,'private'),
 ('_authority_crud_fold_capture_v3(jsonb,integer,integer)','4324197370450be1edcfc6de9b822fd24e838932135c2c3861c438fa62fe5149',true,'s',true,'private'),
 ('_authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','c64f0e0be50cf2b6954b4912201dd238acf768d31eb26578b4155c1f0f697b03',true,'i',true,'private'),
 ('_authority_crud_graph_index_v3(jsonb,jsonb,jsonb)','6402a8ddbf72280f803ced92f33536a500e49252d15159223bd8bafa98c694dd',true,'i',true,'private'),
 ('_authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer)','0e1271f048a93d4632fc6e30346b1a10682e619b4077405048a495840c199fda',true,'s',true,'private'),
 ('authority_resource_crud_journal_value_v3(jsonb,jsonb)','801f9974286e1bd23fb9559e5abf3da66c3fa9ebfd18f27fb18984b0762c6e0d',true,'v',true,'export'),
 ('authority_crud_journal_applied_v3()','d8238730f4bb3d9754ddc7108ad4dc70b348494f51b2dea1567b06cd69e9c7e2',true,'v',true,'private'),
 ('_authority_crud_journal_plan_v3(jsonb,jsonb,jsonb)','e8af1dadee7c4d3e8bf7790a0464ac9c8319bbaac789bb15aec5ef4ceeb56ea6',true,'i',true,'private'),
 ('_authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz)','e37fb29c6f7ff41ab6c0d15c3dfc0da196e7177c36dc848e0dc304b445d14a80',true,'i',true,'private'),
 ('_authority_crud_unique_key_v3(text,jsonb)','b7407a60f467821e6fe19c697ea37079807dbd5bed88c51a4ad645de731cf5b3',true,'i',true,'private'),
 ('authority_crud_unique_guard_v3()','5e8dbb8ba000bde51e8aa64c8e2fb708666f4822bb677a059adc623b0b45eb7d',true,'v',true,'private'),
 ('_authority_crud_sequence_wait_v3(text,integer,integer)','3b40419c3cbb8e156a2926933f7d7075a93129fa34c2294122dcd04f9cf76edf',true,'v',true,'private'),
 ('authority_crud_sequence_guard_v3()','4132523d01f6ddd5e893fa0c21ad9c2c944009dc8e968dc7228e5de3e8bf9ce0',true,'v',true,'private'),
 ('_authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz)','e3ad0cc2300061a6630225ec8956cee4b552f4ff8d9c1804f0dbfb5af0b12692',true,'i',true,'private'),
 ('_authority_crud_lock_rows_v3(jsonb)','e04ceccbff7121da453fc79b071db7d7c3f54b8425cda74f53520143641a22d9',true,'i',true,'private'),
 ('_authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz)','85bef48d34921afb7fd0659fe6554288f47db763cd0c872dcaa92cb713065d85',true,'i',true,'private'),
 ('_authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb)','f1fc57972e2b2575a0a323090cc8560ad975b5d4a7f061a8b28faa2ab6ba6784',true,'i',true,'private'),
 ('_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff',true,'i',true,'private'),
 ('_authority_crud_maximum_v3(jsonb,jsonb)','62f166faf92695eccfc65f5e979ac33b7610a9fb0b640274a361300039541ce0',true,'i',true,'private'),
 ('_authority_crud_pack_v3(jsonb,jsonb,jsonb)','ab5603fc90f193b60e06d29823842f43967d1515ba1d3eaca6fbde97099d6c6c',true,'i',true,'private'),
 ('_authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','81c8fd09ea95dd337e3d56928513de55a24eeb981695185c58c1db06f6c06f24',true,'i',true,'private'),
 ('_authority_resource_crud_prepare_v3(jsonb,integer,integer)','ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4',true,'v',true,'private'),
 ('_authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer)','424927c26adc58d65a55a4567766054c378f1340662d0401146e5e2dac2f0bad',true,'v',true,'private'),
 ('_authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer)','a9e7a60de752dcf436571f457c67de751439e77276005238dab9abed9ef9049b',true,'v',true,'private'),
 ('_authority_crud_scope_capture_v3(jsonb,integer,integer)','7cd250c6e17d5c41737c1afebca7576744bae05ec46af01136678c515e23f5e5',true,'s',true,'private'),
 ('authority_protocol_statement_guard()','7608e2d0a1b1ce2bb11182a349150e5369e2bd97c5fb8abc3da84b3d2e0c229a',true,'v',true,'preserve'),
 ('_authority_resource_crud_store_v3(jsonb)','b3c4cf46195b7a32a2454911b29c8ea51a0e37741ca98380890e911f4e765135',true,'v',true,'private'),
 ('_authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer)','8ebecbc122a5558910017569ac3ea927ad37ea4066dec179a253807b4c5d9574',true,'v',true,'private'),
 ('_authority_crud_unique_wait_v3(text,jsonb,integer,integer)','ded94e6b1bf461dfaf9753a2e71dc73f45f474826b1d7a2f950e097c455629b0',true,'v',true,'private'),
 ('_authority_crud_json_keys_v3(jsonb)','42d2e6afa061f7c443be4e75a6fe3742414583923d2929ba77250c45ccb239d3',true,'i',true,'private'),
 ('_authority_crud_write_metadata_v3(jsonb,jsonb,jsonb)','7bdfa746b1066e54eccfffa3067fa923b09a1364d883c444b19dc5c873181af4',true,'i',true,'private'),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true,'v',true,'preserve'),
 ('authority_grant_mutation_preflight(text)','8ef00bb883b777d2abf07b0f43589dbd5fad7ac01c9bae8b3f22821e549060e8',true,'v',true,'preserve'),
 ('_authority_binding_scope_tier_v3(text,jsonb,jsonb)','81cacba8227f605eaf666624c9ceae52808ddc086b87d258bb33a95611a412bb',true,'i',true,'private'),
 ('_authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer)','9a34cb8196ba7de482bd9270115e1770a6210c9745b235703cb50cb6d0cbea34',true,'s',true,'private'),
 ('authority_binding_sequence_prepare_v3(text,jsonb)','bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc',true,'v',true,'export'),
 ('authority_binding_sequence_finalize_v3()','51e4b66f099b3b7c0a5f144af2ae540b5dbe72d00c52a170cfc7ec2e43f87fdb',true,'v',true,'export'),
 ('authority_binding_insert_stamp_v3(text)','0e37cf1836a1625f1c518c7c847cafe3da04ef9ef692db8c1c23fb27b40d1c71',true,'v',true,'export'),
 ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6',true,'v',true,'export'),
 ('_authority_binding_stage_snapshot_v3()','9e9d561435b0f86c51aec452283505184beee36e1dc02f4af708590955d2eebf',true,'v',true,'private'),
 ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6',true,'v',true,'export'),
 ('authority_binding_stage_sequence_finalize_v3(text)','cd285782054ce7720b1072484e7b24758bcae7f8b7c7a117556b9836c1299a18',true,'v',true,'export'),
 ('authority_installation_enter_v2(text)','9c008ba02cb19f92581324e2b9652fef0fd3555118f1fd5536e74c1a85c5eee8',true,'v',true,'preserve'),
 ('authority_reconcile_enter_v3()','905123661ed76a9f3da2f0374779e049cf2e89374fd4cf3c085c88555e32e013',true,'v',true,'export'),
 ('_authority_audit_binding_store_v3()','77412a99e3ea64432ee6ffe551d84ae7eae02bc2e0be1cbbe8e15941b407f595',true,'v',true,'private'),
 ('_authority_binding_mirror_store_v3()','94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61',true,'v',true,'private'),
 ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','e6dd22497757ec3e7362e45c6d5f4a45cd5ecf5b43714b6849143e5da1bf134a',true,'v',true,'private'),
 ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','8e4c9745f4df62265cb114849d1306493616a93049905a25f17c874dc0e35b9e',true,'v',true,'private'),
 ('_authority_binding_mirror_finalize_v3(text)','fe26d33c679cf15f72b04c243abff2c284fd2e5e35df1da58236cee3f826517e',true,'v',true,'private'),
 ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854',true,'v',true,'private'),
 ('authority_binding_epoch_lock(text[],jsonb)','621ce6546bd8a8fb0c64d73ba47b7094e8a8ddebcf0b76613d2896ebddb25d56',true,'v',true,'preserve'),
 ('_authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','41c8b30fb6b70b3dee28f7a54fa1e692784b63df7ade0c0d1f0dfa955883fe9a',true,'i',true,'private'),
 ('_authority_binding_stage_source_v3(jsonb,oid,integer)','e3bd8688c1e38e2124e21c9f15bcbab1c2aad809352aa0002835d3e888d5088d',true,'v',true,'private'),
 ('_authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer)','3b17c2eb7e40b1d5a6eb09af09fd0c1e9c5c4d8b4678e7537d94abad2e668c22',true,'v',true,'private'),
 ('authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','c78567e12d9c2ac4dabed52f4ff57d538266787beadeba6c855bffe44281619f',true,'v',true,'export'),
 ('authority_binding_withdrawal_sequence_finalize_v3()','7ed02bf2fbfd3107060c4ca7815b99593d90400903676c8ccb32657d68511ea6',true,'v',true,'export'),
 ('authority_cluster_admin_preflight_v4(text,text,text)','dee9de21827355b15b060104dc7232b3f1e784eed23b074c24295ea6e2e40a0d',true,'v',true,'export'),
 ('authority_cluster_admin_preflight(text,text)','2bda979c851a1a59d5ba97dc79c2eff3a14c404f1e50ca7975638f4fafae9700',true,'v',true,'preserve'),
 ('_authority_metadata_preflight_body_v4(text,text,boolean,text)','d547aed450a42acf12a3e1a7f565a97dad4fec25a3ee30049e70275e4d261209',true,'v',true,'private'),
 ('_authority_sequence_freeze_v3(jsonb)','dbb50139a60af61a07690037c20b62c7d0b3dbf6a4cdff1e05307efca6836ef4',true,'v',true,'private'),
 ('_authority_sequence_bind_v3(jsonb,timestamptz)','4e8241c16905238f8f5064a12537cf5ee0892e596d89f2aa8d8a92f6dd31359c',true,'v',true,'private'),
 ('_authority_sequence_default_v3(text)','55bbb442c7aefc7e080eb6dc33b7255444438eb653d9d1f493986315aa8c3196',true,'v',true,'private'),
 ('authority_resource_journal_id_v3()','1890af3f773bb503aa2d4324c56ed4925c1ffac60d36181cc0d7c579f1e8ae18',true,'v',true,'export'),
 ('authority_fga_outbox_id_v3()','75b2ab0cad8f6111bca3dc5bd119f87dbbffa0dbed74480f172aa0f465b672bb',true,'v',true,'export'),
 ('authority_sequence_program_applied_v3()','6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc',true,'v',true,'private'),
 ('authority_sequence_program_completion_v3()','055164a539031177a7605113484f5667702c9074b84d03ab1a827cd614b66e35',true,'v',true,'private'),
 ('_authority_sequence_expect_v3(text)','52e5bda884d0c1cec7bff0ae4843cd1490747432d1a44ee11a5648d6e905bcc2',true,'v',true,'private'),
 ('_authority_sequence_expected_v3()','e318cafb455438dd9a40e3c2cec7cc2d88daedf4307dd1e43248175005ab045b',true,'v',true,'private'),
 ('authority_sequence_expectation_complete_v3()','aef5c1e0bfa60d5587aa8c0f342b3f5df1166a1a699af56019f5bdf36e856c99',true,'v',true,'private'),
 ('resource_journal_emit()','76c8f397a387cb6699642e1d3aa56c2c61f371245eb28f56b14ed19c1d1faeba',false,'v',false,'preserve'),
 ('resource_journal_emit_member()','4dfca2c401a428e6b4ad984b99aae3a34404999ea36ed26b14c70b2ceb1d4053',false,'v',false,'preserve'),
 ('authority_sequence_origin_v3()','d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3',true,'v',true,'private'),
 ('authority_prepared_journal_value_v3(jsonb,jsonb)','b1e7156bf7176c0d30be0f64476e3b81748ff4a15dd27db29db17bca70598f46',true,'v',true,'export'),
 ('_authority_sequence_excluded_v3(oid)','eb4872a7f8c5bb7c40564e17fcc1928eac64bdbd8ac2e5609d261bd9ad36594b',true,'s',true,'private'),
 ('_authority_sequence_shape_v3()','614125faa823e6f14b0d2f58f2a6ed7ea9a5239febef2dd83b7ba4508f0f9014',true,'v',true,'private'),
 ('_authority_protocol_snapshot_v3()','f994c63975e86be78b2854a4f51aed55e615ad2c380b0f58fc1e0390662fc30a',true,'v',true,'private'),
 ('_authority_sequence_probe_v3()','2e2a3266993eadee820fba438960cde53cf25cd05a4e806661e8d62664f075c3',true,'v',true,'private'),
 ('_authority_sequence_header_v3()','375b51310e57a7016673ba26f5b9925d59e67a2599ba74fe9c11d3f5bf9c70f5',true,'v',true,'private'),
 ('_authority_sequence_publish_v3(jsonb)','013f8260baa0607516e57b791a92897d3d4bb143a401dd056166d1fbf70d3128',true,'v',true,'private'),
 ('_authority_sequence_store_v3()','adca627a6c7ce9b1ee755a231793134d5ebcc372f370c694cbac3f067fb471d2',true,'v',true,'private'),
 ('_authority_sequence_reserve_v3(text,jsonb,integer)','76e3ea26f6401f26ad25e168b0dc4399065648b354e7c8b96750a6d802128190',true,'v',true,'private'),
 ('_authority_sequence_select_v3(integer[],timestamptz)','7f9ce472e9d23f7a6182685661f2964bdc0266fefe1a59b9228d9908b171bb09',true,'v',true,'private'),
 ('_authority_sequence_claim_v3(text,jsonb,jsonb)','18cdb51c9e44fa944b355cadf1abcb291eba062ca09f3221118bcd60d736c740',true,'v',true,'private'),
 ('_authority_sequence_applied_v3(text,bigint,jsonb)','0a4c24ded6b6aad09fd077e4a1ad8d40dee440c4e27e44dc20e4300bfc0a5a7d',true,'v',true,'private'),
 ('_authority_sequence_complete_v3()','c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1',true,'v',true,'private'),
 ('authority_resource_finalize_v2(jsonb,integer,integer)','20a9e6ee2af213a514ca21399d62cdb981a399ad7e96cbae330c152d0ecf837d',true,'v',true,'preserve'),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),
 ('_authority_resource_object_program_v2(jsonb,timestamptz)','97f643954fbef4036c37240711c9ce9650045102c77bce1d5e8396d89a4c8464',true,'i',true,'preserve'),
 ('_authority_resource_object_sequence_prepare_v3(jsonb,integer)','bbf639e8b58fee3ee80ce322a7946cd5ae4a3f0a84804270117a369914fc5153',true,'v',true,'private'),
 ('_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','48e8a4f9e9c57161fec84ede30f6a148a15a4cc5162d78dcfff4e048be037564',true,'v',true,'private'),
 ('_authority_resource_physical_relations_capture_v2(jsonb,integer,boolean)','e01481c788b47322941e6c6753d9d38e44e1bdcee973a8fb6292aed42d9ce54f',true,'v',true,'preserve'),
 ('_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','0d6ab18cc9cac1395df175c0c91912737bf8e78464d46da0c385e31aa36c9b66',true,'v',true,'private'),
 ('_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','ca262446dbab831c80c933c45b0095f12ceaa10367477a696266217b44736911',true,'v',true,'private'),
 ('_authority_resource_registration_direct_prepare_v2(jsonb,integer,integer)','ad9230edf198624a3d9caa84ee5a5a9954b79cd9afa58b1e0b64b60eb3dd2807',true,'v',true,'preserve'),
 ('_authority_child_parent_cascade_prewait_v1(jsonb,integer,integer)','801ee44ba52ceb636e3ca820b560b33c4558f7a8e504c1b9047ede50183035d7',false,'v',true,'private'),
 ('_authority_resource_unregistration_prepare_v2(jsonb,integer,integer)','ed2c4fcf57221f8687c3d086a286bb738add6cfa84cebfda2fc0a20a95a37ace',true,'v',true,'preserve'),
 ('authority_role_stage_epoch_lock(text[],jsonb)','2f4e6d4569577abe84313594f72e973d8b5fb63ac2adbd5605640751c7bc5021',true,'v',true,'preserve'),
 ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64',true,'v',true,'export'),
 ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',true,'v',true,'export'),
 ('authority_role_sequence_stamp_v3(jsonb)','1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8',true,'v',true,'export'),
 ('_authority_sa_state_preflight_body_v4(text,boolean,text)','866552ed304b028241b3cf523869fa39104810a924ccb14661684689b76a95f5',true,'v',true,'private'),
 ('_authority_scalar_journal_v3(text,text,jsonb,jsonb)','b6c669cf2485b11b8a84bf8935d30b1707805f7c043c8abfba1c77476eedf4ab',true,'s',true,'private'),
 ('authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','28de0a19487c8105f8ae7495cd1c195a84349fc2e5604493692bbcfaa34136bd',true,'v',true,'export'),
 ('authority_sa_state_preflight_v4(text,boolean,text)','6fbed0052196e4ad096c6047b1e018633760ea80f9edd7c722fb00b7b60900dd',true,'v',true,'export'),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true,'v',true,'preserve'),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true,'v',true,'preserve'),
 ('authority_scalar_sequence_finalize_v3()','c403ea97073dc0833cacdbfbd79691ccd1b11a6b0ca4c71fb2a73112e7d58be8',true,'v',true,'export'),
 ('authority_crud_storage_v3()','f2e0fb99aa034aaae63126e7f6b621fb8da6deb7b8ec21e0852f73bcf2e1e0fe',true,'s',true,'export'),
 ('_authority_resource_ancestor_graph_v2(jsonb,jsonb,jsonb)','0169e22d120961d1959b1eb87b684ab0ecf20c1cdb7c6e4f35289ebe5ce606b7',true,'i',true,'preserve'),
 ('_authority_resource_audit_capture_wait_v2(jsonb,integer,integer,boolean)','48833909f08147b697650810555b86266f9f7b6b0c41951fee89ba22ec25fd97',true,'v',true,'preserve'),
 ('_authority_resource_audit_plan_v2(jsonb,jsonb,jsonb)','f11cd1f48fdf0634bc288b523beb1758e66fbfab54fe020abb580cd0eaa99514',true,'i',true,'preserve'),
 ('_authority_resource_audit_wait_v2(jsonb,integer,integer)','29066819dd86fb4512a79fc4b8d30f88e95df89a74099e91471b39548efeb3e3',true,'v',true,'preserve'),
 ('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0',true,'i',true,'preserve'),
 ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),
 ('_authority_resource_bundle_catalog_v2(integer,integer)','eab6ae0b0d35773cd85b32a52758804f843eb49b289c6296d44df34e92fa3842',true,'v',true,'preserve'),
 ('_authority_resource_capture_index_v2(jsonb,integer)','988ed25715d6c9322bff7d8a6dc4d60b9d849a512d30ff9b70f8a1afbaa464f4',true,'i',true,'preserve'),
 ('_authority_resource_carrier_graph_v2(jsonb,text[],text[],text[],text[])','25cfe0b7f33582cfbee3399700901690952f97cff1e63d989ddde23176f42c80',true,'i',true,'preserve'),
 ('_authority_resource_carrier_scopes_v2(jsonb,jsonb)','0440ef56bc4069d6e1029e94dbab6acea6bddf7b5de88fc109f09f743599b60c',true,'i',true,'preserve'),
 ('_authority_resource_catalog_capture_wait_v2(jsonb,integer,integer,boolean)','c2dce8593b8f7616af573591ed0d439f822054f78f96de78ff8fc20d59efde18',true,'v',true,'preserve'),
 ('_authority_resource_catalog_wait_v2(jsonb,integer,integer)','6231367fd8a56cec22aed190ae2eef6dd8b3f93b2db1a0d8810ca6d9d5d53e97',true,'v',true,'preserve'),
 ('_authority_resource_contained_v2(text,text,jsonb,text)','e8cd715375fb48ff94738b78d82f00087fa548634ca3ebc43edd45dd54c8a758',true,'i',true,'preserve'),
 ('_authority_resource_coordinate_certificate_v2(jsonb,jsonb,text,jsonb,jsonb)','c24b6686e9bd21247289b6efcbd2277902da2cb951134cc770bdbeab4af12fe5',true,'i',true,'preserve'),
 ('_authority_resource_encode_proposed_rules_v2(jsonb,boolean)','e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc',true,'i',true,'preserve'),
 ('_authority_resource_epoch_wait_v2(jsonb,jsonb,jsonb,integer,integer)','52e0cc8f44374d68a98450683564534073a08be0727c31e8846757f906910129',true,'v',true,'preserve'),
 ('_authority_resource_grant_reference_v2(jsonb,text)','df8c0b484673605fdf285a40ab35045b49f622ed66da6d56962846d1228009b4',true,'i',true,'preserve'),
 ('_authority_resource_grant_rule_fp_v2(jsonb)','eaa4bee66714be005240c085088d71cc3fbdb1cb95575c892cfcadd7aedd9671',true,'i',true,'preserve'),
 ('_authority_resource_installation_eligible_v2(text,text,text,text,text,jsonb,timestamptz)','697e605e233cfc83f3f6a75f230e5ee309a0e365d854bb3eae46f73d6d41cbbf',true,'i',true,'preserve'),
 ('_authority_resource_installation_wait_v2(text,text,jsonb,integer,integer)','cdc2aade908f9ed07ef42c20be0ad8f7b92f77bd51bd5f4c6a7080b0671e57db',true,'v',true,'preserve'),
 ('_authority_resource_key_array_v2(jsonb,boolean)','ec975c9c1dd185c9582596cbc96c7916c26f93b20d91c7c9eefb5ef22755d7a1',true,'i',true,'preserve'),
 ('_authority_resource_ledger_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer)','d0ac1b9d8ab0c3c1821baaef668de1bb12c6edb0beddb3f4942874d433f4f2ff',true,'i',true,'preserve'),
 ('_authority_resource_manifest_create_v2()','b9ee82cbaa043c831c36e612387f616941b7cf028e13fb6b215da6679e486ccd',true,'v',true,'preserve'),
 ('_authority_resource_manifest_v2()','a80529dcdf4cb68395a9311f2f7b737fb467f0768c5b8a7e4488679bd5f3c63f',true,'v',true,'preserve'),
 ('_authority_resource_match_wait_v2(jsonb,integer,integer)','6ff5dc168529251407ee765ab0f1a53e4089a124e101128f481ea5382ba3e626',true,'v',true,'preserve'),
 ('_authority_resource_materializable_types_v2()','de8eb0540e5ee90a586412bc1503c3c16c24ba9f99359cae97ed7489c8151136',true,'i',true,'preserve'),
 ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),
 ('_authority_resource_member_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean)','4cda1e3112578a85f8b85c11a17a6d68126eb4eebea678c542fe5eee2e7a2d58',true,'i',true,'preserve'),
 ('_authority_resource_module_identity_v2(text,text,text)','b8c934a9370e413464b0577108ed9e69b42898308851b003ad2f646bd0e94fc8',true,'i',true,'preserve'),
 ('_authority_resource_nested_rows_v2(jsonb,jsonb,integer,integer)','3af0e8ae4591ff8be128e912062f921974d9d7ec9202c8ce1f4a6de651fed360',true,'v',true,'preserve'),
 ('_authority_resource_object_candidates_v2(jsonb,jsonb,text,text,integer)','dd5be24069ae63a2c946ed9a64344a5191f1f85994ce561139853d483d92fab4',true,'i',true,'preserve'),
 ('_authority_resource_object_certificate_v2(jsonb,jsonb,jsonb,jsonb)','9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3',true,'i',true,'preserve'),
 ('_authority_resource_object_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a3b9e3f7fd865d129ee4a9140a5795627e7697e9aa8cd4003ba5cc6a92f5b06e',true,'i',true,'preserve'),
 ('_authority_resource_object_graph_v2(jsonb,text,text,text)','7b51494829379bfdd91f4853099642f2e57c88ad887912e1656c5f5669a7ca76',true,'i',true,'preserve'),
 ('_authority_resource_object_manifest_images_v2(jsonb,jsonb,jsonb)','940501419f3759706e6e56fb6626e61a6896c247ffd3151c5283c0360719ab35',true,'i',true,'preserve'),
 ('_authority_resource_object_materialize_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','01559b0be95e275e46e33b0b00028c80e611b97a64fbc8eb85b0910643dd2505',true,'i',true,'preserve'),
 ('_authority_resource_object_maximum_v2(jsonb,jsonb,jsonb,jsonb)','bf2c9287fdf43dac1cc03a9c62f0a665dfda01792c54fd6440f061ec9343204c',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_sources_v2(jsonb,jsonb)','8beafc61826cbc195149bf41e1ca3402c4f794088fb81da73e91af089fcb00d3',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','98f24f2154bfc6e60611130a825cf0eb93efb6631ed36ba142f8c9a2eb0cae61',true,'i',true,'preserve'),
 ('_authority_resource_object_store_v2(jsonb)','761cb220c553c2d519c5adc6fc14b6ab4675779b205dbc529982863023ac1b5a',true,'v',true,'preserve'),
 ('_authority_resource_object_write_keys_v2(jsonb,jsonb)','55621c02ba3a899e93d5c41eddef68dd231c37500d740e2ff09bfffcb8529072',true,'i',true,'preserve'),
 ('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305',true,'i',true,'preserve'),
 ('_authority_resource_physical_relations_wait_v2(jsonb,integer)','86d6bd4c42c79ee3d6dc95ea2317113fcf99849f0445a03307e598abffecb3f2',true,'v',true,'preserve'),
 ('_authority_resource_predicate_maximum_v2(jsonb,jsonb)','54f35fa496cbd4bbb0ff0d7f838eab7e3dbb1bf17cf5b3ea8a54e55223e68a46',true,'i',true,'preserve'),
 ('_authority_resource_preheld_key_v2(integer,text,boolean)','77d85a114d79fb9d60470f0bdd63e2f688d5164fd5a225c5cebef10e43da78ea',true,'v',true,'preserve'),
 ('_authority_resource_projected_capture_v2(jsonb,integer,text,text,text,boolean)','782d8002dc7498b18696afa46da3429774cbcd9580030b46bb76d6ce97328267',true,'i',true,'preserve'),
 ('_authority_resource_projection_v2(jsonb,text,text)','79fb1eeb6681835031a23733e52c34ca00e1d13bfde63655dfdcfe1c663db0bf',true,'i',true,'preserve'),
 ('_authority_resource_publication_direct_program_v2(jsonb,jsonb,timestamptz)','753c099113766391b73c537756b40729a0e39111983d8fe2b1803407918bd25e',true,'i',true,'preserve'),
 ('_authority_resource_publication_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','2162e671105cd0d167abc538791192b7e8c6861e943f9ac60bba6294254f9058',true,'i',true,'preserve'),
 ('_authority_resource_publication_images_v2(text,text,boolean,timestamptz,jsonb,jsonb,timestamptz)','0a343a95b30ad5ec1de4aaaf900d74e0fef4c44506ca5c406ec9ea7e7916c53a',true,'i',true,'preserve'),
 ('_authority_resource_recipient_verbs_v2(jsonb,jsonb,jsonb,text,boolean,text,boolean)','f6080aad1d9dc4a12c26513ba2638f5fde3f959a79ce83a88a1c16e522b42c29',true,'i',true,'preserve'),
 ('_authority_resource_reconcile_wait_v2(integer,integer)','2e5af4934a850ef95f1a333ad71694bd4f27fa51f1b0de19b670ed9f3ca5d8fa',true,'v',true,'preserve'),
 ('_authority_resource_refusal_certificate_v2(jsonb,jsonb,jsonb,jsonb)','1f5e087abb91e7289bd935f29592eb51b59f93b176dd1a86cee74672aa1f879a',true,'i',true,'preserve'),
 ('_authority_resource_refusal_materialize_v2(jsonb,jsonb,timestamptz)','fc6cef31e2f28cb7b6bf3d5b6f95aa601ac1caf89a55e7405af0c84a302d1eab',true,'i',true,'preserve'),
 ('_authority_resource_refusal_prepare_v2(jsonb,integer,integer)','1cf4deb21d1776d53041718e1a2d453150d83b269a8de108d021b736a348d831',true,'v',true,'preserve'),
 ('_authority_resource_registration_authority_final_v2(jsonb,timestamptz)','5369474ff41744e9375e8b91ed623a1fbeab6c8dcd954f563a89dcdbf672b965',true,'i',true,'preserve'),
 ('_authority_resource_registration_authority_wait_v2(jsonb,jsonb,text,jsonb,integer,integer)','8b92777acd79df9e879a5be7bfd2fc0cb9b70c1230f941a55c8e20d8c1c126bb',true,'v',true,'preserve'),
 ('_authority_resource_registration_binding_wait_v2(jsonb,jsonb,integer)','8737eebc8314ab0caf06537329e3d376f94daaaedd424faf11df30c7d41e8fa2',true,'v',true,'preserve'),
 ('_authority_resource_registration_delete_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','140ccec2507036d09f2e81db00356442d8fd561a742b6e8752b4dd377be26171',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_program_v2(jsonb,jsonb,timestamptz)','89e76fe747ba97a46120af7c1548b02835beba9e19618fb03b0add94bf3c434c',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_sources_v2(jsonb,jsonb)','35a8292b281969ee1003e54336a2acda78e2c592daa4022b1412efd1996a0427',true,'i',true,'preserve'),
 ('_authority_resource_registration_fact_v2(text,text,jsonb)','81397be2c987bdd6787b0cc3fc52692b970c534ab42d126e5f1aafd28484c4c9',true,'i',true,'preserve'),
 ('_authority_resource_registration_intent_certificate_v2(jsonb,jsonb,jsonb,jsonb)','18c7790f1463d3982e3f69b7b80f1e2af3210a1da06202f88abc44cb681d86e5',true,'i',true,'preserve'),
 ('_authority_resource_registration_manifest_images_v2(jsonb,jsonb,jsonb)','acecdc1f6a1f2a36d62c82af93ccad6351700ba1bd927d26240c480ebc5b1596',true,'i',true,'preserve'),
 ('_authority_resource_registration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','455a6cb564a14038aff88f58f383ed79625016ec2896cf0f2f303b0e734a7964',true,'i',true,'preserve'),
 ('_authority_resource_registration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','0d869eee616ea83c8f5c20c179c727022ceecf8ff42cb0a53731aba56d8cb6cc',true,'i',true,'preserve'),
 ('_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_model_v2(text)','89ac1f6c923ab033b5551fff2d098099518b2b7c15b3530f15e798ef70cf20e9',true,'i',true,'preserve'),
 ('_authority_resource_registration_pack_v2(jsonb,jsonb,jsonb)','c7df4fd61023a840f764bfd36b29151f718b35aa360fb93c55fbeb7618d50ec7',true,'i',true,'preserve'),
 ('_authority_resource_registration_parent_graph_v2(jsonb,jsonb,text)','e9bcecbff08deea42f1eb0a2356aa88075ff5d526e754cd5514c99028b8b0f96',true,'i',true,'preserve'),
 ('_authority_resource_registration_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','7c765b761ad28fbde1f64094ef30cf61d70c20b555cb8c5026e172c5eea9d918',true,'i',true,'preserve'),
 ('_authority_resource_registration_pointer_images_v2(text,text,text,text,jsonb,timestamptz,jsonb)','dd37d5f9645e4b380d466079441c945a0e5f95fb44341d75bf4859b09a95e7d8',true,'i',true,'preserve'),
 ('_authority_resource_registration_prepare_v2(jsonb,integer,integer)','c2ab0a869a22e4fec8e5b2735055308a15ba545ef33c21d3f2af9c3f0e2bb773',true,'v',true,'preserve'),
 ('_authority_resource_registration_receipt_images_v2(text,text,text,jsonb,timestamptz,text,jsonb)','4a952ac29b2a28cdaa48f73b0f173a759a4ed455ae43677363284976c960a35c',true,'i',true,'preserve'),
 ('_authority_resource_registration_saved_scopes_v2(jsonb,jsonb,text,text)','d2798409d801254b2a63af2de46033cd560cc6c2bde88193a5d31ffea3daaca3',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_certificate_v2(jsonb,jsonb,text,text,text,text,jsonb,boolean)','e5bbc391fa00cc3362d203916604507a513a81c7963c24e4d0196ba1277f129d',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_images_v2(text,text,jsonb,jsonb)','a6fedeea120947165db033862934904916bf4ca57f6e02ca9a64efcd155b55f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_step_operations_v2(jsonb,jsonb,jsonb)','7a6d30976cbbfa09e2f388994476cdab3f99e5b949dda0463829b1c5f0c36df7',true,'i',true,'preserve'),
 ('_authority_resource_registration_store_v2(jsonb)','dc264ddd6cd90f698104551e0be54173d83d5576df7e0d75a1c75ad3133f3221',true,'v',true,'preserve'),
 ('_authority_resource_registration_version_v2(text)','09aa74b25e294d4d6c5c43c107212c81f0d1b32acc43e5a74f0588dbcb7d9690',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_images_v2(jsonb,timestamptz,jsonb,jsonb,timestamptz)','af4c099a81327d849e561861eba96568eab9a5ae27c4dbbc77f32ea5f381cd6c',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_keys_v2(jsonb,jsonb)','b7deaeb5ee01534ffeeaaa6ed468794f039487e293d07cfec08240ddc2db73d3',true,'i',true,'preserve'),
 ('_authority_resource_require_capture_v2(jsonb,integer,text,text,text)','3052c274445598750d6646cbb4bc1308311befc0e2cdb125961633702ac0bd35',true,'i',true,'preserve'),
 ('_authority_resource_required_reread_v2(jsonb,jsonb,jsonb,integer,integer)','4821805cd8b27cce9cddbf1ebc17186aec073d2bbc64860ab7ab888dffae0aa3',true,'v',true,'preserve'),
 ('_authority_resource_row_image_v2(text,jsonb)','f6c7bdc6437dd7e32592f53af7795438fc97164a8ed1d33f7d9522e659548e42',true,'i',true,'preserve'),
 ('_authority_resource_rule_fingerprint_v2(jsonb,boolean)','4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5',true,'i',true,'preserve'),
 ('_authority_resource_rule_layout_v2(jsonb,jsonb)','fcf600cf8eaafe1211e0b663bd798dbd025bb9429d06066507dd648256b8013d',true,'i',true,'preserve'),
 ('_authority_resource_rule_witness_v2(jsonb,text,jsonb)','ef7b397fd945ad8df12c6f541a3764b34b2242751289085ba43a908089f17a6a',true,'i',true,'preserve'),
 ('_authority_resource_selector_matches_v2(jsonb,text,text,jsonb)','b925d87aa30d19a06d00e346d26e381721cc63c8eb4deb12f0f1a15b3e49da68',true,'i',true,'preserve'),
 ('_authority_resource_selector_rows_v2(jsonb,integer,integer)','d7da86929ecc720bfd1f617a1c02ae074a487c8280e931a91cba0f008c8060ef',true,'v',true,'preserve'),
 ('_authority_resource_selector_shape_v2(jsonb,integer,integer)','c044631ad4287271aa8540488883ec06983a5abb85f484388a25cba713191a3c',true,'v',true,'preserve'),
 ('_authority_resource_source_wait_v2(jsonb,boolean,integer,integer)','1ce9b16ec596aa1521e295cadb310ea5680c69ba5ea12ee995f186adeb5bd654',true,'v',true,'preserve'),
 ('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c',true,'i',true,'private'),
 ('_authority_resource_special_member_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','9415be5436a7ed74e97131d996f346df3f1b02d23c7f5b108fa7788629a0c6ed',true,'i',true,'preserve'),
 ('_authority_resource_subject_change_wait_v2(integer,integer)','bb5f61c161012d21fe2480ffbdc61fc8095ceb1d9d265a13b26530b22b568632',true,'v',true,'preserve'),
 ('_authority_resource_target_contains_v2(jsonb,text,text)','5c3e97459a3935ec873831692d25cf522a7ca8447a97fbb376a1be6aa9fd8186',true,'i',true,'preserve'),
 ('_authority_resource_tuple_relations_v2(jsonb,jsonb,text,jsonb,text)','efc819930de778d8c757833f9d5e3f056f9e7723da3dd2ef1e9d958c2902d0cb',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_audit_hierarchy_v2(jsonb,jsonb,jsonb,jsonb)','6f8f54188fade71649c640691ff5cabeffcf1512f89d4744e138be4b6f6a00d2',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_certificate_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','023353817aec9d9ab441c2e5bd8f9ba66b6d2164d7d71f2d82f646b025a4e615',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_current_v2(jsonb,jsonb,jsonb)','91cb5cb519e0a34e103fcf84df5ecf2259c656282c55a0fc4c88a5f83cd84101',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_direct_program_v2(jsonb,jsonb,timestamptz)','8e88012c6babe593a7203c818726d8c768e7f907015c731c1cf115aa59195e8b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_fold_v2(jsonb,jsonb,timestamptz)','981a3753a9d5149fc3ad5996f3b7664989a1a58b66915f9d639b55b769f818be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_images_v2(text,jsonb,jsonb,jsonb,jsonb,timestamptz)','bd2c3a71cf82e7a55a4d0b3cd271c0114afd4d18bfa5d1196fb8425493c3fd48',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_program_v2(jsonb,jsonb,jsonb,timestamptz)','e6778dd30178f736816a8816a83005179aa0a3c651242c51bf0a9c10207dd5be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_rows_v2(jsonb,jsonb)','559ccb301f1c99a57f71910e7407a76e93f20393b88ef7f77c08d96f6bd211cf',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a5dcf1324a5a8daca8e3e80ccd296cb9f737a8a90a65ddc85f5e36269835300b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','15d8361f789a52deaa920abbf46dddfff367d65bc15668f393e2cd93e61b7009',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_mirror_images_v2(jsonb,text)','2cfc03821a5f30ce8e657ca020329a1e54c29c728a125f1a32e6a8b2b4a7c32c',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_object_v2(jsonb,jsonb,text)','d553151e5ff2b50c946bdefb0f5a47c342de88cd97da547afe5b726d8f9b2e3f',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_acl_v2(jsonb,oid,jsonb)','075c20b7bb9f2d06dec73df64186da0b9d4bcc500b99fcbc28ef9b4f21ce7fea',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_maximum_v2(jsonb,jsonb)','79cded719033e41b9a38951033f494bb29e4b48a8c4def81d0126376f333cb45',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_physical_v2(jsonb)','c78c70847fb31b8d1dc082e413a6cc5827f1b79eee9eb067410258408a22221d',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_roots_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','d59ef0d706c1f24a98b764ba805604e411d5f54980c64e6d2e8efd1ae3d6a306',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_source_metadata_v2(jsonb,jsonb,jsonb)','67fbae698c0f4362c2d1a7245a8db1073e76ad0ba5aef10cf43fc8f2427e5b40',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_tail_program_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','93238ccdb1002e80ed0651b7802a3c392c7a3714ca12bfb77053f6fd399dfe9b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_withdrawal_program_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','ec2574723c93de9016b0156bb712879eecdafdfa2270f97f8cf4df57c52a4069',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_write_keys_v2(jsonb,jsonb)','ee116834532cc77d78fd300dda8c172da48781107d6b1813027c659001619161',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_images_v2(jsonb,jsonb,jsonb,timestamptz,timestamptz)','787963fad1924ff537cd5dd113e5b0cad7e05abbda3d8b3b3e3ca1b7238e5178',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_v2(jsonb,jsonb,jsonb,jsonb,text,jsonb)','c21e989d6476855358771d8780d9bc5e02f9cd5d46540c08d1690071f129aaf3',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_bindings_v2(jsonb,jsonb,jsonb,text,jsonb)','e8eec4698549dca98cc22b3aebd1f6580d4ffd81241fbf82994c50653b8ac900',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_census_v2(jsonb,jsonb)','d27e53aef5e2f64ed1ad158e3aa31047b3845afb8b80908eca271674a4728c13',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','44869037245345da786a82632bb8f22d2a5095769ea5b194cd39ff63933b354d',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_retention_v2(jsonb,text,jsonb,jsonb,jsonb)','50d877065d0b35b3a8b9f13319110f0c736a790c18be146c38ba66fd471ecd81',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_rules_v2(jsonb,jsonb,text,jsonb)','9491569e7691e17074fe14ef74539351bd21fb7776970eb82a6f79a4aef1ea0b',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_roles_v2(jsonb,jsonb,jsonb,text,jsonb,jsonb,jsonb)','7a8a458214d4d7047ef95b7a7d89d1cf30fb44c2b0e641a9d0eddcb3cd3a70bd',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_rules_v2(jsonb,text,text)','7bf6058618cf10048a6cb7671342c222e6dd24ff4825d6743990dd2a8c50e29c',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_split_v2(jsonb)','27da9c2fbe328e2cd4013f991dc62e7ee75ee1031a5bd5e42dd86bcd1fac7282',true,'i',true,'preserve'),
 ('_authority_resource_without_name_v2(jsonb,text,text,text,boolean,boolean)','d97ead12d3586dac0380d636ddfeb73100ddcf5310211834371babd3f3d0468a',true,'i',true,'preserve'),
 ('authority_binding_epoch_changed()','bcf0e606baaa81d738d99f2dfb8882f9723c37ccb59f70fb0785e2507119ccef',true,'v',true,'preserve'),
 ('authority_binding_epoch_read(text[])','37c8fcd579b297a3c7a749b2889ad95a95561341c63bfa4eb3355284ed583b05',true,'s',true,'preserve'),
 ('authority_binding_epoch_scope(text,jsonb)','ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30',true,'s',true,'preserve'),
 ('authority_group_object_scopes(text,text)','ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60',true,'s',true,'preserve'),
 ('authority_protocol_row_account(text,jsonb)','36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e',true,'s',true,'preserve'),
 ('resource_journal_project(text,jsonb)','a792cf1d91d0d5b16d01f530109ad7b08559e1bea98632d30fbeadec4bfbdbb7',false,'i',false,'preserve'),
 ('resource_journal_scope(text,jsonb)','22deae6b397c11f7558bd7e10c64400e06ea0f765f5b7f17ba03fe1d00aa1da9',false,'s',false,'preserve')
 ) pin_expected(signature,digest,definer,volatility,fixed_path,access_mode)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pin_expected.signature)
 WHERE CASE WHEN p.oid IS NULL THEN true ELSE
  (p.proowner=owner_oid AND p.prosecdef=pin_expected.definer AND p.provolatile::text=pin_expected.volatility
   AND CASE WHEN pin_expected.fixed_path THEN p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] ELSE p.proconfig IS NULL END
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pin_expected.digest) IS NOT TRUE
 OR (pin_expected.access_mode='private' AND EXISTS(
   SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid))
 OR (pin_expected.access_mode='export' AND EXISTS(
   SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid
   AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) END) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname._authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)'::regprocedure
   AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT p.proretset AND NOT p.proisstrict
   AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargs=6 AND p.pronargdefaults=0
   AND p.proargmodes IS NULL AND p.provariadic=0 AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('authority_reconcile_enter_v3()','void',0,false), ('authority_installation_enter_v2(text)','integer',1,false), ('_authority_audit_binding_store_v3()','jsonb',0,false), ('_authority_binding_mirror_store_v3()','jsonb',0,false), ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','void',3,false), ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','record',3,true), ('_authority_binding_mirror_finalize_v3(text)','void',1,false), ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','boolean',4,false)
 ) abi_expected(signature,result_type,nargs,returns_set) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||abi_expected.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>abi_expected.result_type::regtype OR p.proretset<>abi_expected.returns_set
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>abi_expected.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
 OR CASE WHEN abi_expected.returns_set THEN p.proargmodes IS DISTINCT FROM ARRAY['i','i','i','t','t']::"char"[]
  OR p.proallargtypes IS DISTINCT FROM ARRAY['jsonb'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype]::oid[]
  OR p.proargnames IS DISTINCT FROM ARRAY['p_snapshot','p_rows','p_reads','logical_rows','logical_reads']::text[]
 ELSE p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL END) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('authority_binding_command_begin_v3(jsonb)','boolean','p_command'),
 ('authority_binding_command_end_v3(jsonb)','void','p_command'),
 ('authority_binding_command_audit_v3(jsonb)','boolean','p_command'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','void','p_snapshot')
 ) e(signature,result_type,argname) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>1 OR p.pronargdefaults<>0
 OR p.provariadic<>0 OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.proargnames IS DISTINCT FROM ARRAY[e.argname]::text[] OR p.proargtypes[0]<>'jsonb'::regtype
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure
  AND p.prorettype='pg_catalog.bool'::regtype AND p.pronargs=6 AND p.proargtypes='3802 3802 25 3802 3802 3802'::oidvector
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND NOT p.proretset AND NOT p.proisstrict AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.proallargtypes IS NULL AND p.proargmodes IS NULL) THEN RETURN false;END IF;
 -- Mirror остаётся единственным AFTER INSERT/UPDATE OF тех же трёх колонок.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.membership_mirror_from_user()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.users'::regclass
  AND t.tgname='membership_mirrors_user_row' AND t.tgfoid='kaname.membership_mirror_from_user()'::regprocedure
  AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=21
  AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgqual IS NULL
  AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND (SELECT array_agg(a.attname::text ORDER BY x.position)
   FROM unnest(t.tgattr) WITH ORDINALITY x(attnum,position)
   JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=x.attnum AND NOT a.attisdropped)
    =ARRAY['account_id','invite_status','invited_by']::text[]) THEN RETURN false;END IF;
 -- Точная схема вызовов: нельзя снять guard, сделать deferred или добавить
 -- второй вызов того же emitter вне скомпилированного eventset.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('projects','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('service_accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_journal_applied','authority_crud_journal_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_guard','authority_crud_fga_id_guard_v3()',7,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_applied','authority_crud_fga_id_applied_v3()',5,0,'',false,NULL,NULL),
 ('resource_journal','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('projects','projects_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('users','users_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('groups','groups_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('roles','roles_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('group_members','group_members_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('memberships','memberships_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('accounts','accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'6163636f756e7400',false,NULL,NULL),
 ('accounts','accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'6163636f756e7400',true,NULL,NULL),
 ('accounts','accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'6163636f756e7400',false,NULL,NULL),
 ('projects','projects_resource_journal_insert_trg','resource_journal_emit()',5,1,'70726f6a65637400',false,NULL,NULL),
 ('projects','projects_resource_journal_update_trg','resource_journal_emit()',17,1,'70726f6a65637400',true,NULL,NULL),
 ('projects','projects_resource_journal_delete_trg','resource_journal_emit()',11,1,'70726f6a65637400',false,NULL,NULL),
 ('users','users_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f7573657200',false,NULL,NULL),
 ('users','users_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f7573657200',true,NULL,NULL),
 ('users','users_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f7573657200',false,NULL,NULL),
 ('groups','groups_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f67726f757000',false,NULL,NULL),
 ('groups','groups_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f67726f757000',true,NULL,NULL),
 ('groups','groups_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f67726f757000',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f736572766963655f6163636f756e7400',true,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('roles','roles_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('roles','roles_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f726f6c6500',true,NULL,NULL),
 ('roles','roles_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f6163636573735f62696e64696e6700',true,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('group_members','group_members_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f67726f75700067726f75705f69640067726f75707300',false,NULL,NULL),
 ('memberships','memberships_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f7573657200757365725f696400757365727300',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f6163636573735f62696e64696e670062696e64696e675f6964006163636573735f62696e64696e677300',false,NULL,NULL),
 ('accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('projects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('projects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('projects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('projects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('roles','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('roles','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('roles','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('roles','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('groups','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('groups','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('groups','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('groups','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('users','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('users','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('users','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('users','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('service_accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('service_accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('service_accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('service_accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('memberships','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('memberships','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('memberships','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('memberships','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_bindings','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_bindings','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_bindings','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_bindings','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_subjects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_subjects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_target_members','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_target_members','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_emitted_tuples','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_emitted_tuples','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_selectors','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_selectors','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_selector_verbs_pending','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_selector_verbs_pending','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_ref','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_ref','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_ref','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_ref','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_create_binding_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_create_binding_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_bind_role_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_bind_role_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_module','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_module','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_module','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_module','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_resource','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_resource','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_resource','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_resource','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_mirror','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_mirror','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_mirror','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_mirror','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_registration_scope','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_registration_scope','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_parent_edge','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_parent_edge','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('grant_delegations','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('grant_delegations','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('grant_delegations','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('grant_delegations','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL)
 ) graph_expected(table_name,trigger_name,signature,trigger_type,nargs,argument_hex,has_qual,old_table,new_table)
 WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||graph_expected.table_name)
   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p')
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||graph_expected.table_name)
   AND t.tgname=graph_expected.trigger_name AND t.tgfoid=to_regprocedure('kaname.'||graph_expected.signature)
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=graph_expected.trigger_type
   AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
   AND t.tgnargs=graph_expected.nargs AND encode(t.tgargs,'hex')=graph_expected.argument_hex AND t.tgattr=''::int2vector
   AND t.tgoldtable::text IS NOT DISTINCT FROM graph_expected.old_table AND t.tgnewtable::text IS NOT DISTINCT FROM graph_expected.new_table
   -- Trigger qual имеет две range-table записи OLD/NEW; pg_get_expr для него
   -- неприменим. Сравнивается вся WHEN-clause trigger-aware deparser, не подстрока.
   AND CASE WHEN graph_expected.has_qual THEN t.tgqual IS NOT NULL
    AND substring(pg_get_triggerdef(t.oid,false) FROM ' WHEN (.*) EXECUTE FUNCTION ')='((old.* IS DISTINCT FROM new.*))'
    ELSE t.tgqual IS NULL END)) THEN RETURN false;END IF;
 -- STABLE: все counts используют снимок вызывающего запроса. Карта содержит
 -- не более 12 OID; посторонние trigger-функции не увеличивают её размер.
 -- Предварительный lookup не бросает ошибку для отсутствующей функции.
 -- Каждый строгий cast остаётся на прежней границе проверки; если он видит
 -- другой OID, ленивый fallback считает исходный каталог, а не подставляет 0.
 WITH requested AS MATERIALIZED (
  SELECT DISTINCT to_regprocedure(signature)::oid AS oid FROM (VALUES
   ('kaname._authority_crud_aux_statement_v3()'),
   ('kaname._authority_crud_aux_write_v3()'),
   ('kaname.authority_binding_epoch_changed()'),
   ('kaname.authority_crud_fga_id_applied_v3()'),
   ('kaname.authority_crud_fga_id_guard_v3()'),
   ('kaname.authority_crud_journal_applied_v3()'),
   ('kaname.authority_crud_sequence_guard_v3()'),
   ('kaname.authority_crud_unique_guard_v3()'),
   ('kaname.authority_sequence_origin_v3()'),
   ('kaname.authority_sequence_program_applied_v3()'),
   ('kaname.resource_journal_emit()'),
   ('kaname.resource_journal_emit_member()')
  ) names(signature)
 ), counts AS MATERIALIZED (
  SELECT t.tgfoid AS oid,count(t.oid) AS n FROM pg_catalog.pg_trigger t
  WHERE t.tgfoid=ANY(ARRAY(SELECT oid FROM requested)) GROUP BY t.tgfoid
 ), snapshot AS MATERIALIZED (
  SELECT coalesce(jsonb_object_agg(r.oid::text,coalesce(c.n,0)),'{}'::jsonb) AS counts
  FROM requested r LEFT JOIN counts c ON c.oid=r.oid WHERE r.oid IS NOT NULL
 )
 SELECT s.counts,coalesce((s.counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
 INTO trigger_counts,trigger_count
 FROM snapshot s CROSS JOIN (SELECT 'kaname._authority_crud_aux_statement_v3()'::regprocedure::oid AS oid) r;
 IF trigger_count<>6 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname._authority_crud_aux_write_v3()'::regprocedure::oid AS oid) r)<>10 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_binding_epoch_changed()'::regprocedure::oid AS oid) r)<>96 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_fga_id_applied_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_fga_id_guard_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_journal_applied_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_sequence_guard_v3()'::regprocedure::oid AS oid) r)<>2 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_unique_guard_v3()'::regprocedure::oid AS oid) r)<>6 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_sequence_origin_v3()'::regprocedure::oid AS oid) r)<>24 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_sequence_program_applied_v3()'::regprocedure::oid AS oid) r)<>2 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.resource_journal_emit()'::regprocedure::oid AS oid) r)<>21 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.resource_journal_emit_member()'::regprocedure::oid AS oid) r)<>3 THEN RETURN false;END IF;
 -- Defaults принадлежат ровно тем же owned sequences; свободный nextval
 -- вместо wrapper вновь открыл бы after-clock unique arbitration.
 FOR expected IN SELECT * FROM (VALUES
  ('resource_journal','sequence_no','authority_resource_journal_id_v3()','resource_journal_sequence_no_seq'),
  ('fga_outbox','id','authority_fga_outbox_id_v3()','fga_outbox_id_seq')
 ) d(table_name,column_name,default_name,sequence_name) LOOP
  IF pg_get_serial_sequence('kaname.'||expected.table_name,expected.column_name)::regclass::oid
   IS DISTINCT FROM to_regclass('kaname.'||expected.sequence_name)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=to_regclass('kaname.'||expected.table_name) AND a.attname=expected.column_name AND NOT a.attisdropped
   AND pg_get_expr(d.adbin,d.adrelid)='kaname.'||expected.default_name) THEN RETURN false;END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','header']::text[] AND p.proargmodes=ARRAY['t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid]) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_protocol_snapshot_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','compatibility_shared','compatibility_exclusive','population_oid',
   'population_shared','population_row_exclusive','population_extra_shared','population_extra_row_exclusive']::text[]
  AND p.proargmodes=ARRAY['t','t','t','t','t','t','t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'oid'::regtype::oid,
   'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid]) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_native_delete_emit_v4(jsonb[])','void',1,ARRAY['p_payloads']),
  ('authority_native_delete_prepare_v4(jsonb[])','uuid',1,ARRAY['p_payloads']),
  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload'])
 ) e(signature,result_type,nargs,names) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>e.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.proargnames IS DISTINCT FROM e.names OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 -- Хранилище инкарнаций и квитанций принадлежит только владельцу протокола.
 IF EXISTS(SELECT 1
  FROM unnest(ARRAY['authority_child_parent_state','authority_child_creation']) AS required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM owner_oid OR c.relkind<>'r' OR c.relpersistence<>'p'
   OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute col
    CROSS JOIN LATERAL aclexplode(col.attacl) a
    WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>owner_oid)
 ) THEN RETURN false;END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_crud_storage_v3()','36bd005f8ee097ce2f71fb396bed20e968aa1c3f9f0baab4554e932e251a9a64',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','7608e2d0a1b1ce2bb11182a349150e5369e2bd97c5fb8abc3da84b3d2e0c229a',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS NOT TRUE THEN
  RAISE EXCEPTION 'child registration state closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 LOCK TABLE kaname.authority_child_parent_state,kaname.authority_child_creation IN ACCESS EXCLUSIVE MODE;
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2)
 OR EXISTS(SELECT 1 FROM kaname.authority_child_parent_state)
 OR EXISTS(SELECT 1 FROM kaname.authority_child_creation) THEN
  RAISE EXCEPTION 'cannot remove active child registration state' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding runtime grant closure incomplete' USING ERRCODE='55000';END IF;
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 FOREACH signature IN ARRAY ARRAY[
  'authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()',
  'authority_native_delete_batch_read_v4()',
  'authority_native_delete_emit_v4(jsonb[])',
  'authority_native_delete_prepare_v4(jsonb[])',
  'authority_native_delete_stamp_v4(uuid,bigint,jsonb)',
  'authority_forward_emit_v4(jsonb[])',
  'authority_forward_prepare_v4(jsonb[])',
  'authority_forward_claim_v4(uuid)',
  'authority_forward_finish_v4(uuid)',
  'authority_group_add_prepare_v3(jsonb,integer,integer)',
  'authority_group_add_finalize_v3(jsonb,integer,integer)',
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_group_add_subject_id_v3()',
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_command_begin_v3(jsonb)',
  'authority_binding_command_end_v3(jsonb)',
  'authority_binding_command_audit_v3(jsonb)',
  'authority_binding_sequence_prepare_v3(text,jsonb)',
  'authority_binding_sequence_finalize_v3()',
  'authority_binding_insert_stamp_v3(text)',
  'authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_finalize_v3(text)',
  'authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)',
  'authority_binding_withdrawal_sequence_finalize_v3()',
  'authority_cluster_admin_preflight_v4(text,text,text)',
  'authority_resource_journal_id_v3()',
  'authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
  'authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_metadata_preflight_v4(text,text,boolean,text,jsonb)',
  'authority_sa_state_preflight_v4(text,boolean,text)',
  'authority_scalar_sequence_finalize_v3()',
  'authority_crud_storage_v3()',

  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_reconcile_enter_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_assert_body_v2(p_intent jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;
BEGIN
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'final' OR p_intent IS DISTINCT FROM manifest->'intent'
 OR manifest->>'decision_at' IS NULL THEN
  RAISE EXCEPTION 'resource closed body requires final manifest' USING ERRCODE='42501';
 END IF;
 -- Resource не является writer личности или каталога. Проверка действует
 -- до смены state на body: даже ошибочный private creator не может включить
 -- SA INSERT/DELETE/reparent и обойти GLOBAL/root защиту absence witness.
 -- Точные разрешённые OLD/NEW оставшихся таблиц дополнительно проверяет
 -- semantic creator; принадлежность этому перечню сама по себе не allow.
 IF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
 ELSE
 IF jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
  WHERE coalesce(w->>'table','') NOT IN (
   'roles','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
   'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
   'resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer',
   'resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox')) THEN
  RAISE EXCEPTION 'resource manifest contains unsupported write domain' USING ERRCODE='42501';
 END IF;
 END IF;
 -- Второй запуск того же тела в одной TX также отвергается. Изменение
 -- касается только уже открытой private temp строки, новых waits нет.
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='body';
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_require_completion_v2() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;
BEGIN
 storage:=to_regclass('pg_temp.kaname_authority_resource_manifest');
 IF TG_RELID IS DISTINCT FROM storage OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER'
 OR TG_LEVEL<>'ROW' OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
  WHERE c.oid=storage AND c.relowner=current_user::regrole::oid AND c.relpersistence='t' AND c.relkind='r') THEN
  RAISE EXCEPTION 'resource completion trigger target invalid' USING ERRCODE='42501';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'body'
 OR jsonb_typeof(manifest->'writes') IS DISTINCT FROM 'array'
 OR jsonb_array_length(manifest->'writes')>100000 THEN
  RAISE EXCEPTION 'resource body did not complete' USING ERRCODE='42501';
 END IF;
 SELECT consumed_required_writes INTO STRICT consumed FROM pg_temp.kaname_authority_resource_manifest;
 IF consumed IS NULL OR cardinality(consumed)>100000
 OR EXISTS(SELECT 1 FROM unnest(consumed) n WHERE n IS NULL OR n<1 OR n>jsonb_array_length(manifest->'writes'))
 OR EXISTS(SELECT 1 FROM unnest(consumed) n GROUP BY n HAVING count(*)<>1)
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(manifest->'writes') w WHERE jsonb_typeof(w->'required') IS DISTINCT FROM 'boolean') THEN
  RAISE EXCEPTION 'resource completion inventory is invalid' USING ERRCODE='42501';
 END IF;
 SELECT count(*)::integer INTO required_count FROM jsonb_array_elements(manifest->'writes') w WHERE w->>'required'='true';
 SELECT count(*)::integer INTO consumed_count FROM unnest(consumed) n
  WHERE manifest->'writes'->(n-1)->>'required'='true';
 IF required_count<>consumed_count THEN
  RAISE EXCEPTION 'resource mandatory effect was omitted' USING ERRCODE='42501';
 END IF;
 -- Audit и вспомогательные очереди не входят в authority32; их точное
 -- применение и завершение последней команды проверяются отдельно.
 IF manifest->'intent'->>'kind'='object' THEN
  IF manifest->>'object_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{object_program,commands}') THEN
   RAISE EXCEPTION 'resource object program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'object_physical';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  PERFORM kaname._authority_crud_require_completion_v3(manifest);
  physical:=manifest->'registration_physical';
 ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4','5') THEN
  IF manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
   OR (manifest->>'object_command')::integer IS DISTINCT FROM jsonb_array_length(manifest#>'{registration_program,commands}') THEN
   RAISE EXCEPTION 'resource registration program did not complete' USING ERRCODE='42501';END IF;
  physical:=manifest->'registration_physical';
  IF jsonb_typeof(physical->'bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'reconcile') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_registration_bindings') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_reconcile_ids') IS DISTINCT FROM 'array'
   OR jsonb_typeof(physical->'subject_changes') IS DISTINCT FROM 'array'
   OR jsonb_typeof(manifest->'consumed_subject_change_ids') IS DISTINCT FROM 'array'
   OR jsonb_array_length(physical->'subject_changes')<>jsonb_array_length(manifest->'consumed_subject_change_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'subject_changes') r
    WHERE NOT (manifest->'consumed_subject_change_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_subject_change_ids') n GROUP BY n HAVING count(*)<>1)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'bindings') WITH ORDINALITY e(value,ordinality)
    WHERE e.value->>'required'='true' AND NOT (manifest->'consumed_registration_bindings') @> jsonb_build_array(e.ordinality))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n
    WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'bindings')
     OR physical->'bindings'->(n::integer-1)->>'required' IS DISTINCT FROM 'true')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_registration_bindings') n GROUP BY n HAVING count(*)<>1)
   OR jsonb_array_length(physical->'reconcile')<>jsonb_array_length(manifest->'consumed_reconcile_ids')
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'reconcile') r
    WHERE NOT (manifest->'consumed_reconcile_ids') @> jsonb_build_array(r->'row'->'id'))
   OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_reconcile_ids') n GROUP BY n HAVING count(*)<>1) THEN
    RAISE EXCEPTION 'resource registration auxiliary effect omitted' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'resource completion intent unsupported' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(physical->'audits') IS DISTINCT FROM 'array'
  OR jsonb_typeof(manifest->'consumed_audit_ids') IS DISTINCT FROM 'array'
  OR jsonb_array_length(physical->'audits')<>jsonb_array_length(manifest->'consumed_audit_ids')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(physical->'audits') a
   WHERE NOT (manifest->'consumed_audit_ids') ? (a->'row'->>'id'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_audit_ids') identifier GROUP BY identifier HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory audit was omitted' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
  OR jsonb_typeof(physical->'outboxes') IS DISTINCT FROM 'array'
  OR jsonb_array_length(manifest->'consumed_object_folds')<>jsonb_array_length(physical->'outboxes')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n
   WHERE n::integer<1 OR n::integer>jsonb_array_length(physical->'outboxes'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(manifest->'consumed_object_folds') n GROUP BY n HAVING count(*)<>1) THEN
   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_fold_body_v2(p_event_type text,p_payload jsonb,p_created_at timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;item jsonb;expected jsonb;row_value jsonb;image jsonb;invoker oid;
 ordinal integer;write_ordinal integer;selected integer:=0;outboxes jsonb;fold_images jsonb;outbox_ordinals jsonb;requires_update boolean:=true;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NULL THEN
  IF kaname._authority_binding_mirror_store_v3() IS NULL THEN RETURN false;END IF;
  expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
  SELECT i.image_no,i.outbox_no INTO write_ordinal,selected FROM pg_temp.kaname_binding_mirror_images i
   WHERE i.table_name='fga_outbox' AND i.new_image=expected AND i.attempted AND i.consumed AND NOT i.folded
   ORDER BY i.command_no,i.image_no LIMIT 1;
  IF write_ordinal IS NULL THEN RAISE EXCEPTION 'binding mirror fold lacks actual journal' USING ERRCODE='42501';END IF;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=selected WHERE singleton;
  invoker:=(kaname.authority_protocol_attestation()->>'invoker_oid')::oid;
  FOR image IN SELECT jsonb_build_object('operation',i.operation,'old',i.old_image,'new',i.new_image)
   FROM pg_temp.kaname_binding_mirror_images i WHERE i.table_name='relation_fact' AND i.outbox_no=selected ORDER BY i.image_no LOOP
   IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT') THEN
    RAISE EXCEPTION 'binding mirror fold requires original SELECT ACL' USING ERRCODE='42501';END IF;
   IF image->>'operation'='INSERT' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT') OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original upsert ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'new';
    INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
    VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
     (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,row_value->>'condition_name',row_value->'condition_params')
    ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
     SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
     WHERE relation_fact.source_version<EXCLUDED.source_version;
   ELSE
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE') OR NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
     RAISE EXCEPTION 'binding mirror fold requires original delete ACL' USING ERRCODE='42501';END IF;
    row_value:=image->'old';
    DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
     AND relation=row_value->>'relation' AND subject=row_value->>'subject';
   END IF;
  END LOOP;
  UPDATE pg_temp.kaname_binding_mirror_program SET active_outbox=NULL WHERE singleton;
  UPDATE pg_temp.kaname_binding_mirror_images SET folded=true WHERE image_no=write_ordinal;
  RETURN true;
 END IF;
 IF manifest->'intent'->>'kind'='object' THEN
  outboxes:=manifest#>'{object_physical,outboxes}';fold_images:=manifest#>'{object_fold,images}';
  outbox_ordinals:=manifest->'object_outbox_write_ordinals';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4') THEN
  outboxes:=manifest#>'{registration_physical,outboxes}';fold_images:=manifest#>'{registration_physical,fold_images}';
  outbox_ordinals:=manifest->'registration_outbox_write_ordinals';
 ELSE RAISE EXCEPTION 'resource fold intent unsupported' USING ERRCODE='42501';END IF;
 IF jsonb_typeof(outboxes) IS DISTINCT FROM 'array' OR jsonb_typeof(fold_images) IS DISTINCT FROM 'array'
 OR jsonb_typeof(outbox_ordinals) IS DISTINCT FROM 'array'
 OR jsonb_typeof(manifest->'consumed_object_folds') IS DISTINCT FROM 'array'
 OR jsonb_array_length(outboxes)>100000 OR jsonb_array_length(fold_images)>100000
 OR jsonb_array_length(outbox_ordinals)<>jsonb_array_length(outboxes) THEN
  RAISE EXCEPTION 'resource fold private program unavailable' USING ERRCODE='42501';END IF;
 expected:=jsonb_build_object('event_type',p_event_type,'payload',p_payload,'created_at',p_created_at);
 ordinal:=0;
 FOR item IN SELECT value FROM jsonb_array_elements(outboxes) LOOP
  ordinal:=ordinal+1;
  IF item->'command' IS DISTINCT FROM manifest->'object_command'
  OR item->'row' IS DISTINCT FROM expected OR (manifest->'consumed_object_folds') @> jsonb_build_array(ordinal) THEN CONTINUE;END IF;
  write_ordinal:=(outbox_ordinals->>(ordinal-1))::integer;
  IF write_ordinal IS NULL OR write_ordinal<1 OR write_ordinal>jsonb_array_length(manifest->'writes') THEN
   RAISE EXCEPTION 'resource fold outbox linkage invalid' USING ERRCODE='42501';END IF;
  -- BEFORE INSERT сопоставил exact image, AFTER ROW подтвердил actual INSERT.
  -- Только обе отметки разрешают fold. Операторный journal trigger идёт
  -- после row triggers; попытка ON CONFLICT DO NOTHING не даёт этого права.
  IF NOT (manifest->'consumed_outbox_writes') @> jsonb_build_array(write_ordinal)
  OR NOT (manifest->'consumed_required_writes') @> jsonb_build_array(write_ordinal) THEN CONTINUE;END IF;
  IF selected=0 THEN selected:=ordinal;END IF;
 END LOOP;
 IF selected=0 THEN RAISE EXCEPTION 'resource fold without matching inserted journal' USING ERRCODE='42501';END IF;
 IF manifest->'intent'->>'kind' IS DISTINCT FROM 'object' THEN
  IF jsonb_typeof(outboxes->(selected-1)->'requires_update_acl') IS DISTINCT FROM 'boolean' THEN
   RAISE EXCEPTION 'registration fold row-lock ACL proof missing' USING ERRCODE='42501';END IF;
  requires_update:=(outboxes->(selected-1)->>'requires_update_acl')::boolean;
 END IF;
 invoker:=(manifest->>'invoker_oid')::oid;
 IF manifest->'intent'->>'Action'='2' THEN
  PERFORM kaname._authority_resource_unregistration_operation_acl_v2(manifest#>'{registration_body,acl}',invoker,
   jsonb_build_object('steps',jsonb_build_array(manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1))));
 END IF;
 FOR image IN SELECT value FROM jsonb_array_elements(fold_images) LOOP
  IF (image->>'outbox')::integer IS DISTINCT FROM selected THEN CONTINUE;END IF;
  IF image->>'table' IS DISTINCT FROM 'relation_fact' OR image->>'operation' NOT IN ('INSERT','UPDATE','DELETE') THEN
   RAISE EXCEPTION 'invalid resource folded physical action' USING ERRCODE='42501';END IF;
  -- INSERT исполняет тот же ON CONFLICT UPDATE, поэтому UPDATE image ниже
  -- является его проверяемым исходом, а не второй независимой командой.
  IF image->>'operation'='UPDATE' THEN CONTINUE;END IF;
  IF image->>'operation'='INSERT' THEN
   IF manifest->'intent'->>'Action'='2' THEN
    RAISE EXCEPTION 'cleanup cannot fold a fact write' USING ERRCODE='42501';END IF;
   IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','INSERT')
   OR NOT has_table_privilege(invoker,'kaname.relation_fact','UPDATE') THEN
    RAISE EXCEPTION 'resource fold requires caller fact upsert ACL' USING ERRCODE='42501';END IF;
   row_value:=image->'new';
   INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version,created_at,condition_name,condition_params)
   VALUES(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject',
    (row_value->>'source_version')::timestamptz,(row_value->>'created_at')::timestamptz,
    row_value->>'condition_name',row_value->'condition_params')
   ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
    SET source_version=EXCLUDED.source_version,condition_name=EXCLUDED.condition_name
    WHERE relation_fact.source_version<EXCLUDED.source_version;
  ELSE
   IF manifest->'intent'->>'Action' IS DISTINCT FROM '2' THEN
    IF NOT has_table_privilege(invoker,'kaname.relation_fact','SELECT')
    OR NOT has_table_privilege(invoker,'kaname.relation_fact','DELETE')
    OR (requires_update AND NOT has_any_column_privilege(invoker,'kaname.relation_fact','UPDATE')) THEN
     RAISE EXCEPTION 'resource fold requires caller fact delete ACL' USING ERRCODE='42501';END IF;
   END IF;
   row_value:=image->'old';
   DELETE FROM ONLY kaname.relation_fact WHERE object_type=row_value->>'object_type' AND object_id=row_value->>'object_id'
    AND relation=row_value->>'relation' AND subject=row_value->>'subject';
  END IF;
 END LOOP;
 UPDATE pg_temp.kaname_authority_resource_manifest SET consumed_object_folds=array_append(consumed_object_folds,selected);
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; manifest jsonb; allowed boolean;step jsonb;sequence_program jsonb;
BEGIN
 -- Один свежий proof/header на этот вызов. Probe сохраняет unsigned NULL
 -- и прежний порядок attestation перед owner/ACL/header проверками.
 SELECT q.proof,q.header INTO STRICT proof,sequence_program FROM kaname._authority_sequence_probe_v3() q;
 IF sequence_program#>>'{frozen,mode}'='authorize' THEN
  RAISE EXCEPTION 'authorization-only callback cannot mutate persistent state' USING ERRCODE='42501';
 END IF;
 IF kaname._authority_group_add_statement_v3(TG_TABLE_NAME,TG_OP) THEN RETURN NULL;END IF;
 manifest:=kaname._authority_producer_resource_v2();
 IF manifest IS NOT NULL THEN
  allowed:=false;
  IF manifest->'intent'->>'kind'='object' THEN
   step:=manifest#>'{object_program,commands}'->((manifest->>'object_command')::integer-1);
   -- Проверяем только текущий выданный private command, не соседние шаги.
   -- Два закрытых UPSERT: members и fact fold команды write. Оба вызывают
   -- statement UPDATE даже без конфликтующей строки или при stale версии.
   -- Синтаксическое UPDATE подтверждает attempted INSERT того же шага;
   -- разрешённые actual row images и обязательность consumption не меняются.
   SELECT manifest->>'object_program_claimed'='true' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(manifest->'writes') w
    WHERE w->'command'=manifest->'object_command' AND w->>'table'=TG_TABLE_NAME
    AND (w->>'operation'=TG_OP OR
     (TG_OP='UPDATE' AND w->>'operation'='INSERT'
      AND ((step->>'Kind'='members' AND TG_TABLE_NAME='access_binding_target_members')
       OR (step->>'Kind'='write' AND TG_TABLE_NAME='relation_fact'))))) INTO allowed;
  ELSIF manifest->'intent'->>'kind'='crud' THEN
   -- Новый маршрут читает только текущую закрытую owner-private команду.
   -- Указание kind в caller JSON само по себе не создаёт ни proof, ни программу.
   PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  ELSIF manifest->'intent'->>'Action' IN ('1','2','3','4') THEN
   step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
   allowed:=manifest->>'registration_program_claimed'='true'
    AND coalesce(step->'operations'->TG_TABLE_NAME,'[]'::jsonb) ? TG_OP;
  END IF;
  IF TG_OP='TRUNCATE' OR NOT coalesce(allowed,false) THEN
   RAISE EXCEPTION 'resource statement absent from current private command' USING ERRCODE='42501';
  END IF;
  RETURN NULL;
 END IF;
 -- В NULL-ветке producer выполнены только private consumer reads;
 -- ни DML, ни callback, ни изменение clock/identity между proof и проверкой нет.
 -- kaname#1034: после удаления parent каскадный child уже не обязан видеть
 -- его anchor; role target cascade также может затронуть другой account.
 -- До отдельной proven классификации adapter выбирает global ДО всех locks.
 IF proof IS NOT NULL AND proof->>'mode'<>'global'
 AND (TG_OP='TRUNCATE' OR (TG_OP='DELETE' AND TG_TABLE_NAME IN ('roles','groups','accounts'))) THEN
  RAISE EXCEPTION 'authority truncate or parent cascade requires global intent' USING ERRCODE='42501';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_registration_command_values_v2(p_input jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb;certificate jsonb;step jsonb;
BEGIN
 manifest:=kaname._authority_producer_resource_v2();IF manifest IS NULL THEN RETURN NULL;END IF;
 certificate:=manifest->'registration_certificate';
 step:=manifest#>'{registration_program,commands}'->((manifest->>'object_command')::integer-1);
 IF manifest->'intent'->>'Action' IS DISTINCT FROM '1'
 OR manifest->>'registration_program_claimed' IS DISTINCT FROM 'true'
 OR step->>'kind' IS DISTINCT FROM 'mirror'
 OR p_input IS DISTINCT FROM certificate->'input_command'
 OR jsonb_typeof(step->'applied') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(step->'projection_unchanged') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'canonical registration command differs from current private step' USING ERRCODE='42501';END IF;
 RETURN jsonb_build_object('command',certificate->'command','catalog',certificate->'catalog',
  'applied',step->'applied','projection_unchanged',step->'projection_unchanged');
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_prewait_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;prepared record;
BEGIN
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864 THEN
  RAISE EXCEPTION 'resource prewait input budget exceeded' USING ERRCODE='54000';END IF;
 IF p_envelope->'abi' IS DISTINCT FROM '2'::jsonb OR jsonb_typeof(p_envelope->'intent') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource prewait ABI mismatch' USING ERRCODE='42501';END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'purpose' IS DISTINCT FROM 'participant' OR proof->>'consumer_abi' IS DISTINCT FROM '2'
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
 OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'resource prewait requires fresh typed participant' USING ERRCODE='42501';END IF;
 IF p_envelope->'intent'->>'kind'='crud' THEN
  IF p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'writer_contract' IS DISTINCT FROM '2' THEN
   RAISE EXCEPTION 'CRUD requires exact full source participant' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_crud_prepare_v3(p_envelope,p_rows,p_reads);
 ELSIF p_envelope->'intent' ? 'kind' THEN
  IF p_envelope->'intent'->>'kind' IS DISTINCT FROM 'object'
  OR p_envelope->'intent' ? 'Action'
  OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending' THEN
   RAISE EXCEPTION 'object route requires exact pending object intent' USING ERRCODE='42501';END IF;
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_object_prepare_v2(p_envelope,p_rows,p_reads);
 ELSE
  -- The closed family dispatcher checks Action and delegates to the complete
  -- direct, withdrawal or refusal compiler. Unknown intents never fall back.
  SELECT * INTO STRICT prepared FROM kaname._authority_resource_registration_prepare_v2(p_envelope,p_rows,p_reads);
 END IF;
 IF prepared.logical_rows IS NULL OR prepared.logical_rows<0 OR prepared.logical_rows>p_rows
 OR prepared.logical_reads IS NULL OR prepared.logical_reads<0 OR prepared.logical_reads>p_reads THEN
  RAISE EXCEPTION 'resource compiler exceeded shared budget' USING ERRCODE='54000';END IF;
 RETURN QUERY SELECT prepared.logical_rows::integer,prepared.logical_reads::integer;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_resource_finalize_v2(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(decision_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE manifest jsonb; expected jsonb; actual jsonb; keys text[]; at_time timestamptz; count_rows integer;
 materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];
BEGIN
 IF p_rows IS NULL OR p_rows<0 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096 THEN
  RAISE EXCEPTION 'resource final budget exceeded' USING ERRCODE='54000';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 IF manifest->>'state' IS DISTINCT FROM 'prepared' OR p_intent IS DISTINCT FROM manifest->'intent' THEN
  RAISE EXCEPTION 'resource final intent mismatch or repeated final clock' USING ERRCODE='42501';
 END IF;
 expected:=manifest->'native_epochs';
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'resource native epoch manifest missing' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(k),ARRAY[]::text[]) INTO keys FROM jsonb_object_keys(expected) k;
 count_rows:=cardinality(keys);
 IF count_rows>4096 OR count_rows>p_rows THEN
  RAISE EXCEPTION 'resource final epoch budget exceeded' USING ERRCODE='54000';
 END IF;
 -- Отсутствие exact epoch не превращается в нулевую revision. Prewait уже
 -- закрепил каждый ключ и его gap; здесь не INSERT и не FOR SHARE/UPDATE.
 SELECT coalesce(jsonb_object_agg(k,CASE WHEN e.key IS NULL THEN 'null'::jsonb
  ELSE jsonb_build_array(e.generation,e.revision) END),'{}'::jsonb)
 INTO actual FROM unnest(keys) k LEFT JOIN kaname.authority_policy_epoch e ON e.key=k;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'resource native source changed' USING ERRCODE='P1034';
 END IF;
 at_time:=clock_timestamp();
 IF manifest->'intent'->>'kind'='object' THEN
  materialized:=kaname._authority_resource_object_materialize_v2(manifest->'object_certificate',
   manifest->'object_effects',manifest->'object_sources',manifest->'object_audit_reservations',
   (manifest->>'transaction_at')::timestamptz,at_time);
  -- Чистая финальная сборка не расширяет preclock maximum: обе TTL ветви
  -- заранее закрыли все logical/physical waits и возможные scope keys.
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final object effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',
   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',
   object_outbox_write_ordinals=materialized->'object_outbox_write_ordinals',
   object_step_obligations=materialized->'step_obligations';
 ELSIF manifest->'intent'->>'kind'='crud' THEN
  PERFORM kaname._authority_crud_manifest_domain_v3(manifest);
  materialized:=kaname._authority_resource_crud_materialize_v3(manifest->'intent',
   manifest->'registration_certificate',manifest->'registration_sources',
   manifest->'registration_body',(manifest->>'transaction_at')::timestamptz,at_time);
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized#>'{program,commands}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'CRUD private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final CRUD effect exceeds preclock physical maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSIF coalesce(manifest->'intent'->>'Action','') IN ('1','2','3','4','5') THEN
  IF manifest->'intent'->>'Action'='5' THEN
   -- A verified negative audit has no installation/native permission to grant.
   -- Its exact one-row body was derived and protected before the final clock.
   IF manifest#>'{registration_authority,refusal_only}' IS DISTINCT FROM 'true'::jsonb
   OR manifest#>'{registration_authority,accounts}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_authority,native_epochs}' IS DISTINCT FROM '{}'::jsonb
   OR manifest#>'{registration_body,writes}' IS DISTINCT FROM '[]'::jsonb
   OR manifest#>>'{registration_certificate,action}' IS DISTINCT FROM '5'
   OR manifest#>>'{registration_body,program,commands,0,kind}' IS DISTINCT FROM 'refusal_audit'
   OR jsonb_array_length(manifest#>'{registration_body,program,commands}') IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'refusal final audit-only invariant invalid' USING ERRCODE='42501';END IF;
  ELSE
   PERFORM kaname._authority_resource_registration_authority_final_v2(manifest->'registration_authority',at_time);
  END IF;
  materialized:=manifest->'registration_body';
  IF manifest->'intent'->>'Action'='2' THEN
   materialized:=kaname._authority_resource_unregistration_materialize_v2(
    materialized->'source_index',materialized->'verified',materialized->'catalog',materialized->'direct',
    materialized->'maximum',materialized->'current',materialized->'reservations',
    (manifest->>'transaction_at')::timestamptz,at_time);
   PERFORM kaname._authority_resource_unregistration_operation_acl_v2(
    manifest#>'{registration_body,acl}',(manifest->>'invoker_oid')::oid,materialized->'cleanup_program');
   materialized:=materialized||jsonb_build_object('acl',manifest#>'{registration_body,acl}');
  END IF;
  IF jsonb_typeof(materialized->'writes') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'physical') IS DISTINCT FROM 'object'
  OR jsonb_typeof(materialized->'program'->'commands') IS DISTINCT FROM 'array'
  OR jsonb_typeof(materialized->'step_obligations') IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'registration private materialization missing' USING ERRCODE='42501';END IF;
  FOR entry IN SELECT value FROM jsonb_array_elements(materialized->'writes') LOOP
   FOREACH field IN ARRAY ARRAY['epoch_write_keys','epoch_share_keys','source_guard_write_keys','source_guard_read_keys',
    'binding_epoch_write_scopes','binding_epoch_share_scopes','deferred_carrier_roles'] LOOP
    actual_keys:=kaname._authority_resource_key_array_v2(entry->field,field LIKE 'binding_epoch_%');
    held_keys:=kaname._authority_resource_key_array_v2(manifest->field,field LIKE 'binding_epoch_%');
    IF field IN ('epoch_share_keys','source_guard_read_keys','binding_epoch_share_scopes') THEN
     held_keys:=held_keys||kaname._authority_resource_key_array_v2(manifest->(CASE field
      WHEN 'epoch_share_keys' THEN 'epoch_write_keys' WHEN 'source_guard_read_keys' THEN 'source_guard_write_keys'
      ELSE 'binding_epoch_write_scopes' END),field LIKE 'binding_epoch_%');
    END IF;
    IF NOT actual_keys<@held_keys THEN
     RAISE EXCEPTION 'final registration effect exceeds preclock maximum' USING ERRCODE='42501';END IF;
   END LOOP;
  END LOOP;
  IF manifest->'intent'->>'Action'<>'5' THEN
   PERFORM kaname._authority_resource_registration_sequence_final_v3(materialized,at_time);
  END IF;
  UPDATE pg_temp.kaname_authority_resource_manifest SET writes=materialized->'writes',registration_body=materialized,
   registration_program=materialized->'program',registration_physical=materialized->'physical',
   registration_step_obligations=materialized->'step_obligations',
   registration_outbox_write_ordinals=materialized->'registration_outbox_write_ordinals';
 ELSE
  RAISE EXCEPTION 'resource final intent compiler unavailable' USING ERRCODE='42501';
 END IF;
 UPDATE pg_temp.kaname_authority_resource_manifest SET state='final',decision_at=at_time;
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 UPDATE pg_temp.kaname_authority_consumer SET finalized=true;
 RETURN QUERY SELECT at_time,count_rows,1;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_resource_unregistration_prepare_v2(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;source_index jsonb;verified jsonb;certificate jsonb;direct jsonb;plan jsonb;maximum jsonb;predicates jsonb;policy jsonb;
 current_state jsonb;reservations jsonb;body jsonb;compiled jsonb;required jsonb;operations jsonb;expected_accounts jsonb;expected_sources jsonb;
 audit_ids jsonb:='{}';audit_id text;key_value text;global_required boolean;source_required boolean;
 bundle_result record;catalog_result record;epoch_result record;current_result record;authority_result record;
 audit_result record;reconcile_result record;subject_result record;relation_result record;
 sequence_body jsonb;used_rows integer:=0;used_reads integer:=0;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' NOT IN ('resource_pending','resource_source_pending')
 OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
 OR to_regclass('pg_temp.kaname_authority_resource_manifest') IS NOT NULL THEN
  RAISE EXCEPTION 'cleanup compiler requires fresh pending RC admission' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows<1 OR p_rows>100000 OR p_reads IS NULL OR p_reads<1 OR p_reads>4096
 OR jsonb_typeof(p_envelope) IS DISTINCT FROM 'object' OR octet_length(p_envelope::text)>67108864
 OR p_envelope#>>'{intent,Action}' IS DISTINCT FROM '2' THEN
  RAISE EXCEPTION 'cleanup compiler input invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO STRICT bundle_result FROM kaname._authority_resource_bundle_catalog_v2(p_rows,p_reads);
 used_rows:=used_rows+bundle_result.logical_rows;used_reads:=used_reads+bundle_result.logical_reads;
 SELECT * INTO STRICT catalog_result FROM kaname._authority_resource_catalog_wait_v2(p_envelope->'catalogs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+catalog_result.logical_rows;used_reads:=used_reads+catalog_result.logical_reads;
 source_index:=kaname._authority_resource_capture_index_v2(p_envelope->'sources',100000);
 verified:=kaname._authority_resource_unregistration_certificate_v2(source_index,bundle_result.catalog,catalog_result.catalog_rows,p_envelope->'catalogs',p_envelope);
 certificate:=verified->'certificate';
 direct:=kaname._authority_resource_unregistration_direct_program_v2(source_index,verified,transaction_timestamp());
 plan:=kaname._authority_resource_unregistration_operation_maximum_v2(verified,direct);
 source_required:=plan->'source_effects'='true'::jsonb;
 IF (proof->>'consumer_profile'='resource_source_pending') IS DISTINCT FROM source_required THEN
  RAISE EXCEPTION 'cleanup SOURCE classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('kind',effect.kind,'id',effect.id) ORDER BY effect.kind COLLATE "C",effect.id COLLATE "C"),'[]'::jsonb)
 INTO expected_sources FROM (
  SELECT 'binding'::text kind,k id FROM jsonb_object_keys(verified->'changed_bindings') k
  UNION ALL SELECT 'role',k FROM jsonb_object_keys(verified->'changed_roles') k) effect;
 IF coalesce(nullif(p_envelope->'source_effects','null'::jsonb),'[]'::jsonb) IS DISTINCT FROM expected_sources THEN
  RAISE EXCEPTION 'cleanup SOURCE write census differs' USING ERRCODE='P1034';END IF;
 maximum:=kaname._authority_resource_unregistration_maximum_v2(source_index,verified,direct,catalog_result.catalog_rows,plan,p_envelope->'native_guards');
 required:=maximum->'required';predicates:=kaname._authority_resource_predicate_maximum_v2(source_index,required);
 policy:=(predicates->'policy_epochs')||(maximum->'policy_epochs');maximum:=jsonb_set(maximum,'{policy_epochs}',policy);
 global_required:=(maximum->>'global')::boolean OR (predicates->>'global')::boolean;
 IF global_required IS NULL OR (proof->>'mode'='global') IS DISTINCT FROM global_required THEN
  RAISE EXCEPTION 'cleanup complete mutation classification changed' USING ERRCODE='P1034';END IF;
 SELECT coalesce(jsonb_agg(q.key ORDER BY q.key COLLATE "C"),'[]'::jsonb) INTO expected_accounts FROM jsonb_object_keys(maximum->'accounts') q(key);
 IF NOT global_required AND (expected_accounts='[]'::jsonb OR proof->'accounts' IS DISTINCT FROM expected_accounts) THEN
  RAISE EXCEPTION 'cleanup complete mutation accounts changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT epoch_result FROM kaname._authority_resource_epoch_wait_v2(maximum->'source_guards',policy,
  maximum->'binding_epochs',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+epoch_result.logical_rows;used_reads:=used_reads+epoch_result.logical_reads;
 SELECT * INTO STRICT current_result FROM kaname._authority_resource_required_reread_v2(source_index,required,
  maximum->'write_sources',p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+current_result.logical_rows;used_reads:=used_reads+current_result.logical_reads;
 IF current_result.predicate_protections IS DISTINCT FROM predicates->'protections' THEN
  RAISE EXCEPTION 'cleanup current predicate maximum changed' USING ERRCODE='P1034';END IF;
 SELECT * INTO STRICT authority_result FROM kaname._authority_resource_registration_authority_wait_v2(
  p_envelope,certificate,bundle_result.model_source,epoch_result.lock_witness,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+authority_result.logical_rows;used_reads:=used_reads+authority_result.logical_reads;
 FOR audit_id IN SELECT jsonb_array_elements_text(verified->'withdrawal_audit_ids') LOOP
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END LOOP;
 audit_id:=NULL;
 IF plan->'audit_possible'='true'::jsonb THEN
  audit_id:=certificate->>'audit_id';
  IF coalesce(audit_id,'') !~ '^evt_[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{20,30}$' OR audit_ids ? audit_id THEN
   RAISE EXCEPTION 'cleanup root audit reservation invalid' USING ERRCODE='42501';END IF;
  audit_ids:=audit_ids||jsonb_build_object(audit_id,true);
 END IF;
 IF audit_ids<>'{}'::jsonb THEN
  SELECT * INTO STRICT audit_result FROM kaname._authority_resource_audit_capture_wait_v2(audit_ids,p_rows-used_rows,p_reads-used_reads,true);
 ELSE SELECT '[]'::jsonb lock_witness,0 logical_rows,0 logical_reads INTO audit_result;END IF;
 used_rows:=used_rows+audit_result.logical_rows;used_reads:=used_reads+audit_result.logical_reads;
 SELECT * INTO STRICT reconcile_result FROM kaname._authority_resource_reconcile_wait_v2((plan->>'reconcile_count')::integer,p_reads-used_reads);
 used_reads:=used_reads+reconcile_result.logical_reads;
 IF (verified->>'withdrawal_subject_count')::integer>0 THEN
  SELECT * INTO STRICT subject_result FROM kaname._authority_resource_subject_change_wait_v2((verified->>'withdrawal_subject_count')::integer,p_reads-used_reads);
 ELSE SELECT '[]'::jsonb reserved_ids,'[]'::jsonb held_relations,'[]'::jsonb held_advisory,0 logical_reads INTO subject_result;END IF;
 used_reads:=used_reads+subject_result.logical_reads;
 operations:=(maximum->'operations')-ARRAY['resource_reconcile_outbox','subject_change_outbox'];
 SELECT * INTO STRICT relation_result FROM kaname._authority_resource_physical_relations_capture_v2(operations,p_reads-used_reads,true);
 used_reads:=used_reads+relation_result.logical_reads;
 reservations:=jsonb_build_object('audit_id',audit_id,'audit_ids',verified->'withdrawal_audit_ids',
  'subject_ids',subject_result.reserved_ids,'reconcile_ids',reconcile_result.reserved_ids);
 current_state:=kaname._authority_resource_unregistration_current_v2(source_index,maximum,direct);
 body:=jsonb_build_object('source_index',source_index,'verified',verified,'catalog',bundle_result.catalog,'direct',direct,
  'maximum',maximum,'current',current_state,'reservations',reservations,'acl',relation_result.acl_capabilities);
 IF used_rows>p_rows OR used_reads>p_reads THEN RAISE EXCEPTION 'cleanup aggregate prewait exceeded' USING ERRCODE='54000';END IF;
 compiled:=jsonb_build_object('intent',p_envelope->'intent','certificate',certificate,'sources',jsonb_build_object('required',required),
  'program',plan,'authority',authority_result.authority,'body',body,'maximum',maximum,'epoch_witness',epoch_result.lock_witness,
  'catalog_rows',catalog_result.catalog_rows,
  'held_relations',relation_result.lock_witness||reconcile_result.held_relations||subject_result.held_relations,
  'held_advisory',(epoch_result.lock_witness->'held_advisory')||audit_result.lock_witness||reconcile_result.held_advisory||subject_result.held_advisory);
 -- Только server-verified frozen inputs; предварительные часы — placeholder
 -- для формы. Authority/fold decision остаётся у единственного finalizer.
 sequence_body:=kaname._authority_resource_unregistration_materialize_v2(source_index,verified,bundle_result.catalog,direct,
  maximum,current_state,reservations,transaction_timestamp(),transaction_timestamp());
 used_reads:=used_reads+kaname._authority_resource_registration_sequence_prepare_v3(sequence_body,2,p_reads-used_reads);
 PERFORM kaname._authority_resource_registration_store_v2(compiled);
 RETURN QUERY SELECT used_rows,used_reads;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_crud_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record;owner_oid oid;trigger_counts jsonb;trigger_count bigint;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a
  WHERE a.attrelid='kaname.users'::regclass AND a.attname='expected_login_kind'
   AND NOT a.attisdropped AND a.attgenerated='s' AND a.atttypid='pg_catalog.name'::regtype) THEN RETURN false;END IF;
 -- ACL typed-entry читается в том же statement и только при обращении к CTE;
 -- строгая подпись и правила экспортного EXECUTE остаются прежними.
 IF EXISTS(WITH typed_entry_exec_acl AS MATERIALIZED (
  SELECT g.grantee FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
  WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
   AND g.privilege_type='EXECUTE'
 ) SELECT 1 FROM (VALUES
 ('_authority_native_write_weights_v4(jsonb)','907111b7e806c46a660311a6a97fcc2ab2f86ea0430260fb501306f0e2ef522e',true,'s',true,'private'),
 ('_authority_native_write_closure_v4()','a6da6a23e1899bf23d71ba4c5969f66cdfe15a4038fb9a89223df803b74c0e14',true,'s',true,'private'),
 ('authority_native_write_arm_v4(uuid)','ec1e1600c2673f4d02947f7dca7b4a719abc794a91d0045bad38fc2c642e5638',true,'v',true,'export'),
 ('authority_native_write_read_v4()','f6a0242967e246de3f3d305655783afd29ed8bef4f4e8d95a8821c965aa33e9c',true,'v',true,'export'),
 ('authority_native_delete_batch_read_v4()','79e71a95aac2ded09885f8c65165ad8ac169ef3b7f09bbda82a11ce1baec80f9',true,'v',true,'export'),
 ('_authority_native_delete_batch_begin_v4()','d5f062e5543ded46945e843444184aed9f958ee776d63413095cc98c0ad5bd10',true,'v',true,'private'),
 ('_authority_native_delete_batch_end_v4()','3b8173b76b57f85ae4f73287e25b6e143a40c72a13d1423bf6ee218fa04d65fa',true,'v',true,'private'),
 ('_authority_native_delete_batch_graph_v4()','7b70a67aa67a72d2bf2a1136bf0477cda6239ef79b6ace61e4b2e6d8f3f841e6',true,'s',true,'private'),
 ('authority_native_delete_emit_v4(jsonb[])','3e36607d0fad78d6e89bf4b1d8212b939225c87f95bdfd0643020d5bb2933c1b',false,'v',true,'export'),
 ('authority_native_delete_prepare_v4(jsonb[])','b25ff1292dbced07ecffa2be2f736411cc61a3bf75dbcacd879ceeb01bc719cf',true,'v',true,'export'),
 ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','bed995919371e883bb0d88698a79f8d634c453068c4caab199d7a76cf026088c',true,'v',true,'export'),
 ('authority_forward_emit_v4(jsonb[])','d41825e5a57dbdc4f78b630f19877f54e94303e6fefc2b79b10e483fc6dd65e3',false,'v',true,'export'),
 ('authority_forward_prepare_v4(jsonb[])','8bfb60e9ff8c301d79c11215fdaac99c8788a78c920cae86182115bdc8e90d74',true,'v',true,'export'),
 ('authority_forward_claim_v4(uuid)','8a7c8ee8eae47a467c0d3370ef6185e93f3db6138aa14319563990fabd3b7be7',true,'v',true,'export'),
 ('authority_forward_finish_v4(uuid)','75683ffd52d23834a7e28814676b67a06d47cfa5a4fd2c2049d5f299f4c00199',true,'v',true,'export'),
 ('_authority_forward_context_v4()','67a9f0c6d896048f52b3eeb396250c7e33e16ab3170b874734154197d247dd5c',true,'v',true,'private'),
 ('_authority_forward_custody_v4()','c5d84795becb1a5b12efc89bb553ac12db864c5ce31c90272041b15a09cd59b4',true,'v',true,'private'),
 ('_authority_forward_shape_v4()','ef281d009e6201f0c03e49cfc049b4950290fe1953bb05b3638536b45b0d66aa',true,'v',true,'private'),
 ('_authority_forward_program_v4(uuid)','d1100eb62bfc267ed7cc58d4d0cd0194f42b6285f8f465939381b60161607cca',true,'v',true,'private'),
 ('_authority_forward_row_v4(bigint,jsonb,boolean)','31eb7a5ae8eec2af1f31d7aa9e55d49c80e787838ec3a34130de6db4b3dcc56f',true,'v',true,'private'),
 ('_authority_forward_complete_v4(uuid)','06cfcd8f144243fc529aacba57f452b0913cc6d5b1ab6bf2daf7c4e6a9a38290',true,'v',true,'private'),
 ('_authority_forward_anchor_complete_v4()','0d9fdf6c02abe69e333b5584eee4628cafb7ec37849b7820e33aba4bea4396f1',true,'v',true,'private'),
 ('_authority_forward_storage_v4()','e8a9cd61f6ee6cc4fbde7361210cf493c8df166cdf3bfd8c49ed47190aa4ef0c',true,'s',true,'private'),
 ('_authority_group_add_program_v3()','e78556f1ccd014face052206b727651ce7e238bc9c3706f5a8d65f1f6559cce4',true,'v',true,'private'),
 ('authority_group_add_prepare_v3(jsonb,integer,integer)','ffe5527b2aed54dd69fa79b366c3717044cafdc98bed16f4c8ed9d39702d606e',true,'v',true,'export'),
 ('authority_group_add_finalize_v3(jsonb,integer,integer)','21d1ddc68b3e1cbf4bdbaabb6038c5bff865e7439420bd96c5e41590c91370dc',true,'v',true,'export'),
 ('_authority_group_add_row_v3(text,text,jsonb,jsonb)','a5973b00860baf37167efaf588cd3f3fe492248214708e3db6fa94ad7367590a',true,'v',true,'private'),
 ('_authority_group_add_statement_v3(text,text)','b2bad5333c59b9db498767c0a6546c089633f849799ab87efa991183ee799b11',true,'v',true,'private'),
 ('authority_group_add_fold_v3(text,jsonb,timestamptz)','cb582cd47c5e210fa7f4c4a4c0a211ba1b120b455ce9a868a453d05335a2d1ef',true,'v',true,'export'),
 ('authority_group_add_subject_id_v3()','bde80ceb4ed141b31a755dadb40e653acf46e9c89171b1bc93b2ac5f7916300e',true,'v',true,'export'),
 ('_authority_group_add_subject_v3(text,text,jsonb)','93f1e1147874032a6e7f4e1c08ad7651148e6ec5f25da7ffc2486d234ae14a8c',true,'v',true,'private'),
 ('_authority_group_add_complete_v3()','158eca8cc62068a844f08ce5f746ad909a504fb429567d11c30d6f496dcd17eb',true,'v',true,'private'),
 ('_authority_group_add_storage_v3()','123966ac8ae04e91375122a48bc6c07c8c48bda2791a763d779f00e506ff81fc',true,'s',true,'private'),
 ('relation_fact_fold_row(text,jsonb,timestamptz)','d22d72ceba1dabe7edc7ff3c197c42ed92beacd87aed68add50aa99150a1d067',false,'v',false,'preserve'),
 ('authority_subject_change_id_guard_v2()','aa4bc39730f137bdf11491afaf41d9c8451c88e2cda40358fc0e33be2f29cb53',true,'v',true,'private'),
 ('authority_subject_change_applied_v2()','fa776df6d3b95dadb13fa1684424b2db105b21f5b8862bd045680fb8129d094e',true,'v',true,'private'),
 ('authority_subject_change_statement_guard_v2()','600129602604e3cac17840ff155738e5c886677cd8be781b62b9b29f2fe785b0',true,'v',true,'private'),
 ('relation_fact_from_journal()','604d827358eab2f756c0c53d9a65cfbaf31b3f5d19ff8adc6e3dab944e8fa70a',false,'v',false,'preserve'),
 ('authority_protocol_grant_runtime(regrole)','94ae2c19e29b666c57be670abf65ae931c36af865d31844aec44998df68939a5',false,'v',true,'preserve'),
 ('authority_binding_command_begin_v3(jsonb)','39696919bfed78731817c77a37920e661801933c5ac544bc26ea5603a7fa39b1',true,'v',true,'export'),
 ('authority_binding_command_end_v3(jsonb)','2c9ee43be689f773c543fc800645f2aae482ec02d392fd28937efa50558915b2',true,'v',true,'export'),
 ('authority_binding_command_audit_v3(jsonb)','93c1bfc6bd6b753868e68ff6e408089f701d189ed6e7c30a32c7998baade872f',true,'v',true,'export'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','62483d22c74491cc60dcbc011c5517f743b3a764dc91a48fa8628ce31bfadcd4',true,'v',true,'private'),
 ('authority_policy_changed()','46a479262309d1ab8cd6efd41ea519921eb57c13ca7b5054ce6550aba366371d',true,'v',true,'preserve'),
 ('authority_audit_id_guard_v2()','a349a4a051b336afdec4cb5422edf5738fe4e354acec98163abc0d4a2c70d8f2',true,'v',true,'preserve'),
 ('authority_audit_applied_v2()','b43a45a017d3b646301d3b0eb746d46ae7ee7d3a0539b2c8b91600c5a4c697a3',true,'v',true,'preserve'),
 ('authority_audit_statement_guard_v2()','cc9fd152b1c8fa68a65eb6451baf977a12b0866cc52668254280265f10f9271c',true,'v',true,'preserve'),
 ('membership_mirror_from_user()','d763127654c0d5852aee7f86d8c5f5ea4fa89464c7f1e3c7df9efbace4e6c405',false,'v',false,'preserve'),
 ('_authority_resource_before_write_v3(jsonb,text,text,jsonb,jsonb)','10cfd5fcbe108b1f0b62f688d7ae80b72e34a536593fae3343c730cc0cb82da5',true,'v',true,'private'),
 ('_authority_resource_effect_applied_v2()','759a821396ab5850fd5aac25756c0403129d685aec1aa7e7f63bf95c8126f136',true,'v',true,'private'),
 ('_authority_resource_write_v2(jsonb,text,text,jsonb,jsonb)','cdb26211660f6fc89ee193516c9bc7cfa3e3bdcd427d3cf71c17c4a047272c2f',true,'v',true,'private'),
 ('_authority_resource_side_v2(jsonb,text,text,text,jsonb)','09f8a713bf8e2a59ec0051910a49f5df93dec5bc5c776271c2f1a54dbb1eb8f1',true,'v',true,'private'),
 ('_authority_crud_anchor_capture_v3(jsonb,integer,integer)','2dee8b172ebd3b228b5c6cc4dec189feae30db2c1c9a4bc98752525025d823c7',true,'s',true,'private'),
 ('_authority_crud_authority_graph_v3(jsonb,jsonb,integer,integer)','3ce64fcc9997385efdac3a546dc44ab66e0b5022ec5d9cb5de8d5bfdcffaec9d',true,'s',true,'private'),
 ('_authority_crud_aux_capture_v3(jsonb,jsonb,integer,integer)','cbe93565f4de42904c6a0e2434db9a21ce0d528902d2a3908a2fec92cb821318',true,'s',true,'private'),
 ('_authority_crud_aux_write_v3()','5b549be379610152a2c2efc86836606fb82c298d885be0125cee3b535cf8cd32',true,'v',true,'private'),
 ('_authority_crud_aux_images_v3(jsonb,jsonb,jsonb,timestamptz)','f7cf945fa67c0bf19182121b6e31655f1939257dabac972618a15cd6fa9eda8b',true,'i',true,'private'),
 ('_authority_crud_aux_statement_v3()','8d2c6a5f46066b400d9c42c158a337eb784a405c895145beedc7205133be7bc6',true,'v',true,'private'),
 ('authority_resource_crud_capture_v3(jsonb,integer,integer)','4ed7f709885d233f48bfd4ff0ced2cabf6b0ec6db07906156530bb6120391f32',true,'s',true,'export'),
 ('_authority_crud_merge_tables_v3(jsonb,jsonb)','beb1fb11dc689c0b6e22411c4edd3ac6025b76fa6bdb74f49bad95b27fa9c1ae',true,'i',true,'private'),
 ('_authority_crud_capture_v3(jsonb,integer,integer)','794f687a5c86e36d6ff91984e7942497dc6765fa3c9c685b514ac8a406cf8182',true,'s',true,'private'),
 ('_authority_crud_cascade_capture_v3(jsonb,integer,integer)','a155c5bf5c0d2e81b9b2b2d3d85f5cb234a3cc162585041237c4e9f6257fd73c',true,'s',true,'private'),
 ('authority_resource_crud_body_values_v3()','d7440d3bbf47f4dbc2b8e254cdfc248b1d79d6dd839de9fb2243e8fc4d76158b',true,'v',true,'export'),
 ('_authority_crud_step_complete_v3(jsonb,integer)','6a1951e0f4eb8b4dcd3a417f68938ac5e4771f04b1cf085938994dc45130e146',true,'v',true,'private'),
 ('authority_resource_crud_step_v3(text,jsonb)','51b2b069757a6860df25f6dcc47558881ce21accf0a5b2ce0f813cd55d37aa50',true,'v',true,'export'),
 ('authority_resource_crud_lock_held_v3(text)','2101acd7137f106b763dbdccf69f7f257ccd8650bc89e7f1d191132fffb51f6f',true,'v',true,'export'),
 ('_authority_crud_require_completion_v3(jsonb)','9a9d56a95bbb255d52eeddf6c07a6f5e5663490ded6d8a558d097848a885d75c',true,'v',true,'private'),
 ('_authority_crud_command_v3(text,jsonb)','c5002541ff2bbabedbcd9d74b6adc04b13a6a36833eefd1631f875d47652eb75',true,'i',true,'private'),
 ('_authority_crud_structural_v3(text,text,text,text)','00d37afb9a7b7c9d4534df79f313c14e13fc16a1756d368d85ca2e5f4d939c13',true,'i',true,'private'),
 ('_authority_crud_command_plan_v3(jsonb,jsonb)','ea252acb7bcebc7c96da591416609deb3b606d01eeda6a3a32e911a0e77af3d1',true,'i',true,'private'),
 ('authority_resource_assert_body_v2(jsonb)','3c9b0e789716d0e0c9d50e98b80ea7e90746703425e13dc92246b210d5c68410',true,'v',true,'preserve'),
 ('_authority_resource_require_completion_v2()','bbcfca0b3d5ff59ad273695dfed2451f1ff37bf4030f8f7083415396dafee0e6',true,'v',true,'preserve'),
 ('authority_resource_fold_body_v2(text,jsonb,timestamptz)','3eb8735862b7643f353c9e10312c2fe9ca251489f875c1faf30289f3d166b5d9',true,'v',true,'preserve'),
 ('authority_resource_prewait_v2(jsonb,integer,integer)','e835d0c4f015334d151c7a902e7cb5c10a8f7d5d2ee2c4d6fad478bd558e5f83',true,'v',true,'preserve'),
 ('_authority_crud_image_v3(integer,text,text,jsonb,jsonb,boolean)','967a84fb10617c3a5f376d63aaf2903538edc5fe1548150b307bae33a70ee3f9',true,'i',true,'private'),
 ('_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)','2e4cf1562674897a696483469505925ba5862b6fe0422f663b330eb96f237b9e',true,'i',true,'private'),
 ('_authority_crud_intent_v3(jsonb)','e62f470c0c69a980308bec36a35f515609cb8fea56c79ec7632ac654a43e0f49',true,'i',true,'private'),
 ('_authority_crud_manifest_domain_v3(jsonb)','72c12f24e9c426b44fcc41b7690423a30675175589cd2ea6554beb48ad555387',true,'v',true,'private'),
 ('_authority_crud_fga_rows_v3(jsonb,text,jsonb,integer,timestamptz)','d84adbcbed2a7a07b7080ddd83eaab375144edbdbb4b4ad9c50ffce92012fc5c',true,'i',true,'private'),
 ('authority_crud_fga_id_guard_v3()','cc6115bf7fafa0e7a70da14aa14db4232644f3a10d1ba34b1df131d93c616a49',true,'v',true,'private'),
 ('authority_crud_fga_id_applied_v3()','12aadb134df61a6f55b28252be5d22773e70f7b75f0a2117577faa2565a99594',true,'v',true,'private'),
 ('_authority_crud_fold_capture_v3(jsonb,integer,integer)','4324197370450be1edcfc6de9b822fd24e838932135c2c3861c438fa62fe5149',true,'s',true,'private'),
 ('_authority_crud_fold_images_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','c64f0e0be50cf2b6954b4912201dd238acf768d31eb26578b4155c1f0f697b03',true,'i',true,'private'),
 ('_authority_crud_graph_index_v3(jsonb,jsonb,jsonb)','6402a8ddbf72280f803ced92f33536a500e49252d15159223bd8bafa98c694dd',true,'i',true,'private'),
 ('_authority_crud_journal_capture_v3(jsonb,jsonb,integer,integer)','0e1271f048a93d4632fc6e30346b1a10682e619b4077405048a495840c199fda',true,'s',true,'private'),
 ('authority_resource_crud_journal_value_v3(jsonb,jsonb)','801f9974286e1bd23fb9559e5abf3da66c3fa9ebfd18f27fb18984b0762c6e0d',true,'v',true,'export'),
 ('authority_crud_journal_applied_v3()','d8238730f4bb3d9754ddc7108ad4dc70b348494f51b2dea1567b06cd69e9c7e2',true,'v',true,'private'),
 ('_authority_crud_journal_plan_v3(jsonb,jsonb,jsonb)','e8af1dadee7c4d3e8bf7790a0464ac9c8319bbaac789bb15aec5ef4ceeb56ea6',true,'i',true,'private'),
 ('_authority_crud_journal_rows_v3(jsonb,jsonb,timestamptz)','e37fb29c6f7ff41ab6c0d15c3dfc0da196e7177c36dc848e0dc304b445d14a80',true,'i',true,'private'),
 ('_authority_crud_unique_key_v3(text,jsonb)','b7407a60f467821e6fe19c697ea37079807dbd5bed88c51a4ad645de731cf5b3',true,'i',true,'private'),
 ('authority_crud_unique_guard_v3()','5e8dbb8ba000bde51e8aa64c8e2fb708666f4822bb677a059adc623b0b45eb7d',true,'v',true,'private'),
 ('_authority_crud_sequence_wait_v3(text,integer,integer)','3b40419c3cbb8e156a2926933f7d7075a93129fa34c2294122dcd04f9cf76edf',true,'v',true,'private'),
 ('authority_crud_sequence_guard_v3()','4132523d01f6ddd5e893fa0c21ad9c2c944009dc8e968dc7228e5de3e8bf9ce0',true,'v',true,'private'),
 ('_authority_crud_key_maximum_v3(jsonb,jsonb,jsonb,jsonb,timestamptz)','e3ad0cc2300061a6630225ec8956cee4b552f4ff8d9c1804f0dbfb5af0b12692',true,'i',true,'private'),
 ('_authority_crud_lock_rows_v3(jsonb)','e04ceccbff7121da453fc79b071db7d7c3f54b8425cda74f53520143641a22d9',true,'i',true,'private'),
 ('_authority_crud_lock_plan_v3(jsonb,jsonb,jsonb,timestamptz)','85bef48d34921afb7fd0659fe6554288f47db763cd0c872dcaa92cb713065d85',true,'i',true,'private'),
 ('_authority_crud_manifest_images_v3(jsonb,jsonb,jsonb,jsonb)','f1fc57972e2b2575a0a323090cc8560ad975b5d4a7f061a8b28faa2ab6ba6784',true,'i',true,'private'),
 ('_authority_resource_crud_materialize_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','b3e2ac3c0942fa7957aa6ecb234c39b388dc80881cdd23545c774cfd05112dff',true,'i',true,'private'),
 ('_authority_crud_maximum_v3(jsonb,jsonb)','62f166faf92695eccfc65f5e979ac33b7610a9fb0b640274a361300039541ce0',true,'i',true,'private'),
 ('_authority_crud_pack_v3(jsonb,jsonb,jsonb)','ab5603fc90f193b60e06d29823842f43967d1515ba1d3eaca6fbde97099d6c6c',true,'i',true,'private'),
 ('_authority_crud_physical_v3(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','81c8fd09ea95dd337e3d56928513de55a24eeb981695185c58c1db06f6c06f24',true,'i',true,'private'),
 ('_authority_resource_crud_prepare_v3(jsonb,integer,integer)','ee22d1a0007376a262864613f3cef81893f76d70f2ceae94fe2e672273914aa4',true,'v',true,'private'),
 ('_authority_crud_relation_wait_v3(jsonb,jsonb,jsonb,integer)','424927c26adc58d65a55a4567766054c378f1340662d0401146e5e2dac2f0bad',true,'v',true,'private'),
 ('_authority_crud_reserve_v3(jsonb,jsonb,jsonb,integer,integer)','a9e7a60de752dcf436571f457c67de751439e77276005238dab9abed9ef9049b',true,'v',true,'private'),
 ('_authority_crud_scope_capture_v3(jsonb,integer,integer)','7cd250c6e17d5c41737c1afebca7576744bae05ec46af01136678c515e23f5e5',true,'s',true,'private'),
 ('authority_protocol_statement_guard()','e188d77b0c72ec88024fb6ab264e2ae639679213ff727b5c61946dfde596bdad',true,'v',true,'preserve'),
 ('_authority_resource_crud_store_v3(jsonb)','b3c4cf46195b7a32a2454911b29c8ea51a0e37741ca98380890e911f4e765135',true,'v',true,'private'),
 ('_authority_crud_tuple_wait_v3(text,jsonb,boolean,integer,integer)','8ebecbc122a5558910017569ac3ea927ad37ea4066dec179a253807b4c5d9574',true,'v',true,'private'),
 ('_authority_crud_unique_wait_v3(text,jsonb,integer,integer)','ded94e6b1bf461dfaf9753a2e71dc73f45f474826b1d7a2f950e097c455629b0',true,'v',true,'private'),
 ('_authority_crud_json_keys_v3(jsonb)','42d2e6afa061f7c443be4e75a6fe3742414583923d2929ba77250c45ccb239d3',true,'i',true,'private'),
 ('_authority_crud_write_metadata_v3(jsonb,jsonb,jsonb)','7bdfa746b1066e54eccfffa3067fa923b09a1364d883c444b19dc5c873181af4',true,'i',true,'private'),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true,'v',true,'preserve'),
 ('authority_grant_mutation_preflight(text)','8ef00bb883b777d2abf07b0f43589dbd5fad7ac01c9bae8b3f22821e549060e8',true,'v',true,'preserve'),
 ('_authority_binding_scope_tier_v3(text,jsonb,jsonb)','81cacba8227f605eaf666624c9ceae52808ddc086b87d258bb33a95611a412bb',true,'i',true,'private'),
 ('_authority_binding_journal_v3(text,text,jsonb,jsonb,jsonb,integer)','9a34cb8196ba7de482bd9270115e1770a6210c9745b235703cb50cb6d0cbea34',true,'s',true,'private'),
 ('authority_binding_sequence_prepare_v3(text,jsonb)','bc276ed48b9a8e9d4eeb6cb472bfbda1a1a400dd8b34992f391f9423143272fc',true,'v',true,'export'),
 ('authority_binding_sequence_finalize_v3()','51e4b66f099b3b7c0a5f144af2ae540b5dbe72d00c52a170cfc7ec2e43f87fdb',true,'v',true,'export'),
 ('authority_binding_insert_stamp_v3(text)','0e37cf1836a1625f1c518c7c847cafe3da04ef9ef692db8c1c23fb27b40d1c71',true,'v',true,'export'),
 ('authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)','de942f0c6c21834ac9ecb177f4dce25e5c66c83101aaaf78bd23805ab04952a6',true,'v',true,'export'),
 ('_authority_binding_stage_snapshot_v3()','9e9d561435b0f86c51aec452283505184beee36e1dc02f4af708590955d2eebf',true,'v',true,'private'),
 ('authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)','efdbe3e491e0c3bd8ade664a61d8e049094cc5b781f7fe14347a94e2dd5979e6',true,'v',true,'export'),
 ('authority_binding_stage_sequence_finalize_v3(text)','cd285782054ce7720b1072484e7b24758bcae7f8b7c7a117556b9836c1299a18',true,'v',true,'export'),
 ('authority_installation_enter_v2(text)','9c008ba02cb19f92581324e2b9652fef0fd3555118f1fd5536e74c1a85c5eee8',true,'v',true,'preserve'),
 ('authority_reconcile_enter_v3()','905123661ed76a9f3da2f0374779e049cf2e89374fd4cf3c085c88555e32e013',true,'v',true,'export'),
 ('_authority_audit_binding_store_v3()','77412a99e3ea64432ee6ffe551d84ae7eae02bc2e0be1cbbe8e15941b407f595',true,'v',true,'private'),
 ('_authority_binding_mirror_store_v3()','94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61',true,'v',true,'private'),
 ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','e6dd22497757ec3e7362e45c6d5f4a45cd5ecf5b43714b6849143e5da1bf134a',true,'v',true,'private'),
 ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','8e4c9745f4df62265cb114849d1306493616a93049905a25f17c874dc0e35b9e',true,'v',true,'private'),
 ('_authority_binding_mirror_finalize_v3(text)','fe26d33c679cf15f72b04c243abff2c284fd2e5e35df1da58236cee3f826517e',true,'v',true,'private'),
 ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854',true,'v',true,'private'),
 ('authority_binding_epoch_lock(text[],jsonb)','621ce6546bd8a8fb0c64d73ba47b7094e8a8ddebcf0b76613d2896ebddb25d56',true,'v',true,'preserve'),
 ('_authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','41c8b30fb6b70b3dee28f7a54fa1e692784b63df7ade0c0d1f0dfa955883fe9a',true,'i',true,'private'),
 ('_authority_binding_stage_source_v3(jsonb,oid,integer)','e3bd8688c1e38e2124e21c9f15bcbab1c2aad809352aa0002835d3e888d5088d',true,'v',true,'private'),
 ('_authority_binding_stage_coordinates_v3(jsonb,text[],boolean,oid,integer,integer)','3b17c2eb7e40b1d5a6eb09af09fd0c1e9c5c4d8b4678e7537d94abad2e668c22',true,'v',true,'private'),
 ('authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)','c78567e12d9c2ac4dabed52f4ff57d538266787beadeba6c855bffe44281619f',true,'v',true,'export'),
 ('authority_binding_withdrawal_sequence_finalize_v3()','7ed02bf2fbfd3107060c4ca7815b99593d90400903676c8ccb32657d68511ea6',true,'v',true,'export'),
 ('authority_cluster_admin_preflight_v4(text,text,text)','dee9de21827355b15b060104dc7232b3f1e784eed23b074c24295ea6e2e40a0d',true,'v',true,'export'),
 ('authority_cluster_admin_preflight(text,text)','2bda979c851a1a59d5ba97dc79c2eff3a14c404f1e50ca7975638f4fafae9700',true,'v',true,'preserve'),
 ('_authority_metadata_preflight_body_v4(text,text,boolean,text)','d547aed450a42acf12a3e1a7f565a97dad4fec25a3ee30049e70275e4d261209',true,'v',true,'private'),
 ('_authority_sequence_freeze_v3(jsonb)','dbb50139a60af61a07690037c20b62c7d0b3dbf6a4cdff1e05307efca6836ef4',true,'v',true,'private'),
 ('_authority_sequence_bind_v3(jsonb,timestamptz)','4e8241c16905238f8f5064a12537cf5ee0892e596d89f2aa8d8a92f6dd31359c',true,'v',true,'private'),
 ('_authority_sequence_default_v3(text)','55bbb442c7aefc7e080eb6dc33b7255444438eb653d9d1f493986315aa8c3196',true,'v',true,'private'),
 ('authority_resource_journal_id_v3()','1890af3f773bb503aa2d4324c56ed4925c1ffac60d36181cc0d7c579f1e8ae18',true,'v',true,'export'),
 ('authority_fga_outbox_id_v3()','75b2ab0cad8f6111bca3dc5bd119f87dbbffa0dbed74480f172aa0f465b672bb',true,'v',true,'export'),
 ('authority_sequence_program_applied_v3()','6ccad306aa7cd3524f1d2f5e172efdac14f2df3fdde38569d022b5a95a555ccc',true,'v',true,'private'),
 ('authority_sequence_program_completion_v3()','055164a539031177a7605113484f5667702c9074b84d03ab1a827cd614b66e35',true,'v',true,'private'),
 ('_authority_sequence_expect_v3(text)','52e5bda884d0c1cec7bff0ae4843cd1490747432d1a44ee11a5648d6e905bcc2',true,'v',true,'private'),
 ('_authority_sequence_expected_v3()','e318cafb455438dd9a40e3c2cec7cc2d88daedf4307dd1e43248175005ab045b',true,'v',true,'private'),
 ('authority_sequence_expectation_complete_v3()','aef5c1e0bfa60d5587aa8c0f342b3f5df1166a1a699af56019f5bdf36e856c99',true,'v',true,'private'),
 ('resource_journal_emit()','76c8f397a387cb6699642e1d3aa56c2c61f371245eb28f56b14ed19c1d1faeba',false,'v',false,'preserve'),
 ('resource_journal_emit_member()','4dfca2c401a428e6b4ad984b99aae3a34404999ea36ed26b14c70b2ceb1d4053',false,'v',false,'preserve'),
 ('authority_sequence_origin_v3()','d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3',true,'v',true,'private'),
 ('authority_prepared_journal_value_v3(jsonb,jsonb)','b1e7156bf7176c0d30be0f64476e3b81748ff4a15dd27db29db17bca70598f46',true,'v',true,'export'),
 ('_authority_sequence_excluded_v3(oid)','eb4872a7f8c5bb7c40564e17fcc1928eac64bdbd8ac2e5609d261bd9ad36594b',true,'s',true,'private'),
 ('_authority_sequence_shape_v3()','614125faa823e6f14b0d2f58f2a6ed7ea9a5239febef2dd83b7ba4508f0f9014',true,'v',true,'private'),
 ('_authority_protocol_snapshot_v3()','f994c63975e86be78b2854a4f51aed55e615ad2c380b0f58fc1e0390662fc30a',true,'v',true,'private'),
 ('_authority_sequence_probe_v3()','2e2a3266993eadee820fba438960cde53cf25cd05a4e806661e8d62664f075c3',true,'v',true,'private'),
 ('_authority_sequence_header_v3()','375b51310e57a7016673ba26f5b9925d59e67a2599ba74fe9c11d3f5bf9c70f5',true,'v',true,'private'),
 ('_authority_sequence_publish_v3(jsonb)','013f8260baa0607516e57b791a92897d3d4bb143a401dd056166d1fbf70d3128',true,'v',true,'private'),
 ('_authority_sequence_store_v3()','adca627a6c7ce9b1ee755a231793134d5ebcc372f370c694cbac3f067fb471d2',true,'v',true,'private'),
 ('_authority_sequence_reserve_v3(text,jsonb,integer)','76e3ea26f6401f26ad25e168b0dc4399065648b354e7c8b96750a6d802128190',true,'v',true,'private'),
 ('_authority_sequence_select_v3(integer[],timestamptz)','7f9ce472e9d23f7a6182685661f2964bdc0266fefe1a59b9228d9908b171bb09',true,'v',true,'private'),
 ('_authority_sequence_claim_v3(text,jsonb,jsonb)','18cdb51c9e44fa944b355cadf1abcb291eba062ca09f3221118bcd60d736c740',true,'v',true,'private'),
 ('_authority_sequence_applied_v3(text,bigint,jsonb)','0a4c24ded6b6aad09fd077e4a1ad8d40dee440c4e27e44dc20e4300bfc0a5a7d',true,'v',true,'private'),
 ('_authority_sequence_complete_v3()','c9f728c4492acf65f92ea6a6f411b3af85e63e765c5226bbf3ea1e80fd9291d1',true,'v',true,'private'),
 ('authority_resource_finalize_v2(jsonb,integer,integer)','f68d6ef701f2e730fd10d2c65aec966d04aceaf54465ac87b684da8157985f0c',true,'v',true,'preserve'),
 ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','47aae35f146c1d05bf9f5f52f9f7b929d69d91f64b39844fd697530c467af440',true,'v',true,'preserve'),
 ('_authority_resource_object_program_v2(jsonb,timestamptz)','97f643954fbef4036c37240711c9ce9650045102c77bce1d5e8396d89a4c8464',true,'i',true,'preserve'),
 ('_authority_resource_object_sequence_prepare_v3(jsonb,integer)','bbf639e8b58fee3ee80ce322a7946cd5ae4a3f0a84804270117a369914fc5153',true,'v',true,'private'),
 ('_authority_resource_object_sequence_final_v3(jsonb,timestamptz)','48e8a4f9e9c57161fec84ede30f6a148a15a4cc5162d78dcfff4e048be037564',true,'v',true,'private'),
 ('_authority_resource_physical_relations_capture_v2(jsonb,integer,boolean)','e01481c788b47322941e6c6753d9d38e44e1bdcee973a8fb6292aed42d9ce54f',true,'v',true,'preserve'),
 ('_authority_resource_registration_sequence_prepare_v3(jsonb,integer,integer)','0d6ab18cc9cac1395df175c0c91912737bf8e78464d46da0c385e31aa36c9b66',true,'v',true,'private'),
 ('_authority_resource_registration_sequence_final_v3(jsonb,timestamptz)','ca262446dbab831c80c933c45b0095f12ceaa10367477a696266217b44736911',true,'v',true,'private'),
 ('_authority_resource_registration_direct_prepare_v2(jsonb,integer,integer)','ad9230edf198624a3d9caa84ee5a5a9954b79cd9afa58b1e0b64b60eb3dd2807',true,'v',true,'preserve'),
 ('_authority_resource_unregistration_prepare_v2(jsonb,integer,integer)','3b4c2286943cb21eb7a8f3f9875bd43a9da46c92268bb2838c30c01102df681d',true,'v',true,'preserve'),
 ('authority_role_stage_epoch_lock(text[],jsonb)','2f4e6d4569577abe84313594f72e973d8b5fb63ac2adbd5605640751c7bc5021',true,'v',true,'preserve'),
 ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','5d47e24c50baaa1619a6cfb2198255c248fec06d535e13febacf7078c6aeae64',true,'v',true,'export'),
 ('authority_role_sequence_finalize_v3()','4b1b5626bc90a7826a4bed308befc83c4e688b636f9dcd59d7446811f20ec891',true,'v',true,'export'),
 ('authority_role_sequence_stamp_v3(jsonb)','1a76eb48aa2c75c7213b7e01fe7530bfe859348a0fb8cf3cb0d79be83e9dd1f8',true,'v',true,'export'),
 ('_authority_sa_state_preflight_body_v4(text,boolean,text)','866552ed304b028241b3cf523869fa39104810a924ccb14661684689b76a95f5',true,'v',true,'private'),
 ('_authority_scalar_journal_v3(text,text,jsonb,jsonb)','b6c669cf2485b11b8a84bf8935d30b1707805f7c043c8abfba1c77476eedf4ab',true,'s',true,'private'),
 ('authority_metadata_preflight_v4(text,text,boolean,text,jsonb)','28de0a19487c8105f8ae7495cd1c195a84349fc2e5604493692bbcfaa34136bd',true,'v',true,'export'),
 ('authority_sa_state_preflight_v4(text,boolean,text)','6fbed0052196e4ad096c6047b1e018633760ea80f9edd7c722fb00b7b60900dd',true,'v',true,'export'),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true,'v',true,'preserve'),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true,'v',true,'preserve'),
 ('authority_scalar_sequence_finalize_v3()','c403ea97073dc0833cacdbfbd79691ccd1b11a6b0ca4c71fb2a73112e7d58be8',true,'v',true,'export'),
 ('authority_crud_storage_v3()','f2e0fb99aa034aaae63126e7f6b621fb8da6deb7b8ec21e0852f73bcf2e1e0fe',true,'s',true,'export'),
 ('_authority_resource_ancestor_graph_v2(jsonb,jsonb,jsonb)','0169e22d120961d1959b1eb87b684ab0ecf20c1cdb7c6e4f35289ebe5ce606b7',true,'i',true,'preserve'),
 ('_authority_resource_audit_capture_wait_v2(jsonb,integer,integer,boolean)','48833909f08147b697650810555b86266f9f7b6b0c41951fee89ba22ec25fd97',true,'v',true,'preserve'),
 ('_authority_resource_audit_plan_v2(jsonb,jsonb,jsonb)','f11cd1f48fdf0634bc288b523beb1758e66fbfab54fe020abb580cd0eaa99514',true,'i',true,'preserve'),
 ('_authority_resource_audit_wait_v2(jsonb,integer,integer)','29066819dd86fb4512a79fc4b8d30f88e95df89a74099e91471b39548efeb3e3',true,'v',true,'preserve'),
 ('_authority_resource_binding_candidates_v2(jsonb,jsonb,text,text,text,boolean)','0dd211dcb360329fa856f8c14692b50169668f73e2c03fd90aea3d3a0d7737b0',true,'i',true,'preserve'),
 ('_authority_resource_binding_certificate_v2(jsonb,jsonb,text,text,text,boolean,jsonb)','ec4d5deaf2df7982eba06a3350b0ae874c7179af6b41912fae3ed4d93e5c9386',true,'i',true,'preserve'),
 ('_authority_resource_bundle_catalog_v2(integer,integer)','eab6ae0b0d35773cd85b32a52758804f843eb49b289c6296d44df34e92fa3842',true,'v',true,'preserve'),
 ('_authority_resource_capture_index_v2(jsonb,integer)','988ed25715d6c9322bff7d8a6dc4d60b9d849a512d30ff9b70f8a1afbaa464f4',true,'i',true,'preserve'),
 ('_authority_resource_carrier_graph_v2(jsonb,text[],text[],text[],text[])','25cfe0b7f33582cfbee3399700901690952f97cff1e63d989ddde23176f42c80',true,'i',true,'preserve'),
 ('_authority_resource_carrier_scopes_v2(jsonb,jsonb)','0440ef56bc4069d6e1029e94dbab6acea6bddf7b5de88fc109f09f743599b60c',true,'i',true,'preserve'),
 ('_authority_resource_catalog_capture_wait_v2(jsonb,integer,integer,boolean)','c2dce8593b8f7616af573591ed0d439f822054f78f96de78ff8fc20d59efde18',true,'v',true,'preserve'),
 ('_authority_resource_catalog_wait_v2(jsonb,integer,integer)','6231367fd8a56cec22aed190ae2eef6dd8b3f93b2db1a0d8810ca6d9d5d53e97',true,'v',true,'preserve'),
 ('_authority_resource_contained_v2(text,text,jsonb,text)','e8cd715375fb48ff94738b78d82f00087fa548634ca3ebc43edd45dd54c8a758',true,'i',true,'preserve'),
 ('_authority_resource_coordinate_certificate_v2(jsonb,jsonb,text,jsonb,jsonb)','c24b6686e9bd21247289b6efcbd2277902da2cb951134cc770bdbeab4af12fe5',true,'i',true,'preserve'),
 ('_authority_resource_encode_proposed_rules_v2(jsonb,boolean)','e2f7cab577d72eedcbf78ccfbe3c3109cf1414d90617a036a95861ab199bbacc',true,'i',true,'preserve'),
 ('_authority_resource_epoch_wait_v2(jsonb,jsonb,jsonb,integer,integer)','52e0cc8f44374d68a98450683564534073a08be0727c31e8846757f906910129',true,'v',true,'preserve'),
 ('_authority_resource_grant_reference_v2(jsonb,text)','df8c0b484673605fdf285a40ab35045b49f622ed66da6d56962846d1228009b4',true,'i',true,'preserve'),
 ('_authority_resource_grant_rule_fp_v2(jsonb)','eaa4bee66714be005240c085088d71cc3fbdb1cb95575c892cfcadd7aedd9671',true,'i',true,'preserve'),
 ('_authority_resource_installation_eligible_v2(text,text,text,text,text,jsonb,timestamptz)','697e605e233cfc83f3f6a75f230e5ee309a0e365d854bb3eae46f73d6d41cbbf',true,'i',true,'preserve'),
 ('_authority_resource_installation_wait_v2(text,text,jsonb,integer,integer)','cdc2aade908f9ed07ef42c20be0ad8f7b92f77bd51bd5f4c6a7080b0671e57db',true,'v',true,'preserve'),
 ('_authority_resource_key_array_v2(jsonb,boolean)','ec975c9c1dd185c9582596cbc96c7916c26f93b20d91c7c9eefb5ef22755d7a1',true,'i',true,'preserve'),
 ('_authority_resource_ledger_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean,integer)','d0ac1b9d8ab0c3c1821baaef668de1bb12c6edb0beddb3f4942874d433f4f2ff',true,'i',true,'preserve'),
 ('_authority_resource_manifest_create_v2()','b9ee82cbaa043c831c36e612387f616941b7cf028e13fb6b215da6679e486ccd',true,'v',true,'preserve'),
 ('_authority_resource_manifest_v2()','a80529dcdf4cb68395a9311f2f7b737fb467f0768c5b8a7e4488679bd5f3c63f',true,'v',true,'preserve'),
 ('_authority_resource_match_wait_v2(jsonb,integer,integer)','6ff5dc168529251407ee765ab0f1a53e4089a124e101128f481ea5382ba3e626',true,'v',true,'preserve'),
 ('_authority_resource_materializable_types_v2()','de8eb0540e5ee90a586412bc1503c3c16c24ba9f99359cae97ed7489c8151136',true,'i',true,'preserve'),
 ('_authority_resource_materialized_types_v2(jsonb,integer)','a1b18cbee25c6da9fa6cbd017b0dbcd69eaa5c692065d0856d6b65cadaad4bac',true,'i',true,'preserve'),
 ('_authority_resource_member_obligations_v2(jsonb,jsonb,jsonb,jsonb,boolean,boolean)','4cda1e3112578a85f8b85c11a17a6d68126eb4eebea678c542fe5eee2e7a2d58',true,'i',true,'preserve'),
 ('_authority_resource_module_identity_v2(text,text,text)','b8c934a9370e413464b0577108ed9e69b42898308851b003ad2f646bd0e94fc8',true,'i',true,'preserve'),
 ('_authority_resource_nested_rows_v2(jsonb,jsonb,integer,integer)','3af0e8ae4591ff8be128e912062f921974d9d7ec9202c8ce1f4a6de651fed360',true,'v',true,'preserve'),
 ('_authority_resource_object_candidates_v2(jsonb,jsonb,text,text,integer)','dd5be24069ae63a2c946ed9a64344a5191f1f85994ce561139853d483d92fab4',true,'i',true,'preserve'),
 ('_authority_resource_object_certificate_v2(jsonb,jsonb,jsonb,jsonb)','9d0b5419a24502e9abfa42b50fed23be08ed5d349af73c6eb79896b17712c8e3',true,'i',true,'preserve'),
 ('_authority_resource_object_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a3b9e3f7fd865d129ee4a9140a5795627e7697e9aa8cd4003ba5cc6a92f5b06e',true,'i',true,'preserve'),
 ('_authority_resource_object_graph_v2(jsonb,text,text,text)','7b51494829379bfdd91f4853099642f2e57c88ad887912e1656c5f5669a7ca76',true,'i',true,'preserve'),
 ('_authority_resource_object_manifest_images_v2(jsonb,jsonb,jsonb)','940501419f3759706e6e56fb6626e61a6896c247ffd3151c5283c0360719ab35',true,'i',true,'preserve'),
 ('_authority_resource_object_materialize_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','01559b0be95e275e46e33b0b00028c80e611b97a64fbc8eb85b0910643dd2505',true,'i',true,'preserve'),
 ('_authority_resource_object_maximum_v2(jsonb,jsonb,jsonb,jsonb)','bf2c9287fdf43dac1cc03a9c62f0a665dfda01792c54fd6440f061ec9343204c',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_sources_v2(jsonb,jsonb)','8beafc61826cbc195149bf41e1ca3402c4f794088fb81da73e91af089fcb00d3',true,'i',true,'preserve'),
 ('_authority_resource_object_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','98f24f2154bfc6e60611130a825cf0eb93efb6631ed36ba142f8c9a2eb0cae61',true,'i',true,'preserve'),
 ('_authority_resource_object_store_v2(jsonb)','761cb220c553c2d519c5adc6fc14b6ab4675779b205dbc529982863023ac1b5a',true,'v',true,'preserve'),
 ('_authority_resource_object_write_keys_v2(jsonb,jsonb)','55621c02ba3a899e93d5c41eddef68dd231c37500d740e2ff09bfffcb8529072',true,'i',true,'preserve'),
 ('_authority_resource_ordinary_member_v2(jsonb,jsonb,text,jsonb,jsonb)','e22a387229f36c3ff81806752df50a0a0b5e03f2d8a66df1f0482180e17b5305',true,'i',true,'preserve'),
 ('_authority_resource_physical_relations_wait_v2(jsonb,integer)','86d6bd4c42c79ee3d6dc95ea2317113fcf99849f0445a03307e598abffecb3f2',true,'v',true,'preserve'),
 ('_authority_resource_predicate_maximum_v2(jsonb,jsonb)','54f35fa496cbd4bbb0ff0d7f838eab7e3dbb1bf17cf5b3ea8a54e55223e68a46',true,'i',true,'preserve'),
 ('_authority_resource_preheld_key_v2(integer,text,boolean)','77d85a114d79fb9d60470f0bdd63e2f688d5164fd5a225c5cebef10e43da78ea',true,'v',true,'preserve'),
 ('_authority_resource_projected_capture_v2(jsonb,integer,text,text,text,boolean)','782d8002dc7498b18696afa46da3429774cbcd9580030b46bb76d6ce97328267',true,'i',true,'preserve'),
 ('_authority_resource_projection_v2(jsonb,text,text)','79fb1eeb6681835031a23733e52c34ca00e1d13bfde63655dfdcfe1c663db0bf',true,'i',true,'preserve'),
 ('_authority_resource_publication_direct_program_v2(jsonb,jsonb,timestamptz)','753c099113766391b73c537756b40729a0e39111983d8fe2b1803407918bd25e',true,'i',true,'preserve'),
 ('_authority_resource_publication_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','2162e671105cd0d167abc538791192b7e8c6861e943f9ac60bba6294254f9058',true,'i',true,'preserve'),
 ('_authority_resource_publication_images_v2(text,text,boolean,timestamptz,jsonb,jsonb,timestamptz)','0a343a95b30ad5ec1de4aaaf900d74e0fef4c44506ca5c406ec9ea7e7916c53a',true,'i',true,'preserve'),
 ('_authority_resource_recipient_verbs_v2(jsonb,jsonb,jsonb,text,boolean,text,boolean)','f6080aad1d9dc4a12c26513ba2638f5fde3f959a79ce83a88a1c16e522b42c29',true,'i',true,'preserve'),
 ('_authority_resource_reconcile_wait_v2(integer,integer)','2e5af4934a850ef95f1a333ad71694bd4f27fa51f1b0de19b670ed9f3ca5d8fa',true,'v',true,'preserve'),
 ('_authority_resource_refusal_certificate_v2(jsonb,jsonb,jsonb,jsonb)','1f5e087abb91e7289bd935f29592eb51b59f93b176dd1a86cee74672aa1f879a',true,'i',true,'preserve'),
 ('_authority_resource_refusal_materialize_v2(jsonb,jsonb,timestamptz)','fc6cef31e2f28cb7b6bf3d5b6f95aa601ac1caf89a55e7405af0c84a302d1eab',true,'i',true,'preserve'),
 ('_authority_resource_refusal_prepare_v2(jsonb,integer,integer)','1cf4deb21d1776d53041718e1a2d453150d83b269a8de108d021b736a348d831',true,'v',true,'preserve'),
 ('_authority_resource_registration_authority_final_v2(jsonb,timestamptz)','5369474ff41744e9375e8b91ed623a1fbeab6c8dcd954f563a89dcdbf672b965',true,'i',true,'preserve'),
 ('_authority_resource_registration_authority_wait_v2(jsonb,jsonb,text,jsonb,integer,integer)','8b92777acd79df9e879a5be7bfd2fc0cb9b70c1230f941a55c8e20d8c1c126bb',true,'v',true,'preserve'),
 ('_authority_resource_registration_binding_wait_v2(jsonb,jsonb,integer)','8737eebc8314ab0caf06537329e3d376f94daaaedd424faf11df30c7d41e8fa2',true,'v',true,'preserve'),
 ('_authority_resource_registration_delete_fold_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','140ccec2507036d09f2e81db00356442d8fd561a742b6e8752b4dd377be26171',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_program_v2(jsonb,jsonb,timestamptz)','89e76fe747ba97a46120af7c1548b02835beba9e19618fb03b0add94bf3c434c',true,'i',true,'preserve'),
 ('_authority_resource_registration_direct_sources_v2(jsonb,jsonb)','35a8292b281969ee1003e54336a2acda78e2c592daa4022b1412efd1996a0427',true,'i',true,'preserve'),
 ('_authority_resource_registration_fact_v2(text,text,jsonb)','81397be2c987bdd6787b0cc3fc52692b970c534ab42d126e5f1aafd28484c4c9',true,'i',true,'preserve'),
 ('_authority_resource_registration_intent_certificate_v2(jsonb,jsonb,jsonb,jsonb)','18c7790f1463d3982e3f69b7b80f1e2af3210a1da06202f88abc44cb681d86e5',true,'i',true,'preserve'),
 ('_authority_resource_registration_manifest_images_v2(jsonb,jsonb,jsonb)','acecdc1f6a1f2a36d62c82af93ccad6351700ba1bd927d26240c480ebc5b1596',true,'i',true,'preserve'),
 ('_authority_resource_registration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','455a6cb564a14038aff88f58f383ed79625016ec2896cf0f2f303b0e734a7964',true,'i',true,'preserve'),
 ('_authority_resource_registration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','0d869eee616ea83c8f5c20c179c727022ceecf8ff42cb0a53731aba56d8cb6cc',true,'i',true,'preserve'),
 ('_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)','909c304c45925ad0cee62e8ddc462b381778fffd89739e36b99195bea4f3b6f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_model_v2(text)','89ac1f6c923ab033b5551fff2d098099518b2b7c15b3530f15e798ef70cf20e9',true,'i',true,'preserve'),
 ('_authority_resource_registration_pack_v2(jsonb,jsonb,jsonb)','c7df4fd61023a840f764bfd36b29151f718b35aa360fb93c55fbeb7618d50ec7',true,'i',true,'preserve'),
 ('_authority_resource_registration_parent_graph_v2(jsonb,jsonb,text)','e9bcecbff08deea42f1eb0a2356aa88075ff5d526e754cd5514c99028b8b0f96',true,'i',true,'preserve'),
 ('_authority_resource_registration_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','7c765b761ad28fbde1f64094ef30cf61d70c20b555cb8c5026e172c5eea9d918',true,'i',true,'preserve'),
 ('_authority_resource_registration_pointer_images_v2(text,text,text,text,jsonb,timestamptz,jsonb)','dd37d5f9645e4b380d466079441c945a0e5f95fb44341d75bf4859b09a95e7d8',true,'i',true,'preserve'),
 ('_authority_resource_registration_prepare_v2(jsonb,integer,integer)','c2ab0a869a22e4fec8e5b2735055308a15ba545ef33c21d3f2af9c3f0e2bb773',true,'v',true,'preserve'),
 ('_authority_resource_registration_receipt_images_v2(text,text,text,jsonb,timestamptz,text,jsonb)','4a952ac29b2a28cdaa48f73b0f173a759a4ed455ae43677363284976c960a35c',true,'i',true,'preserve'),
 ('_authority_resource_registration_saved_scopes_v2(jsonb,jsonb,text,text)','d2798409d801254b2a63af2de46033cd560cc6c2bde88193a5d31ffea3daaca3',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_certificate_v2(jsonb,jsonb,text,text,text,text,jsonb,boolean)','e5bbc391fa00cc3362d203916604507a513a81c7963c24e4d0196ba1277f129d',true,'i',true,'preserve'),
 ('_authority_resource_registration_scope_images_v2(text,text,jsonb,jsonb)','a6fedeea120947165db033862934904916bf4ca57f6e02ca9a64efcd155b55f7',true,'i',true,'preserve'),
 ('_authority_resource_registration_step_operations_v2(jsonb,jsonb,jsonb)','7a6d30976cbbfa09e2f388994476cdab3f99e5b949dda0463829b1c5f0c36df7',true,'i',true,'preserve'),
 ('_authority_resource_registration_store_v2(jsonb)','dc264ddd6cd90f698104551e0be54173d83d5576df7e0d75a1c75ad3133f3221',true,'v',true,'preserve'),
 ('_authority_resource_registration_version_v2(text)','09aa74b25e294d4d6c5c43c107212c81f0d1b32acc43e5a74f0588dbcb7d9690',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_images_v2(jsonb,timestamptz,jsonb,jsonb,timestamptz)','af4c099a81327d849e561861eba96568eab9a5ae27c4dbbc77f32ea5f381cd6c',true,'i',true,'preserve'),
 ('_authority_resource_registration_write_keys_v2(jsonb,jsonb)','b7deaeb5ee01534ffeeaaa6ed468794f039487e293d07cfec08240ddc2db73d3',true,'i',true,'preserve'),
 ('_authority_resource_require_capture_v2(jsonb,integer,text,text,text)','3052c274445598750d6646cbb4bc1308311befc0e2cdb125961633702ac0bd35',true,'i',true,'preserve'),
 ('_authority_resource_required_reread_v2(jsonb,jsonb,jsonb,integer,integer)','4821805cd8b27cce9cddbf1ebc17186aec073d2bbc64860ab7ab888dffae0aa3',true,'v',true,'preserve'),
 ('_authority_resource_row_image_v2(text,jsonb)','f6c7bdc6437dd7e32592f53af7795438fc97164a8ed1d33f7d9522e659548e42',true,'i',true,'preserve'),
 ('_authority_resource_rule_fingerprint_v2(jsonb,boolean)','4dda7544eeae0b21c7d6ba080ce541e68989f6e2f9de72544ff1b23f4dfdb7a5',true,'i',true,'preserve'),
 ('_authority_resource_rule_layout_v2(jsonb,jsonb)','fcf600cf8eaafe1211e0b663bd798dbd025bb9429d06066507dd648256b8013d',true,'i',true,'preserve'),
 ('_authority_resource_rule_witness_v2(jsonb,text,jsonb)','ef7b397fd945ad8df12c6f541a3764b34b2242751289085ba43a908089f17a6a',true,'i',true,'preserve'),
 ('_authority_resource_selector_matches_v2(jsonb,text,text,jsonb)','b925d87aa30d19a06d00e346d26e381721cc63c8eb4deb12f0f1a15b3e49da68',true,'i',true,'preserve'),
 ('_authority_resource_selector_rows_v2(jsonb,integer,integer)','d7da86929ecc720bfd1f617a1c02ae074a487c8280e931a91cba0f008c8060ef',true,'v',true,'preserve'),
 ('_authority_resource_selector_shape_v2(jsonb,integer,integer)','c044631ad4287271aa8540488883ec06983a5abb85f484388a25cba713191a3c',true,'v',true,'preserve'),
 ('_authority_resource_source_wait_v2(jsonb,boolean,integer,integer)','1ce9b16ec596aa1521e295cadb310ea5680c69ba5ea12ee995f186adeb5bd654',true,'v',true,'preserve'),
 ('_authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','a7009eb3fc759ba72f73579f72a23b6078174b556fbcbbcadc91b2e95bb4013c',true,'i',true,'private'),
 ('_authority_resource_special_member_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)','9415be5436a7ed74e97131d996f346df3f1b02d23c7f5b108fa7788629a0c6ed',true,'i',true,'preserve'),
 ('_authority_resource_subject_change_wait_v2(integer,integer)','bb5f61c161012d21fe2480ffbdc61fc8095ceb1d9d265a13b26530b22b568632',true,'v',true,'preserve'),
 ('_authority_resource_target_contains_v2(jsonb,text,text)','5c3e97459a3935ec873831692d25cf522a7ca8447a97fbb376a1be6aa9fd8186',true,'i',true,'preserve'),
 ('_authority_resource_tuple_relations_v2(jsonb,jsonb,text,jsonb,text)','efc819930de778d8c757833f9d5e3f056f9e7723da3dd2ef1e9d958c2902d0cb',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_audit_hierarchy_v2(jsonb,jsonb,jsonb,jsonb)','6f8f54188fade71649c640691ff5cabeffcf1512f89d4744e138be4b6f6a00d2',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_certificate_v2(jsonb,jsonb,jsonb,jsonb,jsonb)','023353817aec9d9ab441c2e5bd8f9ba66b6d2164d7d71f2d82f646b025a4e615',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_current_v2(jsonb,jsonb,jsonb)','91cb5cb519e0a34e103fcf84df5ecf2259c656282c55a0fc4c88a5f83cd84101',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_direct_program_v2(jsonb,jsonb,timestamptz)','8e88012c6babe593a7203c818726d8c768e7f907015c731c1cf115aa59195e8b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_fold_v2(jsonb,jsonb,timestamptz)','981a3753a9d5149fc3ad5996f3b7664989a1a58b66915f9d639b55b769f818be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_images_v2(text,jsonb,jsonb,jsonb,jsonb,timestamptz)','bd2c3a71cf82e7a55a4d0b3cd271c0114afd4d18bfa5d1196fb8425493c3fd48',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_program_v2(jsonb,jsonb,jsonb,timestamptz)','e6778dd30178f736816a8816a83005179aa0a3c651242c51bf0a9c10207dd5be',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_journal_rows_v2(jsonb,jsonb)','559ccb301f1c99a57f71910e7407a76e93f20393b88ef7f77c08d96f6bd211cf',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_materialize_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','a5dcf1324a5a8daca8e3e80ccd296cb9f737a8a90a65ddc85f5e36269835300b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_maximum_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','15d8361f789a52deaa920abbf46dddfff367d65bc15668f393e2cd93e61b7009',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_mirror_images_v2(jsonb,text)','2cfc03821a5f30ce8e657ca020329a1e54c29c728a125f1a32e6a8b2b4a7c32c',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_object_v2(jsonb,jsonb,text)','d553151e5ff2b50c946bdefb0f5a47c342de88cd97da547afe5b726d8f9b2e3f',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_acl_v2(jsonb,oid,jsonb)','075c20b7bb9f2d06dec73df64186da0b9d4bcc500b99fcbc28ef9b4f21ce7fea',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_operation_maximum_v2(jsonb,jsonb)','79cded719033e41b9a38951033f494bb29e4b48a8c4def81d0126376f333cb45',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_physical_v2(jsonb)','c78c70847fb31b8d1dc082e413a6cc5827f1b79eee9eb067410258408a22221d',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_roots_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)','d59ef0d706c1f24a98b764ba805604e411d5f54980c64e6d2e8efd1ae3d6a306',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_source_metadata_v2(jsonb,jsonb,jsonb)','67fbae698c0f4362c2d1a7245a8db1073e76ad0ba5aef10cf43fc8f2427e5b40',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_tail_program_v2(jsonb,jsonb,jsonb,jsonb,timestamptz)','93238ccdb1002e80ed0651b7802a3c392c7a3714ca12bfb77053f6fd399dfe9b',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_withdrawal_program_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','ec2574723c93de9016b0156bb712879eecdafdfa2270f97f8cf4df57c52a4069',true,'i',true,'preserve'),
 ('_authority_resource_unregistration_write_keys_v2(jsonb,jsonb)','ee116834532cc77d78fd300dda8c172da48781107d6b1813027c659001619161',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_images_v2(jsonb,jsonb,jsonb,timestamptz,timestamptz)','787963fad1924ff537cd5dd113e5b0cad7e05abbda3d8b3b3e3ca1b7238e5178',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_binding_v2(jsonb,jsonb,jsonb,jsonb,text,jsonb)','c21e989d6476855358771d8780d9bc5e02f9cd5d46540c08d1690071f129aaf3',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_bindings_v2(jsonb,jsonb,jsonb,text,jsonb)','e8eec4698549dca98cc22b3aebd1f6580d4ffd81241fbf82994c50653b8ac900',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_census_v2(jsonb,jsonb)','d27e53aef5e2f64ed1ad158e3aa31047b3845afb8b80908eca271674a4728c13',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_physical_v2(jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','44869037245345da786a82632bb8f22d2a5095769ea5b194cd39ff63933b354d',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_retention_v2(jsonb,text,jsonb,jsonb,jsonb)','50d877065d0b35b3a8b9f13319110f0c736a790c18be146c38ba66fd471ecd81',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,timestamptz)','414605ec9f19132a0cb9fb3f89d3524e8547c400ae2bc45083865b53bee2fb68',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_projection_v2(jsonb,jsonb,jsonb,jsonb)','89c1b44eb9a74c42c2be80f3f395e05216636481893f47ac85b6696704689ab6',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_role_rules_v2(jsonb,jsonb,text,jsonb)','9491569e7691e17074fe14ef74539351bd21fb7776970eb82a6f79a4aef1ea0b',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_roles_v2(jsonb,jsonb,jsonb,text,jsonb,jsonb,jsonb)','7a8a458214d4d7047ef95b7a7d89d1cf30fb44c2b0e641a9d0eddcb3cd3a70bd',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_rules_v2(jsonb,text,text)','7bf6058618cf10048a6cb7671342c222e6dd24ff4825d6743990dd2a8c50e29c',true,'i',true,'preserve'),
 ('_authority_resource_withdrawal_split_v2(jsonb)','27da9c2fbe328e2cd4013f991dc62e7ee75ee1031a5bd5e42dd86bcd1fac7282',true,'i',true,'preserve'),
 ('_authority_resource_without_name_v2(jsonb,text,text,text,boolean,boolean)','d97ead12d3586dac0380d636ddfeb73100ddcf5310211834371babd3f3d0468a',true,'i',true,'preserve'),
 ('authority_binding_epoch_changed()','bcf0e606baaa81d738d99f2dfb8882f9723c37ccb59f70fb0785e2507119ccef',true,'v',true,'preserve'),
 ('authority_binding_epoch_read(text[])','37c8fcd579b297a3c7a749b2889ad95a95561341c63bfa4eb3355284ed583b05',true,'s',true,'preserve'),
 ('authority_binding_epoch_scope(text,jsonb)','ae4b14d1640a4473eb8852512b1722b6439a178b2f1fde5fdc76dcc637e2fb30',true,'s',true,'preserve'),
 ('authority_group_object_scopes(text,text)','ed9f62070e461be31342d7c4e3cfcbbb2e3542f2309b63f9592b80a46bd3cc60',true,'s',true,'preserve'),
 ('authority_protocol_row_account(text,jsonb)','36453c01ccca68634dcf0aac077f00cb17a82cb6fe9bb2406ac633380c4b4a9e',true,'s',true,'preserve'),
 ('resource_journal_project(text,jsonb)','a792cf1d91d0d5b16d01f530109ad7b08559e1bea98632d30fbeadec4bfbdbb7',false,'i',false,'preserve'),
 ('resource_journal_scope(text,jsonb)','22deae6b397c11f7558bd7e10c64400e06ea0f765f5b7f17ba03fe1d00aa1da9',false,'s',false,'preserve')
 ) pin_expected(signature,digest,definer,volatility,fixed_path,access_mode)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pin_expected.signature)
 WHERE CASE WHEN p.oid IS NULL THEN true ELSE
  (p.proowner=owner_oid AND p.prosecdef=pin_expected.definer AND p.provolatile::text=pin_expected.volatility
   AND CASE WHEN pin_expected.fixed_path THEN p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] ELSE p.proconfig IS NULL END
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pin_expected.digest) IS NOT TRUE
 OR (pin_expected.access_mode='private' AND EXISTS(
   SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid))
 OR (pin_expected.access_mode='export' AND EXISTS(
   SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid
   AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) END) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname._authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)'::regprocedure
   AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT p.proretset AND NOT p.proisstrict
   AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargs=6 AND p.pronargdefaults=0
   AND p.proargmodes IS NULL AND p.provariadic=0 AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('authority_reconcile_enter_v3()','void',0,false), ('authority_installation_enter_v2(text)','integer',1,false), ('_authority_audit_binding_store_v3()','jsonb',0,false), ('_authority_binding_mirror_store_v3()','jsonb',0,false), ('_authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz)','void',3,false), ('_authority_binding_mirror_prepare_v3(jsonb,integer,integer)','record',3,true), ('_authority_binding_mirror_finalize_v3(text)','void',1,false), ('_authority_binding_mirror_before_write_v3(text,text,jsonb,jsonb)','boolean',4,false)
 ) abi_expected(signature,result_type,nargs,returns_set) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||abi_expected.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>abi_expected.result_type::regtype OR p.proretset<>abi_expected.returns_set
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>abi_expected.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
 OR CASE WHEN abi_expected.returns_set THEN p.proargmodes IS DISTINCT FROM ARRAY['i','i','i','t','t']::"char"[]
  OR p.proallargtypes IS DISTINCT FROM ARRAY['jsonb'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype,'integer'::regtype]::oid[]
  OR p.proargnames IS DISTINCT FROM ARRAY['p_snapshot','p_rows','p_reads','logical_rows','logical_reads']::text[]
 ELSE p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL END) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
 ('authority_binding_command_begin_v3(jsonb)','boolean','p_command'),
 ('authority_binding_command_end_v3(jsonb)','void','p_command'),
 ('authority_binding_command_audit_v3(jsonb)','boolean','p_command'),
 ('_authority_binding_mirror_policy_prepare_v3(jsonb)','void','p_snapshot')
 ) e(signature,result_type,argname) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>1 OR p.pronargdefaults<>0
 OR p.provariadic<>0 OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.proargnames IS DISTINCT FROM ARRAY[e.argname]::text[] OR p.proargtypes[0]<>'jsonb'::regtype
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure
  AND p.prorettype='pg_catalog.bool'::regtype AND p.pronargs=6 AND p.proargtypes='3802 3802 25 3802 3802 3802'::oidvector
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND NOT p.proretset AND NOT p.proisstrict AND p.prokind='f' AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.proallargtypes IS NULL AND p.proargmodes IS NULL) THEN RETURN false;END IF;
 -- Mirror остаётся единственным AFTER INSERT/UPDATE OF тех же трёх колонок.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.membership_mirror_from_user()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid='kaname.users'::regclass
  AND t.tgname='membership_mirrors_user_row' AND t.tgfoid='kaname.membership_mirror_from_user()'::regprocedure
  AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=21
  AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
  AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgqual IS NULL
  AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL
  AND (SELECT array_agg(a.attname::text ORDER BY x.position)
   FROM unnest(t.tgattr) WITH ORDINALITY x(attnum,position)
   JOIN pg_catalog.pg_attribute a ON a.attrelid=t.tgrelid AND a.attnum=x.attnum AND NOT a.attisdropped)
    =ARRAY['account_id','invite_status','invited_by']::text[]) THEN RETURN false;END IF;
 -- Точная схема вызовов: нельзя снять guard, сделать deferred или добавить
 -- второй вызов того же emitter вне скомпилированного eventset.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('projects','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('service_accounts','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_unique','authority_crud_unique_guard_v3()',23,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_sequence','authority_crud_sequence_guard_v3()',23,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_before','_authority_crud_aux_write_v3()',31,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_after','_authority_crud_aux_write_v3()',29,0,'',false,NULL,NULL),
 ('issued_account_ids','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('project_resource_quotas','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('identity_admission_windows','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_grant_orphan','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('role_selector_prune','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_aux_statement','_authority_crud_aux_statement_v3()',62,0,'',false,NULL,NULL),
 ('resource_journal','authority_crud_journal_applied','authority_crud_journal_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_guard','authority_crud_fga_id_guard_v3()',7,0,'',false,NULL,NULL),
 ('fga_outbox','authority_crud_fga_id_applied','authority_crud_fga_id_applied_v3()',5,0,'',false,NULL,NULL),
 ('resource_journal','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('fga_outbox','authority_sequence_program_applied_v3','authority_sequence_program_applied_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('accounts','accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('projects','projects_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('projects','projects_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('users','users_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('users','users_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('groups','groups_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('groups','groups_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('service_accounts','service_accounts_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('roles','roles_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('roles','roles_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_insert','authority_sequence_origin_v3()',5,0,'',false,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_update','authority_sequence_origin_v3()',17,0,'',true,NULL,NULL),
 ('access_bindings','access_bindings_000_sequence_origin_delete','authority_sequence_origin_v3()',11,0,'',false,NULL,NULL),
 ('group_members','group_members_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('memberships','memberships_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_000_sequence_origin','authority_sequence_origin_v3()',13,0,'',false,NULL,NULL),
 ('accounts','accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'6163636f756e7400',false,NULL,NULL),
 ('accounts','accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'6163636f756e7400',true,NULL,NULL),
 ('accounts','accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'6163636f756e7400',false,NULL,NULL),
 ('projects','projects_resource_journal_insert_trg','resource_journal_emit()',5,1,'70726f6a65637400',false,NULL,NULL),
 ('projects','projects_resource_journal_update_trg','resource_journal_emit()',17,1,'70726f6a65637400',true,NULL,NULL),
 ('projects','projects_resource_journal_delete_trg','resource_journal_emit()',11,1,'70726f6a65637400',false,NULL,NULL),
 ('users','users_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f7573657200',false,NULL,NULL),
 ('users','users_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f7573657200',true,NULL,NULL),
 ('users','users_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f7573657200',false,NULL,NULL),
 ('groups','groups_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f67726f757000',false,NULL,NULL),
 ('groups','groups_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f67726f757000',true,NULL,NULL),
 ('groups','groups_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f67726f757000',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f736572766963655f6163636f756e7400',true,NULL,NULL),
 ('service_accounts','service_accounts_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f736572766963655f6163636f756e7400',false,NULL,NULL),
 ('roles','roles_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('roles','roles_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f726f6c6500',true,NULL,NULL),
 ('roles','roles_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f726f6c6500',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_insert_trg','resource_journal_emit()',5,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_update_trg','resource_journal_emit()',17,1,'69616d5f6163636573735f62696e64696e6700',true,NULL,NULL),
 ('access_bindings','access_bindings_resource_journal_delete_trg','resource_journal_emit()',11,1,'69616d5f6163636573735f62696e64696e6700',false,NULL,NULL),
 ('group_members','group_members_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f67726f75700067726f75705f69640067726f75707300',false,NULL,NULL),
 ('memberships','memberships_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f7573657200757365725f696400757365727300',false,NULL,NULL),
 ('access_binding_subjects','access_binding_subjects_resource_journal_trg','resource_journal_emit_member()',13,3,'69616d5f6163636573735f62696e64696e670062696e64696e675f6964006163636573735f62696e64696e677300',false,NULL,NULL),
 ('accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('projects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('projects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('projects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('projects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('roles','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('roles','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('roles','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('roles','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('groups','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('groups','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('groups','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('groups','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('users','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('users','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('users','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('users','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('service_accounts','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('service_accounts','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('service_accounts','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('service_accounts','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('memberships','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('memberships','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('memberships','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('memberships','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_bindings','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_bindings','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_bindings','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_bindings','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_subjects','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_subjects','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_subjects','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_target_members','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_target_members','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_target_members','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('access_binding_emitted_tuples','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('access_binding_emitted_tuples','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('access_binding_emitted_tuples','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_selectors','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_selectors','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_selectors','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_selector_verbs_pending','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_selector_verbs_pending','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_selector_verbs_pending','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_rule_ref','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_rule_ref','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_rule_ref','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_rule_ref','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_create_binding_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_create_binding_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_create_binding_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('role_bind_role_rule','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('role_bind_role_rule','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('role_bind_role_rule','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_module','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_module','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_module','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_module','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_resource','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_resource','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_resource','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_resource','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('catalog_verb','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('catalog_verb','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('catalog_verb','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('catalog_verb','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_mirror','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_mirror','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_mirror','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_mirror','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_registration_scope','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_registration_scope','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_registration_scope','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('resource_parent_edge','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('resource_parent_edge','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('resource_parent_edge','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL),
 ('grant_delegations','binding_epoch_insert','authority_binding_epoch_changed()',4,0,'',false,NULL,'new_epoch_rows'),
 ('grant_delegations','binding_epoch_update','authority_binding_epoch_changed()',16,0,'',false,'old_epoch_rows','new_epoch_rows'),
 ('grant_delegations','binding_epoch_delete','authority_binding_epoch_changed()',8,0,'',false,'old_epoch_rows',NULL),
 ('grant_delegations','binding_epoch_truncate','authority_binding_epoch_changed()',32,0,'',false,NULL,NULL)
 ) graph_expected(table_name,trigger_name,signature,trigger_type,nargs,argument_hex,has_qual,old_table,new_table)
 WHERE NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||graph_expected.table_name)
   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p')
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||graph_expected.table_name)
   AND t.tgname=graph_expected.trigger_name AND t.tgfoid=to_regprocedure('kaname.'||graph_expected.signature)
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=graph_expected.trigger_type
   AND t.tgconstraint=0 AND NOT t.tgdeferrable AND NOT t.tginitdeferred
   AND t.tgnargs=graph_expected.nargs AND encode(t.tgargs,'hex')=graph_expected.argument_hex AND t.tgattr=''::int2vector
   AND t.tgoldtable::text IS NOT DISTINCT FROM graph_expected.old_table AND t.tgnewtable::text IS NOT DISTINCT FROM graph_expected.new_table
   -- Trigger qual имеет две range-table записи OLD/NEW; pg_get_expr для него
   -- неприменим. Сравнивается вся WHEN-clause trigger-aware deparser, не подстрока.
   AND CASE WHEN graph_expected.has_qual THEN t.tgqual IS NOT NULL
    AND substring(pg_get_triggerdef(t.oid,false) FROM ' WHEN (.*) EXECUTE FUNCTION ')='((old.* IS DISTINCT FROM new.*))'
    ELSE t.tgqual IS NULL END)) THEN RETURN false;END IF;
 -- STABLE: все counts используют снимок вызывающего запроса. Карта содержит
 -- не более 12 OID; посторонние trigger-функции не увеличивают её размер.
 -- Предварительный lookup не бросает ошибку для отсутствующей функции.
 -- Каждый строгий cast остаётся на прежней границе проверки; если он видит
 -- другой OID, ленивый fallback считает исходный каталог, а не подставляет 0.
 WITH requested AS MATERIALIZED (
  SELECT DISTINCT to_regprocedure(signature)::oid AS oid FROM (VALUES
   ('kaname._authority_crud_aux_statement_v3()'),
   ('kaname._authority_crud_aux_write_v3()'),
   ('kaname.authority_binding_epoch_changed()'),
   ('kaname.authority_crud_fga_id_applied_v3()'),
   ('kaname.authority_crud_fga_id_guard_v3()'),
   ('kaname.authority_crud_journal_applied_v3()'),
   ('kaname.authority_crud_sequence_guard_v3()'),
   ('kaname.authority_crud_unique_guard_v3()'),
   ('kaname.authority_sequence_origin_v3()'),
   ('kaname.authority_sequence_program_applied_v3()'),
   ('kaname.resource_journal_emit()'),
   ('kaname.resource_journal_emit_member()')
  ) names(signature)
 ), counts AS MATERIALIZED (
  SELECT t.tgfoid AS oid,count(t.oid) AS n FROM pg_catalog.pg_trigger t
  WHERE t.tgfoid=ANY(ARRAY(SELECT oid FROM requested)) GROUP BY t.tgfoid
 ), snapshot AS MATERIALIZED (
  SELECT coalesce(jsonb_object_agg(r.oid::text,coalesce(c.n,0)),'{}'::jsonb) AS counts
  FROM requested r LEFT JOIN counts c ON c.oid=r.oid WHERE r.oid IS NOT NULL
 )
 SELECT s.counts,coalesce((s.counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
 INTO trigger_counts,trigger_count
 FROM snapshot s CROSS JOIN (SELECT 'kaname._authority_crud_aux_statement_v3()'::regprocedure::oid AS oid) r;
 IF trigger_count<>6 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname._authority_crud_aux_write_v3()'::regprocedure::oid AS oid) r)<>10 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_binding_epoch_changed()'::regprocedure::oid AS oid) r)<>96 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_fga_id_applied_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_fga_id_guard_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_journal_applied_v3()'::regprocedure::oid AS oid) r)<>1 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_sequence_guard_v3()'::regprocedure::oid AS oid) r)<>2 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_crud_unique_guard_v3()'::regprocedure::oid AS oid) r)<>6 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_sequence_origin_v3()'::regprocedure::oid AS oid) r)<>24 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.authority_sequence_program_applied_v3()'::regprocedure::oid AS oid) r)<>2 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.resource_journal_emit()'::regprocedure::oid AS oid) r)<>21 THEN RETURN false;END IF;
 IF (SELECT coalesce((trigger_counts->>r.oid::text)::bigint,
  (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid=r.oid))
  FROM (SELECT 'kaname.resource_journal_emit_member()'::regprocedure::oid AS oid) r)<>3 THEN RETURN false;END IF;
 -- Defaults принадлежат ровно тем же owned sequences; свободный nextval
 -- вместо wrapper вновь открыл бы after-clock unique arbitration.
 FOR expected IN SELECT * FROM (VALUES
  ('resource_journal','sequence_no','authority_resource_journal_id_v3()','resource_journal_sequence_no_seq'),
  ('fga_outbox','id','authority_fga_outbox_id_v3()','fga_outbox_id_seq')
 ) d(table_name,column_name,default_name,sequence_name) LOOP
  IF pg_get_serial_sequence('kaname.'||expected.table_name,expected.column_name)::regclass::oid
   IS DISTINCT FROM to_regclass('kaname.'||expected.sequence_name)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=to_regclass('kaname.'||expected.table_name) AND a.attname=expected.column_name AND NOT a.attisdropped
   AND pg_get_expr(d.adbin,d.adrelid)='kaname.'||expected.default_name) THEN RETURN false;END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','header']::text[] AND p.proargmodes=ARRAY['t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid]) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_protocol_snapshot_v3()'::regprocedure
  AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND p.proargnames=ARRAY['proof','compatibility_shared','compatibility_exclusive','population_oid',
   'population_shared','population_row_exclusive','population_extra_shared','population_extra_row_exclusive']::text[]
  AND p.proargmodes=ARRAY['t','t','t','t','t','t','t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'oid'::regtype::oid,
   'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid,'boolean'::regtype::oid]) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_native_delete_emit_v4(jsonb[])','void',1,ARRAY['p_payloads']),
  ('authority_native_delete_prepare_v4(jsonb[])','uuid',1,ARRAY['p_payloads']),
  ('authority_native_delete_stamp_v4(uuid,bigint,jsonb)','timestamptz',3,ARRAY['p_nonce','p_id','p_payload'])
 ) e(signature,result_type,nargs,names) LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
 WHERE p.oid IS NULL OR p.prokind<>'f' OR p.prorettype<>e.result_type::regtype OR p.proretset
 OR p.proisstrict OR p.proleakproof OR p.proparallel<>'u' OR p.pronargs<>e.nargs OR p.pronargdefaults<>0 OR p.provariadic<>0
 OR p.proargnames IS DISTINCT FROM e.names OR p.proargmodes IS NOT NULL OR p.proallargtypes IS NOT NULL
 OR p.prolang<>(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')) THEN RETURN false;END IF;
 RETURN kaname._authority_group_add_storage_v3() AND kaname._authority_forward_storage_v4();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(kaname.authority_protocol_tables()) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_statement' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=62
   AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=to_regclass('kaname.'||target)
   AND t.tgname='authority_protocol_row' AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=31
   AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure) THEN RETURN false; END IF;
 END LOOP;
 -- Catalog invalidation is part of the full writer ABI: no early row close
 -- and no missed commit close. Check both pg_trigger and its constraint row.
 IF (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure)<>6
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgfoid='kaname.authority_protocol_catalog_changed()'::regprocedure) THEN RETURN false; END IF;
 FOR target IN SELECT unnest(ARRAY['catalog_module','catalog_resource','catalog_verb']) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||target) AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p') THEN RETURN false; END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_constraint c ON c.oid=t.tgconstraint
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_changed'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=29
   AND t.tgdeferrable AND t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector
   AND c.contype='t' AND c.conname='authority_catalog_changed' AND c.conrelid=t.tgrelid AND c.condeferrable AND c.condeferred)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t
   WHERE t.tgrelid=to_regclass('kaname.'||target) AND t.tgname='authority_catalog_truncated'
   AND t.tgfoid='kaname._authority_protocol_catalog_changed_v3()'::regprocedure
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgtype::integer=32 AND t.tgconstraint=0
   AND NOT t.tgdeferrable AND NOT t.tginitdeferred AND t.tgnargs=0 AND t.tgqual IS NULL)
  THEN RETURN false; END IF;
 END LOOP;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_role_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Общий cutoff backstop принадлежит владельцу и действует на все INSERT/UPDATE.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='kaname.minted_token_revocations'::regclass
  AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR (SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='kaname.minted_token_revocations'::regclass
  AND tgname='authority_minted_cutoff_order_v3' AND tgfoid='kaname._authority_minted_cutoff_order_v3()'::regprocedure
  AND tgenabled='O' AND NOT tgisinternal AND tgtype::integer=23 AND tgnargs=0 AND tgqual IS NULL
  AND tgattr=''::int2vector AND tgconstraint=0 AND NOT tgdeferrable AND NOT tginitdeferred)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_sa_state_preflight_v3(text,boolean,text)'::regprocedure AND a.grantee<>owner_oid
  AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE' OR NOT EXISTS(
   SELECT 1 FROM pg_catalog.pg_proc e CROSS JOIN LATERAL aclexplode(e.proacl) g
   WHERE e.oid='kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'::regprocedure
   AND g.grantee=a.grantee AND g.privilege_type='EXECUTE'))) THEN RETURN false; END IF;
 -- Публичен только void-вход. PUBLIC, grant option и посторонний executor
 -- не являются частью approved runtime profile.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'
   OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc e
    CROSS JOIN LATERAL aclexplode(coalesce(e.proacl,acldefault('f',e.proowner))) g
    WHERE e.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
    AND g.grantee=a.grantee AND g.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p
  WHERE p.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure
  AND p.prorettype='void'::regtype AND p.provolatile='v'
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']) THEN RETURN false; END IF;
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_crud_storage_v3()','62d45446ad94410d718dea89036229c648a6cec5f3fd1bd09393cf3919691f34',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','e188d77b0c72ec88024fb6ab264e2ae639679213ff727b5c61946dfde596bdad',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3();
END $$;
-- +goose StatementEnd

DROP INDEX kaname.resource_parent_edge_direct_children;
DROP FUNCTION kaname._authority_child_parent_cascade_prewait_v1(jsonb,integer,integer);
DROP TABLE kaname.authority_child_creation,kaname.authority_child_parent_state;

-- +goose StatementBegin
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS NOT TRUE THEN
  RAISE EXCEPTION 'child registration state closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd
