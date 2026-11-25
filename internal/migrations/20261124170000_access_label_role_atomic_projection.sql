-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Атомарная проекция apply и подтверждение полного RequireRole доверенным writer.

-- +goose Up
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_role_actor_revoke_grants_v1(p_role oid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $revoke$
DECLARE role_name name;item record;
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 SELECT rolname INTO role_name FROM pg_catalog.pg_roles WHERE oid=p_role;
 IF NOT FOUND THEN RETURN;END IF;
 EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA kaname FROM %I',role_name);
 EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA kaname FROM %I',role_name);
 EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kaname FROM %I',role_name);
 -- Table REVOKE не снимает старые column ACL.
 FOR item IN SELECT c.relname,a.attname FROM pg_catalog.pg_attribute a
  JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='kaname' AND a.attnum>0 AND NOT a.attisdropped
   AND EXISTS(SELECT 1 FROM pg_catalog.aclexplode(a.attacl) x WHERE x.grantee=p_role::oid) LOOP
  EXECUTE format('REVOKE ALL (%I) ON TABLE kaname.%I FROM %I',item.attname,item.relname,role_name);
 END LOOP;
 EXECUTE format('REVOKE ALL ON SCHEMA kaname FROM %I',role_name);
 EXECUTE format('REVOKE CONNECT,TEMPORARY ON DATABASE %I FROM %I',current_database(),role_name);
END;
$revoke$;
-- Владелец миграций явно назначает две независимые учётные записи.
-- До назначения право подтверждать решение закрыто.
CREATE TABLE kaname.authority_role_actor_login (
 singleton boolean PRIMARY KEY CHECK (singleton),
 runtime_oid oid NOT NULL,
 runtime_name name NOT NULL,
 role_oid oid NOT NULL,
 role_name name NOT NULL,
 CONSTRAINT authority_role_actor_distinct
  CHECK (runtime_oid<>role_oid AND runtime_name<>role_name)
);
REVOKE ALL ON kaname.authority_role_actor_login FROM PUBLIC;

CREATE FUNCTION kaname._authority_role_actor_ordinary_login_v1(p_role oid) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $login$
 SELECT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid=p_role AND r.rolcanlogin
  AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname='kaname'
   AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='kaname' AND (c.relowner=r.oid OR (c.relkind IN ('r','p') AND has_table_privilege(r.oid,c.oid,'TRIGGER'))))
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace
   WHERE n.nspname='kaname' AND f.proowner=r.oid)
 )
$login$;

CREATE FUNCTION kaname._authority_role_actor_login_current_v1() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $current$
DECLARE caller_oid oid; enrolled kaname.authority_role_actor_login%ROWTYPE;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF current_setting('role') NOT IN ('none',session_user) THEN RETURN NULL;END IF;
 SELECT r.oid INTO caller_oid FROM pg_catalog.pg_roles r WHERE r.rolname=session_user;
 SELECT p.* INTO enrolled FROM kaname.authority_role_actor_login p WHERE p.singleton;
 IF NOT FOUND OR caller_oid IS DISTINCT FROM enrolled.role_oid
  OR session_user IS DISTINCT FROM enrolled.role_name OR enrolled.runtime_oid=caller_oid
  OR NOT kaname._authority_role_actor_ordinary_login_v1(caller_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid=caller_oid)
  OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.oid=enrolled.runtime_oid
    AND r.rolname=enrolled.runtime_name)
  OR has_table_privilege(caller_oid,'kaname.authority_role_actor_login','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') THEN
  RETURN NULL;
 END IF;
 RETURN jsonb_build_object('invoker_oid',caller_oid,'invoker_name',session_user);
END;
$current$;

CREATE FUNCTION kaname.authority_role_actor_login_ready_v1() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $ready$
 SELECT kaname._authority_role_actor_login_current_v1() IS NOT NULL
$ready$;

CREATE FUNCTION kaname.authority_role_actor_login_configure_v1(p_runtime regrole,p_role regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $configure$
DECLARE runtime_name name;role_name name;previous_oid oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_runtime IS NULL AND p_role IS NULL THEN
  PERFORM kaname.authority_protocol_drain();
  DELETE FROM kaname.authority_role_actor_login WHERE singleton RETURNING role_oid INTO previous_oid;
  IF FOUND THEN PERFORM kaname._authority_role_actor_revoke_grants_v1(previous_oid);END IF;
  RETURN;
 END IF;
 IF p_runtime IS NULL OR p_role IS NULL OR p_runtime=p_role
  OR NOT kaname._authority_role_actor_ordinary_login_v1(p_runtime::oid)
  OR NOT kaname._authority_role_actor_ordinary_login_v1(p_role::oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid=p_role::oid) THEN
  RAISE EXCEPTION 'role actor enrollment requires distinct restricted LOGINs' USING ERRCODE='42501';END IF;
 SELECT r.rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles r WHERE r.oid=p_runtime::oid;
 SELECT r.rolname INTO STRICT role_name FROM pg_catalog.pg_roles r WHERE r.oid=p_role::oid;
 PERFORM kaname.authority_protocol_drain();
 SELECT p.role_oid INTO previous_oid FROM kaname.authority_role_actor_login p WHERE p.singleton FOR UPDATE;
 IF FOUND AND previous_oid<>p_role::oid THEN
  PERFORM kaname._authority_role_actor_revoke_grants_v1(previous_oid);
 END IF;
 INSERT INTO kaname.authority_role_actor_login AS p(singleton,runtime_oid,runtime_name,role_oid,role_name)
 VALUES(true,p_runtime::oid,runtime_name,p_role::oid,role_name)
 ON CONFLICT(singleton) DO UPDATE SET runtime_oid=EXCLUDED.runtime_oid,runtime_name=EXCLUDED.runtime_name,
  role_oid=EXCLUDED.role_oid,role_name=EXCLUDED.role_name
 WHERE (p.runtime_oid,p.runtime_name,p.role_oid,p.role_name)
  IS DISTINCT FROM (EXCLUDED.runtime_oid,EXCLUDED.runtime_name,EXCLUDED.role_oid,EXCLUDED.role_name);
 PERFORM kaname.authority_role_actor_grant_v1(p_role);
END;
$configure$;

DO $custody$
DECLARE sig text; grantee record; owner_oid oid:=current_user::regrole::oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
  CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE c.oid='kaname.authority_role_actor_login'::regclass AND a.grantee<>owner_oid LOOP
  EXECUTE format('REVOKE ALL ON kaname.authority_role_actor_login FROM %I',grantee.rolname);
 END LOOP;
 FOREACH sig IN ARRAY ARRAY['_authority_role_actor_revoke_grants_v1(oid)','_authority_role_actor_ordinary_login_v1(oid)',
  '_authority_role_actor_login_current_v1()','authority_role_actor_login_ready_v1()',
  'authority_role_actor_login_configure_v1(regrole,regrole)'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',sig);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||sig) AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',sig,grantee.rolname);
  END LOOP;
 END LOOP;
END;
$custody$;

-- Учётная запись writer принадлежит доверенному процессу Kaname.
-- Go вызывает функцию только после успешной полной проверки RequireRole
-- на том же writer. В бюджете попытки заранее удерживаются 8 строк и 4 чтения.
CREATE FUNCTION kaname.authority_role_access_label_content_approved_v1() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $approved$
DECLARE proof jsonb;header jsonb;identity jsonb;frozen jsonb;transition jsonb;actor jsonb;
 final_clock timestamptz;prepared_clock timestamptz;root_untouched boolean;operation text;scope jsonb;
 approval jsonb;
BEGIN
 SELECT q.proof,q.header INTO STRICT proof,header FROM kaname._authority_sequence_probe_v3() q;
 IF proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'purpose' IS DISTINCT FROM 'decision' OR proof->>'kind' IS DISTINCT FROM 'role'
  OR header->>'family' IS DISTINCT FROM 'role'
  OR header#>>'{frozen,mode}' IS DISTINCT FROM 'access_label_transition'
  OR jsonb_typeof(header->'selected') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'role apply approval requires exact prepared role writer' USING ERRCODE='42501';END IF;
 identity:=kaname._authority_role_actor_login_current_v1();
 IF identity IS NULL OR identity->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid' THEN
  RAISE EXCEPTION 'role apply approval requires enrolled application identity' USING ERRCODE='42501';END IF;
 SELECT s.frozen,s.decision_at,s.staged_decision_at,
   e.selected AND NOT e.registered AND NOT e.claimed AND NOT e.consumed
   AND e.table_name='resource_journal' AND e.origin->>'table'='roles'
 INTO frozen,final_clock,prepared_clock,root_untouched
 FROM pg_temp.kaname_authority_sequence_program s
 LEFT JOIN pg_temp.kaname_authority_sequence_effects e ON e.ordinal=1 AND e.nonce=s.nonce
 WHERE s.singleton AND s.family='role' AND s.nonce=(proof->>'nonce')::uuid
  AND s.frozen_mode='access_label_transition' AND s.frozen->>'kind'='role.mutation';
 IF NOT FOUND OR root_untouched IS DISTINCT FROM true
  OR final_clock IS NULL OR prepared_clock IS NULL OR final_clock<=prepared_clock
  OR final_clock IS DISTINCT FROM (proof->>'decision_at')::timestamptz
  OR frozen ? 'access_label_method_authorized' OR frozen ? 'access_label_transition_applied' THEN
  RAISE EXCEPTION 'role apply approval program is absent or consumed' USING ERRCODE='42501';END IF;
 transition:=frozen->'access_label_transition';
 actor:=frozen#>'{access_label_authority,actor}';
 IF jsonb_typeof(transition) IS DISTINCT FROM 'object'
  OR coalesce(transition->>'role_id','')='' OR coalesce(transition->>'new_digest','') !~ '^[0-9a-f]{64}$'
  OR jsonb_typeof(actor) IS DISTINCT FROM 'object'
  OR actor->>'type' IS NULL OR actor->>'type' NOT IN ('user','service_account')
  OR actor-ARRAY['type','id']<>'{}'::jsonb OR coalesce(actor->>'id','')=''
  OR (actor->>'id')~'[:#*[:space:][:cntrl:]]'
  OR jsonb_typeof(transition->'new_projection') IS DISTINCT FROM 'array'
  OR jsonb_typeof(frozen->'access_label_required_questions') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'role apply approval lacks exact positive authoring operation' USING ERRCODE='42501';END IF;
 IF frozen#>>'{access_label_scope_census,mode}'='revoke' THEN
  IF frozen->'create' IS DISTINCT FROM 'false'::jsonb
   OR frozen#>'{request,rules}' IS DISTINCT FROM 'true'::jsonb
   OR transition->'new_projection' IS DISTINCT FROM '[]'::jsonb
   OR jsonb_typeof(transition->'old_projection') IS DISTINCT FROM 'array'
   OR transition->'old_projection'='[]'::jsonb
   OR frozen->'access_label_required_questions' IS DISTINCT FROM '[]'::jsonb
   OR frozen ? 'access_label_source_store_oid' THEN
   RAISE EXCEPTION 'role revoke approval requires exact empty positive image' USING ERRCODE='42501';END IF;
 ELSIF frozen#>>'{access_label_scope_census,mode}'='apply' THEN
  IF jsonb_array_length(transition->'new_projection')=0
   OR jsonb_array_length(frozen->'access_label_required_questions') NOT BETWEEN 1 AND 4096 THEN
   RAISE EXCEPTION 'role apply approval requires positive image' USING ERRCODE='42501';END IF;
 ELSE
  RAISE EXCEPTION 'role content approval mode is absent' USING ERRCODE='42501';
 END IF;
 operation:=CASE frozen->'create' WHEN 'true'::jsonb THEN 'role.create' WHEN 'false'::jsonb THEN 'role.update' END;
 scope:=CASE WHEN nullif(transition#>>'{new_row,project_id}','') IS NOT NULL
  THEN jsonb_build_object('type','project','id',transition#>>'{new_row,project_id}')
  ELSE jsonb_build_object('type','account','id',transition#>>'{new_row,account_id}') END;
 IF operation IS NULL OR coalesce(scope->>'id','')='' THEN
  RAISE EXCEPTION 'role apply approval coordinates differ' USING ERRCODE='42501';END IF;
 approval:=jsonb_build_object('result','allow','contract','RequireRole/v1',
  'mode',frozen#>>'{access_label_scope_census,mode}',
  'operation',operation,'role_id',transition->>'role_id','scope',scope,'actor',actor,
  'new_digest',transition->>'new_digest','decision_at',final_clock,
  'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce');
 UPDATE pg_temp.kaname_authority_sequence_program s
  SET frozen=s.frozen||jsonb_build_object('access_label_method_authorized',approval)
 WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=final_clock
  AND s.frozen_mode='access_label_transition'
  AND NOT (s.frozen ? 'access_label_method_authorized');
 IF NOT FOUND THEN
  RAISE EXCEPTION 'role apply approval program changed' USING ERRCODE='42501';END IF;
END;
$approved$;
REVOKE ALL ON FUNCTION kaname.authority_role_access_label_content_approved_v1() FROM PUBLIC;

DO $role_content_private$
DECLARE grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_role_access_label_content_approved_v1()'::regprocedure
    AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_role_access_label_content_approved_v1() FROM %I',grantee.rolname);
 END LOOP;
END;
$role_content_private$;

CREATE FUNCTION kaname.authority_role_actor_grant_v1(p_role regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $grant$
DECLARE role_name name;item record;signature text;owner_oid oid:=current_user::regrole::oid;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_role IS NULL OR NOT kaname._authority_role_actor_ordinary_login_v1(p_role::oid)
  OR NOT EXISTS(SELECT 1 FROM kaname.authority_role_actor_login e
   JOIN pg_catalog.pg_roles r ON r.oid=e.role_oid AND r.rolname=e.role_name
   WHERE e.singleton AND e.role_oid=p_role::oid AND e.runtime_oid<>e.role_oid)
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE roleid=p_role::oid) THEN
  RAISE EXCEPTION 'finite role profile requires independent enrolled LOGIN' USING ERRCODE='42501';END IF;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'finite role profile requires intact writer closure' USING ERRCODE='55000';END IF;
 SELECT rolname INTO STRICT role_name FROM pg_catalog.pg_roles WHERE oid=p_role::oid;
 PERFORM kaname.authority_protocol_require_drain();
 -- Перевыдача заменяет direct grants только выделенного LOGIN. PUBLIC не меняем.
 -- ALL применяется к REVOKE, никогда к выдаче business прав.
 PERFORM kaname._authority_role_actor_revoke_grants_v1(p_role::oid);
 EXECUTE format('GRANT CONNECT,TEMPORARY ON DATABASE %I TO %I',current_database(),role_name);
 EXECUTE format('GRANT USAGE ON SCHEMA kaname TO %I',role_name);
 -- Чтение native sources, checkpoints, discovery и обычных role views.
 FOR item IN SELECT unnest(ARRAY[
  'accounts','projects','clusters','users','service_accounts','groups','group_members','memberships',
  'cluster_admin_grants','roles','grant_delegations','access_bindings','access_binding_subjects',
  'access_binding_target_members','access_binding_emitted_tuples','role_rule_selectors',
  'role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
  'role_grant_orphan','role_selector_prune','catalog_module','catalog_resource','catalog_verb',
  'relation_fact','producer_source_receipt','public_read_publication','resource_mirror','resource_parent_edge',
  'resource_scope_edge','resource_registration_scope','resource_registration_pointer','resource_registration_retirement',
  'resource_journal','fga_outbox','resource_reconcile_outbox','audit_outbox','authority_semantic_identity'
 ]) AS table_name LOOP
  EXECUTE format('GRANT SELECT ON TABLE kaname.%I TO %I',item.table_name,role_name);
 END LOOP;
 -- Только actual Role Create/Update и их обычные проекции; Role.Delete не выдан.
 EXECUTE format('GRANT INSERT,UPDATE ON TABLE kaname.roles TO %I',role_name);
 EXECUTE format('GRANT INSERT,UPDATE,DELETE ON TABLE kaname.role_rule_selectors TO %I',role_name);
 FOR item IN SELECT unnest(ARRAY['role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule']) AS table_name LOOP
  EXECUTE format('GRANT INSERT,DELETE,UPDATE(role_id) ON TABLE kaname.%I TO %I',item.table_name,role_name);
 END LOOP;
 EXECUTE format('GRANT DELETE,UPDATE(role_id) ON TABLE kaname.role_selector_verbs_pending TO %I',role_name);
 EXECUTE format('GRANT INSERT,DELETE,UPDATE(binding_id) ON TABLE kaname.access_binding_emitted_tuples TO %I',role_name);
 -- Promotion меняет только version. Создание/снятие/перепривязка carrier закрыты ACL.
 EXECUTE format('GRANT UPDATE(grant_capability_version) ON TABLE kaname.access_bindings TO %I',role_name);
 -- PostgreSQL row locking требует UPDATE хотя бы одной колонки. Actual source
 -- mutation по этим координатам дополнительно отвергается existing role program.
 FOR item IN SELECT * FROM (VALUES ('accounts','id'),('projects','id'),
  ('catalog_module','module'),('catalog_resource','dotted'),('catalog_verb','verb')) x(table_name,column_name) LOOP
  EXECUTE format('GRANT UPDATE(%I) ON TABLE kaname.%I TO %I',item.column_name,item.table_name,role_name);
 END LOOP;
 -- Invoker FGA fold и journal emitter исполняются в той же signed транзакции.
 EXECUTE format('GRANT INSERT,UPDATE,DELETE ON TABLE kaname.relation_fact TO %I',role_name);
 FOR item IN SELECT unnest(ARRAY['fga_outbox','resource_journal','resource_reconcile_outbox','audit_outbox']) AS table_name LOOP
  EXECUTE format('GRANT INSERT ON TABLE kaname.%I TO %I',item.table_name,role_name);
 END LOOP;
 EXECUTE format('GRANT USAGE ON SEQUENCE kaname.resource_reconcile_outbox_id_seq,kaname.resource_journal_sequence_no_seq,kaname.fga_outbox_id_seq TO %I',role_name);
 -- Approval seat единственный: снимаем в том числе named default grants
 -- и старый seat после reenrollment, затем ниже выдаём ровно текущему LOGIN.
 REVOKE ALL ON FUNCTION kaname.authority_role_access_label_content_approved_v1() FROM PUBLIC;
 FOR item IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_role_access_label_content_approved_v1()'::regprocedure
   AND a.grantee<>owner_oid LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_role_access_label_content_approved_v1() FROM %I',item.rolname);
 END LOOP;
 -- Закрытый список ABI. Ни lifecycle activation, ни group/binding/delegation
 -- prepare, ни forward/native-delete программы через этот профиль не выдаются.
 FOREACH signature IN ARRAY ARRAY[
  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_protocol_discover(jsonb)','authority_protocol_row_account(text,jsonb)',
  'authority_protocol_row_scopes(text,jsonb)','authority_protocol_attestation()',
  'authority_protocol_read_bundle()',
  'authority_full_contract_validate_v3(text,text,text)','authority_staged_contract_validate_v3()',
  'authority_policy_epoch_read(text[])','authority_policy_epoch_lock(jsonb)',
  'authority_policy_epoch_lock_for_write(jsonb,text[])','authority_policy_epoch_lock_full_v2(jsonb,text[],jsonb,integer)',
  'authority_policy_population_read(integer)','authority_policy_object_account(text,text)',
  'authority_binding_epoch_read(text[])','authority_binding_mutation_scopes(text,jsonb)',
  'authority_role_stage_epoch_lock(text[],jsonb)','authority_role_prelock_admit_v3()',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)','authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_compare_epoch_read_v2(text[])','authority_compare_full_v2(text,text[],text,text,text,jsonb,jsonb,integer)',
  'authority_compare_identity_v2(text,text,text)',
  'authority_resource_journal_id_v3()','authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  -- Эти две функции вызываются invoker fold как диспетчеры; не открывают prepare.
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_resource_fold_body_v2(text,jsonb,timestamptz)',
  'relation_fact_fold_row(text,jsonb,timestamptz)',
  'resource_journal_project(text,jsonb)','resource_journal_scope(text,jsonb)',
  'authority_access_label_role_checkpoint_read_v1(text,text,text,integer)',
  'authority_role_access_label_source_read_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)',
  'authority_role_actor_login_ready_v1()','authority_role_access_label_content_approved_v1()'
 ] LOOP
  IF to_regprocedure('kaname.'||signature) IS NULL THEN
   RAISE EXCEPTION 'finite role profile ABI missing: %',signature USING ERRCODE='55000';END IF;
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,role_name);
 END LOOP;
 -- PUBLIC или изменённый default grant не должен открыть private storage/core.
 IF has_table_privilege(p_role,'kaname.authority_role_actor_login','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
  OR has_table_privilege(p_role,'kaname.authority_role_access_label_rule','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
  OR has_table_privilege(p_role,'kaname.authority_access_label_definition','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
  OR has_function_privilege(p_role,'kaname._authority_access_label_role_source_store_v1()','EXECUTE')
  OR has_function_privilege(p_role,'kaname.authority_role_access_label_source_check_v1(text,text,text,timestamptz,text,text,text,text,text,text,text,text,text,text,uuid,text,jsonb,integer,integer)','EXECUTE')
  OR has_function_privilege(p_role,'kaname.authority_access_label_role_projection_apply_v1(jsonb,text,text)','EXECUTE') THEN
  RAISE EXCEPTION 'finite role profile has private access through inherited ACL' USING ERRCODE='42501';END IF;
END;
$grant$;
REVOKE ALL ON FUNCTION kaname.authority_role_actor_grant_v1(regrole) FROM PUBLIC;
DO $private$
DECLARE grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname.authority_role_actor_grant_v1(regrole)'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_role_actor_grant_v1(regrole) FROM %I',grantee.rolname);
 END LOOP;
END
$private$;

-- +goose StatementEnd
-- +goose StatementBegin
DO $access_label_role_atomic_projection$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением атомарной записи проекции роли' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4','0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e',$patch$[
  [
    "   IF access_label_transition->'new_projection'<>'[]'::jsonb THEN",
    "   IF access_label_transition->'new_projection'<>'[]'::jsonb OR access_label_transition->'old_projection'<>'[]'::jsonb THEN"
  ],
  [
    "     -- Clean revoke не требует apply authority или fallback expansion.",
    "     -- Revoke удаляет protected projection; полный RequireRole остаётся обязательным.\n     IF creation OR NOT promote OR access_label_authority_input->'questions' IS DISTINCT FROM '[]'::jsonb THEN\n      RAISE EXCEPTION 'role revoke requires update rules with empty positive questions' USING ERRCODE='42501';END IF;\n     -- Finalize сохраняет канонический пустой census без source store.\n     scanned:=scanned+2;reads:=reads+1;"
  ],
  [
    "    access_label_frozen:=jsonb_build_object('mode','access_label_transition',",
    "    -- Два bounded снимка: после apply и один раз после exact completion.\n    -- Reserve включает role/program/probe overhead; legacy путь не меняется.\n    scanned:=scanned+2*jsonb_array_length(access_label_transition->'new_projection')+8;\n    reads:=reads+8;\n    IF scanned>p_rows OR reads>p_reads THEN\n     RAISE EXCEPTION 'role access label projection completion budget' USING ERRCODE='54000';END IF;\n    access_label_transition:=access_label_transition||jsonb_build_object('write_reserve',\n     jsonb_build_object('rows',2*jsonb_array_length(access_label_transition->'new_projection')+8,'reads',8));\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',"
  ],
  [
    " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
    " IF access_label_frozen#>>'{access_label_scope_census,mode}' IN ('apply','revoke') THEN\n  -- Полная сверка receipt points оплачивается до decision clock.\n  scanned:=scanned+4+jsonb_array_length(access_label_frozen#>'{access_label_scope_census,scopes}')\n   +jsonb_array_length(access_label_frozen#>'{access_label_scope_census,new_definitions}')\n   +3*(access_label_frozen#>>'{access_label_scope_census,max_questions}')::integer;\n  reads:=reads+2;\n  IF scanned>p_rows OR reads>p_reads THEN\n   RAISE EXCEPTION 'role access label receipt completion budget' USING ERRCODE='54000';END IF;\n  access_label_transition:=access_label_transition||jsonb_build_object('authorization_reserve',\n   jsonb_build_object('rows',4+jsonb_array_length(access_label_frozen#>'{access_label_scope_census,scopes}')\n    +jsonb_array_length(access_label_frozen#>'{access_label_scope_census,new_definitions}')\n    +3*(access_label_frozen#>>'{access_label_scope_census,max_questions}')::integer,'reads',2));\n  access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_transition',access_label_transition);\n END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
  ],
  [
    " RETURN jsonb_build_object('rows',scanned,'reads',reads+cost);",
    " RETURN jsonb_build_object('rows',scanned,'reads',reads+cost,'access_label_mode',\n  coalesce(access_label_frozen#>>'{access_label_scope_census,mode}','ordinary'));"
  ]
]$patch$::jsonb),
        ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362','959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940',$patch$[
  [
    "    actual jsonb;",
    "    actual jsonb;actual_projection jsonb;written_xmin text;written_ctid text;"
  ],
  [
    "    target_role_id:=transition->>'role_id';",
    "    target_role_id:=transition->>'role_id';\n    IF transition->'write_reserve' IS DISTINCT FROM jsonb_build_object(\n       'rows',2*jsonb_array_length(transition->'new_projection')+8,'reads',8) THEN\n        RAISE EXCEPTION 'access label projection write reserve missing' USING ERRCODE='42501';END IF;"
  ],
  [
    "    SELECT to_jsonb(r) INTO STRICT actual FROM kaname.roles r WHERE r.id=target_role_id FOR UPDATE;",
    "    SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO STRICT actual,written_xmin,written_ctid FROM kaname.roles r WHERE r.id=target_role_id FOR UPDATE;"
  ],
  [
    "    UPDATE pg_temp.kaname_authority_sequence_program s\n    SET frozen_mode='access_label_transition',",
    "    -- Сверяем весь результат, включая unchanged pairs; лишняя строка\n    -- попадает в sentinel и не превращается в успешную частичную проекцию.\n    SELECT coalesce(jsonb_agg(jsonb_build_array(p.rule_fp,p.definition_id)\n      ORDER BY p.rule_fp COLLATE \"C\",p.definition_id),'[]'::jsonb)\n    INTO actual_projection FROM (\n      SELECT q.rule_fp,q.definition_id FROM kaname.authority_role_access_label_rule q\n      WHERE q.role_id=target_role_id ORDER BY q.rule_fp COLLATE \"C\",q.definition_id\n      LIMIT jsonb_array_length(transition->'new_projection')+1\n    ) p;\n    IF actual_projection IS DISTINCT FROM transition->'new_projection' THEN\n      RAISE EXCEPTION 'access label projection written image differs' USING ERRCODE='40001';END IF;\n    UPDATE pg_temp.kaname_authority_sequence_program s\n    SET frozen_mode='access_label_transition',"
  ],
  [
    "        frozen=s.frozen||jsonb_build_object('access_label_transition_applied',true)",
    "        frozen=s.frozen||jsonb_build_object('access_label_authorized',authorized,'access_label_transition_applied',true,\n         'access_label_applied_generation',jsonb_build_object('xmin',written_xmin,'ctid',written_ctid,\n          'new_digest',transition->>'new_digest'))"
  ],
  [
    "    -- Обязательство остаётся в программе. Существующий completion отклоняет\n    -- commit до подключения проверки полномочий и признака применения.",
    "    -- Completion повторно проверяет точную записанную строку и весь набор pairs."
  ],
  [
    "written_ctid text;",
    "written_ctid text;\n    authorized jsonb;required_questions jsonb;authorization_actor jsonb;\n    question jsonb;canonical_questions jsonb;question_definition_id uuid;final_clock timestamptz;prepared_clock timestamptz;program_frozen jsonb;method_authorized jsonb;expected_method jsonb;source_store oid;actual_points jsonb;expected_points jsonb;"
  ],
  [
    "    SELECT s.frozen->'access_label_transition' INTO STRICT transition",
    "    SELECT s.frozen->'access_label_transition',s.frozen->'access_label_authorized',\n      s.frozen->'access_label_required_questions',s.frozen#>'{access_label_authority,actor}',s.decision_at,s.staged_decision_at,s.frozen,s.frozen->'access_label_method_authorized'\n    INTO STRICT transition,authorized,required_questions,authorization_actor,final_clock,prepared_clock,program_frozen,method_authorized"
  ],
  [
    "    target_role_id:=transition->>'role_id';\n",
    "    target_role_id:=transition->>'role_id';\n    -- Ни actor из request, ни одни source positives не подтверждают method.\n    -- Положительная квитанция подтверждает полный RequireRole на доверенном writer.\n    IF jsonb_typeof(method_authorized) IS DISTINCT FROM 'object'\n       OR jsonb_typeof(required_questions) IS DISTINCT FROM 'array'\n       OR jsonb_typeof(authorization_actor) IS DISTINCT FROM 'object'\n       OR final_clock IS NULL OR prepared_clock IS NULL OR final_clock<=prepared_clock\n       OR final_clock IS DISTINCT FROM (proof->>'decision_at')::timestamptz\n       OR jsonb_typeof(program_frozen->'create') IS DISTINCT FROM 'boolean' THEN\n      RAISE EXCEPTION 'role access label independent method result is absent' USING ERRCODE='42501';END IF;\n    IF authorization_actor-ARRAY['type','id']<>'{}'::jsonb\n       OR authorization_actor->>'type' IS NULL\n       OR authorization_actor->>'type' NOT IN ('user','service_account')\n       OR jsonb_typeof(authorization_actor->'id') IS DISTINCT FROM 'string'\n       OR coalesce(authorization_actor->>'id','')=''\n       OR (authorization_actor->>'id')~'[:#*[:space:][:cntrl:]]'\n       OR program_frozen->>'id' IS DISTINCT FROM target_role_id\n       OR program_frozen#>>'{access_label_authority,role_id}' IS DISTINCT FROM target_role_id\n       OR program_frozen#>>'{access_label_authority,new_digest}' IS DISTINCT FROM transition->>'new_digest'\n       OR coalesce(program_frozen#>>'{access_label_scope_census,mode}','') NOT IN ('apply','revoke') THEN\n      RAISE EXCEPTION 'role access label authorization identity differs' USING ERRCODE='42501';END IF;\n    IF program_frozen#>>'{access_label_scope_census,mode}'='revoke' THEN\n      IF program_frozen->'create' IS DISTINCT FROM 'false'::jsonb\n       OR program_frozen#>'{request,rules}' IS DISTINCT FROM 'true'::jsonb\n       OR transition->'new_projection' IS DISTINCT FROM '[]'::jsonb\n       OR jsonb_typeof(transition->'old_projection') IS DISTINCT FROM 'array'\n       OR transition->'old_projection'='[]'::jsonb\n       OR required_questions IS DISTINCT FROM '[]'::jsonb\n       OR program_frozen ? 'access_label_source_store_oid' THEN\n        RAISE EXCEPTION 'role revoke requires exact empty positive image' USING ERRCODE='42501';END IF;\n    ELSIF jsonb_array_length(required_questions) NOT BETWEEN 1 AND 4096 THEN\n      RAISE EXCEPTION 'role apply requires positive questions' USING ERRCODE='42501';\n    END IF;\n    expected_method:=jsonb_build_object('result','allow','contract','RequireRole/v1',\n      'mode',program_frozen#>>'{access_label_scope_census,mode}',\n      'operation',CASE WHEN (program_frozen->>'create')::boolean THEN 'role.create' ELSE 'role.update' END,\n      'role_id',target_role_id,'scope',CASE WHEN nullif(transition#>>'{new_row,project_id}','') IS NOT NULL\n        THEN jsonb_build_object('type','project','id',transition#>>'{new_row,project_id}')\n        ELSE jsonb_build_object('type','account','id',transition#>>'{new_row,account_id}') END,\n      'actor',authorization_actor,'new_digest',transition->>'new_digest','decision_at',final_clock,\n      'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce');\n    IF method_authorized IS DISTINCT FROM expected_method THEN\n      RAISE EXCEPTION 'role access label independent method result differs' USING ERRCODE='42501';END IF;\n    -- Пересчитываем чистый owner census на запечатанном clock. Declared questions\n    -- никогда не подменяют полный набор обязательств.\n    canonical_questions:=kaname.authority_access_label_role_required_questions_v1(program_frozen,final_clock);\n    IF canonical_questions IS DISTINCT FROM required_questions THEN\n      RAISE EXCEPTION 'role access label required census differs' USING ERRCODE='42501';END IF;\n    FOR question IN SELECT value FROM jsonb_array_elements(required_questions) LOOP\n      question_definition_id:=(question->>'definition_id')::uuid;\n      IF transition#>>ARRAY['definition_witnesses',question_definition_id::text,'scope_kind'] IS DISTINCT FROM question->>'scope_kind'\n       OR transition#>>ARRAY['definition_witnesses',question_definition_id::text,'scope_id'] IS DISTINCT FROM question->>'scope_id' THEN\n       RAISE EXCEPTION 'role access label required point lacks held definition' USING ERRCODE='42501';END IF;\n    END LOOP;\n    IF EXISTS(SELECT 1 FROM (\n       (SELECT value->>1 FROM jsonb_array_elements(transition->'new_projection')\n        EXCEPT SELECT value->>'definition_id' FROM jsonb_array_elements(required_questions))\n       UNION ALL\n       (SELECT value->>'definition_id' FROM jsonb_array_elements(required_questions)\n        EXCEPT SELECT value->>1 FROM jsonb_array_elements(transition->'new_projection'))\n      ) mismatch) THEN\n      RAISE EXCEPTION 'role access label required definition set differs' USING ERRCODE='42501';END IF;\n    IF transition->'authorization_reserve' IS DISTINCT FROM jsonb_build_object(\n      'rows',4+jsonb_array_length(program_frozen#>'{access_label_scope_census,scopes}')\n       +jsonb_array_length(program_frozen#>'{access_label_scope_census,new_definitions}')\n       +3*(program_frozen#>>'{access_label_scope_census,max_questions}')::integer,'reads',2)\n      OR jsonb_array_length(required_questions)>(program_frozen#>>'{access_label_scope_census,max_questions}')::integer THEN\n      RAISE EXCEPTION 'role access label receipt completion reserve absent' USING ERRCODE='42501';END IF;\n    IF program_frozen#>>'{access_label_scope_census,mode}'='apply' THEN\n    source_store:=(program_frozen->>'access_label_source_store_oid')::oid;\n    IF source_store IS NULL\n      OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid\n      OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=source_store\n       AND c.relowner=current_user::regrole::oid AND c.relnamespace=pg_my_temp_schema()\n       AND c.relpersistence='t' AND c.relkind='r'\n       AND NOT (c.relhasrules OR c.relrowsecurity OR c.relhastriggers OR c.relhassubclass)\n       AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a\n        WHERE a.grantee<>c.relowner)) THEN\n      RAISE EXCEPTION 'role access label source receipt custody differs' USING ERRCODE='42501';END IF;\n    -- Единственный полный bounded снимок: лишние/чужие nonce и false видны.\n    -- PK уже проверен до freeze; не вызываем store helper, требующий пустоту.\n    SELECT coalesce(jsonb_agg(jsonb_build_array(q.nonce,q.scope_kind,q.scope_id,q.definition_id,q.satisfied)\n      ORDER BY q.nonce,q.scope_kind COLLATE \"C\",q.scope_id COLLATE \"C\",q.definition_id),'[]'::jsonb)\n      INTO actual_points FROM (\n       SELECT nonce,scope_kind,scope_id,definition_id,satisfied\n       FROM ONLY pg_temp.kaname_authority_access_label_role_source\n       ORDER BY nonce,scope_kind COLLATE \"C\",scope_id COLLATE \"C\",definition_id\n       LIMIT jsonb_array_length(required_questions)+1\n      ) q;\n    SELECT jsonb_agg(jsonb_build_array((proof->>'nonce')::uuid,q->>'scope_kind',q->>'scope_id',\n      (q->>'definition_id')::uuid,true)\n      ORDER BY (q->>'scope_kind') COLLATE \"C\",(q->>'scope_id') COLLATE \"C\",(q->>'definition_id')::uuid)\n      INTO expected_points FROM jsonb_array_elements(required_questions) q;\n    IF actual_points IS DISTINCT FROM expected_points THEN\n      RAISE EXCEPTION 'role access label source receipts incomplete or changed' USING ERRCODE='42501';END IF;\n    ELSE\n      -- Отзыв не создаёт source store. Его пустой census доказан owner выше.\n      source_store:=NULL;\n    END IF;\n    -- Сводная квитанция возникает только здесь после method и полного source set.\n    authorized:=jsonb_build_object('result','allow','role_id',target_role_id,\n      'mode',program_frozen#>>'{access_label_scope_census,mode}',\n      'actor',authorization_actor,'new_digest',transition->>'new_digest','decision_at',final_clock,\n      'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce',\n      'source_store_oid',source_store,'source_count',jsonb_array_length(required_questions),\n      'required_questions_digest',encode(sha256(convert_to(required_questions::text,'UTF8')),'hex'),\n      'method_authorized_digest',encode(sha256(convert_to(method_authorized::text,'UTF8')),'hex'));\n"
  ],
  [
    "'new_digest',transition->>'new_digest'))",
    "'new_digest',transition->>'new_digest',\n          'authorization_digest',encode(sha256(convert_to(authorized::text,'UTF8')),'hex')))"
  ]
]$patch$::jsonb),
        ('authority_sequence_origin_v3()','d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3','5967a2d8acb0d1dc2dc6efea8124479bdc105c5c8cb59a689809974e7439a244',$patch$[
  [
    "  -- Отсутствующий owner после FK cascade штатно не эмитит member event.",
    "  -- Штатный roles_000_* AFTER источник уже зарегистрирован. Private\n  -- projection применяется до journal emitter в той же транзакции.\n  IF TG_TABLE_NAME='roles' AND program->>'family'='role' THEN\n   IF program#>>'{frozen,mode}'='access_label_transition_complete' THEN\n    RAISE EXCEPTION 'access label role program already completed' USING ERRCODE='42501';END IF;\n   IF program#>>'{frozen,mode}'='access_label_transition' THEN\n    IF TG_WHEN<>'AFTER' OR TG_OP NOT IN ('INSERT','UPDATE') OR matches<>1 THEN\n     RAISE EXCEPTION 'access label atomic role origin missing' USING ERRCODE='42501';END IF;\n    PERFORM kaname.authority_access_label_role_projection_apply_v1(actual_origin,\n     CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.xmin::text END,\n     CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.ctid::text END);\n   END IF;\n  END IF;\n  -- Отсутствующий owner после FK cascade штатно не эмитит member event."
  ]
]$patch$::jsonb),
        ('_authority_sequence_complete_v3()','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05',$patch$[
  [
    "DECLARE program jsonb;",
    "DECLARE program jsonb;transition jsonb;generation jsonb;applied jsonb;actual jsonb;actual_projection jsonb;current_xmin text;current_ctid text;"
  ],
  [
    " -- Режим берётся из проверенного заголовка owner program.\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';\n END IF;\n",
    " -- Access label completion follows the exact selected-effect checks below.\n"
  ],
  [
    "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\nEND ",
    "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  SELECT s.frozen->'access_label_transition',s.frozen->'access_label_applied_generation',\n   s.frozen->'access_label_transition_applied' INTO transition,generation,applied\n  FROM pg_temp.kaname_authority_sequence_program s\n  WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen->>'kind'='role.mutation';\n  IF NOT FOUND OR applied IS DISTINCT FROM 'true'::jsonb\n   OR jsonb_typeof(transition) IS DISTINCT FROM 'object'\n   OR jsonb_typeof(generation) IS DISTINCT FROM 'object'\n   OR jsonb_typeof(transition->'new_projection') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(transition->'new_row') IS DISTINCT FROM 'object'\n   OR coalesce(transition->>'role_id','')='' THEN\n   RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(transition->'new_projection')>16384\n   OR transition->'write_reserve' IS DISTINCT FROM jsonb_build_object(\n    'rows',2*jsonb_array_length(transition->'new_projection')+8,'reads',8)\n   OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest' THEN\n   RAISE EXCEPTION 'role access label completion reserve or image missing' USING ERRCODE='42501';END IF;\n  SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO actual,current_xmin,current_ctid\n   FROM kaname.roles r WHERE r.id=transition->>'role_id';\n  IF NOT FOUND OR actual IS DISTINCT FROM transition->'new_row'\n   OR current_xmin IS DISTINCT FROM generation->>'xmin'\n   OR current_ctid IS DISTINCT FROM generation->>'ctid'\n   OR encode(sha256(convert_to(actual::text,'UTF8')),'hex') IS DISTINCT FROM transition->>'new_digest' THEN\n   RAISE EXCEPTION 'role access label completed generation differs' USING ERRCODE='40001';END IF;\n  SELECT coalesce(jsonb_agg(jsonb_build_array(p.rule_fp,p.definition_id)\n    ORDER BY p.rule_fp COLLATE \"C\",p.definition_id),'[]'::jsonb)\n  INTO actual_projection FROM (\n   SELECT q.rule_fp,q.definition_id FROM kaname.authority_role_access_label_rule q\n   WHERE q.role_id=transition->>'role_id' ORDER BY q.rule_fp COLLATE \"C\",q.definition_id\n   LIMIT jsonb_array_length(transition->'new_projection')+1\n  ) p;\n  IF actual_projection IS DISTINCT FROM transition->'new_projection' THEN\n   RAISE EXCEPTION 'role access label completed projection differs' USING ERRCODE='40001';END IF;\n  -- Все selected effects уже consumed. Закрытый режим делает проверку\n  -- одноразовой даже при нескольких deferred callbacks; новые role DML и\n  -- source reads в этой программе теперь отвергаются.\n  UPDATE pg_temp.kaname_authority_sequence_program s SET frozen_mode='access_label_transition_complete'\n   WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid;\n END IF;\nEND "
  ],
  [
    "applied jsonb;",
    "applied jsonb;authorized jsonb;"
  ],
  [
    "s.frozen->'access_label_transition_applied' INTO transition,generation,applied",
    "s.frozen->'access_label_transition_applied',s.frozen->'access_label_authorized' INTO transition,generation,applied,authorized"
  ],
  [
    "OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest' THEN",
    "OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest'\n   OR jsonb_typeof(authorized) IS DISTINCT FROM 'object'\n   OR generation->>'authorization_digest' IS DISTINCT FROM encode(sha256(convert_to(authorized::text,'UTF8')),'hex') THEN"
  ]
]$patch$::jsonb),
        ('_authority_resource_crud_prepare_v3(jsonb,integer,integer)','8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074','dd929f22c0603f1d9e669e2c37c5911c2c89f9ad6494994bb9c035d0fe9c3d7b',$patch$[
  [
    "    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN",
    "    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN\n     -- Удаление принадлежит resource CRUD, не role mutation. До отдельного\n     -- BEFORE DELETE writer с exact manifest/projection отзыв явно закрыт.\n     RAISE EXCEPTION 'role delete access label projection withdrawal is unavailable' USING ERRCODE='42501';"
  ]
]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f','0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd',$patch$[
  [
    " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);",
    " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n IF program#>>'{frozen,mode}'='access_label_transition'\n AND program#>>'{frozen,access_label_scope_census,mode}'='revoke' THEN\n  required_questions:=kaname.authority_access_label_role_required_questions_v1(program->'frozen',at_time);\n  IF required_questions IS DISTINCT FROM '[]'::jsonb\n   OR program#>'{frozen,create}' IS DISTINCT FROM 'false'::jsonb\n   OR program#>'{frozen,request,rules}' IS DISTINCT FROM 'true'::jsonb\n   OR (program->'frozen') ? 'access_label_source_store_oid' THEN\n   RAISE EXCEPTION 'role revoke finalized census differs' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s\n  SET frozen=s.frozen||jsonb_build_object('access_label_required_questions',required_questions,\n   'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time\n   AND s.frozen_mode='access_label_transition'\n   AND NOT (s.frozen ? 'access_label_required_questions');\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role revoke finalized program differs' USING ERRCODE='42501';END IF;\n END IF;\n"
  ]
]$patch$::jsonb),
        ('authority_protocol_grant_runtime(regrole)','2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892','3c51040a4cb1eca5971a109e1786a59ca3fc6e55af8dac0654920783efb821e1',$patch$[
  [
    " PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);",
    " IF EXISTS(SELECT 1 FROM kaname.authority_role_actor_login a WHERE a.singleton AND a.role_oid=p_runtime::oid) THEN\n  RAISE EXCEPTION 'role actor LOGIN requires its finite grants' USING ERRCODE='42501';END IF;\n PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);"
  ],
  [
    " SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;",
    " SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;\n -- Generation1 открывает SELECT по схеме; pin назначения остаётся у владельца.\n EXECUTE format('REVOKE ALL ON kaname.authority_role_actor_login FROM %I',runtime_name);"
  ]
]$patch$::jsonb),
        ('_authority_crud_storage_v3()','1af1f1e917796102591107cf66a04f079145a229c6bb0abd689fcd142de9bfbe','cc3d0947da0f6803ddd05c8da80cb25952d6ef326d2726f991ba649ea3d926ff',$patch$[
  [
    "bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4",
    "0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e"
  ],
  [
    "8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362",
    "959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940"
  ],
  [
    "d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3",
    "5967a2d8acb0d1dc2dc6efea8124479bdc105c5c8cb59a689809974e7439a244"
  ],
  [
    "7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298",
    "a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05"
  ],
  [
    "8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074",
    "dd929f22c0603f1d9e669e2c37c5911c2c89f9ad6494994bb9c035d0fe9c3d7b"
  ],
  [
    "d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f",
    "0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd"
  ],
  [
    "2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892",
    "3c51040a4cb1eca5971a109e1786a59ca3fc6e55af8dac0654920783efb821e1"
  ],
  [
    " IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;\n",
    " IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass\n   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n   AND NOT (c.relhasrules OR c.relrowsecurity OR c.relhastriggers OR c.relhassubclass)\n   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a\n    WHERE a.grantee<>owner_oid)\n   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute x CROSS JOIN LATERAL aclexplode(x.attacl) a\n    WHERE x.attrelid=c.oid AND a.grantee<>owner_oid)) THEN RETURN false;END IF;\n"
  ],
  [
    "   AND g.privilege_type='EXECUTE'\n ) SELECT 1 FROM (VALUES\n",
    "   AND g.privilege_type='EXECUTE'\n ) SELECT 1 FROM (VALUES\n ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),\n ('_authority_role_actor_ordinary_login_v1(oid)','fd9c80440ea162b7d1d07df7466475c86a524f8262ac7ddefa069ccabf2dfe62',false,'s',true,'private'),\n ('_authority_role_actor_login_current_v1()','3b4de3896eb2537e092a47d6ab826e9945fc8f06d7daf5298d397a27fdfe4376',false,'s',true,'private'),\n ('authority_role_actor_login_ready_v1()','dd4d43de7ca6c2255c777c3886febd5bab8fa2075c26fe9033ba558ff64728ec',true,'s',true,'role_login'),\n ('authority_role_actor_login_configure_v1(regrole,regrole)','cd132bea40d552c8160a514600d81dce975b27fc503e4e0e01ad925c90f3654e',false,'v',true,'private'),\n ('authority_role_access_label_content_approved_v1()','b45df17bbda9ce415d579d419b4bd9d76886bcc3da04a8d7f5f0fd0d42a41d36',true,'v',true,'role_login'),\n ('authority_role_actor_grant_v1(regrole)','0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55',false,'v',true,'private'),\n"
  ],
  [
    "    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) END) THEN RETURN false;END IF;",
    "    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) OR (pin_expected.access_mode='role_login' AND EXISTS(\n    SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a\n    WHERE a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'\n      OR NOT EXISTS(SELECT 1 FROM kaname.authority_role_actor_login t\n       JOIN pg_catalog.pg_roles r ON (r.oid,r.rolname)=(t.role_oid,t.role_name)\n       WHERE t.singleton AND t.role_oid=a.grantee)))) END) THEN RETURN false;END IF;"
  ]
]$patch$::jsonb),
        ('_authority_full_contract_storage_v3()','c6d6545229a7d01b3982bbe201e0f711e48afb935bf4c40c6a9c7c7dad9a563d','7ef6978e23de2ce46fa967f28c8e8d348ad93b0dde5db7e75ed976ace4c9bb36',$patch$[
  [
    "1af1f1e917796102591107cf66a04f079145a229c6bb0abd689fcd142de9bfbe",
    "cc3d0947da0f6803ddd05c8da80cb25952d6ef326d2726f991ba649ea3d926ff"
  ]
]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_role_atomic_projection$;
-- +goose StatementEnd


-- +goose Down
SELECT kaname.authority_protocol_drain();

-- +goose StatementBegin
DO $role_apply_down$
BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_role_actor_login)
 OR EXISTS(SELECT 1 FROM kaname.authority_role_access_label_rule) THEN
  RAISE EXCEPTION 'role actor enrollment or access label projection still exists' USING ERRCODE='55000';END IF;
END
$role_apply_down$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $access_label_role_atomic_projection$
DECLARE
    item record;
    replacement jsonb;
    fn regprocedure;
    old_body text;
    new_body text;
    definition text;
    needle text;
BEGIN
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние перед изменением атомарной записи проекции роли' USING ERRCODE='55000';
    END IF;
    FOR item IN SELECT * FROM (VALUES
        ('_authority_full_contract_storage_v3()','7ef6978e23de2ce46fa967f28c8e8d348ad93b0dde5db7e75ed976ace4c9bb36','c6d6545229a7d01b3982bbe201e0f711e48afb935bf4c40c6a9c7c7dad9a563d',$patch$[
  [
    "cc3d0947da0f6803ddd05c8da80cb25952d6ef326d2726f991ba649ea3d926ff",
    "1af1f1e917796102591107cf66a04f079145a229c6bb0abd689fcd142de9bfbe"
  ]
]$patch$::jsonb),
        ('_authority_crud_storage_v3()','cc3d0947da0f6803ddd05c8da80cb25952d6ef326d2726f991ba649ea3d926ff','1af1f1e917796102591107cf66a04f079145a229c6bb0abd689fcd142de9bfbe',$patch$[
  [
    "    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) OR (pin_expected.access_mode='role_login' AND EXISTS(\n    SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a\n    WHERE a.grantee<>owner_oid AND (a.grantee=0 OR a.is_grantable OR a.privilege_type<>'EXECUTE'\n      OR NOT EXISTS(SELECT 1 FROM kaname.authority_role_actor_login t\n       JOIN pg_catalog.pg_roles r ON (r.oid,r.rolname)=(t.role_oid,t.role_name)\n       WHERE t.singleton AND t.role_oid=a.grantee)))) END) THEN RETURN false;END IF;",
    "    SELECT 1 FROM typed_entry_exec_acl g WHERE g.grantee=a.grantee)))) END) THEN RETURN false;END IF;"
  ],
  [
    "   AND g.privilege_type='EXECUTE'\n ) SELECT 1 FROM (VALUES\n ('_authority_role_actor_revoke_grants_v1(oid)','9be92689be1bda5db54c954b756f88eccef63d5fdb73de2a9d121c0629b15e86',false,'v',true,'private'),\n ('_authority_role_actor_ordinary_login_v1(oid)','fd9c80440ea162b7d1d07df7466475c86a524f8262ac7ddefa069ccabf2dfe62',false,'s',true,'private'),\n ('_authority_role_actor_login_current_v1()','3b4de3896eb2537e092a47d6ab826e9945fc8f06d7daf5298d397a27fdfe4376',false,'s',true,'private'),\n ('authority_role_actor_login_ready_v1()','dd4d43de7ca6c2255c777c3886febd5bab8fa2075c26fe9033ba558ff64728ec',true,'s',true,'role_login'),\n ('authority_role_actor_login_configure_v1(regrole,regrole)','cd132bea40d552c8160a514600d81dce975b27fc503e4e0e01ad925c90f3654e',false,'v',true,'private'),\n ('authority_role_access_label_content_approved_v1()','b45df17bbda9ce415d579d419b4bd9d76886bcc3da04a8d7f5f0fd0d42a41d36',true,'v',true,'role_login'),\n ('authority_role_actor_grant_v1(regrole)','0e490ec95c169d8352e2eca5f439d7b3bbab4a2c0667df9c0c82f212c5b8da55',false,'v',true,'private'),\n",
    "   AND g.privilege_type='EXECUTE'\n ) SELECT 1 FROM (VALUES\n"
  ],
  [
    " IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;\n IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c\n  WHERE c.oid='kaname.authority_role_actor_login'::regclass\n   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'\n   AND NOT (c.relhasrules OR c.relrowsecurity OR c.relhastriggers OR c.relhassubclass)\n   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a\n    WHERE a.grantee<>owner_oid)\n   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute x CROSS JOIN LATERAL aclexplode(x.attacl) a\n    WHERE x.attrelid=c.oid AND a.grantee<>owner_oid)) THEN RETURN false;END IF;\n",
    " IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;\n"
  ],
  [
    "3c51040a4cb1eca5971a109e1786a59ca3fc6e55af8dac0654920783efb821e1",
    "2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892"
  ],
  [
    "0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd",
    "d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f"
  ],
  [
    "dd929f22c0603f1d9e669e2c37c5911c2c89f9ad6494994bb9c035d0fe9c3d7b",
    "8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074"
  ],
  [
    "a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05",
    "7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298"
  ],
  [
    "5967a2d8acb0d1dc2dc6efea8124479bdc105c5c8cb59a689809974e7439a244",
    "d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3"
  ],
  [
    "959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940",
    "8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362"
  ],
  [
    "0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e",
    "bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4"
  ]
]$patch$::jsonb),
        ('authority_protocol_grant_runtime(regrole)','3c51040a4cb1eca5971a109e1786a59ca3fc6e55af8dac0654920783efb821e1','2bd4434aa60b0d76eeb9d6eac0475cbbeecf859aa0092f44ea7bf2bf1ace1892',$patch$[
  [
    " SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;\n -- Generation1 открывает SELECT по схеме; pin назначения остаётся у владельца.\n EXECUTE format('REVOKE ALL ON kaname.authority_role_actor_login FROM %I',runtime_name);",
    " SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;"
  ],
  [
    " IF EXISTS(SELECT 1 FROM kaname.authority_role_actor_login a WHERE a.singleton AND a.role_oid=p_runtime::oid) THEN\n  RAISE EXCEPTION 'role actor LOGIN requires its finite grants' USING ERRCODE='42501';END IF;\n PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);",
    " PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);"
  ]
]$patch$::jsonb),
        ('authority_role_sequence_finalize_v3()','0adfc241154b42e561425452f8ceef42eeefa3e802a21111e9e74d5a434830cd','d560c7a10ef3c64a2ec55f2c8e0733e6d4ebc1f134c1be8313e7cd011c22037f',$patch$[
  [
    " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);\n IF program#>>'{frozen,mode}'='access_label_transition'\n AND program#>>'{frozen,access_label_scope_census,mode}'='revoke' THEN\n  required_questions:=kaname.authority_access_label_role_required_questions_v1(program->'frozen',at_time);\n  IF required_questions IS DISTINCT FROM '[]'::jsonb\n   OR program#>'{frozen,create}' IS DISTINCT FROM 'false'::jsonb\n   OR program#>'{frozen,request,rules}' IS DISTINCT FROM 'true'::jsonb\n   OR (program->'frozen') ? 'access_label_source_store_oid' THEN\n   RAISE EXCEPTION 'role revoke finalized census differs' USING ERRCODE='42501';END IF;\n  UPDATE pg_temp.kaname_authority_sequence_program s\n  SET frozen=s.frozen||jsonb_build_object('access_label_required_questions',required_questions,\n   'access_label_required_index','{}'::jsonb)\n  WHERE s.singleton AND s.nonce=(proof->>'nonce')::uuid AND s.decision_at=at_time\n   AND s.frozen_mode='access_label_transition'\n   AND NOT (s.frozen ? 'access_label_required_questions');\n  IF NOT FOUND THEN\n   RAISE EXCEPTION 'role revoke finalized program differs' USING ERRCODE='42501';END IF;\n END IF;\n",
    " PERFORM kaname._authority_sequence_select_v3(ordinals,at_time);"
  ]
]$patch$::jsonb),
        ('_authority_resource_crud_prepare_v3(jsonb,integer,integer)','dd929f22c0603f1d9e669e2c37c5911c2c89f9ad6494994bb9c035d0fe9c3d7b','8375a33475fa65f764f3b8a522185290b7b165cb9bb203d3260c3d9d887a2074',$patch$[
  [
    "    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN\n     -- Удаление принадлежит resource CRUD, не role mutation. До отдельного\n     -- BEFORE DELETE writer с exact manifest/projection отзыв явно закрыт.\n     RAISE EXCEPTION 'role delete access label projection withdrawal is unavailable' USING ERRCODE='42501';",
    "    IF access_label_transition->'old_projection'<>'[]'::jsonb THEN"
  ]
]$patch$::jsonb),
        ('_authority_sequence_complete_v3()','a8d690b1e0af17cf3c09b53ce8cbb651a119c76f16d3c0a0c10990b3cb031c05','7c12702a047d071c672f2e3586297a59110ad6c4f7d696801293436a96dea298',$patch$[
  [
    "OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest'\n   OR jsonb_typeof(authorized) IS DISTINCT FROM 'object'\n   OR generation->>'authorization_digest' IS DISTINCT FROM encode(sha256(convert_to(authorized::text,'UTF8')),'hex') THEN",
    "OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest' THEN"
  ],
  [
    "s.frozen->'access_label_transition_applied',s.frozen->'access_label_authorized' INTO transition,generation,applied,authorized",
    "s.frozen->'access_label_transition_applied' INTO transition,generation,applied"
  ],
  [
    "applied jsonb;authorized jsonb;",
    "applied jsonb;"
  ],
  [
    "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  SELECT s.frozen->'access_label_transition',s.frozen->'access_label_applied_generation',\n   s.frozen->'access_label_transition_applied' INTO transition,generation,applied\n  FROM pg_temp.kaname_authority_sequence_program s\n  WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid AND s.frozen->>'kind'='role.mutation';\n  IF NOT FOUND OR applied IS DISTINCT FROM 'true'::jsonb\n   OR jsonb_typeof(transition) IS DISTINCT FROM 'object'\n   OR jsonb_typeof(generation) IS DISTINCT FROM 'object'\n   OR jsonb_typeof(transition->'new_projection') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(transition->'new_row') IS DISTINCT FROM 'object'\n   OR coalesce(transition->>'role_id','')='' THEN\n   RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(transition->'new_projection')>16384\n   OR transition->'write_reserve' IS DISTINCT FROM jsonb_build_object(\n    'rows',2*jsonb_array_length(transition->'new_projection')+8,'reads',8)\n   OR generation->>'new_digest' IS DISTINCT FROM transition->>'new_digest' THEN\n   RAISE EXCEPTION 'role access label completion reserve or image missing' USING ERRCODE='42501';END IF;\n  SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO actual,current_xmin,current_ctid\n   FROM kaname.roles r WHERE r.id=transition->>'role_id';\n  IF NOT FOUND OR actual IS DISTINCT FROM transition->'new_row'\n   OR current_xmin IS DISTINCT FROM generation->>'xmin'\n   OR current_ctid IS DISTINCT FROM generation->>'ctid'\n   OR encode(sha256(convert_to(actual::text,'UTF8')),'hex') IS DISTINCT FROM transition->>'new_digest' THEN\n   RAISE EXCEPTION 'role access label completed generation differs' USING ERRCODE='40001';END IF;\n  SELECT coalesce(jsonb_agg(jsonb_build_array(p.rule_fp,p.definition_id)\n    ORDER BY p.rule_fp COLLATE \"C\",p.definition_id),'[]'::jsonb)\n  INTO actual_projection FROM (\n   SELECT q.rule_fp,q.definition_id FROM kaname.authority_role_access_label_rule q\n   WHERE q.role_id=transition->>'role_id' ORDER BY q.rule_fp COLLATE \"C\",q.definition_id\n   LIMIT jsonb_array_length(transition->'new_projection')+1\n  ) p;\n  IF actual_projection IS DISTINCT FROM transition->'new_projection' THEN\n   RAISE EXCEPTION 'role access label completed projection differs' USING ERRCODE='40001';END IF;\n  -- Все selected effects уже consumed. Закрытый режим делает проверку\n  -- одноразовой даже при нескольких deferred callbacks; новые role DML и\n  -- source reads в этой программе теперь отвергаются.\n  UPDATE pg_temp.kaname_authority_sequence_program s SET frozen_mode='access_label_transition_complete'\n   WHERE s.singleton AND s.nonce=(program->>'nonce')::uuid;\n END IF;\nEND ",
    "  RAISE EXCEPTION 'selected sequence program is incomplete' USING ERRCODE='42501';END IF;\nEND "
  ],
  [
    " -- Access label completion follows the exact selected-effect checks below.\n",
    " -- Режим берётся из проверенного заголовка owner program.\n IF program->>'family'='role' AND program#>>'{frozen,mode}'='access_label_transition' THEN\n  RAISE EXCEPTION 'role access label transition requires an atomic projection writer' USING ERRCODE='42501';\n END IF;\n"
  ],
  [
    "DECLARE program jsonb;transition jsonb;generation jsonb;applied jsonb;actual jsonb;actual_projection jsonb;current_xmin text;current_ctid text;",
    "DECLARE program jsonb;"
  ]
]$patch$::jsonb),
        ('authority_sequence_origin_v3()','5967a2d8acb0d1dc2dc6efea8124479bdc105c5c8cb59a689809974e7439a244','d1b7a54b0cf83d53d416b6cc2bbcb1c20e60d985356931a45a6804ebf2f27df3',$patch$[
  [
    "  -- Штатный roles_000_* AFTER источник уже зарегистрирован. Private\n  -- projection применяется до journal emitter в той же транзакции.\n  IF TG_TABLE_NAME='roles' AND program->>'family'='role' THEN\n   IF program#>>'{frozen,mode}'='access_label_transition_complete' THEN\n    RAISE EXCEPTION 'access label role program already completed' USING ERRCODE='42501';END IF;\n   IF program#>>'{frozen,mode}'='access_label_transition' THEN\n    IF TG_WHEN<>'AFTER' OR TG_OP NOT IN ('INSERT','UPDATE') OR matches<>1 THEN\n     RAISE EXCEPTION 'access label atomic role origin missing' USING ERRCODE='42501';END IF;\n    PERFORM kaname.authority_access_label_role_projection_apply_v1(actual_origin,\n     CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.xmin::text END,\n     CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.ctid::text END);\n   END IF;\n  END IF;\n  -- Отсутствующий owner после FK cascade штатно не эмитит member event.",
    "  -- Отсутствующий owner после FK cascade штатно не эмитит member event."
  ]
]$patch$::jsonb),
        ('authority_access_label_role_projection_apply_v1(jsonb,text,text)','959fe69a787f20a99919ec47b666cfdf9bf074c01a4ac203b66459fae5da7940','8354841ae2bd79b3fe23fa6bec9aa0d04007384df6354302814b9f2696d60362',$patch$[
  [
    "'new_digest',transition->>'new_digest',\n          'authorization_digest',encode(sha256(convert_to(authorized::text,'UTF8')),'hex')))",
    "'new_digest',transition->>'new_digest'))"
  ],
  [
    "    target_role_id:=transition->>'role_id';\n    -- Ни actor из request, ни одни source positives не подтверждают method.\n    -- Положительная квитанция подтверждает полный RequireRole на доверенном writer.\n    IF jsonb_typeof(method_authorized) IS DISTINCT FROM 'object'\n       OR jsonb_typeof(required_questions) IS DISTINCT FROM 'array'\n       OR jsonb_typeof(authorization_actor) IS DISTINCT FROM 'object'\n       OR final_clock IS NULL OR prepared_clock IS NULL OR final_clock<=prepared_clock\n       OR final_clock IS DISTINCT FROM (proof->>'decision_at')::timestamptz\n       OR jsonb_typeof(program_frozen->'create') IS DISTINCT FROM 'boolean' THEN\n      RAISE EXCEPTION 'role access label independent method result is absent' USING ERRCODE='42501';END IF;\n    IF authorization_actor-ARRAY['type','id']<>'{}'::jsonb\n       OR authorization_actor->>'type' IS NULL\n       OR authorization_actor->>'type' NOT IN ('user','service_account')\n       OR jsonb_typeof(authorization_actor->'id') IS DISTINCT FROM 'string'\n       OR coalesce(authorization_actor->>'id','')=''\n       OR (authorization_actor->>'id')~'[:#*[:space:][:cntrl:]]'\n       OR program_frozen->>'id' IS DISTINCT FROM target_role_id\n       OR program_frozen#>>'{access_label_authority,role_id}' IS DISTINCT FROM target_role_id\n       OR program_frozen#>>'{access_label_authority,new_digest}' IS DISTINCT FROM transition->>'new_digest'\n       OR coalesce(program_frozen#>>'{access_label_scope_census,mode}','') NOT IN ('apply','revoke') THEN\n      RAISE EXCEPTION 'role access label authorization identity differs' USING ERRCODE='42501';END IF;\n    IF program_frozen#>>'{access_label_scope_census,mode}'='revoke' THEN\n      IF program_frozen->'create' IS DISTINCT FROM 'false'::jsonb\n       OR program_frozen#>'{request,rules}' IS DISTINCT FROM 'true'::jsonb\n       OR transition->'new_projection' IS DISTINCT FROM '[]'::jsonb\n       OR jsonb_typeof(transition->'old_projection') IS DISTINCT FROM 'array'\n       OR transition->'old_projection'='[]'::jsonb\n       OR required_questions IS DISTINCT FROM '[]'::jsonb\n       OR program_frozen ? 'access_label_source_store_oid' THEN\n        RAISE EXCEPTION 'role revoke requires exact empty positive image' USING ERRCODE='42501';END IF;\n    ELSIF jsonb_array_length(required_questions) NOT BETWEEN 1 AND 4096 THEN\n      RAISE EXCEPTION 'role apply requires positive questions' USING ERRCODE='42501';\n    END IF;\n    expected_method:=jsonb_build_object('result','allow','contract','RequireRole/v1',\n      'mode',program_frozen#>>'{access_label_scope_census,mode}',\n      'operation',CASE WHEN (program_frozen->>'create')::boolean THEN 'role.create' ELSE 'role.update' END,\n      'role_id',target_role_id,'scope',CASE WHEN nullif(transition#>>'{new_row,project_id}','') IS NOT NULL\n        THEN jsonb_build_object('type','project','id',transition#>>'{new_row,project_id}')\n        ELSE jsonb_build_object('type','account','id',transition#>>'{new_row,account_id}') END,\n      'actor',authorization_actor,'new_digest',transition->>'new_digest','decision_at',final_clock,\n      'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce');\n    IF method_authorized IS DISTINCT FROM expected_method THEN\n      RAISE EXCEPTION 'role access label independent method result differs' USING ERRCODE='42501';END IF;\n    -- Пересчитываем чистый owner census на запечатанном clock. Declared questions\n    -- никогда не подменяют полный набор обязательств.\n    canonical_questions:=kaname.authority_access_label_role_required_questions_v1(program_frozen,final_clock);\n    IF canonical_questions IS DISTINCT FROM required_questions THEN\n      RAISE EXCEPTION 'role access label required census differs' USING ERRCODE='42501';END IF;\n    FOR question IN SELECT value FROM jsonb_array_elements(required_questions) LOOP\n      question_definition_id:=(question->>'definition_id')::uuid;\n      IF transition#>>ARRAY['definition_witnesses',question_definition_id::text,'scope_kind'] IS DISTINCT FROM question->>'scope_kind'\n       OR transition#>>ARRAY['definition_witnesses',question_definition_id::text,'scope_id'] IS DISTINCT FROM question->>'scope_id' THEN\n       RAISE EXCEPTION 'role access label required point lacks held definition' USING ERRCODE='42501';END IF;\n    END LOOP;\n    IF EXISTS(SELECT 1 FROM (\n       (SELECT value->>1 FROM jsonb_array_elements(transition->'new_projection')\n        EXCEPT SELECT value->>'definition_id' FROM jsonb_array_elements(required_questions))\n       UNION ALL\n       (SELECT value->>'definition_id' FROM jsonb_array_elements(required_questions)\n        EXCEPT SELECT value->>1 FROM jsonb_array_elements(transition->'new_projection'))\n      ) mismatch) THEN\n      RAISE EXCEPTION 'role access label required definition set differs' USING ERRCODE='42501';END IF;\n    IF transition->'authorization_reserve' IS DISTINCT FROM jsonb_build_object(\n      'rows',4+jsonb_array_length(program_frozen#>'{access_label_scope_census,scopes}')\n       +jsonb_array_length(program_frozen#>'{access_label_scope_census,new_definitions}')\n       +3*(program_frozen#>>'{access_label_scope_census,max_questions}')::integer,'reads',2)\n      OR jsonb_array_length(required_questions)>(program_frozen#>>'{access_label_scope_census,max_questions}')::integer THEN\n      RAISE EXCEPTION 'role access label receipt completion reserve absent' USING ERRCODE='42501';END IF;\n    IF program_frozen#>>'{access_label_scope_census,mode}'='apply' THEN\n    source_store:=(program_frozen->>'access_label_source_store_oid')::oid;\n    IF source_store IS NULL\n      OR source_store IS DISTINCT FROM to_regclass('pg_temp.kaname_authority_access_label_role_source')::oid\n      OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=source_store\n       AND c.relowner=current_user::regrole::oid AND c.relnamespace=pg_my_temp_schema()\n       AND c.relpersistence='t' AND c.relkind='r'\n       AND NOT (c.relhasrules OR c.relrowsecurity OR c.relhastriggers OR c.relhassubclass)\n       AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a\n        WHERE a.grantee<>c.relowner)) THEN\n      RAISE EXCEPTION 'role access label source receipt custody differs' USING ERRCODE='42501';END IF;\n    -- Единственный полный bounded снимок: лишние/чужие nonce и false видны.\n    -- PK уже проверен до freeze; не вызываем store helper, требующий пустоту.\n    SELECT coalesce(jsonb_agg(jsonb_build_array(q.nonce,q.scope_kind,q.scope_id,q.definition_id,q.satisfied)\n      ORDER BY q.nonce,q.scope_kind COLLATE \"C\",q.scope_id COLLATE \"C\",q.definition_id),'[]'::jsonb)\n      INTO actual_points FROM (\n       SELECT nonce,scope_kind,scope_id,definition_id,satisfied\n       FROM ONLY pg_temp.kaname_authority_access_label_role_source\n       ORDER BY nonce,scope_kind COLLATE \"C\",scope_id COLLATE \"C\",definition_id\n       LIMIT jsonb_array_length(required_questions)+1\n      ) q;\n    SELECT jsonb_agg(jsonb_build_array((proof->>'nonce')::uuid,q->>'scope_kind',q->>'scope_id',\n      (q->>'definition_id')::uuid,true)\n      ORDER BY (q->>'scope_kind') COLLATE \"C\",(q->>'scope_id') COLLATE \"C\",(q->>'definition_id')::uuid)\n      INTO expected_points FROM jsonb_array_elements(required_questions) q;\n    IF actual_points IS DISTINCT FROM expected_points THEN\n      RAISE EXCEPTION 'role access label source receipts incomplete or changed' USING ERRCODE='42501';END IF;\n    ELSE\n      -- Отзыв не создаёт source store. Его пустой census доказан owner выше.\n      source_store:=NULL;\n    END IF;\n    -- Сводная квитанция возникает только здесь после method и полного source set.\n    authorized:=jsonb_build_object('result','allow','role_id',target_role_id,\n      'mode',program_frozen#>>'{access_label_scope_census,mode}',\n      'actor',authorization_actor,'new_digest',transition->>'new_digest','decision_at',final_clock,\n      'backend',proof->'backend','transaction_id',proof->'transaction_id','nonce',proof->'nonce',\n      'source_store_oid',source_store,'source_count',jsonb_array_length(required_questions),\n      'required_questions_digest',encode(sha256(convert_to(required_questions::text,'UTF8')),'hex'),\n      'method_authorized_digest',encode(sha256(convert_to(method_authorized::text,'UTF8')),'hex'));\n",
    "    target_role_id:=transition->>'role_id';\n"
  ],
  [
    "    SELECT s.frozen->'access_label_transition',s.frozen->'access_label_authorized',\n      s.frozen->'access_label_required_questions',s.frozen#>'{access_label_authority,actor}',s.decision_at,s.staged_decision_at,s.frozen,s.frozen->'access_label_method_authorized'\n    INTO STRICT transition,authorized,required_questions,authorization_actor,final_clock,prepared_clock,program_frozen,method_authorized",
    "    SELECT s.frozen->'access_label_transition' INTO STRICT transition"
  ],
  [
    "written_ctid text;\n    authorized jsonb;required_questions jsonb;authorization_actor jsonb;\n    question jsonb;canonical_questions jsonb;question_definition_id uuid;final_clock timestamptz;prepared_clock timestamptz;program_frozen jsonb;method_authorized jsonb;expected_method jsonb;source_store oid;actual_points jsonb;expected_points jsonb;",
    "written_ctid text;"
  ],
  [
    "    -- Completion повторно проверяет точную записанную строку и весь набор pairs.",
    "    -- Обязательство остаётся в программе. Существующий completion отклоняет\n    -- commit до подключения проверки полномочий и признака применения."
  ],
  [
    "        frozen=s.frozen||jsonb_build_object('access_label_authorized',authorized,'access_label_transition_applied',true,\n         'access_label_applied_generation',jsonb_build_object('xmin',written_xmin,'ctid',written_ctid,\n          'new_digest',transition->>'new_digest'))",
    "        frozen=s.frozen||jsonb_build_object('access_label_transition_applied',true)"
  ],
  [
    "    -- Сверяем весь результат, включая unchanged pairs; лишняя строка\n    -- попадает в sentinel и не превращается в успешную частичную проекцию.\n    SELECT coalesce(jsonb_agg(jsonb_build_array(p.rule_fp,p.definition_id)\n      ORDER BY p.rule_fp COLLATE \"C\",p.definition_id),'[]'::jsonb)\n    INTO actual_projection FROM (\n      SELECT q.rule_fp,q.definition_id FROM kaname.authority_role_access_label_rule q\n      WHERE q.role_id=target_role_id ORDER BY q.rule_fp COLLATE \"C\",q.definition_id\n      LIMIT jsonb_array_length(transition->'new_projection')+1\n    ) p;\n    IF actual_projection IS DISTINCT FROM transition->'new_projection' THEN\n      RAISE EXCEPTION 'access label projection written image differs' USING ERRCODE='40001';END IF;\n    UPDATE pg_temp.kaname_authority_sequence_program s\n    SET frozen_mode='access_label_transition',",
    "    UPDATE pg_temp.kaname_authority_sequence_program s\n    SET frozen_mode='access_label_transition',"
  ],
  [
    "    SELECT to_jsonb(r),r.xmin::text,r.ctid::text INTO STRICT actual,written_xmin,written_ctid FROM kaname.roles r WHERE r.id=target_role_id FOR UPDATE;",
    "    SELECT to_jsonb(r) INTO STRICT actual FROM kaname.roles r WHERE r.id=target_role_id FOR UPDATE;"
  ],
  [
    "    target_role_id:=transition->>'role_id';\n    IF transition->'write_reserve' IS DISTINCT FROM jsonb_build_object(\n       'rows',2*jsonb_array_length(transition->'new_projection')+8,'reads',8) THEN\n        RAISE EXCEPTION 'access label projection write reserve missing' USING ERRCODE='42501';END IF;",
    "    target_role_id:=transition->>'role_id';"
  ],
  [
    "    actual jsonb;actual_projection jsonb;written_xmin text;written_ctid text;",
    "    actual jsonb;"
  ]
]$patch$::jsonb),
        ('authority_role_sequence_prepare_v3(jsonb,integer,integer)','0890abdfa2517000901077218dde1cbe48b465003ce4c8e5e74559a2ebaa167e','bcfedb5314ae275e71f5953dac76111ae65f217b4877e8154b224ccc9fe4b6c4',$patch$[
  [
    " RETURN jsonb_build_object('rows',scanned,'reads',reads+cost,'access_label_mode',\n  coalesce(access_label_frozen#>>'{access_label_scope_census,mode}','ordinary'));",
    " RETURN jsonb_build_object('rows',scanned,'reads',reads+cost);"
  ],
  [
    " IF access_label_frozen#>>'{access_label_scope_census,mode}' IN ('apply','revoke') THEN\n  -- Полная сверка receipt points оплачивается до decision clock.\n  scanned:=scanned+4+jsonb_array_length(access_label_frozen#>'{access_label_scope_census,scopes}')\n   +jsonb_array_length(access_label_frozen#>'{access_label_scope_census,new_definitions}')\n   +3*(access_label_frozen#>>'{access_label_scope_census,max_questions}')::integer;\n  reads:=reads+2;\n  IF scanned>p_rows OR reads>p_reads THEN\n   RAISE EXCEPTION 'role access label receipt completion budget' USING ERRCODE='54000';END IF;\n  access_label_transition:=access_label_transition||jsonb_build_object('authorization_reserve',\n   jsonb_build_object('rows',4+jsonb_array_length(access_label_frozen#>'{access_label_scope_census,scopes}')\n    +jsonb_array_length(access_label_frozen#>'{access_label_scope_census,new_definitions}')\n    +3*(access_label_frozen#>>'{access_label_scope_census,max_questions}')::integer,'reads',2));\n  access_label_frozen:=access_label_frozen||jsonb_build_object('access_label_transition',access_label_transition);\n END IF;\n cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);",
    " cost:=kaname._authority_sequence_reserve_v3('role',maximum,p_reads-reads);"
  ],
  [
    "    -- Два bounded снимка: после apply и один раз после exact completion.\n    -- Reserve включает role/program/probe overhead; legacy путь не меняется.\n    scanned:=scanned+2*jsonb_array_length(access_label_transition->'new_projection')+8;\n    reads:=reads+8;\n    IF scanned>p_rows OR reads>p_reads THEN\n     RAISE EXCEPTION 'role access label projection completion budget' USING ERRCODE='54000';END IF;\n    access_label_transition:=access_label_transition||jsonb_build_object('write_reserve',\n     jsonb_build_object('rows',2*jsonb_array_length(access_label_transition->'new_projection')+8,'reads',8));\n    access_label_frozen:=jsonb_build_object('mode','access_label_transition',",
    "    access_label_frozen:=jsonb_build_object('mode','access_label_transition',"
  ],
  [
    "     -- Revoke удаляет protected projection; полный RequireRole остаётся обязательным.\n     IF creation OR NOT promote OR access_label_authority_input->'questions' IS DISTINCT FROM '[]'::jsonb THEN\n      RAISE EXCEPTION 'role revoke requires update rules with empty positive questions' USING ERRCODE='42501';END IF;\n     -- Finalize сохраняет канонический пустой census без source store.\n     scanned:=scanned+2;reads:=reads+1;",
    "     -- Clean revoke не требует apply authority или fallback expansion."
  ],
  [
    "   IF access_label_transition->'new_projection'<>'[]'::jsonb OR access_label_transition->'old_projection'<>'[]'::jsonb THEN",
    "   IF access_label_transition->'new_projection'<>'[]'::jsonb THEN"
  ]
]$patch$::jsonb)
    ) AS changes(signature, before_sha, after_sha, substitutions) LOOP
        fn := pg_catalog.to_regprocedure('kaname.' || item.signature);
        IF fn IS NULL THEN RAISE EXCEPTION 'функция % для миграции отсутствует', item.signature USING ERRCODE='55000';END IF;
        SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(old_body,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
            RAISE EXCEPTION 'исходное тело функции % не соответствует этой миграции', item.signature USING ERRCODE='55000';
        END IF;
        new_body := old_body;
        FOR replacement IN SELECT value FROM pg_catalog.jsonb_array_elements(item.substitutions) LOOP
            needle := replacement->>0;
            IF length(new_body)-length(replace(new_body,needle,'')) IS DISTINCT FROM length(needle) THEN
                RAISE EXCEPTION 'фрагмент тела функции % не уникален', item.signature USING ERRCODE='55000';
            END IF;
            new_body := replace(new_body,needle,replacement->>1);
        END LOOP;
        IF pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(new_body,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'расчётное тело функции % изменилось', item.signature USING ERRCODE='55000';
        END IF;
        -- PostgreSQL восстанавливает сигнатуру и настройки, CREATE OR REPLACE
        -- сохраняет owner/ACL. Меняется ровно одно полное тело с известным SHA.
        definition := pg_catalog.pg_get_functiondef(fn);
        IF length(definition)-length(replace(definition,old_body,'')) IS DISTINCT FROM length(old_body) THEN
            RAISE EXCEPTION 'определение функции % не содержит единственного исходного тела', item.signature USING ERRCODE='55000';
        END IF;
        EXECUTE replace(definition,old_body,new_body);
        IF (SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')
            FROM pg_catalog.pg_proc p WHERE p.oid=fn) IS DISTINCT FROM item.after_sha THEN
            RAISE EXCEPTION 'установленное тело функции % не совпадает с расчётным', item.signature USING ERRCODE='55000';
        END IF;
    END LOOP;
    IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
        RAISE EXCEPTION 'несогласованное состояние после обновления образов доступа' USING ERRCODE='55000';
    END IF;
END
$access_label_role_atomic_projection$;
-- +goose StatementEnd


DROP FUNCTION kaname.authority_role_actor_grant_v1(regrole);
DROP FUNCTION kaname.authority_role_access_label_content_approved_v1();
DROP FUNCTION kaname.authority_role_actor_login_configure_v1(regrole,regrole);
DROP FUNCTION kaname.authority_role_actor_login_ready_v1();
DROP FUNCTION kaname._authority_role_actor_login_current_v1();
DROP FUNCTION kaname._authority_role_actor_ordinary_login_v1(oid);
DROP FUNCTION kaname._authority_role_actor_revoke_grants_v1(oid);
DROP TABLE kaname.authority_role_actor_login;
