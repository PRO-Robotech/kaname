-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: TX protocol, не разрешение grant effects и не strict activation.
-- pg_temp указан последним; все system relations квалифицированы против shadowing.
-- Владелец migration доверенный; обычный runtime не владеет схемой/функциями.
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- kaname#1034: защита полного действия выдачи и сохранение прежних строк при накате (ESC-32).
ALTER TABLE kaname.authority_semantic_identity DROP CONSTRAINT authority_semantic_identity_phase_check;
ALTER TABLE kaname.authority_semantic_identity ADD CONSTRAINT authority_semantic_identity_phase_check CHECK(phase IN ('uninitialized','prepared','transition','active'));
ALTER TABLE kaname.authority_semantic_identity ADD CONSTRAINT authority_semantic_identity_prepared_check CHECK(phase<>'prepared' OR (protocol_version=1 AND model_id IS NOT NULL AND model_id ~ '^[0-9a-f]{64}$' AND catalog_id IS NOT NULL AND catalog_id ~ '^[0-9a-f]{64}$' AND projector_version IS NOT NULL AND projector_version<>''));
CREATE TABLE kaname.authority_writer_protocol (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 enforcement text NOT NULL DEFAULT 'compatibility' CHECK(enforcement IN ('compatibility','strict')),
 protocol_version integer NOT NULL DEFAULT 1 CHECK(protocol_version=1)
);
INSERT INTO kaname.authority_writer_protocol DEFAULT VALUES;
REVOKE ALL ON kaname.authority_writer_protocol FROM PUBLIC;
COMMENT ON TABLE kaname.authority_writer_protocol IS 'kaname#1034: compatibility не включает gates. Переключение strict требует отдельного accepted adapters fingerprint и доказанного drain; migration не выполняет активацию.';

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_prepare(p_model text,p_catalog text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; current_phase text; mode text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_semantic_identity'::regclass;
 IF (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)<>owner_oid THEN RAISE EXCEPTION 'bundle preparation requires migration owner' USING ERRCODE='42501'; END IF;
 IF pg_current_xact_id_if_assigned() IS NOT NULL OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory') THEN RAISE EXCEPTION 'bundle preparation requires fresh transaction' USING ERRCODE='25001'; END IF;
 PERFORM pg_advisory_xact_lock(1262569283,0);
 SELECT enforcement INTO STRICT mode FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
 SELECT phase INTO STRICT current_phase FROM kaname.authority_semantic_identity WHERE singleton FOR UPDATE;
 IF mode<>'compatibility' OR current_phase NOT IN ('uninitialized','prepared') THEN RAISE EXCEPTION 'bundle cannot be prepared in the current lifecycle' USING ERRCODE='55000'; END IF;
 UPDATE kaname.authority_semantic_identity SET phase='prepared',protocol_version=1,model_id=p_model,catalog_id=p_catalog,projector_version=p_projector WHERE singleton;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_discover(p_refs jsonb)
RETURNS TABLE(accounts text[], global_scope boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE ref jsonb; a text; found_row boolean; result text[] := ARRAY[]::text[]; g boolean := false;
BEGIN
 IF jsonb_typeof(p_refs) IS DISTINCT FROM 'array' OR jsonb_array_length(p_refs)>256 THEN
  RAISE EXCEPTION 'invalid authority ownership references' USING ERRCODE='22023';
 END IF;
 FOR ref IN SELECT value FROM jsonb_array_elements(p_refs) LOOP
  IF coalesce(ref->>'id','')='' THEN RAISE EXCEPTION 'invalid authority ownership reference' USING ERRCODE='22023'; END IF;
  a:=NULL; found_row:=false;
  CASE ref->>'kind'
   WHEN 'account' THEN SELECT id,true INTO a,found_row FROM kaname.accounts WHERE id=ref->>'id';
   WHEN 'project' THEN SELECT account_id,true INTO a,found_row FROM kaname.projects WHERE id=ref->>'id';
   WHEN 'group' THEN SELECT account_id,true INTO a,found_row FROM kaname.groups WHERE id=ref->>'id';
   WHEN 'service_account' THEN SELECT account_id,true INTO a,found_row FROM kaname.service_accounts WHERE id=ref->>'id';
   WHEN 'role' THEN SELECT coalesce(r.account_id,p.account_id),true INTO a,found_row FROM kaname.roles r LEFT JOIN kaname.projects p ON p.id=r.project_id WHERE r.id=ref->>'id';
   WHEN 'binding' THEN SELECT CASE b.resource_type WHEN 'account' THEN b.resource_id WHEN 'project' THEN p.account_id END,true INTO a,found_row FROM kaname.access_bindings b LEFT JOIN kaname.projects p ON p.id=b.resource_id AND b.resource_type='project' WHERE b.id=ref->>'id';
   ELSE RAISE EXCEPTION 'unknown authority ownership kind' USING ERRCODE='22023';
  END CASE;
  IF NOT coalesce(found_row,false) THEN RAISE EXCEPTION 'authority ownership source unavailable' USING ERRCODE='P1035'; END IF;
  IF a IS NULL OR a='' THEN g:=true; ELSE result:=array_append(result,a); END IF;
 END LOOP;
 RETURN QUERY SELECT coalesce(array_agg(DISTINCT v ORDER BY v),ARRAY[]::text[]),g FROM unnest(result) v;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_enter(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text)
RETURNS timestamptz LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys integer[]; k integer; logical text[]; actual text[]; global_owner boolean;
 active kaname.authority_semantic_identity%ROWTYPE; protocol kaname.authority_writer_protocol%ROWTYPE;
 grantee record; at_time timestamptz; invoker oid; temp_oid oid; owner_oid oid:=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user);
BEGIN
 -- Уже назначенный xid или advisory lock означает слишком поздний вход.
 -- SELECT FOR UPDATE/предыдущие mutations и legacy advisory locks сюда не проходят.
 IF current_setting('transaction_isolation')<>'read committed'
 OR pg_current_xact_id_if_assigned() IS NOT NULL
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND (locktype='advisory' OR (locktype='relation' AND mode<>'AccessShareLock'))) THEN
  RAISE EXCEPTION 'authority entry requires a fresh unlocked transaction' USING ERRCODE='25001';
 END IF;
 IF p_mode NOT IN ('accounts','global') OR p_mode IS NULL OR p_version IS DISTINCT FROM 1
 OR p_purpose IS NULL OR p_purpose NOT IN ('transition','decision')
 OR p_kind IS NULL OR p_kind NOT IN ('binding','role','group','membership','delegation','resource','identity','catalog','cluster')
 OR p_accounts IS NULL OR cardinality(p_accounts)>256
 OR EXISTS(SELECT 1 FROM unnest(p_accounts) a WHERE a IS NULL OR a='' OR btrim(a)<>a)
 OR (p_mode='accounts' AND (cardinality(p_accounts)=0 OR p_kind IN ('identity','catalog','cluster')))
 OR (p_mode='global' AND cardinality(p_accounts)<>0) THEN
  RAISE EXCEPTION 'invalid authority entry intent' USING ERRCODE='22023';
 END IF;
 SELECT coalesce(array_agg(DISTINCT a ORDER BY a),ARRAY[]::text[]) INTO logical FROM unnest(p_accounts) a;
 IF p_mode='global' THEN PERFORM pg_advisory_xact_lock(1262569283,0);
 ELSE
  PERFORM pg_advisory_xact_lock_shared(1262569283,0);
  SELECT array_agg(key ORDER BY key) INTO keys FROM (SELECT DISTINCT hashtext(a) key FROM unnest(logical) a) q;
  FOREACH k IN ARRAY keys LOOP PERFORM pg_advisory_xact_lock(1262569281,k); END LOOP;
 END IF;
 SELECT * INTO STRICT protocol FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
 SELECT * INTO STRICT active FROM kaname.authority_semantic_identity WHERE singleton FOR SHARE;
 IF protocol.protocol_version<>p_version OR active.protocol_version<>p_version
 OR NOT ((p_purpose='transition' AND protocol.enforcement='compatibility' AND active.phase='prepared') OR (p_purpose='decision' AND protocol.enforcement='strict' AND active.phase='active'))
 OR active.model_id IS DISTINCT FROM p_model OR active.catalog_id IS DISTINCT FROM p_catalog OR active.projector_version IS DISTINCT FROM p_projector THEN
  RAISE EXCEPTION 'authority semantic identity unavailable' USING ERRCODE='P1036';
 END IF;
 SELECT accounts,global_scope INTO actual,global_owner FROM kaname.authority_protocol_discover(p_refs);
 IF p_mode='accounts' AND (global_owner OR actual IS DISTINCT FROM logical) THEN
  RAISE EXCEPTION 'authority ownership classification changed' USING ERRCODE='P1034';
 END IF;
 -- current_setting(role) — проверяемое самим PostgreSQL SET ROLE, не свободный
 -- application GUC. При отсутствии SET ROLE действителен session_user.
 SELECT oid INTO STRICT invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=owner_oid AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 IF temp_oid IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_authority_attestation (
   singleton boolean PRIMARY KEY CHECK(singleton), backend integer NOT NULL, transaction_id xid8 NOT NULL,
   invoker_oid oid NOT NULL, nonce uuid NOT NULL, protocol integer NOT NULL,
   model_id text NOT NULL,catalog_id text NOT NULL,projector_version text NOT NULL,
   mode text NOT NULL,accounts text[] NOT NULL,kind text NOT NULL,purpose text NOT NULL,decision_at timestamptz NOT NULL
  ) ON COMMIT DELETE ROWS;
  REVOKE ALL ON pg_temp.kaname_authority_attestation FROM PUBLIC;
  -- Даже внешние ALTER DEFAULT PRIVILEGES владельца не раскрывают witness.
  FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE c.oid='pg_temp.kaname_authority_attestation'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_attestation FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_attestation) THEN
  RAISE EXCEPTION 'authority attestation is already present' USING ERRCODE='25001';
 END IF;
 at_time:=clock_timestamp();
 INSERT INTO pg_temp.kaname_authority_attestation VALUES(true,pg_backend_pid(),pg_current_xact_id(),invoker,gen_random_uuid(),p_version,p_model,p_catalog,p_projector,p_mode,logical,p_kind,p_purpose,at_time);
 RETURN at_time;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; k integer; expected_mode text;
BEGIN
 -- kaname#1034: locking read не позволяет старому RR/SSI snapshot сохранить
 -- compatibility после strict commit. У participant этот row lock уже взят entry.
 SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose'='transition' AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose'='decision' AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
  RAISE EXCEPTION 'authority transaction attestation mismatch' USING ERRCODE='42501';
 END IF;
 expected_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569283::oid AND objid=0::oid AND objsubid=2 AND mode=expected_mode AND granted) THEN
  RAISE EXCEPTION 'authority cluster barrier missing' USING ERRCODE='42501';
 END IF;
 IF proof->>'mode'='accounts' THEN
  FOR k IN SELECT DISTINCT hashtext(value) FROM jsonb_array_elements_text(proof->'accounts') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569281::oid AND objid=(k::bigint & 4294967295)::oid AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
    RAISE EXCEPTION 'authority account barrier missing' USING ERRCODE='42501';
   END IF;
  END LOOP;
 END IF;
 RETURN proof;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_row_account(p_table text,p_row jsonb) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a text; parent jsonb;
BEGIN
 CASE p_table
 WHEN 'accounts' THEN RETURN p_row->>'id';
 WHEN 'projects','groups','service_accounts','memberships','grant_delegations' THEN RETURN nullif(p_row->>'account_id','');
 WHEN 'roles' THEN
  a:=nullif(p_row->>'account_id','');
  IF a IS NULL THEN SELECT account_id INTO a FROM kaname.projects WHERE id=p_row->>'project_id'; END IF;
  RETURN a;
 WHEN 'access_bindings' THEN
  IF p_row->>'resource_type'='account' THEN RETURN p_row->>'resource_id'; END IF;
  IF p_row->>'resource_type'='project' THEN SELECT account_id INTO a FROM kaname.projects WHERE id=p_row->>'resource_id'; END IF;
  RETURN a;
 WHEN 'group_members' THEN SELECT account_id INTO a FROM kaname.groups WHERE id=p_row->>'group_id'; RETURN a;
 WHEN 'access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples' THEN
  SELECT to_jsonb(b) INTO parent FROM kaname.access_bindings b WHERE id=p_row->>'binding_id';
  RETURN kaname.authority_protocol_row_account('access_bindings',parent);
 WHEN 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule' THEN
  SELECT to_jsonb(r) INTO parent FROM kaname.roles r WHERE id=p_row->>'role_id';
  RETURN kaname.authority_protocol_row_account('roles',parent);
 ELSE RETURN NULL;
 END CASE;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
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
CREATE FUNCTION kaname.authority_protocol_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; a text;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NOT NULL AND proof->>'mode'<>'global' THEN
  IF TG_OP<>'INSERT' THEN
   a:=kaname.authority_protocol_row_account(TG_TABLE_NAME,to_jsonb(OLD));
   IF a IS NULL OR NOT (proof->'accounts' ? a) THEN RAISE EXCEPTION 'authority OLD scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
  IF TG_OP<>'DELETE' THEN
   a:=kaname.authority_protocol_row_account(TG_TABLE_NAME,to_jsonb(NEW));
   IF a IS NULL OR NOT (proof->'accounts' ? a) THEN RAISE EXCEPTION 'authority NEW scope not covered' USING ERRCODE='42501'; END IF;
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- Явный core footprint из принятого writer census. Остальные adapters/read-set
-- и более узкая классификация folded/registration rows обязательны до cutover.
-- Неизвестный row anchor требует global; строка не считается локальной по догадке.
-- +goose StatementBegin
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['accounts','projects','roles','groups','group_members','service_accounts','memberships','grant_delegations','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples','role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','users','cluster_admin_grants','catalog_module','catalog_resource','catalog_verb','resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer','resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox'] LOOP
  EXECUTE format('CREATE TRIGGER authority_protocol_statement BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON kaname.%I FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_protocol_statement_guard()',name);
  EXECUTE format('CREATE TRIGGER authority_protocol_row BEFORE INSERT OR UPDATE OR DELETE ON kaname.%I FOR EACH ROW EXECUTE FUNCTION kaname.authority_protocol_row_guard()',name);
 END LOOP;
END $$;
-- +goose StatementEnd

-- Административный grant-шов общий для bootstrap и реальных PG probes.
-- Никаких CREATE ROLE/паролей и никаких SECURITY DEFINER привилегий у этого API.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE target record; migration_owner oid; runtime_name text;
BEGIN
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid;
 SELECT relowner INTO migration_owner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)<>migration_owner THEN RAISE EXCEPTION 'runtime grants require migration owner' USING ERRCODE='42501'; END IF;
 IF p_runtime::oid=migration_owner OR pg_has_role(p_runtime,migration_owner,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE oid=p_runtime::oid AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='kaname' AND (nspowner<>migration_owner OR has_schema_privilege(p_runtime,oid,'CREATE')))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=p_runtime::oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND (pg_has_role(p_runtime,c.relowner,'MEMBER') OR (c.relkind IN ('r','p') AND has_table_privilege(p_runtime,c.oid,'TRIGGER'))))
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='kaname' AND pg_has_role(p_runtime,f.proowner,'MEMBER')) THEN
  RAISE EXCEPTION 'runtime must be separate from migration ownership and DDL authority' USING ERRCODE='42501';
 END IF;
 EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I',current_database(),runtime_name);
 EXECUTE format('GRANT USAGE ON SCHEMA kaname TO %I',runtime_name);
 EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA kaname TO %I',runtime_name);
 FOR target IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p') AND left(c.relname,10)<>'authority_' AND c.relname<>'goose_db_version' LOOP
  EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE ON TABLE kaname.%I TO %I',target.relname,runtime_name);
 END LOOP;
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_writer_protocol,kaname.authority_semantic_identity FROM %I',runtime_name);
 EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);
 EXECUTE format('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA kaname TO %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_writer_protocol','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains authority metadata mutation privileges' USING ERRCODE='42501';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
LOCK TABLE kaname.authority_writer_protocol IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_semantic_identity WHERE phase='prepared')
 OR EXISTS(SELECT 1 FROM kaname.authority_writer_protocol WHERE enforcement<>'compatibility')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND classid IN (1262569283::oid,1262569281::oid) AND objsubid=2 AND granted) THEN
  RAISE EXCEPTION 'authority protocol rollback requires compatibility and drained writers';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE row record; BEGIN
 FOR row IN SELECT n.nspname,c.relname,t.tgname FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND t.tgname IN ('authority_protocol_statement','authority_protocol_row') LOOP
  EXECUTE format('DROP TRIGGER %I ON %I.%I',row.tgname,row.nspname,row.relname);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_protocol_grant_runtime(regrole);
DROP FUNCTION kaname.authority_protocol_row_guard();
DROP FUNCTION kaname.authority_protocol_statement_guard();
DROP FUNCTION kaname.authority_protocol_row_account(text,jsonb);
DROP FUNCTION kaname.authority_protocol_attestation();
DROP FUNCTION kaname.authority_protocol_enter(text,text[],jsonb,text,text,text,text,integer,text);
DROP FUNCTION kaname.authority_protocol_prepare(text,text,text);
DROP FUNCTION kaname.authority_protocol_discover(jsonb);
DROP TABLE kaname.authority_writer_protocol;
ALTER TABLE kaname.authority_semantic_identity DROP CONSTRAINT authority_semantic_identity_prepared_check;
ALTER TABLE kaname.authority_semantic_identity DROP CONSTRAINT authority_semantic_identity_phase_check;
ALTER TABLE kaname.authority_semantic_identity ADD CONSTRAINT authority_semantic_identity_phase_check CHECK(phase IN ('uninitialized','transition','active'));
