-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: явный lifecycle; migration НЕ выполняет stage/activation.
-- +goose Up
CREATE TABLE kaname.authority_bundle_handoff (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 model_source text NOT NULL CHECK(octet_length(model_source) BETWEEN 1 AND 8388608),
 catalog_json bytea NOT NULL CHECK(octet_length(catalog_json) BETWEEN 1 AND 8388608),
 model_id text NOT NULL CHECK(model_id=encode(sha256(convert_to(model_source,'UTF8')),'hex')),
 catalog_id text NOT NULL CHECK(catalog_id=encode(sha256(catalog_json),'hex')),
 projector_version text NOT NULL CHECK(projector_version<>'')
);
REVOKE ALL ON kaname.authority_bundle_handoff FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE grantee record; BEGIN
 FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_class c
 CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
 WHERE c.oid='kaname.authority_bundle_handoff'::regclass AND a.grantee<>c.relowner LOOP
  EXECUTE format('REVOKE ALL ON kaname.authority_bundle_handoff FROM %I',grantee.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd


-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_tables() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT array_agg(name ORDER BY name COLLATE "C") FROM unnest(ARRAY['accounts','projects','roles','groups','group_members','service_accounts','memberships','grant_delegations','access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples','role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','users','cluster_admin_grants','catalog_module','catalog_resource','catalog_verb','resource_mirror','resource_parent_edge','resource_registration_scope','resource_registration_pointer','resource_registration_retirement','producer_source_receipt','public_read_publication','relation_fact','fga_outbox']::text[]) name
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_require_owner() RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) IS DISTINCT FROM
 (SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass)
 THEN RAISE EXCEPTION 'authority lifecycle requires migration owner' USING ERRCODE='42501'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_drain() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE name text; actual text[]; expected text[]:=kaname.authority_protocol_tables(); guards integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF current_setting('transaction_isolation')<>'read committed' OR pg_current_xact_id_if_assigned() IS NOT NULL
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND (locktype='advisory' OR (locktype='relation' AND mode<>'AccessShareLock')))
 THEN RAISE EXCEPTION 'authority drain requires fresh transaction' USING ERRCODE='25001'; END IF;
 PERFORM set_config('lock_timeout','2s',true);
 PERFORM pg_advisory_xact_lock(1262569283,0);
 -- Сначала dependency tables. Ни protocol, ни identity row пока не заперты.
 FOREACH name IN ARRAY expected LOOP
  EXECUTE format('LOCK TABLE kaname.%I IN ACCESS EXCLUSIVE MODE',name);
 END LOOP;
 SELECT array_agg(q.name ORDER BY q.name COLLATE "C") INTO actual FROM (
  SELECT DISTINCT c.relname::text name FROM pg_catalog.pg_trigger t
  JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='kaname' AND t.tgfoid IN ('kaname.authority_protocol_statement_guard()'::regprocedure,'kaname.authority_protocol_row_guard()'::regprocedure)
 ) q;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'authority guard footprint changed' USING ERRCODE='55000'; END IF;
 SELECT count(*) INTO guards FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='kaname' AND c.relname=ANY(expected) AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal
 AND ((t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure AND t.tgtype=62)
 OR (t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure AND t.tgtype=31));
 IF guards<>2*cardinality(expected) THEN RAISE EXCEPTION 'authority guards are incomplete or disabled' USING ERRCODE='55000'; END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_require_drain() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE name text; db oid:=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database());
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=db AND locktype='advisory' AND classid=1262569283::oid AND objid=0::oid AND objsubid=2 AND mode='ExclusiveLock' AND granted)
 THEN RAISE EXCEPTION 'authority drain barrier absent' USING ERRCODE='42501'; END IF;
 FOREACH name IN ARRAY kaname.authority_protocol_tables() LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=db AND locktype='relation' AND relation=to_regclass(format('kaname.%I',name)) AND mode='AccessExclusiveLock' AND granted)
  THEN RAISE EXCEPTION 'authority dependency drain absent' USING ERRCODE='42501'; END IF;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_stage(p_source text,p_catalog bytea,p_model_id text,p_catalog_id text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE phase_now text;
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 PERFORM 1 FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
 SELECT phase INTO STRICT phase_now FROM kaname.authority_semantic_identity WHERE singleton FOR UPDATE;
 IF phase_now NOT IN ('uninitialized','prepared','transition') THEN RAISE EXCEPTION 'close active bundle before staging' USING ERRCODE='55000'; END IF;
 INSERT INTO kaname.authority_bundle_handoff VALUES(true,p_source,p_catalog,p_model_id,p_catalog_id,p_projector)
 ON CONFLICT(singleton) DO UPDATE SET model_source=excluded.model_source,catalog_json=excluded.catalog_json,model_id=excluded.model_id,catalog_id=excluded.catalog_id,projector_version=excluded.projector_version;
 UPDATE kaname.authority_semantic_identity SET phase='prepared',protocol_version=1,model_id=p_model_id,catalog_id=p_catalog_id,projector_version=p_projector WHERE singleton;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_activate(p_model text,p_catalog text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 PERFORM 1 FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
 PERFORM 1 FROM kaname.authority_semantic_identity WHERE singleton FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a JOIN kaname.authority_bundle_handoff b USING(singleton)
 WHERE a.singleton AND a.phase='prepared' AND a.protocol_version=1 AND a.model_id=p_model AND a.catalog_id=p_catalog AND a.projector_version=p_projector
 AND b.model_id=a.model_id AND b.catalog_id=a.catalog_id AND b.projector_version=a.projector_version)
 THEN RAISE EXCEPTION 'authority prepared bundle mismatch' USING ERRCODE='P1036'; END IF;
 UPDATE kaname.authority_semantic_identity SET phase='active' WHERE singleton;
 UPDATE kaname.authority_writer_protocol SET enforcement='strict' WHERE singleton;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_close() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 PERFORM 1 FROM kaname.authority_writer_protocol WHERE singleton FOR UPDATE;
 UPDATE kaname.authority_semantic_identity SET phase='transition' WHERE singleton AND phase<>'uninitialized';
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_read_bundle()
RETURNS TABLE(model_source text,catalog_json bytea,model_id text,catalog_id text,projector_version text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT b.model_source,b.catalog_json,b.model_id,b.catalog_id,b.projector_version
 FROM kaname.authority_bundle_handoff b JOIN kaname.authority_semantic_identity a USING(singleton)
 JOIN kaname.authority_writer_protocol p USING(singleton)
 WHERE b.singleton AND a.protocol_version=1 AND p.protocol_version=1
 AND ((a.phase='prepared' AND p.enforcement='compatibility') OR (a.phase='active' AND p.enforcement='strict'))
 AND (a.model_id,a.catalog_id,a.projector_version)=(b.model_id,b.catalog_id,b.projector_version)
$$;
-- +goose StatementEnd

-- Изменение actual catalog закрывает старую identity, не переписывает её digest.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_protocol_catalog_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='UPDATE' AND to_jsonb(OLD) IS NOT DISTINCT FROM to_jsonb(NEW) THEN RETURN NEW; END IF;
 IF EXISTS(SELECT 1 FROM kaname.authority_bundle_handoff WHERE singleton) THEN
  UPDATE kaname.authority_semantic_identity SET phase='transition' WHERE singleton AND phase IN ('prepared','active');
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['catalog_module','catalog_resource','catalog_verb'] LOOP
  EXECUTE format('CREATE TRIGGER authority_catalog_changed AFTER INSERT OR UPDATE OR DELETE ON kaname.%I FOR EACH ROW EXECUTE FUNCTION kaname.authority_protocol_catalog_changed()',name);
  EXECUTE format('CREATE TRIGGER authority_catalog_truncated AFTER TRUNCATE ON kaname.%I FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_protocol_catalog_changed()',name);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_enter(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text)
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
 OR p_purpose IS NULL OR p_purpose NOT IN ('transition','decision','participant')
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
 OR NOT ((p_purpose IN ('transition','participant') AND protocol.enforcement='compatibility' AND active.phase='prepared') OR (p_purpose IN ('decision','participant') AND protocol.enforcement='strict' AND active.phase='active'))
 OR active.model_id IS DISTINCT FROM p_model OR active.catalog_id IS DISTINCT FROM p_catalog OR active.projector_version IS DISTINCT FROM p_projector THEN
  RAISE EXCEPTION 'authority semantic identity unavailable' USING ERRCODE='P1036';
 END IF;
 IF p_purpose='participant' AND NOT EXISTS(SELECT 1 FROM kaname.authority_bundle_handoff b WHERE b.singleton AND b.model_id=p_model AND b.catalog_id=p_catalog AND b.projector_version=p_projector) THEN RAISE EXCEPTION 'authority bundle handoff unavailable' USING ERRCODE='P1036'; END IF;
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
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
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
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose' IN ('transition','participant') AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose' IN ('decision','participant') AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
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
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
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
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_writer_protocol,kaname.authority_semantic_identity,kaname.authority_bundle_handoff FROM %I',runtime_name);
 EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);
 EXECUTE format('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA kaname TO %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_bundle_handoff','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_writer_protocol','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains authority metadata mutation privileges' USING ERRCODE='42501';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
SET LOCAL lock_timeout='2s';
-- Тот же порядок, что у lifecycle: не запираем handoff до dependency tables.
-- +goose StatementBegin
DO $$ DECLARE name text; BEGIN
 PERFORM pg_advisory_xact_lock(1262569283,0);
 FOREACH name IN ARRAY kaname.authority_protocol_tables() LOOP
  EXECUTE format('LOCK TABLE kaname.%I IN ACCESS EXCLUSIVE MODE',name);
 END LOOP;
END $$;
-- +goose StatementEnd
LOCK TABLE kaname.authority_bundle_handoff IN ACCESS EXCLUSIVE MODE;
-- Не превращаем действующий handoff в старый более слабый протокол.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_bundle_handoff) THEN RAISE EXCEPTION 'authority lifecycle rollback requires absent handoff'; END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_enter(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text)
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
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
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
DROP TRIGGER authority_catalog_changed ON kaname.catalog_module;
DROP TRIGGER authority_catalog_truncated ON kaname.catalog_module;
DROP TRIGGER authority_catalog_changed ON kaname.catalog_resource;
DROP TRIGGER authority_catalog_truncated ON kaname.catalog_resource;
DROP TRIGGER authority_catalog_changed ON kaname.catalog_verb;
DROP TRIGGER authority_catalog_truncated ON kaname.catalog_verb;
DROP FUNCTION kaname.authority_protocol_catalog_changed();
DROP FUNCTION kaname.authority_protocol_read_bundle();
DROP FUNCTION kaname.authority_protocol_close();
DROP FUNCTION kaname.authority_protocol_activate(text,text,text);
DROP FUNCTION kaname.authority_protocol_stage(text,bytea,text,text,text);
DROP FUNCTION kaname.authority_protocol_require_drain();
DROP FUNCTION kaname.authority_protocol_drain();
DROP FUNCTION kaname.authority_protocol_require_owner();
DROP FUNCTION kaname.authority_protocol_tables();
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
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
DROP TABLE kaname.authority_bundle_handoff;
