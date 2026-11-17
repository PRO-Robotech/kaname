-- +goose Up
-- +goose StatementBegin
-- A writer contract is an owner-activated compatibility boundary, not a GUC,
-- projector bump or claim that a policy decision has already succeeded.
SELECT kaname.authority_protocol_drain();
CREATE TABLE kaname.authority_writer_contract (
 singleton boolean PRIMARY KEY CHECK(singleton),
 required_contract integer NOT NULL CHECK(required_contract IN (1,2)),
 staged_contract integer NOT NULL CHECK(staged_contract IN (1,2))
);
INSERT INTO kaname.authority_writer_contract VALUES(true,1,1);
REVOKE ALL ON kaname.authority_writer_contract FROM PUBLIC;


CREATE FUNCTION kaname._authority_protocol_enter_contract_v3(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text,p_contract integer)
RETURNS timestamptz LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys integer[]; k integer; logical text[]; actual text[]; global_owner boolean;
 active kaname.authority_semantic_identity%ROWTYPE; protocol kaname.authority_writer_protocol%ROWTYPE;
 contract_state kaname.authority_writer_contract%ROWTYPE;
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
 SELECT * INTO STRICT contract_state FROM kaname.authority_writer_contract WHERE singleton FOR SHARE;
 IF p_contract IS NULL OR p_contract NOT IN (1,2) OR contract_state.required_contract<>p_contract
 OR (p_contract=2 AND (active.phase<>'active' OR protocol.enforcement<>'strict' OR contract_state.staged_contract<>2)) THEN
  RAISE EXCEPTION 'authority writer contract unavailable' USING ERRCODE='P1036';
 END IF;
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
   mode text NOT NULL,accounts text[] NOT NULL,kind text NOT NULL,purpose text NOT NULL,decision_at timestamptz NOT NULL,writer_contract integer NOT NULL DEFAULT 1
  ) ON COMMIT DELETE ROWS;
  REVOKE ALL ON pg_temp.kaname_authority_attestation FROM PUBLIC;
  -- Даже внешние ALTER DEFAULT PRIVILEGES владельца не раскрывают witness.
  FOR grantee IN SELECT DISTINCT a.grantee,r.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE c.oid='pg_temp.kaname_authority_attestation'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_attestation FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 -- Idle connections can retain an empty pre-migration owner-owned temp table.
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute WHERE attrelid='pg_temp.kaname_authority_attestation'::regclass AND attname='writer_contract' AND NOT attisdropped) THEN
  ALTER TABLE pg_temp.kaname_authority_attestation ADD COLUMN writer_contract integer NOT NULL DEFAULT 1;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_attestation) THEN
  RAISE EXCEPTION 'authority attestation is already present' USING ERRCODE='25001';
 END IF;
 at_time:=clock_timestamp();
 INSERT INTO pg_temp.kaname_authority_attestation VALUES(true,pg_backend_pid(),pg_current_xact_id(),invoker,gen_random_uuid(),p_version,p_model,p_catalog,p_projector,p_mode,logical,p_kind,p_purpose,at_time,p_contract);
 RETURN at_time;
END $$;

CREATE FUNCTION kaname._authority_consumer_enter_contract_v3(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_purpose text,p_consumer text,p_population jsonb,p_contract integer)
RETURNS timestamptz LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE at_time timestamptz; proof jsonb; storage oid; grantee record;
 owner_oid oid:=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user);
BEGIN
 -- Только wrappers с фиксированным profile могут вызывать этот private helper.
 IF p_consumer NOT IN ('typed','full','resource_pending','resource_source_pending') OR p_consumer IS NULL THEN
  RAISE EXCEPTION 'invalid consumer profile' USING ERRCODE='22023';
 END IF;
 IF p_consumer='full' THEN
  IF p_population IS NULL OR jsonb_typeof(p_population)<>'object'
  OR (SELECT count(*) FROM jsonb_object_keys(p_population))<>3
  OR jsonb_typeof(p_population->'generation') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_population->'count') IS DISTINCT FROM 'number'
  OR jsonb_typeof(p_population->'revision') IS DISTINCT FROM 'string'
  OR (p_population->>'generation') !~ '^[1-9][0-9]*$'
  OR (p_population->>'revision') !~ '^(0|[1-9][0-9]*)$'
  OR (p_population->>'count') !~ '^[1-9][0-9]*$' THEN
   RAISE EXCEPTION 'full population witness required' USING ERRCODE='22023';
  END IF;
  IF (p_population->>'count')::numeric>100000 THEN
   RAISE EXCEPTION 'population witness exceeds budget' USING ERRCODE='54000';
  END IF;
 ELSIF p_population IS NOT NULL THEN
  RAISE EXCEPTION 'unexpected full population witness' USING ERRCODE='22023';
 END IF;
 IF p_consumer IN ('resource_pending','resource_source_pending') AND (p_kind<>'resource' OR p_purpose<>'participant') THEN
  RAISE EXCEPTION 'resource output requires typed participant entry' USING ERRCODE='22023';
 END IF;
 at_time:=kaname._authority_protocol_enter_contract_v3(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,1,p_purpose,p_contract);
 -- Общий admission предшествует любому business wait. Этот namespace отдельно
 -- от cluster/account и от старой bigint registration блокировки.
 IF p_mode='global' THEN PERFORM pg_advisory_xact_lock(1262569292,0);
 ELSE PERFORM pg_advisory_xact_lock_shared(1262569292,0); END IF;
 -- Исторический typed SOURCE writer исключает narrow Resource output.
 -- Resource SOURCE+OUTPUT остаётся ROW EXCLUSIVE: его authored изменения
 -- дополнительно требуют exact EXCLUSIVE keys из server-validated manifest.
 -- SHARE не утверждает полноту census и совместим с другими account writers.
 IF p_consumer IN ('full','typed') THEN
  LOCK TABLE kaname.authority_producer_population_latch IN SHARE MODE;
 ELSIF p_consumer IN ('resource_pending','resource_source_pending') THEN
  LOCK TABLE kaname.authority_producer_population_latch IN ROW EXCLUSIVE MODE;
 END IF;
 SELECT to_jsonb(a) INTO STRICT proof FROM pg_temp.kaname_authority_attestation a;
 storage:=to_regclass('pg_temp.kaname_authority_consumer');
 IF storage IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=storage AND relowner=owner_oid AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted consumer storage' USING ERRCODE='42501';
 END IF;
 IF storage IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_authority_consumer (
   singleton boolean PRIMARY KEY CHECK(singleton),backend integer NOT NULL,
   transaction_id xid8 NOT NULL,invoker_oid oid NOT NULL,nonce uuid NOT NULL,
   abi integer NOT NULL CHECK(abi=2),profile text NOT NULL,
   population jsonb,finalized boolean NOT NULL DEFAULT false
  ) ON COMMIT DELETE ROWS;
  REVOKE ALL ON pg_temp.kaname_authority_consumer FROM PUBLIC;
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid='pg_temp.kaname_authority_consumer'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_consumer FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer) THEN
  RAISE EXCEPTION 'consumer profile already selected' USING ERRCODE='25001';
 END IF;
 INSERT INTO pg_temp.kaname_authority_consumer(singleton,backend,transaction_id,invoker_oid,nonce,abi,profile,population)
 VALUES(true,(proof->>'backend')::integer,(proof->>'transaction_id')::xid8,(proof->>'invoker_oid')::oid,(proof->>'nonce')::uuid,2,p_consumer,p_population);
 -- Это лишь entry time. Ни profile, ни latch не выдают semantic/native allow.
 RETURN at_time;
END $$;

CREATE OR REPLACE FUNCTION kaname._authority_protocol_enter_v1_body(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_protocol_enter_contract_v3(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,p_version,p_purpose,1);
$$;
CREATE OR REPLACE FUNCTION kaname._authority_protocol_enter_v2(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_purpose text,p_consumer text,p_population jsonb)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_consumer_enter_contract_v3(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,p_purpose,p_consumer,p_population,1);
$$;

CREATE OR REPLACE FUNCTION kaname._authority_protocol_attestation_v1_body() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; k integer; expected_mode text;
BEGIN
 -- Unsigned RR сохраняет locking freshness прежнего протокола. Signed RC
 -- использует только private witness, созданный после successful protocol/identity
 -- FOR SHARE в entry: повторное acquisition после final clock запрещено.
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 -- Ряд witness записан тем же entry после получения обоих row locks.
 -- SAVEPOINT rollback, отменяющий их acquisition, отменяет и INSERT witness;
 -- старый witness не проходит xid/backend/nonce и ON COMMIT DELETE ROWS.
 IF current_setting('transaction_isolation')<>'read committed'
 OR (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract c WHERE c.singleton AND c.required_contract=(proof->>'writer_contract')::integer)
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

CREATE FUNCTION kaname.authority_protocol_enter_typed_v3(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_purpose text)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_consumer_enter_contract_v3(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,p_purpose,'typed',NULL,2);
$$;

CREATE FUNCTION kaname.authority_protocol_enter_full_v3(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_purpose text,p_population jsonb)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_consumer_enter_contract_v3(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,p_purpose,'full',p_population,2);
$$;

CREATE FUNCTION kaname.authority_resource_enter_v3(p_mode text,p_accounts text[],p_refs jsonb,p_model text,p_catalog text,p_projector text)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_consumer_enter_contract_v3(p_mode,p_accounts,p_refs,'resource',p_model,p_catalog,p_projector,'participant','resource_pending',NULL,2);
$$;

CREATE FUNCTION kaname.authority_resource_source_enter_v3(p_mode text,p_accounts text[],p_refs jsonb,p_model text,p_catalog text,p_projector text)
RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_consumer_enter_contract_v3(p_mode,p_accounts,p_refs,'resource',p_model,p_catalog,p_projector,'participant','resource_source_pending',NULL,2);
$$;

CREATE FUNCTION kaname.authority_installation_enter_v3(p_kind text,p_model text,p_catalog text,p_projector text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF p_kind IS NULL OR p_kind NOT IN ('catalog','role','binding','identity','cluster') THEN
  RAISE EXCEPTION 'unsupported installation writer family' USING ERRCODE='22023';
 END IF;
 -- Identity belongs to the immutable full startup contract; never adopt DB identity.
 PERFORM kaname._authority_consumer_enter_contract_v3('global',ARRAY[]::text[],'[]'::jsonb,p_kind,p_model,p_catalog,p_projector,'participant','typed',NULL,2);
 RETURN 3;
END $$;
CREATE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$ SELECT false; $$;
CREATE FUNCTION kaname.authority_full_contract_validate_v3(p_model text,p_catalog text,p_projector text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM kaname.authority_writer_contract c
 CROSS JOIN kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p
 JOIN kaname.authority_bundle_handoff b ON b.singleton=p.singleton
 WHERE kaname._authority_full_contract_storage_v3() AND c.singleton AND a.singleton AND p.singleton AND c.required_contract=2 AND c.staged_contract=2
 AND p.enforcement='strict' AND a.phase='active' AND p.protocol_version=1 AND a.protocol_version=1
 AND (a.model_id,a.catalog_id,a.projector_version)=(p_model,p_catalog,p_projector)
 AND (b.model_id,b.catalog_id,b.projector_version)=(p_model,p_catalog,p_projector));
$$;
CREATE FUNCTION kaname.authority_staged_contract_validate_v3() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT required_contract=1 FROM kaname.authority_writer_contract WHERE singleton;
$$;
ALTER FUNCTION kaname.authority_protocol_stage(text,bytea,text,text,text) RENAME TO _authority_protocol_stage_generation1;
ALTER FUNCTION kaname.authority_protocol_activate(text,text,text) RENAME TO _authority_protocol_activate_generation1;
CREATE FUNCTION kaname.authority_protocol_stage(p_source text,p_catalog bytea,p_model_id text,p_catalog_id text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE singleton AND required_contract=1) THEN
  RAISE EXCEPTION 'writer contract downgrade forbidden' USING ERRCODE='P1036';
 END IF;
 PERFORM kaname._authority_protocol_stage_generation1(p_source,p_catalog,p_model_id,p_catalog_id,p_projector);
 UPDATE kaname.authority_writer_contract SET staged_contract=1 WHERE singleton;
END $$;
CREATE FUNCTION kaname.authority_protocol_activate(p_model text,p_catalog text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE singleton AND required_contract=1 AND staged_contract=1) THEN
  RAISE EXCEPTION 'generation1 activation requires generation1 stage' USING ERRCODE='P1036';
 END IF;
 PERFORM kaname._authority_protocol_activate_generation1(p_model,p_catalog,p_projector);
END $$;
CREATE FUNCTION kaname.authority_protocol_stage_full_v3(p_source text,p_catalog bytea,p_model_id text,p_catalog_id text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 PERFORM kaname._authority_protocol_stage_generation1(p_source,p_catalog,p_model_id,p_catalog_id,p_projector);
 UPDATE kaname.authority_writer_contract SET staged_contract=2 WHERE singleton;
END $$;
CREATE FUNCTION kaname.authority_protocol_activate_full_v3(p_model text,p_catalog text,p_projector text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 PERFORM kaname.authority_protocol_require_drain();
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'full writer contract storage unavailable' USING ERRCODE='P1036';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE singleton AND staged_contract=2) THEN
  RAISE EXCEPTION 'full activation requires explicit full stage' USING ERRCODE='P1036';
 END IF;
 PERFORM kaname._authority_protocol_activate_generation1(p_model,p_catalog,p_projector);
 UPDATE kaname.authority_writer_contract SET required_contract=2 WHERE singleton;
END $$;
ALTER FUNCTION kaname.authority_protocol_grant_runtime(regrole) RENAME TO _authority_protocol_grant_runtime_generation1;
CREATE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 FOREACH signature IN ARRAY ARRAY[
  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected record; owner_oid oid; target text;
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
 FOR expected IN SELECT * FROM (VALUES
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','944ba541d302f3d3d0ef2a3479ebeff637ec8ef0cb154134e15f16a9d5611b43',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','08a5fa40928f579b763b6870192f241842145ef57b8889ecef0891768557f9ad',true),
 ('authority_protocol_statement_guard()','d22abfe60fef1cbdae8b23b0b5ebbaa3e4de29593d0fc6d75ec72145b9a1797c',true),
 ('authority_protocol_row_guard()','28a374ab14661c74d6922d400a085f4edf8c8da60269d0b478ac9112a3c08708',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest) THEN RETURN false; END IF;
  IF left(expected.signature,1)='_' AND EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   WHERE p.oid=to_regprocedure('kaname.'||expected.signature) AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;

-- Close default-ACL grants on every new helper and state table. Only the
-- existing owner provisioning command grants the finite public runtime profile.
DO $$ DECLARE f record; r record; BEGIN
 FOR f IN SELECT p.oid,p.oid::regprocedure AS signature,p.proowner FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='kaname' AND (p.proname LIKE '%contract%v3' OR p.proname LIKE '%generation1'
 OR p.proname IN ('authority_protocol_enter_typed_v3','authority_protocol_enter_full_v3','authority_resource_enter_v3','authority_resource_source_enter_v3','authority_installation_enter_v3','authority_protocol_stage_full_v3','authority_protocol_activate_full_v3','authority_protocol_stage','authority_protocol_activate','authority_protocol_grant_runtime')) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',f.signature);
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE p.oid=f.oid AND a.grantee<>f.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',f.signature,r.rolname);
  END LOOP;
 END LOOP;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  JOIN pg_catalog.pg_roles u ON u.oid=a.grantee WHERE c.oid='kaname.authority_writer_contract'::regclass AND a.grantee<>c.relowner LOOP
  EXECUTE format('REVOKE ALL ON TABLE kaname.authority_writer_contract FROM %I',r.rolname);
 END LOOP;
END $$;
DO $$ DECLARE r record; pair record; BEGIN
 FOR pair IN SELECT * FROM (VALUES
  ('authority_protocol_enter_typed_v2(text,text[],jsonb,text,text,text,text,text)','authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'),
  ('authority_protocol_enter_full_v2(text,text[],jsonb,text,text,text,text,text,jsonb)','authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)'),
  ('authority_resource_enter_v2(text,text[],jsonb,text,text,text)','authority_resource_enter_v3(text,text[],jsonb,text,text,text)'),
  ('authority_resource_source_enter_v2(text,text[],jsonb,text,text,text)','authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)'),
  ('authority_installation_enter_v2(text)','authority_installation_enter_v3(text,text,text,text)'),
  ('authority_protocol_enter_typed_v2(text,text[],jsonb,text,text,text,text,text)','authority_full_contract_validate_v3(text,text,text)'),
  ('authority_protocol_enter_typed_v2(text,text[],jsonb,text,text,text,text,text)','authority_staged_contract_validate_v3()')
 ) AS profiles(old_signature,new_signature) LOOP
  FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||pair.old_signature) AND a.privilege_type='EXECUTE' AND a.grantee<>p.proowner LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',pair.new_signature,r.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin
SELECT kaname.authority_protocol_drain();
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2) THEN
  RAISE EXCEPTION 'cannot erase activated full writer contract' USING ERRCODE='P1036';
 END IF;
END $$;
DROP FUNCTION kaname.authority_protocol_grant_runtime(regrole);
ALTER FUNCTION kaname._authority_protocol_grant_runtime_generation1(regrole) RENAME TO authority_protocol_grant_runtime;
DROP FUNCTION kaname.authority_protocol_stage(text,bytea,text,text,text);
DROP FUNCTION kaname.authority_protocol_activate(text,text,text);
ALTER FUNCTION kaname._authority_protocol_stage_generation1(text,bytea,text,text,text) RENAME TO authority_protocol_stage;
ALTER FUNCTION kaname._authority_protocol_activate_generation1(text,text,text) RENAME TO authority_protocol_activate;
DROP FUNCTION kaname.authority_protocol_stage_full_v3(text,bytea,text,text,text);
DROP FUNCTION kaname.authority_protocol_activate_full_v3(text,text,text);
DROP FUNCTION kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text);
DROP FUNCTION kaname.authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb);
DROP FUNCTION kaname.authority_resource_enter_v3(text,text[],jsonb,text,text,text);
DROP FUNCTION kaname.authority_resource_source_enter_v3(text,text[],jsonb,text,text,text);
DROP FUNCTION kaname.authority_installation_enter_v3(text,text,text,text);
DROP FUNCTION kaname.authority_full_contract_validate_v3(text,text,text);
DROP FUNCTION kaname.authority_staged_contract_validate_v3();
DROP FUNCTION kaname._authority_full_contract_storage_v3();


CREATE OR REPLACE FUNCTION kaname._authority_protocol_enter_v1_body(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_version integer,p_purpose text)
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
 INSERT INTO pg_temp.kaname_authority_attestation(singleton,backend,transaction_id,invoker_oid,nonce,protocol,model_id,catalog_id,projector_version,mode,accounts,kind,purpose,decision_at) VALUES(true,pg_backend_pid(),pg_current_xact_id(),invoker,gen_random_uuid(),p_version,p_model,p_catalog,p_projector,p_mode,logical,p_kind,p_purpose,at_time);
 RETURN at_time;
END $$;

CREATE OR REPLACE FUNCTION kaname._authority_protocol_enter_v2(p_mode text,p_accounts text[],p_refs jsonb,p_kind text,p_model text,p_catalog text,p_projector text,p_purpose text,p_consumer text,p_population jsonb)
RETURNS timestamptz LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE at_time timestamptz; proof jsonb; storage oid; grantee record;
 owner_oid oid:=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user);
BEGIN
 -- Только wrappers с фиксированным profile могут вызывать этот private helper.
 IF p_consumer NOT IN ('typed','full','resource_pending','resource_source_pending') OR p_consumer IS NULL THEN
  RAISE EXCEPTION 'invalid consumer profile' USING ERRCODE='22023';
 END IF;
 IF p_consumer='full' THEN
  IF p_population IS NULL OR jsonb_typeof(p_population)<>'object'
  OR (SELECT count(*) FROM jsonb_object_keys(p_population))<>3
  OR jsonb_typeof(p_population->'generation') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_population->'count') IS DISTINCT FROM 'number'
  OR jsonb_typeof(p_population->'revision') IS DISTINCT FROM 'string'
  OR (p_population->>'generation') !~ '^[1-9][0-9]*$'
  OR (p_population->>'revision') !~ '^(0|[1-9][0-9]*)$'
  OR (p_population->>'count') !~ '^[1-9][0-9]*$' THEN
   RAISE EXCEPTION 'full population witness required' USING ERRCODE='22023';
  END IF;
  IF (p_population->>'count')::numeric>100000 THEN
   RAISE EXCEPTION 'population witness exceeds budget' USING ERRCODE='54000';
  END IF;
 ELSIF p_population IS NOT NULL THEN
  RAISE EXCEPTION 'unexpected full population witness' USING ERRCODE='22023';
 END IF;
 IF p_consumer IN ('resource_pending','resource_source_pending') AND (p_kind<>'resource' OR p_purpose<>'participant') THEN
  RAISE EXCEPTION 'resource output requires typed participant entry' USING ERRCODE='22023';
 END IF;
 at_time:=kaname._authority_protocol_enter_v1_body(p_mode,p_accounts,p_refs,p_kind,p_model,p_catalog,p_projector,1,p_purpose);
 -- Общий admission предшествует любому business wait. Этот namespace отдельно
 -- от cluster/account и от старой bigint registration блокировки.
 IF p_mode='global' THEN PERFORM pg_advisory_xact_lock(1262569292,0);
 ELSE PERFORM pg_advisory_xact_lock_shared(1262569292,0); END IF;
 -- Исторический typed SOURCE writer исключает narrow Resource output.
 -- Resource SOURCE+OUTPUT остаётся ROW EXCLUSIVE: его authored изменения
 -- дополнительно требуют exact EXCLUSIVE keys из server-validated manifest.
 -- SHARE не утверждает полноту census и совместим с другими account writers.
 IF p_consumer IN ('full','typed') THEN
  LOCK TABLE kaname.authority_producer_population_latch IN SHARE MODE;
 ELSIF p_consumer IN ('resource_pending','resource_source_pending') THEN
  LOCK TABLE kaname.authority_producer_population_latch IN ROW EXCLUSIVE MODE;
 END IF;
 SELECT to_jsonb(a) INTO STRICT proof FROM pg_temp.kaname_authority_attestation a;
 storage:=to_regclass('pg_temp.kaname_authority_consumer');
 IF storage IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=storage AND relowner=owner_oid AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted consumer storage' USING ERRCODE='42501';
 END IF;
 IF storage IS NULL THEN
  CREATE TEMP TABLE pg_temp.kaname_authority_consumer (
   singleton boolean PRIMARY KEY CHECK(singleton),backend integer NOT NULL,
   transaction_id xid8 NOT NULL,invoker_oid oid NOT NULL,nonce uuid NOT NULL,
   abi integer NOT NULL CHECK(abi=2),profile text NOT NULL,
   population jsonb,finalized boolean NOT NULL DEFAULT false
  ) ON COMMIT DELETE ROWS;
  REVOKE ALL ON pg_temp.kaname_authority_consumer FROM PUBLIC;
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid='pg_temp.kaname_authority_consumer'::regclass AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON pg_temp.kaname_authority_consumer FROM %I',grantee.rolname);
  END LOOP;
 END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer) THEN
  RAISE EXCEPTION 'consumer profile already selected' USING ERRCODE='25001';
 END IF;
 INSERT INTO pg_temp.kaname_authority_consumer(singleton,backend,transaction_id,invoker_oid,nonce,abi,profile,population)
 VALUES(true,(proof->>'backend')::integer,(proof->>'transaction_id')::xid8,(proof->>'invoker_oid')::oid,(proof->>'nonce')::uuid,2,p_consumer,p_population);
 -- Это лишь entry time. Ни profile, ни latch не выдают semantic/native allow.
 RETURN at_time;
END $$;

CREATE OR REPLACE FUNCTION kaname._authority_protocol_attestation_v1_body() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; k integer; expected_mode text;
BEGIN
 -- Unsigned RR сохраняет locking freshness прежнего протокола. Signed RC
 -- использует только private witness, созданный после successful protocol/identity
 -- FOR SHARE в entry: повторное acquisition после final clock запрещено.
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 -- Ряд witness записан тем же entry после получения обоих row locks.
 -- SAVEPOINT rollback, отменяющий их acquisition, отменяет и INSERT witness;
 -- старый witness не проходит xid/backend/nonce и ON COMMIT DELETE ROWS.
 IF current_setting('transaction_isolation')<>'read committed'
 OR (proof->>'backend')::integer<>pg_backend_pid()
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

DROP FUNCTION kaname._authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer);
DROP FUNCTION kaname._authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer);
DROP TABLE kaname.authority_writer_contract;
-- +goose StatementEnd
