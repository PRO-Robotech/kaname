-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытое хранилище координат, ожидающих подтверждения свежести.
-- +goose Up
-- +goose StatementBegin
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'access label freshness authority closure incomplete' USING ERRCODE='55000';END IF;
END $$;
CREATE TABLE kaname.authority_access_label_dirty_root (
 root_type text NOT NULL,
 root_id text NOT NULL,
 generation uuid NOT NULL,
 new_labels jsonb NOT NULL,
 CONSTRAINT authority_access_label_dirty_root_pkey PRIMARY KEY(root_type,root_id),
 CONSTRAINT authority_access_label_dirty_root_generation UNIQUE(root_type,root_id,generation),
 CONSTRAINT authority_access_label_dirty_root_type CHECK(root_type IN ('iam.account','iam.project')),
 CONSTRAINT authority_access_label_dirty_root_id CHECK(root_id<>''),
 CONSTRAINT authority_access_label_dirty_root_labels CHECK(kaname.access_labels_valid_v1(new_labels))
);
CREATE TABLE kaname.authority_access_label_dirty_fact (
 root_type text NOT NULL,
 root_id text NOT NULL,
 generation uuid NOT NULL,
 object_type text NOT NULL,
 object_id text NOT NULL,
 relation text NOT NULL,
 subject text NOT NULL,
 CONSTRAINT authority_access_label_dirty_fact_pkey PRIMARY KEY(root_type,root_id,object_type,object_id,relation,subject),
 CONSTRAINT authority_access_label_dirty_fact_root FOREIGN KEY(root_type,root_id,generation)
  REFERENCES kaname.authority_access_label_dirty_root(root_type,root_id,generation) ON DELETE CASCADE,
 CONSTRAINT authority_access_label_dirty_fact_type CHECK(object_type<>'' AND object_type NOT LIKE '%.%'),
 CONSTRAINT authority_access_label_dirty_fact_id CHECK(object_id<>''),
 CONSTRAINT authority_access_label_dirty_fact_relation CHECK(relation<>''),
 CONSTRAINT authority_access_label_dirty_fact_subject CHECK(subject<>'')
);
CREATE INDEX authority_access_label_dirty_fact_coordinate ON kaname.authority_access_label_dirty_fact(object_type,object_id,relation,subject);
CREATE FUNCTION kaname.authority_access_label_fact_fresh_v1(p_object_type text,p_object_id text,p_relation text,p_subject text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $freshness_getter$
DECLARE invoker_oid oid;
BEGIN
 -- SECURITY DEFINER меняет current_user, но сохраняет role/session_user.
 -- SET ROLE должен проверяться от effective invoker, а не от LOGIN владельца.
 SELECT r.oid INTO STRICT invoker_oid FROM pg_catalog.pg_roles r
 WHERE r.rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF NOT has_table_privilege(invoker_oid,'kaname.relation_fact'::regclass,'SELECT')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c
           WHERE c.oid='kaname.relation_fact'::regclass AND c.relrowsecurity) THEN
  RAISE EXCEPTION 'access label freshness requires relation fact reader' USING ERRCODE='42501';
 END IF;
 IF p_object_type IS NULL OR p_object_type='' OR p_object_type LIKE '%.%'
 OR p_object_id IS NULL OR p_object_id='' OR p_relation IS NULL OR p_relation=''
 OR p_subject IS NULL OR p_subject='' THEN RETURN false;END IF;
 -- STABLE: тот же снимок, что и relation_fact в вызывающем SQL statement.
 RETURN NOT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact f
  WHERE f.object_type=p_object_type AND f.object_id=p_object_id
    AND f.relation=p_relation AND f.subject=p_subject);
END
$freshness_getter$;
CREATE FUNCTION kaname._authority_access_label_freshness_storage_v1() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $freshness_storage$
DECLARE owner_oid oid; item record;
BEGIN
 SELECT c.relowner INTO STRICT owner_oid FROM pg_catalog.pg_class c
 WHERE c.oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname=current_user) THEN RETURN false;END IF;
 FOR item IN SELECT * FROM (VALUES
 ('authority_access_label_dirty_root',ARRAY['root_type','root_id','generation','new_labels']::text[],
  ARRAY['text','text','uuid','jsonb']::text[],5,2),
 ('authority_access_label_dirty_fact',ARRAY['root_type','root_id','generation','object_type','object_id','relation','subject']::text[],
  ARRAY['text','text','uuid','text','text','text','text']::text[],6,2)
 ) e(name,names,types,constraints,indexes) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=to_regclass('kaname.'||item.name)
   AND c.relowner=owner_oid AND c.relkind='r' AND c.relpersistence='p'
   AND NOT(c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relispartition)
   AND c.reloptions IS NULL
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute v CROSS JOIN LATERAL pg_catalog.aclexplode(v.attacl) a
                  WHERE v.attrelid=c.oid AND a.grantee<>owner_oid)
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_attribute v WHERE v.attrelid=c.oid AND v.attnum>0
                  AND (v.attisdropped OR NOT v.attnotnull OR v.atthasdef OR v.attidentity<>'' OR v.attgenerated<>''))
   AND (SELECT array_agg(v.attname::text ORDER BY v.attnum) FROM pg_catalog.pg_attribute v WHERE v.attrelid=c.oid AND v.attnum>0)=item.names
   AND (SELECT array_agg(v.atttypid::regtype::text ORDER BY v.attnum) FROM pg_catalog.pg_attribute v WHERE v.attrelid=c.oid AND v.attnum>0)=item.types
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=c.oid AND NOT t.tgisinternal)
   AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
   AND (SELECT count(*) FROM pg_catalog.pg_constraint q WHERE q.conrelid=c.oid)=item.constraints
   AND (SELECT count(*) FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid)=item.indexes
  ) THEN RETURN false;END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_access_label_dirty_root','authority_access_label_dirty_root_pkey','p',ARRAY[1,2]::smallint[]),
  ('authority_access_label_dirty_root','authority_access_label_dirty_root_generation','u',ARRAY[1,2,3]::smallint[]),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_pkey','p',ARRAY[1,2,4,5,6,7]::smallint[]),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_root','f',ARRAY[1,2,3]::smallint[])
 ) e(tbl,name,kind,keys) LEFT JOIN pg_catalog.pg_constraint c
 ON c.conrelid=to_regclass('kaname.'||e.tbl) AND c.conname=e.name
 WHERE c.oid IS NULL OR c.contype::text<>e.kind OR c.conkey<>e.keys
 OR NOT c.convalidated OR c.condeferrable OR c.condeferred
 OR (e.kind='f' AND (c.confrelid<>'kaname.authority_access_label_dirty_root'::regclass
  OR c.confkey<>ARRAY[1,2,3]::smallint[] OR c.confupdtype<>'a' OR c.confdeltype<>'c' OR c.confmatchtype<>'s'))
 ) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_access_label_dirty_root','authority_access_label_dirty_root_type',
   'root_type=ANYARRAY[''iam.account''::text,''iam.project''::text]'),
  ('authority_access_label_dirty_root','authority_access_label_dirty_root_id','root_id<>''''::text'),
  ('authority_access_label_dirty_root','authority_access_label_dirty_root_labels','kaname.access_labels_valid_v1new_labels'),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_type','object_type<>''''::textANDobject_type!~~''%.%''::text'),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_id','object_id<>''''::text'),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_relation','relation<>''''::text'),
  ('authority_access_label_dirty_fact','authority_access_label_dirty_fact_subject','subject<>''''::text')
 ) e(tbl,name,expression) LEFT JOIN pg_catalog.pg_constraint c
 ON c.conrelid=to_regclass('kaname.'||e.tbl) AND c.conname=e.name
 WHERE c.oid IS NULL OR c.contype<>'c' OR NOT c.convalidated OR c.connoinherit
 OR regexp_replace(pg_catalog.pg_get_expr(c.conbin,c.conrelid),'[[:space:]()]','','g')<>e.expression
 ) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (VALUES
  ('authority_access_label_dirty_root_pkey','authority_access_label_dirty_root','1 2',true,true),
  ('authority_access_label_dirty_root_generation','authority_access_label_dirty_root','1 2 3',true,false),
  ('authority_access_label_dirty_fact_pkey','authority_access_label_dirty_fact','1 2 4 5 6 7',true,true),
  ('authority_access_label_dirty_fact_coordinate','authority_access_label_dirty_fact','4 5 6 7',false,false)
 ) e(name,tbl,keys,uniq,pk) LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=to_regclass('kaname.'||e.name)
 LEFT JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
 WHERE i.indexrelid IS NULL OR i.indrelid<>to_regclass('kaname.'||e.tbl) OR i.indkey::text<>e.keys
 OR i.indisunique<>e.uniq OR i.indisprimary<>e.pk OR NOT(i.indisvalid AND i.indisready AND i.indislive)
 OR i.indpred IS NOT NULL OR i.indexprs IS NOT NULL OR i.indnkeyatts<>i.indnatts
 OR c.relam<>(SELECT oid FROM pg_catalog.pg_am WHERE amname='btree')
 ) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname.authority_access_label_fact_fresh_v1(text,text,text,text)')
  AND p.proowner=owner_oid AND p.prosecdef AND p.provolatile='s'
  AND p.prokind='f' AND p.prorettype='boolean'::regtype AND NOT(p.proretset OR p.proisstrict OR p.proleakproof)
  AND p.proparallel='u' AND p.pronargs=4 AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.proargnames=ARRAY['p_object_type','p_object_id','p_relation','p_subject']::text[]
  AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='e4c33360da2487a704be03f777a47346cca2cf1b8f10ba067da7da71109d1ea1'
  AND EXISTS(SELECT 1 FROM pg_catalog.aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable)
  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(p.proacl) a WHERE a.grantee<>owner_oid AND (a.grantee<>0 OR a.is_grantable))
 ) THEN RETURN false;END IF;
 RETURN true;
END
$freshness_storage$;
DO $freshness_acl$
DECLARE obj record; recipient record;
BEGIN
 -- Снимаем также наследованные default ACL ещё до открытия getter.
 FOR obj IN SELECT c.oid,c.relowner AS owner,format('%I.%I',n.nspname,c.relname) AS name
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='kaname' AND c.relname IN ('authority_access_label_dirty_root','authority_access_label_dirty_fact') LOOP
  EXECUTE format('REVOKE ALL ON TABLE %s FROM PUBLIC',obj.name);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_class c
   CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE c.oid=obj.oid AND a.grantee<>obj.owner LOOP
   EXECUTE format('REVOKE ALL ON TABLE %s FROM %I',obj.name,recipient.rolname);
  END LOOP;
 END LOOP;
 FOR obj IN SELECT p.oid,p.proowner AS owner,p.oid::regprocedure AS name FROM pg_catalog.pg_proc p
 WHERE p.oid IN ('kaname.authority_access_label_fact_fresh_v1(text,text,text,text)'::regprocedure,'kaname._authority_access_label_freshness_storage_v1()'::regprocedure) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',obj.name);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=obj.oid AND a.grantee<>obj.owner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',obj.name,recipient.rolname);
  END LOOP;
 END LOOP;
END $freshness_acl$;
GRANT EXECUTE ON FUNCTION kaname.authority_access_label_fact_fresh_v1(text,text,text,text) TO PUBLIC;
DO $freshness_pins$
DECLARE item record; fn oid; old_body text; new_body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('_authority_protocol_grant_runtime_generation1(regrole)','5a695632e42c5a4f2f2c343cf27e33404e8e826146d809e6606752f5a5f406a1','6769af21b1bf8c88844728c159f849ca77f86a65283c467c604918c22c9eacdd',$patch$[[" EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);", " EXECUTE format('REVOKE ALL ON TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact FROM %I',runtime_name);\n EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);"]]$patch$::jsonb),
 ('_authority_full_contract_storage_v3()','0718dba1cc1f92155447f774059249071089344ac852e0b5842551413e3dc26e','d58e745e786b96c831e081db8cb9af270e10028f4b64cecf373d5611a31fbadb',$patch$[[" RETURN kaname._authority_crud_storage_v3();", " IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_access_label_freshness_storage_v1()')\n  AND p.proowner=owner_oid AND p.prosecdef AND p.provolatile='s' AND p.prokind='f'\n  AND p.prorettype='boolean'::regtype AND NOT(p.proretset OR p.proisstrict OR p.proleakproof)\n  AND p.proparallel='u' AND p.pronargs=0 AND p.pronargdefaults=0 AND p.provariadic=0\n  AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL\n  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='698216e4db290dfaea7145f875e9d83c06322627d8b2a5ce44621731579ad2b4'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid)\n ) OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_protocol_grant_runtime_generation1(regrole)'::regprocedure\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='v'\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='6769af21b1bf8c88844728c159f849ca77f86a65283c467c604918c22c9eacdd'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid)\n ) THEN RETURN false;END IF;\n RETURN kaname._authority_access_label_freshness_storage_v1() AND kaname._authority_crud_storage_v3();"]]$patch$::jsonb)
 ) e(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex')<>item.before_sha THEN
   RAISE EXCEPTION 'freshness prerequisite body differs: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   IF (length(new_body)-length(replace(new_body,pair->>0,'')))/length(pair->>0)<>1 THEN
    RAISE EXCEPTION 'freshness source anchor differs: %',item.signature USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex')<>item.after_sha THEN
   RAISE EXCEPTION 'freshness replacement digest differs' USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF (length(definition)-length(replace(definition,old_body,'')))/length(old_body)<>1 THEN
   RAISE EXCEPTION 'freshness function definition ambiguous' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)<>item.after_sha THEN
   RAISE EXCEPTION 'freshness installed digest differs' USING ERRCODE='55000';END IF;
 END LOOP;
END $freshness_pins$;
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'access label freshness authority closure incomplete' USING ERRCODE='55000';END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'access label freshness authority closure incomplete' USING ERRCODE='55000';END IF;
END $$;
-- Не допускаем окна между проверкой pending и удалением таблиц.
LOCK TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_root)
 OR EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact) THEN
  RAISE EXCEPTION 'pending access label freshness cannot be rolled back' USING ERRCODE='55000';END IF;
END $$;
DO $freshness_pins$
DECLARE item record; fn oid; old_body text; new_body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
 ('_authority_full_contract_storage_v3()','d58e745e786b96c831e081db8cb9af270e10028f4b64cecf373d5611a31fbadb','0718dba1cc1f92155447f774059249071089344ac852e0b5842551413e3dc26e',$patch$[[" IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_access_label_freshness_storage_v1()')\n  AND p.proowner=owner_oid AND p.prosecdef AND p.provolatile='s' AND p.prokind='f'\n  AND p.prorettype='boolean'::regtype AND NOT(p.proretset OR p.proisstrict OR p.proleakproof)\n  AND p.proparallel='u' AND p.pronargs=0 AND p.pronargdefaults=0 AND p.provariadic=0\n  AND p.proargnames IS NULL AND p.proargmodes IS NULL AND p.proallargtypes IS NULL\n  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='698216e4db290dfaea7145f875e9d83c06322627d8b2a5ce44621731579ad2b4'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid)\n ) OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_protocol_grant_runtime_generation1(regrole)'::regprocedure\n  AND p.proowner=owner_oid AND NOT p.prosecdef AND p.provolatile='v'\n  AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]\n  AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')='6769af21b1bf8c88844728c159f849ca77f86a65283c467c604918c22c9eacdd'\n  AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE a.grantee<>owner_oid)\n ) THEN RETURN false;END IF;\n RETURN kaname._authority_access_label_freshness_storage_v1() AND kaname._authority_crud_storage_v3();", " RETURN kaname._authority_crud_storage_v3();"]]$patch$::jsonb),
 ('_authority_protocol_grant_runtime_generation1(regrole)','6769af21b1bf8c88844728c159f849ca77f86a65283c467c604918c22c9eacdd','5a695632e42c5a4f2f2c343cf27e33404e8e826146d809e6606752f5a5f406a1',$patch$[[" EXECUTE format('REVOKE ALL ON TABLE kaname.authority_access_label_dirty_root,kaname.authority_access_label_dirty_fact FROM %I',runtime_name);\n EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);", " EXECUTE format('GRANT SELECT ON TABLE kaname.authority_semantic_identity TO %I',runtime_name);"]]$patch$::jsonb)
 ) e(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT old_body FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(old_body,'UTF8')),'hex')<>item.before_sha THEN
   RAISE EXCEPTION 'freshness prerequisite body differs: %',item.signature USING ERRCODE='55000';END IF;
  new_body:=old_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   IF (length(new_body)-length(replace(new_body,pair->>0,'')))/length(pair->>0)<>1 THEN
    RAISE EXCEPTION 'freshness source anchor differs: %',item.signature USING ERRCODE='55000';END IF;
   new_body:=replace(new_body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(new_body,'UTF8')),'hex')<>item.after_sha THEN
   RAISE EXCEPTION 'freshness replacement digest differs' USING ERRCODE='55000';END IF;
  definition:=pg_get_functiondef(fn);
  IF (length(definition)-length(replace(definition,old_body,'')))/length(old_body)<>1 THEN
   RAISE EXCEPTION 'freshness function definition ambiguous' USING ERRCODE='55000';END IF;
  EXECUTE replace(definition,old_body,new_body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)<>item.after_sha THEN
   RAISE EXCEPTION 'freshness installed digest differs' USING ERRCODE='55000';END IF;
 END LOOP;
END $freshness_pins$;
DROP FUNCTION kaname._authority_access_label_freshness_storage_v1();
DROP FUNCTION kaname.authority_access_label_fact_fresh_v1(text,text,text,text);
DROP TABLE kaname.authority_access_label_dirty_fact;
DROP TABLE kaname.authority_access_label_dirty_root;
DO $$ BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'access label freshness authority closure incomplete' USING ERRCODE='55000';END IF;
END $$;
-- +goose StatementEnd
