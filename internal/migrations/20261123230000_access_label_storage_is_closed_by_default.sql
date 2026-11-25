-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1043: отдельные атрибуты доступа не наследуют право менять обычные labels.
-- На этом шаге принимающего writer нет: непустой INSERT и любая дельта UPDATE
-- запрещены всем, включая owner. Ни GUC, ни фаза протокола не открывают запись.
-- Старые INSERT с пустым значением, UPDATE без дельты и DELETE сохраняются.
-- Down допускается только при целой защите и отсутствии защищённых данных.

-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'access label prior authority closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.access_labels_valid_v1(p_labels jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE entry record;entries integer:=0;
BEGIN
 IF jsonb_typeof(p_labels) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 FOR entry IN SELECT key,value FROM jsonb_each(p_labels) LOOP
  entries:=entries+1;
  IF entries>64 OR octet_length(entry.key) NOT BETWEEN 1 AND 63
  OR entry.key COLLATE "C" !~ '^[a-z][-_./@a-z0-9]{0,62}$'
  OR jsonb_typeof(entry.value) IS DISTINCT FROM 'string'
  OR octet_length(entry.value #>> '{}')>63 THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.access_labels_immutable_v1() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'kaname' OR TG_TABLE_NAME NOT IN
 ('accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror')
 OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP NOT IN ('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'access label guard context invalid' USING ERRCODE='42501';
 END IF;
 IF (TG_OP='INSERT' AND NEW.access_labels IS DISTINCT FROM '{}'::jsonb)
 OR (TG_OP='UPDATE' AND NEW.access_labels IS DISTINCT FROM OLD.access_labels) THEN
  RAISE EXCEPTION 'access label mutation requires a protected writer' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE target text;BEGIN
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  EXECUTE format('ALTER TABLE kaname.%I ADD COLUMN access_labels jsonb NOT NULL DEFAULT ''{}''::jsonb',target);
  EXECUTE format('ALTER TABLE kaname.%I ADD CONSTRAINT access_labels_valid CHECK (kaname.access_labels_valid_v1(access_labels))',target);
  EXECUTE format('CREATE TRIGGER access_labels_immutable BEFORE INSERT OR UPDATE ON kaname.%I FOR EACH ROW EXECUTE FUNCTION kaname.access_labels_immutable_v1()',target);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_access_label_storage_valid_v1() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;target text;relation_id oid;column_number smallint;expected record;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_roles WHERE rolname=current_user) THEN RETURN false;END IF;
 FOR expected IN SELECT * FROM (VALUES
 ('access_labels_valid_v1(jsonb)','5bdcbf012ab0dee0838575bc22c3109d97483e1caf2f5543d810f46be03f9c60',false,'i'),
 ('access_labels_immutable_v1()','ebae429f31cb7558e7c01285fd82e947de6470eb1acc921bab06f46251f62046',false,'v')
 ) p(signature,digest,definer,volatility) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid=to_regprocedure('kaname.'||expected.signature)
   AND p.proowner=owner_oid AND p.prosecdef=expected.definer AND p.provolatile::text=expected.volatility
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=expected.digest
   AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
    WHERE a.grantee<>owner_oid AND NOT (expected.signature='access_labels_valid_v1(jsonb)'
     AND a.grantee=0 AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))) THEN RETURN false;END IF;
 END LOOP;
 -- Проверяем только собственный footprint; чужие штатные триггеры не запрещаем.
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  relation_id:=to_regclass('kaname.'||target);
  IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=relation_id AND relowner=owner_oid AND relkind='r') THEN RETURN false;END IF;
  SELECT a.attnum INTO column_number FROM pg_attribute a JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
   WHERE a.attrelid=relation_id AND a.attname='access_labels' AND NOT a.attisdropped
    AND a.atttypid='jsonb'::regtype AND a.attnotnull AND a.attgenerated=''
    AND pg_get_expr(d.adbin,d.adrelid)='''{}''::jsonb';
  IF column_number IS NULL THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_constraint c WHERE c.conrelid=relation_id AND c.conname='access_labels_valid'
   AND c.contype='c' AND c.convalidated AND NOT c.connoinherit AND c.conkey=ARRAY[column_number]
   AND pg_get_expr(c.conbin,c.conrelid)='kaname.access_labels_valid_v1(access_labels)') THEN RETURN false;END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=relation_id AND t.tgname='access_labels_immutable'
   AND t.tgfoid='kaname.access_labels_immutable_v1()'::regprocedure AND t.tgtype=23
   AND t.tgenabled='O' AND NOT t.tgisinternal AND t.tgnargs=0 AND t.tgqual IS NULL AND t.tgattr=''::int2vector)
  THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text;grantee record;BEGIN
 FOREACH signature IN ARRAY ARRAY['access_labels_valid_v1(jsonb)','access_labels_immutable_v1()','authority_access_label_storage_valid_v1()'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_roles r ON r.oid=a.grantee WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,grantee.rolname);
  END LOOP;
 END LOOP;
 GRANT EXECUTE ON FUNCTION kaname.access_labels_valid_v1(jsonb),kaname.authority_access_label_storage_valid_v1() TO PUBLIC;
 IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'access label installation closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ DECLARE target text;populated boolean;BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF NOT kaname.authority_access_label_storage_valid_v1() OR NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'access label rollback closure incomplete' USING ERRCODE='55000';
 END IF;
 -- Drain удерживает все восемь таблиц до commit, поэтому между проверкой и
 -- DROP никакая запись не может сделать атрибуты непустыми.
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM kaname.%I WHERE access_labels IS DISTINCT FROM ''{}''::jsonb)',target) INTO populated;
  IF populated THEN RAISE EXCEPTION 'access label rollback would remove protected data' USING ERRCODE='55000';END IF;
 END LOOP;
 FOREACH target IN ARRAY ARRAY['accounts','projects','users','service_accounts','groups','roles','access_bindings','resource_mirror'] LOOP
  EXECUTE format('DROP TRIGGER access_labels_immutable ON kaname.%I',target);
  EXECUTE format('ALTER TABLE kaname.%I DROP COLUMN access_labels',target);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_access_label_storage_valid_v1();
DROP FUNCTION kaname.access_labels_immutable_v1();
DROP FUNCTION kaname.access_labels_valid_v1(jsonb);
-- +goose StatementBegin
DO $$ BEGIN IF NOT kaname._authority_full_contract_storage_v3() THEN
 RAISE EXCEPTION 'access label rollback prior authority closure incomplete' USING ERRCODE='55000';END IF;END $$;
-- +goose StatementEnd
