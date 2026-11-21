-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
-- Приёмка: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md
-- kaname#1034: защита полного действия выдачи и сохранение прежних строк при накате (ESC-32).
-- kaname#1034: поколения являются защитой snapshot/recheck, не authority proof.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
CREATE TABLE kaname.authority_binding_epoch (
 scope text PRIMARY KEY,
 revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
 generation text NOT NULL DEFAULT pg_catalog.pg_current_xact_id()::text
);
REVOKE ALL ON kaname.authority_binding_epoch FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT DISTINCT a.grantee,u.rolname FROM pg_catalog.pg_class c
 CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE c.oid='kaname.authority_binding_epoch'::pg_catalog.regclass AND a.grantee<>c.relowner LOOP
  EXECUTE pg_catalog.format('REVOKE ALL ON kaname.authority_binding_epoch FROM %I',r.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
INSERT INTO kaname.authority_binding_epoch(scope) VALUES ('');
INSERT INTO kaname.authority_binding_epoch(scope) SELECT id FROM kaname.accounts;
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_epoch_scope(p_table text,p_row jsonb) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a text; carrier jsonb; role_key text; object_key text;
BEGIN
 -- Новая names/labels/nested выдача может добавить зависимость чужой группы,
 -- которой ещё нет в локальном snapshot. Такие изменения инвалидируют root.
 IF p_table IN ('access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples') THEN
  IF p_table='access_bindings' THEN carrier:=p_row;
  ELSE SELECT pg_catalog.to_jsonb(b) INTO carrier FROM kaname.access_bindings b WHERE b.id=p_row->>'binding_id'; END IF;
  IF carrier IS NULL THEN RETURN ''; END IF;
  role_key:=carrier->>'role_id';
  IF EXISTS(SELECT 1 FROM kaname.role_rule_selectors r WHERE r.role_id=role_key AND (r.arm<>'anchor' OR r.container_type IS NOT NULL)) THEN RETURN ''; END IF;
  IF p_table='access_binding_target_members' AND p_row->>'object_type'='iam.group' THEN object_key:=p_row->>'object_id';
  ELSIF p_table='access_binding_emitted_tuples' AND p_row->>'member_object_type'='iam.group' THEN object_key:=p_row->>'member_object_id';
  ELSIF p_table='access_binding_emitted_tuples' AND p_row->>'object' LIKE 'iam_group:%' THEN object_key:=pg_catalog.substr(p_row->>'object',11); END IF;
  IF object_key IS NOT NULL THEN
   SELECT g.account_id INTO a FROM kaname.groups g WHERE g.id=object_key;
   IF a IS NULL OR a IS DISTINCT FROM kaname.authority_protocol_row_account('access_bindings',carrier) THEN RETURN ''; END IF;
  END IF;
 ELSIF p_table='role_rule_selectors' AND (p_row->>'arm' IS DISTINCT FROM 'anchor' OR p_row->>'container_type' IS NOT NULL) THEN RETURN '';
 END IF;
 IF p_table='resource_mirror' THEN
  a:=nullif(p_row->>'parent_account_id','');
  IF a IS NULL THEN SELECT account_id INTO a FROM kaname.projects WHERE id=p_row->>'parent_project_id'; END IF;
 ELSIF p_table='resource_parent_edge' THEN
  SELECT coalesce(nullif(m.parent_account_id,''),p.account_id) INTO a
   FROM kaname.resource_mirror m JOIN kaname.catalog_resource c ON c.dotted=m.object_type
   LEFT JOIN kaname.projects p ON p.id=m.parent_project_id
   WHERE c.object_type=p_row->>'object_type' AND m.object_id=p_row->>'object_id';
 ELSE a:=kaname.authority_protocol_row_account(p_table,p_row);
 END IF;
 RETURN coalesce(a,'');
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_epoch_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys text[]; k text;
BEGIN
 -- Transition tables принадлежат executor этого statement, не search_path.
 -- По одному bump на distinct OLD+NEW account на statement, не на ledger row.
 IF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT x ORDER BY x) INTO keys FROM (
   SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) x FROM old_epoch_rows o
   UNION SELECT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) FROM new_epoch_rows n) s;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(n))) INTO keys FROM new_epoch_rows n;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o)) ORDER BY kaname.authority_binding_epoch_scope(TG_TABLE_NAME,pg_catalog.to_jsonb(o))) INTO keys FROM old_epoch_rows o;
 ELSE keys:=ARRAY['']::text[];
 END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Глобальная строка shared для account writes: разные accounts не конфликтуют.
 -- Global source change конфликтует с любым apply snapshot.
 IF ''=ANY(keys) THEN
  UPDATE kaname.authority_binding_epoch SET revision=revision+1 WHERE scope='';
 ELSE
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR KEY SHARE;
 END IF;
 FOREACH k IN ARRAY keys LOOP
  IF k<>'' THEN INSERT INTO kaname.authority_binding_epoch(scope,revision) VALUES(k,1)
   ON CONFLICT(scope) DO UPDATE SET revision=kaname.authority_binding_epoch.revision+1; END IF;
 END LOOP;
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_epoch_read(p_accounts text[]) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT (CASE WHEN p_accounts IS NULL THEN
  -- Монотонные nonnegative revisions: любое изменение повышает сумму;
  -- новые строки повышают count. Runtime не может удалять/сбрасывать epochs.
  -- SUM(bigint) — numeric: большие значения не сужаются до float/int64.
  (SELECT pg_catalog.jsonb_build_object('$count',count(*),'$sum',coalesce(sum(revision),0)) FROM kaname.authority_binding_epoch)
 ELSE
  (SELECT coalesce(pg_catalog.jsonb_object_agg(scope,revision),'{}'::jsonb)
   FROM kaname.authority_binding_epoch WHERE scope='' OR scope=ANY(p_accounts))
 END) || (SELECT pg_catalog.jsonb_build_object('$generation',generation,'',revision) FROM kaname.authority_binding_epoch WHERE scope='')
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_binding_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; actual jsonb; at_time timestamptz;
BEGIN
 IF p_expected IS NULL OR pg_catalog.jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'binding epoch snapshot is absent' USING ERRCODE='40001'; END IF;
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL THEN RAISE EXCEPTION 'binding apply requires participant entry' USING ERRCODE='42501'; END IF;
 IF proof->>'purpose' IS DISTINCT FROM 'participant' THEN RAISE EXCEPTION 'binding apply requires ordinary participant' USING ERRCODE='42501'; END IF;
 IF p_accounts IS NULL THEN
  IF proof->>'mode' IS DISTINCT FROM 'global' THEN RAISE EXCEPTION 'binding global epoch requires global entry' USING ERRCODE='42501'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
 ELSE
  IF pg_catalog.cardinality(p_accounts)=0 OR EXISTS(SELECT 1 FROM pg_catalog.unnest(p_accounts) a WHERE a IS NULL OR a='') THEN RAISE EXCEPTION 'invalid binding epoch scope'; END IF;
  IF proof->>'mode'='accounts' AND NOT (proof->'accounts') @> pg_catalog.to_jsonb(p_accounts) THEN RAISE EXCEPTION 'epoch accounts exceed participant scope' USING ERRCODE='42501'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope='' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'binding epochs are uninitialized' USING ERRCODE='40001'; END IF;
  PERFORM scope FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts) ORDER BY scope FOR SHARE;
  IF (SELECT count(*) FROM kaname.authority_binding_epoch WHERE scope=ANY(p_accounts))<>(SELECT count(DISTINCT a) FROM pg_catalog.unnest(p_accounts) a) THEN RAISE EXCEPTION 'binding epoch disappeared' USING ERRCODE='40001'; END IF;
 END IF;
 actual:=kaname.authority_binding_epoch_read(p_accounts);
 IF actual IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'binding stage changed' USING ERRCODE='40001'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE name text;
BEGIN
 -- Замкнутый actual read graph staged reconcile: carrier, authored/projection role,
 -- каталог, собственные объекты, mirror/parents и база diff members/ledger.
 FOREACH name IN ARRAY ARRAY['accounts','projects','roles','groups','users','service_accounts','memberships',
 'access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
 'catalog_module','catalog_resource','catalog_verb','resource_mirror','resource_parent_edge'] LOOP
  EXECUTE pg_catalog.format('CREATE TRIGGER binding_epoch_insert AFTER INSERT ON kaname.%I REFERENCING NEW TABLE AS new_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed()',name);
  EXECUTE pg_catalog.format('CREATE TRIGGER binding_epoch_update AFTER UPDATE ON kaname.%I REFERENCING OLD TABLE AS old_epoch_rows NEW TABLE AS new_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed()',name);
  EXECUTE pg_catalog.format('CREATE TRIGGER binding_epoch_delete AFTER DELETE ON kaname.%I REFERENCING OLD TABLE AS old_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed()',name);
  EXECUTE pg_catalog.format('CREATE TRIGGER binding_epoch_truncate AFTER TRUNCATE ON kaname.%I FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed()',name);
 END LOOP;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_binding_epoch_scope(text,jsonb),kaname.authority_binding_epoch_changed() FROM PUBLIC;
-- read/lock не пишут epochs и не создают attestation; runtime получает лишь эти API.
GRANT EXECUTE ON FUNCTION kaname.authority_binding_epoch_read(text[]),kaname.authority_binding_epoch_lock(text[],jsonb) TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE name text;
BEGIN
 PERFORM kaname.authority_protocol_drain();
 FOREACH name IN ARRAY ARRAY['accounts','projects','roles','groups','users','service_accounts','memberships',
 'access_bindings','access_binding_subjects','access_binding_target_members','access_binding_emitted_tuples',
 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule',
 'catalog_module','catalog_resource','catalog_verb','resource_mirror','resource_parent_edge'] LOOP
  EXECUTE pg_catalog.format('DROP TRIGGER binding_epoch_insert ON kaname.%I',name);
  EXECUTE pg_catalog.format('DROP TRIGGER binding_epoch_update ON kaname.%I',name);
  EXECUTE pg_catalog.format('DROP TRIGGER binding_epoch_delete ON kaname.%I',name);
  EXECUTE pg_catalog.format('DROP TRIGGER binding_epoch_truncate ON kaname.%I',name);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_binding_epoch_lock(text[],jsonb);
DROP FUNCTION kaname.authority_binding_epoch_read(text[]);
DROP FUNCTION kaname.authority_binding_epoch_changed();
DROP FUNCTION kaname.authority_binding_epoch_scope(text,jsonb);
DROP TABLE kaname.authority_binding_epoch;
