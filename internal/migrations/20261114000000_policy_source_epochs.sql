-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- +goose Up
-- САНКЦИЯ: docs/engineering/acceptance/role-rights-stay-within-what-is-named.md,
-- редакция 4, ESC-32 (накат сохраняет ограничения); SHA-256
-- 3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.
-- Запись: docs/specs/reviews/role-rights-stay-within-what-is-named/3131d7ddfffa9b66857b94c70138b6ebfe7bdb77c7ca07f5333db88aefaae690.yaml;
-- событие: https://github.com/PRO-Robotech/kaname/issues/1034#issuecomment-6416087321.
-- Основание сохраняющего ограничения rollout; полное семантическое одобрение
-- новой grant-authority спецификации и включение public gates остаются отдельными.
-- Это защита discovery от phantom/ABA, а не доказательство authority.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
CREATE TABLE kaname.authority_policy_epoch (
 key text PRIMARY KEY,
 revision bigint NOT NULL DEFAULT 0 CHECK (revision>=0),
 generation text NOT NULL DEFAULT pg_catalog.pg_current_xact_id()::text
);
-- Очередь только metadata: полный TX set собирается до deferred flush.
CREATE TABLE kaname.authority_policy_carrier_pending (
 transaction_id xid8 NOT NULL,
 backend_pid integer NOT NULL,
 role_id text NOT NULL,
 PRIMARY KEY(transaction_id,backend_pid,role_id)
);
REVOKE ALL ON kaname.authority_policy_epoch,kaname.authority_policy_carrier_pending FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT DISTINCT u.rolname,c.relname FROM pg_catalog.pg_class c
 CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE c.oid IN ('kaname.authority_policy_epoch'::pg_catalog.regclass,'kaname.authority_policy_carrier_pending'::pg_catalog.regclass) AND a.grantee<>c.relowner LOOP
  EXECUTE pg_catalog.format('REVOKE ALL ON kaname.%I FROM %I',r.relname,r.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
INSERT INTO kaname.authority_policy_epoch(key)
 SELECT '*' UNION SELECT 'user:'||id FROM kaname.users UNION SELECT 'service_account:'||id FROM kaname.service_accounts
 UNION SELECT 'group:'||id FROM kaname.groups UNION SELECT 'role:'||id FROM kaname.roles
 UNION SELECT 'scope:'||id FROM kaname.accounts UNION SELECT 'carriers:role:'||id FROM kaname.roles
 UNION SELECT 'carrier_latch:role:'||id FROM kaname.roles;
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_object_account(p_type text,p_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a text;
BEGIN
 CASE p_type
 WHEN 'account' THEN SELECT id INTO a FROM kaname.accounts WHERE id=p_id;
 WHEN 'project' THEN SELECT account_id INTO a FROM kaname.projects WHERE id=p_id;
 WHEN 'group','iam_group' THEN SELECT account_id INTO a FROM kaname.groups WHERE id=p_id;
 WHEN 'service_account','iam_service_account' THEN SELECT account_id INTO a FROM kaname.service_accounts WHERE id=p_id;
 WHEN 'iam_role' THEN SELECT coalesce(r.account_id,p.account_id) INTO a FROM kaname.roles r LEFT JOIN kaname.projects p ON p.id=r.project_id WHERE r.id=p_id;
 WHEN 'iam_access_binding' THEN SELECT kaname.authority_protocol_row_account('access_bindings',to_jsonb(b)) INTO a FROM kaname.access_bindings b WHERE b.id=p_id;
 ELSE SELECT coalesce(nullif(m.parent_account_id,''),p.account_id) INTO a FROM kaname.resource_mirror m JOIN kaname.catalog_resource c ON c.dotted=m.object_type LEFT JOIN kaname.projects p ON p.id=m.parent_project_id WHERE c.object_type=p_type AND m.object_id=p_id;
 END CASE;
 RETURN nullif(a,'');
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_keys(p_table text,p_row jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys text[]:=ARRAY[]::text[]; carrier jsonb; k text;
BEGIN
 CASE p_table
 WHEN 'users' THEN keys:=ARRAY['user:'||(p_row->>'id')];
 WHEN 'groups' THEN keys:=ARRAY['group:'||(p_row->>'id')];
 WHEN 'roles' THEN keys:=ARRAY['role:'||(p_row->>'id'),'carriers:role:'||(p_row->>'id'),'carrier_latch:role:'||(p_row->>'id')];
 WHEN 'accounts' THEN keys:=ARRAY['user:'||(p_row->>'owner_user_id'),'scope:'||(p_row->>'id')];
 WHEN 'grant_delegations' THEN keys:=ARRAY['service_account:'||(p_row->>'delegate_id'),'scope:'||(p_row->>'account_id'),(p_row->>'delegated_by_type')||':'||(p_row->>'delegated_by_id')];
 WHEN 'memberships' THEN keys:=ARRAY['user:'||(p_row->>'user_id')];
 WHEN 'service_accounts' THEN
  keys:=ARRAY['service_account:'||(p_row->>'id')];
  IF nullif(p_row->>'created_by_id','') IS NOT NULL THEN keys:=keys||((p_row->>'created_by_type')||':'||(p_row->>'created_by_id')); END IF;
 WHEN 'group_members' THEN keys:=ARRAY['group:'||(p_row->>'group_id'),(p_row->>'member_type')||':'||(p_row->>'member_id')];
 WHEN 'cluster_admin_grants' THEN keys:=ARRAY[(p_row->>'subject_type')||':'||(p_row->>'subject_id')];
 WHEN 'access_binding_subjects' THEN
  IF p_row->>'subject_id'='*' OR p_row->>'subject_type'='system_class' THEN keys:=ARRAY['*'];
  ELSE keys:=ARRAY[(p_row->>'subject_type')||':'||(p_row->>'subject_id')]; END IF;
  SELECT pg_catalog.to_jsonb(b) INTO carrier FROM kaname.access_bindings b WHERE b.id=p_row->>'binding_id';
  IF carrier IS NOT NULL THEN keys:=keys||kaname.authority_policy_keys('access_bindings',carrier); END IF;
 WHEN 'access_bindings' THEN
  IF p_row->>'subject_id'='*' OR p_row->>'subject_type'='system_class' THEN keys:=ARRAY['*'];
  ELSE keys:=ARRAY[(p_row->>'subject_type')||':'||(p_row->>'subject_id')]; END IF;
  IF p_row->>'role_id' IS NOT NULL THEN keys:=keys||('carrier_latch:role:'||(p_row->>'role_id')); END IF;
  -- Полная secondary population ограничена отдельным DB constraint; при
  -- превышении guard budget не усекать invalidation, использовать root.
  FOR k IN SELECT s.subject_type||':'||s.subject_id FROM kaname.access_binding_subjects s WHERE s.binding_id=p_row->>'id' LIMIT 4097 LOOP
   keys:=keys||k;
   IF pg_catalog.cardinality(keys)>4096 THEN RETURN ARRAY['*']; END IF;
  END LOOP;
 WHEN 'producer_source_receipt','public_read_publication','resource_registration_scope','resource_registration_retirement' THEN keys:=ARRAY['*'];
 WHEN 'resource_mirror' THEN
  IF EXISTS(SELECT 1 FROM kaname.producer_source_receipt r WHERE r.catalog_type=p_row->>'object_type' AND r.object_id=p_row->>'object_id') THEN keys:=ARRAY['*'];
  ELSE
   k:=nullif(p_row->>'parent_account_id','');
   IF k IS NULL THEN SELECT account_id INTO k FROM kaname.projects WHERE id=p_row->>'parent_project_id'; END IF;
   IF k IS NULL THEN keys:=ARRAY['*']; ELSE keys:=ARRAY['scope:'||k]; END IF;
  END IF;
 WHEN 'relation_fact' THEN
  k:=p_row->>'subject';
  IF k ~ '^(user|service_account):[^#*]+$' THEN keys:=ARRAY[k];
  ELSIF k ~ '^(group|iam_group):[^#*]+#member$' THEN keys:=ARRAY['group:'||split_part(split_part(k,':',2),'#',1)];
  ELSIF k !~ '^(account|project|cluster):[^#*]+$' THEN keys:=ARRAY['*']; END IF;
  -- Иерархическое ребро защищается областью ОБЪЕКТА, не областью subject.
  k:=kaname.authority_policy_object_account(p_row->>'object_type',p_row->>'object_id');
  IF k IS NOT NULL THEN keys:=keys||('scope:'||k);
  ELSIF p_row->>'object_type'='iam_user' THEN keys:=keys||('user:'||(p_row->>'object_id'));
  ELSE keys:=pg_catalog.array_append(keys,'*'); END IF;
 WHEN 'resource_parent_edge' THEN
  k:=kaname.authority_policy_object_account(p_row->>'object_type',p_row->>'object_id');
  IF k IS NULL THEN keys:=ARRAY['*']; ELSE keys:=ARRAY['scope:'||k]; END IF;
 WHEN 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule' THEN keys:=ARRAY['role:'||(p_row->>'role_id')];
 WHEN 'catalog_module','catalog_resource','catalog_verb' THEN keys:=ARRAY['*'];
 WHEN 'projects' THEN keys:=ARRAY['scope:'||(p_row->>'account_id')];
 ELSE RAISE EXCEPTION 'unclassified policy source table %',p_table;
 END CASE;
 IF EXISTS(SELECT 1 FROM pg_catalog.unnest(keys) AS u(value) WHERE u.value IS NULL OR u.value='' OR u.value LIKE '%:') THEN RETURN ARRAY['*']; END IF;
 RETURN keys;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_changed() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE keys text[]; k text; moved boolean:=false;
BEGIN
 IF TG_OP='UPDATE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (
   SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o
   UNION SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) FROM new_policy_rows n) q;
  -- Смена родителя меняет ownership уже известного источника. Это редкая
  -- неоднозначная структурная мутация, заранее требующая GLOBAL writer.
  IF TG_TABLE_NAME IN ('projects','roles') THEN
   SELECT EXISTS(SELECT 1 FROM old_policy_rows o JOIN new_policy_rows n ON to_jsonb(o)->>'id'=to_jsonb(n)->>'id'
    WHERE (to_jsonb(o)->'account_id',to_jsonb(o)->'project_id',to_jsonb(o)->'is_system') IS DISTINCT FROM
          (to_jsonb(n)->'account_id',to_jsonb(n)->'project_id',to_jsonb(n)->'is_system')) INTO moved;
  END IF;
 ELSIF TG_OP='INSERT' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(n))) k FROM new_policy_rows n) q;
 ELSIF TG_OP='DELETE' THEN
  SELECT pg_catalog.array_agg(DISTINCT q.k COLLATE "C" ORDER BY q.k COLLATE "C") INTO keys FROM (SELECT unnest(kaname.authority_policy_keys(TG_TABLE_NAME,to_jsonb(o))) k FROM old_policy_rows o) q;
  IF TG_TABLE_NAME='projects' THEN moved:=true; END IF;
 ELSE moved:=true;
 END IF;
 IF moved OR pg_catalog.cardinality(keys)>4096 THEN keys:=ARRAY['*']; END IF;
 IF keys IS NULL THEN RETURN NULL; END IF;
 -- Порядок root -> typed keys совпадает с protect. Root не меняется от
 -- обычных account/actor writes; его shared locks совместимы друг с другом.
 IF '*'=ANY(keys) THEN UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='*';
 ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE; END IF;
 FOR k IN SELECT DISTINCT x COLLATE "C" FROM pg_catalog.unnest(keys) x WHERE x<>'*' ORDER BY 1 LOOP
  IF TG_TABLE_NAME IN ('access_bindings','access_binding_subjects') AND k LIKE 'carrier_latch:role:%' THEN
   -- Binding держит только SHARE latch. Revision не блокируется во время apply.
   PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR SHARE;
   IF NOT FOUND THEN RAISE EXCEPTION 'carrier latch missing' USING ERRCODE='40001'; END IF;
   INSERT INTO kaname.authority_policy_carrier_pending(transaction_id,backend_pid,role_id)
    VALUES(pg_current_xact_id(),pg_backend_pid(),substr(k,length('carrier_latch:role:')+1)) ON CONFLICT DO NOTHING;
  ELSE
   INSERT INTO kaname.authority_policy_epoch(key,revision) VALUES(k,1)
   ON CONFLICT(key) DO UPDATE SET revision=kaname.authority_policy_epoch.revision+1;
  END IF;
 END LOOP;
 -- Epoch rows никогда не удаляются вместе с источником: delete/recreate
 -- сохраняет монотонное поколение, а переустановка миграции меняет generation.
 RETURN NULL;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_carrier_flush() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE roles text[]; r text;
BEGIN
 -- Первый callback видит весь metadata set TX, независимо от порядка OLD/NEW
 -- business rows. Следующие callbacks видят пустой set. Inventory не читается.
 SELECT array_agg(role_id ORDER BY role_id COLLATE "C") INTO roles FROM (
  SELECT role_id FROM kaname.authority_policy_carrier_pending
  WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid()
  ORDER BY role_id COLLATE "C" LIMIT 4097) pending;
 IF cardinality(roles)>4096 THEN RAISE EXCEPTION 'carrier revision budget exceeded' USING ERRCODE='54000'; END IF;
 FOREACH r IN ARRAY coalesce(roles,ARRAY[]::text[]) LOOP
  UPDATE kaname.authority_policy_epoch SET revision=revision+1 WHERE key='carriers:role:'||r;
  IF NOT FOUND THEN RAISE EXCEPTION 'carrier revision missing' USING ERRCODE='40001'; END IF;
 END LOOP;
 DELETE FROM kaname.authority_policy_carrier_pending WHERE transaction_id=pg_current_xact_id() AND backend_pid=pg_backend_pid();
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER policy_carrier_flush AFTER INSERT ON kaname.authority_policy_carrier_pending
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.authority_policy_carrier_flush();
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_epoch_read(p_keys text[]) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb; n integer;
BEGIN
 IF p_keys IS NULL OR cardinality(p_keys)<1 OR cardinality(p_keys)>4096 OR NOT ('*'=ANY(p_keys))
 OR EXISTS(SELECT 1 FROM unnest(p_keys) k WHERE k IS NULL OR k='') THEN RAISE EXCEPTION 'invalid policy guards' USING ERRCODE='22023'; END IF;
 SELECT count(*),jsonb_object_agg(key,jsonb_build_array(generation,revision)) INTO n,result FROM kaname.authority_policy_epoch WHERE key=ANY(p_keys);
 IF n<>(SELECT count(DISTINCT k) FROM unnest(p_keys) k) THEN RAISE EXCEPTION 'policy guard missing' USING ERRCODE='40001'; END IF;
 RETURN result;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_epoch_lock_for_write(p_expected jsonb,p_write text[]) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; keys text[]; k text; at_time timestamptz;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR coalesce(proof->>'purpose','') NOT IN ('decision','participant') THEN RAISE EXCEPTION 'policy entry required' USING ERRCODE='42501'; END IF;
 IF p_expected IS NULL OR jsonb_typeof(p_expected)<>'object' THEN RAISE EXCEPTION 'policy snapshot missing' USING ERRCODE='40001'; END IF;
 SELECT array_agg(x ORDER BY x COLLATE "C") INTO keys FROM jsonb_object_keys(p_expected) x;
 PERFORM kaname.authority_policy_epoch_read(keys);
 IF p_write IS NULL OR cardinality(p_write)>4096 OR NOT p_write<@keys THEN RAISE EXCEPTION 'invalid policy write guards' USING ERRCODE='22023'; END IF;
 -- GLOBAL выбран до entry; нет повышения режима при отсутствии строки.
 IF proof->>'mode'='global' THEN PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR UPDATE;
 ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key='*' FOR SHARE; END IF;
 FOR k IN SELECT x FROM unnest(keys) x WHERE x<>'*' ORDER BY x COLLATE "C" LOOP
  IF k=ANY(p_write) THEN PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR UPDATE;
  ELSE PERFORM key FROM kaname.authority_policy_epoch WHERE key=k FOR SHARE; END IF;
 END LOOP;
 IF kaname.authority_policy_epoch_read(keys) IS DISTINCT FROM p_expected THEN RAISE EXCEPTION 'policy source footprint changed' USING ERRCODE='40001'; END IF;
 at_time:=clock_timestamp();
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 RETURN at_time;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_policy_epoch_lock(p_expected jsonb) RETURNS timestamptz
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname.authority_policy_epoch_lock_for_write(p_expected,ARRAY[]::text[])
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['users','groups','roles','accounts','grant_delegations','memberships','service_accounts','group_members','cluster_admin_grants',
 'access_bindings','access_binding_subjects','producer_source_receipt','public_read_publication','resource_registration_scope',
 'resource_registration_retirement','resource_mirror','projects','relation_fact','resource_parent_edge',
 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','catalog_module','catalog_resource','catalog_verb'] LOOP
  EXECUTE format('CREATE TRIGGER policy_epoch_insert AFTER INSERT ON kaname.%I REFERENCING NEW TABLE AS new_policy_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_policy_changed()',name);
  EXECUTE format('CREATE TRIGGER policy_epoch_update AFTER UPDATE ON kaname.%I REFERENCING OLD TABLE AS old_policy_rows NEW TABLE AS new_policy_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_policy_changed()',name);
  EXECUTE format('CREATE TRIGGER policy_epoch_delete AFTER DELETE ON kaname.%I REFERENCING OLD TABLE AS old_policy_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_policy_changed()',name);
  EXECUTE format('CREATE TRIGGER policy_epoch_truncate AFTER TRUNCATE ON kaname.%I FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_policy_changed()',name);
 END LOOP;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_policy_keys(text,jsonb),kaname.authority_policy_changed(),kaname.authority_policy_carrier_flush() FROM PUBLIC;
-- Default ACL не должен дать runtime прямой вызов mutation helper.
-- +goose StatementBegin
DO $$ DECLARE r record; BEGIN
 FOR r IN SELECT DISTINCT p.oid::regprocedure signature,u.rolname FROM pg_catalog.pg_proc p
 CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE p.oid IN ('kaname.authority_policy_keys(text,jsonb)'::regprocedure,'kaname.authority_policy_changed()'::regprocedure,'kaname.authority_policy_carrier_flush()'::regprocedure) AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',r.signature,r.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION kaname.authority_policy_object_account(text,text) TO PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.authority_policy_epoch_read(text[]),kaname.authority_policy_epoch_lock(jsonb),kaname.authority_policy_epoch_lock_for_write(jsonb,text[]) TO PUBLIC;
-- +goose Down
-- +goose StatementBegin
DO $$ DECLARE name text; BEGIN
 PERFORM kaname.authority_protocol_drain();
 FOREACH name IN ARRAY ARRAY['users','groups','roles','accounts','grant_delegations','memberships','service_accounts','group_members','cluster_admin_grants',
 'access_bindings','access_binding_subjects','producer_source_receipt','public_read_publication','resource_registration_scope',
 'resource_registration_retirement','resource_mirror','projects','relation_fact','resource_parent_edge',
 'role_rule_selectors','role_selector_verbs_pending','role_verb','role_rule_ref','role_create_binding_rule','role_bind_role_rule','catalog_module','catalog_resource','catalog_verb'] LOOP
  EXECUTE format('DROP TRIGGER policy_epoch_insert ON kaname.%I',name);
  EXECUTE format('DROP TRIGGER policy_epoch_update ON kaname.%I',name);
  EXECUTE format('DROP TRIGGER policy_epoch_delete ON kaname.%I',name);
  EXECUTE format('DROP TRIGGER policy_epoch_truncate ON kaname.%I',name);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_policy_epoch_lock(jsonb);
DROP FUNCTION kaname.authority_policy_epoch_lock_for_write(jsonb,text[]);
DROP FUNCTION kaname.authority_policy_epoch_read(text[]);
DROP FUNCTION kaname.authority_policy_changed();
DROP TRIGGER policy_carrier_flush ON kaname.authority_policy_carrier_pending;
DROP FUNCTION kaname.authority_policy_carrier_flush();
DROP TABLE kaname.authority_policy_carrier_pending;
DROP FUNCTION kaname.authority_policy_keys(text,jsonb);
DROP FUNCTION kaname.authority_policy_object_account(text,text);
DROP TABLE kaname.authority_policy_epoch;
