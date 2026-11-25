-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Фасад внешней записи и проверка допуска клиента. Внутренний фасад
-- сохраняет закрытый ACL, от которого зависит готовность локальных писателей.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_apply_v1(p_dotted text,p_id text)
RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $apply$
 SELECT kaname.authority_metadata_mirror_write_v1(p_dotted,p_id)
$apply$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_metadata_mirror_update_ready_v1(p_client_abi text)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $ready$
DECLARE
 owner_oid oid:=current_user::regrole::oid;
 runtime_oid oid:=session_user::regrole::oid;
 operations_relation regclass:=to_regclass('kaname.operations');
 entry record; fn regprocedure; source_table text;
BEGIN
 IF p_client_abi IS DISTINCT FROM 'resource-metadata-update/v1'
  OR current_setting('role') NOT IN ('none',session_user::text)
  OR NOT EXISTS(SELECT FROM pg_catalog.pg_roles r WHERE r.oid=runtime_oid AND r.rolcanlogin
                 AND NOT (r.rolsuper OR r.rolbypassrls))
  OR kaname.authority_metadata_access_label_ready_v2('metadata-access-label/owner-retention-v2') IS DISTINCT FROM true
 THEN RETURN false;END IF;

 -- Полная запись проверяет возможность взять блокировку operations
 -- и сохранить терминальный результат тем же LOGIN, что пишет зеркало.
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_class c WHERE c.oid=operations_relation
  AND c.relkind='r' AND c.relpersistence='p'
  AND NOT(c.relrowsecurity OR c.relforcerowsecurity OR c.relhasrules OR c.relhassubclass OR c.relispartition))
  OR NOT has_table_privilege(runtime_oid,operations_relation,'SELECT')
  OR NOT has_table_privilege(runtime_oid,operations_relation,'INSERT')
  OR NOT has_table_privilege(runtime_oid,operations_relation,'UPDATE')
  OR NOT has_column_privilege(runtime_oid,'kaname.resource_mirror','labels','UPDATE')
  OR NOT has_column_privilege(runtime_oid,'kaname.resource_mirror','access_labels','UPDATE')
  OR NOT has_table_privilege(runtime_oid,'kaname.audit_outbox','INSERT')
  OR NOT has_table_privilege(runtime_oid,'kaname.resource_reconcile_outbox','INSERT')
  OR NOT has_function_privilege(runtime_oid,'kaname.authority_policy_epoch_read(text[])','EXECUTE')
  OR NOT has_function_privilege(runtime_oid,'kaname.authority_binding_epoch_read(text[])','EXECUTE')
 THEN RETURN false;END IF;

 -- Идентичность внешнего объекта читается в RR от имени сервиса.
 FOREACH source_table IN ARRAY ARRAY[
  'resource_mirror','catalog_resource','catalog_verb','accounts','projects','object_project_binding',
  'producer_source_receipt','public_read_publication','relation_fact','resource_parent_edge',
  'resource_registration_pointer','resource_registration_retirement','resource_registration_scope',
  'users','service_accounts'
 ] LOOP
  IF NOT coalesce(has_table_privilege(runtime_oid,to_regclass('kaname.'||source_table),'SELECT'),false)
  THEN RETURN false;END IF;
 END LOOP;

 FOR entry IN SELECT * FROM (VALUES
  ('authority_metadata_mirror_ordinary_identity_v1(text,text)','438b1f5b2c18e1ee14595ba2748cdd6b354cc86b8689579a3612a6db2331778e',false,'s','sql','jsonb',true),
  ('authority_metadata_mirror_ordinary_discover_v1(text,text,integer,integer)','d781ab3c4a458e8372b1e9b2da20839c2ac819f7132b3aaafd526e712e62e317',false,'v','plpgsql','jsonb',true),
  ('authority_metadata_mirror_ordinary_preflight_v1(text,text,jsonb,jsonb,text,text,text,integer,integer,integer)','adef1db014842ae1bbeb10f5cea328848c5b78e50736a9b2f36b2e76af1f1fc4',true,'v','plpgsql','jsonb',true),
  ('authority_metadata_mirror_ordinary_accept_v1(text,text)','505a89d1cbd2b901d4e795a493233b5b8d2c84a9efff5504ed895c447b993e33',true,'v','plpgsql','void',true),
  ('authority_metadata_mirror_apply_v1(text,text)','cb2691ba2ab143446991753d836ffceeed021851c0cca47767eda7301a4edc14',true,'v','sql','jsonb',true),
  ('authority_metadata_mirror_update_ready_v1(text)',NULL,true,'s','plpgsql','boolean',true),
  ('_authority_metadata_mirror_ordinary_complete_v1()','afaa7ee678a18235c86b0c1e363d5fc69dd26c179867fb650e6c9a37f80f4f88',false,'v','plpgsql','void',false),
  ('_authority_metadata_mirror_ordinary_write_v1(text,text)','33b138ea0156788ad343d1aa73061cbf390bc3ea8b542878bc86b04100ba988c',false,'v','plpgsql','jsonb',false),
  ('_authority_metadata_mirror_ordinary_command_v1()','e1fc6d44aa691e22291ce90c09b739465c863e04e644b50f9367ae20e88b2088',false,'v','plpgsql','jsonb',false),
  ('_authority_metadata_mirror_ordinary_root_v1(text,text,jsonb,jsonb,integer,integer,integer)','ff14596e44ce2b5e14045d3a5785de0685fa6bedea193234471fe5cfa4f194d4',false,'v','plpgsql','jsonb',false)
 ) AS x(signature,digest,definer,volatility,language,result_type,exported) LOOP
  fn:=to_regprocedure('kaname.'||entry.signature);
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang
   WHERE p.oid=fn AND p.proowner=owner_oid AND p.prosecdef=entry.definer
    AND p.prokind='f' AND p.provolatile::text=entry.volatility AND l.lanname=entry.language
    AND p.prorettype=to_regtype(entry.result_type) AND p.proparallel='u'
    AND NOT(p.proretset OR p.proisstrict OR p.proleakproof) AND p.pronargdefaults=0 AND p.provariadic=0
    AND p.proargmodes IS NULL AND p.proallargtypes IS NULL
    AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[]
    AND (entry.digest IS NULL OR encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=entry.digest)
    AND (NOT entry.exported OR EXISTS(SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=runtime_oid
     AND a.privilege_type='EXECUTE' AND NOT a.is_grantable))
    AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
     WHERE a.grantee<>owner_oid AND (NOT entry.exported OR a.privilege_type<>'EXECUTE' OR a.is_grantable
      OR kaname._authority_metadata_access_label_runtime_cohort_v2(a.grantee) IS DISTINCT FROM true)))
  THEN RETURN false;END IF;
 END LOOP;

 RETURN true;
END;
$ready$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $seal$
DECLARE fn regprocedure; recipient record;
BEGIN
 FOREACH fn IN ARRAY ARRAY[
  'kaname.authority_metadata_mirror_apply_v1(text,text)'::regprocedure,
  'kaname.authority_metadata_mirror_update_ready_v1(text)'::regprocedure
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=fn AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$seal$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

DROP FUNCTION kaname.authority_metadata_mirror_update_ready_v1(text);
DROP FUNCTION kaname.authority_metadata_mirror_apply_v1(text,text);
