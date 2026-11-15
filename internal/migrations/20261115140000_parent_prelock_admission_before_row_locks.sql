-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: admission Account/User предшествует explicit parent row locks.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_parent_prelock_admit_v3() RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 -- Единственный эффект unsigned compatibility — прежний consumer admission.
 -- Signed claim проверяется без смены режима, decision_at и состава proof.
 -- Private verifier вызывается владельцем; его результат не выдаётся LOGIN.
 PERFORM kaname.authority_protocol_attestation();
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE r record; BEGIN
 REVOKE ALL ON FUNCTION kaname.authority_parent_prelock_admit_v3() FROM PUBLIC;
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f
 CROSS JOIN LATERAL aclexplode(f.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE f.oid='kaname.authority_parent_prelock_admit_v3()'::regprocedure AND a.grantee<>f.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.authority_parent_prelock_admit_v3() FROM %I',r.rolname);
 END LOOP;
 -- Только уже допущенные runtime executors, без доступа к private verifier.
 FOR r IN SELECT DISTINCT u.rolname FROM pg_catalog.pg_proc f
 CROSS JOIN LATERAL aclexplode(f.proacl) a JOIN pg_catalog.pg_roles u ON u.oid=a.grantee
 WHERE f.oid='kaname.authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)'::regprocedure
 AND a.grantee<>f.proowner AND a.privilege_type='EXECUTE' LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.authority_parent_prelock_admit_v3() TO %I',r.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
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
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
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
 FOR expected IN SELECT * FROM (VALUES
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','007c0ee49b9f8b53790462bb6089e3c4c6f07c2e1193d352b34066ee4b02434a',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','d18b70dce2a016c84b760463daca12ee698a1fbc9c0cb3a0e64bce9a7be7509e',true),
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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE singleton AND required_contract=2) THEN
  RAISE EXCEPTION 'cannot erase activated full parent prelock contract' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
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
 FOR expected IN SELECT * FROM (VALUES
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','007c0ee49b9f8b53790462bb6089e3c4c6f07c2e1193d352b34066ee4b02434a',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','d18b70dce2a016c84b760463daca12ee698a1fbc9c0cb3a0e64bce9a7be7509e',true),
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
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
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
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION kaname.authority_parent_prelock_admit_v3();
