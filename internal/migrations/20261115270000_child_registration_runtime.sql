-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: узкий вход исполнителя Kaname в закрытое тело регистрации.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Runtime Kaname проверяет пользователя на текущем DecisionAt перед входом.
-- SQL сохраняет снимок, точный шаг и обязательный commit; ключи клиента и
-- произвольные образы записи здесь не принимаются.
-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_begin_body_v1(p_intent jsonb) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_begin_body_v1(p_intent);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_step_v1(p_ordinal integer) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_step_v1(p_ordinal);
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname.authority_child_registration_complete_v1() RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT kaname._authority_child_registration_complete_v1();
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_runtime_storage_v1() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 WITH owner_role AS (
  SELECT relowner AS oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass
 ), approved AS (
  SELECT a.grantee FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a, owner_role o
  WHERE p.oid='kaname.authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)'::regprocedure
   AND a.grantee NOT IN (0,o.oid) AND a.privilege_type='EXECUTE' AND NOT a.is_grantable
 ), expected(signature,digest,definer,volatility,language) AS (VALUES
  ('_authority_child_registration_capture_v1(text,text,integer,integer)','13726c6180cfc4c7c9bb7001f0363f06d64bad31035ed845821fb9fd2c8257dc',false,'s','plpgsql'),
  ('_authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer)','5472c35ce47f678131d75e938ceffafecef57c1fcf7630f8b3ae70f1349e1c82',false,'v','plpgsql'),
  ('_authority_child_registration_outcome_v1(jsonb,timestamptz)','868d3dcfd39cdbbcec87e550e8504472db5aa9cec700ed74ca50111f2db9a2fa',false,'s','plpgsql'),
  ('_authority_child_registration_sources_v1(jsonb,jsonb,jsonb,jsonb)','b9a7213485e415a32ad2d71f2b2a47c93b236e0617f2934dd76017e7c884e7be',false,'s','plpgsql'),
  ('_authority_child_registration_program_v1(jsonb,jsonb,jsonb,jsonb,text,text,timestamptz,timestamptz,uuid)','1cb416806c3d5123b4aacc5676e5cc58c9b7c7ab6eaf18d0b5be1b77686549b7',false,'s','plpgsql'),
  ('_authority_child_registration_maximum_v1(jsonb,jsonb,jsonb)','21f54ca5cea648271cde409fc8cab9175cf1cc69d712bd14395f9a32aa378ded',false,'s','plpgsql'),
  ('_authority_child_registration_hold_v1(jsonb,integer,integer)','546f11cf9b517b00d48c050df26637da333f7dc5016610738ac2081677a9c29b',false,'v','plpgsql'),
  ('_authority_child_registration_select_v1(jsonb,timestamptz)','1a6505db61eda4a1447c3e8c837604a308adb74387da25dc4f63e2428c53ccb3',false,'v','plpgsql'),
  ('_authority_child_registration_prepare_v1(jsonb,integer,integer)','d5f65b20fa5af6ea25a043ec99696c488f00521741413e833216e678608cb089',false,'v','plpgsql'),
  ('_authority_child_registration_finalize_v1(jsonb,integer,integer)','9007c266ff5ad31f8cf44cc94b0a1ba6529f8d02ba4ee54f6507e7b102076353',false,'v','plpgsql'),
  ('_authority_child_registration_begin_body_v1(jsonb)','23d1cf16c9baaafb585de00185a2c73dbcb72a6e0b59f6373fed171a838aa578',false,'v','plpgsql'),
  ('_authority_child_registration_step_done_v1(jsonb,integer)','9f7888e6001f38328963d17053bf6d7640688e0a16c09fb82cc10c7971f30586',false,'s','plpgsql'),
  ('_authority_child_registration_step_v1(integer)','2602fe97ef81b1a242b322c697e90b63d005dd30454010fa64abebb0387893eb',false,'v','plpgsql'),
  ('_authority_child_registration_complete_v1()','17686473c29efe97fb787cf2a1495997240719a5913a272404c9b87823f997bb',false,'v','plpgsql'),
  ('authority_child_registration_begin_body_v1(jsonb)','bf7b041190118779c428cbd9bb6a6be6fed8f840f5c571c54f057115343425f9',true,'v','sql'),
  ('authority_child_registration_step_v1(integer)','7ba85ac77d2ac21e1d2afa3ff50738d4547062f850490d20e3f9bf0b9ec7abbc',true,'v','sql'),
  ('authority_child_registration_complete_v1()','4f44ebad4a5aea644f7180b9ae686edc411ef1c7f0262bd12ba6c1064fe5ac23',true,'v','sql')
 )
 SELECT EXISTS(SELECT 1 FROM owner_role o JOIN pg_catalog.pg_roles r ON r.oid=o.oid WHERE r.rolname=current_user)
 AND NOT EXISTS(
  SELECT 1 FROM expected e CROSS JOIN owner_role o
  LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||e.signature)
  LEFT JOIN pg_catalog.pg_language l ON l.oid=p.prolang
  WHERE (p.proowner=o.oid AND p.prosecdef=e.definer AND p.provolatile::text=e.volatility
   AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND l.lanname=e.language
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=e.digest) IS NOT TRUE
  OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
   WHERE a.grantee<>o.oid AND (NOT e.definer OR a.is_grantable OR a.privilege_type<>'EXECUTE'
    OR NOT EXISTS(SELECT 1 FROM approved r WHERE r.grantee=a.grantee)))
  OR (e.definer AND EXISTS(SELECT 1 FROM approved r
   WHERE NOT EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=r.grantee AND a.privilege_type='EXECUTE')))
 );
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 -- Хранилище инкарнаций и квитанций принадлежит только владельцу протокола.
 IF EXISTS(SELECT 1
  FROM unnest(ARRAY['authority_child_parent_state','authority_child_creation']) AS required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM owner_oid OR c.relkind<>'r' OR c.relpersistence<>'p'
   OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute col
    CROSS JOIN LATERAL aclexplode(col.attacl) a
    WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>owner_oid)
 ) THEN RETURN false;END IF;
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
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_child_runtime_storage_v1()','3c62af588f9e5de90587a615a27fb0d89b32576f6c228a471eff954ed11494e1',true),
 ('_authority_crud_storage_v3()','bf385f1f32a62688c84f8fe02190aeda68d0ed7b8514a19a8e8d1344412e2df8',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','53554846c85e31f40b16c788e36527bba3fff4e4c57be01c0bad5ce8c36f45a6',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3() AND kaname._authority_child_runtime_storage_v1();
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding runtime grant closure incomplete' USING ERRCODE='55000';END IF;
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 -- Исторический GRANT SELECT ON ALL TABLES не открывает состояние допуска.
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_child_parent_state,kaname.authority_child_creation FROM %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_child_parent_state','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_child_creation','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains private child registration privileges' USING ERRCODE='42501';
 END IF;
 FOREACH signature IN ARRAY ARRAY[
  'authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()',
  'authority_native_delete_batch_read_v4()',
  'authority_native_delete_emit_v4(jsonb[])',
  'authority_native_delete_prepare_v4(jsonb[])',
  'authority_native_delete_stamp_v4(uuid,bigint,jsonb)',
  'authority_forward_emit_v4(jsonb[])',
  'authority_forward_prepare_v4(jsonb[])',
  'authority_forward_claim_v4(uuid)',
  'authority_forward_finish_v4(uuid)',
  'authority_group_add_prepare_v3(jsonb,integer,integer)',
  'authority_group_add_finalize_v3(jsonb,integer,integer)',
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_group_add_subject_id_v3()',
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_command_begin_v3(jsonb)',
  'authority_binding_command_end_v3(jsonb)',
  'authority_binding_command_audit_v3(jsonb)',
  'authority_binding_sequence_prepare_v3(text,jsonb)',
  'authority_binding_sequence_finalize_v3()',
  'authority_binding_insert_stamp_v3(text)',
  'authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_finalize_v3(text)',
  'authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)',
  'authority_binding_withdrawal_sequence_finalize_v3()',
  'authority_cluster_admin_preflight_v4(text,text,text)',
  'authority_resource_journal_id_v3()',
  'authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
  'authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_metadata_preflight_v4(text,text,boolean,text,jsonb)',
  'authority_sa_state_preflight_v4(text,boolean,text)',
  'authority_scalar_sequence_finalize_v3()',
  'authority_crud_storage_v3()',

  'authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)',
  'authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)',
  'authority_resource_enter_v3(text,text[],jsonb,text,text,text)',
  'authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)',
   'authority_child_registration_begin_body_v1(jsonb)',
   'authority_child_registration_step_v1(integer)',
   'authority_child_registration_complete_v1()',
  'authority_installation_enter_v3(text,text,text,text)',
  'authority_full_contract_validate_v3(text,text,text)',
  'authority_staged_contract_validate_v3()',
  'authority_metadata_preflight_v3(text,text,boolean,text)',
  'authority_role_prelock_admit_v3()',
  'authority_parent_prelock_admit_v3()',
  'authority_reconcile_enter_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE signature text; owner_oid oid; principal record; BEGIN
 SELECT relowner INTO STRICT owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 FOREACH signature IN ARRAY ARRAY[
   'authority_child_registration_begin_body_v1(jsonb)',
   'authority_child_registration_step_v1(integer)',
   'authority_child_registration_complete_v1()',
   '_authority_child_runtime_storage_v1()'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>owner_oid LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,principal.rolname);
  END LOOP;
  IF left(signature,1)='_' THEN CONTINUE;END IF;
  -- Обновляем только уже допущенных участников подписанной resource-транзакции.
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid='kaname.authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)'::regprocedure
    AND a.grantee<>owner_oid AND a.privilege_type='EXECUTE' AND NOT a.is_grantable LOOP
   EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,principal.rolname);
  END LOOP;
 END LOOP;
 IF NOT kaname._authority_full_contract_storage_v3() THEN
  RAISE EXCEPTION 'child registration runtime closure incomplete' USING ERRCODE='55000';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 PERFORM kaname.authority_protocol_drain();
 IF EXISTS(SELECT 1 FROM kaname.authority_writer_contract WHERE required_contract=2) THEN
  RAISE EXCEPTION 'cannot remove active child registration runtime' USING ERRCODE='P1036';
 END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_grant_runtime(p_runtime regrole) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE signature text; runtime_name text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding runtime grant closure incomplete' USING ERRCODE='55000';END IF;
 PERFORM kaname._authority_protocol_grant_runtime_generation1(p_runtime);
 SELECT rolname INTO STRICT runtime_name FROM pg_catalog.pg_roles WHERE oid=p_runtime;
 -- Исторический GRANT SELECT ON ALL TABLES не открывает состояние допуска.
 EXECUTE format('REVOKE ALL ON TABLE kaname.authority_child_parent_state,kaname.authority_child_creation FROM %I',runtime_name);
 IF has_table_privilege(p_runtime,'kaname.authority_child_parent_state','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 OR has_table_privilege(p_runtime,'kaname.authority_child_creation','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') THEN
  RAISE EXCEPTION 'runtime retains private child registration privileges' USING ERRCODE='42501';
 END IF;
 FOREACH signature IN ARRAY ARRAY[
  'authority_native_write_arm_v4(uuid)','authority_native_write_read_v4()',
  'authority_native_delete_batch_read_v4()',
  'authority_native_delete_emit_v4(jsonb[])',
  'authority_native_delete_prepare_v4(jsonb[])',
  'authority_native_delete_stamp_v4(uuid,bigint,jsonb)',
  'authority_forward_emit_v4(jsonb[])',
  'authority_forward_prepare_v4(jsonb[])',
  'authority_forward_claim_v4(uuid)',
  'authority_forward_finish_v4(uuid)',
  'authority_group_add_prepare_v3(jsonb,integer,integer)',
  'authority_group_add_finalize_v3(jsonb,integer,integer)',
  'authority_group_add_fold_v3(text,jsonb,timestamptz)',
  'authority_group_add_subject_id_v3()',
  'authority_resource_crud_capture_v3(jsonb,integer,integer)',
  'authority_resource_crud_body_values_v3()',
  'authority_resource_crud_step_v3(text,jsonb)',
  'authority_resource_crud_lock_held_v3(text)',
  'authority_resource_crud_journal_value_v3(jsonb,jsonb)',
  'authority_binding_command_begin_v3(jsonb)',
  'authority_binding_command_end_v3(jsonb)',
  'authority_binding_command_audit_v3(jsonb)',
  'authority_binding_sequence_prepare_v3(text,jsonb)',
  'authority_binding_sequence_finalize_v3()',
  'authority_binding_insert_stamp_v3(text)',
  'authority_binding_stage_sequence_capture_v3(jsonb,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_prepare_v3(text,text[],jsonb,integer,integer)',
  'authority_binding_stage_sequence_finalize_v3(text)',
  'authority_binding_withdrawal_sequence_prepare_v3(text,text,text,integer,integer)',
  'authority_binding_withdrawal_sequence_finalize_v3()',
  'authority_cluster_admin_preflight_v4(text,text,text)',
  'authority_resource_journal_id_v3()',
  'authority_fga_outbox_id_v3()',
  'authority_prepared_journal_value_v3(jsonb,jsonb)',
  'authority_role_sequence_prepare_v3(jsonb,integer,integer)',
  'authority_role_sequence_finalize_v3()',
  'authority_role_sequence_stamp_v3(jsonb)',
  'authority_metadata_preflight_v4(text,text,boolean,text,jsonb)',
  'authority_sa_state_preflight_v4(text,boolean,text)',
  'authority_scalar_sequence_finalize_v3()',
  'authority_crud_storage_v3()',

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
  'authority_reconcile_enter_v3()',
  'authority_sa_state_preflight_v3(text,boolean,text)'] LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION kaname.%s TO %I',signature,runtime_name);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid; target text;
BEGIN
 SELECT relowner INTO owner_oid FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass;
 IF owner_oid IS DISTINCT FROM (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=to_regclass('kaname.authority_writer_contract') AND relowner=owner_oid AND relkind='r' AND relpersistence='p')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
  WHERE c.oid=to_regclass('kaname.authority_writer_contract') AND a.grantee<>owner_oid) THEN RETURN false; END IF;
 -- Хранилище инкарнаций и квитанций принадлежит только владельцу протокола.
 IF EXISTS(SELECT 1
  FROM unnest(ARRAY['authority_child_parent_state','authority_child_creation']) AS required(name)
  LEFT JOIN pg_catalog.pg_class c ON c.oid=to_regclass('kaname.'||required.name)
  WHERE c.oid IS NULL OR c.relowner IS DISTINCT FROM owner_oid OR c.relkind<>'r' OR c.relpersistence<>'p'
   OR EXISTS(SELECT 1 FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>owner_oid)
   OR EXISTS(SELECT 1 FROM pg_catalog.pg_attribute col
    CROSS JOIN LATERAL aclexplode(col.attacl) a
    WHERE col.attrelid=c.oid AND col.attnum>0 AND NOT col.attisdropped AND a.grantee<>owner_oid)
 ) THEN RETURN false;END IF;
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
 -- Один SQL-запрос на все отпечатки; ACL читается только после совпадения
 -- тела и параметров приватной функции.
 IF EXISTS(SELECT 1 FROM (VALUES
 ('_authority_crud_storage_v3()','bf385f1f32a62688c84f8fe02190aeda68d0ed7b8514a19a8e8d1344412e2df8',true),
 ('authority_parent_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_minted_cutoff_key_v3(text)','e070405bfea920fb884831cd02890bd90810a65f4d617a828b1af9ea48542623',true),
 ('_authority_minted_cutoff_order_v3()','d911640bce1f00a365213aa03845461e4d6f479ca564e40745b810ad2976dd29',true),
 ('authority_sa_state_preflight_v3(text,boolean,text)','980a05e9e1dc6973b93ba6694ea376a70efaa22a4639e5b762b425b81dbad3f7',true),
 ('authority_role_prelock_admit_v3()','0a5d8d81822501af40183c78d52e8897d3bf8583e8b888589a64951a88139247',true),
 ('_authority_protocol_catalog_changed_v3()','974332f1dc2c6f42d12d35c49c89c201ac5deecf153f46070746ca0fcef6fbbb',true),
 ('authority_metadata_preflight_v3(text,text,boolean,text)','ea89b06dc47ce62579a99026522c1d8dd4c0edc585922c71ca77c9ea11b07ed3',true),
 ('_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)','1eae08ffff7b4eb936b224dfa08ed3e49679e968033a8e823e0bd3ef6d9786cf',true),
 ('_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)','7109bc396aeecee56a015a868826ebcf88bc15a050fceacf033b73971ff50aca',true),
 ('_authority_protocol_enter_v1_body(text,text[],jsonb,text,text,text,text,integer,text)','e71e29754a20d3a18054206600cf26cc6c234f26e798a41d9430177f612d68e4',true),
 ('_authority_protocol_enter_v2(text,text[],jsonb,text,text,text,text,text,text,jsonb)','e4a1ca86b280c64e7c9b5a54bbfb1e4152f59732f40c7f0748a5bb1a86fb77b1',true),
 ('_authority_protocol_attestation_v1_body()','2c6a618c91d3b7fff8a5e23734d8d7815d6c38cb9b82adacd2e472202584fc54',true),
 ('authority_protocol_enter_typed_v3(text,text[],jsonb,text,text,text,text,text)','86ecf97ccb3cd5599f434955609fb3f1335dd82231f881deb510638981c8ec7a',true),
 ('authority_protocol_enter_full_v3(text,text[],jsonb,text,text,text,text,text,jsonb)','33c57c5d0b23128b4fa5e694f4863073e7b6bcce4789c3cd98953285a991f1ea',true),
 ('authority_resource_enter_v3(text,text[],jsonb,text,text,text)','8e54f4da31fab3d4706a58039ea84de5ee88c8c258f92f73c65b7e098aebcc2d',true),
 ('authority_resource_source_enter_v3(text,text[],jsonb,text,text,text)','26f28ff899f445a4b2ca54c2d4ea4ac285fb0bf928082475fc862b1d6bddbd6a',true),
 ('authority_installation_enter_v3(text,text,text,text)','c9d988aa2dfb5851a95037d88ab9847da36ec8154507487bc962cc1b3c1f5b44',true),
 ('authority_full_contract_validate_v3(text,text,text)','25bfc4bd59d30c59e9246889a4279e1326b0ecbb5940b220fd52490a8777d1ea',true),
 ('authority_staged_contract_validate_v3()','0438c79b89809642700ab1d12a3dee84f8a0432c3b33589d47d16e8d9ce885b8',true),
 ('authority_protocol_stage_full_v3(text,bytea,text,text,text)','1f7a9c17af7a4c3ec041405fa9f0dddc69cdf3fa666ba72db47247cde8447037',false),
 ('authority_protocol_activate_full_v3(text,text,text)','646328a2433e1d31d17a9c178ac3ab59a5a65d8252accf5295a20d22705d31cf',false),
 ('authority_protocol_attestation()','130a504f7da2b6780cd4e91a2c7103f9fabe765541f0f2611f900ce679ddd502',true),
 ('authority_protocol_statement_guard()','53554846c85e31f40b16c788e36527bba3fff4e4c57be01c0bad5ce8c36f45a6',true),
 ('authority_protocol_row_guard()','cb90a95df9b7105f053ae0c8652407335ef82745a2e749dc395b1c82e8435d12',true),
 ('_authority_protocol_stage_generation1(text,bytea,text,text,text)','7ffb942af742bff4b556f07b00d9d8f75fefba3aa1f00445073140b5c8072bde',false),
 ('_authority_protocol_activate_generation1(text,text,text)','00d97c37e2ab533c232e4cffb975e8d71c3eefa98228e0f39d90249526bf041c',false),
 ('authority_protocol_drain()','f0e36bb29e96ba0417e9143821391b9df518541a017dcd9b171c037e167bc500',false),
 ('authority_protocol_require_drain()','61686507d75a6352d1f0fd97c9e3886c5c361af00778bdf3513693ee2dd6468b',false)
 ) AS pinned(signature,digest,definer)
 LEFT JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||pinned.signature)
 WHERE CASE
  WHEN (p.proowner=owner_oid AND p.prosecdef=pinned.definer
   AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
   AND encode(sha256(convert_to(p.prosrc,'UTF8')),'hex')=pinned.digest) IS NOT TRUE THEN true
  WHEN left(pinned.signature,1)='_' THEN
   EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee<>owner_oid)
  ELSE false
 END) THEN RETURN false; END IF;
 RETURN kaname._authority_crud_storage_v3();
END $$;
-- +goose StatementEnd

DROP FUNCTION kaname._authority_child_runtime_storage_v1();
DROP FUNCTION kaname.authority_child_registration_complete_v1();
DROP FUNCTION kaname.authority_child_registration_step_v1(integer);
DROP FUNCTION kaname.authority_child_registration_begin_body_v1(jsonb);
