-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1034: убрать повторную attestation внутри одного mirror BEFORE.
-- Snapshot остаётся свежим для каждого guard; proof не хранится между вызовами
-- и не принимается от caller. Старые функции сохраняют OID, владельца и ACL.
-- Закреплённые closure тела меняются только при точном исходном prosrc;
-- проверка точного postimage исключает незамеченную неполную замену.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain();END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_binding_mirror_probe_v4() RETURNS TABLE(proof jsonb,metadata jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE owner_oid oid;relation_id oid;result jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'participant' THEN RETURN NEXT;RETURN;END IF;
 IF to_regclass('pg_temp.kaname_binding_mirror_program') IS NULL THEN RETURN NEXT;RETURN;END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[to_regclass('pg_temp.kaname_binding_mirror_program'),to_regclass('pg_temp.kaname_binding_mirror_images'),to_regclass('pg_temp.kaname_binding_mirror_policy_receipt')] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted binding mirror program' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Горячая проверка не читает frozen sources или полный массив images.
 SELECT jsonb_build_object('backend',p.backend,'transaction_id',p.transaction_id,'invoker_oid',p.invoker_oid,
  'nonce',p.nonce,'binding',p.binding_id,'accounts',p.accounts,'epochs',p.epochs,'epoch_clock',p.epoch_clock,
  'final_clock',p.final_clock,'image_limit',p.image_limit) INTO STRICT result FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF result->>'backend' IS DISTINCT FROM proof->>'backend' OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid' OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR proof->>'mode' IS DISTINCT FROM 'accounts' OR result->'accounts' IS DISTINCT FROM proof->'accounts' THEN
  RAISE EXCEPTION 'binding mirror program identity changed' USING ERRCODE='42501';END IF;
 metadata:=result;
 RETURN NEXT;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ DECLARE grantee record;BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_binding_mirror_probe_v4() FROM PUBLIC;
 FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_binding_mirror_probe_v4()'::regprocedure AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_binding_mirror_probe_v4() FROM %I',grantee.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_store_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb;
BEGIN
 SELECT p.metadata INTO STRICT result FROM kaname._authority_binding_mirror_probe_v4() p;
 RETURN result;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_before_write_v3(p_table text,p_operation text,p_old jsonb,p_new jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE metadata jsonb;proof jsonb;header jsonb;v_row_value jsonb;identifier bigint;candidate jsonb;v_image_hash bytea;matched record;sequence_origin jsonb;
BEGIN
 IF p_table NOT IN ('access_binding_target_members','access_binding_emitted_tuples','fga_outbox','relation_fact') THEN RETURN false;END IF;
 -- Одна свежая проверка возвращает proof и metadata этой invocation.
 -- Между чтением witness и использованием нет DML, часов или чужого callback.
 SELECT p.proof,p.metadata INTO STRICT proof,metadata FROM kaname._authority_binding_mirror_probe_v4() p;
 IF metadata IS NULL THEN RETURN false;END IF;
 IF metadata->>'final_clock' IS NULL OR metadata->>'final_clock' IS DISTINCT FROM proof->>'decision_at'
 OR metadata->>'epoch_clock' IS DISTINCT FROM proof->>'decision_at' THEN
  RAISE EXCEPTION 'binding mirror write before final held proof' USING ERRCODE='42501';END IF;
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL OR header->>'family' IS DISTINCT FROM 'binding' OR header->'selected'='null'::jsonb THEN
  RAISE EXCEPTION 'binding mirror selected sequence absent' USING ERRCODE='42501';END IF;
 IF p_table IN ('access_binding_target_members','access_binding_emitted_tuples') THEN
  IF (p_old IS NOT NULL AND p_old->>'binding_id' IS DISTINCT FROM metadata->>'binding')
  OR (p_new IS NOT NULL AND p_new->>'binding_id' IS DISTINCT FROM metadata->>'binding') THEN
   RAISE EXCEPTION 'binding mirror physical binding differs from prepared witness' USING ERRCODE='42501';END IF;
 ELSIF p_table='fga_outbox' THEN
  IF p_operation<>'INSERT' OR p_old IS NOT NULL THEN RETURN false;END IF;
  identifier:=(p_new->>'id')::bigint;v_row_value:=p_new-'id';
  IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e WHERE e.nonce=(header->>'nonce')::uuid
   AND e.table_name='fga_outbox' AND e.reserved_id=identifier AND e.selected AND e.claimed AND NOT e.consumed
   AND e.origin->>'family'='binding.stage' AND e.origin->>'binding'=metadata->>'binding' AND e.row_value=v_row_value) THEN
   RAISE EXCEPTION 'binding mirror journal differs from selected sequence row' USING ERRCODE='42501';END IF;
  SELECT e.origin INTO STRICT sequence_origin FROM pg_temp.kaname_authority_sequence_effects e
   WHERE e.nonce=(header->>'nonce')::uuid AND e.table_name='fga_outbox' AND e.reserved_id=identifier;
  p_new:=v_row_value;
 END IF;
 v_image_hash:=sha256(convert_to(jsonb_build_array(p_old,p_new)::text,'UTF8'));
 SELECT i.* INTO matched FROM pg_temp.kaname_binding_mirror_images i
 WHERE i.table_name=p_table AND i.operation=p_operation AND i.image_hash=v_image_hash
 AND i.old_image IS NOT DISTINCT FROM p_old AND i.new_image IS NOT DISTINCT FROM p_new
 AND NOT i.attempted
 AND i.command_no=(SELECT p.active_command FROM pg_temp.kaname_binding_mirror_program p WHERE singleton)
 AND (p_table<>'relation_fact' OR i.outbox_no=(SELECT p.active_outbox FROM pg_temp.kaname_binding_mirror_program p WHERE singleton))
 AND (sequence_origin IS NULL OR (i.origin->'command'=sequence_origin->'command' AND i.origin->'coordinate'=sequence_origin->'coordinate'))
 ORDER BY i.command_no,i.image_no LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding mirror physical image absent or replayed' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i
  WHERE i.command_no<matched.command_no AND ((i.required AND NOT i.consumed) OR (i.table_name='fga_outbox' AND NOT i.folded))) THEN
  RAISE EXCEPTION 'binding mirror command precedes required effects' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_images SET attempted=true WHERE image_no=matched.image_no;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $pin$ DECLARE original text;replacement text;BEGIN
 SELECT p.prosrc INTO STRICT original FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_crud_storage_v3()'::regprocedure;
 IF encode(sha256(convert_to(original,'UTF8')),'hex')<>'117d174e3a2baae3b026c60ffb274c199537079ec58869ec068593b0fee64c8f' THEN
  RAISE EXCEPTION 'binding mirror corrective source differs' USING ERRCODE='55000';END IF;
 replacement:=original;
 replacement:=replace(replacement,$old$94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61$old$,$new$9a915a6d11fea000ff5e4875b6b1c4e6302c8e0ec2f8879302aa76c9719e6412$new$);
 replacement:=replace(replacement,$old$91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854$old$,$new$f87132c83a55eac79fa1b0a3153e3213549e9a44291a596992c3709d8d3698ae$new$);
 replacement:=replace(replacement,$old$ FOR expected IN SELECT * FROM (VALUES
 ('_authority_native_write_weights_v4(jsonb)',$old$,$new$ FOR expected IN SELECT * FROM (VALUES
 ('_authority_binding_mirror_probe_v4()','559eb1c2cf31d22bdee76608090856e37e2c2c902334ba4e60a83fff3119b678',true,'v',true,'private'),
 ('_authority_native_write_weights_v4(jsonb)',$new$);
 replacement:=replace(replacement,$old$ IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
$old$,$new$ IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_binding_mirror_probe_v4()')
  AND p.prokind='f' AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND NOT p.proisstrict AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND p.proargnames=ARRAY['proof','metadata']::text[] AND p.proargmodes=ARRAY['t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid]) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
$new$);
 IF encode(sha256(convert_to(replacement,'UTF8')),'hex')<>'4d3c92cacb41f5944df922b2537db10a4978bea6d5fcbe181e23a664dab14c79' THEN
  RAISE EXCEPTION 'binding mirror corrective postimage differs' USING ERRCODE='55000';END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_crud_storage_v3() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',replacement);
END $pin$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $pin$ DECLARE original text;replacement text;BEGIN
 SELECT p.prosrc INTO STRICT original FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_full_contract_storage_v3()'::regprocedure;
 IF encode(sha256(convert_to(original,'UTF8')),'hex')<>'4182623e65a4abbcb89341146c6b55b328e66d3793acf3d18251a70546fcef38' THEN
  RAISE EXCEPTION 'binding mirror corrective source differs' USING ERRCODE='55000';END IF;
 replacement:=original;
 replacement:=replace(replacement,$old$117d174e3a2baae3b026c60ffb274c199537079ec58869ec068593b0fee64c8f$old$,$new$4d3c92cacb41f5944df922b2537db10a4978bea6d5fcbe181e23a664dab14c79$new$);
 IF encode(sha256(convert_to(replacement,'UTF8')),'hex')<>'db82f3da8660745249109b43b94099c472232210f870d2ca19430e1e6f0454df' THEN
  RAISE EXCEPTION 'binding mirror corrective postimage differs' USING ERRCODE='55000';END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',replacement);
END $pin$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$ BEGIN IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding mirror corrective closure incomplete' USING ERRCODE='55000';END IF;END $$;
-- +goose StatementEnd

-- +goose Down
-- Точные прежние тела и closure; тот же drain до замены.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain();END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_store_v3() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb;owner_oid oid;relation_id oid;result jsonb;
BEGIN
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind'<>'binding' OR proof->>'purpose'<>'participant' THEN RETURN NULL;END IF;
 IF to_regclass('pg_temp.kaname_binding_mirror_program') IS NULL THEN RETURN NULL;END IF;
 SELECT oid INTO STRICT owner_oid FROM pg_catalog.pg_roles WHERE rolname=current_user;
 FOREACH relation_id IN ARRAY ARRAY[to_regclass('pg_temp.kaname_binding_mirror_program'),to_regclass('pg_temp.kaname_binding_mirror_images'),to_regclass('pg_temp.kaname_binding_mirror_policy_receipt')] LOOP
  IF relation_id IS NULL OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid=relation_id
   AND c.relowner=owner_oid AND c.relpersistence='t' AND c.relkind='r')
  OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
   WHERE c.oid=relation_id AND a.grantee<>owner_oid) THEN
   RAISE EXCEPTION 'untrusted binding mirror program' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Горячая проверка не читает frozen sources или полный массив images.
 SELECT jsonb_build_object('backend',p.backend,'transaction_id',p.transaction_id,'invoker_oid',p.invoker_oid,
  'nonce',p.nonce,'binding',p.binding_id,'accounts',p.accounts,'epochs',p.epochs,'epoch_clock',p.epoch_clock,
  'final_clock',p.final_clock,'image_limit',p.image_limit) INTO STRICT result FROM pg_temp.kaname_binding_mirror_program p WHERE singleton;
 IF result->>'backend' IS DISTINCT FROM proof->>'backend' OR result->>'transaction_id' IS DISTINCT FROM proof->>'transaction_id'
 OR result->>'invoker_oid' IS DISTINCT FROM proof->>'invoker_oid' OR result->>'nonce' IS DISTINCT FROM proof->>'nonce'
 OR proof->>'mode' IS DISTINCT FROM 'accounts' OR result->'accounts' IS DISTINCT FROM proof->'accounts' THEN
  RAISE EXCEPTION 'binding mirror program identity changed' USING ERRCODE='42501';END IF;
 RETURN result;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_before_write_v3(p_table text,p_operation text,p_old jsonb,p_new jsonb) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE metadata jsonb;proof jsonb;header jsonb;v_row_value jsonb;identifier bigint;candidate jsonb;v_image_hash bytea;matched record;sequence_origin jsonb;
BEGIN
 IF p_table NOT IN ('access_binding_target_members','access_binding_emitted_tuples','fga_outbox','relation_fact') THEN RETURN false;END IF;
 metadata:=kaname._authority_binding_mirror_store_v3();IF metadata IS NULL THEN RETURN false;END IF;
 proof:=kaname.authority_protocol_attestation();
 IF metadata->>'final_clock' IS NULL OR metadata->>'final_clock' IS DISTINCT FROM proof->>'decision_at'
 OR metadata->>'epoch_clock' IS DISTINCT FROM proof->>'decision_at' THEN
  RAISE EXCEPTION 'binding mirror write before final held proof' USING ERRCODE='42501';END IF;
 header:=kaname._authority_sequence_header_v3();
 IF header IS NULL OR header->>'family' IS DISTINCT FROM 'binding' OR header->'selected'='null'::jsonb THEN
  RAISE EXCEPTION 'binding mirror selected sequence absent' USING ERRCODE='42501';END IF;
 IF p_table IN ('access_binding_target_members','access_binding_emitted_tuples') THEN
  IF (p_old IS NOT NULL AND p_old->>'binding_id' IS DISTINCT FROM metadata->>'binding')
  OR (p_new IS NOT NULL AND p_new->>'binding_id' IS DISTINCT FROM metadata->>'binding') THEN
   RAISE EXCEPTION 'binding mirror physical binding differs from prepared witness' USING ERRCODE='42501';END IF;
 ELSIF p_table='fga_outbox' THEN
  IF p_operation<>'INSERT' OR p_old IS NOT NULL THEN RETURN false;END IF;
  identifier:=(p_new->>'id')::bigint;v_row_value:=p_new-'id';
  IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_sequence_effects e WHERE e.nonce=(header->>'nonce')::uuid
   AND e.table_name='fga_outbox' AND e.reserved_id=identifier AND e.selected AND e.claimed AND NOT e.consumed
   AND e.origin->>'family'='binding.stage' AND e.origin->>'binding'=metadata->>'binding' AND e.row_value=v_row_value) THEN
   RAISE EXCEPTION 'binding mirror journal differs from selected sequence row' USING ERRCODE='42501';END IF;
  SELECT e.origin INTO STRICT sequence_origin FROM pg_temp.kaname_authority_sequence_effects e
   WHERE e.nonce=(header->>'nonce')::uuid AND e.table_name='fga_outbox' AND e.reserved_id=identifier;
  p_new:=v_row_value;
 END IF;
 v_image_hash:=sha256(convert_to(jsonb_build_array(p_old,p_new)::text,'UTF8'));
 SELECT i.* INTO matched FROM pg_temp.kaname_binding_mirror_images i
 WHERE i.table_name=p_table AND i.operation=p_operation AND i.image_hash=v_image_hash
 AND i.old_image IS NOT DISTINCT FROM p_old AND i.new_image IS NOT DISTINCT FROM p_new
 AND NOT i.attempted
 AND i.command_no=(SELECT p.active_command FROM pg_temp.kaname_binding_mirror_program p WHERE singleton)
 AND (p_table<>'relation_fact' OR i.outbox_no=(SELECT p.active_outbox FROM pg_temp.kaname_binding_mirror_program p WHERE singleton))
 AND (sequence_origin IS NULL OR (i.origin->'command'=sequence_origin->'command' AND i.origin->'coordinate'=sequence_origin->'coordinate'))
 ORDER BY i.command_no,i.image_no LIMIT 1;
 IF NOT FOUND THEN RAISE EXCEPTION 'binding mirror physical image absent or replayed' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM pg_temp.kaname_binding_mirror_images i
  WHERE i.command_no<matched.command_no AND ((i.required AND NOT i.consumed) OR (i.table_name='fga_outbox' AND NOT i.folded))) THEN
  RAISE EXCEPTION 'binding mirror command precedes required effects' USING ERRCODE='42501';END IF;
 UPDATE pg_temp.kaname_binding_mirror_images SET attempted=true WHERE image_no=matched.image_no;
 RETURN true;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $pin$ DECLARE original text;replacement text;BEGIN
 SELECT p.prosrc INTO STRICT original FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_crud_storage_v3()'::regprocedure;
 IF encode(sha256(convert_to(original,'UTF8')),'hex')<>'4d3c92cacb41f5944df922b2537db10a4978bea6d5fcbe181e23a664dab14c79' THEN
  RAISE EXCEPTION 'binding mirror corrective source differs' USING ERRCODE='55000';END IF;
 replacement:=original;
 replacement:=replace(replacement,$old$ IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure('kaname._authority_binding_mirror_probe_v4()')
  AND p.prokind='f' AND p.pronargs=0 AND p.proretset AND p.prorettype='record'::regtype
  AND NOT p.proisstrict AND NOT p.proleakproof AND p.proparallel='u' AND p.pronargdefaults=0 AND p.provariadic=0
  AND p.prolang=(SELECT oid FROM pg_catalog.pg_language WHERE lanname='plpgsql')
  AND p.proargnames=ARRAY['proof','metadata']::text[] AND p.proargmodes=ARRAY['t','t']::"char"[]
  AND p.proallargtypes=ARRAY['jsonb'::regtype::oid,'jsonb'::regtype::oid]) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
$old$,$new$ IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_sequence_probe_v3()'::regprocedure
$new$);
 replacement:=replace(replacement,$old$ FOR expected IN SELECT * FROM (VALUES
 ('_authority_binding_mirror_probe_v4()','559eb1c2cf31d22bdee76608090856e37e2c2c902334ba4e60a83fff3119b678',true,'v',true,'private'),
 ('_authority_native_write_weights_v4(jsonb)',$old$,$new$ FOR expected IN SELECT * FROM (VALUES
 ('_authority_native_write_weights_v4(jsonb)',$new$);
 replacement:=replace(replacement,$old$f87132c83a55eac79fa1b0a3153e3213549e9a44291a596992c3709d8d3698ae$old$,$new$91ee46ad24bb6267178100747185c18546bd1f01566e7b2780403f60c8995854$new$);
 replacement:=replace(replacement,$old$9a915a6d11fea000ff5e4875b6b1c4e6302c8e0ec2f8879302aa76c9719e6412$old$,$new$94398fb5e832f685ced7c84e6975e21e04729db15a39893977cce3dc32809b61$new$);
 IF encode(sha256(convert_to(replacement,'UTF8')),'hex')<>'117d174e3a2baae3b026c60ffb274c199537079ec58869ec068593b0fee64c8f' THEN
  RAISE EXCEPTION 'binding mirror corrective postimage differs' USING ERRCODE='55000';END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_crud_storage_v3() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',replacement);
END $pin$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $pin$ DECLARE original text;replacement text;BEGIN
 SELECT p.prosrc INTO STRICT original FROM pg_catalog.pg_proc p WHERE p.oid='kaname._authority_full_contract_storage_v3()'::regprocedure;
 IF encode(sha256(convert_to(original,'UTF8')),'hex')<>'db82f3da8660745249109b43b94099c472232210f870d2ca19430e1e6f0454df' THEN
  RAISE EXCEPTION 'binding mirror corrective source differs' USING ERRCODE='55000';END IF;
 replacement:=original;
 replacement:=replace(replacement,$old$4d3c92cacb41f5944df922b2537db10a4978bea6d5fcbe181e23a664dab14c79$old$,$new$117d174e3a2baae3b026c60ffb274c199537079ec58869ec068593b0fee64c8f$new$);
 IF encode(sha256(convert_to(replacement,'UTF8')),'hex')<>'4182623e65a4abbcb89341146c6b55b328e66d3793acf3d18251a70546fcef38' THEN
  RAISE EXCEPTION 'binding mirror corrective postimage differs' USING ERRCODE='55000';END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION kaname._authority_full_contract_storage_v3() RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS %L',replacement);
END $pin$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_binding_mirror_probe_v4();
-- +goose StatementBegin
DO $$ BEGIN IF NOT kaname._authority_full_contract_storage_v3() THEN RAISE EXCEPTION 'binding mirror corrective closure incomplete' USING ERRCODE='55000';END IF;END $$;
-- +goose StatementEnd
