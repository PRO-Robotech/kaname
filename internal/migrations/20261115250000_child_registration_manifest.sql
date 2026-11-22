-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: подготовка и единственные часы регистрации потомка.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Штатное закрытое хранилище содержит исходную подготовку. Привязки
-- backend/xid/nonce, модель и удержанные locks проверяет общий getter.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_prepare_v1(p_envelope jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 held record; proof jsonb; relation_id oid; prepared jsonb; expected jsonb;
 policy jsonb; binding_epochs jsonb; source_guards jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 SELECT * INTO STRICT held FROM kaname._authority_child_registration_hold_v1(p_envelope,p_rows,p_reads);
 prepared:=held.prepared;
 proof:=kaname.authority_protocol_attestation();
 policy:=prepared#>'{maximum,policy_epochs}';
 binding_epochs:=prepared#>'{maximum,binding_epochs}';
 source_guards:=prepared#>'{maximum,source_guards}';
 -- RR сравнение проверяло policy_before. Финальное сравнение использует
 -- policy_after: под WRITE могла быть создана прежде отсутствовавшая строка.
 SELECT jsonb_object_agg(key,(prepared#>'{epoch_witness,policy_after}')->key) INTO expected
 FROM jsonb_object_keys(prepared->'native_epochs') key;
 relation_id:=kaname._authority_resource_manifest_create_v2();
 INSERT INTO pg_temp.kaname_authority_resource_manifest(
  abi,backend,transaction_id,invoker_oid,nonce,model_id,catalog_id,projector_version,mode,consumer_profile,accounts,
  intent,state,transaction_at,held_relations,held_advisory,catalog_rows,native_epochs,
  epoch_write_keys,epoch_share_keys,source_guard_write_keys,source_guard_read_keys,
  binding_epoch_write_scopes,binding_epoch_share_scopes,deferred_carrier_roles,epoch_lock_witness,writes,
  object_certificate,object_effects,object_sources,object_audit_reservations,registration_body)
 VALUES(2,proof->>'backend',proof->>'transaction_id',(proof->>'invoker_oid')::oid,proof->>'nonce',
  proof->>'model_id',proof->>'catalog_id',proof->>'projector_version',proof->>'mode',proof->>'consumer_profile',proof->'accounts',
  prepared->'intent','prepared',transaction_timestamp(),
  (prepared->'held_relations')||jsonb_build_array(jsonb_build_object('oid',relation_id,'mode','AccessExclusiveLock')),
  prepared->'held_advisory',prepared->'catalog_rows',expected,
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(policy) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(policy) WHERE value='share'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(source_guards) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(source_guards) WHERE value='share'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(binding_epochs) WHERE value='write'),
  (SELECT coalesce(jsonb_agg(key ORDER BY key COLLATE "C"),'[]'::jsonb) FROM jsonb_each_text(binding_epochs) WHERE value='share'),
  coalesce(prepared#>'{maximum,deferred_carrier_roles}','[]'::jsonb),prepared->'epoch_witness','[]'::jsonb,
  '{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,jsonb_build_object('prepared',prepared,'selected',NULL));
 PERFORM kaname._authority_resource_manifest_v2();
 RETURN QUERY SELECT held.logical_rows,held.logical_reads;
END $$;
-- +goose StatementEnd

-- Часы читаются только после проверки удержанного состояния. Актуальное
-- право человека проверяется вызывающим runner до входа в тело.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_finalize_v1(p_intent jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(decision_at timestamptz,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 manifest jsonb; prepared jsonb; expected jsonb; actual jsonb; selected jsonb; at_time timestamptz;
 keys text[]; count_rows integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'child registration final budget exceeded' USING ERRCODE='54000';
 END IF;
 manifest:=kaname._authority_resource_manifest_v2();
 prepared:=manifest#>'{registration_body,prepared}';
 IF manifest->>'state' IS DISTINCT FROM 'prepared' OR manifest->>'decision_at' IS NOT NULL
  OR manifest->'intent'->>'kind' IS DISTINCT FROM 'child_registration'
  OR p_intent IS DISTINCT FROM manifest->'intent'
  OR p_intent IS DISTINCT FROM prepared->'intent'
  OR manifest->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending' THEN
  RAISE EXCEPTION 'child registration final intent differs or decision already taken' USING ERRCODE='42501';
 END IF;
 expected:=manifest->'native_epochs';
 IF jsonb_typeof(expected) IS DISTINCT FROM 'object' OR NOT expected ? '*' THEN
  RAISE EXCEPTION 'child registration final epochs missing' USING ERRCODE='42501';
 END IF;
 SELECT array_agg(k) INTO keys FROM jsonb_object_keys(expected) k;
 count_rows:=cardinality(keys);
 IF count_rows>4096 OR count_rows>p_rows THEN
  RAISE EXCEPTION 'child registration final epoch budget exceeded' USING ERRCODE='54000';
 END IF;
 SELECT jsonb_object_agg(k,CASE WHEN e.key IS NULL THEN 'null'::jsonb
  ELSE jsonb_build_array(e.generation,e.revision) END)
 INTO actual FROM unnest(keys) k LEFT JOIN kaname.authority_policy_epoch e ON e.key=k;
 IF actual IS DISTINCT FROM expected THEN
  RAISE EXCEPTION 'child registration final epochs changed' USING ERRCODE='P1034';
 END IF;
 at_time:=clock_timestamp();
 selected:=kaname._authority_child_registration_select_v1(prepared,at_time);
 -- До проверки права и отдельного child body здесь не открываются
 -- команды и образы записи. Prepared сохраняется под прежним digest.
 UPDATE pg_temp.kaname_authority_resource_manifest
 SET state='final',decision_at=at_time,registration_body=jsonb_build_object('prepared',prepared,'selected',selected);
 UPDATE pg_temp.kaname_authority_attestation SET decision_at=at_time;
 UPDATE pg_temp.kaname_authority_consumer SET finalized=true;
 RETURN QUERY SELECT at_time,count_rows,1;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE helper record; principal record; BEGIN
 FOR helper IN SELECT oid,oid::regprocedure AS signature,proowner FROM pg_catalog.pg_proc
 WHERE oid IN ('kaname._authority_child_registration_prepare_v1(jsonb,integer,integer)'::regprocedure,
  'kaname._authority_child_registration_finalize_v1(jsonb,integer,integer)'::regprocedure)
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',helper.signature);
  FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee WHERE p.oid=helper.oid AND a.grantee<>helper.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',helper.signature,principal.rolname);
  END LOOP;
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_finalize_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_child_registration_prepare_v1(jsonb,integer,integer);
