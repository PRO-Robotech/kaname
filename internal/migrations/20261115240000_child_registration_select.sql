-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: связывание зарезервированного FGA слота с программой создания.
-- Приёмка: docs/engineering/acceptance/user-child-registration.md
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Вызывающий закрытый финализатор передаёт единственное время решения.
-- Здесь собираются образы и связывается слот; предметные записи отсутствуют.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_select_v1(p_prepared jsonb,p_decision_at timestamptz)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 proof jsonb; sequence_program jsonb; frozen jsonb; intent jsonb; reservations jsonb;
 body jsonb; chosen jsonb:='[]'::jsonb; journal jsonb; tuple_value jsonb;
 physical jsonb; packed jsonb; audit_row jsonb; outbox jsonb;
 tx_at timestamptz:=transaction_timestamp(); command_ordinal integer; audit_ordinal integer; maximum_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_profile' IS DISTINCT FROM 'resource_source_pending'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' OR current_setting('transaction_isolation')<>'read committed'
  OR jsonb_typeof(p_prepared) IS DISTINCT FROM 'object' OR octet_length(p_prepared::text)>67108864
  OR p_prepared->'backend' IS DISTINCT FROM proof->'backend'
  OR p_prepared->'transaction_id' IS DISTINCT FROM proof->'transaction_id'
  OR p_prepared->'nonce' IS DISTINCT FROM proof->'nonce' THEN
  RAISE EXCEPTION 'child registration selection requires the same pending attempt' USING ERRCODE='42501';
 END IF;
 sequence_program:=kaname._authority_sequence_store_v3();
 frozen:=sequence_program->'frozen';
 intent:=p_prepared->'intent';
 reservations:=p_prepared->'reservations';
 maximum_count:=(sequence_program->>'maximum_count')::integer;
 IF sequence_program->>'family' IS DISTINCT FROM 'resource'
  OR sequence_program->'selected' IS DISTINCT FROM 'null'::jsonb
  OR maximum_count NOT BETWEEN 0 AND 1
  OR frozen->>'kind' IS DISTINCT FROM 'child_registration'
  OR frozen->'intent' IS DISTINCT FROM intent
  OR frozen->>'prepared_digest' IS DISTINCT FROM encode(sha256(convert_to(p_prepared::text,'UTF8')),'hex') THEN
  RAISE EXCEPTION 'child registration selection lost the held preparation' USING ERRCODE='42501';
 END IF;
 body:=kaname._authority_child_registration_program_v1(
  p_prepared->'witness',p_prepared->'source_index',p_prepared->'catalog',p_prepared->'catalog_rows',
  intent->>'actor',reservations->>'audit_id',p_decision_at,tx_at,(reservations->>'parent_incarnation')::uuid);
 IF body->>'outcome'='create' THEN
  journal:=body#>'{parent_write,journal}';
  tuple_value:=body#>'{certificate,tuple}';
  IF maximum_count<>1 OR reservations->>'fga_slot' IS DISTINCT FROM '1'
   OR sequence_program#>>'{maximum,0,table}' IS DISTINCT FROM 'fga_outbox'
   OR frozen->'tuple' IS DISTINCT FROM tuple_value
   OR journal IS DISTINCT FROM jsonb_build_object('event_type','fga.tuple.write','created_at',tx_at,
    'payload',jsonb_build_object('user',tuple_value->'User','relation',tuple_value->'Relation',
     'object',tuple_value->'Object','source_version',body->'source_version')) THEN
   RAISE EXCEPTION 'child registration final journal escaped the held slot' USING ERRCODE='42501';
  END IF;
  IF EXISTS(
   SELECT FROM jsonb_array_elements(body#>'{program,steps}') step
   CROSS JOIN LATERAL jsonb_each(kaname._authority_resource_registration_step_operations_v2(
    body->'certificate',body->'program',step)) operation
   WHERE NOT coalesce((p_prepared#>'{maximum,operations}')->operation.key @> operation.value,false)) THEN
   RAISE EXCEPTION 'child registration final operations exceed the held maximum' USING ERRCODE='42501';
  END IF;
  -- Общий компилятор собирает образы зеркала, связей и журнала. Аудит
  -- пользователя готовит child program, поэтому модульный аудит здесь выключен.
  physical:=kaname._authority_resource_registration_physical_v2(body->'certificate',body->'sources',
   jsonb_set(body->'program','{audit_required}','false'::jsonb),reservations,tx_at);
  outbox:=physical#>'{outboxes,0}';
  IF jsonb_array_length(physical->'outboxes') IS DISTINCT FROM 1
   OR outbox->'row' IS DISTINCT FROM journal
   OR jsonb_array_length(physical->'audits') IS DISTINCT FROM 0 THEN
   RAISE EXCEPTION 'child registration final physical program differs from the journal' USING ERRCODE='42501';
  END IF;
  command_ordinal:=(outbox->>'command')::integer;
  audit_row:=body->'audit';
  audit_ordinal:=jsonb_array_length(physical->'commands')+1;
  physical:=physical||jsonb_build_object(
   'commands',(physical->'commands')||jsonb_build_array(jsonb_build_object(
    'kind','registration_audit','row',audit_row,'operations','{"audit_outbox":["INSERT"]}'::jsonb)),
   'audits',jsonb_build_array(jsonb_build_object('command',audit_ordinal,'row',audit_row)),
   'work',(physical->>'work')::integer+2);
  packed:=kaname._authority_resource_registration_pack_v2(p_prepared->'maximum',physical,
   jsonb_build_object('outcome','create','source_version',body->'source_version'));
  body:=body||jsonb_build_object('registration_body',packed);
  chosen:=jsonb_build_array(jsonb_build_object('ordinal',1,
   'origin',jsonb_build_object('family','resource.registration','command',command_ordinal,'ordinal',1),
   'row',journal-'created_at'));
 END IF;
 PERFORM kaname._authority_sequence_bind_v3(chosen,p_decision_at);
 RETURN body||jsonb_build_object('decision_at',p_decision_at);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $$ DECLARE principal record;BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_child_registration_select_v1(jsonb,timestamptz) FROM PUBLIC;
 FOR principal IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_select_v1(jsonb,timestamptz)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_select_v1(jsonb,timestamptz) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_select_v1(jsonb,timestamptz);
