-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Только ранний закрытый source kind 5 для permanent project binding.
-- Held kind 5 недоступен до появления transaction-bound receipt захвата.
-- Это примитив чтения, а не полный registration scope certificate или writer.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)','0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78','31108b790d06a20aa54a2f5685ffe48feb83b99bc74506588c22a759c3aedb9b',
  $changes$[
 [
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';",
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';\n WHEN 5 THEN table_name:='object_project_binding';predicate:='r.object_type=$1 AND r.object_id=$2';"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f','c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb',
  $changes$[
 [
  "0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78",
  "31108b790d06a20aa54a2f5685ffe48feb83b99bc74506588c22a759c3aedb9b"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','c95b06623969b5dd8dc1c49d79ce74a370eed7fa300a9b7867a0e0758fbebb43','8749126dacec2773f4005f80c25019024f907cc027bce43edd0ae2a9d6bf2c71',
  $changes$[
 [
  "fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f",
  "c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $private$
DECLARE target regprocedure;recipient record;
BEGIN
 FOREACH target IN ARRAY ARRAY[
  'kaname._authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','8749126dacec2773f4005f80c25019024f907cc027bce43edd0ae2a9d6bf2c71','c95b06623969b5dd8dc1c49d79ce74a370eed7fa300a9b7867a0e0758fbebb43',
  $changes$[
 [
  "c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb",
  "fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','c0d015f355dc1dae5fe3e10e7f5a51630c922f6405cc89ada7e809e4e4f931eb','fc78cf28e5acf0bec74cf60f8dfb792051ad2d9a798fdc8129c20a60e43f1a6f',
  $changes$[
 [
  "31108b790d06a20aa54a2f5685ffe48feb83b99bc74506588c22a759c3aedb9b",
  "0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)','31108b790d06a20aa54a2f5685ffe48feb83b99bc74506588c22a759c3aedb9b','0b20a22f6bdcc1e18e9de51fda69bfac31a86807e3f265ef05bf74c42d915f78',
  $changes$[
 [
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';\n WHEN 5 THEN table_name:='object_project_binding';predicate:='r.object_type=$1 AND r.object_id=$2';",
  " WHEN 4 THEN table_name:='resource_registration_scope';predicate:='r.object_type=$1 AND r.object_id=$2';"
 ]
]$changes$::jsonb)
 ) AS expected(signature,old_digest,new_digest,changes) LOOP
  found_oid:=pg_catalog.to_regprocedure('kaname.'||step.signature);
  SELECT pg_catalog.pg_get_functiondef(p.oid),p.prosrc INTO STRICT definition,original
  FROM pg_catalog.pg_proc p WHERE p.oid=found_oid;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.old_digest THEN
   RAISE EXCEPTION 'metadata carrier predecessor differs: %',step.signature;END IF;
  FOR pair IN SELECT value FROM jsonb_array_elements(step.changes) LOOP
   IF octet_length(original)-octet_length(replace(original,pair->>0,''))<>octet_length(pair->>0) THEN
    RAISE EXCEPTION 'metadata carrier patch does not match once: %',step.signature;END IF;
   original:=replace(original,pair->>0,pair->>1);
   definition:=replace(definition,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(original,'UTF8')),'hex') IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier expected body differs: %',step.signature;END IF;
  EXECUTE definition;
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=found_oid)
   IS DISTINCT FROM step.new_digest THEN
   RAISE EXCEPTION 'metadata carrier installed body differs: %',step.signature;END IF;
 END LOOP;
END;
$install$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $private$
DECLARE target regprocedure;recipient record;
BEGIN
 FOREACH target IN ARRAY ARRAY[
  'kaname._authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)'::regprocedure] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',target);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=target AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',target,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd
