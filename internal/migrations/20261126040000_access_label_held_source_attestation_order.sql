-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Отказ неподписанного physical-source вызова предшествует чтению temp consumer.
-- Сохраняем signed attestation, finalized consumer и закрытый INVOKER boundary.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)','0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a','908f2c2415c24df236d93178082b33a7c89648a4997fac0b89f958b44ce826bc',
  $changes$[
 [
  " OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'\n OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;",
  " OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;\n -- Неподписанный вызов отклоняем до планирования запроса к временной таблице.\n -- Attestation подтверждает её существование; отдельный запрос сохраняет\n -- исходное требование finalized для физического чтения.\n IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478','57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5',
  $changes$[
 [
  "0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a",
  "908f2c2415c24df236d93178082b33a7c89648a4997fac0b89f958b44ce826bc"
 ]
]$changes$::jsonb),
 ('authority_metadata_service_account_access_label_ready_v1()','60186d3b97e1e4e799c5ce40a8c2c7045b28934706e2f7b46f57adb728a1355d','a1da00bd621a5f851a407d174f21f54045a8508d1435ab55f7813c7c0e81fdae',
  $changes$[
 [
  "f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478",
  "57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5"
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

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $install$
DECLARE step record; pair jsonb; found_oid oid; definition text; original text;
BEGIN
 FOR step IN SELECT * FROM (VALUES
 ('authority_metadata_service_account_access_label_ready_v1()','a1da00bd621a5f851a407d174f21f54045a8508d1435ab55f7813c7c0e81fdae','60186d3b97e1e4e799c5ce40a8c2c7045b28934706e2f7b46f57adb728a1355d',
  $changes$[
 [
  "57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5",
  "f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478"
 ]
]$changes$::jsonb),
 ('authority_metadata_access_label_ready_v2(text)','57682cf2c133a749ed3afba138506807ac08ae6d83b4411f198a06fa285a62f5','f3f807f346b7e6809194341239ca3f5916c2860fa0d1fe5a24acef0296e3a478',
  $changes$[
 [
  "908f2c2415c24df236d93178082b33a7c89648a4997fac0b89f958b44ce826bc",
  "0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a"
 ]
]$changes$::jsonb),
 ('_authority_metadata_access_label_held_source_v1(integer,text,text,integer,integer)','908f2c2415c24df236d93178082b33a7c89648a4997fac0b89f958b44ce826bc','0b04bffacc953161b564752d675e9e60656348aa98c3bd13666dee621609e88a',
  $changes$[
 [
  " OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;\n -- Неподписанный вызов отклоняем до планирования запроса к временной таблице.\n -- Attestation подтверждает её существование; отдельный запрос сохраняет\n -- исходное требование finalized для физического чтения.\n IF NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;",
  " OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'\n OR NOT EXISTS(SELECT 1 FROM pg_temp.kaname_authority_consumer WHERE finalized) THEN\n  RAISE EXCEPTION 'metadata physical capture requires finalized full consumer' USING ERRCODE='42501';END IF;"
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
