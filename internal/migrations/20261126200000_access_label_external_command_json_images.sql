-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- Извлекаем образы OLD и NEW из команды до удаления полей меток.
-- Вместе с телом команды обновляем отпечатки в проверках контракта и готовности.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('_authority_metadata_mirror_command_v1()','52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea','519e6044189b001f6a6b3d94b9e68690ae6491a9fb2e5d309f6b9ca717d14e5a',
   $pairs$[
 [
  "(command->'old'-ARRAY['labels','access_labels']) IS DISTINCT FROM\n     (command->'new'-ARRAY['labels','access_labels'])",
  "((command->'old')-ARRAY['labels','access_labels']) IS DISTINCT FROM\n     ((command->'new')-ARRAY['labels','access_labels'])"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4','0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093',
   $pairs$[
 [
  "52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea",
  "519e6044189b001f6a6b3d94b9e68690ae6491a9fb2e5d309f6b9ca717d14e5a"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f','250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841',
   $pairs$[
 [
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4",
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093"
 ]
]$pairs$::jsonb),
  ('authority_metadata_service_account_access_label_ready_v1()','0af65177bbfcad5e8d4a54502d922ad934de0141b1f63116130377fd184218ae','042ab86ea4d7d0f9deaf4989efa5a51efd43bb8fac1cdcf4ad135ab35d9e5ad7',
   $pairs$[
 [
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4",
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093"
 ],
 [
  "a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f",
  "250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
DO $repin$
DECLARE item record; fn regprocedure; prior_body text; body text; definition text; pair jsonb;
BEGIN
 FOR item IN SELECT * FROM (VALUES
  ('authority_metadata_service_account_access_label_ready_v1()','042ab86ea4d7d0f9deaf4989efa5a51efd43bb8fac1cdcf4ad135ab35d9e5ad7','0af65177bbfcad5e8d4a54502d922ad934de0141b1f63116130377fd184218ae',
   $pairs$[
 [
  "250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841",
  "a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f"
 ],
 [
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093",
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4"
 ]
]$pairs$::jsonb),
  ('_authority_full_contract_storage_v3()','250c74cf3b696e3337a4845f38d748384e524448cd86872fcaf59f2a6961c841','a59db331e044a8960693abd760c379f0de01cb80c02a317496e0eac35d28dc3f',
   $pairs$[
 [
  "0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093",
  "682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4"
 ]
]$pairs$::jsonb),
  ('_authority_crud_storage_v3()','0217a266427178ae68d624340325b5bbd2e8d9d939377db1bebb5396b6af5093','682e0939504415f3796203497d1e747c8e452e63a522bac55de1978cdae815f4',
   $pairs$[
 [
  "519e6044189b001f6a6b3d94b9e68690ae6491a9fb2e5d309f6b9ca717d14e5a",
  "52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea"
 ]
]$pairs$::jsonb),
  ('_authority_metadata_mirror_command_v1()','519e6044189b001f6a6b3d94b9e68690ae6491a9fb2e5d309f6b9ca717d14e5a','52823698e4b0ae99c11735589197cc0e7be627aca9ad3396e05f248241727aea',
   $pairs$[
 [
  "((command->'old')-ARRAY['labels','access_labels']) IS DISTINCT FROM\n     ((command->'new')-ARRAY['labels','access_labels'])",
  "(command->'old'-ARRAY['labels','access_labels']) IS DISTINCT FROM\n     (command->'new'-ARRAY['labels','access_labels'])"
 ]
]$pairs$::jsonb)
 ) AS pins(signature,before_hash,after_hash,changes) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc,pg_get_functiondef(p.oid) INTO STRICT prior_body,definition FROM pg_catalog.pg_proc p
   WHERE p.oid=fn AND p.proowner=current_user::regrole;
  IF encode(sha256(convert_to(prior_body,'UTF8')),'hex') IS DISTINCT FROM item.before_hash THEN
   RAISE EXCEPTION 'Исходное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
  body:=prior_body;
  FOR pair IN SELECT value FROM jsonb_array_elements(item.changes) LOOP
   IF length(body)-length(replace(body,pair->>0,''))<>length(pair->>0) THEN
    RAISE EXCEPTION 'Фрагмент тела функции % не уникален',item.signature USING ERRCODE='55000';
   END IF;
   body:=replace(body,pair->>0,pair->>1);
  END LOOP;
  IF encode(sha256(convert_to(body,'UTF8')),'hex') IS DISTINCT FROM item.after_hash
   OR length(definition)-length(replace(definition,prior_body,''))<>length(prior_body) THEN
   RAISE EXCEPTION 'Расчётный образ функции % изменился',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,prior_body,body);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
     IS DISTINCT FROM item.after_hash THEN
   RAISE EXCEPTION 'Установленное тело функции % изменилось',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Нарушена целостность контракта записи' USING ERRCODE='55000';
 END IF;
END;
$repin$;
-- +goose StatementEnd
