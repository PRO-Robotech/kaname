-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приёмка: docs/engineering/acceptance/grant-authority-matches-the-whole-effect.md §8.3.
-- kaname#1034: свежая полная проверка подписанного lockset на каждом guard;
-- не кэш, не пропуск OLD/NEW и не разрешение public activation.
-- CREATE OR REPLACE сохраняет владельца, OID, signature и runtime ACL.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; expected_mode text; root_present boolean; accounts_present boolean;
BEGIN
 -- kaname#1034: locking read не позволяет старому RR/SSI snapshot сохранить
 -- compatibility после strict commit. У participant этот row lock уже взят entry.
 SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose' IN ('transition','participant') AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose' IN ('decision','participant') AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
  RAISE EXCEPTION 'authority transaction attestation mismatch' USING ERRCODE='42501';
 END IF;
 expected_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 -- Один свежий snapshot lock manager на invocation, не кэш между guards.
 -- MATERIALIZED запрещает повторное чтение pg_locks для каждого account key.
 -- Все проверки ниже читают только этот локальный набор текущего backend/DB.
 WITH held AS MATERIALIZED (
  SELECT l.classid,l.objid,l.mode
  FROM pg_catalog.pg_locks l
  WHERE l.pid=pg_backend_pid()
   AND l.database=(SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname=current_database())
   AND l.locktype='advisory' AND l.objsubid=2 AND l.granted
   AND l.classid IN (1262569283::oid,1262569281::oid)
 ), root_lock AS (
  SELECT EXISTS(SELECT 1 FROM held h WHERE h.classid=1262569283::oid AND h.objid=0::oid AND h.mode=expected_mode) AS present
 )
 SELECT r.present,
  CASE WHEN r.present AND proof->>'mode'='accounts' THEN
   NOT EXISTS (
    SELECT DISTINCT (hashtext(value)::bigint & 4294967295)::oid
     FROM jsonb_array_elements_text(proof->'accounts')
    EXCEPT
    SELECT h.objid FROM held h WHERE h.classid=1262569281::oid AND h.mode='ExclusiveLock'
   )
  ELSE true END
 INTO root_present,accounts_present FROM root_lock r;
 -- Сначала тот же root отказ; malformed accounts не вычисляются до него.
 IF NOT root_present THEN
  RAISE EXCEPTION 'authority cluster barrier missing' USING ERRCODE='42501';
 END IF;
 IF NOT accounts_present THEN
  RAISE EXCEPTION 'authority account barrier missing' USING ERRCODE='42501';
 END IF;
 RETURN proof;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_protocol_attestation() FROM PUBLIC;

-- +goose Down
-- Точная предыдущая функция, после того же drain.
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; temp_oid oid; current_invoker oid; strict_mode boolean; k integer; expected_mode text;
BEGIN
 -- kaname#1034: locking read не позволяет старому RR/SSI snapshot сохранить
 -- compatibility после strict commit. У participant этот row lock уже взят entry.
 SELECT enforcement='strict' INTO STRICT strict_mode FROM kaname.authority_writer_protocol WHERE singleton FOR SHARE;
 temp_oid:=to_regclass('pg_temp.kaname_authority_attestation');
 IF temp_oid IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid=temp_oid AND relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AND relpersistence='t' AND relkind='r') THEN
  RAISE EXCEPTION 'untrusted authority attestation storage' USING ERRCODE='42501';
 END IF;
 SELECT to_jsonb(a) INTO proof FROM pg_temp.kaname_authority_attestation a;
 IF proof IS NULL THEN
  IF NOT strict_mode THEN RETURN NULL; END IF;
  RAISE EXCEPTION 'authority transaction attestation required' USING ERRCODE='42501';
 END IF;
 SELECT oid INTO STRICT current_invoker FROM pg_catalog.pg_roles WHERE rolname=coalesce(nullif(current_setting('role'),'none'),session_user);
 IF (proof->>'backend')::integer<>pg_backend_pid()
 OR (proof->>'transaction_id')::xid8 IS DISTINCT FROM pg_current_xact_id_if_assigned()
 OR (proof->>'invoker_oid')::oid<>current_invoker OR proof->>'nonce' IS NULL
 OR NOT EXISTS(SELECT 1 FROM kaname.authority_semantic_identity a,kaname.authority_writer_protocol p WHERE a.singleton AND p.singleton AND ((proof->>'purpose' IN ('transition','participant') AND p.enforcement='compatibility' AND a.phase='prepared') OR (proof->>'purpose' IN ('decision','participant') AND p.enforcement='strict' AND a.phase='active')) AND a.protocol_version=(proof->>'protocol')::integer AND p.protocol_version=a.protocol_version AND a.model_id=proof->>'model_id' AND a.catalog_id=proof->>'catalog_id' AND a.projector_version=proof->>'projector_version') THEN
  RAISE EXCEPTION 'authority transaction attestation mismatch' USING ERRCODE='42501';
 END IF;
 expected_mode:=CASE WHEN proof->>'mode'='global' THEN 'ExclusiveLock' ELSE 'ShareLock' END;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569283::oid AND objid=0::oid AND objsubid=2 AND mode=expected_mode AND granted) THEN
  RAISE EXCEPTION 'authority cluster barrier missing' USING ERRCODE='42501';
 END IF;
 IF proof->>'mode'='accounts' THEN
  FOR k IN SELECT DISTINCT hashtext(value) FROM jsonb_array_elements_text(proof->'accounts') LOOP
   IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=1262569281::oid AND objid=(k::bigint & 4294967295)::oid AND objsubid=2 AND mode='ExclusiveLock' AND granted) THEN
    RAISE EXCEPTION 'authority account barrier missing' USING ERRCODE='42501';
   END IF;
  END LOOP;
 END IF;
 RETURN proof;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION kaname.authority_protocol_attestation() FROM PUBLIC;
