-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приватная подготовка полного снимка для компилятора владельца.
-- Общая блокировка исключает запись поколений, удержание корней исключает
-- конкурентное закрытие поколения другим рабочим процессом.
-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_root_keys_v1(p_roots jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $keys$
DECLARE coordinate jsonb; typ text; identifier text; result jsonb;
BEGIN
 IF jsonb_typeof(p_roots) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'generation roots must be an array' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_roots)>4096 OR octet_length(p_roots::text)>67108864 THEN
  RAISE EXCEPTION 'generation root key budget exceeded' USING ERRCODE='54000';END IF;
 FOR coordinate IN SELECT value FROM jsonb_array_elements(p_roots) LOOP
  IF jsonb_typeof(coordinate) IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'generation root must be an array' USING ERRCODE='42501';END IF;
  IF jsonb_array_length(coordinate)<>2
  OR jsonb_typeof(coordinate->0) IS DISTINCT FROM 'string'
  OR jsonb_typeof(coordinate->1) IS DISTINCT FROM 'string' THEN
   RAISE EXCEPTION 'generation root coordinate malformed' USING ERRCODE='42501';END IF;
  typ:=coordinate->>0;identifier:=coordinate->>1;
  IF typ NOT IN ('iam.account','iam.project') OR identifier=''
  OR octet_length(identifier)>16384 OR identifier ~ '[:#*[:space:][:cntrl:]]' THEN
   RAISE EXCEPTION 'generation root coordinate invalid' USING ERRCODE='42501';END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(jsonb_build_object('key',q.key,'hash',hashtext(q.key COLLATE "C"))
  ORDER BY hashtext(q.key COLLATE "C"),q.key COLLATE "C"),'[]'::jsonb) INTO result
 FROM (SELECT DISTINCT value::text COLLATE "C" AS key FROM jsonb_array_elements(p_roots)) q;
 RETURN result;
END;
$keys$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_latch_require_v1(p_producer boolean)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $latch$
DECLARE proof jsonb; expected_mode text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_producer IS NULL OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN
  RAISE EXCEPTION 'generation participant requires RC' USING ERRCODE='25001';END IF;
 -- Штатная аттестация проверяет сеанс, транзакцию, nonce, вызывающую роль,
 -- контракт, ограды допуска и точный режим общей блокировки.
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'kind' IS DISTINCT FROM 'resource'
 OR proof->>'consumer_abi' IS DISTINCT FROM '2' THEN
  RAISE EXCEPTION 'generation participant requires signed resource frame' USING ERRCODE='42501';END IF;
 IF p_producer THEN
  IF proof->>'consumer_profile' IS DISTINCT FROM 'full' OR NOT coalesce(
   (proof->>'writer_contract'='1' AND proof->>'purpose'='participant')
   OR (proof->>'writer_contract'='2' AND proof->>'purpose'='decision'),false) THEN
   RAISE EXCEPTION 'generation producer requires full metadata frame' USING ERRCODE='42501';END IF;
  expected_mode:='ShareLock';
 ELSE
  IF proof->>'consumer_profile' IS DISTINCT FROM 'resource_pending'
  OR proof->>'purpose' IS DISTINCT FROM 'participant'
  OR proof->>'consumer_finalized' IS DISTINCT FROM 'false' THEN
   RAISE EXCEPTION 'generation worker requires pending resource frame' USING ERRCODE='42501';END IF;
  expected_mode:='RowExclusiveLock';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
  AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
  AND l.locktype='relation' AND l.relation='kaname.authority_producer_population_latch'::regclass
  AND l.mode=expected_mode AND l.granted) THEN
  RAISE EXCEPTION 'generation population latch is not held' USING ERRCODE='42501';END IF;
 RETURN proof;
END;
$latch$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_roots_hold_v1(p_roots jsonb)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $hold$
DECLARE keys jsonb; physical integer; witness jsonb:='[]';
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 -- Запись поколения уже исключена общей блокировкой. Полный набор корней
 -- берём в один проход перед удержанием источников, политики и привязок.
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
  AND l.locktype='advisory' AND l.objsubid=2
  AND l.classid BETWEEN 1262569295::oid AND 1262569306::oid) THEN
  RAISE EXCEPTION 'generation worker root phase already passed' USING ERRCODE='25001';END IF;
 keys:=kaname._authority_access_label_generation_root_keys_v1(p_roots);
 FOR physical IN SELECT DISTINCT (value->>'hash')::integer
  FROM jsonb_array_elements(keys) ORDER BY 1 LOOP
  PERFORM pg_advisory_xact_lock(1262569306,physical);
  witness:=witness||jsonb_build_array(jsonb_build_object('classid',1262569306,
   'objid',(physical::bigint & 4294967295),'objsubid',2,'mode','ExclusiveLock'));
 END LOOP;
 RETURN jsonb_build_object('keys',keys,'held_advisory',witness);
END;
$hold$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_prepare_v1(
 p_model text,p_id text,p_expected text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $prepare$
DECLARE
 first_capture jsonb;held_capture jsonb;root_keys jsonb;holds jsonb;
 fingerprint text;held_fingerprint text;used_rows integer;used_reads integer;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF p_expected IS NOT NULL AND p_expected COLLATE "C" !~ '^[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'generation observation fingerprint malformed' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 2 AND 4096 THEN
  RAISE EXCEPTION 'generation preparation budget invalid' USING ERRCODE='54000';END IF;
 -- Чтение RR передаёт только хеш. Владелец сам выводит полный набор
 -- корней и физические состояния, включая отсутствие прямого корня.
 first_capture:=kaname._authority_access_label_object_generation_capture_v1(p_model,p_id,p_rows,p_reads);
 used_rows:=(first_capture->>'rows')::integer;used_reads:=(first_capture->>'reads')::integer;
 -- Пустое наблюдение передаётся как SQL NULL.
 IF jsonb_array_length(first_capture->'roots')>0 THEN
  fingerprint:=encode(sha256(convert_to(first_capture::text,'UTF8')),'hex');
 END IF;
 IF fingerprint IS DISTINCT FROM p_expected THEN
  RAISE EXCEPTION 'generation observation changed before root holds' USING ERRCODE='40001';END IF;
 SELECT coalesce(jsonb_agg(k.root_key ORDER BY k.root_key::text COLLATE "C"),'[]'::jsonb)
 INTO root_keys FROM (
  SELECT jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}') root_key
   FROM jsonb_array_elements(first_capture->'roots') r
  UNION
  SELECT jsonb_build_array(first_capture#>>'{direct_root,root_type}',first_capture#>>'{direct_root,root_id}')
   WHERE first_capture->'direct_root'<>'null'::jsonb
 ) k;
 -- Корни удерживаются до ожиданий источников, политики и привязок.
 holds:=kaname._authority_access_label_generation_roots_hold_v1(root_keys);
 -- Новый снимок оператора после возможного ожидания. Удержание корней
 -- исключает закрытие другими рабочими процессами, общая блокировка
 -- исключает запись, в том числе ранее отсутствующего корня или выхода.
 held_capture:=kaname._authority_access_label_object_generation_capture_v1(
  p_model,p_id,p_rows-used_rows,p_reads-used_reads);
 used_rows:=used_rows+(held_capture->>'rows')::integer;
 used_reads:=used_reads+(held_capture->>'reads')::integer;
 IF jsonb_array_length(held_capture->'roots')>0 THEN
  held_fingerprint:=encode(sha256(convert_to(held_capture::text,'UTF8')),'hex');
 END IF;
 IF held_capture IS DISTINCT FROM first_capture OR held_fingerprint IS DISTINCT FROM p_expected THEN
  RAISE EXCEPTION 'generation physical census changed under root holds' USING ERRCODE='40001';END IF;
 -- Компилятор владельца получает снимок и доказательство удержаний
 -- корней. Для закрытия поколения ещё нужны полные выходные графы.
 RETURN jsonb_build_object('fingerprint',held_fingerprint,'capture',held_capture,
  'root_keys',holds->'keys','held_advisory',holds->'held_advisory','rows',used_rows,'reads',used_reads);
END;
$prepare$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text; recipient record;
BEGIN
 FOREACH signature IN ARRAY ARRAY[
  '_authority_access_label_generation_root_keys_v1(jsonb)',
  '_authority_access_label_generation_latch_require_v1(boolean)',
  '_authority_access_label_generation_roots_hold_v1(jsonb)',
  '_authority_access_label_generation_prepare_v1(text,text,text,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_access_label_generation_prepare_v1(text,text,text,integer,integer);
DROP FUNCTION kaname._authority_access_label_generation_roots_hold_v1(jsonb);
DROP FUNCTION kaname._authority_access_label_generation_latch_require_v1(boolean);
DROP FUNCTION kaname._authority_access_label_generation_root_keys_v1(jsonb);
