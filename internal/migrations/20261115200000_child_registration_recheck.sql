-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: повторное чтение под общим ограждением владельцев родителя.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Закрытый шаг подготовки до окончательного DecisionAt. Вызывающий компилятор
-- передаёт закреплённый каталог и индекс предварительного чтения. Функция
-- подтверждает владельцев и перечитывает их источники на той же транзакции.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_recheck_v1(
 p_child_type text,p_child_id text,p_before jsonb,p_index jsonb,p_catalog jsonb,p_rows integer,p_reads integer)
RETURNS TABLE(witness jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proof jsonb; ownership jsonb; parent_scopes jsonb; scope jsonb; current_scope record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 proof:=kaname.authority_protocol_attestation();
 IF proof IS NULL OR proof->>'writer_contract' IS DISTINCT FROM '2'
  OR proof->>'kind' IS DISTINCT FROM 'resource' OR proof->>'purpose' IS DISTINCT FROM 'participant'
  OR proof->>'consumer_abi' IS DISTINCT FROM '2' OR proof->>'consumer_finalized' IS DISTINCT FROM 'false'
  OR NOT coalesce(proof->>'consumer_profile' IN ('resource_pending','resource_source_pending'),false)
  OR current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'child registration recheck requires a pending full resource transaction' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(p_before) IS DISTINCT FROM 'object' OR octet_length(p_before::text)>8388608
  OR jsonb_typeof(p_before->'parent_model') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_before->'parent_id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_before->'child_type') IS DISTINCT FROM 'string'
  OR jsonb_typeof(p_before->'child_id') IS DISTINCT FROM 'string'
  OR p_before->>'child_type' IS DISTINCT FROM p_child_type
  OR p_before->>'child_id' IS DISTINCT FROM p_child_id THEN
  RAISE EXCEPTION 'invalid child registration snapshot' USING ERRCODE='42501';
 END IF;

 ownership:=kaname._authority_resource_registration_saved_scopes_v2(
  p_index,p_catalog,p_before->>'parent_model',p_before->>'parent_id');
 parent_scopes:=ownership->'scopes';
 IF jsonb_typeof(parent_scopes) IS DISTINCT FROM 'array' OR jsonb_array_length(parent_scopes)=0 THEN
  RAISE EXCEPTION 'child registration parent scopes unavailable' USING ERRCODE='42501';
 END IF;
 FOR scope IN SELECT value FROM jsonb_array_elements(parent_scopes) LOOP
  IF coalesce(scope->>'AccountID','')=''
   OR (proof->>'mode'='accounts' AND NOT coalesce((proof->'accounts') ? (scope->>'AccountID'),false)) THEN
   RAISE EXCEPTION 'child registration parent account fence missing' USING ERRCODE='42501';
  END IF;
 END LOOP;
 SELECT s.logical_rows,s.logical_reads INTO STRICT current_scope
 FROM kaname._authority_resource_required_reread_v2(p_index,ownership->'required','{}',p_rows,p_reads) s;

 -- Эта команда получает свежий снимок RC после всех ожиданий. Функция
 -- capture держится одного снимка внутри команды и не берёт новых блокировок.
 SELECT c.witness,c.logical_rows,c.logical_reads INTO STRICT witness,logical_rows,logical_reads
 FROM kaname._authority_child_registration_capture_v1(p_child_type,p_child_id,
  p_rows-current_scope.logical_rows,p_reads-current_scope.logical_reads) c;
 IF witness IS DISTINCT FROM p_before THEN
  RAISE EXCEPTION 'child registration state changed after capture' USING ERRCODE='P1034';
 END IF;
 logical_rows:=logical_rows+current_scope.logical_rows;
 logical_reads:=logical_reads+current_scope.logical_reads;
 RETURN NEXT;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 FOR principal IN SELECT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_recheck_v1(text,text,jsonb,jsonb,jsonb,integer,integer);
