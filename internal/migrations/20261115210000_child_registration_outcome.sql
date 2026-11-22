-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: исход регистрации на окончательное время решения PostgreSQL.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Компилятор передаёт снимок, заново прочитанный под ограждением, после
-- проверки права пользователя. Функция не обращается к таблицам и не пишет.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_outcome_v1(p_witness jsonb,p_decision_at timestamptz)
RETURNS TABLE(outcome text,source_version timestamptz)
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 min_version constant timestamptz:='0001-01-01 00:00:00+00';
 max_version constant timestamptz:='9999-12-31 23:59:59.999999+00';
 child_version timestamptz; replay_version timestamptz; version_watermark timestamptz;
 policy jsonb; max_children integer; max_creates integer; window_seconds integer;
 live_children integer; recent_creations jsonb; window_start timestamptz; oldest_receipt timestamptz;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_decision_at IS NULL OR p_decision_at NOT BETWEEN min_version AND max_version
  OR jsonb_typeof(p_witness) IS DISTINCT FROM 'object' OR octet_length(p_witness::text)>8388608 THEN
  RAISE EXCEPTION 'invalid child registration decision input' USING ERRCODE='22023';
 END IF;

 IF p_witness->>'parent_version' IS NULL THEN
  RETURN QUERY SELECT 'parent_missing'::text,NULL::timestamptz;
  RETURN;
 END IF;
 IF p_witness->>'closed_at' IS NOT NULL THEN
  RETURN QUERY SELECT 'parent_closed'::text,NULL::timestamptz;
  RETURN;
 END IF;
 child_version:=(p_witness->>'child_version')::timestamptz;
 replay_version:=(p_witness->>'replay_version')::timestamptz;
 IF child_version IS NOT NULL THEN
  IF child_version=replay_version THEN
   IF replay_version NOT BETWEEN min_version AND max_version THEN
    RAISE EXCEPTION 'child registration replay version out of range' USING ERRCODE='22023';
   END IF;
   RETURN QUERY SELECT 'replay'::text,replay_version;
  ELSE
   RETURN QUERY SELECT 'child_occupied'::text,NULL::timestamptz;
  END IF;
  RETURN;
 END IF;

 policy:=p_witness->'policy';
 max_children:=(policy->>'MaxChildren')::integer;
 max_creates:=(policy->>'MaxCreates')::integer;
 window_seconds:=(policy->>'WindowSeconds')::integer;
 live_children:=(p_witness->>'live_children')::integer;
 recent_creations:=p_witness->'recent_creations';
 IF (max_children>0 AND max_creates>0 AND window_seconds>0
  AND live_children BETWEEN 0 AND max_children) IS NOT TRUE
  OR jsonb_typeof(recent_creations) IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'invalid child registration quota snapshot' USING ERRCODE='22023';
 END IF;
 IF jsonb_array_length(recent_creations)>least(max_creates,100000) THEN
  RAISE EXCEPTION 'child registration receipt count out of range' USING ERRCODE='22023';
 END IF;
 IF live_children=max_children THEN
  RETURN QUERY SELECT 'capacity'::text,NULL::timestamptz;
  RETURN;
 END IF;

 IF jsonb_array_length(recent_creations)=max_creates THEN
  -- Снимок хранит последние MaxCreates квитанций по убыванию времени.
  -- При обратном ходе часов уже использованный допуск сохраняет расход.
  window_start:=p_decision_at-make_interval(secs=>window_seconds);
  oldest_receipt:=(recent_creations->>-1)::timestamptz;
  IF oldest_receipt IS NULL OR NOT isfinite(oldest_receipt) THEN
   RAISE EXCEPTION 'invalid child registration receipt time' USING ERRCODE='22023';
  END IF;
  IF oldest_receipt>window_start THEN
   RETURN QUERY SELECT 'rate'::text,NULL::timestamptz;
   RETURN;
  END IF;
 END IF;

 version_watermark:=(p_witness->>'version_watermark')::timestamptz;
 IF version_watermark>=max_version THEN
  RAISE EXCEPTION 'child registration source version exhausted' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT 'create'::text,greatest(p_decision_at,version_watermark+interval '1 microsecond');
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._authority_child_registration_outcome_v1(jsonb,timestamptz) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 FOR principal IN SELECT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_outcome_v1(jsonb,timestamptz)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_outcome_v1(jsonb,timestamptz) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_outcome_v1(jsonb,timestamptz);
