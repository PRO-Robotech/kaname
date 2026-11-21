// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Эталон и проверки исполняются в одной выделенной owner-сессии.
// ROLLBACK удаляет тестовый эталон при успехе; defer закрывает транзакцию при ошибке.
func TestResourceCaptureIndexMaterializationMatchesFrozenReference(t *testing.T) {
	ctx, admin, _ := authorityTestDB(t)
	request, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	conn, err := admin.Acquire(request)
	require.NoError(t, err)
	defer conn.Release()
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, rollbackErr := conn.Exec(cleanup, "ROLLBACK")
		require.NoError(t, rollbackErr)
	}()
	_, err = conn.Exec(request, resourceCaptureIndexMaterializationOracleSQL)
	require.NoError(t, err)
}

const resourceCaptureIndexMaterializationOracleSQL = `-- Run as migration owner against candidate migrations, psql -v ON_ERROR_STOP=1 -f this-file.
-- No runtime roles/grants. Reference exists only in this rolled-back test transaction.

BEGIN;
-- TEST ONLY: exact R291 function, only schema/name changed. Execute inside oracle transaction.
CREATE FUNCTION pg_temp.capture_index_r291_reference(p_sources jsonb,p_limit integer) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result jsonb:='{}'::jsonb; source jsonb; state_text jsonb; state jsonb;
 item_key text; kind integer; expected_width integer; n integer; offset_value integer;
 total integer:=0; decoded jsonb; null_project boolean;
BEGIN
 IF p_limit IS NULL OR p_limit<0 OR p_limit>100000
 OR jsonb_typeof(p_sources) IS DISTINCT FROM 'array'
 OR jsonb_array_length(p_sources)>4096 THEN
  RAISE EXCEPTION 'resource capture inventory exceeds budget' USING ERRCODE='54000';
 END IF;
 FOR source IN SELECT value FROM jsonb_array_elements(p_sources) LOOP
  IF jsonb_typeof(source) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(source))<>5
  OR jsonb_typeof(source->'kind') IS DISTINCT FROM 'number'
  OR coalesce(source->>'kind','') !~ '^[1-9][0-9]?$'
  OR jsonb_typeof(source->'type') IS DISTINCT FROM 'string'
  OR jsonb_typeof(source->'id') IS DISTINCT FROM 'string'
  OR jsonb_typeof(source->'projection') IS DISTINCT FROM 'string'
  OR jsonb_typeof(source->'states') IS DISTINCT FROM 'array'
  OR coalesce(source->>'type','')='' OR coalesce(source->>'id','')='' THEN
   RAISE EXCEPTION 'resource capture shape is invalid' USING ERRCODE='22023';
  END IF;
  kind:=(source->>'kind')::integer;
  IF kind<1 OR kind>37 THEN
   RAISE EXCEPTION 'unknown resource capture kind' USING ERRCODE='0A000';
  END IF;
  IF kind NOT IN (32,33,34) AND source->>'projection'<>'' THEN
   RAISE EXCEPTION 'unexpected resource source projection' USING ERRCODE='22023';
  END IF;
  IF kind IN (32,33,34) THEN
   BEGIN
    IF jsonb_typeof((source->>'projection')::jsonb) IS DISTINCT FROM 'object' THEN
     RAISE EXCEPTION 'resource source projection must be an object' USING ERRCODE='22023';
    END IF;
   EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'invalid resource source projection JSON' USING ERRCODE='22023';
   END;
  END IF;
  item_key:=jsonb_build_array(kind,source->>'type',source->>'id',source->>'projection')::text;
  IF result ? item_key THEN
   RAISE EXCEPTION 'duplicate resource capture predicate' USING ERRCODE='22023';
  END IF;
  total:=total+jsonb_array_length(source->'states');
  IF total>p_limit THEN
   RAISE EXCEPTION 'resource capture inventory row budget exceeded' USING ERRCODE='54000';
  END IF;
  decoded:='[]'::jsonb;
  FOR state_text IN SELECT value FROM jsonb_array_elements(source->'states') LOOP
   IF jsonb_typeof(state_text) IS DISTINCT FROM 'string' THEN
    RAISE EXCEPTION 'resource state must be encoded witness' USING ERRCODE='22023';
   END IF;
   BEGIN
    state:=(state_text #>> '{}')::jsonb;
   EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'invalid resource state JSON' USING ERRCODE='22023';
   END;
   IF jsonb_typeof(state) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'invalid resource state shape' USING ERRCODE='22023';
   END IF;
   n:=jsonb_array_length(state);
   expected_width:=CASE kind WHEN 29 THEN 12 WHEN 32 THEN 9 WHEN 34 THEN 12 ELSE 3 END;
   IF n<>expected_width AND NOT (kind=33 AND n=6) THEN
    RAISE EXCEPTION 'resource state tuple width mismatch' USING ERRCODE='22023';
   END IF;
   FOR offset_value IN 0..(n/3-1) LOOP
    null_project:=(kind=29 AND offset_value=3) OR (kind=33 AND n=6 AND offset_value=1);
    IF null_project AND state->(offset_value*3)='null'::jsonb
     AND state->(offset_value*3+1)='null'::jsonb AND state->(offset_value*3+2)='null'::jsonb THEN
     CONTINUE;
    END IF;
    IF jsonb_typeof(state->(offset_value*3)) IS DISTINCT FROM 'string'
    OR coalesce(state->>(offset_value*3),'') !~ '^[0-9]+$'
    OR jsonb_typeof(state->(offset_value*3+1)) IS DISTINCT FROM 'string'
    OR coalesce(state->>(offset_value*3+1),'') !~ '^\([0-9]+,[0-9]+\)$'
    OR jsonb_typeof(state->(offset_value*3+2)) IS DISTINCT FROM 'object' THEN
     RAISE EXCEPTION 'resource tuple witness is incomplete' USING ERRCODE='22023';
    END IF;
   END LOOP;
   decoded:=decoded||jsonb_build_array(state);
  END LOOP;
  result:=result||jsonb_build_object(item_key,jsonb_build_object('source',source,'states',decoded));
 END LOOP;
 RETURN result;
END $$;

CREATE FUNCTION pg_temp.capture_case(label text, input jsonb, lim integer,
 expected_state text DEFAULT '00000', expected_message text DEFAULT NULL)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE old_result jsonb;new_result jsonb; old_state text:='00000';new_state text:='00000';old_message text;new_message text;
BEGIN
 BEGIN old_result:=pg_temp.capture_index_r291_reference(input,lim);
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS old_state=RETURNED_SQLSTATE,old_message=MESSAGE_TEXT;END;
 BEGIN new_result:=kaname._authority_resource_capture_index_v2(input,lim);
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS new_state=RETURNED_SQLSTATE,new_message=MESSAGE_TEXT;END;
 IF old_state IS DISTINCT FROM new_state OR old_message IS DISTINCT FROM new_message
 OR old_result IS DISTINCT FROM new_result OR old_state IS DISTINCT FROM expected_state
 OR (expected_message IS NOT NULL AND old_message IS DISTINCT FROM expected_message) THEN
 RAISE EXCEPTION 'oracle % failed: reference % %, candidate % %, expected % %',label,old_state,old_message,new_state,new_message,expected_state,expected_message; END IF;
END $$;
DO $$
DECLARE s jsonb:=jsonb_build_object('kind',1,'type','t','id','a','projection','','states','[]'::jsonb);
 bad jsonb;state jsonb;trip jsonb:='["1","(0,1)",{"payload":"preserve"}]';sources jsonb;
 k integer;w integer;i integer;fld text;val jsonb;
BEGIN
 PERFORM pg_temp.capture_case('empty','[]',0);
 FOREACH k IN ARRAY ARRAY[-1,100001] LOOP PERFORM pg_temp.capture_case('invalid limit','[]',k,'54000');END LOOP;
 PERFORM pg_temp.capture_case('null limit','[]',NULL,'54000');
 FOR val IN SELECT value FROM jsonb_array_elements('[null,{},true,1,"x"]') LOOP
  PERFORM pg_temp.capture_case('inventory type',val,1,'54000');END LOOP;
 PERFORM pg_temp.capture_case('sql null inventory',NULL,1,'54000');
 FOR val IN SELECT value FROM jsonb_array_elements('[null,[],true,1,"x"]') LOOP
  PERFORM pg_temp.capture_case('source type',jsonb_build_array(val),1,'22023');END LOOP;
 FOREACH fld IN ARRAY ARRAY['kind','type','id','projection','states'] LOOP
  PERFORM pg_temp.capture_case('missing '||fld,jsonb_build_array(s-fld),1,'22023');
  FOR val IN SELECT value FROM jsonb_array_elements('[null,{},[],true,1,"x"]') LOOP
   IF (fld='kind' AND val='1'::jsonb) OR (fld='states' AND val='[]'::jsonb)
    OR (fld IN ('type','id','projection') AND jsonb_typeof(val)='string') THEN CONTINUE; END IF;
   PERFORM pg_temp.capture_case('wrong field type '||fld,jsonb_build_array(jsonb_set(s,ARRAY[fld],val)),1,'22023');
  END LOOP;
 END LOOP;
 PERFORM pg_temp.capture_case('extra field',jsonb_build_array(s||'{"extra":true}'),1,'22023');
 FOREACH fld IN ARRAY ARRAY['type','id'] LOOP PERFORM pg_temp.capture_case('empty '||fld,jsonb_build_array(jsonb_set(s,ARRAY[fld],'""')),1,'22023');END LOOP;
 FOR val IN SELECT value FROM jsonb_array_elements('[0,-1,1.0,100,"1"]') LOOP
  PERFORM pg_temp.capture_case('kind lexical',jsonb_build_array(s||jsonb_build_object('kind',val)),1,'22023');END LOOP;
 FOREACH k IN ARRAY ARRAY[38,99] LOOP PERFORM pg_temp.capture_case('unknown kind',jsonb_build_array(s||jsonb_build_object('kind',k)),1,'0A000');END LOOP;
 PERFORM pg_temp.capture_case('unexpected projection',jsonb_build_array(s||'{"projection":"{}"}'),1,'22023');
 FOR k IN 1..37 LOOP
  bad:=s||jsonb_build_object('kind',k,'projection',CASE WHEN k IN (32,33,34) THEN '{}' ELSE '' END);
  w:=CASE k WHEN 29 THEN 4 WHEN 32 THEN 3 WHEN 34 THEN 4 ELSE 1 END;
  state:='[]';FOR i IN 1..w LOOP state:=state||trip;END LOOP;
  PERFORM pg_temp.capture_case('kind width '||k,jsonb_build_array(bad||jsonb_build_object('states',jsonb_build_array(state::text))),1);
  PERFORM pg_temp.capture_case('wrong width '||k,jsonb_build_array(bad||jsonb_build_object('states',jsonb_build_array('[]'))),1,'22023');
  IF k IN (32,33,34) THEN
   FOREACH fld IN ARRAY ARRAY['','broken','[]','null','true','1','"str"'] LOOP
    PERFORM pg_temp.capture_case('bad projection',jsonb_build_array(bad||jsonb_build_object('projection',fld)),1,'22023');END LOOP;
  END IF;
 END LOOP;
 -- Null triples: permitted positions and every other position, including partial nulls.
 FOREACH k IN ARRAY ARRAY[29,32,33,34] LOOP
  w:=CASE k WHEN 29 THEN 4 WHEN 32 THEN 3 WHEN 33 THEN 2 ELSE 4 END;
  FOR i IN 0..w-1 LOOP
   SELECT jsonb_agg(v ORDER BY n) INTO state FROM jsonb_array_elements(trip||trip||trip||trip) WITH ORDINALITY a(v,n) WHERE n<=w*3;
   state:=jsonb_set(jsonb_set(jsonb_set(state,ARRAY[(i*3)::text],'null'),ARRAY[(i*3+1)::text],'null'),ARRAY[(i*3+2)::text],'null');
   bad:=s||jsonb_build_object('kind',k,'projection',CASE WHEN k IN (32,33,34) THEN '{}' ELSE '' END,'states',jsonb_build_array(state::text));
   PERFORM pg_temp.capture_case('null triple',jsonb_build_array(bad),1,CASE WHEN (k=29 AND i=3) OR (k=33 AND i=1) THEN '00000' ELSE '22023' END);
   state:=jsonb_set(state,ARRAY[(i*3)::text],'"1"');
   PERFORM pg_temp.capture_case('partial null triple',jsonb_build_array(bad||jsonb_build_object('states',jsonb_build_array(state::text))),1,'22023');
  END LOOP;
 END LOOP;
 FOR val IN SELECT value FROM jsonb_array_elements('[null,{},[],true,1]') LOOP
  PERFORM pg_temp.capture_case('unencoded state',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(val))),1,'22023');END LOOP;
 FOREACH fld IN ARRAY ARRAY['broken','null','{}','true','1','"str"','[]','["1","(0,1)"]','["1","(0,1)",{},0]'] LOOP
  PERFORM pg_temp.capture_case('invalid encoded state',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(fld))),1,'22023');END LOOP;
 FOR i IN 0..2 LOOP
  FOR val IN SELECT value FROM jsonb_array_elements('[null,{},[],true,1,"","bad"]') LOOP
   IF i=2 AND val='{}'::jsonb THEN CONTINUE;END IF;
   state:=jsonb_set(trip,ARRAY[i::text],val);
   PERFORM pg_temp.capture_case('witness field',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(state::text))),1,'22023');
  END LOOP;
 END LOOP;
 sources:=jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(trip::text,'[ "2", "(5,6)", {"z":2,"a":1} ]',trip::text)),s||'{"id":"b"}');
 PERFORM pg_temp.capture_case('order multiplicity original encoding',sources,3);
 PERFORM pg_temp.capture_case('row boundary',sources,2,'54000');
 PERFORM pg_temp.capture_case('kind33 full six',jsonb_build_array(s||jsonb_build_object('kind',33,'projection','{}','states',jsonb_build_array((trip||trip)::text))),1);
 PERFORM pg_temp.capture_case('allowed leading zeros and large ctid',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array('["0001","(99999999999999999999,0001)",{}]'))),1);
 PERFORM pg_temp.capture_case('late-source row boundary',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(trip::text)),s||jsonb_build_object('id','b','states',jsonb_build_array(trip::text))),1,'54000','resource capture inventory row budget exceeded');
 PERFORM pg_temp.capture_case('late-source exact total',jsonb_build_array(s||jsonb_build_object('states',jsonb_build_array(trip::text)),s||jsonb_build_object('id','b','states',jsonb_build_array(trip::text))),2);
 PERFORM pg_temp.capture_case('duplicate',jsonb_build_array(s,s),0,'22023','duplicate resource capture predicate');
 PERFORM pg_temp.capture_case('duplicate before row/state',jsonb_build_array(s,s||'{"states":[false]}'),0,'22023','duplicate resource capture predicate');
 PERFORM pg_temp.capture_case('shape before duplicate',jsonb_build_array(s,s||'{"extra":true}'),0,'22023','resource capture shape is invalid');
 PERFORM pg_temp.capture_case('budget before state',jsonb_build_array(s||'{"states":[false]}'),0,'54000','resource capture inventory row budget exceeded');
 PERFORM pg_temp.capture_case('early state before late source',jsonb_build_array(s||'{"states":[false]}',false),2,'22023','resource state must be encoded witness');
 PERFORM pg_temp.capture_case('first state error precedence',jsonb_build_array(s||'{"states":["broken",false]}'),2,'22023','invalid resource state JSON');
 PERFORM pg_temp.capture_case('reverse state error precedence',jsonb_build_array(s||'{"states":[false,"broken"]}'),2,'22023','resource state must be encoded witness');
 PERFORM pg_temp.capture_case('projection textual identity',jsonb_build_array(s||'{"kind":32,"projection":"{}"}',s||'{"kind":32,"projection":"{ }"}'),0);
END $$;
-- Large boundaries: independent aggregate goldens, never run the quadratic reference.
DO $$
DECLARE sources jsonb;expected jsonb;actual jsonb;states jsonb;encoded jsonb;one_source jsonb;code text;
BEGIN
 SELECT jsonb_agg(jsonb_build_object('kind',1,'type','t','id',n::text,'projection','','states','[]'::jsonb) ORDER BY n),
  jsonb_object_agg(jsonb_build_array(1,'t',n::text,'')::text,jsonb_build_object('source',jsonb_build_object('kind',1,'type','t','id',n::text,'projection','','states','[]'::jsonb),'states','[]'::jsonb))
 INTO sources,expected FROM generate_series(1,4096) n;
 actual:=kaname._authority_resource_capture_index_v2(sources,0);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION '4096-source golden mismatch';END IF;
 BEGIN PERFORM kaname._authority_resource_capture_index_v2(sources||jsonb_build_array(sources->0),0);code:='00000';
 EXCEPTION WHEN OTHERS THEN code:=SQLSTATE;END;
 IF code<>'54000' THEN RAISE EXCEPTION '4097-source boundary %',code;END IF;
 SELECT jsonb_agg(jsonb_build_array((n%17)::text,'(0,1)',jsonb_build_object('n',n%17)) ORDER BY n),
 jsonb_agg(jsonb_build_array((n%17)::text,'(0,1)',jsonb_build_object('n',n%17))::text ORDER BY n)
 INTO states,encoded FROM generate_series(1,100000) n;
 one_source:=jsonb_build_object('kind',1,'type','t','id','large','projection','','states',encoded);
 expected:=jsonb_build_object(jsonb_build_array(1,'t','large','')::text,jsonb_build_object('source',one_source,'states',states));
 actual:=kaname._authority_resource_capture_index_v2(jsonb_build_array(one_source),100000);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION '100000-state golden/order/multiplicity mismatch';END IF;
 BEGIN PERFORM kaname._authority_resource_capture_index_v2(jsonb_build_array(one_source||jsonb_build_object('states',encoded||' [false]'::jsonb)),100000);code:='00000';
 EXCEPTION WHEN OTHERS THEN code:=SQLSTATE;END;
 IF code<>'54000' THEN RAISE EXCEPTION '100001-state boundary %',code;END IF;
END $$;
ROLLBACK;
`
