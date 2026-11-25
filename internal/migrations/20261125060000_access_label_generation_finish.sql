-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приватная операция владельца. Компилятор передаёт данные из своего
-- подписанного манифеста после сбора полных графов и повторного чтения в RC.
-- Общий бюджет и удержания всех корней и выходов получают до выбора времени.
-- Рабочая роль получает подтверждение только через штатный компилятор.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_object_generation_finish_v1(
 p_receipt jsonb,p_discharge jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $finish$
DECLARE
 v_root_type text;v_root_id text;v_generation uuid;
 root_state jsonb;current_facts jsonb;current_fact_states jsonb;confirmed jsonb;
 count_facts integer;count_retained integer;count_absent integer;
 count_confirmed integer;count_pending integer;captured_rows integer;affected integer;
 reserve_rows integer;reserve_reads integer;invalid_partition boolean;invalid_readback boolean;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF jsonb_typeof(p_receipt->'state') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_receipt->'facts') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_receipt->'fact_states') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_discharge->'retained') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_discharge->'absent') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_discharge->'pending') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'generation completion evidence absent' USING ERRCODE='42501';END IF;
 IF jsonb_array_length(p_receipt->'state')<>3 THEN
  RAISE EXCEPTION 'generation completion state invalid' USING ERRCODE='42501';END IF;
 v_root_type:=p_receipt#>>'{state,2,root_type}';
 v_root_id:=p_receipt#>>'{state,2,root_id}';
 v_generation:=(p_receipt#>>'{state,2,generation}')::uuid;
 IF v_root_type IS NULL OR v_root_type NOT IN ('iam.account','iam.project')
 OR coalesce(v_root_id,'')='' OR v_generation IS NULL THEN
  RAISE EXCEPTION 'generation completion identity invalid' USING ERRCODE='42501';END IF;
 count_facts:=jsonb_array_length(p_receipt->'facts');
 count_pending:=jsonb_array_length(p_discharge->'pending');
 IF count_facts>100000 OR count_pending>count_facts
 OR jsonb_array_length(p_receipt->'fact_states')<>count_facts THEN
  RAISE EXCEPTION 'generation completion census bound invalid' USING ERRCODE='54000';END IF;
 SELECT count(*)::integer INTO count_retained
 FROM (SELECT 1 FROM jsonb_each(p_discharge->'retained') LIMIT count_facts+1) q;
 SELECT count(*)::integer INTO count_absent
 FROM (SELECT 1 FROM jsonb_each(p_discharge->'absent') LIMIT count_facts+1) q;
 count_confirmed:=count_retained+count_absent;
 -- Пакетная сверка списывает K точечных чтений, включая отсутствие строки.
 reserve_rows:=4+2*count_facts+count_confirmed;
 reserve_reads:=4+count_confirmed;
 IF count_confirmed+count_pending<>count_facts
 OR p_rows IS NULL OR p_reads IS NULL OR p_rows<reserve_rows OR p_reads<reserve_reads THEN
  RAISE EXCEPTION 'generation completion budget insufficient' USING ERRCODE='54000';END IF;

 -- Координата состоит ровно из четырёх строк.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(p_receipt->'facts') a(fact)
  WHERE a.fact IS DISTINCT FROM jsonb_build_object(
   'object_type',a.fact->>'object_type','object_id',a.fact->>'object_id',
   'relation',a.fact->>'relation','subject',a.fact->>'subject')
  OR coalesce(a.fact->>'object_type','')='' OR a.fact->>'object_type' LIKE '%.%'
  OR coalesce(a.fact->>'object_id','')='' OR coalesce(a.fact->>'relation','')=''
  OR coalesce(a.fact->>'subject','')='') THEN
  RAISE EXCEPTION 'generation fact identity invalid' USING ERRCODE='42501';END IF;
 -- Проверяем уникальность перед соединением, чтобы повторы во входе
 -- не приводили к квадратичному росту промежуточного набора.
 IF (SELECT count(DISTINCT (jsonb_build_array(a.fact->>'object_type',a.fact->>'object_id',
   a.fact->>'relation',a.fact->>'subject')::text COLLATE "C"))
   FROM jsonb_array_elements(p_receipt->'facts') a(fact))<>count_facts THEN
  RAISE EXCEPTION 'generation fact repeated' USING ERRCODE='42501';END IF;

 WITH expected AS MATERIALIZED (
  SELECT jsonb_build_array(a.fact->>'object_type',a.fact->>'object_id',
   a.fact->>'relation',a.fact->>'subject')::text COLLATE "C" fact_key,a.fact
  FROM jsonb_array_elements(p_receipt->'facts') a(fact)
 ), classified AS MATERIALIZED (
  SELECT r.key COLLATE "C" fact_key,'retained'::text kind,r.value payload
  FROM jsonb_each(p_discharge->'retained') r
  UNION ALL SELECT a.key COLLATE "C",'absent',a.value
  FROM jsonb_each(p_discharge->'absent') a
  UNION ALL SELECT jsonb_build_array(p.fact->>'object_type',p.fact->>'object_id',
   p.fact->>'relation',p.fact->>'subject')::text COLLATE "C",'pending',p.fact
  FROM jsonb_array_elements(p_discharge->'pending') p(fact)
 ), validity AS MATERIALIZED (
  SELECT (SELECT count(DISTINCT c.fact_key) FROM classified c)<>count_facts
   OR EXISTS(SELECT 1 FROM classified c LEFT JOIN expected e ON e.fact_key=c.fact_key
    WHERE e.fact IS NULL
     OR (c.kind='pending' AND c.payload IS DISTINCT FROM e.fact)
     OR (c.kind='absent' AND c.payload IS DISTINCT FROM 'true'::jsonb)
     OR (c.kind='retained' AND jsonb_typeof(c.payload->'fact') IS DISTINCT FROM 'object')) invalid
 ), accepted AS MATERIALIZED (
  SELECT e.fact,c.kind,c.payload FROM classified c JOIN expected e ON e.fact_key=c.fact_key
  WHERE c.kind<>'pending' AND NOT (SELECT v.invalid FROM validity v)
 )
 SELECT (SELECT v.invalid FROM validity v),
  coalesce(jsonb_agg(jsonb_build_object('coordinate',a.fact,'retained',a.kind='retained',
   'fact',CASE WHEN a.kind='retained' THEN a.payload->'fact' ELSE NULL END)), '[]'::jsonb)
 INTO invalid_partition,confirmed FROM accepted a;
 IF invalid_partition THEN
  RAISE EXCEPTION 'generation classification differs' USING ERRCODE='42501';END IF;

 -- Перечитываем корень и полный физический снимок под прежними удержаниями.
 SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO root_state
 FROM kaname.authority_access_label_dirty_root r
 WHERE r.root_type=v_root_type AND r.root_id=v_root_id;
 IF root_state IS DISTINCT FROM p_receipt->'state' THEN
  RAISE EXCEPTION 'generation changed since owner capture' USING ERRCODE='40001';END IF;
 WITH bounded AS MATERIALIZED (
  SELECT f.xmin::text row_xmin,f.ctid::text row_tid,f row_value,
   f.object_type,f.object_id,f.relation,f.subject
  FROM kaname.authority_access_label_dirty_fact f
  WHERE f.root_type=v_root_type AND f.root_id=v_root_id AND f.generation=v_generation
  LIMIT count_facts+1
 ), counted AS MATERIALIZED (
  SELECT count(*)::integer n FROM bounded
 ), accepted AS MATERIALIZED (
  SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=count_facts
 )
 SELECT (SELECT n FROM counted),
  coalesce(jsonb_agg(jsonb_build_array(a.row_xmin,a.row_tid,to_jsonb(a.row_value))
   ORDER BY a.object_type COLLATE "C",a.object_id COLLATE "C",a.relation COLLATE "C",a.subject COLLATE "C"),'[]'::jsonb),
  coalesce(jsonb_agg(jsonb_build_object('object_type',a.object_type,'object_id',a.object_id,
   'relation',a.relation,'subject',a.subject)
   ORDER BY a.object_type COLLATE "C",a.object_id COLLATE "C",a.relation COLLATE "C",a.subject COLLATE "C"),'[]'::jsonb)
 INTO captured_rows,current_fact_states,current_facts FROM accepted a;
 IF captured_rows<>count_facts OR current_fact_states IS DISTINCT FROM p_receipt->'fact_states'
 OR current_facts IS DISTINCT FROM p_receipt->'facts' THEN
  RAISE EXCEPTION 'generation fact census changed' USING ERRCODE='40001';END IF;

 -- Пакет выполняет K точечных чтений под прежними удержаниями.
 -- Уникальность обеспечивает закреплённый PK relation_fact. LIMIT сохраняет
 -- точечный план чтения для каждой подтверждённой координаты.
 SELECT coalesce(bool_or(CASE WHEN c.retained THEN actual.fact IS DISTINCT FROM c.fact
   ELSE actual.fact IS NOT NULL END),false)
 INTO invalid_readback
 FROM jsonb_to_recordset(confirmed) c(coordinate jsonb,retained boolean,fact jsonb)
 LEFT JOIN LATERAL (
  SELECT to_jsonb(f) fact FROM kaname.relation_fact f
  WHERE (f.object_type,f.object_id,f.relation,f.subject)=
   (c.coordinate->>'object_type',c.coordinate->>'object_id',
    c.coordinate->>'relation',c.coordinate->>'subject') LIMIT 1
 ) actual ON true;
 IF invalid_readback THEN
  RAISE EXCEPTION 'final generation fact image unconfirmed' USING ERRCODE='40001';END IF;

 DELETE FROM kaname.authority_access_label_dirty_fact f
 USING jsonb_to_recordset(confirmed) c(coordinate jsonb,retained boolean,fact jsonb)
 WHERE f.root_type=v_root_type AND f.root_id=v_root_id AND f.generation=v_generation
 AND (f.object_type,f.object_id,f.relation,f.subject)=
  (c.coordinate->>'object_type',c.coordinate->>'object_id',
   c.coordinate->>'relation',c.coordinate->>'subject');
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>count_confirmed THEN
  RAISE EXCEPTION 'generation retirement incomplete' USING ERRCODE='40001';END IF;
 DELETE FROM kaname.authority_access_label_dirty_root r
 WHERE r.root_type=v_root_type AND r.root_id=v_root_id AND r.generation=v_generation
 AND NOT EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact f
  WHERE (f.root_type,f.root_id,f.generation)=(r.root_type,r.root_id,r.generation));
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>(CASE WHEN count_pending=0 THEN 1 ELSE 0 END) THEN
  RAISE EXCEPTION 'generation root retirement incomplete' USING ERRCODE='40001';END IF;
 RETURN jsonb_build_object('confirmed',count_confirmed,'pending',count_pending,
  'rows',reserve_rows,'reads',reserve_reads);
END;
$finish$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer) FROM PUBLIC;
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer);
