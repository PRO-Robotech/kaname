-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_reserve_v1(
 p_held jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $reserve$
DECLARE program jsonb;budget_rows bigint;budget_reads bigint;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
  RAISE EXCEPTION 'generation completion reservation budget invalid' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_held#>'{capture,roots}') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_held->'held_advisory') IS DISTINCT FROM 'array'
  OR jsonb_array_length(p_held#>'{capture,roots}')>4096 THEN
  RAISE EXCEPTION 'generation completion reservation shape invalid' USING ERRCODE='42501';
 END IF;
 WITH receipts AS MATERIALIZED (
   SELECT r AS receipt,jsonb_array_length(r->'facts') AS facts
   FROM jsonb_array_elements(p_held#>'{capture,roots}') r
 ), bounded AS MATERIALIZED (
   SELECT receipt,4+3::bigint*facts AS rows,4+facts::bigint AS reads FROM receipts
 ), costs AS MATERIALIZED (
   SELECT coalesce(sum(rows),0)::bigint AS rows,coalesce(sum(reads),0)::bigint AS reads FROM bounded
 )
 SELECT c.rows,c.reads,CASE WHEN c.rows<=p_rows AND c.reads<=p_reads THEN
   (SELECT coalesce(jsonb_agg(jsonb_build_object('receipt',b.receipt,'reserved_rows',b.rows,
     'reserved_reads',b.reads) ORDER BY b.receipt#>>'{state,2,root_type}' COLLATE "C",
     b.receipt#>>'{state,2,root_id}' COLLATE "C"),'[]'::jsonb) FROM bounded b)
 END
 INTO budget_rows,budget_reads,program FROM costs c;
 IF program IS NULL OR budget_rows>p_rows OR budget_reads>p_reads THEN
  RAISE EXCEPTION 'generation completion exceeds shared budget' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object('roots',program,'reserved_rows',budget_rows,'reserved_reads',budget_reads);
END;
$reserve$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_write_wait_v1(
 p_generation jsonb,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $write_wait$
DECLARE
 capture jsonb;root_packet jsonb;actual_root jsonb;actual_states jsonb;actual_facts jsonb;
 current_capture jsonb;coordinates jsonb;keys jsonb;expected_witness jsonb;key_item jsonb;
 v_type text;v_id text;v_generation uuid;root_count integer;fact_count integer;
 total_facts integer:=0;bounded_rows integer;captured_rows integer;capture_rows integer;capture_reads integer;
 reserve_rows integer;reserve_reads integer;relations jsonb;
BEGIN
 PERFORM kaname._authority_access_label_generation_latch_require_v1(false);
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
  RAISE EXCEPTION 'generation write hold budget invalid' USING ERRCODE='54000';END IF;
 capture:=p_generation->'capture';
 IF jsonb_typeof(capture) IS DISTINCT FROM 'object'
 OR jsonb_typeof(capture->'roots') IS DISTINCT FROM 'array'
 OR jsonb_typeof(capture->'output_states') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_generation->'root_keys') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_generation->'held_advisory') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'generation write hold evidence malformed' USING ERRCODE='42501';END IF;
 IF octet_length(p_generation::text)>67108864 THEN
  RAISE EXCEPTION 'generation write hold packet bound exceeded' USING ERRCODE='54000';END IF;
 root_count:=jsonb_array_length(capture->'roots');
 IF root_count>4096 THEN
  RAISE EXCEPTION 'generation write hold root bound exceeded' USING ERRCODE='54000';END IF;
 FOR root_packet IN SELECT value FROM jsonb_array_elements(capture->'roots') LOOP
  IF jsonb_typeof(root_packet->'state') IS DISTINCT FROM 'array'
  OR jsonb_typeof(root_packet->'facts') IS DISTINCT FROM 'array'
  OR jsonb_typeof(root_packet->'fact_states') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'generation write hold root shape invalid' USING ERRCODE='42501';END IF;
  IF jsonb_array_length(root_packet->'state')<>3
  OR jsonb_typeof(root_packet#>'{state,2}') IS DISTINCT FROM 'object'
  OR jsonb_array_length(root_packet->'facts')<>jsonb_array_length(root_packet->'fact_states') THEN
   RAISE EXCEPTION 'generation write hold physical map invalid' USING ERRCODE='42501';END IF;
  total_facts:=total_facts+jsonb_array_length(root_packet->'facts');
  IF total_facts>100000 THEN
   RAISE EXCEPTION 'generation write hold fact bound exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 IF (SELECT count(DISTINCT jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}'))
  FROM jsonb_array_elements(capture->'roots') r)<>root_count THEN
  RAISE EXCEPTION 'generation write hold root repeated' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(k.root_key),'[]'::jsonb) INTO coordinates FROM (
  SELECT jsonb_build_array(r#>>'{state,2,root_type}',r#>>'{state,2,root_id}') root_key
   FROM jsonb_array_elements(capture->'roots') r
  UNION SELECT jsonb_build_array(capture#>>'{direct_root,root_type}',capture#>>'{direct_root,root_id}')
   WHERE capture->'direct_root'<>'null'::jsonb
 ) k;
 keys:=kaname._authority_access_label_generation_root_keys_v1(coordinates);
 IF keys IS DISTINCT FROM p_generation->'root_keys' THEN
  RAISE EXCEPTION 'generation write hold keys differ from capture' USING ERRCODE='42501';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('classid',1262569306,
  'objid',(h::bigint & 4294967295),'objsubid',2,'mode','ExclusiveLock') ORDER BY h),'[]'::jsonb)
 INTO expected_witness FROM (SELECT DISTINCT (k->>'hash')::integer h FROM jsonb_array_elements(keys) k) q;
 IF expected_witness IS DISTINCT FROM p_generation->'held_advisory' THEN
  RAISE EXCEPTION 'generation write hold witness differs' USING ERRCODE='42501';END IF;
 FOR key_item IN SELECT value FROM jsonb_array_elements(expected_witness) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_backend_pid()
   AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())
   AND l.locktype='advisory' AND l.classid=1262569306::oid
   AND l.objid=(key_item->>'objid')::oid AND l.objsubid=2 AND l.mode='ExclusiveLock' AND l.granted) THEN
   RAISE EXCEPTION 'generation write hold root lock missing' USING ERRCODE='42501';END IF;
 END LOOP;
 IF root_count=0 THEN
  IF p_generation->'fingerprint' IS DISTINCT FROM 'null'::jsonb
  OR capture->'output_states'<>'[]'::jsonb THEN
   RAISE EXCEPTION 'empty generation write hold evidence differs' USING ERRCODE='42501';END IF;
  -- No receipt row exists and no retirement DML can occur. Existing population
  -- latch keeps producer INSERT excluded; do not take needless write relations.
  RETURN jsonb_build_object('held_relations','[]'::jsonb,'rows',0,'reads',0);
 END IF;
 IF p_generation->>'fingerprint' IS DISTINCT FROM encode(sha256(convert_to(capture::text,'UTF8')),'hex') THEN
  RAISE EXCEPTION 'generation write hold fingerprint differs' USING ERRCODE='42501';END IF;
 capture_rows:=jsonb_array_length(capture->'output_states')+root_count+total_facts;
 capture_reads:=1+2*root_count+CASE WHEN capture#>'{direct_root,state}'='null'::jsonb THEN 1 ELSE 0 END;
 IF capture->'rows' IS DISTINCT FROM to_jsonb(capture_rows)
 OR capture->'reads' IS DISTINCT FROM to_jsonb(capture_reads) THEN
  RAISE EXCEPTION 'generation write hold capture accounting differs' USING ERRCODE='42501';END IF;
 -- Two relation waits, one root read, bounded fact TID census and locking
 -- fact reread per root, then complete capture again. Repeated physical reads
 -- and empty sets are charged even when their queries share a CTE statement.
 reserve_rows:=root_count+2*total_facts+capture_rows;
 reserve_reads:=2+3*root_count+capture_reads;
 IF reserve_rows>p_rows OR reserve_reads>p_reads THEN
  RAISE EXCEPTION 'generation write hold budget exhausted' USING ERRCODE='54000';END IF;
 -- Same table order as metadata carry. ROW EXCLUSIVE prevents a late DDL wait
 -- for either DELETE target; FOR UPDATE below prevents late tuple arbitration.
 LOCK TABLE kaname.authority_access_label_dirty_root IN ROW EXCLUSIVE MODE;
 LOCK TABLE kaname.authority_access_label_dirty_fact IN ROW EXCLUSIVE MODE;
 FOR root_packet IN SELECT value FROM jsonb_array_elements(capture->'roots')
  ORDER BY value#>>'{state,2,root_type}' COLLATE "C",value#>>'{state,2,root_id}' COLLATE "C" LOOP
  v_type:=root_packet#>>'{state,2,root_type}';v_id:=root_packet#>>'{state,2,root_id}';
  v_generation:=(root_packet#>>'{state,2,generation}')::uuid;
  SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO actual_root
  FROM kaname.authority_access_label_dirty_root r
  WHERE r.root_type=v_type AND r.root_id=v_id FOR UPDATE OF r;
  IF actual_root IS DISTINCT FROM root_packet->'state' THEN
   RAISE EXCEPTION 'generation root changed during write hold' USING ERRCODE='40001';END IF;
  fact_count:=jsonb_array_length(root_packet->'facts');
  -- Root advisory holds exclude conforming workers; bounded locking reread
  -- additionally proves every physical row and every empty generation set.
  WITH bounded AS MATERIALIZED (
   SELECT f.ctid tid FROM kaname.authority_access_label_dirty_fact f
   WHERE f.root_type=v_type AND f.root_id=v_id AND f.generation=v_generation
   LIMIT fact_count+1
  ), locked AS MATERIALIZED (
   -- Bound the physical TID census BEFORE sorting or locking. Joining by TID
   -- rereads only that bounded set; changed rows fail the exact state comparison.
   SELECT f.xmin::text row_xmin,f.ctid::text row_tid,f row_value,
    f.object_type,f.object_id,f.relation,f.subject
   FROM bounded b JOIN kaname.authority_access_label_dirty_fact f ON f.ctid=b.tid
   WHERE f.root_type=v_type AND f.root_id=v_id AND f.generation=v_generation
   ORDER BY f.object_type COLLATE "C",f.object_id COLLATE "C",f.relation COLLATE "C",f.subject COLLATE "C"
   FOR UPDATE OF f
  )
  SELECT (SELECT count(*)::integer FROM bounded),count(*)::integer,
   coalesce(jsonb_agg(jsonb_build_array(b.row_xmin,b.row_tid,to_jsonb(b.row_value))
    ORDER BY b.object_type COLLATE "C",b.object_id COLLATE "C",b.relation COLLATE "C",b.subject COLLATE "C"),'[]'::jsonb),
   coalesce(jsonb_agg(jsonb_build_object('object_type',b.object_type,'object_id',b.object_id,'relation',b.relation,'subject',b.subject)
    ORDER BY b.object_type COLLATE "C",b.object_id COLLATE "C",b.relation COLLATE "C",b.subject COLLATE "C"),'[]'::jsonb)
   INTO bounded_rows,captured_rows,actual_states,actual_facts FROM locked b;
  IF bounded_rows<>fact_count OR captured_rows<>fact_count OR actual_states IS DISTINCT FROM root_packet->'fact_states'
   OR actual_facts IS DISTINCT FROM root_packet->'facts' THEN
   RAISE EXCEPTION 'generation facts changed during write hold' USING ERRCODE='40001';END IF;
 END LOOP;
 current_capture:=kaname._authority_access_label_object_generation_capture_v1(
  capture->>'object_type',capture->>'object_id',capture_rows,capture_reads);
 IF current_capture IS DISTINCT FROM capture THEN
  RAISE EXCEPTION 'generation full capture changed during write holds' USING ERRCODE='40001';END IF;
 relations:=jsonb_build_array(
  jsonb_build_object('oid','kaname.authority_access_label_dirty_root'::regclass::oid,'mode','RowExclusiveLock'),
  jsonb_build_object('oid','kaname.authority_access_label_dirty_fact'::regclass::oid,'mode','RowExclusiveLock'));
 RETURN jsonb_build_object('held_relations',relations,'rows',reserve_rows,'reads',reserve_reads);
END;
$write_wait$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_retained_facts_v1(
 p_pending jsonb,p_certificate jsonb,p_sources jsonb,p_physical jsonb,p_folded jsonb,
 p_at timestamptz,p_work integer) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE supported jsonb:='{}';covered jsonb:='{}';retained jsonb:='{}';absent jsonb:='{}';
 pending jsonb:='[]';seen jsonb:='{}';entry record;row_value jsonb;binding jsonb;desired jsonb;
 tuple_value jsonb;member jsonb;fact jsonb;key_value text;member_key text;ledger_key text;
 model_type text;object_id text;object_ref text;binding_id text;work integer:=0;family text;
BEGIN
 IF jsonb_typeof(p_pending) IS DISTINCT FROM 'array' OR p_at IS NULL
 OR p_work IS NULL OR p_work<0 OR p_work>400000
 OR jsonb_typeof(p_certificate->'graphs') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_certificate->'bindings') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_physical->'members') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_physical->'ledger') IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_folded->'facts') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'retained fact compiler input incomplete' USING ERRCODE='42501';END IF;
 FOREACH family IN ARRAY ARRAY['bindings','pointers','cluster_grants'] LOOP
  IF jsonb_typeof(p_sources->family) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'retained holder family omitted' USING ERRCODE='42501';END IF;
 END LOOP;
 -- Отсутствие факта подтверждает полная удержанная выборка его объекта.
 FOR entry IN SELECT * FROM jsonb_each(p_certificate->'graphs') LOOP
  row_value:=entry.value;model_type:=row_value->>'model_type';object_id:=row_value->>'object_id';
  IF coalesce(model_type,'')='' OR model_type LIKE '%.%' OR coalesce(object_id,'')='' THEN
   RAISE EXCEPTION 'retained fact graph identity invalid' USING ERRCODE='42501';END IF;
  covered:=covered||jsonb_build_object(jsonb_build_array(model_type,object_id)::text,true);
  work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 -- Удержанный указатель регистрации является независимым источником.
 FOR entry IN SELECT * FROM jsonb_each(p_sources->'pointers') LOOP
  row_value:=entry.value;work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
  IF row_value->'active' IS DISTINCT FROM 'true'::jsonb THEN CONTINUE;END IF;
  key_value:=jsonb_build_array(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject')::text;
  supported:=supported||jsonb_build_object(key_value,jsonb_build_object('kind','registration_pointer','source',entry.key));
 END LOOP;
 FOR entry IN SELECT * FROM jsonb_each(p_sources->'cluster_grants') LOOP
  row_value:=entry.value;work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
  IF row_value->>'granted_until' IS NOT NULL AND (row_value->>'granted_until')::timestamptz<=p_at THEN CONTINUE;END IF;
  key_value:=jsonb_build_array('cluster',row_value->>'cluster_id','system_admin',
    (row_value->>'subject_type')||':'||(row_value->>'subject_id'))::text;
  supported:=supported||jsonb_build_object(key_value,jsonb_build_object('kind','cluster_admin_grant','source',entry.key));
 END LOOP;
 -- Используем желаемые кортежи из проверенного сертификата привязки.
 -- Старая активная запись журнала сама по себе не подтверждает отбор
 -- по текущему селектору, срок действия и отсутствие отзыва.
 FOR entry IN SELECT * FROM jsonb_each(p_certificate->'bindings') LOOP
  binding_id:=entry.key;binding:=p_sources->'bindings'->binding_id;work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
  IF jsonb_typeof(binding) IS DISTINCT FROM 'object' OR binding->>'id' IS DISTINCT FROM binding_id
   OR jsonb_typeof(entry.value->'desired') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'retained binding proof lacks its held carrier' USING ERRCODE='42501';END IF;
  IF binding->>'status' IS DISTINCT FROM 'ACTIVE' OR binding->>'revoked_at' IS NOT NULL
   OR (binding->>'expires_at' IS NOT NULL AND (binding->>'expires_at')::timestamptz<=p_at) THEN CONTINUE;END IF;
  FOR desired IN SELECT value FROM jsonb_array_elements(entry.value->'desired') LOOP
   work:=work+1;
   IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
   IF desired->>'Status' IS DISTINCT FROM 'ACTIVE' THEN CONTINUE;END IF;
   member_key:=jsonb_build_array(binding_id,binding->>'role_id',desired->>'RuleFP',desired->>'ObjectType',desired->>'ObjectID')::text;
   member:=p_physical->'members'->member_key;
   IF member->>'verification_status' IS DISTINCT FROM 'ACTIVE' THEN CONTINUE;END IF;
   IF jsonb_typeof(desired->'Tuples') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'retained desired tuple set absent' USING ERRCODE='42501';END IF;
   FOR tuple_value IN SELECT value FROM jsonb_array_elements(desired->'Tuples') LOOP
    work:=work+1;
    IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
    object_ref:=tuple_value->>'Object';
    IF position(':' IN object_ref)<=1 OR position(':' IN object_ref)=length(object_ref)
     OR coalesce(tuple_value->>'Relation','')='' OR coalesce(tuple_value->>'User','')='' THEN
     RAISE EXCEPTION 'retained desired tuple coordinate invalid' USING ERRCODE='42501';END IF;
    model_type:=split_part(object_ref,':',1);object_id:=substr(object_ref,position(':' IN object_ref)+1);
    IF model_type LIKE '%.%' THEN RAISE EXCEPTION 'retained fact uses model dictionary' USING ERRCODE='42501';END IF;
    ledger_key:=jsonb_build_array(binding_id,desired->>'ObjectType',desired->>'ObjectID',
      tuple_value->>'User',tuple_value->>'Relation',object_ref)::text;
    IF NOT (p_physical->'ledger') ? ledger_key THEN CONTINUE;END IF;
    key_value:=jsonb_build_array(model_type,object_id,tuple_value->>'Relation',tuple_value->>'User')::text;
    supported:=supported||jsonb_build_object(key_value,jsonb_build_object('kind','verified_binding',
      'binding',binding_id,'member_key',member_key,'ledger_key',ledger_key));
    IF tuple_value->>'User'='user:*' THEN
     key_value:=jsonb_build_array(model_type,object_id,tuple_value->>'Relation','system_class:authenticated')::text;
     supported:=supported||jsonb_build_object(key_value,jsonb_build_object('kind','verified_binding',
       'binding',binding_id,'member_key',member_key,'ledger_key',ledger_key));
    END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 -- Структурный указатель родителя подтверждают итоговая запись журнала
 -- и точная удержанная привязка. Селектор и TTL на него не влияют.
 FOR entry IN SELECT * FROM jsonb_each(p_physical->'ledger') LOOP
  row_value:=entry.value;work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained structural holder work exceeded' USING ERRCODE='54000';END IF;
  binding_id:=row_value->>'binding_id';binding:=p_sources->'bindings'->binding_id;
  IF jsonb_typeof(binding) IS DISTINCT FROM 'object' OR binding->>'id' IS DISTINCT FROM binding_id THEN
   RAISE EXCEPTION 'retained structural carrier missing' USING ERRCODE='42501';END IF;
  IF row_value->>'source'='binding' AND row_value->>'member_object_type'='' AND row_value->>'member_object_id'=''
   AND binding->>'resource_type' IN ('account','project','cluster') AND coalesce(binding->>'resource_id','')<>''
   AND row_value->>'object'='iam_access_binding:'||binding_id
   AND row_value->>'relation'=binding->>'resource_type'
   AND row_value->>'fga_user'=(binding->>'resource_type')||':'||(binding->>'resource_id') THEN
   key_value:=jsonb_build_array('iam_access_binding',binding_id,binding->>'resource_type',row_value->>'fga_user')::text;
   supported:=supported||jsonb_build_object(key_value,jsonb_build_object('kind','binding_structural_parent',
     'binding',binding_id,'ledger_key',entry.key));
  END IF;
 END LOOP;
 -- Сохраняем точную итоговую строку факта, включая условие и версию.
 -- Проверка завершения сверяет её целиком.
 FOR row_value IN SELECT value FROM jsonb_array_elements(p_pending) LOOP
  work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'retained fact work exceeded' USING ERRCODE='54000';END IF;
  key_value:=jsonb_build_array(row_value->>'object_type',row_value->>'object_id',row_value->>'relation',row_value->>'subject')::text;
  IF seen ? key_value OR NOT covered ? jsonb_build_array(row_value->>'object_type',row_value->>'object_id')::text THEN
   RAISE EXCEPTION 'pending fact duplicate or outside complete held output graph' USING ERRCODE='42501';END IF;
  seen:=seen||jsonb_build_object(key_value,true);fact:=p_folded->'facts'->key_value;
  IF fact IS NULL THEN absent:=absent||jsonb_build_object(key_value,true);
  ELSIF supported ? key_value THEN
   retained:=retained||jsonb_build_object(key_value,jsonb_build_object('fact',fact,'holder',supported->key_value));
  ELSE pending:=pending||jsonb_build_array(row_value);
  END IF;
 END LOOP;
 RETURN jsonb_build_object('retained',retained,'absent',absent,'pending',pending,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_generation_discharge_v1(
 p_program jsonb,p_certificate jsonb,p_sources jsonb,p_materialized jsonb,
 p_at timestamptz,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $discharge$
DECLARE
 entry record;receipt jsonb;root_row jsonb;root_key text;seen_roots jsonb:='{}';
 flat jsonb;classified jsonb;partitioned jsonb;result jsonb;
 count_facts integer;rows_reserved integer:=0;reads_reserved integer:=0;
 reserve_rows integer;reserve_reads integer;work integer:=0;classification_work integer;
 pending_count integer;flat_count integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_at IS NULL OR NOT isfinite(p_at) OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000
  OR jsonb_typeof(p_program->'roots') IS DISTINCT FROM 'array'
  OR jsonb_array_length(p_program->'roots')>4096
  OR jsonb_typeof(p_program->'reserved_rows') IS DISTINCT FROM 'number'
  OR jsonb_typeof(p_program->'reserved_reads') IS DISTINCT FROM 'number'
  OR (p_program->>'reserved_rows') !~ '^[0-9]{1,6}$'
  OR (p_program->>'reserved_reads') !~ '^[0-9]{1,6}$'
  OR (p_program->>'reserved_rows')::integer>100000
  OR (p_program->>'reserved_reads')::integer>4096
  OR jsonb_typeof(p_materialized#>'{physical,members}') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_materialized#>'{physical,ledger}') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_materialized#>'{fold,facts}') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'generation discharge owner program incomplete' USING ERRCODE='42501';END IF;
 FOR entry IN SELECT value,ordinality FROM jsonb_array_elements(p_program->'roots') WITH ORDINALITY LOOP
  receipt:=entry.value->'receipt';root_row:=receipt#>'{state,2}';
  IF jsonb_typeof(receipt->'state') IS DISTINCT FROM 'array'
   OR jsonb_array_length(receipt->'state')<>3
   OR jsonb_typeof(receipt->'facts') IS DISTINCT FROM 'array'
   OR jsonb_typeof(receipt->'fact_states') IS DISTINCT FROM 'array'
   OR jsonb_typeof(root_row) IS DISTINCT FROM 'object'
   OR jsonb_typeof(receipt#>'{state,0}') IS DISTINCT FROM 'string'
   OR coalesce(receipt#>>'{state,0}','')=''
   OR jsonb_typeof(receipt#>'{state,1}') IS DISTINCT FROM 'string'
   OR coalesce(receipt#>>'{state,1}','')=''
   OR coalesce(root_row->>'root_type','') NOT IN ('iam.account','iam.project')
   OR coalesce(root_row->>'root_id','')='' OR coalesce(root_row->>'generation','')=''
   OR jsonb_typeof(entry.value->'reserved_rows') IS DISTINCT FROM 'number'
   OR jsonb_typeof(entry.value->'reserved_reads') IS DISTINCT FROM 'number'
   OR (entry.value->>'reserved_rows') !~ '^[0-9]{1,6}$'
   OR (entry.value->>'reserved_reads') !~ '^[0-9]{1,6}$' THEN
   RAISE EXCEPTION 'generation discharge receipt shape differs' USING ERRCODE='42501';END IF;
  -- UUID и физическая история остаются исходными, без реконструкции receipt.
  PERFORM (root_row->>'generation')::uuid;
  root_key:=jsonb_build_array(root_row->>'root_type',root_row->>'root_id')::text;
  IF seen_roots ? root_key THEN
   RAISE EXCEPTION 'generation discharge root repeated' USING ERRCODE='42501';END IF;
  seen_roots:=seen_roots||jsonb_build_object(root_key,true);
  count_facts:=jsonb_array_length(receipt->'facts');
  IF count_facts>100000 OR jsonb_array_length(receipt->'fact_states')<>count_facts THEN
   RAISE EXCEPTION 'generation discharge fact census incomplete' USING ERRCODE='54000';END IF;
  -- Проверяем полную четырёхстрочную координату, уникальность внутри корня
  -- и соответствие физической версии именно этому поколению.
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(receipt->'facts') WITH ORDINALITY f(value,ord)
   WHERE f.value IS DISTINCT FROM jsonb_build_object('object_type',f.value->>'object_type',
    'object_id',f.value->>'object_id','relation',f.value->>'relation','subject',f.value->>'subject')
    OR coalesce(f.value->>'object_type','')='' OR f.value->>'object_type' LIKE '%.%'
    OR coalesce(f.value->>'object_id','')='' OR coalesce(f.value->>'relation','')=''
    OR coalesce(f.value->>'subject','')=''
    OR jsonb_typeof(receipt->'fact_states'->(f.ord::integer-1)) IS DISTINCT FROM 'array'
    OR jsonb_array_length(receipt->'fact_states'->(f.ord::integer-1))<>3
    OR jsonb_typeof(receipt->'fact_states'->(f.ord::integer-1)->0) IS DISTINCT FROM 'string'
    OR coalesce(receipt->'fact_states'->(f.ord::integer-1)->>0,'')=''
    OR jsonb_typeof(receipt->'fact_states'->(f.ord::integer-1)->1) IS DISTINCT FROM 'string'
    OR coalesce(receipt->'fact_states'->(f.ord::integer-1)->>1,'')=''
    OR receipt->'fact_states'->(f.ord::integer-1)->2 IS DISTINCT FROM
      f.value||jsonb_build_object('root_type',root_row->>'root_type','root_id',root_row->>'root_id',
       'generation',root_row->>'generation'))
   OR (SELECT count(DISTINCT f.value) FROM jsonb_array_elements(receipt->'facts') f(value))<>count_facts THEN
   RAISE EXCEPTION 'generation discharge physical fact receipt differs' USING ERRCODE='42501';END IF;
  reserve_rows:=(entry.value->>'reserved_rows')::integer;
  reserve_reads:=(entry.value->>'reserved_reads')::integer;
  -- Максимум finish при подтверждении всех N фактов: 4+3N / 4+N.
  IF reserve_rows<4+3*count_facts OR reserve_reads<4+count_facts THEN
   RAISE EXCEPTION 'generation discharge lacks preclock completion reserve' USING ERRCODE='54000';END IF;
  rows_reserved:=rows_reserved+reserve_rows;reads_reserved:=reads_reserved+reserve_reads;
  work:=work+1+3*count_facts;
  IF rows_reserved>100000 OR reads_reserved>4096 OR work>p_work THEN
   RAISE EXCEPTION 'generation discharge aggregate budget exceeded' USING ERRCODE='54000';END IF;
 END LOOP;
 IF rows_reserved<>(p_program->>'reserved_rows')::integer
  OR reads_reserved<>(p_program->>'reserved_reads')::integer THEN
  RAISE EXCEPTION 'generation discharge reservation totals differ' USING ERRCODE='42501';END IF;
 IF p_program->'roots'='[]'::jsonb THEN
  RETURN jsonb_build_object('roots','[]'::jsonb,'pending',0,'work',work,'completed',false);
 END IF;
 -- Одна семантическая классификация для всех корней. Общий tuple разных
 -- поколений выводится один раз, но ниже возвращается в каждый исходный root.
 SELECT coalesce(jsonb_agg(fact ORDER BY fact::text COLLATE "C"),'[]'::jsonb),count(*)::integer
 INTO flat,flat_count FROM (
  SELECT DISTINCT f.value fact FROM jsonb_array_elements(p_program->'roots') r
  CROSS JOIN LATERAL jsonb_array_elements(r#>'{receipt,facts}') f
 ) unique_facts;
 classified:=kaname._authority_access_label_retained_facts_v1(flat,p_certificate,p_sources,
  p_materialized->'physical',p_materialized->'fold',p_at,p_work-work);
 IF jsonb_typeof(classified->'retained') IS DISTINCT FROM 'object'
  OR jsonb_typeof(classified->'absent') IS DISTINCT FROM 'object'
  OR jsonb_typeof(classified->'pending') IS DISTINCT FROM 'array'
  OR jsonb_typeof(classified->'work') IS DISTINCT FROM 'number'
  OR (classified->>'work') !~ '^[0-9]{1,6}$' THEN
  RAISE EXCEPTION 'generation semantic classification missing' USING ERRCODE='42501';END IF;
 classification_work:=(classified->>'work')::integer;work:=work+classification_work;
 IF work>p_work THEN RAISE EXCEPTION 'generation semantic work exceeded' USING ERRCODE='54000';END IF;
 IF (SELECT count(*) FROM jsonb_each(classified->'retained'))
   +(SELECT count(*) FROM jsonb_each(classified->'absent'))
   +jsonb_array_length(classified->'pending')<>flat_count THEN
  RAISE EXCEPTION 'generation semantic partition lost a fact' USING ERRCODE='42501';END IF;
 -- Проверенный helper возвращает ровно одну категорию каждого ключа.
 -- Никакой ACTIVE ledger, неподтверждённый desired или совпавший ключ сам
 -- по себе не становится retained; сохраняется полный final fact image.
 WITH classified_keys AS MATERIALIZED (
  SELECT key,'retained' kind,value FROM jsonb_each(classified->'retained')
  UNION ALL SELECT key,'absent',value FROM jsonb_each(classified->'absent')
  UNION ALL SELECT jsonb_build_array(value->>'object_type',value->>'object_id',
   value->>'relation',value->>'subject')::text,'pending',value FROM jsonb_array_elements(classified->'pending')
 ), expected AS MATERIALIZED (
  SELECT r.ordinality root_no,f.ordinality fact_no,f.value fact,
   jsonb_build_array(f.value->>'object_type',f.value->>'object_id',f.value->>'relation',f.value->>'subject')::text key
  FROM jsonb_array_elements(p_program->'roots') WITH ORDINALITY r(value,ordinality)
  CROSS JOIN LATERAL jsonb_array_elements(r.value#>'{receipt,facts}') WITH ORDINALITY f(value,ordinality)
 ), grouped AS (
  SELECT e.root_no,
   coalesce(jsonb_object_agg(e.key,c.value) FILTER(WHERE c.kind='retained'),'{}'::jsonb) retained,
   coalesce(jsonb_object_agg(e.key,c.value) FILTER(WHERE c.kind='absent'),'{}'::jsonb) absent,
   coalesce(jsonb_agg(e.fact ORDER BY e.fact_no) FILTER(WHERE c.kind='pending'),'[]'::jsonb) pending
  FROM expected e JOIN classified_keys c USING(key) GROUP BY e.root_no
 ) SELECT coalesce(jsonb_object_agg(root_no::text,jsonb_build_object(
  'retained',retained,'absent',absent,'pending',pending)),'{}'::jsonb) INTO partitioned FROM grouped;
 SELECT coalesce(jsonb_agg(jsonb_build_object('receipt',r.value->'receipt',
  'discharge',coalesce(partitioned->r.ordinality::text,
   '{"retained":{},"absent":{},"pending":[]}'::jsonb),
  'reserved_rows',r.value->'reserved_rows','reserved_reads',r.value->'reserved_reads')
  ORDER BY r.ordinality),'[]'::jsonb),
  coalesce(sum(jsonb_array_length(coalesce(partitioned->r.ordinality::text->'pending','[]'::jsonb))),0)::integer
 INTO result,pending_count FROM jsonb_array_elements(p_program->'roots') WITH ORDINALITY r(value,ordinality);
 RETURN jsonb_build_object('roots',result,'pending',pending_count,'work',work,'completed',false);
END;
$discharge$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $private$
DECLARE signature text;recipient record;
BEGIN
 FOREACH signature IN ARRAY ARRAY['_authority_access_label_generation_reserve_v1(jsonb,integer,integer)','_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','_authority_access_label_retained_facts_v1(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)'] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $generation_repin$
DECLARE item record; edit jsonb; fn oid; previous text; updated text; definition text; old_fragment text;
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler prior closure incomplete' USING ERRCODE='55000';
 END IF;
 FOR item IN SELECT * FROM (VALUES
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74',$patch$[[" generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;", " generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;\n generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;"], [" used_reads:=used_reads+relations_result.logical_reads;", " used_reads:=used_reads+relations_result.logical_reads;\n -- Закрытие использует только захваченный владельцем состав поколения.\n -- Все ожидания записи и бюджет подтверждения входят в общий prewait.\n IF generation IS NOT NULL AND jsonb_array_length(generation#>'{capture,roots}')>0 THEN\n  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1(\n   generation,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation_write_wait->>'rows')::integer;\n  used_reads:=used_reads+(generation_write_wait->>'reads')::integer;\n  generation_relation_holds:=generation_write_wait->'held_relations';\n  generation_program:=kaname._authority_access_label_generation_reserve_v1(\n   generation,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation_program->>'reserved_rows')::integer;\n  used_reads:=used_reads+(generation_program->>'reserved_reads')::integer;\n ELSE\n  generation_program:='{\"roots\":[],\"reserved_rows\":0,\"reserved_reads\":0}'::jsonb;\n END IF;\n sources:=jsonb_set(sources,'{access_label_generation}',generation_program);"], ["'held_relations',relations_result.lock_witness,'held_advisory',held_advisory", "'held_relations',relations_result.lock_witness||generation_relation_holds,'held_advisory',held_advisory"]]$patch$::jsonb),
  ('authority_resource_finalize_v2(jsonb,integer,integer)','20a9e6ee2af213a514ca21399d62cdb981a399ad7e96cbae330c152d0ecf837d','3f8f2e3fb9568fef85b809dea80a67ceaf9160f9e6511c9c2bbddc685af477bc',$patch$[[" materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];", " materialized jsonb;generation_final jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];"], ["  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);", "  generation_final:=kaname._authority_access_label_generation_discharge_v1(\n   manifest#>'{object_sources,access_label_generation}',manifest->'object_certificate',\n   manifest->'object_sources',materialized,at_time,400000-(materialized->>'work')::integer);\n  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);"], ["   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',", "   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',\n   object_sources=jsonb_set(object_sources,'{access_label_generation}',generation_final),"]]$patch$::jsonb),
  ('_authority_resource_require_completion_v2()','e1c6b94cd3542ce6e1055c70a7ef067675ebbd3826084e24c04d21b3df29f203','8047f0ba0196eb1cff0b51a18a0ed35003cc7a9e09f8f3639cb087a63b29263d',$patch$[["DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;", "DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;\n generation_program jsonb;generation_item jsonb;generation_result jsonb;pending integer:=0;"], ["   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;\n RETURN NULL;", "   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;\n IF manifest->'intent'->>'kind'='object' THEN\n  generation_program:=manifest#>'{object_sources,access_label_generation}';\n  IF jsonb_typeof(generation_program->'roots') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(generation_program->'pending') IS DISTINCT FROM 'number'\n   OR generation_program->'completed' IS DISTINCT FROM 'false'::jsonb THEN\n   RAISE EXCEPTION 'generation completion program missing' USING ERRCODE='42501';END IF;\n  FOR generation_item IN SELECT value FROM jsonb_array_elements(generation_program->'roots') LOOP\n   generation_result:=kaname._authority_access_label_object_generation_finish_v1(\n    generation_item->'receipt',generation_item->'discharge',\n    (generation_item->>'reserved_rows')::integer,(generation_item->>'reserved_reads')::integer);\n   pending:=pending+(generation_result->>'pending')::integer;\n  END LOOP;\n  IF pending IS DISTINCT FROM (generation_program->>'pending')::integer THEN\n   RAISE EXCEPTION 'generation completion pending count changed' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(generation_program->'roots')>0 THEN\n   -- Даже если отложенная проверка запущена до COMMIT, последующий\n   -- вызов подписанного тела не сможет изменить уже сверенные факты.\n   UPDATE pg_temp.kaname_authority_resource_manifest SET state='settled',\n    object_sources=jsonb_set(object_sources,'{access_label_generation,completed}','true'::jsonb)\n   WHERE state='body';\n   IF NOT FOUND THEN RAISE EXCEPTION 'generation completion seal missing' USING ERRCODE='42501';END IF;\n  END IF;\n END IF;\n RETURN NULL;"]]$patch$::jsonb),
  ('authority_resource_object_body_values_v2()','6e897b0435468258916f05eddaf0e2f068a5f7a4f16c91d72ea1e1f30a73c130','018eae2f8d2ab833e4f89c421360f605f1774bd34b979cb8026b903aa258a6aa',$patch$[["DECLARE manifest jsonb;commands jsonb;audits jsonb;", "DECLARE manifest jsonb;commands jsonb;audits jsonb;pending jsonb;"], [" commands:=manifest#>'{object_program,commands}';audits:=manifest#>'{object_physical,audits}';", " commands:=manifest#>'{object_program,commands}';audits:=manifest#>'{object_physical,audits}';\n pending:=manifest#>'{object_sources,access_label_generation,pending}';\n IF jsonb_typeof(pending) IS DISTINCT FROM 'number' OR (pending#>>'{}')::integer NOT BETWEEN 0 AND 100000 THEN\n  RAISE EXCEPTION 'generation pending status unavailable' USING ERRCODE='42501';END IF;"], [" 'transaction_at',manifest->'transaction_at','decision_at',manifest->'decision_at');", " 'transaction_at',manifest->'transaction_at','decision_at',manifest->'decision_at','access_label_pending',pending);"]]$patch$::jsonb),
  ('_authority_crud_storage_v3()','52766af3af2c70ce578b719f2e2ab625f08c4eaec9d20800e3449ee080556c79','244ada6a1bda64a9c67ec0c996ab9f3ff4d1d080c4ea3f92be05da23737c18ae',$patch$[[" ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',true,'v',true,'preserve'),", " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74',true,'v',true,'preserve'),\n ('authority_resource_object_body_values_v2()','018eae2f8d2ab833e4f89c421360f605f1774bd34b979cb8026b903aa258a6aa',true,'v',true,'preserve'),\n ('_authority_access_label_generation_reserve_v1(jsonb,integer,integer)','a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478',false,'v',true,'private'),\n ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d',false,'v',true,'private'),\n ('_authority_access_label_retained_facts_v1(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','df7911418cc20c8eb1ef362f3459905fffc5992d3bb7821131b7c81f54eeef8b',false,'i',true,'private'),\n ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','00ecb86fd27e78d11b9490d216a22979a3de7592c9605f0b5b2997eeeb323be2',false,'v',true,'private'),\n ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','ee16e64da9f78e48c8d0bafbb6190653d9f05637ddd4238a703aeee95afcfbfe',false,'v',true,'private'),"], [" ('authority_resource_finalize_v2(jsonb,integer,integer)','20a9e6ee2af213a514ca21399d62cdb981a399ad7e96cbae330c152d0ecf837d',true,'v',true,'preserve'),", " ('authority_resource_finalize_v2(jsonb,integer,integer)','3f8f2e3fb9568fef85b809dea80a67ceaf9160f9e6511c9c2bbddc685af477bc',true,'v',true,'preserve'),"], [" ('_authority_resource_require_completion_v2()','e1c6b94cd3542ce6e1055c70a7ef067675ebbd3826084e24c04d21b3df29f203',true,'v',true,'preserve'),", " ('_authority_resource_require_completion_v2()','8047f0ba0196eb1cff0b51a18a0ed35003cc7a9e09f8f3639cb087a63b29263d',true,'v',true,'preserve'),"]]$patch$::jsonb),
  ('_authority_full_contract_storage_v3()','82592325bc1fb010dfae9ce81004246bab8cb2b58c4385cfd5cf99d89c0de2ab','1f24ecd5e3d8cbe36d8d7e5168503664dbbb006ad6186942e6122aae9e510dea',$patch$[[" ('_authority_crud_storage_v3()','52766af3af2c70ce578b719f2e2ab625f08c4eaec9d20800e3449ee080556c79',true),", " ('_authority_crud_storage_v3()','244ada6a1bda64a9c67ec0c996ab9f3ff4d1d080c4ea3f92be05da23737c18ae',true),"]]$patch$::jsonb)
 ) changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT previous FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(previous,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'generation compiler baseline changed: %',item.signature USING ERRCODE='55000';
  END IF;
  updated:=previous;
  FOR edit IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   old_fragment:=edit->>0;
   IF length(updated)-length(replace(updated,old_fragment,'')) IS DISTINCT FROM length(old_fragment) THEN
    RAISE EXCEPTION 'generation compiler patch ambiguous: %',item.signature USING ERRCODE='55000';
   END IF;
   updated:=replace(updated,old_fragment,edit->>1);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler candidate changed: %',item.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,previous,'')) IS DISTINCT FROM length(previous) THEN
   RAISE EXCEPTION 'generation compiler definition ambiguous: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,previous,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
   IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler installed bytes changed: %',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler final closure incomplete' USING ERRCODE='55000';
 END IF;
END;
$generation_repin$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
-- +goose StatementBegin
DO $generation_repin$
DECLARE item record; edit jsonb; fn oid; previous text; updated text; definition text; old_fragment text;
BEGIN
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler prior closure incomplete' USING ERRCODE='55000';
 END IF;
 FOR item IN SELECT * FROM (VALUES
  ('_authority_full_contract_storage_v3()','1f24ecd5e3d8cbe36d8d7e5168503664dbbb006ad6186942e6122aae9e510dea','82592325bc1fb010dfae9ce81004246bab8cb2b58c4385cfd5cf99d89c0de2ab',$patch$[[" ('_authority_crud_storage_v3()','244ada6a1bda64a9c67ec0c996ab9f3ff4d1d080c4ea3f92be05da23737c18ae',true),", " ('_authority_crud_storage_v3()','52766af3af2c70ce578b719f2e2ab625f08c4eaec9d20800e3449ee080556c79',true),"]]$patch$::jsonb),
  ('_authority_crud_storage_v3()','244ada6a1bda64a9c67ec0c996ab9f3ff4d1d080c4ea3f92be05da23737c18ae','52766af3af2c70ce578b719f2e2ab625f08c4eaec9d20800e3449ee080556c79',$patch$[[" ('_authority_resource_require_completion_v2()','8047f0ba0196eb1cff0b51a18a0ed35003cc7a9e09f8f3639cb087a63b29263d',true,'v',true,'preserve'),", " ('_authority_resource_require_completion_v2()','e1c6b94cd3542ce6e1055c70a7ef067675ebbd3826084e24c04d21b3df29f203',true,'v',true,'preserve'),"], [" ('authority_resource_finalize_v2(jsonb,integer,integer)','3f8f2e3fb9568fef85b809dea80a67ceaf9160f9e6511c9c2bbddc685af477bc',true,'v',true,'preserve'),", " ('authority_resource_finalize_v2(jsonb,integer,integer)','20a9e6ee2af213a514ca21399d62cdb981a399ad7e96cbae330c152d0ecf837d',true,'v',true,'preserve'),"], [" ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74',true,'v',true,'preserve'),\n ('authority_resource_object_body_values_v2()','018eae2f8d2ab833e4f89c421360f605f1774bd34b979cb8026b903aa258a6aa',true,'v',true,'preserve'),\n ('_authority_access_label_generation_reserve_v1(jsonb,integer,integer)','a5534c220f2aecea6de405b3605f3580bd2f3ddd7e6dc049b64e182ec46f7478',false,'v',true,'private'),\n ('_authority_access_label_generation_write_wait_v1(jsonb,integer,integer)','942b891c77f6f45f815120118166d8c4a1aec0a1af81d13b7bd6a2acb94e078d',false,'v',true,'private'),\n ('_authority_access_label_retained_facts_v1(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','df7911418cc20c8eb1ef362f3459905fffc5992d3bb7821131b7c81f54eeef8b',false,'i',true,'private'),\n ('_authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer)','00ecb86fd27e78d11b9490d216a22979a3de7592c9605f0b5b2997eeeb323be2',false,'v',true,'private'),\n ('_authority_access_label_object_generation_finish_v1(jsonb,jsonb,integer,integer)','ee16e64da9f78e48c8d0bafbb6190653d9f05637ddd4238a703aeee95afcfbfe',false,'v',true,'private'),", " ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',true,'v',true,'preserve'),"]]$patch$::jsonb),
  ('authority_resource_object_body_values_v2()','018eae2f8d2ab833e4f89c421360f605f1774bd34b979cb8026b903aa258a6aa','6e897b0435468258916f05eddaf0e2f068a5f7a4f16c91d72ea1e1f30a73c130',$patch$[[" 'transaction_at',manifest->'transaction_at','decision_at',manifest->'decision_at','access_label_pending',pending);", " 'transaction_at',manifest->'transaction_at','decision_at',manifest->'decision_at');"], [" commands:=manifest#>'{object_program,commands}';audits:=manifest#>'{object_physical,audits}';\n pending:=manifest#>'{object_sources,access_label_generation,pending}';\n IF jsonb_typeof(pending) IS DISTINCT FROM 'number' OR (pending#>>'{}')::integer NOT BETWEEN 0 AND 100000 THEN\n  RAISE EXCEPTION 'generation pending status unavailable' USING ERRCODE='42501';END IF;", " commands:=manifest#>'{object_program,commands}';audits:=manifest#>'{object_physical,audits}';"], ["DECLARE manifest jsonb;commands jsonb;audits jsonb;pending jsonb;", "DECLARE manifest jsonb;commands jsonb;audits jsonb;"]]$patch$::jsonb),
  ('_authority_resource_require_completion_v2()','8047f0ba0196eb1cff0b51a18a0ed35003cc7a9e09f8f3639cb087a63b29263d','e1c6b94cd3542ce6e1055c70a7ef067675ebbd3826084e24c04d21b3df29f203',$patch$[["   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;\n IF manifest->'intent'->>'kind'='object' THEN\n  generation_program:=manifest#>'{object_sources,access_label_generation}';\n  IF jsonb_typeof(generation_program->'roots') IS DISTINCT FROM 'array'\n   OR jsonb_typeof(generation_program->'pending') IS DISTINCT FROM 'number'\n   OR generation_program->'completed' IS DISTINCT FROM 'false'::jsonb THEN\n   RAISE EXCEPTION 'generation completion program missing' USING ERRCODE='42501';END IF;\n  FOR generation_item IN SELECT value FROM jsonb_array_elements(generation_program->'roots') LOOP\n   generation_result:=kaname._authority_access_label_object_generation_finish_v1(\n    generation_item->'receipt',generation_item->'discharge',\n    (generation_item->>'reserved_rows')::integer,(generation_item->>'reserved_reads')::integer);\n   pending:=pending+(generation_result->>'pending')::integer;\n  END LOOP;\n  IF pending IS DISTINCT FROM (generation_program->>'pending')::integer THEN\n   RAISE EXCEPTION 'generation completion pending count changed' USING ERRCODE='42501';END IF;\n  IF jsonb_array_length(generation_program->'roots')>0 THEN\n   -- Даже если отложенная проверка запущена до COMMIT, последующий\n   -- вызов подписанного тела не сможет изменить уже сверенные факты.\n   UPDATE pg_temp.kaname_authority_resource_manifest SET state='settled',\n    object_sources=jsonb_set(object_sources,'{access_label_generation,completed}','true'::jsonb)\n   WHERE state='body';\n   IF NOT FOUND THEN RAISE EXCEPTION 'generation completion seal missing' USING ERRCODE='42501';END IF;\n  END IF;\n END IF;\n RETURN NULL;", "   RAISE EXCEPTION 'resource mandatory journal fold was omitted' USING ERRCODE='42501';END IF;\n RETURN NULL;"], ["DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;\n generation_program jsonb;generation_item jsonb;generation_result jsonb;pending integer:=0;", "DECLARE manifest jsonb; physical jsonb; storage oid; consumed integer[]; required_count integer; consumed_count integer;"]]$patch$::jsonb),
  ('authority_resource_finalize_v2(jsonb,integer,integer)','3f8f2e3fb9568fef85b809dea80a67ceaf9160f9e6511c9c2bbddc685af477bc','20a9e6ee2af213a514ca21399d62cdb981a399ad7e96cbae330c152d0ecf837d',$patch$[["   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',\n   object_sources=jsonb_set(object_sources,'{access_label_generation}',generation_final),", "   object_program=materialized->'program',object_physical=materialized->'physical',object_fold=materialized->'fold',"], ["  generation_final:=kaname._authority_access_label_generation_discharge_v1(\n   manifest#>'{object_sources,access_label_generation}',manifest->'object_certificate',\n   manifest->'object_sources',materialized,at_time,400000-(materialized->>'work')::integer);\n  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);", "  PERFORM kaname._authority_resource_object_sequence_final_v3(materialized,at_time);"], [" materialized jsonb;generation_final jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];", " materialized jsonb;entry jsonb;field text;actual_keys text[];held_keys text[];"]]$patch$::jsonb),
  ('_authority_resource_object_prepare_v2(jsonb,integer,integer)','12eb8205cc999d9207d3497b838c5dc2badd80e28ded8805435c7a818a8a3c74','354c92f45d67eacb524ae16293f8fe7c9bfa4456ea1a9263f945e3fd346a52a4',$patch$[["'held_relations',relations_result.lock_witness||generation_relation_holds,'held_advisory',held_advisory", "'held_relations',relations_result.lock_witness,'held_advisory',held_advisory"], [" used_reads:=used_reads+relations_result.logical_reads;\n -- Закрытие использует только захваченный владельцем состав поколения.\n -- Все ожидания записи и бюджет подтверждения входят в общий prewait.\n IF generation IS NOT NULL AND jsonb_array_length(generation#>'{capture,roots}')>0 THEN\n  generation_write_wait:=kaname._authority_access_label_generation_write_wait_v1(\n   generation,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation_write_wait->>'rows')::integer;\n  used_reads:=used_reads+(generation_write_wait->>'reads')::integer;\n  generation_relation_holds:=generation_write_wait->'held_relations';\n  generation_program:=kaname._authority_access_label_generation_reserve_v1(\n   generation,p_rows-used_rows,p_reads-used_reads);\n  used_rows:=used_rows+(generation_program->>'reserved_rows')::integer;\n  used_reads:=used_reads+(generation_program->>'reserved_reads')::integer;\n ELSE\n  generation_program:='{\"roots\":[],\"reserved_rows\":0,\"reserved_reads\":0}'::jsonb;\n END IF;\n sources:=jsonb_set(sources,'{access_label_generation}',generation_program);", " used_reads:=used_reads+relations_result.logical_reads;"], [" generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;\n generation_program jsonb;generation_write_wait jsonb;generation_relation_holds jsonb:='[]'::jsonb;", " generation jsonb;generation_model text;generation_holds jsonb:='[]'::jsonb;"]]$patch$::jsonb)
 ) changes(signature,before_sha,after_sha,substitutions) LOOP
  fn:=to_regprocedure('kaname.'||item.signature);
  SELECT p.prosrc INTO STRICT previous FROM pg_catalog.pg_proc p WHERE p.oid=fn;
  IF encode(sha256(convert_to(previous,'UTF8')),'hex') IS DISTINCT FROM item.before_sha THEN
   RAISE EXCEPTION 'generation compiler baseline changed: %',item.signature USING ERRCODE='55000';
  END IF;
  updated:=previous;
  FOR edit IN SELECT value FROM jsonb_array_elements(item.substitutions) LOOP
   old_fragment:=edit->>0;
   IF length(updated)-length(replace(updated,old_fragment,'')) IS DISTINCT FROM length(old_fragment) THEN
    RAISE EXCEPTION 'generation compiler patch ambiguous: %',item.signature USING ERRCODE='55000';
   END IF;
   updated:=replace(updated,old_fragment,edit->>1);
  END LOOP;
  IF encode(sha256(convert_to(updated,'UTF8')),'hex') IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler candidate changed: %',item.signature USING ERRCODE='55000';
  END IF;
  definition:=pg_catalog.pg_get_functiondef(fn);
  IF length(definition)-length(replace(definition,previous,'')) IS DISTINCT FROM length(previous) THEN
   RAISE EXCEPTION 'generation compiler definition ambiguous: %',item.signature USING ERRCODE='55000';
  END IF;
  EXECUTE replace(definition,previous,updated);
  IF (SELECT encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') FROM pg_catalog.pg_proc p WHERE p.oid=fn)
   IS DISTINCT FROM item.after_sha THEN
   RAISE EXCEPTION 'generation compiler installed bytes changed: %',item.signature USING ERRCODE='55000';
  END IF;
 END LOOP;
 IF kaname._authority_full_contract_storage_v3() IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'generation compiler final closure incomplete' USING ERRCODE='55000';
 END IF;
END;
$generation_repin$;
-- +goose StatementEnd
DROP FUNCTION kaname._authority_access_label_generation_discharge_v1(jsonb,jsonb,jsonb,jsonb,timestamptz,integer);
DROP FUNCTION kaname._authority_access_label_retained_facts_v1(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz,integer);
DROP FUNCTION kaname._authority_access_label_generation_write_wait_v1(jsonb,integer,integer);
DROP FUNCTION kaname._authority_access_label_generation_reserve_v1(jsonb,integer,integer);
