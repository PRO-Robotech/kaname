-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Закрытая компиляция сохранённых и отзываемых фактов из удержанного снимка.

-- +goose Up
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_member_partition_v1(
 p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,
 p_frontiers jsonb,p_rows integer,p_work integer) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE binding_id text;source jsonb;binding jsonb;independent_ledger jsonb:='{}';state jsonb;row_value jsonb;coord text;typ text;identifier text;
 coords jsonb:='{}';affected jsonb:='{}';unrelated jsonb:='{}';cleanup jsonb:='{}';required jsonb:='{}';
 required_frontiers jsonb:='{}';graph jsonb;ancestry jsonb;catalog_row jsonb;frontier jsonb;
 seen jsonb;queue jsonb;node jsonb;parent jsonb;position_no integer;depth_no integer;found_root boolean;
 model text;root_model text;key_value text;used integer:=0;work integer:=0;count_value integer;
BEGIN
 IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project') OR coalesce(p_root_id,'')=''
 OR p_bindings IS NULL OR cardinality(p_bindings)>4096
 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_frontiers) IS DISTINCT FROM 'object'
 OR p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000
 OR octet_length(p_index::text)+octet_length(p_frontiers::text)>67108864 THEN
  RAISE EXCEPTION 'protected member partition input invalid' USING ERRCODE='42501';END IF;
 root_model:=CASE p_root_type WHEN 'iam.account' THEN 'account' ELSE 'project' END;
 -- Добавляем координаты из журнала, в том числе без текущего участника.
 -- required сохраняет полные удержанные предикаты.
 FOREACH binding_id IN ARRAY p_bindings LOOP
  IF coalesce(binding_id,'')='' THEN RAISE EXCEPTION 'partition carrier missing' USING ERRCODE='42501';END IF;
  source:=kaname._authority_resource_require_capture_v2(p_index,8,'binding',binding_id);
  required:=required||jsonb_build_object(jsonb_build_array(8,'binding',binding_id,'')::text,true);
  IF jsonb_array_length(source->'states')<>1 OR source#>>'{states,0,2,id}' IS DISTINCT FROM binding_id THEN
   RAISE EXCEPTION 'partition binding source identity differs' USING ERRCODE='42501';END IF;
  binding:=source#>'{states,0,2}';work:=work+1;
  source:=kaname._authority_resource_require_capture_v2(p_index,10,'binding',binding_id);
  required:=required||jsonb_build_object(jsonb_build_array(10,'binding',binding_id,'')::text,true);
  FOR state IN SELECT value FROM jsonb_array_elements(source->'states') LOOP
   row_value:=state->2;used:=used+1;work:=work+1;
   IF used>p_rows OR work>p_work THEN RAISE EXCEPTION 'protected member partition budget exceeded' USING ERRCODE='54000';END IF;
   typ:=row_value->>'object_type';identifier:=row_value->>'object_id';
   IF row_value->>'binding_id' IS DISTINCT FROM binding_id OR coalesce(typ,'')='' OR coalesce(identifier,'')='' THEN
    RAISE EXCEPTION 'partition member identity differs' USING ERRCODE='42501';END IF;
   coords:=coords||jsonb_build_object(jsonb_build_array(typ,identifier)::text,jsonb_build_array(typ,identifier));
  END LOOP;
  source:=kaname._authority_resource_require_capture_v2(p_index,11,'binding',binding_id);
  required:=required||jsonb_build_object(jsonb_build_array(11,'binding',binding_id,'')::text,true);
  FOR state IN SELECT value FROM jsonb_array_elements(source->'states') LOOP
   row_value:=state->2;used:=used+1;work:=work+1;
   IF used>p_rows OR work>p_work THEN RAISE EXCEPTION 'protected ledger partition budget exceeded' USING ERRCODE='54000';END IF;
   IF row_value->>'binding_id' IS DISTINCT FROM binding_id THEN RAISE EXCEPTION 'partition ledger carrier differs' USING ERRCODE='42501';END IF;
   -- BuildRoleTuples создаёт эту связь с областью привязки для каждой роли
   -- с правилами. Проверяем точный кортеж, не зависящий от меток.
   IF row_value->>'source'='binding'
    AND row_value->>'member_object_type'='' AND row_value->>'member_object_id'=''
    AND binding->>'resource_type' IN ('account','project','cluster') AND coalesce(binding->>'resource_id','')<>''
    AND row_value->>'object'='iam_access_binding:'||binding_id
    AND row_value->>'relation'=binding->>'resource_type'
    AND row_value->>'fga_user'=(binding->>'resource_type')||':'||(binding->>'resource_id') THEN
    key_value:=jsonb_build_array(binding_id,'','',row_value->>'fga_user',row_value->>'relation',row_value->>'object')::text;
    independent_ledger:=independent_ledger||jsonb_build_object(key_value,state);
    CONTINUE;
   END IF;
   IF row_value->>'source' IS DISTINCT FROM 'member' THEN
    RAISE EXCEPTION 'protected metadata requires stale binding-wide ledger cleanup' USING ERRCODE='42501';END IF;
   typ:=row_value->>'member_object_type';identifier:=row_value->>'member_object_id';
   IF coalesce(typ,'')='' OR coalesce(identifier,'')='' THEN
    RAISE EXCEPTION 'partition ledger member provenance absent' USING ERRCODE='42501';END IF;
   coords:=coords||jsonb_build_object(jsonb_build_array(typ,identifier)::text,jsonb_build_array(typ,identifier));
  END LOOP;
 END LOOP;
 -- Одна проекция и один обход для каждой координаты участника.
 FOR coord,row_value IN SELECT key,value FROM jsonb_each(coords) ORDER BY key COLLATE "C" LOOP
  typ:=row_value->>0;identifier:=row_value->>1;
  graph:=kaname._authority_resource_projection_v2(p_index,typ,identifier);
  required:=required||(graph->'required');work:=work+1;
  IF work>p_work THEN RAISE EXCEPTION 'protected projection work exceeded' USING ERRCODE='54000';END IF;
  IF typ=p_root_type AND identifier=p_root_id THEN
   IF graph->'present' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'protected root disappeared' USING ERRCODE='42501';END IF;
   affected:=affected||jsonb_build_object(coord,jsonb_build_object('kind','direct','graph',graph));CONTINUE;
  END IF;
  IF graph->'present' IS DISTINCT FROM 'true'::jsonb THEN
   -- Для отсутствующей проекции требуется отдельная точная очистка.
   cleanup:=cleanup||jsonb_build_object(coord,jsonb_build_object('kind','absent_member','graph',graph));CONTINUE;
  END IF;
  SELECT count(*),jsonb_agg(r)->0 INTO count_value,catalog_row
   FROM jsonb_array_elements(coalesce(nullif(p_catalog#>'{Live,Resources}','null'::jsonb),'[]'::jsonb)) r
   WHERE (r->>'Module')||'.'||(r->>'Resource')=typ;
  IF count_value<>1 OR coalesce(catalog_row->>'ObjectType','')='' THEN
   RAISE EXCEPTION 'partition member live model mapping unconfirmed' USING ERRCODE='42501';END IF;
  model:=catalog_row->>'ObjectType';
  -- Сохраняем источники для материализации. Принадлежность области
  -- отдельно вычисляем по полному графу ресурсных связей.
  ancestry:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);
  required:=required||(ancestry->'required');
  queue:=jsonb_build_array(jsonb_build_array(model,identifier,0));position_no:=0;seen:='{}';found_root:=false;
  WHILE position_no<jsonb_array_length(queue) LOOP
   node:=queue->position_no;position_no:=position_no+1;work:=work+1;
   IF work>p_work THEN RAISE EXCEPTION 'protected ancestry work exceeded' USING ERRCODE='54000';END IF;
   key_value:=jsonb_build_array(node->>0,node->>1)::text;depth_no:=(node->>2)::integer;
   IF seen ? key_value THEN CONTINUE;END IF;
   seen:=seen||jsonb_build_object(key_value,true);
   IF node->>0=root_model AND node->>1=p_root_id THEN found_root:=true;EXIT;END IF;
   frontier:=p_frontiers->key_value;
   IF jsonb_typeof(frontier) IS DISTINCT FROM 'object'
    OR frontier->>'object_type' IS DISTINCT FROM node->>0 OR frontier->>'object_id' IS DISTINCT FROM node->>1
    OR jsonb_typeof(frontier->'parents') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'complete owner scope frontier missing' USING ERRCODE='42501';END IF;
   IF jsonb_array_length(frontier->'parents')>4 OR (depth_no>=5 AND frontier->'parents'<>'[]'::jsonb) THEN
    RAISE EXCEPTION 'protected ancestry exceeds native read boundary' USING ERRCODE='54000';END IF;
   required_frontiers:=required_frontiers||jsonb_build_object(key_value,true);
   FOR parent IN SELECT value FROM jsonb_array_elements(frontier->'parents') LOOP
    IF jsonb_typeof(parent) IS DISTINCT FROM 'array' OR jsonb_array_length(parent)<>2
     OR coalesce(parent->>0,'')='' OR parent->>0 LIKE '%.%' OR coalesce(parent->>1,'')='' THEN
     RAISE EXCEPTION 'owner scope frontier parent invalid' USING ERRCODE='42501';END IF;
    queue:=queue||jsonb_build_array(jsonb_build_array(parent->>0,parent->>1,depth_no+1));
   END LOOP;
   IF jsonb_array_length(queue)>4096 THEN RAISE EXCEPTION 'protected ancestry node bound exceeded' USING ERRCODE='54000';END IF;
  END LOOP;
  IF found_root THEN affected:=affected||jsonb_build_object(coord,jsonb_build_object('kind','nested','graph',graph,'path_nodes',seen));
  ELSE unrelated:=unrelated||jsonb_build_object(coord,true);END IF;
 END LOOP;
 RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'affected',affected,'unrelated',unrelated,
  'cleanup',cleanup,'independent_ledger',independent_ledger,'required',required,'required_frontiers',required_frontiers,'work',work,'logical_rows',0,'logical_reads',0);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_old_facts_v2(
 p_root_type text,p_root_id text,p_bindings text[],p_index jsonb,p_catalog jsonb,p_frontiers jsonb,p_rows integer,p_work integer)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE root jsonb; source jsonb; binding_id text; row_value jsonb; state jsonb;
 ledger jsonb:='[]'; objects jsonb; states jsonb; facts jsonb; selected_states jsonb;
 used integer:=0; work integer:=0; n integer;partition jsonb;
BEGIN
 IF p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project')
 OR p_root_id IS NULL OR p_root_id='' OR p_bindings IS NULL
 OR cardinality(p_bindings)>4096 OR jsonb_typeof(p_index) IS DISTINCT FROM 'object'
 OR p_rows IS NULL OR p_rows<0 OR p_rows>100000
 OR p_work IS NULL OR p_work<0 OR p_work>400000
 OR octet_length(p_index::text)>67108864
 OR EXISTS(SELECT 1 FROM unnest(p_bindings) b WHERE b IS NULL OR b='')
 OR cardinality(p_bindings)<>(SELECT count(DISTINCT b COLLATE "C") FROM unnest(p_bindings) b) THEN
  RAISE EXCEPTION 'access label old output input invalid' USING ERRCODE='42501';END IF;
 root:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_root_id);
 IF jsonb_array_length(root->'states')<>1 THEN
  RAISE EXCEPTION 'access label old root missing' USING ERRCODE='42501';END IF;
 state:=root->'states'->0;row_value:=state->2;
 IF jsonb_typeof(state) IS DISTINCT FROM 'array' OR jsonb_array_length(state)<>3
 OR coalesce(state->>0,'')='' OR coalesce(state->>1,'')=''
 OR jsonb_typeof(row_value) IS DISTINCT FROM 'object' OR row_value->>'id' IS DISTINCT FROM p_root_id
 OR kaname.access_labels_valid_v1(row_value->'access_labels') IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'access label old root physical image missing' USING ERRCODE='42501';END IF;
 root:=state;
 partition:=kaname._authority_access_label_member_partition_v1(p_root_type,p_root_id,p_bindings,p_index,p_catalog,p_frontiers,p_rows,p_work);
 IF partition->'cleanup'<>'{}'::jsonb THEN
  RAISE EXCEPTION 'protected metadata requires exact absent-member cleanup before mutation' USING ERRCODE='42501';END IF;
 work:=1+(partition->>'work')::integer;
 -- Владелец уже подтвердил полный перечень привязок. Учитываем старые
 -- выходы и при отозванной привязке или удалённом участнике.
 FOREACH binding_id IN ARRAY p_bindings LOOP
  source:=kaname._authority_resource_require_capture_v2(p_index,8,'binding',binding_id);
  IF jsonb_array_length(source->'states')<>1 OR source#>>'{states,0,2,id}' IS DISTINCT FROM binding_id THEN
   RAISE EXCEPTION 'old output carrier absent' USING ERRCODE='42501';END IF;
  source:=kaname._authority_resource_require_capture_v2(p_index,10,'binding',binding_id);
  n:=jsonb_array_length(source->'states');work:=work+1+n;
  source:=kaname._authority_resource_require_capture_v2(p_index,11,'binding',binding_id);
  n:=jsonb_array_length(source->'states');used:=used+n;work:=work+n;
  IF used>p_rows OR work>p_work THEN
   RAISE EXCEPTION 'access label old output budget exceeded' USING ERRCODE='54000';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(source->'states') s
   WHERE jsonb_typeof(s) IS DISTINCT FROM 'array' OR jsonb_array_length(s)<>3
    OR coalesce(s->>0,'')='' OR coalesce(s->>1,'')=''
    OR jsonb_typeof(s->2) IS DISTINCT FROM 'object' OR s->2->>'binding_id' IS DISTINCT FROM binding_id
    OR coalesce(s->2->>'fga_user','')='' OR coalesce(s->2->>'relation','')=''
    OR position(':' IN coalesce(s->2->>'object',''))<=1
    OR position(':' IN s->2->>'object')=length(s->2->>'object')
    OR split_part(s->2->>'object',':',1) LIKE '%.%'
    OR s->2->>'source' IS NULL OR s->2->>'source' NOT IN ('binding','member')
  ) THEN RAISE EXCEPTION 'old emitted tuple physical image invalid' USING ERRCODE='42501';END IF;
  -- В набор отзыва идут выходы участников из области изменяемого ресурса.
  SELECT ledger||coalesce(jsonb_agg(s ORDER BY s::text COLLATE "C"),'[]'::jsonb) INTO ledger
  FROM jsonb_array_elements(source->'states') s
  WHERE (partition->'affected') ? jsonb_build_array(s->2->>'member_object_type',s->2->>'member_object_id')::text;
 END LOOP;
 -- Сначала ограничили сырые строки; только потом DISTINCT и сортировка.
 -- Для scope_self и вторичных выходов берём настоящий Tuple.Object.
 SELECT coalesce(jsonb_agg(jsonb_build_object('object_type',q.typ,'object_id',q.id)
  ORDER BY q.typ COLLATE "C",q.id COLLATE "C"),'[]'::jsonb) INTO objects
 FROM (SELECT DISTINCT split_part(s->2->>'object',':',1) COLLATE "C" typ,
  substr(s->2->>'object',position(':' IN s->2->>'object')+1) COLLATE "C" id
  FROM jsonb_array_elements(ledger) s) q;
 states:='[]';
 FOR row_value IN SELECT value FROM jsonb_array_elements(objects) LOOP
  -- Полная выборка фактов объекта уже перечитана под блокировкой.
  source:=kaname._authority_resource_require_capture_v2(p_index,6,row_value->>'object_type',row_value->>'object_id');
  n:=jsonb_array_length(source->'states');used:=used+n;work:=work+1+n;
  IF used>p_rows OR work>p_work THEN
   RAISE EXCEPTION 'access label old fact predicate budget exceeded' USING ERRCODE='54000';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(source->'states') s
   WHERE jsonb_typeof(s) IS DISTINCT FROM 'array' OR jsonb_array_length(s)<>3
    OR coalesce(s->>0,'')='' OR coalesce(s->>1,'')=''
    OR s->2->>'object_type' IS DISTINCT FROM row_value->>'object_type'
    OR s->2->>'object_id' IS DISTINCT FROM row_value->>'object_id'
    OR coalesce(s->2->>'relation','')='' OR coalesce(s->2->>'subject','')=''
  ) THEN RAISE EXCEPTION 'old fact object predicate differs' USING ERRCODE='42501';END IF;
  states:=states||(source->'states');
 END LOOP;
 -- Сохраняем действительный subject, включая существующее user:* ->
 -- system_class:authenticated соответствие из _authority_crud_fold_capture_v3.
 -- Здесь собираем координаты и удержанные строки для следующего этапа.
 WITH emitted AS MATERIALIZED (
  SELECT DISTINCT split_part(s->2->>'object',':',1) COLLATE "C" typ,
   substr(s->2->>'object',position(':' IN s->2->>'object')+1) COLLATE "C" id,
   (s->2->>'relation') COLLATE "C" rel,(s->2->>'fga_user') COLLATE "C" subject
  FROM jsonb_array_elements(ledger) s
 ), actual AS MATERIALIZED (
  SELECT s FROM jsonb_array_elements(states) s WHERE EXISTS(SELECT 1 FROM emitted e
   WHERE s->2->>'object_type'=e.typ AND s->2->>'object_id'=e.id AND s->2->>'relation'=e.rel
    AND (s->2->>'subject'=e.subject OR (e.subject='user:*' AND s->2->>'subject'='system_class:authenticated')))
 )
 SELECT coalesce(jsonb_agg(jsonb_build_object('object_type',s->2->>'object_type','object_id',s->2->>'object_id',
    'relation',s->2->>'relation','subject',s->2->>'subject')
   ORDER BY s->2->>'object_type' COLLATE "C",s->2->>'object_id' COLLATE "C",s->2->>'relation' COLLATE "C",s->2->>'subject' COLLATE "C"),'[]'::jsonb),
  coalesce(jsonb_agg(s ORDER BY s->2->>'object_type' COLLATE "C",s->2->>'object_id' COLLATE "C",s->2->>'relation' COLLATE "C",s->2->>'subject' COLLATE "C"),'[]'::jsonb)
 INTO facts,selected_states FROM actual;
 IF jsonb_array_length(facts)<>(SELECT count(DISTINCT jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text COLLATE "C") FROM jsonb_array_elements(facts) f) THEN
  RAISE EXCEPTION 'old fact census duplicate' USING ERRCODE='42501';END IF;
 work:=work+jsonb_array_length(facts);
 IF work>p_work THEN RAISE EXCEPTION 'access label old fact key budget exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('root_type',p_root_type,'root_id',p_root_id,'old_root',root,
  'partition',partition,'facts',facts,'old_fact_states',selected_states,'objects',objects,'old_ledger_states',ledger,
  'logical_rows',0,'logical_reads',0,'output_rows',used,'work',work);
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
-- План составляет владелец из перечитанного OLD index. Здесь нет чтений БД.
-- Координата держателя берётся из member_object_* строки журнала, а набор
-- кандидатов ограничен точными фактическими выходами, которые меняет команда.
CREATE FUNCTION kaname._authority_metadata_access_label_retention_plan_v1(
 p_index jsonb,p_catalog jsonb,p_outputs jsonb,p_old_outputs jsonb,
 p_root_type text,p_old jsonb,p_new jsonb,p_work integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $retention_plan$
DECLARE
 root_capture jsonb; output_row jsonb; output_key text; output_coord jsonb;
 graph jsonb; ancestors jsonb; entry record; ancestor jsonb; new_ancestors jsonb;
 holders jsonb; holder jsonb; output_type text; output_id text; binding_id text;
 facts jsonb; tuple_object text; tuple_user text; tuple_relation text; coordinate_key text;
 required jsonb:='{}'; graphs jsonb:='{}'; bindings jsonb:='{}'; coordinates jsonb:='{}';
 work integer:=0;
BEGIN
 IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_outputs) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_old_outputs->'objects') IS DISTINCT FROM 'array'
  OR jsonb_typeof(p_old_outputs->'facts') IS DISTINCT FROM 'array'
  OR p_root_type IS NULL OR p_root_type NOT IN ('iam.account','iam.project')
  OR p_old_outputs->>'root_type' IS DISTINCT FROM p_root_type
  OR p_old_outputs->>'root_id' IS DISTINCT FROM p_old->>'id'
  OR jsonb_typeof(p_old) IS DISTINCT FROM 'object' OR coalesce(p_old->>'id','')=''
  OR jsonb_typeof(p_new) IS DISTINCT FROM 'object'
  OR (p_old-ARRAY['name','description','labels','access_labels']) IS DISTINCT FROM
     (p_new-ARRAY['name','description','labels','access_labels'])
  OR p_old->'access_labels' IS NOT DISTINCT FROM p_new->'access_labels'
  OR kaname.access_labels_valid_v1(p_new->'access_labels') IS DISTINCT FROM true
  OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'metadata retention plan requires the verified OLD and NEW root'
   USING ERRCODE='42501';
 END IF;
 root_capture:=kaname._authority_resource_require_capture_v2(p_index,30,p_root_type,p_old->>'id');
 IF jsonb_array_length(root_capture->'states')<>1
  OR root_capture#>'{states,0,2}' IS DISTINCT FROM p_old THEN
  RAISE EXCEPTION 'metadata retention OLD projection changed' USING ERRCODE='40001';
 END IF;

 SELECT coalesce(jsonb_object_agg(
  jsonb_build_array(f->>'object_type',f->>'object_id',f->>'relation',f->>'subject')::text,true),'{}')
 INTO facts FROM jsonb_array_elements(p_old_outputs->'facts') f;
 work:=jsonb_array_length(p_old_outputs->'facts');
 IF work>p_work THEN
  RAISE EXCEPTION 'metadata retention plan fact budget exhausted' USING ERRCODE='54000';
 END IF;
 FOR output_row IN SELECT value FROM jsonb_array_elements(p_old_outputs->'objects') LOOP
  output_type:=output_row->>'object_type';
  output_id:=output_row->>'object_id';
  output_key:=jsonb_build_array(output_type,output_id)::text;
  output_coord:=p_outputs->output_key;
  IF output_coord->>'model_type' IS DISTINCT FROM output_type
   OR output_coord->>'object_id' IS DISTINCT FROM output_id
   OR coalesce(output_coord->>'object_type','')='' THEN
   RAISE EXCEPTION 'metadata retention output has no held coordinate' USING ERRCODE='42501';
  END IF;
  graph:=kaname._authority_resource_object_graph_v2(
   p_index,output_coord->>'object_type',output_type,output_id);
  work:=work+1+(graph->>'holder_count')::integer;
  IF work>p_work THEN
   RAISE EXCEPTION 'metadata retention output graph budget exhausted' USING ERRCODE='54000';
  END IF;
  required:=required||(graph->'required');
  graphs:=graphs||jsonb_build_object(output_key,graph||output_coord);
  bindings:=bindings||(graph->'bindings');

  -- Kind 35 перечисляет журнал по Tuple.Object. Он включает держателей,
  -- для которых объект участника отличается от объекта итогового кортежа.
  holders:=kaname._authority_resource_require_capture_v2(p_index,35,output_type,output_id);
  tuple_object:=output_type||':'||output_id;
  FOR holder IN SELECT value->2 FROM jsonb_array_elements(holders->'states') LOOP
   work:=work+1;
   IF work>p_work THEN
    RAISE EXCEPTION 'metadata retention holder budget exhausted' USING ERRCODE='54000';
   END IF;
   tuple_user:=holder->>'fga_user';
   tuple_relation:=holder->>'relation';
   IF coalesce(tuple_user,'')='' OR coalesce(tuple_relation,'')=''
    OR holder->>'object' IS DISTINCT FROM tuple_object THEN
    RAISE EXCEPTION 'metadata retention ledger coordinate differs from the held output'
     USING ERRCODE='42501';
   END IF;
   IF NOT (facts ? jsonb_build_array(output_type,output_id,tuple_relation,tuple_user)::text)
    AND NOT (tuple_user='user:*' AND facts ?
             jsonb_build_array(output_type,output_id,tuple_relation,'system_class:authenticated')::text) THEN
    CONTINUE;
   END IF;
   binding_id:=holder->>'binding_id';
   IF coalesce(binding_id,'')='' OR NOT (bindings ? binding_id) THEN
    RAISE EXCEPTION 'metadata retention holder does not belong to the held output'
     USING ERRCODE='42501';
   END IF;
   IF holder->>'member_object_type'='' AND holder->>'member_object_id'='' THEN
    CONTINUE;
   END IF;
   IF coalesce(holder->>'member_object_type','')='' OR coalesce(holder->>'member_object_id','')='' THEN
    RAISE EXCEPTION 'metadata retention holder member coordinate incomplete' USING ERRCODE='42501';
   END IF;
   coordinate_key:=jsonb_build_array(binding_id,holder->>'member_object_type',holder->>'member_object_id')::text;
   coordinates:=coordinates||jsonb_build_object(coordinate_key,true);
  END LOOP;
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(coordinates))>4096 THEN
  RAISE EXCEPTION 'metadata retention coordinate count exhausted' USING ERRCODE='54000';
 END IF;
 FOR entry IN SELECT c.key::jsonb AS coord,c.key FROM jsonb_object_keys(coordinates) c(key) LOOP
  graph:=kaname._authority_resource_projection_v2(p_index,entry.coord->>1,entry.coord->>2);
  ancestors:=kaname._authority_resource_ancestor_graph_v2(p_index,p_catalog,graph);
  required:=required||(graph->'required')||(ancestors->'required');
  IF graph->>'object_type'=p_root_type AND graph->>'object_id'=p_old->>'id' THEN
   graph:=jsonb_set(graph,'{projection}',p_new);
  END IF;
  new_ancestors:='[]';
  FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors->'ancestors') LOOP
   IF ancestor->>'object_type'=p_root_type AND ancestor->>'object_id'=p_old->>'id' THEN
    ancestor:=jsonb_set(ancestor,'{projection}',p_new);
   END IF;
   new_ancestors:=new_ancestors||jsonb_build_array(ancestor);
  END LOOP;
  coordinates:=jsonb_set(coordinates,ARRAY[entry.key],graph||jsonb_build_object('ancestors',new_ancestors));
  work:=work+1+jsonb_array_length(new_ancestors);
  IF work>p_work THEN
   RAISE EXCEPTION 'metadata retention projection budget exhausted' USING ERRCODE='54000';
  END IF;
 END LOOP;
 RETURN jsonb_build_object('required',required,'graphs',graphs,'bindings',bindings,
  'coordinates',coordinates,'work',work);
END;
$retention_plan$;

-- Предложения компилятора Go подтверждаются по списку координат владельца.
-- Никакой ответ Go не задаёт состав держателей или физические строки.
CREATE FUNCTION kaname._authority_metadata_access_label_retention_certify_v1(
 p_index jsonb,p_catalog jsonb,p_plan jsonb,p_desired jsonb,p_work integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $certify$
DECLARE
 entry record; binding_id text; verified jsonb; expected jsonb; carrier jsonb;
 bindings jsonb:='{}'; ids text[]; required jsonb; work integer:=0;
BEGIN
 expected:=p_plan->'coordinates';
 IF jsonb_typeof(p_plan->'graphs') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'required') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'bindings') IS DISTINCT FROM 'object'
  OR jsonb_typeof(expected) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_desired) IS DISTINCT FROM 'object'
  OR octet_length(p_desired::text)>8388608
  OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000
  OR EXISTS(SELECT 1 FROM jsonb_object_keys(p_desired) k WHERE NOT (expected ? k))
  OR EXISTS(SELECT 1 FROM jsonb_object_keys(expected) k WHERE NOT (p_desired ? k)) THEN
  RAISE EXCEPTION 'metadata retention proposals differ from held coordinate census'
   USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(id ORDER BY id COLLATE "C"),ARRAY[]::text[]) INTO ids
 FROM jsonb_object_keys(p_plan->'bindings') id;
 carrier:=kaname._authority_resource_carrier_graph_v2(p_index,ids,ids,ARRAY[]::text[],ARRAY[]::text[]);
 required:=(p_plan->'required')||(carrier->'required');
 work:=cardinality(ids)+(SELECT count(*) FROM jsonb_object_keys(required));
 IF work>p_work THEN
  RAISE EXCEPTION 'metadata retention carrier budget exhausted' USING ERRCODE='54000';
 END IF;
 FOREACH binding_id IN ARRAY ids LOOP
  bindings:=bindings||jsonb_build_object(binding_id,jsonb_build_object('desired','[]'::jsonb));
 END LOOP;
 FOR entry IN SELECT key,value FROM jsonb_each(expected) LOOP
  binding_id:=(entry.key::jsonb)->>0;
  IF NOT (bindings ? binding_id) THEN
   RAISE EXCEPTION 'metadata retention coordinate binding absent' USING ERRCODE='42501';
  END IF;
  verified:=kaname._authority_resource_coordinate_certificate_v2(
   p_index,p_catalog,binding_id,entry.value,p_desired->entry.key);
  work:=work+1+(verified->>'work')::integer;
  IF work>p_work THEN
   RAISE EXCEPTION 'metadata retention certificate budget exhausted' USING ERRCODE='54000';
  END IF;
  bindings:=jsonb_set(bindings,ARRAY[binding_id,'desired'],
   (bindings#>ARRAY[binding_id,'desired'])||(verified->'desired'));
 END LOOP;
 RETURN jsonb_build_object('required',required,'graphs',p_plan->'graphs','bindings',bindings,'work',work);
END;
$certify$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Компилятор Go видит только семантическую проекцию и определения нужных
-- привязок. Версии физических строк и полные выборки остаются у владельца.
CREATE FUNCTION kaname._authority_metadata_access_label_retention_inputs_v1(
 p_index jsonb,p_plan jsonb,p_work integer
) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $inputs$
DECLARE
 coordinates jsonb; ids text[]; binding_id text; role_id text; captured jsonb;
 binding jsonb; subjects jsonb; role_row jsonb; selectors jsonb; result jsonb:='{}';
 work integer:=0;
BEGIN
 coordinates:=p_plan->'coordinates';
 IF jsonb_typeof(p_index) IS DISTINCT FROM 'object'
  OR jsonb_typeof(coordinates) IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_plan->'bindings') IS DISTINCT FROM 'object'
  OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'metadata retention input must come from the owner plan' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(DISTINCT c.key::jsonb->>0),ARRAY[]::text[]) INTO ids
 FROM jsonb_object_keys(coordinates) c(key);
 FOREACH binding_id IN ARRAY ids LOOP
  IF coalesce(binding_id,'')='' OR NOT (p_plan->'bindings') ? binding_id THEN
   RAISE EXCEPTION 'metadata retention compiler binding missing from owner plan' USING ERRCODE='42501';
  END IF;
  captured:=kaname._authority_resource_require_capture_v2(p_index,8,'binding',binding_id);
  binding:=captured#>'{states,0,2}';
  IF jsonb_array_length(captured->'states')<>1 OR binding->>'id' IS DISTINCT FROM binding_id THEN
   RAISE EXCEPTION 'metadata retention compiler binding source differs' USING ERRCODE='42501';
  END IF;
  captured:=kaname._authority_resource_require_capture_v2(p_index,9,'binding',binding_id);
  SELECT coalesce(jsonb_agg(s->2 ORDER BY ordinality),'[]') INTO subjects
  FROM jsonb_array_elements(captured->'states') WITH ORDINALITY AS subject(s,ordinality);
  role_id:=nullif(binding->>'role_id','');
  role_row:=NULL;
  selectors:='[]';
  IF role_id IS NOT NULL THEN
   captured:=kaname._authority_resource_require_capture_v2(p_index,12,'role',role_id);
   role_row:=captured#>'{states,0,2}';
   IF jsonb_array_length(captured->'states')<>1 OR role_row->>'id' IS DISTINCT FROM role_id THEN
    RAISE EXCEPTION 'metadata retention compiler role source differs' USING ERRCODE='42501';
   END IF;
   captured:=kaname._authority_resource_require_capture_v2(p_index,13,'role',role_id);
   SELECT coalesce(jsonb_agg(s->2 ORDER BY ordinality),'[]') INTO selectors
   FROM jsonb_array_elements(captured->'states') WITH ORDINALITY AS selector(s,ordinality);
  END IF;
  work:=work+1+jsonb_array_length(subjects)+jsonb_array_length(selectors);
  IF work>p_work THEN
   RAISE EXCEPTION 'metadata retention compiler input work exhausted' USING ERRCODE='54000';
  END IF;
  result:=result||jsonb_build_object(binding_id,jsonb_build_object('binding',binding,
    'subject_rows',subjects,'role',role_row,'selector_rows',selectors));
 END LOOP;
 IF octet_length(result::text)+octet_length(coordinates::text)>8388608 THEN
  RAISE EXCEPTION 'metadata retention compiler input byte budget exhausted' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object('bindings',result,'coordinates',coordinates,'work',work);
END;
$inputs$;
-- +goose StatementEnd

-- +goose StatementBegin
-- Удержанный физический снимок остаётся за владельцем. Go получает только
-- вход для расчёта и возвращает предложения по выведенным здесь координатам.
CREATE FUNCTION kaname._authority_metadata_access_label_retention_prepare_v1(
 p_patch jsonb,p_rename boolean,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $prepare_retention$
DECLARE
 session_state jsonb; held jsonb; replay jsonb; census jsonb; source_index jsonb;
 root_type text; root_id text; old_row jsonb; new_row jsonb; holder_ids text[];
 bundle record; catalog_payload jsonb; invoker oid; frontiers jsonb; old_outputs jsonb;
 plan jsonb; inputs jsonb; packet jsonb; used_rows integer; used_reads integer; used_work integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 4 AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN 10 AND 4096
  OR p_work IS NULL OR p_work NOT BETWEEN 4 AND 400000 THEN
  RAISE EXCEPTION 'metadata retention prepare budget invalid' USING ERRCODE='54000';
 END IF;
 session_state:=kaname._authority_metadata_access_label_stashed_v1();
 IF session_state ? 'retention' THEN
  RAISE EXCEPTION 'metadata retention already prepared' USING ERRCODE='42501';
 END IF;
 invoker:=(session_state#>>'{plan,invoker_oid}')::oid;
 IF NOT coalesce(has_function_privilege(invoker,'kaname.authority_protocol_read_bundle()','EXECUTE'),false) THEN
  RAISE EXCEPTION 'metadata retention needs original admitted catalog access' USING ERRCODE='42501';
 END IF;
 SELECT * INTO STRICT bundle FROM kaname.authority_protocol_read_bundle();
 IF to_jsonb(bundle.catalog_id) IS DISTINCT FROM session_state->'catalog_id' THEN
  RAISE EXCEPTION 'metadata retention catalog changed' USING ERRCODE='P1034';
 END IF;
 catalog_payload:=convert_from(bundle.catalog_json,'UTF8')::jsonb;
 held:=kaname._authority_metadata_access_label_hold_and_replay_v1(
  p_patch,p_rename,p_rows-2,p_reads-2,p_work-2);
 used_rows:=2+(held->>'rows')::integer;
 used_reads:=2+(held->>'reads')::integer;
 used_work:=2+(held->>'work')::integer;
 replay:=held->'replay';
 census:=replay->'census';
 source_index:=replay->'source_index';
 root_type:=census->>'root_type';
 root_id:=census->>'root_id';
 old_row:=census->'old_root';
 new_row:=old_row||p_patch;
 IF root_type IS NULL OR root_id IS NULL OR root_id IS DISTINCT FROM old_row->>'id'
  OR jsonb_typeof(census->'binding_ids') IS DISTINCT FROM 'array'
  OR jsonb_typeof(replay->'frontier_witnesses') IS DISTINCT FROM 'object'
  OR jsonb_typeof(source_index) IS DISTINCT FROM 'object'
  OR new_row->'access_labels' IS DISTINCT FROM census->'new_labels'
  OR jsonb_typeof(held->'root_physical') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'metadata retention held replay incomplete' USING ERRCODE='42501';
 END IF;
 SELECT coalesce(array_agg(b.id ORDER BY b.id COLLATE "C"),ARRAY[]::text[])
 INTO holder_ids FROM jsonb_array_elements_text(census->'binding_ids') b(id);
 SELECT coalesce(jsonb_object_agg(f.key,f.value->'frontier'),'{}'),used_work+count(*)::integer
 INTO frontiers,used_work FROM jsonb_each(replay->'frontier_witnesses') f;
 IF used_work>p_work THEN
  RAISE EXCEPTION 'metadata retention frontier work exceeded' USING ERRCODE='54000';
 END IF;
 old_outputs:=kaname._authority_access_label_old_facts_v2(
  root_type,root_id,holder_ids,source_index,catalog_payload,frontiers,p_rows-used_rows,p_work-used_work);
 used_work:=used_work+(old_outputs->>'work')::integer;
 plan:=kaname._authority_metadata_access_label_retention_plan_v1(
  source_index,catalog_payload,session_state#>'{discovery,outputs}',old_outputs,root_type,old_row,new_row,p_work-used_work);
 used_work:=used_work+(plan->>'work')::integer;
 inputs:=kaname._authority_metadata_access_label_retention_inputs_v1(source_index,plan,p_work-used_work);
 used_work:=used_work+(inputs->>'work')::integer;
 IF used_rows>p_rows OR used_reads>p_reads OR used_work>p_work THEN
  RAISE EXCEPTION 'metadata retention shared prepare budget exhausted' USING ERRCODE='54000';
 END IF;
 packet:=jsonb_build_object(
  'source_index',source_index,'catalog',catalog_payload,'plan',plan,
  'partition_required',old_outputs#>'{partition,required}','candidate_facts',old_outputs->'facts',
  'root_physical',held->'root_physical','root_type',root_type,'root_id',root_id,
  'old_row',old_row,'new_row',new_row);
 IF octet_length(packet::text)>67108864 THEN
  RAISE EXCEPTION 'metadata retention private packet too large' USING ERRCODE='54000';
 END IF;
 UPDATE pg_temp.kaname_authority_metadata_discovery d
 SET prepared=jsonb_set(d.prepared,'{retention}',packet)
 WHERE d.singleton AND d.prepared=session_state AND NOT (d.prepared ? 'retention');
 IF NOT FOUND THEN
  RAISE EXCEPTION 'metadata retention owner custody changed' USING ERRCODE='42501';
 END IF;
 RETURN inputs||jsonb_build_object('rows',used_rows,'reads',used_reads,'work',used_work);
END;
$prepare_retention$;

-- Из процесса Go принимаются только предложения desired. Полный набор
-- держателей, каталог и физические источники берутся из закрытого пакета.
CREATE FUNCTION kaname._authority_metadata_access_label_retention_compile_v1(
 p_desired jsonb,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $compile_retention$
DECLARE
 session_state jsonb; packet jsonb; certificate jsonb; required jsonb;
 sources jsonb; root_key text; used_work integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 session_state:=kaname._authority_metadata_access_label_stashed_v1();
 packet:=session_state->'retention';
 IF jsonb_typeof(packet) IS DISTINCT FROM 'object'
  OR jsonb_typeof(packet->'candidate_facts') IS DISTINCT FROM 'array'
  OR jsonb_typeof(packet->'partition_required') IS DISTINCT FROM 'object'
  OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'metadata retention owner packet unavailable' USING ERRCODE='42501';
 END IF;
 certificate:=kaname._authority_metadata_access_label_retention_certify_v1(
  packet->'source_index',packet->'catalog',packet->'plan',p_desired,p_work);
 root_key:=jsonb_build_array(30,packet->>'root_type',packet->>'root_id','')::text;
 required:=(packet->'partition_required')||(certificate->'required')||jsonb_build_object(root_key,true);
 sources:=kaname._authority_resource_object_physical_sources_v2(packet->'source_index',required);
 used_work:=(certificate->>'work')::integer+(sources->>'work')::integer;
 IF used_work>p_work THEN
  RAISE EXCEPTION 'metadata retention shared compile budget exhausted' USING ERRCODE='54000';
 END IF;
 RETURN jsonb_build_object(
  'receipt',jsonb_build_object('root_type',packet->'root_type','root_id',packet->'root_id',
   'old_labels',packet#>'{old_row,access_labels}','new_labels',packet#>'{new_row,access_labels}',
   'facts',packet->'candidate_facts'),
  'retention',jsonb_build_object('certificate',certificate,'sources',sources,
   'physical',jsonb_build_object('members',sources->'members','ledger',sources->'ledger'),
   'folded',jsonb_build_object('facts',sources->'facts')),
  'root_physical',packet->'root_physical','old_row',packet->'old_row','new_row',packet->'new_row',
  'rows',1,'reads',1,'work',used_work);
END;
$compile_retention$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_metadata_access_label_retained_select_v1(
 p_frozen jsonb,p_at timestamptz,p_work integer
) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $retained$
DECLARE evidence jsonb;decision jsonb;facts jsonb;work integer;value jsonb;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 evidence:=p_frozen->'retention';
 IF jsonb_typeof(p_frozen) IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_frozen->'candidate_facts') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_frozen->'prior_facts') IS DISTINCT FROM 'array'
 OR jsonb_typeof(evidence) IS DISTINCT FROM 'object'
 OR p_at IS NULL OR NOT isfinite(p_at)
 OR p_work IS NULL OR p_work NOT BETWEEN 0 AND 400000 THEN
  RAISE EXCEPTION 'metadata final retained evidence incomplete' USING ERRCODE='42501';END IF;
 work:=jsonb_array_length(p_frozen->'candidate_facts')+jsonb_array_length(p_frozen->'prior_facts');
 IF work>p_work THEN RAISE EXCEPTION 'metadata final retained union budget exhausted' USING ERRCODE='54000';END IF;
 FOR value IN SELECT f FROM jsonb_array_elements((p_frozen->'candidate_facts')||(p_frozen->'prior_facts')) f LOOP
  IF jsonb_typeof(value) IS DISTINCT FROM 'object'
   OR value-ARRAY['object_type','object_id','relation','subject']<>'{}'::jsonb
   OR coalesce(value->>'object_type','')='' OR value->>'object_type' LIKE '%.%'
   OR coalesce(value->>'object_id','')='' OR coalesce(value->>'relation','')='' OR coalesce(value->>'subject','')='' THEN
   RAISE EXCEPTION 'metadata final fact coordinate malformed' USING ERRCODE='42501';END IF;
 END LOOP;
 decision:=kaname._authority_access_label_retained_facts_v1(p_frozen->'candidate_facts',
  evidence->'certificate',evidence->'sources',evidence->'physical',evidence->'folded',p_at,p_work-work);
 work:=work+(decision->>'work')::integer;
 -- Сохраняем факты прежних поколений до отдельной сверки поколения и строк.
 SELECT coalesce(jsonb_agg(f ORDER BY f->>'object_type' COLLATE "C",f->>'object_id' COLLATE "C",
  f->>'relation' COLLATE "C",f->>'subject' COLLATE "C"),'[]'::jsonb) INTO facts
 FROM (SELECT pending.fact AS f FROM jsonb_array_elements(decision->'pending') pending(fact)
  UNION SELECT prior.fact FROM jsonb_array_elements(p_frozen->'prior_facts') prior(fact)) q;
 RETURN jsonb_build_object('facts',facts,'retained',decision->'retained','absent',decision->'absent','work',work);
END;
$retained$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text;recipient record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
  '_authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)',
  '_authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer)',
  '_authority_metadata_access_label_retention_certify_v1(jsonb,jsonb,jsonb,jsonb,integer)',
  '_authority_metadata_access_label_retention_inputs_v1(jsonb,jsonb,integer)',
  '_authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)',
  '_authority_metadata_access_label_retention_compile_v1(jsonb,integer)',
  '_authority_metadata_access_label_retained_select_v1(jsonb,timestamptz,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
   JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,recipient.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_drain();
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_metadata_access_label_retained_select_v1(jsonb,timestamptz,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_compile_v1(jsonb,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_inputs_v1(jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_certify_v1(jsonb,jsonb,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_metadata_access_label_retention_plan_v1(jsonb,jsonb,jsonb,jsonb,text,jsonb,jsonb,integer);
DROP FUNCTION kaname._authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
DROP FUNCTION kaname._authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer);
