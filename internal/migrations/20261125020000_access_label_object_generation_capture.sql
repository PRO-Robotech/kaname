-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Приватное наблюдение поколений, без выдачи полномочий и без retirement.
-- STABLE сохраняет один снимок для всех чтений внутри вызова. Будущий worker
-- обязан повторить его под полными удержаниями до выбора финального времени.

-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_access_label_object_generation_capture_v1(
 p_model text,p_id text,p_rows integer,p_reads integer
) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $capture$
DECLARE
 root_identity jsonb;root_state jsonb;root_identities jsonb[];roots jsonb[]:=ARRAY[]::jsonb[];
 direct_type text;direct_root jsonb:='null';direct_linked boolean;
 output_states jsonb:='[]';fact_states jsonb;facts jsonb;
 used_rows integer:=0;used_reads integer:=0;captured_rows integer;remaining_rows integer;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF coalesce(p_model,'')='' OR p_model LIKE '%.%' OR coalesce(p_id,'')=''
 OR octet_length(p_model)>16384 OR octet_length(p_id)>16384
 OR p_model ~ '[:#*[:space:][:cntrl:]]' OR p_id ~ '[:#*[:space:][:cntrl:]]' THEN
  RAISE EXCEPTION 'generation capture coordinate invalid' USING ERRCODE='42501';END IF;
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000
 OR p_reads IS NULL OR p_reads NOT BETWEEN 1 AND 4096 THEN
  RAISE EXCEPTION 'generation capture budget invalid' USING ERRCODE='54000';END IF;

 -- Координата факта использует model type, как индекс dirty_fact_coordinate.
 -- Прямой корень проверяется независимо от наличия accounts/projects и фактов:
 -- пустое поколение удалённого ресурса тоже должно попасть в снимок.
 direct_type:=CASE p_model WHEN 'account' THEN 'iam.account' WHEN 'project' THEN 'iam.project' END;
 IF direct_type IS NOT NULL THEN
  direct_root:=jsonb_build_object('root_type',direct_type,'root_id',p_id,'state',NULL);
 END IF;

 used_reads:=used_reads+1;
 -- Ограничиваем физическую выборку ДО сортировки и удаления повторов корней.
 -- MATERIALIZED не позволяет перенести LIMIT за сортировку. При sentinel
 -- accepted пуст: агрегаты не собирают JSON и не сортируют прочитанный хвост.
 WITH bounded AS MATERIALIZED (
  SELECT d.xmin::text row_xmin,d.ctid::text row_tid,d row_value,
   d.root_type,d.root_id,d.relation,d.subject
  FROM kaname.authority_access_label_dirty_fact d
  WHERE d.object_type=p_model AND d.object_id=p_id LIMIT p_rows+1
 ), counted AS MATERIALIZED (
  SELECT count(*)::integer n FROM bounded
 ), accepted AS MATERIALIZED (
  SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=p_rows
 )
 SELECT (SELECT n FROM counted),
  (SELECT coalesce(jsonb_agg(jsonb_build_array(a.row_xmin,a.row_tid,to_jsonb(a.row_value))
   ORDER BY a.root_type COLLATE "C",a.root_id COLLATE "C",a.relation COLLATE "C",a.subject COLLATE "C"),'[]'::jsonb)
   FROM accepted a),
  (SELECT coalesce(array_agg(jsonb_build_array(k.root_type,k.root_id)
   ORDER BY k.root_type COLLATE "C",k.root_id COLLATE "C"),ARRAY[]::jsonb[])
   FROM (SELECT a.root_type COLLATE "C" root_type,a.root_id COLLATE "C" root_id FROM accepted a
    UNION SELECT direct_type COLLATE "C",p_id COLLATE "C"
     WHERE direct_type IS NOT NULL AND (SELECT n FROM counted)<=p_rows) k),
  (SELECT coalesce(bool_or(a.root_type=direct_type AND a.root_id=p_id),false) FROM accepted a)
 INTO captured_rows,output_states,root_identities,direct_linked;
 IF captured_rows>p_rows THEN
  RAISE EXCEPTION 'generation output census row budget exceeded' USING ERRCODE='54000';END IF;
 used_rows:=used_rows+captured_rows;

 FOREACH root_identity IN ARRAY root_identities LOOP
  IF used_reads>=p_reads THEN
   RAISE EXCEPTION 'generation root read budget exceeded' USING ERRCODE='54000';END IF;
  used_reads:=used_reads+1;
  SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r)) INTO root_state
  FROM kaname.authority_access_label_dirty_root r
  WHERE r.root_type=root_identity->>0 AND r.root_id=root_identity->>1;
  IF root_identity=jsonb_build_array(direct_type,p_id) THEN
   direct_root:=jsonb_set(direct_root,'{state}',coalesce(root_state,'null'::jsonb));
  END IF;
  IF root_state IS NULL THEN
   -- Отсутствие прямого корня явно отражено в direct_root. У найденного через
   -- факт корня отсутствие недопустимо: FK и единый снимок должны его сохранить.
   IF root_identity IS DISTINCT FROM jsonb_build_array(direct_type,p_id) OR direct_linked THEN
    RAISE EXCEPTION 'generation output root missing' USING ERRCODE='40001';END IF;
   CONTINUE;
  END IF;
  used_rows:=used_rows+1;
  IF used_rows>p_rows THEN
   RAISE EXCEPTION 'generation root row budget exceeded' USING ERRCODE='54000';END IF;
  IF used_reads>=p_reads THEN
   RAISE EXCEPTION 'generation fact read budget exceeded' USING ERRCODE='54000';END IF;
  used_reads:=used_reads+1;remaining_rows:=p_rows-used_rows;
  -- Полный набор поколения включает и другие объекты: выборка только исходной
  -- координаты не доказывает состав всех затронутых субъектов.
  WITH bounded AS MATERIALIZED (
   SELECT d.xmin::text row_xmin,d.ctid::text row_tid,d row_value,
    d.object_type,d.object_id,d.relation,d.subject
   FROM kaname.authority_access_label_dirty_fact d
   WHERE d.root_type=root_identity->>0 AND d.root_id=root_identity->>1
    AND d.generation=(root_state#>>'{2,generation}')::uuid
   LIMIT remaining_rows+1
  ), counted AS MATERIALIZED (
   SELECT count(*)::integer n FROM bounded
  ), accepted AS MATERIALIZED (
   SELECT b.* FROM bounded b WHERE (SELECT n FROM counted)<=remaining_rows
  )
  SELECT (SELECT n FROM counted),
   coalesce(jsonb_agg(jsonb_build_array(a.row_xmin,a.row_tid,to_jsonb(a.row_value))
    ORDER BY a.object_type COLLATE "C",a.object_id COLLATE "C",a.relation COLLATE "C",a.subject COLLATE "C"),'[]'::jsonb),
   coalesce(jsonb_agg(jsonb_build_object('object_type',a.object_type,'object_id',a.object_id,
    'relation',a.relation,'subject',a.subject)
    ORDER BY a.object_type COLLATE "C",a.object_id COLLATE "C",a.relation COLLATE "C",a.subject COLLATE "C"),'[]'::jsonb)
   INTO captured_rows,fact_states,facts FROM accepted a;
  IF captured_rows>remaining_rows THEN
   RAISE EXCEPTION 'generation fact census row budget exceeded' USING ERRCODE='54000';END IF;
  used_rows:=used_rows+captured_rows;
  -- Расширенный массив PL/pgSQL дополняется без повторного копирования JSON
  -- всех прежних корней. Внешнее представление собирается один раз в RETURN.
  roots:=array_append(roots,jsonb_build_object('state',root_state,'facts',facts,'fact_states',fact_states));
 END LOOP;
 -- Считаем каждую повторно прочитанную физическую строку, включая output
 -- predicate, и каждое чтение пустого набора. Здесь нет locks или DML.
 RETURN jsonb_build_object('object_type',p_model,'object_id',p_id,'direct_root',direct_root,
  'output_states',output_states,'roots',to_jsonb(roots),'rows',used_rows,'reads',used_reads);
END;
$capture$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE recipient record;
BEGIN
 REVOKE ALL ON FUNCTION kaname._authority_access_label_object_generation_capture_v1(text,text,integer,integer) FROM PUBLIC;
 -- ALTER DEFAULT PRIVILEGES также не должен открывать приватный снимок.
 FOR recipient IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
  CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_access_label_object_generation_capture_v1(text,text,integer,integer)'::regprocedure
   AND a.grantee<>p.proowner LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_access_label_object_generation_capture_v1(text,text,integer,integer) FROM %I',recipient.rolname);
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_access_label_object_generation_capture_v1(text,text,integer,integer);
