-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- kaname#1045: закрытое чтение состояния и пределов регистрации потомка.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN PERFORM kaname.authority_protocol_drain(); END $$;
-- +goose StatementEnd

-- Один снимок без ожидания блокировок. При проверке после ожидания вызывающий
-- должен начать новый RC statement под общим ограждением родителя. Вызывающий
-- проверяет право пользователя до чтения состояния и повторяет проверку перед записью.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_child_registration_capture_v1(
 p_child_type text,p_child_id text,p_rows integer,p_reads integer)
RETURNS TABLE(witness jsonb,logical_rows integer,logical_reads integer)
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 child_model text; parent_dotted text; parent_model text; parent_key text; parent_action text;
 policy jsonb; parts text[]; parent_segments integer; max_children integer; max_creates integer;
 parent_version timestamptz; incarnation uuid; closed_at timestamptz;
 child_version timestamptz; direct_parent boolean; replay_version timestamptz;
 live_children integer; candidate record; recent_creations timestamptz[]:=ARRAY[]::timestamptz[];
 version_sources record; version_watermark timestamptz; parent_subject text;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_rows IS NULL OR p_rows NOT BETWEEN 0 AND 100000 OR p_reads IS NULL OR p_reads NOT BETWEEN 0 AND 4096 THEN
  RAISE EXCEPTION 'invalid child registration read budget' USING ERRCODE='22023';
 END IF;
 IF p_child_type IS NULL OR octet_length(p_child_type)>512 OR p_child_id IS NULL OR octet_length(p_child_id)>512
  OR p_child_id COLLATE "C" !~ '^[a-z0-9]([a-z0-9._-]*[a-z0-9])?(/[a-z0-9]([a-z0-9._-]*[a-z0-9])?)+$' THEN
  RAISE EXCEPTION 'invalid child registration coordinates' USING ERRCODE='22023';
 END IF;
 IF p_rows<3 OR p_reads<1 THEN
  RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
 END IF;
 -- Все три строки имеют точные уникальные ключи. Имена модели и каталога
 -- различаются. Модельные имена нужны для рёбер, точечные для зеркала и квитанций.
 SELECT c.object_type,p.dotted,p.object_type,v.container_relation,c.child_registration
 INTO child_model,parent_dotted,parent_model,parent_action,policy
 FROM kaname.catalog_resource c
 JOIN kaname.catalog_resource p ON p.object_type=c.parent_types[array_position(c.parent_names,'parent')]
  AND p.live AND p.module=c.module
 JOIN kaname.catalog_verb v ON v.module=c.module AND v.resource=c.resource AND v.verb=c.child_registration->>'Verb'
  AND v.live AND NOT v.per_object AND v.container_parent=p.object_type AND v.container_relation<>''
 WHERE c.dotted=p_child_type AND c.live AND c.child_registration IS NOT NULL;
 IF NOT FOUND OR left(parent_action,2)='v_' THEN
  RAISE EXCEPTION 'child registration policy unavailable' USING ERRCODE='42501';
 END IF;
 logical_rows:=3;
 logical_reads:=1;
 parts:=string_to_array(p_child_id,'/');
 parent_segments:=(policy->>'ParentSegments')::integer;
 parent_key:=array_to_string(parts[1:parent_segments],'/');
 IF cardinality(parts)<=parent_segments OR octet_length(child_model)+1+octet_length(p_child_id)>512
  OR octet_length(parent_model)+1+octet_length(parent_key)>512 THEN
  RAISE EXCEPTION 'invalid child registration path' USING ERRCODE='22023';
 END IF;

 logical_reads:=logical_reads+1;
 IF logical_reads>p_reads THEN
  RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
 END IF;
 SELECT m.source_version,s.incarnation,s.closed_at INTO parent_version,incarnation,closed_at
 FROM kaname.resource_mirror m
 LEFT JOIN kaname.authority_child_parent_state s USING(object_type,object_id)
 WHERE m.object_type=parent_dotted AND m.object_id=parent_key;
 IF FOUND THEN
  logical_rows:=logical_rows+1+CASE WHEN incarnation IS NULL THEN 0 ELSE 1 END;
 END IF;

 IF parent_version IS NOT NULL AND closed_at IS NULL THEN
  logical_reads:=logical_reads+1;
  IF logical_rows>p_rows OR logical_reads>p_reads THEN
   RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
  END IF;
  SELECT m.source_version,e.object_id IS NOT NULL,c.source_version
  INTO child_version,direct_parent,replay_version
  FROM kaname.resource_mirror m
  LEFT JOIN kaname.resource_parent_edge e ON e.object_type=child_model AND e.object_id=m.object_id
   AND e.parent_type=parent_model AND e.parent_id=parent_key AND e.depth=1
  LEFT JOIN kaname.authority_child_creation c ON c.child_type=m.object_type AND c.child_id=m.object_id
   AND c.source_version=m.source_version AND c.parent_incarnation=incarnation AND e.object_id IS NOT NULL
  WHERE m.object_type=p_child_type AND m.object_id=p_child_id;
  IF FOUND THEN
   logical_rows:=logical_rows+1+CASE WHEN direct_parent THEN 1 ELSE 0 END
    +CASE WHEN replay_version IS NULL THEN 0 ELSE 1 END;
  ELSE
   -- Для точного повтора состояние и текущая версия уже достаточны.
   -- Ёмкость проверяется только для нового объекта.
   max_children:=(policy->>'MaxChildren')::integer;
   max_creates:=(policy->>'MaxCreates')::integer;
   live_children:=0;
   logical_reads:=logical_reads+1;
   IF logical_rows>p_rows OR logical_reads>p_reads THEN
    RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
   END IF;
   -- Индекс упорядочивает рёбра до отсечения. Пустое зеркало не расходует
   -- ёмкость, но его ребро учитывается в бюджете чтения.
   FOR candidate IN
    SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror m WHERE m.object_type=p_child_type AND m.object_id=e.object_id) AS live
    FROM kaname.resource_parent_edge e
    WHERE e.parent_type=parent_model AND e.parent_id=parent_key AND e.object_type=child_model AND e.depth=1
    ORDER BY e.object_id LIMIT (p_rows-logical_rows+1)
   LOOP
    logical_rows:=logical_rows+1;
    IF candidate.live THEN
     logical_rows:=logical_rows+1;
     live_children:=live_children+1;
    END IF;
    IF logical_rows>p_rows THEN
     RAISE EXCEPTION 'child registration capacity capture budget exceeded' USING ERRCODE='54000';
    END IF;
    EXIT WHEN live_children=max_children;
   END LOOP;

   IF incarnation IS NOT NULL THEN
    logical_reads:=logical_reads+1;
    IF logical_reads>p_reads THEN
     RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
    END IF;
    -- Не привязываем выборку к времени предварительного чтения. Суффикса
    -- из MaxCreates новых квитанций достаточно для расчёта на DecisionAt.
    SELECT ARRAY(SELECT c.created_at FROM kaname.authority_child_creation c
     WHERE c.parent_incarnation=incarnation AND c.child_type=p_child_type
     ORDER BY c.created_at DESC LIMIT least(max_creates,p_rows-logical_rows+1)) INTO recent_creations;
    logical_rows:=logical_rows+cardinality(recent_creations);
   END IF;

   IF live_children<max_children THEN
    -- Повторная регистрация должна идти после сохранённых версий этого ключа.
    -- Именованные указатели сюда не входят: они не могут хранить связь parent.
    logical_reads:=logical_reads+4;
    IF logical_rows>p_rows OR logical_reads>p_reads THEN
     RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
    END IF;
    parent_subject:=parent_model||':'||parent_key;
    SELECT
     (SELECT r.delete_through FROM kaname.resource_registration_retirement r
      WHERE r.object_type=child_model AND r.object_id=p_child_id AND r.relation='parent' AND r.subject=parent_subject) AS retired_at,
     (SELECT f.source_version FROM kaname.relation_fact f
      WHERE f.object_type=child_model AND f.object_id=p_child_id AND f.relation='parent' AND f.subject=parent_subject) AS fact_version,
     (SELECT c.source_version FROM kaname.authority_child_creation c
      WHERE c.child_type=p_child_type AND c.child_id=p_child_id ORDER BY c.source_version DESC LIMIT 1) AS receipt_version,
     e.latest_version AS edge_version,e.edge_count
    INTO STRICT version_sources
    FROM (SELECT max(e.source_version) AS latest_version,count(*)::integer AS edge_count
     FROM kaname.resource_parent_edge e WHERE e.object_type=child_model AND e.object_id=p_child_id) e;
    version_watermark:=greatest(version_sources.retired_at,version_sources.fact_version,
     version_sources.receipt_version,version_sources.edge_version);
    logical_rows:=logical_rows+version_sources.edge_count
     +CASE WHEN version_sources.retired_at IS NULL THEN 0 ELSE 1 END
     +CASE WHEN version_sources.fact_version IS NULL THEN 0 ELSE 1 END
     +CASE WHEN version_sources.receipt_version IS NULL THEN 0 ELSE 1 END;
   END IF;
  END IF;
 END IF;
 IF logical_rows>p_rows OR logical_reads>p_reads THEN
  RAISE EXCEPTION 'child registration capture budget exceeded' USING ERRCODE='54000';
 END IF;
 witness:=jsonb_build_object(
  'child_type',p_child_type,'child_model',child_model,'child_id',p_child_id,
  'parent_type',parent_dotted,'parent_model',parent_model,'parent_id',parent_key,'parent_action',parent_action,
  'policy',policy,'parent_version',parent_version,'parent_incarnation',incarnation,'closed_at',closed_at,
  'child_version',child_version,'replay_version',replay_version,'live_children',live_children,
  'recent_creations',recent_creations,'version_watermark',version_watermark);
 RETURN NEXT;
END $$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION kaname._authority_child_registration_capture_v1(text,text,integer,integer) FROM PUBLIC;
-- +goose StatementBegin
DO $$ DECLARE principal record; BEGIN
 FOR principal IN SELECT r.rolname FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
  JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
  WHERE p.oid='kaname._authority_child_registration_capture_v1(text,text,integer,integer)'::regprocedure AND a.grantee<>p.proowner
 LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname._authority_child_registration_capture_v1(text,text,integer,integer) FROM %I',principal.rolname);
 END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION kaname._authority_child_registration_capture_v1(text,text,integer,integer);
