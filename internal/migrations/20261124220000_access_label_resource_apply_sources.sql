-- Copyright (c) PRO-Robotech
-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Составная часть owner preflight. Передаётся только вывод проверки
-- определений из удержанных OLD/NEW, а не описание права от клиента.
-- +goose Up
SELECT kaname.authority_protocol_require_owner();

-- +goose StatementBegin
CREATE FUNCTION kaname._authority_resource_access_label_sources_hold_v1(
 p_actor_type text,p_actor_id text,p_requirements jsonb,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $held$
DECLARE
 group_ids text[];
 source_count integer;
 source_limit integer;
 sources jsonb;
 used_rows integer;
 used_reads integer:=2;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF current_setting('transaction_isolation') IS DISTINCT FROM 'read committed'
  OR p_actor_type IS NULL OR p_actor_type NOT IN ('user','service_account')
  OR coalesce(p_actor_id,'')='' OR p_actor_id ~ '[:#*[:space:][:cntrl:]]'
  OR jsonb_typeof(p_requirements) IS DISTINCT FROM 'array'
  OR jsonb_array_length(p_requirements) NOT BETWEEN 1 AND 128 THEN
  RAISE EXCEPTION 'invalid exact resource apply source request' USING ERRCODE='42501';END IF;
 used_rows:=1+jsonb_array_length(p_requirements);
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
  RAISE EXCEPTION 'resource apply source capture budget exhausted' USING ERRCODE='54000';END IF;
 IF p_actor_type='user' THEN
  PERFORM u.id FROM kaname.users u WHERE u.id=p_actor_id AND u.email_verified_at IS NOT NULL FOR SHARE;
 ELSE
  PERFORM u.id FROM kaname.service_accounts u WHERE u.id=p_actor_id AND u.enabled FOR SHARE;
 END IF;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'resource apply actor is inactive' USING ERRCODE='42501';END IF;
 SELECT coalesce(array_agg(m.group_id ORDER BY m.group_id COLLATE "C"),ARRAY[]::text[]) INTO group_ids
 FROM (
  SELECT gm.group_id FROM kaname.group_members gm JOIN kaname.groups g ON g.id=gm.group_id
  WHERE gm.member_type=p_actor_type AND gm.member_id=p_actor_id
  ORDER BY gm.group_id COLLATE "C" LIMIT least((p_rows-used_rows)/2,4096)+1 FOR SHARE OF gm,g
 ) m;
 IF cardinality(group_ids)>least((p_rows-used_rows)/2,4096) THEN
  RAISE EXCEPTION 'resource apply membership source budget exhausted' USING ERRCODE='54000';END IF;
 used_rows:=used_rows+2*cardinality(group_ids);
 used_reads:=used_reads+2;
 IF used_reads>p_reads THEN
  RAISE EXCEPTION 'resource apply source capture budget exhausted' USING ERRCODE='54000';END IF;
 -- Четыре удержанные строки на носителя: binding, субъект, роль и источник
 -- apply. Границы области и stamped definition поступают из owner compiler.
 source_limit:=least((p_rows-used_rows)/4,4096);
 WITH wanted AS MATERIALIZED (
   SELECT q.definition_id,q.scope_kind,q.scope_id
   FROM jsonb_to_recordset(p_requirements) q(definition_id uuid,scope_kind text,scope_id text)
  ), recipients AS MATERIALIZED (
   SELECT p_actor_type AS subject_type,p_actor_id AS subject_id
   UNION ALL SELECT 'group',g FROM unnest(group_ids) g
  ), captured AS MATERIALIZED (
  SELECT w.definition_id,w.scope_kind,w.scope_id,b.id AS binding_id,
   s.subject_type AS recipient_type,s.subject_id AS recipient_id,
   a.rule_fp,r.id AS role_id,b.xmin::text AS binding_xmin,b.ctid::text AS binding_ctid,
   r.xmin::text AS role_xmin,r.ctid::text AS role_ctid
  FROM wanted w CROSS JOIN recipients u
  JOIN kaname.access_binding_subjects s ON s.subject_type=u.subject_type AND s.subject_id=u.subject_id
  JOIN kaname.access_bindings b ON b.id=s.binding_id AND b.role_id IS NOT NULL
  JOIN kaname.roles r ON r.id=b.role_id AND r.live
  JOIN kaname.authority_role_access_label_rule a ON a.role_id=r.id AND a.definition_id=w.definition_id
  WHERE s.resource_type=w.scope_kind AND s.resource_id=w.scope_id
   AND b.resource_type=w.scope_kind AND b.resource_id=w.scope_id
   AND b.status='ACTIVE' AND b.revoked_at IS NULL AND b.grant_capability_version=1
   AND ((jsonb_typeof(b.target)='object' AND NOT (b.target ? 'resources')) OR b.target->'resources'='[]'::jsonb)
  LIMIT source_limit+1 FOR SHARE OF b,s,r,a
 ), grouped AS (
  SELECT c.definition_id,count(*)::integer AS ct,
   jsonb_agg(to_jsonb(c) ORDER BY c.binding_id,c.recipient_type,c.recipient_id,c.rule_fp) AS variants
  FROM captured c GROUP BY c.definition_id
 )
 SELECT coalesce(sum(g.ct),0)::integer,coalesce(jsonb_object_agg(g.definition_id,g.variants),'{}'::jsonb)
 INTO source_count,sources FROM grouped g;
 IF source_count>source_limit THEN
  RAISE EXCEPTION 'resource apply source capture budget exhausted' USING ERRCODE='54000';END IF;
 used_rows:=used_rows+4*source_count;
 RETURN jsonb_build_object('actor',jsonb_build_object('type',p_actor_type,'id',p_actor_id),
  'sources',sources,'source_count',source_count,'rows',used_rows,'reads',used_reads);
END;
$held$;
-- +goose StatementEnd

-- Вызывается после окончательного decision_at. Полный signed owner frame
-- связывает frozen evidence с этой мутацией; поздние физические ожидания
-- не нужны, поскольку все положительные источники уже удержаны.
-- +goose StatementBegin
CREATE FUNCTION kaname._authority_resource_access_label_sources_require_v1(
 p_receipt jsonb,p_requirements jsonb,p_at timestamptz,p_rows integer,p_reads integer
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $apply$
DECLARE
 requirement jsonb;
 candidate jsonb;
 verdict jsonb;
 authorized boolean;
 used_rows integer;
 used_reads integer:=1;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 IF p_at IS NULL OR NOT isfinite(p_at)
  OR jsonb_typeof(p_receipt->'actor') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_receipt->'sources') IS DISTINCT FROM 'object'
  OR jsonb_typeof(p_receipt->'source_count') IS DISTINCT FROM 'number'
  OR (p_receipt->>'source_count')::integer NOT BETWEEN 0 AND 4096
  OR jsonb_typeof(p_requirements) IS DISTINCT FROM 'array'
  OR jsonb_array_length(p_requirements) NOT BETWEEN 1 AND 128 THEN
  RAISE EXCEPTION 'resource apply source receipt is incomplete' USING ERRCODE='42501';END IF;
 used_rows:=jsonb_array_length(p_requirements)+(p_receipt->>'source_count')::integer;
 IF p_rows IS NULL OR p_rows NOT BETWEEN used_rows AND 100000
  OR p_reads IS NULL OR p_reads NOT BETWEEN used_reads AND 4096 THEN
  RAISE EXCEPTION 'resource apply final source budget exhausted' USING ERRCODE='54000';END IF;
 FOR requirement IN SELECT value FROM jsonb_array_elements(p_requirements) LOOP
  authorized:=false;
  FOR candidate IN SELECT value FROM jsonb_array_elements(
   coalesce(p_receipt->'sources'->(requirement->>'definition_id'),'[]'::jsonb)) s
   WHERE s.value->'scope_kind'=requirement->'scope_kind' AND s.value->'scope_id'=requirement->'scope_id'
  LOOP
   IF used_rows>p_rows-8 OR used_reads>p_reads-2 THEN
    RAISE EXCEPTION 'resource apply final source budget exhausted' USING ERRCODE='54000';END IF;
   verdict:=kaname._authority_access_label_source_check_v2(
    p_receipt#>>'{actor,type}',p_receipt#>>'{actor,id}',requirement->>'scope_kind',requirement->>'scope_id',
    (requirement->>'definition_id')::uuid,candidate->>'binding_id',candidate->>'recipient_type',candidate->>'recipient_id',
    candidate->>'rule_fp',p_at,p_rows-used_rows,candidate->>'role_id',candidate->>'binding_xmin',
    candidate->>'binding_ctid',candidate->>'role_xmin',candidate->>'role_ctid');
   used_rows:=used_rows+(verdict->>'rows')::integer;
   used_reads:=used_reads+(verdict->>'reads')::integer;
   IF used_rows>p_rows OR used_reads>p_reads OR used_rows IS NULL OR used_reads IS NULL THEN
    RAISE EXCEPTION 'resource apply final source budget exhausted' USING ERRCODE='54000';END IF;
   IF verdict->'allowed'='true'::jsonb THEN authorized:=true;EXIT;END IF;
  END LOOP;
  IF NOT authorized THEN
   RAISE EXCEPTION 'resource access label apply denied in exact scope' USING ERRCODE='42501';END IF;
 END LOOP;
 RETURN jsonb_build_object('rows',used_rows,'reads',used_reads);
END;
$apply$;
-- +goose StatementEnd

-- +goose StatementBegin
DO $private$
DECLARE signature text;grantee record;
BEGIN
 PERFORM kaname.authority_protocol_require_owner();
 FOREACH signature IN ARRAY ARRAY[
  '_authority_resource_access_label_sources_hold_v1(text,text,jsonb,integer,integer)',
  '_authority_resource_access_label_sources_require_v1(jsonb,jsonb,timestamptz,integer,integer)'
 ] LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM PUBLIC',signature);
  FOR grantee IN SELECT DISTINCT r.rolname FROM pg_catalog.pg_proc p
   CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) a JOIN pg_catalog.pg_roles r ON r.oid=a.grantee
   WHERE p.oid=to_regprocedure('kaname.'||signature) AND a.grantee<>p.proowner LOOP
   EXECUTE format('REVOKE ALL ON FUNCTION kaname.%s FROM %I',signature,grantee.rolname);
  END LOOP;
 END LOOP;
END;
$private$;
-- +goose StatementEnd

-- +goose Down
SELECT kaname.authority_protocol_require_owner();
DROP FUNCTION kaname._authority_resource_access_label_sources_require_v1(jsonb,jsonb,timestamptz,integer,integer);
DROP FUNCTION kaname._authority_resource_access_label_sources_hold_v1(text,text,jsonb,integer,integer);
